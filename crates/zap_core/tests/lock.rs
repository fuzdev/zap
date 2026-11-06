//! Lock subsystem tests (the tracked `remote_file` pin).
//!
//! The correctness core is exercised **without an eval**: `resolve_lock` (cold-start
//! mint / stale-config / idempotent re-validate) and `execute_plan` materializing a
//! tracked file from the lock pin run against an in-memory `ZapConfig` + a real local
//! HTTP server (dep-free, a std `TcpListener` on a worker thread). One fgro-gated test
//! covers the `run_lock_check` config↔lock wiring. Real-target execution stays manual.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;
mod scratch;

use std::collections::BTreeMap;
use std::io::{Read, Write};

use common::{fgro, fgro_available, local_machine};
use zap_core::commands::lock::{LockCheckReport, run_lock_check_in};
use zap_core::commands::render_lock_check;
use zap_core::connection::Connection;
use zap_core::event::EventHandler;
use zap_core::lock::{
    ColdStart, EntryStatus, LockAddressing, LockStanding, NameOnlyRef, NameOnlyRefs,
    UnverifiableEntry, classify_lock, inspect_lock, is_lock_eligible, lock_path_for, read_zap_lock,
    resolve_lock, write_zap_lock,
};
use zap_core::resource::{Markers, detect_all, execute_plan};
use zap_types::lock::{LOCK_VERSION, LockEntry, ZapLock};
use zap_types::plan::{DiffInputs, diff};
use zap_types::scalar::ContentHash;
use zap_types::schema::{Resource, ResourceId, Target, ZapConfig};
use zap_types::secrecy::{SecretReason, ValueShape};
use zap_types::text::Text;
use zap_types::var_ref::Segment::{Ref, Text as Lit};
use zap_types::var_ref::{marker, shown};

/// A throwaway one-shot HTTP/1.1 server: serves `body` once, returns its url.
fn serve_once(body: Vec<u8>) -> String {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        if let Ok((mut sock, _)) = listener.accept() {
            let mut buf = [0u8; 1024];
            let _ = sock.read(&mut buf);
            let header = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            let _ = sock.write_all(header.as_bytes());
            let _ = sock.write_all(&body);
            let _ = sock.flush();
        }
    });
    format!("http://{addr}/zig")
}

fn blake3_hex(bytes: &[u8]) -> ContentHash {
    ContentHash::of_bytes(bytes)
}

/// A config with a single tracked remote file (no in-config `blake3`) at `path`.
fn tracked_config(url: &str, path: &str) -> ZapConfig {
    serde_json::from_value(serde_json::json!({
        "target": {"local": true},
        "resources": [{
            "id": "zig", "type": "file", "path": Text::from_inert(path).unwrap(),
            "content": {"type": "remote", "url": Text::from_inert(url).unwrap(), "extract": {"type": "none"}},
        }],
    }))
    .unwrap()
}

/// A config with a single tracked build (no in-config `blake3`) fetching its source
/// from `url` — the lock pins the resolved *source* blake3 (the build's provenance).
fn tracked_build_config(url: &str) -> ZapConfig {
    serde_json::from_value(serde_json::json!({
        "target": {"local": true},
        "resources": [{
            "id": "ghostty", "type": "build",
            "source": {"type": "remote", "url": Text::from_inert(url).unwrap(), "extract": {"type": "tar.xz"}},
            "run": "zig build -p $HOME/.local",
            "output": "$HOME/.local/bin/ghostty",
        }],
    }))
    .unwrap()
}

#[tokio::test]
async fn resolve_lock_cold_start_mints_the_pin() {
    let body = b"zig-bytes".to_vec();
    let pin = blake3_hex(&body);
    let url = serve_once(body);

    let home = scratch::tempdir().unwrap();
    let cfg_dir = scratch::tempdir().unwrap();
    let config_path = cfg_dir.path().join("zap.ts"); // need not exist — no lock yet
    let config = tracked_config(&url, "/opt/zig");

    let resolved = resolve_lock(&config, &config_path, home.path(), ColdStart::Mint)
        .await
        .unwrap();
    assert_eq!(resolved.newly_resolved, vec![ResourceId("zig".to_owned())]);
    let entry = resolved
        .lock
        .entries
        .get(&ResourceId("zig".to_owned()))
        .unwrap();
    assert_eq!(entry.pin(), Some(&pin));
}

#[tokio::test]
async fn resolve_lock_validates_an_existing_entry_without_refetch() {
    // A pre-existing, correct entry: resolve_lock must validate (no stale error) and
    // not re-resolve — proven by pointing at a dead url that would fail if dialed.
    let cfg_dir = scratch::tempdir().unwrap();
    let config_path = cfg_dir.path().join("zap.ts");
    let config = tracked_config("http://127.0.0.1:1/zig", "/opt/zig");
    let resource = &config.resources[0];

    // Build a correct entry (fixed point: hash with this pin folded).
    let pin = blake3_hex(b"whatever");
    let probe = LockEntry::RemoteFile {
        config_hash: String::new(),
        blake3: pin.clone(),
    };
    let config_hash = LockAddressing::of(&config)
        .entry_config_hash(resource, &probe, env(&[]))
        .unwrap();
    let mut lock = ZapLock {
        toolchain: common::toolchain(),
        ..ZapLock::default()
    };
    lock.entries.insert(
        ResourceId("zig".to_owned()),
        LockEntry::RemoteFile {
            config_hash,
            blake3: pin.clone(),
        },
    );
    write_zap_lock(&lock_path_for(&config_path), &lock).unwrap();

    let home = scratch::tempdir().unwrap();
    let resolved = resolve_lock(&config, &config_path, home.path(), ColdStart::Mint)
        .await
        .unwrap();
    assert!(resolved.newly_resolved.is_empty(), "no refetch");
    assert_eq!(
        resolved.lock.entries[&ResourceId("zig".to_owned())].pin(),
        Some(&pin)
    );
}

#[tokio::test]
async fn resolve_lock_rejects_a_stale_entry() {
    // An entry whose config_hash doesn't match the current config → LockStale (never
    // auto-reconciled). No fetch happens (the entry exists).
    let cfg_dir = scratch::tempdir().unwrap();
    let config_path = cfg_dir.path().join("zap.ts");
    let config = tracked_config("http://127.0.0.1:1/zig", "/opt/zig");

    let mut lock = ZapLock {
        toolchain: common::toolchain(),
        ..ZapLock::default()
    };
    lock.entries.insert(
        ResourceId("zig".to_owned()),
        LockEntry::RemoteFile {
            config_hash: "deliberately-wrong".to_owned(),
            blake3: blake3_hex(b"x"),
        },
    );
    write_zap_lock(&lock_path_for(&config_path), &lock).unwrap();

    let home = scratch::tempdir().unwrap();
    let err = resolve_lock(&config, &config_path, home.path(), ColdStart::Mint)
        .await
        .unwrap_err();
    assert!(
        matches!(err, zap_core::error::Error::LockStale { .. }),
        "{err:?}"
    );
}

#[tokio::test]
async fn resolve_lock_cold_start_mints_a_build_pin() {
    // A tracked build with no in-config blake3: resolve_lock fetches + hashes the source
    // archive and mints a `Build` entry pinning the resolved source blake3 (what the
    // provenance the executor records in the `<output>.zap-build` sidecar digests).
    let body = b"ghostty-source-archive".to_vec();
    let pin = blake3_hex(&body);
    let url = serve_once(body);

    let home = scratch::tempdir().unwrap();
    let cfg_dir = scratch::tempdir().unwrap();
    let config_path = cfg_dir.path().join("zap.ts");
    let config = tracked_build_config(&url);

    let resolved = resolve_lock(&config, &config_path, home.path(), ColdStart::Mint)
        .await
        .unwrap();
    assert_eq!(
        resolved.newly_resolved,
        vec![ResourceId("ghostty".to_owned())]
    );
    let entry = resolved
        .lock
        .entries
        .get(&ResourceId("ghostty".to_owned()))
        .unwrap();
    assert_eq!(entry.pin(), Some(&pin));
    assert!(
        matches!(entry, LockEntry::Build { .. }),
        "must mint a Build entry, got {entry:?}"
    );
}

#[tokio::test]
async fn execute_plan_materializes_a_tracked_file_from_the_folded_pin() {
    let body = b"zig-binary".to_vec();
    let pin = blake3_hex(&body);
    let url = serve_once(body.clone());

    let home = scratch::tempdir().unwrap();
    let dest_dir = scratch::tempdir().unwrap();
    let dest = dest_dir.path().join("zig");

    let resources = vec![res(serde_json::json!({
        "id": "zig", "type": "file", "path": dest.to_string_lossy(),
        "content": {"type": "remote", "url": url, "extract": {"type": "none"}},
    }))];

    // The lock holds the tracked file's resolved pin; `diff` folds it into `Change.desired`
    // so the plan fact is self-contained — exactly the production path (`apply` resolves the
    // lock, then `diff` folds, then `execute_plan` runs the folded fact lock-free). The pin
    // the file is materialized + verified against rides in the fact, not a side channel.
    let mut lock = ZapLock {
        toolchain: common::toolchain(),
        ..ZapLock::default()
    };
    lock.entries.insert(
        ResourceId("zig".to_owned()),
        LockEntry::RemoteFile {
            config_hash: String::new(),
            blake3: pin,
        },
    );
    let plan = diff(DiffInputs {
        resources: &resources,
        detected: &all_absent(&resources),
        target: &local_target(),
        machine: &local_machine(),
        lock: Some(&lock),
        pending: &BTreeMap::new(),
        var: &zap_types::last_run::ReportVar::unset,
    })
    .plan;

    let outcomes = execute_plan(
        &Connection::Local,
        &plan,
        Some(home.path()),
        &EventHandler::Null,
    )
    .await;
    assert!(
        outcomes.iter().all(|o| !o.is_failure()),
        "tracked fetch+write must succeed: {outcomes:?}"
    );
    assert_eq!(std::fs::read(&dest).unwrap(), body);
}

// --- classify_entry: the shared gate/enforcement predicate (no eval, no network) ---

/// A tracked remote-file resource at `/opt/zig` with the given (literal or
/// reference-bearing) url.
/// An `apt_repo` whose signing key is fetched from `key_url`, its pin tracked unless
/// `key_blake3` is given.
fn apt_repo_resource(key_url: &str, key_blake3: Option<&ContentHash>) -> Resource {
    let mut json = serde_json::json!({
        "id": "pgdg", "type": "apt_repo", "key_url": Text::from_inert(key_url).unwrap(),
        "source": "deb https://apt.example/apt stable main",
    });
    if let Some(pin) = key_blake3 {
        json["key_blake3"] = serde_json::json!(pin);
    }
    res(json)
}

/// A tracked `apt_repo` key is a lock pin like a tracked `remote` file's: a cold start
/// fetches it and mints an `apt_key` entry pinning the key's blake3; a declared
/// `key_blake3` vendors it, with no entry.
#[tokio::test]
async fn resolve_lock_cold_start_mints_an_apt_key_pin() {
    let body = b"-----BEGIN PGP PUBLIC KEY BLOCK-----\npgdg\n".to_vec();
    let pin = blake3_hex(&body);
    let url = serve_once(body);
    let home = scratch::tempdir().unwrap();
    let cfg_dir = scratch::tempdir().unwrap();
    let config_path = cfg_dir.path().join("zap.ts");
    let config = |resource: Resource| ZapConfig {
        resources: vec![resource],
        ..tracked_config(&url, "/opt/unused")
    };

    let resolved = resolve_lock(
        &config(apt_repo_resource(&url, None)),
        &config_path,
        home.path(),
        ColdStart::Mint,
    )
    .await
    .unwrap();
    assert_eq!(resolved.newly_resolved, vec![ResourceId("pgdg".to_owned())]);
    let entry = &resolved.lock.entries[&ResourceId("pgdg".to_owned())];
    assert!(matches!(entry, LockEntry::AptKey { .. }), "{entry:?}");
    assert_eq!(entry.pin(), Some(&pin));

    assert!(!is_lock_eligible(&apt_repo_resource(&url, Some(&pin))));
    let vendored = resolve_lock(
        &config(apt_repo_resource(&url, Some(&pin))),
        &config_path,
        home.path(),
        ColdStart::Mint,
    )
    .await
    .unwrap();
    assert!(vendored.lock.entries.is_empty());
}

/// A key past what detection can read back mints no pin: the fetch stops at the cap and
/// the cold start fails, naming it.
#[tokio::test]
async fn resolve_lock_refuses_an_apt_key_over_the_cap() {
    let max = usize::try_from(zap_types::observe::apt_repo::KEY_READ_MAX).unwrap();
    let url = serve_once(vec![b'k'; max + 1]);
    let home = scratch::tempdir().unwrap();
    let cfg_dir = scratch::tempdir().unwrap();
    let config = ZapConfig {
        resources: vec![apt_repo_resource(&url, None)],
        ..tracked_config(&url, "/opt/unused")
    };
    let error = resolve_lock(
        &config,
        &cfg_dir.path().join("zap.ts"),
        home.path(),
        ColdStart::Mint,
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(error.contains(&format!("{max}-byte cap")), "{error}");
}

/// An `apt_key` entry is addressed by the key url as it resolves: a reference whose
/// value moves the url reads stale, as a `remote` file's does, and one unset can't be
/// verified.
#[test]
fn an_apt_key_entry_moves_with_its_resolved_url() {
    let resource = apt_repo_resource(&format!("{}/key.asc", marker("REPO_BASE")), None);
    let entry = entry_for(
        &resource,
        &no_names(),
        env(&[("REPO_BASE", "https://a.example.com")]),
    );
    assert!(matches!(entry, LockEntry::AptKey { .. }), "{entry:?}");
    let classify = |value: Option<&str>| {
        let pairs: Vec<(&str, &str)> = value.map(|v| ("REPO_BASE", v)).into_iter().collect();
        no_names()
            .classify_entry(&resource, &entry, env(&pairs))
            .unwrap()
    };
    assert_eq!(
        classify(Some("https://a.example.com")),
        EntryStatus::Current
    );
    assert_eq!(classify(Some("https://b.example.com")), EntryStatus::Stale);
    assert!(matches!(classify(None), EntryStatus::Unverifiable { .. }));
}

fn tracked_resource(url: &str) -> Resource {
    res(serde_json::json!({
        "id": "zig", "type": "file", "path": "/opt/zig",
        "content": {"type": "remote", "url": Text::from_inert(url).unwrap(), "extract": {"type": "none"}},
    }))
}

/// The entry the lock mints for `resource` with `pin` (an arbitrary label, hashed into a
/// well-formed pin), through the real address function with nothing set in the env.
fn minted_entry(resource: &Resource, pin: &str) -> LockEntry {
    entry_with_pin(resource, &no_names(), env(&[]), pin)
}

/// A tracked build resource fetching from `url` with build command `run`.
fn tracked_build_resource(url: &str, run: &str) -> Resource {
    res(serde_json::json!({
        "id": "ghostty", "type": "build",
        "source": {"type": "remote", "url": Text::from_inert(url).unwrap(), "extract": {"type": "tar.xz"}},
        "run": Text::from_inert(run).unwrap(),
        "output": "/opt/ghostty/bin/ghostty",
    }))
}

/// [`minted_entry`] for a tracked build.
fn minted_build_entry(resource: &Resource, pin: &str) -> LockEntry {
    minted_entry(resource, pin)
}

#[test]
fn classify_entry_current_when_hash_matches() {
    let resource = tracked_resource("https://forge.example/zig.tar.xz");
    let entry = minted_entry(&resource, "deadbeef");
    assert_eq!(
        no_names()
            .classify_entry(&resource, &entry, |_| Some("set".to_owned()))
            .unwrap(),
        EntryStatus::Current
    );
}

#[test]
fn classify_entry_stale_when_config_changed() {
    // Minted for one url; the config now declares another → the stored config_hash no
    // longer matches the recomputed one.
    let entry = minted_entry(
        &tracked_resource("https://OLD.example/zig.tar.xz"),
        "deadbeef",
    );
    let now = tracked_resource("https://NEW.example/zig.tar.xz");
    assert_eq!(
        no_names()
            .classify_entry(&now, &entry, |_| Some("set".to_owned()))
            .unwrap(),
        EntryStatus::Stale
    );
}

#[test]
fn classify_entry_unverifiable_when_a_url_var_is_unset() {
    // A reference-bearing url whose var is unset can't be hashed faithfully → fail
    // closed (never Current/Stale), naming the unset var.
    let resource = tracked_resource(&format!(
        "{forge_base}/zig.tar.xz",
        forge_base = marker("FORGE_BASE")
    ));
    let entry = minted_entry(&resource, "deadbeef");
    assert_eq!(
        no_names()
            .classify_entry(&resource, &entry, |_| None)
            .unwrap(),
        EntryStatus::Unverifiable {
            unresolved: vec!["FORGE_BASE".to_owned()],
        }
    );
}

#[test]
fn classify_entry_unverifiable_when_a_url_var_is_empty() {
    // An exported-but-blank var is just as unresolvable as an unset one — folding
    // `""` into the hash would read as a confident Current/Stale (fail open). Same
    // predicate as `unresolved_env_vars` / `unverifiable_env_vars`.
    let resource = tracked_resource(&format!(
        "{forge_base}/zig.tar.xz",
        forge_base = marker("FORGE_BASE")
    ));
    let entry = minted_entry(&resource, "deadbeef");
    assert_eq!(
        no_names()
            .classify_entry(&resource, &entry, |_| Some(String::new()))
            .unwrap(),
        EntryStatus::Unverifiable {
            unresolved: vec!["FORGE_BASE".to_owned()],
        }
    );
}

#[test]
fn classify_entry_verifies_a_url_var_that_is_set() {
    // The same var, now present → the unverifiable guard clears and the hash compares
    // against the injected env: current under the value the entry was minted with, stale
    // under any other (a non-secret value is part of the address).
    let resource = tracked_resource(&format!(
        "{forge_base}/zig.tar.xz",
        forge_base = marker("FORGE_BASE")
    ));
    let minted_with = env(&[("FORGE_BASE", "https://forge.example")]);
    let entry = entry_for(&resource, &no_names(), &minted_with);
    assert_eq!(
        no_names()
            .classify_entry(&resource, &entry, &minted_with)
            .unwrap(),
        EntryStatus::Current
    );
    assert_eq!(
        no_names()
            .classify_entry(
                &resource,
                &entry,
                env(&[("FORGE_BASE", "https://other.example")])
            )
            .unwrap(),
        EntryStatus::Stale
    );
}

// --- the entry address never depends on a secret's value ---

/// The addressing of a config with no `mask` / `unmask` lists.
fn no_names() -> LockAddressing {
    names(&[], &[])
}

/// The addressing of a config declaring these `mask` / `unmask` lists.
fn names(mask: &[&str], unmask: &[&str]) -> LockAddressing {
    let config: ZapConfig = serde_json::from_value(serde_json::json!({
        "target": {"local": true}, "resources": [],
        "mask_vars": mask, "unmask_vars": unmask,
    }))
    .unwrap();
    LockAddressing::of(&config)
}

/// An env reader over fixed pairs; any other name is unset.
fn env(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> + use<> {
    let pairs: BTreeMap<String, String> = pairs
        .iter()
        .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
        .collect();
    move |name| pairs.get(name).cloned()
}

/// The entry the lock mints for `resource` under `addressing` and `env_get`, with a
/// fixed pin.
fn entry_for(
    resource: &Resource,
    addressing: &LockAddressing,
    env_get: impl Fn(&str) -> Option<String>,
) -> LockEntry {
    entry_with_pin(resource, addressing, env_get, "pinned-bytes")
}

/// [`entry_for`] with the pin's label given: the entry of `resource`'s own kind,
/// addressed by the real address function (the fixed point — the entry folded as its
/// own pin).
fn entry_with_pin(
    resource: &Resource,
    addressing: &LockAddressing,
    env_get: impl Fn(&str) -> Option<String>,
    pin: &str,
) -> LockEntry {
    let blake3 = ContentHash::of_bytes(pin.as_bytes());
    let entry = |config_hash: String| match resource.kind {
        zap_types::schema::ResourceKind::Build(_) => LockEntry::Build {
            config_hash,
            blake3: blake3.clone(),
        },
        zap_types::schema::ResourceKind::AptRepo(_) => LockEntry::AptKey {
            config_hash,
            blake3: blake3.clone(),
        },
        _ => LockEntry::RemoteFile {
            config_hash,
            blake3: blake3.clone(),
        },
    };
    let config_hash = addressing
        .entry_config_hash(resource, &entry(String::new()), env_get)
        .unwrap();
    entry(config_hash)
}

/// `entry_for`'s address alone.
fn address(
    resource: &Resource,
    addressing: &LockAddressing,
    env_get: impl Fn(&str) -> Option<String>,
) -> String {
    entry_for(resource, addressing, env_get)
        .config_hash()
        .to_owned()
}

/// A url variable whose value holds a password is a secret by that value's form: the
/// address takes its token, so a rotated password doesn't move it, while losing the
/// form (or gaining it) does. Unset, the variable has no form to read and the entry is
/// unverifiable, as for any reference the address takes by value. The lock commands
/// note it with what makes it read as a secret, and `unmask` addresses it by value.
#[test]
fn a_url_var_holding_a_password_is_addressed_by_its_token() {
    let resource = tracked_resource(&marker("ARTIFACT_URL"));
    let with = |url: &str| env(&[("ARTIFACT_URL", url)]);
    let one = "https://ci:hunter2@files.example.com/zig";
    let rotated = "https://ci:rotated@files.example.com/zig";
    let plain = "https://files.example.com/zig";
    let addressing = no_names();
    let entry = entry_for(&resource, &addressing, with(one));
    assert_eq!(
        addressing
            .classify_entry(&resource, &entry, with(rotated))
            .unwrap(),
        EntryStatus::Current
    );
    assert_eq!(
        addressing
            .classify_entry(&resource, &entry, with(plain))
            .unwrap(),
        EntryStatus::Stale
    );
    assert_eq!(
        addressing
            .classify_entry(
                &resource,
                &entry_for(&resource, &addressing, with(plain)),
                with(one)
            )
            .unwrap(),
        EntryStatus::Stale
    );
    assert_eq!(
        addressing
            .classify_entry(&resource, &entry, env(&[]))
            .unwrap(),
        EntryStatus::Unverifiable {
            unresolved: vec!["ARTIFACT_URL".to_owned()]
        }
    );
    assert_eq!(
        addressing.name_only_refs(&resource, with(one)),
        [NameOnlyRef {
            name: "ARTIFACT_URL".to_owned(),
            reason: SecretReason::Value(ValueShape::UrlPassword),
        }]
    );
    assert!(addressing.name_only_refs(&resource, with(plain)).is_empty());
    assert!(addressing.name_only_refs(&resource, env(&[])).is_empty());

    let unmasked = names(&[], &["ARTIFACT_URL"]);
    assert!(unmasked.name_only_refs(&resource, with(one)).is_empty());
    assert_eq!(
        unmasked
            .classify_entry(
                &resource,
                &entry_for(&resource, &unmasked, with(one)),
                with(rotated)
            )
            .unwrap(),
        EntryStatus::Stale
    );
}

/// A variable the config uses as a fetch credential is a secret wherever else it
/// stands: in the url too, the address takes its token, set or not, under any name.
#[test]
fn a_fetch_credential_is_addressed_by_its_token_wherever_it_stands() {
    let config: ZapConfig = serde_json::from_value(serde_json::json!({
        "target": {"local": true},
        "resources": [{
            "id": "zig", "type": "file", "path": "/opt/zig",
            "content": {"type": "remote", "extract": {"type": "none"},
                        "url": Text::of_pieces([
                            Lit("https://files.example.com/zig?pat="), Ref("GH_PAT"),
                        ]),
                        "auth": {"scheme": "bearer", "token": Text::reference("GH_PAT")}},
        }],
    }))
    .unwrap();
    let addressing = LockAddressing::of(&config);
    let resource = &config.resources[0];
    let entry = entry_for(resource, &addressing, env(&[("GH_PAT", "one")]));
    for now in [env(&[("GH_PAT", "two")]), env(&[])] {
        assert_eq!(
            addressing.classify_entry(resource, &entry, now).unwrap(),
            EntryStatus::Current
        );
    }
    // The config's own statement, so no note asks for an `unmask`.
    assert!(
        addressing
            .name_only_refs(resource, env(&[("GH_PAT", "one")]))
            .is_empty()
    );
}

#[test]
fn a_secret_named_url_var_never_reaches_the_entry_address() {
    // `zap.lock` is committed: an address that moved with the token would let anyone
    // holding the lock test guesses at it offline.
    let resource = tracked_resource(&format!(
        "https://files.example.com/zig?token={secret_token}",
        secret_token = marker("SECRET_TOKEN")
    ));
    let one = address(&resource, &no_names(), env(&[("SECRET_TOKEN", "hunter2")]));
    let other = address(&resource, &no_names(), env(&[("SECRET_TOKEN", "correct")]));
    let unset = address(&resource, &no_names(), env(&[]));
    assert_eq!(one, other, "two values of a secret, one address");
    assert_eq!(one, unset, "and the same address with it unset");

    // The reference itself is still addressed: another secret's name is another address.
    let renamed = tracked_resource(&format!(
        "https://files.example.com/zig?token={other_token}",
        other_token = marker("OTHER_TOKEN")
    ));
    assert_ne!(one, address(&renamed, &no_names(), env(&[])));
}

#[test]
fn a_non_secret_url_var_still_moves_the_entry_address() {
    // The ordinary staleness signal: a changed non-secret value is a changed location.
    let resource = tracked_resource(&format!(
        "{files_base}/zig.tar.xz",
        files_base = marker("FILES_BASE")
    ));
    let one = address(
        &resource,
        &no_names(),
        env(&[("FILES_BASE", "https://a.example.com")]),
    );
    let other = address(
        &resource,
        &no_names(),
        env(&[("FILES_BASE", "https://b.example.com")]),
    );
    assert_ne!(one, other);
}

#[test]
fn the_configs_mask_and_unmask_lists_decide_what_the_address_masks() {
    let a = env(&[("SIGNED_QUERY", "aaa"), ("PUBLIC_KEY_ID", "aaa")]);
    let b = env(&[("SIGNED_QUERY", "bbb"), ("PUBLIC_KEY_ID", "bbb")]);

    // `SIGNED_QUERY` doesn't look like a secret: its value is addressed until `mask`
    // names it.
    let masked = tracked_resource(&format!(
        "https://files.example.com/zig?{signed_query}",
        signed_query = marker("SIGNED_QUERY")
    ));
    assert_ne!(
        address(&masked, &no_names(), &a),
        address(&masked, &no_names(), &b)
    );
    let rule = names(&["SIGNED_QUERY"], &[]);
    assert_eq!(address(&masked, &rule, &a), address(&masked, &rule, &b));

    // `PUBLIC_KEY_ID` looks like one (`KEY`): masked until `unmask` exempts it.
    let unmasked = tracked_resource(&format!(
        "https://files.example.com/{public_key_id}/zig",
        public_key_id = marker("PUBLIC_KEY_ID")
    ));
    assert_eq!(
        address(&unmasked, &no_names(), &a),
        address(&unmasked, &no_names(), &b)
    );
    let rule = names(&[], &["PUBLIC_KEY_ID"]);
    assert_ne!(address(&unmasked, &rule, &a), address(&unmasked, &rule, &b));
}

#[test]
fn the_verifier_masks_by_the_configs_own_lists() {
    // Minting and verifying must read one rule: an entry minted under the config's
    // `mask` list verifies under another value of the masked variable, through the
    // per-entry predicate and the whole-config one.
    let config: ZapConfig = serde_json::from_value(serde_json::json!({
        "target": {"local": true},
        "mask_vars": ["SIGNED_QUERY"],
        "resources": [{
            "id": "zig", "type": "file", "path": "/opt/zig",
            "content": {"type": "remote", "extract": {"type": "none"},
                        "url": Text::of_pieces([
                            Lit("https://files.example.com/zig?"),
                            Ref("SIGNED_QUERY"),
                        ])},
        }],
    }))
    .unwrap();
    let resource = &config.resources[0];
    let secrets = LockAddressing::of(&config);
    let entry = entry_for(resource, &secrets, env(&[("SIGNED_QUERY", "aaa")]));
    let other = env(&[("SIGNED_QUERY", "bbb")]);
    assert_eq!(
        secrets.classify_entry(resource, &entry, &other).unwrap(),
        EntryStatus::Current
    );
    let mut lock = ZapLock {
        toolchain: common::toolchain(),
        ..ZapLock::default()
    };
    lock.entries.insert(resource.id.clone(), entry);
    assert_eq!(
        classify_lock(&config, &lock, &other).unwrap(),
        LockStanding::default(),
    );
}

/// A plain variable whose value holds a secret the config registers elsewhere — a
/// signed url carrying another variable's token — is folded with that secret as its
/// token: the committed address doesn't move with the secret, so it can't confirm a
/// guess at it, while the rest of the plain value still moves it.
#[test]
fn a_secret_inside_a_plain_value_is_addressed_as_its_token() {
    let config: ZapConfig = serde_json::from_value(serde_json::json!({
        "target": {"local": true},
        "resources": [
            {"id": "zig", "type": "file", "path": "/opt/zig",
             "content": {"type": "remote", "extract": {"type": "none"},
                         "url": Text::of_pieces([Ref("DOWNLOAD_URL")])}},
            {"id": "signed", "type": "file", "path": "/opt/signed",
             "content": {"type": "remote", "extract": {"type": "none"},
                         "url": Text::of_pieces([Lit("https://h/s?"), Ref("SIGNING_SECRET")])}},
        ],
    }))
    .unwrap();
    let resource = &config.resources[0];
    let addressing = LockAddressing::of(&config);
    let with = |secret: &str, url: &str| {
        address(
            resource,
            &addressing,
            env(&[("SIGNING_SECRET", secret), ("DOWNLOAD_URL", url)]),
        )
    };
    let a = with("s3cr3t-aaaa", "https://h/zig?sig=s3cr3t-aaaa");
    let b = with("s3cr3t-bbbb", "https://h/zig?sig=s3cr3t-bbbb");
    assert_eq!(a, b, "the secret inside the plain url stands as its token");
    assert_ne!(
        a,
        with("s3cr3t-aaaa", "https://h/other?sig=s3cr3t-aaaa"),
        "the plain part still moves the address"
    );
}

/// A secret shorter than the address floor is no part of how a plain value is
/// folded: a 3-character secret that spells part of a download url leaves the url's
/// address as it would be with any other secret.
#[test]
fn a_short_secret_does_not_move_a_plain_address() {
    let config: ZapConfig = serde_json::from_value(serde_json::json!({
        "target": {"local": true},
        "resources": [
            {"id": "zig", "type": "file", "path": "/opt/zig",
             "content": {"type": "remote", "extract": {"type": "none"},
                         "url": Text::of_pieces([Ref("DOWNLOAD_URL")])}},
            {"id": "signed", "type": "file", "path": "/opt/signed",
             "content": {"type": "remote", "extract": {"type": "none"},
                         "url": Text::of_pieces([Lit("https://h/s?"), Ref("SIGNING_SECRET")])}},
        ],
    }))
    .unwrap();
    let addressing = LockAddressing::of(&config);
    let with = |secret: &str| {
        address(
            &config.resources[0],
            &addressing,
            env(&[
                ("SIGNING_SECRET", secret),
                ("DOWNLOAD_URL", "https://ziglang.org/zig.tar.xz"),
            ]),
        )
    };
    assert_eq!(with("zig"), with("org"));
    assert_eq!(with("zig"), with("an-unrelated-long-secret"));
}

/// The address floor is 8 characters, counted on each form a secret is masked in: a
/// secret of exactly 8 inside a plain value is masked, one of 7 is not, nor one that is
/// 7 once trimmed, nor one whose decoded form is shorter (`abcd\n\n` spelled out,
/// whose line breaks decode to `abcd`).
#[test]
fn the_address_floor_counts_each_form_of_a_secret() {
    let config: ZapConfig = serde_json::from_value(serde_json::json!({
        "target": {"local": true},
        "resources": [
            {"id": "dl", "type": "file", "path": "/opt/dl",
             "content": {"type": "remote", "extract": {"type": "none"},
                         "url": Text::of_pieces([Ref("DOWNLOAD_URL")])}},
            {"id": "signed", "type": "file", "path": "/opt/signed",
             "content": {"type": "remote", "extract": {"type": "none"},
                         "url": Text::of_pieces([Lit("https://h/s?"), Ref("SIGNING_SECRET")])}},
        ],
    }))
    .unwrap();
    let addressing = LockAddressing::of(&config);
    let with = |secret: &str| {
        address(
            &config.resources[0],
            &addressing,
            env(&[
                ("SIGNING_SECRET", secret),
                ("DOWNLOAD_URL", "https://h/abcdefgh/abcd/x"),
            ]),
        )
    };
    let unrelated = with("an-unrelated-long-secret");
    assert_ne!(with("abcdefgh"), unrelated, "8 characters: masked");
    assert_eq!(with("bcdefgh"), unrelated, "7 characters: not masked");
    assert_eq!(with(" bcdefgh "), unrelated, "7 once trimmed: not masked");
    assert_eq!(with(r"abcd\n\n"), unrelated, "4 once decoded: not masked");
}

/// An entry whose address takes a plain value isn't minted while a secret the config
/// references is unset: the value could hold the secret, which can't be masked
/// unknown. The variable is named. Checked then, an entry whose address still matches
/// reads current — its plain value holds no secret — as does one with no plain value.
#[tokio::test]
async fn an_unset_secret_holds_an_entry_with_a_plain_value() {
    const SECRET: &str = "ZAP_TEST_NEVER_SET_SIGNING_SECRET";
    let plain_url = |base: &str| Text::of_pieces([Lit(base), Lit("?h="), Ref("HOME")]);
    let config = |base: &str| -> ZapConfig {
        serde_json::from_value(serde_json::json!({
            "target": {"local": true},
            "resources": [
                {"id": "plain", "type": "file", "path": "/opt/plain",
                 "content": {"type": "remote", "extract": {"type": "none"},
                             "url": plain_url(base)}},
                {"id": "literal", "type": "file", "path": "/opt/literal",
                 "content": {"type": "remote", "extract": {"type": "none"},
                             "url": "https://h/literal"}},
                {"id": "signed", "type": "file", "path": "/opt/signed",
                 "content": {"type": "remote", "extract": {"type": "none"},
                             "url": Text::of_pieces([Lit("https://h/s?"), Ref(SECRET)])}},
            ],
        }))
        .unwrap()
    };
    let config_now = config("https://h/plain");
    let addressing = LockAddressing::of(&config_now);
    let set = env(&[("HOME", "/home/x"), (SECRET, "a-long-signing-secret")]);
    let unset = env(&[("HOME", "/home/x")]);
    for resource in &config_now.resources[..2] {
        let entry = entry_for(resource, &addressing, &set);
        assert_eq!(
            addressing.classify_entry(resource, &entry, &unset).unwrap(),
            EntryStatus::Current,
            "{}",
            resource.id.0
        );
    }

    // The mint refuses it too, before any fetch, naming the variable; a preview counts
    // it unmintable.
    let served = config("http://127.0.0.1:1/plain");
    let home = scratch::tempdir().unwrap();
    let cfg_dir = scratch::tempdir().unwrap();
    let config_path = cfg_dir.path().join("zap.ts");
    let only_plain = ZapConfig {
        resources: vec![served.resources[0].clone()],
        ..served.clone()
    };
    let error = LockAddressing::of(&served)
        .resolve_entry(&only_plain.resources[0], home.path())
        .await
        .unwrap_err();
    assert!(
        matches!(&error, zap_core::error::Error::LockUnverifiable { vars, .. } if vars == SECRET),
        "{error}"
    );
    let preview = resolve_lock(
        &ZapConfig {
            resources: vec![served.resources[0].clone(), served.resources[2].clone()],
            ..served
        },
        &config_path,
        home.path(),
        ColdStart::Preview,
    )
    .await
    .unwrap();
    assert!(
        preview
            .unmintable
            .iter()
            .any(|unmintable| unmintable.id.0 == "plain" && unmintable.vars == SECRET),
        "{:?}",
        preview.unmintable
    );
}

#[test]
fn a_secret_bearing_entry_address_is_byte_stable() {
    // The masked form is part of every committed address that names a secret: a change
    // to the token's spelling moves them all, so it is pinned like the layout is.
    let resource = tracked_resource(&format!(
        "https://files.example.com/zig?token={}",
        marker("SECRET_TOKEN")
    ));
    assert_eq!(
        address(&resource, &no_names(), env(&[])),
        "59a552fb4246b2959e37468a4935bed009bd9106c6663a1ee83511d0a7a00036",
    );
}

#[tokio::test]
async fn the_mint_path_masks_by_the_configs_own_lists() {
    // The real mint (`resolve_lock`: fetch, then address) against the verifier, for
    // both entry kinds. `PATH` is set in every test process, so naming it in `mask`
    // gives the mint a set, masked variable without touching the environment: the
    // minted address must not hold its value, so the entry verifies under any other.
    for build in [false, true] {
        let url = format!("{}?p={}", serve_once(b"bytes".to_vec()), marker("PATH"));
        let home = scratch::tempdir().unwrap();
        let cfg_dir = scratch::tempdir().unwrap();
        let config_path = cfg_dir.path().join("zap.ts");
        let mut config = if build {
            tracked_build_config(&url)
        } else {
            tracked_config(&url, "/opt/zig")
        };
        config.mask_vars = Some(vec![zap_types::scalar::EnvVarName::new("PATH").unwrap()]);
        let resolved = resolve_lock(&config, &config_path, home.path(), ColdStart::Mint)
            .await
            .unwrap();
        assert_eq!(resolved.newly_resolved.len(), 1, "build: {build}");
        assert_eq!(
            classify_lock(&config, &resolved.lock, env(&[("PATH", "/elsewhere")])).unwrap(),
            LockStanding::default(),
            "build: {build}"
        );
    }
}

#[tokio::test]
async fn the_mint_path_addresses_a_non_secret_value_from_the_operator_env() {
    // `PATH` again, unmasked this time: the mint folds the value the fetch resolved, so
    // the entry is current under the process env and stale under any other.
    let url = format!("{}?p={}", serve_once(b"bytes".to_vec()), marker("PATH"));
    let home = scratch::tempdir().unwrap();
    let cfg_dir = scratch::tempdir().unwrap();
    let config = tracked_config(&url, "/opt/zig");
    let resolved = resolve_lock(
        &config,
        &cfg_dir.path().join("zap.ts"),
        home.path(),
        ColdStart::Mint,
    )
    .await
    .unwrap();
    assert_eq!(
        classify_lock(&config, &resolved.lock, zap_core::resolve::env_var).unwrap(),
        LockStanding::default()
    );
    assert_eq!(
        classify_lock(&config, &resolved.lock, env(&[("PATH", "/elsewhere")]))
            .unwrap()
            .stale,
        vec!["zig".to_owned()]
    );
}

#[test]
fn a_builds_secret_references_never_reach_the_entry_address() {
    // Every place a build can name a secret: the source url and the output path resolve
    // (masked), `run` and `env` values are addressed as written.
    let resource = res(serde_json::json!({
        "id": "ghostty", "type": "build",
        "source": {"type": "remote", "extract": {"type": "tar.xz"},
                   "url": Text::of_pieces([
                       Lit("https://files.example.com/src.tar.xz?token="),
                       Ref("SOURCE_TOKEN"),
                   ])},
        "run": Text::of_pieces([Lit("make install TOKEN="), Ref("BUILD_TOKEN")]),
        "cwd": "src",
        "env": {"UPSTREAM": Text::reference("ENV_PASSWORD")},
        "output": Text::of_pieces([Lit("/opt/"), Ref("OUTPUT_KEY"), Lit("/bin/ghostty")]),
    }));
    let secret_names = ["SOURCE_TOKEN", "BUILD_TOKEN", "ENV_PASSWORD", "OUTPUT_KEY"];
    let unset = address(&resource, &no_names(), env(&[]));
    for name in secret_names {
        for value in ["hunter2", "correct"] {
            assert_eq!(
                address(&resource, &no_names(), env(&[(name, value)])),
                unset,
                "{name}={value} moved the address"
            );
        }
    }
    // …and the entry verifies with none of them set.
    let entry = entry_for(&resource, &no_names(), env(&[]));
    assert_eq!(
        no_names()
            .classify_entry(&resource, &entry, env(&[]))
            .unwrap(),
        EntryStatus::Current
    );
}

/// Minted where the token was set, checked where it isn't (CI, a reviewer's machine).
/// An address that still matches reads current: the bytes folded are the ones minted,
/// whatever its plain parts hold. One that changed because a plain value holds the
/// secret — masked when minted, unmasked now — reads unverifiable, naming the secret,
/// not stale.
#[test]
fn an_unset_secret_reads_unverifiable_only_where_the_address_changed() {
    let config: ZapConfig = serde_json::from_value(serde_json::json!({
        "target": {"local": true},
        "resources": [
            {"id": "zig", "type": "file", "path": "/opt/zig",
             "content": {"type": "remote", "extract": {"type": "none"},
                         "url": Text::of_pieces([
                             Ref("FILES_BASE"),
                             Lit("/zig?token="),
                             Ref("SECRET_TOKEN"),
                         ])}},
            {"id": "go", "type": "file", "path": "/opt/go",
             "content": {"type": "remote", "extract": {"type": "none"},
                         "url": Text::of_pieces([
                             Lit("https://files.example.com/go?token="),
                             Ref("SECRET_TOKEN"),
                         ])}},
            {"id": "dl", "type": "file", "path": "/opt/dl",
             "content": {"type": "remote", "extract": {"type": "none"},
                         "url": Text::of_pieces([Ref("DOWNLOAD_URL")])}},
        ],
    }))
    .unwrap();
    let secrets = LockAddressing::of(&config);
    let (base, download) = (
        ("FILES_BASE", "https://files.example.com"),
        (
            "DOWNLOAD_URL",
            "https://files.example.com/dl?sig=hunter2-long",
        ),
    );
    let minted = env(&[base, download, ("SECRET_TOKEN", "hunter2-long")]);
    let mut lock = ZapLock {
        toolchain: common::toolchain(),
        ..ZapLock::default()
    };
    for resource in &config.resources {
        lock.entries
            .insert(resource.id.clone(), entry_for(resource, &secrets, &minted));
    }

    let standing = classify_lock(&config, &lock, env(&[base, download])).unwrap();
    assert_eq!(
        standing,
        LockStanding {
            unverifiable: vec![UnverifiableEntry {
                id: "dl".to_owned(),
                vars: vec!["SECRET_TOKEN".to_owned()],
            }],
            ..LockStanding::default()
        },
        "`zig` and `go` are current"
    );
    // With the secret set again, all three are current.
    assert_eq!(
        classify_lock(&config, &lock, &minted).unwrap(),
        LockStanding::default()
    );
    // A non-secret reference fails closed when unset, naming only itself.
    assert_eq!(
        classify_lock(&config, &lock, env(&[]))
            .unwrap()
            .unverifiable,
        vec![
            UnverifiableEntry {
                id: "zig".to_owned(),
                vars: vec!["FILES_BASE".to_owned()],
            },
            UnverifiableEntry {
                id: "dl".to_owned(),
                vars: vec!["DOWNLOAD_URL".to_owned()],
            },
        ]
    );
}

#[test]
fn classify_build_entry_current_when_hash_matches() {
    // The kind-agnostic predicate folds a `Build` entry's pin too — minted for this
    // exact resource, so it classifies Current.
    let resource = tracked_build_resource("https://forge.example/ghostty.tar.xz", "zig build");
    let entry = minted_build_entry(&resource, "deadbeef");
    assert_eq!(
        no_names()
            .classify_entry(&resource, &entry, |_| Some("set".to_owned()))
            .unwrap(),
        EntryStatus::Current
    );
}

#[test]
fn classify_build_entry_stale_when_run_changes() {
    // `run` is a build hash-relevant field (desired state). Editing it leaves the pin
    // valid but invalidates config_hash → Stale (run `zap update`).
    let entry = minted_build_entry(
        &tracked_build_resource("https://forge.example/ghostty.tar.xz", "zig build"),
        "deadbeef",
    );
    let now = tracked_build_resource(
        "https://forge.example/ghostty.tar.xz",
        "zig build -Doptimize=ReleaseFast",
    );
    assert_eq!(
        no_names()
            .classify_entry(&now, &entry, |_| Some("set".to_owned()))
            .unwrap(),
        EntryStatus::Stale
    );
}

#[test]
fn classify_build_entry_unverifiable_when_a_url_var_is_unset() {
    // A reference-bearing source url with the var unset can't be hashed faithfully →
    // fail closed, naming the var (proves unresolved_hash_vars scans the build source).
    let resource = tracked_build_resource(
        &format!("{}/ghostty.tar.xz", marker("FORGE_BASE")),
        "zig build",
    );
    let entry = minted_build_entry(&resource, "deadbeef");
    assert_eq!(
        no_names()
            .classify_entry(&resource, &entry, |_| None)
            .unwrap(),
        EntryStatus::Unverifiable {
            unresolved: vec!["FORGE_BASE".to_owned()],
        }
    );
}

// --- inspect_lock: the read-only commands' withhold rule (no eval, no network) ---

/// A stale pin is **withheld**, so the resource it belongs to behaves exactly like one
/// whose pin was never minted: detection holds, the planner holds it out of the
/// changeset, and the caller's existing verdict plumbing turns that into a nonzero exit.
///
/// This is the whole mechanism behind decision 1, and it is the chain `deploy`'s wetrun
/// preflight walks (`detect_and_diff`) before mapping a non-empty `held` to
/// `PreflightUndetermined` — that last mapping is covered by the deploy unit test, since
/// reaching it for real needs git + SSH, which this hermetic suite never does.
#[tokio::test]
async fn a_stale_pin_is_withheld_so_its_resource_holds() {
    let cfg_dir = scratch::tempdir().unwrap();
    let config_path = cfg_dir.path().join("zap.ts");
    // A literal url (verifiable anywhere) that is never dialed — nothing here fetches.
    let config = tracked_config("http://127.0.0.1:1/zig", "/opt/zig");

    let mut lock = ZapLock {
        toolchain: common::toolchain(),
        ..ZapLock::default()
    };
    lock.entries.insert(
        ResourceId("zig".to_owned()),
        LockEntry::RemoteFile {
            config_hash: "deliberately-wrong".to_owned(),
            blake3: blake3_hex(b"x"),
        },
    );
    write_zap_lock(&lock_path_for(&config_path), &lock).unwrap();

    let (retained, standing) = inspect_lock(&config, &config_path, |_| Some("set".to_owned()))
        .expect("inspect_lock reads and classifies");
    assert_eq!(standing.stale, vec!["zig".to_owned()]);
    assert!(standing.has_errors());
    assert!(
        retained.as_ref().is_some_and(|l| l.entries.is_empty()),
        "a stale pin must not reach detection: {retained:?}"
    );

    // Detection can't compare against a pin it wasn't given → Undetermined → held.
    let detections = detect_all(
        &Connection::Local,
        &config.target,
        &config.resources,
        None,
        retained.as_ref(),
        Markers::Skip,
    )
    .await
    .unwrap()
    .detections;
    let detected: BTreeMap<_, _> = config
        .resources
        .iter()
        .map(|r| r.id.clone())
        .zip(detections)
        .collect();
    let result = diff(DiffInputs {
        resources: &config.resources,
        detected: &detected,
        target: &config.target,
        machine: &local_machine(),
        lock: retained.as_ref(),
        pending: &BTreeMap::new(),
        var: &zap_types::last_run::ReportVar::unset,
    });
    assert!(
        result.plan.changes.is_empty(),
        "a held resource contributes no change: {:?}",
        result.plan.changes
    );
    assert_eq!(result.held.len(), 1, "{:?}", result.held);
    assert!(
        result.held[0].describe().contains("zap update zig"),
        "the hold must name the fix: {}",
        result.held[0].describe()
    );
}

/// A current pin is kept — withholding is scoped to the entries that don't answer, not
/// a blanket distrust of the ledger.
#[test]
fn a_current_pin_survives_inspection() {
    let cfg_dir = scratch::tempdir().unwrap();
    let config_path = cfg_dir.path().join("zap.ts");
    let config = tracked_config("http://127.0.0.1:1/zig", "/opt/zig");
    let entry = minted_entry(&config.resources[0], "deadbeef");
    let mut lock = ZapLock {
        toolchain: common::toolchain(),
        ..ZapLock::default()
    };
    lock.entries.insert(ResourceId("zig".to_owned()), entry);
    write_zap_lock(&lock_path_for(&config_path), &lock).unwrap();

    let (retained, standing) = inspect_lock(&config, &config_path, |_| Some("set".to_owned()))
        .expect("inspect_lock reads and classifies");
    assert!(!standing.has_errors(), "{standing:?}");
    assert_eq!(retained.expect("a lock exists").entries.len(), 1);
}

/// A cold start (no lock file at all) is a *standing*, not an absence of one: every
/// eligible resource reads `missing`, so the read-only commands report it and exit 1
/// rather than silently comparing against nothing.
#[test]
fn a_cold_start_classifies_every_eligible_resource_missing() {
    let cfg_dir = scratch::tempdir().unwrap();
    let config_path = cfg_dir.path().join("zap.ts"); // no adjacent zap.lock
    let config = tracked_config("http://127.0.0.1:1/zig", "/opt/zig");

    let (retained, standing) = inspect_lock(&config, &config_path, |_| Some("set".to_owned()))
        .expect("a missing lock is not an error");
    assert!(retained.is_none());
    assert_eq!(standing.missing, vec!["zig".to_owned()]);
    assert_eq!(standing.exit_code(), 1);
}

/// An unverifiable pin is withheld as a stale one is: its address names a reference
/// unset here, so nothing compares against it, and the standing alone is an error.
#[test]
fn an_unverifiable_pin_is_withheld() {
    let cfg_dir = scratch::tempdir().unwrap();
    let config_path = cfg_dir.path().join("zap.ts");
    let url = format!("{}/zig", marker("ZAP_T_FORGE_BASE"));
    let config = tracked_config(&url, "/opt/zig");
    let set = env(&[("ZAP_T_FORGE_BASE", "https://forge.example")]);
    let entry = entry_with_pin(&config.resources[0], &no_names(), &set, "deadbeef");
    let mut lock = ZapLock {
        toolchain: common::toolchain(),
        ..ZapLock::default()
    };
    lock.entries.insert(ResourceId("zig".to_owned()), entry);
    write_zap_lock(&lock_path_for(&config_path), &lock).unwrap();

    // Where the reference is set the pin is current and kept…
    let (retained, standing) = inspect_lock(&config, &config_path, &set).unwrap();
    assert_eq!(standing, LockStanding::default());
    assert_eq!(retained.unwrap().entries.len(), 1);

    // …and where it is unset the pin is withheld, the only error in the standing.
    let (retained, standing) = inspect_lock(&config, &config_path, |_| None).unwrap();
    assert_eq!(
        standing,
        LockStanding {
            unverifiable: vec![UnverifiableEntry {
                id: "zig".to_owned(),
                vars: vec!["ZAP_T_FORGE_BASE".to_owned()],
            }],
            ..LockStanding::default()
        }
    );
    assert!(standing.has_errors());
    assert_eq!(standing.error_count(), 1);
    assert_eq!(standing.exit_code(), 1);
    assert!(
        retained.as_ref().is_some_and(|l| l.entries.is_empty()),
        "an unverifiable pin must not reach detection: {retained:?}"
    );
}

/// Each of missing, stale, and unverifiable is an error on its own; orphans alone are
/// not.
#[test]
fn each_unanswered_standing_is_an_error_and_an_orphan_is_not() {
    let one = || vec!["x".to_owned()];
    let unverifiable = || {
        vec![UnverifiableEntry {
            id: "x".to_owned(),
            vars: vec!["V".to_owned()],
        }]
    };
    for standing in [
        LockStanding {
            missing: one(),
            ..LockStanding::default()
        },
        LockStanding {
            stale: one(),
            ..LockStanding::default()
        },
        LockStanding {
            unverifiable: unverifiable(),
            ..LockStanding::default()
        },
    ] {
        assert!(standing.has_errors(), "{standing:?}");
        assert_eq!(
            (standing.error_count(), standing.exit_code()),
            (1, 1),
            "{standing:?}"
        );
    }
    let all = LockStanding {
        missing: one(),
        stale: one(),
        unverifiable: unverifiable(),
        orphans: one(),
    };
    assert_eq!((all.error_count(), all.exit_code()), (3, 1));
    let orphaned = LockStanding {
        orphans: one(),
        ..LockStanding::default()
    };
    assert!(!orphaned.has_errors());
    assert_eq!((orphaned.error_count(), orphaned.exit_code()), (0, 0));
}

/// A tracked build's declared signature is checked before its pin is minted: a source
/// whose check doesn't pass mints no entry. It fails closed either way — no `minisign`
/// to run, or one that rejects what was served — so this holds without the tool
/// installed, and says nothing of which of the two refused.
#[tokio::test]
async fn a_build_whose_signature_does_not_verify_mints_no_pin() {
    let url = serve_once(b"ghostty-source-archive".to_vec());
    let home = scratch::tempdir().unwrap();
    let cfg_dir = scratch::tempdir().unwrap();
    let config_path = cfg_dir.path().join("zap.ts");
    let mut config = serde_json::to_value(tracked_build_config(&url)).unwrap();
    // The signature is served by a second one-shot server, as bytes that are none.
    config["resources"][0]["source"]["verify"] = serde_json::json!({
        "scheme": "minisign",
        "public_key": "RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3",
        "signature_url": Text::from_inert(serve_once(b"not a signature".to_vec())).unwrap(),
    });
    let config: ZapConfig = serde_json::from_value(config).unwrap();

    let error = resolve_lock(&config, &config_path, home.path(), ColdStart::Mint)
        .await
        .unwrap_err();
    assert!(
        matches!(error, zap_core::error::Error::SignatureVerification { .. }),
        "{error:?}"
    );
}

/// `zap.lock`'s `version` is stamped on every write, never echoed back from the parsed
/// file — otherwise the first `LOCK_VERSION` bump would strand old files at their old
/// version, with nothing that ever rewrites them.
#[test]
fn a_write_stamps_the_current_lock_version() {
    let dir = scratch::tempdir().unwrap();
    let path = dir.path().join("zap.lock");
    let stale_version = ZapLock {
        version: 0,
        toolchain: None,
        entries: BTreeMap::new(),
    };
    write_zap_lock(&path, &stale_version).unwrap();
    assert_eq!(
        read_zap_lock(&path).unwrap().expect("written").version,
        LOCK_VERSION
    );
}

#[test]
fn render_lock_check_reports_stale_and_unverifiable() {
    let report = LockCheckReport {
        stale_toolchain: None,
        standing: LockStanding {
            stale: vec!["zig".to_owned()],
            unverifiable: vec![UnverifiableEntry {
                id: "ghostty".to_owned(),
                vars: vec!["FORGE_BASE".to_owned()],
            }],
            ..LockStanding::default()
        },
        name_only: Vec::new(),
    };
    assert_eq!(report.exit_code(), 1);
    let out = render_lock_check(&report);
    assert!(out.contains("`zig` is stale"), "{out}");
    assert!(out.contains("`ghostty` cannot be verified"), "{out}");
    assert!(out.contains("FORGE_BASE"), "{out}");
    assert!(!out.contains("consistent"), "{out}");
}

#[test]
fn render_lock_check_consistent_when_all_empty() {
    let report = LockCheckReport::default();
    assert_eq!(report.exit_code(), 0);
    assert!(render_lock_check(&report).contains("consistent"));
}

// --- helpers shared with the execution-test shape ---

fn res(json: serde_json::Value) -> Resource {
    serde_json::from_value(json).expect("valid resource json")
}

const fn local_target() -> Target {
    Target::local()
}

fn all_absent(resources: &[Resource]) -> BTreeMap<ResourceId, zap_types::detected::Detection> {
    resources
        .iter()
        .map(|r| (r.id.clone(), zap_types::detected::Detection::Absent))
        .collect()
}

// --- fgro-gated: the run_lock_check config↔lock wiring ---

#[tokio::test]
async fn run_lock_check_reports_a_missing_entry() {
    if !fgro_available() {
        eprintln!("skipping run_lock_check_reports_a_missing_entry: ZAP_FGRO not set");
        return;
    }
    let dir = scratch::tempdir().unwrap();
    let home = scratch::tempdir().unwrap();
    let config_path = dir.path().join("zap.ts");
    scratch::write_config(
        &config_path,
        r"export default (zap) => ({
            target: zap.target({local: true}),
            resources: [
                zap.file({
                    id: 'zig',
                    path: '/opt/zig',
                    content: {type: 'remote', url: 'https://example.invalid/zig', extract: {type: 'none'}},
                }),
            ],
        });
        ",
    )
    .unwrap();

    // No lock yet → the eligible tracked file is missing an entry → exit 1.
    let report = run_lock_check_in(Some(home.path()), fgro(), &config_path)
        .await
        .unwrap();
    assert_eq!(report.standing.missing, vec!["zig".to_owned()]);
    assert_eq!(report.exit_code(), 1);
}

/// `zap update` must clear a stale entry even when upstream bytes are unchanged: the
/// stale-lock error prescribes it, so an edit around an unchanged source (here, the
/// entry's `config_hash` predates the config) has to be repaired by `update`, not only
/// by `zap lock`.
#[tokio::test]
async fn run_update_refreshes_a_stale_entry_with_an_unchanged_pin() {
    if !fgro_available() {
        eprintln!(
            "skipping run_update_refreshes_a_stale_entry_with_an_unchanged_pin: ZAP_FGRO not set"
        );
        return;
    }
    let body = b"zig-bytes".to_vec();
    let url = serve_once(body.clone());
    let dir = scratch::tempdir().unwrap();
    let home = scratch::tempdir().unwrap();
    let config_path = dir.path().join("zap.ts");
    scratch::write_config(
        &config_path,
        format!(
            r"export default (zap) => ({{
            target: zap.target({{local: true}}),
            resources: [
                zap.file({{
                    id: 'zig',
                    path: '/opt/zig',
                    content: {{type: 'remote', url: '{url}', extract: {{type: 'none'}}}},
                }}),
            ],
        }});
        "
        ),
    )
    .unwrap();

    // The pin is right (the served bytes) but the entry's config_hash predates the
    // config — the shape an edit to the resource leaves behind.
    let mut lock = ZapLock {
        toolchain: common::toolchain(),
        ..ZapLock::default()
    };
    lock.entries.insert(
        ResourceId("zig".to_owned()),
        LockEntry::RemoteFile {
            config_hash: "predates-the-config".to_owned(),
            blake3: blake3_hex(&body),
        },
    );
    write_zap_lock(&lock_path_for(&config_path), &lock).unwrap();
    let stale = run_lock_check_in(Some(home.path()), fgro(), &config_path)
        .await
        .unwrap();
    assert_eq!(stale.standing.stale, vec!["zig".to_owned()]);

    let report =
        zap_core::commands::update::run_update_in(Some(home.path()), fgro(), &config_path, &[])
            .await
            .unwrap();
    assert!(
        matches!(
            report.outcomes.as_slice(),
            [zap_core::commands::update::UpdateOutcome::Refreshed { id, .. }] if id == "zig"
        ),
        "expected one Refreshed outcome, got {:?}",
        report.outcomes
    );
    assert_eq!(report.exit_code(), 0);
    let rendered = zap_core::commands::update::render_update(&report);
    assert!(rendered.contains("Refreshed"), "got: {rendered}");

    // The rewritten entry keeps the pin and now carries the current config_hash.
    let current = run_lock_check_in(Some(home.path()), fgro(), &config_path)
        .await
        .unwrap();
    assert!(
        current.standing.stale.is_empty(),
        "stale after update: {:?}",
        current.standing.stale
    );
    assert_eq!(current.exit_code(), 0);
    let lock = read_zap_lock(&lock_path_for(&config_path))
        .unwrap()
        .unwrap();
    match &lock.entries[&ResourceId("zig".to_owned())] {
        LockEntry::RemoteFile { blake3, .. } => assert_eq!(*blake3, blake3_hex(&body)),
        other @ (LockEntry::Build { .. } | LockEntry::AptKey { .. }) => {
            panic!("expected a remote_file entry, got {other:?}")
        }
    }
}

/// `zap update` advances a tracked `apt_repo` key's pin to what its url now serves — a
/// rotated upstream key — and the advance is what the lock's diff shows.
#[tokio::test]
async fn run_update_advances_an_apt_key_pin() {
    if !fgro_available() {
        eprintln!("skipping run_update_advances_an_apt_key_pin: ZAP_FGRO not set");
        return;
    }
    let rotated = b"rotated pgdg key\n".to_vec();
    let url = serve_once(rotated.clone());
    let dir = scratch::tempdir().unwrap();
    let home = scratch::tempdir().unwrap();
    let config_path = dir.path().join("zap.ts");
    scratch::write_config(
        &config_path,
        format!(
            r"export default (zap) => ({{
            target: zap.target({{local: true}}),
            resources: [
                zap.apt_repo({{
                    id: 'pgdg',
                    key_url: '{url}',
                    source: 'deb https://apt.example/apt stable main',
                }}),
            ],
        }});
        "
        ),
    )
    .unwrap();
    let resource = apt_repo_resource(&url, None);
    let mut lock = ZapLock {
        toolchain: common::toolchain(),
        ..ZapLock::default()
    };
    lock.entries.insert(
        ResourceId("pgdg".to_owned()),
        entry_with_pin(&resource, &no_names(), env(&[]), "the old key"),
    );
    write_zap_lock(&lock_path_for(&config_path), &lock).unwrap();
    let current = run_lock_check_in(Some(home.path()), fgro(), &config_path)
        .await
        .unwrap();
    assert_eq!(current.exit_code(), 0, "{:?}", current.standing);

    let report =
        zap_core::commands::update::run_update_in(Some(home.path()), fgro(), &config_path, &[])
            .await
            .unwrap();
    assert!(
        matches!(
            report.outcomes.as_slice(),
            [zap_core::commands::update::UpdateOutcome::Advanced { id, from: Some(_), .. }]
                if id == "pgdg"
        ),
        "{:?}",
        report.outcomes
    );
    let lock = read_zap_lock(&lock_path_for(&config_path))
        .unwrap()
        .unwrap();
    assert_eq!(lock.version, LOCK_VERSION);
    let entry = &lock.entries[&ResourceId("pgdg".to_owned())];
    assert!(matches!(entry, LockEntry::AptKey { .. }), "{entry:?}");
    assert_eq!(entry.pin(), Some(&blake3_hex(&rotated)));
}

#[tokio::test]
async fn run_lock_check_reports_a_stale_entry() {
    if !fgro_available() {
        eprintln!("skipping run_lock_check_reports_a_stale_entry: ZAP_FGRO not set");
        return;
    }
    let dir = scratch::tempdir().unwrap();
    let home = scratch::tempdir().unwrap();
    let config_path = dir.path().join("zap.ts");
    scratch::write_config(
        &config_path,
        r"export default (zap) => ({
            target: zap.target({local: true}),
            resources: [
                zap.file({
                    id: 'zig',
                    path: '/opt/zig',
                    content: {type: 'remote', url: 'https://forge.example/zig.tar.xz', extract: {type: 'none'}},
                }),
            ],
        });
        ",
    )
    .unwrap();

    // An on-disk entry whose config_hash deliberately doesn't match the (literal,
    // verifiable) config → stale, not missing: config_hash drift is caught by
    // `--check`, not only at apply time.
    let mut lock = ZapLock {
        toolchain: common::toolchain(),
        ..ZapLock::default()
    };
    lock.entries.insert(
        ResourceId("zig".to_owned()),
        LockEntry::RemoteFile {
            config_hash: "deliberately-wrong".to_owned(),
            blake3: blake3_hex(b"x"),
        },
    );
    write_zap_lock(&lock_path_for(&config_path), &lock).unwrap();

    let report = run_lock_check_in(Some(home.path()), fgro(), &config_path)
        .await
        .unwrap();
    assert_eq!(report.standing.stale, vec!["zig".to_owned()]);
    assert!(report.standing.missing.is_empty());
    assert!(report.standing.unverifiable.is_empty());
    assert_eq!(report.exit_code(), 1);
}

/// `zap lock` and `zap update` mint under the config's own `mask` list: `PATH` (set in
/// every test process) is masked by name, so the entries each command writes verify
/// under any other value of it.
#[tokio::test]
async fn the_lock_commands_mask_by_the_configs_own_lists() {
    if !fgro_available() {
        eprintln!("skipping the_lock_commands_mask_by_the_configs_own_lists: ZAP_FGRO not set");
        return;
    }
    for command in ["lock", "update"] {
        let served = serve_once(b"zig-bytes".to_vec());
        let dir = scratch::tempdir().unwrap();
        let home = scratch::tempdir().unwrap();
        let config_path = dir.path().join("zap.ts");
        scratch::write_config(
            &config_path,
            format!(
                r"export default (zap) => {{
                zap.target({{local: true}});
                zap.mask('PATH');
                zap.file({{
                    id: 'zig',
                    path: `/opt/${{zap.env('ZAP_TEST_UNSET_DIR_KEY')}}/zig`,
                    content: {{type: 'remote', url: `{served}?p=${{zap.env('PATH')}}`,
                        extract: {{type: 'none'}}}},
                }});
            }};
            "
            ),
        )
        .unwrap();
        // `PATH` is in `mask`: addressed by name deliberately, so not noted. The path's
        // reference only looks like a secret (and the mint, which fetches the url alone,
        // needs no value for it): noted by every command.
        let noted = vec![NameOnlyRefs {
            id: "zig".to_owned(),
            vars: by_name(&["ZAP_TEST_UNSET_DIR_KEY"]),
        }];
        if command == "lock" {
            let report =
                zap_core::commands::lock::run_lock_in(Some(home.path()), fgro(), &config_path)
                    .await
                    .unwrap();
            assert_eq!(report.name_only, noted);
        } else {
            let report = zap_core::commands::update::run_update_in(
                Some(home.path()),
                fgro(),
                &config_path,
                &[],
            )
            .await
            .unwrap();
            assert_eq!(report.exit_code(), 0, "{:?}", report.outcomes);
            assert_eq!(report.name_only, noted);
        }
        let checked = run_lock_check_in(Some(home.path()), fgro(), &config_path)
            .await
            .unwrap();
        assert_eq!(checked.name_only, noted, "zap lock --check");
        assert_eq!(checked.exit_code(), 0, "a note is not an error");
        let lock = read_zap_lock(&lock_path_for(&config_path))
            .unwrap()
            .unwrap();
        let mut config = tracked_config(
            &format!("{served}?p={}", marker("PATH")),
            &format!("/opt/{}/zig", marker("ZAP_TEST_UNSET_DIR_KEY")),
        );
        config.mask_vars = Some(vec![zap_types::scalar::EnvVarName::new("PATH").unwrap()]);
        assert_eq!(
            classify_lock(&config, &lock, env(&[("PATH", "/elsewhere")])).unwrap(),
            LockStanding::default(),
            "zap {command}"
        );
    }
}

// --- references addressed by name only are reported ---

/// References noted for their name.
fn by_name(names: &[&str]) -> Vec<NameOnlyRef> {
    names
        .iter()
        .map(|name| NameOnlyRef {
            name: (*name).to_owned(),
            reason: SecretReason::Name,
        })
        .collect()
}

#[test]
fn name_only_refs_are_the_secret_shaped_names_the_address_resolves() {
    let resource = tracked_resource(&format!(
        "{files_base}/{keycloak_version}/zig?t={secret_token}",
        files_base = marker("FILES_BASE"),
        keycloak_version = marker("KEYCLOAK_VERSION"),
        secret_token = marker("SECRET_TOKEN")
    ));
    // The name rule matches `KEY` inside `KEYCLOAK_VERSION`: reported, so it can be seen.
    assert_eq!(
        no_names().name_only_refs(&resource, env(&[])),
        by_name(&["KEYCLOAK_VERSION", "SECRET_TOKEN"])
    );
    // `unmask` makes one count by value. A name in `mask` is addressed by name because
    // the config says so — whether or not it also looks like a secret — so it isn't
    // listed: the note is for names nobody has ruled on.
    assert_eq!(
        names(&[], &["KEYCLOAK_VERSION"]).name_only_refs(&resource, env(&[])),
        by_name(&["SECRET_TOKEN"])
    );
    assert_eq!(
        names(&["FILES_BASE", "SECRET_TOKEN"], &[]).name_only_refs(&resource, env(&[])),
        by_name(&["KEYCLOAK_VERSION"])
    );
    // A build's url and output are resolved; a reference in `run` is addressed as written.
    let build = res(serde_json::json!({
        "id": "ghostty", "type": "build",
        "source": {"type": "remote", "extract": {"type": "tar.xz"},
                   "url": Text::of_pieces([
                       Lit("https://files.example.com/src.tar.xz?t="),
                       Ref("SOURCE_TOKEN"),
                   ])},
        "run": Text::of_pieces([Lit("make TOKEN="), Ref("BUILD_TOKEN")]),
        "output": Text::of_pieces([Lit("/opt/"), Ref("OUTPUT_KEY"), Lit("/bin/ghostty")]),
    }));
    assert_eq!(
        no_names().name_only_refs(&build, env(&[])),
        by_name(&["OUTPUT_KEY", "SOURCE_TOKEN"])
    );
    // Not lock-eligible (a declared pin): nothing is addressed in the lock.
    let vendored = res(serde_json::json!({
        "id": "zig", "type": "file", "path": "/opt/zig",
        "content": {"type": "remote", "extract": {"type": "none"},
                    "url": Text::of_pieces([
                        Lit("https://files.example.com/zig?t="),
                        Ref("SECRET_TOKEN"),
                    ]),
                    "blake3": "ab".repeat(32)},
    }));
    assert!(no_names().name_only_refs(&vendored, env(&[])).is_empty());
}

#[test]
fn the_lock_reports_render_what_is_addressed_by_name_only() {
    let name_only = vec![NameOnlyRefs {
        id: "zig".to_owned(),
        vars: by_name(&["KEYCLOAK_VERSION", "SECRET_TOKEN"]),
    }];
    let note = format!(
        "note: `zig`: {keycloak_version} (named like a secret), {secret_token} (named like a \
         secret) — addressed by name only (the value is not part of the lock address, and \
         a change to it never reads stale); `unmask` any that is not a secret\n",
        keycloak_version = shown("KEYCLOAK_VERSION"),
        secret_token = shown("SECRET_TOKEN")
    );

    // `zap lock --check`: from the config, with no effect on the verdict.
    let config = tracked_config(
        &format!(
            "https://files.example.com/{keycloak_version}/zig?t={secret_token}",
            keycloak_version = marker("KEYCLOAK_VERSION"),
            secret_token = marker("SECRET_TOKEN")
        ),
        "/opt/zig",
    );
    let entry = entry_for(&config.resources[0], &LockAddressing::of(&config), env(&[]));
    let mut lock = ZapLock {
        toolchain: common::toolchain(),
        ..ZapLock::default()
    };
    lock.entries.insert(ResourceId("zig".to_owned()), entry);
    let checked = LockCheckReport {
        stale_toolchain: None,
        standing: classify_lock(&config, &lock, env(&[])).unwrap(),
        name_only: zap_core::lock::name_only_refs(&config, &config.resources, env(&[])),
    };
    assert_eq!(checked.name_only, name_only);
    assert_eq!(checked.exit_code(), 0);
    assert_eq!(
        render_lock_check(&checked),
        format!("lock is consistent with config\n{note}")
    );
    // Nothing addressed by name: nothing said.
    assert_eq!(
        render_lock_check(&LockCheckReport::default()),
        "lock is consistent with config\n"
    );

    // `zap lock` and `zap update`.
    let toolchain = ContentHash::of_bytes(b"fgro");
    let locked = zap_core::commands::LockReport {
        path: "zap.lock".to_owned(),
        toolchain: toolchain.clone(),
        previous_toolchain: None,
        locked: vec!["zig".to_owned()],
        name_only: name_only.clone(),
    };
    assert_eq!(
        zap_core::commands::render_lock(&locked),
        format!(
            "pinned fgro {}\nwrote zap.lock — pinned 1 resource(s): zig\n{note}",
            toolchain.as_str()
        )
    );
    let updated = zap_core::commands::UpdateReport {
        outcomes: vec![zap_core::commands::update::UpdateOutcome::Unchanged {
            id: "zig".to_owned(),
        }],
        name_only,
    };
    assert_eq!(
        zap_core::commands::render_update(&updated),
        format!("all 1 pin(s) already up to date\n{note}")
    );
    // …and after the summary of a run that changed something.
    let advanced = zap_core::commands::UpdateReport {
        outcomes: vec![zap_core::commands::update::UpdateOutcome::Advanced {
            id: "zig".to_owned(),
            from: None,
            to: "abc123".to_owned(),
        }],
        name_only: updated.name_only,
    };
    assert_eq!(
        zap_core::commands::render_update(&advanced),
        format!("Advanced: zig (none → abc123)\n{note}")
    );
}

// --- a mint never fetches a url with an unset reference ---

/// A config file with one tracked remote file at `url`.
fn write_tracked_config(dir: &std::path::Path, url: &str) -> std::path::PathBuf {
    let config_path = dir.join("zap.ts");
    scratch::write_config(
        &config_path,
        format!(
            r"export default (zap) => {{
                zap.target({{local: true}});
                zap.file({{
                    id: 'zig',
                    path: '/opt/zig',
                    content: {{type: 'remote', url: {url}, extract: {{type: 'none'}}}},
                }});
            }};
            ",
            url = authored(url)
        ),
    )
    .unwrap();
    config_path
}

/// The inert text `inert` as a config writes it: a template literal with a
/// `zap.env('NAME')` where each reference is.
fn authored(inert: &str) -> String {
    let body: String = zap_types::var_ref::segments(inert)
        .map(|segment| match segment {
            Lit(text) => text
                .replace('\\', "\\\\")
                .replace('`', "\\`")
                .replace("${", "\\${"),
            Ref(name) => format!("${{zap.env('{name}')}}"),
        })
        .collect();
    format!("`{body}`")
}

#[tokio::test]
async fn a_cold_start_refuses_to_mint_from_a_url_with_an_unset_reference() {
    // The server would answer the url the unset reference leaves behind; its bytes must
    // not become this resource's pin. Secret-named or not, for both entry kinds.
    for name in ["ZAP_TEST_UNSET_SECRET_TOKEN", "ZAP_TEST_UNSET_BASE"] {
        for build in [false, true] {
            let url = format!("{}?v={}", serve_once(b"bytes".to_vec()), marker(name));
            let home = scratch::tempdir().unwrap();
            let cfg_dir = scratch::tempdir().unwrap();
            let config_path = cfg_dir.path().join("zap.ts");
            let config = if build {
                tracked_build_config(&url)
            } else {
                tracked_config(&url, "/opt/zig")
            };
            let error = resolve_lock(&config, &config_path, home.path(), ColdStart::Mint)
                .await
                .unwrap_err();
            assert!(
                matches!(&error, zap_core::error::Error::FetchVarUnset { vars, .. } if vars == name),
                "{name}, build {build}: {error:?}"
            );
            assert_eq!(error.exit_code(), 2);
            assert!(error.to_string().contains(name), "{error}");
        }
    }
}

#[tokio::test]
async fn the_lock_commands_refuse_to_mint_from_a_url_with_an_unset_reference() {
    if !fgro_available() {
        eprintln!(
            "skipping the_lock_commands_refuse_to_mint_from_a_url_with_an_unset_reference: ZAP_FGRO not set"
        );
        return;
    }
    let url = format!(
        "{}?t={}",
        serve_once(b"bytes".to_vec()),
        marker("ZAP_TEST_UNSET_SECRET_TOKEN")
    );
    let dir = scratch::tempdir().unwrap();
    let home = scratch::tempdir().unwrap();
    let config_path = write_tracked_config(dir.path(), &url);
    let written = std::fs::read(lock_path_for(&config_path)).ok();

    let error = zap_core::commands::lock::run_lock_in(Some(home.path()), fgro(), &config_path)
        .await
        .unwrap_err();
    assert!(
        matches!(error, zap_core::error::Error::FetchVarUnset { .. }),
        "{error:?}"
    );
    assert_eq!(error.exit_code(), 2);

    let report =
        zap_core::commands::update::run_update_in(Some(home.path()), fgro(), &config_path, &[])
            .await
            .unwrap();
    // the entry fails with the code the error has from `zap lock`
    assert_eq!(report.exit_code(), 2);
    let rendered = zap_core::commands::render_update(&report);
    assert!(
        rendered.contains("ZAP_TEST_UNSET_SECRET_TOKEN unset or empty"),
        "{rendered}"
    );
    // The note is about the target's declaration, so it is there for a failed entry too.
    assert_eq!(
        report.name_only,
        [NameOnlyRefs {
            id: "zig".to_owned(),
            vars: by_name(&["ZAP_TEST_UNSET_SECRET_TOKEN"]),
        }]
    );
    assert!(
        rendered.contains(&format!(
            "note: `zig`: {zap_test_unset_secret_token}",
            zap_test_unset_secret_token = shown("ZAP_TEST_UNSET_SECRET_TOKEN")
        )),
        "{rendered}"
    );
    assert_eq!(
        std::fs::read(lock_path_for(&config_path)).ok(),
        written,
        "neither command wrote a lock"
    );
}

// --- no error names a resolved url ---

/// A one-shot server answering `403 Forbidden`; returns its base url.
fn serve_forbidden() -> String {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        if let Ok((mut sock, _)) = listener.accept() {
            let mut buf = [0u8; 4096];
            let _ = sock.read(&mut buf);
            let _ = sock.write_all(
                b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            );
            let _ = sock.flush();
        }
    });
    format!("http://{addr}")
}

/// Assert `text` names the url by its reference to `PATH`, spelled `reference` — the way
/// a text of that kind holds one — and holds none of what `PATH` — set in every test
/// process, standing in for a secret — resolves to.
fn assert_names_only_the_reference(text: &str, reference: &str) {
    assert!(text.contains(reference), "the declared url: {text}");
    let path = std::env::var("PATH").expect("PATH is set");
    let leaked: Vec<&str> = path
        .split(':')
        .filter(|segment| segment.len() >= 4 && text.contains(segment))
        .collect();
    assert!(leaked.is_empty(), "resolved value {leaked:?} in: {text}");
}

/// The reference to `PATH` as a `Debug` form of text holding it spells it.
fn debugged_reference() -> String {
    format!("{:?}", marker("PATH")).trim_matches('"').to_owned()
}

#[tokio::test]
async fn a_failed_cold_start_fetch_names_the_declared_url() {
    // A refused request, and one that can't be sent (whose transport error quotes the
    // url it was sent to).
    for base in [serve_forbidden(), "http://127.0.0.1:1".to_owned()] {
        for build in [false, true] {
            let url = format!("{base}/zig?token={}", marker("PATH"));
            let home = scratch::tempdir().unwrap();
            let cfg_dir = scratch::tempdir().unwrap();
            let config = if build {
                tracked_build_config(&url)
            } else {
                tracked_config(&url, "/opt/zig")
            };
            let error = resolve_lock(
                &config,
                &cfg_dir.path().join("zap.ts"),
                home.path(),
                ColdStart::Mint,
            )
            .await
            .unwrap_err();
            assert!(
                matches!(error, zap_core::error::Error::Fetch { .. }),
                "{error:?}"
            );
            assert_names_only_the_reference(&error.to_string(), &marker("PATH"));
            assert_names_only_the_reference(&format!("{error:?}"), &debugged_reference());
        }
    }
}

#[tokio::test]
async fn the_lock_commands_failed_fetch_names_the_declared_url() {
    if !fgro_available() {
        eprintln!(
            "skipping the_lock_commands_failed_fetch_names_the_declared_url: ZAP_FGRO not set"
        );
        return;
    }
    for base in [serve_forbidden(), "http://127.0.0.1:1".to_owned()] {
        let dir = scratch::tempdir().unwrap();
        let home = scratch::tempdir().unwrap();
        let config_path =
            write_tracked_config(dir.path(), &format!("{base}/zig?token={}", marker("PATH")));

        // `zap lock`: the error the binary prints.
        let error = zap_core::commands::lock::run_lock_in(Some(home.path()), fgro(), &config_path)
            .await
            .unwrap_err();
        assert_names_only_the_reference(&error.to_string(), &marker("PATH"));

        // `zap update`: the outcome it renders (and holds).
        let report =
            zap_core::commands::update::run_update_in(Some(home.path()), fgro(), &config_path, &[])
                .await
                .unwrap();
        assert_eq!(report.exit_code(), 1);
        assert_names_only_the_reference(
            &zap_core::commands::render_update(&report),
            &shown("PATH"),
        );
        assert_names_only_the_reference(&format!("{:?}", report.outcomes), &debugged_reference());
    }
}

// --- a dry apply previews past a pin it can't mint ---

/// A dry `zap apply` on a cold lock whose tracked url references an unset variable
/// renders like `zap plan` does — the resource held, the run exit 1 — where the mint
/// itself is an error. A wetrun is stopped by its env gate before any mint, and
/// `--no-lock` never mints.
#[tokio::test]
async fn a_dry_apply_holds_a_resource_whose_pin_it_cannot_mint() {
    use zap_core::commands::apply::{ApplyOptions, render_apply, run_apply_in};

    if !fgro_available() {
        eprintln!(
            "skipping a_dry_apply_holds_a_resource_whose_pin_it_cannot_mint: ZAP_FGRO not set"
        );
        return;
    }
    // The server would answer the url the unset reference leaves behind.
    let url = format!(
        "{}?t={}",
        serve_once(b"bytes".to_vec()),
        marker("ZAP_TEST_UNSET_SECRET_TOKEN")
    );
    let dir = scratch::tempdir().unwrap();
    let home = scratch::tempdir().unwrap();
    let config_path = write_tracked_config(dir.path(), &url);
    let written = std::fs::read(lock_path_for(&config_path)).ok();

    let dry = run_apply_in(
        Some(home.path()),
        fgro(),
        &config_path,
        ApplyOptions::default(),
    )
    .await
    .expect("a preview renders");
    assert_eq!(dry.exit_code(), 1);
    assert!(dry.plan.changes.is_empty(), "{:?}", dry.plan.changes);
    assert!(dry.auto_locked.is_empty());
    assert_eq!(dry.held.len(), 1, "{:?}", dry.held);
    assert_eq!(dry.held[0].resource_id, ResourceId("zig".to_owned()));
    assert_eq!(
        dry.held[0].describe(),
        "no pin could be minted — its fetch url references ZAP_TEST_UNSET_SECRET_TOKEN, \
         unset or empty in the environment; set it and re-run"
    );
    assert_eq!(dry.unverifiable, ["ZAP_TEST_UNSET_SECRET_TOKEN"]);
    let rendered = render_apply(&dry);
    assert!(rendered.contains("UNDETERMINED"), "{rendered}");
    assert!(rendered.contains("no pin could be minted"), "{rendered}");
    assert_eq!(std::fs::read(lock_path_for(&config_path)).ok(), written);

    // `--no-lock`: no mint is tried, so the resource holds as any unpinned one does.
    let offline = run_apply_in(
        Some(home.path()),
        fgro(),
        &config_path,
        ApplyOptions {
            no_lock: true,
            ..ApplyOptions::default()
        },
    )
    .await
    .unwrap();
    assert_eq!(offline.exit_code(), 1);
    assert!(
        offline.held[0].describe().contains("zap update zig"),
        "{:?}",
        offline.held
    );

    // A wetrun never reaches the mint: the env gate names the variable first.
    for no_lock in [false, true] {
        let error = run_apply_in(
            Some(home.path()),
            fgro(),
            &config_path,
            ApplyOptions {
                wetrun: true,
                no_lock,
                ..ApplyOptions::default()
            },
        )
        .await
        .unwrap_err();
        assert!(
            matches!(&error, zap_core::error::Error::WetrunRefused(message)
                if message.contains("ZAP_TEST_UNSET_SECRET_TOKEN")),
            "{error:?}"
        );
        assert_eq!(error.exit_code(), 2);
    }
}

#[tokio::test]
async fn a_previewing_cold_start_leaves_an_unmintable_pin_out() {
    // Two tracked files: one mints, one names an unset variable. A preview keeps the
    // pin it could mint and records the other; a required mint is the error.
    let good = serve_once(b"good".to_vec());
    let bad = format!(
        "{}?t={}",
        serve_once(b"bad".to_vec()),
        marker("ZAP_TEST_UNSET_SECRET_TOKEN")
    );
    let config: ZapConfig = serde_json::from_value(serde_json::json!({
        "target": {"local": true},
        "resources": [
            {"id": "good", "type": "file", "path": "/opt/good",
             "content": {"type": "remote", "url": good, "extract": {"type": "none"}}},
            {"id": "bad", "type": "file", "path": "/opt/bad",
             "content": {"type": "remote", "url": Text::from_inert(bad).unwrap(), "extract": {"type": "none"}}},
        ],
    }))
    .unwrap();
    let home = scratch::tempdir().unwrap();
    let cfg_dir = scratch::tempdir().unwrap();
    let config_path = cfg_dir.path().join("zap.ts");

    let preview = resolve_lock(&config, &config_path, home.path(), ColdStart::Preview)
        .await
        .unwrap();
    assert_eq!(preview.newly_resolved, [ResourceId("good".to_owned())]);
    assert_eq!(
        preview.unmintable,
        [zap_core::lock::Unmintable {
            id: ResourceId("bad".to_owned()),
            vars: "ZAP_TEST_UNSET_SECRET_TOKEN".to_owned(),
        }]
    );
    assert!(
        !preview
            .lock
            .entries
            .contains_key(&ResourceId("bad".to_owned()))
    );

    // Any other failure is still a failure for a preview: an unreachable host.
    let unreachable = tracked_config("http://127.0.0.1:1/zig", "/opt/zig");
    let error = resolve_lock(&unreachable, &config_path, home.path(), ColdStart::Preview)
        .await
        .unwrap_err();
    assert!(
        matches!(error, zap_core::error::Error::Fetch { .. }),
        "{error:?}"
    );
}

/// A config with two tracked files, `zig` and `zag`, whose urls reference the unset
/// `ZAP_TEST_UNSET_ZIG_TOKEN` and `ZAP_TEST_UNSET_ZAG_TOKEN`.
fn write_two_unmintable_config(dir: &std::path::Path) -> std::path::PathBuf {
    let config_path = dir.join("zap.ts");
    scratch::write_config(
        &config_path,
        r"export default (zap) => {
            zap.target({local: true});
            for (const id of ['zig', 'zag']) {
                zap.file({
                    id,
                    path: `/opt/${id}`,
                    content: {
                        type: 'remote',
                        url: `http://127.0.0.1:1/${id}?t=${zap.env(
                            `ZAP_TEST_UNSET_${id.toUpperCase()}_TOKEN`,
                        )}`,
                        extract: {type: 'none'},
                    },
                });
            }
        };
        ",
    )
    .unwrap();
    config_path
}

/// Each resource a dry apply couldn't mint a pin for is held for its own reason: the
/// variable its own url references.
#[tokio::test]
async fn a_dry_apply_names_each_unmintable_resources_own_reference() {
    use zap_core::commands::apply::{ApplyOptions, run_apply_in};

    if !fgro_available() {
        eprintln!(
            "skipping a_dry_apply_names_each_unmintable_resources_own_reference: ZAP_FGRO not set"
        );
        return;
    }
    let dir = scratch::tempdir().unwrap();
    let home = scratch::tempdir().unwrap();
    let config_path = write_two_unmintable_config(dir.path());
    let dry = run_apply_in(
        Some(home.path()),
        fgro(),
        &config_path,
        ApplyOptions::default(),
    )
    .await
    .unwrap();
    assert_eq!(dry.held.len(), 2, "{:?}", dry.held);
    for held in &dry.held {
        let own = format!(
            "references ZAP_TEST_UNSET_{}_TOKEN,",
            held.resource_id.0.to_uppercase()
        );
        assert!(
            held.describe().contains(&own),
            "{}: {}",
            held.resource_id.0,
            held.describe()
        );
    }
}

/// `zap update <id>` notes the references of the resources it was asked to update, and
/// only those — whatever became of the update itself.
#[tokio::test]
async fn update_notes_only_its_targets_name_only_references() {
    if !fgro_available() {
        eprintln!("skipping update_notes_only_its_targets_name_only_references: ZAP_FGRO not set");
        return;
    }
    let dir = scratch::tempdir().unwrap();
    let home = scratch::tempdir().unwrap();
    let config_path = write_two_unmintable_config(dir.path());
    let report = zap_core::commands::update::run_update_in(
        Some(home.path()),
        fgro(),
        &config_path,
        &["zag".to_owned()],
    )
    .await
    .unwrap();
    assert_eq!(report.exit_code(), 2, "the reference is unset: {report:?}");
    assert_eq!(
        report.name_only,
        vec![NameOnlyRefs {
            id: "zag".to_owned(),
            vars: by_name(&["ZAP_TEST_UNSET_ZAG_TOKEN"]),
        }]
    );
}
