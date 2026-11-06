//! Fixture staging and identity.
//!
//! The checked-in fixtures live in `crates/xtask/fixtures/differential/`, and the
//! bootstrap-replace scenario's own in `crates/xtask/fixtures/bootstrap/` (outside the
//! tree the base snapshot hashes: the base doesn't depend on them). A run never
//! evaluates them in place — `apply` writes `zap.lock` beside the config,
//! and `pins.ts` and `origin_ca.ts` are generated — so they're copied into per-run
//! trees that mirror the repo layout, `src/lib` copied in beside them, keeping the
//! fixtures' relative recipe imports valid while nothing is written to the repo.
//! Each binary gets a tree of its own, so each reads the `zap.lock` it minted.
//!
//! zap evaluates a config only when its module graph stays inside the config's
//! project: the nearest directory at or above it whose `package.json` holds more than a
//! type marker, found by a walk that stops below any directory another user owns
//! or every user can write. So each staged tree is a project of its own
//! ([`STAGE_PACKAGE_JSON`] at its root), holds its modules as plain files (a link
//! back to the repo would resolve outside it), and lives under a run directory in
//! the user's own cache ([`create_run_dir`]), never below the world-writable
//! `/tmp`. The local bundle the VM runs is a project the same way.
//!
//! Every config is evaluated with the `fgro` build the harness runs both binaries
//! with, and only through a lock that pins it, so each staged config, and the local
//! bundle's, starts beside a `zap.lock` holding that toolchain pin and no entry
//! ([`toolchain_lock`]). The pin is generated from the binary the harness ships, never
//! checked in: an `fgro` build isn't reproducible across machines, so a committed
//! hash would name one machine's build and refuse every other.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use super::vm::Distro;
use super::{content, process};

/// The fixture tree, relative to the repo root.
pub const FIXTURE_DIR: &str = "crates/xtask/fixtures/differential";

/// The bootstrap-replace scenario's fixtures (`bootstrap`), relative to the repo root:
/// staged beside the kitchen sinks, and not part of [`base_hash`].
pub const BOOTSTRAP_DIR: &str = "crates/xtask/fixtures/bootstrap";

/// Bumped when the base build procedure changes in a way the fixture hash can't
/// see, forcing every base snapshot to rebuild.
const BASE_PROCEDURE_VERSION: u32 = 5;

/// Where each run's scratch tree goes, under the harness's cache directory: one
/// directory per run, named for the process that made it.
pub const RUNS_DIR: &str = "runs";

/// The `package.json` at the root of each staged tree and of the local bundle,
/// which makes the tree the fixtures' project. Its `name` is what ends zap's walk
/// up to the project; a `type`-only file would not.
pub const STAGE_PACKAGE_JSON: &str =
    "{\n\t\"name\": \"zap-differential-stage\",\n\t\"private\": true,\n\t\"type\": \"module\"\n}\n";

/// Create this run's scratch directory under `runs` (owner-only, removed when the
/// returned guard drops), first removing the ones earlier runs left: a run that is
/// killed leaves its directory, and the next run sweeps every one whose process is
/// gone.
///
/// # Errors
/// `runs` or the run's directory can't be made.
pub fn create_run_dir(runs: &Path) -> Result<tempfile::TempDir, String> {
    std::fs::create_dir_all(runs)
        .map_err(|error| format!("making {} failed: {error}", runs.display()))?;
    sweep_dead_dirs(runs, "");
    tempfile::Builder::new()
        .prefix(&format!("{}-", std::process::id()))
        .tempdir_in(runs)
        .map_err(|error| {
            format!(
                "creating a run directory in {} failed: {error}",
                runs.display()
            )
        })
}

/// Remove the directories in `dir` named `<prefix><pid>-…` whose process is no longer
/// running. Another harness run's, still running, is left alone. Best-effort.
pub fn sweep_dead_dirs(dir: &Path, prefix: &str) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(pid) = name
            .to_str()
            .and_then(|name| name.strip_prefix(prefix))
            .and_then(|name| name.split_once('-'))
            .map(|(pid, _)| pid)
        else {
            continue;
        };
        let Ok(pid) = pid.parse::<u32>() else {
            continue;
        };
        let live = pid == std::process::id() || Path::new("/proc").join(pid.to_string()).exists();
        if !live {
            let _ = std::fs::remove_dir_all(entry.path());
        }
    }
}

/// The generated modules a staged tree carries beside the fixtures.
#[derive(Debug, Clone, Copy)]
pub struct Generated<'a> {
    /// `pins.ts`: the blake3 of the served artifacts (`content::Artifacts::pins_module`).
    pub pins: &'a str,
    /// `origin_ca.ts`: the test CA the https origin is served under
    /// (`pki::Pki::ca_module`).
    pub origin_ca: &'a str,
    /// The `zap.lock` every config starts beside ([`toolchain_lock`]).
    pub lock: &'a str,
}

/// A `zap.lock` pinning the `fgro` build whose blake3 is `fgro_blake3`, with no
/// entry: what a config needs before any command evaluates it. `zap lock` and an
/// apply wetrun keep the pin and add the entries.
pub fn toolchain_lock(fgro_blake3: &str) -> String {
    format!(
        "{{\n  \"version\": 2,\n  \"toolchain\": {{\n    \"fgro_blake3\": \"{fgro_blake3}\"\n  }},\n  \"entries\": {{}}\n}}\n"
    )
}

/// Write `lock` beside every `zap.ts` under `dir`.
fn write_locks(dir: &Path, lock: &str) -> std::io::Result<()> {
    for entry in std::fs::read_dir(dir)? {
        let path = entry?.path();
        if path.is_dir() {
            write_locks(&path, lock)?;
        } else if path.file_name().is_some_and(|name| name == "zap.ts") {
            std::fs::write(path.with_file_name("zap.lock"), lock)?;
        }
    }
    Ok(())
}

/// One binary's staged fixture tree for a run.
#[derive(Debug)]
pub struct Staged {
    /// The mirror root (holds `package.json`, `crates/xtask/fixtures/differential/…`,
    /// and `src/lib`).
    pub root: PathBuf,
}

impl Staged {
    /// Copy the fixtures (the kitchen sinks and the bootstrap-replace scenario's) and
    /// `src/lib` into `root`, write the generated modules and each config's toolchain
    /// lock, and make `root` the tree's project ([`STAGE_PACKAGE_JSON`]).
    ///
    /// # Errors
    /// Any filesystem error, as a message.
    pub fn create(repo: &Path, root: &Path, generated: Generated<'_>) -> Result<Self, String> {
        let io = |error: std::io::Error| format!("staging the fixtures failed: {error}");
        let dest = root.join(FIXTURE_DIR);
        copy_tree(&repo.join(FIXTURE_DIR), &dest).map_err(io)?;
        std::fs::write(dest.join("pins.ts"), generated.pins).map_err(io)?;
        std::fs::write(dest.join("origin_ca.ts"), generated.origin_ca).map_err(io)?;
        write_locks(&dest, generated.lock).map_err(io)?;
        let bootstrap = root.join(BOOTSTRAP_DIR);
        copy_tree(&repo.join(BOOTSTRAP_DIR), &bootstrap).map_err(io)?;
        write_locks(&bootstrap, generated.lock).map_err(io)?;
        copy_tree(&repo.join("src/lib"), &root.join("src/lib")).map_err(io)?;
        std::fs::write(root.join("package.json"), STAGE_PACKAGE_JSON).map_err(io)?;
        Ok(Self {
            root: root.to_path_buf(),
        })
    }

    /// The SSH kitchen-sink config for `distro`.
    pub fn ssh_config(&self, distro: Distro) -> PathBuf {
        self.root
            .join(FIXTURE_DIR)
            .join(distro.name())
            .join("zap.ts")
    }

    /// The bootstrap-replace scenario's `config` (`provision` or `retired`).
    pub fn bootstrap_config(&self, config: &str) -> PathBuf {
        self.root.join(BOOTSTRAP_DIR).join(config).join("zap.ts")
    }

    /// Where the bootstrap-replace scenario's generated keys module goes.
    pub fn bootstrap_keys_module(&self) -> PathBuf {
        self.root.join(BOOTSTRAP_DIR).join("keys.ts")
    }
}

/// Where the local bundle carries the `fgro` build, relative to its root.
pub const BUNDLE_FGRO: &str = "bin/fgro";

/// The relative path of the local-connection config inside a staged tree.
pub fn local_config_relative() -> String {
    format!("{FIXTURE_DIR}/debian-local/zap.ts")
}

/// A tar stream of everything the local suite needs on the VM, rooted at a project
/// of its own ([`STAGE_PACKAGE_JSON`]): the local fixture, `pins.ts`, the two
/// `src/lib` modules its type import names, the config's toolchain `lock`, `binaries` at
/// their given relative paths (the `fgro` build among them, at `bin/fgro`), and — when
/// `seed` is given — a warm content cache for those files under `seed/`. The local
/// fixture imports no `origin_ca.ts`: the guest already trusts the CA, which the SSH
/// kitchen sink installed.
///
/// # Errors
/// Staging or packing failed.
pub fn local_bundle(
    repo: &Path,
    scratch: &Path,
    pins: &str,
    lock: &str,
    binaries: &[(&str, &Path)],
    seed: Option<&BTreeMap<String, Vec<u8>>>,
) -> Result<Vec<u8>, String> {
    let io = |error: std::io::Error| format!("staging the local fixture failed: {error}");
    let root = scratch.join("local-bundle");
    let fixture = root.join(FIXTURE_DIR);
    copy_tree(
        &repo.join(FIXTURE_DIR).join("debian-local"),
        &fixture.join("debian-local"),
    )
    .map_err(io)?;
    std::fs::write(fixture.join("pins.ts"), pins).map_err(io)?;
    write_locks(&fixture, lock).map_err(io)?;
    std::fs::write(root.join("package.json"), STAGE_PACKAGE_JSON).map_err(io)?;
    let lib = root.join("src/lib");
    std::fs::create_dir_all(&lib).map_err(io)?;
    for module in ["zap.ts", "schema.ts"] {
        std::fs::copy(repo.join("src/lib").join(module), lib.join(module)).map_err(io)?;
    }
    for (relative, binary) in binaries {
        let dest = root.join(relative);
        if let Some(parent) = dest.parent() {
            std::fs::create_dir_all(parent).map_err(io)?;
        }
        std::fs::copy(binary, dest).map_err(io)?;
    }
    if let Some(files) = seed {
        content::seed_content_cache(files, &root.join("seed")).map_err(io)?;
    }
    let archive = scratch.join("local-bundle.tar");
    let mut command = Command::new("tar");
    command
        .arg("-C")
        .arg(&root)
        .arg("-cf")
        .arg(&archive)
        .arg(".");
    let output = process::run(command, None, Duration::from_secs(60))
        .map_err(|error| format!("failed to run tar: {error}"))?;
    if !output.success() {
        return Err(format!(
            "packing the local fixture failed: {}",
            output.describe_failure()
        ));
    }
    std::fs::read(&archive).map_err(io)
}

/// The identity of a base snapshot: blake3 over everything that decides what the
/// base looks like — the `pristine` snapshot it starts from (its creation time), the
/// fixture tree, the generated pins, the `src/lib` modules the fixtures import, the
/// binary that converges it and which side of the comparison it is (`builder`: the
/// side's name and its binary), the `fgro` build that evaluates its configs
/// (`fgro_blake3`), the root script that prepares the machine ahead of
/// the apply (`prepare`), the test CA the base's trust store is given
/// (`ca_fingerprint`: a base that trusts another authority can't fetch from this
/// run's origin), and the base procedure version. A base whose recorded hash differs
/// is rebuilt.
///
/// # Errors
/// A file couldn't be read.
pub fn base_hash(
    repo: &Path,
    builder: (&str, &Path),
    pins: &str,
    pristine: &str,
    prepare: &str,
    ca_fingerprint: &str,
    fgro_blake3: &str,
) -> Result<String, String> {
    let (side, binary) = builder;
    let mut hasher = blake3::Hasher::new();
    hasher.update(format!("zap-differential-base-v{BASE_PROCEDURE_VERSION}\n").as_bytes());
    hasher.update(format!("pristine={pristine}\n").as_bytes());
    hasher.update(format!("builder={side}\n").as_bytes());
    hasher.update(format!("prepare={}\n", blake3::hash(prepare.as_bytes()).to_hex()).as_bytes());
    hasher.update(format!("ca={ca_fingerprint}\n").as_bytes());
    hasher.update(format!("fgro={fgro_blake3}\n").as_bytes());
    let mut files = Vec::new();
    collect_files(&repo.join(FIXTURE_DIR), &mut files)
        .and_then(|()| collect_files(&repo.join("src/lib"), &mut files))
        .map_err(|error| format!("hashing the fixtures failed: {error}"))?;
    files.sort();
    for file in files {
        let bytes = std::fs::read(&file)
            .map_err(|error| format!("reading {} failed: {error}", file.display()))?;
        let relative = file.strip_prefix(repo).unwrap_or(&file);
        hasher.update(relative.to_string_lossy().as_bytes());
        hasher.update(b"\0");
        hasher.update(blake3::hash(&bytes).as_bytes());
    }
    hasher.update(pins.as_bytes());
    let binary_bytes = std::fs::read(binary).map_err(|error| {
        format!(
            "reading the {side} binary {} failed: {error}",
            binary.display()
        )
    })?;
    hasher.update(blake3::hash(&binary_bytes).as_bytes());
    Ok(hasher.finalize().to_hex()[..16].to_owned())
}

/// The snapshot description recording `hash`.
pub fn base_description(hash: &str) -> String {
    format!("zap differential base; fixture={hash}")
}

/// Whether a snapshot description records `hash`.
pub fn description_matches(description: &str, hash: &str) -> bool {
    description
        .split(|c: char| c.is_whitespace() || c == ';')
        .any(|token| token == format!("fixture={hash}"))
}

fn collect_files(dir: &Path, out: &mut Vec<PathBuf>) -> std::io::Result<()> {
    for entry in std::fs::read_dir(dir)? {
        let path = entry?.path();
        if path.is_dir() {
            collect_files(&path, out)?;
        } else {
            out.push(path);
        }
    }
    Ok(())
}

fn copy_tree(from: &Path, to: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(to)?;
    for entry in std::fs::read_dir(from)? {
        let path = entry?.path();
        let dest = to.join(path.file_name().unwrap_or_default());
        if path.is_dir() {
            copy_tree(&path, &dest)?;
        } else {
            std::fs::copy(&path, &dest)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        BOOTSTRAP_DIR, FIXTURE_DIR, Generated, STAGE_PACKAGE_JSON, Staged, base_description,
        base_hash, create_run_dir, description_matches, toolchain_lock,
    };

    #[test]
    fn descriptions_round_trip_and_reject_other_hashes() {
        let description = base_description("0123456789abcdef");
        assert!(description_matches(&description, "0123456789abcdef"));
        assert!(!description_matches(&description, "0123456789abcdee"));
        assert!(!description_matches(&description, "0123456789abcde"));
        assert!(!description_matches("", "0123456789abcdef"));
    }

    /// A minimal repo: one fixture file, one bootstrap-replace config, and one `src/lib`
    /// module.
    fn repo() -> tempfile::TempDir {
        let repo = tempfile::tempdir().expect("tempdir");
        let provision = format!("{BOOTSTRAP_DIR}/provision");
        for (dir, file) in [
            (FIXTURE_DIR, "zap.ts"),
            (provision.as_str(), "zap.ts"),
            ("src/lib", "zap.ts"),
        ] {
            let dir = repo.path().join(dir);
            std::fs::create_dir_all(&dir).expect("mkdir");
            std::fs::write(dir.join(file), "export default () => {};\n").expect("write");
        }
        repo
    }

    #[test]
    fn the_base_hash_names_its_builder() {
        let repo = repo();
        let bin = repo.path().join("zap-a");
        let other = repo.path().join("zap-b");
        std::fs::write(&bin, b"binary a").expect("write");
        std::fs::write(&other, b"binary b").expect("write");
        let hash = |side, binary, pins, pristine| {
            base_hash(
                repo.path(),
                (side, binary),
                pins,
                pristine,
                "prepare",
                "ca",
                "f",
            )
            .expect("hash")
        };
        let base = hash("oracle", &bin, "pins", "t0");
        assert_eq!(base.len(), 16);
        assert_eq!(base, hash("oracle", &bin, "pins", "t0"));
        // the same binary on the other side builds a different base
        assert_ne!(base, hash("candidate", &bin, "pins", "t0"));
        assert_ne!(base, hash("oracle", &other, "pins", "t0"));
        assert_ne!(base, hash("oracle", &bin, "other pins", "t0"));
        assert_ne!(base, hash("oracle", &bin, "pins", "t1"));
        let with = |prepare, ca| {
            base_hash(
                repo.path(),
                ("oracle", &bin),
                "pins",
                "t0",
                prepare,
                ca,
                "f",
            )
            .expect("hash")
        };
        assert_eq!(base, with("prepare", "ca"));
        assert_ne!(base, with("another", "ca"));
        assert!(
            base_hash(
                repo.path(),
                ("oracle", &repo.path().join("missing")),
                "p",
                "t",
                "prepare",
                "ca",
                "f"
            )
            .is_err()
        );
    }

    /// The bootstrap-replace scenario's fixtures are not the base's: editing them
    /// doesn't move its hash, so no base rebuild waits on them.
    #[test]
    fn the_base_hash_leaves_the_bootstrap_fixtures_out() {
        let repo = repo();
        let bin = repo.path().join("zap");
        std::fs::write(&bin, b"binary").expect("write");
        let hash = || {
            base_hash(
                repo.path(),
                ("oracle", &bin),
                "pins",
                "t0",
                "prepare",
                "ca",
                "f",
            )
            .expect("hash")
        };
        let before = hash();
        let provision = repo.path().join(BOOTSTRAP_DIR).join("provision/zap.ts");
        std::fs::write(&provision, "export default () => { /* edited */ };\n").expect("write");
        std::fs::write(repo.path().join(BOOTSTRAP_DIR).join("keys.ts"), "x").expect("write");
        assert_eq!(hash(), before);
        // while a kitchen-sink edit does
        std::fs::write(repo.path().join(FIXTURE_DIR).join("zap.ts"), "edited").expect("write");
        assert_ne!(hash(), before);
    }

    /// A base is one authority's: built trusting one CA, it is not the base of a run
    /// served under another.
    #[test]
    fn the_base_hash_names_the_ca_it_trusts() {
        let repo = repo();
        let bin = repo.path().join("zap");
        std::fs::write(&bin, b"binary").expect("write");
        let hash = |ca| {
            base_hash(
                repo.path(),
                ("oracle", &bin),
                "pins",
                "t0",
                "prepare",
                ca,
                "f",
            )
            .expect("hash")
        };
        let one = "aa".repeat(32);
        let other = "ab".repeat(32);
        assert_eq!(hash(&one), hash(&one));
        assert_ne!(hash(&one), hash(&other));
    }

    /// A staged tree holds the fixtures, both generated modules, and `src/lib` as plain
    /// files, under a `package.json` that makes it a project.
    #[test]
    fn a_staged_tree_carries_the_generated_modules() {
        let repo = repo();
        let stage = tempfile::tempdir().expect("tempdir");
        let generated = Generated {
            pins: "export const BLOB_BLAKE3 = 'b';\n",
            origin_ca: "export const ORIGIN_CA_PEM = 'c';\n",
            lock: &toolchain_lock(&"f".repeat(64)),
        };
        let staged =
            Staged::create(repo.path(), &stage.path().join("oracle"), generated).expect("staged");
        let dir = staged.root.join(FIXTURE_DIR);
        assert_eq!(
            std::fs::read_to_string(dir.join("pins.ts")).expect("pins"),
            generated.pins
        );
        assert_eq!(
            std::fs::read_to_string(dir.join("origin_ca.ts")).expect("origin_ca"),
            generated.origin_ca
        );
        assert!(dir.join("zap.ts").is_file());
        // the config starts beside its toolchain lock
        assert_eq!(
            std::fs::read_to_string(dir.join("zap.lock")).expect("lock"),
            generated.lock
        );
        let lib = staged.root.join("src/lib/zap.ts");
        assert!(lib.is_file());
        assert!(!lib.is_symlink());
        assert!(!staged.root.join("src").is_symlink());
        assert_eq!(
            std::fs::read_to_string(staged.root.join("package.json")).expect("package.json"),
            STAGE_PACKAGE_JSON
        );
        // the bootstrap-replace configs are staged too, each beside its toolchain lock
        assert!(staged.bootstrap_config("provision").is_file());
        assert_eq!(
            std::fs::read_to_string(
                staged
                    .bootstrap_config("provision")
                    .with_file_name("zap.lock")
            )
            .expect("lock"),
            generated.lock
        );
        assert_eq!(
            staged.bootstrap_keys_module(),
            staged.root.join(BOOTSTRAP_DIR).join("keys.ts")
        );
        // nothing is written into the repo's own fixtures
        assert!(!repo.path().join(FIXTURE_DIR).join("origin_ca.ts").exists());
    }

    /// The generated lock is one `zap` reads: version 2, the toolchain pin, no entry.
    #[test]
    fn the_toolchain_lock_pins_the_given_build_and_nothing_else() {
        let pin = "a".repeat(64);
        let value: serde_json::Value = serde_json::from_str(&toolchain_lock(&pin)).expect("json");
        assert_eq!(
            value,
            serde_json::json!({"version": 2, "toolchain": {"fgro_blake3": pin}, "entries": {}})
        );
    }

    /// A base is evaluated by one `fgro` build: another builds a different base.
    #[test]
    fn the_base_hash_names_the_fgro_build() {
        let repo = repo();
        let bin = repo.path().join("zap");
        std::fs::write(&bin, b"binary").expect("write");
        let hash = |fgro| {
            base_hash(
                repo.path(),
                ("oracle", &bin),
                "pins",
                "t0",
                "prepare",
                "ca",
                fgro,
            )
            .expect("hash")
        };
        assert_eq!(hash("f1"), hash("f1"));
        assert_ne!(hash("f1"), hash("f2"));
    }

    /// The stage's `package.json` names the tree, which is what makes it a project
    /// rather than a type marker zap's walk passes over.
    #[test]
    fn the_stage_package_json_is_more_than_a_type_marker() {
        let value: serde_json::Value = serde_json::from_str(STAGE_PACKAGE_JSON).expect("json");
        let object = value.as_object().expect("an object");
        assert!(
            object
                .keys()
                .any(|key| key != "type" && key != "sideEffects")
        );
        assert_eq!(object["name"], "zap-differential-stage");
    }

    /// A run directory is named for its process; a dead process's is swept by the
    /// next run, a live one's is kept, and the guard removes its own.
    #[test]
    fn run_dirs_are_swept_when_their_process_is_gone() {
        let runs = tempfile::tempdir().expect("tempdir");
        // pid 0 is never a process under /proc
        let dead = runs.path().join("0-stale");
        let live = runs.path().join(format!("{}-other", std::process::id()));
        let unrelated = runs.path().join("keep-me");
        for dir in [&dead, &live, &unrelated] {
            std::fs::create_dir_all(dir).expect("mkdir");
        }
        let run = create_run_dir(runs.path()).expect("run dir");
        assert!(!dead.exists());
        assert!(live.exists());
        assert!(unrelated.exists());
        let name = run
            .path()
            .file_name()
            .and_then(|n| n.to_str())
            .expect("name");
        assert!(name.starts_with(&format!("{}-", std::process::id())));
        let path = run.path().to_path_buf();
        drop(run);
        assert!(!path.exists());
    }

    /// The kitchen sinks import the generated CA module; the local fixture, whose
    /// bundle carries none, does not.
    #[test]
    fn only_the_ssh_fixtures_import_the_ca() {
        let common = include_str!("../../fixtures/differential/common.ts");
        assert!(common.contains("import { ORIGIN_CA_PEM } from './origin_ca.ts';"));
        let local = include_str!("../../fixtures/differential/debian-local/zap.ts");
        assert!(!local.contains("origin_ca"));
        assert!(!local.contains("ZAPDIFF_ORIGIN"));
    }
}
