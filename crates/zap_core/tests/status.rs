//! Tests for `zap status` (the last run, offline).
//!
//! The bulk are eval-free goldens over `build_status_report` / `render_status`
//! (construct a config + an in-memory last-run report, assert the join, the exit code,
//! and the render). The end-to-end tests exercise `run_detect_in` → `run_status_in` with
//! `~/.zap` pointed at a tempdir (injected, not via `ZAP_HOME` — `set_var` is `unsafe`,
//! forbidden workspace-wide) and so need `fgro`; they skip cleanly without `ZAP_FGRO`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;
mod scratch;

use std::path::Path;

use common::{fgro, fgro_available};
use zap_core::commands::status::{
    Standing, StatusReport, build_status_report, render_status, run_status_in,
};
use zap_core::home::{config_dir_for, config_slug, last_run_path_for};
use zap_core::last_run::report_var_with;
use zap_core::lock::LockStanding;
use zap_core::secret::{SecretMasker, SecretRegistry};
use zap_types::last_run::{
    LAST_RUN_VERSION, LastRun, ReportVar, ResourceRecord, RunCommand, Verdict, desired_hash,
    target_hash,
};
use zap_types::lock::{LockEntry, ZapLock};
use zap_types::scalar::ContentHash;
use zap_types::schema::{PackageManager, Resource, ResourceId, ServiceManager, Target, ZapConfig};
use zap_types::text::Text;
use zap_types::var_ref::Segment::{Ref, Text as Lit};

/// A directory resource at `/opt/<id>`.
fn dir(id: &str) -> Resource {
    serde_json::from_value(serde_json::json!({
        "id": id, "type": "directory", "path": format!("/opt/{id}"),
    }))
    .unwrap()
}

/// A masker with nothing registered.
fn no_secrets() -> SecretMasker {
    SecretRegistry::new().freeze().unwrap()
}

/// A masker holding one secret.
fn masking(name: &str, value: &str) -> SecretMasker {
    let mut registry = SecretRegistry::new();
    registry.register(name, value);
    registry.freeze().unwrap()
}

/// The report resolver for `config` over a fixed env — hermetic.
fn var_over<'a>(
    config: &ZapConfig,
    masker: &'a SecretMasker,
    env: &'a [(&'a str, &'a str)],
) -> impl Fn(&str) -> ReportVar + use<'a> {
    report_var_with(config, masker, move |name| {
        env.iter()
            .find(|(key, _)| *key == name)
            .map(|(_, value)| (*value).to_owned())
    })
}

/// A clean lock standing — the goldens below are about the report join, not the ledger.
fn clean() -> LockStanding {
    LockStanding::default()
}

fn config(resources: Vec<Resource>) -> ZapConfig {
    ZapConfig {
        target: Target {
            package_manager: Some(PackageManager::Apt),
            service_manager: Some(ServiceManager::Systemd),
            ..Target::local()
        },
        resources,
        ..ZapConfig::default()
    }
}

/// A report whose records are `(resource, verdict)`, each hashed as the resource is now
/// under `env` and `masker`, read against [`config`]'s target.
fn report_under(
    records: &[(&Resource, Verdict)],
    env: &[(&str, &str)],
    masker: &SecretMasker,
) -> LastRun {
    let var = var_over(&ZapConfig::default(), masker, env);
    LastRun {
        version: LAST_RUN_VERSION,
        ran_at: "2026-09-28T12:00:00Z".to_owned(),
        command: RunCommand::Plan,
        host: "local".to_owned(),
        target_hash: Some(target_hash(&config(Vec::new()).target, &var).unwrap()),
        unverifiable: Vec::new(),
        plan_hash: None,
        resources: records
            .iter()
            .map(|(resource, verdict)| {
                let hashed = desired_hash(resource, &var, None).unwrap();
                (
                    resource.id.clone(),
                    ResourceRecord {
                        verdict: *verdict,
                        desired_hash: Some(hashed.hash),
                        references_secret: hashed.references_secret,
                    },
                )
            })
            .collect(),
        batches: Vec::new(),
    }
}

fn report(records: &[(&Resource, Verdict)]) -> LastRun {
    report_under(records, &[], &no_secrets())
}

fn status_under(
    config: &ZapConfig,
    last_run: Option<&LastRun>,
    standing: LockStanding,
    env: &[(&str, &str)],
    masker: &SecretMasker,
) -> StatusReport {
    build_status_report(
        config,
        last_run,
        None,
        standing,
        Vec::new(),
        var_over(config, masker, env),
    )
}

fn status(config: &ZapConfig, last_run: Option<&LastRun>, standing: LockStanding) -> StatusReport {
    status_under(config, last_run, standing, &[], &no_secrets())
}

fn standing_of(report: &StatusReport, id: &str) -> Standing {
    report
        .resources
        .iter()
        .find(|r| r.id.0 == id)
        .unwrap_or_else(|| panic!("no line for {id}"))
        .standing
}

/// Every declared resource read converged, unchanged since: exit 0, and the render says
/// when, by what, and what the 0 claims.
#[test]
fn an_all_converged_last_run_exits_zero() {
    let (a, b) = (dir("a"), dir("b"));
    let config = config(vec![a.clone(), b.clone()]);
    let run = report(&[(&a, Verdict::Converged), (&b, Verdict::Converged)]);
    let report = status(&config, Some(&run), clean());
    assert_eq!(
        standing_of(&report, "a"),
        Standing::Read(Verdict::Converged)
    );
    assert_eq!(report.exit_code(), 0);

    let rendered = render_status(&report);
    assert!(
        rendered.contains("last run on local: zap plan, at 2026-09-28T12:00:00Z"),
        "{rendered}"
    );
    assert!(
        rendered.contains("not that the target still is"),
        "{rendered}"
    );
    assert!(
        rendered.contains("  converged    a  directory\n"),
        "{rendered}"
    );
}

/// Drift and absence read in the last run are established: exit 2.
#[test]
fn a_drifted_or_absent_verdict_exits_two() {
    let (a, b, c) = (dir("a"), dir("b"), dir("c"));
    let config = config(vec![a.clone(), b.clone(), c.clone()]);
    let run = report(&[
        (&a, Verdict::Converged),
        (&b, Verdict::Drifted),
        (&c, Verdict::Absent),
    ]);
    let report = status(&config, Some(&run), clean());
    assert_eq!(standing_of(&report, "b"), Standing::Read(Verdict::Drifted));
    assert_eq!(standing_of(&report, "c"), Standing::Read(Verdict::Absent));
    assert_eq!(report.exit_code(), 2);
    let rendered = render_status(&report);
    assert!(
        rendered.contains("  drifted      b  directory\n"),
        "{rendered}"
    );
    assert!(
        rendered.contains("  absent       c  directory\n"),
        "{rendered}"
    );
}

/// An undetermined verdict establishes nothing: exit 1, outranking a sibling's drift.
#[test]
fn an_undetermined_verdict_exits_one_over_drift() {
    let (a, b) = (dir("a"), dir("b"));
    let config = config(vec![a.clone(), b.clone()]);
    let run = report(&[(&a, Verdict::Drifted), (&b, Verdict::Undetermined)]);
    let report = status(&config, Some(&run), clean());
    assert_eq!(
        standing_of(&report, "b"),
        Standing::Read(Verdict::Undetermined)
    );
    assert_eq!(report.exit_code(), 1);
    assert!(render_status(&report).contains("  undetermined b  directory\n"));
}

/// A resource edited since the run keeps its old verdict, flagged — and a converged
/// verdict for a config that no longer exists is no claim at all: exit 1.
#[test]
fn a_resource_changed_since_the_run_is_flagged_and_exits_one() {
    let a = dir("a");
    let run = report(&[(&a, Verdict::Converged)]);
    let edited: Resource = serde_json::from_value(serde_json::json!({
        "id": "a", "type": "directory", "path": "/opt/a", "mode": "700",
    }))
    .unwrap();
    let report = status(&config(vec![edited]), Some(&run), clean());
    assert_eq!(
        standing_of(&report, "a"),
        Standing::ChangedSince(Verdict::Converged)
    );
    assert_eq!(report.exit_code(), 1);
    let rendered = render_status(&report);
    assert!(
        rendered.contains("  converged    a  directory  — config changed since"),
        "{rendered}"
    );
}

/// A recorded hash that couldn't be computed can't vouch for the resource.
#[test]
fn a_missing_recorded_hash_reads_as_changed_since() {
    let a = dir("a");
    let mut run = report(&[(&a, Verdict::Converged)]);
    run.resources
        .get_mut(&ResourceId("a".to_owned()))
        .unwrap()
        .desired_hash = None;
    let report = status(&config(vec![a]), Some(&run), clean());
    assert_eq!(
        standing_of(&report, "a"),
        Standing::ChangedSince(Verdict::Converged)
    );
}

/// A report filed for another host is no last run for this one.
#[test]
fn a_report_for_another_host_is_not_this_hosts_last_run() {
    let a = dir("a");
    let mut run = report(&[(&a, Verdict::Converged)]);
    run.host = "elsewhere.example.com".to_owned();
    let report = status(&config(vec![a]), Some(&run), clean());
    assert_eq!(standing_of(&report, "a"), Standing::NotInLastRun);
    assert_eq!(report.exit_code(), 1);
}

/// A current-version report with no target hash can't vouch that the target is the one
/// read, so every verdict predates it.
#[test]
fn a_missing_target_hash_reads_every_verdict_as_changed_since() {
    let (a, b) = (dir("a"), dir("b"));
    let mut run = report(&[(&a, Verdict::Converged), (&b, Verdict::Drifted)]);
    run.target_hash = None;
    let report = status(&config(vec![a, b]), Some(&run), clean());
    assert_eq!(
        standing_of(&report, "a"),
        Standing::ChangedSince(Verdict::Converged)
    );
    assert_eq!(
        standing_of(&report, "b"),
        Standing::ChangedSince(Verdict::Drifted)
    );
    assert_eq!(report.exit_code(), 1);
}

/// The on-disk lock pin folds into the recompute: a pin advanced since the run reads
/// changed since, the pin the run read against reads as read.
#[test]
fn a_lock_pin_advanced_since_the_run_reads_changed_since() {
    let file: Resource = serde_json::from_value(serde_json::json!({
        "id": "zig", "type": "file", "path": "/opt/zig",
        "content": {"type": "remote", "url": "https://x/zig.tar.xz",
                    "extract": {"type": "tar.xz"}},
    }))
    .unwrap();
    let lock = |pin: char| ZapLock {
        entries: [(
            ResourceId("zig".to_owned()),
            LockEntry::RemoteFile {
                config_hash: String::new(),
                blake3: ContentHash::new(pin.to_string().repeat(64)).unwrap(),
            },
        )]
        .into(),
        toolchain: common::toolchain(),
        ..ZapLock::default()
    };
    let config = config(vec![file.clone()]);
    let masker = no_secrets();
    let then = lock('a');
    let mut run = report(&[(&file, Verdict::Converged)]);
    run.resources
        .get_mut(&ResourceId("zig".to_owned()))
        .unwrap()
        .desired_hash = Some(
        desired_hash(
            &file,
            var_over(&config, &masker, &[]),
            then.entries.values().next(),
        )
        .unwrap()
        .hash,
    );
    let status_with = |lock: &ZapLock| {
        build_status_report(
            &config,
            Some(&run),
            Some(lock),
            clean(),
            Vec::new(),
            var_over(&config, &masker, &[]),
        )
    };
    assert_eq!(
        standing_of(&status_with(&then), "zig"),
        Standing::Read(Verdict::Converged)
    );
    assert_eq!(
        standing_of(&status_with(&lock('b')), "zig"),
        Standing::ChangedSince(Verdict::Converged)
    );
}

/// A resource declared since the run isn't in it: exit 1, even beside drift.
#[test]
fn a_resource_not_in_the_last_run_exits_one() {
    let (a, added) = (dir("a"), dir("added"));
    let run = report(&[(&a, Verdict::Drifted)]);
    let report = status(&config(vec![a, added]), Some(&run), clean());
    assert_eq!(standing_of(&report, "added"), Standing::NotInLastRun);
    assert_eq!(report.exit_code(), 1);
    assert!(
        render_status(&report).contains("  not read     added  directory  — not in the last run")
    );
}

/// A resource the run read that is no longer declared is an orphan — listed, but
/// warn-only (it can't make the declared set unestablished), matching `lock --check`.
#[test]
fn an_orphan_is_listed_but_does_not_change_the_exit_code() {
    let (a, gone) = (dir("a"), dir("gone"));
    let run = report(&[(&a, Verdict::Converged), (&gone, Verdict::Drifted)]);
    let report = status(&config(vec![a]), Some(&run), clean());
    assert_eq!(
        standing_of(&report, "gone"),
        Standing::Orphaned(Verdict::Drifted)
    );
    // Declared first, orphans after.
    assert_eq!(report.resources.last().unwrap().id.0, "gone");
    assert_eq!(report.exit_code(), 0);
    let rendered = render_status(&report);
    assert!(
        rendered.contains("  orphaned     gone  — read drifted, no longer declared"),
        "{rendered}"
    );
}

/// No last run: every declared resource is unread, exit 1 — and an empty config has
/// nothing unestablished, exit 0.
#[test]
fn no_last_run_exits_one_unless_nothing_is_declared() {
    let report = status(&config(vec![dir("a")]), None, clean());
    assert_eq!(standing_of(&report, "a"), Standing::NotInLastRun);
    assert_eq!(report.exit_code(), 1);
    let rendered = render_status(&report);
    assert!(rendered.contains("no last run on local"), "{rendered}");
    assert!(
        rendered.contains("  not read     a  directory"),
        "{rendered}"
    );

    assert_eq!(status(&config(Vec::new()), None, clean()).exit_code(), 0);
}

/// A target whose host doesn't resolve can't name its report, and says why.
#[test]
fn an_unresolved_host_says_why_there_is_no_last_run() {
    let mut cfg = config(vec![dir("a")]);
    cfg.target = serde_json::from_value(serde_json::json!({
        "host": Text::reference("ZAP_TEST_UNSET_HOST"), "user": "deploy",
    }))
    .unwrap();
    let run = report(&[(&dir("a"), Verdict::Converged)]);
    let report = status(&cfg, Some(&run), clean());
    assert!(report.host.is_none());
    assert!(
        report.last_run.is_none(),
        "a report for another host isn't this one"
    );
    assert_eq!(report.exit_code(), 1);
    let rendered = render_status(&report);
    assert!(
        rendered.contains("the target names no host here")
            && rendered.contains("references a variable that is unset or empty"),
        "{rendered}"
    );
}

/// A lock problem exits 1 on its own, over an otherwise converged run, and leads the
/// render with the lock's banner and fix.
#[test]
fn a_lock_standing_error_exits_one_on_its_own() {
    let a = dir("a");
    let run = report(&[(&a, Verdict::Converged)]);
    let standing = LockStanding {
        stale: vec!["ghostty".to_owned()],
        ..LockStanding::default()
    };
    let report = status(&config(vec![a]), Some(&run), standing);
    assert_eq!(report.exit_code(), 1);
    let rendered = render_status(&report);
    assert!(
        rendered.starts_with(
            "  LOCK — the pin ledger does not answer for 1 resource(s), so they are withheld \
             from the comparison below:\n      ghostty — stale: "
        ),
        "{rendered}"
    );
    assert!(rendered.contains("zap update ghostty"), "{rendered}");
}

/// The ranking, whole: unestablished (1) outranks drift (2) outranks converged (0);
/// orphans never move it.
#[test]
fn the_exit_code_ranks_unestablished_over_drift_over_converged() {
    let (a, b) = (dir("a"), dir("b"));
    let cfg = config(vec![a.clone(), b.clone()]);
    let code = |records: &[(&Resource, Verdict)]| {
        status(&cfg, Some(&report(records)), clean()).exit_code()
    };
    assert_eq!(
        code(&[(&a, Verdict::Converged), (&b, Verdict::Converged)]),
        0
    );
    assert_eq!(code(&[(&a, Verdict::Converged), (&b, Verdict::Absent)]), 2);
    assert_eq!(
        code(&[(&a, Verdict::Drifted), (&b, Verdict::Undetermined)]),
        1
    );
    // `b` not in the run.
    assert_eq!(code(&[(&a, Verdict::Drifted)]), 1);
}

/// A run that couldn't resolve a reference compared against empty strings: its
/// converged verdicts aren't evidence, so `status` exits 1 under the banner — even with
/// every hash matching (an unset var resolves empty on both sides).
#[test]
fn an_unverifiable_last_run_exits_one() {
    let a = dir("a");
    let mut run = report(&[(&a, Verdict::Converged)]);
    run.unverifiable = vec!["ZAP_PROBE_APP".to_owned()];
    let report = status(&config(vec![a]), Some(&run), clean());
    assert_eq!(
        standing_of(&report, "a"),
        Standing::Read(Verdict::Converged)
    );
    assert_eq!(report.exit_code(), 1);
    let rendered = render_status(&report);
    assert!(
        rendered.starts_with("  UNVERIFIABLE — the last run couldn't resolve 1"),
        "{rendered}"
    );
    assert!(rendered.contains("ZAP_PROBE_APP"), "{rendered}");
}

/// A reference unset *here* can't establish "unchanged since" either: exit 1, under the
/// comparing commands' own banner.
#[test]
fn an_unverifiable_status_env_exits_one() {
    let a = dir("a");
    let run = report(&[(&a, Verdict::Converged)]);
    let cfg = config(vec![a]);
    let report = build_status_report(
        &cfg,
        Some(&run),
        None,
        clean(),
        vec!["ZAP_PROBE_APP".to_owned()],
        var_over(&cfg, &no_secrets(), &[]),
    );
    assert_eq!(report.exit_code(), 1);
    assert!(render_status(&report).contains("UNVERIFIABLE — 1 referenced variable(s)"));
}

/// A changed non-secret value — here in a `script`'s `check`, a field the lock's
/// `config_hash` doesn't resolve — reads "config changed since".
#[test]
fn a_changed_non_secret_value_reads_changed_since() {
    let script: Resource = serde_json::from_value(serde_json::json!({
        "id": "app", "type": "script",
        "check": Text::of_pieces([Lit("test \"$(app --version)\" = "), Ref("APP_VERSION")]),
        "run": "install-app",
    }))
    .unwrap();
    let cfg = config(vec![script.clone()]);
    let run = report_under(
        &[(&script, Verdict::Converged)],
        &[("APP_VERSION", "1.0")],
        &no_secrets(),
    );
    let same = status_under(
        &cfg,
        Some(&run),
        clean(),
        &[("APP_VERSION", "1.0")],
        &no_secrets(),
    );
    assert_eq!(
        standing_of(&same, "app"),
        Standing::Read(Verdict::Converged)
    );
    assert_eq!(same.exit_code(), 0);
    let bumped = status_under(
        &cfg,
        Some(&run),
        clean(),
        &[("APP_VERSION", "1.1")],
        &no_secrets(),
    );
    assert_eq!(
        standing_of(&bumped, "app"),
        Standing::ChangedSince(Verdict::Converged)
    );
    assert_eq!(bumped.exit_code(), 1);
}

/// A resource that references a secret reads unchanged whatever the secret's value, so
/// its line says so — and the exit-0 line doesn't claim more than it can.
#[test]
fn a_secret_bearing_resource_says_a_changed_value_isnt_visible() {
    let file: Resource = serde_json::from_value(serde_json::json!({
        "id": "env", "type": "file", "path": "/srv/app/.env",
        "content": {"type": "template", "template": "KEY={{key}}\n",
                    "vars": {"key": Text::reference("SECRET_APP_KEY")}},
    }))
    .unwrap();
    let cfg = config(vec![file.clone(), dir("plain")]);
    let run = report_under(
        &[
            (&file, Verdict::Converged),
            (&dir("plain"), Verdict::Converged),
        ],
        &[("SECRET_APP_KEY", "one")],
        &no_secrets(),
    );
    let report = status_under(
        &cfg,
        Some(&run),
        clean(),
        &[("SECRET_APP_KEY", "two")],
        &no_secrets(),
    );
    assert_eq!(
        standing_of(&report, "env"),
        Standing::Read(Verdict::Converged)
    );
    assert_eq!(report.exit_code(), 0);
    let rendered = render_status(&report);
    assert!(
        rendered.contains(
            "  converged    env  file  — depends on a secret; a changed value isn't visible offline"
        ),
        "{rendered}"
    );
    assert!(
        rendered.contains("unchanged since (a changed secret value excepted)"),
        "{rendered}"
    );
    assert!(!rendered.contains("plain  directory  —"), "{rendered}");
}

/// A changed target — here the package manager — makes every verdict predate it: every
/// read resource is "config changed since", exit 1, under a note naming the target.
#[test]
fn a_changed_target_makes_every_verdict_predate_it() {
    let (a, b) = (dir("a"), dir("b"));
    let run = report(&[(&a, Verdict::Converged), (&b, Verdict::Converged)]);
    let mut cfg = config(vec![a, b]);
    assert_eq!(status(&cfg, Some(&run), clean()).exit_code(), 0);
    cfg.target.package_manager = Some(PackageManager::Apk);
    let report = status(&cfg, Some(&run), clean());
    assert!(report.target_changed);
    assert_eq!(
        standing_of(&report, "a"),
        Standing::ChangedSince(Verdict::Converged)
    );
    assert_eq!(
        standing_of(&report, "b"),
        Standing::ChangedSince(Verdict::Converged)
    );
    assert_eq!(report.exit_code(), 1);
    assert!(
        render_status(&report).contains("the target (`zap.target`) changed since the last run"),
        "{}",
        render_status(&report)
    );
}

/// A secret carried inside another variable's value (connection parameters holding the
/// password) is masked out of the recorded hash — so `status` needs the secret too, to
/// mask it the same way. Without it the recompute differs and the resource reads
/// "config changed since": fail-closed, never a false "unchanged".
#[test]
fn a_status_run_without_the_secret_reads_changed_since() {
    let script: Resource = serde_json::from_value(serde_json::json!({
        "id": "db", "type": "script",
        "check": Text::of_pieces([Lit("psql "), Ref("PG_CONNECTION"), Lit(" -c 'select 1'")]),
        "run": "true",
    }))
    .unwrap();
    let cfg = config(vec![script.clone()]);
    let env = [("PG_CONNECTION", "host=db user=app password=hunter2")];
    let secret = masking("SECRET_DB_PASSWORD", "hunter2");
    let run = report_under(&[(&script, Verdict::Converged)], &env, &secret);
    let with = status_under(&cfg, Some(&run), clean(), &env, &secret);
    assert_eq!(standing_of(&with, "db"), Standing::Read(Verdict::Converged));
    assert!(with.resources[0].references_secret);
    let without = status_under(&cfg, Some(&run), clean(), &env, &no_secrets());
    assert_eq!(
        standing_of(&without, "db"),
        Standing::ChangedSince(Verdict::Converged)
    );
}

/// A variable whose value has a credential's form (a URL holding a password) is a
/// secret itself: the recorded hash holds its token, so `status` recomputes it from
/// that variable alone, and a changed password doesn't read as a changed config.
/// Without the variable there is no form to read, and the resource reads "config
/// changed since".
#[test]
fn a_value_shaped_secret_is_recorded_as_its_token() {
    let script: Resource = serde_json::from_value(serde_json::json!({
        "id": "db", "type": "script",
        "check": Text::of_pieces([Lit("psql "), Ref("DATABASE_URL"), Lit(" -c 'select 1'")]),
        "run": "true",
    }))
    .unwrap();
    let cfg = config(vec![script.clone()]);
    let env = [("DATABASE_URL", "postgres://app:hunter2@db/app")];
    let run = report_under(&[(&script, Verdict::Converged)], &env, &no_secrets());
    for now in [env, [("DATABASE_URL", "postgres://app:rotated@db/app")]] {
        let status = status_under(&cfg, Some(&run), clean(), &now, &no_secrets());
        assert_eq!(
            standing_of(&status, "db"),
            Standing::Read(Verdict::Converged)
        );
        assert!(status.resources[0].references_secret);
    }
    for now in [&[][..], &[("DATABASE_URL", "postgres://db/app")]] {
        let status = status_under(&cfg, Some(&run), clean(), now, &no_secrets());
        assert_eq!(
            standing_of(&status, "db"),
            Standing::ChangedSince(Verdict::Converged)
        );
    }
}

#[test]
fn config_slug_is_stable_and_path_specific() {
    // Pure — no fs: `config_slug` takes an already-absolute path.
    let a = Path::new("/home/x/proj/zap.ts");
    assert_eq!(config_slug(a), config_slug(a), "same path → same slug");
    assert!(
        config_slug(a).starts_with("zap-"),
        "slug keeps the basename"
    );
    assert_ne!(
        config_slug(a),
        config_slug(Path::new("/home/x/proj/other.ts")),
        "different name → different slug"
    );
    assert_ne!(
        config_slug(a),
        config_slug(Path::new("/home/y/proj/zap.ts")),
        "same basename, different dir → no collision"
    );
}

/// Write a config with a converged directory and an absent one.
fn write_config(proj: &Path) -> std::path::PathBuf {
    let config_path = proj.join("zap.ts");
    let present = proj.join("present");
    std::fs::create_dir(&present).unwrap();
    scratch::write_config(
        &config_path,
        format!(
            r"
export default (zap) => {{
    zap.target({{local: true, package_manager: 'apt'}});
    zap.directory({{id: 'present', path: {present:?}}});
    zap.directory({{id: 'missing', path: {missing:?}}});
}};
",
            present = present.to_string_lossy(),
            missing = proj.join("missing").to_string_lossy(),
        ),
    )
    .unwrap();
    config_path
}

/// `detect` writes the last run; `status` reads it back offline with the verdicts it
/// recorded, the command, and an unchanged config.
#[tokio::test]
async fn status_reads_the_last_run_detect_wrote() {
    if !fgro_available() {
        eprintln!("skipping status_reads_the_last_run_detect_wrote: ZAP_FGRO not set");
        return;
    }
    let proj = scratch::tempdir().unwrap();
    let config_path = write_config(proj.path());
    let home = scratch::tempdir().unwrap();

    // Nothing run yet.
    let before = run_status_in(Some(home.path()), fgro(), &config_path)
        .await
        .unwrap();
    assert!(before.last_run.is_none());
    assert_eq!(before.exit_code(), 1);

    zap_core::commands::detect::run_detect_in(
        Some(home.path()),
        fgro(),
        &config_path,
        false,
        false,
    )
    .await
    .unwrap();
    let report = run_status_in(Some(home.path()), fgro(), &config_path)
        .await
        .unwrap();
    assert_eq!(report.host.as_deref(), Some("local"));
    assert_eq!(
        report.last_run.as_ref().unwrap().command,
        RunCommand::Detect
    );
    assert_eq!(
        standing_of(&report, "present"),
        Standing::Read(Verdict::Converged)
    );
    assert_eq!(
        standing_of(&report, "missing"),
        Standing::Read(Verdict::Absent)
    );
    assert_eq!(report.exit_code(), 2);
}

/// A file at the report's path that isn't a current-version report — another version, or
/// a per-host entry map beside it — reads as no last run, never as verdicts.
#[tokio::test]
async fn a_report_of_another_version_reads_as_no_last_run() {
    if !fgro_available() {
        eprintln!("skipping a_report_of_another_version_reads_as_no_last_run: ZAP_FGRO not set");
        return;
    }
    let proj = scratch::tempdir().unwrap();
    let config_path = write_config(proj.path());
    let home = scratch::tempdir().unwrap();

    // A converged-for-everything report, one version on.
    let path = last_run_path_for(home.path(), &config_path, "local");
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    let mut future = serde_json::json!({
        "version": LAST_RUN_VERSION + 1,
        "ran_at": "2026-09-28T12:00:00Z",
        "command": "plan",
        "host": "local",
        "target_hash": null,
        "unverifiable": [],
        "resources": {
            "present": {"verdict": "converged", "desired_hash": null, "references_secret": false},
            "missing": {"verdict": "converged", "desired_hash": null, "references_secret": false},
        },
        "batches": [],
    });
    std::fs::write(&path, serde_json::to_vec(&future).unwrap()).unwrap();
    // And a per-host entry map beside the report directory, claiming the same.
    std::fs::write(
        config_dir_for(home.path(), &config_path).join("local.json"),
        br#"{"present": {"config_hash": "h", "detection": {"outcome": "converged"},
                         "detected_at": "2026-05-24T18:03:00Z"}}"#,
    )
    .unwrap();

    let report = run_status_in(Some(home.path()), fgro(), &config_path)
        .await
        .unwrap();
    assert!(report.last_run.is_none());
    assert!(
        report
            .resources
            .iter()
            .all(|r| r.standing == Standing::NotInLastRun)
    );

    // The same file at the current version is read.
    future["version"] = serde_json::json!(LAST_RUN_VERSION);
    std::fs::write(&path, serde_json::to_vec(&future).unwrap()).unwrap();
    let report = run_status_in(Some(home.path()), fgro(), &config_path)
        .await
        .unwrap();
    assert!(report.last_run.is_some());
    // Its null hashes can't vouch for the resources.
    assert_eq!(
        standing_of(&report, "present"),
        Standing::ChangedSince(Verdict::Converged)
    );
}
