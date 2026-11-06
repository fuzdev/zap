//! End-to-end test for `run_plan_in` (fgro-gated).
//!
//! Mirrors the `detection` suite's e2e: evaluate a real `zap.ts`, detect against
//! the local machine with `~/.zap` pointed at a tempdir, and diff to a plan fact.
//! Checks nothing where `ZAP_FGRO` is unset (`required_programs.rs` fails there). The
//! pure plan-diff logic itself is covered by `zap_types`' hand-authored goldens;
//! this proves the eval → detect → diff wiring.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;
mod scratch;

use common::{fgro, fgro_available};
use zap_core::commands::plan::{render_plan, run_plan_in};
use zap_core::lock::{lock_path_for, write_zap_lock};
use zap_types::lock::{LockEntry, ZapLock};
use zap_types::plan::ChangeAction;
use zap_types::scalar::ContentHash;
use zap_types::schema::ResourceId;

#[tokio::test]
async fn run_plan_in_local_end_to_end() {
    if !fgro_available() {
        eprintln!("skipping run_plan_in_local_end_to_end: ZAP_FGRO not set");
        return;
    }
    let proj = scratch::tempdir().unwrap();
    let config_path = proj.path().join("zap.ts");
    // `/tmp` exists → converged → dropped from the fact; the bogus package is
    // surely absent → a create, fronted by the synthetic cache-update.
    scratch::write_config(
        &config_path,
        r"
export default (zap) => {
    zap.target({local: true, package_manager: 'apt'});
    zap.directory({id: 'tmp', name: 'tmp', path: '/tmp'});
    zap.pkg({id: 'definitely-not-installed-xyz', name: 'nope', from: {apt: 'definitely-not-installed-xyz'}});
};
",
    )
    .unwrap();

    let home = scratch::tempdir().unwrap();
    let report = run_plan_in(Some(home.path()), fgro(), &config_path, false, false)
        .await
        .expect("plan should succeed");

    assert_eq!(report.target, "local");
    assert!(report.plan_hash.hash().is_some_and(|hash| !hash.is_empty()));
    // The pass is recorded as `plan`'s last run.
    let last = zap_core::last_run::read_last_run(home.path(), &config_path, "local").unwrap();
    assert_eq!(last.command, zap_types::last_run::RunCommand::Plan);

    let ids: Vec<&str> = report
        .plan
        .changes
        .iter()
        .map(|c| c.resource_id.0.as_str())
        .collect();
    // Converged directory is absent; the package + its cache-update are present.
    assert!(
        !ids.contains(&"tmp"),
        "converged /tmp should be dropped: {ids:?}"
    );
    assert!(ids.contains(&"definitely-not-installed-xyz"), "{ids:?}");
    assert!(ids.contains(&"cache-update-apt"), "{ids:?}");

    let pkg = report
        .plan
        .changes
        .iter()
        .find(|c| c.resource_id.0 == "definitely-not-installed-xyz")
        .unwrap();
    assert_eq!(pkg.action, ChangeAction::Create);
}

/// A tracked remote file whose lock entry no longer answers for the config: `plan`
/// **validates** the ledger, withholds the stale pin, and the resource holds.
///
/// Without the withholding, the target still holds the old bytes and the stale pin still
/// matches them, so `plan` would print `(no changes — converged)` and exit 0 while
/// `apply` refuses the same config outright. A read-only role that can't be
/// trusted about "converged" is worse than one that says it doesn't know.
#[tokio::test]
async fn plan_over_a_stale_pin_withholds_it_and_does_not_claim_converged() {
    if !fgro_available() {
        eprintln!(
            "skipping plan_over_a_stale_pin_withholds_it_and_does_not_claim_converged: ZAP_FGRO not set"
        );
        return;
    }
    let proj = scratch::tempdir().unwrap();
    let config_path = proj.path().join("zap.ts");
    // A literal url, never dialed: `plan` does no network IO, and the pin is withheld
    // before any fetch could be considered.
    scratch::write_config(
        &config_path,
        r"
export default (zap) => {
    zap.target({local: true});
    zap.file({
        id: 'zig',
        path: '/opt/zig',
        content: {type: 'remote', url: 'https://forge.example/zig.tar.xz', extract: {type: 'none'}},
    });
};
",
    )
    .unwrap();

    // An on-disk entry whose config_hash deliberately doesn't match the config — the
    // shape a forgotten `zap update` after a version bump leaves behind.
    let mut lock = ZapLock {
        toolchain: common::toolchain(),
        ..ZapLock::default()
    };
    lock.entries.insert(
        ResourceId("zig".to_owned()),
        LockEntry::RemoteFile {
            config_hash: "deliberately-wrong".to_owned(),
            blake3: ContentHash::of_bytes(b"old-bytes"),
        },
    );
    write_zap_lock(&lock_path_for(&config_path), &lock).unwrap();

    let home = scratch::tempdir().unwrap();
    let report = run_plan_in(Some(home.path()), fgro(), &config_path, false, false)
        .await
        .expect("plan should succeed — a stale pin is a verdict, not an error");

    assert_eq!(report.lock_standing.stale, vec!["zig".to_owned()]);
    assert_eq!(report.held.len(), 1, "{:?}", report.held);
    assert!(report.plan.changes.is_empty(), "{:?}", report.plan.changes);
    assert_eq!(report.exit_code(), 1);

    let rendered = render_plan(&report);
    assert!(rendered.contains("LOCK —"), "{rendered}");
    assert!(rendered.contains("zap update zig"), "{rendered}");
    // The empty changeset must not claim convergence. ("neither converged nor drifted"
    // in the UNDETERMINED banner is the retraction, not the claim.)
    assert!(
        !rendered.contains("(no changes — converged)"),
        "an empty changeset must not read as converged here: {rendered}"
    );
    assert!(rendered.contains("see UNDETERMINED above"), "{rendered}");
}

/// The cold start: a tracked file with no pin holds and names the fix, and the
/// standing says *missing* rather than leaving the operator to infer it from a
/// detector's prose.
#[tokio::test]
async fn plan_cold_start_holds_a_missing_pin_and_names_the_fix() {
    if !fgro_available() {
        eprintln!(
            "skipping plan_cold_start_holds_a_missing_pin_and_names_the_fix: ZAP_FGRO not set"
        );
        return;
    }
    let proj = scratch::tempdir().unwrap();
    let config_path = proj.path().join("zap.ts"); // no adjacent zap.lock
    scratch::write_config(
        &config_path,
        r"
export default (zap) => {
    zap.target({local: true});
    zap.file({
        id: 'zig',
        path: '/opt/zig',
        content: {type: 'remote', url: 'https://forge.example/zig.tar.xz', extract: {type: 'none'}},
    });
};
",
    )
    .unwrap();

    let home = scratch::tempdir().unwrap();
    let report = run_plan_in(Some(home.path()), fgro(), &config_path, false, false)
        .await
        .expect("plan should succeed");

    assert_eq!(report.lock_standing.missing, vec!["zig".to_owned()]);
    assert_eq!(report.held.len(), 1, "{:?}", report.held);
    assert_eq!(report.exit_code(), 1);
    assert!(report.held[0].describe().contains("zap update zig"));
}
