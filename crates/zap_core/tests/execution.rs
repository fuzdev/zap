//! Execution tests (local apply).
//!
//! The acceptance bar is **idempotency**: a wetrun followed by a re-detect leaves
//! every resource `Converged`, so a second plan is empty. `wetrun_then_redetect_*`
//! proves that end-to-end against a real [`Connection::Local`] in a tempdir
//! (operator-owned paths — no `sudo`, no eval), exercising the native-fs executor
//! (directory / file / link) and a command-step kind (script) together.
//!
//! The `MockConnection` tests pin the command-step runner's ordering guarantees
//! (stop-on-first-failure, verify-aborts-the-plan) deterministically. A fgro-gated
//! e2e proves the full `run_apply_in` wiring (eval → detect → diff → execute).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;
mod scratch;

use std::collections::BTreeMap;

use common::{fgro, fgro_available, local_machine};
use zap_core::connection::{CommandOutput, Connection, MockConnection};
use zap_core::event::EventHandler;
use zap_core::resource::{Markers, detect_all, execute_plan};
use zap_types::detected::Detection;
use zap_types::event::ChangeOutcome;
use zap_types::last_run::RunCommand;
use zap_types::plan::{DiffInputs, Plan, diff};
use zap_types::schema::{Resource, ResourceId, Target};
use zap_types::text::Text;
use zap_types::var_ref::Segment::{Ref, Text as Lit};

fn res(json: serde_json::Value) -> Resource {
    serde_json::from_value(json).expect("valid resource json")
}

const fn local_target() -> Target {
    Target::local()
}

/// Pair `detect_all`'s positional outcomes back with their resource ids (what
/// `diff` consumes), mirroring the command cores.
fn by_id(resources: &[Resource], detections: Vec<Detection>) -> BTreeMap<ResourceId, Detection> {
    resources
        .iter()
        .map(|r| r.id.clone())
        .zip(detections)
        .collect()
}

/// All-`Absent` detections — every resource is a create. Used by the mock tests,
/// which drive execution directly rather than probing.
fn all_absent(resources: &[Resource]) -> BTreeMap<ResourceId, Detection> {
    resources
        .iter()
        .map(|r| (r.id.clone(), Detection::Absent))
        .collect()
}

const fn ok_output() -> CommandOutput {
    CommandOutput {
        success: true,
        code: 0,
        stdout: String::new(),
        stderr: String::new(),
    }
}

fn fail_output() -> CommandOutput {
    CommandOutput {
        success: false,
        code: 1,
        stdout: String::new(),
        stderr: "boom".to_owned(),
    }
}

/// A fresh host converges in one apply: a script whose `cwd` a `directory` it depends
/// on creates reads as not applied while the directory is missing (never held), the
/// directory is made first, the script's `run` then enters it — its `env` exported —
/// and a second detection finds nothing to do. Against a real local target.
#[tokio::test]
async fn a_script_whose_cwd_another_resource_creates_converges_in_one_apply() {
    let proj = scratch::tempdir().unwrap();
    let work = proj.path().canonicalize().unwrap().join("work");
    let work_path = work.to_string_lossy().into_owned();
    let resources = vec![
        res(serde_json::json!({
            "id": "s", "type": "script", "depends_on": ["dir"], "cwd": work_path,
            "env": {"ZAP_T_NAME": "it's applied"},
            "check": r#"test "$(cat marker)" = "$ZAP_T_NAME""#,
            "run": r#"printf '%s' "$ZAP_T_NAME" > marker"#,
        })),
        res(serde_json::json!({"id": "dir", "type": "directory", "path": work_path})),
    ];
    let conn = Connection::Local;
    let target = local_target();
    let home = scratch::tempdir().unwrap();
    let plan_now = || async {
        let detected = detect_all(
            &conn,
            &target,
            &resources,
            Some(home.path()),
            None,
            Markers::Skip,
        )
        .await
        .unwrap()
        .detections;
        diff(DiffInputs {
            resources: &resources,
            detected: &by_id(&resources, detected),
            target: &target,
            machine: &local_machine(),
            lock: None,
            pending: &BTreeMap::new(),
            var: &zap_types::last_run::ReportVar::unset,
        })
    };

    let first = plan_now().await;
    assert!(first.held.is_empty(), "nothing is held: {:?}", first.held);
    let order: Vec<&str> = first
        .plan
        .changes
        .iter()
        .map(|change| change.resource_id.0.as_str())
        .collect();
    assert_eq!(order, ["dir", "s"]);

    let outcomes = execute_plan(&conn, &first.plan, None, &EventHandler::Null)
        .await
        .outcomes;
    let failures: Vec<&ChangeOutcome> = outcomes.iter().filter(|o| o.is_failure()).collect();
    assert!(failures.is_empty(), "no change should fail: {failures:?}");
    assert_eq!(
        std::fs::read_to_string(work.join("marker")).unwrap(),
        "it's applied"
    );

    let second = plan_now().await;
    assert!(
        second.held.is_empty() && second.plan.changes.is_empty(),
        "{second:?}"
    );
}

/// The acceptance bar: wetrun → re-detect → all converged → empty plan, against a
/// real local target in a tempdir. Exercises directory + file + link (native-fs)
/// and script (command-step) together.
#[tokio::test]
async fn wetrun_then_redetect_is_idempotent() {
    let proj = scratch::tempdir().unwrap();
    let base = proj.path();
    let sub = base.join("sub");
    let file = sub.join("hello.txt");
    let link = base.join("link");
    let marker = base.join("marker");

    let p = |path: &std::path::Path| path.to_string_lossy().into_owned();
    let resources = vec![
        res(serde_json::json!({"id": "dir", "type": "directory", "path": p(&sub), "mode": "755"})),
        res(serde_json::json!({
            "id": "f", "type": "file", "path": p(&file),
            "content": {"type": "inline", "content": "hi\n"}, "depends_on": ["dir"],
        })),
        res(serde_json::json!({
            "id": "ln", "type": "link", "path": p(&link), "target": p(&file), "depends_on": ["f"],
        })),
        res(serde_json::json!({
            "id": "s", "type": "script",
            "check": format!("test -f {}", p(&marker)), "run": format!("touch {}", p(&marker)),
        })),
    ];

    let conn = Connection::Local;
    let target = local_target();
    let home = scratch::tempdir().unwrap();

    // First detect: nothing exists yet → the plan has every resource as a create.
    let detected = detect_all(
        &conn,
        &target,
        &resources,
        Some(home.path()),
        None,
        Markers::Skip,
    )
    .await
    .unwrap()
    .detections;
    let plan = diff(DiffInputs {
        resources: &resources,
        detected: &by_id(&resources, detected),
        target: &target,
        machine: &local_machine(),
        lock: None,
        pending: &BTreeMap::new(),
        var: &zap_types::last_run::ReportVar::unset,
    })
    .plan;
    assert_eq!(
        plan.changes.len(),
        4,
        "first plan creates all four: {plan:?}"
    );

    // Wetrun: execute. Every change must complete.
    let outcomes = execute_plan(&conn, &plan, None, &EventHandler::Null)
        .await
        .outcomes;
    let failures: Vec<&ChangeOutcome> = outcomes.iter().filter(|o| o.is_failure()).collect();
    assert!(failures.is_empty(), "no change should fail: {failures:?}");

    // Side effects actually landed.
    assert!(sub.is_dir(), "directory created");
    assert_eq!(std::fs::read_to_string(&file).unwrap(), "hi\n");
    assert_eq!(std::fs::read_link(&link).unwrap(), file);
    assert!(marker.exists(), "script ran");

    // Re-detect and diff again: a converged machine produces an empty plan.
    let redetected = detect_all(
        &conn,
        &target,
        &resources,
        Some(home.path()),
        None,
        Markers::Skip,
    )
    .await
    .unwrap()
    .detections;
    let plan2 = diff(DiffInputs {
        resources: &resources,
        detected: &by_id(&resources, redetected),
        target: &target,
        machine: &local_machine(),
        lock: None,
        pending: &BTreeMap::new(),
        var: &zap_types::last_run::ReportVar::unset,
    })
    .plan;
    assert!(
        plan2.changes.is_empty(),
        "second plan must be empty (idempotent), got: {:?}",
        plan2.changes
    );
}

/// A failed command-step change halts the plan: later changes are `Skipped`, not run
/// (the mock has no recording for the second command, so running it would error).
#[tokio::test]
async fn command_steps_stop_on_first_failure() {
    let resources = vec![
        res(serde_json::json!({"id": "a", "type": "script", "check": "false", "run": "cmd-a"})),
        res(serde_json::json!({
            "id": "b", "type": "script", "check": "false", "run": "cmd-b", "depends_on": ["a"],
        })),
    ];
    let target = local_target();
    let plan = diff(DiffInputs {
        resources: &resources,
        detected: &all_absent(&resources),
        target: &target,
        machine: &local_machine(),
        lock: None,
        pending: &BTreeMap::new(),
        var: &zap_types::last_run::ReportVar::unset,
    })
    .plan;

    // `cmd-a` fails; `cmd-b` is intentionally unrecorded — if it ran, the mock errors.
    let conn = Connection::Mock(MockConnection::new("mock").with("cmd-a", fail_output()));
    let outcomes = execute_plan(&conn, &plan, None, &EventHandler::Null)
        .await
        .outcomes;

    assert_eq!(outcomes.len(), 2);
    assert!(
        matches!(&outcomes[0], ChangeOutcome::Failed { resource_id, .. } if resource_id.0 == "a"),
        "first change failed: {:?}",
        outcomes[0]
    );
    assert!(
        matches!(&outcomes[1], ChangeOutcome::Skipped { resource_id, .. } if resource_id.0 == "b"),
        "second change skipped after the failure: {:?}",
        outcomes[1]
    );
}

/// Each change that ran is timed around its run, the one that failed included; one that
/// was skipped never ran and has no time. Against a real local target, whose commands
/// take as long as they say.
#[tokio::test]
async fn each_change_that_ran_is_timed_around_its_run() {
    let resources = vec![
        res(serde_json::json!({"id": "a", "type": "script", "check": "false", "run": "sleep 0.3"})),
        res(serde_json::json!({
            "id": "b", "type": "script", "check": "false", "run": "sleep 0.2; exit 3",
            "depends_on": ["a"],
        })),
        res(serde_json::json!({
            "id": "c", "type": "script", "check": "false", "run": "true", "depends_on": ["b"],
        })),
    ];
    let target = local_target();
    let plan = diff(DiffInputs {
        resources: &resources,
        detected: &all_absent(&resources),
        target: &target,
        machine: &local_machine(),
        lock: None,
        pending: &BTreeMap::new(),
        var: &zap_types::last_run::ReportVar::unset,
    })
    .plan;

    let executed = execute_plan(&Connection::Local, &plan, None, &EventHandler::Null).await;
    assert!(
        matches!(
            &executed.outcomes[..],
            [
                ChangeOutcome::Completed { .. },
                ChangeOutcome::Failed { .. },
                ChangeOutcome::Skipped { .. },
            ]
        ),
        "{:?}",
        executed.outcomes
    );
    let timed: Vec<(&str, std::time::Duration)> = executed
        .records
        .iter()
        .map(|record| (record.resource_id.0.as_str(), record.took))
        .collect();
    assert!(
        matches!(timed[..], [("a", a), ("b", b)]
            if a >= std::time::Duration::from_millis(300)
                && b >= std::time::Duration::from_millis(200)),
        "{timed:?}"
    );
}

/// All command steps succeeding completes the whole plan, in order.
#[tokio::test]
async fn command_steps_all_complete() {
    let resources = vec![
        res(serde_json::json!({"id": "a", "type": "script", "check": "false", "run": "cmd-a"})),
        res(serde_json::json!({
            "id": "b", "type": "script", "check": "false", "run": "cmd-b", "depends_on": ["a"],
        })),
    ];
    let target = local_target();
    let plan = diff(DiffInputs {
        resources: &resources,
        detected: &all_absent(&resources),
        target: &target,
        machine: &local_machine(),
        lock: None,
        pending: &BTreeMap::new(),
        var: &zap_types::last_run::ReportVar::unset,
    })
    .plan;

    let conn = Connection::Mock(
        MockConnection::new("mock")
            .with("cmd-a", ok_output())
            .with("cmd-b", ok_output()),
    );
    let outcomes = execute_plan(&conn, &plan, None, &EventHandler::Null)
        .await
        .outcomes;

    assert!(
        outcomes
            .iter()
            .all(|o| matches!(o, ChangeOutcome::Completed { .. })),
        "all complete: {outcomes:?}"
    );
}

/// Command steps resolve references before running. An unset var
/// resolves to empty (deterministic + hermetic — no `set_var`, which is forbidden),
/// and the mock is keyed on the *resolved* string, so a verbatim (unresolved) run
/// would miss the recording and error.
#[tokio::test]
async fn command_steps_resolve_env_var_references() {
    let resources = vec![res(serde_json::json!({
        "id": "a", "type": "script", "check": "false",
        "run": Text::of_pieces([
            Lit("echo ready-"),
            Ref("ZAP_DEFINITELY_UNSET_VAR_123"),
            Lit("-done"),
        ]),
    }))];
    let target = local_target();
    let plan = diff(DiffInputs {
        resources: &resources,
        detected: &all_absent(&resources),
        target: &target,
        machine: &local_machine(),
        lock: None,
        pending: &BTreeMap::new(),
        var: &zap_types::last_run::ReportVar::unset,
    })
    .plan;

    // Recorded under the resolved form (empty var collapses the marker).
    let conn = Connection::Mock(MockConnection::new("mock").with("echo ready--done", ok_output()));
    let outcomes = execute_plan(&conn, &plan, None, &EventHandler::Null)
        .await
        .outcomes;

    assert!(
        matches!(&outcomes[0], ChangeOutcome::Completed { .. }),
        "resolved command ran (an unresolved reference would miss the mock): {:?}",
        outcomes[0]
    );
}

/// A `verify` whose assertion fails fails the change and aborts the plan — the
/// safety-gate semantics (the failing command exits non-zero).
#[tokio::test]
async fn verify_failure_aborts_the_plan() {
    let resources = vec![
        res(serde_json::json!({
            "id": "gate", "type": "verify",
            "assertions": [{"type": "command", "run": "gate-check"}],
        })),
        res(serde_json::json!({
            "id": "after", "type": "script", "check": "false", "run": "cmd-after",
            "depends_on": ["gate"],
        })),
    ];
    let target = local_target();
    let plan = diff(DiffInputs {
        resources: &resources,
        detected: &all_absent(&resources),
        target: &target,
        machine: &local_machine(),
        lock: None,
        pending: &BTreeMap::new(),
        var: &zap_types::last_run::ReportVar::unset,
    })
    .plan;

    // The gate assertion command fails; `cmd-after` is unrecorded (must not run).
    let conn = Connection::Mock(MockConnection::new("mock").with("gate-check", fail_output()));
    let outcomes = execute_plan(&conn, &plan, None, &EventHandler::Null)
        .await
        .outcomes;

    assert_eq!(outcomes.len(), 2);
    assert!(
        matches!(&outcomes[0], ChangeOutcome::Failed { resource_id, .. } if resource_id.0 == "gate"),
        "verify gate failed: {:?}",
        outcomes[0]
    );
    assert!(
        matches!(&outcomes[1], ChangeOutcome::Skipped { .. }),
        "downstream change skipped: {:?}",
        outcomes[1]
    );
}

/// An empty plan executes to no outcomes (converged machine — nothing to do).
#[tokio::test]
async fn empty_plan_executes_to_nothing() {
    let conn = Connection::Mock(MockConnection::new("mock"));
    let plan = Plan {
        references: BTreeMap::new(),
        changes: Vec::new(),
        target: local_target(),
        machine: local_machine(),
    };
    let outcomes = execute_plan(&conn, &plan, None, &EventHandler::Null)
        .await
        .outcomes;
    assert!(outcomes.is_empty());
}

/// The command that wrote the config's last run on `local`.
fn last_command(home: &std::path::Path, config_path: &std::path::Path) -> RunCommand {
    zap_core::last_run::read_last_run(home, config_path, "local")
        .unwrap()
        .command
}

/// A wetrun's time covers what it ran once bound to its review: each change, and the
/// re-detect after them, whose check here takes as long as it says. A change's own time
/// is its run. Gated on `ZAP_FGRO` (config eval).
#[tokio::test]
async fn a_wetruns_time_covers_its_changes_and_the_re_detect() {
    use std::time::Duration;

    use zap_core::commands::apply::{ApplyOptions, run_apply_in};

    if !fgro_available() {
        eprintln!("skipping a_wetruns_time_covers_its_changes_and_the_re_detect: ZAP_FGRO not set");
        return;
    }
    let proj = scratch::tempdir().unwrap();
    let config_path = proj.path().join("zap.ts");
    let marker = proj.path().join("marker");
    scratch::write_config(
        &config_path,
        format!(
            r"
export default (zap) => {{
    zap.target({{local: true}});
    zap.script({{id: 'slow', check: 'sleep 0.3; test -f {marker}', run: 'sleep 0.2; touch {marker}'}});
}};
",
            marker = marker.display()
        ),
    )
    .unwrap();
    let home = scratch::tempdir().unwrap();
    let options = |wetrun| ApplyOptions {
        wetrun,
        ..ApplyOptions::default()
    };
    let dry = run_apply_in(Some(home.path()), fgro(), &config_path, options(false))
        .await
        .unwrap();
    assert_eq!(dry.run, None);
    let wet = run_apply_in(Some(home.path()), fgro(), &config_path, options(true))
        .await
        .unwrap();
    assert_eq!(
        wet.exit_code(),
        0,
        "{}",
        zap_core::commands::render_apply(&wet)
    );
    let run = wet.run.expect("an executed wetrun is timed");
    let [slow] = &run.changes[..] else {
        panic!("{run:?}")
    };
    assert_eq!(slow.resource_id.0, "slow");
    assert!(slow.took >= Duration::from_millis(200), "{run:?}");
    // the change's 0.2s and the re-detect's check, 0.3s
    assert!(run.total >= Duration::from_millis(500), "{run:?}");
    assert!(run.total >= slow.took, "{run:?}");
}

/// Full wiring through `run_apply_in`: dry-run shows a create, wetrun applies it, and
/// a second dry-run is converged (empty). Gated on `ZAP_FGRO` (config eval).
#[tokio::test]
async fn run_apply_in_local_end_to_end() {
    use zap_core::commands::apply::{ApplyOptions, run_apply_in};

    if !fgro_available() {
        eprintln!("skipping run_apply_in_local_end_to_end: ZAP_FGRO not set");
        return;
    }

    let proj = scratch::tempdir().unwrap();
    let config_path = proj.path().join("zap.ts");
    let managed = proj.path().join("managed");
    scratch::write_config(
        &config_path,
        format!(
            r"
export default (zap) => {{
    zap.target({{local: true}});
    zap.directory({{id: 'managed', name: 'managed dir', path: {path:?}, mode: '755'}});
}};
",
            path = managed.to_string_lossy()
        ),
    )
    .unwrap();

    let home = scratch::tempdir().unwrap();

    // Dry-run: the directory is absent → one pending create, exit code 2 (drift).
    let dry = run_apply_in(
        Some(home.path()),
        fgro(),
        &config_path,
        ApplyOptions::default(),
    )
    .await
    .unwrap();
    assert_eq!(dry.plan.changes.len(), 1, "{:?}", dry.plan.changes);
    assert!(!dry.wetrun);
    assert_eq!(dry.exit_code(), 2);
    assert!(!managed.exists(), "dry-run must not create anything");
    assert_eq!(last_command(home.path(), &config_path), RunCommand::Apply);

    // Wetrun: create it. No failures, exit 0.
    let wet = run_apply_in(
        Some(home.path()),
        fgro(),
        &config_path,
        ApplyOptions {
            wetrun: true,
            expect_plan: None,
            emit_json: true,
            no_lock: false,
            bootstrap: false,
            no_cache: false,
            prompt: None,
            progress: None,
        },
    )
    .await
    .unwrap();
    assert!(wet.wetrun);
    assert!(managed.is_dir(), "wetrun created the directory");
    // The post-apply re-detection confirms convergence — no residual, exit 0.
    assert!(wet.residual.is_empty(), "{:?}", wet.residual);
    assert_eq!(wet.exit_code(), 0);
    // Its re-detection is the last run, replacing the report of the pass before.
    let last = last_command(home.path(), &config_path);
    assert_eq!(last, RunCommand::ApplyAfterChanges);

    // Converged: a second dry-run is empty (idempotent), exit 0.
    let again = run_apply_in(
        Some(home.path()),
        fgro(),
        &config_path,
        ApplyOptions::default(),
    )
    .await
    .unwrap();
    assert!(
        again.plan.changes.is_empty(),
        "second apply must be converged: {:?}",
        again.plan.changes
    );
    assert_eq!(again.exit_code(), 0);
}

/// A wetrun executes only the plan that was reviewed. With nothing previewed on the host
/// it refuses (exit 2, nothing created), rendering the plan and recording that preview;
/// the next wetrun binds to it and executes. `--expect-plan` binds explicitly: a
/// mismatch refuses, the right hash executes with no prior preview at all.
#[tokio::test]
async fn apply_wetrun_executes_only_a_reviewed_plan() {
    use zap_core::commands::apply::{ApplyOptions, render_apply, run_apply_in};
    use zap_types::last_run::PlanUnreviewed;

    if !fgro_available() {
        eprintln!("skipping apply_wetrun_executes_only_a_reviewed_plan: ZAP_FGRO not set");
        return;
    }

    let proj = scratch::tempdir().unwrap();
    let config_path = proj.path().join("zap.ts");
    let managed = proj.path().join("managed");
    scratch::write_config(
        &config_path,
        format!(
            r"
export default (zap) => {{
    zap.target({{local: true}});
    zap.directory({{id: 'managed', name: 'managed dir', path: {path:?}, mode: '755'}});
}};
",
            path = managed.to_string_lossy()
        ),
    )
    .unwrap();
    let home = scratch::tempdir().unwrap();
    let wetrun = || ApplyOptions {
        wetrun: true,
        ..ApplyOptions::default()
    };

    // Nothing previewed yet: refused, nothing ran, and the refusal is itself the preview.
    let refused = run_apply_in(Some(home.path()), fgro(), &config_path, wetrun())
        .await
        .unwrap();
    assert_eq!(
        refused.refused,
        Some(PlanUnreviewed::NoPreview { prior: None }),
        "{refused:?}"
    );
    assert_eq!(refused.exit_code(), 2);
    assert!(refused.run.is_none());
    assert!(!refused.streamed(), "a refusal emits no event");
    assert!(!managed.exists(), "a refused wetrun must create nothing");
    assert_eq!(
        last_command(home.path(), &config_path),
        RunCommand::ApplyRefused
    );
    let rendered = render_apply(&refused);
    assert!(rendered.contains("(wetrun, refused)"), "{rendered}");
    assert!(rendered.contains("REFUSED"), "{rendered}");
    assert!(
        rendered.contains(&format!(
            "--expect-plan {}",
            refused.plan_hash.hash().unwrap()
        )),
        "{rendered}"
    );

    // The same plan again binds to that preview and executes.
    let wet = run_apply_in(Some(home.path()), fgro(), &config_path, wetrun())
        .await
        .unwrap();
    assert_eq!(wet.refused, None, "{wet:?}");
    assert_eq!(wet.exit_code(), 0);
    assert!(wet.streamed());
    assert!(managed.is_dir(), "the bound wetrun created the directory");

    // A `detect` pass previews no plan, so a wetrun after it can't bind — unless the
    // plan is empty, which needs no review (the directory is converged now).
    let _ = std::fs::remove_dir(&managed);
    zap_core::commands::detect::run_detect_in(
        Some(home.path()),
        fgro(),
        &config_path,
        false,
        false,
    )
    .await
    .unwrap();
    let after_detect = run_apply_in(Some(home.path()), fgro(), &config_path, wetrun())
        .await
        .unwrap();
    assert_eq!(
        after_detect.refused,
        Some(PlanUnreviewed::NoPreview {
            prior: Some(RunCommand::Detect)
        }),
        "{after_detect:?}"
    );
    assert!(!managed.exists());

    // An explicit hash binds alone: wrong → refused; right → executes with no preview.
    let wrong = run_apply_in(
        Some(home.path()),
        fgro(),
        &config_path,
        ApplyOptions {
            expect_plan: Some("not-the-plan".to_owned()),
            ..wetrun()
        },
    )
    .await
    .unwrap();
    assert_eq!(
        wrong.refused,
        Some(PlanUnreviewed::Expected {
            expected: "not-the-plan".to_owned()
        })
    );
    assert!(!managed.exists());
    let right = run_apply_in(
        Some(home.path()),
        fgro(),
        &config_path,
        ApplyOptions {
            expect_plan: refused.plan_hash.hash().map(str::to_owned),
            ..wetrun()
        },
    )
    .await
    .unwrap();
    assert_eq!(right.refused, None, "{right:?}");
    assert!(managed.is_dir());

    // `--expect-plan` on a dry run is a usage error: a dry run only previews.
    let dry = run_apply_in(
        Some(home.path()),
        fgro(),
        &config_path,
        ApplyOptions {
            expect_plan: refused.plan_hash.hash().map(str::to_owned),
            ..ApplyOptions::default()
        },
    )
    .await;
    assert!(
        matches!(dry, Err(zap_core::error::Error::ExpectPlanWithoutWetrun)),
        "{dry:?}"
    );
}

/// An `apply` dry run whose diff depends on an unset reference must report
/// **unverifiable** and exit 1 — not print a confident changeset with a footnote.
///
/// The changeset it computed is unsound in both directions: the desired content resolves
/// to the empty string, so the comparison can mask real drift (live already holds empty)
/// and manufacture false drift (live holds the real value). "Converged" and "drifted" are
/// both claims about the target, and neither was established.
#[tokio::test]
async fn apply_dry_run_reports_an_unverifiable_diff() {
    use zap_core::commands::apply::{ApplyOptions, render_apply, run_apply_in};

    if !fgro_available() {
        eprintln!("skipping apply_dry_run_reports_an_unverifiable_diff: ZAP_FGRO not set");
        return;
    }

    let proj = scratch::tempdir().unwrap();
    let config_path = proj.path().join("zap.ts");
    let managed = proj.path().join("app.env");
    scratch::write_config(
        &config_path,
        format!(
            r"
export default (zap) => {{
    zap.target({{local: true}});
    zap.file({{
        id: 'app-env',
        path: {path:?},
        content: {{
            type: 'template',
            template: 'SECRET={{{{secret}}}}',
            vars: {{secret: zap.env('ZAP_TEST_UNVERIFIABLE_SECRET')}},
        }},
    }});
}};
",
            path = managed.to_string_lossy()
        ),
    )
    .unwrap();
    let home = scratch::tempdir().unwrap();

    let report = run_apply_in(
        Some(home.path()),
        fgro(),
        &config_path,
        ApplyOptions::default(),
    )
    .await
    .unwrap();

    assert_eq!(
        report.unverifiable,
        vec!["ZAP_TEST_UNVERIFIABLE_SECRET".to_owned()]
    );
    // 1 (can't tell), not 2 (drifted) — even though the diff did produce a pending change.
    assert_eq!(report.exit_code(), 1, "{:?}", report.plan.changes);
    assert!(!managed.exists(), "a dry run must not create anything");

    // The verdict leads the report; it is not a trailing `warning:` line.
    let rendered = render_apply(&report);
    assert!(rendered.contains("UNVERIFIABLE"), "{rendered}");
    assert!(
        rendered.contains("ZAP_TEST_UNVERIFIABLE_SECRET"),
        "{rendered}"
    );
}

/// Text that spells a reference in a `file`'s inline content is the file's own text —
/// the content takes no reference: no pass resolves it, so an unset variable of that
/// name makes the dry run neither unverifiable nor a wetrun refused, and the file is
/// written holding the characters as declared.
// `{env:NAME}` is the notation a reference is shown in, written out here as text.
#[allow(clippy::literal_string_with_formatting_args)]
#[tokio::test]
async fn text_that_spells_a_reference_in_inline_content_is_written_as_it_is() {
    use zap_core::commands::apply::{ApplyOptions, render_apply, run_apply_in};

    if !fgro_available() {
        eprintln!("skipping the inline-content text test: ZAP_FGRO not set");
        return;
    }

    let proj = scratch::tempdir().unwrap();
    let config_path = proj.path().join("zap.ts");
    let managed = proj.path().join("app.env");
    scratch::write_config(
        &config_path,
        format!(
            r"
export default (zap) => {{
    zap.target({{local: true}});
    zap.file({{
        id: 'app-env',
        path: {path:?},
        content: {{type: 'inline',
            content: 'SECRET=$$ZAP_TEST_INLINE_UNSET_SECRET$$ {{env:ZAP_TEST_INLINE_UNSET_SECRET}}'}},
    }});
}};
",
            path = managed.to_string_lossy()
        ),
    )
    .unwrap();
    let home = scratch::tempdir().unwrap();

    let dry = run_apply_in(
        Some(home.path()),
        fgro(),
        &config_path,
        ApplyOptions::default(),
    )
    .await
    .unwrap();
    assert_eq!(dry.unverifiable, Vec::<String>::new());
    assert_eq!(dry.exit_code(), 2, "{:?}", dry.plan.changes);
    assert!(!render_apply(&dry).contains("UNVERIFIABLE"));

    let wet = run_apply_in(
        Some(home.path()),
        fgro(),
        &config_path,
        ApplyOptions {
            wetrun: true,
            ..ApplyOptions::default()
        },
    )
    .await
    .unwrap();
    assert_eq!(wet.exit_code(), 0, "{}", render_apply(&wet));
    assert_eq!(
        std::fs::read_to_string(&managed).unwrap(),
        "SECRET=$$ZAP_TEST_INLINE_UNSET_SECRET$$ {env:ZAP_TEST_INLINE_UNSET_SECRET}"
    );
}

/// An `apply` whose detection couldn't probe a resource must report **undetermined**
/// and exit 1 — on the dry run *and* the wetrun.
///
/// The observed-side twin of `apply_dry_run_reports_an_unverifiable_diff`. A held
/// resource is dropped from the changeset (a failed probe must never be read as
/// "absent" and created), which is correct but silent: the changeset came back empty,
/// rendered "(no changes — converged)", and exited 0, with the whole finding demoted to
/// a `warning:` line indistinguishable from "you have uncommitted changes". A wetrun was
/// worse still — "applied: 0 ok, 0 failed" and exit 0 about a target it never read.
#[tokio::test]
async fn apply_reports_an_undetermined_resource_on_both_run_modes() {
    use zap_core::commands::apply::{ApplyOptions, render_apply, run_apply_in};

    if !fgro_available() {
        eprintln!(
            "skipping apply_reports_an_undetermined_resource_on_both_run_modes: ZAP_FGRO not set"
        );
        return;
    }

    let proj = scratch::tempdir().unwrap();
    let config_path = proj.path().join("zap.ts");
    // A `service` on a target whose declared `service_manager` has no backend
    // (`launchd`): the detector can't probe it, so it reports `Undetermined` without
    // running a single command (which is what keeps this hermetic — no service manager
    // is touched). An *undeclared* manager is a structural-gate error, not a hold.
    scratch::write_config(
        &config_path,
        r"
export default (zap) => {
    zap.target({local: true, service_manager: 'launchd'});
    zap.service({id: 'unprobeable', service: 'nginx', enabled: true});
};
",
    )
    .unwrap();
    let home = scratch::tempdir().unwrap();

    let dry = run_apply_in(
        Some(home.path()),
        fgro(),
        &config_path,
        ApplyOptions::default(),
    )
    .await
    .unwrap();
    assert_eq!(dry.held.len(), 1, "{:?}", dry.held);
    assert_eq!(dry.held[0].resource_id.0, "unprobeable");
    assert!(
        dry.plan.changes.is_empty(),
        "a failed probe must not become a create: {:?}",
        dry.plan.changes
    );
    // 1 (can't tell), not 0 (converged) — the empty changeset is not evidence.
    assert_eq!(dry.exit_code(), 1);

    // The verdict leads the report; it is not a trailing `warning:` line.
    let rendered = render_apply(&dry);
    assert!(rendered.contains("UNDETERMINED"), "{rendered}");
    assert!(rendered.contains("unprobeable"), "{rendered}");
    assert!(
        !rendered.contains("warning: cannot determine"),
        "the hold must not double as a warning: {rendered}"
    );

    // A wetrun makes the stronger claim ("the target is now converged"), so it must not
    // exit 0 either — nothing was applied for the resource it couldn't read.
    let wet = run_apply_in(
        Some(home.path()),
        fgro(),
        &config_path,
        ApplyOptions {
            wetrun: true,
            ..ApplyOptions::default()
        },
    )
    .await
    .unwrap();
    assert_eq!(wet.held.len(), 1, "{:?}", wet.held);
    assert_eq!(wet.exit_code(), 1, "{:?}", wet.run);
}

/// A wetrun whose every command exits 0 can still leave a resource unconverged — the
/// canonical case is a `script` whose `check` still fails after `run`. `apply`
/// already re-detects after executing (for its last-run report); consuming that
/// re-detection is what turns "applied: N ok" from a command-success report into a
/// convergence claim: the non-converged remainder is the **residual** verdict, and
/// it exits 1.
#[tokio::test]
async fn apply_wetrun_reports_residual_when_a_completed_change_does_not_converge() {
    use zap_core::commands::apply::{ApplyOptions, render_apply, run_apply_in};

    if !fgro_available() {
        eprintln!(
            "skipping apply_wetrun_reports_residual_when_a_completed_change_does_not_converge: \
             ZAP_FGRO not set"
        );
        return;
    }

    let proj = scratch::tempdir().unwrap();
    let config_path = proj.path().join("zap.ts");
    // `run` always succeeds; `check` never passes — execution completes cleanly, but
    // the post-apply re-detection still reads the script absent.
    scratch::write_config(
        &config_path,
        r"
export default (zap) => {
    zap.target({local: true});
    zap.script({id: 'never-converges', name: 'never converges', check: 'false', run: 'true'});
};
",
    )
    .unwrap();
    let home = scratch::tempdir().unwrap();

    // The preview the wetrun binds to.
    run_apply_in(
        Some(home.path()),
        fgro(),
        &config_path,
        ApplyOptions::default(),
    )
    .await
    .unwrap();
    let wet = run_apply_in(
        Some(home.path()),
        fgro(),
        &config_path,
        ApplyOptions {
            wetrun: true,
            ..ApplyOptions::default()
        },
    )
    .await
    .unwrap();
    let summary = wet.run.as_ref().expect("wetrun has a summary").summary;
    assert_eq!(
        (summary.completed, summary.failed),
        (1, 0),
        "the change itself must succeed: {summary:?}"
    );
    assert_eq!(wet.residual.len(), 1, "{:?}", wet.residual);
    assert_eq!(wet.residual[0].resource_id.0, "never-converges");
    // "applied: 1 ok" with a non-converged post-state must not exit 0 — the wetrun's
    // claim is convergence, and the re-detection refuted it.
    assert_eq!(wet.exit_code(), 1);

    // The verdict is rendered as a banner naming the resource, not silently carried.
    let rendered = render_apply(&wet);
    assert!(
        rendered.contains(
            "\n  RESIDUAL — 1 resource does not read converged after this apply:\n      \
             never-converges — absent\n  its commands (if any) exited 0, but re-detection \
             did not confirm the declared state. inspect it (zap plan --diff) and re-run.\n"
        ),
        "{rendered}"
    );
}

/// Remote (vendored) `none` content: a real fetch over HTTP → verify the pin → copy
/// the bytes to the target file, end-to-end against a `Connection::Local`. The
/// throwaway one-shot HTTP server is dep-free (a std `TcpListener` on a worker
/// thread). `tar.xz` extraction is not covered here (it shells out to `tar`).
#[tokio::test]
async fn remote_none_vendored_fetches_verifies_and_writes_the_target() {
    use std::io::{Read, Write};

    let body = b"ghostty-binary-bytes".to_vec();
    let pin = blake3::hash(&body).to_hex().to_string();

    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let served = body.clone();
    std::thread::spawn(move || {
        if let Ok((mut sock, _)) = listener.accept() {
            let mut buf = [0u8; 1024];
            let _ = sock.read(&mut buf);
            let header = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                served.len()
            );
            let _ = sock.write_all(header.as_bytes());
            let _ = sock.write_all(&served);
            let _ = sock.flush();
        }
    });
    let url = format!("http://{addr}/ghostty");

    let home = scratch::tempdir().unwrap(); // content-cache root
    let dest_dir = scratch::tempdir().unwrap();
    let dest = dest_dir.path().join("ghostty");

    let resources = vec![res(serde_json::json!({
        "id": "ghostty", "type": "file", "path": dest.to_string_lossy(), "mode": "750",
        "content": {"type": "remote", "url": url, "blake3": pin, "extract": {"type": "none"}},
    }))];
    let plan = diff(DiffInputs {
        resources: &resources,
        detected: &all_absent(&resources),
        target: &local_target(),
        machine: &local_machine(),
        lock: None,
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
    .await
    .outcomes;
    assert!(
        outcomes.iter().all(|o| !o.is_failure()),
        "remote fetch+write must succeed: {outcomes:?}"
    );
    assert_eq!(std::fs::read(&dest).unwrap(), body);
    assert_eq!(
        std::os::unix::fs::MetadataExt::mode(&std::fs::metadata(&dest).unwrap()) & 0o7777,
        0o750,
        "the placed file carries its declared mode"
    );
}

/// A script source that fires a restart of the `app` service, planned with the source
/// absent and the service converged — so the service change exists only because of the
/// trigger. Returns the plan and the service change's `Run` commands.
fn triggered_restart_plan() -> (Plan, Vec<String>) {
    let resources = vec![
        res(serde_json::json!({"id": "src", "type": "script", "check": "false", "run": "cmd-src"})),
        res(serde_json::json!({
            "id": "svc", "type": "service", "service": "app", "enabled": true,
            "restart_on": ["src"],
        })),
    ];
    let mut target = local_target();
    target.service_manager = Some(zap_types::schema::ServiceManager::Systemd);
    let detected = BTreeMap::from([
        (ResourceId("src".to_owned()), Detection::Absent),
        (ResourceId("svc".to_owned()), Detection::Converged),
    ]);
    let plan = diff(DiffInputs {
        resources: &resources,
        detected: &detected,
        target: &target,
        machine: &local_machine(),
        lock: None,
        pending: &BTreeMap::new(),
        var: &zap_types::last_run::ReportVar::unset,
    })
    .plan;
    let service_steps = plan
        .changes
        .iter()
        .find(|change| change.resource_id.0 == "svc")
        .expect("the trigger promotes the service")
        .steps
        .iter()
        .filter_map(zap_types::plan::PlanStep::execution)
        .map(|execution| execution.text().to_owned())
        .collect();
    (plan, service_steps)
}

/// The plan for `resources`, all absent, on a systemd target.
fn absent_plan(resources: &[Resource]) -> Plan {
    let mut target = local_target();
    target.service_manager = Some(zap_types::schema::ServiceManager::Systemd);
    diff(DiffInputs {
        resources,
        detected: &all_absent(resources),
        target: &target,
        machine: &local_machine(),
        lock: None,
        pending: &BTreeMap::new(),
        var: &zap_types::last_run::ReportVar::unset,
    })
    .plan
}

/// A command that exits `code` having printed `stderr`.
fn exits(code: i32, stderr: &str) -> CommandOutput {
    CommandOutput {
        success: false,
        code,
        stdout: String::new(),
        stderr: stderr.to_owned(),
    }
}

/// A distinctive piece of each constant script a typed step runs, and of the feeder
/// around a put of a command's output: none of them is ever in what zap prints.
const SCRIPT_MARKS: [&str; 5] = [
    "/proc/self/fd/3",
    "mktemp -u ./.zap.XXXXXX",
    "sha512sum",
    "left unchanged\" >&2; exit 93",
    "zap_c=",
];

/// The commands a `user` with keys and a sudo grant runs.
struct UserCommands {
    useradd: &'static str,
    home_owner: &'static str,
    dir: String,
    keys_put: String,
    unlock: &'static str,
    sudoers_put: String,
}

fn user_commands() -> (Plan, UserCommands) {
    use zap_types::put::{FileAttrs, PutCheck, RunAs, dir_attrs_command, file_put_command};

    let plan = absent_plan(&[res(serde_json::json!({
        "id": "u", "type": "user", "username": "deploy",
        "ssh_keys": {"keys": ["ssh-ed25519 AAAA deploy@host"]},
        "sudo": "nopasswd",
    }))]);
    let commands = UserCommands {
        useradd: "id -u -- 'deploy' >/dev/null 2>&1 || sudo useradd -m -d '/home/deploy' -- 'deploy'",
        // an absent account's home is nothing or root's: given to the user either way
        home_owner: "sudo chown -h -- 'deploy:' '/home/deploy'",
        dir: format!(
            "sudo mkdir -p -- '/home/deploy/.ssh' && {}",
            dir_attrs_command(
                RunAs::Root,
                "/home/deploy/.ssh",
                FileAttrs {
                    mode: Some("700"),
                    owner: Some("deploy"),
                    group: Some("deploy"),
                    ..FileAttrs::NONE
                },
            )
        ),
        // The puts run as the plan says — the account, root — and with the plan's
        // check, on a mock as on any connection.
        keys_put: file_put_command(
            RunAs::User("deploy"),
            "/home/deploy/.ssh/authorized_keys",
            FileAttrs::mode("600"),
            PutCheck::None,
        ),
        unlock: "sudo usermod -p '*' -- 'deploy'",
        sudoers_put: file_put_command(
            RunAs::Root,
            "/etc/sudoers.d/deploy",
            FileAttrs::mode("440"),
            PutCheck::Sudoers,
        ),
    };
    (plan, commands)
}

/// A `user`'s keys and sudo grant are installed by the put script, run as the plan
/// says and in the plan's order; the text travels on the put's stdin, so no command
/// holds it.
#[tokio::test]
async fn a_users_files_are_put_by_the_put_script_as_the_plan_says() {
    let (plan, commands) = user_commands();
    let all = [
        commands.useradd,
        commands.home_owner,
        &commands.dir,
        &commands.keys_put,
        commands.unlock,
        &commands.sudoers_put,
    ];
    let mut mock = MockConnection::new("mock");
    for command in all {
        mock = mock.with(command, ok_output());
    }
    let conn = Connection::Mock(mock);
    let outcomes = execute_plan(&conn, &plan, None, &EventHandler::Null)
        .await
        .outcomes;
    assert!(
        outcomes
            .iter()
            .all(|o| matches!(o, ChangeOutcome::Completed { .. })),
        "{outcomes:?}"
    );
    let Connection::Mock(mock) = &conn else {
        unreachable!()
    };
    let issued = mock.issued_commands();
    assert_eq!(issued, all);
    for command in &issued {
        assert!(!command.contains("AAAA"), "{command}");
        assert!(!command.contains("NOPASSWD"), "{command}");
    }
}

/// A typed step that fails is named by what it does — never by the script it ran.
#[tokio::test]
async fn a_failed_typed_step_is_named_without_its_script() {
    let (plan, commands) = user_commands();
    let refused = "zap: /etc/sudoers.d/deploy: visudo did not accept the new content; left \
                   unchanged\n";
    let failure = |failing: &str, output: CommandOutput| {
        let mut mock = MockConnection::new("mock");
        for command in [
            commands.useradd,
            commands.home_owner,
            &commands.dir,
            &commands.keys_put,
            commands.unlock,
            &commands.sudoers_put,
        ] {
            let result = if command == failing {
                output.clone()
            } else {
                ok_output()
            };
            mock = mock.with(command, result);
        }
        let plan = plan.clone();
        async move {
            let conn = Connection::Mock(mock);
            let outcomes = execute_plan(&conn, &plan, None, &EventHandler::Null)
                .await
                .outcomes;
            let ChangeOutcome::Failed { error, .. } = &outcomes[0] else {
                panic!("the change must fail: {outcomes:?}");
            };
            for mark in SCRIPT_MARKS {
                assert!(!error.contains(mark), "{mark}: {error}");
            }
            error.clone()
        }
    };
    assert_eq!(
        failure(&commands.sudoers_put, exits(93, refused)).await,
        "put /etc/sudoers.d/deploy (mode 440, as root, checked by visudo) exited 93: zap: \
         /etc/sudoers.d/deploy: visudo did not accept the new content; left unchanged"
    );
    assert_eq!(
        failure(&commands.keys_put, exits(1, "sudo: unknown user deploy\n")).await,
        "put /home/deploy/.ssh/authorized_keys (mode 600, as deploy) exited 1: sudo: unknown \
         user deploy"
    );
    assert_eq!(
        failure(
            &commands.dir,
            exits(
                93,
                "zap: /home/deploy/.ssh: not a directory of its own (a symbolic link is not \
                 followed); left unchanged\n"
            )
        )
        .await,
        "dir /home/deploy/.ssh (mode 700, owner deploy:deploy, as root, created if missing) \
         exited 93: zap: /home/deploy/.ssh: not a directory of its own (a symbolic link is not \
         followed); left unchanged"
    );
    // A command step is named by its text, as declared.
    assert_eq!(
        failure(commands.unlock, exits(6, "usermod: no such user\n")).await,
        "`sudo usermod -p '*' -- 'deploy'` exited 6: usermod: no such user"
    );
}

/// The steps that feed the put from a command on the target, and the `pg_hba` rule, run
/// as the text they lower to — and fail under their own names too.
#[tokio::test]
async fn a_lowered_step_runs_its_command_and_fails_under_its_own_name() {
    // An `apt_repo`'s key is installed ahead of its steps, from the content cache here,
    // so its list put is reached with the key in place.
    let home = scratch::tempdir().unwrap();
    let key_url = "https://example.com/key.asc";
    let key = b"pgdg key\n";
    let key_pin = zap_types::scalar::ContentHash::of_bytes(key);
    let cached = zap_core::resolver::content_cache_path(home.path(), key_pin.as_str(), key_url);
    std::fs::create_dir_all(cached.parent().unwrap()).unwrap();
    std::fs::write(&cached, key).unwrap();
    let key_install = [
        zap_types::put::make_dirs_command(zap_types::put::RunAs::Caller, "/usr/share/keyrings"),
        zap_types::put::file_put_command(
            zap_types::put::RunAs::Caller,
            "/usr/share/keyrings/pgdg.asc",
            zap_types::schema::APT_KEY_ATTRS,
            zap_types::put::PutCheck::None,
        ),
    ];
    let plans = [
        (
            res(serde_json::json!({
                "id": "db", "type": "database", "engine": "postgresql",
                "database_name": "app", "username": "app",
                "auth": {"method": "scram-sha-256", "hosts": ["127.0.0.1/32"]},
            })),
            "pg_hba rule: host    app    app    127.0.0.1/32    scram-sha-256 (as postgres, in the \
             server's hba_file, above its first host record, unless it is already there; an \
             added rule reloads the server's configuration) exited 1: zap: PostgreSQL \
             reported no hba_file",
            &[][..],
        ),
        (
            res(serde_json::json!({
                "id": "pgdg", "type": "apt_repo", "key_url": key_url,
                "key_blake3": key_pin, "source": "deb https://example.com/apt stable main",
            })),
            "put /etc/apt/sources.list.d/pgdg.list (mode 644, as root) exited 1: zap: \
             PostgreSQL reported no hba_file",
            &key_install[..],
        ),
        (
            res(serde_json::json!({
                "id": "swap", "type": "swap", "size": "1G", "path": "/swapfile",
            })),
            "put /etc/fstab (keeps its mode, 644 if new; as root) exited 1: zap: PostgreSQL \
             reported no hba_file",
            &[][..],
        ),
    ];
    for (resource, expected, ahead) in plans {
        let plan = absent_plan(&[resource]);
        let steps = &plan.changes[0].steps;
        // the last typed step: a swap's path check comes ahead of its fstab put
        let typed = steps
            .iter()
            .rposition(|step| step.summary().is_some())
            .expect("a typed step");
        let mut mock = MockConnection::new("mock");
        for command in ahead {
            mock = mock.with(command.clone(), ok_output());
        }
        for (index, step) in steps.iter().enumerate() {
            let Some(execution) = step.execution() else {
                continue;
            };
            let output = if index == typed {
                exits(1, "zap: PostgreSQL reported no hba_file\n")
            } else {
                ok_output()
            };
            mock = mock.with(execution.text(), output);
        }
        let conn = Connection::Mock(mock);
        let outcomes = execute_plan(&conn, &plan, Some(home.path()), &EventHandler::Null)
            .await
            .outcomes;
        let ChangeOutcome::Failed { error, .. } = &outcomes[0] else {
            panic!("the change must fail: {outcomes:?}");
        };
        assert_eq!(error, expected);
        for mark in SCRIPT_MARKS {
            assert!(!error.contains(mark), "{mark}: {error}");
        }
        let Connection::Mock(mock) = &conn else {
            unreachable!()
        };
        // The step ran as the text it lowers to, after what runs ahead of it.
        let lowered = steps[typed].execution().unwrap().text().to_owned();
        let issued = mock.issued_commands();
        assert_eq!(issued.last(), Some(&lowered));
        assert_eq!(issued.len(), ahead.len() + typed + 1);
        assert_eq!(&issued[..ahead.len()], ahead);
    }
}

/// The one command that makes the pending directory: the directory script, as a mock
/// runs it.
fn pending_mkdir() -> String {
    zap_types::put::make_dirs_command(zap_types::put::RunAs::Caller, "/var/lib/zap/pending")
}

/// The one command that records `app`'s marker: the put script, run as a mock runs it.
fn pending_put() -> String {
    zap_types::put::file_put_command(
        zap_types::put::RunAs::Caller,
        "/var/lib/zap/pending/app",
        zap_types::put::FileAttrs::mode("644"),
        zap_types::put::PutCheck::None,
    )
}

/// The commands that give the marker's directories their mode, as a mock runs them.
fn pending_dir_modes() -> [String; 2] {
    ["/var/lib/zap", "/var/lib/zap/pending"].map(|dir| {
        zap_types::put::dir_attrs_command(
            zap_types::put::RunAs::Caller,
            dir,
            zap_types::put::FileAttrs::mode("755"),
        )
    })
}
const PENDING_RM: &str = "rm -f -- '/var/lib/zap/pending/app'";

/// The marker is recorded before the source runs and cleared once the service's
/// restart completes.
#[tokio::test]
async fn a_triggered_restart_records_then_clears_its_pending_marker() {
    let (plan, service_steps) = triggered_restart_plan();
    let mut mock = MockConnection::new("mock")
        .with(pending_mkdir(), ok_output())
        .with(pending_dir_modes()[0].clone(), ok_output())
        .with(pending_dir_modes()[1].clone(), ok_output())
        .with(pending_put(), ok_output())
        .with("cmd-src", ok_output())
        .with(PENDING_RM, ok_output());
    for step in &service_steps {
        mock = mock.with(step.clone(), ok_output());
    }
    let conn = Connection::Mock(mock);
    let outcomes = execute_plan(&conn, &plan, None, &EventHandler::Null)
        .await
        .outcomes;
    assert!(
        outcomes
            .iter()
            .all(|o| matches!(o, ChangeOutcome::Completed { .. })),
        "{outcomes:?}"
    );
    let Connection::Mock(mock) = &conn else {
        unreachable!()
    };
    assert!(mock.issued(&pending_put()), "marker recorded");
    assert!(mock.issued(PENDING_RM), "marker cleared after the restart");
}

/// A restart that fails leaves the marker for the next plan to re-fire from.
#[tokio::test]
async fn a_failed_restart_leaves_its_pending_marker() {
    let (plan, service_steps) = triggered_restart_plan();
    let mut mock = MockConnection::new("mock")
        .with(pending_mkdir(), ok_output())
        .with(pending_dir_modes()[0].clone(), ok_output())
        .with(pending_dir_modes()[1].clone(), ok_output())
        .with(pending_put(), ok_output())
        .with("cmd-src", ok_output());
    for step in &service_steps {
        mock = mock.with(step.clone(), fail_output());
    }
    let conn = Connection::Mock(mock);
    let outcomes = execute_plan(&conn, &plan, None, &EventHandler::Null)
        .await
        .outcomes;
    assert!(
        matches!(&outcomes[1], ChangeOutcome::Failed { resource_id, .. } if resource_id.0 == "svc"),
        "{outcomes:?}"
    );
    let Connection::Mock(mock) = &conn else {
        unreachable!()
    };
    // `rm -f` is unrecorded, so issuing it would also have failed the lookup.
    assert!(!mock.issued(PENDING_RM), "marker kept for the next plan");
}

/// A marker that can't be recorded fails the source change before it runs, so no
/// source ever changes without a record that its service owes a restart.
#[tokio::test]
async fn an_unrecordable_marker_fails_the_source_before_it_runs() {
    let (plan, _) = triggered_restart_plan();
    let conn = Connection::Mock(MockConnection::new("mock").with(pending_mkdir(), fail_output()));
    let outcomes = execute_plan(&conn, &plan, None, &EventHandler::Null)
        .await
        .outcomes;
    let ChangeOutcome::Failed {
        resource_id, error, ..
    } = &outcomes[0]
    else {
        panic!("the source must fail: {outcomes:?}");
    };
    assert_eq!(resource_id.0, "src");
    assert!(error.contains("pending restart of `app`"), "{error}");
    let Connection::Mock(mock) = &conn else {
        unreachable!()
    };
    assert!(!mock.issued("cmd-src"), "the source never ran");
}

/// An inline `file` resource at `path` — the cache-soundness tests' one resource.
fn inline_file(id: &str, path: &std::path::Path, content: &str) -> Resource {
    res(serde_json::json!({
        "id": id, "type": "file", "path": path.to_string_lossy(),
        "content": {"type": "inline", "content": content},
    }))
}

/// Detect and diff — the `plan` core.
async fn plan_for(resources: &[Resource]) -> Plan {
    let target = local_target();
    let detected = detect_all(
        &Connection::Local,
        &target,
        resources,
        None,
        None,
        Markers::Skip,
    )
    .await
    .unwrap()
    .detections;
    diff(DiffInputs {
        resources,
        detected: &by_id(resources, detected),
        target: &target,
        machine: &local_machine(),
        lock: None,
        pending: &BTreeMap::new(),
        var: &zap_types::last_run::ReportVar::unset,
    })
    .plan
}

/// Plan, execute, and re-detect — the `apply --wetrun` core.
async fn apply_for(resources: &[Resource]) {
    let plan = plan_for(resources).await;
    let outcomes = execute_plan(&Connection::Local, &plan, None, &EventHandler::Null)
        .await
        .outcomes;
    assert!(outcomes.iter().all(|o| !o.is_failure()), "{outcomes:?}");
    detect_all(
        &Connection::Local,
        &local_target(),
        resources,
        None,
        None,
        Markers::Skip,
    )
    .await
    .unwrap();
}

/// Two configs managing one path on one host: B's write drifts A's file on A's next
/// plan — nothing A read earlier stands in for reading it again.
#[tokio::test]
async fn another_configs_write_drifts() {
    let proj = scratch::tempdir().unwrap();
    let path = proj.path().join("chrony.conf");

    apply_for(&[inline_file("chrony", &path, "v1\n")]).await;
    apply_for(&[inline_file("chrony", &path, "v2\n")]).await;
    assert_eq!(std::fs::read_to_string(&path).unwrap(), "v2\n");

    let resources = [inline_file("chrony", &path, "v1\n")];
    let plan = plan_for(&resources).await;
    assert_eq!(plan.changes.len(), 1, "A must rewrite B's bytes: {plan:?}");
    apply_for(&resources).await;
    assert_eq!(std::fs::read_to_string(&path).unwrap(), "v1\n");
}

/// One config, A → B → A across a resource-id rename: the revert rewrites the renamed
/// resource's bytes, though its hash (which omits the id) matches the original's.
#[tokio::test]
async fn reverting_a_renamed_resource_rewrites_it() {
    let proj = scratch::tempdir().unwrap();
    let path = proj.path().join("x.conf");

    apply_for(&[inline_file("x", &path, "v1\n")]).await;
    apply_for(&[inline_file("y", &path, "v2\n")]).await;

    let plan = plan_for(&[inline_file("x", &path, "v1\n")]).await;
    assert_eq!(plan.changes.len(), 1, "the revert must rewrite: {plan:?}");
}

/// A hand edit that keeps the size and inode (an in-place rewrite, as an editor or
/// `sed -i`-less write does) drifts on the next plan.
#[tokio::test]
async fn an_in_place_out_of_band_edit_drifts() {
    use std::io::{Seek, Write};

    let proj = scratch::tempdir().unwrap();
    let path = proj.path().join("sshd.conf");
    let resources = [inline_file("sshd", &path, "PasswordAuthentication no\n")];

    apply_for(&resources).await;
    assert!(plan_for(&resources).await.changes.is_empty());

    let mut file = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
    file.rewind().unwrap();
    file.write_all(b"PasswordAuthentication on\n").unwrap();
    drop(file);

    let plan = plan_for(&resources).await;
    assert_eq!(plan.changes.len(), 1, "the hand edit must drift: {plan:?}");
}

/// A symbolic link planted at a managed file's path, pointing at a file that already
/// holds the declared bytes: the content read follows it and matches, the path's own
/// metadata says it isn't the file, so it drifts — and the apply replaces the link with
/// a regular file carrying the declared mode, leaving what it pointed at alone. Then
/// the next plan is empty: what a write installs is what detection reads as converged.
#[tokio::test]
async fn a_link_at_a_managed_file_drifts_and_is_replaced_not_followed() {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    let proj = scratch::tempdir().unwrap();
    let path = proj.path().join("app.env");
    let victim = proj.path().join("victim");
    std::fs::write(&victim, "TOKEN=1\n").unwrap();
    std::fs::set_permissions(&victim, std::fs::Permissions::from_mode(0o644)).unwrap();
    std::os::unix::fs::symlink(&victim, &path).unwrap();

    let resources = [res(serde_json::json!({
        "id": "env", "type": "file", "path": path.to_string_lossy(), "mode": "600",
        "content": {"type": "inline", "content": "TOKEN=1\n"},
    }))];
    let plan = plan_for(&resources).await;
    assert_eq!(plan.changes.len(), 1, "the link is not the file: {plan:?}");
    apply_for(&resources).await;

    let installed = std::fs::symlink_metadata(&path).unwrap();
    assert!(installed.is_file(), "a regular file replaced the link");
    assert_eq!(installed.mode() & 0o7777, 0o600);
    assert_eq!(std::fs::read_to_string(&path).unwrap(), "TOKEN=1\n");
    assert_eq!(
        std::fs::metadata(&victim).unwrap().mode() & 0o7777,
        0o644,
        "the mode went to the new file, not through the link"
    );
    assert_eq!(
        std::fs::read_dir(proj.path())
            .unwrap()
            .filter(|entry| entry.as_ref().unwrap().file_name() != "package.json")
            .count(),
        2,
        "no staged file is left"
    );
    let again = plan_for(&resources).await;
    assert!(again.changes.is_empty(), "{again:?}");
}

/// A mode that drifts with the content unchanged converges by the same write: the file
/// is installed again with its mode, and the next plan is empty.
#[tokio::test]
async fn a_drifted_mode_converges_through_the_write() {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    let proj = scratch::tempdir().unwrap();
    let path = proj.path().join("app.conf");
    let resources = [res(serde_json::json!({
        "id": "conf", "type": "file", "path": path.to_string_lossy(), "mode": "640",
        "content": {"type": "inline", "content": "a=1\n"},
    }))];
    apply_for(&resources).await;
    assert!(plan_for(&resources).await.changes.is_empty());

    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666)).unwrap();
    assert_eq!(plan_for(&resources).await.changes.len(), 1);
    apply_for(&resources).await;
    assert_eq!(std::fs::metadata(&path).unwrap().mode() & 0o7777, 0o640);
    assert!(plan_for(&resources).await.changes.is_empty());
}

/// A link planted at a managed directory's path drifts even when the link's own mode
/// reads as the declared one — it is not the directory — and the directory itself
/// converges. (That the change refuses the link, leaving what it points at alone and
/// asking nothing of `sudo`, is pinned where no failure can reach a real `sudo`: the
/// native directory change's own tests and the directory script's.)
#[tokio::test]
async fn a_link_at_a_managed_directory_drifts_and_the_directory_converges() {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    let proj = scratch::tempdir().unwrap();
    let victim = proj.path().join("victim");
    std::fs::create_dir(&victim).unwrap();
    std::fs::set_permissions(&victim, std::fs::Permissions::from_mode(0o700)).unwrap();
    let path = proj.path().join("data");
    std::os::unix::fs::symlink(&victim, &path).unwrap();

    let resources = [res(serde_json::json!({
        "id": "data", "type": "directory", "path": path.to_string_lossy(), "mode": "777",
    }))];
    let plan = plan_for(&resources).await;
    assert_eq!(
        plan.changes.len(),
        1,
        "a link is not the directory: {plan:?}"
    );

    std::fs::remove_file(&path).unwrap();
    apply_for(&resources).await;
    assert_eq!(std::fs::metadata(&path).unwrap().mode() & 0o7777, 0o777);
    assert_eq!(std::fs::metadata(&victim).unwrap().mode() & 0o7777, 0o700);
    assert!(plan_for(&resources).await.changes.is_empty());
}

/// A directory's mode and owner are one command — the descriptor script — after the
/// directory script that makes it; nothing names the path to `chmod` or `chown` it.
#[tokio::test]
async fn a_directory_change_is_a_mkdir_and_one_attrs_command() {
    use zap_types::put::{FileAttrs, RunAs, dir_attrs_command, make_dirs_command};

    let mkdir = make_dirs_command(RunAs::Caller, "/srv/app");

    let resources = [res(serde_json::json!({
        "id": "d", "type": "directory", "path": "/srv/app", "mode": "750", "owner": "app",
    }))];
    let attrs = dir_attrs_command(
        RunAs::Caller,
        "/srv/app",
        FileAttrs {
            mode: Some("750"),
            owner: Some("app"),
            group: None,
            ..FileAttrs::NONE
        },
    );
    let plan = diff(DiffInputs {
        resources: &resources,
        detected: &all_absent(&resources),
        target: &local_target(),
        machine: &local_machine(),
        lock: None,
        pending: &BTreeMap::new(),
        var: &zap_types::last_run::ReportVar::unset,
    })
    .plan;
    let conn = Connection::Mock(
        MockConnection::new("mock")
            .with(mkdir.clone(), ok_output())
            .with(attrs.clone(), ok_output()),
    );
    let outcomes = execute_plan(&conn, &plan, None, &EventHandler::Null)
        .await
        .outcomes;
    assert!(outcomes.iter().all(|o| !o.is_failure()), "{outcomes:?}");
    let Connection::Mock(mock) = &conn else {
        unreachable!()
    };
    assert_eq!(mock.issued_commands(), [mkdir.as_str(), attrs.as_str()]);
}
