//! The text `zap deploy` prints: the header and version line, the plan preview a dry
//! run or a refusal shows, the outcome lines of a wetrun, and the banners and warnings
//! under them.

use std::fmt::Write as _;
use std::time::Duration;

use zap_types::deploy::{ARCHIVE_ENV, DeployAction, DeployPlan, DeployStepId, DriftPreflight};
use zap_types::event::StepOutcome;
use zap_types::last_run::PlanUnreviewed;

use super::{
    DIRTY_NEEDS_FORCE, DeployOutcome, DeployReport, DeployRun, FailureState, Rollback,
    RollbackOutcome, StepSummary, SwapFailure,
};
use crate::commands::RefusalText;
use crate::commands::prompt::Confirmation;
use crate::escape::{escape_line, render_block};
use crate::progress::count;

/// Render a [`DeployReport`] to the text shown by `zap deploy`.
///
/// Every plan-derived line is read from the report's plan, and the `plan_hash` is
/// printed only under a render that lists the whole of it — so what the hash covers is
/// what was shown — and never for a plan that names no one machine. Text that came from the config, the environment, the command line,
/// or the target is escaped on its way out (`escape_line`).
#[must_use]
pub fn render_deploy(report: &DeployReport) -> String {
    let mut out = String::new();
    let plan = &report.plan;
    let mode = match (report.wetrun, &report.outcome, report.confirmation) {
        (false, ..) => "dry-run",
        (true, DeployOutcome::Refused(_), Some(Confirmation::Asking)) => {
            "wetrun, awaiting confirmation"
        }
        (true, DeployOutcome::Refused(_), Some(Confirmation::Declined)) => "wetrun, declined",
        (true, DeployOutcome::Refused(_), _) => "wetrun, refused",
        (true, _, Some(Confirmation::Accepted)) => "wetrun, confirmed",
        (true, ..) => "wetrun",
    };
    let _ = writeln!(
        out,
        "deploy — target {} ({mode})",
        escape_line(&report.target)
    );
    let _ = writeln!(
        out,
        "  version: {} (previous: {})",
        escape_line(&plan.version),
        escape_line(report.previous_version.as_deref().unwrap_or("none"))
    );

    match &report.outcome {
        DeployOutcome::PreflightDrift => {
            let _ = writeln!(out, "  preflight: drift detected — nothing deployed");
        }
        DeployOutcome::PreflightUndetermined => {
            let _ = writeln!(
                out,
                "  preflight: incomplete — nothing deployed (the drift gate could not probe \
                 every resource, so \"no drift\" was never established)"
            );
        }
        DeployOutcome::AlreadyDeployed => {
            let _ = writeln!(
                out,
                "  server already at this version (use --force to redeploy)"
            );
        }
        DeployOutcome::DryRun => {
            render_plan_preview(&mut out, plan);
            // A bare wetrun binds only to a preview that was recorded.
            let _ = if report.recorded.is_some() {
                writeln!(out, "  (dry-run — re-run with --wetrun to deploy)")
            } else {
                writeln!(
                    out,
                    "  (dry-run — re-run with --wetrun --expect-plan {} to deploy)",
                    report.plan_hash
                )
            };
        }
        DeployOutcome::DryRunUnbindable(reason) => {
            render_plan_preview(&mut out, plan);
            let _ = writeln!(
                out,
                "  (dry-run — a wetrun of this config is refused, so this plan has no \
                 plan_hash and is not recorded as a preview)"
            );
            render_block(&mut out, "  UNBINDABLE — ", reason);
        }
        DeployOutcome::DryRunDirty => {
            render_plan_preview(&mut out, plan);
            let _ = writeln!(
                out,
                "  (dry-run — a wetrun of this tree is refused, so this plan has no \
                 plan_hash and is not recorded as a preview)"
            );
            render_block(&mut out, "  DIRTY — ", DIRTY_NEEDS_FORCE);
        }
        DeployOutcome::Refused(reason) if report.confirmation == Some(Confirmation::Asking) => {
            render_plan_preview(&mut out, plan);
            crate::commands::render_refused(&mut out, reason, &DEPLOY_REFUSAL, report.confirmation);
        }
        DeployOutcome::Refused(reason) => {
            render_plan_preview(&mut out, plan);
            crate::commands::render_refused(&mut out, reason, &DEPLOY_REFUSAL, report.confirmation);
            let hash = &report.plan_hash;
            // Only a render that was recorded can be bound to without the hash.
            let _ = match (reason, report.recorded) {
                (_, None) => writeln!(
                    out,
                    "  review the plan above, then re-run with --expect-plan {hash}"
                ),
                (PlanUnreviewed::Expected { .. }, Some(_)) => writeln!(
                    out,
                    "  review the plan above, then re-run with --expect-plan {hash}, or \
                     without --expect-plan (it binds to this preview)"
                ),
                (PlanUnreviewed::NoPreview { .. } | PlanUnreviewed::Changed { .. }, Some(_)) => {
                    writeln!(
                        out,
                        "  review the plan above, then re-run `zap deploy --wetrun` with the \
                     same flags (it binds to this preview) or pass --expect-plan {hash}"
                    )
                }
            };
        }
        DeployOutcome::Deployed(run) => render_run(&mut out, report, run, None),
        DeployOutcome::Failed { run, left } => {
            render_run(&mut out, report, run, Some(left));
            let _ = writeln!(
                out,
                "  this deploy spent its review: before re-running, preview again with \
                 `zap deploy` (or pass --expect-plan with the hash that preview prints)"
            );
        }
    }

    crate::commands::render_lock_standing(
        &mut out,
        &report.lock_standing,
        "so the drift preflight cannot check them and a wetrun stops there",
    );
    crate::commands::render_undetermined(&mut out, &report.held);
    crate::commands::render_warnings(&mut out, &plan.warnings);
    crate::commands::render_warnings(&mut out, &report.warnings);
    render_verdict(&mut out, report);
    if report.outcome.shows_hash() {
        let _ = writeln!(out, "plan_hash: {}", report.plan_hash);
    }
    out
}

/// `deploy`'s refusal wording. Its plan is computed from the config, the pins in
/// `zap.lock` (through the preflight's digest), the checkout (the version and tree
/// state), the invocation's flags, what the target serves, and the environment values
/// the host, the connecting user, and the health domain resolve from.
pub(super) const DEPLOY_REFUSAL: RefusalText = RefusalText {
    no_preview: "no deploy plan has been previewed for this host.",
    moved: "the config, `zap.lock`, the checkout, the flags, the target, or the \
            environment its host, user, or health domain resolve from",
};

/// Preview body: the whole plan — everything `plan_hash` covers beyond the version line
/// above it and the plan's warnings below. The resolved host and the declared target,
/// the tree and preflight facts, then each step with its action in full.
fn render_plan_preview(out: &mut String, plan: &DeployPlan) {
    let _ = writeln!(out, "  host: {}", escape_line(&plan.host));
    crate::commands::render_target(out, &plan.target);
    crate::commands::render_references(out, &plan.references);
    let _ = writeln!(
        out,
        "  tree: {}",
        if plan.dirty {
            "uncommitted changes or untracked files — the artifacts ship as the tree has them"
        } else {
            "clean"
        }
    );
    let _ = writeln!(
        out,
        "  preflight: {}",
        match &plan.preflight {
            DriftPreflight::Checks { resources, digest } => format!(
                "{resources} apply-managed resource(s), digest {}, are checked for drift \
                 before the steps",
                escape_line(digest)
            ),
            DriftPreflight::Skipped => "skipped (--skip-preflight)".to_owned(),
            DriftPreflight::NothingDeclared =>
                "no apply-managed resources declared — nothing to check".to_owned(),
        }
    );
    for step in &plan.steps {
        let _ = writeln!(out, "  - {} ({})", escape_line(&step.name), step.id);
        render_action(out, &step.action);
    }
}

/// One step's action under its name, every field of it: the command, script, paths, or
/// URL it holds. Each variant reads differently, so two actions that differ in kind
/// alone don't render alike.
fn render_action(out: &mut String, action: &DeployAction) {
    const INDENT: &str = "      ";
    match action {
        DeployAction::Build { command } => {
            render_block(out, &format!("{INDENT}local$ "), command);
        }
        DeployAction::Tarball { command } => {
            render_block(out, &format!("{INDENT}local$ "), command);
            let _ = writeln!(
                out,
                "{INDENT}writes ${ARCHIVE_ENV}: a file in a private directory of this run, \
                 removed when it ends"
            );
        }
        DeployAction::Upload { remote } => {
            let _ = writeln!(
                out,
                "{INDENT}the archive → target:{} (as the connecting user, mode 600, checked \
                 against its SHA-512)",
                escape_line(remote)
            );
        }
        DeployAction::ExtractSwap { script } => {
            let _ = writeln!(
                out,
                "{INDENT}target script (its stdin: the archive's SHA-512):"
            );
            render_block(out, &format!("{INDENT}  "), script);
        }
        DeployAction::Restart { command } => {
            render_block(out, &format!("{INDENT}target$ "), command);
        }
        DeployAction::Health {
            url,
            url_label,
            attempts,
            interval_ms,
        } => render_poll(
            out,
            "healthy on 2xx",
            url,
            url_label,
            *attempts,
            *interval_ms,
        ),
        DeployAction::Readiness {
            url,
            url_label,
            attempts,
            interval_ms,
        } => render_poll(
            out,
            "ready on 2xx, unserved on 404",
            url,
            url_label,
            *attempts,
            *interval_ms,
        ),
    }
}

/// A polled URL: as declared, how it is read, its budget, and — where a reference in it
/// resolves — the URL the plan names.
fn render_poll(
    out: &mut String,
    reads: &str,
    url: &str,
    url_label: &str,
    attempts: u32,
    interval_ms: u64,
) {
    let _ = writeln!(
        out,
        "      GET {} — {reads}; up to {attempts} attempt(s), {interval_ms} ms apart",
        escape_line(url)
    );
    if url_label != url {
        let _ = writeln!(out, "      polls {}", escape_line(url_label));
    }
}

/// One row of a wetrun's table: its status, what it is, how long it took when it ran,
/// and what it says.
struct Row {
    /// `ok`, `FAIL`, or `skip`.
    status: &'static str,
    /// The step id, or `preflight`, escaped.
    id: String,
    /// How long it ran, or empty for one that didn't.
    took: String,
    /// Its summary, error, or reason, escaped as a block when written; may be empty.
    text: String,
}

/// Wetrun body: a table of the drift preflight, each step, and the rollback when one
/// ran — each row's status, its id, how long it took, and its summary, error, or
/// reason, in aligned columns. A step's summary is text the engine wrote
/// ([`StepSummary`]), never a command's output.
fn render_run(
    out: &mut String,
    report: &DeployReport,
    run: &DeployRun,
    left: Option<&FailureState>,
) {
    let took = |took: Duration| format_elapsed(took);
    let mut rows = vec![match &report.plan.preflight {
        DriftPreflight::Checks { resources, .. } => Row {
            status: "ok",
            id: "preflight".to_owned(),
            took: run.preflight.map(took).unwrap_or_default(),
            text: format!(
                "{}, no drift",
                count(
                    *resources,
                    "apply-managed resource",
                    "apply-managed resources"
                )
            ),
        },
        DriftPreflight::Skipped => Row {
            status: "skip",
            id: "preflight".to_owned(),
            took: String::new(),
            text: "--skip-preflight".to_owned(),
        },
        DriftPreflight::NothingDeclared => Row {
            status: "skip",
            id: "preflight".to_owned(),
            took: String::new(),
            text: "no apply-managed resources declared".to_owned(),
        },
    }];
    for outcome in &report.step_outcomes {
        let (status, step, text) = match outcome {
            StepOutcome::Completed { step, .. } => {
                let summary = run
                    .step(step)
                    .and_then(|record| record.summary.as_ref())
                    .map(render_summary)
                    .unwrap_or_default();
                ("ok", step, summary)
            }
            StepOutcome::Failed { step, error } => ("FAIL", step, error.clone()),
            StepOutcome::Skipped { step, reason } => ("skip", step, reason.clone()),
        };
        rows.push(Row {
            status,
            id: escape_line(step).into_owned(),
            took: run
                .step(step)
                .map(|record| took(record.took))
                .unwrap_or_default(),
            text,
        });
    }
    if let Some(FailureState::AfterSwap(rollback)) = left {
        let previous = report
            .previous_version
            .as_deref()
            .unwrap_or("the previous release");
        let (status, took_text, text) = match rollback {
            Rollback::NotStarted => (
                "skip",
                String::new(),
                "nothing known to return to (see the warnings below)".to_owned(),
            ),
            Rollback::Ran { outcome, took: ran } => {
                let (status, text) = match outcome {
                    RollbackOutcome::RolledBack {
                        health_checked: true,
                    } => (
                        "ok",
                        format!("{previous} restored and restarted, health OK"),
                    ),
                    RollbackOutcome::RolledBack {
                        health_checked: false,
                    } => ("ok", format!("{previous} restored and restarted")),
                    RollbackOutcome::Unconfirmed => (
                        "FAIL",
                        format!(
                            "{previous} restored, but not confirmed serving (see the warnings \
                             below)"
                        ),
                    ),
                    RollbackOutcome::NotDone => (
                        "skip",
                        "not rolled back (see the warnings below)".to_owned(),
                    ),
                    RollbackOutcome::Failed => (
                        "FAIL",
                        "could not re-point `current` (see the warnings below)".to_owned(),
                    ),
                };
                (status, took(*ran), text)
            }
        };
        rows.push(Row {
            status,
            id: DeployStepId::Rollback.as_str().to_owned(),
            took: took_text,
            text,
        });
    }
    render_rows(out, &rows);
}

/// `rows` as a table: the status, the id padded to the widest, the duration
/// right-aligned in its own column, then the text, whose further lines align under its
/// first.
fn render_rows(out: &mut String, rows: &[Row]) {
    let id_width = rows
        .iter()
        .map(|row| row.id.chars().count())
        .max()
        .unwrap_or(0);
    let took_width = rows
        .iter()
        .map(|row| row.took.chars().count())
        .max()
        .unwrap_or(0);
    for row in rows {
        // a table with no time in it has no column for one
        let lead = if took_width == 0 {
            format!("  {:<6}{:<id_width$}", row.status, row.id)
        } else {
            format!(
                "  {:<6}{:<id_width$}  {:>took_width$}",
                row.status, row.id, row.took
            )
        };
        if row.text.is_empty() {
            let _ = writeln!(out, "{}", lead.trim_end());
        } else {
            render_block(out, &format!("{lead}  "), &row.text);
        }
    }
}

/// The most of a summary the outcome line shows, in characters.
const SUMMARY_CHARS: usize = 120;

/// A step's summary as its row shows it: an upload's size, or at most the first line of
/// what a poll said, cut at [`SUMMARY_CHARS`].
fn render_summary(summary: &StepSummary) -> String {
    match summary {
        StepSummary::Uploaded { bytes } => format!("{} sent", format_size(*bytes)),
        StepSummary::Said(said) => {
            let line = said
                .lines()
                .map(str::trim)
                .find(|line| !line.is_empty())
                .unwrap_or_default();
            if line.chars().count() > SUMMARY_CHARS {
                let cut: String = line.chars().take(SUMMARY_CHARS).collect();
                format!("{cut}…")
            } else {
                line.to_owned()
            }
        }
    }
}

/// The closing verdict of a wetrun that reached its steps: on success, the version now
/// live on the plan's host, the one it replaced, and the time the run took; on failure,
/// the step that failed and the state the target was left in ([`FailureState`]).
fn render_verdict(out: &mut String, report: &DeployReport) {
    let plan = &report.plan;
    let host = escape_line(&plan.host);
    let previous = report.previous_version.as_deref().map(escape_line);
    match &report.outcome {
        DeployOutcome::Deployed(run) => {
            let _ = writeln!(
                out,
                "deployed {} to {host} (previous: {}) in {}",
                escape_line(&plan.version),
                previous.as_deref().unwrap_or("none"),
                format_elapsed(run.total)
            );
        }
        DeployOutcome::Failed { run, left } => {
            let failed = report
                .step_outcomes
                .iter()
                .find_map(|outcome| match outcome {
                    StepOutcome::Failed { step, .. } => Some(escape_line(step)),
                    StepOutcome::Completed { .. } | StepOutcome::Skipped { .. } => None,
                });
            let previous = previous.as_deref().unwrap_or("the previous release");
            let state = match left {
                FailureState::BeforeSwap => {
                    "nothing was released, and `current` was not moved".to_owned()
                }
                FailureState::AtSwap(SwapFailure::NotSwapped) => {
                    "`current` does not name this release, so nothing was released".to_owned()
                }
                FailureState::AtSwap(SwapFailure::Unknown) => {
                    "the swap is not known to have completed, and nothing was rolled back (see \
                     the step's error above)"
                        .to_owned()
                }
                FailureState::AfterSwap(Rollback::NotStarted) => {
                    "not rolled back: no release was known to return to, so the failed release \
                     is live — manual intervention required (see the warnings above)"
                        .to_owned()
                }
                FailureState::AfterSwap(Rollback::Ran { outcome, .. }) => match outcome {
                    RollbackOutcome::RolledBack {
                        health_checked: true,
                    } => format!("rolled back: {previous} is live again"),
                    RollbackOutcome::RolledBack {
                        health_checked: false,
                    } => {
                        format!("rolled back: {previous} restored and restarted (no health check)")
                    }
                    RollbackOutcome::Unconfirmed => format!(
                        "rolled back to {previous}, which is not confirmed serving — manual \
                         intervention required"
                    ),
                    RollbackOutcome::NotDone => "not rolled back, so `current` is as the \
                                                 warnings above say — check it by hand"
                        .to_owned(),
                    RollbackOutcome::Failed => "the rollback failed, so the host may be serving \
                                                the failed release — manual intervention \
                                                required (see the warnings above)"
                        .to_owned(),
                },
            };
            let _ = writeln!(
                out,
                "deploy FAILED{} on {host} after {} — {state}",
                failed.map(|step| format!(" at {step}")).unwrap_or_default(),
                format_elapsed(run.total)
            );
        }
        DeployOutcome::DryRun
        | DeployOutcome::DryRunUnbindable(_)
        | DeployOutcome::DryRunDirty
        | DeployOutcome::AlreadyDeployed
        | DeployOutcome::Refused(_)
        | DeployOutcome::PreflightDrift
        | DeployOutcome::PreflightUndetermined => {}
    }
}

/// A size as a row shows it: bytes under a thousand (`512 B`), then tenths of the
/// largest decimal unit it reaches (`4.2 MB`).
pub(super) fn format_size(bytes: u64) -> String {
    const UNITS: [&str; 4] = ["kB", "MB", "GB", "TB"];
    if bytes < 1000 {
        return format!("{bytes} B");
    }
    let mut scale: u128 = 1000;
    let mut unit = UNITS[0];
    for next in &UNITS[1..] {
        if u128::from(bytes) < scale * 1000 {
            break;
        }
        scale *= 1000;
        unit = next;
    }
    let tenths = u128::from(bytes) * 10 / scale;
    format!("{}.{} {unit}", tenths / 10, tenths % 10)
}

/// A duration as an outcome line shows it: tenths of a second under ten seconds
/// (`0.4s`, `9.9s`), whole seconds under a minute (`42s`), then minutes and seconds
/// (`3m 07s`) and hours and minutes (`1h 02m`).
pub(super) fn format_elapsed(took: Duration) -> String {
    let tenths = took.as_millis() / 100;
    if tenths < 100 {
        return format!("{}.{}s", tenths / 10, tenths % 10);
    }
    let seconds = took.as_secs();
    if seconds < 60 {
        format!("{seconds}s")
    } else if seconds < 3600 {
        format!("{}m {:02}s", seconds / 60, seconds % 60)
    } else {
        format!("{}h {:02}m", seconds / 3600, seconds % 3600 / 60)
    }
}
