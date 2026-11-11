//! The text `zap deploy` prints: the header and version line, the plan preview a dry
//! run or a refusal shows, the outcome lines of a wetrun, and the banners and warnings
//! under them.

use std::fmt::Write as _;

use zap_types::deploy::{ARCHIVE_ENV, DeployAction, DeployPlan, DriftPreflight};
use zap_types::event::StepOutcome;
use zap_types::last_run::PlanUnreviewed;

use super::{DIRTY_NEEDS_FORCE, DeployOutcome, DeployReport};
use crate::commands::RefusalText;
use crate::commands::prompt::Confirmation;
use crate::escape::{escape_line, render_block};

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
        DeployOutcome::Deployed => render_step_outcomes(&mut out, report),
        DeployOutcome::Failed => {
            render_step_outcomes(&mut out, report);
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
    if report.outcome.shows_hash() {
        let _ = writeln!(out, "plan_hash: {}", report.plan_hash);
    }
    out
}

/// `deploy`'s refusal wording. Its plan is computed from the config, the pins in
/// `zap.lock` (through the preflight's digest), the checkout (the version and tree
/// state), the invocation's flags, what the target serves, and the environment values
/// the host, the connecting user, and the health domain resolve from.
const DEPLOY_REFUSAL: RefusalText = RefusalText {
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

/// Wetrun body: per-step outcome lines.
fn render_step_outcomes(out: &mut String, report: &DeployReport) {
    for outcome in &report.step_outcomes {
        match outcome {
            StepOutcome::Completed { step, .. } => {
                let _ = writeln!(out, "  ok    {}", escape_line(step));
            }
            StepOutcome::Failed { step, error } => {
                render_block(out, &format!("  FAIL  {}  — ", escape_line(step)), error);
            }
            StepOutcome::Skipped { step, reason } => {
                render_block(out, &format!("  skip  {}  — ", escape_line(step)), reason);
            }
        }
    }
}
