//! The text `zap deploy` prints: the header and version line, the plan preview a dry
//! run or a refusal shows, the outcome lines of a wetrun, and the banners and warnings
//! under them.

use std::borrow::Cow;
use std::fmt::Write as _;
use std::time::Duration;

use zap_types::deploy::{
    ARCHIVE_ENV, DeployAction, DeployPlan, DeployStepId, DriftPreflight, ReleaseSwap,
};
use zap_types::event::StepOutcome;
use zap_types::last_run::PlanUnreviewed;
use zap_types::plan::Machine;

use super::{
    DIRTY_NEEDS_FORCE, DeployOutcome, DeployReport, DeployRun, FailureState, Rollback,
    RollbackOutcome, StepSummary, SwapFailure,
};
use crate::commands::RefusalText;
use crate::commands::prompt::Confirmation;
use crate::commands::result_table::{Row, format_elapsed, render_rows};
use crate::escape::{escape_line, render_block};
use crate::progress::count;

/// Render a [`DeployReport`] to the text shown by `zap deploy`.
///
/// Every plan-derived line is read from the report's plan, and the `plan_hash` is
/// printed only under a render that lists the whole of it — so what the hash covers is
/// what the render lists — and never for a plan that names no one machine. Text that came from
/// the config, the environment, the command line, the checkout, or the target is
/// escaped on its way out (`escape_line`).
///
/// A preview of the plan — a dry run, or a refusal or question in its place — comes in
/// groups a blank line apart: what is shipped where and by whom, the two gates (the tree
/// and the drift preflight), the steps, and what the run does with the plan (its
/// footer, or the refusal banner). Its last block restates the lines that tell one
/// deploy of an app from the next (`render_recap`), so the `plan_hash` and a question
/// under it are read beside them rather than a script's length below them.
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
    let _ = writeln!(out, "  version: {}", version_text(plan));

    let previewed = match &report.outcome {
        DeployOutcome::PreflightDrift => {
            let _ = writeln!(out, "  preflight: drift detected — nothing deployed");
            false
        }
        DeployOutcome::PreflightUndetermined => {
            let _ = writeln!(
                out,
                "  preflight: incomplete — nothing deployed (the drift gate could not probe \
                 every resource, so \"no drift\" was never established)"
            );
            false
        }
        DeployOutcome::AlreadyDeployed => {
            let _ = writeln!(
                out,
                "  server already at this version (use --force to redeploy)"
            );
            false
        }
        DeployOutcome::DryRun => {
            render_plan_preview(&mut out, &report.target, plan);
            // A bare wetrun binds only to a preview that was recorded.
            let _ = if report.recorded.is_some() {
                writeln!(out, "\n  (dry-run — re-run with --wetrun to deploy)")
            } else {
                writeln!(
                    out,
                    "\n  (dry-run — re-run with --wetrun --expect-plan {} to deploy)",
                    report.plan_hash
                )
            };
            true
        }
        DeployOutcome::DryRunUnbindable(reason) => {
            render_plan_preview(&mut out, &report.target, plan);
            let _ = writeln!(
                out,
                "\n  (dry-run — a wetrun of this config is refused, so this plan has no \
                 plan_hash and is not recorded as a preview)"
            );
            render_block(&mut out, "  UNBINDABLE — ", reason);
            true
        }
        DeployOutcome::DryRunDirty => {
            render_plan_preview(&mut out, &report.target, plan);
            let _ = writeln!(
                out,
                "\n  (dry-run — a wetrun of this tree is refused, so this plan has no \
                 plan_hash and is not recorded as a preview)"
            );
            render_block(&mut out, "  DIRTY — ", DIRTY_NEEDS_FORCE);
            true
        }
        DeployOutcome::Refused(reason) if report.confirmation == Some(Confirmation::Asking) => {
            render_plan_preview(&mut out, &report.target, plan);
            crate::commands::render_refused(&mut out, reason, &DEPLOY_REFUSAL, report.confirmation);
            true
        }
        DeployOutcome::Refused(reason) => {
            render_plan_preview(&mut out, &report.target, plan);
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
            true
        }
        DeployOutcome::Deployed(run) => {
            render_run(&mut out, report, run, None);
            false
        }
        DeployOutcome::Failed { run, left } => {
            render_run(&mut out, report, run, Some(left));
            let _ = writeln!(
                out,
                "  this deploy spent its review: before re-running, preview again with \
                 `zap deploy` (or pass --expect-plan with the hash that preview prints)"
            );
            false
        }
    };

    crate::commands::render_lock_standing(
        &mut out,
        &report.lock_standing,
        "which the drift preflight cannot check, so a wetrun stops there",
    );
    crate::commands::render_undetermined(&mut out, &report.held);
    crate::commands::render_warnings(&mut out, &plan.warnings);
    crate::commands::render_warnings(&mut out, &report.warnings);
    render_verdict(&mut out, report);
    if previewed {
        render_recap(&mut out, plan);
    }
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

/// The version line's text: the version, then what it replaces ([`replaces_text`]).
fn version_text(plan: &DeployPlan) -> String {
    format!("{} ({})", escape_line(&plan.version), replaces_text(plan))
}

/// What a release replaces, as the version line and a deploy's closing line say it:
/// `previous: <release>`, or `first release` when nothing was live.
fn replaces_text(plan: &DeployPlan) -> String {
    plan.previous.as_deref().map_or_else(
        || "first release".to_owned(),
        |previous| format!("previous: {}", escape_line(previous)),
    )
}

/// The commit line's text: the commit's subject, under a key that says whose it is —
/// for a dirty tree the commit under the uncommitted changes, which the key says before
/// the subject's own text can — or, in words no subject's line begins with, that it has
/// none.
fn commit_text(plan: &DeployPlan) -> String {
    let key = if plan.dirty {
        "commit (under uncommitted changes)"
    } else {
        "commit"
    };
    let subject = escape_line(&plan.subject);
    if subject.is_empty() {
        format!("{key} has no subject line")
    } else {
        format!("{key}: {subject}")
    }
}

/// The tree line's text.
const fn tree_text(plan: &DeployPlan) -> &'static str {
    if plan.dirty {
        "uncommitted changes or untracked files — the artifacts ship as the tree has them"
    } else {
        "clean"
    }
}

/// What the drift preflight does, as a sentence; `with_digest` closes one that checks
/// with the digest it checks against.
fn preflight_text(plan: &DeployPlan, with_digest: bool) -> String {
    match &plan.preflight {
        DriftPreflight::Checks { resources, digest } => {
            let checks = format!(
                "checks {} for drift before the steps",
                count(
                    *resources,
                    "apply-managed resource",
                    "apply-managed resources"
                )
            );
            if with_digest {
                format!("{checks} — digest {}", escape_line(digest))
            } else {
                checks
            }
        }
        DriftPreflight::Skipped => "skipped (--skip-preflight)".to_owned(),
        DriftPreflight::NothingDeclared => {
            "no apply-managed resources declared — nothing to check".to_owned()
        }
    }
}

/// Preview body: the whole plan — everything `plan_hash` covers beyond the version line
/// above it and the plan's warnings below — in three groups a blank line apart.
///
/// First what is shipped where: the commit's subject ([`commit_text`]), the machine — the resolved host
/// where the header's declared one (`declared`) doesn't already say it, and the
/// connecting user ([`render_machine`](crate::commands::render_machine), as the
/// convergence previews print it) — the operator recorded as deploying, the declared
/// target, and the values of the references the plan uses. Then the gates: the tree,
/// and what the drift preflight checks. Then each step with its action in full.
fn render_plan_preview(out: &mut String, declared: &str, plan: &DeployPlan) {
    let _ = writeln!(out, "  {}", commit_text(plan));
    crate::commands::render_machine(
        out,
        declared,
        &Machine::Remote {
            host: plan.host.clone(),
            user: plan.user.clone(),
        },
    );
    let _ = writeln!(out, "  deployed by: {}", escape_line(&plan.deployed_by));
    crate::commands::render_target(out, &plan.target);
    crate::commands::render_references(out, &plan.references);

    let _ = writeln!(out, "\n  tree: {}", tree_text(plan));
    let _ = writeln!(out, "  preflight: {}", preflight_text(plan, true));

    let _ = writeln!(out);
    for step in &plan.steps {
        let _ = writeln!(out, "  - {} ({})", escape_line(&step.name), step.id);
        render_action(out, plan, &step.action);
    }
}

/// The closing block of a preview: the lines that tell one deploy of an app from the
/// next — the commit, the version and the release it replaces, the host and the connecting user,
/// the tree, and what the preflight checks — restated from the plan with the text the
/// lines above it print, last before the `plan_hash` and any question under it.
fn render_recap(out: &mut String, plan: &DeployPlan) {
    let _ = writeln!(out, "\n  in short:");
    let _ = writeln!(out, "    {}", commit_text(plan));
    let _ = writeln!(out, "    version: {}", version_text(plan));
    let _ = writeln!(out, "    host: {}", escape_line(&plan.host));
    let _ = writeln!(
        out,
        "    user: {}",
        plan.user
            .as_deref()
            .map_or(Cow::Borrowed(crate::commands::NO_USER), escape_line)
    );
    let _ = writeln!(out, "    tree: {}", tree_text(plan));
    let _ = writeln!(out, "    preflight: {}", preflight_text(plan, false));
}

/// One step's action under its name, every field of it: the command, script, paths, or
/// URL it holds. Each variant reads differently, so two actions that differ in kind
/// alone don't render alike.
fn render_action(out: &mut String, plan: &DeployPlan, action: &DeployAction) {
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
        DeployAction::ExtractSwap(swap) => render_swap(out, plan, swap),
        DeployAction::Restart { command } => {
            render_block(out, &format!("{INDENT}target$ "), command);
        }
        DeployAction::Health {
            url,
            url_label,
            attempts,
            interval_ms,
            timeout_ms,
        } => render_poll(
            out,
            "healthy on 2xx",
            &Poll {
                url,
                url_label,
                attempts: *attempts,
                interval_ms: *interval_ms,
                timeout_ms: *timeout_ms,
            },
        ),
        DeployAction::Readiness {
            url,
            url_label,
            attempts,
            interval_ms,
            timeout_ms,
        } => render_poll(
            out,
            "ready on 2xx, unserved on 404",
            &Poll {
                url,
                url_label,
                attempts: *attempts,
                interval_ms: *interval_ms,
                timeout_ms: *timeout_ms,
            },
        ),
    }
}

/// The extract-and-swap step: the values of the config's and the run's that its script
/// embeds, one labelled line each — the app it works in, the release `current` must
/// still name, each shared file it links, each `prepare` command, how many releases it
/// keeps — then the script in full ([`DeployPlan::swap_script`], built from those same
/// values and the plan's).
///
/// Each line leads at the column the step's other lines do; the script's lines stand
/// further in, so none of its text stands where one of these does.
fn render_swap(out: &mut String, plan: &DeployPlan, swap: &ReleaseSwap) {
    const INDENT: &str = "      ";
    let _ = writeln!(out, "{INDENT}app: {}", escape_line(&swap.app));
    let _ = match &plan.previous {
        Some(previous) => writeln!(
            out,
            "{INDENT}replaces: {} — `current` must still name it",
            escape_line(previous)
        ),
        None => writeln!(
            out,
            "{INDENT}replaces: none — nothing may be at `current` yet"
        ),
    };
    for file in &swap.shared {
        let _ = writeln!(out, "{INDENT}links: shared/{}", escape_line(file));
    }
    for command in &swap.prepare {
        render_block(out, &format!("{INDENT}prepare: "), command);
    }
    let keeps = count(swap.keep as usize, "release", "releases");
    let _ = match &plan.previous {
        Some(previous) => writeln!(
            out,
            "{INDENT}keeps: {keeps}, counting this one and {}",
            escape_line(previous)
        ),
        None => writeln!(out, "{INDENT}keeps: {keeps}, counting this one"),
    };
    let _ = writeln!(
        out,
        "{INDENT}target script (its stdin: the archive's SHA-512):"
    );
    render_block(out, &format!("{INDENT}  "), &plan.swap_script(swap));
}

/// A polled URL and its budget, as a step holds them.
struct Poll<'a> {
    /// As declared: a reference in it resolves when it is polled.
    url: &'a str,
    /// With its references resolved, as the plan names it.
    url_label: &'a str,
    /// How many attempts.
    attempts: u32,
    /// The wait between two attempts, in milliseconds.
    interval_ms: u64,
    /// How long one attempt may take, in milliseconds.
    timeout_ms: u64,
}

/// A polled URL: one line that says the whole of what is done — the URL it polls, how
/// an answer is read (`reads`), and its budget ([`poll_budget`]) — and, where a
/// reference in it resolves, a second with the URL as declared, which names where its
/// domain comes from.
fn render_poll(out: &mut String, reads: &str, poll: &Poll<'_>) {
    let _ = writeln!(
        out,
        "      GET {} — {reads}; {}",
        escape_line(poll.url_label),
        poll_budget(poll)
    );
    if poll.url_label != poll.url {
        let _ = writeln!(out, "      declared as {}", escape_line(poll.url));
    }
}

/// How long a poll may run: its attempts, the wait between two, the time each is
/// given, and the most all of it takes — every wait and every attempt run to its limit.
fn poll_budget(poll: &Poll<'_>) -> String {
    let each = format_millis(poll.timeout_ms);
    if poll.attempts <= 1 {
        return format!(
            "{}, {each} at most",
            count(poll.attempts as usize, "attempt", "attempts")
        );
    }
    let total = u64::from(poll.attempts - 1)
        .saturating_mul(poll.interval_ms)
        .saturating_add(u64::from(poll.attempts).saturating_mul(poll.timeout_ms));
    format!(
        "up to {}, {} apart, {each} each ({} at most)",
        count(poll.attempts as usize, "attempt", "attempts"),
        format_millis(poll.interval_ms),
        format_millis(total)
    )
}

/// A plan's milliseconds as a preview states them: in hours, minutes and seconds, the
/// seconds with as many decimals as the value needs (`2s`, `1.5s`, `0.25s`, `1m 43s`,
/// `1m 32.5s`, `1h 5s`), so the value is stated exactly.
///
/// The wetrun's own durations (`format_elapsed`) are measured, so they are cut to a
/// tenth of a second, a second, or a minute (truncated, never rounded up) and take a
/// fixed shape, two parts with the second one padded (`1m 07s`, `1m 00s`), so they read
/// alike down the result table's time column. A plan's are declared: cut, one would
/// misstate what the poll does, so they are exact, and a part that is zero is left out
/// (`1m`, `1h 5s`) rather than padded.
pub(super) fn format_millis(ms: u64) -> String {
    let (hours, rest) = (ms / 3_600_000, ms % 3_600_000);
    let (minutes, rest) = (rest / 60_000, rest % 60_000);
    let (seconds, millis) = (rest / 1000, rest % 1000);
    let mut parts = Vec::new();
    if hours > 0 {
        parts.push(format!("{hours}h"));
    }
    if minutes > 0 {
        parts.push(format!("{minutes}m"));
    }
    if millis > 0 {
        let fraction = format!("{millis:03}");
        parts.push(format!("{seconds}.{}s", fraction.trim_end_matches('0')));
    } else if seconds > 0 || parts.is_empty() {
        parts.push(format!("{seconds}s"));
    }
    parts.join(" ")
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
            tag: String::new(),
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
            tag: String::new(),
            text: "--skip-preflight".to_owned(),
        },
        DriftPreflight::NothingDeclared => Row {
            status: "skip",
            id: "preflight".to_owned(),
            took: String::new(),
            tag: String::new(),
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
            tag: String::new(),
            text,
        });
    }
    if let Some(FailureState::AfterSwap(rollback)) = left {
        // the row's text is escaped as a block when it is written
        let previous = report
            .plan
            .previous
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
            tag: String::new(),
            text,
        });
    }
    render_rows(out, &rows);
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
    let previous = plan.previous.as_deref().map(escape_line);
    match &report.outcome {
        DeployOutcome::Deployed(run) => {
            let _ = writeln!(
                out,
                "deployed {} to {host} ({}) in {}",
                escape_line(&plan.version),
                replaces_text(plan),
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
