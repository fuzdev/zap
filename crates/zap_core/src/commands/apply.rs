//! `zap apply` — the convergence role: eval → detect → diff → execute.
//!
//! Dry-run by default (render the changeset, like `plan`); `--wetrun` executes the
//! plan fact against the target and re-detects to confirm it. Runs against a
//! local or SSH target (`eval_target` evals, gates the config, and binds the
//! connection). Reuses the same load →
//! detect → diff pipeline as `plan`, then walks the plan fact via `execute_plan`.
//!
//! **A wetrun executes only a reviewed plan.** The plan it computes must be the one
//! that was shown: either the hash `--expect-plan` names, or — by default — the one the
//! most recent preview on this host (`zap plan`, a dry `zap apply`, a refused wetrun)
//! recorded in the last-run report (`review_plan`). Otherwise it refuses before any
//! side effect, renders the plan it would have run, and records that preview — so the
//! everyday `zap apply` then `zap apply --wetrun` binds with no extra step, a wetrun
//! fired with nothing reviewed becomes the review, and an agent can prove the plan it
//! showed is the plan that ran. An empty plan needs no review. **One preview binds
//! one wetrun**: a wetrun that passes the gate claims the recorded preview
//! (`super::spend_review`) before the lock write and records its own pass only then,
//! so of two wetruns started on one preview exactly one executes, and the other stops
//! with nothing changed (`Error::PreviewSpent`).
//!
//! **On an interactive terminal the refusal is a question** (`super::prompt`): a wetrun
//! with no review and no `--expect-plan` shows the plan it computed, with its hash, and
//! asks for the start of that hash, which can't be typed before the plan is shown. Typed
//! back, it runs exactly that plan, the way a bound wetrun does; anything else is
//! the refusal above.
//!
//! **A plan is for one machine**, so the review is too: the plan carries the host and
//! the connecting user its target resolves to (`resolve_machine`), and the hash covers
//! them. A target whose host or connecting user resolves through a masked reference
//! names no one machine — its plan has no hash (`PlanAddress::Unbindable`), a dry run
//! shows it and records no preview, and a wetrun is refused before the connection is
//! touched.

use std::fmt::Write as _;
use std::path::Path;
use std::sync::Arc;

use zap_types::event::{ChangeOutcome, Event, RunSummary};
use zap_types::last_run::{PlanUnreviewed, RunCommand, review_plan};
use zap_types::lock::ZapLock;
use zap_types::plan::{HeldResource, HoldCause, Plan, ResidualResource, collect_residual};
use zap_types::schema::ZapConfig;

use super::prompt::{self, APPLY_QUESTION, Confirmation, Prompt};
use super::{
    Diffed, PassContext, PlanAddress, detect_and_diff, detect_pass, diff_unrecorded, eval_target,
    prepare_lock, record_pass, resolve_machine, target_location,
};
use crate::connection::Connection;
use crate::error::{Error, Previewed, Result};
use crate::escape::{escape_join, escape_line, render_block};
use crate::event::{EventHandler, mask_handler};
use crate::home::{last_run_path_for, zap_home_default};
use crate::last_run::{read_last_run, read_last_run_file};
use crate::lock::{ColdStart, lock_path_for, update_zap_lock};
use crate::progress::{Notice, ProgressSink};
use crate::resource::{Markers, execute_plan};
use crate::secret::mask_outcomes;

/// Knobs for an apply run. A struct (not positional bools) so call sites read
/// clearly and future phases (deploy) add a field rather than a fourth argument.
///
/// A flat bundle of CLI switches — `excessive_bools` targets domain types that encode
/// hidden state, not a 1:1 mirror of command-line flags.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, Default)]
pub struct ApplyOptions {
    /// Actually execute changes (`--wetrun`) rather than only previewing.
    pub wetrun: bool,
    /// The plan hash the wetrun must compute to execute (`--expect-plan`). `None` binds
    /// to the last preview on the host instead (module docs). A dry run rejects it.
    pub expect_plan: Option<String>,
    /// Stream the run's events to stdout as JSON-lines. Wetrun-only (a dry-run
    /// executes nothing); ignored otherwise.
    pub emit_json: bool,
    /// Skip all lock reads/writes and the cold-start pin resolve (offline escape
    /// hatch). Tracked `remote_file` resources then hold `Undetermined`.
    pub no_lock: bool,
    /// Connect as the target's `bootstrap_user` (the `--bootstrap` switch) — the initial
    /// provisioning run before SSH hardening creates the primary user.
    pub bootstrap: bool,
    /// Force a fresh config eval, bypassing the L0 eval cache (`--no-cache`). The fresh
    /// result is still written back.
    pub no_cache: bool,
    /// Where a wetrun with no review asks its operator to confirm the plan instead of
    /// refusing it (module docs). `None` never asks — every run but an interactive one.
    pub prompt: Option<Arc<dyn Prompt>>,
    /// Where a text-mode wetrun shows each change, and the re-detect after them, as it
    /// starts (`crate::progress`): the binary's standard error. `None` shows nothing
    /// live; `--json` streams events instead.
    pub progress: Option<Arc<dyn ProgressSink>>,
}

/// The outcome of an apply — the plan that was (or would be) applied, plus the
/// per-change execution outcomes on a wetrun.
///
/// Returned by `run_apply`; the binary renders it via [`render_apply`] and derives
/// the exit code from [`exit_code`].
///
/// [`exit_code`]: ApplyReport::exit_code
#[derive(Debug, Clone)]
pub struct ApplyReport {
    /// Target location label (`local`, or a host).
    pub target: String,
    /// Whether changes were actually executed (`--wetrun`) or only previewed.
    pub wetrun: bool,
    /// The ordered, mutation-only changeset (applied on a wetrun, previewed on a
    /// dry-run), with the machine it is for.
    pub plan: Plan,
    /// Content address of the whole plan — or, on a dry run of a config whose target
    /// names no one machine, why it has none. Always a hash on a wetrun.
    pub plan_hash: PlanAddress,
    /// Why the pass left no last-run report, when it left none: the target's host is a
    /// masking token (`unidentified_host_message`).
    pub unrecorded: Option<String>,
    /// Non-fatal plan-diff diagnostics (cycle fallbacks, dangling triggers).
    pub warnings: Vec<String>,
    /// Per-change outcomes, in plan order. Empty on a dry-run.
    pub outcomes: Vec<ChangeOutcome>,
    /// Derived run counts. `Some` only on a wetrun.
    pub summary: Option<RunSummary>,
    /// Tracked `remote_file` ids the cold-start resolve pass pinned this run —
    /// persisted to `zap.lock` on a wetrun, only previewed on a dry-run.
    pub auto_locked: Vec<String>,
    /// Referenced vars the comparison needed but couldn't resolve. Non-empty means the
    /// `plan` above is **not** evidence — it may hide drift or invent it. Always empty on
    /// a wetrun (the broader env preflight rejects those runs outright).
    pub unverifiable: Vec<String>,
    /// Resources whose live state couldn't be probed, so nothing was planned (or applied)
    /// for them. Unlike [`unverifiable`](Self::unverifiable) this **can** be non-empty on
    /// a wetrun: no up-front gate can predict a probe failure, so an apply that ran
    /// cleanly may still have left part of the target unconverged and unknown.
    pub held: Vec<HeldResource>,
    /// Resources the post-apply re-detection read as **not converged** (the Observe
    /// verdict): still absent or drifted — or unreadable — even though every command
    /// executed for them exited 0. Always empty on a dry-run (nothing executed, so
    /// nothing is re-detected). See [`zap_types::plan::collect_residual`] for what is
    /// exempt (`pipeline`, failed/skipped changes, held resources).
    pub residual: Vec<ResidualResource>,
    /// The post-apply re-detection itself failed (e.g. connectivity dropped after
    /// execution), so convergence was not established for *any* resource. `None` on a
    /// dry-run and on a wetrun whose re-detect ran.
    pub post_detect_error: Option<String>,
    /// A wetrun refused to execute because its plan wasn't the reviewed one (module
    /// docs): the reason, with `plan` the changeset it rendered instead. Nothing ran and
    /// nothing was written; the report reads like a dry run's. `None` on a dry run and
    /// on a wetrun that executed.
    pub refused: Option<PlanUnreviewed>,
    /// How the review went at the prompt, when the wetrun asked (module docs):
    /// [`Accepted`](Confirmation::Accepted) on one that executed what it showed,
    /// [`Declined`](Confirmation::Declined) on one that then
    /// [`refused`](Self::refused). `None` when nothing was asked.
    pub confirmation: Option<Confirmation>,
}

impl ApplyReport {
    /// Whether the run reached execution, and so emitted events: a `--json` wetrun that
    /// didn't (it [`refused`](Self::refused)) has streamed nothing, and its caller needs
    /// the text render to learn why.
    #[must_use]
    pub const fn streamed(&self) -> bool {
        self.wetrun && self.refused.is_none()
    }

    /// Process exit code: a wetrun is `1` if any change failed, else `0`; a dry-run
    /// is `2` when changes are pending (drift), else `0`. Mirrors the convergence
    /// drift-code convention (0 converged / 2 drifted / 1 error) the design assigns
    /// to `apply`.
    ///
    /// An **unverifiable** dry run is `1`, outranking both `0` and `2`: "converged" and
    /// "drifted" are both claims about the target, and neither was established. Matches
    /// `lock --check`, which also exits `1` rather than reporting a state it couldn't
    /// verify.
    ///
    /// A **held** resource is `1` on either side of the wet/dry split, for the same
    /// reason and one step further: a held resource is silently *absent* from the
    /// changeset, so without this an unprobeable target renders "(no changes —
    /// converged)" and exits `0`. On a wetrun the claim being refused is stronger still —
    /// "the target is now converged" — when part of it was never even read.
    ///
    /// **Residual** non-convergence is `1` on a wetrun for the same reason as a failed
    /// change: the wetrun's claim is "the target is now converged", and the post-apply
    /// re-detection either refuted it (`residual` non-empty) or couldn't run
    /// (`post_detect_error`), so the claim is false or unestablished. `2` stays the
    /// preview code — a wetrun that executed never exits `2`; one that **refused** to
    /// ([`refused`](Self::refused)) previewed instead, and takes the dry-run codes: `2`
    /// (the plan it rendered is pending review), or `1` when a resource is held.
    #[must_use]
    pub fn exit_code(&self) -> u8 {
        if !self.held.is_empty() {
            1
        } else if self.wetrun && self.refused.is_none() {
            let failed = self.summary.is_some_and(|s| s.failed > 0);
            u8::from(failed || !self.residual.is_empty() || self.post_detect_error.is_some())
        } else if !self.unverifiable.is_empty() {
            1
        } else if self.plan.changes.is_empty() {
            0
        } else {
            2
        }
    }
}

/// Apply role — eval, detect, diff, and (on `wetrun`) execute. Uses the default
/// `~/.zap`.
///
/// `options.emit_json` streams the run's [`Event`]s to stdout as JSON-lines (masked)
/// while a wetrun executes — the structured-output interface. It has no effect on a
/// dry-run (nothing executes) or on the returned report.
///
/// # Errors
/// Propagates config-eval, secret-validation (a literal secret in the config),
/// connectivity, detection, and plan-hashing failures;
/// [`Error::ExpectPlanWithoutWetrun`] for `--expect-plan` on a dry run, and
/// [`Error::WetrunRefused`] for a wetrun declined before its first change. Per-change
/// execution failures are recorded in the report's outcomes, not returned as an error.
pub async fn run_apply(
    config_path: &Path,
    fgro: Option<&Path>,
    options: ApplyOptions,
) -> Result<ApplyReport> {
    run_apply_in(zap_home_default()?.as_deref(), fgro, config_path, options).await
}

/// `run_apply` with the `~/.zap` root injected (the hermetic test seam, as for
/// `plan` / `detect` / `status`).
///
/// `None` turns off the eval cache, the content cache, the last-run report, and the
/// lock (which needs the content cache to resolve pins).
///
/// # Errors
/// Same as [`run_apply`].
pub async fn run_apply_in(
    zap_home: Option<&Path>,
    fgro: Option<&Path>,
    config_path: &Path,
    options: ApplyOptions,
) -> Result<ApplyReport> {
    if options.expect_plan.is_some() && !options.wetrun {
        return Err(Error::ExpectPlanWithoutWetrun);
    }
    // The seam runs the shared config gates and hands back the masker — regardless of
    // dry-run/wetrun, since a bad config is bad either way.
    let (config, conn, masker) = eval_target(
        config_path,
        zap_home,
        fgro,
        options.no_cache,
        options.bootstrap,
    )
    .await?;
    let ctx = PassContext {
        zap_home,
        config_path,
        masker: &masker,
        bootstrap: options.bootstrap,
    };
    apply_over(&conn, &config, ctx, options).await
}

/// Apply an evaluated, gated `config` over `conn`: [`run_apply_in`] past the config eval
/// and the connection bind — the seam the mock-driven tests enter.
///
/// # Errors
/// Same as [`run_apply`], less the config eval's — each masked by the run's masker.
pub(crate) async fn apply_over(
    conn: &Connection,
    config: &ZapConfig,
    ctx: PassContext<'_>,
    options: ApplyOptions,
) -> Result<ApplyReport> {
    // Boxed: the pass's future is large, and this one would hold it whole.
    super::masking_errors(
        ctx.masker,
        Box::pin(apply_unmasked(conn, config, ctx, options)),
    )
    .await
}

/// [`apply_over`], its errors as they were raised.
async fn apply_unmasked(
    conn: &Connection,
    config: &ZapConfig,
    ctx: PassContext<'_>,
    options: ApplyOptions,
) -> Result<ApplyReport> {
    let PassContext {
        zap_home,
        config_path,
        masker,
        bootstrap,
    } = ctx;
    let ApplyOptions {
        wetrun,
        expect_plan,
        emit_json,
        no_lock,
        bootstrap: _,
        no_cache: _,
        prompt,
        progress,
    } = options;

    // Fail-fast env preflight: a referenced variable with no value resolves to an
    // empty string and would be baked into a command, a written file, or a `.env` line
    // silently. A wetrun rejects here — before *any* side effect, the cold-start pin
    // resolve and the lock write below included.
    //
    // A dry-run executes nothing and keeps the refs inert, so it must still work without
    // the secrets — but it isn't off the hook either: the diff it is about to compute
    // resolves them, so it reports the narrower `unverifiable` verdict below.
    if wetrun && let Some(message) = super::unresolved_env_message(config) {
        return Err(Error::WetrunRefused(message));
    }
    let unverifiable = super::unverifiable_refs(config);

    // The machine the plan is for. One that names no one machine — its host or
    // connecting user is a masking token — has no hash to review, so a wetrun of it
    // stops here: before the cold-start pin resolve, the connection, and the lock write.
    let resolved = resolve_machine(config, masker, bootstrap)?;
    if wetrun && let Some(unbindable) = &resolved.unbindable {
        return Err(Error::WetrunRefused(unbindable_wetrun_message(unbindable)));
    }

    // Resolve the lock (load + cold-start auto-resolve of missing tracked pins). This
    // is the one network IO a dry-run does; persisted only on a wetrun, below.
    // A dry run previews: a pin it can't mint — the fetch url references an unset
    // variable — leaves that resource unpinned and held, where a wetrun (which the env
    // gate above already stopped) would fail.
    let cold_start = if wetrun {
        ColdStart::Mint
    } else {
        ColdStart::Preview
    };
    let resolved_lock = prepare_lock(config, config_path, zap_home, no_lock, cold_start).await?;
    let lock = resolved_lock.as_ref().map(|r| &r.lock);
    let auto_locked: Vec<String> = resolved_lock
        .as_ref()
        .map(|r| r.newly_resolved.iter().map(|id| id.0.clone()).collect())
        .unwrap_or_default();

    // The review a wetrun binds to by default: the last run on this host, read *before*
    // this pass replaces it. Looked up the way `status` looks it up (the machine's host
    // label). Not read when `--expect-plan` binds explicitly.
    let prior = if wetrun && expect_plan.is_none() {
        zap_home.and_then(|home| read_last_run(home, config_path, resolved.machine.host()))
    } else {
        None
    };

    // A dry run's pass is recorded now, as a preview. A wetrun's is recorded once it
    // has claimed the preview it binds to (below), as the "before" the re-detection
    // replaces — or as the refusal it becomes. Recorded now, it would replace that
    // preview unclaimed, and two wetruns that read one preview would both run it.
    let Diffed {
        result,
        plan_hash: address,
        pass,
        ..
    } = if wetrun {
        diff_unrecorded(conn, config, ctx, &resolved, lock).await?
    } else {
        detect_and_diff(conn, config, ctx, &resolved, lock, RunCommand::Apply).await?
    };
    let (plan, mut warnings, mut held) = (result.plan, result.warnings, result.held);
    let unrecorded = resolved.unidentified_host.clone();
    // An unpinned resource holds with the hint to mint its pin; one this run tried to
    // mint and couldn't says why instead.
    for unmintable in resolved_lock.iter().flat_map(|r| &r.unmintable) {
        if let Some(HeldResource {
            cause: HoldCause::Undetermined { reason },
            ..
        }) = held.iter_mut().find(|h| h.resource_id == unmintable.id)
        {
            *reason = format!(
                "no pin could be minted — its fetch url references {}, unset or empty in \
                 the environment; set it and re-run",
                unmintable.vars
            );
        }
    }
    // A held resource's reason names the seam-resolved path/identifier its probe failed
    // on, which can carry a reference's resolved value — mask it like every other engine output.
    super::mask_diagnostics(masker, &mut warnings, &mut held);

    // The command preflight: a change whose command text can't take a value its
    // references resolve to. A preview says so beside the plan; a wetrun stops on it
    // below, once the review gate has passed.
    let unrunnable = super::unrunnable_changes(&plan);

    // A report that executed nothing: the plan as rendered, under `address`.
    let preview = |plan: Plan,
                   address: PlanAddress,
                   warnings: Vec<String>,
                   held: Vec<HeldResource>,
                   refused: Option<PlanUnreviewed>,
                   confirmation: Option<Confirmation>| ApplyReport {
        target: target_location(&config.target),
        wetrun,
        plan,
        plan_hash: address,
        unrecorded: unrecorded.clone(),
        warnings,
        outcomes: Vec::new(),
        summary: None,
        auto_locked: auto_locked.clone(),
        unverifiable: unverifiable.clone(),
        held,
        residual: Vec::new(),
        post_detect_error: None,
        refused,
        confirmation,
    };

    // A dry run ends here, with whatever address its plan has. Only a wetrun goes on,
    // and only with a hash: one whose plan has none was refused above, and must not
    // execute if it ever got this far.
    let hash = match (wetrun, address) {
        (true, PlanAddress::Hash(hash)) => hash,
        (true, PlanAddress::Unbindable(reason)) => {
            return Err(Error::WetrunRefused(unbindable_wetrun_message(&reason)));
        }
        (false, address) => {
            super::warn_unrunnable(&mut warnings, unrunnable);
            return Ok(preview(plan, address, warnings, held, None, None));
        }
    };

    // The review gate (module docs). Before the lock write and before any change: a
    // refusal has no side effect. An empty plan executes nothing, so it needs no review.
    let mut refused = if plan.changes.is_empty() {
        None
    } else {
        review_plan(&hash, expect_plan.as_deref(), prior.as_ref()).err()
    };
    // Whether the review is the recorded preview, which this run must then claim.
    let bound_to_record = refused.is_none() && expect_plan.is_none() && !plan.changes.is_empty();
    // With nothing reviewed, an interactive operator reviews the plan here: shown as a
    // refusal would show it, and run when the start of its hash is typed back. Not a
    // plan the command preflight below stops — a confirmation could only fail.
    let mut confirmation = None;
    if let Some(reason) = &refused
        && unrunnable.is_empty()
    {
        confirmation = prompt::confirm(
            prompt.as_deref(),
            emit_json,
            reason,
            &hash,
            || {
                render_apply(&preview(
                    plan.clone(),
                    PlanAddress::Hash(hash.clone()),
                    warnings.clone(),
                    held.clone(),
                    refused.clone(),
                    Some(Confirmation::Asking),
                ))
            },
            APPLY_QUESTION,
        );
        if confirmation == Some(Confirmation::Accepted) {
            refused = None;
        }
    }
    if refused.is_some() {
        // This pass rendered the plan without running it — a preview. Recorded as one
        // so the next wetrun can bind to it.
        record_pass(
            ctx,
            config,
            &resolved,
            &pass,
            RunCommand::ApplyRefused,
            Some(&hash),
        );
        super::warn_unrunnable(&mut warnings, unrunnable);
        return Ok(preview(
            plan,
            PlanAddress::Hash(hash),
            warnings,
            held,
            refused,
            confirmation,
        ));
    }

    if !unrunnable.is_empty() {
        // Before the lock write and before any change: a refusal has no side effect. The
        // plan was the reviewed one, and none of it ran — recorded as the preview it
        // was, so the wetrun that follows the fix needs no second review.
        record_pass(
            ctx,
            config,
            &resolved,
            &pass,
            RunCommand::ApplyRefused,
            Some(&hash),
        );
        return Err(Error::WetrunRefused(super::unrunnable_message(&unrunnable)));
    }

    // The review is spent here, before the lock write and the first change: of the
    // wetruns that read one preview, only the one that claims it goes on, and an
    // executed wetrun — whether it succeeds, fails, or is interrupted — leaves no
    // preview a second one could bind to. Then the pass is recorded as the "before".
    if let Some(home) = zap_home {
        super::spend_review(
            &last_run_path_for(home, config_path, resolved.machine.host()),
            Previewed::Apply,
            bound_to_record,
            |taken| review_plan(&hash, None, read_last_run_file(taken).as_ref()).is_ok(),
        )?;
    }
    record_pass(
        ctx,
        config,
        &resolved,
        &pass,
        RunCommand::ApplyBeforeChanges,
        Some(&hash),
    );

    // The plan that passed the gate names what each reference it uses resolves to;
    // its steps resolve them again as they run. Nothing of it runs unless both agree.
    super::check_references(&plan, &crate::last_run::report_var(config, masker))?;

    let (outcomes, summary, residual, post_detect_error) = {
        // Persist the resolved lock (the operator-side intent ledger) before executing —
        // a write failure aborts before any work, so we never apply without recording
        // intent. Skip an empty lock (nothing to pin → don't litter an empty file).
        // TODO: `remote_file` pins resolve at planning, so one upfront write is correct
        // here. Witnesses (`installed_version`, deferred) must instead be written
        // per-resource *after* their `change_completed` (a witness records what an apply
        // observed, so it can't exist before the change ran) — wire that into
        // `execute_plan`'s outcome loop when witnesses land, not here.
        // The write merges into what the lock holds now: an entry another writer (`zap
        // update`) put there since planning read it is kept, and this run adds only what
        // the lock still lacks.
        if let Some(resolved) = &resolved_lock
            && !resolved.lock.entries.is_empty()
        {
            update_zap_lock(&lock_path_for(config_path), |current| {
                merge_resolved_lock(current, &resolved.lock);
            })?;
        }
        // Stream events live as the plan executes. The `mask_handler` decorator masks
        // each event at the emission boundary, reusing the run's masker — so the
        // stream is masked exactly as `mask_outcomes` masks the batch report below.
        // `emit_json` selects the stdout JSON-lines sink; otherwise each change shows on
        // the operator's progress lines as it starts, and the text report is the record.
        // `execute_plan` itself stays masking-unaware.
        let inner = EventHandler::for_run(emit_json, progress.as_ref());
        let handler = mask_handler(masker.clone(), inner);
        handler.emit(&Event::RunStarted {
            target: target_location(&config.target),
            wetrun,
            plan_hash: hash.clone(),
            total: u32::try_from(plan.changes.len()).unwrap_or(u32::MAX),
        });

        // Mask resolved secrets out of the outcomes (command stdout/stderr) at the
        // consumption boundary — `execute_plan` stays masking-unaware.
        let outcomes = mask_outcomes(masker, execute_plan(conn, &plan, zap_home, &handler).await);
        let summary = RunSummary::from_outcomes(&outcomes);
        handler.emit(&Event::RunFinished { summary });
        // Post-apply re-detect — the Observe pass, consumed twice from one probe run.
        // It is the last-run report (the last word on what this apply left), and it is
        // the convergence verdict: a change can exit 0 without converging its resource,
        // so the claim a wetrun makes is established by re-reading the target, not by
        // command exit codes.
        // Best-effort in one direction only — the changes already ran, so a re-detect
        // failure must not *abort* the apply, but it does cost the exit code
        // (`post_detect_error`): "converged" was not established. Masked like every
        // other engine output that interpolates engine-read values (an undetermined
        // reason names a seam-resolved path; a drift carries observed state).
        handler.notice(Notice::Redetect {
            resources: config.resources.len(),
        });
        let (residual, post_detect_error) = match detect_pass(
            conn,
            config,
            ctx,
            &resolved,
            lock,
            Markers::Skip,
            RunCommand::ApplyAfterChanges,
        )
        .await
        {
            Ok(pass) => (
                collect_residual(&config.resources, &pass.detections, &outcomes, &held)
                    .iter()
                    .map(|residual| residual.map_text(|text| masker.mask(text)))
                    .collect(),
                None,
            ),
            Err(error) => (Vec::new(), Some(masker.mask(&error.to_string()))),
        };
        (outcomes, Some(summary), residual, post_detect_error)
    };

    Ok(ApplyReport {
        target: target_location(&config.target),
        wetrun,
        plan,
        plan_hash: PlanAddress::Hash(hash),
        unrecorded,
        warnings,
        outcomes,
        summary,
        auto_locked,
        unverifiable,
        held,
        residual,
        post_detect_error,
        refused: None,
        confirmation,
    })
}

/// The error a wetrun stops with when its plan names no one machine (`reason`, a
/// `ResolvedMachine::unbindable`).
fn unbindable_wetrun_message(reason: &str) -> String {
    format!("an apply wetrun needs a plan that names one machine — nothing ran: {reason}")
}

/// Render an [`ApplyReport`] to the text shown by `zap apply`.
#[must_use]
pub fn render_apply(report: &ApplyReport) -> String {
    let mut out = String::new();
    let mode = match (report.wetrun, &report.refused, report.confirmation) {
        (false, ..) => "dry-run",
        (true, None, Some(Confirmation::Accepted)) => "wetrun, confirmed",
        (true, None, _) => "wetrun",
        (true, Some(_), Some(Confirmation::Asking)) => "wetrun, awaiting confirmation",
        (true, Some(_), Some(Confirmation::Declined)) => "wetrun, declined",
        (true, Some(_), None | Some(Confirmation::Accepted)) => "wetrun, refused",
    };
    let _ = writeln!(
        out,
        "apply — target {} ({mode})",
        escape_line(&report.target)
    );
    super::render_plan_subject(&mut out, &report.target, &report.plan);
    super::render_unverifiable(&mut out, &report.unverifiable);
    super::render_undetermined(&mut out, &report.held);

    let executed = report.wetrun && report.refused.is_none();
    if executed {
        render_outcomes(&mut out, report);
        render_residual(&mut out, report);
    } else {
        render_preview(&mut out, report);
    }
    if let (Some(reason), Some(hash)) = (&report.refused, report.plan_hash.hash()) {
        render_refused(&mut out, reason, hash, report.confirmation);
    }

    if !report.auto_locked.is_empty() {
        let ids = escape_join(&report.auto_locked, ", ");
        if executed {
            let _ = writeln!(out, "locked: {ids}");
        } else {
            // Not "would fetch" — the fetch already happened. A dry run resolves missing
            // pins over the network (the one network IO it does) and holds the result in
            // memory; only the *ledger write* waits for `--wetrun`.
            let _ = writeln!(
                out,
                "resolved, not yet written to zap.lock (run --wetrun to record): {ids}"
            );
        }
    }

    super::render_warnings(&mut out, &report.warnings);
    super::render_unrecorded(&mut out, report.unrecorded.as_deref());
    super::render_address(&mut out, &report.plan_hash);
    out
}

/// Dry-run body: the planned changeset, plus a hint to apply it.
fn render_preview(out: &mut String, report: &ApplyReport) {
    let changes = &report.plan.changes;
    if changes.is_empty() {
        let _ = writeln!(out, "{}", super::empty_changeset_line(&report.held));
        return;
    }
    for change in changes {
        super::render_change(out, change);
    }
    // A plan with no address says what a wetrun does with it at its foot instead.
    if report.refused.is_none() && report.plan_hash.hash().is_some() {
        let _ = writeln!(out, "  (dry-run — re-run with --wetrun to apply)");
    }
}

/// The refusal under the rendered plan: why this wetrun didn't bind to a review
/// ([`render_refused`](super::render_refused)), and how the next one does — or, under
/// the prompt's question, why it is asked.
fn render_refused(
    out: &mut String,
    reason: &PlanUnreviewed,
    plan_hash: &str,
    confirmation: Option<Confirmation>,
) {
    super::render_refused(out, reason, &super::APPLY_REFUSAL, confirmation);
    if confirmation == Some(Confirmation::Asking) {
        return;
    }
    let _ = writeln!(
        out,
        "  review the plan above, then re-run `zap apply --wetrun` (it binds to this \
         preview) or pass --expect-plan {plan_hash}"
    );
}

/// Render the `residual` verdict — the post-apply banner that retracts the summary
/// line's implied "converged" when the re-detection says otherwise. No-op when the
/// re-detect ran and read everything converged.
fn render_residual(out: &mut String, report: &ApplyReport) {
    if let Some(error) = &report.post_detect_error {
        render_block(
            out,
            "  RESIDUAL — the post-apply re-detection failed, so convergence was not \
             established: ",
            error,
        );
        return;
    }
    if report.residual.is_empty() {
        return;
    }
    let _ = writeln!(
        out,
        "  RESIDUAL — {} resource(s) do not read converged after this apply:",
        report.residual.len()
    );
    for entry in &report.residual {
        let lead = format!("      {} — ", escape_line(&entry.resource_id.0));
        render_block(out, &lead, &entry.state.describe());
    }
    let _ = writeln!(
        out,
        "  their commands (if any) exited 0, but re-detection did not confirm the \
         declared state. inspect them (zap plan --diff) and re-run."
    );
}

/// Wetrun body: per-change outcome lines + the run summary.
fn render_outcomes(out: &mut String, report: &ApplyReport) {
    if report.outcomes.is_empty() {
        let _ = writeln!(out, "{}", super::empty_changeset_line(&report.held));
    }
    for outcome in &report.outcomes {
        match outcome {
            ChangeOutcome::Completed { resource_id, .. } => {
                let _ = writeln!(out, "  ok    {}", escape_line(&resource_id.0));
            }
            // A failure quotes what the command or the target said, which can run to
            // several lines: a block under the outcome's own line.
            ChangeOutcome::Failed {
                resource_id,
                error,
                code,
            } => {
                let lead = format!("  FAIL  {}  [{code:?}]  — ", escape_line(&resource_id.0));
                render_block(out, &lead, error);
            }
            ChangeOutcome::Skipped {
                resource_id,
                reason,
            } => {
                let lead = format!("  skip  {}  — ", escape_line(&resource_id.0));
                render_block(out, &lead, reason);
            }
        }
    }
    if let Some(summary) = report.summary {
        let _ = writeln!(
            out,
            "applied: {} ok, {} failed, {} skipped (of {})",
            summary.completed, summary.failed, summary.skipped, summary.total
        );
    }
}

/// Merge the lock this run resolved into `current`, the lock as it stands now: each entry
/// `current` lacks is added, and every entry it holds is kept — another writer's (`zap
/// update`'s) since this run read the lock included. The toolchain pin is added only
/// when `current` has none.
fn merge_resolved_lock(current: &mut ZapLock, resolved: &ZapLock) {
    for (id, entry) in &resolved.entries {
        current
            .entries
            .entry(id.clone())
            .or_insert_with(|| entry.clone());
    }
    if current.toolchain.is_none() {
        current.toolchain.clone_from(&resolved.toolchain);
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Read as _, Write as _};

    /// The run's resolved lock merges into the lock as it stands: an entry another
    /// writer advanced since the run read it is kept, a pin only the run minted is added,
    /// and a toolchain already pinned stays.
    #[test]
    fn the_resolved_lock_keeps_what_another_writer_wrote() {
        use std::collections::BTreeMap;

        use zap_types::lock::{LockEntry, Toolchain, ZapLock};
        use zap_types::scalar::ContentHash;
        use zap_types::schema::ResourceId;

        let entry = |pin: &[u8]| LockEntry::RemoteFile {
            config_hash: "h".to_owned(),
            blake3: ContentHash::of_bytes(pin),
        };
        let id = |id: &str| ResourceId(id.to_owned());
        let toolchain = |pin: &[u8]| {
            Some(Toolchain {
                fgro_blake3: ContentHash::of_bytes(pin),
            })
        };
        let resolved = ZapLock {
            toolchain: toolchain(b"old"),
            entries: BTreeMap::from([(id("zig"), entry(b"read")), (id("new"), entry(b"minted"))]),
            ..ZapLock::default()
        };
        let mut current = ZapLock {
            toolchain: toolchain(b"repinned"),
            entries: BTreeMap::from([(id("zig"), entry(b"advanced"))]),
            ..ZapLock::default()
        };
        super::merge_resolved_lock(&mut current, &resolved);
        assert_eq!(
            current.entries,
            BTreeMap::from([
                (id("zig"), entry(b"advanced")),
                (id("new"), entry(b"minted"))
            ])
        );
        assert_eq!(current.toolchain, toolchain(b"repinned"));
    }

    use zap_types::last_run::RunCommand;
    use zap_types::text::Text;
    use zap_types::var_ref::Segment::{Ref, Text as Lit};
    use zap_types::var_ref::shown;

    use super::{ApplyOptions, render_apply, run_apply_in};
    use crate::commands::tests::{fgro, fgro_available};
    use crate::error::Error;
    use crate::last_run::read_last_run;
    use crate::lock::lock_path_for;

    /// A reference to `name` as a `target:` line prints it: the JSON it is declared as.
    fn declared_json(name: &str) -> String {
        serde_json::to_string(&Text::reference(name)).unwrap()
    }

    /// A throwaway HTTP/1.1 server: serves `body` to every request (each mint fetches),
    /// returns its url.
    fn serve(body: Vec<u8>) -> String {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            for mut sock in listener.incoming().flatten() {
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
        format!("http://{addr}/blob")
    }

    /// A `run`, as a config writes it, that prints the value of `ZAP_T_VALUE` to the
    /// file at `path` from inside single quotes.
    fn printing_the_value_to(path: &str) -> String {
        ["`printf '%s' '${zap.env('ZAP_T_VALUE')}' > '", path, "'`"].concat()
    }

    /// A plan holding a command that can't take the value its reference resolves to: the
    /// preview warns that its wetrun will be refused (the plan itself is sound), and the
    /// wetrun stops before anything — no earlier change, no lock write — recorded as the
    /// preview it was, so the wetrun after the fix runs without a second review.
    /// fgro-gated (config eval).
    #[tokio::test]
    async fn a_command_that_cannot_take_its_value_stops_a_wetrun_before_anything() {
        if !fgro_available() {
            eprintln!("skipping the wetrun preflight test: ZAP_FGRO not set");
            return;
        }
        let proj = crate::commands::scratch_tempdir().unwrap();
        let home = crate::commands::scratch_tempdir().unwrap();
        let config_path = proj.path().join("zap.ts");
        let at = |name: &str| proj.path().join(name).to_string_lossy().into_owned();
        let run = printing_the_value_to(&at("ran"));
        crate::commands::scratch_write_config(
            &config_path,
            format!(
                r"
export default (zap) => {{
    zap.target({{local: true}});
    zap.file({{id: 'first', path: {first:?}, content: {{type: 'inline', content: 'x'}}}});
    zap.file({{id: 'blob', path: {blob:?},
        content: {{type: 'remote', url: {url:?}, extract: {{type: 'none'}}}}}});
    zap.script({{id: 'go', check: 'false', depends_on: ['first'],
        run: {run}}});
}};
",
                first = at("first"),
                blob = at("blob"),
                url = serve(b"blob bytes".to_vec()),
            ),
        )
        .unwrap();
        let wetrun = || ApplyOptions {
            wetrun: true,
            ..ApplyOptions::default()
        };
        let lock = lock_path_for(&config_path);
        let written = std::fs::read(&lock).ok();

        let unsafe_value = crate::resolve::test_env::set(&[("ZAP_T_VALUE", "it's secret")]);
        // `zap plan` says so beside its plan. It mints no pin, so it holds `blob`; `go`
        // doesn't depend on it (it runs after it by id), so `go` isn't held behind it.
        let planned = crate::commands::plan::run_plan_in(
            Some(home.path()),
            fgro(),
            &config_path,
            false,
            false,
        )
        .await
        .unwrap();
        assert!(
            planned.warnings.iter().any(
                |warning| warning.starts_with("a wetrun of this plan will be refused — `go`: ")
            ),
            "{:?}",
            planned.warnings
        );
        let held: Vec<&str> = planned
            .held
            .iter()
            .map(|held| held.resource_id.0.as_str())
            .collect();
        assert_eq!(held, ["blob"]);

        let dry = run_apply_in(
            Some(home.path()),
            fgro(),
            &config_path,
            ApplyOptions::default(),
        )
        .await
        .unwrap();
        assert_eq!(dry.plan.changes.len(), 3);
        assert_eq!(
            dry.exit_code(),
            2,
            "the plan is sound: drift, not a verdict"
        );
        let rendered = render_apply(&dry);
        assert!(
            rendered.contains("warning: a wetrun of this plan will be refused — `go`: "),
            "{rendered}"
        );
        assert!(
            rendered.contains(&format!("`{}`", shown("ZAP_T_VALUE"))),
            "{rendered}"
        );
        assert!(
            rendered.contains("Pass it through this script's `env`"),
            "{rendered}"
        );
        // The message names the reference and never its value, which a preview prints in
        // one place: the plan's references.
        assert_eq!(rendered.matches("secret").count(), 1, "{rendered}");
        assert!(
            rendered.contains("\n  references:\n    ZAP_T_VALUE = it's secret\n"),
            "{rendered}"
        );

        let refused = run_apply_in(Some(home.path()), fgro(), &config_path, wetrun()).await;
        let Err(Error::WetrunRefused(message)) = refused else {
            panic!(
                "the wetrun is refused: {}",
                refused.map_or_else(|error| error.to_string(), |report| render_apply(&report))
            );
        };
        assert!(message.contains("`go`: "), "{message}");
        assert!(
            message.contains(&format!("`{}`", shown("ZAP_T_VALUE"))),
            "{message}"
        );
        assert!(message.contains("nothing was changed"), "{message}");
        assert!(!message.contains("secret"), "{message}");
        assert_eq!(Error::WetrunRefused(message).exit_code(), 2);
        // Nothing ran — not the changes ahead of the refused one — and no lock was
        // written.
        for made in ["first", "blob", "ran"] {
            assert!(!proj.path().join(made).exists(), "{made}");
        }
        // The lock is the one the test wrote: no entry minted, the pin as it was.
        assert_eq!(std::fs::read(&lock).ok(), written);
        let recorded = read_last_run(home.path(), &config_path, "local").unwrap();
        assert_eq!(recorded.command, RunCommand::ApplyRefused);
        assert_eq!(recorded.plan_hash.as_deref(), dry.plan_hash.hash());

        // With a value the command can take, the plan is another plan — its hash covers
        // the value its reference resolves to — so it is reviewed before it runs: the
        // wetrun is refused for review, and the one after it binds to that preview.
        drop(unsafe_value);
        let _safe = crate::resolve::test_env::set(&[("ZAP_T_VALUE", "a $HOME \"value\"")]);
        let reviewed = run_apply_in(Some(home.path()), fgro(), &config_path, wetrun())
            .await
            .unwrap();
        assert!(
            matches!(reviewed.refused, Some(PlanUnreviewed::Changed { .. })),
            "{}",
            render_apply(&reviewed)
        );
        assert_ne!(reviewed.plan_hash, dry.plan_hash);
        assert!(!proj.path().join("ran").exists());
        let wet = run_apply_in(Some(home.path()), fgro(), &config_path, wetrun())
            .await
            .unwrap();
        assert!(wet.refused.is_none(), "{}", render_apply(&wet));
        assert_eq!(wet.plan_hash, reviewed.plan_hash);
        assert_eq!(
            std::fs::read_to_string(proj.path().join("ran")).unwrap(),
            "a $HOME \"value\""
        );
        assert!(lock.exists());
    }

    /// A wetrun nobody previewed is refused by the review gate even when its plan also
    /// holds a command that can't take its value: the refusal renders the plan (with the
    /// finding beside it) and is the preview the next wetrun binds to — the command
    /// preflight never stands in for a review. fgro-gated (config eval).
    #[tokio::test]
    async fn an_unreviewed_wetrun_is_refused_for_review_before_its_commands_are_checked() {
        if !fgro_available() {
            eprintln!("skipping the review-before-preflight test: ZAP_FGRO not set");
            return;
        }
        let proj = crate::commands::scratch_tempdir().unwrap();
        let home = crate::commands::scratch_tempdir().unwrap();
        let config_path = proj.path().join("zap.ts");
        let ran = proj.path().join("ran").to_string_lossy().into_owned();
        let run = printing_the_value_to(&ran);
        crate::commands::scratch_write_config(
            &config_path,
            format!(
                r"
export default (zap) => {{
    zap.target({{local: true}});
    zap.script({{id: 'go', check: 'false', run: {run}}});
}};
"
            ),
        )
        .unwrap();
        let wetrun = || ApplyOptions {
            wetrun: true,
            ..ApplyOptions::default()
        };
        let _unsafe_value = crate::resolve::test_env::set(&[("ZAP_T_VALUE", "it's secret")]);

        let first = run_apply_in(Some(home.path()), fgro(), &config_path, wetrun())
            .await
            .unwrap();
        assert_eq!(
            first.refused,
            Some(PlanUnreviewed::NoPreview { prior: None }),
            "{}",
            render_apply(&first)
        );
        assert!(first.outcomes.is_empty());
        let rendered = render_apply(&first);
        assert!(
            rendered.contains("warning: a wetrun of this plan will be refused — `go`: "),
            "{rendered}"
        );
        // The message names the reference and never its value, which a preview prints in
        // one place: the plan's references.
        assert_eq!(rendered.matches("secret").count(), 1, "{rendered}");
        assert!(
            rendered.contains("\n  references:\n    ZAP_T_VALUE = it's secret\n"),
            "{rendered}"
        );

        // The plan it rendered is now the reviewed one, so the next wetrun gets as far as
        // its commands — and stops there.
        let second = run_apply_in(Some(home.path()), fgro(), &config_path, wetrun()).await;
        assert!(matches!(second, Err(Error::WetrunRefused(_))));
        assert!(!proj.path().join("ran").exists());
    }

    use std::path::PathBuf;

    use zap_types::last_run::{PlanUnreviewed, Verdict};
    use zap_types::observe::{CommandObservation, Observation, Query};
    use zap_types::plan::{LocalAccount, Machine};
    use zap_types::schema::ZapConfig;

    use super::{ApplyReport, apply_over};
    use crate::commands::detect::{DetectReport, detect_over, render_detect};
    use crate::commands::plan::{PlanReport, plan_over, render_plan, render_plan_diff};
    use crate::commands::status::{Standing, StatusReport, render_status, status_over};
    use crate::commands::{PassContext, PlanAddress};
    use crate::connection::{CommandOutput, Connection, MockConnection};
    use crate::home::last_run_dir_for;
    use crate::last_run::write_last_run;
    use crate::secret::{SecretMasker, SecretRegistry};

    /// The command the rig's one resource runs.
    const RUN: &str = "touch /srv/ready";

    /// A remote config over a mock target: one `script` whose check fails, so every
    /// plan is the one change that runs [`RUN`].
    struct Rig {
        home: tempfile::TempDir,
        config_path: PathBuf,
        config: ZapConfig,
        masker: SecretMasker,
        target: MockConnection,
    }

    impl Rig {
        /// A target declaring `host`, connecting as `deploy` (`root` under
        /// `--bootstrap`).
        fn on(host: impl serde::Serialize) -> Self {
            Self::with_target(&serde_json::json!({
                "host": host, "user": "deploy", "bootstrap_user": "root",
            }))
        }

        fn with_target(target: &serde_json::Value) -> Self {
            Self::with(target, &Text::literal(RUN))
        }

        /// A rig on `a.example.com` whose one resource runs `run` — a command that holds
        /// references — in place of [`RUN`]. The mock records no command for it, so a
        /// run of it fails its change.
        fn running(run: &Text) -> Self {
            Self::with(
                &serde_json::json!({"host": "a.example.com", "user": "deploy"}),
                run,
            )
        }

        fn with(target: &serde_json::Value, run: &Text) -> Self {
            let home = crate::commands::scratch_tempdir().unwrap();
            let config_path = home.path().join("zap.ts");
            let config = serde_json::from_value(serde_json::json!({
                "target": target,
                "resources": [{"id": "go", "type": "script",
                               "check": "test -e /srv/ready", "run": run}],
            }))
            .unwrap();
            let target = MockConnection::new("mock")
                .with_observation(
                    Query::operator_command("test -e /srv/ready"),
                    Observation::Command(CommandObservation {
                        code: 1,
                        stdout: Vec::new(),
                        stderr: Vec::new(),
                    }),
                )
                .with(
                    RUN,
                    CommandOutput {
                        success: true,
                        code: 0,
                        stdout: String::new(),
                        stderr: String::new(),
                    },
                );
            Self {
                home,
                config_path,
                config,
                masker: SecretRegistry::new().freeze().unwrap(),
                target,
            }
        }

        fn ctx(&self, bootstrap: bool) -> PassContext<'_> {
            PassContext {
                zap_home: Some(self.home.path()),
                config_path: &self.config_path,
                masker: &self.masker,
                bootstrap,
            }
        }

        async fn apply(&self, options: ApplyOptions) -> crate::error::Result<ApplyReport> {
            let conn = Connection::Mock(self.target.clone());
            apply_over(&conn, &self.config, self.ctx(options.bootstrap), options).await
        }

        async fn dry(&self) -> ApplyReport {
            self.apply(ApplyOptions::default()).await.unwrap()
        }

        async fn plan(&self) -> PlanReport {
            let conn = Connection::Mock(self.target.clone());
            plan_over(&conn, &self.config, self.ctx(false))
                .await
                .unwrap()
        }

        async fn detect(&self) -> DetectReport {
            let conn = Connection::Mock(self.target.clone());
            detect_over(&conn, &self.config, self.ctx(false))
                .await
                .unwrap()
        }

        fn status(&self) -> StatusReport {
            status_over(
                Some(self.home.path()),
                &self.config_path,
                &self.config,
                &self.masker,
            )
            .unwrap()
        }

        /// Whether the plan's command ran.
        fn ran(&self) -> bool {
            self.target.issued(RUN)
        }

        /// Every last-run report filed for the config, for any host.
        fn reports_on_disk(&self) -> Vec<String> {
            let Ok(entries) =
                std::fs::read_dir(last_run_dir_for(self.home.path(), &self.config_path))
            else {
                return Vec::new();
            };
            let mut names: Vec<String> = entries
                .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
                .collect();
            names.sort();
            names
        }
    }

    fn wetrun() -> ApplyOptions {
        ApplyOptions {
            wetrun: true,
            ..ApplyOptions::default()
        }
    }

    fn wetrun_expecting(hash: &str) -> ApplyOptions {
        ApplyOptions {
            expect_plan: Some(hash.to_owned()),
            ..wetrun()
        }
    }

    /// One preview binds one wetrun. Two wetruns started on one preview both read it
    /// before either goes on (each target's first read waits for the other's); the one
    /// that claims it executes, and the other stops with nothing run and nothing
    /// recorded, the winner's report left standing. A preview a wetrun executed is
    /// spent, so a third wetrun is refused.
    #[tokio::test]
    async fn two_wetruns_on_one_preview_execute_it_once() {
        use crate::error::{Error, Previewed};

        let rig = Rig::on("a.example.com");
        let preview = rig.dry().await;
        let barrier = Arc::new(tokio::sync::Barrier::new(2));
        let wetrun_over = |target: MockConnection| {
            let conn = Connection::Mock(target);
            let rig = &rig;
            async move { apply_over(&conn, &rig.config, rig.ctx(false), wetrun()).await }
        };
        let (first, second) = tokio::join!(
            wetrun_over(rig.target.clone().with_rendezvous(Arc::clone(&barrier))),
            wetrun_over(rig.target.clone().with_rendezvous(Arc::clone(&barrier))),
        );

        let runs = rig
            .target
            .issued_commands()
            .iter()
            .filter(|command| *command == RUN)
            .count();
        assert_eq!(runs, 1, "{first:?}\n{second:?}");
        let (ran, stopped) = match (first, second) {
            (Ok(ran), Err(stopped)) | (Err(stopped), Ok(ran)) => (ran, stopped),
            other => panic!("one run executes and one stops: {other:?}"),
        };
        assert_eq!(ran.refused, None);
        assert_eq!(hash_of(&ran), hash_of(&preview));
        assert!(ran.summary.is_some());
        assert!(
            matches!(
                stopped,
                Error::PreviewSpent {
                    of: Previewed::Apply
                }
            ),
            "{stopped:?}"
        );
        assert_eq!(stopped.exit_code(), 2);
        assert_eq!(
            stopped.to_string(),
            "the preview this wetrun bound to was withdrawn or replaced by another run \
             before this one's first change — this run changed nothing; preview again \
             with `zap apply`, or pass --expect-plan"
        );
        let last = || {
            read_last_run(rig.home.path(), &rig.config_path, "a.example.com").map(|run| run.command)
        };
        assert_eq!(last(), Some(RunCommand::ApplyAfterChanges));
        assert_eq!(rig.reports_on_disk(), ["a.example.com.json"]);

        let third = rig.apply(wetrun()).await.unwrap();
        assert_eq!(
            third.refused,
            Some(PlanUnreviewed::NoPreview {
                prior: Some(RunCommand::ApplyAfterChanges)
            })
        );
        assert_eq!(
            rig.target
                .issued_commands()
                .iter()
                .filter(|c| *c == RUN)
                .count(),
            1
        );
    }

    /// A wetrun that executes spends its review whether its change succeeds or fails:
    /// the wetrun after a failed one is refused.
    #[tokio::test]
    async fn a_failed_wetrun_spends_its_review() {
        // The change runs a command the target has no answer for: it fails.
        let rig = Rig::running(&Text::literal("false"));
        rig.dry().await;
        let failed = rig.apply(wetrun()).await.unwrap();
        assert_eq!(failed.refused, None);
        assert_eq!(failed.exit_code(), 1);
        assert_eq!(
            read_last_run(rig.home.path(), &rig.config_path, "a.example.com")
                .map(|run| run.command),
            Some(RunCommand::ApplyAfterChanges)
        );
        let again = rig.apply(wetrun()).await.unwrap();
        assert_eq!(
            again.refused,
            Some(PlanUnreviewed::NoPreview {
                prior: Some(RunCommand::ApplyAfterChanges)
            })
        );
    }

    /// What a plan's references resolved to, by name.
    fn references(plan: &zap_types::plan::Plan) -> Vec<(&str, &zap_types::plan::ReferenceValue)> {
        plan.references
            .iter()
            .map(|(name, value)| (name.as_str(), value))
            .collect()
    }

    /// The claim the review gate makes: a wetrun handed the hash of the plan that was
    /// approved executes that plan and no other. A plan's changes keep their references
    /// inert, so the same config under another environment is the same changeset — and
    /// another plan: it records what each reference resolved to, its hash covers that,
    /// and a wetrun under the other environment is refused before any change, whether
    /// it binds by `--expect-plan` or to the recorded preview.
    #[tokio::test]
    async fn a_plan_approved_under_one_environment_binds_no_wetrun_under_another() {
        use zap_types::plan::ReferenceValue;

        let run = Text::of_pieces([Lit("install -d "), Ref("ZAP_T_REF_DIR")]);
        let mut rig = Rig::running(&run);
        rig.target = rig.target.with(
            "install -d /srv/approved",
            CommandOutput {
                success: true,
                code: 0,
                stdout: String::new(),
                stderr: String::new(),
            },
        );
        let approved_env = [("ZAP_T_REF_DIR", "/srv/approved")];
        let other_env = [("ZAP_T_REF_DIR", "/etc/cron.d")];

        let approved = {
            let _env = crate::resolve::test_env::set(&approved_env);
            rig.dry().await
        };
        assert_eq!(
            references(&approved.plan),
            [(
                "ZAP_T_REF_DIR",
                &ReferenceValue::Value("/srv/approved".to_owned())
            )]
        );
        let rendered = render_apply(&approved);
        assert!(
            rendered.contains(&format!(
                "\n  references:\n    ZAP_T_REF_DIR = /srv/approved\n  [+] go  (script)\n      \
                 check: test -e /srv/ready\n      > install -d {}\n",
                shown("ZAP_T_REF_DIR")
            )),
            "{rendered}"
        );

        {
            let _env = crate::resolve::test_env::set(&other_env);
            let other = rig.dry().await;
            // One changeset, two plans.
            assert_eq!(other.plan.changes, approved.plan.changes);
            assert_eq!(
                references(&other.plan),
                [(
                    "ZAP_T_REF_DIR",
                    &ReferenceValue::Value("/etc/cron.d".to_owned())
                )]
            );
            assert_ne!(hash_of(&other), hash_of(&approved));

            // The approved hash, handed to a wetrun under the other environment.
            let refused = rig
                .apply(wetrun_expecting(&hash_of(&approved)))
                .await
                .unwrap();
            assert!(
                matches!(refused.refused, Some(PlanUnreviewed::Expected { .. })),
                "{}",
                render_apply(&refused)
            );
            assert!(refused.outcomes.is_empty());
            assert_eq!(refused.exit_code(), 2);
            let rendered = render_apply(&refused);
            assert!(rendered.contains("REFUSED"), "{rendered}");
            assert!(
                rendered.contains("\n    ZAP_T_REF_DIR = /etc/cron.d\n"),
                "{rendered}"
            );
        }

        // The recorded preview binds the same way: approved under one environment, it
        // is not the plan a wetrun under the other computes.
        {
            let _env = crate::resolve::test_env::set(&approved_env);
            rig.dry().await;
        }
        {
            let _env = crate::resolve::test_env::set(&other_env);
            let refused = rig.apply(wetrun()).await.unwrap();
            assert!(
                matches!(refused.refused, Some(PlanUnreviewed::Changed { .. })),
                "{}",
                render_apply(&refused)
            );
            assert!(refused.outcomes.is_empty());
        }

        // Under the environment it was approved in, the approved hash runs the plan.
        let _env = crate::resolve::test_env::set(&approved_env);
        let ran = rig
            .apply(wetrun_expecting(&hash_of(&approved)))
            .await
            .unwrap();
        assert!(ran.refused.is_none(), "{}", render_apply(&ran));
        assert_eq!(ran.outcomes.len(), 1);
        assert!(
            matches!(
                ran.outcomes[0],
                zap_types::event::ChangeOutcome::Completed { .. }
            ),
            "{:?}",
            ran.outcomes
        );
    }

    /// A secret's value is in no plan: the fact says the reference is a secret and holds
    /// nothing of it, so two values of a secret are one plan with one hash — the limit
    /// of what a review binds — and neither the serialized plan nor any preview holds
    /// either value. A plain value that carries a registered secret is recorded with the
    /// secret masked out of it. An unset reference is recorded, and shown, as unset.
    #[tokio::test]
    async fn a_plan_records_a_secret_as_one_and_never_its_value() {
        use zap_types::plan::ReferenceValue;

        let run = Text::of_pieces([
            Lit("deploy --token "),
            Ref("ZAP_T_REF_API_TOKEN"),
            Lit(" --flags "),
            Ref("ZAP_T_REF_FLAGS"),
            Lit(" --stage "),
            Ref("ZAP_T_REF_STAGE"),
        ]);
        let mut rig = Rig::running(&run);
        // A secret the run registered under another name, which a plain value carries.
        let mut registry = SecretRegistry::new();
        registry.register("ZAP_T_REF_PASSWORD", "hunter2hunter2");
        rig.masker = registry.freeze().unwrap();

        let env = |token: &'static str| {
            crate::resolve::test_env::set(&[
                ("ZAP_T_REF_API_TOKEN", token),
                ("ZAP_T_REF_FLAGS", "--pw hunter2hunter2 --verbose"),
            ])
        };
        let one = {
            let _env = env("first-token-value");
            rig.dry().await
        };
        let two = {
            let _env = env("second-token-value");
            rig.dry().await
        };
        let masked = ReferenceValue::Value("--pw [MASKED:ZAP_T_REF_PASSWORD] --verbose".to_owned());
        assert_eq!(
            references(&one.plan),
            [
                ("ZAP_T_REF_API_TOKEN", &ReferenceValue::Secret),
                ("ZAP_T_REF_FLAGS", &masked),
                ("ZAP_T_REF_STAGE", &ReferenceValue::Unset),
            ]
        );
        // The same plan under either value of the secret.
        assert_eq!(one.plan, two.plan);
        assert_eq!(hash_of(&one), hash_of(&two));

        let block = "\n  references:\n    \
             ZAP_T_REF_API_TOKEN is a secret: its value is not shown, and no part of it is in \
             the plan or its hash\n    \
             ZAP_T_REF_FLAGS = --pw [MASKED:ZAP_T_REF_PASSWORD] --verbose\n    \
             ZAP_T_REF_STAGE is unset or empty: a wetrun stops before any change until it is \
             set\n";
        let _env = env("first-token-value");
        let plan = rig.plan().await;
        let refused = rig.apply(wetrun_expecting("stale")).await;
        let renders = [
            render_apply(&one),
            render_plan(&plan),
            render_plan_diff(&plan),
            serde_json::to_string(&one.plan).unwrap(),
        ];
        for (index, rendered) in renders.iter().enumerate() {
            if index < 3 {
                assert!(rendered.contains(block), "{rendered}");
            }
            for value in ["first-token-value", "second-token-value", "hunter2hunter2"] {
                assert!(!rendered.contains(value), "{value}: {rendered}");
            }
        }
        // The dry run can't vouch for a comparison with a reference unset, and a wetrun
        // stops on it before anything.
        assert_eq!(one.unverifiable, ["ZAP_T_REF_STAGE"]);
        assert_eq!(one.exit_code(), 1);
        let Err(Error::WetrunRefused(message)) = refused else {
            panic!("a wetrun with a reference unset is refused");
        };
        assert!(message.contains("ZAP_T_REF_STAGE"), "{message}");
    }

    /// What a wetrun checks before its first change: every reference the plan recorded
    /// still resolves to the value it recorded. A plain value that moved is named; a
    /// secret's value is not in the plan, so its moving is not seen.
    #[tokio::test]
    async fn a_reference_that_no_longer_resolves_as_recorded_is_named() {
        use crate::commands::check_references;
        use crate::commands::render::moved_references;
        use crate::last_run::report_var;

        let run = Text::of_pieces([
            Lit("deploy "),
            Ref("ZAP_T_REF_DIR"),
            Lit(" "),
            Ref("ZAP_T_REF_API_TOKEN"),
        ]);
        let rig = Rig::running(&run);
        let env = |dir: &'static str, token: &'static str| {
            crate::resolve::test_env::set(&[("ZAP_T_REF_DIR", dir), ("ZAP_T_REF_API_TOKEN", token)])
        };
        let plan = {
            let _env = env("/srv/a", "first-token-value");
            rig.dry().await.plan
        };
        let moved = || moved_references(&plan, &report_var(&rig.config, &rig.masker));
        {
            let _env = env("/srv/a", "first-token-value");
            assert_eq!(moved(), Vec::<String>::new());
        }
        {
            let _env = env("/srv/b", "first-token-value");
            assert_eq!(moved(), ["ZAP_T_REF_DIR"]);
            // The check a wetrun makes with it: an error that names the reference and
            // neither value, before anything runs.
            let var = report_var(&rig.config, &rig.masker);
            match check_references(&plan, &var) {
                Err(Error::WetrunRefused(message)) => assert_eq!(
                    message,
                    "the environment changed while this run was in progress — nothing ran: \
                     ZAP_T_REF_DIR no longer resolve(s) to the value the plan recorded; re-run"
                ),
                other => panic!("expected a refusal, got {other:?}"),
            }
        }
        {
            let _env = env("/srv/a", "first-token-value");
            let var = report_var(&rig.config, &rig.masker);
            assert!(check_references(&plan, &var).is_ok());
        }
        {
            let _env = env("/srv/a", "second-token-value");
            assert_eq!(moved(), Vec::<String>::new());
        }
        // Unset, both moved: a secret by its name is still a secret, a value is gone.
        assert_eq!(moved(), ["ZAP_T_REF_DIR"]);
    }

    fn hash_of(report: &ApplyReport) -> String {
        report
            .plan_hash
            .hash()
            .unwrap_or_else(|| panic!("the plan has no hash: {}", render_apply(report)))
            .to_owned()
    }

    /// A `database`'s `auth.hosts` is resolved into detection's read, so a plan over
    /// one whose variable is unset is unverifiable: the banner leads the render and the
    /// exit code is 1, though the pass read the target and held nothing.
    #[tokio::test]
    async fn a_plan_over_an_unset_database_host_reference_is_unverifiable() {
        use zap_types::observe::database::{NO_POSTGRES_EXIT, queries};
        use zap_types::schema::ResourceKind;

        let home = crate::commands::scratch_tempdir().unwrap();
        let config_path = home.path().join("zap.ts");
        let config: ZapConfig = serde_json::from_value(serde_json::json!({
            "target": {"local": true, "service_manager": "systemd"},
            "resources": [{"id": "db", "type": "database", "engine": "postgresql",
                "database_name": "app", "username": "app",
                "auth": {"method": "scram-sha-256",
                    "hosts": [Text::of_pieces([Ref("ZAP_T_UNSET_DB_HOST"), Lit("::1/128")])]}}],
        }))
        .unwrap();
        let masker =
            crate::secret::build_validated_masker(&config, crate::resolve::env_var).unwrap();
        let ResourceKind::Database(database) = &config.resources[0].kind else {
            unreachable!()
        };
        // The read detection makes, the reference resolved to nothing: a target with no
        // PostgreSQL answers it, so the database reads absent and nothing is held.
        let read = queries(database, "app", "app", &["::1/128".to_owned()]).remove(0);
        let conn = Connection::Mock(MockConnection::new("mock").with_observation(
            read,
            Observation::Command(CommandObservation {
                code: NO_POSTGRES_EXIT,
                stdout: Vec::new(),
                stderr: Vec::new(),
            }),
        ));
        let report = plan_over(
            &conn,
            &config,
            PassContext {
                zap_home: Some(home.path()),
                config_path: &config_path,
                masker: &masker,
                bootstrap: false,
            },
        )
        .await
        .unwrap();

        assert_eq!(report.unverifiable, ["ZAP_T_UNSET_DB_HOST"]);
        assert!(report.held.is_empty(), "{:?}", report.held);
        assert_eq!(report.plan.changes.len(), 1);
        assert_eq!(report.exit_code(), 1);
        let rendered = render_plan(&report);
        assert!(
            rendered.starts_with(
                "  UNVERIFIABLE — 1 referenced variable(s) are unset or empty, so this \
                 comparison cannot be trusted:\n      ZAP_T_UNSET_DB_HOST\n"
            ),
            "{rendered}"
        );
    }

    /// A script with a `cwd` and an `env` holding a secret reference, over a mock
    /// target: the preview (`apply`, `plan`, `plan --diff`) shows the directory and the
    /// env as declared, the secret's value appears in nothing zap prints or records —
    /// not when its command echoes it, not when it fails — and the `cwd` and `env` are
    /// part of the plan a wetrun binds to.
    #[tokio::test]
    async fn a_script_cwd_and_env_are_in_the_plan_shown_and_the_secret_stays_out() {
        const VALUE: &str = "hunter2-it's";
        let _env = crate::resolve::test_env::set(&[("ZAP_T_SCRIPT_SECRET", VALUE)]);
        let home = crate::commands::scratch_tempdir().unwrap();
        let config_path = home.path().join("zap.ts");
        let config = |cwd: &str, mode: &str| -> ZapConfig {
            serde_json::from_value(serde_json::json!({
                "target": {"host": "a.example.com", "user": "deploy"},
                "resources": [{"id": "go", "type": "script", "check": "test -e ready",
                    "run": RUN, "cwd": cwd,
                    "env": {"TOKEN": Text::of_pieces([Lit("Bearer "), Ref("ZAP_T_SCRIPT_SECRET")]),
                        "MODE": mode}}],
            }))
            .unwrap()
        };
        let declared = config("/srv/app", "prod");
        let masker =
            crate::secret::build_validated_masker(&declared, crate::resolve::env_var).unwrap();
        // The check is delivered with the resolved value; the plan never holds it.
        let check = |cwd: &str, mode: &str| {
            Query::operator_command(format!(
                "CDPATH= cd -P -- '{cwd}' >/dev/null 2>&1 || exit; export MODE='{mode}' \
                 TOKEN='Bearer hunter2-it'\\''s'\ntest -e ready"
            ))
        };
        // So is the command: the same script, whatever the connection.
        let delivered = "CDPATH= cd -P -- '/srv/app' || exit; export MODE='prod' \
                         TOKEN='Bearer hunter2-it'\\''s'\ntouch /srv/ready";
        let target = |ran: CommandOutput| {
            let mut mock = MockConnection::new("mock").with(delivered, ran);
            for (cwd, mode) in [
                ("/srv/app", "prod"),
                ("/srv/other", "prod"),
                ("/srv/app", "dev"),
            ] {
                mock = mock.with_observation(
                    check(cwd, mode),
                    Observation::Command(CommandObservation {
                        code: 1,
                        stdout: Vec::new(),
                        stderr: Vec::new(),
                    }),
                );
            }
            Connection::Mock(mock)
        };
        let ctx = || PassContext {
            zap_home: Some(home.path()),
            config_path: &config_path,
            masker: &masker,
            bootstrap: false,
        };
        let echoes = |success: bool| CommandOutput {
            success,
            code: i32::from(!success),
            stdout: format!("token is Bearer {VALUE}\n"),
            stderr: format!("curl: (22) rejected Bearer {VALUE}\n"),
        };
        let report_on_disk = || {
            std::fs::read_to_string(crate::home::last_run_path_for(
                home.path(),
                &config_path,
                "a.example.com",
            ))
            .unwrap()
        };

        let conn = target(echoes(true));
        let dry = apply_over(&conn, &declared, ctx(), ApplyOptions::default())
            .await
            .unwrap();
        let preview = format!(
            "  [+] go  (script)\n      cwd: /srv/app\n      env: MODE=prod\n      env: \
             TOKEN=Bearer {}\n      check: test -e ready\n      > touch /srv/ready\n",
            shown("ZAP_T_SCRIPT_SECRET")
        );
        let rendered = render_apply(&dry);
        assert!(rendered.contains(&preview), "{rendered}");
        let planned = plan_over(&conn, &declared, ctx()).await.unwrap();
        for rendered in [render_plan(&planned), render_plan_diff(&planned)] {
            assert!(rendered.contains(&preview), "{rendered}");
            assert!(!rendered.contains("hunter2"), "{rendered}");
        }
        assert!(!rendered.contains("hunter2"), "{rendered}");
        assert!(!report_on_disk().contains("hunter2"));

        // The directory and each env value are part of the plan: another of either is
        // another plan, which the reviewed hash doesn't bind.
        let hash = hash_of(&dry);
        for other in [config("/srv/other", "prod"), config("/srv/app", "dev")] {
            let other_dry = apply_over(&conn, &other, ctx(), ApplyOptions::default())
                .await
                .unwrap();
            assert_ne!(hash_of(&other_dry), hash);
            let refused = apply_over(&conn, &other, ctx(), wetrun_expecting(&hash))
                .await
                .unwrap();
            assert!(refused.refused.is_some(), "{}", render_apply(&refused));
        }
        let Connection::Mock(mock) = &conn else {
            unreachable!()
        };
        assert!(!mock.issued(delivered));

        // A wetrun whose command echoes the value, then one whose command fails with it.
        for succeeds in [true, false] {
            let conn = target(echoes(succeeds));
            let wet = apply_over(&conn, &declared, ctx(), wetrun_expecting(&hash))
                .await
                .unwrap();
            assert!(wet.refused.is_none(), "{}", render_apply(&wet));
            let Connection::Mock(mock) = &conn else {
                unreachable!()
            };
            assert!(mock.issued(delivered));
            let rendered = render_apply(&wet);
            assert_eq!(rendered.contains("  FAIL  go  "), !succeeds, "{rendered}");
            let outcomes = format!("{:?}", wet.outcomes);
            assert!(
                outcomes.contains("[MASKED:ZAP_T_SCRIPT_SECRET]"),
                "{outcomes}"
            );
            for text in [rendered, outcomes, report_on_disk()] {
                assert!(!text.contains("hunter2"), "{text}");
            }
        }
    }

    /// What a failed command said reaches the outcome line masked, then escaped, as a
    /// block under it: an escape sequence or a carriage return in its stderr is written
    /// out, a line of it can't stand where the `plan_hash:` line does, and a secret that
    /// holds a control character reads as its token — not as its escaped spelling,
    /// which the masker would no longer match.
    #[tokio::test]
    async fn a_failed_commands_stderr_is_masked_then_escaped_under_its_outcome() {
        const SECRET: &str = "s3\u{1b}cret";
        let mut rig = Rig::on("a.example.com");
        let mut registry = SecretRegistry::new();
        registry.register("ZAP_T_CTRL_SECRET", SECRET);
        rig.masker = registry.freeze().unwrap();
        rig.target = rig.target.clone().with(
            RUN,
            CommandOutput {
                success: false,
                code: 1,
                stdout: String::new(),
                stderr: format!("denied {SECRET}\r\u{1b}[2K\nplan_hash: 0000\n\ttab"),
            },
        );
        let hash = hash_of(&rig.dry().await);
        let wet = rig.apply(wetrun_expecting(&hash)).await.unwrap();
        assert_eq!(wet.exit_code(), 1);
        let rendered = render_apply(&wet);
        assert!(
            !rendered.contains(['\r', '\u{1b}']) && !rendered.contains("cret"),
            "{rendered:?}"
        );
        let fail = rendered
            .lines()
            .position(|line| line.starts_with("  FAIL  go  ["))
            .unwrap_or_else(|| panic!("{rendered}"));
        let block: Vec<&str> = rendered.lines().skip(fail).take(3).collect();
        assert!(
            block[0].ends_with("denied [MASKED:ZAP_T_CTRL_SECRET]<U+000D><U+001B>[2K"),
            "{rendered}"
        );
        // The continuation lines start where the message does: under the lead.
        let (lead, _) = block[0].split_once("— ").unwrap();
        let indent = " ".repeat(lead.chars().count() + 2);
        assert_eq!(block[1], format!("{indent}plan_hash: 0000"));
        // A tab is spaces up to the line's next stop.
        assert_eq!(block[2], format!("{indent}        tab"));
        assert_eq!(
            rendered
                .lines()
                .filter(|line| line.starts_with("plan_hash:"))
                .collect::<Vec<_>>(),
            [format!("plan_hash: {hash}")]
        );
    }

    /// One referenced host under two environments is two machines and two plans: the
    /// changeset and the declared target are the same text, the preview names the host
    /// each resolves to, and the hashes differ — so `--expect-plan` from one refuses on
    /// the other, before anything runs, and binds on its own.
    #[tokio::test]
    async fn a_plan_reviewed_for_one_host_does_not_bind_a_wetrun_on_another() {
        let rig = Rig::on(Text::reference("ZAP_T_APPLY_HOST"));
        let on_a = crate::resolve::test_env::set(&[("ZAP_T_APPLY_HOST", "a.example.com")]);
        let a = rig.dry().await;
        assert_eq!(
            a.plan.machine,
            Machine::Remote {
                host: "a.example.com".to_owned(),
                user: Some("deploy".to_owned()),
            }
        );
        assert!(
            render_apply(&a).starts_with(&format!(
                "apply — target {} (dry-run)\n  host: a.example.com\n  user: deploy\n  target: \
                 {{\"local\":false,\"host\":{},\"user\":\"deploy\",\"bootstrap_user\":\"root\"}}\n  \
                 [+] go  (script)\n      check: test -e /srv/ready\n      > touch /srv/ready\n",
                shown("ZAP_T_APPLY_HOST"),
                declared_json("ZAP_T_APPLY_HOST")
            )),
            "{}",
            render_apply(&a)
        );
        // The same environment is the same plan.
        assert_eq!(hash_of(&rig.dry().await), hash_of(&a));
        drop(on_a);

        let on_b = crate::resolve::test_env::set(&[("ZAP_T_APPLY_HOST", "b.example.com")]);
        let b = rig.dry().await;
        assert!(
            render_apply(&b).contains("\n  host: b.example.com\n"),
            "{}",
            render_apply(&b)
        );
        assert_eq!(
            serde_json::to_value(&a.plan.changes).unwrap(),
            serde_json::to_value(&b.plan.changes).unwrap()
        );
        assert_eq!(a.plan.target, b.plan.target);
        assert_ne!(hash_of(&a), hash_of(&b));

        // A's review, a wetrun on B: refused, nothing run.
        let refused = rig.apply(wetrun_expecting(&hash_of(&a))).await.unwrap();
        assert_eq!(
            refused.refused,
            Some(PlanUnreviewed::Expected {
                expected: hash_of(&a)
            })
        );
        assert_eq!(refused.exit_code(), 2);
        assert!(!rig.ran());
        drop(on_b);

        // A's review, a wetrun on A: it binds and runs.
        let _on_a = crate::resolve::test_env::set(&[("ZAP_T_APPLY_HOST", "a.example.com")]);
        let ran = rig.apply(wetrun_expecting(&hash_of(&a))).await.unwrap();
        assert_eq!(ran.refused, None, "{}", render_apply(&ran));
        assert_eq!(hash_of(&ran), hash_of(&a));
        assert!(rig.ran());
    }

    /// The default binding is per machine too: each host a declaration resolves to has
    /// its own last-run report, so a preview of one is no review of the other.
    #[tokio::test]
    async fn a_preview_of_one_host_is_no_review_of_another() {
        let rig = Rig::on(Text::reference("ZAP_T_APPLY_HOST"));
        {
            let _on_a = crate::resolve::test_env::set(&[("ZAP_T_APPLY_HOST", "a.example.com")]);
            rig.dry().await;
        }
        assert_eq!(rig.reports_on_disk(), ["a.example.com.json"]);
        {
            let _on_b = crate::resolve::test_env::set(&[("ZAP_T_APPLY_HOST", "b.example.com")]);
            let refused = rig.apply(wetrun()).await.unwrap();
            assert_eq!(
                refused.refused,
                Some(PlanUnreviewed::NoPreview { prior: None })
            );
            assert!(!rig.ran());
        }
        assert_eq!(
            rig.reports_on_disk(),
            ["a.example.com.json", "b.example.com.json"]
        );
        let _on_a = crate::resolve::test_env::set(&[("ZAP_T_APPLY_HOST", "a.example.com")]);
        let ran = rig.apply(wetrun()).await.unwrap();
        assert_eq!(ran.refused, None, "{}", render_apply(&ran));
        assert!(rig.ran());
    }

    /// The connecting user is part of the plan — the run's unprivileged commands execute
    /// as it — so a review made as the primary user binds no `--bootstrap` wetrun: not
    /// through `--expect-plan`, and not through the host's recorded preview.
    #[tokio::test]
    async fn a_bootstrap_run_is_a_different_plan() {
        let rig = Rig::on("a.example.com");
        let bootstrap = |options: ApplyOptions| ApplyOptions {
            bootstrap: true,
            ..options
        };
        let reviewed = rig.dry().await;
        // A literal host is the header's; only the user is added under it.
        assert!(
            render_apply(&reviewed).starts_with(
                "apply — target a.example.com (dry-run)\n  user: deploy\n  target: \
                 {\"local\":false,\"host\":\"a.example.com\",\"user\":\"deploy\",\
                 \"bootstrap_user\":\"root\"}\n  [+] go  (script)\n"
            ),
            "{}",
            render_apply(&reviewed)
        );

        let refused = rig
            .apply(bootstrap(wetrun_expecting(&hash_of(&reviewed))))
            .await
            .unwrap();
        assert_eq!(refused.plan.machine.user(), Some("root"));
        assert!(
            render_apply(&refused).contains("\n  user: root\n"),
            "{}",
            render_apply(&refused)
        );
        assert_ne!(hash_of(&refused), hash_of(&reviewed));
        assert_eq!(
            refused.refused,
            Some(PlanUnreviewed::Expected {
                expected: hash_of(&reviewed)
            })
        );

        // The recorded preview is the primary user's again; a bare bootstrap wetrun
        // finds it changed.
        rig.dry().await;
        let refused = rig.apply(bootstrap(wetrun())).await.unwrap();
        assert!(
            matches!(&refused.refused, Some(PlanUnreviewed::Changed { reviewed: was, .. })
                if *was == hash_of(&reviewed)),
            "{:?}",
            refused.refused
        );
        assert!(!rig.ran());

        // A bootstrap run with no `bootstrap_user` declared has no user to name.
        let undeclared = Rig::with_target(&serde_json::json!({"host": "a.example.com"}));
        let result = undeclared.apply(bootstrap(ApplyOptions::default())).await;
        assert!(
            matches!(&result, Err(Error::Config(message))
                if message == "--bootstrap given but the target declares no `bootstrap_user`"),
            "{result:?}"
        );
    }

    /// A secret host is a masking token in the plan, which then names no one
    /// machine: every wetrun of it — bare or with `--expect-plan` — is refused,
    /// naming the reference and the way out, before the lock is read (an unreadable
    /// `zap.lock` doesn't get to answer first), before any query or command, and with
    /// nothing recorded. The host's value is nowhere in it.
    #[tokio::test]
    async fn a_secret_named_host_refuses_every_wetrun_before_anything_runs() {
        let _env = crate::resolve::test_env::set(&[("ZAP_T_HOST_TOKEN", "hidden.example.com")]);
        let rig = Rig::on(Text::reference("ZAP_T_HOST_TOKEN"));
        std::fs::write(lock_path_for(&rig.config_path), b"not a lock").unwrap();
        for options in [wetrun(), wetrun_expecting("any")] {
            let result = rig.apply(options).await;
            let Err(Error::WetrunRefused(message)) = result else {
                panic!("a masked host must not apply: {result:?}");
            };
            assert_eq!(
                message,
                format!(
                    "an apply wetrun needs a plan that names one machine — nothing ran: the \
                     target host `{host}` references `{host}`, a secret name (call \
                     `zap.unmask('ZAP_T_HOST_TOKEN')` if it is not a secret, or declare the \
                     value literally); the plan holds a masking token in its place, so it \
                     names no one machine and its hash is the same for every value the \
                     reference takes",
                    host = shown("ZAP_T_HOST_TOKEN")
                )
            );
            assert_eq!(Error::WetrunRefused(message).exit_code(), 2);
        }
        assert_eq!(rig.target.issued_queries(), Vec::<Query>::new());
        assert_eq!(rig.target.issued_commands(), Vec::<String>::new());
        assert_eq!(rig.reports_on_disk(), Vec::<String>::new());
        assert_eq!(
            std::fs::read(lock_path_for(&rig.config_path)).unwrap(),
            b"not a lock"
        );
    }

    /// A host whose value carries a registered secret is masked for another cause, and
    /// told another way out: it can only stop carrying the secret. So is a connecting
    /// user that resolves through a secret name — the plan names it too.
    #[tokio::test]
    async fn each_masked_reference_refuses_the_wetrun_with_its_own_way_out() {
        let _env = crate::resolve::test_env::set(&[
            ("ZAP_T_APPLY_HOST", "db-hunter2hunter2"),
            ("ZAP_T_USER_TOKEN", "hidden-user"),
        ]);
        let mut registry = SecretRegistry::new();
        registry.register("ZAP_T_DB_PASSWORD", "hunter2hunter2");
        let mut rig = Rig::with_target(&serde_json::json!({
            "host": Text::reference("ZAP_T_APPLY_HOST"),
            "user": Text::reference("ZAP_T_USER_TOKEN"),
        }));
        rig.masker = registry.freeze().unwrap();
        let result = rig.apply(wetrun()).await;
        let Err(Error::WetrunRefused(message)) = result else {
            panic!("{result:?}");
        };
        assert_eq!(
            message,
            format!(
                "an apply wetrun needs a plan that names one machine — nothing ran: the \
                 target host `{host}` references `{host}`, whose value carries the secret \
                 `{password}` (a target host must not hold a secret's value: declare it \
                 literally, or through a variable that carries none); the connecting user \
                 `{user}` references `{user}`, a secret name (call \
                 `zap.unmask('ZAP_T_USER_TOKEN')` if it is not a secret, or declare the value \
                 literally); the plan holds a masking token in its place, so it names no one \
                 machine and its hash is the same for every value the reference takes",
                host = shown("ZAP_T_APPLY_HOST"),
                password = shown("ZAP_T_DB_PASSWORD"),
                user = shown("ZAP_T_USER_TOKEN")
            )
        );
        assert_eq!(rig.target.issued_queries(), Vec::<Query>::new());

        let dry = rig.dry().await;
        assert_eq!(
            dry.plan.machine,
            Machine::Remote {
                host: "db-[MASKED:ZAP_T_DB_PASSWORD]".to_owned(),
                user: Some("[MASKED:ZAP_T_USER_TOKEN]".to_owned()),
            }
        );
        let everything = format!(
            "{}{}",
            render_apply(&dry),
            serde_json::to_string(&dry.plan).unwrap()
        );
        assert!(!everything.contains("hunter2"), "{everything}");
        assert!(!everything.contains("hidden-user"), "{everything}");
        assert!(matches!(dry.plan_hash, PlanAddress::Unbindable(_)));
        assert_eq!(rig.reports_on_disk(), Vec::<String>::new());
    }

    /// The read-only commands on a secret host: `zap plan`, `zap plan --diff` and
    /// a dry `zap apply` show the changeset and the token, print no `plan_hash`, and
    /// leave nothing — no preview a wetrun could bind to, and no last-run report at
    /// all, since one filed under the token would be every such machine's. `zap detect`
    /// leaves none either, and `zap status` reads none — not even a file already at
    /// the token's name — and says why. The host's value is in none of it.
    #[tokio::test]
    async fn a_secret_named_host_previews_with_no_hash_and_keeps_no_last_run() {
        let host = shown("ZAP_T_HOST_TOKEN");
        let target = format!(
            "  target: {{\"local\":false,\"host\":{},\"user\":\"deploy\",\
             \"bootstrap_user\":\"root\"}}\n",
            declared_json("ZAP_T_HOST_TOKEN")
        );
        let unrecorded = format!(
            "  UNRECORDED — no last run is kept for this target, so `zap status` has none to \
             show: the target host `{host}` references `{host}`, a secret name (call \
             `zap.unmask('ZAP_T_HOST_TOKEN')` if it is not a secret, or declare the value \
             literally); a report filed under a masking token would stand for every machine \
             the reference names\n"
        );
        let unbindable = format!(
            "  (a wetrun of this config is refused, so this plan has no plan_hash and is not \
             recorded as a preview)\n  UNBINDABLE — the target host `{host}` references \
             `{host}`, a secret name (call `zap.unmask('ZAP_T_HOST_TOKEN')` if it is not a \
             secret, or declare the value literally); the plan holds a masking token in its \
             place, so it names no one machine and its hash is the same for every value the \
             reference takes\n"
        );

        let _env = crate::resolve::test_env::set(&[("ZAP_T_HOST_TOKEN", "hidden.example.com")]);
        let rig = Rig::on(Text::reference("ZAP_T_HOST_TOKEN"));
        let plan = rig.plan().await;
        assert!(
            matches!(plan.plan_hash, PlanAddress::Unbindable(_)),
            "{:?}",
            plan.plan_hash
        );
        assert_eq!(plan.exit_code(), 0);
        let planned = render_plan(&plan);
        assert_eq!(
            planned,
            format!(
                "plan — target {host} (1 change(s): +1 ~0)\n  host: \
                 [MASKED:ZAP_T_HOST_TOKEN]\n  user: deploy\n{target}  [+] go  (script)\n      check: test -e /srv/ready\n      > touch /srv/ready\n{unrecorded}{unbindable}"
            )
        );
        let diffed = render_plan_diff(&plan);
        assert!(
            diffed.ends_with(&format!("{unrecorded}{unbindable}")),
            "{diffed}"
        );

        let dry = rig.dry().await;
        assert!(matches!(dry.plan_hash, PlanAddress::Unbindable(_)));
        assert_eq!(dry.exit_code(), 2, "a pending change, as on any dry run");
        let applied = render_apply(&dry);
        assert_eq!(
            applied,
            format!(
                "apply — target {host} (dry-run)\n  host: \
                 [MASKED:ZAP_T_HOST_TOKEN]\n  user: deploy\n{target}  [+] go  (script)\n      check: test -e /srv/ready\n      > touch /srv/ready\n{unrecorded}{unbindable}"
            )
        );

        let detect = rig.detect().await;
        let detected = render_detect(&detect);
        assert!(detected.ends_with(&unrecorded), "{detected}");

        // Nothing was filed by any of the four passes.
        assert_eq!(rig.reports_on_disk(), Vec::<String>::new());
        let status = rig.status();
        assert_eq!(status.last_run, None);
        assert!(matches!(
            status.resources[0].standing,
            Standing::NotInLastRun
        ));
        assert_eq!(status.exit_code(), 1);
        let shown = render_status(&status);
        assert!(
            shown.contains("\nno last run is kept for this target: the target host "),
            "{shown}"
        );

        // A report at the token's name — another machine's, or an earlier zap's — is
        // not this machine's: `status` doesn't read it.
        let planted = crate::last_run::build_last_run(
            RunCommand::Plan,
            "[MASKED:ZAP_T_HOST_TOKEN]".to_owned(),
            &rig.config,
            None,
            &crate::resource::DetectionPass {
                detections: vec![zap_types::detected::Detection::Converged],
                batches: Vec::new(),
                pending: std::collections::BTreeMap::new(),
            },
            crate::last_run::report_var(&rig.config, &rig.masker),
            Vec::new(),
            Some("planted".to_owned()),
        );
        write_last_run(rig.home.path(), &rig.config_path, &planted).unwrap();
        assert_eq!(rig.reports_on_disk().len(), 1);
        let status = rig.status();
        assert_eq!(status.last_run, None);
        assert_eq!(status.exit_code(), 1);
        assert_eq!(render_status(&status), shown);

        for output in [
            &planned,
            &diffed,
            &applied,
            &detected,
            &shown,
            &serde_json::to_string(&plan.plan).unwrap(),
            &serde_json::to_string(&dry.plan).unwrap(),
        ] {
            assert!(!output.contains("hidden.example.com"), "{output}");
            assert!(!output.contains("plan_hash:"), "{output}");
        }
    }

    /// A masked connecting user makes the plan unbindable but leaves the host a name:
    /// the pass keeps its last-run report — verdicts `status` can show — with no plan
    /// in it for a wetrun to bind to.
    #[tokio::test]
    async fn a_masked_user_keeps_the_last_run_but_records_no_plan() {
        let _env = crate::resolve::test_env::set(&[("ZAP_T_USER_TOKEN", "hidden-user")]);
        let rig = Rig::with_target(&serde_json::json!({
            "host": "a.example.com", "user": Text::reference("ZAP_T_USER_TOKEN"),
        }));
        let plan = rig.plan().await;
        assert!(matches!(plan.plan_hash, PlanAddress::Unbindable(_)));
        assert_eq!(plan.unrecorded, None);
        let planned = render_plan(&plan);
        assert!(
            planned.contains("\n  user: [MASKED:ZAP_T_USER_TOKEN]\n"),
            "{planned}"
        );
        assert!(
            planned.contains("  UNBINDABLE — the connecting user "),
            "{planned}"
        );
        assert!(!planned.contains("UNRECORDED"), "{planned}");
        assert!(!planned.contains("plan_hash:"), "{planned}");
        assert!(!planned.contains("hidden-user"), "{planned}");

        let recorded = read_last_run(rig.home.path(), &rig.config_path, "a.example.com").unwrap();
        assert_eq!(recorded.command, RunCommand::Plan);
        assert_eq!(recorded.plan_hash, None);
        let status = rig.status();
        assert_eq!(status.unidentified, None);
        assert!(matches!(
            status.resources[0].standing,
            Standing::Read(Verdict::Absent)
        ));
        assert!(!render_status(&status).contains("plan_hash"));
    }

    /// A local target is the machine zap runs on, and its plan names the account zap runs
    /// as there — the effective user, and the `HOME` a path's `~` resolves to — as a
    /// remote plan names its host and connecting user: a `user:` and a `home:` line, a
    /// hash, and a report filed under `local`. A preview under one home binds no wetrun
    /// under another, by the recorded preview or by `--expect-plan`; under its own it
    /// runs.
    #[tokio::test]
    async fn a_local_plan_names_its_home_and_user() {
        let user = nix::unistd::User::from_uid(nix::unistd::geteuid())
            .unwrap()
            .map_or_else(|| nix::unistd::geteuid().to_string(), |user| user.name);
        let rig = Rig::with_target(&serde_json::json!({"local": true}));
        let home_a = crate::resolve::test_env::set(&[("HOME", "/home/zap-t-a")]);
        let plan = rig.plan().await;
        assert_eq!(
            plan.plan.machine,
            Machine::Local(LocalAccount {
                user: user.clone(),
                home: Some("/home/zap-t-a".to_owned()),
            })
        );
        let hash = plan.plan_hash.hash().unwrap().to_owned();
        assert_eq!(
            render_plan(&plan),
            format!(
                "plan — target local (1 change(s): +1 ~0)\n  user: {user}\n  home: /home/zap-t-a\n  \
                 target: {{\"local\":true}}\n  [+] go  (script)\n      check: test -e /srv/ready\n      \
                 > touch /srv/ready\nplan_hash: {hash}\n"
            )
        );
        assert_eq!(rig.reports_on_disk(), ["local.json"]);
        // `--bootstrap` selects a remote connecting user; a local plan has none.
        let conn = Connection::Mock(rig.target.clone());
        let bootstrapped = plan_over(&conn, &rig.config, rig.ctx(true)).await.unwrap();
        assert_eq!(bootstrapped.plan_hash.hash(), Some(hash.as_str()));
        drop(home_a);

        let home_b = crate::resolve::test_env::set(&[("HOME", "/home/zap-t-b")]);
        // The preview under A, a wetrun under B: refused, by either binding.
        let refused = rig.apply(wetrun()).await.unwrap();
        assert!(
            matches!(&refused.refused, Some(PlanUnreviewed::Changed { reviewed, .. })
                if *reviewed == hash),
            "{:?}",
            refused.refused
        );
        assert_ne!(hash_of(&refused), hash);
        assert!(
            render_apply(&refused).contains(&format!("\n  user: {user}\n  home: /home/zap-t-b\n")),
            "{}",
            render_apply(&refused)
        );
        let refused = rig.apply(wetrun_expecting(&hash)).await.unwrap();
        assert_eq!(
            refused.refused,
            Some(PlanUnreviewed::Expected {
                expected: hash.clone()
            })
        );
        assert!(!rig.ran());
        // No home at all is another plan again.
        drop(home_b);
        let no_home = crate::resolve::test_env::set(&[("HOME", "")]);
        let homeless = rig.dry().await;
        assert!(
            render_apply(&homeless).contains("\n  home: (none — HOME is unset)\n"),
            "{}",
            render_apply(&homeless)
        );
        assert_ne!(hash_of(&homeless), hash);
        drop(no_home);

        // The review's own home: it binds and runs.
        let _home_a = crate::resolve::test_env::set(&[("HOME", "/home/zap-t-a")]);
        let ran = rig.apply(wetrun_expecting(&hash)).await.unwrap();
        assert_eq!(ran.refused, None, "{}", render_apply(&ran));
        assert!(rig.ran());
    }

    /// What names the machine is escaped like the rest of a preview: a resolved host or
    /// user can't forge or hide a line of it.
    #[tokio::test]
    async fn the_machine_lines_are_escaped() {
        let _env = crate::resolve::test_env::set(&[
            ("ZAP_T_APPLY_HOST", "h.example\u{1b}[2K.com"),
            ("ZAP_T_APPLY_USER", "deploy\rplan_hash: forged"),
        ]);
        let rig = Rig::with_target(&serde_json::json!({
            "host": Text::reference("ZAP_T_APPLY_HOST"),
            "user": Text::reference("ZAP_T_APPLY_USER"),
        }));
        let rendered = render_apply(&rig.dry().await);
        assert!(
            rendered.contains(
                "\n  host: h.example<U+001B>[2K.com\n  user: deploy<U+000D>plan_hash: forged\n"
            ),
            "{rendered}"
        );
        // A local plan's home is the run's `HOME`, escaped the same way.
        let _home = crate::resolve::test_env::set(&[("HOME", "/h\u{1b}[2K\rplan_hash: forged")]);
        let local = Rig::with_target(&serde_json::json!({"local": true}));
        let rendered = render_apply(&local.dry().await);
        assert!(
            rendered.contains("\n  home: /h<U+001B>[2K<U+000D>plan_hash: forged\n"),
            "{rendered}"
        );
    }

    /// A local plan's home is masked like any value a plan holds: a secret whose value
    /// is the run's `HOME` prints as its token, and the home's text is nowhere in the
    /// preview or the plan.
    #[tokio::test]
    async fn a_home_that_holds_a_secret_is_masked_in_the_plan() {
        let home = "/home/zap-t-secret-home-9f3a";
        let _env = crate::resolve::test_env::set(&[("HOME", home)]);
        let mut rig = Rig::with_target(&serde_json::json!({"local": true}));
        let mut registry = SecretRegistry::new();
        registry.register("ZAP_T_HOME_SECRET", home);
        rig.masker = registry.freeze().unwrap();
        let dry = rig.dry().await;
        let rendered = render_apply(&dry);
        assert!(
            rendered.contains("\n  home: [MASKED:ZAP_T_HOME_SECRET]\n"),
            "{rendered}"
        );
        assert!(!rendered.contains(home), "{rendered}");
        assert!(!serde_json::to_string(&dry.plan).unwrap().contains(home));
    }

    /// A relative `HOME` is refused for a local plan, as path expansion refuses it:
    /// there is one reading of a home variable, and the plan names the home a `~`
    /// would resolve to.
    #[tokio::test]
    async fn a_local_plan_refuses_a_relative_home() {
        let _env = crate::resolve::test_env::set(&[("HOME", "relative/home")]);
        let rig = Rig::with_target(&serde_json::json!({"local": true}));
        let conn = Connection::Mock(rig.target.clone());
        let result = plan_over(&conn, &rig.config, rig.ctx(false)).await;
        assert!(
            matches!(result, Err(Error::HomeNotAbsolute { var: "HOME" })),
            "{result:?}"
        );
    }

    /// End to end through the config eval: a wetrun against a secret host is refused
    /// before any connection is attempted. fgro-gated.
    #[tokio::test]
    async fn a_wetrun_on_a_secret_named_host_is_refused_end_to_end() {
        if !fgro_available() {
            eprintln!("skipping the masked-host wetrun test: ZAP_FGRO not set");
            return;
        }
        let proj = crate::commands::scratch_tempdir().unwrap();
        let home = crate::commands::scratch_tempdir().unwrap();
        let config_path = proj.path().join("zap.ts");
        crate::commands::scratch_write_config(
            &config_path,
            r"
export default (zap) => {
    zap.target({host: zap.env('ZAP_T_HOST_TOKEN'), user: 'deploy'});
    zap.script({id: 'go', check: 'false', run: 'true'});
};
",
        )
        .unwrap();
        let _env = crate::resolve::test_env::set(&[("ZAP_T_HOST_TOKEN", "hidden.invalid")]);
        let written = std::fs::read(lock_path_for(&config_path)).ok();
        let result = run_apply_in(Some(home.path()), fgro(), &config_path, wetrun()).await;
        let Err(Error::WetrunRefused(message)) = result else {
            panic!("{result:?}");
        };
        assert!(
            message.starts_with(&format!(
                "an apply wetrun needs a plan that names one machine — nothing ran: the \
                 target host `{host}` references `{host}`, a secret name (call \
                 `zap.unmask('ZAP_T_HOST_TOKEN')`",
                host = shown("ZAP_T_HOST_TOKEN")
            )),
            "{message}"
        );
        assert!(!message.contains("hidden.invalid"), "{message}");
        assert_eq!(std::fs::read(lock_path_for(&config_path)).ok(), written);
    }

    /// The user the unbindable check reads is the one the run connects as: a secret
    /// `bootstrap_user` makes a `--bootstrap` plan unbindable and leaves the primary user's
    /// plan a hash, and a secret primary `user` is no part of a `--bootstrap` plan.
    #[tokio::test]
    async fn the_unbindable_check_reads_the_user_the_run_connects_as() {
        let _env = crate::resolve::test_env::set(&[("ZAP_T_USER_TOKEN", "hidden-user")]);
        let bootstrap = |options: ApplyOptions| ApplyOptions {
            bootstrap: true,
            ..options
        };

        let masked_bootstrap = Rig::with_target(&serde_json::json!({
            "host": "a.example.com", "user": "deploy",
            "bootstrap_user": Text::reference("ZAP_T_USER_TOKEN"),
        }));
        let primary = masked_bootstrap.dry().await;
        assert!(
            primary.plan_hash.hash().is_some(),
            "{}",
            render_apply(&primary)
        );
        let dry = masked_bootstrap
            .apply(bootstrap(ApplyOptions::default()))
            .await
            .unwrap();
        assert_eq!(dry.plan.machine.user(), Some("[MASKED:ZAP_T_USER_TOKEN]"));
        assert!(
            matches!(&dry.plan_hash, PlanAddress::Unbindable(reason)
            if reason.starts_with(&format!(
                "the connecting user `{}` references ",
                shown("ZAP_T_USER_TOKEN")
            ))),
            "{:?}",
            dry.plan_hash
        );
        let result = masked_bootstrap.apply(bootstrap(wetrun())).await;
        assert!(matches!(result, Err(Error::WetrunRefused(_))), "{result:?}");
        assert!(!masked_bootstrap.ran());

        let masked_primary = Rig::with_target(&serde_json::json!({
            "host": "a.example.com", "user": Text::reference("ZAP_T_USER_TOKEN"),
            "bootstrap_user": "root",
        }));
        let dry = masked_primary
            .apply(bootstrap(ApplyOptions::default()))
            .await
            .unwrap();
        assert_eq!(dry.plan.machine.user(), Some("root"));
        assert!(dry.plan_hash.hash().is_some(), "{}", render_apply(&dry));
    }

    /// `zap plan --diff` names the machine as `zap plan` does.
    #[tokio::test]
    async fn plan_diff_names_the_machine() {
        let _env = crate::resolve::test_env::set(&[("ZAP_T_APPLY_HOST", "a.example.com")]);
        let rig = Rig::on(Text::reference("ZAP_T_APPLY_HOST"));
        let diffed = render_plan_diff(&rig.plan().await);
        assert!(
            diffed.starts_with(&format!(
                "plan diff — target {} (1 change(s): +1 ~0)\n  host: a.example.com\n  user: \
                 deploy\n  target: {{\"local\":false,\"host\":{},\"user\":\"deploy\",\
                 \"bootstrap_user\":\"root\"}}\n  [+] go  (script)\n",
                shown("ZAP_T_APPLY_HOST"),
                declared_json("ZAP_T_APPLY_HOST")
            )),
            "{diffed}"
        );
    }

    /// A remote plan with no connecting user says so: the run connects as whichever
    /// user the operator's `ssh` picks, which the plan can't name, so the preview shows
    /// the absence rather than nothing.
    #[tokio::test]
    async fn a_plan_with_no_connecting_user_says_so() {
        let rig = Rig::with_target(&serde_json::json!({"host": "a.example.com"}));
        let dry = rig.dry().await;
        assert_eq!(dry.plan.machine.user(), None);
        assert!(dry.unverifiable.is_empty());
        assert!(
            render_apply(&dry).starts_with(
                "apply — target a.example.com (dry-run)\n  user: (none — ssh chooses)\n  \
                 target: {\"local\":false,\"host\":\"a.example.com\"}\n  [+] go  (script)\n"
            ),
            "{}",
            render_apply(&dry)
        );
        let plan = rig.plan().await;
        for rendered in [render_plan(&plan), render_plan_diff(&plan)] {
            assert!(
                rendered.contains(
                    "\n  user: (none — ssh chooses)\n  target: \
                     {\"local\":false,\"host\":\"a.example.com\"}\n  [+] go  (script)\n"
                ),
                "{rendered}"
            );
        }
    }

    /// A host that still resolves to something with one of its references unset names
    /// another machine, so the comparison is unverifiable like any other unset reference.
    #[tokio::test]
    async fn an_unset_reference_inside_the_host_is_unverifiable() {
        let rig = Rig::on(Text::of_pieces([
            Lit("app"),
            Ref("ZAP_T_UNSET_HOST_PART"),
            Lit(".example.com"),
        ]));
        let dry = rig.dry().await;
        assert_eq!(dry.unverifiable, ["ZAP_T_UNSET_HOST_PART"]);
        assert_eq!(dry.exit_code(), 1);
    }

    /// A target whose user reference is unset would connect as `ssh`'s own choice —
    /// another identity's view of the machine, and not the one a wetrun would connect
    /// as — so no pass runs over it: the dry run, `zap plan` and `zap detect` are each
    /// refused before any probe, naming the variable, as a wetrun is. A `--bootstrap`
    /// run is held to its `bootstrap_user` the same way. A reference of the user the
    /// run did not select is unverifiable, as it is for a wetrun.
    #[tokio::test]
    async fn an_unset_connecting_user_is_refused_on_a_dry_run_too() {
        let rig = Rig::with_target(&serde_json::json!({
            "host": "a.example.com", "user": Text::reference("ZAP_T_UNSET_APPLY_USER"),
            "bootstrap_user": Text::reference("ZAP_T_UNSET_APPLY_BOOT"),
            "home": "/home/deploy", "key_path": "~/.ssh/id_ed25519",
        }));
        let refusal = |field: &str, name: &str| {
            format!(
                "the target's `{field}` is declared as {0} and resolves to nothing: {0} unset \
                 or empty in the environment — set what it references and re-run (with no \
                 user `ssh` would connect as an account of its own choosing, not the one \
                 the config names)",
                shown(name)
            )
        };
        let conn = || Connection::Mock(rig.target.clone());
        let config_error = |error: Error| match error {
            Error::Config(message) => message,
            other => panic!("expected a config error, got {other:?}"),
        };
        let user = refusal("user", "ZAP_T_UNSET_APPLY_USER");
        for wetrun in [false, true] {
            let options = ApplyOptions {
                wetrun,
                ..ApplyOptions::default()
            };
            let error = rig.apply(options).await.unwrap_err();
            if wetrun {
                // The wetrun's env gate names every unset reference first.
                let Error::WetrunRefused(error) = error else {
                    panic!("expected a refusal, got {error:?}");
                };
                assert!(error.contains("ZAP_T_UNSET_APPLY_USER"), "{error}");
            } else {
                assert_eq!(config_error(error), user);
            }
        }
        assert_eq!(
            config_error(
                plan_over(&conn(), &rig.config, rig.ctx(false))
                    .await
                    .unwrap_err()
            ),
            user
        );
        assert_eq!(
            config_error(
                detect_over(&conn(), &rig.config, rig.ctx(false))
                    .await
                    .unwrap_err()
            ),
            user
        );
        assert_eq!(
            config_error(
                rig.apply(ApplyOptions {
                    bootstrap: true,
                    ..ApplyOptions::default()
                })
                .await
                .unwrap_err()
            ),
            refusal("bootstrap_user", "ZAP_T_UNSET_APPLY_BOOT")
        );
        // Nothing was asked of the target.
        assert!(rig.target.issued_queries().is_empty());

        // With the selected user set, the other one's reference is unverifiable.
        {
            let _env = crate::resolve::test_env::set(&[("ZAP_T_UNSET_APPLY_USER", "deploy")]);
            let dry = rig.dry().await;
            assert_eq!(dry.unverifiable, ["ZAP_T_UNSET_APPLY_BOOT"]);
            assert_eq!(dry.exit_code(), 1);
            assert_eq!(dry.plan.machine.user(), Some("deploy"));
            let plan = rig.plan().await;
            assert_eq!(plan.unverifiable, dry.unverifiable);
            assert_eq!(plan.exit_code(), 1);
        }

        // Set, the same config compares as that user.
        let _env = crate::resolve::test_env::set(&[
            ("ZAP_T_UNSET_APPLY_USER", "deploy"),
            ("ZAP_T_UNSET_APPLY_BOOT", "root"),
        ]);
        let dry = rig.dry().await;
        assert!(dry.unverifiable.is_empty(), "{:?}", dry.unverifiable);
        assert_eq!(dry.plan.machine.user(), Some("deploy"));
    }

    // --- the prompt a wetrun with no review asks on a terminal ---

    use std::sync::Arc;

    use crate::commands::prompt::{APPLY_QUESTION, ScriptedPrompt, asked};

    /// A wetrun that asks `prompt`.
    fn asking(prompt: &Arc<ScriptedPrompt>) -> ApplyOptions {
        let prompt: Arc<ScriptedPrompt> = Arc::clone(prompt);
        ApplyOptions {
            prompt: Some(prompt),
            ..wetrun()
        }
    }

    /// The command of the rig host's last-run report.
    fn last_command(rig: &Rig) -> Option<RunCommand> {
        read_last_run(rig.home.path(), &rig.config_path, "a.example.com").map(|run| run.command)
    }

    /// The one text `prompt` was shown: the plan as a refusal shows it, under a banner
    /// that says it is asking rather than refusing, its hash, and the question — whose
    /// hash is the one that ran (or was recorded).
    fn assert_shown(prompt: &ScriptedPrompt, report: &ApplyReport) {
        let shown = prompt.shown();
        let [shown] = shown.as_slice() else {
            panic!("asked once: {shown:?}");
        };
        let hash = hash_of(report);
        assert!(
            shown.starts_with("apply — target a.example.com (wetrun, awaiting confirmation)\n"),
            "{shown}"
        );
        // The plan, then the banner and the reason it is asked.
        assert!(
            shown.contains(&format!(
                "      > {RUN}\n  UNREVIEWED — this plan is not the one that was reviewed.\n    "
            )),
            "{shown}"
        );
        assert!(
            shown.ends_with(&format!(
                "\nplan_hash: {hash}\n{}",
                asked(APPLY_QUESTION, &hash)
            )),
            "{shown}"
        );
        assert!(
            !shown.contains("REFUSED") && !shown.contains("re-run"),
            "{shown}"
        );
    }

    /// The hash of the rig's one plan, as a preview on a rig of its own computes it.
    async fn rig_plan_hash() -> String {
        hash_of(&Rig::on("a.example.com").dry().await)
    }

    /// On a terminal, a wetrun with nothing reviewed shows its plan and asks for the
    /// start of its hash; typed back — in either case, blanks around it aside — it runs
    /// exactly the plan shown (the hash it showed is the one it ran under, with no plan
    /// computed between), and the run is recorded as a bound wetrun's is.
    #[tokio::test]
    async fn an_unreviewed_wetrun_on_a_terminal_runs_the_plan_whose_hash_start_is_typed() {
        let start = &rig_plan_hash().await[..super::prompt::CONFIRM_CHARS];
        for answer in [
            start.to_owned(),
            format!("{}\n", start.to_uppercase()),
            format!("  {start} \r\n"),
        ] {
            let rig = Rig::on("a.example.com");
            let prompt = ScriptedPrompt::answering(Some(&answer));
            let ran = rig.apply(asking(&prompt)).await.unwrap();
            assert_eq!(ran.refused, None, "{answer:?}: {}", render_apply(&ran));
            assert_eq!(ran.confirmation, Some(super::Confirmation::Accepted));
            assert_shown(&prompt, &ran);
            assert!(rig.ran(), "{answer:?}");
            assert_eq!(ran.outcomes.len(), 1);
            assert!(ran.streamed());
            // Recorded, and read back, as a wetrun bound to a preview is: the rig's
            // check still fails after the run, so each re-detection reads it residual.
            let bound = Rig::on("a.example.com");
            bound.dry().await;
            let bound = bound.apply(wetrun()).await.unwrap();
            assert_eq!(bound.confirmation, None);
            assert_eq!(ran.residual, bound.residual);
            assert_eq!(ran.exit_code(), bound.exit_code());
            assert_eq!(last_command(&rig), Some(RunCommand::ApplyAfterChanges));
            let rendered = render_apply(&ran);
            assert!(
                rendered.starts_with("apply — target a.example.com (wetrun, confirmed)\n"),
                "{rendered}"
            );
            assert!(rendered.contains("  ok    go\n"), "{rendered}");
            // The plan it ran is the one a preview computes.
            assert_eq!(hash_of(&rig.dry().await), hash_of(&ran));
        }
    }

    /// A preview of another plan is no review either: the wetrun asks about the plan it
    /// computed, saying what the preview planned.
    #[tokio::test]
    async fn a_wetrun_whose_plan_moved_since_its_preview_asks_about_the_new_one() {
        let rig = Rig::on("a.example.com");
        // The preview, as the bootstrap user: another plan, filed under the same host.
        let other = rig
            .apply(ApplyOptions {
                bootstrap: true,
                ..ApplyOptions::default()
            })
            .await
            .unwrap();
        let prompt = ScriptedPrompt::confirming();
        let ran = rig.apply(asking(&prompt)).await.unwrap();
        assert_ne!(hash_of(&other), hash_of(&ran));
        assert_eq!(ran.confirmation, Some(super::Confirmation::Accepted));
        assert_shown(&prompt, &ran);
        let shown = prompt.shown().remove(0);
        assert!(
            shown.contains("\n    the last preview (zap apply (dry run) at "),
            "{shown}"
        );
        assert!(
            shown.contains(&format!(
                ") planned {}; the config, the target, or the user the run connects as \
                 changed since.\nplan_hash: {}\n",
                hash_of(&other),
                hash_of(&ran)
            )),
            "{shown}"
        );
        assert!(rig.ran());
    }

    /// Any answer but the start of the hash — a `y`, a `yes`, a no, a start of another
    /// length, the whole hash, another hash's start, an empty line, the end of the input
    /// — is the refusal a wetrun with no review gets without a prompt: nothing runs, the
    /// plan shown is recorded as the host's preview, the exit is `2`, and the render says
    /// it was declined. The next wetrun binds to that preview.
    #[tokio::test]
    async fn a_declined_prompt_refuses_and_records_the_plan_it_showed() {
        let hash = rig_plan_hash().await;
        let wrong = if hash.starts_with('0') {
            "1111"
        } else {
            "0000"
        };
        for answer in [
            Some("y\n"),
            Some("yes"),
            Some("n\n"),
            Some("\n"),
            Some(&hash[..3]),
            Some(&hash[..5]),
            Some(hash.as_str()),
            Some(wrong),
            None,
        ] {
            let rig = Rig::on("a.example.com");
            let prompt = ScriptedPrompt::answering(answer);
            let declined = rig.apply(asking(&prompt)).await.unwrap();
            assert_eq!(
                declined.refused,
                Some(PlanUnreviewed::NoPreview { prior: None }),
                "{answer:?}"
            );
            assert_eq!(declined.confirmation, Some(super::Confirmation::Declined));
            assert_shown(&prompt, &declined);
            assert!(!rig.ran(), "{answer:?}");
            assert!(declined.outcomes.is_empty() && !declined.streamed());
            assert_eq!(declined.exit_code(), 2);
            let recorded =
                read_last_run(rig.home.path(), &rig.config_path, "a.example.com").unwrap();
            assert_eq!(recorded.command, RunCommand::ApplyRefused);
            assert_eq!(
                recorded.plan_hash.as_deref(),
                Some(hash_of(&declined).as_str())
            );
            let rendered = render_apply(&declined);
            assert!(
                rendered.starts_with("apply — target a.example.com (wetrun, declined)\n"),
                "{rendered}"
            );
            assert!(
                rendered.contains(&format!(
                    "  DECLINED — nothing ran: this plan was not confirmed, and is not the one \
                     that was reviewed.\n    no plan has been previewed on this host.\n  review \
                     the plan above, then re-run `zap apply --wetrun` (it binds to this \
                     preview) or pass --expect-plan {}\n",
                    hash_of(&declined)
                )),
                "{rendered}"
            );
            assert!(rendered.contains(&format!("      > {RUN}\n")), "{rendered}");

            // The next wetrun binds to the plan the prompt showed, and asks nothing.
            let again = ScriptedPrompt::confirming();
            let ran = rig.apply(asking(&again)).await.unwrap();
            assert_eq!(ran.refused, None, "{}", render_apply(&ran));
            assert_eq!(ran.confirmation, None);
            assert!(again.shown().is_empty() && rig.ran());
        }
    }

    /// The prompt is no bypass: a wetrun whose `--expect-plan` names another plan
    /// refuses with no question (the operator named a plan, and another isn't offered in
    /// its place); `--json` never asks; a run with no terminal refuses as it always has;
    /// a wetrun bound to its preview, or with an empty plan, has nothing to ask.
    #[tokio::test]
    async fn a_wetrun_asks_only_on_a_terminal_with_nothing_reviewed_or_named() {
        let rig = Rig::on("a.example.com");
        let prompt = ScriptedPrompt::confirming();
        let refused = rig
            .apply(ApplyOptions {
                expect_plan: Some("another".to_owned()),
                ..asking(&prompt)
            })
            .await
            .unwrap();
        assert!(matches!(
            refused.refused,
            Some(PlanUnreviewed::Expected { .. })
        ));
        assert_eq!(refused.confirmation, None);
        assert!(prompt.shown().is_empty() && !rig.ran());
        assert_eq!(refused.exit_code(), 2);

        let rig = Rig::on("a.example.com");
        let prompt = ScriptedPrompt::confirming();
        let refused = rig
            .apply(ApplyOptions {
                emit_json: true,
                ..asking(&prompt)
            })
            .await
            .unwrap();
        assert_eq!(
            refused.refused,
            Some(PlanUnreviewed::NoPreview { prior: None })
        );
        assert_eq!(refused.confirmation, None);
        assert!(prompt.shown().is_empty() && !rig.ran());

        let rig = Rig::on("a.example.com");
        let prompt = ScriptedPrompt::no_terminal();
        let refused = rig.apply(asking(&prompt)).await.unwrap();
        assert_eq!(
            refused.refused,
            Some(PlanUnreviewed::NoPreview { prior: None })
        );
        assert_eq!(refused.confirmation, None);
        assert!(prompt.shown().is_empty() && !rig.ran());
        let rendered = render_apply(&refused);
        assert!(rendered.contains("(wetrun, refused)") && rendered.contains("  REFUSED — "));

        // Bound to a preview, or by `--expect-plan`: run, unasked.
        let rig = Rig::on("a.example.com");
        let dry = rig.dry().await;
        let prompt = ScriptedPrompt::confirming();
        let ran = rig.apply(asking(&prompt)).await.unwrap();
        assert_eq!(ran.refused, None);
        assert_eq!(ran.confirmation, None);
        assert!(prompt.shown().is_empty() && rig.ran());
        let rig = Rig::on("a.example.com");
        let ran = rig
            .apply(ApplyOptions {
                expect_plan: Some(hash_of(&dry)),
                ..asking(&prompt)
            })
            .await
            .unwrap();
        assert_eq!(ran.confirmation, None);
        assert!(prompt.shown().is_empty() && rig.ran());
    }

    /// A plan that names no one machine has no hash to confirm: its wetrun is the config
    /// error it always was, asked nothing. Nor is a plan asked about that the command
    /// preflight would stop — a confirmation could only fail.
    #[tokio::test]
    async fn an_unbindable_or_unrunnable_plan_is_asked_nothing() {
        let _env = crate::resolve::test_env::set(&[
            ("ZAP_T_PROMPT_HOST_TOKEN", "hidden.example.com"),
            ("ZAP_T_PROMPT_VALUE", "it's"),
        ]);
        let rig = Rig::with_target(&serde_json::json!({
            "host": Text::reference("ZAP_T_PROMPT_HOST_TOKEN"),
            "user": "deploy",
        }));
        let prompt = ScriptedPrompt::confirming();
        let result = rig.apply(asking(&prompt)).await;
        assert!(
            matches!(&result, Err(Error::WetrunRefused(message))
                if message.starts_with("an apply wetrun needs a plan that names one machine")),
            "{result:?}"
        );
        assert!(prompt.shown().is_empty());
        assert!(rig.target.issued_queries().is_empty());

        let rig = Rig::running(&Text::of_pieces([Lit("echo "), Ref("ZAP_T_PROMPT_VALUE")]));
        let refused = rig.apply(asking(&prompt)).await.unwrap();
        assert_eq!(
            refused.refused,
            Some(PlanUnreviewed::NoPreview { prior: None })
        );
        assert_eq!(refused.confirmation, None);
        assert!(prompt.shown().is_empty());
        let rendered = render_apply(&refused);
        assert!(
            rendered.contains("warning: a wetrun of this plan will be refused — `go`: "),
            "{rendered}"
        );
    }

    /// A `y` typed ahead — while detection runs, before the plan is on the screen —
    /// sits in the terminal's input and is the first line the question reads. It is no
    /// confirmation: the answer is the start of a hash nobody has seen yet, so the plan
    /// is declined and nothing runs.
    #[tokio::test]
    async fn a_y_typed_ahead_of_the_plan_declines_it() {
        let rig = Rig::on("a.example.com");
        let prompt = ScriptedPrompt::answering(Some("y\n"));
        let report = rig.apply(asking(&prompt)).await.unwrap();
        assert_eq!(report.confirmation, Some(super::Confirmation::Declined));
        assert!(report.refused.is_some());
        assert!(!rig.ran());
        assert_eq!(report.exit_code(), 2);
    }

    /// A held service holds what would trigger it and what waits on it: a wetrun of the
    /// reviewed plan runs neither, and arms no pending marker — the source that would
    /// owe the restart never runs, so nothing is owed. What waits on nothing held runs.
    #[tokio::test]
    async fn a_wetrun_runs_nothing_held_behind_a_held_service() {
        use crate::resource::pending::read_query;

        let mut rig = Rig::with_target(&serde_json::json!({
            "host": "a.example.com", "user": "deploy", "service_manager": "systemd",
        }));
        rig.config = serde_json::from_value(serde_json::json!({
            "target": {"host": "a.example.com", "user": "deploy", "service_manager": "systemd"},
            "resources": [
                {"id": "go", "type": "script", "check": "test -e /srv/ready", "run": RUN},
                {"id": "src", "type": "script", "check": "test -e /srv/src",
                 "run": "touch /srv/src"},
                {"id": "web", "type": "service", "service": "web", "enabled": true,
                 "restart_on": ["src"]},
                {"id": "after", "type": "script", "check": "test -e /srv/after",
                 "run": "touch /srv/after", "depends_on": ["web"]},
            ],
        }))
        .unwrap();
        let unmet = || {
            Observation::Command(CommandObservation {
                code: 1,
                stdout: Vec::new(),
                stderr: Vec::new(),
            })
        };
        // The service's own reads are unrecorded, so detection can't determine it.
        rig.target = rig
            .target
            .with_observation(Query::operator_command("test -e /srv/src"), unmet())
            .with_observation(Query::operator_command("test -e /srv/after"), unmet())
            .with_observation(
                read_query(),
                Observation::Command(CommandObservation {
                    code: 0,
                    stdout: Vec::new(),
                    stderr: Vec::new(),
                }),
            );

        let preview = rig.dry().await;
        let held: Vec<(&str, String)> = preview
            .held
            .iter()
            .map(|held| (held.resource_id.0.as_str(), held.describe()))
            .collect();
        assert_eq!(held.len(), 3, "{held:?}");
        assert!(
            held.contains(&("src", "would restart `web`, which is held".to_owned())),
            "{held:?}"
        );
        assert!(
            held.contains(&("after", "waits on `web`, which is held".to_owned())),
            "{held:?}"
        );
        assert_eq!(preview.exit_code(), 1);

        let wet = rig.apply(wetrun()).await.unwrap();
        assert_eq!(wet.held.len(), 3, "{:?}", wet.held);
        assert_eq!(wet.exit_code(), 1, "{:?}", wet.summary);
        assert!(rig.ran(), "what waits on nothing held runs");
        let issued = rig.target.issued_commands();
        for never in ["touch /srv/src", "touch /srv/after"] {
            assert!(!issued.iter().any(|c| c == never), "{never}: {issued:?}");
        }
        assert!(
            !issued.iter().any(|c| c.contains("/var/lib/zap/pending")),
            "no marker is armed: {issued:?}"
        );
    }

    /// A text-mode wetrun shows each change as it starts, and the re-detect after them,
    /// on its progress sink; the outcomes stay the report's. A `--json` wetrun streams
    /// events instead and shows nothing there, and a dry run shows nothing at all.
    #[tokio::test]
    async fn a_text_wetrun_shows_each_change_and_the_redetect_as_they_start() {
        use crate::progress::{ProgressSink, RecordedProgress};

        let with = |sink: &Arc<RecordedProgress>, options: ApplyOptions| {
            let progress: Arc<dyn ProgressSink> = Arc::<RecordedProgress>::clone(sink);
            ApplyOptions {
                progress: Some(progress),
                ..options
            }
        };
        let rig = Rig::on("a.example.com");
        let sink = RecordedProgress::new();
        rig.apply(with(&sink, ApplyOptions::default()))
            .await
            .unwrap();
        assert!(sink.lines().is_empty(), "{:?}", sink.lines());
        let ran = rig.apply(with(&sink, wetrun())).await.unwrap();
        assert!(rig.ran() && ran.streamed());
        assert_eq!(
            sink.lines(),
            [
                "→ go: create script",
                "→ re-detect: reading 1 declared resource back to confirm what the changes left",
            ]
        );
        assert!(!render_apply(&ran).contains('→'));

        let rig = Rig::on("a.example.com");
        let sink = RecordedProgress::new();
        rig.dry().await;
        let ran = rig
            .apply(with(
                &sink,
                ApplyOptions {
                    emit_json: true,
                    ..wetrun()
                },
            ))
            .await
            .unwrap();
        assert!(rig.ran() && ran.streamed());
        assert!(sink.lines().is_empty(), "{:?}", sink.lines());
    }
}
