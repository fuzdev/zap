//! `zap deploy` — release a new version to a remote target.
//!
//! Deploy is an imperative act, not convergence (each run ships a new immutable,
//! versioned release and atomically swaps `current`), so it's a command that produces a
//! pure [`DeployPlan`] and walks it — mirroring how `apply` produces and walks the
//! convergence plan fact. The pure plan (including the remote extract-and-swap script)
//! is built in `zap_types::deploy`; this module does the IO: resolve the version (git),
//! build and archive locally (the archive in a private directory of the run), install
//! the archive on the target as the connecting user, run the remote script with the
//! archive's digest on its stdin, restart the service, and HTTP-poll the health
//! endpoint.
//!
//! Dry-run by default (render the plan); `--wetrun` executes. A wetrun first runs a
//! drift **preflight** (reusing `detect_and_diff`) so a new artifact isn't shipped
//! against stale apply-managed config. Deploy requires a **remote** target. A wetrun
//! shows each phase as it starts — the preflight, each step, a rollback — on the
//! operator's progress lines (`crate::progress`), or streams its steps' events under
//! `--json`. An outcome that reached the steps carries what the run measured
//! ([`DeployRun`]), and a failed one where it left the target ([`FailureState`]): before
//! the swap, at it, or after it with the rollback's result.
//!
//! **A wetrun executes only a reviewed plan.** A dry run renders the whole
//! [`DeployPlan`] — the host and endpoints it resolves to, the tree and preflight facts,
//! every step's command, script, and paths — prints its `plan_hash`, and records it as
//! the host's deploy preview (`crate::deploy_preview`). A wetrun executes only if the
//! plan it computes is the reviewed one (`review_deploy_plan`): the hash `--expect-plan`
//! names, or — by default — the recorded preview's. Otherwise it refuses before the
//! drift preflight and before any step, renders the plan it would have run, and records
//! that render as the preview, so a wetrun fired with nothing reviewed becomes the
//! review — or, on an interactive terminal, shows that plan and asks to deploy it
//! (`super::prompt`): the start of its hash typed back runs it as a bound wetrun runs,
//! from the drift preflight on, and anything else is the refusal. The hash is rendered
//! only with the plan it stands for, and a preview is recorded only by a pass that
//! renders one ([`DeployOutcome::preview_pass`]), before the binary writes it: the record
//! says the plan was printed, not that anyone read it. The binary withdraws it when its
//! write fails ([`DeployReport::preview`], `super::preview`); a preview whose output was
//! written but discarded or cut short still binds the next bare wetrun, and
//! `--expect-plan` is the binding for output that may be truncated or a reader who isn't
//! the runner. A deploy
//! that gets as far as its steps withdraws the preview first, so one review covers one
//! execution, whichever way it ends. The preview is a record of its own: the last-run
//! report `apply` binds to is neither read nor written by it.
//!
//! A plan whose host or health domain resolves through a masked reference names no one
//! machine, so its hash would stand for every machine the reference could name and its
//! preview would be filed under a token. A wetrun of such a config is an error before
//! the connection is touched (`unbindable_message`); a dry run still renders the plan,
//! with no hash and no preview ([`DeployOutcome::DryRunUnbindable`]).
//!
//! A working tree with uncommitted changes or untracked files deploys only under
//! `--force`, which names the release `<hash>-dirty-<id>` by the tree's changes.
//! Without it the release would ship the tree under the commit's version, so a wetrun
//! is an error before the connection is touched ([`Error::DirtyTree`]), and a dry run
//! renders the plan with no hash and no preview ([`DeployOutcome::DryRunDirty`]).
//!
//! Machine-free gates run *before* the connection is touched, so a misconfigured deploy
//! costs no IO: the shared secret + structure gates (the latter covering
//! `deploy.health.domain`), plus the unresolved-reference env preflight — `apply`'s,
//! applied here for the same reason (see `super::unresolved_env_message`). The deploy
//! domain is a declared config field, so it needs no gate of its own: an absent one is
//! unrepresentable, a blank literal is structural, and an unset reference is just
//! another unresolved ref.
//!
//! This module is the run itself: the gates, the plan, the review, and the drift
//! preflight. The rest is by role: `checkout` reads the working tree's state and
//! version, `live` what the target serves, `walk` executes the steps, `health` polls
//! the health and readiness endpoints, `rollback` undoes a failed release after its
//! swap, and `render` is the text `zap deploy` prints.
//!
//! Execution against a real target is validated by hand (`docs/testing.md`); the suite
//! covers the pure plan (`zap_types::deploy`), the masker, and the orchestration over a
//! `MockConnection`.

mod checkout;
mod health;
pub(crate) mod live;
mod render;
mod rollback;
mod walk;

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use zap_types::config_hash::deploy_plan_hash;
use zap_types::deploy::{
    DeployContext, DeployPlan, DeployStepId, DriftPreflight, deploy_references, plan_deploy,
};
use zap_types::deploy_preview::{DeployPreviewPass, DeployUnreviewed, review_deploy_plan};
use zap_types::detected::Detection;
use zap_types::event::{Event, RunSummary, StepOutcome};
use zap_types::last_run::{ReportVar, RunCommand, host_label, resolved_label};
use zap_types::lock::ZapLock;
use zap_types::plan::{HeldResource, PlanResult, Trigger};
use zap_types::schema::{ResourceId, ResourceKind, ZapConfig};
use zap_types::text::Text;

use super::preview::RecordedPreview;
use super::prompt::{self, Confirmation, DEPLOY_QUESTION, Prompt};
use super::{
    Diffed, NAMES_NO_ONE_MACHINE, PassContext, connecting_user, detect_and_diff, eval_target,
    masked_label_refs, target_location,
};
use crate::connection::{Connection, RunOptions};
use crate::deploy_preview::{
    new_deploy_preview, read_deploy_preview, read_deploy_preview_file, write_deploy_preview,
};
use crate::error::{Error, Previewed, Result};
use crate::event::{EventHandler, mask_handler};
use crate::home::deploy_preview_path_for;
use crate::home::zap_home_default;
use crate::last_run::report_var;
use crate::lock::{LockStanding, inspect_lock};
use crate::progress::{Notice, ProgressSink, count};
use crate::resolve::env_var;

use checkout::{Shipped, git_shipped, git_uncommitted};
use live::{LiveReadError, live_release_present, server_version};
pub use render::render_deploy;
use walk::{AppWalk, ReleaseArchive, Stopped, execute_deploy_plan};

/// Knobs for a deploy run (mirrors [`ApplyOptions`](super::apply::ApplyOptions)).
///
/// A flat bundle of CLI flags — the `excessive_bools` lint targets domain types
/// where a flag combination encodes hidden state, not a 1:1 mirror of the
/// command-line switches, which is what this is.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, Default)]
pub struct DeployOptions {
    /// Actually execute the deploy (`--wetrun`) rather than only previewing the plan.
    pub wetrun: bool,
    /// The deploy plan hash the wetrun must compute to execute (`--expect-plan`). `None`
    /// binds to the host's recorded deploy preview instead (module docs). A dry run
    /// rejects it.
    pub expect_plan: Option<String>,
    /// Deploy even when the server already runs this version (`--force`), and version
    /// a dirty tree `<hash>-dirty-<id>` by its `dirty_id`. Without it a wetrun of a
    /// dirty tree is refused ([`DIRTY_NEEDS_FORCE`]) and a dry run previews it as
    /// [`DeployOutcome::DryRunDirty`].
    pub force: bool,
    /// Leave the local build step out of the plan even when `deploy.build` is set.
    pub skip_build: bool,
    /// Skip the pre-deploy drift preflight. A fact of the plan
    /// ([`DriftPreflight::Skipped`]): it is rendered and hashed.
    pub skip_preflight: bool,
    /// Connect as the target's `bootstrap_user` (the `--bootstrap` switch) — the initial
    /// provisioning run before SSH hardening creates the primary user.
    pub bootstrap: bool,
    /// Stream the run's events to stdout as JSON-lines (wetrun-only).
    pub emit_json: bool,
    /// Force a fresh config eval, bypassing the L0 eval cache (`--no-cache`).
    pub no_cache: bool,
    /// Where a wetrun with no review asks its operator to confirm the plan instead of
    /// refusing it (module docs). `None` never asks — every run but an interactive one.
    pub prompt: Option<Arc<dyn Prompt>>,
    /// Where a text-mode wetrun shows each phase as it starts (`crate::progress`): the
    /// binary's standard error. `None` shows nothing live; `--json` streams events
    /// instead.
    pub progress: Option<Arc<dyn ProgressSink>>,
    /// Where a test collects the wetrun's events, in place of the stdout or null sink.
    #[cfg(test)]
    pub capture: Option<Arc<std::sync::Mutex<Vec<Event>>>>,
}

/// How a deploy ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeployOutcome {
    /// Dry-run — the plan was rendered, nothing executed.
    DryRun,
    /// Dry-run of a plan that names no one machine: rendered, nothing executed, and
    /// neither hashed for the operator nor recorded, since no wetrun of this config can
    /// run. Carries why (`unbindable_message`).
    DryRunUnbindable(String),
    /// Dry-run over a working tree with uncommitted changes or untracked files and no
    /// `--force`: rendered, nothing executed, and neither hashed nor recorded, since a
    /// wetrun of it is refused ([`DIRTY_NEEDS_FORCE`]) — it would ship the tree under
    /// the commit's version.
    DryRunDirty,
    /// The release was deployed: every step completed.
    Deployed(DeployRun),
    /// The server already runs this version (skipped; use `--force` to redeploy).
    AlreadyDeployed,
    /// A wetrun refused to execute because its plan isn't the reviewed one — the hash
    /// `--expect-plan` named, or the host's recorded preview: the reason, with the
    /// report's plan the one it rendered instead. No preflight and no step ran.
    Refused(DeployUnreviewed),
    /// A drift preflight found pending apply changes; deploy bailed.
    PreflightDrift,
    /// A drift preflight could not probe every resource, so "no drift" was never
    /// established; deploy bailed rather than shipping against an unread target.
    PreflightUndetermined,
    /// A step failed during a wetrun.
    Failed {
        /// What the run measured and learned up to its end.
        run: DeployRun,
        /// Where the failure left the target.
        left: FailureState,
    },
}

/// What a wetrun that reached its steps measured and learned as it ran.
///
/// Carried on the outcome rather than read from a clock at render time, so a render is
/// a function of its report.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DeployRun {
    /// How long the drift preflight's detection pass took, when the plan's preflight
    /// checks.
    pub preflight: Option<Duration>,
    /// Each step that was attempted, in the order run.
    pub steps: Vec<StepRecord>,
    /// From the start of the drift preflight to the end of the run, a rollback
    /// included: what the deploy took once it was bound to its review.
    pub total: Duration,
}

impl DeployRun {
    /// The record of the step whose outcome names `step`, if it was attempted.
    #[must_use]
    pub fn step(&self, step: &str) -> Option<&StepRecord> {
        self.steps.iter().find(|record| record.id.as_str() == step)
    }
}

/// One attempted step of a wetrun: how long it took, and what it says in the report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StepRecord {
    /// Which step.
    pub id: DeployStepId,
    /// How long it ran.
    pub took: Duration,
    /// Its one-line summary, for a step whose result the engine itself describes.
    pub summary: Option<StepSummary>,
}

/// A step's summary on its outcome line: text the engine wrote, never a command's
/// output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StepSummary {
    /// The upload sent the release archive, this many bytes.
    Uploaded {
        /// The archive's size.
        bytes: u64,
    },
    /// What a poll found (the health check's attempts, the readiness gate's answer).
    Said(String),
}

/// Where a failed wetrun left the target, by where its failure fell against the swap of
/// `current`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FailureState {
    /// A step before the extract-and-swap failed: nothing was released, and `current`
    /// was not moved.
    BeforeSwap,
    /// The extract-and-swap step failed, and nothing was rolled back: what a read of
    /// `current` established about the swap.
    AtSwap(SwapFailure),
    /// A step after the swap failed, and the auto-rollback ran: how it went.
    AfterSwap(Rollback),
}

/// What a failed extract-and-swap step establishes about `current`, read back after the
/// failure (`walk::swap_ran`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SwapFailure {
    /// `current` names another release, or none: this run's release is not live.
    NotSwapped,
    /// Not known: `current` names this version — this run's swap, or another deploy's
    /// of the same version — or could not be read. A swap can come before such a failure
    /// (the connection lost after it, or the swap line lost with a failed exit).
    Unknown,
}

/// The auto-rollback of a failure after the swap (`rollback`'s module docs).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rollback {
    /// It never started: there was nothing to return to — no previous release is known,
    /// or the previous release is this same version (a `--force` redeploy) — so
    /// `current` is left at the failed release.
    NotStarted,
    /// It ran.
    Ran {
        /// How it left the target.
        outcome: RollbackOutcome,
        /// How long it ran.
        took: Duration,
    },
}

/// How the auto-rollback left the target.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RollbackOutcome {
    /// `current` names the previous release again, which was restarted.
    RolledBack {
        /// Whether the plan checks health, and so the restored release was found
        /// healthy.
        health_checked: bool,
    },
    /// `current` names the previous release again, but its restart or its health check
    /// failed: it is not confirmed serving.
    Unconfirmed,
    /// Its compare-and-swap moved nothing, and `current` is as the warnings say: another
    /// deploy holds the app's lock, `current` no longer names the failed release or
    /// names nothing, or the previous release is gone from the host.
    NotDone,
    /// The re-point itself failed: what `current` names is not known.
    Failed,
}

/// The outcome of a deploy — the plan that was (or would be) applied, plus per-step
/// outcomes on a wetrun. The binary renders it via [`render_deploy`] and maps
/// [`DeployReport::exit_code`].
#[derive(Debug, Clone)]
pub struct DeployReport {
    /// Target location label (a host; deploy is remote-only).
    pub target: String,
    /// Whether the run was a `--wetrun`. The [`outcome`](Self::outcome) says how far it
    /// got: a wetrun can stop before its steps (already deployed, refused, a preflight
    /// bail).
    pub wetrun: bool,
    /// How it ended.
    pub outcome: DeployOutcome,
    /// The deploy plan (previewed on a dry-run, executed on a wetrun), as rendered: any
    /// registered secret value in its text is masked ([`DeployPlan::map_text`]). Every
    /// plan-derived line of the render is read from here.
    pub plan: DeployPlan,
    /// Content address of the deploy plan the run computed.
    pub plan_hash: String,
    /// Per-step outcomes, in plan order. Empty unless a wetrun executed.
    pub step_outcomes: Vec<StepOutcome>,
    /// Non-fatal diagnostics (a dirty tree under --force, drift preflight, …).
    pub warnings: Vec<String>,
    /// Resources the drift preflight couldn't probe. Non-empty means the preflight's
    /// verdict covered only part of the target — the gate didn't fully run. Empty
    /// whenever the preflight was skipped or the run is a dry run.
    pub held: Vec<HeldResource>,
    /// How the config's tracked pins stand for the drift preflight. A non-current pin is
    /// withheld from detection, so on a wetrun this is normally *why* a resource is
    /// [`held`](Self::held), and on a dry run it is what the wetrun's preflight will
    /// bail on — and it names the fix; a refused wetrun carries it as a dry run does.
    /// Default (clean) when the plan's preflight doesn't check (skipped, or nothing
    /// declared), and for an already-deployed target.
    pub lock_standing: LockStanding,
    /// The pass this run was recorded as, when it was: the host's deploy preview now
    /// holds [`plan_hash`](Self::plan_hash), and a wetrun with no `--expect-plan` binds
    /// to it. `None` for an outcome that is no preview
    /// ([`DeployOutcome::preview_pass`]) and for a preview that couldn't be recorded.
    pub recorded: Option<DeployPreviewPass>,
    /// How the review went at the prompt, when the wetrun asked (module docs):
    /// [`Accepted`](Confirmation::Accepted) on one that went on as a reviewed wetrun,
    /// [`Declined`](Confirmation::Declined) on one [`Refused`](DeployOutcome::Refused)
    /// after it. `None` when nothing was asked.
    pub confirmation: Option<Confirmation>,
    /// The record behind [`recorded`](Self::recorded): what the binary withdraws when
    /// the report never arrives ([`RecordedPreview::withdraw`]).
    pub preview: Option<RecordedPreview>,
}

impl DeployOutcome {
    /// Whether the render prints the `plan_hash`. Only under the plan it stands for —
    /// its steps previewed in full, or as their outcomes — since a hash is a handle on a
    /// plan rendered with it, and `--expect-plan` must not be able to name one that
    /// wasn't — and only for a plan that names one machine.
    #[must_use]
    pub const fn shows_hash(&self) -> bool {
        match self {
            Self::DryRun | Self::Refused(_) | Self::Deployed(_) | Self::Failed { .. } => true,
            Self::DryRunUnbindable(_)
            | Self::DryRunDirty
            | Self::AlreadyDeployed
            | Self::PreflightDrift
            | Self::PreflightUndetermined => false,
        }
    }

    /// The preview this outcome stands as: the pass that rendered a plan for review and
    /// executed none of it. `Some` exactly for the outcomes whose plan and hash were
    /// rendered with nothing run, which are the ones recorded as the host's deploy
    /// preview — so a recorded hash is always one rendered with its plan. Rendered, not
    /// read: the record is written before the binary writes the report, which withdraws
    /// it when that write fails, and leaves it when a reader discards or cuts short what
    /// was written.
    #[must_use]
    pub const fn preview_pass(&self) -> Option<DeployPreviewPass> {
        match self {
            Self::DryRun => Some(DeployPreviewPass::DryRun),
            Self::Refused(_) => Some(DeployPreviewPass::RefusedWetrun),
            Self::DryRunUnbindable(_)
            | Self::DryRunDirty
            | Self::Deployed(_)
            | Self::Failed { .. }
            | Self::AlreadyDeployed
            | Self::PreflightDrift
            | Self::PreflightUndetermined => None,
        }
    }

    /// What the run measured, for an outcome that reached its steps.
    #[must_use]
    pub const fn run(&self) -> Option<&DeployRun> {
        match self {
            Self::Deployed(run) | Self::Failed { run, .. } => Some(run),
            Self::DryRun
            | Self::DryRunUnbindable(_)
            | Self::DryRunDirty
            | Self::AlreadyDeployed
            | Self::Refused(_)
            | Self::PreflightDrift
            | Self::PreflightUndetermined => None,
        }
    }

    /// Whether the release was deployed.
    #[must_use]
    pub const fn is_deployed(&self) -> bool {
        matches!(self, Self::Deployed(_))
    }

    /// Whether a step failed.
    #[must_use]
    pub const fn is_failed(&self) -> bool {
        matches!(self, Self::Failed { .. })
    }
}

/// A deploy changed the target when it reached its steps, which build, upload, and swap
/// ([`DeployReport::streamed`]); one that stopped before them only answered.
impl super::Delivered for DeployReport {
    fn exit_code(&self) -> u8 {
        Self::exit_code(self)
    }
    fn changed(&self) -> bool {
        self.streamed()
    }
    fn preview(&self) -> Option<&RecordedPreview> {
        self.preview.as_ref()
    }
}

impl DeployReport {
    /// Whether the run reached its steps, and so emitted events: a `--json` wetrun that
    /// didn't has streamed nothing, and its caller needs the text render to learn why.
    #[must_use]
    pub const fn streamed(&self) -> bool {
        self.wetrun && self.outcome.run().is_some()
    }

    /// Process exit code: `Failed` is `1`, a refusal and either preflight bail are `2`,
    /// everything else (dry-run, deployed, already-deployed) is `0`.
    #[must_use]
    pub const fn exit_code(&self) -> u8 {
        match self.outcome {
            DeployOutcome::Failed { .. } => 1,
            DeployOutcome::Refused(_)
            | DeployOutcome::PreflightDrift
            | DeployOutcome::PreflightUndetermined => 2,
            DeployOutcome::DryRun
            | DeployOutcome::DryRunUnbindable(_)
            | DeployOutcome::DryRunDirty
            | DeployOutcome::Deployed(_)
            | DeployOutcome::AlreadyDeployed => 0,
        }
    }
}

/// Deploy a release. Uses the default `~/.zap` (for the eval cache, the deploy preview,
/// and the preflight).
///
/// # Errors
/// Propagates config-eval, secret-validation, lock, connectivity, and git failures
/// (fatal setup errors); rejects `--expect-plan` on a dry run
/// ([`Error::ExpectPlanWithoutWetrun`]), a wetrun with an unset reference or of a plan
/// that names no one machine ([`Error::WetrunRefused`]), and a wetrun of a dirty tree
/// without `--force`; and stops a wetrun whose recorded preview can't be withdrawn, or
/// was withdrawn or replaced by another run first. Per-step execution failures are
/// recorded in the report, not returned as an error.
pub async fn run_deploy(
    config_path: &Path,
    fgro: Option<&Path>,
    options: &DeployOptions,
) -> Result<DeployReport> {
    run_deploy_in(zap_home_default()?.as_deref(), fgro, config_path, options).await
}

/// [`run_deploy`] with the `~/.zap` root injected (the hermetic test seam).
///
/// # Errors
/// Same as [`run_deploy`].
pub async fn run_deploy_in(
    zap_home: Option<&Path>,
    fgro: Option<&Path>,
    config_path: &Path,
    options: &DeployOptions,
) -> Result<DeployReport> {
    if options.expect_plan.is_some() && !options.wetrun {
        return Err(Error::ExpectPlanWithoutWetrun);
    }
    let (config, target_conn, masker) = eval_target(
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
    // Operator-side commands (git, build, tarball, health) run locally; the target
    // connection receives the archive and runs the remote script / restart. The release
    // archive is made in a private directory under the system's temporary one.
    deploy_over(
        &Connection::Local,
        &target_conn,
        &config,
        ctx,
        options,
        &std::env::temp_dir(),
    )
    .await
}

/// Deploy an evaluated, gated `config` over the two connections: `local` for the
/// operator-side commands, `target_conn` for the target's. [`run_deploy_in`] past the
/// config eval and the connection bind. `scratch` is the directory a wetrun makes its
/// private release-archive directory in.
///
/// # Errors
/// Same as [`run_deploy`], less the config eval's — each masked by the run's masker.
async fn deploy_over(
    local: &Connection,
    target_conn: &Connection,
    config: &ZapConfig,
    ctx: PassContext<'_>,
    options: &DeployOptions,
    scratch: &Path,
) -> Result<DeployReport> {
    // Boxed: the deploy's future is large, and this one would hold it whole.
    super::masking_errors(
        ctx.masker,
        Box::pin(deploy_unmasked(
            local,
            target_conn,
            config,
            ctx,
            options,
            scratch,
        )),
    )
    .await
}

/// [`deploy_over`], its errors as they were raised.
async fn deploy_unmasked(
    local: &Connection,
    target_conn: &Connection,
    config: &ZapConfig,
    ctx: PassContext<'_>,
    options: &DeployOptions,
    scratch: &Path,
) -> Result<DeployReport> {
    let PassContext {
        zap_home,
        config_path,
        masker,
        ..
    } = ctx;
    // Deploy is remote-only (a release swap targets a server, not the operator box).
    if config.target.is_local() {
        return Err(Error::Config(
            "deploy requires a remote target with `host` (it ships a release over SSH)".to_owned(),
        ));
    }
    let deploy = config.deploy.clone().ok_or_else(|| {
        Error::Config("no `deploy` block in the config — add `zap.deploy({…})`".to_owned())
    })?;
    if deploy.service.is_some() && config.target.service_manager.is_none() {
        return Err(Error::Config(
            "`deploy.service` is set but `target.service_manager` is not".to_owned(),
        ));
    }

    // The same fail-fast env preflight `apply` runs, for the same reason: deploy
    // consumes the whole config — its drift preflight detects every apply-managed
    // resource, and an unset reference resolves to an empty string there too, so the
    // desired side of that comparison is half-built. A wetrun rejects; a dry run warns.
    let env_warning = super::unresolved_env_message(config);
    if let Some(message) = &env_warning
        && options.wetrun
    {
        return Err(Error::WetrunRefused(message.clone()));
    }

    let mut warnings: Vec<String> = env_warning.into_iter().collect();

    // What the plan is for, resolved: the declared host and health domain alone are the
    // same text for every value a reference takes. Resolved as the last-run report
    // labels a host, so a secret reference stays its token — which names no one
    // machine, so a plan holding one can't be bound and a wetrun of it is refused. The
    // connecting user is held to the same rule: the plan carries it by value, so one
    // that is a secret's would put a function of that secret in the hash.
    let var = report_var(config, masker);
    let target_host = host_label(&config.target, &var)
        .ok_or_else(|| Error::Config("the target's `host` resolves to nothing".to_owned()))?;
    let health_domain = deploy
        .health
        .as_ref()
        .map(|health| resolved_label(&health.domain, &var))
        .unwrap_or_default();
    // What the references the `deploy` block uses resolve to, as the plan records them.
    let references = deploy_references(&deploy, &var);
    let unbindable = unbindable_message(
        config,
        connecting_user(&config.target, ctx.bootstrap)?,
        &var,
    );
    if let Some(unbindable) = &unbindable
        && options.wetrun
    {
        return Err(Error::WetrunRefused(format!(
            "a deploy wetrun needs a plan that names one machine — nothing ran: {unbindable}"
        )));
    }

    // The tree's state, read operator-side before the target is touched. Without
    // `--force` a dirty tree has no version of its own: the release would take the
    // commit's hash while shipping the tree's artifacts, and a later deploy of that
    // commit would find it "already deployed". A wetrun refuses it; a dry run previews
    // it, unhashed (`DryRunDirty`).
    let dirty = git_uncommitted(local, masker).await?;
    let dirty_unforced = dirty && !options.force;
    if dirty_unforced && options.wetrun {
        return Err(Error::DirtyTree);
    }

    // What the drift preflight does, and over what: a fact of the plan. The preflight
    // compares against the on-disk pins — deploy doesn't mint lock entries (that's
    // `apply` / `zap lock`), and a pin the ledger can't vouch for is withheld, so its
    // resource holds and the gate bails `PreflightUndetermined` rather than shipping a
    // release against an invalidated lock. The lock is read once, here, so the pins the
    // plan's digest names are the ones the preflight detects against.
    let (preflight, checked) = if config.resources.is_empty() {
        (DriftPreflight::NothingDeclared, None)
    } else if options.skip_preflight {
        (DriftPreflight::Skipped, None)
    } else {
        let (lock, standing) = inspect_lock(config, config_path, env_var)?;
        let preflight =
            DriftPreflight::checks(&config.resources, lock.as_ref()).map_err(Error::PlanHash)?;
        (preflight, Some((lock, standing)))
    };

    target_conn.check_connectivity().await?;

    // Resolve version + deploy metadata (operator-side + one remote read), so every
    // outcome — including the short-circuits — carries a real version and plan.
    if dirty && options.force {
        warnings.push("deploying with uncommitted changes or untracked files (--force)".to_owned());
    }
    let Shipped { version, subject } = git_shipped(local, dirty && options.force, masker).await?;
    // A failed read is reported now, not folded into "not deployed yet": `previous` is
    // the auto-rollback's only target, so losing it silently disarms the post-swap net.
    //
    // A `current` that names no release is refused here, before anything is built or
    // sent: the script's own check would stop the run before its swap, so it could only
    // fail, and the run would have shipped a release for nothing.
    let previous_version = match server_version(target_conn, &deploy.path).await {
        Ok(previous) => previous,
        Err(LiveReadError::NoRelease(message)) => {
            return Err(Error::LiveReleaseUnknown(message));
        }
        Err(LiveReadError::Unreadable(error) | LiveReadError::NotALink(error)) => {
            warnings.push(format!(
                "could not read the live release symlink ({error}) — treating the target as \
                 never-deployed. If this deploy fails after the symlink swap there will be \
                 no known release to roll back to, and `current` would be left at the \
                 failed one"
            ));
            None
        }
    };

    // Every return below funnels through `finish`, which masks what the report renders
    // at the consumption boundary: its narrative (a rollback warning quotes a failed
    // remote command's stderr, a held reason a seam-resolved path), and its plan, which
    // carries the version read off the target, the resolved connecting user, and the
    // operator identity. The step outcomes and the event stream are masked where
    // they are produced. The plan is masked last, so what executes and what `plan_hash`
    // addresses is the plan as computed — and through its typed text map, which has no
    // serialized form in between to fail and hand the plan back unmasked.
    //
    // It is also the one place a preview is recorded: for the outcomes that rendered a
    // plan and its hash and ran nothing, under the host the computed plan names.
    let mask = |mut report: DeployReport| {
        if let DeployOutcome::DryRunUnbindable(reason) = &mut report.outcome {
            *reason = masker.mask(reason);
        }
        super::mask_diagnostics(masker, &mut report.warnings, &mut report.held);
        if let DeployOutcome::Deployed(run) | DeployOutcome::Failed { run, .. } =
            &mut report.outcome
        {
            for record in &mut run.steps {
                if let Some(StepSummary::Said(said)) = &mut record.summary {
                    *said = masker.mask(said);
                }
            }
        }
        report.plan = report.plan.map_text(|text| masker.mask(text));
        report
    };
    let finish = |mut report: DeployReport| {
        if let Some(pass) = report.outcome.preview_pass() {
            match record_preview(
                zap_home,
                config_path,
                pass,
                &report.plan.host,
                &report.plan_hash,
            ) {
                Ok(preview) => {
                    report.recorded = Some(pass);
                    report.preview = Some(preview);
                }
                Err(why) => report.warnings.push(format!(
                    "this preview was not recorded ({why}), so a wetrun binds to it only \
                     with --expect-plan {}",
                    report.plan_hash
                )),
            }
        }
        Ok(mask(report))
    };

    // Build the content-addressed deploy plan once; the report carries it through
    // every branch (we only flip `outcome` / `step_outcomes`).
    let plan = plan_deploy(
        &deploy,
        &config.target,
        &DeployContext {
            version: version.clone(),
            subject,
            target_user: target_conn.user().to_owned(),
            deployed_by: deployed_by(local).await,
            previous_version,
            target_host,
            health_domain,
            dirty,
            skip_build: options.skip_build,
            preflight,
            references,
        },
    );
    let plan_hash = deploy_plan_hash(&plan).map_err(Error::PlanHash)?;
    let mut report = DeployReport {
        target: target_location(&config.target),
        wetrun: options.wetrun,
        outcome: DeployOutcome::DryRun,
        plan,
        plan_hash,
        step_outcomes: Vec::new(),
        warnings,
        held: Vec::new(),
        lock_standing: LockStanding::default(),
        recorded: None,
        confirmation: None,
        preview: None,
    };

    // Already-deployed short-circuit — for a `current` that names a release on the host.
    // One that names a missing release (a `--force` of the live version killed between
    // its renames, or a release removed by hand) serves nothing, so the run goes on as
    // a redeploy, whose script recovers what was moved aside.
    // A dirty tree's dry run is not short-circuited: the tree is not what the live
    // release holds, and the preview says what a wetrun needs.
    if report.plan.previous.as_deref() == Some(report.plan.version.as_str())
        && !options.force
        && !dirty_unforced
    {
        if live_release_present(target_conn, &deploy.path).await? {
            report.outcome = DeployOutcome::AlreadyDeployed;
            return finish(report);
        }
        report.warnings.push(format!(
            "`current` names releases/{}, which is not on the host (a deploy that did not \
             finish, or a release removed by hand) — this run redeploys it",
            report.plan.version
        ));
    }

    // The review gate. After the short-circuit above, which runs nothing and so has
    // nothing to review; before the preflight and every step, so a refusal has read the
    // version and the live release and done nothing else. `--force` and
    // `--skip-preflight` don't reach past it. The recorded preview is read only when no
    // `--expect-plan` binds explicitly, and before `finish` can replace it.
    // `binding` is what the wetrun passed under, and `None` on a dry run.
    //
    // First, what the preflight will meet in the lock, said under both previews — the
    // dry run and a refusal — as well as a bail: a pin the ledger doesn't answer for
    // holds its resource, and the wetrun stops on it.
    if let Some((_, standing)) = &checked {
        report.lock_standing = standing.clone();
    }
    let binding = if options.wetrun {
        match review_gate(
            zap_home,
            config_path,
            &report.plan.host,
            &report.plan_hash,
            options.expect_plan.as_deref(),
        ) {
            Ok(binding) => Some(binding),
            Err(reason) => {
                // With nothing reviewed, an interactive operator reviews the plan here:
                // shown as a refusal would show it, masked as every render is, and
                // deployed when the start of its hash is typed back.
                report.confirmation = prompt::confirm(
                    options.prompt.as_deref(),
                    options.emit_json,
                    &reason,
                    &report.plan_hash,
                    || {
                        let mut asking = report.clone();
                        asking.outcome = DeployOutcome::Refused(reason.clone());
                        asking.confirmation = Some(Confirmation::Asking);
                        render_deploy(&mask(asking))
                    },
                    DEPLOY_QUESTION,
                );
                if report.confirmation == Some(Confirmation::Accepted) {
                    Some(Binding::Confirmed)
                } else {
                    report.outcome = DeployOutcome::Refused(reason);
                    return finish(report);
                }
            }
        }
    } else {
        None
    };

    // The wetrun's sink (masked at the boundary), made before the preflight so that
    // phase shows as it starts: the JSON-lines stream, or the operator's progress lines.
    // The stream itself begins with the steps.
    let inner = EventHandler::for_run(options.emit_json, options.progress.as_ref());
    #[cfg(test)]
    let inner = options
        .capture
        .as_ref()
        .map_or(inner, |events| EventHandler::Capture(Arc::clone(events)));
    let handler = mask_handler(masker.clone(), inner);
    let started = Instant::now();
    let mut preflight_took = None;

    // Drift preflight (wetrun only): don't ship an artifact against stale apply config.
    // `checked` is the lock read for a plan whose preflight checks, so the gate runs
    // exactly when the plan says it does. A bail leaves the recorded preview in place:
    // nothing ran, and the same plan can deploy once the drift is cleared.
    if options.wetrun
        && let Some((lock, _)) = checked
    {
        if let DriftPreflight::Checks { resources, .. } = report.plan.preflight {
            handler.notice(Notice::DriftPreflight { resources });
        }
        let Diffed {
            result: drift,
            detected,
            ..
        } = drift_preflight(target_conn, config, ctx, lock.as_ref()).await?;
        preflight_took = Some(started.elapsed());
        let drifted = preflight_drift_count(config, &drift, &detected);
        report.warnings.extend(drift.warnings);
        // A held resource is one the preflight *could not check*. It contributes no
        // change, so a gate that counted only changes would pass on it: an unprobeable
        // nginx config or firewall would read as "no drift" and the release would ship.
        // The gate has to fail closed on a check it didn't run, the same way it fails on
        // one it ran and didn't like.
        report.held = drift.held;
        if drifted > 0 {
            report.warnings.push(drift_warning(drifted));
            report.outcome = DeployOutcome::PreflightDrift;
            return finish(report);
        }
        if !report.held.is_empty() {
            report.outcome = DeployOutcome::PreflightUndetermined;
            return finish(report);
        }
    }

    let Some(binding) = binding else {
        // Dry-run: the plan preview is the output. A plan that names no one machine is
        // shown without the hash and recorded nowhere.
        if let Some(unbindable) = unbindable {
            if dirty_unforced {
                report.warnings.push(DIRTY_NEEDS_FORCE.to_owned());
            }
            report.outcome = DeployOutcome::DryRunUnbindable(unbindable);
        } else if dirty_unforced {
            report.outcome = DeployOutcome::DryRunDirty;
        }
        return finish(report);
    };

    // The review is spent here, before the first step: an executed deploy — whether it
    // succeeds, fails, or is interrupted — leaves no preview a second wetrun could bind
    // to. A preview that can't be withdrawn stops the deploy.
    spend_preview(
        zap_home,
        config_path,
        &report.plan.host,
        &report.plan_hash,
        binding,
    )?;

    // Wetrun: stream events, walk the plan, stop on first fail.
    handler.emit(&Event::RunStarted {
        target: report.target.clone(),
        wetrun: true,
        plan_hash: report.plan_hash.clone(),
        total: u32::try_from(report.plan.steps.len()).unwrap_or(u32::MAX),
    });
    let walked = execute_deploy_plan(
        local,
        target_conn,
        AppWalk {
            app: &deploy.path,
            swap_script: &DeployPlan::swap_script,
        },
        &report.plan,
        ReleaseArchive::under(scratch),
        &handler,
        &mut report.warnings,
    )
    .await;
    let outcomes: Vec<StepOutcome> = walked
        .outcomes
        .into_iter()
        .map(|outcome| outcome.map_text(|text| masker.mask(text)))
        .collect();
    let mut run = DeployRun {
        preflight: preflight_took,
        steps: walked.records,
        total: Duration::ZERO,
    };

    // Where a failure left the target. One before the extract-and-swap never moved
    // `current`; one at it may follow a swap (`walk::swap_ran`), so nothing is undone and
    // the report says the swap is not known not to have happened. One after it leaves
    // `current` at the just-shipped, broken release: the auto-rollback re-points it at
    // the previous release and restarts, so the host returns to known-good rather than
    // sitting broken until a manual rollback.
    let left = match walked.failed {
        None => None,
        Some(Stopped::AtSwap(swap)) => Some(FailureState::AtSwap(swap)),
        Some(Stopped::At(_)) if rollback::extract_swap_succeeded(&outcomes) => {
            let rolling = Instant::now();
            let ran = rollback::attempt_rollback(
                target_conn,
                &deploy.path,
                &report.plan,
                &handler,
                &mut report.warnings,
            )
            .await;
            Some(FailureState::AfterSwap(ran.map_or(
                Rollback::NotStarted,
                |outcome| Rollback::Ran {
                    outcome,
                    took: rolling.elapsed(),
                },
            )))
        }
        Some(Stopped::At(_)) => Some(FailureState::BeforeSwap),
    };
    run.total = started.elapsed();
    report.outcome = match left {
        None => DeployOutcome::Deployed(run),
        Some(left) => DeployOutcome::Failed { run, left },
    };
    report.step_outcomes = outcomes;

    handler.emit(&Event::RunFinished {
        summary: RunSummary::from_step_outcomes(&report.step_outcomes),
    });
    finish(report)
}

/// What a wetrun's review bound to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Binding {
    /// The hash `--expect-plan` named.
    Expected,
    /// The host's recorded deploy preview.
    Recorded,
    /// The operator's confirmation at the prompt, of the plan it was shown.
    Confirmed,
}

/// The review gate: whether a wetrun's `plan_hash` is the reviewed one, and what it
/// bound to. `--expect-plan` binds alone and the record isn't read; otherwise the
/// host's recorded preview must hold the hash, so [`Binding::Recorded`] is only ever
/// the result of having read that record.
///
/// # Errors
/// The [`DeployUnreviewed`] reason the wetrun refuses with.
fn review_gate(
    zap_home: Option<&Path>,
    config_path: &Path,
    host: &str,
    plan_hash: &str,
    expected: Option<&str>,
) -> std::result::Result<Binding, DeployUnreviewed> {
    if expected.is_some() {
        review_deploy_plan(plan_hash, expected, None)?;
        return Ok(Binding::Expected);
    }
    let recorded = zap_home.and_then(|home| read_deploy_preview(home, config_path, host));
    review_deploy_plan(plan_hash, None, recorded.as_ref())?;
    Ok(Binding::Recorded)
}

/// Spend the review a wetrun passed, before its first step: take the host's recorded
/// preview away, whichever way the wetrun bound ([`super::spend_review`]). A wetrun
/// that bound to the record executes only when the record it takes still previews
/// `plan_hash`.
///
/// # Errors
/// [`Error::PreviewWithdraw`] when a record is there and can't be taken, and
/// [`Error::PreviewSpent`] when the wetrun bound to the record and another run took it
/// first — only the run that takes the file executes under it. Either stops the
/// deploy with nothing run.
fn spend_preview(
    zap_home: Option<&Path>,
    config_path: &Path,
    host: &str,
    plan_hash: &str,
    binding: Binding,
) -> Result<()> {
    let Some(home) = zap_home else {
        return Ok(());
    };
    super::spend_review(
        &deploy_preview_path_for(home, config_path, host),
        Previewed::Deploy,
        binding == Binding::Recorded,
        |taken| {
            review_deploy_plan(
                plan_hash,
                None,
                read_deploy_preview_file(taken, host).as_ref(),
            )
            .is_ok()
        },
    )
}

/// Record `pass` as the deploy preview of `plan_hash` on `host`, and return the record
/// for the binary to withdraw if the report that shows it never arrives.
///
/// # Errors
/// Why nothing was recorded — no `~/.zap` root, or the write failed — for the warning
/// that tells the operator the next wetrun won't bind to this render.
fn record_preview(
    zap_home: Option<&Path>,
    config_path: &Path,
    pass: DeployPreviewPass,
    host: &str,
    plan_hash: &str,
) -> std::result::Result<RecordedPreview, String> {
    let zap_home = zap_home.ok_or("zap has no state directory: set ZAP_HOME or HOME")?;
    let preview = new_deploy_preview(pass, host, plan_hash);
    write_deploy_preview(zap_home, config_path, &preview).map_err(|error| error.to_string())?;
    Ok(RecordedPreview::deploy(
        deploy_preview_path_for(zap_home, config_path, host),
        pass,
        preview.host,
        preview.plan_hash,
        preview.ran_at,
    ))
}

/// Why this config's deploy plan names no one machine, if it doesn't: its target host,
/// health domain, or connecting user (`user`, as declared) resolves through a reference
/// `var` masks. For the host and the domain the plan holds a token where the name would
/// be and hashes the same for every machine the reference could name; the connecting
/// user is in the plan by value, so a masked one would make the hash a function of a
/// secret. Each kind closes with its own reason, the two joined when both occur. Either
/// way no wetrun of the plan runs and no hash of it is shown. `None` when all three
/// resolve by value.
///
/// Each masked reference carries the way out for its own cause: a secret one is
/// unmasked or replaced by a literal; one whose value carries a secret can only stop
/// carrying it.
fn unbindable_message(
    config: &ZapConfig,
    user: Option<&Text>,
    var: &impl Fn(&str) -> ReportVar,
) -> Option<String> {
    let health = config.deploy.as_ref().and_then(|d| d.health.as_ref());
    let named = masked_label_refs(
        &[
            ("target host", config.target.host()),
            ("health domain", health.map(|h| &h.domain)),
        ],
        var,
    )
    .map(|refs| format!("{refs}{NAMES_NO_ONE_MACHINE}"));
    let carried = masked_label_refs(&[("connecting user", user)], var)
        .map(|refs| format!("{refs}{CARRIES_THE_USER}"));
    let reasons: Vec<String> = named.into_iter().chain(carried).collect();
    (!reasons.is_empty()).then(|| reasons.join("; "))
}

/// Why a dirty tree without `--force` doesn't deploy: the wetrun's refusal, and what a
/// dry run of it says ([`DeployOutcome::DryRunDirty`]).
pub const DIRTY_NEEDS_FORCE: &str = "the working tree has uncommitted changes or untracked \
    files, and without --force the release would ship them under the commit's version — \
    commit them, or pass --force to deploy the tree as <hash>-dirty-<id>, named by its \
    changes";

/// What follows from a masked connecting user: the closing clause of its unbindable
/// reason. Unlike the host and the health domain, whose masked labels put a token in
/// the plan, the user is in the plan as the connection resolved it.
const CARRIES_THE_USER: &str = "; the plan carries the connecting user by value, so its hash \
    would be a function of that secret";

/// `user@host` of the operator machine: `whoami` and `hostname`, each taken only from a
/// run that succeeded with an answer. Neither side is ever empty. A user `whoami`
/// didn't name is this process's effective user, by its name in the user database, or
/// as `uid <n>` (never `$USER`, which the caller sets); a host `hostname` didn't name
/// (a system without the program) is `uname -n`'s, or `unknown`. It is a hashed plan
/// field, so a run whose `whoami` fails where its preview's didn't plans another hash.
async fn deployed_by(local: &Connection) -> String {
    let user = answer_of(local, "whoami").await.unwrap_or_else(|| {
        let uid = nix::unistd::geteuid();
        match nix::unistd::User::from_uid(uid) {
            Ok(Some(user)) if !user.name.is_empty() => user.name,
            _ => format!("uid {uid}"),
        }
    });
    let host = match answer_of(local, "hostname").await {
        Some(host) => host,
        None => answer_of(local, "uname -n")
            .await
            .unwrap_or_else(|| "unknown".to_owned()),
    };
    format!("{user}@{host}")
}

/// What `command` printed on the operator machine, trimmed, when it ran, succeeded, and
/// printed something.
async fn answer_of(local: &Connection, command: &str) -> Option<String> {
    let output = local.run(command, &RunOptions::default()).await.ok()?;
    let answer = output.stdout.trim();
    (output.success && !answer.is_empty()).then(|| answer.to_owned())
}

/// The drift preflight's detection and diff — recorded as the
/// [`DeployPreflight`](RunCommand::DeployPreflight) last run.
///
/// # Errors
/// Propagates detection failures (connectivity, the pending-marker read) and
/// `resolve_machine`'s.
async fn drift_preflight(
    conn: &Connection,
    config: &ZapConfig,
    ctx: PassContext<'_>,
    lock: Option<&ZapLock>,
) -> Result<Diffed> {
    let machine = super::resolve_machine(config, ctx.masker, ctx.bootstrap)?;
    detect_and_diff(
        conn,
        config,
        ctx,
        &machine,
        lock,
        RunCommand::DeployPreflight,
    )
    .await
}

/// The warning of a drift preflight that counted `drifted` resources as drifted: how
/// many, and the flow that clears them.
fn drift_warning(drifted: usize) -> String {
    format!(
        "{} — review the changes with `zap apply`, converge with `zap apply --wetrun`, then \
         re-run this deploy: its review still binds unless `zap.lock` changed",
        count(
            drifted,
            "apply-managed resource has drifted",
            "apply-managed resources have drifted"
        )
    )
}

/// How many apply-managed resources the drift preflight counts as drifted in `result`:
/// each change, and each resource held behind another (only a change is ever held
/// behind one), but none that changes only because something that always runs does.
///
/// A `pipeline` is no drift: it detects absent by construction and always runs, so
/// counting it would fail every preflight (the same exemption as `residual`). Nor is a
/// service the planner promotes only because such a source fires: one whose detection
/// in `detected` is converged, with no pending marker, every source that fired it
/// already exempt. So a service that restarts on a pipeline is no drift, and nor is one
/// that restarts on that service, while a pending marker, a service that also drifted,
/// and a trigger with any drifted source still are.
///
/// The rule is the same for a change and for a resource held behind another, whose
/// would-be trigger the planner keeps on the [`HeldResource`], and both feed one fixed
/// point: a service held only behind an unread resource, fired only by a pipeline, is
/// undetermined, not drift.
fn preflight_drift_count(
    config: &ZapConfig,
    result: &PlanResult,
    detected: &BTreeMap<ResourceId, Detection>,
) -> usize {
    let mut exempt: BTreeSet<&ResourceId> = config
        .resources
        .iter()
        .filter(|resource| matches!(resource.kind, ResourceKind::Pipeline(_)))
        .map(|resource| &resource.id)
        .collect();
    // Every planned change and every hold behind another, with the trigger it carries.
    let behind = result.held.iter().filter(|held| !held.is_undetermined());
    let counted: Vec<(&ResourceId, Option<&Trigger>)> = result
        .plan
        .changes
        .iter()
        .map(|change| (&change.resource_id, change.trigger.as_ref()))
        .chain(behind.map(|held| (&held.resource_id, held.trigger.as_ref())))
        .collect();
    // To a fixed point: a promotion spreads through the services triggered by one.
    loop {
        let only_triggered: Vec<&ResourceId> = counted
            .iter()
            .filter(|(id, _)| !exempt.contains(id))
            .filter(|(id, trigger)| {
                detected.get(*id) == Some(&Detection::Converged)
                    && trigger.is_some_and(|trigger| {
                        !trigger.pending
                            && !trigger.sources.is_empty()
                            && trigger.sources.iter().all(|source| exempt.contains(source))
                    })
            })
            .map(|(id, _)| *id)
            .collect();
        if only_triggered.is_empty() {
            break;
        }
        exempt.extend(only_triggered);
    }
    counted
        .iter()
        .filter(|(id, _)| !exempt.contains(id))
        .count()
}

#[cfg(test)]
mod tests;
