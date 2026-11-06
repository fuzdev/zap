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
//! against stale apply-managed config. Deploy requires a **remote** target.
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
//! from the drift preflight on, and anything else is the refusal. The hash is printed
//! only with the plan it stands for, and a preview is
//! recorded only by a pass that printed one ([`DeployOutcome::preview_pass`]). A deploy
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
//! Execution against a real target is validated by hand (`docs/testing.md`); the suite
//! covers the pure plan (`zap_types::deploy`), the masker, and the orchestration over a
//! `MockConnection`.

mod health;
mod rollback;

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::path::Path;
use std::sync::Arc;

use zap_types::config_hash::deploy_plan_hash;
use zap_types::deploy::{
    ARCHIVE_ENV, DeployAction, DeployContext, DeployPlan, DeployStep, DriftPreflight,
    SCRIPT_ERROR_PREFIX, SCRIPT_WARNING_PREFIX, SWAPPED_LINE, deploy_references, plan_deploy,
};
use zap_types::event::{Event, RunSummary, StepOutcome};

use zap_types::deploy_preview::{DeployPreviewPass, DeployUnreviewed, review_deploy_plan};
use zap_types::detected::Detection;
use zap_types::last_run::{PlanUnreviewed, ReportVar, RunCommand, host_label, resolved_label};
use zap_types::lock::ZapLock;
use zap_types::plan::{HeldResource, PlanResult, Trigger};
use zap_types::schema::{ResourceId, ResourceKind, ZapConfig};
use zap_types::shell::single_quote;
use zap_types::text::Text;

use super::prompt::{self, Confirmation, DEPLOY_QUESTION, Prompt};
use super::{
    Diffed, NAMES_NO_ONE_MACHINE, PassContext, RefusalText, connecting_user, detect_and_diff,
    eval_target, masked_label_refs, target_location,
};
use crate::connection::{CommandOutput, Connection, RunOptions};
use crate::deploy_preview::{
    new_deploy_preview, read_deploy_preview, read_deploy_preview_file, write_deploy_preview,
};
use crate::error::{Error, Previewed, Result};
use crate::escape::{escape_line, render_block};
use crate::event::{EventHandler, mask_handler};
use crate::home::deploy_preview_path_for;
use crate::home::zap_home_default;
use crate::last_run::report_var;
use crate::lock::{LockStanding, inspect_lock};
use crate::resolve::env_var;
use crate::secret::SecretMasker;

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
    /// The release was deployed.
    Deployed,
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
    /// The release version (short git hash, possibly `-dirty-<id>`), as computed. The render
    /// reads the plan's.
    pub version: String,
    /// The version previously on the server, if any.
    pub previous_version: Option<String>,
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
}

impl DeployOutcome {
    /// Whether the render prints the `plan_hash`. Only under a plan it showed — its
    /// steps previewed in full, or as their outcomes — since a hash is a handle on a plan that was shown,
    /// and `--expect-plan` must not be able to name one that wasn't — and only for a
    /// plan that names one machine.
    #[must_use]
    pub const fn shows_hash(&self) -> bool {
        match self {
            Self::DryRun | Self::Refused(_) | Self::Deployed | Self::Failed => true,
            Self::DryRunUnbindable(_)
            | Self::DryRunDirty
            | Self::AlreadyDeployed
            | Self::PreflightDrift
            | Self::PreflightUndetermined => false,
        }
    }

    /// The preview this outcome stands as: the pass that rendered a plan for review and
    /// executed none of it. `Some` exactly for the outcomes whose plan and hash were
    /// printed with nothing run, which are the ones recorded as the host's deploy
    /// preview — so a recorded hash is always one that was shown.
    #[must_use]
    pub const fn preview_pass(&self) -> Option<DeployPreviewPass> {
        match self {
            Self::DryRun => Some(DeployPreviewPass::DryRun),
            Self::Refused(_) => Some(DeployPreviewPass::RefusedWetrun),
            Self::DryRunUnbindable(_)
            | Self::DryRunDirty
            | Self::Deployed
            | Self::Failed
            | Self::AlreadyDeployed
            | Self::PreflightDrift
            | Self::PreflightUndetermined => None,
        }
    }
}

impl DeployReport {
    /// Whether the run reached its steps, and so emitted events: a `--json` wetrun that
    /// didn't has streamed nothing, and its caller needs the text render to learn why.
    #[must_use]
    pub const fn streamed(&self) -> bool {
        self.wetrun
            && matches!(
                self.outcome,
                DeployOutcome::Deployed | DeployOutcome::Failed
            )
    }

    /// Process exit code: `Failed` is `1`, a refusal and either preflight bail are `2`,
    /// everything else (dry-run, deployed, already-deployed) is `0`.
    #[must_use]
    pub const fn exit_code(&self) -> u8 {
        match self.outcome {
            DeployOutcome::Failed => 1,
            DeployOutcome::Refused(_)
            | DeployOutcome::PreflightDrift
            | DeployOutcome::PreflightUndetermined => 2,
            DeployOutcome::DryRun
            | DeployOutcome::DryRunUnbindable(_)
            | DeployOutcome::DryRunDirty
            | DeployOutcome::Deployed
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
    let version = git_version(local, dirty && options.force, masker).await?;
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
    // remote command's stderr, a held reason a seam-resolved path), the version read
    // off the target, and its plan, whose script carries the resolved connecting user
    // and operator identity. The step outcomes and the event stream are masked where
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
        report.previous_version = report
            .previous_version
            .map(|previous| masker.mask(&previous));
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
                Ok(()) => report.recorded = Some(pass),
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
            target_user: target_conn.user().to_owned(),
            deployed_by: deployed_by(local).await,
            previous_version: previous_version.clone(),
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
        version,
        previous_version,
        plan,
        plan_hash,
        step_outcomes: Vec::new(),
        warnings,
        held: Vec::new(),
        lock_standing: LockStanding::default(),
        recorded: None,
        confirmation: None,
    };

    // Already-deployed short-circuit — for a `current` that names a release on the host.
    // One that names a missing release (a `--force` of the live version killed between
    // its renames, or a release removed by hand) serves nothing, so the run goes on as
    // a redeploy, whose script recovers what was moved aside.
    // A dirty tree's dry run is not short-circuited: the tree is not what the live
    // release holds, and the preview says what a wetrun needs.
    if report.previous_version.as_deref() == Some(report.version.as_str())
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
            report.version
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

    // Drift preflight (wetrun only): don't ship an artifact against stale apply config.
    // `checked` is the lock read for a plan whose preflight checks, so the gate runs
    // exactly when the plan says it does. A bail leaves the recorded preview in place:
    // nothing ran, and the same plan can deploy once the drift is cleared.
    if options.wetrun
        && let Some((lock, _)) = checked
    {
        let Diffed {
            result: drift,
            detected,
            ..
        } = drift_preflight(target_conn, config, ctx, lock.as_ref()).await?;
        let drifted = preflight_drift_count(config, &drift, &detected);
        report.warnings.extend(drift.warnings);
        // A held resource is one the preflight *could not check*. It contributes no
        // change, so a gate that counted only changes would pass on it: an unprobeable
        // nginx config or firewall would read as "no drift" and the release would ship.
        // The gate has to fail closed on a check it didn't run, the same way it fails on
        // one it ran and didn't like.
        report.held = drift.held;
        if drifted > 0 {
            report.warnings.push(format!(
                "{drifted} apply-managed resource(s) have drifted — review the changes with \
                 `zap apply`, converge with `zap apply --wetrun`, then re-run this deploy: \
                 its review still binds unless `zap.lock` changed"
            ));
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

    // Wetrun: stream events (masked at the boundary), walk the plan, stop on first fail.
    let inner = if options.emit_json {
        EventHandler::Stdout
    } else {
        EventHandler::Null
    };
    #[cfg(test)]
    let inner = options
        .capture
        .as_ref()
        .map_or(inner, |events| EventHandler::Capture(Arc::clone(events)));
    let handler = mask_handler(masker.clone(), inner);
    handler.emit(&Event::RunStarted {
        target: report.target.clone(),
        wetrun: true,
        plan_hash: report.plan_hash.clone(),
        total: u32::try_from(report.plan.steps.len()).unwrap_or(u32::MAX),
    });
    let outcomes = execute_deploy_plan(
        local,
        target_conn,
        AppLive {
            app: &deploy.path,
            previous: report.previous_version.as_deref(),
        },
        &report.plan,
        ReleaseArchive::under(scratch),
        &handler,
        &mut report.warnings,
    )
    .await;
    let outcomes: Vec<StepOutcome> = outcomes
        .into_iter()
        .map(|outcome| outcome.map_text(|text| masker.mask(text)))
        .collect();
    report.outcome = if outcomes.iter().any(StepOutcome::is_failure) {
        DeployOutcome::Failed
    } else {
        DeployOutcome::Deployed
    };
    report.step_outcomes = outcomes;

    // Auto-rollback: a failure *after* the atomic swap (restart / health) leaves
    // `current` pointing at the just-shipped, broken release. Re-point it at the
    // previous release and restart so the host returns to known-good rather than
    // sitting broken until a manual rollback. A pre-swap failure (build / tarball /
    // upload / extract_swap) never moved `current`, so there's nothing to undo.
    if report.outcome == DeployOutcome::Failed
        && rollback::extract_swap_succeeded(&report.step_outcomes)
    {
        rollback::attempt_rollback(
            target_conn,
            &deploy.path,
            &report.plan,
            report.previous_version.as_deref(),
            &report.version,
            &handler,
            &mut report.warnings,
        )
        .await;
    }

    handler.emit(&Event::RunFinished {
        summary: RunSummary::from_step_outcomes(&report.step_outcomes),
    });
    finish(report)
}

/// Walk the deploy plan, executing each step's IO. Stops at the first failure
/// (later steps become `Skipped`), emitting a started + outcome event per attempted
/// step through `handler` (where masking happens). `archive` is dropped when the walk
/// ends, however it ends: the operator's copy of the release goes with it.
async fn execute_deploy_plan(
    local: &Connection,
    target: &Connection,
    live: AppLive<'_>,
    plan: &DeployPlan,
    mut archive: ReleaseArchive,
    handler: &EventHandler,
    warnings: &mut Vec<String>,
) -> Vec<StepOutcome> {
    let mut outcomes = Vec::with_capacity(plan.steps.len());
    let mut aborted_by: Option<String> = None;

    for step in &plan.steps {
        let outcome = if let Some(failed) = &aborted_by {
            StepOutcome::Skipped {
                step: step.id.to_string(),
                reason: format!("aborted after `{failed}` failed"),
            }
        } else {
            handler.emit(&Event::StepStarted {
                step: step.id.to_string(),
                name: step.name.clone(),
            });
            let release = Release {
                app: live.app,
                version: &plan.version,
                previous: live.previous,
            };
            match run_step(local, target, release, step, &mut archive, warnings).await {
                Ok(StepRun::Ran(output)) => StepOutcome::Completed {
                    step: step.id.to_string(),
                    output,
                },
                Ok(StepRun::NotRun(reason)) => StepOutcome::Skipped {
                    step: step.id.to_string(),
                    reason,
                },
                Err(error) => {
                    aborted_by = Some(step.id.to_string());
                    StepOutcome::Failed {
                        step: step.id.to_string(),
                        error,
                    }
                }
            }
        };
        handler.emit(&Event::from_step_outcome(&outcome));
        outcomes.push(outcome);
    }
    outcomes
}

/// Whether a step actually ran — the distinction [`StepOutcome`] draws between
/// `Completed` and `Skipped`, which a bare `Ok(String)` collapsed.
///
/// One step can decline to run without failing: a `Readiness` gate the target doesn't
/// serve. Reporting it as `Completed` would tell a machine consumer of the event stream
/// that the step *passed* — the schema-drift check reporting success without having run.
/// The reason rides the variant, so "not run" can't be written without saying why.
enum StepRun {
    /// The step ran, with this summary.
    Ran(String),
    /// The step deliberately did not run, for this reason.
    NotRun(String),
}

/// The release archive of one run: the operator's copy, and what the target was sent.
///
/// The operator's copy is a file in a directory made for this run — mode `700`, under a
/// name nobody could have prepared — so no other account on the operator machine can
/// read the release, replace it between its creation and its upload, or aim `tar` at a
/// file of the operator's through a link. Dropping this removes the directory.
struct ReleaseArchive {
    /// The directory the private one is made in.
    scratch: std::path::PathBuf,
    /// The private directory holding the archive, once the `Tarball` step made it.
    dir: Option<tempfile::TempDir>,
    /// Where the archive went on the target and the SHA-512 of the bytes sent, once the
    /// `Upload` step installed it.
    uploaded: Option<(String, String)>,
}

impl ReleaseArchive {
    /// The archive's file name inside its directory.
    const NAME: &str = "release.tar.gz";

    /// A release whose private directory will be made in `scratch`.
    fn under(scratch: &Path) -> Self {
        Self {
            scratch: scratch.to_path_buf(),
            dir: None,
            uploaded: None,
        }
    }

    /// Make the private directory and, in it, the empty archive file at mode `600` for
    /// `tar` to write, returning the file's path.
    fn create(&mut self) -> std::io::Result<std::path::PathBuf> {
        use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};

        // The mode is the directory's from its creation: a default one would be the
        // umask's, open to the operator's group or to everyone.
        let dir = tempfile::Builder::new()
            .prefix("zap-release-")
            .permissions(std::fs::Permissions::from_mode(0o700))
            .tempdir_in(&self.scratch)?;
        let path = dir.path().join(Self::NAME);
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)?;
        self.dir = Some(dir);
        Ok(path)
    }

    /// The archive's bytes, as `tar` left them.
    async fn read(&self) -> std::result::Result<Vec<u8>, String> {
        let dir = self
            .dir
            .as_ref()
            .ok_or_else(|| "no release archive was created to upload".to_owned())?;
        tokio::fs::read(dir.path().join(Self::NAME))
            .await
            .map_err(|error| format!("the release archive could not be read: {error}"))
    }
}

/// The app a deploy ships to: its path on the target and the release the plan read as
/// live there.
#[derive(Clone, Copy)]
struct AppLive<'a> {
    /// The app path (`deploy.path`).
    app: &'a str,
    /// The release live when the plan was made (`None` on a first deploy).
    previous: Option<&'a str>,
}

/// The release a deploy's steps ship: the app path on the target, the version, and the
/// release the plan read as live.
#[derive(Clone, Copy)]
struct Release<'a> {
    /// The app path (`deploy.path`).
    app: &'a str,
    /// The version the plan ships.
    version: &'a str,
    /// The release live when the plan was made (`None` on a first deploy).
    previous: Option<&'a str>,
}

/// Execute one deploy step. `Ok` carries whether it ran ([`StepRun`]); `Err(message)`
/// fails the step (and aborts the deploy).
///
/// `archive` carries the release from the step that creates it to the one that uploads
/// it, and its digest from there to the script that extracts it.
async fn run_step(
    local: &Connection,
    target: &Connection,
    release: Release<'_>,
    step: &DeployStep,
    archive: &mut ReleaseArchive,
    warnings: &mut Vec<String>,
) -> std::result::Result<StepRun, String> {
    match &step.action {
        DeployAction::Build { command } => run_captured(local, command).await.map(StepRun::Ran),
        DeployAction::Tarball { command } => {
            let path = archive.create().map_err(|error| {
                format!("no private directory for the release archive: {error}")
            })?;
            // The path reaches `tar` through its environment: it is no part of the
            // plan's command, and on no argv but `tar`'s own.
            let options = RunOptions {
                env: vec![(ARCHIVE_ENV.to_owned(), path.to_string_lossy().into_owned())],
                ..RunOptions::default()
            };
            captured(local.run(command, &options).await)?;
            Ok(StepRun::Ran("created the release archive".to_owned()))
        }
        DeployAction::Upload { remote } => {
            let bytes = archive.read().await?;
            let digest = crate::digest::sha512_hex(&bytes);
            target
                .push_bytes(remote, &bytes, zap_types::deploy::UPLOAD_ATTRS)
                .await
                .map_err(|error| upload_failure(remote, &error.to_string()))?;
            archive.uploaded = Some((remote.clone(), digest));
            // The target holds it; the operator's copy has no further use.
            archive.dir = None;
            Ok(StepRun::Ran(format!("uploaded {remote}")))
        }
        DeployAction::ExtractSwap { script } => {
            let (remote, digest) = archive
                .uploaded
                .as_ref()
                .ok_or_else(|| "no release archive was uploaded to extract".to_owned())?;
            // The digest is the script's stdin, never its text: the plan was hashed
            // before the archive existed.
            let ran = target
                .run_with_stdin(script, format!("{digest}\n").as_bytes())
                .await;
            // What the script recovered from a deploy that did not finish, and what its
            // housekeeping after the swap could not do, is the operator's to see,
            // whether or not this one goes on to fail.
            if let Ok(output) = &ran {
                warnings.extend(script_warnings(&output.stdout));
            }
            let ran = swap_ran(target, release, ran).await;
            if let Ok((_, Some(failure))) = &ran {
                warnings.push(failure.clone());
            }
            if ran.is_err() {
                // The script removes the archive on every exit of its own; this covers
                // a script that never started. Best-effort.
                let _ = target
                    .run_default(&format!("rm -f -- {}", single_quote(remote)))
                    .await;
            }
            ran.map(|(output, _)| StepRun::Ran(output))
        }
        DeployAction::Restart { command } => run_captured(target, command).await.map(StepRun::Ran),
        // The health/readiness URLs carry the declared `deploy.health.domain`, which may
        // be a reference; the pollers resolve it themselves (the plan stays
        // inert, so the dry-run render shows what was declared). An unset reference
        // resolves to an empty host, which fails the step rather than skipping it; the
        // wetrun env preflight rejects that case first.
        DeployAction::Health {
            url,
            attempts,
            interval_ms,
            ..
        } => health::http_health_check(url, *attempts, *interval_ms)
            .await
            .map(StepRun::Ran),
        DeployAction::Readiness {
            url,
            attempts,
            interval_ms,
            ..
        } => {
            // The poller resolves; these messages report the URL as declared, which is
            // what the operator wrote and what the plan renders.
            match health::http_readiness_check(url, *attempts, *interval_ms).await {
                health::ReadinessOutcome::Ready => {
                    Ok(StepRun::Ran(format!("ready: live schema matches at {url}")))
                }
                health::ReadinessOutcome::Absent => {
                    // Loud-warn rather than fail: an absent `/ready` is a
                    // misconfiguration (backend doesn't serve it, or nginx doesn't
                    // proxy it), not schema drift — rolling back an otherwise-healthy
                    // release would be wrong. The warning nudges the operator to wire
                    // the gate; the deploy proceeds on the liveness check alone.
                    warnings.push(format!(
                    "readiness gate SKIPPED — GET {url} returned 404. The `/ready` schema-drift gate \
                     isn't being served: confirm the backend mounts it and nginx proxies `/ready`. \
                     This release shipped with no schema-drift protection."
                ));
                    Ok(StepRun::NotRun(format!("{url} absent (404)")))
                }
                health::ReadinessOutcome::NotReady(msg) => Err(msg),
            }
        }
    }
}

/// The extract-and-swap script's run, read by its [`SWAPPED_LINE`] rather than by its
/// exit status alone: `Ok` once `current` names the new release — its stdout without
/// that line and its marked lines, and, when the run was not clean, the warning that
/// says so — and `Err` for a run that swapped nothing, whatever its status.
///
/// A swapped release is live, so the deploy goes on to restart and check it (and
/// rolls back when that fails); one the script never swapped is never restarted.
///
/// The line is not trusted from a script that failed: a `prepare` command can reach the
/// script's own stdout (through `/proc`, or a descriptor it was handed) and print it,
/// then fail the script before its swap. So a failed run that printed it is read as
/// swapped only once `current` is read again and names `release`. A `current` that
/// names anything else, or is no symbolic link, is a run that swapped nothing. A read
/// that fails leaves the line believed, as does a `current` that already named the
/// version before the run (a `--force` redeploy of the live version, where the read
/// can't tell a swap from none), each with a warning that the swap could not be
/// confirmed. A run that exited 0 with the line ran its swap: nothing the script runs
/// comes after it.
///
/// A run that exited 0 without the line ran its swap (nothing exits 0 before it) and the
/// line was garbled (a `prepare` command's partial write ahead of it); it is taken as
/// swapped once `current`, read again, names the version. A failed run without the line
/// swapped nothing: another deploy of the same version may have swapped since it let go
/// of the lock, and that release is not this run's to restart or roll back.
async fn swap_ran(
    target: &Connection,
    release: Release<'_>,
    ran: Result<CommandOutput>,
) -> std::result::Result<(String, Option<String>), String> {
    let output = ran.map_err(|error| error.to_string())?;
    let swapped = output.stdout.lines().any(|line| line == SWAPPED_LINE);
    let shown = output
        .stdout
        .lines()
        .filter(|line| !is_marked(line))
        .collect::<Vec<_>>()
        .join("\n");
    let shown = shown.trim().to_owned();
    let fresh = release.previous != Some(release.version);
    if !swapped {
        if output.success
            && let Ok(Some(live)) = server_version(target, release.app).await
            && live == release.version
        {
            return Ok((
                shown,
                Some(format!(
                    "the extract-and-swap script's swap line was missing or garbled, but \
                     `current` names releases/{live} — the new release is live, and is \
                     restarted and checked as usual"
                )),
            ));
        }
        return Err(if output.success {
            "the extract-and-swap script ended without swapping `current`, so nothing was \
             released"
                .to_owned()
        } else {
            script_failure(&output)
        });
    }
    if output.success {
        return Ok((shown, None));
    }
    let why = script_failure(&output);
    let unconfirmed = match server_version(target, release.app).await {
        Ok(Some(live)) if live == release.version => {
            (!fresh).then(|| format!("`current` already named releases/{live} before the run"))
        }
        Ok(live) => {
            return Err(format!(
                "the script printed the swap line but `current` names {} — it swapped \
                 nothing, so nothing was released: {why}",
                live.map_or_else(|| "nothing".to_owned(), |live| format!("releases/{live}"))
            ));
        }
        Err(LiveReadError::NotALink(_)) => {
            return Err(format!(
                "the script printed the swap line but `current` is not a symlink — it \
                 swapped nothing, so nothing was released: {why}"
            ));
        }
        Err(LiveReadError::NoRelease(message)) => {
            return Err(format!(
                "the script printed the swap line but {message} — it swapped nothing, so \
                 nothing was released: {why}"
            ));
        }
        Err(LiveReadError::Unreadable(error)) => Some(error),
    };
    let failure = unconfirmed.map_or_else(
        || {
            format!(
                "the extract-and-swap script failed after it swapped `current` ({why}) — \
                 the new release is live, and is restarted and checked as usual"
            )
        },
        |error| {
            format!(
                "the extract-and-swap script failed after it printed the swap line ({why}), \
                 and the swap could not be confirmed ({error}) — the new release is taken \
                 as live, and is restarted and checked as usual"
            )
        },
    );
    Ok((shown, Some(failure)))
}

/// Whether `line` of the extract-and-swap script's stdout is one of its marks: the
/// swap line, a warning, or its error.
fn is_marked(line: &str) -> bool {
    line == SWAPPED_LINE
        || line.starts_with(SCRIPT_WARNING_PREFIX)
        || line.starts_with(SCRIPT_ERROR_PREFIX)
}

/// How many lines of a failed script's standard error its message carries when the
/// script marked no error of its own.
const FAILURE_TAIL_LINES: usize = 10;

/// What a failed extract-and-swap script said: the error it marked on its stdout
/// ([`SCRIPT_ERROR_PREFIX`], its own refusal) when there is one, else the last lines
/// of its standard error — where a command the script runs, such as `mv`, says why it
/// failed — or of its stdout less its marked lines when stderr is empty. A `prepare`
/// command's output goes to stderr, so a line it prints can stand as neither: all of
/// stderr would bury the reason, and an `ERROR:` line a prepare tool printed is no
/// reason of the script's.
fn script_failure(output: &CommandOutput) -> String {
    if let Some(reason) = output
        .stdout
        .lines()
        .rev()
        .find_map(|line| line.strip_prefix(SCRIPT_ERROR_PREFIX))
    {
        return format!("ERROR: {}", reason.trim());
    }
    let lines: Vec<&str> = output
        .stderr
        .lines()
        .filter(|line| !line.trim().is_empty())
        .collect();
    if lines.is_empty() {
        let stdout: Vec<&str> = output
            .stdout
            .lines()
            .filter(|line| !is_marked(line))
            .collect();
        return non_empty("", &stdout.join("\n"));
    }
    let start = lines.len().saturating_sub(FAILURE_TAIL_LINES);
    let tail = lines[start..].join("\n");
    if start == 0 {
        tail
    } else {
        format!("…\n{tail}")
    }
}

/// The lines of the extract-and-swap script's stdout that it marked as warnings
/// ([`SCRIPT_WARNING_PREFIX`]), without the mark. Every `prepare` command's output goes
/// to the script's stderr, so what a command prints adds no warning, unless it reaches
/// the script's own stdout anyway (see [`swap_ran`]), when a line it prints with the
/// mark is lifted as a warning like the script's own: narrative, deciding nothing.
fn script_warnings(stdout: &str) -> impl Iterator<Item = String> + '_ {
    stdout
        .lines()
        .filter_map(|line| line.strip_prefix(SCRIPT_WARNING_PREFIX))
        .map(str::to_owned)
}

/// A failed upload's message: what the install said, then what it needs. The archive
/// goes into the app path, so that directory missing or not the connecting user's to
/// write is the usual cause on a first deploy — and the install's own words for it are
/// a `cd` or a create that failed.
fn upload_failure(remote: &str, error: &str) -> String {
    let app = remote.rsplit_once('/').map_or(remote, |(dir, _)| dir);
    format!(
        "{error} — the release archive is installed into the app path ({app}), which must \
         exist and be writable by the connecting user; if `zap apply` creates it, run that \
         first"
    )
}

/// Run a step's command on `conn` (local for build/tarball, the target for
/// extract-swap/restart), returning its trimmed stdout or an error carrying stderr.
pub(super) async fn run_captured(
    conn: &Connection,
    command: &str,
) -> std::result::Result<String, String> {
    captured(conn.run(command, &RunOptions::default()).await)
}

/// A step command's result as its trimmed stdout, or an error carrying its stderr.
fn captured(ran: Result<CommandOutput>) -> std::result::Result<String, String> {
    let output = ran.map_err(|error| error.to_string())?;
    if output.success {
        Ok(output.stdout.trim().to_owned())
    } else {
        Err(non_empty(&output.stderr, &output.stdout))
    }
}

/// Whether the working tree has uncommitted changes or untracked files git doesn't
/// ignore, read through [`DIRTY_TREE_STATUS`].
///
/// # Errors
/// [`Error::Git`] when the tree can't be read: "clean" is a fact of the plan, never a
/// default for a read that failed.
async fn git_uncommitted(local: &Connection, masker: &SecretMasker) -> Result<bool> {
    let out = local.run(DIRTY_TREE_STATUS, &RunOptions::default()).await?;
    if !out.success {
        return Err(git_error(
            "the working tree",
            DIRTY_TREE_STATUS,
            &out,
            masker,
        ));
    }
    Ok(!out.stdout.trim().is_empty())
}

/// A failed git read as an [`Error::Git`]: what couldn't be read, the command, and the
/// first line git said — masked, then escaped — so a checkout git refuses to trust and
/// a directory that is no checkout read differently. With nothing said, the usual cause.
fn git_error(what: &str, command: &str, out: &CommandOutput, masker: &SecretMasker) -> Error {
    let said = out
        .stderr
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty());
    Error::Git(said.map_or_else(
        || format!("could not read {what} (`{command}`) — run from the app's checkout"),
        |line| {
            format!(
                "could not read {what} (`{command}`): {}",
                escape_line(&masker.mask(line))
            )
        },
    ))
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

/// Record `pass` as the deploy preview of `plan_hash` on `host`.
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
) -> std::result::Result<(), String> {
    let zap_home = zap_home.ok_or("zap has no state directory: set ZAP_HOME or HOME")?;
    write_deploy_preview(
        zap_home,
        config_path,
        &new_deploy_preview(pass, host, plan_hash),
    )
    .map_err(|error| error.to_string())
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

/// The short git commit hash, with `-dirty-` and the tree's [`dirty_id`] when `dirty`
/// is set.
async fn git_version(local: &Connection, dirty: bool, masker: &SecretMasker) -> Result<String> {
    const COMMAND: &str = "git rev-parse --short=12 HEAD";
    let out = local.run(COMMAND, &RunOptions::default()).await?;
    if !out.success {
        return Err(git_error("the commit hash", COMMAND, &out, masker));
    }
    let hash = out.stdout.trim();
    Ok(if dirty {
        format!("{hash}-dirty-{}", dirty_id(local, masker).await?)
    } else {
        hash.to_owned()
    })
}

/// The `git` every read of the working tree runs, with the checkout settings that would
/// narrow what it compares forced: `core.fsmonitor=false`, `core.untrackedCache=false`,
/// `core.ignoreStat=false`, `core.fileMode=true` (a mode change counts),
/// `core.autocrlf=false` (no line-ending conversion), and `core.splitIndex=false` (the
/// copy of the index writes no shared index into the checkout's `.git`). A checkout on
/// a filesystem without executable bits, or one checked out with `core.autocrlf=true`,
/// therefore reads dirty.
macro_rules! dirty_git {
    () => {
        "git -c core.fsmonitor=false -c core.untrackedCache=false -c core.ignoreStat=false \
         -c core.fileMode=true -c core.autocrlf=false -c core.splitIndex=false"
    };
}

/// The prefix every read of the working tree runs under: an index of the checkout's
/// own entries — each path, mode, blob id, and stage, read with `git ls-files -s` — and
/// nothing else, in a directory of its own that is removed when the read ends, or is
/// stopped by a signal.
///
/// The checkout's index also caches what each file's `stat` looked like when git last
/// read it and which directories held no new files, and git believes a file unchanged
/// when its `stat` still matches. A `core.fsmonitor` that reports nothing changed lets
/// those caches go stale: a later `git status` writes them back trusted, after which a
/// file rewritten to its old size within the second it was read, or a file added to a
/// directory in that second, reads unchanged to git with the monitor off as well; a
/// file whose size and mtime were set back reads unchanged under `core.trustctime=false`
/// with no monitor at all. The copy holds no `stat` data and none of the index's flags
/// (`assume-unchanged`, `skip-worktree`, the monitor's and the untracked cache's), so
/// git compares every file's contents. `core.ignoreStat`, which would mark every entry
/// of the copy unchanged, is off while it is built and read ([`dirty_git!`]).
macro_rules! entries_index {
    () => {
        concat!(
            "zap_x=$(mktemp -d) && trap 'rm -rf -- \"$zap_x\"' EXIT && trap 'exit 1' HUP INT TERM && ",
            dirty_git!(),
            " ls-files -s -z --full-name -- ':/' > \"$zap_x/entries\" && ",
            "GIT_INDEX_FILE=$zap_x/index && export GIT_INDEX_FILE && ",
            dirty_git!(),
            " update-index -z --index-info < \"$zap_x/entries\" && ",
        )
    };
}

/// The dirty check: any change to a tracked or staged file and any untracked file git
/// doesn't ignore, read against [`entries_index!`]'s copy of the index with the
/// settings [`dirty_git!`] forces, and a submodule whose checkout moved or holds
/// changes its own index shows (`--ignore-submodules=none`, past
/// `submodule.<name>.ignore` and `diff.ignoreSubmodules`; `--untracked-files=normal`,
/// past `status.showUntrackedFiles`). What the checkout's attributes say still decides
/// what a change is: a clean filter (`filter=…`, `.git/info/attributes` included) or an
/// `eol` or `text` attribute can make a worktree that differs from `HEAD` read clean,
/// and a flag can't turn either off. A submodule's own index is read as it is, so an
/// `assume-unchanged` edit or a stale `stat` inside one can read clean. A sparse
/// checkout's files outside its cone read as deleted, so its tree reads dirty.
const DIRTY_TREE_STATUS: &str = concat!(
    entries_index!(),
    dirty_git!(),
    " status --porcelain --untracked-files=normal --ignore-submodules=none",
);

/// The git commands [`dirty_id`] reads the working tree through, in order: the changes
/// to tracked files, the untracked files git doesn't ignore, and (with any) the blob ids
/// of their contents, each against [`entries_index!`]'s copy of the index with the
/// settings [`dirty_git!`] forces. Each covers the whole work tree whatever directory
/// zap runs from (as the dirty check, `git status`, does), with names relative to its
/// top; none applies a configured external diff or `textconv` (the checkout's
/// attributes still apply: see [`DIRTY_TREE_STATUS`]), and none writes to the
/// repository. The blob ids come through `xargs`, so no list of names is ever one
/// command line. An untracked nested repository is listed as one `name/` entry and
/// never hashed: it counts by its name alone. An untracked symlink counts by its target
/// path, as git records one (dangling or naming a directory alike), on an `l <id>` line.
/// Every counted name gets its line in name order, so which name is the symlink names
/// the tree; the regular files between two symlinks are hashed in one call. Names reach
/// every command as arguments, never as shell text.
const DIRTY_TREE_DIFF: &str = concat!(
    entries_index!(),
    dirty_git!(),
    " diff HEAD --binary --no-ext-diff --no-textconv --no-color --no-relative \
     --ignore-submodules=none",
);
const DIRTY_TREE_UNTRACKED: &str = concat!(
    entries_index!(),
    dirty_git!(),
    " ls-files -o --exclude-standard -z --full-name -- ':/'",
);
const DIRTY_TREE_BLOBS: &str = concat!(
    entries_index!(),
    "zap_top=$(",
    dirty_git!(),
    " rev-parse --show-toplevel) && cd -- \"$zap_top\" && ",
    dirty_git!(),
    " ls-files -o --exclude-standard -z --full-name -- ':/' | ",
    "xargs -0 sh -c 'zap_n=$#; for f do [ \"$zap_n\" -eq 0 ] || { zap_n=0; set --; }; ",
    "case $f in */) ;; *) if [ -L \"$f\" ]; then ",
    "[ $# -eq 0 ] || ",
    dirty_git!(),
    " hash-object --no-filters -- \"$@\" || exit 1; set --; ",
    "zap_t=$(readlink -- \"$f\" && echo x) || exit 1; ",
    "zap_id=$(printf %s \"${zap_t%?x}\" | ",
    dirty_git!(),
    " hash-object --stdin) || exit 1; ",
    "printf \"l %s\\n\" \"$zap_id\"; ",
    "else set -- \"$@\" \"$f\"; fi;; esac; done; ",
    "[ $# -eq 0 ] || ",
    dirty_git!(),
    " hash-object --no-filters -- \"$@\"' zap",
);

/// The id of an uncommitted tree: 8 lowercase hex of the blake3 over what the tree adds
/// to `HEAD` — its tracked changes, and its untracked files' names and contents (a
/// symlink's target path) — read as the bytes git prints, never a decoded text.
///
/// A function of the tree alone (no clock, no stash commit), so a dry run and the
/// wetrun bound to it name the same release, and two different dirty trees on one
/// commit are two releases rather than one extracted over the other.
///
/// # Errors
/// [`Error::Git`] when a read fails, or when the blob ids don't answer the untracked
/// names one for one (a file that went away between the reads).
async fn dirty_id(local: &Connection, masker: &SecretMasker) -> Result<String> {
    let read = |command: &'static str| async move {
        local
            .run_stdout_bytes(command)
            .await?
            .map_err(|out| git_error("the uncommitted tree", command, &out, masker))
    };
    let diff = read(DIRTY_TREE_DIFF).await?;
    let untracked = read(DIRTY_TREE_UNTRACKED).await?;
    // a `name/` entry is an untracked nested repository, which gets no blob id
    let names = untracked
        .split(|&b| b == 0)
        .filter(|n| !n.is_empty() && !n.ends_with(b"/"))
        .count();
    let blobs = if names == 0 {
        Vec::new()
    } else {
        read(DIRTY_TREE_BLOBS).await?
    };
    let lines: Vec<&[u8]> = blobs
        .split(|&b| b == b'\n')
        .filter(|id| !id.is_empty())
        .collect();
    if lines.len() != names {
        return Err(Error::Git(format!(
            "could not read the uncommitted tree (`{DIRTY_TREE_BLOBS}`): {} blob id(s) for \
             {names} untracked file(s) — the tree changed while it was read",
            lines.len()
        )));
    }
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"zap-dirty-tree\0");
    for part in [&diff, &untracked, &blobs] {
        hasher.update(&(part.len() as u64).to_le_bytes());
        hasher.update(part);
    }
    let hex = hasher.finalize().to_hex();
    Ok(hex[..8].to_owned())
}

/// `user@host` of the operator machine (best-effort; empty parts tolerated).
async fn deployed_by(local: &Connection) -> String {
    let user = local
        .run("whoami", &RunOptions::default())
        .await
        .map(|o| o.stdout.trim().to_owned())
        .unwrap_or_default();
    let host = local
        .run("hostname", &RunOptions::default())
        .await
        .map(|o| o.stdout.trim().to_owned())
        .unwrap_or_default();
    format!("{user}@{host}")
}

/// `server_version`'s exit for "nothing at `current`".
const NOT_DEPLOYED_EXIT: i32 = 3;
/// `server_version`'s exit for a `current` that exists but isn't a symlink.
const NOT_A_LINK_EXIT: i32 = 4;

/// The read `server_version` runs: `readlink` of `current` when it is a link, else exit
/// [`NOT_A_LINK_EXIT`] when something else is there, or [`NOT_DEPLOYED_EXIT`] when
/// nothing is.
fn server_version_command(app_path: &str) -> String {
    let current = single_quote(&format!("{app_path}/current"));
    format!(
        "if [ -L {current} ]; then readlink -- {current}; elif [ -e {current} ]; then exit {NOT_A_LINK_EXIT}; else exit {NOT_DEPLOYED_EXIT}; fi"
    )
}

/// Why [`server_version`] read no live release.
#[derive(Debug, Clone, PartialEq, Eq)]
enum LiveReadError {
    /// The read itself failed: the command didn't run, or `readlink` failed.
    Unreadable(String),
    /// Something that isn't a symbolic link is at `current`.
    NotALink(String),
    /// `current` is a link, and what it names is no release's name.
    NoRelease(String),
}

impl std::fmt::Display for LiveReadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unreadable(message) | Self::NotALink(message) | Self::NoRelease(message) => {
                f.write_str(message)
            }
        }
    }
}

/// The version currently serving on the target, derived from the live `current`
/// symlink (`{app_path}/current` → `releases/<version>`; the release dir is named
/// by version, so the basename *is* the live version). Trailing slashes are dropped,
/// and a basename that is no release's name (`zap_types::deploy::release_of_link`) is
/// [`LiveReadError::NoRelease`]: a `.` segment or a path below a release would name a
/// release by a word that isn't its, which the rollback and the prune would then not
/// know.
///
/// `Ok(None)` means the symlink isn't there — a host that has never been deployed to.
/// [`LiveReadError::Unreadable`] means the read itself failed, and
/// [`LiveReadError::NotALink`] that something else is at `current`; neither is the same
/// thing and must not be silently folded into it: this value is the auto-rollback's only
/// target, so a swallowed error would disarm the post-swap safety net (and mislabel the
/// failure as "no previous release is known") on a host that in fact has one. The caller
/// surfaces it before shipping, while the operator can still act.
///
/// The symlink is authoritative — it reflects an out-of-band rollback (a manual
/// `ln -sfn` of `current`), which `deploy_info.json` cannot: that file is stamped
/// at swap time and a later rollback never rewrites it, so it drifts from reality.
/// Reading the swap target keeps "previous" honest about what's actually serving.
async fn server_version(
    target: &Connection,
    app_path: &str,
) -> std::result::Result<Option<String>, LiveReadError> {
    let cmd = server_version_command(app_path);
    let out = target
        .run(&cmd, &RunOptions::default())
        .await
        .map_err(|error| LiveReadError::Unreadable(error.to_string()))?;
    // Exit 3 is the command *working* and finding nothing at `current` — not deployed
    // yet. Anything else that isn't success (a `current` that isn't a link, a `readlink`
    // that failed, ssh's 255) is a failed read; an `app_path` the user can't search reads
    // as nothing there.
    if out.code == NOT_DEPLOYED_EXIT {
        return Ok(None);
    }
    if !out.success {
        let stderr = out.stderr.trim();
        return Err(if out.code == NOT_A_LINK_EXIT {
            LiveReadError::NotALink(format!("{app_path}/current exists but is not a symlink"))
        } else {
            LiveReadError::Unreadable(format!(
                "couldn't read {app_path}/current (exit {}): {stderr}",
                out.code
            ))
        });
    }
    let link = out.stdout.strip_suffix('\n').unwrap_or(&out.stdout);
    zap_types::deploy::release_of_link(link)
        .map(|version| Some(version.to_owned()))
        .ok_or_else(|| {
            LiveReadError::NoRelease(format!(
                "{app_path}/current names {link}, which is no release (releases/<version>)"
            ))
        })
}

/// Whether `current` resolves to a release directory on the target: `false` for a link
/// whose release is missing.
async fn live_release_present(target: &Connection, app_path: &str) -> Result<bool> {
    let cmd = format!("test -d {}", single_quote(&format!("{app_path}/current")));
    Ok(target.run(&cmd, &RunOptions::default()).await?.success)
}

/// The first non-empty of stderr / stdout, trimmed (a failed command's message).
fn non_empty(stderr: &str, stdout: &str) -> String {
    let stderr = stderr.trim();
    if stderr.is_empty() {
        let stdout = stdout.trim();
        if stdout.is_empty() {
            "no output".to_owned()
        } else {
            stdout.to_owned()
        }
    } else {
        stderr.to_owned()
    }
}

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
            super::render_refused(&mut out, reason, &DEPLOY_REFUSAL, report.confirmation);
        }
        DeployOutcome::Refused(reason) => {
            render_plan_preview(&mut out, plan);
            super::render_refused(&mut out, reason, &DEPLOY_REFUSAL, report.confirmation);
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

    super::render_lock_standing(
        &mut out,
        &report.lock_standing,
        "so the drift preflight cannot check them and a wetrun stops there",
    );
    super::render_undetermined(&mut out, &report.held);
    super::render_warnings(&mut out, &plan.warnings);
    super::render_warnings(&mut out, &report.warnings);
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
    super::render_target(out, &plan.target);
    super::render_references(out, &plan.references);
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
