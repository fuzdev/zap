//! The detection pass the convergence and deploy cores share: preparing the lock,
//! running and recording the pass, spending a review, and diffing the pass into a plan.

use std::collections::BTreeMap;
use std::path::Path;

use zap_types::config_hash::plan_hash;
use zap_types::detected::Detection;
use zap_types::last_run::RunCommand;
use zap_types::lock::ZapLock;
use zap_types::plan::{DiffInputs, PlanResult, TriggerKind, diff};
use zap_types::schema::{ResourceId, ResourceKind, ZapConfig};

use crate::connection::Connection;
use crate::error::{Error, Previewed, Result};
use crate::home::take_record;
use crate::last_run::{build_last_run, report_var, write_last_run};
use crate::lock::{ColdStart, ResolvedLock, inspect_lock, resolve_lock};
use crate::resolve::env_var;
use crate::resource::pending::{declares_trigger, marker_stem};
use crate::resource::{DetectionPass, Markers, detect_all};
use crate::secret::SecretMasker;

use super::{PlanAddress, ResolvedMachine, unverifiable_refs};

/// Build the in-memory lock for a run: load `zap.lock` and resolve any missing tracked
/// `remote_file` pins (the one network IO a dry-run does), unless locking is disabled.
///
/// Returns `None` when `no_lock` is set or there is no `zap_home` (the content-cache
/// root the resolver needs) — downstream, tracked remote files then hold
/// `Undetermined` rather than being guessed. The caller persists the resolved lock
/// only on a `--wetrun` (the operator-side ledger write). A config with no tracked
/// remote files yields an empty lock (cheap; nothing to persist). `cold_start` is
/// [`ColdStart::Preview`] for a dry run, which renders past a pin it can't mint.
///
/// # Errors
/// Propagates lock-stale / read / resolve / hash failures from [`resolve_lock`].
pub(super) async fn prepare_lock(
    config: &ZapConfig,
    config_path: &Path,
    zap_home: Option<&Path>,
    no_lock: bool,
    cold_start: ColdStart,
) -> Result<Option<ResolvedLock>> {
    if no_lock {
        return Ok(None);
    }
    let Some(home) = zap_home else {
        return Ok(None);
    };
    Ok(Some(
        resolve_lock(config, config_path, home, cold_start).await?,
    ))
}

/// What every detection pass of one command shares: the `~/.zap` root (the content
/// cache a `remote` file's desired digest comes from, and the last-run report's home —
/// `None` turns both off), the config path the report is filed under, and the run's
/// masker, which masks every registered secret out of the values the report hashes, and
/// whether the run connects as the bootstrap user — which user its plans name.
#[derive(Debug, Clone, Copy)]
pub struct PassContext<'a> {
    /// The `~/.zap` root.
    pub zap_home: Option<&'a Path>,
    /// The config being run, which names the report's directory.
    pub config_path: &'a Path,
    /// The run's secret masker.
    pub masker: &'a SecretMasker,
    /// Whether the run connects as the target's `bootstrap_user` (`--bootstrap`).
    pub bootstrap: bool,
}

/// One detection pass over `config` — [`detect_all`], then the last-run report of what
/// it read, as `command`.
///
/// The one path every command's detection takes, so every pass writes the report
/// (latest-only per config and host) and none can skip it — a host that names no one
/// machine has none (`record_pass`). Detection never reads it back.
/// The report is taken the way `status` reads it back: its host and hashes through
/// [`report_var`], its pins from the **on-disk** lock (`inspect_lock`, which withholds a
/// non-current pin as `status` does — never `lock`, which on an `apply` dry run holds
/// pins resolved but not yet written), plus the pass's [`unverifiable_refs`]. The write
/// is advisory: a failure is swallowed, as for the other `~/.zap` state — the report
/// left in place still says when and by what it was taken.
///
/// # Errors
/// Propagates [`detect_all`]'s failures (connectivity, the pending-marker read); a failed
/// pass writes no report.
pub(super) async fn detect_pass(
    conn: &Connection,
    config: &ZapConfig,
    ctx: PassContext<'_>,
    machine: &ResolvedMachine,
    lock: Option<&ZapLock>,
    markers: Markers,
    command: RunCommand,
) -> Result<DetectionPass> {
    let pass = detect_all(
        conn,
        &config.target,
        &config.resources,
        ctx.zap_home,
        lock,
        markers,
    )
    .await?;
    record_pass(ctx, config, machine, &pass, command, None);
    Ok(pass)
}

/// Write the last-run report for `pass` (see [`detect_pass`]) — none without a `~/.zap`
/// root; advisory, so every failure — a lock that can't be read, the unverifiable scan,
/// the write — leaves no new report rather than one it can't vouch for. It is filed
/// under `machine`'s host, the machine the command resolved once for all its passes.
/// `plan_hash` is the plan the pass computed, when it planned and the plan has an
/// address ([`detect_and_diff`]).
///
/// None either for a host that resolves through a masked reference
/// ([`unidentified_host_message`]): the report's file name and `host` would be a token
/// every machine behind the reference shares, so one machine's verdicts would be read
/// back as another's.
///
/// [`unidentified_host_message`]: super::unidentified_host_message
pub(super) fn record_pass(
    ctx: PassContext<'_>,
    config: &ZapConfig,
    machine: &ResolvedMachine,
    pass: &DetectionPass,
    command: RunCommand,
    plan_hash: Option<&str>,
) {
    let Some(zap_home) = ctx.zap_home else {
        return;
    };
    let config_path = ctx.config_path;
    if machine.unidentified_host.is_some() {
        return;
    }
    let host = machine.machine.host().to_owned();
    let var = report_var(config, ctx.masker);
    let Ok((on_disk, _)) = inspect_lock(config, config_path, env_var) else {
        return;
    };
    let unverifiable = unverifiable_refs(config);
    let report = build_last_run(
        command,
        host,
        config,
        on_disk.as_ref(),
        pass,
        var,
        unverifiable,
        plan_hash.map(str::to_owned),
    );
    let _ = write_last_run(zap_home, config_path, &report);
}

/// Spend the review a wetrun passed, before its first change: take the recorded
/// preview at `record` away ([`take_record`]), whichever way the wetrun bound, so that
/// no later wetrun binds to it.
///
/// A wetrun `bound_to_record` executes only when the record it takes is one that
/// `binds` its plan (read from where the take holds it): of the runs that read one
/// preview, the one that takes it executes, and another finds the name empty or holding
/// a later record, which it puts back — best effort: a record that can't be put back
/// is gone, which costs a new preview, never a second execution. A wetrun bound
/// otherwise (`--expect-plan`, a confirmation, an empty plan) needs nothing of the
/// record and lets it go.
///
/// # Errors
/// [`Error::PreviewWithdraw`] when a record is there and can't be taken, and
/// [`Error::PreviewSpent`] when the wetrun bound to the record and another run took it
/// first. Either stops the wetrun with nothing run.
pub(super) fn spend_review(
    record: &Path,
    of: Previewed,
    bound_to_record: bool,
    binds: impl FnOnce(&Path) -> bool,
) -> Result<()> {
    let taken = take_record(record).map_err(|error| Error::PreviewWithdraw {
        of,
        path: record.display().to_string(),
        message: error.to_string(),
    })?;
    match taken {
        _ if !bound_to_record => Ok(()),
        Some(taken) if binds(taken.held()) => Ok(()),
        Some(taken) => {
            taken.restore();
            Err(Error::PreviewSpent { of })
        }
        None => Err(Error::PreviewSpent { of }),
    }
}

/// What [`detect_and_diff`] produces: the diff, the observed side it was taken against,
/// the plan's content address, and the detection pass itself (so `apply` can re-record
/// the pass under another command when it refuses to execute).
pub(super) struct Diffed {
    /// The plan plus warnings and the held verdict.
    pub result: PlanResult,
    /// The observed `before` side per resource, kept in memory for `plan --diff`, as
    /// read: `plan` masks it before it reaches a report.
    pub detected: BTreeMap<ResourceId, Detection>,
    /// [`plan_hash`] of `result.plan`, or why the plan has none.
    pub plan_hash: PlanAddress,
    /// The pass the diff was taken from.
    pub pass: DetectionPass,
}

/// Detect live state and diff it to the plan fact — the shared core of `plan`, `apply`,
/// and `deploy`'s preflight. The pass ([`detect_pass`], recorded as `command`) returns
/// one outcome per resource in config order; zipping rejoins each with its id into the
/// map `diff` consumes.
///
/// Returns the whole [`PlanResult`] (plan + warnings + the [`held`] verdict) and the
/// per-resource [`Detection`] map. The map is the observed `before` side the
/// `plan --diff` renderer joins against `Change.desired`, kept in memory only (never
/// persisted into the plan fact, which stays observed-free); `apply` /
/// `deploy`-preflight ignore it.
///
/// The plan is for `machine`, which the caller resolved for the run
/// ([`resolve_machine`]). When that names no one machine the plan has no address:
/// nothing is hashed, and the pass is recorded — if its host identifies a machine at
/// all — with no plan to bind to.
///
/// [`held`]: zap_types::plan::PlanResult::held
/// [`resolve_machine`]: super::resolve_machine
///
/// # Errors
/// Propagates detection failures (e.g. a connection error a detector couldn't
/// localize to one resource).
pub(super) async fn detect_and_diff(
    conn: &Connection,
    config: &ZapConfig,
    ctx: PassContext<'_>,
    machine: &ResolvedMachine,
    lock: Option<&ZapLock>,
    command: RunCommand,
) -> Result<Diffed> {
    let diffed = diff_unrecorded(conn, config, ctx, machine, lock).await?;
    // The report carries the plan this pass computed, so a later wetrun can bind to it
    // (`review_plan`); recorded after the diff, which is why this doesn't go through
    // `detect_pass`.
    record_pass(
        ctx,
        config,
        machine,
        &diffed.pass,
        command,
        diffed.plan_hash.hash(),
    );
    Ok(diffed)
}

/// [`detect_and_diff`] with the pass left unrecorded, for a caller that records it
/// later: an `apply` wetrun, whose pass would otherwise replace the preview it binds
/// to before it has claimed it.
///
/// # Errors
/// Same as [`detect_and_diff`].
pub(super) async fn diff_unrecorded(
    conn: &Connection,
    config: &ZapConfig,
    ctx: PassContext<'_>,
    machine: &ResolvedMachine,
    lock: Option<&ZapLock>,
) -> Result<Diffed> {
    // The pending markers are read in the detection pass's own batch, and only when the
    // config declares a trigger: nothing else can write one.
    let markers = if declares_trigger(&config.resources) {
        Markers::Read
    } else {
        Markers::Skip
    };
    let pass = detect_all(
        conn,
        &config.target,
        &config.resources,
        ctx.zap_home,
        lock,
        markers,
    )
    .await?;
    let detected: BTreeMap<ResourceId, Detection> = config
        .resources
        .iter()
        .map(|resource| resource.id.clone())
        .zip(pass.detections.iter().cloned())
        .collect();
    let (pending, orphans) = pending_triggers(config, pass.pending.clone());
    // The values the plan records for the references its changes use: resolved as the
    // machine was, so a secret is never among them.
    let var = report_var(config, ctx.masker);
    let mut result = diff(DiffInputs {
        resources: &config.resources,
        detected: &detected,
        target: &config.target,
        machine: &machine.machine,
        lock,
        pending: &pending,
        var: &var,
    });
    result.warnings.extend(orphans);
    let plan_hash = match &machine.unbindable {
        Some(reason) => PlanAddress::Unbindable(reason.clone()),
        None => PlanAddress::Hash(plan_hash(&result.plan).map_err(Error::PlanHash)?),
    };
    Ok(Diffed {
        result,
        detected,
        plan_hash,
        pass,
    })
}

/// The pending-trigger `markers` read from the target (keyed by marker stem) that belong
/// to this config's services, keyed by service name, plus a warning for each marker no
/// service here manages.
///
/// The markers are read only when the config declares a trigger (a `file.triggers`,
/// `restart_on`, or `reload_on`): nothing else can write one. Read live every pass, like
/// every resource (another operator, another config, a failed run all move it).
pub(super) fn pending_triggers(
    config: &ZapConfig,
    mut markers: BTreeMap<String, TriggerKind>,
) -> (BTreeMap<String, TriggerKind>, Vec<String>) {
    let mut pending = BTreeMap::new();
    for resource in &config.resources {
        if let ResourceKind::Service(service) = &resource.kind
            && let Some(kind) = markers.remove(&marker_stem(&service.service))
        {
            pending.insert(service.service.as_str().to_owned(), kind);
        }
    }
    let orphans = markers
        .into_iter()
        .map(|(stem, kind)| {
            format!(
                "a pending {} of `{stem}` is recorded on the target by an earlier apply, but \
                 no service in this config manages it — remove {}/{stem} once it's handled",
                kind.as_str(),
                crate::resource::pending::PENDING_DIR,
            )
        })
        .collect();
    (pending, orphans)
}
