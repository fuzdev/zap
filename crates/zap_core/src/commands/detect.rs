//! `zap detect` — live detected state, no diff (the Detect-stage inspector).
//!
//! The detect-half of `run_plan`: eval the config, probe the target via a
//! `Connection`, and render raw detected state. Distinct from `status` (offline, the
//! last-run report only) — `detect` probes live, against a local or SSH target. Its pass
//! writes that report, like every detection pass.

use std::fmt::Write as _;
use std::path::Path;

use zap_types::detected::Detection;
use zap_types::last_run::RunCommand;
use zap_types::schema::{ResourceId, ResourceType, ZapConfig};

use super::{PassContext, detect_pass, eval_target, resolve_machine, target_location};
use crate::connection::Connection;
use crate::error::Result;
use crate::escape::{escape_line, render_block};
use crate::home::zap_home_default;
use crate::lock::{LockStanding, inspect_lock};
use crate::resolve::env_var;
use crate::resource::Markers;

/// One resource's detected line, joined with its declared kind for rendering.
#[derive(Debug, Clone)]
pub struct DetectLine {
    /// Which resource this line is for.
    pub resource_id: ResourceId,
    /// The detection outcome (existence, convergence, observed current state).
    pub detection: Detection,
    /// The declared kind.
    pub kind: ResourceType,
}

/// Live detection report. Returned by `run_detect`; the binary renders it.
#[derive(Debug, Clone)]
pub struct DetectReport {
    /// Target location label (`local`, or a host).
    pub target: String,
    /// Declared package manager, for the header.
    pub package_manager: Option<String>,
    /// Declared service manager, for the header.
    pub service_manager: Option<String>,
    /// Per-resource detected state in config order.
    pub resources: Vec<DetectLine>,
    /// Referenced vars the comparison needed but couldn't resolve. Non-empty means the
    /// per-resource verdicts below are **not** evidence: `Converged` / `Drifted` were
    /// decided against a desired side containing empty strings.
    pub unverifiable: Vec<String>,
    /// How the config's tracked pins stand against `zap.lock`. A non-current pin is
    /// withheld from detection, so an entry here is normally *why* its resource came back
    /// `Undetermined`.
    pub lock_standing: LockStanding,
    /// Why the pass left no last-run report, when it left none: the target's host is a
    /// masking token (`unidentified_host_message`).
    pub unrecorded: Option<String>,
}

/// A detection only answers.
impl super::Delivered for DetectReport {
    fn exit_code(&self) -> u8 {
        Self::exit_code(self)
    }
    fn changed(&self) -> bool {
        false
    }
}

impl DetectReport {
    /// Process exit code: `1` when the detection was **unverifiable**, any resource came
    /// back [`Undetermined`](Detection::Undetermined), or the **lock standing** has
    /// errors; else `0`.
    ///
    /// `detect` is the stage inspector under `plan`, running the same resolution, so it
    /// carries the same verdicts — otherwise dropping a level would silently launder an
    /// untrustworthy comparison into a confident-looking one. An undetermined resource is
    /// the reason `plan` holds it out of the changeset, so a probe failure here is the
    /// same "not established" answer, not a successful detection run. It needs no report
    /// field: the per-resource lines already carry it, and this derives from them.
    ///
    /// The lock check is the same belt-and-braces as
    /// [`PlanReport::exit_code`](super::plan::PlanReport::exit_code): a withheld pin
    /// already lands its resource in `Undetermined`, but the code mustn't ride on a
    /// detector's choice to hold.
    #[must_use]
    pub fn exit_code(&self) -> u8 {
        let undetermined = self
            .resources
            .iter()
            .any(|line| matches!(line.detection, Detection::Undetermined { .. }));
        u8::from(!self.unverifiable.is_empty() || undetermined || self.lock_standing.has_errors())
    }
}

/// Render a [`DetectReport`] to the text shown by `zap detect`.
#[must_use]
pub fn render_detect(report: &DetectReport) -> String {
    let mut out = String::new();
    super::render_lock_standing(
        &mut out,
        &report.lock_standing,
        super::LOCK_WITHHELD_FROM_COMPARISON,
    );
    super::render_unverifiable(&mut out, &report.unverifiable);
    let pkg = escape_line(report.package_manager.as_deref().unwrap_or("none"));
    let svc = escape_line(report.service_manager.as_deref().unwrap_or("none"));
    let _ = writeln!(
        out,
        "detected live state — target {} (pkg: {pkg}, service: {svc})",
        escape_line(&report.target)
    );
    let _ = writeln!(out, "{} resource(s):", report.resources.len());
    for line in &report.resources {
        let mark = match line.detection {
            Detection::Converged => "ok",
            Detection::Drifted { .. } => "drift",
            Detection::Absent => "absent",
            Detection::Undetermined { .. } => "?",
        };
        let id = escape_line(&line.resource_id.0);
        let kind = line.kind.as_str();
        // What was observed — an owner, a link's destination, a probe's own words —
        // is the target's text, and a reason can run to several lines.
        let lead = format!("  {mark:<6} {id}  {kind}  — ");
        render_block(&mut out, &lead, &line.detection.describe());
    }
    super::render_unrecorded(&mut out, report.unrecorded.as_deref());
    out
}

/// Build the live detection report for `config_path`, using the default `~/.zap`.
///
/// `no_cache` (`--no-cache`) forces a fresh config eval, bypassing the L0 eval cache.
///
/// `bootstrap` connects as the target's `bootstrap_user` (the `--bootstrap` switch) — the
/// initial provisioning run before SSH hardening creates the primary user.
///
/// # Errors
/// Propagates config-eval, secret-validation (a literal secret in the config), and
/// detection failures (including SSH connectivity for a remote target).
pub async fn run_detect(
    config_path: &Path,
    fgro: Option<&Path>,
    no_cache: bool,
    bootstrap: bool,
) -> Result<DetectReport> {
    run_detect_in(
        zap_home_default()?.as_deref(),
        fgro,
        config_path,
        no_cache,
        bootstrap,
    )
    .await
}

/// `run_detect` with the `~/.zap` root injected (the hermetic test seam, as for
/// `status`). `None` turns off the eval cache, the content cache, and the last-run
/// report.
///
/// `bootstrap` selects the target's `bootstrap_user` as the connecting identity.
///
/// # Errors
/// Same as [`run_detect`].
pub async fn run_detect_in(
    zap_home: Option<&Path>,
    fgro: Option<&Path>,
    config_path: &Path,
    no_cache: bool,
    bootstrap: bool,
) -> Result<DetectReport> {
    // The masker the seam's gate builds is kept: an `Undetermined` reason is the one
    // detection string that carries a seam-resolved value (the path or identifier the
    // probe failed on), and `detect` renders it.
    let (config, conn, masker) =
        eval_target(config_path, zap_home, fgro, no_cache, bootstrap).await?;
    let ctx = PassContext {
        zap_home,
        config_path,
        masker: &masker,
        bootstrap,
    };
    detect_over(&conn, &config, ctx).await
}

/// Detect an evaluated, gated `config` over `conn`: [`run_detect_in`] past the config
/// eval and the connection bind — the seam the mock-driven tests enter.
///
/// # Errors
/// Same as [`run_detect`], less the config eval's — each masked by the run's masker.
pub(crate) async fn detect_over(
    conn: &Connection,
    config: &ZapConfig,
    ctx: PassContext<'_>,
) -> Result<DetectReport> {
    super::masking_errors(ctx.masker, detect_unmasked(conn, config, ctx)).await
}

/// [`detect_over`], its errors as they were raised.
async fn detect_unmasked(
    conn: &Connection,
    config: &ZapConfig,
    ctx: PassContext<'_>,
) -> Result<DetectReport> {
    let PassContext {
        config_path,
        masker,
        bootstrap,
        ..
    } = ctx;
    // Load the on-disk lock (existing tracked pins) — but `detect` never *mints* a pin
    // (no cold-start network resolve): it reports raw state, so a tracked file with no
    // entry stays `Undetermined`. Minting belongs to `apply`/`zap lock`. It does
    // validate: a stale or unverifiable pin is withheld, so it holds like a missing one
    // rather than being compared against.
    let (lock, lock_standing) = inspect_lock(config, config_path, env_var)?;
    // Detection resolves references into the desired side it compares against, so an unset
    // reference makes each verdict untrustworthy — carried on the report, not swallowed.
    let unverifiable = super::unverifiable_refs(config);
    let machine = resolve_machine(config, masker, bootstrap)?;
    let pass = detect_pass(
        conn,
        config,
        ctx,
        &machine,
        lock.as_ref(),
        Markers::Skip,
        RunCommand::Detect,
    )
    .await?;

    // `detect_all` returns one detection per resource, in config order, so zipping
    // rejoins each with its declared kind without a lookup.
    let resources = config
        .resources
        .iter()
        .zip(pass.detections)
        .map(|(resource, detection)| DetectLine {
            resource_id: resource.id.clone(),
            detection: detection.map_text(|text| masker.mask(text)),
            kind: resource.kind(),
        })
        .collect();

    Ok(DetectReport {
        target: target_location(&config.target),
        package_manager: config.target.package_manager.map(|m| m.as_str().to_owned()),
        service_manager: config.target.service_manager.map(|m| m.as_str().to_owned()),
        resources,
        unverifiable,
        lock_standing,
        unrecorded: machine.unidentified_host,
    })
}
