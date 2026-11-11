//! The wetrun's step walk: each step of the [`DeployPlan`] executed in order over the
//! two connections — the build and the archive operator-side, the upload, the
//! extract-and-swap script, and the restart on the target, the health and readiness
//! polls over HTTP — stopping at the first failure, with a started and an outcome
//! event per step.

use std::path::Path;
use std::time::Instant;

use zap_types::deploy::{
    ARCHIVE_ENV, DeployAction, DeployPlan, DeployStep, DeployStepId, SCRIPT_ERROR_PREFIX,
    SCRIPT_WARNING_PREFIX, SWAPPED_LINE,
};
use zap_types::event::{Event, StepOutcome};
use zap_types::shell::single_quote;

use super::live::{LiveReadError, server_version};
use super::{StepRecord, StepSummary, SwapFailure, health};
use crate::connection::{CommandOutput, Connection, RunOptions};
use crate::error::Result;
use crate::event::EventHandler;

/// What a walk of the deploy plan did: each step's outcome, in plan order, the record of
/// each attempted step, and the step that failed, if one did.
pub(super) struct Walked {
    /// Every step's outcome.
    pub(super) outcomes: Vec<StepOutcome>,
    /// Each attempted step's time and summary, in the order run.
    pub(super) records: Vec<StepRecord>,
    /// The step that failed and stopped the walk.
    pub(super) failed: Option<Stopped>,
}

/// Where a walk stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Stopped {
    /// A step other than the extract-and-swap failed.
    At(DeployStepId),
    /// The extract-and-swap step failed, with what is known of the swap.
    AtSwap(SwapFailure),
}

/// Walk the deploy plan, executing each step's IO. Stops at the first failure
/// (later steps become `Skipped`), emitting a started + outcome event per attempted
/// step through `handler` (where masking happens), and timing each attempted step.
/// `archive` is dropped when the walk ends, however it ends: the operator's copy of the
/// release goes with it.
pub(super) async fn execute_deploy_plan(
    local: &Connection,
    target: &Connection,
    live: AppLive<'_>,
    plan: &DeployPlan,
    mut archive: ReleaseArchive,
    handler: &EventHandler,
    warnings: &mut Vec<String>,
) -> Walked {
    let mut outcomes = Vec::with_capacity(plan.steps.len());
    let mut records = Vec::with_capacity(plan.steps.len());
    let mut failed: Option<Stopped> = None;

    for step in &plan.steps {
        let outcome = if let Some(failed) = failed {
            let failed = match failed {
                Stopped::At(id) => id,
                Stopped::AtSwap(_) => DeployStepId::ExtractSwap,
            };
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
            let started = Instant::now();
            let ran = run_step(local, target, release, step, &mut archive, warnings).await;
            let mut record = StepRecord {
                id: step.id,
                took: started.elapsed(),
                summary: None,
            };
            let outcome = match ran {
                Ok(StepRun::Ran { output, summary }) => {
                    record.summary = summary;
                    StepOutcome::Completed {
                        step: step.id.to_string(),
                        output,
                    }
                }
                Ok(StepRun::NotRun(reason)) => StepOutcome::Skipped {
                    step: step.id.to_string(),
                    reason,
                },
                Err(StepFailure { error, swap }) => {
                    failed = Some(match (step.id, swap) {
                        (DeployStepId::ExtractSwap, swap) => {
                            // a swap failure that said nothing of the swap is unknown
                            Stopped::AtSwap(swap.unwrap_or(SwapFailure::Unknown))
                        }
                        (id, _) => Stopped::At(id),
                    });
                    StepOutcome::Failed {
                        step: step.id.to_string(),
                        error,
                    }
                }
            };
            records.push(record);
            outcome
        };
        handler.emit(&Event::from_step_outcome(&outcome));
        outcomes.push(outcome);
    }
    Walked {
        outcomes,
        records,
        failed,
    }
}

/// Whether a step actually ran — the distinction [`StepOutcome`] draws between
/// `Completed` and `Skipped`, which a bare `Ok(String)` collapsed.
///
/// One step can decline to run without failing: a `Readiness` gate the target doesn't
/// serve. Reporting it as `Completed` would tell a machine consumer of the event stream
/// that the step *passed* — the schema-drift check reporting success without having run.
/// The reason rides the variant, so "not run" can't be written without saying why.
enum StepRun {
    /// The step ran: what it printed or did (the event's `output`), and the summary its
    /// outcome line shows, when the engine has one to give.
    Ran {
        /// The command's output, or what the engine did.
        output: String,
        /// The outcome line's summary.
        summary: Option<StepSummary>,
    },
    /// The step deliberately did not run, for this reason.
    NotRun(String),
}

impl StepRun {
    /// A run whose output is a command's, or a fact with nothing to summarize.
    const fn output(output: String) -> Self {
        Self::Ran {
            output,
            summary: None,
        }
    }
}

/// The release archive of one run: the operator's copy, and what the target was sent.
///
/// The operator's copy is a file in a directory made for this run — mode `700`, under a
/// name nobody could have prepared — so no other account on the operator machine can
/// read the release, replace it between its creation and its upload, or aim `tar` at a
/// file of the operator's through a link. Dropping this removes the directory.
pub(super) struct ReleaseArchive {
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
    pub(super) fn under(scratch: &Path) -> Self {
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
pub(super) struct AppLive<'a> {
    /// The app path (`deploy.path`).
    pub(super) app: &'a str,
    /// The release live when the plan was made (`None` on a first deploy).
    pub(super) previous: Option<&'a str>,
}

/// The release a deploy's steps ship: the app path on the target, the version, and the
/// release the plan read as live.
#[derive(Clone, Copy)]
pub(super) struct Release<'a> {
    /// The app path (`deploy.path`).
    pub(super) app: &'a str,
    /// The version the plan ships.
    pub(super) version: &'a str,
    /// The release live when the plan was made (`None` on a first deploy).
    pub(super) previous: Option<&'a str>,
}

/// Why a step failed: its message, and for the extract-and-swap step, what is known of
/// the swap.
struct StepFailure {
    /// The step's error.
    error: String,
    /// What a failed extract-and-swap establishes about `current`; `None` for every
    /// other step.
    swap: Option<SwapFailure>,
}

impl From<String> for StepFailure {
    fn from(error: String) -> Self {
        Self { error, swap: None }
    }
}

/// Execute one deploy step. `Ok` carries whether it ran ([`StepRun`]); `Err`
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
) -> std::result::Result<StepRun, StepFailure> {
    match &step.action {
        DeployAction::Build { command } => {
            Ok(run_captured(local, command).await.map(StepRun::output)?)
        }
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
            Ok(StepRun::output("created the release archive".to_owned()))
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
            Ok(StepRun::Ran {
                output: format!("uploaded {remote}"),
                summary: Some(StepSummary::Uploaded {
                    bytes: u64::try_from(bytes.len()).unwrap_or(u64::MAX),
                }),
            })
        }
        DeployAction::ExtractSwap { script } => {
            // never ran: `current` is as it was
            let (remote, digest) = archive.uploaded.as_ref().ok_or_else(|| StepFailure {
                error: "no release archive was uploaded to extract".to_owned(),
                swap: Some(SwapFailure::NotSwapped),
            })?;
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
            ran.map(|(output, _)| StepRun::output(output))
                .map_err(|(swap, error)| StepFailure {
                    error,
                    swap: Some(swap),
                })
        }
        DeployAction::Restart { command } => {
            Ok(run_captured(target, command).await.map(StepRun::output)?)
        }
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
        } => Ok(health::http_health_check(url, *attempts, *interval_ms)
            .await
            .map(|said| StepRun::Ran {
                output: said.clone(),
                summary: Some(StepSummary::Said(said)),
            })?),
        DeployAction::Readiness {
            url,
            attempts,
            interval_ms,
            ..
        } => {
            // The poller resolves; these messages report the URL as declared, which is
            // what the operator wrote and what the plan renders.
            match health::http_readiness_check(url, *attempts, *interval_ms).await {
                health::ReadinessOutcome::Ready => Ok(StepRun::Ran {
                    output: format!("ready: live schema matches at {url}"),
                    summary: Some(StepSummary::Said("live schema matches".to_owned())),
                }),
                health::ReadinessOutcome::Absent => {
                    // Loud-warn rather than fail: an absent `/ready` is a
                    // misconfiguration (backend doesn't serve it, or nginx doesn't
                    // proxy it), not schema drift — rolling back an otherwise-healthy
                    // release would be wrong. The warning nudges the operator to wire
                    // the gate; the deploy proceeds on the liveness check alone.
                    warnings.push(format!(
                        "readiness gate SKIPPED — GET {url} returned 404. The `/ready` \
                         schema-drift gate isn't being served: confirm the backend mounts it \
                         and nginx proxies `/ready`. This release shipped with no schema-drift \
                         protection."
                    ));
                    Ok(StepRun::NotRun(format!("{url} absent (404)")))
                }
                health::ReadinessOutcome::NotReady(msg) => Err(msg.into()),
            }
        }
    }
}

/// The extract-and-swap script's run, read by its [`SWAPPED_LINE`] rather than by its
/// exit status alone: `Ok` once `current` names the new release — its stdout without
/// that line and its marked lines, and, when the run was not clean, the warning that
/// says so — and `Err` for a run that swapped nothing, whatever its status, with what a
/// read of `current` established about it ([`SwapFailure`]).
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
pub(super) async fn swap_ran(
    target: &Connection,
    release: Release<'_>,
    ran: Result<CommandOutput>,
) -> std::result::Result<(String, Option<String>), (SwapFailure, String)> {
    let output = match ran {
        Ok(output) => output,
        Err(error) => return Err((read_back(target, release).await, error.to_string())),
    };
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
        if !output.success {
            return Err((read_back(target, release).await, script_failure(&output)));
        }
        return match server_version(target, release.app).await {
            Ok(Some(live)) if live == release.version => Ok((
                shown,
                Some(format!(
                    "the extract-and-swap script's swap line was missing or garbled, but \
                     `current` names releases/{live} — the new release is live, and is \
                     restarted and checked as usual"
                )),
            )),
            Ok(_) | Err(LiveReadError::NotALink(_) | LiveReadError::NoRelease(_)) => Err((
                SwapFailure::NotSwapped,
                "the extract-and-swap script ended without swapping `current`, so nothing \
                 was released"
                    .to_owned(),
            )),
            Err(LiveReadError::Unreadable(error)) => Err((
                SwapFailure::Unknown,
                format!(
                    "the extract-and-swap script ended without its swap line, and `current` \
                     could not be read back to tell whether it swapped: {error}"
                ),
            )),
        };
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
            return Err((
                SwapFailure::NotSwapped,
                format!(
                    "the script printed the swap line but `current` names {} — it swapped \
                     nothing, so nothing was released: {why}",
                    live.map_or_else(|| "nothing".to_owned(), |live| format!("releases/{live}"))
                ),
            ));
        }
        Err(LiveReadError::NotALink(_)) => {
            return Err((
                SwapFailure::NotSwapped,
                format!(
                    "the script printed the swap line but `current` is not a symlink — it \
                     swapped nothing, so nothing was released: {why}"
                ),
            ));
        }
        Err(LiveReadError::NoRelease(message)) => {
            return Err((
                SwapFailure::NotSwapped,
                format!(
                    "the script printed the swap line but {message} — it swapped nothing, so \
                     nothing was released: {why}"
                ),
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

/// What `current`, read back after a swap that failed, establishes: that it names some
/// other release, or none, so this run's release is not live
/// ([`NotSwapped`](SwapFailure::NotSwapped)) — or nothing, when it names this version
/// (this run's swap, or another deploy's of the same version) or can't be read.
async fn read_back(target: &Connection, release: Release<'_>) -> SwapFailure {
    match server_version(target, release.app).await {
        Ok(Some(live)) if live == release.version => SwapFailure::Unknown,
        Ok(_) | Err(LiveReadError::NotALink(_) | LiveReadError::NoRelease(_)) => {
            SwapFailure::NotSwapped
        }
        Err(LiveReadError::Unreadable(_)) => SwapFailure::Unknown,
    }
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
