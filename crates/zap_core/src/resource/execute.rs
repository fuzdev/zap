//! Plan execution over a [`Connection`] — the Apply half of Describe → Detect →
//! Plan → Apply → Observe.
//!
//! [`execute_plan`] walks the plan fact's already-topologically-sorted, triggers-
//! injected `changes` in order. Two execution shapes fall out of the fact:
//!
//! - **Command-step kinds** (package / script / installer / service / `apt_repo` /
//!   swap / firewall / database / pipeline): uniform — take each step's text
//!   ([`PlanStep::execution`]: a [`PlanStep::Run`]'s own, a typed step's lowered to the
//!   command around its constant script), resolve its references
//!   (`resolve_command`: a value that could leave the step's quoting fails the change
//!   before the step runs), then run via `conn.run_composed` (the planner has already
//!   baked in any `sudo`). A put of text the plan holds runs the put script with that
//!   text on its stdin (`Connection::run_put`) and resolves nothing. A `script`'s steps
//!   run in its `cwd` with its `env` exported — what its `check` ran with. swap (fstab
//!   persist), database (guarded create + GRANT + per-host `pg_hba`), and `apt_repo`
//!   (the sources-list write) emit real, idempotent steps. [`PlanStep::Note`] steps are
//!   render-only and execute as
//!   no-ops — they stand only for genuinely unrunnable previews (a
//!   sizeless `swap`, `verify` assertion descriptions).
//! - **Native-fs kinds** (file / directory / link): carry no command steps — the
//!   executor reads the typed `desired` variant and applies the filesystem op via
//!   the `Connection`'s native-fs methods (per-op try-native-then-sudo), resolving
//!   paths through the shared `resolve_kind_fields`
//!   seam — the same reference resolution + target-home (`Connection::apply_home`)
//!   detection probed (an undeclared remote home fails the change, never guesses).
//! - **`verify`**: a safety gate — re-runs its assertions, each as its own command:
//!   the command and the reading of its result are the ones detection batches
//!   (`zap_types::observe::verify`); any failure fails the change and **aborts** the
//!   plan.
//!
//! **Triggers are at-least-once.** Before the first source of a triggered service
//! runs, the executor records a pending marker on the target (`super::pending`), and
//! it clears the marker only after the service's own change completes — so a reload
//! that fails, or a run that dies between the source and the service, leaves a marker
//! the next plan re-fires from, instead of a trigger that silently never happens.
//!
//! **Stop on first failure.** A failed change halts execution: every later change is
//! recorded [`ChangeOutcome::Skipped`] rather than run, since a dependent must not
//! execute on a broken dependency. A `verify` failure is just a change failure, so
//! the abort is the same path. The outcomes vector covers every change (run,
//! failed, or skipped) so the caller can render where the run halted and derive the
//! [`RunSummary`](zap_types::event::RunSummary).

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::time::{Duration, Instant};

use zap_types::config_hash::{build_provenance, extract_provenance};
use zap_types::error_code::{ErrorCode, NO_EXIT_CODE, classify_error};
use zap_types::event::{ChangeOutcome, Event};
use zap_types::extract::extract_archive_command;
use zap_types::fetch_url::{FetchSide, fetch_url_problem};
use zap_types::observe::apt_repo::KEY_READ_MAX;
use zap_types::observe::{self, verify};
use zap_types::plan::{Change, Plan, PlanStep, StepExecution, TriggerKind};
use zap_types::postgres::{PgHbaField, pg_hba_field_problem};
use zap_types::put::{FileAttrs, REFUSED_EXIT, RunAs, Snapshot, Unset};
use zap_types::schema::ResourceId;
use zap_types::schema::{
    APT_KEY_ATTRS, AptRepoResource, BuildResource, BuildSource, DirectoryResource, ExtractMode,
    FileContent, FileResource, RemoteAuth, RemoteContent, RemoteSource, ResolvedField,
    ResolvedFields, Resource, ResourceKind, ScriptResource, VerifyAssertion,
};
use zap_types::secrecy::Redacted;
use zap_types::shell::single_quote;
use zap_types::validate::resolved_field_problem;

use super::pending::{clear_pending, record_pending};
use super::{resolve_kind_fields, short_pin};
use crate::connection::{CommandOutput, Connection, RunOptions};
use crate::error::Error;
use crate::event::EventHandler;
use crate::resolve::{
    UnsafeValue, resolve_command, resolve_env_value, resolve_field, resolve_sql_identifier,
    resolve_template,
};
use crate::resolver;

/// A change that failed: the message its `ChangeOutcome::Failed` carries, and its
/// triage code.
///
/// A change failure is an expected operational outcome the operator inspects, not an
/// engine fault, so an executor's IO error ends here as a message. Its code is taken
/// before the error is flattened: from the error's own structure where it has one
/// ([`Error::error_code`] — a native call's io error classifies by its kind), and from
/// the words only for a failure that is nothing but words ([`Failure::words`]: zap's own
/// reason), and from its exit code and what it printed for a command that ran
/// ([`Failure::exited`]). Context a caller wraps around a failure
/// ([`Failure::map_message`]) keeps the code of what failed.
#[derive(Debug)]
pub(crate) struct Failure {
    /// The triage code.
    pub(crate) code: ErrorCode,
    /// What the change's failure says.
    pub(crate) message: String,
}

impl Failure {
    /// This failure with its message rewritten by `wrap`, its code kept.
    fn map_message(self, wrap: impl FnOnce(String) -> String) -> Self {
        Self {
            code: self.code,
            message: wrap(self.message),
        }
    }
}

impl From<Error> for Failure {
    fn from(error: Error) -> Self {
        Self {
            code: error.error_code(),
            message: error.to_string(),
        }
    }
}

impl Failure {
    /// A failure that is nothing but words — zap's own reason — classified by them.
    fn words(message: String) -> Self {
        Self {
            code: classify_error(&message, NO_EXIT_CODE),
            message,
        }
    }

    /// A command that ran and exited `code`, failing the change with `message`:
    /// classified by its exit code and what it printed (`output`).
    fn exited(output: &str, code: i32, message: String) -> Self {
        Self {
            code: classify_error(output, code),
            message,
        }
    }
}

/// One change a wetrun ran, and how long it took.
///
/// Timed from just before the pending markers it arms (its own work, since one it can't
/// record fails it) to the trigger it settles, so the time is what the change cost the
/// run. A change that was skipped never ran and has none.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChangeRecord {
    /// Which change, by its resource.
    pub resource_id: ResourceId,
    /// How long it ran.
    pub took: Duration,
}

/// What [`execute_plan`] did: one [`ChangeOutcome`] per change in plan order, and a
/// [`ChangeRecord`] for each change it ran (completed or failed), in the order it ran
/// them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Executed {
    /// Each change's outcome, in plan order.
    pub outcomes: Vec<ChangeOutcome>,
    /// Each change that ran, timed.
    pub records: Vec<ChangeRecord>,
}

/// Execute a plan against `conn`, returning one [`ChangeOutcome`] per change in plan
/// order, and how long each change that ran took ([`Executed`]).
///
/// Stops at the first failure (later changes become `Skipped`). Native-fs paths are
/// resolved through the shared `resolve_kind_fields`
/// seam (references + target-home); a command step's references resolve env-only, leaving
/// `~` / `$HOME` for the target shell.
///
/// Per-change failures are recorded as outcomes, not returned as an `Err` — a broken
/// command is an expected operational result the operator inspects, not an engine
/// fault. (Connectivity is already verified by `detect_all` before this runs.)
///
/// Each change emits a `ChangeStarted` event before it runs (skipped changes don't —
/// they never started) and its outcome event after, through `handler`. The handler is
/// where masking happens ([`mask_handler`](crate::event::mask_handler)); `execute_plan`
/// stays masking-unaware. Pass [`EventHandler::Null`] for a non-streaming run.
pub async fn execute_plan(
    conn: &Connection,
    plan: &Plan,
    zap_home: Option<&Path>,
    handler: &EventHandler,
) -> Executed {
    let mut outcomes = Vec::with_capacity(plan.changes.len());
    let mut records = Vec::with_capacity(plan.changes.len());
    let mut aborted_by: Option<String> = None;
    let arming = trigger_arming(&plan.changes);
    let mut armed: BTreeSet<&str> = BTreeSet::new();

    for change in &plan.changes {
        let outcome = if let Some(failed) = &aborted_by {
            ChangeOutcome::Skipped {
                resource_id: change.resource_id.clone(),
                reason: format!("aborted after `{failed}` failed"),
            }
        } else {
            handler.emit(&Event::ChangeStarted {
                resource_id: change.resource_id.clone(),
                action: change.action,
                kind: change.desired.kind(),
            });
            let started = Instant::now();
            let result = match arm_pending(conn, &arming, &mut armed, change).await {
                Ok(()) => match run_change(conn, zap_home, change).await {
                    Ok(output) => Ok(settle_trigger(conn, change, output).await),
                    Err(error) => Err(error),
                },
                Err(error) => Err(error),
            };
            records.push(ChangeRecord {
                resource_id: change.resource_id.clone(),
                took: started.elapsed(),
            });
            match result {
                Ok(output) => ChangeOutcome::Completed {
                    resource_id: change.resource_id.clone(),
                    output,
                },
                Err(Failure { code, message }) => {
                    aborted_by = Some(change.resource_id.0.clone());
                    ChangeOutcome::Failed {
                        resource_id: change.resource_id.clone(),
                        error: message,
                        code,
                    }
                }
            }
        };
        handler.emit(&Event::from_outcome(&outcome));
        outcomes.push(outcome);
    }
    Executed { outcomes, records }
}

/// For each change id, the services its completion fires and the action each owes —
/// read off the triggered service changes' `sources`.
fn trigger_arming(changes: &[Change]) -> BTreeMap<&ResourceId, Vec<(&str, TriggerKind)>> {
    let mut arming: BTreeMap<&ResourceId, Vec<(&str, TriggerKind)>> = BTreeMap::new();
    for change in changes {
        let (Some(trigger), ResourceKind::Service(service)) =
            (&change.trigger, &change.desired.kind)
        else {
            continue;
        };
        for source in &trigger.sources {
            arming
                .entry(source)
                .or_default()
                .push((service.service.as_str(), trigger.kind));
        }
    }
    arming
}

/// Record the pending marker of every service `change` fires, before it runs — once
/// per service per run (`armed`). A failure fails `change` with nothing yet changed,
/// which is why the record comes first: a source that ran with no marker is exactly the
/// lost trigger this exists to prevent.
async fn arm_pending<'a>(
    conn: &Connection,
    arming: &BTreeMap<&ResourceId, Vec<(&'a str, TriggerKind)>>,
    armed: &mut BTreeSet<&'a str>,
    change: &Change,
) -> Result<(), Failure> {
    for &(service, kind) in arming.get(&change.resource_id).into_iter().flatten() {
        if !armed.insert(service) {
            continue;
        }
        if let Err(error) = record_pending(conn, service, kind).await {
            return Err(Failure::from(error).map_message(|error| {
                format!(
                    "couldn't record the pending {} of `{service}` before this change, so \
                     it didn't run: {error}",
                    kind.as_str()
                )
            }));
        }
    }
    Ok(())
}

/// After a triggered service change completes, clear its pending marker. A failed
/// clear doesn't fail the change — its action did run — but it's reported in the
/// output, since the marker re-fires the action on the next apply.
async fn settle_trigger(conn: &Connection, change: &Change, output: String) -> String {
    let (Some(trigger), ResourceKind::Service(service)) = (&change.trigger, &change.desired.kind)
    else {
        return output;
    };
    match clear_pending(conn, &service.service).await {
        Ok(()) => output,
        Err(error) => {
            let separator = if output.is_empty() || output.ends_with('\n') {
                ""
            } else {
                "\n"
            };
            format!(
                "{output}{separator}(couldn't clear the pending {kind} marker of `{name}`: \
                 {error} — the next apply repeats the {kind})\n",
                kind = trigger.kind.as_str(),
                name = service.service,
            )
        }
    }
}

/// Execute one change. `Ok(summary)` on success; `Err(failure)` means the change
/// failed (and the plan aborts), with its triage code ([`Failure`]). Dispatches
/// native-fs kinds and `verify` to bespoke executors; everything else runs its command
/// steps.
///
/// Command-step kinds classify at the shell exit code inside [`run_steps`]. The bespoke
/// executors (file/dir/link/verify/build) classify an engine error by its structure as
/// it is flattened — a native call's io error by its kind — and zap's own reasons by
/// their words.
async fn run_change(
    conn: &Connection,
    zap_home: Option<&Path>,
    change: &Change,
) -> Result<String, Failure> {
    // Every reference in the change's command text resolves here, through the function
    // the wetrun preflight ran over the whole plan — so a value a command can't take
    // fails the change before any of it runs, should one get past the preflight.
    let commands = change_commands(change).map_err(Failure::words)?;
    match (&change.desired.kind, commands) {
        (ResourceKind::File(file), ChangeCommands::File { validate }) => {
            execute_file(conn, zap_home, &change.desired, file, validate).await
        }
        (ResourceKind::Build(build), ChangeCommands::Build { run, env }) => {
            execute_build(conn, zap_home, &change.desired, build, &run, env).await
        }
        (ResourceKind::AptRepo(repo), ChangeCommands::Steps { steps, options }) => {
            let key = install_apt_key(conn, zap_home, &change.desired, repo).await?;
            let output = run_steps(conn, &steps, &options).await?;
            Ok(format!("{key}\n{output}").trim_end().to_owned())
        }
        (_, ChangeCommands::Steps { steps, options }) => run_steps(conn, &steps, &options).await,
        (kind, ChangeCommands::None) => run_native(conn, &change.desired, kind).await,
        (_, ChangeCommands::File { .. } | ChangeCommands::Build { .. }) => Err(Failure::words(
            "internal: a change's commands don't match its kind".to_owned(),
        )),
    }
}

/// Execute a change that runs no command text of its own: a `directory`, a `link`, a
/// `verify`.
async fn run_native(
    conn: &Connection,
    desired: &Resource,
    kind: &ResourceKind,
) -> Result<String, Failure> {
    match kind {
        ResourceKind::Directory(dir) => execute_directory(conn, desired, dir).await,
        ResourceKind::Link(_) => execute_link(conn, desired).await,
        ResourceKind::Verify(verify) => execute_verify(conn, &verify.assertions).await,
        _ => Err(Failure::words(
            "internal: a change with commands was given none".to_owned(),
        )),
    }
}

/// The command text one change runs, with its references resolved — the only
/// form in which the executor holds a command.
///
/// Its `Debug` shows the shape, the declared text, and the variables' names, never a
/// resolved command or value.
#[derive(PartialEq, Eq)]
pub(crate) enum ChangeCommands<'a> {
    /// A command-step kind: its steps, and the working directory and environment they
    /// run in.
    Steps {
        /// Each step that runs, in order.
        steps: Vec<StepCommand<'a>>,
        /// A `script`'s `cwd` (verbatim) and its `env`, each value resolved; the default
        /// for every other kind. Never `elevated` — a `sudo` in a step's text is the
        /// step's own.
        options: RunOptions,
    },
    /// A `file`: its `validate`, when it declares one — as declared, and as it runs.
    File {
        /// The declared command and its resolved form.
        validate: Option<(&'a str, String)>,
    },
    /// A `build`: its `run`, and the `env` it runs with.
    Build {
        /// The resolved build command.
        run: String,
        /// The resolved environment.
        env: Vec<(String, String)>,
    },
    /// A kind that runs no command text holding a reference: `directory`, `link`,
    /// `verify`.
    None,
}

/// One step of a change, as the executor holds it. Its `Debug` shows the step's name
/// and no resolved text ([`StepAction`]'s).
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct StepCommand<'a> {
    /// How a failure names the step: a command's declared text in backticks, or a typed
    /// step's label (`PlanStep::summary`) — never a resolved value, and never the text
    /// of a constant script.
    pub(crate) name: String,
    /// What runs.
    pub(crate) action: StepAction<'a>,
}

/// What a step runs. Its `Debug` shows a put's command and the length of its text, and
/// no resolved command.
#[derive(PartialEq, Eq)]
pub(crate) enum StepAction<'a> {
    /// Command text, its references resolved.
    Run(String),
    /// The put script's command, and the text it installs on its stdin
    /// ([`Connection::run_put`]). Neither holds a reference.
    Put {
        /// The command that runs the put script.
        command: String,
        /// The text installed.
        content: &'a str,
    },
}

impl std::fmt::Debug for ChangeCommands<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Steps { steps, options } => f
                .debug_struct("Steps")
                .field("steps", steps)
                .field("options", options)
                .finish(),
            Self::File { validate } => f
                .debug_struct("File")
                .field(
                    "validate",
                    &validate.as_ref().map(|(declared, _)| (declared, Redacted)),
                )
                .finish(),
            Self::Build { run: _, env } => f
                .debug_struct("Build")
                .field("run", &Redacted)
                .field(
                    "env_names",
                    &env.iter()
                        .map(|(name, _)| name.as_str())
                        .collect::<Vec<_>>(),
                )
                .finish(),
            Self::None => f.write_str("None"),
        }
    }
}

impl std::fmt::Debug for StepAction<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Run(_) => f.debug_tuple("Run").field(&Redacted).finish(),
            Self::Put { command, content } => f
                .debug_struct("Put")
                .field("command", command)
                .field("content_len", &content.len())
                .finish(),
        }
    }
}

/// The [`StepCommand`] of one plan step, `None` for a note.
///
/// # Errors
/// Why the step can't run, naming it as a failure would.
fn step_command(step: &PlanStep, site: Advice) -> Result<Option<StepCommand<'_>>, String> {
    let Some(execution) = step.execution() else {
        return Ok(None);
    };
    let name = step.summary().map_or_else(
        || format!("`{}`", execution.text()),
        |summary| summary.label(),
    );
    let action = match execution {
        StepExecution::Command(text) => match resolve_command(&text) {
            Ok(resolved) => StepAction::Run(resolved),
            Err(error) => {
                return Err(format!(
                    "{name} was not run: {error}{}",
                    advice(&error, site)
                ));
            }
        },
        // Nothing resolves a reference in a put's path or its text: the text is
        // installed as the plan holds it, which is what detection compares against.
        // The fields this text is built from take no reference, by their type; a plan
        // that holds one anyway — or half of one — is refused here, before anything
        // runs.
        StepExecution::Put { command, content } => {
            if [command.as_str(), content]
                .into_iter()
                .any(zap_types::var_ref::holds_delimiter)
            {
                return Err(format!(
                    "{name} was not run: its path or its text holds a reference, which a \
                     file zap installs as written can't take"
                ));
            }
            StepAction::Put { command, content }
        }
    };
    Ok(Some(StepCommand { name, action }))
}

/// Resolve every reference in the command text `change` runs — the one place it happens,
/// shared by the wetrun preflight ([`refused_changes`]) and the executor (`run_change`),
/// so what one accepts the other runs.
///
/// Command text is a plan step — a `Run`'s own, or the command a typed step lowers to
/// (`PlanStep::execution`) — a `file`'s `validate`, a `build`'s `run`
/// ([`resolve_command`]); a put of text the plan holds resolves nothing, and is refused
/// if it holds a reference; a `build`'s and a `script`'s `env` values resolve as values
/// ([`resolve_env_value`]); a `database`'s role and database names are checked as the SQL
/// identifiers its `GRANT` makes of them ([`resolve_sql_identifier`]). A file's content,
/// a path, and a fetch url are not command text and aren't read here.
///
/// # Errors
/// Why the change can't run: the command (as declared), the variable whose value its
/// place can't take — never the value — and what to do about it there.
pub(crate) fn change_commands(change: &Change) -> Result<ChangeCommands<'_>, String> {
    let kind = &change.desired.kind;
    match kind {
        ResourceKind::File(file) => {
            let validate = file
                .validate
                .as_deref()
                .map(|validate| {
                    resolve_command(validate)
                        .map(|command| (validate, command))
                        .map_err(|error| {
                            format!(
                                "validate `{validate}` was not run, and the file was not \
                                 written: {error}{}",
                                advice(&error, Advice::ReadFromFile)
                            )
                        })
                })
                .transpose()?;
            // A template the executor would refuse to render stops the wetrun before
            // anything runs, as a command's refused value does.
            if let FileContent::Template(template) = &file.content {
                resolve_template(template).map_err(|error| {
                    format!("the template was not rendered, and the file was not written: {error}")
                })?;
            }
            Ok(ChangeCommands::File { validate })
        }
        ResourceKind::Build(build) => {
            let (run, env) = build_command(build)?;
            Ok(ChangeCommands::Build { run, env })
        }
        ResourceKind::Directory(_) | ResourceKind::Link(_) | ResourceKind::Verify(_) => {
            Ok(ChangeCommands::None)
        }
        ResourceKind::Package(_)
        | ResourceKind::AptRepo(_)
        | ResourceKind::Script(_)
        | ResourceKind::Installer(_)
        | ResourceKind::User(_)
        | ResourceKind::Service(_)
        | ResourceKind::Database(_)
        | ResourceKind::Swap(_)
        | ResourceKind::Firewall(_)
        | ResourceKind::Pipeline(_) => {
            if let ResourceKind::Database(database) = kind {
                for (field, name) in [
                    (ResolvedField::Username, &database.username),
                    (ResolvedField::DatabaseName, &database.database_name),
                ] {
                    resolve_sql_identifier(name)
                        .and_then(|value| {
                            UnsafeValue::held_to(field.as_str(), value, |value| {
                                resolved_field_problem(field, value)
                            })
                        })
                        .map_err(|error| {
                            format!(
                                "database `{field}` `{}` can't be used: {error}",
                                name.as_inert()
                            )
                        })?;
                }
                for (index, host) in database.auth_hosts().iter().enumerate() {
                    let field = format!("auth.hosts[{index}]");
                    resolve_field(host)
                        .and_then(|value| {
                            UnsafeValue::held_to(&field, value, |host| {
                                pg_hba_field_problem(host, PgHbaField::Host)
                            })
                        })
                        .map_err(|error| {
                            format!(
                                "database `{field}` `{}` can't be used: {error}",
                                host.as_inert()
                            )
                        })?;
                }
            }
            // A url handed to `curl` is held, as it resolved, to the rule for a url the
            // target fetches. (An `apt_repo` key is zap's own fetch, held to the rule
            // for those by the resolver.)
            let fetched = match kind {
                ResourceKind::Installer(installer) => Some(("installer", "url", &installer.url)),
                _ => None,
            };
            if let Some((what, field, url)) = fetched {
                resolve_field(url)
                    .and_then(|value| {
                        UnsafeValue::held_to(field, value, |url| {
                            fetch_url_problem(url, FetchSide::Target)
                        })
                    })
                    .map_err(|error| {
                        format!(
                            "{what} `{field}` `{}` can't be used: {error}",
                            url.as_inert()
                        )
                    })?;
            }
            // TODO(execution): a `pipeline` runs its steps flat — one `Run(step.run)` per
            // step, in declared order. Its `cwd` / `env` / `depends_on` /
            // `max_concurrency` aren't honored; the structural config gate
            // (`validate_config_structure`) rejects them at `zap plan`. Honor them
            // (intra-pipeline DAG via the layered scheduler, threaded `RunOptions`) and
            // relax the gate together when the scheduler lands.
            let site = match kind {
                ResourceKind::Script(_) => Advice::ScriptRun,
                ResourceKind::Pipeline(_) => Advice::ReadFromFile,
                _ => Advice::ZapCommand,
            };
            let steps = change
                .steps
                .iter()
                .filter_map(|step| step_command(step, site).transpose())
                .collect::<Result<Vec<_>, String>>()?;
            let options = match kind {
                ResourceKind::Script(script) => script_options(script)?,
                _ => RunOptions::default(),
            };
            Ok(ChangeCommands::Steps { steps, options })
        }
    }
}

/// Where a `build`'s `run` executes: its `cwd` when absolute, else that path under the
/// extracted source directory `source_dir` (the directory itself when no `cwd` is
/// declared). A relative path would otherwise be entered from wherever the connection
/// starts — the login home over SSH, zap's own directory locally.
fn build_cwd(cwd: Option<&str>, source_dir: &str) -> String {
    match cwd {
        Some(cwd) if cwd.starts_with('/') => cwd.to_owned(),
        Some(cwd) if !cwd.is_empty() => format!("{source_dir}/{cwd}"),
        _ => source_dir.to_owned(),
    }
}

/// The working directory and environment a `script`'s `run` executes in: its `cwd`,
/// verbatim, and its `env` with each value's references resolved as a value
/// quoted after it resolves ([`resolve_env_value`]), so `env` carries any value to the
/// command. The same `cwd` and values its `check` ran with.
///
/// # Errors
/// The change's failure, naming the `env` key and the variable whose value no
/// environment can carry.
fn script_options(script: &ScriptResource) -> Result<RunOptions, String> {
    let env = script
        .env
        .iter()
        .flatten()
        .map(|(name, value)| {
            resolve_env_value(value)
                .map(|value| (name.as_str().to_owned(), value))
                .map_err(|error| {
                    format!(
                        "`{}` was not run: env.{}: {error}",
                        script.run.as_inert(),
                        name.as_str()
                    )
                })
        })
        .collect::<Result<Vec<_>, String>>()?;
    Ok(RunOptions {
        cwd: script.cwd.as_ref().map(std::path::PathBuf::from),
        env,
    })
}

/// Where a refused value was bound for — which decides what an operator can do about it.
#[derive(Debug, Clone, Copy)]
enum Advice {
    /// A `build`'s `run`, which its `env` reaches.
    BuildRun,
    /// A `script`'s `run`, which its `env` reaches.
    ScriptRun,
    /// An operator's own command with no `env` of its own: a `validate`, a `pipeline`
    /// step.
    ReadFromFile,
    /// A command zap composes from a resource's fields.
    ZapCommand,
}

/// What to do about `error` at `site` — for a single quote, the one refusal with a way
/// around it; empty otherwise.
const fn advice(error: &UnsafeValue, site: Advice) -> &'static str {
    if !matches!(error, UnsafeValue::SingleQuote { .. }) {
        return "";
    }
    match site {
        Advice::BuildRun => {
            ". Pass it through this build's `env`, which is quoted after it resolves, or \
             have the command read it from a file"
        }
        Advice::ScriptRun => {
            ". Pass it through this script's `env`, which is quoted after it resolves, or \
             have the command read it from a file"
        }
        Advice::ReadFromFile => ". Have the command read it from a file",
        Advice::ZapCommand => {
            ". zap composes this command from the resource's fields, which can't take such \
             a value"
        }
    }
}

/// Every change of `plan` a wetrun would refuse to run, as `<resource id>: <why>` — the
/// wetrun preflight's finding, empty when every change's command text resolves.
///
/// It resolves exactly what the executor resolves, through the same function
/// (`change_commands`), over the whole plan and before any of it runs — so a value a
/// command can't take stops a wetrun with nothing changed, instead of failing the change
/// that holds it after the ones ahead of it ran.
#[must_use]
pub fn refused_changes(plan: &Plan) -> Vec<String> {
    plan.changes
        .iter()
        .filter_map(|change| {
            change_commands(change)
                .err()
                .map(|why| format!("`{}`: {why}", change.resource_id.0))
        })
        .collect()
}

/// Run a change's steps in order, concatenating their stdout. A command is composed
/// with `options` (a `script`'s `cwd` and `env`; the default for every other kind, which
/// leaves the step as it is) into the one script every connection runs
/// ([`Connection::run_composed`]); a put of text the plan holds runs the put script with
/// the text on its stdin ([`Connection::run_put`]). A non-zero exit fails the change
/// (and aborts the plan) — the `cd` into a working directory that can't be entered among
/// them: the step is not run anywhere else. `Note` steps are render-only previews and
/// aren't here.
///
/// Each command arrives resolved (`change_commands`): references resolved
/// **env-only** — `$HOME` / `~` are intentionally *not* expanded, so they expand in the
/// target shell (correct for the SSH phase, where the home is the remote's, not the
/// operator's; for native-fs *paths* the seam still uses the full
/// `expand_runtime_path`).
///
/// A resolved value is run but never echoed back — the error message names the step by
/// its [`StepCommand::name`] (a command as declared, references intact; a typed step by
/// its label, without its script), so a resolved secret can't surface through it. The
/// residual leak surface (a command's *own* stdout/stderr) is masked downstream:
/// `mask_outcomes` for the batch report and the `mask_handler` emission decorator for the
/// event stream, both reusing the run's `SecretMasker`.
async fn run_steps(
    conn: &Connection,
    steps: &[StepCommand<'_>],
    options: &RunOptions,
) -> Result<String, Failure> {
    let mut output = String::new();
    for StepCommand { name, action } in steps {
        let ran = match action {
            StepAction::Run(resolved) => conn.run_composed(resolved, options).await,
            // A put runs as the plan says and where its path says: no kind that plans
            // one has a working directory or an environment to run it in.
            StepAction::Put { .. } if *options != RunOptions::default() => {
                return Err(Failure::words(format!(
                    "internal: {name} was planned with a working directory"
                )));
            }
            StepAction::Put { command, content } => conn.run_put(command, content.as_bytes()).await,
        };
        // A connection-level failure (no shell exit code): classified by the error — a
        // spawn's io error by its kind, what `ssh` said by its words (e.g. "connection
        // refused" → transient).
        let result = ran?;
        if !result.success {
            // Classify from the real exit code + stderr, then report the step by its
            // name, so neither a resolved secret nor a script's text can
            // leak into the rendered failure.
            return Err(Failure::exited(
                &result.stderr,
                result.code,
                format!("{name} exited {}: {}", result.code, result.stderr.trim()),
            ));
        }
        output.push_str(&result.stdout);
    }
    Ok(output)
}

/// Resolve a kind's path fields for execution (the shared seam + target-home), or the
/// error to fail the change.
fn resolved_paths(conn: &Connection, desired: &Resource) -> crate::error::Result<ResolvedFields> {
    resolve_kind_fields(conn, &desired.kind)
}

/// Write a `file`: materialize content (`remote` fetches + copies/extracts verified
/// bytes; `source` reads the target; inline/template render purely) with its
/// mode/owner/group — set as part of the write for a file, and on the extracted
/// directory for a tar. A declared `validate` gates the write — see [`write_validated`].
///
/// The parent directory is created first when it is missing ([`Connection::make_dir`]),
/// each directory made given the owner and group of the nearest one that was there and
/// the creating user's default mode.
async fn execute_file(
    conn: &Connection,
    zap_home: Option<&Path>,
    desired: &Resource,
    file: &FileResource,
    validate: Option<(&str, String)>,
) -> Result<String, Failure> {
    let path = resolved_paths(conn, desired)?
        .take(ResolvedField::Path)
        .map_err(|error| Failure::words(error.to_string()))?;

    // Ensure the parent directory exists before writing — a `file` whose parent dir
    // isn't there would otherwise fail the write, forcing the author to declare a
    // `directory` resource just to hold it. `make_dir` is idempotent like `mkdir -p` (a
    // no-op when the parent is already present, e.g. declared as its own `directory`
    // and ordered via `depends_on`). The tar-extract branch creates its own target.
    if let Some(parent) = path
        .rfind('/')
        .map(|i| &path[..i])
        .filter(|p| !p.is_empty())
    {
        conn.make_dir(parent).await?;
    }

    match validate {
        Some((validate, command)) => {
            write_validated(conn, zap_home, &path, file, validate, &command).await
        }
        None => materialize_file(conn, zap_home, &path, file).await,
    }
}

/// The mode, owner, and group a `file` declares, with what it leaves unset kept from
/// what its path holds ([`Unset::Keep`]): an existing file's owner, group, and mode (less
/// any set-id or sticky bit), or for a new file its directory's owner and group.
fn declared_attrs(file: &FileResource) -> FileAttrs<'_> {
    FileAttrs {
        mode: file.mode.as_deref(),
        owner: file.owner.as_deref(),
        group: file.group.as_deref(),
        unset: Unset::Keep,
    }
}

/// Materialize a `file`'s content at the resolved `path` with its mode/owner/group,
/// returning the change summary. The unconditional half of [`execute_file`].
///
/// A regular file is installed whole — content, owner, and mode in one write
/// ([`Connection::write_file`] / [`Connection::place_file`]) — so no `chmod` or `chown`
/// follows it by name, and a change to the mode or owner alone rewrites the file the
/// same way. What the file leaves unset is kept from what `path` holds
/// ([`declared_attrs`]). An extracted tree's directory is set through
/// [`Connection::set_dir_attrs`], which refuses a symbolic link at `path`; one the
/// extraction made again for another pin already has the removed one's owner and mode.
async fn materialize_file(
    conn: &Connection,
    zap_home: Option<&Path>,
    path: &str,
    file: &FileResource,
) -> Result<String, Failure> {
    let attrs = declared_attrs(file);
    match &file.content {
        FileContent::Remote(RemoteContent {
            url,
            blake3,
            extract,
            auth,
        }) => {
            execute_file_remote(
                conn,
                zap_home,
                path,
                RemoteFetch {
                    url,
                    // The resolved pin — read straight from the (self-contained) plan
                    // fact: a vendored file's declared `blake3`, or a tracked file's lock
                    // pin already folded into `Change.desired` by `diff`'s `fold_tracked_pin`.
                    pin: blake3.as_deref(),
                    extract: *extract,
                    auth: auth.as_ref(),
                },
                attrs,
            )
            .await
        }
        FileContent::Source { path: source } => {
            let source_path = conn.apply_home(source)?;
            let content = conn.read_source(&source_path).await?;
            conn.write_bytes(path, &content, attrs).await?;
            Ok(format!("wrote {path}"))
        }
        FileContent::Inline { content } => {
            conn.write_file(path, content, attrs).await?;
            Ok(format!("wrote {path}"))
        }
        // Template values resolve references (operator env), refusing a value that would
        // add a line to the file; `~` / `$HOME` stay literal (content text, not a target
        // path).
        FileContent::Template(template) => {
            let content = resolve_template(template).map_err(|error| {
                Failure::words(format!(
                    "the template was not rendered, and the file was not written: {error}"
                ))
            })?;
            conn.write_file(path, &content, attrs).await?;
            Ok(format!("wrote {path}"))
        }
    }
}

/// Materialize a `file` whose `validate` command must pass, rolling back on failure.
///
/// Snapshot `path` ([`Connection::snapshot`]: bytes + mode/owner/group through one
/// descriptor, held in memory, so a secret-bearing file never gets a second copy on the
/// target), write, then run `validate` against the file in place — a config some larger file includes (an nginx site under
/// `sites-enabled/*`) can only be checked as part of the whole. If the write or the
/// check fails, restore the snapshot (or remove a file that didn't exist before) and
/// fail the change, so the service reload the file would trigger never runs. A failed
/// write that left the path as snapshotted restores nothing.
///
/// The rejected content is on disk between the write and the restore — one command's
/// round trip. A run killed inside that window leaves it there, and detection then
/// reads the file as converged, since its bytes match what was declared; a `verify`
/// running the same command is what surfaces that on the next plan.
///
/// `command` is `validate` with its operator references resolved like a command step's
/// (`change_commands`) — before the snapshot and the write, so a value the command
/// text can't take fails the change with the file untouched — and the error reports the
/// unresolved `validate` so a resolved secret can't surface through it.
async fn write_validated(
    conn: &Connection,
    zap_home: Option<&Path>,
    path: &str,
    file: &FileResource,
    validate: &str,
    command: &str,
) -> Result<String, Failure> {
    let snapshot = conn.snapshot(path).await?;
    let failure = match materialize_file(conn, zap_home, path, file).await {
        Ok(summary) => match run_validate(conn, validate, command).await {
            Ok(()) => return Ok(format!("{summary} (validated)")),
            Err(error) => error,
        },
        // A write that failed usually failed before its install (a fetch, a digest, an
        // owner not created yet): when the path still holds what was snapshotted, there
        // is nothing to roll back, and restoring would rewrite a file zap never touched.
        Err(error) => {
            if conn.snapshot(path).await.is_ok_and(|now| now == snapshot) {
                return Err(error.map_message(|error| format!("{error}; {path} was not changed")));
            }
            error
        }
    };
    match restore_snapshot(conn, path, file, snapshot).await {
        // what failed is the write or its check, whatever the rollback did
        Ok(restored) => Err(failure.map_message(|failure| format!("{failure}; {restored}"))),
        Err(error) => Err(failure.map_message(|failure| {
            format!(
                "{failure}; rollback failed, so {path} still holds the rejected content: {}",
                error.message
            )
        })),
    }
}

/// Run a `file`'s `validate` command — `command`, the declared `validate` with its
/// references resolved — `Err` carrying the unresolved command, its exit code, and its
/// output when it fails.
async fn run_validate(conn: &Connection, validate: &str, command: &str) -> Result<(), Failure> {
    let result = conn.run_default(command).await?;
    if result.success {
        return Ok(());
    }
    // `nginx -t` reports on stderr; fall back to stdout for a checker that doesn't.
    let output = if result.stderr.trim().is_empty() {
        result.stdout.trim()
    } else {
        result.stderr.trim()
    };
    Err(Failure::exited(
        output,
        result.code,
        format!("validate `{validate}` exited {}: {output}", result.code),
    ))
}

/// Put a [`Snapshot`] back at `path`, returning what was done for the change's failure
/// message. The previous bytes are installed in one write, like any other, with the
/// owner and group they had and their mode less any set-id or sticky bit the file's
/// declared mode doesn't carry ([`restored_mode`]).
async fn restore_snapshot(
    conn: &Connection,
    path: &str,
    file: &FileResource,
    snapshot: Snapshot,
) -> Result<String, Failure> {
    match snapshot {
        Snapshot::Absent => {
            conn.remove_file(path).await?;
            Ok(format!("removed the new {path}"))
        }
        Snapshot::File {
            mode,
            uid,
            gid,
            bytes,
        } => {
            let mode = format!("{:o}", restored_mode(mode, file.mode.as_deref()));
            let (owner, group) = (uid.to_string(), gid.to_string());
            let attrs = FileAttrs {
                mode: Some(&mode),
                owner: Some(&owner),
                group: Some(&group),
                ..FileAttrs::NONE
            };
            conn.write_bytes(path, &bytes, attrs).await?;
            Ok(format!("restored the previous {path}"))
        }
    }
}

/// The mode a rollback gives the bytes it restores: the mode they had, less any set-user-id,
/// set-group-id, or sticky bit the file's `declared` mode doesn't also carry. A file
/// someone made set-id while zap read it — or one the config never meant to be — isn't
/// made so again by root; a config that declares the bit keeps it.
fn restored_mode(observed: u32, declared: Option<&str>) -> u32 {
    let declared_special = declared
        .and_then(|mode| u32::from_str_radix(mode, 8).ok())
        .map_or(0, |mode| mode & 0o7000);
    observed & (0o777 | declared_special)
}

/// The resolved spec for materializing a `remote` file — what to fetch and how to
/// place it. Groups the `FileContent::Remote` fields (plus the resolved `pin`) so the
/// executor signature stays small.
struct RemoteFetch<'a> {
    /// Fetch location (still reference-bearing; resolved inside).
    url: &'a str,
    /// The resolved content pin from the plan fact's `Change.desired`: a vendored file's
    /// declared `blake3`, or a tracked file's lock pin already folded in by `diff`.
    /// `None` means a tracked file reached execution unfolded (an invariant error — the
    /// fact must be self-contained, so the fold runs before execution).
    pin: Option<&'a str>,
    /// How the fetched bytes are materialized (a tar variant carries its own
    /// `strip_components`).
    extract: ExtractMode,
    /// Optional fetch credential.
    auth: Option<&'a RemoteAuth>,
}

/// Materialize a `remote` file: resolve (fetch + verify) the content operator-side,
/// then push it to the target. `none` installs the verified file at `path` with
/// `attrs`; a tar archive is staged on the target and extracted into `path` — a
/// directory of its own, never through a symbolic link at `path` — its contents owned by
/// the extracting user, then the `.zap_remote_hash` sentinel (the pin) is recorded for
/// detection and `attrs` are set on the directory.
async fn execute_file_remote(
    conn: &Connection,
    zap_home: Option<&Path>,
    path: &str,
    fetch: RemoteFetch<'_>,
    attrs: FileAttrs<'_>,
) -> Result<String, Failure> {
    let RemoteFetch {
        url,
        pin,
        extract,
        auth,
    } = fetch;
    let Some(pin) = pin else {
        return Err(Failure::words(
            "tracked remote file reached execution with no pin (expected the lock \
                    resolve pass to mint one, or a declared `blake3` to vendor it)"
                .to_owned(),
        ));
    };
    let root = zap_home.ok_or_else(|| {
        Failure::words("no content-cache root for remote-file resolution".to_owned())
    })?;
    // The resolver resolves the url's references itself and names the declared form in
    // its errors.
    let resolved = resolver::resolve_content(root, url, Some(pin), auth, None).await?;
    let short = short_pin(pin);

    if extract.is_tar() {
        // Stage into a per-run private `mktemp -d` dir + extract (escalating — `path` is
        // often root-owned) + clean up on every exit path. See [`extract_remote_archive`].
        extract_remote_archive(conn, &resolved, path, extract, pin).await?;
        conn.set_dir_attrs(path, attrs).await?;
        Ok(format!("extracted {short} → {path}"))
    } else {
        // Final placement: `place_file` escalates per the two-tier rule (natively first
        // on `Local`, the `sudo` put for a root-owned `path` / over SSH), unlike
        // `copy_file` (the unprivileged `/tmp` staging primitive).
        conn.place_file(&resolved.path, path, attrs).await?;
        Ok(format!("fetched {short} → {path}"))
    }
}

/// Install an `apt_repo`'s signing key, ahead of its steps: resolve the bytes its pin
/// names on the operator's machine — the content cache's, or a fetch of `key_url` that
/// stops past [`KEY_READ_MAX`] — read them into memory once, check that they are at
/// most `KEY_READ_MAX` bytes and that their blake3 is the pin, and install exactly
/// those bytes at the key path, `644` `root:root` ([`APT_KEY_ATTRS`]).
///
/// The install is [`Connection::write_bytes`]'s: staged beside the key, checked against
/// the bytes' SHA-512, renamed over it. So the live key is replaced only by the pinned
/// bytes, and bytes that aren't the pin's fail the change with the key as it was,
/// naming both digests (the resolver's verification, or the check here).
async fn install_apt_key(
    conn: &Connection,
    zap_home: Option<&Path>,
    desired: &Resource,
    repo: &AptRepoResource,
) -> Result<String, Failure> {
    // The pin comes from the (self-contained) plan fact: a vendored key's declared
    // `key_blake3`, or a tracked key's lock pin folded in by `diff`'s `fold_tracked_pin`.
    let Some(pin) = repo.key_blake3.as_ref() else {
        return Err(Failure::words(
            "tracked apt_repo key reached execution with no pin (expected the lock resolve \
             pass to mint one, or a declared `key_blake3` to vendor it)"
                .to_owned(),
        ));
    };
    let root = zap_home.ok_or_else(|| {
        Failure::words("no content-cache root for apt_repo key resolution".to_owned())
    })?;
    let max = u64::from(KEY_READ_MAX);
    let resolved = resolver::resolve_content_within(
        root,
        &repo.key_url,
        Some(pin.as_str()),
        None,
        None,
        Some(max),
    )
    .await?;
    let key = read_key(&resolved.path, max).await?;
    let read = zap_types::scalar::ContentHash::of_bytes(&key);
    if read != *pin {
        return Err(Failure::words(format!(
            "content hash mismatch for {}: declared {pin}, read {read}",
            repo.key_url.as_inert()
        )));
    }
    let (key_path, _) = observe::apt_repo::paths(&desired.id.0, repo);
    if let Some(parent) = key_path
        .rfind('/')
        .map(|i| &key_path[..i])
        .filter(|p| !p.is_empty())
    {
        conn.make_dir(parent).await?;
    }
    conn.write_bytes(&key_path, &key, APT_KEY_ATTRS).await?;
    Ok(format!("installed key {} → {key_path}", short_pin(pin)))
}

/// The bytes at `path` (the content cache's copy of a key), refused past `max` bytes —
/// read at most one byte past it, so an oversized file is never read whole.
async fn read_key(path: &Path, max: u64) -> Result<Vec<u8>, Failure> {
    use tokio::io::AsyncReadExt as _;
    let unreadable = |error: std::io::Error| {
        Failure::words(format!("the signing key could not be read: {error}"))
    };
    let file = tokio::fs::File::open(path).await.map_err(unreadable)?;
    let mut key = Vec::new();
    file.take(max + 1)
        .read_to_end(&mut key)
        .await
        .map_err(unreadable)?;
    if key.len() as u64 > max {
        return Err(Failure::words(format!(
            "the signing key is larger than {max} bytes, which detection can't compare \
             against its pin; refusing to install it"
        )));
    }
    Ok(key)
}

/// Whether [`extract_archive`] may escalate to write a possibly root-owned `dest`.
///
/// `Escalate` — the `remote` **file** branch: `dest` is the resource's declared `path`
/// (often root-owned, e.g. `/opt/zig`), so the extract script runs under `sudo` —
/// unconditionally over SSH (the SSH file-op posture bakes `sudo`), as the operator
/// first and then under `sudo` over `Local` — matching the two-tier posture of the
/// sibling file ops (`write_file`, `place_file`, `make_dir`, …).
///
/// `Unprivileged` — the `build` branch: `dest` is `src` inside an ephemeral per-run
/// `mktemp -d` (`/tmp/zap-build-XXXXXX`) scratch dir, and the subsequent `build.run`
/// executes there as the unprivileged login user. Escalating there would create a
/// root-owned cwd the build then can't write, with no repair path — so it deliberately
/// stays unprivileged.
#[derive(Clone, Copy)]
enum ExtractPrivilege {
    Unprivileged,
    Escalate,
}

/// Stage a verified archive at `staged` on the target and extract it into `dest` via a
/// target-side `tar` (no xz/gz Rust dep; identical over `Local` and `Ssh`), then remove
/// the staged tarball. Callers place `staged` inside a per-run private [`stage_dir`]
/// (`0700`, connecting-user-owned), so the fixed `archive.<ext>` basename can't collide
/// or be pre-created by another user.
///
/// The extraction is the constant `zap_types::extract::EXTRACT_ARCHIVE` script: it
/// refuses a symbolic link at `dest`, extracts into a fresh private directory beside
/// it, held open, and swaps that into place, giving what it extracts to the user running
/// it — root under `sudo` — whatever owners the archive recorded, with no set-id bit and
/// nothing group- or world-writable. `replaces` is its pin argument: `Some(pin)` writes
/// the sentinel into the new tree and replaces a `dest` holding one, so a pin advance
/// leaves no file of the old archive; a `dest` zap didn't extract is replaced only when
/// empty, and otherwise refused.
/// This wrapper owns the copy + run IO and applies the `privilege` posture (see
/// [`ExtractPrivilege`] / [`run_extract`]).
async fn extract_archive(
    conn: &Connection,
    cached: &resolver::ResolvedContent,
    staged: &str,
    dest: &str,
    extract: ExtractMode,
    replaces: Option<&str>,
    privilege: ExtractPrivilege,
) -> Result<(), Failure> {
    // The staged tarball lands in the caller's per-run private staging dir (0700,
    // connecting-user-owned), so the push stays the unprivileged `copy_file`; only the
    // extract into `dest` may escalate. The script extracts only bytes whose SHA-512 is
    // the one the resolver read with the blake3 it verified, from a copy of its own.
    conn.copy_file(&cached.path, staged).await?;
    let command =
        |run_as| extract_archive_command(run_as, staged, dest, extract, replaces, &cached.sha512);
    let result = run_extract(
        conn,
        &command(RunAs::Caller),
        &command(RunAs::Root),
        privilege,
    )
    .await?;
    if !result.success {
        return Err(Failure::exited(
            &result.stderr,
            result.code,
            format!("extract failed: {}", result.stderr.trim()),
        ));
    }
    Ok(())
}

/// Run the extract script — `as_caller` with no `sudo`, `as_root` under it — per its
/// `privilege` posture. `Unprivileged` runs it as the caller (the build-scratch extract).
/// `Escalate` runs it as root: unconditionally over `Ssh` / `Mock` (the SSH file-op
/// posture bakes `sudo`; the mock records that form), and over `Local` as the operator
/// first, then under `sudo` when that attempt failed — unless the failure was the
/// script's own refusal (`REFUSED_EXIT`: a link at the destination, a missing tool),
/// which more privilege wouldn't change.
async fn run_extract(
    conn: &Connection,
    as_caller: &str,
    as_root: &str,
    privilege: ExtractPrivilege,
) -> crate::error::Result<CommandOutput> {
    match privilege {
        ExtractPrivilege::Unprivileged => conn.run_default(as_caller).await,
        ExtractPrivilege::Escalate => match conn {
            Connection::Local => {
                let plain = conn.run_default(as_caller).await?;
                if retries_as_root(&plain) {
                    conn.run_default(as_root).await
                } else {
                    Ok(plain)
                }
            }
            // Mock records the sudo-ful form here (matching the SSH posture), whereas the
            // put a mock records for a write is sudo-less. Both deliberate: a golden
            // fixture combining an escalated extract with a `write_file` / `place_file`
            // shows `sudo` on the extract but not the write.
            Connection::Ssh(_) | Connection::Mock(_) => conn.run_default(as_root).await,
        },
    }
}

/// Whether the operator's own attempt at the extract script is followed by one under
/// `sudo`: when it failed, and not by the script's own refusal — its verdict on what it
/// was asked or found, which root would be given too.
const fn retries_as_root(attempt: &CommandOutput) -> bool {
    !attempt.success && attempt.code != REFUSED_EXIT
}

/// Create a per-run **private** staging directory on the target via `mktemp -d`,
/// returning its path with surrounding whitespace trimmed (`mktemp` prints it with a
/// trailing newline).
///
/// `template` keeps a `zap-remote-`/`zap-build-` prefix for operator debuggability; the
/// trailing `XXXXXX` mktemp fills with randomness. The dir is `0700` and owned by the
/// **connecting user** (mktemp's default) — the security property: the unprivileged
/// `copy_file` stage can write into it, an escalated (root) extract still reads it, and
/// no other local user can pre-create the path to swap bytes between the copy and the
/// extract. A name derived from the pin would be guessable: the pin is public, committed
/// in `zap.lock`.
///
/// A name made per run can't be reconstructed by another run, so a hard crash (SIGKILL,
/// a dropped SSH connection) between here and [`cleanup_dir`] orphans a `0700` dir that
/// no run reclaims — left to the OS `/tmp` reaper.
///
/// # Errors
/// The `mktemp` stderr when it exits non-zero (an expected per-change [`Failure`]).
async fn stage_dir(conn: &Connection, template: &str) -> Result<String, Failure> {
    let result = conn
        .run_default(&format!("mktemp -d -- {}", single_quote(template)))
        .await?;
    if !result.success {
        return Err(Failure::exited(
            &result.stderr,
            result.code,
            format!("mktemp failed: {}", result.stderr.trim()),
        ));
    }
    Ok(result.stdout.trim().to_owned())
}

/// Best-effort removal of a [`stage_dir`] staging directory — issued on **every** exit
/// path of a materialization (success or any failure), so a failed copy, extract, or
/// build leaves no private staging tree behind. A removal failure is ignored: the dir is
/// `0700` and short-lived, so a rare leak is a cosmetic annoyance, not a correctness or
/// security problem.
async fn cleanup_dir(conn: &Connection, dir: &str) {
    let _ = conn
        .run_default(&format!("rm -rf -- {}", single_quote(dir)))
        .await;
}

/// Materialize a `remote` **file** archive: stage it into a per-run private
/// [`stage_dir`], extract into `dest` (escalating — `dest` is often root-owned) with the
/// [`extract_provenance`] of `pin` and `extract` for its extract sentinel, and
/// [`cleanup_dir`] the staging dir on **every** exit path (success or a failed extract).
/// The private dir carries the randomness, so the staged tarball takes a fixed
/// `archive.<ext>` basename inside it.
///
/// The extract script writes the sentinel into the new tree before swapping it in, so a
/// tree is never in place without it; an extraction that fails before the swap leaves
/// `dest` as it was, and the next pass plans the same change again.
///
/// # Errors
/// The `mktemp` / extract [`Failure`]; cleanup runs before it returns either way.
async fn extract_remote_archive(
    conn: &Connection,
    cached: &resolver::ResolvedContent,
    dest: &str,
    extract: ExtractMode,
    pin: &str,
) -> Result<(), Failure> {
    let provenance = extract_provenance(pin, extract);
    let dir = stage_dir(conn, "/tmp/zap-remote-XXXXXX").await?;
    let staged = format!("{dir}/archive.{ext}", ext = extract.format_str());
    let extracted = extract_archive(
        conn,
        cached,
        &staged,
        dest,
        extract,
        Some(&provenance),
        ExtractPrivilege::Escalate,
    )
    .await;
    cleanup_dir(conn, &dir).await;
    extracted
}

/// Build a `build` resource — `run` and `env` being its command and environment with
/// their references resolved ([`build_command`], before anything is fetched or staged):
/// resolve + verify its source operator-side (the resolver
/// runs minisign at fetch), extract it into an ephemeral build dir on the target, run
/// the build command, assert `output` appeared, and write the provenance sidecar
/// (`<output>.zap-build`: the digest of the source pin and how it is built,
/// [`build_provenance`]) that detection
/// compares against. The private
/// staging dir is removed on every exit path. zap owns source + provenance; the `run`
/// command owns the build + install (e.g. `zig build -p $HOME/.local`).
async fn execute_build(
    conn: &Connection,
    zap_home: Option<&Path>,
    desired: &Resource,
    build: &BuildResource,
    run: &str,
    env: Vec<(String, String)>,
) -> Result<String, Failure> {
    let output = resolved_paths(conn, desired)?
        .take(ResolvedField::Output)
        .map_err(|error| Failure::words(error.to_string()))?;
    let root = zap_home.ok_or_else(|| {
        Failure::words("no content-cache root for build source resolution".to_owned())
    })?;

    let BuildSource::Remote(RemoteSource {
        url,
        extract,
        auth,
        verify,
        blake3,
    }) = &build.source;

    // The resolved pin comes from the (self-contained) plan fact: a vendored source's
    // declared `blake3`, or a tracked source's lock pin already folded into
    // `Change.desired` by `diff`'s `fold_tracked_pin`.
    let Some(pin) = blake3.as_deref() else {
        return Err(Failure::words(
            "tracked build source reached execution unfolded (expected `diff` to fold the \
             lock pin into the plan fact, or a declared `blake3` to vendor it)"
                .to_owned(),
        ));
    };

    // Resolve + verify the source (operator-side; minisign runs in the resolver on a
    // cache-miss fetch), then stage + extract into a fresh ephemeral build dir.
    let resolved =
        resolver::resolve_content(root, url, Some(pin), auth.as_ref(), verify.as_ref()).await?;

    // Per-run private staging dir (`mktemp -d`, `0700`, connecting-user-owned): no other
    // local user can pre-create the path and swap bytes under the unprivileged build
    // extract. `mktemp` mints a fresh empty dir, so nothing is cleared first.
    let build_dir = stage_dir(conn, "/tmp/zap-build-XXXXXX").await?;
    let staged = format!("{build_dir}/archive.{ext}", ext = extract.format_str());
    // The source is extracted into a name not yet there beside the archive: the extract
    // script replaces only an absent or empty destination it didn't extract.
    let source_dir = format!("{build_dir}/src");

    // Run the fallible body, then remove the staging dir on **every** exit path (success
    // or any failure). The inner async block captures the locals and yields the change
    // result; cleanup issues after.
    let outcome: Result<String, Failure> = async {
        // No pin: the build owns provenance via the `<output>.zap-build` sidecar.
        // `Unprivileged`: `build_dir` is an ephemeral scratch whose subsequent `build.run`
        // executes as the login user — a `sudo` extract would leave it a root-owned cwd
        // the build can't write, with no repair path.
        extract_archive(
            conn,
            &resolved,
            &staged,
            &source_dir,
            *extract,
            None,
            ExtractPrivilege::Unprivileged,
        )
        .await?;

        // Run the build in its cwd, under the extracted source dir unless absolute. A
        // reference resolves env-only; `$HOME` / `~` stay for the target shell, so
        // `-p $HOME/.local` expands target-side.
        let cwd = build_cwd(build.cwd.as_deref(), &source_dir);
        let opts = RunOptions {
            cwd: Some(std::path::PathBuf::from(cwd)),
            env,
        };
        let result = conn.run_composed(run, &opts).await?;
        if !result.success {
            return Err(build_failed(build, &result));
        }

        // The build must have produced `output` — a `run`/`output` mismatch shouldn't
        // silently write a sidecar that detection would then read as converged.
        if !conn.exists(&output).await? {
            return Err(Failure::words(format!(
                "build ran but produced no output at {output} (check `run` / `output`)"
            )));
        }

        // Record provenance next to the output: the digest of the source pin and how it
        // is built, which detection compares against.
        let sidecar = observe::build::sidecar_path(&output);
        let provenance = build_provenance(pin, build);
        conn.write_file(&sidecar, &provenance, FileAttrs::NONE)
            .await?;

        let short = short_pin(pin);
        Ok(format!("built {short} → {output}"))
    }
    .await;

    // Remove the private staging dir (best-effort) on every exit path.
    cleanup_dir(conn, &build_dir).await;
    outcome
}

/// The failure of a `build` whose `run` exited non-zero, classified by its exit code and
/// stderr. It names the unresolved `run`, not the resolved form, so a secret can't leak.
fn build_failed(build: &BuildResource, result: &CommandOutput) -> Failure {
    Failure::exited(
        &result.stderr,
        result.code,
        format!(
            "build `{}` exited {}: {}",
            build.run.as_inert(),
            result.code,
            result.stderr.trim()
        ),
    )
}

/// A `build`'s `run` and `env` with their references resolved: `run` as command
/// text ([`resolve_command`]), each `env` value as a value quoted — or set on the process
/// — after it resolves ([`resolve_env_value`]), so `env` carries any value to the build.
///
/// # Errors
/// The change's failure, naming the variable whose value its place can't take.
fn build_command(build: &BuildResource) -> Result<(String, Vec<(String, String)>), String> {
    let not_run = |error: String| format!("build `{}` was not run: {error}", build.run.as_inert());
    let run = resolve_command(&build.run)
        .map_err(|error| not_run(format!("{error}{}", advice(&error, Advice::BuildRun))))?;
    let env = build
        .env
        .iter()
        .flatten()
        .map(|(name, value)| {
            resolve_env_value(value)
                .map(|value| (name.as_str().to_owned(), value))
                .map_err(|error| not_run(format!("env.{}: {error}", name.as_str())))
        })
        .collect::<Result<Vec<_>, String>>()?;
    Ok((run, env))
}

/// Create a `directory` (and parents), then set its mode/owner/group — on the directory
/// itself: a symbolic link at `path` fails the change rather than being followed. A
/// directory made here, the leaf included, takes the owner and group of the nearest one
/// that was there ([`Connection::make_dir`]), so what the resource leaves unset is
/// inherited; what it declares is then set.
async fn execute_directory(
    conn: &Connection,
    desired: &Resource,
    dir: &DirectoryResource,
) -> Result<String, Failure> {
    let path = resolved_paths(conn, desired)?
        .take(ResolvedField::Path)
        .map_err(|error| Failure::words(error.to_string()))?;
    conn.make_dir(&path).await?;
    let attrs = FileAttrs {
        mode: dir.mode.as_deref(),
        owner: dir.owner.as_deref(),
        group: dir.group.as_deref(),
        ..FileAttrs::NONE
    };
    conn.set_dir_attrs(&path, attrs).await?;
    Ok(format!("created directory {path}"))
}

/// Create (or repoint) a `link`'s symlink.
async fn execute_link(conn: &Connection, desired: &Resource) -> Result<String, Failure> {
    let mut fields = resolved_paths(conn, desired)?;
    let path = fields
        .take(ResolvedField::Path)
        .map_err(|error| Failure::words(error.to_string()))?;
    let target = fields
        .take(ResolvedField::Target)
        .map_err(|error| Failure::words(error.to_string()))?;
    conn.make_symlink(&target, &path).await?;
    Ok(format!("linked {path} -> {target}"))
}

/// Run every assertion of a `verify` resource, one command each, returning the
/// human-readable failures (empty = all passed).
///
/// Each assertion's command ([`verify::assertion_command`]) and the reading of its exit
/// status and stdout ([`verify::assertion_failure`]) are the ones detection batches
/// (`verify::queries` / `verify::interpret`), so detect-time and apply-time assertions
/// can't mean different things. Each runs as the connecting user, with no `sudo`, as
/// detection runs it.
///
/// # Errors
/// Propagates a connection error running an assertion's command.
async fn verify_failures(
    conn: &Connection,
    assertions: &[VerifyAssertion],
) -> crate::error::Result<Vec<String>> {
    let mut failures = Vec::new();
    for assertion in assertions {
        let result = conn
            .run_default(&verify::assertion_command(assertion))
            .await?;
        failures.extend(verify::assertion_failure(
            assertion,
            result.code,
            result.stdout.as_bytes(),
        ));
    }
    Ok(failures)
}

/// Re-run a `verify`'s assertions (the safety gate). All pass → completed; any fail
/// → the change fails and the plan aborts.
async fn execute_verify(
    conn: &Connection,
    assertions: &[VerifyAssertion],
) -> Result<String, Failure> {
    let failures = verify_failures(conn, assertions).await?;
    if failures.is_empty() {
        Ok(format!("{} assertion(s) passed", assertions.len()))
    } else {
        Err(Failure::words(format!(
            "verify failed: {}",
            failures.join("; ")
        )))
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use zap_types::config_hash::extract_provenance;

    use zap_types::error_code::ErrorCode;
    use zap_types::plan::{Change, Plan, PlanStep};
    use zap_types::put::FileAttrs;
    use zap_types::schema::{BuildResource, ExtractMode, Resource, Target};
    use zap_types::shell::single_quote;
    use zap_types::text::Text;
    use zap_types::var_ref::Segment::{Ref, Text as Lit};
    use zap_types::var_ref::{marker, shown};

    use super::{
        ChangeCommands, ExtractPrivilege, Failure, RunAs, StepAction, StepCommand, arm_pending,
        build_command, build_failed, change_commands, extract_archive, extract_remote_archive,
        refused_changes, retries_as_root, run_change, run_steps, run_validate, stage_dir,
        write_validated,
    };
    use crate::connection::{CommandOutput, Connection, MockConnection, RunOptions, SshConnection};
    use crate::test_support::local_machine;

    /// Each step as its name and the text it runs — a put's command, then `<<<` and its
    /// text — for a comparison whose failure shows the text, which a step's `Debug` doesn't.
    fn shown_steps(steps: &[StepCommand<'_>]) -> Vec<(String, String)> {
        steps
            .iter()
            .map(|step| {
                let text = match &step.action {
                    StepAction::Run(text) => text.clone(),
                    StepAction::Put { command, content } => format!("{command} <<< {content}"),
                };
                (step.name.clone(), text)
            })
            .collect()
    }

    /// A run's directory and environment, for a comparison whose failure shows the values,
    /// which its `Debug` doesn't.
    fn shown_options(options: &RunOptions) -> (Option<std::path::PathBuf>, Vec<(String, String)>) {
        (options.cwd.clone(), options.env.clone())
    }

    const fn ok_output() -> CommandOutput {
        CommandOutput {
            success: true,
            code: 0,
            stdout: String::new(),
            stderr: String::new(),
        }
    }

    /// A successful command whose captured stdout is `stdout` (e.g. an `mktemp -d` path).
    fn stdout_output(stdout: &str) -> CommandOutput {
        CommandOutput {
            success: true,
            code: 0,
            stdout: stdout.to_owned(),
            stderr: String::new(),
        }
    }

    /// A failed command (exit 1) carrying `stderr`.
    fn failed_output(stderr: &str) -> CommandOutput {
        CommandOutput {
            success: false,
            code: 1,
            stdout: String::new(),
            stderr: stderr.to_owned(),
        }
    }

    /// A change for `desired` (a resource's JSON) running `steps`.
    fn change(desired: serde_json::Value, steps: Vec<PlanStep>) -> Change {
        let desired: Resource = serde_json::from_value(desired).unwrap();
        Change {
            resource_id: desired.id.clone(),
            action: zap_types::plan::ChangeAction::Create,
            steps,
            desired,
            depends_on: Vec::new(),
            trigger: None,
        }
    }

    /// The command text a step runs.
    fn ran<'a>(step: &'a StepCommand<'_>) -> &'a str {
        match &step.action {
            StepAction::Run(text) | StepAction::Put { command: text, .. } => text,
        }
    }

    fn script_change(steps: Vec<PlanStep>) -> Change {
        change(
            serde_json::json!({"id": "s", "type": "script", "check": "false", "run": "x"}),
            steps,
        )
    }

    /// A step's reference that resolves to a value holding a single quote fails the
    /// change before any of its steps runs, naming the variable and never the value —
    /// the executor's own refusal, with no preflight ahead of it.
    #[tokio::test]
    async fn a_step_whose_value_holds_a_single_quote_is_not_run() {
        let _env = crate::resolve::test_env::set(&[("ZAP_T_ROLE", "app'; touch pwned; '")]);
        let conn = Connection::Mock(MockConnection::new("m").with("true", ok_output()));
        let change = script_change(vec![
            PlanStep::run("true"),
            PlanStep::run(format!(
                "sudo -u postgres createuser -- '{}'",
                marker("ZAP_T_ROLE")
            )),
            PlanStep::run("true"),
        ]);
        let error = run_change(&conn, None, &change).await.unwrap_err().message;
        assert!(
            error.contains(&format!("`{}`", shown("ZAP_T_ROLE"))),
            "{error}"
        );
        assert!(error.contains("was not run"), "{error}");
        assert!(!error.contains("pwned"), "{error}");
        let Connection::Mock(mock) = &conn else {
            unreachable!()
        };
        // Nothing of the change reached the connection — not the step ahead of it.
        assert!(mock.issued_commands().is_empty());
    }

    /// A typed step whose reference resolves to a value its command can't take is
    /// refused under its own name: the refusal holds neither the value nor the script.
    #[test]
    fn a_refused_typed_step_is_named_without_its_script() {
        let _env = crate::resolve::test_env::set(&[("ZAP_T_ROLE", "app'; touch pwned; '")]);
        let rule: PlanStep = serde_json::from_value(serde_json::json!({"pg_hba_rule": {
            "database": "app", "user": marker("ZAP_T_ROLE"), "host": "::1/128", "method": "scram-sha-256",
        }}))
        .unwrap();
        let change = change(
            serde_json::json!({"id": "db", "type": "database", "engine": "postgresql",
                "database_name": "app", "username": "app"}),
            vec![PlanStep::run("true"), rule],
        );
        let error = change_commands(&change).unwrap_err();
        assert!(
            error.starts_with(&format!(
                "pg_hba rule: host    app    {}    ::1/128    scram-sha-256 (as postgres, in the \
                 server's hba_file, above its first host record, unless it is already there; an \
                 added rule reloads the server's configuration) was not \
                 run: ",
                marker("ZAP_T_ROLE")
            )),
            "{error}"
        );
        assert!(
            error.contains(&format!("`{}`", shown("ZAP_T_ROLE"))),
            "{error}"
        );
        for gone in ["pwned", "/proc/self/fd", "mktemp", "SHOW hba_file"] {
            assert!(!error.contains(gone), "{gone}: {error}");
        }
    }

    /// An `installer`'s change as the planner makes it, with the url and shell given.
    fn installer_change(url: &str, shell: &str) -> Change {
        use zap_types::plan::{DiffInputs, diff};
        use zap_types::text::Text;

        let resource: Resource = serde_json::from_value(serde_json::json!({
            "id": "tool", "type": "installer", "check": "/opt/tool",
            "url": Text::from_inert(url.to_owned()).unwrap(),
            "shell": Text::from_inert(shell.to_owned()).unwrap(),
        }))
        .unwrap();
        diff(DiffInputs {
            resources: std::slice::from_ref(&resource),
            detected: &[(resource.id.clone(), zap_types::detected::Detection::Absent)].into(),
            target: &Target::local(),
            machine: &local_machine(),
            lock: None,
            pending: &std::collections::BTreeMap::new(),
            var: &zap_types::last_run::ReportVar::unset,
        })
        .plan
        .changes
        .remove(0)
    }

    /// An installer's step runs its fetch with the references of its url and shell
    /// resolved, and a failure of it is named by the url as declared and the shell —
    /// never by the fetch's own text, and never by a resolved value.
    #[tokio::test]
    async fn a_failed_installer_step_is_named_by_its_url_as_declared() {
        let _env = crate::resolve::test_env::set(&[("ZAP_T_MIRROR", "mirror.example.com")]);
        let change = installer_change(
            &format!("https://{}/install.sh", marker("ZAP_T_MIRROR")),
            "sh -s -- --yes",
        );
        let ChangeCommands::Steps { steps, .. } = change_commands(&change).unwrap() else {
            panic!("an installer's commands");
        };
        let fetch = "zap_s=$(curl --proto '=https' --proto-redir '=https' -fsSL -- \
                     'https://mirror.example.com/install.sh') || exit; \
                     [ -n \"$zap_s\" ] || { echo 'zap: the installer script is empty' >&2; exit 1; }; \
                     printf '%s\\n' \"$zap_s\" | sh -s -- --yes";
        let name = format!(
            "run the script fetched from https://{}/install.sh (piped to sh -s -- --yes)",
            marker("ZAP_T_MIRROR")
        );
        assert_eq!(shown_steps(&steps), [(name.clone(), fetch.to_owned())]);
        let conn = Connection::Mock(MockConnection::new("m").with(
            fetch,
            CommandOutput {
                success: false,
                code: 22,
                stdout: String::new(),
                stderr: "curl: (22) The requested URL returned error: 404\n".to_owned(),
            },
        ));
        let error = run_change(&conn, None, &change).await.unwrap_err().message;
        assert_eq!(
            error,
            format!("{name} exited 22: curl: (22) The requested URL returned error: 404")
        );
    }

    /// An installer's shell is command text: a reference in it that resolves to a value
    /// holding a single quote refuses the step under its name, with neither the value
    /// nor the fetch's text.
    #[test]
    fn a_refused_installer_step_is_named_without_its_fetch() {
        let _env = crate::resolve::test_env::set(&[("ZAP_T_CHANNEL", "x'; touch pwned; '")]);
        let change = installer_change(
            "https://e.x/install.sh",
            &format!("sh -s -- {}", marker("ZAP_T_CHANNEL")),
        );
        let error = change_commands(&change).unwrap_err();
        assert!(
            error.starts_with(&format!(
                "run the script fetched from https://e.x/install.sh (piped to sh -s -- {}) was \
                 not run: ",
                marker("ZAP_T_CHANNEL")
            )),
            "{error}"
        );
        assert!(
            error.contains(&format!("`{}`", shown("ZAP_T_CHANNEL"))),
            "{error}"
        );
        for gone in ["pwned", "zap_s", "curl", "printf"] {
            assert!(!error.contains(gone), "{gone}: {error}");
        }
    }

    /// A put of text the plan holds resolves nothing: the executor holds the put
    /// script's command and the text, and what it sends is the text behind its SHA-512.
    #[test]
    fn a_text_put_holds_its_command_and_its_text_unresolved() {
        use zap_types::put::{PutCheck, file_put_command};

        // Set, so a resolution of the text would show.
        let _env = crate::resolve::test_env::set(&[("ZAP_T_KEY", "resolved")]);
        let put = |content: &str| -> PlanStep {
            serde_json::from_value(serde_json::json!({"put": {
                "path": "/etc/sudoers.d/deploy", "run_as": "root", "check": "sudoers",
                "source": {"text": {"mode": "440", "content": content}},
            }}))
            .unwrap()
        };
        let user = serde_json::json!({"id": "u", "type": "user", "username": "deploy"});
        let line = "deploy ALL=(ALL) NOPASSWD: /bin/kill $$\n";
        let change = change(user, vec![put(line), PlanStep::note("a note")]);
        let ChangeCommands::Steps { steps, options } = change_commands(&change).unwrap() else {
            panic!("a user's commands");
        };
        assert_eq!(
            shown_options(&options),
            shown_options(&RunOptions::default())
        );
        assert_eq!(
            shown_steps(&steps),
            [(
                "put /etc/sudoers.d/deploy (mode 440, as root, checked by visudo)".to_owned(),
                format!(
                    "{} <<< {line}",
                    file_put_command(
                        RunAs::Root,
                        "/etc/sudoers.d/deploy",
                        FileAttrs::mode("440"),
                        PutCheck::Sudoers,
                    )
                ),
            )]
        );
        assert_eq!(
            crate::connection::put_payload(line.as_bytes()),
            format!("{}\n{line}", crate::digest::sha512_hex(line.as_bytes())).into_bytes()
        );

        // A reference in the text is refused, not resolved and not installed as written.
        let referenced = change_commands(&Change {
            steps: vec![put(&format!("deploy ALL=(ALL) {}\n", marker("ZAP_T_KEY")))],
            ..change
        })
        .unwrap_err();
        assert_eq!(
            referenced,
            "put /etc/sudoers.d/deploy (mode 440, as root, checked by visudo) was not run: \
             its path or its text holds a reference, which a file zap installs as written \
             can't take"
        );
        assert!(!referenced.contains("resolved"));
    }

    /// A reference in a text put's path is refused as one in its text is: the put's
    /// command is run as the plan holds it.
    #[test]
    fn a_text_put_whose_path_holds_a_reference_is_refused() {
        let _env = crate::resolve::test_env::set(&[("ZAP_T_NAME", "resolved")]);
        let put: PlanStep = serde_json::from_value(serde_json::json!({"put": {
            "path": format!("/etc/sudoers.d/{}", marker("ZAP_T_NAME")), "run_as": "root",
            "check": "sudoers",
            "source": {"text": {"mode": "440", "content": "deploy ALL=(ALL) ALL\n"}},
        }}))
        .unwrap();
        let change = change(
            serde_json::json!({"id": "u", "type": "user", "username": "deploy"}),
            vec![put],
        );
        assert_eq!(
            change_commands(&change).unwrap_err(),
            format!(
                "put /etc/sudoers.d/{} (mode 440, as root, checked by visudo) was not run: its \
                 path or its text holds a reference, which a file zap installs as written \
                 can't take",
                marker("ZAP_T_NAME")
            )
        );
    }

    /// The executor hands a put the text the step holds: the put script, run for real
    /// as the test's own user, installs exactly those bytes — blank lines, trailing
    /// spaces, and shell text included — at the step's mode. A put handed a working
    /// directory runs nothing.
    #[tokio::test]
    async fn a_put_step_installs_exactly_the_text_it_holds() {
        use std::os::unix::fs::PermissionsExt as _;
        use zap_types::put::{PutCheck, file_put_command};

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("installed");
        let content = "first line  \n\n\tit's $HOME `id` \\n $$ last, spaces after  \n\n";
        let steps = [StepCommand {
            name: "put the file".to_owned(),
            action: StepAction::Put {
                command: file_put_command(
                    RunAs::Caller,
                    path.to_str().unwrap(),
                    FileAttrs::mode("640"),
                    PutCheck::None,
                ),
                content,
            },
        }];

        let refused = run_steps(
            &Connection::Local,
            &steps,
            &RunOptions {
                cwd: Some(dir.path().to_path_buf()),
                ..RunOptions::default()
            },
        )
        .await
        .unwrap_err()
        .message;
        assert_eq!(
            refused,
            "internal: put the file was planned with a working directory"
        );
        assert!(!path.exists());

        let output = run_steps(&Connection::Local, &steps, &RunOptions::default())
            .await
            .unwrap();
        assert_eq!(output, "");
        assert_eq!(std::fs::read(&path).unwrap(), content.as_bytes());
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o7777,
            0o640
        );
    }

    /// The plan of a `user` with keys and a grant: the text each put sends is the text
    /// detection compares the target's file against.
    #[test]
    fn a_users_puts_send_the_text_detection_compares() {
        use zap_types::schema::{ResourceKind, SudoMode, UserSudo, build_sudoers_content};

        let resource: Resource = serde_json::from_value(serde_json::json!({
            "id": "u", "type": "user", "username": "deploy",
            "ssh_keys": {"keys": ["ssh-ed25519 AAAA one", "ssh-rsa BBBB two"]},
            "sudo": {"mode": "nopasswd", "commands": ["/bin/a", "/bin/b"]},
        }))
        .unwrap();
        let ResourceKind::User(user) = &resource.kind else {
            unreachable!()
        };
        let Some((mode, scope)) = user.sudo.as_ref().and_then(UserSudo::grant) else {
            panic!("a grant");
        };
        let detected = std::collections::BTreeMap::from([(
            resource.id.clone(),
            zap_types::detected::Detection::Absent,
        )]);
        let plan = zap_types::plan::diff(zap_types::plan::DiffInputs {
            resources: std::slice::from_ref(&resource),
            detected: &detected,
            target: &Target::local(),
            machine: &local_machine(),
            lock: None,
            pending: &std::collections::BTreeMap::new(),
            var: &zap_types::last_run::ReportVar::unset,
        })
        .plan;
        let ChangeCommands::Steps { steps, .. } = change_commands(&plan.changes[0]).unwrap() else {
            panic!("a user's commands");
        };
        let sent: Vec<(&str, &str)> = steps
            .iter()
            .filter_map(|step| match &step.action {
                StepAction::Put { command, content } => Some((command.as_str(), *content)),
                StepAction::Run(_) => None,
            })
            .collect();
        let [(keys_put, keys), (sudoers_put, sudoers)] = sent.as_slice() else {
            panic!("two puts: {steps:?}");
        };
        assert!(
            keys_put.starts_with("sudo -u 'deploy' sh -c '"),
            "{keys_put}"
        );
        assert!(sudoers_put.starts_with("sudo sh -c '"), "{sudoers_put}");
        assert_eq!(*keys, "ssh-ed25519 AAAA one\nssh-rsa BBBB two\n");
        assert_eq!(*sudoers, build_sudoers_content(&user.username, mode, scope));
        assert_eq!(mode, SudoMode::Nopasswd);
        assert_eq!(*sudoers, "deploy ALL=(ALL) NOPASSWD: /bin/a, /bin/b\n");
    }

    /// A native file operation that fails on the local connection carries the code of
    /// its io error's kind, whatever its message says: a copy from a source that isn't
    /// there is not found, and a directory below a regular file has something in its
    /// way. The messages are the ones the errors always printed.
    #[tokio::test]
    async fn a_native_failure_is_classified_by_its_io_error() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("plain");
        std::fs::write(&file, "x").unwrap();
        let missing = dir.path().join("missing");
        let at = |path: &Path| path.to_string_lossy().into_owned();

        let copy = change(
            serde_json::json!({"id": "copy", "type": "file", "path": at(&dir.path().join("out")),
                "content": {"type": "source", "path": at(&missing)}}),
            Vec::new(),
        );
        let Failure { code, message } = run_change(&Connection::Local, None, &copy)
            .await
            .unwrap_err();
        assert_eq!(code, ErrorCode::NotFound, "{message}");
        assert_eq!(
            message,
            format!(
                "failed to read file {}: there is no file there",
                at(&missing)
            )
        );

        let below = change(
            serde_json::json!({"id": "below", "type": "directory",
                "path": at(&file.join("sub"))}),
            Vec::new(),
        );
        let Failure { code, message } = run_change(&Connection::Local, None, &below)
            .await
            .unwrap_err();
        assert_eq!(code, ErrorCode::Conflict, "{message}");
        assert!(
            message.starts_with(&format!("failed to mkdir {}: ", at(&file.join("sub")))),
            "{message}"
        );
    }

    /// A `source` is read through the snapshot script: its bytes arrive raw (a binary
    /// source is copied whole), and a symbolic link at the source — to a file the
    /// connecting user may read or not — and anything that isn't a regular file (a
    /// device read whole would never end) are refused with nothing written.
    #[tokio::test]
    async fn a_source_is_copied_raw_and_only_from_a_regular_file() {
        let dir = crate::test_scratch::tempdir();
        let at = |name: &str| dir.path().join(name).to_string_lossy().into_owned();
        let binary = b"\0\xff\n\x80 not utf-8 \xc3";
        std::fs::write(at("binary"), binary).unwrap();
        std::os::unix::fs::symlink(at("binary"), at("link")).unwrap();
        let copy = |source: &str, out: &str| {
            change(
                serde_json::json!({"id": out, "type": "file", "path": at(out),
                    "content": {"type": "source", "path": source}}),
                Vec::new(),
            )
        };
        run_change(&Connection::Local, None, &copy(&at("binary"), "out"))
            .await
            .unwrap();
        assert_eq!(std::fs::read(at("out")).unwrap(), binary);
        for (source, refusal) in [
            (at("link"), "a symbolic link is not read through"),
            ("/dev/zero".to_owned(), "not a regular file"),
        ] {
            let Failure { message, .. } =
                run_change(&Connection::Local, None, &copy(&source, "refused"))
                    .await
                    .unwrap_err();
            assert!(message.contains(refusal), "{source}: {message}");
            assert!(!Path::new(&at("refused")).exists(), "{source}");
        }
    }

    /// A link whose `path` is a directory is refused natively, with something in its way:
    /// the change says so and is a conflict.
    #[tokio::test]
    async fn a_link_over_a_directory_is_a_conflict() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().to_string_lossy().into_owned();
        let link = change(
            serde_json::json!({"id": "l", "type": "link", "path": path, "target": "/srv/x"}),
            Vec::new(),
        );
        let Failure { code, message } = run_change(&Connection::Local, None, &link)
            .await
            .unwrap_err();
        assert_eq!(code, ErrorCode::Conflict, "{message}");
        assert_eq!(
            message,
            format!("failed to symlink {path}: is a directory, not a link")
        );
    }

    /// A validated write that fails before its install says the path wasn't changed, and
    /// keeps the code of what failed: a source that isn't there is not found, though no
    /// word of the message says so.
    #[tokio::test]
    async fn a_validated_write_that_failed_keeps_the_code_of_its_cause() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("source");
        let (source, target) = (
            source.to_string_lossy().into_owned(),
            dir.path().join("target").to_string_lossy().into_owned(),
        );
        let file: zap_types::schema::FileResource = serde_json::from_value(serde_json::json!({
            "path": target,
            "content": {"type": "source", "path": source},
            "validate": "true",
        }))
        .unwrap();
        let Failure { code, message } =
            write_validated(&Connection::Local, None, &target, &file, "true", "true")
                .await
                .unwrap_err();
        assert_eq!(code, ErrorCode::NotFound, "{message}");
        assert_eq!(
            message,
            format!(
                "failed to read file {source}: there is no file there; {target} was not changed"
            )
        );
    }

    /// A pending marker that can't be recorded fails its change with the code of why:
    /// a marker directory whose script ran past its deadline is a timeout, which no word
    /// of the message classifies.
    #[tokio::test]
    async fn an_unrecorded_trigger_keeps_the_code_of_its_cause() {
        use std::collections::{BTreeMap, BTreeSet};

        use zap_types::plan::TriggerKind;

        let conn = Connection::Mock(MockConnection::new("m").with(
            zap_types::put::make_dirs_command(RunAs::Caller, super::super::pending::PENDING_DIR),
            CommandOutput {
                success: false,
                code: 124,
                stdout: String::new(),
                stderr: String::new(),
            },
        ));
        let source = change(
            serde_json::json!({"id": "conf", "type": "file", "path": "/etc/app.conf",
                "content": {"type": "inline", "content": "x"}}),
            Vec::new(),
        );
        let arming = BTreeMap::from([(&source.resource_id, vec![("app", TriggerKind::Restart)])]);
        let Failure { code, message } = arm_pending(&conn, &arming, &mut BTreeSet::new(), &source)
            .await
            .unwrap_err();
        assert_eq!(code, ErrorCode::Transient, "{message}");
        assert!(
            message.starts_with(
                "couldn't record the pending restart of `app` before this change, so it \
                 didn't run: failed to mkdir /var/lib/zap/pending: it did not finish within"
            ),
            "{message}"
        );
    }

    /// A `validate` that exits 127 — its checker isn't installed — is not found, read
    /// from the exit code as a command step's failure is; its words alone say nothing.
    #[tokio::test]
    async fn a_validate_that_exits_127_is_not_found() {
        let conn = Connection::Mock(MockConnection::new("m").with(
            "nginx -t",
            CommandOutput {
                success: false,
                code: 127,
                stdout: String::new(),
                stderr: "sh: 1: nginx: not found\n".to_owned(),
            },
        ));
        let Failure { code, message } = run_validate(&conn, "nginx -t", "nginx -t")
            .await
            .unwrap_err();
        assert_eq!(code, ErrorCode::NotFound, "{message}");
        assert_eq!(
            message,
            "validate `nginx -t` exited 127: sh: 1: nginx: not found"
        );
    }

    /// A `build` whose `run` exits 127 is not found, read from the exit code.
    #[test]
    fn a_build_that_exits_127_is_not_found() {
        let build: BuildResource = serde_json::from_value(serde_json::json!({
            "source": {"type": "remote", "url": "https://h/x.tar.gz", "extract": {"type": "tar.gz"}},
            "run": "zig build", "output": "/opt/x",
        }))
        .unwrap();
        let Failure { code, message } = build_failed(
            &build,
            &CommandOutput {
                success: false,
                code: 127,
                stdout: String::new(),
                stderr: "sh: 1: zig: not found\n".to_owned(),
            },
        );
        assert_eq!(code, ErrorCode::NotFound, "{message}");
        assert_eq!(
            message,
            "build `zig build` exited 127: sh: 1: zig: not found"
        );
    }

    /// A value with every other shell metacharacter, in a position zap single-quoted —
    /// directly, and under a second `sh -c` layer — reaches the command literally,
    /// through a real shell.
    #[tokio::test]
    async fn a_value_without_a_single_quote_is_literal_in_a_quoted_step() {
        let value = "$HOME `id` \"q\" ; rm -rf x | & * \\ $(id) #\n second line";
        let _env = crate::resolve::test_env::set(&[("ZAP_T_VALUE", value)]);
        let dir = tempfile::tempdir().unwrap();
        let flat = dir.path().join("flat");
        let nested = dir.path().join("nested");
        let print = |out: &Path| {
            format!(
                "printf '%s' {} > {}",
                single_quote(&marker("ZAP_T_VALUE")),
                single_quote(&out.to_string_lossy())
            )
        };
        let change = script_change(vec![
            PlanStep::run(print(&flat)),
            PlanStep::note("a note is not run"),
            PlanStep::run(format!("sh -c {}", single_quote(&print(&nested)))),
        ]);
        run_change(&Connection::Local, None, &change).await.unwrap();
        assert_eq!(std::fs::read_to_string(&flat).unwrap(), value);
        assert_eq!(std::fs::read_to_string(&nested).unwrap(), value);
    }

    /// The preflight's finding names the resource and the variable — never the value —
    /// for each kind of command text, with the advice that is true there; and what isn't
    /// command text (a file's content, a path, an `env` value, a fetch url) is never a
    /// finding, whatever it resolves to.
    /// A template value with a line break would add a line to the file: the wetrun
    /// preflight refuses the change by the variable's name, and the executor writes
    /// nothing; a `;` or a `}` in a value is the file's grammar, and is written.
    #[tokio::test]
    async fn a_template_value_with_a_line_break_is_refused_before_anything_is_written() {
        let _env = crate::resolve::test_env::set(&[
            ("ZAP_T_TPL_LF", "a.example\nEXTRA=1"),
            ("ZAP_T_TPL_SEMI", "a.example; }"),
        ]);
        let dir = crate::test_scratch::tempdir();
        let file = |name: &str, var: &str| {
            change(
                serde_json::json!({"id": name, "type": "file",
                    "path": dir.path().join(name).to_string_lossy(),
                    "content": {"type": "template", "template": "DOMAIN={{d}}\n",
                        "vars": {"d": Text::reference(var)}}}),
                Vec::new(),
            )
        };
        let (refused, written) = (
            file("refused", "ZAP_T_TPL_LF"),
            file("written", "ZAP_T_TPL_SEMI"),
        );
        let plan = Plan {
            references: std::collections::BTreeMap::new(),
            target: Target::local(),
            machine: local_machine(),
            changes: vec![refused.clone(), written.clone()],
        };
        assert_eq!(
            refused_changes(&plan),
            [format!(
                "`refused`: the template was not rendered, and the file was not written: `{}` \
                 resolves to a value containing a line break (CR or LF), which a template \
                 value can't hold: it would add a line to the file",
                shown("ZAP_T_TPL_LF")
            )]
        );
        let Failure { message, .. } = run_change(&Connection::Local, None, &refused)
            .await
            .unwrap_err();
        assert!(message.contains("line break"), "{message}");
        assert!(!message.contains("EXTRA"), "{message}");
        // The write refuses it too, whatever reached it.
        let zap_types::schema::ResourceKind::File(refused_file) = &refused.desired.kind else {
            unreachable!()
        };
        let path = dir.path().join("refused").to_string_lossy().into_owned();
        let Failure { message, .. } =
            super::materialize_file(&Connection::Local, None, &path, refused_file)
                .await
                .unwrap_err();
        assert!(message.contains("line break"), "{message}");
        assert!(!dir.path().join("refused").exists());
        run_change(&Connection::Local, None, &written)
            .await
            .unwrap();
        assert_eq!(
            std::fs::read_to_string(dir.path().join("written")).unwrap(),
            "DOMAIN=a.example; }\n"
        );
    }

    /// A template value that isn't its variable's declared kind is refused by the wetrun
    /// preflight, by the variable and the kind, and the executor writes nothing; the
    /// same value in a variable with no kind is text, and is written.
    #[tokio::test]
    async fn a_template_value_that_is_not_its_kind_is_refused_before_anything_is_written() {
        let _env = crate::resolve::test_env::set(&[("ZAP_T_TPL_HOST", "a.example; }")]);
        let dir = crate::test_scratch::tempdir();
        let file = |name: &str, kinds: serde_json::Value| {
            change(
                serde_json::json!({"id": name, "type": "file",
                    "path": dir.path().join(name).to_string_lossy(),
                    "content": {"type": "template", "template": "server_name {{d}};\n",
                        "vars": {"d": Text::reference("ZAP_T_TPL_HOST")}, "kinds": kinds}}),
                Vec::new(),
            )
        };
        let refused = file("refused", serde_json::json!({"d": "hostname"}));
        let written = file("written", serde_json::json!({}));
        let plan = Plan {
            references: std::collections::BTreeMap::new(),
            target: Target::local(),
            machine: local_machine(),
            changes: vec![refused.clone(), written.clone()],
        };
        let found = refused_changes(&plan);
        assert_eq!(found.len(), 1, "{found:?}");
        assert!(
            found[0].starts_with(
                "`refused`: the template was not rendered, and the file was not written: \
                 `content.vars.d` resolves to a value that is not a host name"
            ),
            "{found:?}"
        );
        assert!(
            found[0].ends_with("which its kind `hostname` refuses"),
            "{found:?}"
        );
        let Failure { message, .. } = run_change(&Connection::Local, None, &refused)
            .await
            .unwrap_err();
        assert!(message.contains("`hostname`"), "{message}");
        assert!(!dir.path().join("refused").exists());
        run_change(&Connection::Local, None, &written)
            .await
            .unwrap();
        assert_eq!(
            std::fs::read_to_string(dir.path().join("written")).unwrap(),
            "server_name a.example; };\n"
        );
    }

    #[test]
    fn the_preflight_refuses_command_text_only_and_advises_per_site() {
        let _env = crate::resolve::test_env::set(&[
            ("ZAP_T_QUOTE", "it's secret"),
            ("ZAP_T_DQUOTE", "se\"cret"),
        ]);
        let source = serde_json::json!(
            {"type": "remote",
             "url": Text::of_pieces([Lit("https://h/"), Ref("ZAP_T_QUOTE"), Lit(".tar.gz")]),
             "extract": {"type": "tar.gz"}}
        );
        let run = |text: &str| vec![PlanStep::run(text)];
        let plan = Plan {
            references: std::collections::BTreeMap::new(),
            target: Target::local(),
            machine: local_machine(),
            changes: vec![
                // Not command text: content, paths, a url, `env` values.
                change(
                    serde_json::json!({"id": "content", "type": "file",
                        "path": Text::of_pieces([Lit("/etc/"), Ref("ZAP_T_QUOTE")]),
                        "content": {"type": "template", "template": "{{a}} {{b}}",
                            "vars": {"a": Text::reference("ZAP_T_QUOTE"),
                                     "b": Text::reference("ZAP_T_DQUOTE")}}}),
                    Vec::new(),
                ),
                change(
                    serde_json::json!({"id": "dir", "type": "directory",
                        "path": Text::of_pieces([Lit("/srv/"), Ref("ZAP_T_QUOTE")])}),
                    Vec::new(),
                ),
                change(
                    serde_json::json!({"id": "env", "type": "build", "source": source, "run": "make",
                        "output": Text::of_pieces([Lit("/opt/"), Ref("ZAP_T_QUOTE")]),
                        "env": {"GIVEN": Text::reference("ZAP_T_QUOTE")}}),
                    run("make"),
                ),
                change(
                    serde_json::json!({"id": "script-env", "type": "script", "check": "false",
                    "run": "x",
                    "env": {"GIVEN": Text::of_pieces([
                        Ref("ZAP_T_QUOTE"), Lit(" "), Ref("ZAP_T_DQUOTE"),
                    ])}}),
                    run("x"),
                ),
                change(
                    serde_json::json!({"id": "dq", "type": "script", "check": "false", "run": "x"}),
                    run(&format!("echo '{}'", marker("ZAP_T_DQUOTE"))),
                ),
                // Command text.
                change(
                    serde_json::json!({"id": "script", "type": "script", "check": "false", "run": "x"}),
                    run(&format!("echo '{}'", marker("ZAP_T_QUOTE"))),
                ),
                change(
                    serde_json::json!({"id": "user", "type": "user", "username": "app"}),
                    run(&format!(
                        "sudo usermod -s '{}' -- 'app'",
                        marker("ZAP_T_QUOTE")
                    )),
                ),
                change(
                    serde_json::json!({"id": "validated", "type": "file", "path": "/etc/x",
                        "content": {"type": "inline", "content": "x"},
                        "validate": Text::of_pieces([Lit("check '"), Ref("ZAP_T_QUOTE"), Lit("'")])}),
                    Vec::new(),
                ),
                change(
                    serde_json::json!({"id": "build", "type": "build", "source": source,
                        "run": Text::of_pieces([Lit("make T='"), Ref("ZAP_T_QUOTE"), Lit("'")]),
                        "output": "/opt/x"}),
                    run(&format!("make T='{}'", marker("ZAP_T_QUOTE"))),
                ),
                change(
                    serde_json::json!({"id": "db", "type": "database", "engine": "postgresql",
                        "database_name": "app", "username": Text::reference("ZAP_T_DQUOTE"),
                        "auth": {"method": "scram-sha-256", "hosts": []}}),
                    run(&format!(
                        "sudo -u postgres createuser -- '{}'",
                        marker("ZAP_T_DQUOTE")
                    )),
                ),
            ],
        };
        let refused = refused_changes(&plan);
        let advised = [
            (
                format!(
                    "`script`: `echo '{}'` was not run: `{}`",
                    marker("ZAP_T_QUOTE"),
                    shown("ZAP_T_QUOTE")
                ),
                "Pass it through this script's `env`, which is quoted after it resolves",
            ),
            (
                format!(
                    "`user`: `sudo usermod -s '{}' -- 'app'` was not run",
                    marker("ZAP_T_QUOTE")
                ),
                "zap composes this command",
            ),
            (
                format!(
                    "`validated`: validate `check '{}'` was not run, and the file was not \
                     written",
                    marker("ZAP_T_QUOTE")
                ),
                "rest would run as shell. Have the command read it from a file",
            ),
            (
                format!(
                    "`build`: build `make T='{}'` was not run",
                    marker("ZAP_T_QUOTE")
                ),
                "Pass it through this build's `env`",
            ),
            (
                format!(
                    "`db`: database `username` `{}` can't be used: `{}` resolves to a value \
                     containing a double quote",
                    marker("ZAP_T_DQUOTE"),
                    shown("ZAP_T_DQUOTE")
                ),
                "would run as SQL",
            ),
        ];
        assert_eq!(refused.len(), advised.len(), "{refused:#?}");
        for (finding, (start, advice)) in refused.iter().zip(advised) {
            assert!(finding.starts_with(&start), "{finding}");
            assert!(finding.contains(advice), "{finding}");
            assert!(
                !finding.contains("secret") && !finding.contains("cret"),
                "{finding}"
            );
        }
        // No advice names an `env` a site doesn't have.
        assert!(refused[0].contains("`env`"), "{refused:#?}");
        assert!(
            !refused[1].contains("`env`") && !refused[2].contains("`env`"),
            "{refused:#?}"
        );
    }

    /// A build's relative `cwd` is under its extracted source; an absolute one is
    /// taken as written.
    #[test]
    fn a_build_cwd_is_under_the_source_unless_absolute() {
        let dir = "/tmp/zap-build-abc";
        assert_eq!(super::build_cwd(None, dir), dir);
        assert_eq!(super::build_cwd(Some(""), dir), dir);
        assert_eq!(
            super::build_cwd(Some("sub/dir"), dir),
            "/tmp/zap-build-abc/sub/dir"
        );
        assert_eq!(super::build_cwd(Some("/srv/src"), dir), "/srv/src");
    }

    /// A script change for `cwd` and `env`, running `run` as its one step.
    fn script_in(run: &str, cwd: Option<&str>, env: &serde_json::Value) -> Change {
        change(
            serde_json::json!({"id": "s", "type": "script", "check": "false",
                "run": Text::from_inert(run).unwrap(), "cwd": cwd, "env": env}),
            vec![PlanStep::run(run)],
        )
    }

    /// A value no command text can take, and that a shell would mangle anywhere but
    /// inside the quoting zap gives an `env` value.
    const AWKWARD: &str = "it's '' a `$HOME` \"q\" ; \\ value\n second line";

    /// A script's `run` executes in its `cwd` with its `env` — every command of a
    /// compound `run` sees both — through a real run on a local target.
    #[tokio::test]
    async fn a_script_runs_in_its_cwd_with_its_env_on_a_local_target() {
        let _env = crate::resolve::test_env::set(&[("ZAP_T_VALUE", AWKWARD)]);
        let dir = tempfile::tempdir().unwrap();
        let cwd = dir.path().canonicalize().unwrap();
        let cwd = cwd.to_string_lossy();
        // Entered through a symlink, the directory is still the one it names.
        let link = tempfile::tempdir().unwrap();
        let link = link.path().join("link");
        std::os::unix::fs::symlink(dir.path(), &link).unwrap();
        // Three commands, each reading the env; the first and last also the directory.
        let run = r#"printf '%s' "$ZAP_T_GIVEN" > given && test "$ZAP_T_MODE" = prod; pwd | tr -d '\n'; printf '|%s' "$ZAP_T_GIVEN""#;
        let change = script_in(
            run,
            Some(&link.to_string_lossy()),
            &serde_json::json!({
                "ZAP_T_GIVEN": Text::of_pieces([Lit("<"), Ref("ZAP_T_VALUE"), Lit(">")]),
                "ZAP_T_MODE": "prod",
            }),
        );
        let output = run_change(&Connection::Local, None, &change).await.unwrap();
        assert_eq!(output, format!("{cwd}|<{AWKWARD}>"));
        assert_eq!(
            std::fs::read_to_string(dir.path().join("given")).unwrap(),
            format!("<{AWKWARD}>")
        );
    }

    /// Over SSH the same `run` is delivered as one script: the `cd` that ends it when
    /// the `cwd` can't be entered, the `env` exported with each resolved value quoted,
    /// then the command — and, run as delivered, it sees what the local run sees.
    #[tokio::test]
    async fn a_script_run_is_delivered_over_ssh_in_its_cwd_with_its_env() {
        let _env = crate::resolve::test_env::set(&[("ZAP_T_VALUE", "it's $HOME\nx")]);
        let change = script_in(
            "make install && make check",
            Some("/srv/my app"),
            &serde_json::json!({
                "TOKEN": Text::of_pieces([Lit("<"), Ref("ZAP_T_VALUE"), Lit(">")]),
                "MODE": "prod",
            }),
        );
        let ChangeCommands::Steps { steps, options } = change_commands(&change).unwrap() else {
            panic!("a script's commands");
        };
        assert_eq!(
            shown_steps(&steps),
            [(
                "`make install && make check`".to_owned(),
                "make install && make check".to_owned()
            )]
        );
        assert_eq!(
            SshConnection::wrap_remote(ran(&steps[0]), &options),
            "CDPATH= cd -P -- '/srv/my app' || exit; export MODE='prod' TOKEN='<it'\\''s $HOME\nx>'\n\
             make install && make check"
        );

        let dir = tempfile::tempdir().unwrap();
        let cwd = dir.path().canonicalize().unwrap();
        let cwd = cwd.to_string_lossy();
        let change = script_in(
            r#"test "$MODE" = prod && pwd -P | tr -d '\n'; printf '|%s' "$TOKEN""#,
            Some(&cwd),
            &serde_json::json!({
                "TOKEN": Text::of_pieces([Lit("<"), Ref("ZAP_T_VALUE"), Lit(">")]),
                "MODE": "prod",
            }),
        );
        let ChangeCommands::Steps { steps, options } = change_commands(&change).unwrap() else {
            panic!("a script's commands");
        };
        let delivered = SshConnection::wrap_remote(ran(&steps[0]), &options);
        let ran = Connection::Local.run_default(&delivered).await.unwrap();
        assert_eq!(ran.stdout, format!("{cwd}|<it's $HOME\nx>"), "{delivered}");
    }

    /// A script's check and its `run` are composed with one line: the same `cd` into
    /// the same directory and the same exported values, the check's differing only in
    /// discarding what its `cd` prints.
    #[test]
    fn a_script_check_and_its_run_enter_the_same_cwd_with_the_same_env() {
        let _env = crate::resolve::test_env::set(&[("ZAP_T_VALUE", "it's $HOME\nx")]);
        for (cwd, env) in [
            (
                Some("/srv/my app"),
                serde_json::json!({
                    "B": Text::of_pieces([Lit("<"), Ref("ZAP_T_VALUE"), Lit(">")]),
                    "A": "1",
                }),
            ),
            (Some("/srv/my app"), serde_json::Value::Null),
            (None, serde_json::json!({"A": "1"})),
        ] {
            let change = script_in("make install", cwd, &env);
            let ChangeCommands::Steps { steps, options } = change_commands(&change).unwrap() else {
                panic!("a script's commands");
            };
            let run = SshConnection::wrap_remote(ran(&steps[0]), &options);
            let env: Vec<(&str, &str)> = options
                .env
                .iter()
                .map(|(name, value)| (name.as_str(), value.as_str()))
                .collect();
            let check =
                zap_types::observe::script::ScriptCheck::new("make -q install", cwd, &env).snippet;
            let context = |text: &str, command: &str| {
                text.strip_suffix(command)
                    .unwrap_or_else(|| panic!("{text}"))
                    .to_owned()
            };
            assert_eq!(
                context(&check, "make -q install").replace(" >/dev/null 2>&1", ""),
                context(&run, "make install"),
            );
            assert!(context(&run, "make install").ends_with('\n'));
        }
    }

    /// A script with neither a `cwd` nor `env` runs as it is written, with nothing
    /// composed around it.
    #[test]
    fn a_script_with_no_cwd_or_env_is_delivered_bare() {
        let change = script_in("make install", None, &serde_json::Value::Null);
        let ChangeCommands::Steps { steps, options } = change_commands(&change).unwrap() else {
            panic!("a script's commands");
        };
        assert_eq!(
            shown_options(&options),
            shown_options(&RunOptions::default())
        );
        assert_eq!(
            SshConnection::wrap_remote(ran(&steps[0]), &options),
            "make install"
        );
    }

    /// A `run` whose `cwd` can't be entered fails the change and runs nothing — not in
    /// the directory zap happens to be in: the one script every connection is handed
    /// ends at its `cd`, with `cd`'s own message.
    #[tokio::test]
    async fn a_script_whose_cwd_cannot_be_entered_fails_with_nothing_run() {
        let dir = tempfile::tempdir().unwrap();
        let ran = dir.path().join("ran");
        let gone = dir.path().join("gone").to_string_lossy().into_owned();
        let run = format!("touch {}", single_quote(&ran.to_string_lossy()));
        let change = script_in(&run, Some(&gone), &serde_json::Value::Null);
        let delivered = format!("CDPATH= cd -P -- '{gone}' || exit\n{run}");

        let error = run_change(&Connection::Local, None, &change)
            .await
            .unwrap_err()
            .message;
        assert!(error.starts_with(&format!("`{run}` exited ")), "{error}");
        assert!(error.contains("cd") && error.contains(&gone), "{error}");
        assert!(!ran.exists());

        // A remote target is handed the same text, whose failure fails the change.
        let failed = Connection::Local.run_default(&delivered).await.unwrap();
        assert!(!failed.success, "{failed:?}");
        let conn = Connection::Mock(MockConnection::new("m").with(&delivered, failed));
        let remote = run_change(&conn, None, &change).await.unwrap_err().message;
        assert_eq!(remote, error);
        let Connection::Mock(mock) = &conn else {
            unreachable!()
        };
        assert_eq!(mock.issued_commands(), [delivered]);

        // The same change with a directory that is there does run.
        let here = dir.path().to_string_lossy().into_owned();
        run_change(
            &Connection::Local,
            None,
            &script_in(&run, Some(&here), &serde_json::Value::Null),
        )
        .await
        .unwrap();
        assert!(ran.exists());
    }

    /// The failure of a `run` whose `cwd` can't be entered names the command as
    /// declared — a reference in it stays the reference, never the value it resolves
    /// to.
    #[tokio::test]
    async fn a_script_that_could_not_enter_its_cwd_names_its_command_as_declared() {
        let _env = crate::resolve::test_env::set(&[("ZAP_T_VALUE", "resolved-value")]);
        let dir = tempfile::tempdir().unwrap();
        let gone = dir.path().join("gone").to_string_lossy().into_owned();
        let change = script_in(
            &format!("echo '{}'", marker("ZAP_T_VALUE")),
            Some(&gone),
            &serde_json::Value::Null,
        );
        let error = run_change(&Connection::Local, None, &change)
            .await
            .unwrap_err()
            .message;
        assert!(
            error.starts_with(&format!("`echo '{}'` exited ", marker("ZAP_T_VALUE"))),
            "{error}"
        );
        assert!(error.contains(&gone), "{error}");
        assert!(!error.contains("resolved-value"), "{error}");
    }

    /// A local script's `env` is exported by the script it runs, not set on the shell's
    /// process — so no value, a `PATH` naming nothing included, keeps the shell from
    /// starting, and the command sees it as a remote one does.
    #[tokio::test]
    async fn a_local_script_env_cannot_keep_its_shell_from_starting() {
        let dir = tempfile::tempdir().unwrap();
        let cwd = dir.path().to_string_lossy().into_owned();
        let change = script_in(
            r#"echo "hi $PATH""#,
            Some(&cwd),
            &serde_json::json!({"PATH": "/nonexistent"}),
        );
        assert_eq!(
            run_change(&Connection::Local, None, &change).await.unwrap(),
            "hi /nonexistent\n"
        );
    }

    /// A script `env` value that resolves to something no environment can carry (a NUL)
    /// is the preflight's finding — the resource, the `env` key, the variable, never the
    /// value — and the executor refuses the same change before any of it runs.
    #[tokio::test]
    async fn a_script_env_value_holding_a_nul_is_refused_before_anything_runs() {
        let _env = crate::resolve::test_env::set(&[("ZAP_T_NUL", "a\0secret")]);
        let change = script_in(
            "make",
            None,
            &serde_json::json!({
                "GIVEN": Text::of_pieces([Lit("<"), Ref("ZAP_T_NUL"), Lit(">")]),
            }),
        );
        let plan = Plan {
            references: std::collections::BTreeMap::new(),
            target: Target::local(),
            machine: local_machine(),
            changes: vec![script_in("true", None, &serde_json::Value::Null), change],
        };
        let refused = refused_changes(&plan);
        assert_eq!(refused.len(), 1, "{refused:#?}");
        assert!(
            refused[0].starts_with(&format!(
                "`s`: `make` was not run: env.GIVEN: `{}`",
                shown("ZAP_T_NUL")
            )),
            "{refused:#?}"
        );
        assert!(refused[0].contains("NUL byte"), "{refused:#?}");
        assert!(!refused[0].contains("secret"), "{refused:#?}");

        let conn = Connection::Mock(MockConnection::new("m").with("make", ok_output()));
        let error = run_change(&conn, None, &plan.changes[1])
            .await
            .unwrap_err()
            .message;
        assert_eq!(format!("`s`: {error}"), refused[0]);
        let Connection::Mock(mock) = &conn else {
            unreachable!()
        };
        assert!(mock.issued_commands().is_empty());
    }

    /// The `env` channel carries any value — a single quote included — byte for byte:
    /// set on the process for a local target, quoted into the script for a remote one
    /// (run here through the delivery under the local `sh`).
    #[tokio::test]
    async fn an_env_value_reaches_the_build_byte_exact() {
        let value = "it's '' a `$HOME` \"q\" ; \\ value\n second line";
        let _env = crate::resolve::test_env::set(&[("ZAP_T_VALUE", value)]);
        let build: BuildResource = serde_json::from_value(serde_json::json!({
            "source": {"type": "remote", "url": "https://h/x.tar.gz", "extract": {"type": "tar.gz"}},
            "run": "sh -c 'printf \"%s\" \"$ZAP_T_GIVEN\"'",
            "output": "/opt/x",
            "env": {"ZAP_T_GIVEN": Text::of_pieces([Lit("<"), Ref("ZAP_T_VALUE"), Lit(">")])},
        }))
        .unwrap();
        let (run, env) = build_command(&build).unwrap();
        assert_eq!(env, [("ZAP_T_GIVEN".to_owned(), format!("<{value}>"))]);
        let options = RunOptions {
            env,
            ..RunOptions::default()
        };
        let local = Connection::Local
            .run_composed(&run, &options)
            .await
            .unwrap();
        assert_eq!(local.stdout, format!("<{value}>"));
        let remote = Connection::Local
            .run_default(&SshConnection::wrap_remote(&run, &options))
            .await
            .unwrap();
        assert_eq!(remote.stdout, format!("<{value}>"));
    }

    /// A `build` whose `run` can't take a value fails naming the variable; one whose
    /// `env` value holds a NUL names the `env` key too.
    #[test]
    fn a_build_whose_command_cannot_take_a_value_is_refused() {
        let _env = crate::resolve::test_env::set(&[
            ("ZAP_T_QUOTE", "it's secret"),
            ("ZAP_T_NUL", "a\0secret"),
        ]);
        let build = |run: Text, given: Text| -> BuildResource {
            serde_json::from_value(serde_json::json!({
                "source": {"type": "remote", "url": "https://h/x.tar.gz", "extract": {"type": "tar.gz"}},
                "run": run, "output": "/opt/x", "env": {"GIVEN": given},
            }))
            .unwrap()
        };
        let error = build_command(&build(
            Text::of_pieces([Lit("make TOKEN='"), Ref("ZAP_T_QUOTE"), Lit("'")]),
            Text::literal("x"),
        ))
        .unwrap_err();
        assert!(
            error.contains(&format!("`{}`", shown("ZAP_T_QUOTE"))),
            "{error}"
        );
        assert!(!error.contains("secret"), "{error}");
        let error =
            build_command(&build(Text::literal("make"), Text::reference("ZAP_T_NUL"))).unwrap_err();
        assert!(
            error.contains("env.GIVEN") && error.contains(&format!("`{}`", shown("ZAP_T_NUL"))),
            "{error}"
        );
        assert!(!error.contains("secret"), "{error}");
    }

    /// A `build` whose `run` can't take a value fails before its source is fetched: the
    /// error is the refusal, not the fetch of a url nothing serves.
    #[tokio::test]
    async fn a_build_is_refused_before_its_source_is_fetched() {
        let _env = crate::resolve::test_env::set(&[("ZAP_T_QUOTE", "it's secret")]);
        let home = tempfile::tempdir().unwrap();
        let desired: Resource = serde_json::from_value(serde_json::json!({
            "id": "b", "type": "build",
            "source": {"type": "remote", "url": "http://127.0.0.1:1/x.tar.gz", "extract": {"type": "tar.gz"}},
            "run": Text::of_pieces([Lit("make TOKEN='"), Ref("ZAP_T_QUOTE"), Lit("'")]),
            "output": "/opt/x",
        }))
        .unwrap();
        let change = Change {
            resource_id: desired.id.clone(),
            action: zap_types::plan::ChangeAction::Create,
            steps: Vec::new(),
            desired,
            depends_on: Vec::new(),
            trigger: None,
        };
        let conn = Connection::Mock(MockConnection::new("m"));
        let error = run_change(&conn, Some(home.path()), &change)
            .await
            .unwrap_err()
            .message;
        assert!(
            error.contains(&format!("`{}`", shown("ZAP_T_QUOTE"))),
            "{error}"
        );
        assert!(error.contains("was not run"), "{error}");
        let Connection::Mock(mock) = &conn else {
            unreachable!()
        };
        assert!(mock.issued_commands().is_empty());
    }

    /// A `build` whose source isn't cached fetches it and checks its declared signature
    /// before anything reaches the target: a check that doesn't pass fails the change
    /// with nothing staged. It fails closed either way — no `minisign` to run, or one
    /// that rejects what was served — so this holds without the tool installed, and
    /// says nothing of which of the two refused.
    #[tokio::test]
    async fn a_build_fetched_at_execution_checks_its_signature_first() {
        let home = tempfile::tempdir().unwrap();
        let body = b"source archive".to_vec();
        let pin = blake3::hash(&body).to_hex().to_string();
        let url = serve_once(body);
        let desired: Resource = serde_json::from_value(serde_json::json!({
            "id": "b", "type": "build",
            "source": {"type": "remote", "url": url, "extract": {"type": "tar.gz"},
                       "blake3": pin,
                       "verify": {"scheme": "minisign",
                                  "public_key": "RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3",
                                  "signature_url": serve_once(b"not a signature".to_vec())}},
            "run": "make",
            "output": "/opt/x",
        }))
        .unwrap();
        let change = Change {
            resource_id: desired.id.clone(),
            action: zap_types::plan::ChangeAction::Create,
            steps: Vec::new(),
            desired,
            depends_on: Vec::new(),
            trigger: None,
        };
        let conn = Connection::Mock(MockConnection::new("m"));
        let error = run_change(&conn, Some(home.path()), &change)
            .await
            .unwrap_err()
            .message;
        assert!(
            error.contains(&format!(
                "signature verification failed for {url}: minisign "
            )),
            "{error}"
        );
        let Connection::Mock(mock) = &conn else {
            unreachable!()
        };
        assert!(
            mock.issued_commands().is_empty(),
            "{:?}",
            mock.issued_commands()
        );
    }

    /// A `validate` command that can't take a value fails the change before the file is
    /// snapshotted or written: nothing reaches the connection.
    #[tokio::test]
    async fn write_validated_refuses_an_unquotable_value_before_writing() {
        let _env = crate::resolve::test_env::set(&[("ZAP_T_QUOTE", "it's secret")]);
        let conn = Connection::Mock(MockConnection::new("m"));
        let change = change(
            serde_json::json!({"id": "f", "type": "file", "path": "/etc/app.conf",
            "content": {"type": "inline", "content": "new"},
            "validate": Text::of_pieces([
                Lit("check --token '"), Ref("ZAP_T_QUOTE"), Lit("'"),
            ])}),
            Vec::new(),
        );
        let error = run_change(&conn, None, &change).await.unwrap_err().message;
        assert!(
            error.contains(&format!("`{}`", shown("ZAP_T_QUOTE"))),
            "{error}"
        );
        assert!(error.contains("the file was not written"), "{error}");
        assert!(!error.contains("secret"), "{error}");
        let Connection::Mock(mock) = &conn else {
            unreachable!()
        };
        assert!(mock.issued_commands().is_empty());
    }

    /// The extract script for `staged` → `dest`, as `run_as`, the archive's SHA-512
    /// `sha512`.
    fn extract(
        run_as: RunAs<'static>,
        staged: &str,
        dest: &str,
        mode: ExtractMode,
        pin: Option<&str>,
        sha512: &str,
    ) -> String {
        zap_types::extract::extract_archive_command(run_as, staged, dest, mode, pin, sha512)
    }

    /// A resolved archive: bytes on disk and the digests a resolve read of them, the
    /// SHA-512 what the extract script is told to expect.
    fn cached_archive() -> (tempfile::TempDir, crate::resolver::ResolvedContent, String) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("zig.tar.xz");
        std::fs::write(&path, b"archive-bytes").unwrap();
        let sha512 = crate::digest::sha512_hex(b"archive-bytes");
        let resolved = crate::resolver::ResolvedContent {
            blake3: zap_types::scalar::ContentHash::of_bytes(b"archive-bytes"),
            sha512: sha512.clone(),
            path,
        };
        (dir, resolved, sha512)
    }

    /// On this machine the extract is tried as the operator first; `sudo` follows a
    /// failure, but never the script's own refusal and never a success.
    #[test]
    fn only_a_failed_extract_that_was_not_refused_is_retried_as_root() {
        let exit = |code: i32| CommandOutput {
            success: code == 0,
            code,
            stdout: String::new(),
            stderr: String::new(),
        };
        assert!(!retries_as_root(&exit(0)));
        assert!(!retries_as_root(&exit(zap_types::put::REFUSED_EXIT)));
        for failed in [1, 2, 126, 127] {
            assert!(retries_as_root(&exit(failed)), "{failed}");
        }
    }

    #[tokio::test]
    async fn extract_archive_unprivileged_runs_the_script_as_the_caller() {
        // The `build` branch (`Unprivileged`, no pin): `extract_archive` issues precisely
        // the extract script with no `sudo` (the `copy_file` stage is a Mock no-op). A
        // drift surfaces as an unrecorded `MockCommand` error.
        let mode = ExtractMode::TarXz {
            strip_components: 1,
        };
        let (_cache, cached, sha512) = cached_archive();
        let cmd = extract(
            RunAs::Caller,
            "/tmp/z.tar.xz",
            "/opt/x",
            mode,
            None,
            &sha512,
        );
        assert!(cmd.starts_with("sh -c '"), "{cmd}");
        assert!(
            cmd.contains(" --no-same-owner --no-same-permissions "),
            "{cmd}"
        );
        let conn = Connection::Mock(MockConnection::new("m").with(cmd, ok_output()));
        let result = extract_archive(
            &conn,
            &cached,
            "/tmp/z.tar.xz",
            "/opt/x",
            mode,
            None,
            ExtractPrivilege::Unprivileged,
        )
        .await;
        assert!(result.is_ok(), "{result:?}");
        // A build's plan binds the extraction its source goes through.
        assert_binds_what_ran(
            &conn,
            &change(
                serde_json::json!({"id": "b", "type": "build",
                    "source": {"type": "remote", "url": "https://h/x.tar.xz",
                        "blake3": "a".repeat(64), "extract": {"type": "tar.xz"}},
                    "run": "make install", "output": "/opt/x/bin/x"}),
                Vec::new(),
            ),
        );
    }

    #[tokio::test]
    async fn extract_archive_escalated_runs_the_script_under_sudo() {
        // The `remote` file branch (`Escalate`, pin-bearing): the same script, as root.
        // The Mock records the `sudo` form (matching the SSH posture); recording the
        // caller's form would fail as an unrecorded command.
        let mode = ExtractMode::TarXz {
            strip_components: 0,
        };
        let (_cache, cached, sha512) = cached_archive();
        let cmd = extract(
            RunAs::Root,
            "/tmp/zap-remote-PIN.tar.xz",
            "/opt/zig",
            mode,
            Some("PIN"),
            &sha512,
        );
        assert!(cmd.starts_with("sudo sh -c '"), "{cmd}");
        assert!(
            cmd.contains(" --no-same-owner --no-same-permissions ") && cmd.contains("umask 022; "),
            "{cmd}"
        );
        assert!(
            cmd.ends_with(&format!(
                " sh '/tmp/zap-remote-PIN.tar.xz' '/opt/zig' 'J' '0' 'PIN' '{sha512}'"
            )),
            "{cmd}"
        );
        let conn = Connection::Mock(MockConnection::new("m").with(cmd, ok_output()));
        let result = extract_archive(
            &conn,
            &cached,
            "/tmp/zap-remote-PIN.tar.xz",
            "/opt/zig",
            mode,
            Some("PIN"),
            ExtractPrivilege::Escalate,
        )
        .await;
        assert!(result.is_ok(), "{result:?}");
    }

    #[tokio::test]
    async fn extract_remote_archive_stages_privately_extracts_records_the_pin_and_cleans_up() {
        // The whole remote-file chain, in order: `mktemp -d` a private dir, run the
        // escalated extract script whose arguments embed the *trimmed* dir and the
        // sentinel's provenance, then clean the dir up. The script writes the sentinel
        // into the tree it swaps in; nothing else installs it. Mock errors loudly on any
        // unrecorded command (the `copy_file` stage is a Mock no-op).
        let mode = ExtractMode::TarXz {
            strip_components: 0,
        };
        let dir = "/tmp/zap-remote-test123";
        let staged = format!("{dir}/archive.tar.xz");
        let provenance = extract_provenance("PIN", mode);
        let (_cache, cached, sha512) = cached_archive();
        let script = extract(
            RunAs::Root,
            &staged,
            "/opt/zig",
            mode,
            Some(&provenance),
            &sha512,
        );
        let cleanup = format!("rm -rf -- {}", single_quote(dir));
        let conn = Connection::Mock(
            MockConnection::new("m")
                .with(
                    "mktemp -d -- '/tmp/zap-remote-XXXXXX'",
                    stdout_output(&format!("{dir}\n")),
                )
                .with(script.clone(), ok_output())
                .with(cleanup.clone(), ok_output()),
        );
        let result = extract_remote_archive(&conn, &cached, "/opt/zig", mode, "PIN").await;
        assert!(result.is_ok(), "{result:?}");
        let Connection::Mock(mock) = &conn else {
            unreachable!()
        };
        assert_eq!(
            mock.issued_commands(),
            [
                "mktemp -d -- '/tmp/zap-remote-XXXXXX'".to_owned(),
                script,
                cleanup,
            ]
        );
        // What the plan's hash binds of a remote archive's change covers what ran.
        assert_binds_what_ran(
            &conn,
            &change(
                serde_json::json!({"id": "zig", "type": "file", "path": "/opt/zig",
                    "content": {"type": "remote", "url": "https://h/zig.tar.xz",
                        "blake3": "a".repeat(64), "extract": {"type": "tar.xz"}}}),
                Vec::new(),
            ),
        );
    }

    #[tokio::test]
    async fn extract_remote_archive_cleans_up_and_records_no_pin_when_the_extract_fails() {
        // A failed extract propagates and the `rm -rf <dir>` still runs; nothing follows
        // it (the sentinel is the script's, written only into a tree it swapped in).
        let mode = ExtractMode::TarXz {
            strip_components: 0,
        };
        let dir = "/tmp/zap-remote-test123";
        let staged = format!("{dir}/archive.tar.xz");
        let provenance = extract_provenance("PIN", mode);
        let (_cache, cached, sha512) = cached_archive();
        let script = extract(
            RunAs::Root,
            &staged,
            "/opt/zig",
            mode,
            Some(&provenance),
            &sha512,
        );
        let cleanup = format!("rm -rf -- {}", single_quote(dir));
        let conn = Connection::Mock(
            MockConnection::new("m")
                .with(
                    "mktemp -d -- '/tmp/zap-remote-XXXXXX'",
                    stdout_output(&format!("{dir}\n")),
                )
                .with(
                    script.clone(),
                    failed_output("tar: Unexpected EOF in archive"),
                )
                .with(cleanup.clone(), ok_output()),
        );
        let result = extract_remote_archive(&conn, &cached, "/opt/zig", mode, "PIN").await;
        let err = result
            .expect_err("the injected extract failure must propagate")
            .message;
        assert!(err.contains("Unexpected EOF"), "{err}");
        let Connection::Mock(mock) = &conn else {
            unreachable!()
        };
        assert_eq!(
            mock.issued_commands(),
            [
                "mktemp -d -- '/tmp/zap-remote-XXXXXX'".to_owned(),
                script,
                cleanup,
            ],
            "cleanup must run even when the extract fails, and nothing after it"
        );
    }

    #[tokio::test]
    async fn stage_dir_returns_the_trimmed_mktemp_path() {
        // `mktemp -d` prints the created dir with a trailing newline; the helper trims it
        // so callers get a clean path to shell-escape.
        let conn = Connection::Mock(MockConnection::new("m").with(
            "mktemp -d -- '/tmp/zap-remote-XXXXXX'",
            stdout_output("/tmp/zap-remote-aB3x91\n"),
        ));
        let dir = stage_dir(&conn, "/tmp/zap-remote-XXXXXX").await.unwrap();
        assert_eq!(dir, "/tmp/zap-remote-aB3x91");
    }

    #[tokio::test]
    async fn stage_dir_errors_with_the_mktemp_stderr() {
        // A non-zero `mktemp` fails the change, carrying its stderr so the operator sees
        // why (a full/unwritable `/tmp`, a denied mount, …).
        let conn = Connection::Mock(MockConnection::new("m").with(
            "mktemp -d -- '/tmp/zap-build-XXXXXX'",
            failed_output("mktemp: failed to create directory: Permission denied"),
        ));
        let err = stage_dir(&conn, "/tmp/zap-build-XXXXXX")
            .await
            .expect_err("a non-zero mktemp must error")
            .message;
        assert!(err.contains("Permission denied"), "{err}");
    }

    /// A `mktemp` that exits 127 — none on the target — is not found, read from its exit
    /// code; its words alone say nothing.
    #[tokio::test]
    async fn a_mktemp_that_exits_127_is_not_found() {
        let conn = Connection::Mock(MockConnection::new("m").with(
            "mktemp -d -- '/tmp/zap-build-XXXXXX'",
            CommandOutput {
                success: false,
                code: 127,
                stdout: String::new(),
                stderr: "sh: 1: mktemp: nope\n".to_owned(),
            },
        ));
        let Failure { code, message } =
            stage_dir(&conn, "/tmp/zap-build-XXXXXX").await.unwrap_err();
        assert_eq!(code, ErrorCode::NotFound, "{message}");
        assert_eq!(message, "mktemp failed: sh: 1: mktemp: nope");
    }

    /// An extract that exits 127 — a decompressor missing on the target — is not found,
    /// read from its exit code; its words alone say nothing.
    #[tokio::test]
    async fn an_extract_that_exits_127_is_not_found() {
        let mode = ExtractMode::TarXz {
            strip_components: 0,
        };
        let (_cache, cached, sha512) = cached_archive();
        let cmd = extract(
            RunAs::Caller,
            "/tmp/z.tar.xz",
            "/opt/x",
            mode,
            None,
            &sha512,
        );
        let conn = Connection::Mock(MockConnection::new("m").with(
            cmd,
            CommandOutput {
                success: false,
                code: 127,
                stdout: String::new(),
                stderr: "tar: xz: nope\n".to_owned(),
            },
        ));
        let Failure { code, message } = extract_archive(
            &conn,
            &cached,
            "/tmp/z.tar.xz",
            "/opt/x",
            mode,
            None,
            ExtractPrivilege::Unprivileged,
        )
        .await
        .unwrap_err();
        assert_eq!(code, ErrorCode::NotFound, "{message}");
        assert_eq!(message, "extract failed: tar: xz: nope");
    }

    /// A validated inline `file` at `/etc/x` declaring mode `600`, checked by `nginx -t`.
    fn validated_file() -> zap_types::schema::FileResource {
        serde_json::from_value(serde_json::json!({
            "path": "/etc/x",
            "content": {"type": "inline", "content": "new"},
            "mode": "600",
            "validate": "nginx -t",
        }))
        .unwrap()
    }

    /// The put a mock is asked for when `/etc/x` is written with `attrs`.
    fn put_x(attrs: FileAttrs<'_>) -> String {
        zap_types::put::file_put_command(
            RunAs::Caller,
            "/etc/x",
            attrs,
            zap_types::put::PutCheck::None,
        )
    }

    /// The put of the declared content: mode `600`, the owner and group kept.
    fn declared_put() -> String {
        put_x(FileAttrs::mode("600").keeping())
    }

    /// The put that restores what the snapshot observed: `644`, owner and group `0`.
    fn restoring_put() -> String {
        put_x(FileAttrs {
            mode: Some("644"),
            owner: Some("0"),
            group: Some("0"),
            ..FileAttrs::NONE
        })
    }

    /// The one command a validated write of `/etc/x` reads its snapshot with.
    fn snapshot_x() -> String {
        zap_types::put::file_snapshot_command(RunAs::Caller, "/etc/x")
    }

    /// The mock's recordings for a validated write over an existing `/etc/x` whose
    /// snapshot answers `snapshot` (`old`, observed `644 0 0` by default): the snapshot
    /// and the one put that writes the content with its declared mode.
    fn file_mock(snapshot: &str) -> MockConnection {
        MockConnection::new("m")
            .with(snapshot_x(), stdout_output(snapshot))
            .with(declared_put(), ok_output())
    }

    fn existing_file_mock() -> MockConnection {
        file_mock("file 644 0 0 3\nold")
    }

    /// The commands a mock was asked for that change a mode or owner by name.
    fn by_name_changes(conn: &Connection) -> Vec<String> {
        let Connection::Mock(mock) = conn else {
            unreachable!()
        };
        mock.issued_commands()
            .into_iter()
            .filter(|command| command.starts_with("chmod ") || command.starts_with("chown "))
            .collect()
    }

    #[tokio::test]
    async fn write_validated_keeps_a_write_that_passes() {
        // A passing check keeps the write: no restore runs (Mock errors on any unrecorded
        // command, so the restoring put would fail the test if issued). The write is the
        // one put — its mode an argument — and nothing names the file to `chmod` it.
        let conn = Connection::Mock(existing_file_mock().with("nginx -t", ok_output()));
        let summary = write_validated(
            &conn,
            None,
            "/etc/x",
            &validated_file(),
            "nginx -t",
            "nginx -t",
        )
        .await
        .unwrap();
        assert_eq!(summary, "wrote /etc/x (validated)");
        let Connection::Mock(mock) = &conn else {
            unreachable!()
        };
        assert_eq!(
            mock.issued_commands(),
            [snapshot_x().as_str(), declared_put().as_str(), "nginx -t"],
            "the snapshot is one command"
        );
    }

    #[tokio::test]
    async fn write_validated_restores_the_previous_file_when_the_check_fails() {
        // The failed check fails the change with its output, and the snapshot goes back
        // in one put: the bytes, with the observed mode and owner as its arguments.
        let conn = Connection::Mock(
            existing_file_mock()
                .with(
                    "nginx -t",
                    failed_output("[emerg] unknown directive \"http2\" in /etc/x:5"),
                )
                .with(restoring_put(), ok_output()),
        );
        let err = write_validated(
            &conn,
            None,
            "/etc/x",
            &validated_file(),
            "nginx -t",
            "nginx -t",
        )
        .await
        .expect_err("a failed check must fail the change")
        .message;
        assert!(
            err.starts_with("validate `nginx -t` exited 1: [emerg] unknown directive"),
            "{err}"
        );
        assert!(err.ends_with("restored the previous /etc/x"), "{err}");
        let Connection::Mock(mock) = &conn else {
            unreachable!()
        };
        // The rollback names every attribute, so nothing is kept from the rejected file.
        assert!(restoring_put().ends_with("sh '/etc/x' '644' '0:0' '' ''"));
        assert_eq!(
            mock.issued_commands().last(),
            Some(&restoring_put()),
            "the observed mode and owner go back with the bytes"
        );
        assert_eq!(by_name_changes(&conn), Vec::<String>::new());
    }

    /// A rollback never makes a file set-id that the config doesn't declare so: a file
    /// observed `4755` (made so, say, between the snapshot's read and the write) goes
    /// back `755` — no put of the snapshot carries `4755` — while a declared `4755`
    /// keeps the bit, and a declared sticky bit keeps only itself.
    #[tokio::test]
    async fn a_rollback_restores_no_set_id_bit_the_config_does_not_declare() {
        let restore_as = |mode: &str| {
            put_x(FileAttrs {
                mode: Some(mode),
                owner: Some("0"),
                group: Some("0"),
                ..FileAttrs::NONE
            })
        };
        let conn = Connection::Mock(
            file_mock("file 4755 0 0 3\nold")
                .with("nginx -t", failed_output("[emerg] bad"))
                .with(restore_as("755"), ok_output()),
        );
        let err = write_validated(
            &conn,
            None,
            "/etc/x",
            &validated_file(),
            "nginx -t",
            "nginx -t",
        )
        .await
        .expect_err("a failed check must fail the change")
        .message;
        assert!(err.ends_with("restored the previous /etc/x"), "{err}");
        let Connection::Mock(mock) = &conn else {
            unreachable!()
        };
        assert_eq!(mock.issued_commands().last(), Some(&restore_as("755")));
        assert!(
            !mock
                .issued_commands()
                .iter()
                .any(|command| command.contains("'4755'")),
            "{:?}",
            mock.issued_commands()
        );
        assert_eq!(super::restored_mode(0o4755, Some("4755")), 0o4755);
        assert_eq!(super::restored_mode(0o6755, Some("4755")), 0o4755);
        assert_eq!(super::restored_mode(0o7777, Some("1777")), 0o1777);
        assert_eq!(super::restored_mode(0o2644, Some("644")), 0o644);
        assert_eq!(super::restored_mode(0o4755, None), 0o755);
    }

    /// A snapshot that refuses — a link at the name, something that isn't a regular file,
    /// a file past the limit — or whose answer doesn't parse fails the change before
    /// anything is written; the refusal names the path.
    #[tokio::test]
    async fn a_refused_or_garbled_snapshot_fails_the_change_before_the_write() {
        let refused = CommandOutput {
            success: false,
            code: zap_types::put::REFUSED_EXIT,
            stdout: String::new(),
            stderr: "zap: /etc/x: a symbolic link is not read through; left unchanged\n".to_owned(),
        };
        for (answer, says) in [
            (refused, "a symbolic link is not read through"),
            (stdout_output("file 644 0 0 9\nold"), "doesn't parse"),
            (stdout_output("file 644 0 0 3\noldX"), "doesn't parse"),
            (stdout_output("file 6x4 0 0 3\nold"), "doesn't parse"),
            (stdout_output("absent\nX"), "doesn't parse"),
            (stdout_output("old"), "doesn't parse"),
        ] {
            let conn = Connection::Mock(MockConnection::new("m").with(snapshot_x(), answer));
            let err = write_validated(
                &conn,
                None,
                "/etc/x",
                &validated_file(),
                "nginx -t",
                "nginx -t",
            )
            .await
            .expect_err("a snapshot that didn't read fails the change")
            .message;
            assert!(err.contains("/etc/x") && err.contains(says), "{err}");
            let Connection::Mock(mock) = &conn else {
                unreachable!()
            };
            assert_eq!(
                mock.issued_commands(),
                [snapshot_x()],
                "nothing was written"
            );
        }
    }

    #[tokio::test]
    async fn a_write_that_failed_before_its_install_restores_nothing() {
        // The put fails and the path still holds what was snapshotted: nothing to roll
        // back, so no restore runs (a mock errors on an unrecorded command) and the
        // failure says the file was not changed.
        let conn = Connection::Mock(
            MockConnection::new("m")
                .with(snapshot_x(), stdout_output("file 644 0 0 3\nold"))
                .with(
                    declared_put(),
                    failed_output("zap: /etc/x: no chown on this machine"),
                ),
        );
        let err = write_validated(
            &conn,
            None,
            "/etc/x",
            &validated_file(),
            "nginx -t",
            "nginx -t",
        )
        .await
        .expect_err("a failed write fails the change")
        .message;
        assert!(err.ends_with("; /etc/x was not changed"), "{err}");
        assert!(
            !err.contains("restored") && !err.contains("rollback"),
            "{err}"
        );
        let Connection::Mock(mock) = &conn else {
            unreachable!()
        };
        assert_eq!(
            mock.issued_commands(),
            [snapshot_x(), declared_put(), snapshot_x()],
            "the path read again, and nothing written back"
        );
    }

    #[tokio::test]
    async fn write_validated_removes_a_new_file_when_the_check_fails() {
        // Nothing was there before, so rollback removes what the write created.
        let conn = Connection::Mock(
            MockConnection::new("m")
                .with(snapshot_x(), stdout_output("absent\n"))
                .with(declared_put(), ok_output())
                .with("nginx -t", failed_output("[emerg] bad"))
                .with("rm -f -- '/etc/x'", ok_output()),
        );
        let err = write_validated(
            &conn,
            None,
            "/etc/x",
            &validated_file(),
            "nginx -t",
            "nginx -t",
        )
        .await
        .expect_err("a failed check must fail the change")
        .message;
        assert!(err.ends_with("removed the new /etc/x"), "{err}");
        let Connection::Mock(mock) = &conn else {
            unreachable!()
        };
        assert!(
            mock.issued("rm -f -- '/etc/x'"),
            "the new file wasn't removed"
        );
    }

    #[tokio::test]
    async fn write_validated_says_so_when_the_rollback_fails() {
        // A restore that can't complete must not read as a clean rollback: the message
        // names the file as still holding the rejected content.
        let conn = Connection::Mock(
            MockConnection::new("m")
                .with(snapshot_x(), stdout_output("absent\n"))
                .with(declared_put(), ok_output())
                .with("nginx -t", failed_output("[emerg] bad"))
                .with(
                    "rm -f -- '/etc/x'",
                    failed_output("rm: Read-only file system"),
                ),
        );
        let err = write_validated(
            &conn,
            None,
            "/etc/x",
            &validated_file(),
            "nginx -t",
            "nginx -t",
        )
        .await
        .expect_err("a failed check must fail the change")
        .message;
        assert!(
            err.contains("rollback failed, so /etc/x still holds the rejected content"),
            "{err}"
        );
    }

    /// A validated write's failure keeps the code of what failed — its check — whatever
    /// the rollback then did: restored the file, or failed for a reason of another kind.
    /// A check that exits 127 is not found, though its words say nothing.
    #[tokio::test]
    async fn a_rolled_back_write_keeps_the_code_of_its_check() {
        let not_installed = CommandOutput {
            success: false,
            code: 127,
            stdout: String::new(),
            stderr: "sh: 1: nginx: nope\n".to_owned(),
        };
        let validated = |conn: Connection| async move {
            write_validated(
                &conn,
                None,
                "/etc/x",
                &validated_file(),
                "nginx -t",
                "nginx -t",
            )
            .await
            .unwrap_err()
        };
        let restored = validated(Connection::Mock(
            existing_file_mock()
                .with("nginx -t", not_installed.clone())
                .with(restoring_put(), ok_output()),
        ))
        .await;
        assert_eq!(restored.code, ErrorCode::NotFound, "{}", restored.message);
        assert_eq!(
            restored.message,
            "validate `nginx -t` exited 127: sh: 1: nginx: nope; restored the previous /etc/x"
        );
        let unrestored = validated(Connection::Mock(
            MockConnection::new("m")
                .with(snapshot_x(), stdout_output("absent\n"))
                .with(declared_put(), ok_output())
                .with("nginx -t", not_installed)
                .with(
                    "rm -f -- '/etc/x'",
                    failed_output("rm: cannot remove '/etc/x': Permission denied"),
                ),
        ))
        .await;
        assert_eq!(
            unrestored.code,
            ErrorCode::NotFound,
            "{}",
            unrestored.message
        );
        assert_eq!(
            unrestored.message,
            "validate `nginx -t` exited 127: sh: 1: nginx: nope; rollback failed, so /etc/x \
             still holds the rejected content: failed to remove /etc/x: rm: cannot remove \
             '/etc/x': Permission denied"
        );
    }

    /// A `validate` that says why on stdout alone — stderr empty, or only whitespace — is
    /// reported and classified by what it printed there.
    #[tokio::test]
    async fn a_validate_that_reports_on_stdout_is_read_from_it() {
        let conn = Connection::Mock(MockConnection::new("m").with(
            "nginx -t",
            CommandOutput {
                success: false,
                code: 1,
                stdout: "open() \"/etc/x\" failed (13: Permission denied)\n".to_owned(),
                stderr: " \n".to_owned(),
            },
        ));
        let Failure { code, message } = run_validate(&conn, "nginx -t", "nginx -t")
            .await
            .unwrap_err();
        assert_eq!(code, ErrorCode::Permission, "{message}");
        assert_eq!(
            message,
            "validate `nginx -t` exited 1: open() \"/etc/x\" failed (13: Permission denied)"
        );
    }

    #[tokio::test]
    async fn a_source_file_is_put_with_its_declared_mode_and_owner() {
        // `source` content takes the same one write as inline content: the declared
        // mode, owner, and group are the put's arguments. A mock errors on an
        // unrecorded command, so a put without them would fail the change.
        let file: zap_types::schema::FileResource = serde_json::from_value(serde_json::json!({
            "path": "/etc/x",
            "content": {"type": "source", "path": "/srv/x.src"},
            "mode": "640",
            "owner": "app",
            "group": "www",
        }))
        .unwrap();
        let attrs = FileAttrs {
            mode: Some("640"),
            owner: Some("app"),
            group: Some("www"),
            ..FileAttrs::NONE
        }
        .keeping();
        let snapshot = zap_types::put::file_snapshot_command(RunAs::Caller, "/srv/x.src");
        let conn = Connection::Mock(
            MockConnection::new("m")
                .with(snapshot.as_str(), stdout_output("file 600 0 0 4\na=1\n"))
                .with(put_x(attrs), ok_output()),
        );
        let summary = super::materialize_file(&conn, None, "/etc/x", &file)
            .await
            .unwrap();
        assert_eq!(summary, "wrote /etc/x");
        let Connection::Mock(mock) = &conn else {
            unreachable!()
        };
        assert_eq!(
            mock.issued_commands(),
            [snapshot.as_str(), put_x(attrs).as_str()]
        );
        assert!(put_x(attrs).ends_with("sh '/etc/x' '640' 'app:www' '' 'keep'"));
    }

    /// The command a mock is asked for that makes `path` and its missing parents.
    fn mkdirs(path: &str) -> String {
        zap_types::put::make_dirs_command(RunAs::Caller, path)
    }

    /// The constant scripts `command` runs.
    fn scripts_in(command: &str) -> Vec<&'static str> {
        [
            zap_types::put::FILE_PUT,
            zap_types::put::DIR_ATTRS,
            zap_types::put::FILE_SNAPSHOT,
            zap_types::put::MAKE_DIRS,
            zap_types::extract::EXTRACT_ARCHIVE,
        ]
        .into_iter()
        .filter(|script| command.contains(script))
        .collect()
    }

    /// Every constant script `conn` was asked to run is one `change`'s plan binds
    /// (`Change::native_scripts`), and it was asked to run at least one.
    fn assert_binds_what_ran(conn: &Connection, change: &Change) {
        let Connection::Mock(mock) = conn else {
            unreachable!()
        };
        let ran: Vec<&str> = mock
            .issued_commands()
            .iter()
            .flat_map(|command| scripts_in(command))
            .collect();
        assert!(!ran.is_empty(), "{:?}", mock.issued_commands());
        let bound = change.native_scripts();
        for script in ran {
            assert!(bound.contains(&script), "unbound: {}", &script[..40]);
        }
    }

    /// What zap runs to carry out a `file` or `directory` change — through the put, the
    /// snapshot, and the directory script, which no step of the plan holds — is what
    /// the plan's hash binds: the file's write, a validated file's snapshot and
    /// rollback, the directory's mode.
    #[tokio::test]
    async fn the_scripts_a_native_change_runs_are_the_ones_its_plan_binds() {
        let file = change(
            serde_json::json!({"id": "f", "type": "file", "path": "/etc/x", "mode": "600",
                "content": {"type": "inline", "content": "new"}}),
            Vec::new(),
        );
        let conn = Connection::Mock(
            MockConnection::new("m")
                .with(mkdirs("/etc"), ok_output())
                .with(declared_put(), ok_output()),
        );
        run_change(&conn, None, &file).await.unwrap();
        assert_binds_what_ran(&conn, &file);

        let validated = change(
            serde_json::json!({"id": "f", "type": "file", "path": "/etc/x", "mode": "600",
                "content": {"type": "inline", "content": "new"}, "validate": "nginx -t"}),
            Vec::new(),
        );
        let conn = Connection::Mock(
            existing_file_mock()
                .with(mkdirs("/etc"), ok_output())
                .with("nginx -t", failed_output("bad"))
                .with(restoring_put(), ok_output()),
        );
        run_change(&conn, None, &validated).await.unwrap_err();
        assert_binds_what_ran(&conn, &validated);

        let directory = change(
            serde_json::json!({"id": "d", "type": "directory", "path": "/srv/d", "mode": "750"}),
            Vec::new(),
        );
        let conn = Connection::Mock(
            MockConnection::new("m")
                .with(mkdirs("/srv/d"), ok_output())
                .with(
                    zap_types::put::dir_attrs_command(
                        RunAs::Caller,
                        "/srv/d",
                        FileAttrs::mode("750"),
                    ),
                    ok_output(),
                ),
        );
        run_change(&conn, None, &directory).await.unwrap();
        assert_binds_what_ran(&conn, &directory);
    }

    /// A remote archive's change runs only scripts its plan binds — the extraction (which
    /// writes the sentinel) and, with a declared mode, the directory script on what it
    /// extracted — carried out whole through `run_change` from a seeded content cache.
    #[tokio::test]
    async fn a_remote_archive_change_runs_only_scripts_its_plan_binds() {
        let home = tempfile::tempdir().unwrap();
        let body = b"archive-bytes";
        let pin = blake3::hash(body).to_hex().to_string();
        let cached = home.path().join("cache/files").join(&pin);
        std::fs::create_dir_all(&cached).unwrap();
        std::fs::write(cached.join("zig.tar.xz"), body).unwrap();
        let archive = change(
            serde_json::json!({"id": "zig", "type": "file", "path": "/opt/zig", "mode": "755",
                "content": {"type": "remote", "url": "https://h/zig.tar.xz", "blake3": pin,
                    "extract": {"type": "tar.xz"}}}),
            Vec::new(),
        );
        let mode = ExtractMode::TarXz {
            strip_components: 0,
        };
        let dir = "/tmp/zap-remote-t";
        let staged = format!("{dir}/archive.tar.xz");
        let dir_attrs =
            zap_types::put::dir_attrs_command(RunAs::Caller, "/opt/zig", FileAttrs::mode("755"));
        let conn = Connection::Mock(
            MockConnection::new("m")
                .with(mkdirs("/opt"), ok_output())
                .with(
                    "mktemp -d -- '/tmp/zap-remote-XXXXXX'",
                    stdout_output(&format!("{dir}\n")),
                )
                .with(
                    extract(
                        RunAs::Root,
                        &staged,
                        "/opt/zig",
                        mode,
                        Some(&extract_provenance(&pin, mode)),
                        &crate::digest::sha512_hex(body),
                    ),
                    ok_output(),
                )
                .with(format!("rm -rf -- {}", single_quote(dir)), ok_output())
                .with(dir_attrs.clone(), ok_output()),
        );
        run_change(&conn, Some(home.path()), &archive)
            .await
            .unwrap();
        let Connection::Mock(mock) = &conn else {
            unreachable!()
        };
        assert!(mock.issued(&dir_attrs), "{:?}", mock.issued_commands());
        assert_binds_what_ran(&conn, &archive);
    }

    /// A url `curl` is handed is held, as it resolved, to the rule for every url zap
    /// fetches: the change is refused before anything runs, naming the field and the
    /// declared url, never the value.
    #[test]
    fn a_url_that_resolves_to_one_zap_would_not_fetch_refuses_its_change() {
        use zap_types::plan::{Change, ChangeAction};
        use zap_types::schema::{Resource, ResourceId};
        use zap_types::var_ref::marker;

        let _env = crate::resolve::test_env::set(&[
            ("ZAP_T_MIRROR_SECRET", "http://mirror.secret.example"),
            ("ZAP_T_LOOPBACK", "http://127.0.0.1:8080"),
            ("ZAP_T_HTTPS", "https://mirror.example"),
        ]);
        let change = |resource: serde_json::Value| {
            let desired: Resource = serde_json::from_value(resource).unwrap();
            Change {
                resource_id: desired.id.clone(),
                action: ChangeAction::Create,
                steps: Vec::new(),
                desired,
                depends_on: Vec::<ResourceId>::new(),
                trigger: None,
            }
        };
        let url =
            |name: &str, path: &str| serde_json::json!(Text::of_pieces([Ref(name), Lit(path)]));
        let error = change_commands(&change(
            serde_json::json!({"id": "tool", "type": "installer", "check": "/opt/tool",
                "url": url("ZAP_T_MIRROR_SECRET", "/install.sh")}),
        ))
        .map(|_| ())
        .unwrap_err();
        assert!(
            error.starts_with(&format!(
                "installer `url` `{}",
                marker("ZAP_T_MIRROR_SECRET")
            )),
            "{error}"
        );
        assert!(
            error.contains("resolves to a value that is not an `https://` URL"),
            "{error}"
        );
        assert!(!error.contains("secret"), "{error}");
        // The target fetches it: plain http is refused for a loopback host too.
        let error = change_commands(&change(
            serde_json::json!({"id": "tool", "type": "installer", "check": "/opt/tool",
            "url": url("ZAP_T_LOOPBACK", "/install.sh")}),
        ))
        .map(|_| ())
        .unwrap_err();
        assert!(
            error.contains(
                "`url` resolves to a value that is not an `https://` URL; the target fetches \
                 it, over https only"
            ),
            "{error}"
        );
        change_commands(&change(
            serde_json::json!({"id": "tool", "type": "installer", "check": "/opt/tool",
            "url": url("ZAP_T_HTTPS", "/install.sh")}),
        ))
        .map(|_| ())
        .unwrap();
    }

    /// A `database`'s names and hosts are held, as they resolved, to what a `pg_hba.conf`
    /// rule line reads as itself before any command is composed: the change is refused,
    /// naming the field and the declared text, never the value.
    #[test]
    fn a_database_field_that_resolves_to_one_a_rule_line_misreads_refuses_its_change() {
        use zap_types::plan::{Change, ChangeAction};
        use zap_types::schema::{Resource, ResourceId};
        use zap_types::var_ref::marker;

        let _env = crate::resolve::test_env::set(&[
            ("ZAP_T_HBA_ROLE_SECRET", "all"),
            ("ZAP_T_HBA_NET_SECRET", "0.0.0.0/0 trust #hidden"),
            ("ZAP_T_HBA_PLAIN", "app"),
        ]);
        let reference = |name: &str| serde_json::json!({"$env": name});
        let change = |username: serde_json::Value, hosts: serde_json::Value| {
            let desired: Resource = serde_json::from_value(serde_json::json!({
                "id": "db", "type": "database", "engine": "postgresql",
                "database_name": "app", "username": username, "auth": {"hosts": hosts},
            }))
            .unwrap();
            Change {
                resource_id: desired.id.clone(),
                action: ChangeAction::Create,
                steps: Vec::new(),
                desired,
                depends_on: Vec::<ResourceId>::new(),
                trigger: None,
            }
        };
        for (username, hosts, starts, problem) in [
            (
                reference("ZAP_T_HBA_ROLE_SECRET"),
                serde_json::json!([]),
                format!("database `username` `{}`", marker("ZAP_T_HBA_ROLE_SECRET")),
                "`username` resolves to a value that is `all`, which `pg_hba.conf` reads as a keyword",
            ),
            (
                serde_json::json!("app"),
                serde_json::json!(["10.0.0.0/8", reference("ZAP_T_HBA_NET_SECRET")]),
                format!(
                    "database `auth.hosts[1]` `{}`",
                    marker("ZAP_T_HBA_NET_SECRET")
                ),
                "`auth.hosts[1]` resolves to a value that holds a character that changes what \
                 a `pg_hba.conf` rule line means",
            ),
        ] {
            let error = change_commands(&change(username, hosts))
                .map(|_| ())
                .unwrap_err();
            assert!(error.starts_with(&starts), "{error}");
            assert!(error.contains(problem), "{error}");
            assert!(!error.contains("hidden"), "{error}");
            assert!(!error.contains("0.0.0.0"), "{error}");
        }
        change_commands(&change(
            reference("ZAP_T_HBA_PLAIN"),
            serde_json::json!(["10.0.0.0/8"]),
        ))
        .map(|_| ())
        .unwrap();
    }

    /// One-shot loopback HTTP server: serves `body` once, returns its url.
    fn serve_once(body: Vec<u8>) -> String {
        use std::io::{Read as _, Write as _};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            if let Ok((mut socket, _)) = listener.accept() {
                let mut buf = [0u8; 1024];
                let _ = socket.read(&mut buf);
                let header = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = socket.write_all(header.as_bytes());
                let _ = socket.write_all(&body);
                let _ = socket.flush();
            }
        });
        format!("http://{addr}/pgdg.asc")
    }

    /// The `apt_repo` change for a repo whose key is fetched from `url` and pinned to
    /// `pin` (vendored, as a tracked key's lock pin is folded into the fact).
    fn apt_repo_change(url: &str, pin: &str) -> Change {
        let resource: Resource = serde_json::from_value(serde_json::json!({
            "id": "pgdg", "type": "apt_repo", "key_url": url, "key_blake3": pin,
            "source": "deb https://example.test/apt stable main",
        }))
        .unwrap();
        let resources = [resource];
        let detected = std::iter::once((
            resources[0].id.clone(),
            zap_types::detected::Detection::Absent,
        ))
        .collect();
        let plan = zap_types::plan::diff(zap_types::plan::DiffInputs {
            resources: &resources,
            detected: &detected,
            target: &Target::local(),
            machine: &local_machine(),
            lock: None,
            pending: &std::collections::BTreeMap::new(),
            var: &zap_types::last_run::ReportVar::unset,
        })
        .plan;
        plan.changes.into_iter().next().unwrap()
    }

    /// An `apt_repo` installs its key — the bytes its pin names, from the content
    /// cache, through the put script at `644 root:root` — before its list is written and
    /// the index refreshed; nothing fetches the key on the target.
    #[tokio::test]
    async fn an_apt_repo_installs_its_pinned_key_before_its_list() {
        let home = crate::test_scratch::tempdir();
        let url = "https://example.test/pgdg.asc";
        let pin = crate::resolver::store_content(home.path(), url, b"pgdg key\n")
            .await
            .unwrap();
        let change = apt_repo_change(url, pin.as_str());
        let mkdirs = zap_types::put::make_dirs_command(RunAs::Caller, "/usr/share/keyrings");
        let key_put = zap_types::put::file_put_command(
            RunAs::Caller,
            "/usr/share/keyrings/pgdg.asc",
            zap_types::schema::APT_KEY_ATTRS,
            zap_types::put::PutCheck::None,
        );
        let mut mock = MockConnection::new("m")
            .with(mkdirs.clone(), ok_output())
            .with(key_put.clone(), ok_output());
        let mut stepped = Vec::new();
        for step in &change.steps {
            let text = step.execution().unwrap().text().to_owned();
            mock = mock.with(text.clone(), ok_output());
            stepped.push(text);
        }
        let conn = Connection::Mock(mock);
        let summary = run_change(&conn, Some(home.path()), &change).await.unwrap();
        assert!(summary.starts_with("installed key "), "{summary}");
        let Connection::Mock(mock) = &conn else {
            unreachable!()
        };
        let mut expected = vec![mkdirs, key_put];
        expected.extend(stepped);
        assert_eq!(mock.issued_commands(), expected);
        assert!(!expected.iter().any(|command| command.contains("curl")));
    }

    /// A fetched key whose bytes aren't its pin's fails the change naming both digests,
    /// and nothing runs on the target: the live key is never replaced by unpinned bytes.
    #[tokio::test]
    async fn an_apt_key_that_is_not_its_pin_changes_nothing() {
        let home = crate::test_scratch::tempdir();
        let pin = zap_types::scalar::ContentHash::of_bytes(b"pgdg key\n");
        let fetched = zap_types::scalar::ContentHash::of_bytes(b"rotated key\n");
        let url = serve_once(b"rotated key\n".to_vec());
        let change = apt_repo_change(&url, pin.as_str());
        let conn = Connection::Mock(MockConnection::new("m"));
        let Failure { message, .. } = run_change(&conn, Some(home.path()), &change)
            .await
            .unwrap_err();
        assert!(message.contains(pin.as_str()), "{message}");
        assert!(message.contains(fetched.as_str()), "{message}");
        let Connection::Mock(mock) = &conn else {
            unreachable!()
        };
        assert!(
            mock.issued_commands().is_empty(),
            "{:?}",
            mock.issued_commands()
        );
    }

    /// A key past what detection can read back is refused at install, before anything
    /// runs: a cached one by its read (at most one byte past the cap is read), a fetched
    /// one by the fetch, which stops at the cap.
    #[tokio::test]
    async fn an_apt_key_over_the_cap_is_refused_before_anything_runs() {
        let max = usize::try_from(zap_types::observe::apt_repo::KEY_READ_MAX).unwrap();
        let oversized = vec![b'k'; max + 1];
        let home = crate::test_scratch::tempdir();
        let url = "https://example.test/big.asc";
        let pin = crate::resolver::store_content(home.path(), url, &oversized)
            .await
            .unwrap();
        let conn = Connection::Mock(MockConnection::new("m"));
        let Failure { message, .. } = run_change(
            &conn,
            Some(home.path()),
            &apt_repo_change(url, pin.as_str()),
        )
        .await
        .unwrap_err();
        assert!(message.contains("larger than"), "{message}");
        let served = serve_once(oversized);
        let other = zap_types::scalar::ContentHash::of_bytes(b"another key");
        let Failure { message, .. } = run_change(
            &conn,
            Some(home.path()),
            &apt_repo_change(&served, other.as_str()),
        )
        .await
        .unwrap_err();
        assert!(message.contains(&format!("{max}-byte cap")), "{message}");
        let Connection::Mock(mock) = &conn else {
            unreachable!()
        };
        assert!(
            mock.issued_commands().is_empty(),
            "{:?}",
            mock.issued_commands()
        );
    }

    /// The `Debug` of a change's commands shows their shape, the declared text, and the
    /// variables' names — no resolved command or value.
    #[test]
    fn change_commands_debug_shows_no_resolved_value() {
        let secret = "hunter2-s3cret";
        let commands = [
            ChangeCommands::Steps {
                steps: vec![
                    StepCommand {
                        name: "`curl`".to_owned(),
                        action: StepAction::Run(format!("curl -H {secret}")),
                    },
                    StepCommand {
                        name: "install".to_owned(),
                        action: StepAction::Put {
                            command: "sh -c put".to_owned(),
                            content: "x\n",
                        },
                    },
                ],
                options: RunOptions {
                    cwd: None,
                    env: vec![("TOKEN".to_owned(), secret.to_owned())],
                },
            },
            ChangeCommands::File {
                validate: Some(("nginx -t -c conf", format!("nginx -t {secret}"))),
            },
            ChangeCommands::Build {
                run: format!("make {secret}"),
                env: vec![("BUILD_TOKEN".to_owned(), secret.to_owned())],
            },
            ChangeCommands::None,
        ];
        let shown = format!("{commands:?} {commands:#?}");
        assert!(!shown.contains("hunter2"), "{shown}");
        for name in [
            "`curl`",
            "sh -c put",
            "nginx -t -c conf",
            "TOKEN",
            "BUILD_TOKEN",
        ] {
            assert!(shown.contains(name), "{name}: {shown}");
        }
    }
}
