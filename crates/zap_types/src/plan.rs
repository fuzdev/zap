//! The plan fact — the executable changeset.
//!
//! Each `Change` is a *decided mutation* keyed by `resource_id` (no `id` / UUID —
//! a random id in a content-addressed fact is self-contradictory). What the
//! executor consumes and nothing else: the action, the exact commands, the
//! desired state, and the dependency/trigger ordering. Detection-derived
//! *narrative* (the current/`before` state, the human `reason`, unchanged/skip
//! entries) and *execution state* (the per-change outcome, timestamps, output,
//! errors) are
//! deliberately **not** here — narrative is a render-time detection join, and
//! execution state is `event::ChangeOutcome`, populated by `zap_core`.
//! `config_hash::plan_hash` is blake3 over this struct's canonical JSON, on the `Plan`
//! hash domain — its own version axis, not a resource's `config_hash`'s.
//!
//! A plan is **for one machine**: beside the declared target, whose references
//! stay inert, it carries the [`Machine`] those references resolve to — the host, and
//! the user the run connects as; for the machine zap runs on, the user zap runs as and
//! the home its paths' `~` resolves to. So one declaration under two environments is two
//! plans with two hashes, and a review of one is not a review of the other.
//!
//! A plan is **for one environment** the same way: its changes keep their references
//! inert, and beside them it carries what each reference they use resolved to
//! ([`Plan::references`], a [`ReferenceValue`] by name). A path, a URL, a command or an
//! `env` value that comes from the environment is therefore part of the plan and of its
//! hash, and the same changeset under another value is another plan. A secret is the
//! exception by design: the plan says a reference is one and holds none of its value.
//!
//! The `before` / `reason` / skip exclusion is the leaner, leak-safe cut (current
//! on-target contents can't leak into an emitted fact; the hash doesn't thrash on
//! incidental detected-state noise). The `--diff` renderer
//! (`zap_core`'s `render_plan_diff` over the pure `diff_view`) settles the boundary:
//! the `before` state stays out of the fact and is rejoined at render time from the
//! in-memory detection map against each `Change.desired` — never persisted or hashed.
//!
//! The *desired* side, by contrast, is resolved **into** the fact: a tracked
//! `remote_file`/`build` source's or `apt_repo` key's pin lives in the lock (config
//! carries `blake3: None` / `key_blake3: None`),
//! so [`diff`] folds the lock pin into each `Change.desired` (`fold_tracked_pin`). The
//! fact thus carries the fully-resolved desired pin (config ⊕ lock) — making `plan_hash`
//! a faithful content address (advancing a pin via `zap update` changes the hash) and
//! the same desired-state completeness `compute_config_hash` already has. The pin is
//! committed, version-controlled desired state, categorically unlike the environment
//! values (references / `~`/`$HOME` / `auth`) that stay inert in each change by design
//! — a reference's value is recorded beside the changes, never substituted into one.

use std::cmp::Reverse;
use std::collections::{BTreeMap, BTreeSet, BinaryHeap};

use serde::{Deserialize, Serialize};

use crate::detected::{CurrentState, Detection};
use crate::event::ChangeOutcome;
use crate::last_run::{LOCAL_HOST, ReportVar, host_label, resolved_label};
use crate::lock::ZapLock;
use crate::scalar::{EnvVarName, PackageName};
use crate::schema::{
    BuildSource, FileContent, PackageResource, Resource, ResourceId, ResourceKind, ResourceType,
    ScriptResource, Target,
};
use crate::text::Text;
use crate::var_ref::ref_names;
use crate::{package_managers, service_managers};

mod step;
mod steps;

pub use step::{
    DirStep, InstallerStep, PgHbaRuleStep, PlanStep, ProducerSummary, PutAs, PutCommand, PutMode,
    PutProducer, PutSource, PutStep, PutText, SWAP_PATH_CHECK, StepExecution, StepSummary,
    SwapCheckStep,
};

/// The mutation a change performs.
///
/// Skipped/converged resources are absent from the fact (they're derived for the
/// dry-run view), so there is no `skip` variant. There is no `delete` either: the
/// planner never removes undeclared state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChangeAction {
    /// The resource does not exist and will be created.
    Create,
    /// The resource exists but diverges from desired and will be updated.
    Update,
}

/// Which lifecycle action a triggered service performs after its sources complete.
///
/// One enum rather than a `trigger_restart` + `trigger_reload` boolean pair, whose
/// `{true, true}` would be representable but meaningless — a change does one or the
/// other.
/// Ordered so the stronger action is the max: a restart subsumes a reload.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TriggerKind {
    /// A reload of the running service after the trigger sources complete
    /// (`systemctl try-reload-or-restart`, `rc-service --ifstarted <svc> reload`).
    Reload,
    /// A restart of the running service after the trigger sources complete
    /// (`systemctl try-restart`, `rc-service --ifstarted <svc> restart`).
    Restart,
}

impl TriggerKind {
    /// The marker-file spelling of this kind (`restart` / `reload`).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Reload => "reload",
            Self::Restart => "restart",
        }
    }

    /// Parse a marker-file spelling; `None` for anything else.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "reload" => Some(Self::Reload),
            "restart" => Some(Self::Restart),
            _ => None,
        }
    }
}

/// Why a service change carries a restart/reload, and what arms its pending marker.
///
/// A trigger is **at-least-once**: the executor records a pending marker on the target
/// before the first of its `sources` runs and clears it only after the service's own
/// change completes, so an apply that dies anywhere between leaves the marker, and the
/// next plan re-fires the action from it (`pending`). At least one of `sources` /
/// `pending` is set — a trigger with neither is never built.
///
/// The action acts only on a running service: a stopped one is left stopped, and its
/// change completing clears the marker all the same, since a service that isn't running
/// owes nothing — it starts on the new state. A trigger on a service declared
/// `running: false` is a config error (`validate::triggers_on_stopped_services`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Trigger {
    /// The lifecycle action — the stronger of what the sources and a pending marker ask
    /// for.
    pub kind: TriggerKind,
    /// The changes in this plan that fire it (trigger sources that aren't converged).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sources: Vec<ResourceId>,
    /// An earlier apply fired it and never completed the action (a pending marker was
    /// found on the target).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub pending: bool,
}

/// One decided mutation — exactly what the executor consumes.
///
/// A batched install and its cache update are changes of no declared resource: each
/// carries a stand-in `desired` that declares nothing of its own (a `package` with no
/// name, a `script`), and what it does is its steps.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Change {
    /// Identity across plan, lock, the last-run report, and events.
    pub resource_id: ResourceId,
    /// The mutation to perform.
    pub action: ChangeAction,
    /// Steps to run, in order — executable [`PlanStep::Run`] commands and typed
    /// operations interleaved with non-executable [`PlanStep::Note`] previews. Empty for
    /// native-IO resources (file/directory/link write via `desired` + `std::fs` — no
    /// pre-baked command).
    pub steps: Vec<PlanStep>,
    /// Fully-resolved desired resource state (drives native-IO resources and
    /// verification). For a tracked `remote_file`/`build` source (or `apt_repo` key) this
    /// is the authored config with the lock pin folded into `blake3` (`key_blake3`)
    /// (`fold_tracked_pin`) — config ⊕
    /// lock, not the symbolic `blake3: None`. The authored form stays in
    /// `ZapConfig::resources`; references / `~`/`$HOME` / `auth` remain inert here.
    pub desired: Resource,
    /// Resource IDs this change waits on (the resource-graph edges).
    pub depends_on: Vec<ResourceId>,
    /// Lifecycle action fired by a trigger (`file.triggers` push / `restart_on` /
    /// `reload_on` pull, or a pending marker an earlier apply left); `None` when no
    /// trigger fired.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trigger: Option<Trigger>,
}

impl Change {
    /// The constant scripts carrying out this change can run that none of its steps
    /// holds: a `file`, `directory`, or `build` change has no step for zap's own write —
    /// `zap_core` makes a file's or directory's missing directories through
    /// [`MAKE_DIRS`](crate::put::MAKE_DIRS), installs a file through
    /// [`FILE_PUT`](crate::put::FILE_PUT), sets a
    /// directory's mode and owner through [`DIR_ATTRS`](crate::put::DIR_ATTRS), and
    /// extracts an archive through [`EXTRACT_ARCHIVE`](crate::extract::EXTRACT_ARCHIVE),
    /// each run as root over SSH and wherever a native write on the machine zap runs on
    /// is refused, and reads what a validated file's write replaces through
    /// [`FILE_SNAPSHOT`](crate::put::FILE_SNAPSHOT); a `link` is made through
    /// [`LINK_PUT`](crate::put::LINK_PUT). A `service` with a trigger records its pending
    /// marker (under `/var/lib/zap/pending`) through
    /// [`MAKE_DIRS`](crate::put::MAKE_DIRS), [`DIR_ATTRS`](crate::put::DIR_ATTRS), and
    /// [`FILE_PUT`](crate::put::FILE_PUT) before the first source runs. An `apt_repo`
    /// installs its signing key, ahead of its steps, through
    /// [`MAKE_DIRS`](crate::put::MAKE_DIRS) and [`FILE_PUT`](crate::put::FILE_PUT).
    /// Empty for every other kind, whose steps hold what it runs.
    ///
    /// A script listed that a run doesn't reach (a directory with no mode or owner, a
    /// local write that succeeds natively) only widens what the hash binds.
    #[must_use]
    pub fn native_scripts(&self) -> Vec<&'static str> {
        self.native()
            .into_iter()
            .map(|(script, _)| script)
            .collect()
    }

    /// The commands [`native_scripts`](Self::native_scripts) run in, as `zap_core`
    /// composes them, with every value the change supplies — a path, a mode, an owner, a
    /// pin — left empty: what `plan_hash` covers of them, as it covers a typed step's
    /// text. So a plan reviewed under one zap is not the plan of a zap whose scripts, or
    /// the arguments, privilege, or limits it calls them with, differ.
    #[must_use]
    pub fn native_commands(&self) -> Vec<String> {
        self.native()
            .into_iter()
            .map(|(_, command)| command)
            .collect()
    }

    /// Each native script with its command template ([`native_commands`](Self::native_commands)).
    fn native(&self) -> Vec<(&'static str, String)> {
        use crate::extract::{EXTRACT_ARCHIVE, extract_archive_command};
        use crate::put::{
            DIR_ATTRS, FILE_PUT, FILE_SNAPSHOT, FileAttrs, LINK_PUT, MAKE_DIRS, PutCheck, RunAs,
            dir_attrs_command, file_put_command, file_snapshot_command, link_put_command,
            make_dirs_command,
        };

        // A `file`'s own write keeps what it leaves unset; zap's other files (a build's
        // provenance sidecar, a validated write's rollback) are fresh.
        let put_as = |attrs| {
            (
                FILE_PUT,
                file_put_command(RunAs::Root, "", attrs, PutCheck::None),
            )
        };
        let put = || put_as(FileAttrs::NONE);
        let keeping_put = || put_as(FileAttrs::NONE.keeping());
        let dir_attrs = || {
            (
                DIR_ATTRS,
                dir_attrs_command(RunAs::Root, "", FileAttrs::NONE),
            )
        };
        let make_dirs = || (MAKE_DIRS, make_dirs_command(RunAs::Root, ""));
        match &self.desired.kind {
            // Each `file` first makes its missing parent directories. An archive: the
            // extraction (as root, replacing another pin's tree, and writing the sentinel
            // recording its pin) and the extracted directory's mode and owner.
            ResourceKind::File(file) => match &file.content {
                FileContent::Remote(remote) if remote.extract.is_tar() => vec![
                    make_dirs(),
                    (
                        EXTRACT_ARCHIVE,
                        extract_archive_command(RunAs::Root, "", "", remote.extract, Some(""), ""),
                    ),
                    dir_attrs(),
                ],
                // A validated write: the snapshot it rolls back to, the put, and the
                // rollback's put of the snapshot, which names every attribute.
                _ if file.validate.is_some() => vec![
                    make_dirs(),
                    (FILE_SNAPSHOT, file_snapshot_command(RunAs::Root, "")),
                    keeping_put(),
                    put(),
                ],
                // A `source`: its bytes, read on the target through the snapshot script,
                // then the put.
                FileContent::Source { .. } => vec![
                    make_dirs(),
                    (FILE_SNAPSHOT, file_snapshot_command(RunAs::Root, "")),
                    keeping_put(),
                ],
                _ => vec![make_dirs(), keeping_put()],
            },
            ResourceKind::Directory(_) => vec![make_dirs(), dir_attrs()],
            // The link's own write, as root over SSH.
            ResourceKind::Link(_) => vec![(LINK_PUT, link_put_command("sudo ", "", ""))],
            // A triggered service's pending marker: its directory, and the marker's write.
            // Both directories are given `755` and the marker `644`.
            ResourceKind::Service(_) if self.trigger.is_some() => vec![
                make_dirs(),
                (
                    DIR_ATTRS,
                    dir_attrs_command(RunAs::Root, "", FileAttrs::mode("755")),
                ),
                put_as(FileAttrs::mode("644")),
            ],
            // The source's extraction into the build directory, as the connecting user,
            // and the provenance sidecar beside the output.
            ResourceKind::Build(build) => {
                let BuildSource::Remote(source) = &build.source;
                vec![
                    (
                        EXTRACT_ARCHIVE,
                        extract_archive_command(RunAs::Caller, "", "", source.extract, None, ""),
                    ),
                    put(),
                ]
            }
            // The signing key's install: its directory, then the pinned bytes, put whole.
            ResourceKind::AptRepo(_) => vec![make_dirs(), put_as(crate::schema::APT_KEY_ATTRS)],
            _ => Vec::new(),
        }
    }
}

/// The machine a plan is for: what its declared target resolves to in the environment
/// the plan was computed in.
///
/// The declared [`Target`] names a machine only up to its references — a
/// `host: zap.env('DEPLOY_HOST')` is the same text for every machine the variable can name —
/// so the plan carries the resolved names beside it. They are resolved the way a
/// last-run report labels a host ([`resolved_label`]): a secret reference is its
/// masking token and a value carrying a secret has the secret masked out, so no secret's
/// value is in a plan. A name holding such a token identifies nothing
/// ([`masked_refs`](crate::last_run::masked_refs)); whether a plan with one may be bound
/// to is the caller's rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Machine {
    /// The machine zap runs on, as the account zap runs as — what a remote plan's host
    /// and connecting user are to it.
    Local(LocalAccount),
    /// A machine reached over SSH.
    Remote {
        /// The host, its references resolved.
        host: String,
        /// The user the run connects as, its references resolved — the target's `user`,
        /// or its `bootstrap_user` on a `--bootstrap` run. `None` when none is declared
        /// or it resolves empty: a connection would then name the host alone and `ssh`
        /// pick the user, so `zap_core` plans for a target that declares none and
        /// refuses one whose declared user resolves empty.
        ///
        /// Part of the plan because the same changeset run as another user is another
        /// set of effects: a command step that doesn't itself say `sudo`, and every
        /// login-lane probe (a `script`'s `check` among them), runs as this user —
        /// under its permissions, with its shell, home, and environment, and owning
        /// what the command creates. A path *field* doesn't depend on it: a `~` there
        /// resolves through the declared `target.home`.
        user: Option<String>,
    },
}

impl Machine {
    /// The machine `target` names when its references resolve through `var`, connecting
    /// as `connecting_user` — the declared user the run selected, references unresolved.
    /// A local target is the machine zap runs on, which `local` names; it is called for
    /// no other. `None` when a remote host resolves empty: it names no machine.
    #[must_use]
    pub fn resolve(
        target: &Target,
        connecting_user: Option<&Text>,
        local: impl FnOnce() -> LocalAccount,
        var: impl Fn(&str) -> ReportVar,
    ) -> Option<Self> {
        if target.is_local() {
            return Some(Self::Local(local()));
        }
        let host = host_label(target, &var)?;
        let user = connecting_user
            .map(|user| resolved_label(user, &var))
            .filter(|user| !user.is_empty());
        Some(Self::Remote { host, user })
    }

    /// The host label: `local`, or the resolved remote host — the name a last-run report
    /// of this machine is filed under ([`host_label`]).
    #[must_use]
    pub fn host(&self) -> &str {
        match self {
            Self::Local(_) => LOCAL_HOST,
            Self::Remote { host, .. } => host,
        }
    }

    /// The user the plan's changes run as: the account zap runs as on the machine it
    /// runs on, else the resolved connecting user, when the remote machine has one.
    #[must_use]
    pub fn user(&self) -> Option<&str> {
        match self {
            Self::Local(account) => Some(&account.user),
            Self::Remote { user, .. } => user.as_deref(),
        }
    }
}

/// The account zap runs as on the machine it runs on, read once per run: the effective
/// user and the home a path's `~` resolves to.
///
/// Part of a local plan because the same changeset on the machine zap runs on is another
/// set of effects under another account or another home: every change is made as this
/// user (a native write first, `sudo` only when it is refused), and every `~` or `$HOME`
/// in a path field is this home. A wetrun under `sudo` runs as root, so a plan previewed
/// without it doesn't bind it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalAccount {
    /// The effective user's name, or its uid in decimal when the password database names
    /// none.
    pub user: String,
    /// The home a `~` or `$HOME` in a path field resolves to: `HOME` as the run reads it,
    /// an `--env-file`'s value included. `None` when it is unset or empty, which a path
    /// that references the home then refuses.
    pub home: Option<String>,
}

/// What a reference a plan uses resolved to in the environment the plan was computed in.
///
/// Three states and no fourth: a text with a magic meaning (an empty string for
/// "unset", a token for "secret") would be a value some environment could also hold.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReferenceValue {
    /// The variable's value. A registered secret inside it — a password in a DSN — is
    /// that secret's masking token, so the plan holds no secret's value here either.
    Value(String),
    /// The variable is a secret ([`SecretRule`](crate::secrecy::SecretRule)): the plan
    /// holds none of its value, so two plans that differ only in a secret's value are
    /// one plan with one hash.
    Secret,
    /// The variable is unset or empty. A wetrun's environment gate refuses such a plan
    /// before anything runs; a preview shows it.
    Unset,
}

impl ReferenceValue {
    /// What `var`, the resolver a last-run report and a plan's [`Machine`] read a
    /// reference through, says of a reference.
    #[must_use]
    pub fn of(var: ReportVar) -> Self {
        match var {
            ReportVar::Secret(_) => Self::Secret,
            ReportVar::Value(value) | ReportVar::Masked(value) => {
                if value.is_empty() {
                    Self::Unset
                } else {
                    Self::Value(value)
                }
            }
        }
    }

    /// This value with its text passed through `f` — how a plan's values are masked for
    /// display.
    #[must_use]
    pub fn map_text(&self, f: impl Fn(&str) -> String) -> Self {
        match self {
            Self::Value(value) => Self::Value(f(value)),
            Self::Secret => Self::Secret,
            Self::Unset => Self::Unset,
        }
    }
}

/// What each reference `changes` use resolves to through `var`, by name: every
/// reference in a change's `desired` — a fetch credential's included — and in the text
/// of its steps.
///
/// These are the references a wetrun of this changeset resolves, and no others. A
/// reference of a resource with no change is not among them: nothing of that resource
/// runs, and a value that would change what the resource is makes it drift and enter
/// the changeset. Nor is the target's own text: the plan's [`Machine`] is what its host
/// and connecting user resolve to.
#[must_use]
pub fn references(
    changes: &[Change],
    var: &dyn Fn(&str) -> ReportVar,
) -> BTreeMap<EnvVarName, ReferenceValue> {
    let mut names: BTreeSet<String> = BTreeSet::new();
    for change in changes {
        change.desired.for_each_text(|_, text| {
            names.extend(text.ref_names().map(str::to_owned));
        });
        for step in &change.steps {
            step.for_each_text(|text| names.extend(ref_names(text).map(str::to_owned)));
        }
    }
    names
        .into_iter()
        .filter_map(|name| {
            let value = ReferenceValue::of(var(&name));
            // A reference's name is an `EnvVarName` wherever one is read
            // (`var_ref::segments`), so this never drops one.
            Some((EnvVarName::new(name).ok()?, value))
        })
        .collect()
}

/// The plan fact — an ordered changeset (mutations only, topologically sorted).
///
/// With it: the target it was computed for, the machine that target resolved to, and
/// what the references its changes use resolved to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Plan {
    /// Changes in dependency order.
    pub changes: Vec<Change>,
    /// The machine descriptor the plan was diffed against. Recorded so the fact is
    /// **self-describing**: `Change.steps` are derived from
    /// `target.{package,service}_manager`, so without this the fact wouldn't say
    /// which manager produced them (and `plan_hash` would capture the target only
    /// transitively, via the command strings). Keying it in makes two plans for
    /// different managers hash differently even where their commands coincide.
    pub target: Target,
    /// The machine `target` resolved to when the plan was computed — what makes the
    /// plan, and its hash, one machine's.
    pub machine: Machine,
    /// What each reference the changes use resolved to when the plan was computed
    /// ([`references`]) — what makes the plan, and its hash, one environment's. The
    /// changes themselves keep their references inert, and the executor resolves them
    /// when it runs; a wetrun executes only while they still resolve to these.
    pub references: BTreeMap<EnvVarName, ReferenceValue>,
}

/// The result of plan-diff: the plan fact, the resources held out of it, and any
/// non-fatal warnings.
///
/// Warnings (cycle fallbacks, dangling trigger references) are *narrative* — they
/// render for the operator but are not part of the content-addressed fact.
/// [`held`](Self::held) is **not** narrative: it is the verdict that part of the
/// comparison didn't happen, so a caller can't read the plan as a complete answer.
#[derive(Debug, Clone)]
pub struct PlanResult {
    /// The plan fact.
    pub plan: Plan,
    /// Non-fatal diagnostics surfaced to the operator (not hashed).
    pub warnings: Vec<String>,
    /// Resources no change was planned for: those whose live state couldn't be
    /// determined, and those held behind them. Non-empty means the plan is **partial**:
    /// the undetermined ones are neither "converged" nor "drifted", they are unknown,
    /// and the rest wait on them. See [`HeldResource`].
    pub held: Vec<HeldResource>,
}

/// A resource held out of the plan fact: one detection couldn't determine, or one held
/// behind such a resource.
///
/// The observed-side twin of the unresolved-reference `unverifiable` verdict: there the
/// *desired* side couldn't be built, here the *live* side couldn't be read. Both make a
/// comparison an unestablished claim rather than a finding, so both are reported as
/// verdicts that lead the render and set a non-zero exit — not as a `warning:` line under
/// an otherwise confident-looking "converged".
///
/// The planner holds rather than creating (a failed probe is not evidence of absence),
/// which is correct but silent: the resource simply vanishes from the changeset. Carrying
/// it here is what keeps the silence from reading as convergence.
///
/// A hold spreads: a change that waits on a held resource is held behind it, and so is
/// a change that would restart or reload a held service (its restart would be owed with
/// nothing to run it). [`HoldCause`] says which; only an
/// [`Undetermined`](HoldCause::Undetermined) hold is a resource whose state is unknown.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeldResource {
    /// The resource no change is planned for.
    pub resource_id: ResourceId,
    /// Why it is held.
    pub cause: HoldCause,
    /// The trigger its change would carry, as [`Change::trigger`]: the sources that
    /// fire it (each held as well) and, unless its own state is undetermined, a pending
    /// marker. A resource no trigger fired carries `None`.
    pub trigger: Option<Trigger>,
}

/// Why a [`HeldResource`] is held.
///
/// One root and two ways a hold spreads from it, set by [`diff`]:
///
/// - forward along `depends_on`, the implicit "a service waits for its trigger
///   sources" edges included: a change waits on what it depends on, so it can't run
///   before a held resource does. A converged resource in between carries the hold on
///   (it changes nothing, so it is not reported) and `on` names the reported holds it
///   reaches. The exception is a converged service whose only change is a restart or
///   reload a pending marker owes: it waits only on what it declares, so an unreadable
///   trigger source doesn't hold it;
/// - in reverse along a trigger edge only: a held service's restart or reload would be
///   owed by each source whose change fires it, with no change to run it and no
///   pending marker to remember it, so those sources are held too. A plain
///   `depends_on` is never followed in reverse: what a held resource depends on can
///   still run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HoldCause {
    /// Detection couldn't determine the resource's state — its live state is unknown.
    Undetermined {
        /// Why detection couldn't determine it (the `Undetermined` reason).
        reason: String,
    },
    /// The change waits on held resources, directly or through converged ones.
    Waits {
        /// The held resources it waits on, sorted.
        on: Vec<ResourceId>,
    },
    /// The change would restart or reload a held service.
    Triggers {
        /// The held service.
        service: ResourceId,
        /// What this resource's change would make the service do.
        kind: TriggerKind,
    },
}

impl HeldResource {
    /// Whether detection couldn't determine this resource (the hold's root), rather
    /// than it being held behind another.
    #[must_use]
    pub const fn is_undetermined(&self) -> bool {
        matches!(self.cause, HoldCause::Undetermined { .. })
    }

    /// Why it is held, as one line of prose: the detection reason,
    /// ``waits on `a`, which is held``, or ``would restart `s`, which is held``.
    #[must_use]
    pub fn describe(&self) -> String {
        match &self.cause {
            HoldCause::Undetermined { reason } => reason.clone(),
            HoldCause::Waits { on } => {
                let names = on
                    .iter()
                    .map(|id| format!("`{}`", id.0))
                    .collect::<Vec<_>>()
                    .join(", ");
                let verb = if on.len() == 1 { "is" } else { "are" };
                format!("waits on {names}, which {verb} held")
            }
            HoldCause::Triggers { service, kind } => {
                format!("would {} `{}`, which is held", kind.as_str(), service.0)
            }
        }
    }
}

/// A resource that is **not converged after a wetrun**.
///
/// The post-apply re-detection (the Observe pass) read it as still absent, drifted,
/// or unreadable, even though every command executed for it exited 0.
///
/// The third verdict in the unestablished-claim family: `unverifiable` (the *desired*
/// side couldn't be built), [`HeldResource`] (the *live* side couldn't be read before
/// planning), and this — the live side was re-read **after** execution and does not
/// match. It is what lets `apply` assert *convergence* rather than command success: a
/// step can exit 0 without converging its resource (a `script` whose `check` still
/// fails, a mutation whose probe reads back differently), and without this verdict
/// that run reported "applied: N ok" and exited 0.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResidualResource {
    /// The resource that should be converged but isn't.
    pub resource_id: ResourceId,
    /// The non-converged post-state the re-detection observed.
    pub state: ResidualState,
}

/// The post-state of a [`ResidualResource`] — [`Detection`] with `Converged`
/// unrepresentable (a converged resource is by definition not residual).
///
/// Serialized like `Detection` (internally tagged), minus the arm that can't occur.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum ResidualState {
    /// Still absent after its change completed.
    Absent,
    /// Still diverging from desired, carrying the freshly observed state.
    Drifted {
        /// The observed post-apply state, typed per kind.
        current: CurrentState,
    },
    /// The post-apply re-probe couldn't read it — convergence is unestablished,
    /// which for a wetrun's final claim disqualifies exactly as observed drift does.
    Undetermined {
        /// Why the re-probe couldn't determine the state.
        reason: String,
    },
}

impl ResidualResource {
    /// This residual with the free text of its state passed through `f`, its resource
    /// id kept ([`Detection::map_text`] states the rule).
    #[must_use]
    pub fn map_text(&self, f: impl Fn(&str) -> String) -> Self {
        let Self { resource_id, state } = self;
        Self {
            resource_id: resource_id.clone(),
            state: match state {
                ResidualState::Absent => ResidualState::Absent,
                ResidualState::Drifted { current } => ResidualState::Drifted {
                    current: current.map_text(&f),
                },
                ResidualState::Undetermined { reason } => {
                    ResidualState::Undetermined { reason: f(reason) }
                }
            },
        }
    }
}

impl ResidualState {
    /// The residual reading of a post-apply [`Detection`] — `None` for `Converged`
    /// (not residual), so this doubles as [`collect_residual`]'s filter.
    #[must_use]
    pub fn from_detection(detection: &Detection) -> Option<Self> {
        match detection {
            Detection::Converged => None,
            Detection::Absent => Some(Self::Absent),
            Detection::Drifted { current } => Some(Self::Drifted {
                current: current.clone(),
            }),
            Detection::Undetermined { reason } => Some(Self::Undetermined {
                reason: reason.clone(),
            }),
        }
    }

    /// Human render label: `absent`, `drifted`, or `undetermined — <reason>`.
    #[must_use]
    pub fn describe(&self) -> String {
        match self {
            Self::Absent => "absent".to_owned(),
            Self::Drifted { .. } => "drifted".to_owned(),
            Self::Undetermined { reason } => format!("undetermined — {reason}"),
        }
    }
}

/// Collect every resource the post-apply re-detection read as not converged — the
/// **Observe** verdict `zap apply --wetrun` reports as `residual`.
///
/// `detections` pairs with `resources` **by position** (the `detect_all` contract).
/// Three exemptions, each because "not converged" is either impossible or already
/// reported louder:
///
/// - a `pipeline` detects `absent` by construction (imperative — it always runs), so
///   its post-state can never read converged and is not residual;
/// - a resource whose change **failed** — or was skipped by stop-on-first-failure —
///   is already the run's headline failure (exit 1); its non-convergence is implied;
/// - a resource **held** out of the plan is already the `undetermined` verdict;
///   nothing was applied for it, so nothing is residual.
///
/// A resource with *no* change (converged at pre-detection) is still checked: one
/// resource's execution can break another's state. Every resource is re-read live
/// here — nothing is served from an earlier pass.
#[must_use]
pub fn collect_residual(
    resources: &[Resource],
    detections: &[Detection],
    outcomes: &[ChangeOutcome],
    held: &[HeldResource],
) -> Vec<ResidualResource> {
    let exempt: BTreeSet<&ResourceId> = outcomes
        .iter()
        .filter_map(|outcome| match outcome {
            ChangeOutcome::Failed { resource_id, .. }
            | ChangeOutcome::Skipped { resource_id, .. } => Some(resource_id),
            ChangeOutcome::Completed { .. } => None,
        })
        .chain(held.iter().map(|h| &h.resource_id))
        .collect();
    resources
        .iter()
        .zip(detections)
        .filter(|(resource, _)| {
            !matches!(resource.kind, ResourceKind::Pipeline(_)) && !exempt.contains(&resource.id)
        })
        .filter_map(|(resource, detection)| {
            ResidualState::from_detection(detection).map(|state| ResidualResource {
                resource_id: resource.id.clone(),
                state,
            })
        })
        .collect()
}

/// What the diff decided for a resource before skips are filtered out. Maps to
/// [`ChangeAction`] for emitted mutations; `Skip` / `Hold` resources are dropped
/// from the fact (skips are derived for the dry-run view; holds are warned about).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Decision {
    Create,
    Update,
    Skip,
    /// Detection couldn't determine the resource's state — plan no change and report
    /// it, rather than treat a failed probe as `create` — or the change is held behind
    /// such a resource (`propagate_holds`).
    Hold,
}

impl Decision {
    /// Whether this decision produces a change the executor runs (so a trigger
    /// source "fires" and the change is emitted). `Skip` and `Hold` produce nothing.
    const fn is_change(self) -> bool {
        matches!(self, Self::Create | Self::Update)
    }
}

/// A change under construction — `Decision::Skip` entries are kept through trigger
/// injection (so a skip can be promoted to update) and dropped at the end;
/// `Decision::Hold` entries are also dropped (and never promoted).
struct Work {
    resource_id: ResourceId,
    kind: ResourceType,
    decision: Decision,
    steps: Vec<PlanStep>,
    desired: Resource,
    depends_on: Vec<ResourceId>,
    /// The edges in `depends_on` that [`inject_triggers`] added for a service's trigger
    /// sources and the resource didn't declare.
    trigger_deps: Vec<ResourceId>,
    trigger: Option<Trigger>,
    /// For a service, each source whose change fires its restart or reload, with what
    /// it asks for — the reverse trigger edges a hold on the service follows.
    fired_by: Vec<(ResourceId, TriggerKind)>,
}

/// What [`diff`] plans from: the declared resources, what detection read of each, and
/// what completes and places the desired state.
#[derive(Clone, Copy)]
pub struct DiffInputs<'a> {
    /// The config's resources — the desired state.
    pub resources: &'a [Resource],
    /// What detection read, keyed by resource id.
    pub detected: &'a BTreeMap<ResourceId, Detection>,
    /// The config's target.
    pub target: &'a Target,
    /// The machine the target resolves to, which the plan names.
    pub machine: &'a Machine,
    /// The lock whose pins complete a tracked source's desired state, if there is one.
    pub lock: Option<&'a ZapLock>,
    /// The restarts and reloads the target still owes, by service.
    pub pending: &'a BTreeMap<String, TriggerKind>,
    /// How a reference resolves in the environment the plan is computed in — the
    /// resolver `machine` was built through.
    pub var: &'a dyn Fn(&str) -> ReportVar,
}

// By hand: the resolver is a closure, which has no `Debug`.
impl std::fmt::Debug for DiffInputs<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DiffInputs")
            .field("resources", &self.resources)
            .field("detected", &self.detected)
            .field("target", &self.target)
            .field("machine", &self.machine)
            .field("lock", &self.lock)
            .field("pending", &self.pending)
            .finish_non_exhaustive()
    }
}

/// Diff detected state against desired (the config) to produce the plan fact.
///
/// The pure half of the Describe → Detect → Plan → Apply → Observe pipeline: the IO
/// (config eval + detection) happens in `zap_core`; this consumes its
/// [`Detection`] outcomes and emits the ordered, mutation-only changeset.
/// Sort → decide action → trigger injection → package batching. Identity is
/// `resource_id` (no
/// random change ids, so `depends_on` references resource ids directly), skips are
/// derived not stored, and file/directory/link carry no steps (native `std::fs`
/// IO at execution). `detected` is keyed by `resource_id`; a missing entry holds
/// (defensive — `detect_all` returns one per resource).
///
/// `var` is how a reference resolves in the environment the plan is computed in — the
/// resolver `machine` was built through. The plan records what each reference its
/// changes use resolves to ([`references`]); nothing is substituted into a change.
///
/// `lock` completes the desired state: a *tracked* `remote_file`/`build` source carries
/// `blake3: None` in config, and an `apt_repo` key `key_blake3: None` (its pin lives in
/// the lock), so `fold_tracked_pin` folds the lock pin into each `Change.desired` here — the same lock fold `compute_config_hash`
/// applies. The fact thus holds the fully-resolved desired pin (config ⊕ lock), so it is
/// **self-contained**: `plan_hash` is a faithful content address, `--diff` reads the
/// desired pin from `Change.desired` alone, and the executor materializes a tracked source
/// straight from `Change.desired` (no lock at execution). `None`
/// folds nothing (a tracked file with no pin is held `Undetermined` upstream and never
/// emitted, so an unfolded `None` never reaches the fact).
///
/// # Precondition: a structurally-valid config
///
/// Every `resources` set reaching this function through `zap_core` has already passed the
/// structural gate ([`crate::validate`] + [`dependency_cycle`]), which rejects duplicate
/// ids, dependency cycles, and dangling `depends_on` / `restart_on` / `reload_on` /
/// `triggers` references as a hard error *before* any detection runs. The warnings this
/// function still emits for those conditions are therefore unreachable from the binary —
/// they exist for **direct callers** (tests, and any future consumer of the pure crate),
/// which is why they degrade rather than panic.
///
/// The two "cannot plan" degradations (duplicate ids, cycle) return an **empty plan**, so
/// a direct caller that skips the gate reads "converged" with a warning — the exact shape
/// [`PlanResult::held`] exists to prevent. That is tolerable only because the gate is
/// upstream of every real call. `tests/planning.rs`'s
/// `every_diff_warning_is_also_a_structural_gate_error` pins the pairing, so a new warning
/// added here without a matching validator fails the suite rather than silently becoming
/// the binary's only signal.
#[must_use]
pub fn diff(inputs: DiffInputs<'_>) -> PlanResult {
    let DiffInputs {
        resources,
        detected,
        target,
        machine,
        lock,
        pending,
        var,
    } = inputs;
    let mut warnings = Vec::new();

    // Unique ids are a precondition: the plan/detection map/dep graph all key
    // on `resource_id`, so a duplicate would silently collapse edges and clobber
    // detections. Treat it as fatal, the same as a cycle — a wrong plan is worse
    // than no plan.
    let duplicates = crate::validate::duplicate_resource_ids(resources);
    if !duplicates.is_empty() {
        warnings.push(format!(
            "duplicate resource ids, cannot plan: {}",
            join_ids(&duplicates)
        ));
        return PlanResult {
            plan: Plan {
                changes: Vec::new(),
                target: target.clone(),
                machine: machine.clone(),
                references: BTreeMap::new(),
            },
            warnings,
            held: Vec::new(),
        };
    }

    // Sort by every ordering edge — declared and trigger — so each service comes after
    // its trigger sources, which `inject_triggers`' in-order read relies on. A cycle is
    // fatal to ordering — emit an empty plan with a warning (the structural gate rejects
    // a cycle first; defensive depth).
    let edges = ordering_edges(resources);
    let order = match topo_order(resources, |index| edges[index].clone()) {
        Ok(order) => order,
        Err(cycle) => {
            warnings.push(format!(
                "dependency cycle, cannot plan: {}",
                join_ids(&cycle)
            ));
            return PlanResult {
                plan: Plan {
                    changes: Vec::new(),
                    target: target.clone(),
                    machine: machine.clone(),
                    references: BTreeMap::new(),
                },
                warnings,
                held: Vec::new(),
            };
        }
    };

    let all_ids: BTreeSet<&str> = resources.iter().map(|r| r.id.0.as_str()).collect();
    let kind_by_id: BTreeMap<&str, ResourceType> = resources
        .iter()
        .map(|r| (r.id.0.as_str(), r.kind()))
        .collect();

    // One working change per resource, in dependency order.
    let mut works: Vec<Work> = order
        .iter()
        .map(|&index| {
            let resource = &resources[index];
            let decision = decide(detected.get(&resource.id));
            let depends_on = resource_deps(resource)
                .into_iter()
                .filter(|dep| all_ids.contains(dep.0.as_str()))
                .collect();
            let mut desired = resource.clone();
            fold_tracked_pin(&mut desired, lock);
            Work {
                resource_id: resource.id.clone(),
                kind: resource.kind(),
                decision,
                steps: steps::resource_steps(resource, target, detected.get(&resource.id)),
                desired,
                depends_on,
                trigger_deps: Vec::new(),
                trigger: None,
                fired_by: Vec::new(),
            }
        })
        .collect();

    // Service-stop footguns are narrative (the plan is complete and correct; the
    // operator just needs to know it stops something), so they stay warnings.
    warn_service_stops(resources, detected, &mut warnings);

    inject_triggers(
        &mut works,
        resources,
        target,
        &all_ids,
        &kind_by_id,
        pending,
        &mut warnings,
    );
    // Resources whose state couldn't be determined are held (not created) — the
    // create-on-failed-probe guard — and the hold spreads to what can't run without
    // them, before batching, so a held package is never merged into an install.
    // Reported as a verdict, not a warning.
    let held = propagate_holds(&mut works, detected);
    batch_packages(&mut works, target);

    // Drop skips and holds: skips are derived for the dry-run view, holds change
    // nothing (we couldn't determine their state) — neither belongs in the fact. A
    // dropped dependency is replaced by the emitted changes it waits on, transitively,
    // so the fact is self-contained without losing an order: `V → X → C` with `X`
    // converged still runs `C` before `V`.
    let deps_by_id: BTreeMap<ResourceId, Vec<ResourceId>> = works
        .iter()
        .map(|w| (w.resource_id.clone(), w.depends_on.clone()))
        .collect();
    let mut emitted: Vec<Work> = works
        .into_iter()
        .filter(|w| w.decision.is_change())
        .collect();
    let present: BTreeSet<ResourceId> = emitted.iter().map(|w| w.resource_id.clone()).collect();
    for work in &mut emitted {
        // Sorted for a canonical, deterministic hash.
        work.depends_on = emitted_deps(&work.depends_on, &present, &deps_by_id)
            .into_iter()
            .collect();
    }

    // Canonical emit order: topologically sort the surviving changes (synthetic
    // batch/cache nodes included) so the plan and its hash are deterministic. The
    // emitted graph is a contraction of an acyclic one and batching never merges
    // across a dependent change, so a cycle here is a planner bug.
    let final_order = topo_order(&emitted, |index| emitted[index].depends_on.clone())
        .unwrap_or_else(|cycle| internal_cycle("the emitted changes", &cycle));
    let changes: Vec<Change> = final_order
        .into_iter()
        .map(|index| {
            let work = &emitted[index];
            Change {
                resource_id: work.resource_id.clone(),
                action: match work.decision {
                    Decision::Create => ChangeAction::Create,
                    // `Skip` / `Hold` were filtered above; treat any residue as update.
                    Decision::Update | Decision::Skip | Decision::Hold => ChangeAction::Update,
                },
                steps: work.steps.clone(),
                desired: work.desired.clone(),
                depends_on: work.depends_on.clone(),
                trigger: work.trigger.clone(),
            }
        })
        .collect();

    let references = references(&changes, var);
    PlanResult {
        plan: Plan {
            changes,
            target: target.clone(),
            machine: machine.clone(),
            references,
        },
        warnings,
        held,
    }
}

/// The resource ids caught in a dependency cycle, if any — the pure pre-flight check
/// behind the planner's structural gate.
///
/// The graph is every ordering edge (`ordering_edges`): the declared `depends_on`
/// and the implicit trigger edges, since a service runs after what triggers it. A
/// cycle through either kind is rejected — [`diff`] could order neither its trigger
/// read nor its emitted changes.
///
/// [`diff`] also detects a cycle (it must topo-sort), but it does so *after* detection
/// and degrades to an empty plan; running this up front lets the gate reject a cyclic
/// config at `plan` time, before any SSH/probe IO, with a real error instead of a
/// silent "converged" no-op. Ids referenced but not declared are ignored (a dangling
/// edge is [`crate::validate::unresolved_references`]'s concern, not a false cycle).
/// `None` means the dependency graph is acyclic.
#[must_use]
pub fn dependency_cycle(resources: &[Resource]) -> Option<Vec<ResourceId>> {
    let edges = ordering_edges(resources);
    topo_order(resources, |index| edges[index].clone()).err()
}

/// Each resource's ordering edges, by index: its declared `depends_on`, and for a
/// service the implicit trigger edges — every resource it `restart_on` / `reload_on`,
/// and every `file` whose `triggers` names it. A `triggers` entry naming a resource
/// that isn't a service adds no edge (the structural gate rejects it). Ids not in
/// `resources` are kept; [`topo_order`] ignores them.
fn ordering_edges(resources: &[Resource]) -> Vec<Vec<ResourceId>> {
    let services: BTreeSet<&str> = resources
        .iter()
        .filter(|r| r.kind() == ResourceType::Service)
        .map(|r| r.id.0.as_str())
        .collect();
    let mut pushed: BTreeMap<&str, Vec<ResourceId>> = BTreeMap::new();
    for resource in resources {
        let ResourceKind::File(file) = &resource.kind else {
            continue;
        };
        for service in file.triggers.iter().flatten() {
            if services.contains(service.0.as_str()) {
                pushed
                    .entry(service.0.as_str())
                    .or_default()
                    .push(resource.id.clone());
            }
        }
    }
    resources
        .iter()
        .map(|resource| {
            let mut edges = resource_deps(resource);
            if let ResourceKind::Service(service) = &resource.kind {
                edges.extend(service.restart_on.iter().flatten().cloned());
                edges.extend(service.reload_on.iter().flatten().cloned());
                if let Some(files) = pushed.get(resource.id.0.as_str()) {
                    edges.extend(files.iter().cloned());
                }
            }
            edges
        })
        .collect()
}

/// Decide a resource's action from its detected outcome. Absent → create;
/// drifted → update; converged → skip (dropped from the fact); undetermined →
/// hold (dropped + warned — never silently created). A missing entry holds too:
/// `detect_all` returns one per resource, so it is unreachable, and a fallback that
/// guessed a create would be the "couldn't tell → create" footgun.
const fn decide(detected: Option<&Detection>) -> Decision {
    match detected {
        None | Some(Detection::Undetermined { .. }) => Decision::Hold,
        Some(Detection::Absent) => Decision::Create,
        Some(Detection::Drifted { .. }) => Decision::Update,
        Some(Detection::Converged) => Decision::Skip,
    }
}

/// Hold every resource no change can be planned for, and report each with its cause.
///
/// The roots are the resources detection couldn't determine (already `Decision::Hold`):
/// the plan changes nothing for them rather than treating a failed probe as a create.
/// From them, to a fixpoint ([`HoldCause`] states the two rules):
///
/// - **forward** along `depends_on` (the implicit trigger edges included): a change with
///   a held dependency is held, `Waits`; a converged dependency carries the hold on,
///   unreported, since it changes nothing. A converged service whose only change is the
///   restart or reload a pending marker owes follows only the edges it declares: no
///   source fired it, so a held source has nothing it waits for. A source that fired
///   and was then held still holds it, since its sources name that source;
/// - **in reverse along a trigger edge**: each source whose change fires a held
///   service is held, `Triggers` — its change would leave that restart or reload owed
///   with nothing to run it and no pending marker armed for it.
///
/// Returned as a typed verdict rather than pushed onto `warnings`, because it is not
/// narrative — a held resource means the plan below is partial. A warning line reads as
/// "the answer, with an aside"; this *is* the answer for those resources. Reported in
/// `works` order. See [`HeldResource`].
fn propagate_holds(
    works: &mut [Work],
    detected: &BTreeMap<ResourceId, Detection>,
) -> Vec<HeldResource> {
    let index_of: BTreeMap<ResourceId, usize> = works
        .iter()
        .enumerate()
        .map(|(index, work)| (work.resource_id.clone(), index))
        .collect();
    // A converged service whose only change is an owed restart or reload follows only
    // its declared edges.
    let deps: Vec<Vec<usize>> = works
        .iter()
        .map(|work| {
            let owed_only = matches!(detected.get(&work.resource_id), Some(Detection::Converged))
                && work
                    .trigger
                    .as_ref()
                    .is_some_and(|trigger| trigger.pending && trigger.sources.is_empty());
            work.depends_on
                .iter()
                .filter(|dep| !(owed_only && work.trigger_deps.contains(dep)))
                .filter_map(|dep| index_of.get(dep).copied())
                .collect()
        })
        .collect();
    let undetermined: Vec<bool> = works.iter().map(|w| w.decision == Decision::Hold).collect();
    let changes: Vec<bool> = works.iter().map(|w| w.decision.is_change()).collect();

    // Per resource: the reported holds it carries — itself when it is held, what its
    // dependencies carry when it is converged — and the holds found so far. A hold's
    // cause is settled in the pass that finds it, so no cause names a resource held
    // after it, and none explains another in a circle: a service held for its trigger
    // waits on no source held for it. Everything only grows, so the loop ends.
    let count = works.len();
    let mut carried: Vec<BTreeSet<usize>> = vec![BTreeSet::new(); count];
    let mut waits: Vec<BTreeSet<usize>> = vec![BTreeSet::new(); count];
    let mut triggers: Vec<Option<(usize, TriggerKind)>> = vec![None; count];
    let mut settled = vec![false; count];
    let is_held =
        |index: usize, waits: &[BTreeSet<usize>], triggers: &[Option<(usize, TriggerKind)>]| {
            undetermined[index] || !waits[index].is_empty() || triggers[index].is_some()
        };
    loop {
        let mut moved = false;
        // Forward, repeated to its own fixpoint. `works` follows every edge, implicit
        // trigger edges included, so one pass settles it; the repeat keeps the result
        // independent of that order.
        loop {
            let mut forward_moved = false;
            for index in 0..count {
                let upstream: BTreeSet<usize> = deps[index]
                    .iter()
                    .flat_map(|&dep| carried[dep].iter().copied())
                    .collect();
                if changes[index]
                    && !settled[index]
                    && triggers[index].is_none()
                    && !upstream.is_empty()
                    && waits[index] != upstream
                {
                    waits[index].clone_from(&upstream);
                    forward_moved = true;
                }
                let now = if is_held(index, &waits, &triggers) {
                    BTreeSet::from([index])
                } else {
                    upstream
                };
                if carried[index] != now {
                    carried[index] = now;
                    forward_moved = true;
                }
            }
            if !forward_moved {
                break;
            }
            moved = true;
        }
        for (index, settled) in settled.iter_mut().enumerate() {
            *settled = is_held(index, &waits, &triggers);
        }
        // Reverse, along trigger edges only.
        for (index, work) in works.iter().enumerate() {
            if !is_held(index, &waits, &triggers) {
                continue;
            }
            for (source, kind) in &work.fired_by {
                let Some(&source) = index_of.get(source) else {
                    continue;
                };
                if changes[source] && !is_held(source, &waits, &triggers) {
                    triggers[source] = Some((index, *kind));
                    moved = true;
                }
            }
        }
        if !moved {
            break;
        }
    }

    let id = |index: usize| works[index].resource_id.clone();
    let held: Vec<HeldResource> = (0..count)
        .filter_map(|index| {
            let cause = if undetermined[index] {
                HoldCause::Undetermined {
                    reason: match detected.get(&works[index].resource_id) {
                        Some(Detection::Undetermined { reason }) => reason.clone(),
                        _ => "state could not be determined".to_owned(),
                    },
                }
            } else if !waits[index].is_empty() {
                let mut on: Vec<ResourceId> = waits[index].iter().map(|&i| id(i)).collect();
                on.sort();
                HoldCause::Waits { on }
            } else if let Some((service, kind)) = triggers[index] {
                HoldCause::Triggers {
                    service: id(service),
                    kind,
                }
            } else {
                return None;
            };
            Some(HeldResource {
                resource_id: id(index),
                cause,
                // every source of a held trigger is held too, so batching never remaps one
                trigger: works[index].trigger.clone(),
            })
        })
        .collect();
    for entry in &held {
        works[index_of[&entry.resource_id]].decision = Decision::Hold;
    }
    held
}

/// Warn when a running service is configured `running: false` — applying will
/// **stop** it. Reads the typed `Drifted` current state (`is_running`).
fn warn_service_stops(
    resources: &[Resource],
    detected: &BTreeMap<ResourceId, Detection>,
    warnings: &mut Vec<String>,
) {
    for resource in resources {
        let ResourceKind::Service(service) = &resource.kind else {
            continue;
        };
        if service.running != Some(false) {
            continue;
        }
        if let Some(Detection::Drifted {
            current: CurrentState::Service {
                is_running: true, ..
            },
        }) = detected.get(&resource.id)
        {
            warnings.push(format!(
                "service `{}` is running but config sets running:false — applying will STOP it",
                resource.id.0
            ));
        }
    }
}

/// A resource's declared `depends_on` ids (a typed base field). Unknown-to-config
/// ids are kept here and filtered by the caller against the resource set.
fn resource_deps(resource: &Resource) -> Vec<ResourceId> {
    resource.depends_on.clone()
}

/// Fold a *tracked* `remote_file`/`build` source's or `apt_repo` key's lock pin into its
/// desired state.
///
/// A tracked source carries `blake3: None` in config — its pin lives in the lock — so
/// the raw clone's desired state is incomplete. Folding the lock pin into `content`/
/// `source`'s `blake3` makes a tracked source indistinguishable from a vendored one (a
/// declared `blake3`), so the one resolved pin is uniform across detect / plan / execute.
/// A vendored pin is already `Some` and left untouched; a tracked source with no lock
/// entry stays `None` (held `Undetermined` upstream, never emitted into the fact).
fn fold_tracked_pin(desired: &mut Resource, lock: Option<&ZapLock>) {
    let Some(pin) = lock
        .and_then(|lock| lock.entries.get(&desired.id))
        .and_then(crate::lock::LockEntry::pin)
    else {
        return;
    };
    match &mut desired.kind {
        ResourceKind::File(file) => {
            if let FileContent::Remote(remote) = &mut file.content
                && remote.blake3.is_none()
            {
                remote.blake3 = Some(pin.clone());
            }
        }
        ResourceKind::Build(build) => {
            let BuildSource::Remote(remote) = &mut build.source;
            let blake3 = &mut remote.blake3;
            if blake3.is_none() {
                *blake3 = Some(pin.clone());
            }
        }
        ResourceKind::AptRepo(repo) if repo.key_blake3.is_none() => {
            repo.key_blake3 = Some(pin.clone());
        }
        _ => {}
    }
}

/// Inject service-restart/reload triggers (the `file.triggers` push model, the
/// service `restart_on` / `reload_on` pull model, and `pending` — the markers an
/// earlier apply left for actions it never completed, keyed by service name),
/// appending the trigger's command, promoting a converged service to `update` (its steps
/// then the trigger alone, after the manager's unit reload) when a trigger fires, and
/// adding the implicit "service waits for its trigger sources"
/// dependency edges.
fn inject_triggers(
    works: &mut [Work],
    resources: &[Resource],
    target: &Target,
    all_ids: &BTreeSet<&str>,
    kind_by_id: &BTreeMap<&str, ResourceType>,
    pending: &BTreeMap<String, TriggerKind>,
    warnings: &mut Vec<String>,
) {
    // file -> services it pushes a restart to. Validate the references.
    let mut file_triggers: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for resource in resources {
        let ResourceKind::File(file) = &resource.kind else {
            continue;
        };
        let Some(triggers) = &file.triggers else {
            continue;
        };
        for target_id in triggers {
            let target_id = target_id.0.clone();
            if !all_ids.contains(target_id.as_str()) {
                warnings.push(format!(
                    "file `{}` triggers unknown resource `{target_id}`",
                    resource.id.0
                ));
                continue;
            }
            if kind_by_id.get(target_id.as_str()) != Some(&ResourceType::Service) {
                warnings.push(format!(
                    "file `{}` triggers non-service resource `{target_id}`; triggers only restart services",
                    resource.id.0
                ));
                continue;
            }
            file_triggers
                .entry(target_id)
                .or_default()
                .push(resource.id.0.clone());
        }
    }

    // Live "fires a change" set so a service promoted by its own trigger is visible
    // to a service that restarts on it (an in-order, mutate-as-you-go read). Complete
    // because `works` follows `ordering_edges`: every trigger source, a promoted
    // service included, is decided before the service it fires. A held source never
    // fires (we couldn't determine it).
    let mut fires_change: BTreeMap<String, bool> = works
        .iter()
        .map(|w| (w.resource_id.0.clone(), w.decision.is_change()))
        .collect();

    let sm = target.service_manager;
    for work in works.iter_mut() {
        if work.kind != ResourceType::Service {
            continue;
        }
        let service_id = work.resource_id.0.clone();
        let ResourceKind::Service(service) = &work.desired.kind else {
            continue;
        };
        let restart_on = service.restart_on.clone().unwrap_or_default();
        let reload_on = service.reload_on.clone().unwrap_or_default();
        let service_name = service.service.as_str().to_owned();

        for id in restart_on.iter().chain(&reload_on) {
            if !all_ids.contains(id.0.as_str()) {
                warnings.push(format!(
                    "service `{service_id}` restart_on/reload_on references unknown resource `{}`",
                    id.0
                ));
            }
        }

        // Effective restart sources = explicit restart_on + file pushes.
        let mut effective_restart: Vec<String> = restart_on.iter().map(|id| id.0.clone()).collect();
        if let Some(files) = file_triggers.get(&service_id) {
            effective_restart.extend(files.iter().cloned());
        }
        dedup_preserving(&mut effective_restart);

        let fires = |id: &str| fires_change.get(id).copied().unwrap_or(false);
        let restart_sources: Vec<&String> =
            effective_restart.iter().filter(|id| fires(id)).collect();
        let reload_sources: Vec<&String> = reload_on
            .iter()
            .map(|id| &id.0)
            .filter(|id| fires(id))
            .collect();
        let fired = if restart_sources.is_empty() {
            (!reload_sources.is_empty()).then_some(TriggerKind::Reload)
        } else {
            Some(TriggerKind::Restart)
        };
        // A held service never runs, so a pending marker for it waits for a plan that
        // can determine it.
        let carried = pending
            .get(&service_name)
            .copied()
            .filter(|_| work.decision != Decision::Hold);
        work.fired_by = restart_sources
            .iter()
            .map(|id| (ResourceId((*id).clone()), TriggerKind::Restart))
            .chain(
                reload_sources
                    .iter()
                    .filter(|id| !restart_sources.contains(id))
                    .map(|id| (ResourceId((*id).clone()), TriggerKind::Reload)),
            )
            .collect();
        if let Some(kind) = fired.max(carried) {
            let mut sources: Vec<ResourceId> = restart_sources
                .into_iter()
                .chain(reload_sources)
                .map(|id| ResourceId(id.clone()))
                .collect();
            sources.sort();
            sources.dedup();
            work.trigger = Some(Trigger {
                kind,
                sources,
                pending: carried.is_some(),
            });
            // A converged service runs only its trigger: its lifecycle already holds, so
            // re-running it (an enable, a start) is no part of what fired. The manager's
            // unit reload stays ahead of it, so a changed unit file is what restarts.
            if work.decision == Decision::Skip {
                work.steps = sm
                    .and_then(service_managers::daemon_reload)
                    .map(|reload| PlanStep::run(format!("sudo {reload}")))
                    .into_iter()
                    .collect();
                work.decision = Decision::Update;
                fires_change.insert(service_id, true);
            }
            work.steps.push(service_managers::manager_step(
                service_managers::trigger_for(sm, kind, &service_name),
                sm,
                kind.as_str(),
                &service_name,
            ));
        }

        // Implicit deps: the service waits for every trigger source that exists.
        let mut implicit: Vec<String> = effective_restart;
        implicit.extend(reload_on.iter().map(|id| id.0.clone()));
        dedup_preserving(&mut implicit);
        for dep in implicit {
            if all_ids.contains(dep.as_str()) {
                let dep_id = ResourceId(dep);
                if !work.depends_on.contains(&dep_id) {
                    work.depends_on.push(dep_id.clone());
                    work.trigger_deps.push(dep_id);
                }
            }
        }
    }
}

/// Batch `create` package installs into one command per layer, injecting a synthetic
/// cache-update change that runs first. Groups by the target's package manager,
/// merges each layer of 2+ into one `batch-install-<pm>` change (`-2`, `-3`, … for the
/// later layers), and remaps dependents onto the batch. Keyed on resource ids (no
/// change-id remap needed — identity is the resource id).
///
/// A layer never spans another resource: when a package waits on anything that waits on
/// another package (`P2 → S → P1`, `S` a change or not), merging the two would make the
/// batch wait on itself, so `P2` goes in a later layer ([`package_layers`]). The cache update
/// waits on the first layer's external dependencies; each later layer waits on the
/// cache update and its own.
fn batch_packages(works: &mut Vec<Work>, target: &Target) {
    let Some(pm) = target.package_manager else {
        return;
    };

    // Eligible: package, create, with a name for this package manager.
    let mut eligible: Vec<(ResourceId, PackageName)> = Vec::new();
    for work in works.iter() {
        if work.kind != ResourceType::Package || work.decision != Decision::Create {
            continue;
        }
        if let ResourceKind::Package(package) = &work.desired.kind
            && let Some(name) = package.from.get(&pm)
        {
            eligible.push((work.resource_id.clone(), name.clone()));
        }
    }
    if eligible.is_empty() {
        return;
    }
    let Some(update_cmd) = package_managers::update_cache(pm).map(|cmd| format!("sudo {cmd}"))
    else {
        return; // unknown manager — leave individual installs as-is.
    };

    let eligible_ids: BTreeSet<ResourceId> = eligible.iter().map(|(id, _)| id.clone()).collect();
    let layer_of = package_layers(works, &eligible_ids);
    let mut layers: Vec<Vec<(ResourceId, PackageName)>> = Vec::new();
    for (id, name) in eligible {
        let layer = layer_of[&id];
        if layers.len() <= layer {
            layers.resize_with(layer + 1, Vec::new);
        }
        layers[layer].push((id, name));
    }

    let deps_of: BTreeMap<ResourceId, Vec<ResourceId>> = works
        .iter()
        .map(|w| (w.resource_id.clone(), w.depends_on.clone()))
        .collect();
    // A layer's external deps: its members' deps outside the layer.
    let external = |members: &[(ResourceId, PackageName)]| -> Vec<ResourceId> {
        let inside: BTreeSet<&ResourceId> = members.iter().map(|(id, _)| id).collect();
        let deps: BTreeSet<ResourceId> = members
            .iter()
            .flat_map(|(id, _)| deps_of[id].iter())
            .filter(|dep| !inside.contains(dep))
            .cloned()
            .collect();
        deps.into_iter().collect()
    };

    let cache_id = ResourceId(format!("cache-update-{}", pm.as_str()));
    let cache_work = Work {
        resource_id: cache_id.clone(),
        kind: ResourceType::Script,
        decision: Decision::Create,
        steps: vec![PlanStep::run(update_cmd.clone())],
        desired: synthetic_script(&cache_id, &update_cmd),
        depends_on: external(&layers[0]),
        trigger_deps: Vec::new(),
        trigger: None,
        fired_by: Vec::new(),
    };

    // Each package merged into a batch, and the batch it was merged into.
    let mut merged: BTreeMap<ResourceId, ResourceId> = BTreeMap::new();
    let mut batch_works: Vec<Work> = Vec::new();
    for (layer, members) in layers.iter().enumerate() {
        // The first layer waits on what the cache update waits on; a later one also on
        // its own external deps.
        let mut depends_on = vec![cache_id.clone()];
        if layer > 0 {
            depends_on.extend(external(members));
        }
        if let [(only, _)] = members.as_slice() {
            // One package: just front it with the cache update.
            for work in works.iter_mut() {
                if &work.resource_id == only {
                    work.depends_on.clone_from(&depends_on);
                }
            }
            continue;
        }
        // 2+ packages: merge into one install, its names each a word.
        let pkg_names = members
            .iter()
            .map(|(_, name)| name.as_str())
            .collect::<Vec<_>>()
            .join(" ");
        let Some(install_cmd) =
            package_managers::install(pm, &pkg_names).map(|cmd| format!("sudo {cmd}"))
        else {
            return;
        };
        let batch_id = if layer == 0 {
            ResourceId(format!("batch-install-{}", pm.as_str()))
        } else {
            ResourceId(format!("batch-install-{}-{}", pm.as_str(), layer + 1))
        };
        for (id, _) in members {
            merged.insert(id.clone(), batch_id.clone());
        }
        batch_works.push(Work {
            resource_id: batch_id.clone(),
            kind: ResourceType::Package,
            decision: Decision::Create,
            steps: vec![PlanStep::run(install_cmd)],
            desired: synthetic_batch_package(&batch_id),
            depends_on,
            trigger_deps: Vec::new(),
            trigger: None,
            fired_by: Vec::new(),
        });
    }

    works.retain(|work| !merged.contains_key(&work.resource_id));
    works.push(cache_work);
    works.extend(batch_works);
    // Remap every change's deps on a merged package onto its batch — and its trigger
    // sources, which the executor arms pending markers from by change id.
    for work in works.iter_mut() {
        let mut remapped = false;
        for dep in &mut work.depends_on {
            if let Some(batch) = merged.get(dep) {
                dep.clone_from(batch);
                remapped = true;
            }
        }
        if remapped {
            work.depends_on.sort();
            work.depends_on.dedup();
        }
        if let Some(trigger) = &mut work.trigger
            && trigger
                .sources
                .iter()
                .any(|source| merged.contains_key(source))
        {
            for source in &mut trigger.sources {
                if let Some(batch) = merged.get(source) {
                    source.clone_from(batch);
                }
            }
            trigger.sources.sort();
            trigger.sources.dedup();
        }
    }
}

/// The batch layer of each eligible package: the lowest layer whose batch runs after
/// every package it reaches through anything but another eligible package, so no batch
/// waits on itself.
///
/// A package shares its layer with an eligible package it depends on directly. Any other
/// resource in between — a change, a converged or held resource, a service no trigger
/// fired — puts it one layer later than every package that resource reaches, whatever
/// it is: the emitted plan replaces a dropped resource by what it waits on
/// ([`emitted_deps`]), so a resource that changes nothing still orders. Then a batch's
/// dependencies, and their closure through dropped resources, reach only earlier layers,
/// and the cache update's (the first layer's) reach no package at all — the emitted
/// graph stays acyclic for every acyclic config.
fn package_layers(works: &[Work], eligible: &BTreeSet<ResourceId>) -> BTreeMap<ResourceId, usize> {
    let index_of: BTreeMap<&ResourceId, usize> = works
        .iter()
        .enumerate()
        .map(|(index, work)| (&work.resource_id, index))
        .collect();
    let order = topo_order(works, |index| works[index].depends_on.clone())
        .unwrap_or_else(|cycle| internal_cycle("the planned changes", &cycle));
    // Per work: the highest layer of an eligible package it is or reaches.
    let mut reach: Vec<Option<usize>> = vec![None; works.len()];
    let mut layers = BTreeMap::new();
    for index in order {
        let work = &works[index];
        let deps = work
            .depends_on
            .iter()
            .filter_map(|dep| index_of.get(dep).copied());
        if eligible.contains(&work.resource_id) {
            let layer = deps
                .map(|dep| {
                    if eligible.contains(&works[dep].resource_id) {
                        reach[dep].unwrap_or(0)
                    } else {
                        reach[dep].map_or(0, |layer| layer + 1)
                    }
                })
                .max()
                .unwrap_or(0);
            reach[index] = Some(layer);
            layers.insert(work.resource_id.clone(), layer);
        } else {
            reach[index] = deps.filter_map(|dep| reach[dep]).max();
        }
    }
    layers
}

/// Build the synthetic `script` resource standing in for a package-cache update.
fn synthetic_script(id: &ResourceId, run: &str) -> Resource {
    Resource {
        id: id.clone(),
        name: None,
        depends_on: Vec::new(),
        kind: ResourceKind::Script(ScriptResource {
            check: Text::literal("true"),
            run: Text::literal(run),
            cwd: None,
            env: None,
        }),
    }
}

/// Build the synthetic `package` resource standing in for a batched install.
///
/// It declares no name: the packages it installs are the words of its one step's
/// command, and a name holds one package.
fn synthetic_batch_package(id: &ResourceId) -> Resource {
    Resource {
        id: id.clone(),
        name: None,
        depends_on: Vec::new(),
        kind: ResourceKind::Package(PackageResource {
            from: BTreeMap::new(),
            check: None,
        }),
    }
}

/// In-place dedup preserving first-seen order.
fn dedup_preserving(items: &mut Vec<String>) {
    let mut seen = BTreeSet::new();
    items.retain(|item| seen.insert(item.clone()));
}

/// The emitted changes among `deps`, each dropped one (converged, held, or batched
/// away) replaced by what it depends on, transitively.
fn emitted_deps(
    deps: &[ResourceId],
    present: &BTreeSet<ResourceId>,
    deps_by_id: &BTreeMap<ResourceId, Vec<ResourceId>>,
) -> BTreeSet<ResourceId> {
    let mut out = BTreeSet::new();
    let mut seen = BTreeSet::new();
    let mut stack: Vec<&ResourceId> = deps.iter().collect();
    while let Some(dep) = stack.pop() {
        if present.contains(dep) {
            out.insert(dep.clone());
        } else if seen.insert(dep)
            && let Some(next) = deps_by_id.get(dep)
        {
            stack.extend(next);
        }
    }
    out
}

/// A cycle in a graph the planner built from an acyclic, validated config: an
/// internal error, never a reason to emit changes in an arbitrary order.
///
/// # Panics
///
/// Always: the planner has a bug.
#[expect(
    clippy::panic,
    reason = "an invariant of the planner's own graphs, not of its input"
)]
fn internal_cycle(graph: &str, cycle: &[ResourceId]) -> ! {
    panic!(
        "zap internal error: a dependency cycle in {graph} ({}); please report this",
        join_ids(cycle)
    )
}

/// Render a list of resource ids for a warning message.
fn join_ids(ids: &[ResourceId]) -> String {
    ids.iter()
        .map(|id| id.0.as_str())
        .collect::<Vec<_>>()
        .join(", ")
}

/// Kahn topological sort over `items`, ordering dependencies before dependents.
/// `deps_of(i)` yields item `i`'s dependency ids; ids not in `items` are ignored.
/// Returns indices in dependency order, or the ids left in a cycle on failure.
/// Ready nodes are emitted in `resource_id` order, so the ordering — and thus the
/// plan hash — is canonical and independent of the config's declaration order.
fn topo_order<T: HasId>(
    items: &[T],
    deps_of: impl Fn(usize) -> Vec<ResourceId>,
) -> Result<Vec<usize>, Vec<ResourceId>> {
    let index_of: BTreeMap<&str, usize> = items
        .iter()
        .enumerate()
        .map(|(i, item)| (item.id_str(), i))
        .collect();
    let count = items.len();
    let mut dependents: Vec<Vec<usize>> = vec![Vec::new(); count];
    let mut indegree = vec![0usize; count];
    #[expect(
        clippy::needless_range_loop,
        reason = "`i` is the node itself, passed to `deps_of` and stored in `dependents`, not only an index into `indegree`"
    )]
    for i in 0..count {
        for dep in deps_of(i) {
            if let Some(&j) = index_of.get(dep.0.as_str()) {
                dependents[j].push(i);
                indegree[i] += 1;
            }
        }
    }
    // Ready set ordered by `(id, index)` so ties break on id — canonical regardless
    // of how the resources were declared.
    let mut ready: BinaryHeap<Reverse<(&str, usize)>> = (0..count)
        .filter(|&i| indegree[i] == 0)
        .map(|i| Reverse((items[i].id_str(), i)))
        .collect();
    let mut order = Vec::with_capacity(count);
    while let Some(Reverse((_, i))) = ready.pop() {
        order.push(i);
        for &k in &dependents[i] {
            indegree[k] -= 1;
            if indegree[k] == 0 {
                ready.push(Reverse((items[k].id_str(), k)));
            }
        }
    }
    if order.len() == count {
        Ok(order)
    } else {
        Err((0..count)
            .filter(|i| !order.contains(i))
            .map(|i| ResourceId(items[i].id_str().to_owned()))
            .collect())
    }
}

/// Lets [`topo_order`] read an id from either a `Resource` or a `Work`.
trait HasId {
    fn id_str(&self) -> &str;
}

impl HasId for Resource {
    fn id_str(&self) -> &str {
        &self.id.0
    }
}

impl HasId for Work {
    fn id_str(&self) -> &str {
        &self.resource_id.0
    }
}
