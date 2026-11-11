//! The deploy plan — the pure, inspectable changeset for a release deploy.
//!
//! `zap deploy` is an **imperative act**, not convergence: each deploy ships a new
//! immutable, versioned release and atomically swaps `current` to it, so there is no
//! stable desired state to converge toward ("detect drift on a release" is
//! meaningless). It is therefore a command, not a resource — but it still earns a
//! *pure plan*, mirroring Describe → Plan → Apply: [`plan_deploy`] turns the declared
//! [`DeploySpec`] plus IO-resolved inputs (the version, the resolved host, what the
//! invocation chose, …) into an ordered [`DeployPlan`]. The remote extract-and-swap
//! **script is generated here, purely** ([`DeployPlan::swap_script`]), from the values
//! the plan holds — so it is golden-testable, the values it embeds are the ones the
//! dry run shows beside it, and the dry run renders every command, script, path, and URL
//! the plan holds: what its hash covers is what the preview shows. The IO that executes
//! the plan (build / scp / ssh / HTTP) lives in `zap_core`.
//!
//! App-specific steps are declarative [`DeploySpec`] fields — `shared` (files symlinked
//! from `shared/` into each release), `prepare` (post-extract commands), and `health`
//! — so the engine owns only the **universal release mechanism**: build → tarball →
//! upload → lock → recover → verify → extract → symlink shared → prepare → atomic swap →
//! record info → prune.

use std::collections::BTreeMap;
use std::fmt::Write as _;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::config_hash::{HashDomain, hash_canonical};
use crate::last_run::{ReportVar, declared_fields, fold_lock_pin};
use crate::lock::ZapLock;
use crate::plan::ReferenceValue;
use crate::scalar::EnvVarName;
use crate::schema::{DeploySpec, Resource, ServiceManager, Target};
use crate::service_managers;
// The workspace's one shell-quoting definition: the remote extract-and-swap script
// is generated here but *runs* on the target, so its quoting must be the same rule
// the detector and planner use.
use crate::shell::single_quote;
use crate::var_ref::map_literals;

/// The fixed set of deploy step identities, minted by [`plan_deploy`] and matched on by
/// `zap_core`'s walk + rollback (the post-swap rollback gate keys off
/// [`ExtractSwap`](Self::ExtractSwap)).
///
/// An enum, not bare string consts, so the planner, the rollback logic, and
/// `extract_swap_succeeded` can't silently desync — adding a step forces every `match`.
/// `Rollback` is part of the set (the rollback walk emits it) rather than a stray
/// literal. Serializes to its `snake_case` token, so `DeployStep.id` and the
/// general-purpose `StepOutcome.step` wire string are byte-unchanged.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeployStepId {
    /// Build the release artifact locally.
    Build,
    /// Tar the built artifact.
    Tarball,
    /// Upload the tarball to the target.
    Upload,
    /// Extract on the target and atomically swap `current` — the pre/post-swap boundary
    /// for rollback.
    ExtractSwap,
    /// Restart the service.
    Restart,
    /// Post-restart HTTP health check.
    Health,
    /// Post-health `/ready` schema-drift deploy gate (column-presence probe).
    Readiness,
    /// Roll back to the prior release (runtime-injected on a post-swap failure).
    Rollback,
}

impl DeployStepId {
    /// The stable wire token (`"build"`, `"extract_swap"`, …) — equals the
    /// `#[serde(rename_all = "snake_case")]` form, so it doubles as the `StepOutcome.step`
    /// string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Build => "build",
            Self::Tarball => "tarball",
            Self::Upload => "upload",
            Self::ExtractSwap => "extract_swap",
            Self::Restart => "restart",
            Self::Health => "health",
            Self::Readiness => "readiness",
            Self::Rollback => "rollback",
        }
    }
}

impl std::fmt::Display for DeployStepId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The ordered deploy plan — a content-addressable artifact.
///
/// Like the convergence plan fact (hash it with
/// [`deploy_plan_hash`](crate::config_hash::deploy_plan_hash), which rides its own
/// version axis rather than a resource hash's). Only applicable steps are
/// present — a deploy with no `build`, or one that skips it, has no `Build` step. A step
/// that *is* planned but declines to run at execution time (a `Readiness` gate the
/// target doesn't serve) reports `Skipped`, alongside the abort cascade: a step that
/// didn't run must never report `Completed`, or a consumer reads an unrun gate as a
/// passed one.
///
/// The plan names the machine it is for, so its hash can't stand for the same release on
/// another one: [`target`](Self::target) is the declared descriptor, as the convergence
/// plan carries it, [`host`](Self::host) the host that descriptor resolves to — a
/// referenced host is one declaration for as many machines as there are values — and
/// [`user`](Self::user) who it connects as. It names the release: its
/// [`version`](Self::version), the commit's [`subject`](Self::subject), the release it
/// replaces ([`previous`](Self::previous)), and who ships it
/// ([`deployed_by`](Self::deployed_by)); the extract-and-swap script is built from these
/// ([`swap_script`](Self::swap_script)), so what a preview shows of them is what the
/// script embeds. It also holds the two facts of the run that change what a wetrun does
/// without changing a step: a dirty tree ([`dirty`](Self::dirty)) and what the drift
/// preflight does — whether it runs, and over which declared resources
/// ([`preflight`](Self::preflight)).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeployPlan {
    /// The release version (short git hash, with `-dirty-<8 hex>` for a forced dirty
    /// tree).
    pub version: String,
    /// The subject line of the commit the version names ([`DeployContext::subject`]).
    /// For a dirty tree it is still that commit's: it says nothing of the uncommitted
    /// changes.
    pub subject: String,
    /// The release live on the target when the plan was made
    /// ([`DeployContext::previous_version`]), `None` when nothing was: the release the
    /// script requires `current` to name, records in `deploy_info.json`, keeps from the
    /// prune, and a failure after the swap rolls back to.
    pub previous: Option<String>,
    /// The declared target, its references inert.
    pub target: Target,
    /// The host the target resolves to ([`DeployContext::target_host`]): the name, not
    /// what `ssh -G` resolves it to, which is configuration rather than the machine.
    // TODO: binding the machine to a reviewed plan would fold its host key's
    // fingerprint here (read where the connection checks it), not `ssh -G`'s output.
    pub host: String,
    /// The user the run connects as ([`DeployContext::target_user`]), by value; `None`
    /// when the target declares none, and `ssh` picks it. The uploaded archive is named
    /// for it, and the steps on the target run as it.
    pub user: Option<String>,
    /// `user@host` of the operator machine ([`DeployContext::deployed_by`]), which the
    /// script records in `deploy_info.json`.
    pub deployed_by: String,
    /// The working tree held uncommitted changes or untracked files: the artifacts
    /// packed are the tree's, not the commit's. Only a forced plan of one runs, and its
    /// [`version`](Self::version) names the tree (`-dirty-<8 hex>`); without `--force`
    /// the plan is a preview no wetrun executes.
    pub dirty: bool,
    /// What the wetrun's drift preflight does before the steps.
    pub preflight: DriftPreflight,
    /// What each reference the `deploy` block uses resolved to when the plan was
    /// computed ([`deploy_references`]), as the convergence plan carries its own.
    pub references: BTreeMap<EnvVarName, ReferenceValue>,
    /// The steps, in execution order.
    pub steps: Vec<DeployStep>,
    /// Plan-time findings the operator must see — today only a `deploy.service`
    /// restart the target's declared manager can't honor (`launchd`: no restart verb),
    /// which would otherwise vanish from the step list silently and leave the old
    /// process serving a "successful" release. Absent from the wire when empty, so a
    /// plan with nothing to warn about hashes exactly as before.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
}

impl DeployPlan {
    /// This plan with every free-text field passed through `f`: the version, the commit's
    /// subject, the previous release, the host, the connecting user, the operator, the
    /// declared target's text, each reference's value, each step's name and its action's
    /// commands, paths, names and URLs, and the warnings. The closed-set fields — step
    /// ids, action tags, the preflight (its digest is a hash, not text), counts — are
    /// kept as they are. The extract-and-swap script is built from the mapped values
    /// ([`swap_script`](Self::swap_script)).
    ///
    /// How a plan is masked for display: a typed map with no serialized form in between,
    /// so there is nothing that can fail and hand back the plan unmapped, and a field
    /// added to the plan doesn't compile until it is placed here.
    #[must_use]
    pub fn map_text(&self, f: impl Fn(&str) -> String) -> Self {
        let Self {
            version,
            subject,
            previous,
            target,
            host,
            user,
            deployed_by,
            dirty,
            preflight,
            references,
            steps,
            warnings,
        } = self;
        Self {
            version: f(version),
            subject: f(subject),
            previous: previous.as_deref().map(&f),
            target: target.map_text(&f),
            host: f(host),
            user: user.as_deref().map(&f),
            deployed_by: f(deployed_by),
            dirty: *dirty,
            preflight: preflight.clone(),
            references: references
                .iter()
                .map(|(name, value)| (name.clone(), value.map_text(&f)))
                .collect(),
            steps: steps
                .iter()
                .map(|DeployStep { id, name, action }| DeployStep {
                    id: *id,
                    name: f(name),
                    action: action.map_text(&f),
                })
                .collect(),
            warnings: warnings.iter().map(|warning| f(warning)).collect(),
        }
    }
}

impl DeployPlan {
    /// The script the extract-and-swap step `swap` runs on the target: built from this
    /// plan's version, previous release, operator and connecting user, and `swap`'s own
    /// values, and from nothing else, so the same plan always runs the same script and
    /// the values a preview shows beside it are the ones it embeds
    /// (`extract_swap_script`).
    ///
    /// The plan holds the values, not the text: its address covers the text too
    /// ([`deploy_plan_hash`](crate::config_hash::deploy_plan_hash)), so a plan reviewed
    /// under one zap doesn't bind one whose script differs.
    #[must_use]
    pub fn swap_script(&self, swap: &ReleaseSwap) -> String {
        extract_swap_script(self, swap)
    }
}

/// What a wetrun's drift preflight does before the steps — a fact of the plan, since it
/// changes what the wetrun does without changing a step.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DriftPreflight {
    /// The config's apply-managed resources are checked for drift; drift, or a resource
    /// that can't be read, stops the deploy. Names what is checked
    /// ([`DriftPreflight::checks`]), so a resource added, removed, or edited is another
    /// plan.
    Checks {
        /// How many resources are declared.
        resources: usize,
        /// The content address of the declared resources, by id, lowercase hex.
        digest: String,
    },
    /// The check is skipped (`--skip-preflight`).
    Skipped,
    /// The config declares no apply-managed resources, so there is nothing to check.
    NothingDeclared,
}

impl DriftPreflight {
    /// The preflight that checks `resources` — the desired side of its comparison, as a
    /// count and a digest.
    ///
    /// The digest addresses each resource by id: its declared state — every field but
    /// identity (`id` / `name` / `depends_on`) and a fetch `auth` — with each reference
    /// left as written, as the convergence plan holds a resource, plus the pin `lock`
    /// holds for it. So it is a function of the config and the lock alone: no
    /// environment value, secret or not, moves it, and it is safe to render. Hashed on
    /// [`HashDomain::Deploy`]. Declaration order isn't part of it.
    ///
    /// # Errors
    /// A `serde_json` error if a resource can't be serialized.
    pub fn checks(
        resources: &[Resource],
        lock: Option<&ZapLock>,
    ) -> Result<Self, serde_json::Error> {
        let mut declared: BTreeMap<&str, Value> = BTreeMap::new();
        for resource in resources {
            let mut fields = Value::Object(declared_fields(resource)?);
            fold_lock_pin(
                &mut fields,
                lock.and_then(|lock| lock.entries.get(&resource.id)),
            );
            declared.insert(resource.id.0.as_str(), fields);
        }
        Ok(Self::Checks {
            resources: resources.len(),
            digest: hash_canonical(HashDomain::Deploy, &declared)?,
        })
    }
}

/// One step of a deploy, with a stable `id` / `name` (for events) and a typed action.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeployStep {
    /// Step identifier within the run.
    pub id: DeployStepId,
    /// Human-readable label.
    pub name: String,
    /// What this step does.
    pub action: DeployAction,
}

/// The attributes an [`Upload`](DeployAction::Upload) installs the archive with: mode
/// `600`, the connecting user's.
pub const UPLOAD_ATTRS: crate::put::FileAttrs<'static> = crate::put::FileAttrs::mode("600");

/// The command an [`Upload`](DeployAction::Upload) to `remote` runs.
///
/// On a target it puts to by script, that is [`FILE_PUT`](crate::put::FILE_PUT) as the
/// connecting user, with [`UPLOAD_ATTRS`]. The plan names the step and not this text,
/// so the deploy plan's address covers it
/// ([`deploy_plan_hash`](crate::config_hash::deploy_plan_hash)).
#[must_use]
pub fn upload_put_command(remote: &str) -> String {
    crate::put::file_put_command(
        crate::put::RunAs::Caller,
        remote,
        UPLOAD_ATTRS,
        crate::put::PutCheck::None,
    )
}

/// What a [`DeployStep`] does — each variant maps to one IO executor in `zap_core`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum DeployAction {
    /// Build locally before packaging (the command run by a local `sh`; stdout
    /// captured).
    Build {
        /// The build command.
        command: String,
    },
    /// Create the release archive locally.
    Tarball {
        /// The `tar` command. It writes the file [`ARCHIVE_ENV`] names: a file in a
        /// private directory the run creates for it and removes when it ends.
        command: String,
    },
    /// Install the archive on the target, as the connecting user: staged, checked
    /// against its SHA-512, and renamed into place at mode `600`
    /// ([`FILE_PUT`](crate::put::FILE_PUT)).
    Upload {
        /// Where on the target it is installed.
        remote: String,
    },
    /// Run the remote extract + symlink-swap script on the target, which
    /// [`DeployPlan::swap_script`] builds from these values and the plan's. Its stdin is
    /// the archive's SHA-512 as one line of lowercase hex.
    ExtractSwap(ReleaseSwap),
    /// Restart the service on the target after the swap.
    Restart {
        /// The restart command.
        command: String,
    },
    /// Poll an HTTP health endpoint (locally) until it succeeds or the budget runs out.
    Health {
        /// Full URL to poll, as declared: a reference in it resolves when it is polled.
        url: String,
        /// `url` with its references resolved the way the plan's host is — a value, or
        /// a secret's masking token — so the plan names the endpoint it is for.
        url_label: String,
        /// How many attempts before failing.
        attempts: u32,
        /// Delay between attempts, in milliseconds.
        interval_ms: u64,
        /// How long one attempt may take, in milliseconds ([`PROBE_TIMEOUT_MS`]).
        timeout_ms: u64,
    },
    /// Poll the `/ready` schema-drift deploy gate (after liveness). `2xx` → the
    /// live DB schema matches the running code, deploy proceeds; `503` (schema
    /// drift / DB unreachable) → failed deploy → rollback; a persistent `404` →
    /// a loud warning (the gate is absent — the backend doesn't serve `/ready`
    /// or nginx doesn't proxy it) and the deploy proceeds on liveness alone.
    Readiness {
        /// Full URL to poll (`https://<domain>/ready`), as declared.
        url: String,
        /// `url` with its references resolved, as [`Health`](Self::Health)'s is.
        url_label: String,
        /// How many attempts before deciding.
        attempts: u32,
        /// Delay between attempts, in milliseconds.
        interval_ms: u64,
        /// How long one attempt may take, in milliseconds ([`PROBE_TIMEOUT_MS`]).
        timeout_ms: u64,
    },
}

/// What the extract-and-swap step does with a release on the target, as values.
///
/// The app it works in, how many releases it keeps, the shared files it links, and the
/// commands it prepares the release with.
/// The script is built from these and the plan's own values — the version, the release
/// it replaces, the operator, the connecting user — by [`DeployPlan::swap_script`], and
/// from nothing else, so a preview that shows them shows what the script embeds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReleaseSwap {
    /// The app path on the target (`deploy.path`): it holds `releases/`, `shared/`,
    /// `current`, and the uploaded archive.
    pub app: String,
    /// How many releases are kept (`deploy.releases`), this one and the one it replaces
    /// among them.
    pub keep: u32,
    /// The files under `<app>/shared/` linked into the release (`deploy.shared`).
    pub shared: Vec<String>,
    /// The commands run in the release before the swap (`deploy.prepare`), each in a
    /// shell of its own.
    pub prepare: Vec<String>,
}

impl ReleaseSwap {
    /// This swap with every free-text field passed through `f` ([`DeployPlan::map_text`]).
    #[must_use]
    pub fn map_text(&self, f: impl Fn(&str) -> String) -> Self {
        let Self {
            app,
            keep,
            shared,
            prepare,
        } = self;
        Self {
            app: f(app),
            keep: *keep,
            shared: shared.iter().map(|file| f(file)).collect(),
            prepare: prepare.iter().map(|command| f(command)).collect(),
        }
    }
}

/// How long one health or readiness attempt may take, in milliseconds: the whole
/// request, from connecting to the last byte of the answer.
///
/// Each poll in a plan carries it, so the budget a preview states for a poll is the one
/// the poll runs with.
pub const PROBE_TIMEOUT_MS: u64 = 5_000;

impl DeployAction {
    /// This action with every free-text field passed through `f`
    /// ([`DeployPlan::map_text`]). A polled `url` holds its domain's references inert:
    /// the text around them is mapped and each reference kept, so `f` never reaches a
    /// reference's name.
    #[must_use]
    pub fn map_text(&self, f: impl Fn(&str) -> String) -> Self {
        match self {
            Self::Build { command } => Self::Build {
                command: f(command),
            },
            Self::Tarball { command } => Self::Tarball {
                command: f(command),
            },
            Self::Upload { remote } => Self::Upload { remote: f(remote) },
            Self::ExtractSwap(swap) => Self::ExtractSwap(swap.map_text(&f)),
            Self::Restart { command } => Self::Restart {
                command: f(command),
            },
            Self::Health {
                url,
                url_label,
                attempts,
                interval_ms,
                timeout_ms,
            } => Self::Health {
                url: map_literals(url, &f),
                url_label: f(url_label),
                attempts: *attempts,
                interval_ms: *interval_ms,
                timeout_ms: *timeout_ms,
            },
            Self::Readiness {
                url,
                url_label,
                attempts,
                interval_ms,
                timeout_ms,
            } => Self::Readiness {
                url: map_literals(url, &f),
                url_label: f(url_label),
                attempts: *attempts,
                interval_ms: *interval_ms,
                timeout_ms: *timeout_ms,
            },
        }
    }
}

/// Inputs the pure planner can't read off the config.
///
/// Values **discovered** at run time (the git version and tree state, the operator
/// identity, what the target currently serves), the resolved connecting user, host, and
/// health domain, and what the invocation chose (`--skip-build`, the drift preflight).
/// Gathered in `zap_core`, then fed in so [`plan_deploy`] stays pure and deterministic
/// for a given context.
///
/// Everything here is genuinely undiscoverable from `zap.ts` alone. Declared
/// configuration — the deploy domain included — belongs on
/// [`DeploySpec`], not in this struct: a value the config
/// could state but the engine sources from ambient env is unthreadable by the config and
/// invisible to the env preflight.
#[derive(Debug, Clone)]
pub struct DeployContext {
    /// Release version (short git hash; `-dirty-<8 hex>`, the tree's id, when forced
    /// over a dirty tree).
    pub version: String,
    /// The subject line of the commit the version names, as `zap_core` read and bounded
    /// it, with any registered secret already masked out.
    pub subject: String,
    /// The resolved connecting user (`target.user()` with references resolved), empty
    /// when the target declares none. It is part of the uploaded archive's name
    /// (`archive_path`), and the plan names it ([`DeployPlan::user`]).
    pub target_user: String,
    /// `user@host` of the operator machine (recorded in `deploy_info.json`).
    pub deployed_by: String,
    /// The currently-deployed version on the target, if any.
    pub previous_version: Option<String>,
    /// The host the target resolves to, as the last-run report labels it
    /// ([`host_label`](crate::last_run::host_label)): a secret reference as its
    /// masking token, any other as its value.
    pub target_host: String,
    /// `deploy.health.domain` resolved the way [`target_host`](Self::target_host) is
    /// ([`resolved_label`](crate::last_run::resolved_label)). Read only when the spec
    /// declares a health block.
    pub health_domain: String,
    /// The working tree has uncommitted changes or untracked files.
    pub dirty: bool,
    /// Leave the `Build` step out of the plan (`--skip-build`): the release packs the
    /// artifacts as they are.
    pub skip_build: bool,
    /// What the wetrun's drift preflight does.
    pub preflight: DriftPreflight,
    /// What each reference the `deploy` block uses resolves to
    /// ([`deploy_references`]).
    pub references: BTreeMap<EnvVarName, ReferenceValue>,
}

/// What each reference `deploy` uses resolves to through `var`, by name.
///
/// The deploy plan's [`references`](crate::plan::references). The block's texts are the
/// ones [`DeploySpec::for_each_text`] walks: today its health check's domain.
///
/// The target's own references are not among them: the plan carries what its host and
/// connecting user resolve to ([`DeployPlan::host`], [`DeployPlan::user`]).
#[must_use]
pub fn deploy_references(
    deploy: &DeploySpec,
    var: &dyn Fn(&str) -> ReportVar,
) -> BTreeMap<EnvVarName, ReferenceValue> {
    let mut references = BTreeMap::new();
    deploy.for_each_text(|_, text| {
        for name in text.ref_names() {
            if let Ok(key) = EnvVarName::new(name) {
                references.insert(key, ReferenceValue::of(var(name)));
            }
        }
    });
    references
}

/// The environment variable the `Tarball` step's command reads the local archive's path
/// from.
///
/// The path isn't in the plan: it is a file in a directory the run creates — mode
/// `700`, under a name nobody could have prepared — so it differs from run to run, and a
/// plan is the same for the same inputs. The command names the variable instead, and
/// the executor sets it.
pub const ARCHIVE_ENV: &str = "ZAP_DEPLOY_ARCHIVE";

/// Where the release archive for `version` is uploaded on the target: a dot-file in the
/// app path, named for the resolved connecting `user` and the version.
///
/// The app path is a directory the connecting user already has to write — the extract
/// script creates `releases/`, `current.new`, and `deploy_info.json` there — and whoever
/// else can write it can already re-point `current`, so the archive is exposed to no one
/// the release isn't. A shared directory (`/tmp`) would let any account on the target
/// prepare the name. The script still trusts nothing about the name: it checks the file
/// it opens against the digest of the archive that was built ([`extract_swap_script`]).
///
/// The `user` segment keeps two connecting users' archives apart (a leftover of one is
/// never the other's to replace) and puts the connecting user in the plan by value.
fn archive_path(app: &str, user: &str, version: &str) -> String {
    format!("{app}/.zap-deploy-{user}-{version}.tar.gz")
}

/// The canonical readiness-probe path the deploy gate polls (the spine
/// schema-drift `/ready` route). A health step already targeting this path is
/// itself the readiness gate, so the auto-emitted readiness step is skipped to
/// avoid a redundant second poll.
const READINESS_PATH: &str = "/ready";

/// Build the ordered [`DeployPlan`] from the declared options + IO-resolved context.
///
/// Only applicable steps are emitted: `Build` only with a `build` command the run
/// doesn't skip, `Restart` only with a `service`, `Health` only with a `health` block.
///
/// Each condition is a single `Option` on the declared spec or a choice the context
/// states, so a step can only go missing because the config or the invocation didn't
/// ask for it — never because an ambient input was absent. The health URL a step polls
/// keeps its reference inert (the domain is a declared field, resolved at the
/// IO boundary like every other reference); beside it the step carries the URL with the
/// context's resolved domain, so two environments' endpoints are two plans.
#[must_use]
pub fn plan_deploy(opts: &DeploySpec, target: &Target, ctx: &DeployContext) -> DeployPlan {
    let archive = archive_path(&opts.path, &ctx.target_user, &ctx.version);
    let mut steps = Vec::new();

    if let Some(build) = &opts.build
        && !ctx.skip_build
    {
        steps.push(DeployStep {
            id: DeployStepId::Build,
            name: "Build application".to_owned(),
            action: DeployAction::Build {
                command: build.clone(),
            },
        });
    }

    let artifacts = opts
        .artifacts
        .iter()
        .map(|a| single_quote(a))
        .collect::<Vec<_>>()
        .join(" ");
    steps.push(DeployStep {
        id: DeployStepId::Tarball,
        name: "Create tarball".to_owned(),
        action: DeployAction::Tarball {
            command: format!("tar -czf \"${ARCHIVE_ENV}\" -- {artifacts}"),
        },
    });

    steps.push(DeployStep {
        id: DeployStepId::Upload,
        name: "Upload tarball".to_owned(),
        action: DeployAction::Upload { remote: archive },
    });

    steps.push(DeployStep {
        id: DeployStepId::ExtractSwap,
        name: "Extract and swap release".to_owned(),
        action: DeployAction::ExtractSwap(ReleaseSwap {
            app: opts.path.clone(),
            keep: opts.releases,
            shared: opts.shared.clone(),
            prepare: opts.prepare.clone(),
        }),
    });

    let mut warnings = Vec::new();
    if let Some(service) = &opts.service {
        match restart_command(target.service_manager, service) {
            Some(command) => steps.push(DeployStep {
                id: DeployStepId::Restart,
                name: format!("Restart {service}"),
                action: DeployAction::Restart { command },
            }),
            // Never drop the step silently: the release would swap in, the old process
            // would keep serving, and the health poll would pass against it.
            None => warnings.push(format!(
                "`deploy.service` `{service}` will not be restarted: zap has no restart \
                 command for the target's service manager ({}), so the swapped release keeps \
                 the old process running until it is restarted by hand",
                target
                    .service_manager
                    .map_or("undeclared", ServiceManager::as_str)
            )),
        }
    }

    if let Some(health) = &opts.health {
        steps.push(DeployStep {
            id: DeployStepId::Health,
            name: "Health check".to_owned(),
            action: DeployAction::Health {
                url: format!("https://{}{}", health.domain.as_inert(), health.path),
                url_label: format!("https://{}{}", ctx.health_domain, health.path),
                attempts: health.attempts.get(),
                interval_ms: health.interval_ms,
                timeout_ms: PROBE_TIMEOUT_MS,
            },
        });

        // Readiness deploy gate — poll `/ready` (the spine schema-drift probe)
        // after liveness, UNLESS the health step already targets `/ready` (a
        // consumer that folded readiness into liveness — then that step IS the
        // gate and a second poll is redundant). Default-on at the deploy layer,
        // not per-consumer config: every fuz_app consumer serves `/ready`, so a
        // health-gated deploy is schema-gated too. `2xx` → proceed; `503` →
        // failed deploy → rollback; `404` → loud warning (gate absent — backend
        // doesn't serve `/ready`, or nginx doesn't proxy it) and the deploy
        // proceeds on liveness. Reuses the health poll cadence + the deploy domain.
        if health.path != READINESS_PATH {
            steps.push(DeployStep {
                id: DeployStepId::Readiness,
                name: "Readiness check".to_owned(),
                action: DeployAction::Readiness {
                    url: format!("https://{}{READINESS_PATH}", health.domain.as_inert()),
                    url_label: format!("https://{}{READINESS_PATH}", ctx.health_domain),
                    attempts: health.attempts.get(),
                    interval_ms: health.interval_ms,
                    timeout_ms: PROBE_TIMEOUT_MS,
                },
            });
        }
    }

    DeployPlan {
        version: ctx.version.clone(),
        subject: ctx.subject.clone(),
        previous: ctx.previous_version.clone(),
        target: target.clone(),
        host: ctx.target_host.clone(),
        user: (!ctx.target_user.is_empty()).then(|| ctx.target_user.clone()),
        deployed_by: ctx.deployed_by.clone(),
        dirty: ctx.dirty,
        preflight: ctx.preflight.clone(),
        references: ctx.references.clone(),
        steps,
        warnings,
    }
}

/// The restart command for `service`, preceded by a manager `daemon-reload` when the
/// manager has one. Carries `sudo` (deploy runs as the login user; the restart needs
/// privilege) — unlike the `service_managers` verbs, which are sudo-free for the
/// planner to prefix. `None` for a manager without a restart verb.
fn restart_command(sm: Option<ServiceManager>, service: &str) -> Option<String> {
    let restart = service_managers::restart_for(sm, service)?;
    // daemon-reload is manager-specific (systemd has one; OpenRC re-reads init scripts
    // each call, so its `daemon_reload` is `None`) — route through the template rather
    // than hardcoding the systemd form, so an OpenRC target doesn't mis-emit it.
    Some(sm.and_then(service_managers::daemon_reload).map_or_else(
        || format!("sudo {restart}"),
        |reload| format!("sudo {reload} && sudo {restart}"),
    ))
}

/// What the extract-and-swap script does with the uploaded archive before it extracts
/// anything: open it once, and go on only when the open file is this user's own regular
/// file, writable by nobody else, whose SHA-512 is the digest read from stdin.
///
/// A `stat` or an `id` that prints nothing fails the check it feeds: an owner or a mode
/// that wasn't read is never taken for an acceptable one.
///
/// Everything after — the digest, the extraction — goes through that one descriptor
/// (`/proc/self/fd/3`), so a file swapped in at the name afterwards is never read, and
/// the checks on its owner and mode mean no other account can change the bytes between
/// the digest and the extraction.
const ARCHIVE_CHECK: &str = r#"[ -d /proc/self/fd ] || zap_fail "no /proc on this machine to hold the release archive open through"
[ -f "$zap_archive" ] || zap_fail "no release archive at $zap_archive"
exec 3<"$zap_archive"
zap_fd=/proc/self/fd/3
zap_uid=$(id -u) && [ -n "$zap_uid" ] && [ -f $zap_fd ] && [ "$(stat -L -c %u $zap_fd)" = "$zap_uid" ] || zap_fail "$zap_archive is not a file this user uploaded"
case "$(stat -L -c %a $zap_fd)" in ""|*[2367]|*[2367]?) zap_fail "$zap_archive can be written by other users";; esac
zap_got=$(sha512sum <&3)
[ "${zap_got%% *}" = "$zap_want" ] || zap_fail "$zap_archive is not the archive this deploy built"
"#;

/// The shell function the extract-and-swap script prunes old releases with.
///
/// `zap_prune <releases dir> <current link> <keep> <version> <previous>` keeps `keep`
/// releases and removes the rest, in a subshell of its own. A release is an entry of the releases
/// directory that is a directory itself (not a link to one) and is named as zap names a
/// release: a commit hash — 4 to 64 lowercase hex digits — with an optional
/// `-dirty-` and 8 lowercase hex digits (a dirty tree's id).
/// Anything else there is not zap's and is never removed, whatever its name holds.
///
/// What is kept, in this order, `keep` in all: the release just deployed (`version`,
/// which `current` points at by the time the prune runs — the link is read too, so a
/// release it names is kept whichever that is); the release that was live before
/// (`previous`, the empty word when there was none), which is where a deploy that fails
/// after the swap is rolled back to, and so is never removed, however old it is; then
/// the others, newest first by the directory's modification time in whole seconds
/// (`stat -c %Y`, the same number under coreutils and `BusyBox`), two of the same second
/// in name order. The first two are kept whatever `keep` is, which is why a `keep`
/// below 2 is refused where the config is read: it could not be honored. Names are read
/// a line at a time and removed as `./<name>` after `--`: the shape leaves no name that
/// holds a blank, a line break, or a leading `-`.
///
/// The live release is the last segment of what `current` names, trailing slashes
/// dropped. A `current` naming anything but a release by that rule, or `version` —
/// nothing (`/`), a `.` or `..` segment (`releases/<version>/.`), a path below a
/// release — could name a release the prune would not know to keep, so it removes
/// nothing and fails, saying what `current` names. No `current` at all keeps only
/// `version` and `previous`. A target with no `sort` prunes nothing and fails, saying
/// so: without it the order the releases are kept in can't be read.
///
/// It holds no single quote.
pub const PRUNE_RELEASES: &str = r#"zap_prune() (
  if ! command -v sort >/dev/null; then
    printf "no sort on this machine, so no release was pruned\n" >&2
    exit 1
  fi
  CDPATH= cd -P -- "$1" || exit 1
  zap_is_release() {
    zap_b=${1%-dirty-????????}
    case ${1#"$zap_b"} in ""|-dirty-[0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]) ;; *) return 1;; esac
    case $zap_b in ""|*[!0-9a-f]*) return 1;; esac
    [ ${#zap_b} -ge 4 ] && [ ${#zap_b} -le 64 ]
  }
  if zap_live=$(readlink -- "$2"); then
    zap_link=$zap_live
    while :; do case $zap_live in */) zap_live=${zap_live%/};; *) break;; esac; done
    zap_live=${zap_live##*/}
    case $zap_live in "") zap_known=;; "$4") zap_known=1;; *) zap_is_release "$zap_live" && zap_known=1 || zap_known=;; esac
    if [ -z "$zap_known" ]; then
      printf "current names %s, which is no release, so no release was pruned\n" "$zap_link" >&2
      exit 1
    fi
  else
    zap_live=
  fi
  for zap_n in *; do
    zap_is_release "$zap_n" || continue
    [ -d "./$zap_n" ] && [ ! -L "./$zap_n" ] || continue
    zap_t=$(stat -c %Y -- "./$zap_n") && [ -n "$zap_t" ] || continue
    case $zap_n in "$zap_live"|"$4"|"$5") zap_k=0;; *) zap_k=1;; esac
    echo "$zap_k $zap_t $zap_n"
  done | LC_ALL=C sort -k1,1n -k2,2nr -k3,3 | {
    zap_i=0
    while IFS=" " read -r zap_k zap_t zap_n; do
      zap_i=$((zap_i + 1))
      [ "$zap_i" -gt "$3" ] && [ "$zap_k" = 1 ] || continue
      rm -rf -- "./$zap_n" || exit 1
    done
  }
)
"#;

/// Whether `name` is named as zap names a release: a commit hash — 4 to 64 lowercase
/// hex digits — with an optional `-dirty-` and 8 lowercase hex digits. The shape
/// [`PRUNE_RELEASES`] reads releases by.
#[must_use]
pub fn is_release_name(name: &str) -> bool {
    let hex = |text: &str| {
        text.bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    };
    let base = match name.split_once("-dirty-") {
        Some((base, id)) if id.len() == 8 && hex(id) => base,
        Some(_) => return false,
        None => name,
    };
    (4..=64).contains(&base.len()) && hex(base)
}

/// The release a `current` link's text names: its last segment, trailing slashes
/// dropped, when that is a release's name ([`is_release_name`]).
///
/// `None` for text that names no release that way — nothing, a `.` or `..` segment, a
/// path below a release — since its last segment is then not the release it reaches.
#[must_use]
pub fn release_of_link(link: &str) -> Option<&str> {
    let name = link.trim_end_matches('/').rsplit('/').next()?;
    is_release_name(name).then_some(name)
}

/// The call of [`PRUNE_RELEASES`]' function for an app at `app`.
///
/// It keeps `keep` releases, having just deployed `version` over `previous` — the
/// release that was live, `None` on a first deploy (the empty word, which is no
/// release's name).
#[must_use]
pub fn prune_releases_call(app: &str, keep: u32, version: &str, previous: Option<&str>) -> String {
    format!(
        "zap_prune {} {} {keep} {} {}",
        single_quote(&format!("{app}/releases")),
        single_quote(&format!("{app}/current")),
        single_quote(version),
        single_quote(previous.unwrap_or_default()),
    )
}

/// What the rollback's remote command found, and so what it did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RollbackSwap {
    /// `current` still named the failed release and now names the previous one.
    RolledBack,
    /// `current` no longer named the failed release — a deploy of another version since
    /// replaced it, or it was re-pointed by hand — so it was left as it is.
    Replaced,
    /// Another deploy of the app holds the deploy lock; `current` was left as it is.
    Busy,
    /// `current` is no symlink at all, so it names no release; it was left as it is.
    Absent,
    /// `current` still named the failed release, but the previous release is no longer
    /// a directory (pruned, or removed by hand), so `current` was left as it is rather
    /// than pointed at nothing.
    Gone,
}

impl RollbackSwap {
    /// The word the remote command prints for each outcome, alone on its stdout.
    #[must_use]
    pub const fn token(self) -> &'static str {
        match self {
            Self::RolledBack => "rolled_back",
            Self::Replaced => "replaced",
            Self::Busy => "busy",
            Self::Absent => "absent",
            Self::Gone => "gone",
        }
    }

    /// The outcome a successful run of the command printed, or an error for anything
    /// else: an outcome that wasn't read is never taken for one.
    ///
    /// # Errors
    /// The text it was given, when it is no outcome's token.
    pub fn parse(stdout: &str) -> Result<Self, String> {
        [
            Self::RolledBack,
            Self::Replaced,
            Self::Busy,
            Self::Absent,
            Self::Gone,
        ]
        .into_iter()
        .find(|outcome| stdout.trim() == outcome.token())
        .ok_or_else(|| format!("the rollback printed no outcome it knows: {stdout:?}"))
    }
}

/// The auto-rollback's remote command: re-point `current` at the release `previous`
/// only while it still names the release `failed` that this deploy swapped in.
///
/// A compare-and-swap over the extract-and-swap script's atomic swap, run by `zap_core`
/// after a deploy fails past the swap. It takes the app's deploy lock
/// ([`deploy_lock_path`]) the way the script does, without waiting: the script has
/// exited by now, so the lock held means another deploy of the app is working in it,
/// and that deploy decides what `current` names. With the lock, it compares the link's
/// text to the path the swap wrote, so a deploy of another version that replaced the
/// release since, or a hand re-point, is never undone. A deploy planned before this
/// one's swap never gets that far (the script checks `current` against its plan), so
/// what is left is a `--force` redeploy of the same version planned after this one's
/// swap: it writes the same text, and this rollback can undo it. It re-points only at
/// a `previous` that is still a directory, so it never leaves `current` naming nothing.
/// It prints its [`RollbackSwap`] token on success; with no `flock` on the target, or
/// a lock it can't open, it exits nonzero with none, which the caller reads as a failed
/// rollback rather than another deploy's lock.
#[must_use]
pub fn rollback_swap_command(app_path: &str, failed: &str, previous: &str) -> String {
    let release = |version: &str| format!("{app_path}/releases/{version}");
    let current = format!("{app_path}/current");
    let staged = format!("{current}.new");
    format!(
        "command -v flock >/dev/null && umask o-rwx && \
         {{ [ -e {lock} ] || command : >>{lock}; }} && exec 9<{lock} && \
         if ! flock -n 9; then echo {busy}; \
         elif [ ! -L {current} ]; then echo {absent}; \
         elif [ \"$(readlink -- {current})\" != {failed} ]; then echo {replaced}; \
         elif [ ! -d {previous} ]; then echo {gone}; \
         else ln -sfn -- {previous} {staged} && mv -Tf -- {staged} {current} && echo {done}; fi",
        lock = single_quote(&deploy_lock_path(app_path)),
        current = single_quote(&current),
        failed = single_quote(&release(failed)),
        previous = single_quote(&release(previous)),
        staged = single_quote(&staged),
        busy = RollbackSwap::Busy.token(),
        replaced = RollbackSwap::Replaced.token(),
        absent = RollbackSwap::Absent.token(),
        gone = RollbackSwap::Gone.token(),
        done = RollbackSwap::RolledBack.token(),
    )
}

/// `text` as a JSON string, quotes included.
fn json_string(text: &str) -> String {
    Value::String(text.to_owned()).to_string()
}

/// Where the deploy lock of an app at `app` lives: a dot-file in the app path, never
/// removed, holding no data.
///
/// The extract-and-swap script holds a kernel `flock` on it for its whole life, and the
/// auto-rollback takes it again to re-point `current`, so two deploys of one app never
/// work in its `releases/` at once. It is created, when absent, with no permission for
/// other users: an account outside the connecting user and its group can't open it,
/// and so can't hold it. Both take it on a read-only descriptor, so a group member
/// the umask gave read alone can still hold it.
#[must_use]
pub fn deploy_lock_path(app: &str) -> String {
    format!("{app}/.zap-deploy.lock")
}

/// The mark that starts a warning line on the extract-and-swap script's stdout.
///
/// The script marks what the operator must see though the deploy goes on: what it
/// recovered from a deploy that did not finish, and what its housekeeping after the
/// swap could not do. The executor lifts each such line into the run's warnings. Every
/// `prepare` command's output goes to the script's stderr, so what a command prints
/// adds no warning; one that reaches the script's own stdout anyway (through `/proc`,
/// or a descriptor it was handed, as [`SWAPPED_LINE`] says) can print the mark and add
/// a warning of its words. A warning is narrative only: it changes no outcome.
pub const SCRIPT_WARNING_PREFIX: &str = "zap warning: ";

/// The mark that starts the line on the extract-and-swap script's stdout that says why
/// it stopped, when it stopped itself (its `zap_fail`).
///
/// The executor reports a failed script by this line when there is one: the script's
/// stderr also holds every `prepare` command's output, where an `ERROR:` line of a
/// tool's own would pass for the script's reason. A `prepare` command that reaches the
/// script's stdout ([`SWAPPED_LINE`]) can print this mark too, and so word the reason a
/// failed run reports; the text decides nothing, since what the deploy does turns on
/// the script's exit status and its swap line.
pub const SCRIPT_ERROR_PREFIX: &str = "zap error: ";

/// The line the extract-and-swap script prints on its stdout as soon as `current` names
/// the new release, alone on its line.
///
/// The executor reads the swap as done by this line, not by the script's exit status:
/// a release is live once the line is printed, so it is restarted and health-checked
/// (and rolled back on a failure) whatever comes after, and a script that exited
/// without it — a failure before the swap, or a `prepare` command that ended the
/// script — swapped nothing. Before the swap only the script's warning lines
/// ([`SCRIPT_WARNING_PREFIX`]) and its error ([`SCRIPT_ERROR_PREFIX`]) go to its stdout:
/// a `prepare` command's output goes to its stderr. A `prepare` command that reaches the script's stdout anyway can print
/// the line, so the executor believes it from a script that then failed only once
/// `current` is read again and names the new release.
pub const SWAPPED_LINE: &str = "zap: current swapped";

/// What the extract-and-swap script does in `releases/` once it holds the deploy lock,
/// before anything else there: put right what a deploy that did not finish left.
///
/// Every hidden entry zap names belongs to a run that is no longer alive — a live one
/// would hold the lock — so: the staging directory (`.zap-stage`) is removed; a release
/// moved aside under its version (`.zap-old-<version>`) is moved back when
/// `releases/<version>` is absent (a run killed between its two renames, which under
/// `--force` of the live version leaves `current` naming nothing) and removed when the
/// name is filled again. Any other entry is left alone. Each step is a warning line
/// ([`SCRIPT_WARNING_PREFIX`]).
///
/// It reads the releases directory from `$zap_releases` and holds no single quote.
const RECOVER_RELEASES: &str = r#"for zap_e in "$zap_releases"/.zap-stage "$zap_releases"/.zap-old-*; do
  [ -e "$zap_e" ] || [ -L "$zap_e" ] || continue
  zap_n=${zap_e##*/}
  case $zap_n in
    .zap-stage)
      rm -rf -- "$zap_e"
      zap_warn "removed releases/$zap_n, the staging directory of a deploy that did not finish";;
    .zap-old-*)
      zap_v=${zap_n#.zap-old-}
      if [ -e "$zap_releases/$zap_v" ] || [ -L "$zap_releases/$zap_v" ]; then
        rm -rf -- "$zap_e"
        zap_warn "removed releases/$zap_n, the release a deploy that did not finish had replaced"
      else
        mv -T -- "$zap_e" "$zap_releases/$zap_v"
        zap_warn "restored releases/$zap_v, which a deploy that did not finish had moved aside"
      fi;;
  esac
done
"#;

/// Generate the remote extract-and-swap script (pure), from `plan`'s version, previous
/// release, operator and connecting user, and `swap`'s app path, retention, `shared`
/// files and `prepare` commands — nothing else ([`DeployPlan::swap_script`]). The
/// archive it extracts is the one the upload installs (`archive_path`). The target's
/// `date` stamps `deploy_info.json` (no `jq` dependency), whose other values are written
/// as JSON strings here, so the file parses whatever a version or an operator's name
/// holds.
///
/// Nothing the config, the operator machine or the target supplied is read by the
/// shell: each such value is one single-quoted word, and a message is printed by
/// `printf` from one. The `prepare` commands are the exception, being commands: each is
/// run by a shell of its own (`sh -ec`), its stdout sent to the script's stderr, so a
/// command that exits or `exec`s ends itself, not the script, and fails the script when
/// it fails.
///
/// Its stdin is one line: the SHA-512 of the archive the run built, in lowercase hex.
/// The digest isn't known when the plan is made (the build runs after it), so the script
/// reads it rather than holding it, and detaches its stdin once it has.
///
/// Then it takes the app's deploy lock ([`deploy_lock_path`]) on descriptor 9 with
/// `flock -n` and holds it until it exits: another deploy of the app holding it stops
/// this one at once (`another deploy is running for this app`, exit 1), before anything
/// in `releases/` is touched, and a target with no `flock` is told so. The `prepare`
/// commands run with descriptor 9 closed, so a process one of them leaves running
/// doesn't hold the lock past the script; the script's own copy stays open while they
/// run. Under the lock it recovers what a deploy that did not finish left in
/// `releases/` ([`RECOVER_RELEASES`]), then checks that `current` still names the
/// release the plan read as live ([`DeployPlan::previous`], by the link's last
/// segment with trailing slashes dropped; no link at all for none): a deploy that swapped since the plan was made stops this
/// one (exit 1, before anything else), so the release this one rolls back to and the
/// one its prune keeps are the ones live just before its swap.
///
/// The archive at `archive` is removed on every exit of the script — a trap set before
/// anything can fail, whose own failure never changes the script's exit status — and as
/// soon as it is extracted. It is extracted only after
/// [`ARCHIVE_CHECK`] passes, with `--no-same-owner --no-same-permissions`: the release's
/// files belong to the user extracting them whatever ids the archive recorded (as root,
/// `tar` would otherwise restore the operator machine's), with no set-id bit and under
/// that user's umask.
///
/// The release is extracted into a hidden staging directory in `releases/`
/// (`.zap-stage`), where the shared links are made and `prepare` runs; only then
/// does it take its name, `releases/<version>`. Whatever held that name — a directory
/// left by an earlier deploy of the same version, or the live release under `--force` —
/// is moved aside (`.zap-old-<version>`) first and removed after the swap, so a release
/// directory never holds files of two extractions. On exit, what was moved aside is
/// removed only once the name is filled again; moved aside and not replaced (the rename
/// failed, or a signal landed between the two renames), it is moved back. The flag that
/// says so is set before the move, so a signal during it can't leave the moved-aside
/// release unaccounted for. The staging directory is removed on every exit. A run killed
/// outright gets no exit of its own; the next deploy's recovery does the same work. The
/// exit's work in `releases/` is done only by a run that took the lock, so a run turned
/// away touches nothing of the one that holds it. Under `--force` of the live version,
/// `current` names nothing between the two renames. Hidden names are never a release's,
/// so the prune never reads them.
///
/// Once `current` names the new release the script prints [`SWAPPED_LINE`], and what
/// follows — removing what was moved aside, writing `deploy_info.json`, the prune — is
/// housekeeping: a failure there is a warning line, each of its error lines a warning
/// of its own, and the script still exits 0, its last line `Deployed version <version>`.
fn extract_swap_script(plan: &DeployPlan, swap: &ReleaseSwap) -> String {
    let app = &swap.app;
    let version = &plan.version;
    let archive = archive_path(app, plan.user.as_deref().unwrap_or_default(), version);
    let releases_dir = format!("{app}/releases");
    let shared_dir = format!("{app}/shared");
    let current = format!("{app}/current");
    let release = format!("{releases_dir}/{version}");

    let mut script = String::from("set -e\n");
    let _ = writeln!(script, "zap_archive={}", single_quote(&archive));
    // The release is built under a hidden name in `releases/` (the same filesystem, so
    // the rename into place is one `rename`), and what held its name is moved aside
    // first, under a name carrying the version so a later run can put it back. One run
    // at a time works there (the lock), so the names need nothing of the run's own.
    let _ = writeln!(script, "zap_releases={}", single_quote(&releases_dir));
    let _ = writeln!(script, "zap_rel={}", single_quote(&release));
    let _ = writeln!(
        script,
        "zap_stage={}",
        single_quote(&format!("{releases_dir}/.zap-stage"))
    );
    let _ = writeln!(
        script,
        "zap_old={}",
        single_quote(&format!("{releases_dir}/.zap-old-{version}"))
    );
    script.push_str(concat!(
        "zap_moved=\n",
        "zap_locked=\n",
        // Its reason goes to stderr for the operator and, marked
        // (`SCRIPT_ERROR_PREFIX`), to stdout, where no `prepare` command's output goes.
        "zap_fail() { printf \"ERROR: %s\\n\" \"$1\" >&2; printf \"zap error: %s\\n\" \"$1\"; exit 1; }\n",
        // `SCRIPT_WARNING_PREFIX`, which a test holds this to. On stdout, which carries
        // only the script's own lines: a `prepare` command's output goes to stderr.
        "zap_warn() { printf \"zap warning: %s\\n\" \"$1\"; }\n",
        "trap 'rm -f -- \"$zap_archive\" || :; if [ -n \"$zap_locked\" ]; then ",
        "if [ -e \"$zap_rel\" ] || [ -L \"$zap_rel\" ]; then rm -rf -- \"$zap_old\" || :; ",
        "elif [ -n \"$zap_moved\" ]; then mv -T -- \"$zap_old\" \"$zap_rel\" || :; fi; ",
        "rm -rf -- \"$zap_stage\" || :; fi' EXIT\n",
        "trap 'exit 1' HUP INT TERM\n",
        "IFS= read -r zap_want && [ ${#zap_want} -eq 128 ] || ",
        "zap_fail \"the digest of the release archive did not arrive\"\n",
        "exec </dev/null\n",
    ));
    let _ = writeln!(script, "cd -- {}", single_quote(app));

    // One deploy of the app at a time: the lock is held on descriptor 9 until the
    // script exits, opened with no permission for other users, and a deploy that finds
    // it held stops before it touches anything.
    let lock = deploy_lock_path(app);
    script.push_str(concat!(
        "command -v flock >/dev/null || zap_fail \"no flock on this machine to hold the deploy lock with\"\n",
        "zap_umask=$(umask)\n",
        "umask o-rwx\n",
    ));
    // Made by an append when absent, then opened read-only: `flock` needs only an open
    // descriptor, so a group member the umask gave read alone can still hold it.
    // `command` keeps a redirection's failure from ending the shell before `zap_fail`.
    let _ = writeln!(
        script,
        "[ -e {lock_q} ] || command : >>{lock_q} || zap_fail {}",
        single_quote(&format!("cannot create the deploy lock {lock}")),
        lock_q = single_quote(&lock),
    );
    let _ = writeln!(
        script,
        "command exec 9<{} || zap_fail {}",
        single_quote(&lock),
        single_quote(&format!("cannot open the deploy lock {lock}")),
    );
    script.push_str(concat!(
        "umask \"$zap_umask\"\n",
        "flock -n 9 || zap_fail \"another deploy is running for this app\"\n",
        "zap_locked=1\n",
    ));
    let _ = writeln!(script, "mkdir -p -- {}", single_quote(&releases_dir));
    script.push_str(RECOVER_RELEASES);

    // What the plan read off `current` still holds under the lock — compared the way the
    // plan read it, by the link's last segment — so the release this deploy rolls back
    // to and the one the prune keeps are the ones live just before its swap, and a deploy
    // planned before another one swapped stops here.
    let _ = writeln!(
        script,
        "zap_cur=$(readlink -- {} 2>/dev/null) || zap_cur=",
        single_quote(&current)
    );
    script.push_str(
        "zap_now=\"it names $zap_cur now\"; [ -n \"$zap_cur\" ] || zap_now=\"it is not a link now\"\n",
    );
    // Trailing slashes dropped, as the plan's read drops them; a plan that read no
    // live release goes on only with nothing there at all — no link, and nothing else
    // the swap's rename would fail on after the release is staged.
    let still = plan.previous.as_deref().map_or_else(
        || format!("[ -z \"$zap_cur\" ] && ! [ -e {} ]", single_quote(&current)),
        |previous| {
            script.push_str(concat!(
                "zap_was=$zap_cur\n",
                "while :; do case $zap_was in */) zap_was=${zap_was%/};; *) break;; esac; done\n",
            ));
            format!(
                "[ -n \"$zap_cur\" ] && [ \"${{zap_was##*/}}\" = {} ]",
                single_quote(previous)
            )
        },
    );
    let _ = writeln!(
        script,
        "{still} || zap_fail \"\\`current\\` changed since this deploy was planned: $zap_now (another deploy ran, or something else is there now); run zap deploy again\""
    );

    // Verify each declared shared file exists (apply must have provisioned them).
    for file in &swap.shared {
        let _ = writeln!(
            script,
            "[ -f {} ] || zap_fail {}",
            single_quote(&format!("{shared_dir}/{file}")),
            single_quote(&format!(
                "{file} not found under shared/ — run `zap apply` first"
            )),
        );
    }

    // Check the archive, then extract the file that was checked into a fresh staging
    // directory, and drop it.
    script.push_str(ARCHIVE_CHECK);
    script.push_str(concat!(
        "mkdir -- \"$zap_stage\"\n",
        "tar -xzf $zap_fd --no-same-owner --no-same-permissions -C \"$zap_stage\"\n",
        "exec 3<&-\nrm -f -- \"$zap_archive\"\n",
    ));

    // Symlink shared files into the release root. A directory the release ships at a
    // shared name fails the deploy: `ln -sfn` would put the link inside it and exit 0,
    // and the release would run on the shipped directory, not the shared file.
    for file in &swap.shared {
        let at = format!("\"$zap_stage\"/{}", single_quote(file));
        let _ = writeln!(
            script,
            "if [ -d {at} ] && [ ! -L {at} ]; then zap_fail {}; fi",
            single_quote(&format!(
                "the release ships a directory at {file}, where a shared file is linked"
            )),
        );
        let _ = writeln!(
            script,
            "ln -sfn -- {} {at}",
            single_quote(&format!("{shared_dir}/{file}")),
        );
    }

    // Post-extract prepare commands, in the staged release, with the lock's descriptor
    // closed for them: a process one leaves running doesn't hold the lock past the
    // script, whose own copy stays open while they run. Each runs in a shell of its
    // own (`sh -e`), so an `exit` or an `exec` in one ends that command, not the script,
    // and its output goes to the script's stderr: the script's stdout carries only its
    // own lines, `SWAPPED_LINE` among them.
    if !swap.prepare.is_empty() {
        script.push_str("cd -- \"$zap_stage\"\n");
        for command in &swap.prepare {
            let _ = writeln!(script, "sh -ec {} 9>&- >&2", single_quote(command));
        }
    }

    // The complete release takes its name: whatever held it (a release left from an
    // earlier deploy of this version, the live one under `--force`) is moved aside
    // first, so every `releases/<version>` is one whole extraction.
    let _ = writeln!(script, "cd -- {}", single_quote(app));
    script.push_str(concat!(
        "if [ -e \"$zap_rel\" ] || [ -L \"$zap_rel\" ]; then ",
        "zap_moved=1; mv -T -- \"$zap_rel\" \"$zap_old\"; fi\n",
        "mv -T -- \"$zap_stage\" \"$zap_rel\"\n",
    ));

    // Atomic symlink swap.
    let _ = writeln!(
        script,
        "ln -sfn -- {} {}",
        single_quote(&release),
        single_quote(&format!("{current}.new")),
    );
    let _ = writeln!(
        script,
        "mv -Tf -- {} {}",
        single_quote(&format!("{current}.new")),
        single_quote(&current),
    );
    // From here the release is live: the executor reads this line as the swap done,
    // and restarts and health-checks it whatever follows. What follows is housekeeping,
    // and a failure of it is a warning, never the script's exit status.
    let _ = writeln!(script, "echo {}", single_quote(SWAPPED_LINE));
    script.push_str(concat!(
        "zap_after() { zap_warn \"after the swap, $1\"; printf '%s\\n' \"$2\" | ",
        "while IFS= read -r zap_l; do [ -z \"$zap_l\" ] || zap_warn \"$zap_l\"; done; }\n",
    ));
    let _ = writeln!(
        script,
        "zap_e=$(rm -rf -- \"$zap_old\" 2>&1) || zap_after {} \"$zap_e\"",
        single_quote(&format!(
            "releases/.zap-old-{version} was not removed; the next deploy removes it"
        )),
    );

    // Record deploy info (no `jq`: the target's `date` stamps `deployed_at`). Each value
    // arrives as a JSON string of its own, printed by `%s` as it is.
    let previous_json = plan
        .previous
        .as_deref()
        .map_or_else(|| "null".to_owned(), json_string);
    let _ = writeln!(
        script,
        "zap_e=$(printf '{{\"version\":%s,\"deployed_by\":%s,\"previous_version\":%s,\"deployed_at\":\"%s\"}}\\n' {} {} {} \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\" 2>&1 > {}) || zap_after {} \"$zap_e\"",
        single_quote(&json_string(version)),
        single_quote(&json_string(&plan.deployed_by)),
        single_quote(&previous_json),
        single_quote(&format!("{app}/deploy_info.json")),
        single_quote("deploy_info.json was not written"),
    );

    // Prune old releases beyond the retention count — never the release this script
    // just swapped in, nor the one that was live before it, which a failed deploy is
    // rolled back to.
    script.push_str(PRUNE_RELEASES);
    let _ = writeln!(
        script,
        "zap_e=$({} 2>&1) || zap_after {} \"$zap_e\"",
        prune_releases_call(app, swap.keep, version, plan.previous.as_deref()),
        single_quote("the old releases were not pruned"),
    );

    let _ = write!(
        script,
        "printf 'Deployed version %s\\n' {}",
        single_quote(version)
    );
    script
}

#[cfg(test)]
mod tests {
    use super::{
        ARCHIVE_CHECK, ARCHIVE_ENV, DeployAction, DeployContext, DeployPlan, DeployStepId,
        DriftPreflight, PRUNE_RELEASES, ReleaseSwap, RollbackSwap, SCRIPT_WARNING_PREFIX,
        SWAPPED_LINE, deploy_lock_path, deploy_references, plan_deploy, rollback_swap_command,
        upload_put_command,
    };
    use crate::scalar::EnvVarName;
    use crate::schema::{DeployHealth, DeploySpec, ServiceManager, Target};
    use crate::text::Text;
    use crate::var_ref::Segment::{Ref, Text as Lit};
    use crate::var_ref::marker;
    use std::collections::BTreeMap;

    fn opts() -> DeploySpec {
        DeploySpec {
            build: Some("gro build".to_owned()),
            artifacts: vec!["build/".to_owned(), "package.json".to_owned()],
            path: "/root/app".to_owned(),
            releases: 5,
            service: Some(crate::scalar::ServiceName::new("app").unwrap()),
            shared: vec![".env.production".to_owned()],
            prepare: vec!["deno cache src/lib/server/server.ts".to_owned()],
            health: Some(DeployHealth {
                domain: Text::literal("example.com"),
                path: "/health".to_owned(),
                attempts: std::num::NonZeroU32::new(15).unwrap(),
                interval_ms: 2000,
            }),
        }
    }

    fn target() -> Target {
        Target {
            service_manager: Some(ServiceManager::Systemd),
            ..Target::default()
        }
    }

    fn ctx() -> DeployContext {
        DeployContext {
            references: BTreeMap::new(),
            version: "abc1234".to_owned(),
            subject: "Ship the release".to_owned(),
            target_user: "deploy".to_owned(),
            deployed_by: "op@laptop".to_owned(),
            previous_version: Some("def5678".to_owned()),
            target_host: "app.example.com".to_owned(),
            health_domain: "example.com".into(),
            dirty: false,
            skip_build: false,
            preflight: checks(),
        }
    }

    /// A preflight that checks one resource, with a stand-in digest.
    fn checks() -> DriftPreflight {
        DriftPreflight::Checks {
            resources: 1,
            digest: "d1".to_owned(),
        }
    }

    #[test]
    fn full_deploy_plans_every_step_in_order() {
        let plan = plan_deploy(&opts(), &target(), &ctx());
        let ids: Vec<&str> = plan.steps.iter().map(|s| s.id.as_str()).collect();
        assert_eq!(
            ids,
            [
                "build",
                "tarball",
                "upload",
                "extract_swap",
                "restart",
                "health",
                "readiness"
            ]
        );
        assert_eq!(plan.version, "abc1234");
    }

    #[test]
    fn skips_inapplicable_steps() {
        // No build, no service, no health → just tarball/upload/extract_swap.
        let mut o = opts();
        o.build = None;
        o.service = None;
        o.health = None;
        let plan = plan_deploy(&o, &target(), &ctx());
        let ids: Vec<&str> = plan.steps.iter().map(|s| s.id.as_str()).collect();
        assert_eq!(ids, ["tarball", "upload", "extract_swap"]);
    }

    #[test]
    fn a_service_the_manager_cannot_restart_is_a_warning_not_a_dropped_step() {
        let target = Target {
            service_manager: Some(ServiceManager::Launchd),
            ..Target::default()
        };
        let plan = plan_deploy(&opts(), &target, &ctx());
        assert!(
            !plan
                .steps
                .iter()
                .any(|step| step.id == DeployStepId::Restart)
        );
        assert_eq!(
            plan.warnings,
            [
                "`deploy.service` `app` will not be restarted: zap has no restart command \
                 for the target's service manager (launchd), so the swapped release keeps the \
                 old process running until it is restarted by hand"
            ]
        );
    }

    #[test]
    fn health_steps_ride_the_declared_block_alone() {
        // Both verification steps hang off one `Option` on the declared spec, so they can
        // only go missing because the config omitted `health` — never because an ambient
        // input was absent (a second, env-sourced condition would drop the health step
        // *and* the `/ready` gate silently when it went missing).
        let mut o = opts();
        o.health = None;
        let plan = plan_deploy(&o, &target(), &ctx());
        assert!(!plan.steps.iter().any(|s| s.id == DeployStepId::Health));
        assert!(!plan.steps.iter().any(|s| s.id == DeployStepId::Readiness));
    }

    #[test]
    fn the_health_url_keeps_its_var_reference_inert() {
        // The domain is a declared field like any other, so a reference in it stays inert
        // in the plan and is resolved at the IO boundary — the dry-run render shows what
        // the config declared, and the plan a dry run shows is the plan a wetrun executes.
        let mut o = opts();
        o.health = Some(DeployHealth {
            domain: Text::reference("DEPLOY_DOMAIN"),
            path: "/health".to_owned(),
            attempts: std::num::NonZeroU32::new(15).unwrap(),
            interval_ms: 2000,
        });
        let plan = plan_deploy(&o, &target(), &ctx());
        let urls: Vec<&str> = plan
            .steps
            .iter()
            .filter_map(|s| match &s.action {
                DeployAction::Health { url, .. } | DeployAction::Readiness { url, .. } => {
                    Some(url.as_str())
                }
                _ => None,
            })
            .collect();
        assert_eq!(
            urls,
            [
                format!("https://{}/health", marker("DEPLOY_DOMAIN")),
                format!("https://{}/ready", marker("DEPLOY_DOMAIN")),
            ]
        );
    }

    #[test]
    fn readiness_step_emitted_alongside_health() {
        // The default health step targets liveness (`/health`); readiness is the
        // distinct `/ready` schema-drift gate.
        let plan = plan_deploy(&opts(), &target(), &ctx());
        let readiness = plan.steps.iter().find_map(|s| match &s.action {
            DeployAction::Readiness { url, .. } => Some(url.clone()),
            _ => None,
        });
        assert_eq!(readiness.as_deref(), Some("https://example.com/ready"));
    }

    #[test]
    fn readiness_step_skipped_when_health_already_targets_ready() {
        // A consumer that folded readiness into liveness (`health.path = '/ready'`)
        // already polls the drift gate; the auto-emitted readiness step would be a
        // redundant second poll, so it's skipped — the health step IS the gate.
        let mut o = opts();
        o.health = Some(DeployHealth {
            domain: Text::literal("example.com"),
            path: "/ready".to_owned(),
            attempts: std::num::NonZeroU32::new(15).unwrap(),
            interval_ms: 2000,
        });
        let plan = plan_deploy(&o, &target(), &ctx());
        assert!(!plan.steps.iter().any(|s| s.id == DeployStepId::Readiness));
        assert!(plan.steps.iter().any(|s| s.id == DeployStepId::Health));
    }

    #[test]
    fn extract_swap_script_is_idempotent_and_complete() {
        let plan = plan_deploy(&opts(), &target(), &ctx());
        let script = plan
            .steps
            .iter()
            .find_map(|s| match &s.action {
                DeployAction::ExtractSwap(swap) => Some(plan.swap_script(swap)),
                _ => None,
            })
            .unwrap();
        // shared-file guard + symlink, prepare, atomic swap, deploy_info, prune.
        assert!(script.contains("shared/.env.production"));
        assert!(script.contains("deno cache src/lib/server/server.ts"));
        assert!(script.contains("ln -sfn -- '/root/app/releases/abc1234' '/root/app/current.new'"));
        assert!(script.contains("mv -Tf -- '/root/app/current.new' '/root/app/current'"));
        assert!(script.contains("\"previous_version\":%s"));
        // prune keeps this release and the one it replaced, and caps the total at
        // releases (5); a first deploy names no previous release.
        assert!(script.contains(PRUNE_RELEASES));
        assert!(script.contains(
            "\nzap_e=$(zap_prune '/root/app/releases' '/root/app/current' 5 'abc1234' 'def5678' 2>&1) || "
        ));
        let first = plan_deploy(
            &opts(),
            &target(),
            &DeployContext {
                previous_version: None,
                ..ctx()
            },
        );
        let DeployAction::ExtractSwap(swap) = &first.steps[3].action else {
            panic!("{first:?}");
        };
        assert!(
            first.swap_script(swap).contains(
                "zap_prune '/root/app/releases' '/root/app/current' 5 'abc1234' '' 2>&1)"
            )
        );
        assert!(script.ends_with("\nprintf 'Deployed version %s\\n' 'abc1234'"));
        // No listing is word-split into `rm`.
        for gone in ["ls -t", "xargs", "grep -vxF"] {
            assert!(!script.contains(gone), "{gone}: {script}");
        }
        // no jq dependency.
        assert!(!script.contains("jq"));
    }

    /// What the script was handed arrives as words, never as shell: a shared file's
    /// name, a version, an operator's name and the version read off the target are each
    /// single-quoted wherever they stand, and `deploy_info.json` holds each as a JSON
    /// string.
    #[test]
    fn the_script_quotes_every_value_and_writes_valid_json() {
        let odd = "o'dd \"q\" $(zapodd) `zapodd` \\n %s\tzapodd";
        let spec = DeploySpec {
            shared: vec![odd.to_owned()],
            prepare: Vec::new(),
            ..opts()
        };
        let context = DeployContext {
            version: odd.to_owned(),
            deployed_by: odd.to_owned(),
            previous_version: Some(odd.to_owned()),
            ..ctx()
        };
        let plan = plan_deploy(&spec, &target(), &context);
        let script = plan
            .steps
            .iter()
            .find_map(|s| match &s.action {
                DeployAction::ExtractSwap(swap) => Some(plan.swap_script(swap)),
                _ => None,
            })
            .unwrap();
        let quoted = crate::shell::single_quote;
        let json = serde_json::to_string(odd).unwrap();
        assert_eq!(json, r#""o'dd \"q\" $(zapodd) `zapodd` \\n %s\tzapodd""#);
        // The values appear only inside single-quoted words: with every such word taken
        // out, none of the value is left.
        let mut rest = script.clone();
        for word in [
            quoted(&format!("/root/app/shared/{odd}")),
            quoted(&format!(
                "{odd} not found under shared/ — run `zap apply` first"
            )),
            quoted(&format!(
                "the release ships a directory at {odd}, where a shared file is linked"
            )),
            quoted(&format!("/root/app/releases/.zap-old-{odd}")),
            quoted(&format!(
                "releases/.zap-old-{odd} was not removed; the next deploy removes it"
            )),
            quoted(&format!("/root/app/releases/{odd}")),
            quoted(&format!("/root/app/.zap-deploy-deploy-{odd}.tar.gz")),
            quoted(&json),
            quoted(odd),
        ] {
            assert!(rest.contains(&word), "{word}: {script}");
            rest = rest.replace(&word, "");
        }
        assert!(!rest.contains("zapodd"), "{rest}");
        // The info line: three JSON values and the target's date.
        let info = script
            .lines()
            .find(|line| line.contains("deploy_info.json"))
            .unwrap();
        assert_eq!(
            info,
            format!(
                "zap_e=$(printf '{{\"version\":%s,\"deployed_by\":%s,\"previous_version\":%s,\
                 \"deployed_at\":\"%s\"}}\\n' {0} {0} {0} \
                 \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\" 2>&1 > '/root/app/deploy_info.json') || \
                 zap_after 'deploy_info.json was not written' \"$zap_e\"",
                quoted(&json)
            )
        );
        // No previous release is JSON's `null`.
        let first = plan_deploy(
            &opts(),
            &target(),
            &DeployContext {
                previous_version: None,
                ..ctx()
            },
        );
        let DeployAction::ExtractSwap(swap) = &first.steps[3].action else {
            panic!("{first:?}");
        };
        assert!(
            first
                .swap_script(swap)
                .contains(r#"'"abc1234"' '"op@laptop"' 'null' "#)
        );
    }

    /// The archive is made at a path the plan doesn't hold — the command names the
    /// variable the executor sets — and uploaded into the app path under a name carrying
    /// the connecting user and the version. No step names a shared directory.
    #[test]
    fn the_archive_is_staged_in_no_shared_directory() {
        let plan = plan_deploy(&opts(), &target(), &ctx());
        let tarball = plan.steps.iter().find_map(|s| match &s.action {
            DeployAction::Tarball { command } => Some(command.as_str()),
            _ => None,
        });
        assert_eq!(
            tarball,
            Some(r#"tar -czf "$ZAP_DEPLOY_ARCHIVE" -- 'build/' 'package.json'"#)
        );
        assert_eq!(ARCHIVE_ENV, "ZAP_DEPLOY_ARCHIVE");
        let remote = plan.steps.iter().find_map(|s| match &s.action {
            DeployAction::Upload { remote } => Some(remote.as_str()),
            _ => None,
        });
        assert_eq!(remote, Some("/root/app/.zap-deploy-deploy-abc1234.tar.gz"));
        assert!(!serde_json::to_string(&plan).unwrap().contains("/tmp"));

        // Another connecting user is another archive name, so another plan.
        let as_root = plan_deploy(
            &opts(),
            &target(),
            &DeployContext {
                target_user: "root".to_owned(),
                ..ctx()
            },
        );
        assert!(
            serde_json::to_string(&as_root)
                .unwrap()
                .contains("/root/app/.zap-deploy-root-abc1234.tar.gz")
        );
    }

    /// Under the lock, `current` must still be what the plan read: the release it
    /// named, or — when it named none — nothing at all, so a directory or file that
    /// appeared there stops the deploy before anything is staged, as a link does.
    #[test]
    fn the_locked_check_refuses_whatever_isnt_the_current_the_plan_read() {
        use std::os::unix::fs::symlink;

        let dir = std::env::temp_dir().join(format!("zap-current-check-{}", std::process::id()));
        let check = |previous: Option<&str>| {
            let plan = plan_deploy(
                &DeploySpec {
                    path: dir.display().to_string(),
                    ..opts()
                },
                &target(),
                &DeployContext {
                    previous_version: previous.map(str::to_owned),
                    ..ctx()
                },
            );
            let script = plan
                .steps
                .iter()
                .find_map(|s| match &s.action {
                    DeployAction::ExtractSwap(swap) => Some(plan.swap_script(swap)),
                    _ => None,
                })
                .unwrap();
            let lines: Vec<&str> = script.lines().collect();
            let from = lines
                .iter()
                .position(|l| l.starts_with("zap_cur="))
                .unwrap();
            let to = lines
                .iter()
                .position(|l| l.contains("changed since this deploy was planned"))
                .unwrap();
            let fail = lines.iter().find(|l| l.starts_with("zap_fail()")).unwrap();
            let mut snippet = format!("{fail}\n");
            for line in &lines[from..=to] {
                snippet.push_str(line);
                snippet.push('\n');
            }
            let out = std::process::Command::new("sh")
                .args(["-c", &snippet])
                .output()
                .unwrap();
            (out.status.success(), String::from_utf8(out.stdout).unwrap())
        };
        let current = dir.join("current");
        let reset = || {
            let _ = std::fs::remove_file(&current);
            let _ = std::fs::remove_dir(&current);
        };
        std::fs::create_dir_all(dir.join("releases/def5678")).unwrap();

        // No live release planned: only nothing at `current` passes.
        assert!(check(None).0);
        for there in ["a directory", "a file", "a link", "a dangling link"] {
            match there {
                "a directory" => std::fs::create_dir(&current).unwrap(),
                "a file" => std::fs::write(&current, "").unwrap(),
                "a link" => symlink("releases/def5678", &current).unwrap(),
                _ => symlink("nowhere", &current).unwrap(),
            }
            let (passed, out) = check(None);
            reset();
            assert!(!passed, "{there}: {out}");
            assert!(
                out.contains("changed since this deploy was planned"),
                "{out}"
            );
        }

        // A live release planned: only a link to it passes.
        symlink("releases/def5678", &current).unwrap();
        assert!(check(Some("def5678")).0);
        reset();
        std::fs::create_dir(&current).unwrap();
        let (passed, out) = check(Some("def5678"));
        reset();
        assert!(!passed && out.contains("it is not a link now"), "{out}");
        let (passed, out) = check(Some("def5678"));
        assert!(!passed && out.contains("it is not a link now"), "{out}");
        symlink("releases/other", &current).unwrap();
        let (passed, out) = check(Some("def5678"));
        reset();
        assert!(
            !passed && out.contains("it names releases/other now"),
            "{out}"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The script removes the archive on every exit — the trap is set before anything
    /// that can fail — reads the digest and detaches its stdin before the app's own
    /// commands, and extracts only after the file it holds open passed every check:
    /// through that descriptor, never by the name again, and without the archive's
    /// owners or set-id bits.
    #[test]
    fn the_script_extracts_only_the_file_it_checked() {
        let plan = plan_deploy(&opts(), &target(), &ctx());
        let script = plan
            .steps
            .iter()
            .find_map(|s| match &s.action {
                DeployAction::ExtractSwap(swap) => Some(plan.swap_script(swap)),
                _ => None,
            })
            .unwrap();
        let lines: Vec<&str> = script.lines().collect();
        let at = |needle: &str| {
            lines
                .iter()
                .position(|line| line.contains(needle))
                .unwrap_or_else(|| panic!("{needle}: {script}"))
        };
        assert_eq!(
            &lines[..11],
            [
                "set -e",
                "zap_archive='/root/app/.zap-deploy-deploy-abc1234.tar.gz'",
                "zap_releases='/root/app/releases'",
                "zap_rel='/root/app/releases/abc1234'",
                "zap_stage='/root/app/releases/.zap-stage'",
                "zap_old='/root/app/releases/.zap-old-abc1234'",
                "zap_moved=",
                "zap_locked=",
                "zap_fail() { printf \"ERROR: %s\\n\" \"$1\" >&2; printf \"zap error: %s\\n\" \"$1\"; exit 1; }",
                "zap_warn() { printf \"zap warning: %s\\n\" \"$1\"; }",
                concat!(
                    "trap 'rm -f -- \"$zap_archive\" || :; if [ -n \"$zap_locked\" ]; then ",
                    "if [ -e \"$zap_rel\" ] || [ -L \"$zap_rel\" ]; then rm -rf -- \"$zap_old\" || :; ",
                    "elif [ -n \"$zap_moved\" ]; then mv -T -- \"$zap_old\" \"$zap_rel\" || :; fi; ",
                    "rm -rf -- \"$zap_stage\" || :; fi' EXIT",
                ),
            ]
        );
        // The warning mark is the one the executor lifts.
        assert!(
            lines[9].starts_with(&format!("zap_warn() {{ printf \"{SCRIPT_WARNING_PREFIX}%s")),
            "{script}"
        );
        // The lock is taken once the digest is in and the app is the working directory,
        // and held before anything in `releases/` is touched: the recovery, the archive's
        // checks, the staging directory.
        let locked = at("flock -n 9 || zap_fail \"another deploy is running for this app\"");
        assert_eq!(lines[locked + 1], "zap_locked=1", "{script}");
        assert!(at("cd -- '/root/app'") < at("command exec 9<"), "{script}");
        assert!(
            at("command -v flock") < locked && at("command exec 9<") < locked,
            "{script}"
        );
        assert!(at("exec </dev/null") < locked, "{script}");
        // The live release the plan read is checked again under the lock, after the
        // recovery and before the archive is looked at.
        let still_live =
            at("[ -n \"$zap_cur\" ] && [ \"${zap_was##*/}\" = 'def5678' ] || zap_fail");
        assert!(at("done") < still_live, "{script}");
        assert!(still_live < at("[ -f '/root/app/shared/"), "{script}");
        for after in [
            "mkdir -p -- '/root/app/releases'",
            "for zap_e in",
            "zap_cur=$(readlink -- '/root/app/current' 2>/dev/null) || zap_cur=",
            "[ -f '/root/app/shared/.env.production' ]",
            "exec 3<\"$zap_archive\"",
            "mkdir -- \"$zap_stage\"",
        ] {
            assert!(locked < at(after), "{after}: {script}");
        }
        let extract = at("tar -x");
        assert_eq!(
            lines[extract],
            "tar -xzf $zap_fd --no-same-owner --no-same-permissions -C \"$zap_stage\""
        );
        for check in [
            "IFS= read -r zap_want",
            "exec </dev/null",
            "exec 3<\"$zap_archive\"",
            "zap_uid=$(id -u) && [ -n \"$zap_uid\" ] && [ -f $zap_fd ] && ",
            "stat -L -c %u $zap_fd)\" = \"$zap_uid\" ]",
            "stat -L -c %a $zap_fd)\" in \"\"|*[2367]|*[2367]?)",
            "zap_got=$(sha512sum <&3)",
            "[ \"${zap_got%% *}\" = \"$zap_want\" ] || zap_fail",
            "mkdir -- \"$zap_stage\"",
        ] {
            assert!(at(check) < extract, "{check}: {script}");
        }
        // The release takes its name only once it is whole: after `prepare`, what held
        // the name moved aside first, and that removed only after the swap.
        let aside = at("then zap_moved=1; mv -T -- \"$zap_rel\" \"$zap_old\"; fi");
        let placed = at("mv -T -- \"$zap_stage\" \"$zap_rel\"");
        let swapped = at("mv -Tf -- '/root/app/current.new' '/root/app/current'");
        let dropped = lines
            .iter()
            .rposition(|line| {
                line.starts_with("zap_e=$(rm -rf -- \"$zap_old\" 2>&1) || zap_after ")
            })
            .expect("what was moved aside is removed");
        // The swap is announced on the line after it, before any housekeeping.
        assert_eq!(
            lines[swapped + 1],
            format!("echo '{SWAPPED_LINE}'"),
            "{script}"
        );
        assert!(at("deno cache") < aside, "{script}");
        assert!(
            aside < placed && placed < swapped && swapped < dropped,
            "{script}"
        );
        // `prepare` runs in the staged release, each command in a shell of its own with
        // the lock's descriptor closed and its stdout on the script's stderr.
        let prepare = at("deno cache");
        assert_eq!(at("cd -- \"$zap_stage\"") + 1, prepare, "{script}");
        assert_eq!(
            lines[prepare], "sh -ec 'deno cache src/lib/server/server.ts' 9>&- >&2",
            "{script}"
        );
        // The stdin is detached before any command of the app's can read it, and the
        // archive is gone before they run.
        assert!(at("exec </dev/null") < at("cd -- '/root/app'"), "{script}");
        let removed = lines
            .iter()
            .position(|line| *line == "rm -f -- \"$zap_archive\"")
            .expect("the archive is removed once it is extracted");
        assert!(extract < removed && removed < prepare, "{script}");
        assert!(at("exec 3<&-") < prepare, "{script}");
        // The name is opened once; nothing else reads it.
        assert_eq!(script.matches("<\"$zap_archive\"").count(), 1, "{script}");
        assert!(!script.contains("tar -xzf '"), "{script}");
    }

    /// The whole script for one plan, pinned: what a dry run prints and the plan's hash
    /// covers, so any change to it is a reviewed one. The archive's checks and the prune
    /// are constants with tests of their own, and stand in by name.
    #[test]
    fn the_extract_swap_script_golden() {
        let plan = plan_deploy(&opts(), &target(), &ctx());
        let script = plan
            .steps
            .iter()
            .find_map(|s| match &s.action {
                DeployAction::ExtractSwap(swap) => Some(plan.swap_script(swap)),
                _ => None,
            })
            .unwrap();
        assert_eq!(deploy_lock_path("/root/app"), "/root/app/.zap-deploy.lock");
        let golden = [
            GOLDEN_HEAD,
            ARCHIVE_CHECK,
            GOLDEN_MIDDLE,
            PRUNE_RELEASES,
            GOLDEN_TAIL,
        ]
        .concat();
        assert_eq!(script, golden);
    }

    const GOLDEN_HEAD: &str = r#"set -e
zap_archive='/root/app/.zap-deploy-deploy-abc1234.tar.gz'
zap_releases='/root/app/releases'
zap_rel='/root/app/releases/abc1234'
zap_stage='/root/app/releases/.zap-stage'
zap_old='/root/app/releases/.zap-old-abc1234'
zap_moved=
zap_locked=
zap_fail() { printf "ERROR: %s\n" "$1" >&2; printf "zap error: %s\n" "$1"; exit 1; }
zap_warn() { printf "zap warning: %s\n" "$1"; }
trap 'rm -f -- "$zap_archive" || :; if [ -n "$zap_locked" ]; then if [ -e "$zap_rel" ] || [ -L "$zap_rel" ]; then rm -rf -- "$zap_old" || :; elif [ -n "$zap_moved" ]; then mv -T -- "$zap_old" "$zap_rel" || :; fi; rm -rf -- "$zap_stage" || :; fi' EXIT
trap 'exit 1' HUP INT TERM
IFS= read -r zap_want && [ ${#zap_want} -eq 128 ] || zap_fail "the digest of the release archive did not arrive"
exec </dev/null
cd -- '/root/app'
command -v flock >/dev/null || zap_fail "no flock on this machine to hold the deploy lock with"
zap_umask=$(umask)
umask o-rwx
[ -e '/root/app/.zap-deploy.lock' ] || command : >>'/root/app/.zap-deploy.lock' || zap_fail 'cannot create the deploy lock /root/app/.zap-deploy.lock'
command exec 9<'/root/app/.zap-deploy.lock' || zap_fail 'cannot open the deploy lock /root/app/.zap-deploy.lock'
umask "$zap_umask"
flock -n 9 || zap_fail "another deploy is running for this app"
zap_locked=1
mkdir -p -- '/root/app/releases'
for zap_e in "$zap_releases"/.zap-stage "$zap_releases"/.zap-old-*; do
  [ -e "$zap_e" ] || [ -L "$zap_e" ] || continue
  zap_n=${zap_e##*/}
  case $zap_n in
    .zap-stage)
      rm -rf -- "$zap_e"
      zap_warn "removed releases/$zap_n, the staging directory of a deploy that did not finish";;
    .zap-old-*)
      zap_v=${zap_n#.zap-old-}
      if [ -e "$zap_releases/$zap_v" ] || [ -L "$zap_releases/$zap_v" ]; then
        rm -rf -- "$zap_e"
        zap_warn "removed releases/$zap_n, the release a deploy that did not finish had replaced"
      else
        mv -T -- "$zap_e" "$zap_releases/$zap_v"
        zap_warn "restored releases/$zap_v, which a deploy that did not finish had moved aside"
      fi;;
  esac
done
zap_cur=$(readlink -- '/root/app/current' 2>/dev/null) || zap_cur=
zap_now="it names $zap_cur now"; [ -n "$zap_cur" ] || zap_now="it is not a link now"
zap_was=$zap_cur
while :; do case $zap_was in */) zap_was=${zap_was%/};; *) break;; esac; done
[ -n "$zap_cur" ] && [ "${zap_was##*/}" = 'def5678' ] || zap_fail "\`current\` changed since this deploy was planned: $zap_now (another deploy ran, or something else is there now); run zap deploy again"
[ -f '/root/app/shared/.env.production' ] || zap_fail '.env.production not found under shared/ — run `zap apply` first'
"#;

    const GOLDEN_MIDDLE: &str = r#"mkdir -- "$zap_stage"
tar -xzf $zap_fd --no-same-owner --no-same-permissions -C "$zap_stage"
exec 3<&-
rm -f -- "$zap_archive"
if [ -d "$zap_stage"/'.env.production' ] && [ ! -L "$zap_stage"/'.env.production' ]; then zap_fail 'the release ships a directory at .env.production, where a shared file is linked'; fi
ln -sfn -- '/root/app/shared/.env.production' "$zap_stage"/'.env.production'
cd -- "$zap_stage"
sh -ec 'deno cache src/lib/server/server.ts' 9>&- >&2
cd -- '/root/app'
if [ -e "$zap_rel" ] || [ -L "$zap_rel" ]; then zap_moved=1; mv -T -- "$zap_rel" "$zap_old"; fi
mv -T -- "$zap_stage" "$zap_rel"
ln -sfn -- '/root/app/releases/abc1234' '/root/app/current.new'
mv -Tf -- '/root/app/current.new' '/root/app/current'
echo 'zap: current swapped'
zap_after() { zap_warn "after the swap, $1"; printf '%s\n' "$2" | while IFS= read -r zap_l; do [ -z "$zap_l" ] || zap_warn "$zap_l"; done; }
zap_e=$(rm -rf -- "$zap_old" 2>&1) || zap_after 'releases/.zap-old-abc1234 was not removed; the next deploy removes it' "$zap_e"
zap_e=$(printf '{"version":%s,"deployed_by":%s,"previous_version":%s,"deployed_at":"%s"}\n' '"abc1234"' '"op@laptop"' '"def5678"' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" 2>&1 > '/root/app/deploy_info.json') || zap_after 'deploy_info.json was not written' "$zap_e"
"#;

    const GOLDEN_TAIL: &str = r#"zap_e=$(zap_prune '/root/app/releases' '/root/app/current' 5 'abc1234' 'def5678' 2>&1) || zap_after 'the old releases were not pruned' "$zap_e"
printf 'Deployed version %s\n' 'abc1234'"#;

    /// The swap's script is built from the values the plan shows beside it and from
    /// nothing else: each value the preview lifts out of it — the operator, the
    /// retention, each shared file, each `prepare` command, the release it requires
    /// `current` to name — and the version, app path and connecting user, stands in the
    /// script as one quoted word, and a change to any of them is a change to the script;
    /// a change to anything else the plan holds is none.
    #[test]
    fn the_swap_script_is_built_from_the_values_the_plan_shows() {
        use crate::shell::single_quote;

        type Edit = (&'static str, fn(&mut DeployPlan, &mut ReleaseSwap));

        let plan = plan_deploy(&opts(), &target(), &ctx());
        let DeployAction::ExtractSwap(swap) = &plan.steps[3].action else {
            panic!("{plan:?}");
        };
        let script = plan.swap_script(swap);
        assert_eq!(swap.app, "/root/app");
        assert_eq!(swap.keep, 5);
        assert_eq!(swap.shared, [".env.production"]);
        assert_eq!(swap.prepare, ["deno cache src/lib/server/server.ts"]);
        assert_eq!(plan.previous.as_deref(), Some("def5678"));
        assert_eq!(plan.deployed_by, "op@laptop");
        assert_eq!(plan.user.as_deref(), Some("deploy"));
        for shown in [
            format!(
                "{} {} {} ",
                single_quote("\"abc1234\""),
                single_quote("\"op@laptop\""),
                single_quote("\"def5678\"")
            ),
            format!(
                "zap_prune {} {} 5 {} {} 2>&1",
                single_quote("/root/app/releases"),
                single_quote("/root/app/current"),
                single_quote("abc1234"),
                single_quote("def5678")
            ),
            format!("[ \"${{zap_was##*/}}\" = {} ]", single_quote("def5678")),
            format!(
                "[ -f {} ]",
                single_quote("/root/app/shared/.env.production")
            ),
            format!(
                "sh -ec {} 9>&- >&2",
                single_quote("deno cache src/lib/server/server.ts")
            ),
            format!(
                "zap_archive={}",
                single_quote("/root/app/.zap-deploy-deploy-abc1234.tar.gz")
            ),
        ] {
            assert!(script.contains(&shown), "{shown}\n{script}");
        }

        let moving: [Edit; 9] = [
            ("version", |plan, _| plan.version.push('0')),
            ("previous", |plan, _| {
                plan.previous = Some("0123abcd".to_owned());
            }),
            ("no previous", |plan, _| plan.previous = None),
            ("deployed_by", |plan, _| plan.deployed_by.push('x')),
            ("user", |plan, _| plan.user = None),
            ("app", |_, swap| swap.app.push('x')),
            ("keep", |_, swap| swap.keep += 1),
            ("shared", |_, swap| swap.shared.push("other".to_owned())),
            ("prepare", |_, swap| swap.prepare.clear()),
        ];
        let still: [Edit; 7] = [
            ("subject", |plan, _| plan.subject.push('x')),
            ("host", |plan, _| plan.host.push('x')),
            ("target", |plan, _| plan.target = Target::default()),
            ("dirty", |plan, _| plan.dirty = !plan.dirty),
            ("preflight", |plan, _| {
                plan.preflight = DriftPreflight::Skipped;
            }),
            ("warnings", |plan, _| plan.warnings.push("w".to_owned())),
            ("other steps", |plan, _| plan.steps.truncate(4)),
        ];
        for (moves, edits) in [(true, &moving[..]), (false, &still[..])] {
            for (name, edit) in edits {
                let (mut edited, mut swap) = (plan.clone(), swap.clone());
                edit(&mut edited, &mut swap);
                assert_eq!(edited.swap_script(&swap) != script, moves, "{name}");
            }
        }
    }

    /// The archive the swap's script extracts is the one the upload step installs, for a
    /// connecting user by value, for none, and for one the render's masking reached: the
    /// upload holds the path it installs at and the swap the app it works in, and both
    /// name the archive by the one rule (`archive_path`).
    #[test]
    fn the_swap_extracts_the_archive_the_upload_installs() {
        use crate::shell::single_quote;

        let archives = |plan: &DeployPlan| {
            let remote = plan
                .steps
                .iter()
                .find_map(|s| match &s.action {
                    DeployAction::Upload { remote } => Some(remote.clone()),
                    _ => None,
                })
                .unwrap();
            let DeployAction::ExtractSwap(swap) = &plan.steps[3].action else {
                panic!("{plan:?}");
            };
            let script = plan.swap_script(swap);
            let named = script
                .lines()
                .find_map(|line| line.strip_prefix("zap_archive="))
                .unwrap()
                .to_owned();
            (single_quote(&remote), named, remote)
        };
        let user = plan_deploy(
            &opts(),
            &target(),
            &DeployContext {
                target_user: "opsuser".to_owned(),
                ..ctx()
            },
        );
        let none = plan_deploy(
            &opts(),
            &target(),
            &DeployContext {
                target_user: String::new(),
                ..ctx()
            },
        );
        let masked = user.map_text(|text| text.replace("opsuser", "[MASKED:ZAP_T_USER]"));
        for (plan, archive) in [
            (&user, "/root/app/.zap-deploy-opsuser-abc1234.tar.gz"),
            (&none, "/root/app/.zap-deploy--abc1234.tar.gz"),
            (
                &masked,
                "/root/app/.zap-deploy-[MASKED:ZAP_T_USER]-abc1234.tar.gz",
            ),
        ] {
            let (uploaded, extracted, remote) = archives(plan);
            assert_eq!(remote, archive);
            assert_eq!(extracted, uploaded, "{archive}");
        }
        assert_eq!(none.user, None);
    }

    /// A `current` link names its release by its last segment, trailing slashes
    /// dropped, and only when that segment is a release's name: a `.` segment, a path
    /// below a release, or nothing names none.
    #[test]
    fn a_link_names_a_release_only_by_a_release_name() {
        use super::{is_release_name, release_of_link};

        for name in ["abcd", "abc1234", &"f".repeat(64), "abc1234-dirty-0123abcd"] {
            assert!(is_release_name(name), "{name}");
        }
        for name in [
            "",
            "abc",
            &"f".repeat(65),
            "ABC1234",
            "v1",
            ".",
            "..",
            "abc1234-dirty-",
            "abc1234-dirty-0123abc",
            "abc1234-dirty-0123abcde",
            "abc1234-dirty-0123ABCD",
            "abc1234-dirty-0123abcd-dirty-0123abcd",
            "-dirty-0123abcd",
            "abc 1234",
        ] {
            assert!(!is_release_name(name), "{name:?}");
        }
        for (link, release) in [
            ("/srv/app/releases/abc1234", Some("abc1234")),
            ("releases/abc1234", Some("abc1234")),
            ("abc1234", Some("abc1234")),
            ("releases/abc1234/", Some("abc1234")),
            ("releases/abc1234//", Some("abc1234")),
            ("releases/abc1234/.", None),
            ("releases/abc1234/..", None),
            ("releases/abc1234/sub", None),
            ("/", None),
            ("", None),
            ("releases/v1", None),
        ] {
            assert_eq!(release_of_link(link), release, "{link:?}");
        }
    }

    #[test]
    fn rollback_swap_command_re_points_only_its_own_release_under_the_lock() {
        let cmd = rollback_swap_command("/root/app", "abc1234", "def5678");
        assert_eq!(
            cmd,
            "command -v flock >/dev/null && umask o-rwx && \
             { [ -e '/root/app/.zap-deploy.lock' ] || command : >>'/root/app/.zap-deploy.lock'; } \
             && exec 9<'/root/app/.zap-deploy.lock' && if ! flock -n 9; then echo busy; elif [ ! -L '/root/app/current' ]; then echo absent; \
             elif [ \"$(readlink -- '/root/app/current')\" != \
             '/root/app/releases/abc1234' ]; then echo replaced; \
             elif [ ! -d '/root/app/releases/def5678' ]; then echo gone; else ln -sfn -- \
             '/root/app/releases/def5678' '/root/app/current.new' && mv -Tf -- \
             '/root/app/current.new' '/root/app/current' && echo rolled_back; fi"
        );
        // Every value is one single-quoted word.
        let odd = rollback_swap_command("/srv/it's", "a b", "$(c)");
        assert!(odd.contains("'/srv/it'\\''s/releases/a b'"), "{odd}");
        assert!(odd.contains("'/srv/it'\\''s/releases/$(c)'"), "{odd}");
    }

    #[test]
    fn a_rollback_outcome_is_read_only_from_its_own_token() {
        assert_eq!(
            RollbackSwap::parse("rolled_back\n"),
            Ok(RollbackSwap::RolledBack)
        );
        assert_eq!(RollbackSwap::parse("replaced"), Ok(RollbackSwap::Replaced));
        assert_eq!(RollbackSwap::parse("busy"), Ok(RollbackSwap::Busy));
        assert_eq!(RollbackSwap::parse("absent"), Ok(RollbackSwap::Absent));
        assert_eq!(RollbackSwap::parse("gone"), Ok(RollbackSwap::Gone));
        for unknown in ["", "rolled_back busy", "ok"] {
            assert!(RollbackSwap::parse(unknown).is_err(), "{unknown:?}");
        }
    }

    #[test]
    fn restart_uses_daemon_reload_then_systemctl() {
        let plan = plan_deploy(&opts(), &target(), &ctx());
        let restart = plan.steps.iter().find_map(|s| match &s.action {
            DeployAction::Restart { command } => Some(command.clone()),
            _ => None,
        });
        assert_eq!(
            restart.as_deref(),
            Some("sudo systemctl daemon-reload && sudo systemctl restart app")
        );
    }

    #[test]
    fn restart_on_openrc_omits_the_daemon_reload() {
        // OpenRC has no daemon-reload (it re-reads init scripts each call), so its
        // restart step is the bare `rc-service … restart` — never the systemd reload.
        let target = Target {
            service_manager: Some(ServiceManager::Openrc),
            ..Target::default()
        };
        let plan = plan_deploy(&opts(), &target, &ctx());
        let restart = plan.steps.iter().find_map(|s| match &s.action {
            DeployAction::Restart { command } => Some(command.clone()),
            _ => None,
        });
        assert_eq!(restart.as_deref(), Some("sudo rc-service app restart"));
    }

    /// The plan names its machine: the same release for another host, or for another
    /// declared target, is another plan with another hash.
    #[test]
    fn the_plan_is_for_one_target() {
        use crate::config_hash::deploy_plan_hash;

        let hash = |target: &Target, ctx: &DeployContext| {
            deploy_plan_hash(&plan_deploy(&opts(), target, ctx)).unwrap()
        };
        let base = hash(&target(), &ctx());
        assert_eq!(base, hash(&target(), &ctx()));
        let elsewhere = DeployContext {
            target_host: "other.example.com".to_owned(),
            ..ctx()
        };
        assert_ne!(base, hash(&target(), &elsewhere));
        // Same host and same steps: the port is in no command, so only the carried
        // target tells these two apart.
        let other_port: Target =
            serde_json::from_value(serde_json::json!({"host": "h", "port": 2222})).unwrap();
        let default_port: Target =
            serde_json::from_value(serde_json::json!({"host": "h"})).unwrap();
        assert_ne!(hash(&default_port, &ctx()), hash(&other_port, &ctx()));
    }

    /// A skipped build is left out of the plan, not planned and declined: the preview
    /// lists what runs, and the plan hashes apart from the one that builds.
    #[test]
    fn a_skipped_build_is_not_planned() {
        use crate::config_hash::deploy_plan_hash;

        let skipping = DeployContext {
            skip_build: true,
            ..ctx()
        };
        let built = plan_deploy(&opts(), &target(), &ctx());
        let skipped = plan_deploy(&opts(), &target(), &skipping);
        assert_eq!(built.steps[0].id, DeployStepId::Build);
        assert!(skipped.steps.iter().all(|s| s.id != DeployStepId::Build));
        assert_eq!(skipped.steps.len() + 1, built.steps.len());
        assert_ne!(
            deploy_plan_hash(&built).unwrap(),
            deploy_plan_hash(&skipped).unwrap()
        );
    }

    /// A polled URL is carried twice: as declared, which is what the poller resolves,
    /// and with the context's resolved domain, which is what makes one referenced domain
    /// under two environments two plans.
    #[test]
    fn a_health_url_is_labelled_with_the_resolved_domain() {
        use crate::config_hash::deploy_plan_hash;

        let mut o = opts();
        o.health = Some(DeployHealth {
            domain: Text::reference("DEPLOY_DOMAIN"),
            path: "/health".to_owned(),
            attempts: std::num::NonZeroU32::new(15).unwrap(),
            interval_ms: 2000,
        });
        let plan_for = |domain: &str| {
            let ctx = DeployContext {
                health_domain: domain.to_owned(),
                ..ctx()
            };
            plan_deploy(&o, &target(), &ctx)
        };
        let plan = plan_for("a.example.com");
        let labels: Vec<(&str, &str)> = plan
            .steps
            .iter()
            .filter_map(|s| match &s.action {
                DeployAction::Health { url, url_label, .. }
                | DeployAction::Readiness { url, url_label, .. } => {
                    Some((url.as_str(), url_label.as_str()))
                }
                _ => None,
            })
            .collect();
        let health = format!("https://{}/health", marker("DEPLOY_DOMAIN"));
        let ready = format!("https://{}/ready", marker("DEPLOY_DOMAIN"));
        assert_eq!(
            labels,
            [
                (health.as_str(), "https://a.example.com/health"),
                (ready.as_str(), "https://a.example.com/ready"),
            ]
        );
        assert_ne!(
            deploy_plan_hash(&plan).unwrap(),
            deploy_plan_hash(&plan_for("b.example.com")).unwrap()
        );
    }

    /// The tree's state and what the preflight does change no step, so the plan states
    /// each as a fact of its own — and hashes apart on any of them.
    #[test]
    fn the_tree_and_the_preflight_are_facts_of_the_plan() {
        use crate::config_hash::deploy_plan_hash;

        let base = plan_deploy(&opts(), &target(), &ctx());
        let dirty = plan_deploy(
            &opts(),
            &target(),
            &DeployContext {
                dirty: true,
                ..ctx()
            },
        );
        let with_preflight =
            |preflight| plan_deploy(&opts(), &target(), &DeployContext { preflight, ..ctx() });
        let unchecked = with_preflight(DriftPreflight::Skipped);
        let nothing = with_preflight(DriftPreflight::NothingDeclared);
        assert!(!base.dirty && base.preflight == checks());
        assert!(dirty.dirty && unchecked.preflight == DriftPreflight::Skipped);
        // What the preflight checks is a fact too: another count, or another digest.
        let more = with_preflight(DriftPreflight::Checks {
            resources: 2,
            digest: "d1".to_owned(),
        });
        let edited = with_preflight(DriftPreflight::Checks {
            resources: 1,
            digest: "d2".to_owned(),
        });
        let plans = [&base, &dirty, &unchecked, &nothing, &more, &edited];
        let hashes: Vec<String> = plans
            .iter()
            .map(|plan| deploy_plan_hash(plan).unwrap())
            .collect();
        for (i, plan) in plans.iter().enumerate() {
            assert_eq!(base.steps, plan.steps);
            for j in 0..i {
                assert_ne!(hashes[i], hashes[j], "{i} {j}");
            }
        }
    }

    /// The deploy plan's address, pinned: a change to what the plan holds or to how it
    /// hashes moves this value. Under
    /// [`HashDomain`](crate::config_hash::HashDomain)'s rule a move the hashed bytes
    /// show needs no bump of
    /// [`DEPLOY_PLAN_HASH_VERSION`](crate::config_hash::DEPLOY_PLAN_HASH_VERSION).
    #[test]
    fn the_deploy_plan_address_is_byte_stable() {
        use crate::config_hash::deploy_plan_hash;

        assert_eq!(
            deploy_plan_hash(&plan_deploy(&opts(), &target(), &ctx())).unwrap(),
            "560908e46c1161d854dbf12b3c3dbd320efefbd82bc517d956034b8d43757239"
        );
    }

    /// A reviewed deploy plan binds the put its upload runs, the script its swap runs,
    /// and the rollback's swap: the plan holds the text of none, and its address moves
    /// with each.
    #[test]
    fn the_deploy_plan_address_moves_with_the_scripts_it_names() {
        use crate::config_hash::{deploy_plan_hash, deploy_plan_hash_with};
        use crate::put::FILE_PUT;

        let plan = plan_deploy(&opts(), &target(), &ctx());
        assert!(
            plan.steps
                .iter()
                .any(|step| matches!(step.action, DeployAction::Upload { .. }))
        );
        let held = serde_json::to_string(&plan).unwrap();
        assert!(!held.contains(FILE_PUT));
        assert!(!held.contains(SWAPPED_LINE), "{held}");
        let address = deploy_plan_hash(&plan).unwrap();
        let rollback = || rollback_swap_command("", "", "");
        assert_eq!(
            address,
            deploy_plan_hash_with(&plan, upload_put_command, DeployPlan::swap_script, rollback)
                .unwrap()
        );
        assert!(upload_put_command("/x").contains(FILE_PUT));
        let moved = deploy_plan_hash_with(
            &plan,
            |remote| upload_put_command(remote).replace(FILE_PUT, "edited"),
            DeployPlan::swap_script,
            rollback,
        )
        .unwrap();
        assert_ne!(moved, address, "the upload's put");
        let moved = deploy_plan_hash_with(
            &plan,
            upload_put_command,
            |plan, swap| plan.swap_script(swap).replace("flock -n 9", "flock -n 8"),
            rollback,
        )
        .unwrap();
        assert_ne!(moved, address, "the swap's script");
        assert!(rollback().contains("flock -n 9"));
        let moved =
            deploy_plan_hash_with(&plan, upload_put_command, DeployPlan::swap_script, || {
                rollback().replace("flock -n 9", "flock -n 8")
            })
            .unwrap();
        assert_ne!(moved, address, "the rollback's swap");
    }

    /// The preflight's digest names the declared resources: adding, removing, renaming,
    /// or editing one moves it, as does a lock pin; the order they are declared in and a
    /// fetch credential don't. References stay as written, so it is the same digest in
    /// every environment.
    #[test]
    fn the_preflight_digest_names_the_declared_resources() {
        use crate::lock::{LockEntry, ZapLock};
        use crate::scalar::ContentHash;
        use crate::schema::{Resource, ResourceId};

        let res = |json: serde_json::Value| -> Resource { serde_json::from_value(json).unwrap() };
        let dir = |id: &str, path: Text| {
            res(serde_json::json!({"id": id, "type": "directory", "path": path}))
        };
        let under =
            |root: &'static str, name: &'static str| Text::of_pieces([Lit(root), Ref(name)]);
        let remote = |token: &str| {
            res(serde_json::json!({
                "id": "blob", "type": "file", "path": "/opt/blob",
                "content": {"type": "remote", "url": "https://x/y", "extract": {"type": "none"},
                            "auth": {"scheme": "bearer", "token": Text::reference(token)}},
            }))
        };
        let digest = |resources: &[Resource], lock: Option<&ZapLock>| match DriftPreflight::checks(
            resources, lock,
        )
        .unwrap()
        {
            DriftPreflight::Checks {
                resources: count,
                digest,
            } => {
                assert_eq!(count, resources.len());
                digest
            }
            other => panic!("{other:?}"),
        };
        let two = [
            dir("data", under("/srv/", "APP_DIR")),
            dir("logs", under("/var/log/", "API_KEY")),
        ];
        let base = digest(&two, None);
        assert_eq!(base.len(), 64);
        assert_eq!(base, digest(&two, None));
        // Declaration order is no part of what is checked.
        assert_eq!(base, digest(&[two[1].clone(), two[0].clone()], None));

        assert_ne!(base, digest(&two[..1], None), "one removed");
        assert_ne!(
            base,
            digest(
                &[two[0].clone(), dir("logs", Text::literal("/var/log/other"))],
                None
            ),
            "one edited"
        );
        assert_ne!(
            base,
            digest(
                &[
                    two[0].clone(),
                    dir("renamed", under("/var/log/", "API_KEY"))
                ],
                None
            ),
            "one renamed"
        );
        assert_ne!(
            base,
            digest(
                &[dir("data", under("/srv/", "OTHER_DIR")), two[1].clone()],
                None
            ),
            "another reference"
        );

        // A fetch credential is no declared state; the pin detection compares against is.
        let tracked = [remote("A_TOKEN")];
        let unpinned = digest(&tracked, None);
        assert_eq!(unpinned, digest(&[remote("B_TOKEN")], None));
        let lock = ZapLock {
            entries: [(
                ResourceId("blob".to_owned()),
                LockEntry::RemoteFile {
                    config_hash: String::new(),
                    blake3: ContentHash::new("a".repeat(64)).unwrap(),
                },
            )]
            .into(),
            ..ZapLock::default()
        };
        assert_ne!(unpinned, digest(&tracked, Some(&lock)), "a lock pin");
    }

    /// The preflight digest's address is byte-stable, on the deploy plan's own version
    /// axis: a change to what it hashes, to the domain it is hashed on, or to
    /// `DEPLOY_PLAN_HASH_VERSION` moves this value.
    #[test]
    fn the_preflight_digest_address_is_byte_stable() {
        use crate::schema::Resource;

        let res = |json: serde_json::Value| -> Resource { serde_json::from_value(json).unwrap() };
        let resources = [
            res(serde_json::json!({"id": "data", "type": "directory",
                "path": Text::of_pieces([Lit("/srv/"), Ref("APP_DIR")])})),
            res(serde_json::json!({"id": "logs", "type": "directory",
                "path": Text::of_pieces([Lit("/var/log/"), Ref("API_KEY")])})),
        ];
        assert_eq!(
            DriftPreflight::checks(&resources, None).unwrap(),
            DriftPreflight::Checks {
                resources: 2,
                digest: "762c64d091ab47ff5897635aee8e1935099e3551bfc8b7c18975c0c5b69f496d"
                    .to_owned(),
            }
        );
    }

    /// The deploy plan records what each reference of the `deploy` block resolves to —
    /// by value, as a secret, or as unset — and its hash covers them. A deploy that
    /// takes no reference records none.
    #[test]
    fn the_deploy_plan_records_what_its_references_resolve_to() {
        use crate::config_hash::deploy_plan_hash;
        use crate::last_run::ReportVar;
        use crate::plan::ReferenceValue;
        use crate::secrecy::SecretReason;

        let mut spec = opts();
        assert!(deploy_references(&spec, &|_| panic!("no reference to resolve")).is_empty());
        spec.health.as_mut().unwrap().domain = Text::of_pieces([
            Ref("SUB"),
            Lit("."),
            Ref("DOMAIN"),
            Lit(":"),
            Ref("PORT_TOKEN"),
        ]);
        let var = |name: &str| match name {
            "SUB" => ReportVar::Value("api".to_owned()),
            "DOMAIN" => ReportVar::Value(String::new()),
            _ => ReportVar::Secret(SecretReason::Declared),
        };
        let references = deploy_references(&spec, &var);
        assert_eq!(
            serde_json::to_value(&references).unwrap(),
            serde_json::json!({
                "DOMAIN": "unset", "PORT_TOKEN": "secret", "SUB": {"value": "api"},
            })
        );
        let with = |references: &BTreeMap<EnvVarName, ReferenceValue>| {
            plan_deploy(
                &spec,
                &target(),
                &DeployContext {
                    references: references.clone(),
                    ..ctx()
                },
            )
        };
        let plan = with(&references);
        assert_eq!(plan.references, references);
        let mut other = references;
        other.insert(
            EnvVarName::new("SUB").unwrap(),
            ReferenceValue::Value("www".to_owned()),
        );
        assert_ne!(
            deploy_plan_hash(&with(&other)).unwrap(),
            deploy_plan_hash(&plan).unwrap()
        );
        // A value is text of the plan, masked for display with the rest of it.
        let masked = plan.map_text(|text| text.replace("api", "[MASKED:X]"));
        assert_eq!(
            masked.references[&EnvVarName::new("SUB").unwrap()],
            ReferenceValue::Value("[MASKED:X]".to_owned())
        );
    }

    /// The preflight's wire form, which the plan's hash covers.
    #[test]
    fn the_preflight_serializes_what_it_checks() {
        assert_eq!(
            serde_json::to_value(checks()).unwrap(),
            serde_json::json!({"checks": {"resources": 1, "digest": "d1"}})
        );
        assert_eq!(
            serde_json::to_value(DriftPreflight::Skipped).unwrap(),
            serde_json::json!("skipped")
        );
        assert_eq!(
            serde_json::to_value(DriftPreflight::NothingDeclared).unwrap(),
            serde_json::json!("nothing_declared")
        );
    }

    /// `map_text` maps the text around a reference and never its name: in the declared
    /// target, and in a polled url, which holds its domain's reference inert.
    #[test]
    fn map_text_keeps_every_reference() {
        let mut o = opts();
        o.health = Some(DeployHealth {
            domain: Text::of_pieces([Lit("KEY."), Ref("API_KEY_DOMAIN")]),
            ..o.health.clone().unwrap()
        });
        let target: Target = serde_json::from_value(serde_json::json!({
            "host": Text::of_pieces([Ref("HOST_KEY"), Lit(".KEY.example")]),
            "user": Text::reference("KEY"), "home": "/home/KEY",
        }))
        .unwrap();
        let plan = plan_deploy(&o, &target, &ctx());
        let mapped = plan.map_text(|text| text.replace("KEY", "[gone]"));
        assert_eq!(
            serde_json::to_value(&mapped.target).unwrap(),
            serde_json::json!({
                "local": false,
                "host": Text::of_pieces([Ref("HOST_KEY"), Lit(".[gone].example")]),
                "user": Text::reference("KEY"), "home": "/home/[gone]",
            })
        );
        let urls: Vec<&str> = mapped
            .steps
            .iter()
            .filter_map(|step| match &step.action {
                DeployAction::Health { url, .. } | DeployAction::Readiness { url, .. } => {
                    Some(url.as_str())
                }
                _ => None,
            })
            .collect();
        assert!(!urls.is_empty());
        for url in urls {
            assert!(
                url.starts_with(&format!("https://[gone].{}/", marker("API_KEY_DOMAIN"))),
                "{url:?}"
            );
        }
    }

    /// `map_text` reaches every string a plan holds and nothing else: mapping each to a
    /// marker leaves no original text in the plan's serialized form, while its shape —
    /// step ids, action tags, the managers, the counts — is unchanged.
    #[test]
    fn map_text_reaches_every_string_and_only_strings() {
        fn strings(value: &serde_json::Value, out: &mut Vec<String>) {
            match value {
                serde_json::Value::String(text) => out.push(text.clone()),
                serde_json::Value::Array(items) => items.iter().for_each(|v| strings(v, out)),
                serde_json::Value::Object(map) => map.values().for_each(|v| strings(v, out)),
                _ => {}
            }
        }

        let mut o = opts();
        o.prepare = vec!["npm ci".to_owned()];
        let target: Target = serde_json::from_value(serde_json::json!({
            "host": "h.example", "user": "deploy", "bootstrap_user": "root", "port": 2222,
            "key_path": "/keys/id", "home": "/home/deploy", "service_manager": "systemd",
        }))
        .unwrap();
        let mut plan = plan_deploy(&o, &target, &ctx());
        plan.warnings.push("a warning".to_owned());
        let mapped = plan.map_text(|_| "X".to_owned());

        let mut found = Vec::new();
        strings(&serde_json::to_value(&mapped).unwrap(), &mut found);
        found.sort();
        found.dedup();
        // What is left besides the marker is the closed-set tokens — step ids, action
        // tags, the service manager — and the preflight's digest.
        assert_eq!(
            found,
            [
                "X",
                "build",
                "d1",
                "extract_swap",
                "health",
                "readiness",
                "restart",
                "systemd",
                "tarball",
                "upload"
            ]
        );
        assert_eq!(mapped.steps.len(), plan.steps.len());
        assert_eq!(plan.map_text(str::to_owned), plan);
    }
}
