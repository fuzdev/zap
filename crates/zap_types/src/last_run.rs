//! The last-run report — what the most recent detection pass read, per declared
//! resource: the on-disk shape, its version gate, and the hash it records per resource.
//!
//! Every detection pass (`detect`, `plan`, both `apply` passes, `deploy`'s drift
//! preflight) writes one, latest-only per config and host, and `zap status` reads it
//! back offline. A host that resolves through a masked reference has none: its label
//! ([`host_label`]) is a token every machine behind the reference shares
//! ([`masked_refs`]), so `zap_core` neither files nor reads a report under it. Detection never reads it: it is a record of what was seen, not an input
//! to what is seen next. The IO (the path under `~/.zap`, the atomic write, the clock,
//! the operator env) is `zap_core`'s; this module is the contract.
//!
//! It holds **verdicts only** — a [`Verdict`] per resource, never a
//! [`CurrentState`](crate::detected::CurrentState), a reason, or a raw observation — so
//! nothing the target returned is persisted. Its hashes ([`desired_hash`],
//! [`target_hash`]) and host label resolve the references in a config's
//! [`Text`]s — the fields that take one — and take every secret reference as a
//! fixed token, never its value, and — as `zap_core` resolves them — every other value
//! with each registered secret masked out of it.

use std::collections::BTreeMap;
use std::convert::Infallible;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::config_hash::{HashDomain, fields_minus_identity, hash_canonical};
use crate::detected::Detection;
use crate::lock::LockEntry;
use crate::observe::BatchRecord;
use crate::schema::{
    BuildResource, BuildSource, FileContent, FileResource, RemoteContent, RemoteSource, Resource,
    ResourceId, ResourceKind, Target, TextRole,
};
use crate::secrecy::SecretReason;
use crate::text::Text;
use crate::var_ref::{self, masked_token};

/// The report format's version. A file whose `version` isn't this one — an older
/// report, or no report at all — is read as **no last run**, never interpreted.
///
/// Bump on any change to [`LastRun`]'s shape or to what a field means.
pub const LAST_RUN_VERSION: u32 = 4;

/// The host label of a local target — the name its report is filed under.
pub const LOCAL_HOST: &str = "local";

/// A resource's verdict in the pass — the [`Detection`] minus everything it observed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    /// Exists and matches desired state.
    Converged,
    /// Exists but diverges from desired state.
    Drifted,
    /// Doesn't exist on the target.
    Absent,
    /// The pass couldn't determine its state.
    Undetermined,
}

impl Verdict {
    /// The verdict of `detection`.
    #[must_use]
    pub const fn of(detection: &Detection) -> Self {
        match detection {
            Detection::Converged => Self::Converged,
            Detection::Drifted { .. } => Self::Drifted,
            Detection::Absent => Self::Absent,
            Detection::Undetermined { .. } => Self::Undetermined,
        }
    }

    /// The verdict's wire name, which is also its rendered label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Converged => "converged",
            Self::Drifted => "drifted",
            Self::Absent => "absent",
            Self::Undetermined => "undetermined",
        }
    }
}

/// The command pass that wrote a report.
///
/// A wetrun `apply` detects twice — before its changes, to plan them, and after, to
/// confirm them — and each pass writes, so the report after a wetrun is the re-detection
/// unless that failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RunCommand {
    /// `zap detect`.
    Detect,
    /// `zap plan`.
    Plan,
    /// A dry-run `zap apply`.
    Apply,
    /// `zap apply --wetrun`'s detection before its changes ran.
    ApplyBeforeChanges,
    /// `zap apply --wetrun`'s re-detection after its changes ran.
    ApplyAfterChanges,
    /// `zap apply --wetrun` that refused to execute because its plan wasn't the reviewed
    /// one ([`review_plan`]) — it rendered the plan and changed nothing, so it stands as
    /// a preview.
    ApplyRefused,
    /// `zap deploy --wetrun`'s drift preflight.
    DeployPreflight,
}

impl RunCommand {
    /// How the command renders in `zap status`.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Detect => "zap detect",
            Self::Plan => "zap plan",
            Self::Apply => "zap apply (dry run)",
            Self::ApplyBeforeChanges => "zap apply --wetrun, before its changes ran",
            Self::ApplyAfterChanges => "zap apply --wetrun, after its changes ran",
            Self::ApplyRefused => "zap apply --wetrun, refused (its plan was not the reviewed one)",
            Self::DeployPreflight => "zap deploy --wetrun's drift preflight",
        }
    }

    /// Whether the pass showed the operator a plan and executed none of it — the passes
    /// whose recorded [`LastRun::plan_hash`] a wetrun may bind to ([`review_plan`]).
    /// `detect` plans nothing; the wetrun's own two passes and deploy's preflight plan
    /// but never render a changeset for review.
    #[must_use]
    pub const fn previews_plan(self) -> bool {
        matches!(self, Self::Plan | Self::Apply | Self::ApplyRefused)
    }
}

/// How a recorded pass reads in a refusal — the name of the command pass that wrote the
/// record a wetrun looked up.
pub trait PassLabel: Copy {
    /// The pass as a refusal names it.
    fn label(self) -> &'static str;
}

impl PassLabel for RunCommand {
    fn label(self) -> &'static str {
        // The inherent method, which `zap status` renders with too.
        Self::label(self)
    }
}

/// No pass: the label of a record kind that can't occur (a record written only by
/// previews has no pass that previewed nothing).
impl PassLabel for Infallible {
    fn label(self) -> &'static str {
        match self {}
    }
}

/// Why a wetrun refused to execute: the plan it computed isn't the one that was reviewed.
///
/// `P` names the pass that wrote a preview, `N` a recorded pass that previewed nothing.
/// `apply` binds to the last-run report, which any detection pass writes, so both are a
/// [`RunCommand`]; a command whose record only previews write has no `N` at all
/// ([`Infallible`]), and its [`NoPreview`](Self::NoPreview) is always "nothing recorded".
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlanUnreviewed<P = RunCommand, N = RunCommand> {
    /// `--expect-plan` named a hash the fresh plan doesn't have.
    Expected {
        /// The hash the operator expected.
        expected: String,
    },
    /// No plan has been reviewed on this host — nothing recorded, or a record of a pass
    /// that didn't preview a plan (`prior`).
    NoPreview {
        /// The recorded pass, when there is one.
        prior: Option<N>,
    },
    /// The last preview's plan differs from the fresh one — what the plan is computed
    /// from changed in between.
    Changed {
        /// The plan the last preview rendered.
        reviewed: String,
        /// The pass that rendered it.
        command: P,
        /// When it ran.
        ran_at: String,
    },
}

/// What a wetrun finds recorded for its host when it looks for the review to bind to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Recorded<'a, P, N> {
    /// Nothing is recorded.
    Nothing,
    /// The record is of a pass that previewed no plan.
    NotAPreview(N),
    /// The record is of a pass that rendered a plan and executed none of it.
    Preview {
        /// The plan it rendered.
        plan_hash: &'a str,
        /// The pass that rendered it.
        command: P,
        /// When it ran.
        ran_at: &'a str,
    },
}

/// Whether a wetrun's `fresh` plan is the reviewed one, given what is `recorded` for its
/// host — the rule every command's review gate shares.
///
/// An explicit `expected` hash (`--expect-plan`) binds alone: it must equal `fresh`, and
/// `recorded` isn't consulted. Otherwise the record must be a preview whose hash is
/// `fresh`. Pure: the caller reads the record and computes the hash.
///
/// # Errors
/// The [`PlanUnreviewed`] reason, which the caller renders beside the fresh plan.
pub fn review_against<P, N>(
    fresh: &str,
    expected: Option<&str>,
    recorded: Recorded<'_, P, N>,
) -> Result<(), PlanUnreviewed<P, N>> {
    if let Some(expected) = expected {
        return if expected == fresh {
            Ok(())
        } else {
            Err(PlanUnreviewed::Expected {
                expected: expected.to_owned(),
            })
        };
    }
    match recorded {
        Recorded::Nothing => Err(PlanUnreviewed::NoPreview { prior: None }),
        Recorded::NotAPreview(command) => Err(PlanUnreviewed::NoPreview {
            prior: Some(command),
        }),
        Recorded::Preview { plan_hash, .. } if plan_hash == fresh => Ok(()),
        Recorded::Preview {
            plan_hash,
            command,
            ran_at,
        } => Err(PlanUnreviewed::Changed {
            reviewed: plan_hash.to_owned(),
            command,
            ran_at: ran_at.to_owned(),
        }),
    }
}

/// Whether an `apply` wetrun's `fresh` plan is the reviewed one — the review a wetrun
/// requires before it executes.
///
/// An explicit `expected` hash (`--expect-plan`) binds alone: it must equal `fresh`.
/// Otherwise the binding is the most recent pass on the host (`prior`): it must have
/// previewed a plan ([`RunCommand::previews_plan`]) whose hash is `fresh`. Pure: the
/// caller reads the report and computes the hash.
///
/// # Errors
/// The [`PlanUnreviewed`] reason, which the caller renders beside the fresh plan.
pub fn review_plan(
    fresh: &str,
    expected: Option<&str>,
    prior: Option<&LastRun>,
) -> Result<(), PlanUnreviewed> {
    review_against(
        fresh,
        expected,
        prior.map_or(Recorded::Nothing, LastRun::recorded),
    )
}

/// One resource's line in a report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceRecord {
    /// What the pass concluded.
    pub verdict: Verdict,
    /// The resource's [`desired_hash`] when the pass ran — what `zap status` compares to
    /// say "config changed since". `None` when it couldn't be computed.
    pub desired_hash: Option<String>,
    /// Whether the resource holds a secret reference. Its hash takes the
    /// secret as a fixed token, so a changed secret value doesn't move it — and `status`
    /// says so beside the verdict.
    pub references_secret: bool,
}

/// The last-run report for one config and host — the file's whole contents.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LastRun {
    /// Always [`LAST_RUN_VERSION`] for a report this zap writes.
    pub version: u32,
    /// When the pass finished, RFC 3339 UTC (the operator machine's clock).
    pub ran_at: String,
    /// The command pass that wrote it.
    pub command: RunCommand,
    /// The host the pass read ([`host_label`]) — `local`, or the remote host with its
    /// references resolved. Every reference in it resolved by value: no report
    /// is written for a host that holds a masking token.
    pub host: String,
    /// The pass's [`target_hash`] — every resource's verdict was read against this
    /// target, so a changed one (a package or service manager, a home, a user) makes
    /// them all predate it. `None` when it couldn't be computed.
    pub target_hash: Option<String>,
    /// The variable names the pass's comparison referenced but couldn't resolve (unset
    /// or empty) — names only, never values. Non-empty means the verdicts compared
    /// against a desired side with empty strings in it, so they aren't evidence.
    pub unverifiable: Vec<String>,
    /// The content address of the plan the pass computed from its verdicts, when it
    /// planned (`detect` doesn't). For a pass that previewed it
    /// ([`RunCommand::previews_plan`]) this is the reviewed plan a later wetrun binds
    /// to ([`review_plan`]).
    pub plan_hash: Option<String>,
    /// Every resource the pass read, by id.
    pub resources: BTreeMap<ResourceId, ResourceRecord>,
    /// The query batches the pass ran (see [`BatchRecord`]).
    pub batches: Vec<BatchRecord>,
}

/// How one reference resolves for the report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReportVar {
    /// A secret variable ([`SecretRule::classify`](crate::secrecy::SecretRule::classify)),
    /// with why it is one: it resolves to its [`masked_token`], never its value.
    Secret(SecretReason),
    /// Any other variable: its operator-env value (empty when unset, as at a run).
    Value(String),
    /// Any other variable whose value carries a registered secret: the value with each
    /// secret in it replaced by its token (a DSN holding a password, say). It counts as
    /// referencing a secret.
    Masked(String),
}

impl ReportVar {
    /// How every reference resolves where there is no environment to read: unset, by
    /// value. The resolver of a caller that plans from a config alone.
    #[must_use]
    pub const fn unset(_name: &str) -> Self {
        Self::Value(String::new())
    }
}

/// Resolve every reference in `text` through `var` — a secret one to its
/// [`masked_token`], any other to its value — noting in `secret` whether one was
/// secret.
fn resolve_refs(text: &Text, var: &impl Fn(&str) -> ReportVar, secret: &mut bool) -> String {
    text.resolve(|name| match var(name) {
        ReportVar::Secret(_) => {
            *secret = true;
            masked_token(name)
        }
        ReportVar::Value(value) => value,
        ReportVar::Masked(value) => {
            *secret = true;
            value
        }
    })
}

/// `text` as a report names it — what [`host_label`] does for a target's host.
///
/// Every reference is resolved through `var`: a secret one to its
/// [`masked_token`], any other to its value.
#[must_use]
pub fn resolved_label(text: &Text, var: impl Fn(&str) -> ReportVar) -> String {
    resolve_refs(text, &var, &mut false)
}

/// A reference in a label that `var` didn't resolve by value, and why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MaskedRef {
    /// The variable is itself a secret, so it resolves to its own masking token.
    Secret {
        /// The variable.
        name: String,
        /// Why it is a secret — which decides the way out a message offers.
        reason: SecretReason,
    },
    /// The variable is no secret itself, but its value holds a registered secret's.
    CarriesSecret {
        /// The variable.
        name: String,
        /// The secrets masked out of its value, each once, in order.
        secrets: Vec<String>,
    },
}

/// The references in `text` that `var` doesn't resolve by value — a secret one, or
/// one whose value carries a secret — in order, each once.
///
/// A label holding one stands for every value the reference could take, so it
/// identifies nothing: two machines behind one masked host reference share a label.
#[must_use]
pub fn masked_refs(text: &Text, var: impl Fn(&str) -> ReportVar) -> Vec<MaskedRef> {
    let mut refs: Vec<MaskedRef> = Vec::new();
    let mut seen: Vec<&str> = Vec::new();
    for name in text.ref_names() {
        if seen.contains(&name) {
            continue;
        }
        seen.push(name);
        match var(name) {
            ReportVar::Value(_) => {}
            ReportVar::Secret(reason) => refs.push(MaskedRef::Secret {
                name: name.to_owned(),
                reason,
            }),
            ReportVar::Masked(value) => refs.push(MaskedRef::CarriesSecret {
                name: name.to_owned(),
                secrets: var_ref::masked_token_names(&value),
            }),
        }
    }
    refs
}

/// A resource's [`desired_hash`] and whether it references a secret.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DesiredHash {
    /// The hash, lowercase hex.
    pub hash: String,
    /// Whether any reference it resolved was secret.
    pub references_secret: bool,
}

/// The hash a report records for a resource: its declared state as written, the value
/// each of its [`Text`]s resolves to through `var`, and the lock pin detection compares
/// against.
///
/// References resolve in a `Text` and nowhere else: a field that takes none — inline
/// content, a template body, a `verify` command, a `name` — is hashed as written, and a
/// reference can't be declared in one. So the hash
/// moves when a declared field changes, and when the value a reference-taking field
/// resolves to does (a path, a template variable, a `script`'s `check` and `env`).
///
/// A secret reference resolves to its fixed token before anything else sees it,
/// and — as `zap_core` resolves them — any other reference's *value* has every
/// registered secret in it masked ([`ReportVar::Masked`]), so no registered secret's
/// value enters the hash; there is no escaped form to chase, because nothing has been
/// escaped yet. (Literal config text is hashed as written: the secret gate rejects a
/// secret hardcoded there.)
/// Identity (`id` / `name` / `depends_on`) is left out, as for `config_hash`, and so is
/// a `remote` file's or `build` source's `auth` — an operator credential, not declared
/// state. `~` / `$HOME` stay literal (the target's home — [`target_hash`] covers it).
/// Hashed on [`HashDomain::LastRun`], whose version is the report format's; it need not
/// equal the lock's `config_hash`.
///
/// # Errors
/// A `serde_json` error if the resource can't be serialized.
pub fn desired_hash(
    resource: &Resource,
    var: impl Fn(&str) -> ReportVar,
    lock_entry: Option<&LockEntry>,
) -> Result<DesiredHash, serde_json::Error> {
    let mut secret = false;
    let mut resolved = Vec::new();
    resource.for_each_text(|role, text| match role {
        TextRole::Resource | TextRole::TargetIdentity | TextRole::Deploy => {
            resolved.push(Value::String(resolve_refs(text, &var, &mut secret)));
        }
        TextRole::FetchCredential => {}
    });
    let mut fields = declared_fields(resource)?;
    fields.insert(RESOLVED_KEY.to_owned(), Value::Array(resolved));
    let mut value = Value::Object(fields);
    fold_lock_pin(&mut value, lock_entry);
    Ok(DesiredHash {
        hash: hash_canonical(HashDomain::LastRun, &value)?,
        references_secret: secret,
    })
}

/// The key a report hash holds its resolved [`Text`] values under, in the order the
/// config's walk visits them — beside the declared fields, which hold them as written.
const RESOLVED_KEY: &str = "__resolved";

/// A resource's declared state as its hashes take it: every field but identity
/// (`id` / `name` / `depends_on`) and a fetch `auth`, with each reference left
/// as written.
///
/// # Errors
/// A `serde_json` error if the resource can't be serialized.
pub(crate) fn declared_fields(
    resource: &Resource,
) -> Result<serde_json::Map<String, Value>, serde_json::Error> {
    fields_minus_identity(&without_fetch_auth(resource))
}

/// Add the pin `lock_entry` holds to a resource's hashed `fields`, as `__lock_pin`.
pub(crate) fn fold_lock_pin(fields: &mut Value, lock_entry: Option<&LockEntry>) {
    if let (Value::Object(map), Some(pin)) = (fields, lock_entry.and_then(LockEntry::pin)) {
        map.insert("__lock_pin".to_owned(), Value::String(pin.to_string()));
    }
}

/// `resource` with a `remote` file's or `build` source's fetch `auth` cleared — an
/// operator credential, not declared state.
///
/// Matched on the typed shape rather than serialized field names, so a renamed field
/// can't carry the credential into a hash, and no other field that happens to be named
/// `auth` (a `database`'s rules, a template variable) is taken for one. A fetch
/// credential is a [`RemoteAuth`](crate::schema::RemoteAuth): this clears the fields
/// that hold one, and the config's walk names its text a
/// [`TextRole::FetchCredential`].
#[must_use]
fn without_fetch_auth(resource: &Resource) -> Resource {
    let mut resource = resource.clone();
    match &mut resource.kind {
        ResourceKind::File(FileResource {
            content: FileContent::Remote(RemoteContent { auth, .. }),
            ..
        })
        | ResourceKind::Build(BuildResource {
            source: BuildSource::Remote(RemoteSource { auth, .. }),
            ..
        }) => *auth = None,
        _ => {}
    }
    resource
}

/// The hash a report records for the target the pass read.
///
/// The whole `zap.target(...)` descriptor as written — host, users, port, key path,
/// home, managers, everything, so any change reads as one — and the value each of its
/// [`Text`]s (`host`, `user`, `bootstrap_user`) resolves to through `var`, as for
/// [`desired_hash`], on [`HashDomain::LastRun`].
///
/// # Errors
/// A `serde_json` error if the target can't be serialized.
pub fn target_hash(
    target: &Target,
    var: impl Fn(&str) -> ReportVar,
) -> Result<String, serde_json::Error> {
    let mut resolved = Vec::new();
    target.for_each_text(|_, text| {
        resolved.push(Value::String(resolve_refs(text, &var, &mut false)));
    });
    let mut wrapped = serde_json::Map::new();
    wrapped.insert("__target".to_owned(), serde_json::to_value(target)?);
    wrapped.insert(RESOLVED_KEY.to_owned(), Value::Array(resolved));
    hash_canonical(HashDomain::LastRun, &Value::Object(wrapped))
}

/// The host label of a target: what its report is filed and recorded under, and the
/// host its plan names.
///
/// `local`, or the remote host with its references resolved through `var` (a
/// secret one as its token — a label that names no one machine, [`masked_refs`]).
/// `None` when a remote host resolves empty — no run could have connected.
#[must_use]
pub fn host_label(target: &Target, var: impl Fn(&str) -> ReportVar) -> Option<String> {
    if target.is_local() {
        return Some(LOCAL_HOST.to_owned());
    }
    let host = target
        .host()
        .map(|host| resolve_refs(host, &var, &mut false))
        .unwrap_or_default();
    (!host.is_empty()).then_some(host)
}

impl LastRun {
    /// The report as a wetrun's review gate reads it: a preview when its pass rendered a
    /// plan for review ([`RunCommand::previews_plan`]) and recorded that plan's hash,
    /// otherwise a pass that previewed nothing.
    #[must_use]
    pub fn recorded(&self) -> Recorded<'_, RunCommand, RunCommand> {
        match &self.plan_hash {
            Some(plan_hash) if self.command.previews_plan() => Recorded::Preview {
                plan_hash,
                command: self.command,
                ran_at: &self.ran_at,
            },
            _ => Recorded::NotAPreview(self.command),
        }
    }

    /// Parse a report file's bytes: `None` for anything that isn't a current-version
    /// report — unparseable bytes, a missing or different `version`, or a shape this
    /// version doesn't read.
    ///
    /// The version is checked before the shape, so a file from another format is never
    /// misread as a report even where its fields happen to fit.
    #[must_use]
    pub fn parse(bytes: &[u8]) -> Option<Self> {
        let value: Value = serde_json::from_slice(bytes).ok()?;
        let version = value.get("version")?.as_u64()?;
        if version != u64::from(LAST_RUN_VERSION) {
            return None;
        }
        serde_json::from_value(value).ok()
    }
}

#[cfg(test)]
mod tests {
    use super::{
        LAST_RUN_VERSION, LastRun, ReportVar, ResourceRecord, RunCommand, Verdict, desired_hash,
        host_label, target_hash,
    };
    use crate::detected::{CurrentState, Detection, FileDrift};
    use crate::lock::LockEntry;
    use crate::observe::{BatchRecord, Lane};
    use crate::scalar::ContentHash;
    use crate::schema::{Resource, ResourceId, Target};
    use crate::text::Text;
    use crate::var_ref::Segment::{Ref, Text as Lit};

    /// A stand-in for the engine's name rule: here `SECRET_*` names are secrets; `env`
    /// supplies the rest.
    fn resolver(env: &[(&str, &str)]) -> impl Fn(&str) -> ReportVar {
        let env: Vec<(String, String)> = env
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect();
        move |name| {
            if name.starts_with("SECRET_") {
                ReportVar::Secret(crate::secrecy::SecretReason::Name)
            } else {
                ReportVar::Value(
                    env.iter()
                        .find(|(k, _)| k == name)
                        .map(|(_, v)| v.clone())
                        .unwrap_or_default(),
                )
            }
        }
    }

    fn res(json: serde_json::Value) -> Resource {
        serde_json::from_value(json).unwrap()
    }

    /// A changed non-secret value moves the hash wherever it appears — including the
    /// fields the lock's `config_hash` leaves unresolved (a script's check and env).
    #[test]
    fn a_non_secret_value_moves_the_hash_in_every_field() {
        let script = res(serde_json::json!({
            "id": "s", "type": "script",
            "check": Text::of_pieces([Lit("test \"$(app --version)\" = "), Ref("APP_VERSION")]),
            "run": "install-app", "env": {"CHANNEL": Text::reference("APP_CHANNEL")},
        }));
        let hash = |env: &[(&str, &str)]| desired_hash(&script, resolver(env), None).unwrap();
        let base = hash(&[("APP_VERSION", "1.0"), ("APP_CHANNEL", "stable")]);
        assert!(!base.references_secret);
        assert_ne!(
            base,
            hash(&[("APP_VERSION", "1.1"), ("APP_CHANNEL", "stable")])
        );
        assert_ne!(
            base,
            hash(&[("APP_VERSION", "1.0"), ("APP_CHANNEL", "beta")])
        );
    }

    /// A secret resolves to its token: its value never reaches the hash, and the
    /// resource is marked as depending on one.
    #[test]
    fn a_secret_value_never_reaches_the_hash() {
        let file = res(serde_json::json!({
            "id": "env", "type": "file", "path": "/srv/app/.env",
            "content": {"type": "template", "template": "KEY={{key}}\nHOST={{host}}\n",
                        "vars": {"key": Text::reference("SECRET_KEY"),
                                 "host": Text::reference("APP_HOST")}},
        }));
        // The resolver never hands out a secret's value, so two runs differing only in
        // it are identical by construction; the non-secret still moves it.
        let hash = |host: &str| desired_hash(&file, resolver(&[("APP_HOST", host)]), None).unwrap();
        let one = hash("a.example");
        assert!(one.references_secret);
        assert_ne!(one.hash, hash("b.example").hash);
    }

    /// Text that spells a reference — `{env:NAME}`, as one is shown, or `$$NAME$$` — is
    /// its own characters, in a field that takes a reference and in one that takes
    /// none: the variable it happens to name moves nothing and marks no secret, while
    /// the text itself still moves the hash.
    #[test]
    fn text_that_spells_a_reference_is_hashed_as_written() {
        let hash = |resource: &Resource, value: &str| {
            desired_hash(resource, resolver(&[("X", value)]), None).unwrap()
        };
        let cases = |x: &str| {
            [
                serde_json::json!({
                    "id": "inline", "name": format!("name {x}"), "type": "file", "path": "/etc/motd",
                    "content": {"type": "inline", "content": format!("hello {x}\n")},
                }),
                serde_json::json!({
                    "id": "body", "type": "file", "path": "/etc/app.conf",
                    "content": {"type": "template", "template": format!("{x} {{{{v}}}}"),
                                "vars": {"v": "literal"}},
                }),
                serde_json::json!({
                    "id": "verify", "type": "verify", "assertions": [
                        {"type": "path_exists", "path": format!("/srv/{x}")},
                        {"type": "command", "run": format!("echo {x}"), "expect": x},
                    ],
                }),
                serde_json::json!({
                    "id": "pkg", "type": "package", "from": {"apt": "curl"},
                    "check": format!("command -v {x}"),
                }),
                serde_json::json!({
                    "id": "script", "type": "script", "check": format!("test -e /srv/{x}"),
                    "run": format!("echo {x}"), "env": {"V": x},
                }),
                serde_json::json!({
                    "id": "build", "type": "build", "run": "make", "output": "/opt/b",
                    "source": {"type": "remote", "url": "https://x/s.tgz",
                               "extract": {"type": "tar.gz"}},
                    "cwd": format!("/src/{x}"),
                }),
            ]
            .map(res)
        };
        for (plain, secret) in [("{env:X}", "{env:SECRET_X}"), ("$$X$$", "$$SECRET_X$$")] {
            for (reference, literal) in cases(plain).iter().zip(&cases(secret)) {
                let id = &reference.id.0;
                let one = hash(reference, "one");
                assert_eq!(one, hash(reference, "two"), "{id}: `X` is not referenced");
                assert!(
                    !hash(literal, "one").references_secret,
                    "{id}: `SECRET_X` is not referenced"
                );
                assert_ne!(one.hash, hash(literal, "one").hash, "{id}: the text moved");
            }
        }
    }

    /// Each resolved value belongs to its field: two references trading values is a
    /// different desired state, though the declaration and the set of values are the
    /// same.
    #[test]
    fn two_references_trading_values_move_the_hash() {
        let link = res(serde_json::json!({
            "id": "l", "type": "link", "path": Text::reference("LINK_AT"),
            "target": Text::reference("LINK_TO"),
        }));
        let hash = |at: &str, to: &str| {
            desired_hash(&link, resolver(&[("LINK_AT", at), ("LINK_TO", to)]), None).unwrap()
        };
        assert_ne!(hash("/srv/a", "/srv/b"), hash("/srv/b", "/srv/a"));
    }

    /// The report's hashes are part of its format: what a resource and a target hash to
    /// is fixed for a `LAST_RUN_VERSION`, so a change to what is hashed — a field's
    /// form on the wire, the order the resolved values are taken in — fails here until
    /// the version moves with it.
    #[test]
    fn a_report_hash_is_byte_stable() {
        let env = resolver(&[("APP_DIR", "/srv/app"), ("APP_HOST", "a.example")]);
        let file = res(serde_json::json!({
            "id": "f", "name": "n", "type": "file",
            "path": Text::of_pieces([Ref("APP_DIR"), Lit("/app.conf")]),
            "content": {"type": "template", "template": "{{host}} {{port}} {{key}}",
                        "vars": {"host": Text::reference("APP_HOST"), "port": 8080,
                                 "key": Text::reference("SECRET_KEY")}},
            "validate": Text::of_pieces([Lit("test -s "), Ref("APP_DIR"), Lit("/app.conf")]),
        }));
        assert_eq!(LAST_RUN_VERSION, 4);
        assert_eq!(
            desired_hash(&file, &env, None).unwrap().hash,
            "72e2367625346ba4ed0f8fa8e87759cd802f78b109432fb117ff849f1229fbd2"
        );
        let remote: Target = serde_json::from_value(serde_json::json!({
            "host": Text::reference("APP_HOST"), "user": "deploy", "home": "/home/deploy",
            "package_manager": "apt",
        }))
        .unwrap();
        assert_eq!(
            target_hash(&remote, &env).unwrap(),
            "44de05e6bcbc3e28cf993467bf4c7f87ea1e43022c089b8ce5ab664534acc307"
        );
    }

    /// A fetch credential is one thing to both of its readers: the texts the walk names
    /// a credential are the texts `without_fetch_auth` removes.
    #[test]
    fn a_fetch_credential_is_what_without_fetch_auth_clears() {
        use super::without_fetch_auth;
        use crate::schema::TextRole;
        let texts = |resource: &Resource, wanted: TextRole| {
            let mut texts = Vec::new();
            resource.for_each_text(|role, text| {
                if role == wanted {
                    texts.push(text.as_inert().to_owned());
                }
            });
            texts
        };
        for resource in [
            res(serde_json::json!({
                "id": "f", "type": "file", "path": "/opt/x",
                "content": {"type": "remote", "url": "https://x/y",
                            "auth": {"scheme": "bearer", "token": Text::reference("FILE_TOKEN")}},
            })),
            res(serde_json::json!({
                "id": "b", "type": "build", "run": "make", "output": "/opt/b",
                "source": {"type": "remote", "url": "https://x/s.tgz",
                           "auth": {"scheme": "bearer", "token": Text::reference("BUILD_TOKEN")}},
            })),
        ] {
            let cleared = without_fetch_auth(&resource);
            assert_eq!(texts(&resource, TextRole::FetchCredential).len(), 1);
            assert_eq!(texts(&cleared, TextRole::FetchCredential), [""; 0]);
            assert_eq!(
                texts(&resource, TextRole::Resource),
                texts(&cleared, TextRole::Resource)
            );
        }
    }

    /// Identity and a fetch credential are no part of it; the lock pin is.
    #[test]
    fn identity_and_auth_are_left_out_and_the_pin_folds_in() {
        let remote = |id: &str, token: Text| {
            res(serde_json::json!({
                "id": id, "name": id, "type": "file", "path": "/opt/x",
                "content": {"type": "remote", "url": "https://x/y", "extract": {"type": "none"},
                            "auth": {"scheme": "bearer", "token": token}},
            }))
        };
        let hash = |resource: &Resource, pin: Option<&LockEntry>| {
            desired_hash(resource, resolver(&[]), pin).unwrap()
        };
        let base = hash(&remote("a", Text::reference("SECRET_TOKEN")), None);
        assert_eq!(
            base,
            hash(&remote("b", Text::reference("OTHER_TOKEN")), None)
        );
        assert!(!base.references_secret, "auth isn't declared state");
        let pin = LockEntry::RemoteFile {
            config_hash: String::new(),
            blake3: ContentHash::new("a".repeat(64)).unwrap(),
        };
        assert_ne!(
            base.hash,
            hash(&remote("a", Text::literal("t")), Some(&pin)).hash
        );
    }

    /// A `build` source's fetch credential is left out too; its url is not.
    #[test]
    fn a_build_sources_auth_is_left_out() {
        let build = |url: &str, token: &str| {
            res(serde_json::json!({
                "id": "b", "name": "b", "type": "build", "run": "make", "output": "/opt/b",
                "source": {"type": "remote", "url": url,
                           "auth": {"scheme": "bearer", "token": Text::reference(token)}},
            }))
        };
        let hash = |resource: &Resource| desired_hash(resource, resolver(&[]), None).unwrap();
        let base = hash(&build("https://x/s.tgz", "SECRET_TOKEN"));
        assert_eq!(base, hash(&build("https://x/s.tgz", "OTHER_TOKEN")));
        assert!(!base.references_secret, "auth isn't declared state");
        assert_ne!(
            base.hash,
            hash(&build("https://x/t.tgz", "SECRET_TOKEN")).hash
        );
    }

    /// Any change to the target moves its hash — a manager, the home, the connecting
    /// user alike — and a masked value counts as referencing a secret.
    #[test]
    fn the_target_hash_moves_with_any_target_field() {
        let target = |json: serde_json::Value| -> Target { serde_json::from_value(json).unwrap() };
        let hash = |t: &Target| target_hash(t, resolver(&[("APP_HOST", "h")])).unwrap();
        let base = target(serde_json::json!({
            "host": Text::reference("APP_HOST"), "user": "deploy", "home": "/home/deploy",
            "package_manager": "apt", "service_manager": "systemd",
        }));
        for changed in [
            serde_json::json!({"host": Text::reference("APP_HOST"), "user": "deploy",
                               "home": "/home/deploy", "package_manager": "apk", "service_manager": "systemd"}),
            serde_json::json!({"host": Text::reference("APP_HOST"), "user": "deploy",
                               "home": "/home/deploy",
                               "package_manager": "apt", "service_manager": "openrc"}),
            serde_json::json!({"host": Text::reference("APP_HOST"), "user": "deploy", "home": "/srv",
                               "package_manager": "apt", "service_manager": "systemd"}),
            serde_json::json!({"host": Text::reference("APP_HOST"), "user": "ops",
                               "home": "/home/deploy",
                               "package_manager": "apt", "service_manager": "systemd"}),
        ] {
            assert_ne!(hash(&base), hash(&target(changed.clone())), "{changed}");
        }
        assert_ne!(
            hash(&base),
            target_hash(&base, resolver(&[("APP_HOST", "other")])).unwrap()
        );

        let file = res(serde_json::json!({
            "id": "f", "type": "directory",
            "path": Text::of_pieces([Lit("/srv/"), Ref("DATABASE_URL")]),
        }));
        let masked = desired_hash(
            &file,
            |_: &str| ReportVar::Masked("postgres://app:[MASKED:SECRET_DB]@db".to_owned()),
            None,
        )
        .unwrap();
        assert!(masked.references_secret);
    }

    #[test]
    fn a_host_label_takes_a_secret_as_its_token() {
        let target = |host: &str| -> Target {
            serde_json::from_value(
                serde_json::json!({"host": Text::reference(host), "user": "deploy"}),
            )
            .unwrap()
        };
        assert_eq!(
            host_label(&Target::local(), resolver(&[])).as_deref(),
            Some("local")
        );
        assert_eq!(
            host_label(&target("APP_HOST"), resolver(&[("APP_HOST", "h.example")])).as_deref(),
            Some("h.example")
        );
        assert_eq!(
            host_label(&target("SECRET_HOST"), resolver(&[])).as_deref(),
            Some("[MASKED:SECRET_HOST]")
        );
        assert_eq!(host_label(&target("APP_HOST"), resolver(&[])), None);
    }

    fn report() -> LastRun {
        LastRun {
            version: LAST_RUN_VERSION,
            ran_at: "2026-09-28T12:00:00Z".to_owned(),
            command: RunCommand::Plan,
            host: "local".to_owned(),
            target_hash: Some("t".to_owned()),
            unverifiable: vec!["APP_HOST".to_owned()],
            plan_hash: Some("p".to_owned()),
            resources: [(
                ResourceId("motd".to_owned()),
                ResourceRecord {
                    verdict: Verdict::Drifted,
                    desired_hash: Some("h".to_owned()),
                    references_secret: false,
                },
            )]
            .into(),
            batches: vec![BatchRecord {
                lane: Lane::Login,
                queries: 1,
            }],
        }
    }

    #[test]
    fn review_binds_to_an_explicit_hash_alone() {
        use super::{PlanUnreviewed, review_plan};
        // `--expect-plan` decides by itself — a matching prior is irrelevant, and so is a
        // missing one.
        assert_eq!(review_plan("p", Some("p"), None), Ok(()));
        let mut stale = report();
        stale.plan_hash = Some("other".to_owned());
        assert_eq!(review_plan("p", Some("p"), Some(&stale)), Ok(()));
        assert_eq!(
            review_plan("p", Some("q"), Some(&report())),
            Err(PlanUnreviewed::Expected {
                expected: "q".to_owned()
            })
        );
    }

    #[test]
    fn review_binds_to_the_last_preview() {
        use super::{PlanUnreviewed, review_plan};
        // The fixture is a `plan` pass that rendered "p".
        assert_eq!(review_plan("p", None, Some(&report())), Ok(()));
        assert_eq!(
            review_plan("p", None, None),
            Err(PlanUnreviewed::NoPreview { prior: None })
        );
        // A pass that planned without rendering (the wetrun's own, deploy's preflight) or
        // one that didn't plan (`detect`) is no review, whatever hash it carries.
        for command in [
            RunCommand::Detect,
            RunCommand::ApplyBeforeChanges,
            RunCommand::ApplyAfterChanges,
            RunCommand::DeployPreflight,
        ] {
            let mut run = report();
            run.command = command;
            assert_eq!(
                review_plan("p", None, Some(&run)),
                Err(PlanUnreviewed::NoPreview {
                    prior: Some(command)
                }),
                "{command:?}"
            );
        }
        // A refused wetrun rendered its plan: it counts.
        let mut refused = report();
        refused.command = RunCommand::ApplyRefused;
        assert_eq!(review_plan("p", None, Some(&refused)), Ok(()));
        // The preview's plan differs: the config or the target moved since.
        let mut moved = report();
        moved.plan_hash = Some("q".to_owned());
        assert_eq!(
            review_plan("p", None, Some(&moved)),
            Err(PlanUnreviewed::Changed {
                reviewed: "q".to_owned(),
                command: RunCommand::Plan,
                ran_at: "2026-09-28T12:00:00Z".to_owned(),
            })
        );
    }

    #[test]
    fn a_report_round_trips() {
        let bytes = serde_json::to_vec(&report()).unwrap();
        assert_eq!(LastRun::parse(&bytes), Some(report()));
    }

    #[test]
    fn another_version_is_no_report() {
        let mut value = serde_json::to_value(report()).unwrap();
        for other in [LAST_RUN_VERSION + 1, LAST_RUN_VERSION - 1, 0] {
            value["version"] = serde_json::json!(other);
            assert_eq!(
                LastRun::parse(&serde_json::to_vec(&value).unwrap()),
                None,
                "{other}"
            );
        }
        value.as_object_mut().unwrap().remove("version");
        assert_eq!(LastRun::parse(&serde_json::to_vec(&value).unwrap()), None);
    }

    /// A file of another format is no report — even a map of per-resource entries with a
    /// resource named `version`.
    #[test]
    fn a_file_of_another_format_is_no_report() {
        let cache = serde_json::json!({
            "version": {"config_hash": "h", "detection": {"outcome": "converged"},
                        "detected_at": "2026-05-24T18:03:00Z"},
            "motd": {"config_hash": "h", "detection": {"outcome": "converged"},
                     "detected_at": "2026-05-24T18:03:00Z"},
        });
        assert_eq!(LastRun::parse(&serde_json::to_vec(&cache).unwrap()), None);
        assert_eq!(LastRun::parse(b"not json"), None);
    }

    #[test]
    fn a_verdict_keeps_nothing_the_detection_observed() {
        let drifted = Detection::Drifted {
            current: CurrentState::File {
                drift: FileDrift::Content,
            },
        };
        assert_eq!(Verdict::of(&drifted), Verdict::Drifted);
        let held = Detection::Undetermined {
            reason: "/home/secret-path".to_owned(),
        };
        assert_eq!(Verdict::of(&held), Verdict::Undetermined);
        assert_eq!(
            serde_json::to_string(&Verdict::of(&held)).unwrap(),
            "\"undetermined\""
        );
    }

    /// `--expect-plan` names a plan by its whole hash: a prefix of the fresh one, the
    /// empty string, another case, or the hash with more after it is another plan.
    #[test]
    fn review_matches_an_explicit_hash_whole() {
        use super::{PlanUnreviewed, review_plan};
        for expected in ["", "abc", "ABCDEF", "abcdef0", " abcdef"] {
            assert_eq!(
                review_plan("abcdef", Some(expected), None),
                Err(PlanUnreviewed::Expected {
                    expected: expected.to_owned()
                }),
                "{expected:?}"
            );
        }
    }

    /// A label resolves a reference by value or to its token, and `masked_refs` names
    /// the ones that didn't resolve by value — secret, or carrying a secret, with
    /// the secrets it carries — once each, in order.
    #[test]
    fn a_label_names_the_references_it_could_not_resolve_by_value() {
        use super::{MaskedRef, ReportVar, masked_refs, resolved_label};
        use crate::secrecy::SecretReason;
        let var = |name: &str| match name {
            "HOST" => ReportVar::Value("a.example.com".to_owned()),
            "DSN" => ReportVar::Masked("db://[MASKED:PW]@h".to_owned()),
            _ => ReportVar::Secret(SecretReason::Name),
        };
        assert_eq!(
            resolved_label(&Text::of_pieces([Ref("HOST"), Lit(":22")]), var),
            "a.example.com:22"
        );
        assert_eq!(
            resolved_label(
                &Text::of_pieces([Ref("API_KEY"), Lit("."), Ref("HOST")]),
                var
            ),
            "[MASKED:API_KEY].a.example.com"
        );
        assert_eq!(
            masked_refs(&Text::of_pieces([Ref("HOST"), Lit(" literal")]), var),
            []
        );
        assert_eq!(
            masked_refs(
                &Text::of_pieces([
                    Ref("API_KEY"),
                    Lit(" "),
                    Ref("HOST"),
                    Lit(" "),
                    Ref("DSN"),
                    Lit(" "),
                    Ref("API_KEY"),
                    Lit(" "),
                    Ref("DSN"),
                ]),
                var
            ),
            [
                MaskedRef::Secret {
                    name: "API_KEY".to_owned(),
                    reason: SecretReason::Name,
                },
                MaskedRef::CarriesSecret {
                    name: "DSN".to_owned(),
                    secrets: vec!["PW".to_owned()],
                },
            ]
        );
    }
}
