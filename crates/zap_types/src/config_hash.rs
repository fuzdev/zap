//! Content-addressed hashing for the pure layer.
//!
//! `config_hash` addresses a resource's *desired* state (drives lock staleness);
//! `plan_hash` addresses the whole changeset (drives `zap plan` inspection / CI /
//! diffing); `deploy_plan_hash` does the same for the imperative deploy plan; the
//! last-run report's hashes ride a domain of their own
//! ([`desired_hash`](crate::last_run::desired_hash)). All are blake3 over deterministic
//! JSON (object keys recursively sorted, array order preserved), prefixed with the
//! version of a [`HashDomain`] — one version axis per artifact kind, so an address moves
//! only for reasons that are actually about it. A resource-hash bump re-addresses the
//! lock entries keyed by a resource's hash; it has nothing to say about
//! what a changeset *is*, and so must not churn plan hashes.
//!
//! [`ConfigHashInputs`] is the inspectable value the `config_hash` consumes: it
//! holds the complete set of *captured* inputs (the resolved desired-state fields
//! plus any folded lock pin), built once at the resolution boundary by
//! [`ConfigHashInputs::collect`]. Everything **not** represented there is, by
//! construction, outside the content address — see the type's docs for the
//! deliberate non-captures. `plan_hash`'s inputs are the
//! [`Plan`] itself (already a typed value), the shell text its typed steps run
//! (`scripted_step_text`), and the constant scripts the changes zap carries out itself
//! can run (`native_script_text`), so it needs no separate inputs type.
//!
//! The provenance digests ([`build_provenance`], [`extract_provenance`]) are what a
//! target records beside what zap built or extracted, for detection to compare: blake3
//! over a fixed tag, [`PROVENANCE_VERSION`], and canonical JSON, outside every
//! [`HashDomain`].

use serde::Serialize;
use serde_json::{Map, Value};

use crate::deploy::DeployPlan;
use crate::lock::LockEntry;
use crate::plan::{Change, Plan, PlanStep};
use crate::schema::{
    BuildResource, BuildSource, DeclaredPackageCheck, ExtractMode, FileContent, FileResource,
    PackageResource, RemoteContent, RemoteSource, ResolvedField, ResolvedFields, Resource,
    ResourceKind,
};

/// Bump to re-address every resource's `config_hash`, under [`HashDomain`]'s rule.
///
/// For this domain that is a change the canonical serialization doesn't show: how a
/// field resolves before hashing (the resolver a lock entry's address is computed with
/// resolves a secret reference to its fixed
/// [`masked_token`](crate::var_ref::masked_token), never its value), or what the lock
/// folds in.
///
/// A change to *which* references are secret ([`SecretRule`](crate::secrecy::SecretRule))
/// needs no bump: an address it affects moves between a value and a token, so the
/// entry reads stale on its own, and every other address is the one it was. Nor does
/// masking a plain value before it is hashed (a secret of at least the address floor
/// that occurs inside it folded as its token): only an address whose value holds such a
/// secret moves, from the raw value to the masked one, and reads stale on its own.
///
/// Scoped to [`HashDomain::Resource`]: it re-addresses the `config_hash` on every lock
/// entry, and *only* those — plan and deploy-plan hashes fold their own versions. A bump
/// reads every tracked pin as stale until `zap update` re-mints it, so it costs every
/// operator a reviewed update pass. A detection-logic change alone is **not** a reason to
/// bump: nothing caches a verdict, so the next pass reads live under the new logic.
pub const RESOURCE_HASH_VERSION: u32 = 10;

/// Bump to re-address every [`plan_hash`], under [`HashDomain`]'s rule.
///
/// The text a plan runs is hashed: a typed step's (`scripted_step_text`) and a native
/// change's, in the command it runs in
/// ([`Change::native_commands`](crate::plan::Change::native_commands)), alike.
/// Independent of [`RESOURCE_HASH_VERSION`]: a different axis, counted separately.
pub const PLAN_HASH_VERSION: u32 = 7;

/// Bump to re-address every [`deploy_plan_hash`] and preflight digest, under
/// [`HashDomain`]'s rule — the role [`PLAN_HASH_VERSION`] plays for the convergence
/// changeset, for the imperative deploy plan.
///
/// The text a deploy plan runs is hashed: each step's own, the command an upload runs
/// its constant script in, the extract-and-swap script built from the plan's values, and
/// the rollback's swap.
pub const DEPLOY_PLAN_HASH_VERSION: u32 = 10;

/// Which artifact an address is for — the version axis every hash here folds in.
///
/// Each variant carries its **own** version constant, so bumping one re-addresses only
/// its own artifacts. Naming the domain is required rather than defaulted: a new
/// content address in this module is a choice about which invalidation axis it rides,
/// and the wrong (silent) answer couples one artifact's addresses to another's changes.
///
/// **When to bump a version**: only for a change to an artifact's shape or meaning that
/// the hashed bytes can't show — the same bytes coming to stand for something else, or
/// a way of resolving a value before it is hashed. A change the bytes do show moves
/// every address it touches by itself. Every constant script an executor runs for an
/// artifact is hashed text, a step's own and the native and deploy scripts a plan names
/// but doesn't hold, so no edit to one bumps a version. The commands composed directly
/// around a path are not hashed (the `rm -f --` that clears a pending marker, or removes
/// what a failed validated write created): a change to what one of those does is a
/// change the bytes can't show, and bumps the version.
///
/// This is *independent version axes*, not separation: only the version **number** is
/// folded, so two domains that hold the same version hash identical canonical bytes
/// identically. Their inputs are different shapes — a changeset, a deploy plan or the
/// resources its preflight checks, a resource or `__target`-wrapped target — so no input
/// of one is an input of another in practice.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashDomain {
    /// A resource's resolved desired state → the lock entry `config_hash`. Versioned by
    /// [`RESOURCE_HASH_VERSION`].
    Resource,
    /// The convergence changeset → [`plan_hash`]. Versioned by [`PLAN_HASH_VERSION`].
    Plan,
    /// The imperative deploy plan → [`deploy_plan_hash`]. Versioned by
    /// [`DEPLOY_PLAN_HASH_VERSION`].
    Deploy,
    /// A resource's declared state as the last-run report records it →
    /// [`desired_hash`](crate::last_run::desired_hash). Versioned by the report's own
    /// format version, [`LAST_RUN_VERSION`](crate::last_run::LAST_RUN_VERSION).
    LastRun,
}

impl HashDomain {
    /// This domain's version — the value folded into its addresses.
    #[must_use]
    pub const fn version(self) -> u32 {
        match self {
            Self::Resource => RESOURCE_HASH_VERSION,
            Self::Plan => PLAN_HASH_VERSION,
            Self::Deploy => DEPLOY_PLAN_HASH_VERSION,
            Self::LastRun => crate::last_run::LAST_RUN_VERSION,
        }
    }
}

/// Serialize a value to canonical JSON: object keys recursively sorted, array
/// order preserved, so identical effective configs produce identical bytes.
///
/// # Errors
/// Returns an error if `value` cannot be serialized to JSON.
fn to_canonical_json<T: Serialize>(value: &T) -> Result<String, serde_json::Error> {
    let json_value = serde_json::to_value(value)?;
    Ok(canonicalize(&json_value).to_string())
}

/// Recursively sort object keys; preserve array order; pass scalars through.
fn canonicalize(value: &Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort_unstable();
            let mut out = Map::new();
            for key in keys {
                if let Some(val) = map.get(key) {
                    out.insert(key.clone(), canonicalize(val));
                }
            }
            Value::Object(out)
        }
        Value::Array(items) => Value::Array(items.iter().map(canonicalize).collect()),
        other => other.clone(),
    }
}

/// blake3 hex of a value's canonical JSON, prefixed with `domain`'s version number.
///
/// # Errors
/// Returns an error if `value` cannot be serialized to JSON.
pub fn hash_canonical<T: Serialize>(
    domain: HashDomain,
    value: &T,
) -> Result<String, serde_json::Error> {
    let json = to_canonical_json(value)?;
    let mut hasher = blake3::Hasher::new();
    hasher.update(&domain.version().to_le_bytes());
    hasher.update(json.as_bytes());
    Ok(hasher.finalize().to_hex().to_string())
}

/// Content address of a plan (the changeset). See the module docs.
///
/// The address covers the plan, the shell text each typed step in it runs
/// (`scripted_step_text`), and the commands a change zap carries out itself runs its
/// constant scripts in
/// ([`Change::native_commands`](crate::plan::Change::native_commands)) — so a plan
/// reviewed under one zap is not the plan of a zap whose scripts differ, though the plan
/// itself holds no script.
///
/// # Errors
/// Returns an error if the plan cannot be serialized.
pub fn plan_hash(plan: &Plan) -> Result<String, serde_json::Error> {
    plan_hash_with(plan, scripted_step_text, native_script_text)
}

/// The command each constant script a change can run that none of its steps holds is
/// run in ([`Change::native_commands`](crate::plan::Change::native_commands)): empty for a
/// change whose steps are what it runs.
fn native_script_text(change: &Change) -> Vec<String> {
    change.native_commands()
}

/// The shell text a typed step runs, which the plan names but doesn't hold: `None` for a
/// `Run` (its text is the step) and a `Note` (it runs nothing).
///
/// For a [`PlanStep::Put`], [`PlanStep::Dir`], [`PlanStep::PgHbaRule`],
/// [`PlanStep::Installer`], and [`PlanStep::SwapCheck`] it is the whole of
/// [`PlanStep::execution`]'s text: the constant script
/// ([`FILE_PUT`](crate::put::FILE_PUT), [`DIR_ATTRS`](crate::put::DIR_ATTRS),
/// [`PG_HBA_ADD_RULE`](crate::postgres::PG_HBA_ADD_RULE),
/// [`SWAP_PATH_CHECK`](crate::plan::SWAP_PATH_CHECK)) and everything composed around
/// it — a producer's command, its setup and its guard, the feeder that captures and
/// digests its output, the `mkdir`, the `hba_file` read — and the fetch an installer's
/// script arrives by. It is computed from the step, so an edit to any of them moves the
/// address of every plan that runs it.
fn scripted_step_text(step: &PlanStep) -> Option<String> {
    match step {
        PlanStep::Run(_) | PlanStep::Note(_) => None,
        PlanStep::Put(_)
        | PlanStep::Dir(_)
        | PlanStep::PgHbaRule(_)
        | PlanStep::Installer(_)
        | PlanStep::SwapCheck(_) => step
            .execution()
            .map(|execution| execution.text().to_owned()),
    }
}

/// [`plan_hash`] with the text a step runs given by `scripted`, and the scripts a change
/// zap carries out itself can run by `native`.
fn plan_hash_with(
    plan: &Plan,
    scripted: impl Fn(&PlanStep) -> Option<String>,
    native: impl Fn(&Change) -> Vec<String>,
) -> Result<String, serde_json::Error> {
    /// What a plan's address is computed over.
    #[derive(Serialize)]
    struct Addressed<'a> {
        plan: &'a Plan,
        /// The text each typed step runs, in plan order.
        scripted: Vec<String>,
        /// The scripts each change can run that none of its steps holds, a list per
        /// change in plan order.
        native: Vec<Vec<String>>,
    }
    let scripted = plan
        .changes
        .iter()
        .flat_map(|change| &change.steps)
        .filter_map(scripted)
        .collect();
    let native = plan.changes.iter().map(native).collect();
    hash_canonical(
        HashDomain::Plan,
        &Addressed {
            plan,
            scripted,
            native,
        },
    )
}

/// Content address of a deploy plan — [`plan_hash`]'s counterpart for the imperative
/// release act, on its own version axis.
///
/// The address covers the plan and the text it names but doesn't hold: the command
/// each [`Upload`](crate::deploy::DeployAction::Upload) step runs its constant script in
/// ([`upload_put_command`](crate::deploy::upload_put_command)), the script each
/// [`ExtractSwap`](crate::deploy::DeployAction::ExtractSwap) step runs
/// ([`DeployPlan::swap_script`]), and, for a plan that swaps a release in, the
/// auto-rollback's compare-and-swap
/// ([`rollback_swap_command`](crate::deploy::rollback_swap_command)) with its app path
/// and versions left empty (the plan fixes those elsewhere). Every other step holds the
/// text it runs.
///
/// # Errors
/// Returns an error if the plan cannot be serialized.
pub fn deploy_plan_hash(plan: &DeployPlan) -> Result<String, serde_json::Error> {
    deploy_plan_hash_with(
        plan,
        crate::deploy::upload_put_command,
        DeployPlan::swap_script,
        || crate::deploy::rollback_swap_command("", "", ""),
    )
}

/// [`deploy_plan_hash`] with the command an upload to a path runs given by `upload`,
/// the script an extract-and-swap step runs by `swap`, and the rollback's swap by
/// `rollback`.
pub(crate) fn deploy_plan_hash_with(
    plan: &DeployPlan,
    upload: impl Fn(&str) -> String,
    swap: impl Fn(&DeployPlan, &crate::deploy::ReleaseSwap) -> String,
    rollback: impl Fn() -> String,
) -> Result<String, serde_json::Error> {
    /// What a deploy plan's address is computed over.
    #[derive(Serialize)]
    struct Addressed<'a> {
        plan: &'a DeployPlan,
        /// The command each upload runs, in plan order.
        uploads: Vec<String>,
        /// The script each extract-and-swap step runs, in plan order.
        swaps: Vec<String>,
        /// The rollback's swap, when the plan swaps a release in.
        rollback: Option<String>,
    }
    let uploads = plan
        .steps
        .iter()
        .filter_map(|step| match &step.action {
            crate::deploy::DeployAction::Upload { remote } => Some(upload(remote)),
            _ => None,
        })
        .collect();
    let swaps: Vec<String> = plan
        .steps
        .iter()
        .filter_map(|step| match &step.action {
            crate::deploy::DeployAction::ExtractSwap(release) => Some(swap(plan, release)),
            _ => None,
        })
        .collect();
    let rollback = (!swaps.is_empty()).then(rollback);
    hash_canonical(
        HashDomain::Deploy,
        &Addressed {
            plan,
            uploads,
            swaps,
            rollback,
        },
    )
}

/// The tag every provenance digest begins with, before its version: it sets these
/// digests apart from every [`HashDomain`] address, which begins with a version alone.
const PROVENANCE_TAG: &[u8] = b"zap-provenance\0";

/// Bump to change what every provenance digest records.
///
/// Covers [`build_provenance`] and [`extract_provenance`]: a target's recorded digest
/// then differs from the desired one, so each `build` rebuilds and each extracted
/// `remote` file re-extracts once.
pub const PROVENANCE_VERSION: u32 = 1;

/// What a `build` output's provenance sidecar records, 64 lowercase hex.
///
/// blake3 over a fixed tag, [`PROVENANCE_VERSION`], and the canonical JSON of the
/// source `pin`, the extract format and strip count, and `run`, `cwd`, and `env` as
/// declared — so editing any of them rebuilds, as advancing the pin does.
///
/// A reference in `run` or `env` is hashed inert, never resolved: a secret's value never
/// reaches the target, and a change to a value alone does not rebuild.
#[must_use]
pub fn build_provenance(pin: &str, build: &BuildResource) -> String {
    let BuildSource::Remote(RemoteSource { extract, .. }) = &build.source;
    let mut fields = Map::new();
    fields.insert("kind".to_owned(), Value::String("build".to_owned()));
    fields.insert("pin".to_owned(), Value::String(pin.to_owned()));
    insert_extract(&mut fields, *extract);
    fields.insert(
        "run".to_owned(),
        Value::String(build.run.as_inert().to_owned()),
    );
    insert_opt(&mut fields, "cwd", build.cwd.as_deref());
    if let Some(env) = &build.env {
        let env = env
            .iter()
            .map(|(name, value)| {
                (
                    name.as_str().to_owned(),
                    Value::String(value.as_inert().to_owned()),
                )
            })
            .collect();
        fields.insert("env".to_owned(), Value::Object(env));
    }
    provenance_digest(&fields)
}

/// What an extracted `remote` file's sentinel records, 64 lowercase hex.
///
/// blake3 over a fixed tag, [`PROVENANCE_VERSION`], and the canonical JSON of the
/// tarball `pin` and the extract format and strip count — so a strip-count change
/// re-extracts the same tarball.
#[must_use]
pub fn extract_provenance(pin: &str, extract: ExtractMode) -> String {
    let mut fields = Map::new();
    fields.insert("kind".to_owned(), Value::String("extract".to_owned()));
    fields.insert("pin".to_owned(), Value::String(pin.to_owned()));
    insert_extract(&mut fields, extract);
    provenance_digest(&fields)
}

/// The extract format token and its strip count, the same fields `config_hash` takes.
fn insert_extract(fields: &mut Map<String, Value>, extract: ExtractMode) {
    fields.insert(
        "extract".to_owned(),
        Value::String(extract.format_str().to_owned()),
    );
    fields.insert(
        "strip_components".to_owned(),
        Value::from(extract.strip_components()),
    );
}

/// blake3 hex over the provenance tag, its version, and `fields` as canonical JSON.
fn provenance_digest(fields: &Map<String, Value>) -> String {
    let json = canonicalize(&Value::Object(fields.clone())).to_string();
    let mut hasher = blake3::Hasher::new();
    hasher.update(PROVENANCE_TAG);
    hasher.update(&PROVENANCE_VERSION.to_le_bytes());
    hasher.update(json.as_bytes());
    hasher.finalize().to_hex().to_string()
}

/// The complete set of inputs folded into a resource's `config_hash` — the
/// inspectable value the hash consumes.
///
/// Everything **not** represented here is, by construction, outside the content
/// address. The deliberate non-captures are, in one place:
/// - **identity** (`id` / `name` / `depends_on`) — renaming a resource mustn't churn
///   its hash, so these are stripped from [`fields`](Self::fields);
/// - **the target home** (`~` / `$HOME`) — left literal by the injected `resolve`,
///   resolved at the IO boundary instead, so the address is machine-independent;
/// - **`auth` credentials** — operator-machine state, never declared desired state
///   (a `file remote` / `build` source omits it from its captured fields);
/// - **a `file`'s `validate`** — the command a write is checked by before it is
///   installed; it changes what is accepted, not what the content (or its pin) is, so
///   editing it doesn't re-address the entry;
/// - **all target *observed* state** — what detection reads, never an input to the
///   desired-state address.
///
/// Built once at the resolution boundary by [`collect`](Self::collect) (the only
/// place the `resolve` closure is applied — [`fields`](Self::fields) then holds
/// concrete resolved values), and content-addressed by [`hash`](Self::hash).
/// Deliberately does **not** derive `Serialize`: the hash is produced by `hash`,
/// which fixes the byte layout, not by serializing this struct
/// directly (the address would then follow the struct's shape, and a refactor of it
/// would invalidate every persisted `config_hash`).
#[derive(Debug, Clone)]
pub struct ConfigHashInputs {
    /// The per-kind selected, already-resolved desired-state fields (identity
    /// stripped; target home left literal). The captured desired state, verbatim
    /// as hashed — minus the lock pin, which is held separately and folded by `hash`.
    fields: Map<String, Value>,
    /// The lock-pinned identity folded into the hash (a tracked `remote_file`/`build`/`apt_key`
    /// resolved blake3), if any — the entry's *pinned state*, never its own
    /// `config_hash` field (which is the fixed-point output, not an input).
    lock_pin: Option<String>,
}

impl ConfigHashInputs {
    /// Collect a resource's captured `config_hash` inputs, applying `resolve` once
    /// here (the boundary) so the result holds concrete resolved values.
    ///
    /// Pure: the reference / `~` / `$HOME` resolution is injected as `resolve` (env
    /// reads are IO and live in `zap_core`), while the per-kind field *selection* —
    /// schema knowledge — stays here. Two resources with identical effective config
    /// produce equal inputs.
    ///
    /// The optional `lock_entry` contributes its **pinned identity** (a tracked
    /// `remote_file`'s resolved blake3) — *not* the entry's own `config_hash` field,
    /// which is the fixed-point output of this very function. So
    /// advancing a pin moves the hash, as any other desired-state change does. Pass `None`
    /// for a vendored file (its declared `blake3` is already in-config via
    /// `file_fields`) or any non-pinned kind.
    ///
    /// All three path-resolution consumers (hash / detect / execute) read the resolved
    /// path fields from the one shared [`ResourceKind::resolved_fields`] seam, so a
    /// resolved value can't drift between them. `package` selects its fields explicitly
    /// (`package.check` resolves only as a path — a choice by variant the flat seam can't
    /// express). Every other kind serializes its typed payload minus
    /// identity — a superset that never under-hashes — then overwrites the seam's
    /// resolved fields. Resolution is **unconditional** (matching the detectors), so
    /// gating here (as a `package` check's variant does) would diverge and reintroduce a
    /// stale hit.
    ///
    /// # Errors
    /// Returns a `serde_json` error if the resource or selected fields can't be
    /// serialized.
    pub fn collect(
        resource: &Resource,
        resolve: impl Fn(&str) -> String,
        lock_entry: Option<&LockEntry>,
    ) -> Result<Self, serde_json::Error> {
        let resolved = resource.kind.resolved_fields(&resolve);
        let fields = match &resource.kind {
            ResourceKind::Package(package) => package_fields(package, &resolve)?,
            // `file` content addressing is bespoke (rendered bytes / source path /
            // remote pin), but its top-level `path` comes from the shared seam.
            ResourceKind::File(file) => file_fields(file, &resolved, &resolve)?,
            // `build` source addressing is bespoke (same shape as `file remote`): the
            // resolved source url, never the operator `auth` credential.
            ResourceKind::Build(build) => build_fields(build, &resolved, &resolve)?,
            // `apt_repo`: the typed payload, with the key's fetch url resolved as a
            // `remote` file's is — a tracked key's address moves with what it is fetched
            // from, a secret reference by its token.
            // No bump: no `apt_repo` address was persisted before `apt_key` entries existed.
            ResourceKind::AptRepo(repo) => {
                let mut fields = fields_minus_identity(resource)?;
                fields.insert("key_url".to_owned(), Value::String(resolve(&repo.key_url)));
                fields
            }
            // Every other kind: serialize the typed payload minus identity (the
            // never-under-hash superset), then overwrite the seam's resolved fields.
            // Sourcing from the typed serialization keeps a later-added field in the
            // hash automatically (no hand-selected arm to drift from the schema).
            _ => {
                let mut fields = fields_minus_identity(resource)?;
                for (field, value) in resolved.iter() {
                    fields.insert(field.as_str().to_owned(), Value::String(value.to_owned()));
                }
                fields
            }
        };
        Ok(Self {
            fields,
            lock_pin: lock_entry.and_then(LockEntry::pin).map(ToString::to_string),
        })
    }

    /// The captured desired-state fields (resolved; identity stripped; **without** the
    /// lock pin). The exact map hashed, minus the separately-held pin — inspectable so
    /// a caller can explain *why* a hash moved.
    #[must_use]
    pub const fn fields(&self) -> &Map<String, Value> {
        &self.fields
    }

    /// The folded lock pin, if any (held apart from [`fields`](Self::fields) so the
    /// desired-state map and the pinned identity are distinguishable).
    #[must_use]
    pub fn lock_pin(&self) -> Option<&str> {
        self.lock_pin.as_deref()
    }

    /// Content-address these inputs into the `config_hash` hex.
    ///
    /// Rides [`HashDomain::Resource`], so `RESOURCE_HASH_VERSION` is folded in and a
    /// bump re-addresses every lock entry. The lock pin (when present) is folded under
    /// the distinct `__lock_pin` key. Every persisted `config_hash` (a lock entry's)
    /// records this layout, so it stays **byte-identical**.
    ///
    /// # Errors
    /// Returns a `serde_json` error if the captured fields can't be serialized.
    pub fn hash(&self) -> Result<String, serde_json::Error> {
        self.lock_pin.as_ref().map_or_else(
            || hash_canonical(HashDomain::Resource, &self.fields),
            |pin| {
                let mut fields = self.fields.clone();
                fields.insert("__lock_pin".to_owned(), Value::String(pin.clone()));
                hash_canonical(HashDomain::Resource, &fields)
            },
        )
    }
}

/// Compute a resource's content-addressed `config_hash` — addresses its *desired*
/// state, keying lock entries.
///
/// The convenience composition of [`ConfigHashInputs::collect`] +
/// [`ConfigHashInputs::hash`]; use the inputs value directly when the captured
/// fields need inspecting. Passing the entry a hash produced reproduces the same
/// hash iff the rest of the config is unchanged.
///
/// # Errors
/// Returns a `serde_json` error if the resource or selected fields can't be
/// serialized.
pub fn compute_config_hash(
    resource: &Resource,
    resolve: impl Fn(&str) -> String,
    lock_entry: Option<&LockEntry>,
) -> Result<String, serde_json::Error> {
    ConfigHashInputs::collect(resource, resolve, lock_entry)?.hash()
}

/// Hash fields for a `package`: the `from` mapping plus the optional `check`,
/// resolved only when it is a path (mirroring detection, which expands a
/// path-shaped check but runs a command-shaped one verbatim).
fn package_fields(
    package: &PackageResource,
    resolve: impl Fn(&str) -> String,
) -> Result<Map<String, Value>, serde_json::Error> {
    let mut fields = Map::new();
    fields.insert("type".to_owned(), Value::String("package".to_owned()));
    fields.insert("from".to_owned(), serde_json::to_value(&package.from)?);
    if let Some(check) = &package.check {
        // Resolve only a path check, matching detection: it expands a path (`/`…/`~`) but
        // runs a command as written, so the hash makes the same choice — or a
        // reference-bearing path check's hash wouldn't move with the env its detection
        // reads.
        let value = match check {
            DeclaredPackageCheck::Path(path) => resolve(path),
            DeclaredPackageCheck::Command(command) => command.clone(),
        };
        fields.insert("check".to_owned(), Value::String(value));
    }
    Ok(fields)
}

/// Hash fields for a `file`: resolved path + mode/owner/group/triggers + content
/// addressing. Content addressing depends on the source kind: inline/template hash
/// the rendered bytes; `source` hashes only the resolved source path (the bytes live
/// on the target); `remote` hashes the resolved `url` + extract strategy + a
/// *declared* (vendored) blake3 pin (a tracked file's lock-pinned blake3 folds in via
/// the lock-fold, not here). `validate` is a deliberate non-capture (see
/// [`ConfigHashInputs`]).
fn file_fields(
    file: &FileResource,
    resolved: &ResolvedFields,
    resolve: impl Fn(&str) -> String,
) -> Result<Map<String, Value>, serde_json::Error> {
    let mut fields = Map::new();
    fields.insert("type".to_owned(), Value::String("file".to_owned()));
    // `path` from the shared seam — the same resolved value the detector probes and
    // the executor writes (the seam carries `file.path`).
    let path = resolved
        .get(ResolvedField::Path)
        .map_or_else(|| resolve(&file.path), str::to_owned);
    fields.insert("path".to_owned(), Value::String(path));
    insert_opt(&mut fields, "mode", file.mode.as_deref());
    insert_opt(&mut fields, "owner", file.owner.as_deref());
    insert_opt(&mut fields, "group", file.group.as_deref());
    if let Some(triggers) = &file.triggers {
        fields.insert("triggers".to_owned(), serde_json::to_value(triggers)?);
    }
    match &file.content {
        FileContent::Remote(RemoteContent {
            url,
            blake3,
            extract,
            // `auth` is an operator-machine credential, not declared desired state —
            // deliberately excluded from the content address; folding it would make the
            // hash machine-specific.
            auth: _,
        }) => {
            fields.insert(
                "content_type".to_owned(),
                Value::String("remote".to_owned()),
            );
            // `url` resolves operator references (the home stays literal — same rule as
            // `path`); it drives both the fetch and the content address.
            fields.insert("content_url".to_owned(), Value::String(resolve(url)));
            // Hash the *stable string token* + a separate strip field, not the
            // `ExtractMode` struct, so the address doesn't follow the enum's shape.
            // Strip-count is desired state (changes the on-target layout), hashed only
            // when non-zero, so a strip-less archive's address has no strip term. The
            // extract sentinel records it too (`extract_provenance`), so a strip-count
            // change re-extracts the same tarball.
            fields.insert(
                "extract".to_owned(),
                Value::String(extract.format_str().to_owned()),
            );
            if extract.strip_components() > 0 {
                fields.insert(
                    "strip_components".to_owned(),
                    Value::from(extract.strip_components()),
                );
            }
            // A declared (vendored) pin is part of desired state — changing it
            // re-addresses the resource. A tracked file (None) gets its pin from the
            // lock, folded in by the lock-fold, not here.
            if let Some(blake3) = blake3 {
                fields.insert("blake3".to_owned(), Value::String(blake3.to_string()));
            }
        }
        FileContent::Source { path } => {
            fields.insert(
                "content_type".to_owned(),
                Value::String("source".to_owned()),
            );
            fields.insert("content_path".to_owned(), Value::String(resolve(path)));
        }
        FileContent::Inline { content } => {
            fields.insert(
                "content_type".to_owned(),
                Value::String("inline".to_owned()),
            );
            fields.insert(
                "rendered_content".to_owned(),
                Value::String(content.clone()),
            );
        }
        FileContent::Template(template) => {
            fields.insert(
                "content_type".to_owned(),
                Value::String("template".to_owned()),
            );
            fields.insert(
                "rendered_content".to_owned(),
                Value::String(template.render(&resolve)),
            );
        }
    }
    Ok(fields)
}

/// Hash fields for a `build`: resolved `output` (from the shared seam) +
/// `run`/`cwd`/`env` (desired state, hashed verbatim like `script.run`) + source
/// addressing. The source mirrors `file remote`: the resolved `url`, the `extract`
/// strategy, a non-zero `strip_components`, the `verify` block, and a *declared*
/// (vendored) blake3 pin. `auth` is an operator credential — excluded (same rule as
/// `file`'s). A *tracked* source (no declared blake3) gets its pin from the lock,
/// folded in by the lock-fold, not here.
fn build_fields(
    build: &BuildResource,
    resolved: &ResolvedFields,
    resolve: impl Fn(&str) -> String,
) -> Result<Map<String, Value>, serde_json::Error> {
    let mut fields = Map::new();
    fields.insert("type".to_owned(), Value::String("build".to_owned()));
    // `output` from the shared seam — the same resolved path the detector probes
    // and the executor installs to.
    let output = resolved
        .get(ResolvedField::Output)
        .map_or_else(|| resolve(&build.output), str::to_owned);
    fields.insert("output".to_owned(), Value::String(output));
    fields.insert("run".to_owned(), serde_json::to_value(&build.run)?);
    insert_opt(&mut fields, "cwd", build.cwd.clone());
    if let Some(env) = &build.env {
        fields.insert("env".to_owned(), serde_json::to_value(env)?);
    }
    match &build.source {
        BuildSource::Remote(RemoteSource {
            url,
            extract,
            // operator-machine credential, excluded from the content address
            auth: _,
            verify,
            blake3,
        }) => {
            fields.insert("source_type".to_owned(), Value::String("remote".to_owned()));
            fields.insert("source_url".to_owned(), Value::String(resolve(url)));
            // Stable string token + separate strip field (see `file_fields`).
            fields.insert(
                "extract".to_owned(),
                Value::String(extract.format_str().to_owned()),
            );
            if extract.strip_components() > 0 {
                fields.insert(
                    "strip_components".to_owned(),
                    Value::from(extract.strip_components()),
                );
            }
            if let Some(verify) = verify {
                fields.insert("verify".to_owned(), serde_json::to_value(verify)?);
            }
            if let Some(blake3) = blake3 {
                fields.insert("blake3".to_owned(), Value::String(blake3.to_string()));
            }
        }
    }
    Ok(fields)
}

/// Serialize a resource's typed payload to a field map minus the identity fields
/// (`id` / `name` / `depends_on`). The never-under-hash superset shared by every
/// catch-all kind; `type` and all kind fields are retained.
pub(crate) fn fields_minus_identity(
    resource: &Resource,
) -> Result<Map<String, Value>, serde_json::Error> {
    let value = serde_json::to_value(resource)?;
    let Value::Object(mut map) = value else {
        // A resource always serializes to an object; anything else is a schema bug.
        // Degrading to an empty map would make every such resource hash identically, so
        // a stale lock pin could read current for the wrong one — fail closed.
        return Err(<serde_json::Error as serde::ser::Error>::custom(
            "resource did not serialize to a JSON object",
        ));
    };
    map.remove("id");
    map.remove("name");
    map.remove("depends_on");
    Ok(map)
}

/// Insert a `Some` string field; skip `None` (so an absent optional doesn't alter
/// the hash relative to a config that never set it).
fn insert_opt(fields: &mut Map<String, Value>, key: &str, value: Option<impl AsRef<str>>) {
    if let Some(value) = value {
        fields.insert(key.to_owned(), Value::String(value.as_ref().to_owned()));
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ConfigHashInputs, DEPLOY_PLAN_HASH_VERSION, HashDomain, PLAN_HASH_VERSION,
        RESOURCE_HASH_VERSION, compute_config_hash, hash_canonical,
    };
    use crate::lock::LockEntry;
    use crate::scalar::ContentHash;
    use crate::schema::Resource;
    use crate::text::Text;
    use crate::var_ref::Segment::{Ref, Text as Lit};
    use crate::var_ref::marker;

    // Valid 64-lowercase-hex pins for fixtures (real shape, arbitrary value).
    const PIN_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const PIN_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    /// `compute_config_hash` with no lock fold — the common test shape.
    fn hash(resource: &Resource, resolve: impl Fn(&str) -> String) -> String {
        compute_config_hash(resource, resolve, None).unwrap()
    }

    fn res(json: serde_json::Value) -> Resource {
        serde_json::from_value(json).unwrap()
    }

    /// Identity resolver — keeps the hash deterministic and env-independent.
    fn identity(value: &str) -> String {
        value.to_owned()
    }

    #[test]
    fn hash_is_deterministic_and_ignores_identity_fields() {
        let a = res(serde_json::json!({
            "id": "d", "name": "dir A", "type": "directory", "path": "/opt/x", "mode": "755"
        }));
        let b = res(serde_json::json!({
            "id": "d2", "name": "dir B", "type": "directory", "path": "/opt/x", "mode": "755"
        }));
        // Same effective config (different id/name) → same hash.
        assert_eq!(hash(&a, identity), hash(&b, identity));
    }

    #[test]
    fn hash_changes_with_desired_state() {
        let base = res(serde_json::json!({"id": "d", "type": "directory", "path": "/opt/x"}));
        let other = res(serde_json::json!({"id": "d", "type": "directory", "path": "/opt/y"}));
        assert_ne!(hash(&base, identity), hash(&other, identity));
    }

    #[test]
    fn resolver_feeds_the_hash() {
        let resource = res(serde_json::json!({"id": "d", "type": "directory",
                "path": Text::of_pieces([Ref("HOME"), Lit("/x")])}));
        let resolved = hash(&resource, |_| "/home/me/x".to_owned());
        let literal = hash(&resource, identity);
        // Different resolution of the same path field → different hash.
        assert_ne!(resolved, literal);
    }

    #[test]
    fn link_hash_tracks_resolved_path_and_target() {
        // A link whose path/target carry an env reference (as a site config's
        // `DEPLOY_DOMAIN` reference does). The detector resolves both before probing, so the
        // hash must too — otherwise an env change that re-targets the link would
        // leave the resource's content address unchanged.
        let resource = res(serde_json::json!({
            "id": "ln", "type": "link",
            "path": Text::of_pieces([Lit("/etc/nginx/sites-enabled/"), Ref("DEPLOY_DOMAIN")]),
            "target": Text::of_pieces([Lit("/etc/nginx/sites-available/"), Ref("DEPLOY_DOMAIN")]),
        }));
        let staging = hash(&resource, |s| {
            s.replace(&marker("DEPLOY_DOMAIN"), "staging")
        });
        let prod = hash(&resource, |s| s.replace(&marker("DEPLOY_DOMAIN"), "prod"));
        // Same literal config, different env resolution → different hash.
        assert_ne!(staging, prod);
    }

    #[test]
    fn installer_hash_tracks_resolved_check() {
        let resource = res(serde_json::json!({
            "id": "fnm", "type": "installer",
            "url": "https://fnm.vercel.app/install",
            "check": Text::of_pieces([Ref("HOME"), Lit("/.local/share/fnm")]),
        }));
        let alice = hash(&resource, |s| s.replace(&marker("HOME"), "/home/alice"));
        let bob = hash(&resource, |s| s.replace(&marker("HOME"), "/home/bob"));
        assert_ne!(alice, bob);
    }

    #[test]
    fn link_resolves_path_and_target_independently() {
        // Each resolved field must feed the hash on its own — a regression where
        // only one of path/target were resolved would leave the other stale.
        let resource = res(serde_json::json!({
            "id": "ln", "type": "link", "path": Text::of_pieces([Ref("A"), Lit("/p")]),
            "target": Text::of_pieces([Ref("B"), Lit("/t")]),
        }));
        let base = hash(&resource, identity);
        let path_changed = hash(&resource, |s| s.replace(&marker("A"), "/x"));
        let target_changed = hash(&resource, |s| s.replace(&marker("B"), "/y"));
        assert_ne!(base, path_changed, "resolving path must move the hash");
        assert_ne!(base, target_changed, "resolving target must move the hash");
        assert_ne!(path_changed, target_changed);
    }

    #[test]
    fn installer_spread_keeps_non_path_fields() {
        // Spread-then-overwrite must not drop sibling fields: two installers
        // differing only in `url` (which the detector hashes literally, never
        // resolves) must hash differently.
        let a = res(serde_json::json!({
            "id": "i", "type": "installer", "url": "https://a.example/install", "check": "/opt/x",
        }));
        let b = res(serde_json::json!({
            "id": "i", "type": "installer", "url": "https://b.example/install", "check": "/opt/x",
        }));
        assert_ne!(hash(&a, identity), hash(&b, identity));
    }

    #[test]
    fn remote_hash_tracks_url_pin_and_extract() {
        let url = Text::of_pieces([Ref("BASE"), Lit("/zig.tar.xz")]);
        let base = res(serde_json::json!({
            "id": "zig", "type": "file", "path": "/opt/zig",
            "content": {"type": "remote", "url": url,
                        "blake3": PIN_A, "extract": {"type": "tar.xz"}},
        }));
        let h = |r: &Resource| hash(r, |s| s.replace(&marker("BASE"), "https://x"));
        let base_hash = h(&base);

        // Resolving the url feeds the hash (the unresolved reference hashes differently).
        assert_ne!(base_hash, hash(&base, identity));

        // Changing the vendored pin re-addresses the resource.
        let repin = res(serde_json::json!({
            "id": "zig", "type": "file", "path": "/opt/zig",
            "content": {"type": "remote", "url": url,
                        "blake3": PIN_B, "extract": {"type": "tar.xz"}},
        }));
        assert_ne!(base_hash, h(&repin), "advancing the pin must move the hash");

        // A tracked file (no declared pin) hashes differently from the vendored one.
        let tracked = res(serde_json::json!({
            "id": "zig", "type": "file", "path": "/opt/zig",
            "content": {"type": "remote", "url": url, "extract": {"type": "tar.xz"}},
        }));
        assert_ne!(base_hash, h(&tracked));
    }

    /// A build source's `verify` block is part of its address, the lock entry's
    /// included: declaring, dropping, or changing the key moves it, so a pin minted
    /// under one signature check reads stale under another.
    #[test]
    fn a_builds_verify_block_moves_its_address() {
        let build = |verify: Option<serde_json::Value>| {
            let mut source = serde_json::json!({
                "type": "remote", "url": "https://x.example/tool.tar.xz",
                "extract": {"type": "tar.xz"},
            });
            if let Some(verify) = verify {
                source["verify"] = verify;
            }
            res(serde_json::json!({
                "id": "tool", "type": "build", "source": source,
                "run": "make install", "output": "/opt/tool/bin/tool",
            }))
        };
        let key = |key: &str| Some(serde_json::json!({"scheme": "minisign", "public_key": key}));
        let entry = LockEntry::Build {
            config_hash: String::new(),
            blake3: ContentHash::new(PIN_A).unwrap(),
        };
        let mut seen = std::collections::BTreeSet::new();
        for resource in [
            build(None),
            build(key(
                "RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3",
            )),
            build(key(
                "RWTAPRW2qy9FjsBiMAByBI6ZPPBM9ygMVv3nPbpmK3hhgBoRxkY0pGHC",
            )),
        ] {
            let address = compute_config_hash(&resource, identity, Some(&entry)).unwrap();
            assert!(seen.insert(address), "{resource:?}");
        }
    }

    #[test]
    fn strip_components_folds_only_when_nonzero() {
        let make = |strip: serde_json::Value| {
            let extract = if strip.is_null() {
                serde_json::json!({"type": "tar.xz"})
            } else {
                serde_json::json!({"type": "tar.xz", "strip_components": strip})
            };
            res(serde_json::json!({
                "id": "zig", "type": "file", "path": "/opt/zig",
                "content": {
                    "type": "remote", "url": "https://x/zig.tar.xz", "blake3": PIN_A,
                    "extract": extract,
                },
            }))
        };
        let absent = hash(&make(serde_json::Value::Null), identity);
        let zero = hash(&make(serde_json::json!(0)), identity);
        let one = hash(&make(serde_json::json!(1)), identity);
        let two = hash(&make(serde_json::json!(2)), identity);

        // Absent and `0` are the no-strip default — same hash.
        assert_eq!(absent, zero, "strip_components:0 must hash like absent");
        // A real strip count is desired state — it moves the hash, and distinct counts differ.
        assert_ne!(absent, one, "strip_components:1 must move the hash");
        assert_ne!(one, two, "distinct strip counts must hash differently");
    }

    #[test]
    fn lock_fold_moves_the_hash_and_is_a_fixed_point() {
        // A tracked remote file (no in-config pin): the lock pin folds into the hash.
        let tracked = res(serde_json::json!({
            "id": "zig", "type": "file", "path": "/opt/zig",
            "content": {"type": "remote", "url": "https://x/zig", "extract": {"type": "none"}},
        }));
        let no_lock = compute_config_hash(&tracked, identity, None).unwrap();
        let pin_a = LockEntry::RemoteFile {
            config_hash: String::new(),
            blake3: ContentHash::new(PIN_A).unwrap(),
        };
        let pin_b = LockEntry::RemoteFile {
            config_hash: String::new(),
            blake3: ContentHash::new(PIN_B).unwrap(),
        };
        let with_a = compute_config_hash(&tracked, identity, Some(&pin_a)).unwrap();
        let with_b = compute_config_hash(&tracked, identity, Some(&pin_b)).unwrap();

        // Folding a pin moves the hash; advancing the pin moves it again.
        assert_ne!(no_lock, with_a, "folding a pin must move the hash");
        assert_ne!(with_a, with_b, "advancing the pin must move the hash");

        // Fixed point: the *entry's own* config_hash field is never an input, so
        // re-folding the same pin reproduces the same hash regardless of that field.
        let pin_a_filled = LockEntry::RemoteFile {
            config_hash: "whatever-irrelevant".to_owned(),
            blake3: ContentHash::new(PIN_A).unwrap(),
        };
        assert_eq!(
            with_a,
            compute_config_hash(&tracked, identity, Some(&pin_a_filled)).unwrap()
        );
    }

    #[test]
    fn inputs_collect_then_hash_equals_compute_config_hash() {
        // The convenience fn is exactly collect + hash — the inputs value is the
        // inspectable intermediate, not a different computation.
        let resource = res(serde_json::json!({
            "id": "d", "type": "directory", "path": "/opt/x", "mode": "755"
        }));
        let inputs = ConfigHashInputs::collect(&resource, identity, None).unwrap();
        assert_eq!(
            inputs.hash().unwrap(),
            compute_config_hash(&resource, identity, None).unwrap()
        );
    }

    #[test]
    fn lock_pin_is_a_named_input_not_buried_in_the_field_map() {
        // A tracked remote file: the pin is held apart from the desired-state fields
        // (visible via `lock_pin()`, absent from `fields()`)…
        let tracked = res(serde_json::json!({
            "id": "zig", "type": "file", "path": "/opt/zig",
            "content": {"type": "remote", "url": "https://x/zig", "extract": {"type": "none"}},
        }));
        let pin = LockEntry::RemoteFile {
            config_hash: String::new(),
            blake3: ContentHash::new(PIN_A).unwrap(),
        };
        let inputs = ConfigHashInputs::collect(&tracked, identity, Some(&pin)).unwrap();
        assert_eq!(inputs.lock_pin(), Some(PIN_A));
        assert!(!inputs.fields().contains_key("__lock_pin"));
        // …yet still folds into the hash, byte-identical to folding it in as a field.
        assert_eq!(
            inputs.hash().unwrap(),
            compute_config_hash(&tracked, identity, Some(&pin)).unwrap()
        );
    }

    #[test]
    fn each_domain_folds_its_own_version() {
        // The point of the split: each domain reads its own constant, so bumping one
        // leaves the others' addresses where they are.
        assert_eq!(HashDomain::Resource.version(), RESOURCE_HASH_VERSION);
        assert_eq!(HashDomain::Plan.version(), PLAN_HASH_VERSION);
        assert_eq!(HashDomain::Deploy.version(), DEPLOY_PLAN_HASH_VERSION);
    }

    #[test]
    fn a_version_bump_moves_only_its_own_domain() {
        // Same bytes, different version → a different address. Asserted through the two
        // domains that currently *hold* different versions, which is what proves a
        // resource-hash bump cannot reach the plan address.
        let value = serde_json::json!({"a": 1});
        assert_ne!(
            hash_canonical(HashDomain::Resource, &value).unwrap(),
            hash_canonical(HashDomain::Plan, &value).unwrap(),
        );
    }

    #[test]
    fn the_resource_address_is_byte_stable() {
        // Every persisted `config_hash` — the `zap.lock` entries in every consumer repo —
        // is this layout. An accidental change to it
        // (a folded domain tag, a reordered update) would read as "every pin is stale"
        // across the ecosystem, so it is pinned rather than left to review.
        //
        // Regenerate when `RESOURCE_HASH_VERSION` bumps — it *should* move then; run
        // the test and copy the actual value. Never hand-edit toward a guess.
        let resource = res(serde_json::json!({
            "id": "d", "type": "directory", "path": "/opt/x", "mode": "755"
        }));
        assert_eq!(
            hash(&resource, identity),
            "e45dc3a43372bd82ed6d6aa93e59613e735e63a0acfb1ddd354808edaa59b621",
        );
    }

    #[test]
    fn the_plan_address_is_byte_stable() {
        // A `plan_hash` is what a reviewer copies into `--expect-plan` and what a
        // last-run report records for the next wetrun to bind to. It folds
        // `PLAN_HASH_VERSION`'s value and the canonical JSON of the whole `Plan` — the
        // changes, the declared target, the machine it resolved to, and what the
        // references the changes use resolved to — and the text of the scripts its
        // changes run. A change to any of them moves it, and
        // every recorded preview then reads as another plan.
        //
        // Regenerate when `PLAN_HASH_VERSION` bumps, or a script the change runs
        // changes — it *should* move then; run the test and copy the actual value.
        // Never hand-edit toward a guess.
        use crate::plan::{DiffInputs, Machine, diff};
        use crate::schema::Target;
        use std::collections::BTreeMap;

        let resources = [res(serde_json::json!({
            "id": "d", "type": "directory", "path": "/opt/x", "mode": "755"
        }))];
        let target: Target = serde_json::from_value(serde_json::json!({
            "host": Text::reference("DEPLOY_HOST"), "user": "deploy", "package_manager": "apt",
        }))
        .unwrap();
        let hash = |target: &Target, machine: &Machine| {
            let plan = diff(DiffInputs {
                resources: &resources,
                detected: &absent(&resources),
                target,
                machine,
                lock: None,
                pending: &BTreeMap::new(),
                var: &crate::last_run::ReportVar::unset,
            })
            .plan;
            super::plan_hash(&plan).unwrap()
        };
        assert_eq!(
            hash(
                &target,
                &Machine::Remote {
                    host: "a.example.com".to_owned(),
                    user: Some("deploy".to_owned()),
                }
            ),
            "bd04bdcde5af4cf7f18a99fe325017e7d646962b4dcf204a033c34f4d7e1a3be",
        );
        assert_eq!(
            hash(&Target::local(), &local_machine()),
            "5b17662d7d58fcd1231fb7f8dea617074fabca783783f46b87d7c9920636fe5d"
        );
    }

    /// A plan of one change whose steps are `steps`.
    fn plan_of(steps: Vec<crate::plan::PlanStep>) -> crate::plan::Plan {
        use crate::plan::{DiffInputs, diff};
        use crate::schema::Target;
        use std::collections::BTreeMap;

        let resources = [res(serde_json::json!({
            "id": "d", "type": "directory", "path": "/opt/x", "mode": "755"
        }))];
        let mut plan = diff(DiffInputs {
            resources: &resources,
            detected: &absent(&resources),
            target: &Target::local(),
            machine: &local_machine(),
            lock: None,
            pending: &BTreeMap::new(),
            var: &crate::last_run::ReportVar::unset,
        })
        .plan;
        plan.changes[0].steps = steps;
        plan
    }

    /// One typed step of each shape, as JSON: a put of held text, a put of a command's
    /// output with a guard, a directory, a `pg_hba` rule, a put of each other producer's
    /// output (one of them with a setup), an installer, a swap file's path check.
    fn typed_steps() -> [serde_json::Value; 8] {
        [
            serde_json::json!({"put": {
                "path": "/etc/sudoers.d/deploy", "run_as": "root", "check": "sudoers",
                "source": {"text": {"mode": "440", "content": "deploy ALL=(ALL) ALL\n"}},
            }}),
            serde_json::json!({"put": {
                "path": "/etc/fstab", "run_as": {"user": "app"}, "check": "none",
                "source": {"command": {
                    "mode": {"keep": {"if_new": "644"}},
                    "producer": {"fstab_swap_entry": {"path": "/swapfile"}},
                }},
            }}),
            serde_json::json!({"dir": {
                "path": "/home/deploy/.ssh", "mode": "700", "owner": "deploy",
                "group": "deploy",
            }}),
            serde_json::json!({"pg_hba_rule": {
                "database": "app", "user": "app", "host": "::1/128", "method": "scram-sha-256",
            }}),
            serde_json::json!({"put": {
                "path": "/etc/apt/sources.list.d/x.list", "run_as": "root", "check": "none",
                "source": {"command": {
                    "mode": {"set": "644"},
                    "producer": {"apt_source_line": {"line": "deb https://e.x/apt stable main"}},
                }},
            }}),
            serde_json::json!({"put": {
                "path": "/home/app/.ssh/authorized_keys", "run_as": {"user": "app"},
                "check": "none",
                "source": {"command": {
                    "mode": {"set": "600"},
                    "producer": {"authorized_keys_of": {"account": "ops"}},
                }},
            }}),
            serde_json::json!({"installer": {"url": "https://e.x/i.sh", "shell": "sh"}}),
            serde_json::json!({"swap_check": {"path": "/swapfile"}}),
        ]
    }

    fn steps_of(json: &[serde_json::Value]) -> Vec<crate::plan::PlanStep> {
        json.iter()
            .map(|step| serde_json::from_value(step.clone()).expect("a valid step"))
            .collect()
    }

    /// A reviewed plan binds the scripts its typed steps run: the plan holds none of
    /// their text, and its address moves with each of them.
    #[test]
    fn the_plan_address_moves_with_each_script_a_typed_step_runs() {
        use crate::plan::SWAP_PATH_CHECK;
        use crate::postgres::PG_HBA_ADD_RULE;
        use crate::put::{DIR_ATTRS, FILE_PUT};

        let plan = plan_of(steps_of(&typed_steps()));
        let json = serde_json::to_string(&plan).unwrap();
        for script in [FILE_PUT, DIR_ATTRS, PG_HBA_ADD_RULE, SWAP_PATH_CHECK] {
            assert!(!json.contains(script));
        }
        let address = super::plan_hash(&plan).unwrap();
        assert_eq!(
            address,
            super::plan_hash_with(&plan, super::scripted_step_text, super::native_script_text)
                .unwrap()
        );
        // Each constant script, and the text composed around one: the feeder of a
        // command's output, the mode read of a file that keeps its mode, the `mkdir`
        // ahead of the directory script, the `hba_file` read; each producer's command,
        // the guard of one and the setup of another; an installer's fetch, its check
        // of what arrived, and its pipe.
        for edited in [
            FILE_PUT,
            DIR_ATTRS,
            PG_HBA_ADD_RULE,
            SWAP_PATH_CHECK,
            "zap_h=$(printf %s \"$zap_c\" | sha512sum) || exit 1; ",
            "zap_m=$(stat -L -c %a ",
            "sudo mkdir -p ",
            "SHOW hba_file",
            ". /etc/os-release && printf ",
            "awk '{ print }' /etc/fstab",
            "END { exit !found }",
            "sudo -u 'ops' cat -- ",
            "[ -n \"$SRC_HOME\" ] || { echo 'zap: no home directory for ops'",
            "curl --proto '=https' --proto-redir '=https' -fsSL",
            "[ -n \"$zap_s\" ] || { echo 'zap: the installer script is empty' >&2; exit 1; }",
            "printf '%s\\n' \"$zap_s\" | ",
        ] {
            let seen = std::cell::Cell::new(false);
            let moved = super::plan_hash_with(
                &plan,
                |step| {
                    super::scripted_step_text(step).map(|text| {
                        seen.set(seen.get() || text.contains(edited));
                        text.replace(edited, "edited")
                    })
                },
                super::native_script_text,
            )
            .unwrap();
            assert!(seen.get(), "no step runs {edited}");
            assert_ne!(moved, address, "{edited}");
        }
        // Each step on its own: a plan of that one step moves with the script it runs,
        // so no shape of step leans on another to bind a script they share.
        for (step, script) in typed_steps().iter().zip([
            FILE_PUT,
            FILE_PUT,
            DIR_ATTRS,
            PG_HBA_ADD_RULE,
            FILE_PUT,
            FILE_PUT,
            "zap_s=$(",
            SWAP_PATH_CHECK,
        ]) {
            let alone = plan_of(steps_of(std::slice::from_ref(step)));
            let moved = super::plan_hash_with(
                &alone,
                |step| super::scripted_step_text(step).map(|text| text.replace(script, "edited")),
                super::native_script_text,
            )
            .unwrap();
            assert_ne!(moved, super::plan_hash(&alone).unwrap(), "{step}");
        }
        // A command and a note are their own text in the plan: nothing more is hashed.
        for step in [
            crate::plan::PlanStep::run("true"),
            crate::plan::PlanStep::note("a note"),
        ] {
            assert_eq!(super::scripted_step_text(&step), None);
        }
    }

    /// Every resource of `resources` detected `absent`, so each plans a create.
    fn absent(
        resources: &[Resource],
    ) -> std::collections::BTreeMap<crate::schema::ResourceId, crate::detected::Detection> {
        resources
            .iter()
            .map(|resource| (resource.id.clone(), crate::detected::Detection::Absent))
            .collect()
    }

    /// A plan of one change of `resource`, detected `absent` (a create).
    fn plan_of_resource(resource: serde_json::Value) -> crate::plan::Plan {
        use crate::plan::{DiffInputs, diff};
        use crate::schema::Target;
        use std::collections::BTreeMap;

        let resources = [res(resource)];
        diff(DiffInputs {
            resources: &resources,
            detected: &absent(&resources),
            target: &Target::local(),
            machine: &local_machine(),
            lock: None,
            pending: &BTreeMap::new(),
            var: &crate::last_run::ReportVar::unset,
        })
        .plan
    }

    /// A reviewed plan binds the scripts zap carries a `file`, `directory`, or `build`
    /// change out through, though such a change has no step that holds them: the plan
    /// holds none of their text, and its address moves with each script the change can
    /// run and with the command it runs it in — so a zap whose put, directory, extract,
    /// or snapshot script differs from the one that previewed computes another hash for
    /// the plan. A change whose steps are what it runs adds nothing.
    #[test]
    fn the_plan_address_moves_with_each_script_a_native_change_runs() {
        use crate::extract::EXTRACT_ARCHIVE;
        use crate::put::{DIR_ATTRS, FILE_PUT, FILE_SNAPSHOT, LINK_PUT, MAKE_DIRS};

        let pin = "a".repeat(64);
        let cases: [(serde_json::Value, &[&str]); 8] = [
            (
                serde_json::json!({"id": "f", "type": "file", "path": "/etc/x",
                    "content": {"type": "inline", "content": "x\n"}}),
                &[MAKE_DIRS, FILE_PUT],
            ),
            (
                serde_json::json!({"id": "f", "type": "file", "path": "/etc/x",
                    "content": {"type": "inline", "content": "x\n"}, "validate": "nginx -t"}),
                &[MAKE_DIRS, FILE_SNAPSHOT, FILE_PUT, FILE_PUT],
            ),
            (
                serde_json::json!({"id": "f", "type": "file", "path": "/etc/x",
                    "content": {"type": "source", "path": "/srv/x"}}),
                &[MAKE_DIRS, FILE_SNAPSHOT, FILE_PUT],
            ),
            (
                serde_json::json!({"id": "f", "type": "file", "path": "/opt/z",
                    "content": {"type": "remote", "url": "https://h/z", "blake3": pin}}),
                &[MAKE_DIRS, FILE_PUT],
            ),
            (
                serde_json::json!({"id": "f", "type": "file", "path": "/opt/zig",
                    "content": {"type": "remote", "url": "https://h/zig.tar.xz", "blake3": pin,
                        "extract": {"type": "tar.xz", "strip_components": 1}}}),
                &[MAKE_DIRS, EXTRACT_ARCHIVE, DIR_ATTRS],
            ),
            (
                serde_json::json!({"id": "d", "type": "directory", "path": "/opt/x", "mode": "755"}),
                &[MAKE_DIRS, DIR_ATTRS],
            ),
            (
                serde_json::json!({"id": "l", "type": "link", "path": "/opt/l", "target": "/opt/x"}),
                &[LINK_PUT],
            ),
            (
                serde_json::json!({"id": "b", "type": "build",
                    "source": {"type": "remote", "url": "https://h/g.tar.xz", "blake3": pin,
                        "extract": {"type": "tar.xz"}},
                    "run": "make install", "output": "/opt/g/bin/g"}),
                &[EXTRACT_ARCHIVE, FILE_PUT],
            ),
        ];
        for (resource, scripts) in cases {
            let plan = plan_of_resource(resource.clone());
            assert_eq!(plan.changes.len(), 1, "{resource}");
            assert_eq!(plan.changes[0].native_scripts(), scripts, "{resource}");
            let json = serde_json::to_string(&plan).unwrap();
            let address = super::plan_hash(&plan).unwrap();
            let commands = plan.changes[0].native_commands();
            assert_eq!(commands.len(), scripts.len(), "{resource}");
            for (script, command) in scripts.iter().zip(&commands) {
                assert!(
                    command.contains(script),
                    "{resource}: the command runs the script"
                );
                if [FILE_SNAPSHOT, DIR_ATTRS, MAKE_DIRS].contains(script) {
                    let timeout = format!("timeout {} sh -c", crate::put::SCRIPT_TIMEOUT_SECS);
                    assert!(command.contains(&timeout), "{resource}: {command}");
                }
                if *script == FILE_SNAPSHOT {
                    let limit = crate::put::SNAPSHOT_MAX_BYTES.to_string();
                    assert!(command.ends_with(&limit), "{resource}");
                }
            }
            // The composition around a script is bound too: who it runs as, its arguments.
            let moved = super::plan_hash_with(&plan, super::scripted_step_text, |change| {
                super::native_script_text(change)
                    .into_iter()
                    .map(|text| text.replacen("sh -c ", "sh -e -c ", 1))
                    .collect()
            })
            .unwrap();
            assert_ne!(moved, address, "{resource}: the composed command");
            // So do the limits a builder composes in: the timeout, the snapshot's size.
            let timeout = format!("timeout {} ", crate::put::SCRIPT_TIMEOUT_SECS);
            let limit = format!(" {}", crate::put::SNAPSHOT_MAX_BYTES);
            for bound in [&timeout, &limit] {
                if commands
                    .iter()
                    .any(|command| command.contains(bound.as_str()))
                {
                    let moved = super::plan_hash_with(&plan, super::scripted_step_text, |change| {
                        super::native_script_text(change)
                            .into_iter()
                            .map(|text| text.replace(bound.as_str(), " 1 "))
                            .collect()
                    })
                    .unwrap();
                    assert_ne!(moved, address, "{resource}: {bound}");
                }
            }
            for script in scripts {
                assert!(!json.contains(script), "{resource}");
                let moved = super::plan_hash_with(&plan, super::scripted_step_text, |change| {
                    super::native_script_text(change)
                        .into_iter()
                        .map(|text| text.replace(script, "edited"))
                        .collect()
                })
                .unwrap();
                assert_ne!(moved, address, "{resource}: {}", &script[..40]);
            }
        }
        // A `file`'s own write keeps what it leaves unset; a validated file's rollback and
        // a build's sidecar are fresh writes. The two are different commands, each bound.
        // An extracted archive puts nothing: its script writes the sentinel.
        let file_puts = |resource: serde_json::Value| {
            plan_of_resource(resource).changes[0]
                .native_commands()
                .into_iter()
                .filter(|command| command.contains(FILE_PUT))
                .map(|command| command.rsplit(' ').next().unwrap().to_owned())
                .collect::<Vec<_>>()
        };
        assert_eq!(
            file_puts(
                serde_json::json!({"id": "f", "type": "file", "path": "/etc/x",
                "content": {"type": "inline", "content": "x\n"}, "validate": "nginx -t"})
            ),
            ["'keep'", "''"]
        );
        assert_eq!(
            file_puts(
                serde_json::json!({"id": "f", "type": "file", "path": "/opt/zig",
                "content": {"type": "remote", "url": "https://h/zig.tar.xz", "blake3": pin,
                    "extract": {"type": "tar.xz"}}})
            ),
            Vec::<String>::new()
        );
        // A `script` runs its steps, which hold their own text.
        let script = plan_of_resource(serde_json::json!({
            "id": "s", "type": "script", "check": "true", "run": "true"
        }));
        assert_eq!(script.changes[0].native_scripts(), Vec::<&str>::new());
    }

    /// A service with a trigger records its pending marker before its first source runs,
    /// through `MAKE_DIRS`, `DIR_ATTRS`, and `FILE_PUT`: its change binds each, and moves
    /// with each. A
    /// service with no trigger records nothing.
    #[test]
    fn a_triggered_service_binds_the_scripts_its_pending_marker_is_written_with() {
        use crate::plan::{Trigger, TriggerKind};
        use crate::put::{DIR_ATTRS, FILE_PUT, MAKE_DIRS};

        let mut plan =
            plan_of_resource(serde_json::json!({"id": "s", "type": "service", "service": "web"}));
        assert_eq!(plan.changes.len(), 1);
        assert_eq!(plan.changes[0].native_scripts(), Vec::<&str>::new());
        plan.changes[0].trigger = Some(Trigger {
            kind: TriggerKind::Restart,
            sources: Vec::new(),
            pending: true,
        });
        assert_eq!(
            plan.changes[0].native_scripts(),
            [MAKE_DIRS, DIR_ATTRS, FILE_PUT]
        );
        let address = super::plan_hash(&plan).unwrap();
        for script in [MAKE_DIRS, DIR_ATTRS, FILE_PUT] {
            let moved = super::plan_hash_with(&plan, super::scripted_step_text, |change| {
                super::native_script_text(change)
                    .into_iter()
                    .map(|text| text.replace(script, "edited"))
                    .collect()
            })
            .unwrap();
            assert_ne!(moved, address, "{}", &script[..40]);
        }
    }

    /// Every field of every typed step is part of the plan's address.
    #[test]
    fn the_plan_address_moves_with_each_field_of_a_typed_step() {
        let steps = typed_steps();
        let address =
            |steps: &[serde_json::Value]| super::plan_hash(&plan_of(steps_of(steps))).unwrap();
        let edits: [(usize, &str, serde_json::Value); 24] = [
            (0, "/put/path", serde_json::json!("/etc/sudoers.d/other")),
            (0, "/put/run_as", serde_json::json!({"user": "deploy"})),
            (0, "/put/check", serde_json::json!("none")),
            (0, "/put/source/text/mode", serde_json::json!("400")),
            (
                0,
                "/put/source/text/content",
                serde_json::json!("deploy ALL=(ALL) NOPASSWD: ALL\n"),
            ),
            (1, "/put/path", serde_json::json!("/etc/fstab2")),
            (1, "/put/run_as", serde_json::json!("root")),
            (1, "/put/check", serde_json::json!("sudoers")),
            (
                1,
                "/put/source/command/mode",
                serde_json::json!({"set": "644"}),
            ),
            (
                1,
                "/put/source/command/mode/keep/if_new",
                serde_json::json!("600"),
            ),
            (
                1,
                "/put/source/command/producer/fstab_swap_entry/path",
                serde_json::json!("/swapfile2"),
            ),
            (
                1,
                "/put/source/command/producer",
                serde_json::json!({"apt_source_line": {"line": "/swapfile"}}),
            ),
            (
                4,
                "/put/source/command/producer/apt_source_line/line",
                serde_json::json!("deb https://e.x/apt testing main"),
            ),
            (
                5,
                "/put/source/command/producer/authorized_keys_of/account",
                serde_json::json!("admin"),
            ),
            (6, "/installer/url", serde_json::json!("https://e.x/j.sh")),
            (6, "/installer/shell", serde_json::json!("bash")),
            (2, "/dir/path", serde_json::json!("/home/deploy/.ssh2")),
            (2, "/dir/mode", serde_json::json!("750")),
            (2, "/dir/owner", serde_json::json!("root")),
            (2, "/dir/group", serde_json::json!("root")),
            (3, "/pg_hba_rule/database", serde_json::json!("other")),
            (3, "/pg_hba_rule/user", serde_json::json!("other")),
            (3, "/pg_hba_rule/host", serde_json::json!("127.0.0.1/32")),
            (7, "/swap_check/path", serde_json::json!("/swap/file")),
        ];
        let mut seen = std::collections::BTreeSet::new();
        seen.insert(address(&steps));
        for (index, pointer, value) in edits {
            let mut edited = steps.clone();
            *edited[index]
                .pointer_mut(pointer)
                .unwrap_or_else(|| panic!("no {pointer}")) = value;
            assert!(seen.insert(address(&edited)), "{index} {pointer}");
        }
        let mut method = steps.clone();
        method[3]["pg_hba_rule"]["method"] = serde_json::json!("md5");
        assert!(seen.insert(address(&method)), "pg_hba_rule method");
        // The order of the steps is part of it too.
        let mut reordered = steps;
        reordered.swap(2, 3);
        assert!(seen.insert(address(&reordered)));
    }

    #[test]
    fn a_lock_entry_address_is_byte_stable() {
        // A tracked `remote` file with its lock pin folded in — the address every
        // `zap.lock` entry's `config_hash` records, pinned for a real-shaped resource (an
        // operator `auth` credential, a literal `$HOME`, identity fields). The address
        // folds `RESOURCE_HASH_VERSION`'s value, the canonical JSON of the captured
        // fields (`auth` and identity excluded, `$HOME` literal), and the pin under
        // `__lock_pin`. A change to any of them moves it, and every consumer's pin would
        // then read stale; renaming the constant or its domain must not.
        let ghostty = res(serde_json::json!({
            "id": "ghostty", "name": "Ghostty terminal (prebuilt)", "type": "file",
            "path": "$HOME/.local/bin/ghostty", "mode": "755",
            "content": {
                "type": "remote",
                "url": "https://files.example.com/api/files/ghostty-linux-x86_64",
                "extract": {"type": "none"},
                "auth": {"scheme": "bearer", "token": Text::reference("FILES_TOKEN")},
            },
            "depends_on": ["files-api-token"],
        }));
        let entry = LockEntry::RemoteFile {
            config_hash: String::new(),
            blake3: ContentHash::new(
                "b9835f3bca0fe620f7b682c45ff1be58cc529c7980a1ebf9ab1e3c409f36041c",
            )
            .unwrap(),
        };
        assert_eq!(
            compute_config_hash(&ghostty, identity, Some(&entry)).unwrap(),
            "dca386475f816bcd78408560c0a78ddcf7dfc20c7e1f825bfaefd9bce8cce9f8",
        );
    }

    #[test]
    fn a_build_entry_address_is_byte_stable() {
        // A tracked `build` with its lock pin folded in — the address a `zap.lock` build
        // entry's `config_hash` records. `run` and each `env` value are folded in their
        // typed wire form — a plain string, `{"$env": "NAME"}` for a whole reference,
        // `{"$text": [...]}` for a mix — so a reference in either is part of the address
        // as written, and a change to that form would read stale the pin of every
        // tracked build that holds one. Pinned here with a mixed `run` and a
        // whole-reference `env` value.
        //
        // Regenerate when `RESOURCE_HASH_VERSION` bumps — it *should* move then; run
        // the test and copy the actual value. Never hand-edit toward a guess.
        let build = res(serde_json::json!({
            "id": "tool", "name": "Tool (from source)", "type": "build",
            "source": {
                "type": "remote",
                "url": "https://files.example.com/tool-1.2.3.tar.xz",
                "extract": {"type": "tar.xz"},
            },
            "run": Text::of_pieces([Lit("make install PREFIX="), Ref("PREFIX")]),
            "output": "/opt/tool/bin/tool",
            "env": {"JOBS": Text::reference("BUILD_JOBS")},
        }));
        let entry = LockEntry::Build {
            config_hash: String::new(),
            blake3: ContentHash::new(PIN_A).unwrap(),
        };
        assert_eq!(
            compute_config_hash(&build, identity, Some(&entry)).unwrap(),
            "f308ef14ce377888d987fc5d7a08e78617d10bc2455f3729f27aede36fdd83f5",
        );
    }

    /// Inline content is hashed as written, never resolved: the marker the env-only
    /// resolver would substitute, a literal `$$VAR$$`, and a `~` all pass through.
    #[test]
    fn inline_content_is_hashed_verbatim() {
        let env_only = |input: &str| input.replace(&marker("DIR"), "/srv/app");
        let written = format!("literal ~/$$NOPE$$ {}\n", marker("DIR"));
        assert_ne!(env_only(&written), written);
        let resource = res(serde_json::json!({
            "id": "f", "type": "file", "path": "/etc/f",
            "content": {"type": "inline", "content": written},
        }));
        let inputs = ConfigHashInputs::collect(&resource, env_only, None).unwrap();
        assert_eq!(
            inputs.fields()["rendered_content"],
            serde_json::Value::String(written)
        );
    }

    #[test]
    fn captured_fields_exclude_identity() {
        // `fields()` is the inspectable captured desired state — identity stripped, so
        // the leak-surface contract ("everything not here is uncaptured") is checkable.
        let resource = res(serde_json::json!({
            "id": "d", "name": "a dir", "type": "directory", "path": "/opt/x",
        }));
        let inputs = ConfigHashInputs::collect(&resource, identity, None).unwrap();
        let fields = inputs.fields();
        assert!(!fields.contains_key("id"));
        assert!(!fields.contains_key("name"));
        assert!(!fields.contains_key("depends_on"));
        assert_eq!(fields.get("path"), Some(&serde_json::json!("/opt/x")));
    }

    /// The machine zap runs on, as a fixture names it.
    fn local_machine() -> crate::plan::Machine {
        crate::plan::Machine::Local(crate::plan::LocalAccount {
            user: "op".to_owned(),
            home: Some("/home/op".to_owned()),
        })
    }

    /// The build in `json`, a `build` resource.
    fn build_of(json: serde_json::Value) -> crate::schema::BuildResource {
        match res(json).kind {
            crate::schema::ResourceKind::Build(build) => build,
            other => panic!("not a build: {other:?}"),
        }
    }

    #[test]
    fn build_provenance_moves_with_the_pin_and_every_build_field() {
        let base = serde_json::json!({
            "id": "b", "type": "build", "output": "/opt/x/bin/x", "run": "make",
            "source": {"type": "remote", "url": "https://h/x.tar.gz", "extract": {"type": "tar.gz"}}
        });
        let provenance = |edit: &dyn Fn(&mut serde_json::Value), pin: &str| {
            let mut json = base.clone();
            edit(&mut json);
            super::build_provenance(pin, &build_of(json))
        };
        let same = provenance(&|_| {}, PIN_A);
        // Pinned, so a change to the tag, the version, or the layout fails here.
        assert_eq!(
            same,
            "33853fdcb7c1d5c4bf16352311a69546de79666e104259b33b6fe761b710e775"
        );
        let edits: [&dyn Fn(&mut serde_json::Value); 5] = [
            &|json| json["run"] = "make install".into(),
            &|json| json["cwd"] = "/src".into(),
            &|json| json["env"] = serde_json::json!({"CC": "clang"}),
            &|json| json["source"]["extract"] = serde_json::json!({"type": "tar.xz"}),
            &|json| {
                json["source"]["extract"] =
                    serde_json::json!({"type": "tar.gz", "strip_components": 1});
            },
        ];
        for edit in edits {
            assert_ne!(provenance(edit, PIN_A), same);
        }
        assert_ne!(provenance(&|_| {}, PIN_B), same);
        // Neither the output path, the url, nor the verify block is part of it.
        assert_eq!(
            provenance(
                &|json| json["source"]["url"] = "https://h/y.tar.gz".into(),
                PIN_A
            ),
            same
        );
    }

    #[test]
    fn extract_provenance_moves_with_the_pin_and_the_strip_count() {
        use crate::schema::ExtractMode;
        let tar = |strip_components| ExtractMode::TarXz { strip_components };
        let same = super::extract_provenance(PIN_A, tar(0));
        assert_eq!(same.len(), 64);
        assert_ne!(super::extract_provenance(PIN_A, tar(1)), same);
        assert_ne!(super::extract_provenance(PIN_B, tar(0)), same);
        assert_ne!(
            super::extract_provenance(
                PIN_A,
                ExtractMode::TarGz {
                    strip_components: 0
                }
            ),
            same
        );
        // Never a bare pin, which is what an older sentinel holds: it reads as drift.
        assert_ne!(same, PIN_A);
    }
}
