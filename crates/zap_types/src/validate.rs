//! Pure config validators.
//!
//! Checks over a parsed config that the schema's types can't express — a rule
//! relating two resources, or a field to the target. Pure: they read the parsed
//! config and return findings, no IO.

use std::collections::{BTreeMap, BTreeSet};

use crate::scalar::EnvVarName;

use crate::fetch_url::{FetchSide, fetch_url_problem, written_fetch_url_problem};
use crate::postgres::{PgHbaField, pg_hba_field_problem, pg_hba_written_problem};
use crate::schema::{
    DeploySpec, FileContent, FirewallAllowRule, FirewallBackend, ResolvedField, Resource,
    ResourceId, ResourceKind, ResourceType, ServiceManager, SshKeys, Target, TemplatePiece,
    UserResource, ZapConfig, path_matches,
};
use crate::text::{TEXT_KEY, wire_literals};

/// Resource ids that appear more than once (sorted, deduplicated).
///
/// Identity must be unique: the plan, the lock, the last-run report, the detection
/// map, and the dependency graph all key on `resource_id`, so a duplicate silently
/// collapses edges and clobbers detections — a wrong plan with no error. The
/// planner treats any duplicate as fatal (empty plan + warning), the same as a
/// dependency cycle. An empty result means the ids are unique.
#[must_use]
pub fn duplicate_resource_ids(resources: &[Resource]) -> Vec<ResourceId> {
    let mut seen: BTreeSet<&str> = BTreeSet::new();
    let mut duplicates: BTreeSet<ResourceId> = BTreeSet::new();
    for resource in resources {
        if !seen.insert(resource.id.0.as_str()) {
            duplicates.insert(resource.id.clone());
        }
    }
    duplicates.into_iter().collect()
}

/// Structural reference errors — a reference that doesn't resolve to a declared resource.
///
/// Covers `depends_on`, service `restart_on` / `reload_on`, and file `triggers` (which
/// must name a *service* — triggers only restart services). Each unresolved reference is
/// a config bug that would otherwise silently drop a dependency edge or a restart and
/// **converge to a wrong state with no error** — the one failure a convergence tool
/// exists to prevent — so the planner gate (`zap_core`) rejects them at `plan` time,
/// before any detection runs. Returns one message per offending reference; an empty
/// result means every reference resolves. (Intra-config cycles are caught by
/// [`crate::plan::dependency_cycle`], not here.) An id that is no name is
/// [`unusable_resource_ids`]' finding, and is not reported again as unknown.
#[must_use]
pub fn unresolved_references(resources: &[Resource]) -> Vec<String> {
    let kinds: BTreeMap<&str, ResourceType> = resources
        .iter()
        .map(|resource| (resource.id.0.as_str(), resource.kind()))
        .collect();
    let known = |id: &ResourceId| kinds.contains_key(id.0.as_str()) || !id.is_name();

    let mut errors = Vec::new();
    for resource in resources {
        let id = &resource.id.0;
        for dep in &resource.depends_on {
            if !known(dep) {
                errors.push(format!(
                    "resource `{id}` depends_on unknown resource `{}`",
                    dep.0
                ));
            }
        }
        match &resource.kind {
            ResourceKind::Service(service) => {
                for (field, ids) in [
                    ("restart_on", &service.restart_on),
                    ("reload_on", &service.reload_on),
                ] {
                    for target_id in ids.iter().flatten() {
                        if !known(target_id) {
                            errors.push(format!(
                                "service `{id}` {field} references unknown resource `{}`",
                                target_id.0
                            ));
                        }
                    }
                }
            }
            ResourceKind::File(file) => {
                for target_id in file.triggers.iter().flatten() {
                    match kinds.get(target_id.0.as_str()) {
                        None if !target_id.is_name() => {}
                        None => errors.push(format!(
                            "file `{id}` triggers unknown resource `{}`",
                            target_id.0
                        )),
                        Some(ResourceType::Service) => {}
                        Some(_) => errors.push(format!(
                            "file `{id}` triggers non-service resource `{}` (triggers only restart services)",
                            target_id.0
                        )),
                    }
                }
            }
            _ => {}
        }
    }
    errors
}

/// Triggers on a service declared `running: false`.
///
/// A trigger restarts or reloads only a running service, and this one is kept stopped,
/// so its `restart_on` / `reload_on`, or a file's `triggers` naming it, would never act:
/// a declared restart that silently does nothing. Returns one message per offending
/// declaration.
#[must_use]
pub fn triggers_on_stopped_services(resources: &[Resource]) -> Vec<String> {
    let stopped: BTreeSet<&str> = resources
        .iter()
        .filter(|resource| {
            matches!(&resource.kind, ResourceKind::Service(service) if service.running == Some(false))
        })
        .map(|resource| resource.id.0.as_str())
        .collect();
    let mut errors = Vec::new();
    for resource in resources {
        let id = &resource.id.0;
        match &resource.kind {
            ResourceKind::Service(service) if stopped.contains(id.as_str()) => {
                for (field, ids) in [
                    ("restart_on", &service.restart_on),
                    ("reload_on", &service.reload_on),
                ] {
                    if ids.as_ref().is_some_and(|ids| !ids.is_empty()) {
                        errors.push(format!(
                            "service `{id}` sets `{field}` but `running: false`: a trigger \
                             restarts or reloads only a running service"
                        ));
                    }
                }
            }
            ResourceKind::File(file) => {
                for target_id in file.triggers.iter().flatten() {
                    if stopped.contains(target_id.0.as_str()) {
                        errors.push(format!(
                            "file `{id}` triggers service `{}`, which sets `running: false`: a \
                             trigger restarts or reloads only a running service",
                            target_id.0
                        ));
                    }
                }
            }
            _ => {}
        }
    }
    errors
}

/// `pipeline` features the **sequential** executor does not honor.
///
/// Returns a message per pipeline that declares one, so a config can't quietly lose a
/// step's `cwd` / `env` / `depends_on`, the pipeline's shared `env`, or a
/// `max_concurrency > 1` it expects to be honored. Rejecting them keeps zap's
/// "never silently ignore declared intent" contract; `name`
/// is a label the plan prints, so it is kept. Empty means clean.
#[must_use]
pub fn unsupported_pipeline_features(resources: &[Resource]) -> Vec<String> {
    let mut errors = Vec::new();
    for resource in resources {
        let ResourceKind::Pipeline(pipeline) = &resource.kind else {
            continue;
        };
        let id = &resource.id.0;
        if pipeline.env.is_some() {
            errors.push(format!(
                "pipeline `{id}` sets `env`, which the sequential executor doesn't apply \
                 (inline the vars into each step's `run`)"
            ));
        }
        if pipeline.max_concurrency.is_some_and(|n| n.get() > 1) {
            errors.push(format!(
                "pipeline `{id}` sets `max_concurrency` > 1, but the executor runs steps one \
                 at a time (remove it)"
            ));
        }
        for step in &pipeline.steps {
            let mut dropped = Vec::new();
            // what to inline into the step's `run` instead
            let mut inline = Vec::new();
            if step.cwd.is_some() {
                dropped.push("cwd");
                inline.push("a `cd`");
            }
            if step.env.is_some() {
                dropped.push("env");
                inline.push("the vars");
            }
            let mut remedies = Vec::new();
            if !inline.is_empty() {
                remedies.push(format!(
                    "inline {} into the step's `run`",
                    inline.join(" and ")
                ));
            }
            if step.depends_on.is_some() {
                dropped.push("depends_on");
                remedies.push(
                    "steps run in declared order, so order them instead of `depends_on`".to_owned(),
                );
            }
            if !dropped.is_empty() {
                errors.push(format!(
                    "pipeline `{id}` step `{}` sets {}, which the sequential executor doesn't \
                     apply ({})",
                    step.id,
                    dropped.join(" / "),
                    remedies.join("; ")
                ));
            }
        }
    }
    errors
}

/// `pipeline` step ids that appear more than once within their pipeline.
///
/// A step's id is what names it within the pipeline: a step's `depends_on` would name
/// the steps it follows by id, so two steps with one id leave the name meaning either.
/// Returns one message per pipeline and repeated id, in the order the id first repeats.
/// Empty means every pipeline's step ids are unique.
#[must_use]
pub fn duplicate_pipeline_step_ids(resources: &[Resource]) -> Vec<String> {
    let mut errors = Vec::new();
    for resource in resources {
        let ResourceKind::Pipeline(pipeline) = &resource.kind else {
            continue;
        };
        let mut seen: BTreeSet<&str> = BTreeSet::new();
        let mut reported: BTreeSet<&str> = BTreeSet::new();
        for step in &pipeline.steps {
            let step_id = step.id.as_str();
            if !seen.insert(step_id) && reported.insert(step_id) {
                errors.push(format!(
                    "pipeline `{}` has more than one step with the id `{step_id}`; each step's \
                     id must be unique within its pipeline",
                    resource.id.0
                ));
            }
        }
    }
    errors
}

/// Firewall allow rules a backend can't express.
///
/// nftables has no application-profile concept (a ufw-only feature), so a `Named` allow
/// rule (`OpenSSH`, `Nginx Full`) under the nftables backend has no nft form — the step
/// builder would silently skip it, leaving a port unintentionally closed. A closed-port
/// surprise on a *security control* is exactly the silent-wrong-convergence this gate
/// exists to prevent, so it's a hard error at `plan`: rewrite the rule as a port/proto
/// pair (`{port: 22, proto: 'tcp'}`). Empty means clean.
#[must_use]
pub fn unsupported_firewall_rules(resources: &[Resource]) -> Vec<String> {
    let mut errors = Vec::new();
    for resource in resources {
        let ResourceKind::Firewall(firewall) = &resource.kind else {
            continue;
        };
        if firewall.backend != FirewallBackend::Nftables {
            continue;
        }
        for rule in &firewall.allow {
            if let FirewallAllowRule::Named(name) = rule {
                errors.push(format!(
                    "firewall `{}` uses the named profile `{name}` with the nftables backend, \
                     which has no application profiles — use a port/proto rule \
                     (e.g. {{port: 22, proto: 'tcp'}})",
                    resource.id.0
                ));
            }
        }
    }
    errors
}

/// `user` resources whose explicit `ssh_keys.keys` holds no key.
///
/// An empty list — or one whose every entry is blank — renders an empty
/// `authorized_keys`, which detection reads as missing: the resource could never
/// converge, and with the password field held at the disabled `*` the account would take
/// no login at all. Declare at least one key, or leave `ssh_keys` out. Empty means clean.
#[must_use]
pub fn empty_ssh_keys(resources: &[Resource]) -> Vec<String> {
    resources
        .iter()
        .filter_map(|resource| match &resource.kind {
            ResourceKind::User(UserResource {
                ssh_keys: Some(SshKeys::Keys { keys }),
                ..
            }) if keys.iter().all(|key| key.trim().is_empty()) => Some(format!(
                "user `{}` declares `ssh_keys.keys` with no key — declare at least one, or \
                 leave `ssh_keys` out",
                resource.id.0
            )),
            _ => None,
        })
        .collect()
}

/// `user` resources named `root`.
///
/// zap manages a user's home as `/home/<name>`
/// ([`user_home_dir`](crate::schema::user_home_dir)): its `home_mode` and `ssh_keys`
/// paths are derived from the name at plan time, never read from the target. root's
/// home is `/root`, so those would land in a `/home/root` the account doesn't use; a
/// `user` named `root` is refused whatever it declares. Manage root's files with `file`
/// and `directory` resources. Empty means clean.
#[must_use]
pub fn managed_root_user(resources: &[Resource]) -> Vec<String> {
    resources
        .iter()
        .filter_map(|resource| match &resource.kind {
            ResourceKind::User(user) if user.username.as_str() == "root" => Some(format!(
                "user `{}` declares `username: 'root'`, whose home is /root, but zap manages \
                 a user's home as /home/<name>, so it can't manage root (manage root's files \
                 with `file` and `directory` resources)",
                resource.id.0
            )),
            _ => None,
        })
        .collect()
}

/// An nftables firewall declared without a companion persistence service.
///
/// ufw persists its own rules; the nftables backend writes `/etc/nftables.nft` and loads
/// it once with `nft -f`, so without the nftables service loading that file at boot the
/// rules silently vanish on the next reboot — a closed-port surprise on a security
/// control. That the firewall needs a co-present service is an invariant the schema can't
/// express, so it's a hard error here (the same posture as [`unsupported_firewall_rules`]):
/// an nftables firewall with no enabled `service: 'nftables'` in the same config is
/// rejected at `plan`. Empty means every nftables firewall has its persistence service.
#[must_use]
pub fn missing_firewall_persistence(resources: &[Resource]) -> Vec<String> {
    let has_nftables_service = resources.iter().any(|resource| {
        matches!(
            &resource.kind,
            ResourceKind::Service(service) if &*service.service == "nftables" && service.enabled
        )
    });
    if has_nftables_service {
        return Vec::new();
    }
    resources
        .iter()
        .filter_map(|resource| {
            let ResourceKind::Firewall(firewall) = &resource.kind else {
                return None;
            };
            (firewall.backend == FirewallBackend::Nftables).then(|| {
                format!(
                    "firewall `{}` uses the nftables backend but no enabled \
                     `service: 'nftables'` is declared — `nft -f` loads the ruleset once, so \
                     the rules would not survive a reboot; declare a `service` resource \
                     (service: 'nftables', enabled: true) to reload /etc/nftables.nft at boot",
                    resource.id.0
                )
            })
        })
        .collect()
}

/// Findings for *service intent* on a target that declares no `service_manager`.
///
/// Service intent is anything the planner turns into a manager verb: a `service`
/// resource (enable / start, and its `restart_on` / `reload_on`), a `file` with
/// `triggers` (a restart), and `deploy.service` (the post-swap restart). A `database`
/// is not one: its added `pg_hba` rule is put in force by `pg_reload_conf()`, which asks
/// the server, not its manager. Without a declared manager there is no
/// honest verb to emit — guessing `systemctl` on a host that may run `OpenRC`, or
/// silently dropping deploy's restart so the release health-checks the *old* process,
/// are both fabricated machine state. The rule is *detect or declare, never guess*, so
/// an undeclared manager with service intent is a config error at `plan`. A
/// declared-but-unsupported manager (`launchd`) is a different case and not this
/// check's: it parses, detects as `undetermined`, and plans a `Note` in place of each
/// verb.
///
/// Empty when a manager is declared or nothing needs one.
#[must_use]
pub fn missing_service_manager(
    resources: &[Resource],
    deploy: Option<&DeploySpec>,
    service_manager: Option<ServiceManager>,
) -> Vec<String> {
    if service_manager.is_some() {
        return Vec::new();
    }
    let mut intents: Vec<String> = resources
        .iter()
        .filter_map(|resource| {
            let what = match &resource.kind {
                ResourceKind::Service(_) => "service",
                ResourceKind::File(file)
                    if file.triggers.as_ref().is_some_and(|ids| !ids.is_empty()) =>
                {
                    "file with `triggers`"
                }
                _ => return None,
            };
            Some(format!("{what} `{}`", resource.id.0))
        })
        .collect();
    if let Some(service) = deploy.and_then(|deploy| deploy.service.as_ref()) {
        intents.push(format!("`deploy.service` `{service}`"));
    }
    if intents.is_empty() {
        return Vec::new();
    }
    vec![format!(
        "the target declares no `service_manager`, but the config needs one for: {} — \
         declare `service_manager: 'systemd'` (or `'openrc'`) on `zap.target`",
        intents.join(", ")
    )]
}

/// `file` resources whose `validate` can't be honored.
///
/// A blank command would pass vacuously (`sh -c ''` exits 0). A `remote` file is
/// rejected too: an extracting one materializes a directory tree the executor can't
/// snapshot, and a copied one is an artifact (a binary) whose snapshot would pull the
/// whole prior file over the wire for a check nobody writes. `validate` is for text
/// config — `inline`, `template`, `source`. Empty means clean.
#[must_use]
pub fn unsupported_file_validate(resources: &[Resource]) -> Vec<String> {
    let mut errors = Vec::new();
    for resource in resources {
        let ResourceKind::File(file) = &resource.kind else {
            continue;
        };
        let Some(validate) = &file.validate else {
            continue;
        };
        let id = &resource.id.0;
        if validate.is_blank() {
            errors.push(format!(
                "file `{id}` sets an empty `validate`, which would pass every write \
                 (set a command, or remove `validate`)"
            ));
        }
        if matches!(file.content, FileContent::Remote(_)) {
            errors.push(format!(
                "file `{id}` sets `validate` on `remote` content; `validate` gates text \
                 config (`inline` / `template` / `source`), so remove it or check the \
                 artifact with a `verify` resource"
            ));
        }
    }
    errors
}

/// Resource fields that hold a NUL byte, one finding each.
///
/// Every string a resource declares ends up in a shell command or a path — a `script`'s
/// `check` / `cwd` / `env` values, a `verify` assertion's `run` / `expect` / `path`, a
/// `package`'s `check` and names, every path zap reads or writes — and none of those can
/// carry a NUL: a shell drops it silently (so `test -d /e<NUL>tc` would run as
/// `test -d /etc` and read converged), and a path or argv can't hold one at all. So a
/// NUL anywhere in a resource is a config error — except in a `file`'s `inline` content
/// and `template` body and vars, which are written as bytes, never to a shell. Each
/// finding names the field by its path in the resource (`env.KEY`, `assertions[1].run`).
#[must_use]
pub fn nul_bytes(resources: &[Resource]) -> Vec<String> {
    let mut errors = Vec::new();
    for resource in resources {
        let Ok(value) = serde_json::to_value(resource) else {
            // Unreachable for a parsed resource, but a resource this gate can't read is
            // one it can't vouch for: a finding, never a pass.
            errors.push(format!(
                "resource `{}` couldn't be checked for NUL bytes",
                resource.id.0.replace('\0', "\\0")
            ));
            continue;
        };
        let file = matches!(resource.kind, ResourceKind::File(_));
        let mut found = Vec::new();
        walk_nul(&value, "", file, &mut found);
        for field in found {
            errors.push(format!(
                "resource `{}`: `{field}` {NUL_FINDING}",
                resource.id.0.replace('\0', "\\0")
            ));
        }
    }
    errors
}

/// The tail of a NUL finding.
const NUL_FINDING: &str = "contains a NUL byte, which no shell command or path can carry (a \
     shell would drop it and run a different command)";

/// Fields of the `target` and the `deploy` block that hold a NUL byte, one finding each.
///
/// [`nul_bytes`]' counterpart for the config's non-resource strings: the connection
/// identity (on `ssh`'s argv), the declared `home` (in every remote path), and the deploy
/// block's paths, commands, and names (in the scripts a deploy runs on the target). Each
/// finding names the field by its path (`target.home`, `deploy.prepare[0]`).
#[must_use]
pub fn config_nul_bytes(target: &Target, deploy: Option<&DeploySpec>) -> Vec<String> {
    let mut found = Vec::new();
    let mut unchecked = Vec::new();
    match serde_json::to_value(target) {
        Ok(value) => walk_nul(&value, "target", false, &mut found),
        Err(_) => unchecked.push("`target` couldn't be checked for NUL bytes".to_owned()),
    }
    if let Some(deploy) = deploy {
        match serde_json::to_value(deploy) {
            Ok(value) => walk_nul(&value, "deploy", false, &mut found),
            Err(_) => unchecked.push("`deploy` couldn't be checked for NUL bytes".to_owned()),
        }
    }
    found
        .into_iter()
        .map(|field| format!("`{field}` {NUL_FINDING}"))
        .chain(unchecked)
        .collect()
}

/// The paths (`a.b[1].c`) of every string in `value` that holds a NUL byte — a map key
/// too — skipping a `file`'s content (`file`: inline content, template body and vars).
fn walk_nul(value: &serde_json::Value, path: &str, file: bool, found: &mut Vec<String>) {
    let content = file && matches!(path, "content.content" | "content.template");
    let vars = file && (path == "content.vars" || path.starts_with("content.vars."));
    // A field that takes a reference is one field, however its text is spelled on the
    // wire: its literal pieces are checked, and a reference's name holds no NUL.
    if let Some(literals) = wire_literals(value) {
        if literals.iter().any(|text| text.contains('\0')) && !content && !vars {
            found.push(path.to_owned());
        }
        return;
    }
    match value {
        serde_json::Value::Array(items) => {
            for (index, item) in items.iter().enumerate() {
                walk_nul(item, &format!("{path}[{index}]"), file, found);
            }
        }
        serde_json::Value::Object(fields) if !vars => {
            for (key, field) in fields {
                // A map key is a string too (an `env` name, a package manager).
                let at = if path.is_empty() {
                    key.clone()
                } else {
                    format!("{path}.{key}")
                };
                if key.contains('\0') {
                    found.push(format!("{at} (its name)"));
                }
                walk_nul(field, &at, file, found);
            }
        }
        _ => {}
    }
}

/// A `deploy.path` that isn't an absolute path, as a finding.
///
/// The path is single-quoted into the release script and is where the archive is
/// installed, so it is used as written — `~` is not expanded, and it takes no reference
/// — and a relative one would be taken from wherever the connecting user's session
/// starts.
#[must_use]
pub fn unusable_deploy_path(deploy: Option<&DeploySpec>) -> Vec<String> {
    let Some(path) = deploy.map(|deploy| deploy.path.as_str()) else {
        return Vec::new();
    };
    let mut errors = Vec::new();
    if !path.starts_with('/') {
        errors.push(
            "`deploy.path` is not an absolute path; the release is installed under it as \
             written, `~` is not expanded, and a relative path would start from the \
             connecting user's login directory; write the full path"
                .to_owned(),
        );
    }
    errors
}

/// Each `deploy.shared` entry the release script can't use as written, one finding each.
///
/// An entry names a file under the app's `shared/` directory, and is linked at the same
/// name in each release. So an entry is a relative path that names a file — not one
/// that ends in `/` or in a `.` component, which names a directory — with no `..`
/// component (which would name a file outside `shared/`, and link outside the release)
/// and no control character, which no preview could show as the name it is. Any other
/// character is the file's own: the release script single-quotes the entry wherever it
/// stands. A NUL is [`config_nul_bytes`]' finding, and not repeated here.
///
/// Each finding names the entry by its index and quotes it.
#[must_use]
pub fn unusable_deploy_shared(deploy: Option<&DeploySpec>) -> Vec<String> {
    let Some(deploy) = deploy else {
        return Vec::new();
    };
    deploy
        .shared
        .iter()
        .enumerate()
        .filter_map(|(index, entry)| {
            let reason = if entry.is_empty() {
                "is empty; it names a file under the app's `shared/` directory"
            } else if entry.starts_with('/') {
                "is an absolute path; a shared file is named relative to the app's `shared/` \
                 directory"
            } else if entry.ends_with('/') || entry.rsplit('/').next() == Some(".") {
                "names a directory, not a file (it ends in `/` or `.`); a shared entry is a \
                 file linked into each release"
            } else if entry.split('/').any(|component| component == "..") {
                "holds a `..` component, which would name a file outside the app's `shared/` \
                 directory and link it outside the release"
            } else if entry.chars().any(|c| c.is_control() && c != '\0') {
                "holds a control character, which a file's name in a preview and in the \
                 release script's messages can't show; rename the file"
            } else {
                return None;
            };
            Some(format!("`deploy.shared[{index}]` (`{entry}`) {reason}"))
        })
        .collect()
}

/// Each `deploy.artifacts` entry `tar` would read as something other than the path it
/// is, one finding each.
///
/// The entries are the operands of the local `tar` that packs the release, each
/// single-quoted — which keeps a shell from reading one, and not `tar`: an operand that
/// begins with `-` is an option to it, whatever the quoting, and one that begins with
/// `@` is, to a BSD `tar`, an archive whose entries it packs in place of the file. A
/// blank entry is [`unusable_strings`]' finding.
#[must_use]
pub fn unusable_deploy_artifacts(deploy: Option<&DeploySpec>) -> Vec<String> {
    let Some(deploy) = deploy else {
        return Vec::new();
    };
    deploy
        .artifacts
        .iter()
        .enumerate()
        .filter_map(|(index, entry)| {
            let reason = match entry.chars().next() {
                Some('-') => "begins with `-`, which `tar` would read as an option",
                Some('@') => {
                    "begins with `@`, which a BSD `tar` would read as an archive to copy \
                     entries from"
                }
                _ => return None,
            };
            Some(format!(
                "`deploy.artifacts[{index}]` (`{entry}`) {reason}; write the path with a \
                 leading `./`"
            ))
        })
        .collect()
}

/// A `script`'s `cwd` that isn't an absolute path, one finding each.
///
/// A script's `check` and its `run` each enter `cwd` from where they start — the login
/// home over SSH, zap's own directory on a local target — so only an absolute path names
/// one directory for both, on every connection (`~` is not expanded, and an empty path
/// is no directory). A `cwd` is entered as declared and takes no reference.
///
/// A `build`'s relative `cwd` is not a finding here: it is taken under the extracted
/// source directory, the one place a build starts from on every connection.
#[must_use]
pub fn unusable_working_directories(resources: &[Resource]) -> Vec<String> {
    let mut errors = Vec::new();
    for resource in resources {
        let id = &resource.id.0;
        let ResourceKind::Script(script) = &resource.kind else {
            continue;
        };
        let Some(cwd) = script.cwd.as_deref() else {
            continue;
        };
        if !cwd.starts_with('/') {
            errors.push(format!(
                "resource `{id}`: `cwd` is not an absolute path; the check and the `run` \
                 each enter it from where they start, which differs by connection, and \
                 `~` is not expanded; write the full path"
            ));
        }
    }
    errors
}

/// The names an `env` map declares.
fn env_names<V>(env: Option<&BTreeMap<EnvVarName, V>>) -> Vec<&EnvVarName> {
    env.into_iter().flat_map(BTreeMap::keys).collect()
}

/// `env` names that begin with `__zap_`, one finding each — in a `script`'s, a
/// `build`'s, and a `pipeline`'s (and its steps') `env`.
///
/// `__zap_` is the namespace of the variables zap's own command wrapper uses on the
/// target. A local command's wrapper overwrites and unsets them, while a remote
/// command's `env` is exported after that, so a name there would reach a command on one
/// kind of target and not the other. (Checked here, not in
/// [`EnvVarName`], which also names the references
/// `mask` / `unmask` list — operator-environment names the wrapper never sees.)
#[must_use]
pub fn reserved_env_names(resources: &[Resource]) -> Vec<String> {
    let mut errors = Vec::new();
    for resource in resources {
        let mut maps: Vec<(String, Vec<&EnvVarName>)> = Vec::new();
        match &resource.kind {
            ResourceKind::Script(script) => {
                maps.push(("env".to_owned(), env_names(script.env.as_ref())));
            }
            ResourceKind::Build(build) => {
                maps.push(("env".to_owned(), env_names(build.env.as_ref())));
            }
            ResourceKind::Pipeline(pipeline) => {
                maps.push(("env".to_owned(), env_names(pipeline.env.as_ref())));
                for (index, step) in pipeline.steps.iter().enumerate() {
                    maps.push((format!("steps[{index}].env"), env_names(step.env.as_ref())));
                }
            }
            _ => {}
        }
        for (field, names) in maps {
            for name in names {
                if name.starts_with(RESERVED_ENV_PREFIX) {
                    errors.push(format!(
                        "resource `{}`: `{field}.{name}` uses a name beginning with \
                         `{RESERVED_ENV_PREFIX}`, which zap reserves for the variables of \
                         its own command wrapper; rename it",
                        resource.id.0
                    ));
                }
            }
        }
    }
    errors
}

/// The prefix of the shell variables zap's command wrapper uses on the target.
pub const RESERVED_ENV_PREFIX: &str = "__zap_";

/// Findings for a `deploy` block whose declared health gate has a blank `domain`.
///
/// Nesting `domain` inside [`DeployHealth`](crate::schema::DeployHealth) already makes
/// "health with no domain" unrepresentable, so the one bad state the type still permits
/// is the empty string — from a mis-templated constant, say. It would build `https:///…`
/// and fail every poll. Note this checks the **literal**: a reference is
/// non-blank here by construction, and an unset one is the env preflight's business
/// (`zap_core::commands::unresolved_env_message`), so the two gates compose without
/// either special-casing the other.
///
/// Empty means the deploy block is fine (or absent, or declares no health gate).
#[must_use]
pub fn blank_health_domain(deploy: Option<&DeploySpec>) -> Vec<String> {
    let Some(health) = deploy.and_then(|deploy| deploy.health.as_ref()) else {
        return Vec::new();
    };
    if health.domain.is_blank() {
        return vec![format!(
            "`deploy.health.domain` is empty — there is no host to poll for `{}`, so the \
             health check and the `/ready` gate could never pass; set a domain (typically \
             `zap.env('DEPLOY_DOMAIN')`) or remove `deploy.health`",
            health.path
        )];
    }
    Vec::new()
}

/// Resource ids that aren't names ([`ResourceId::is_name`]), one finding each.
///
/// A resource's own `id` is held, and every id it names another resource by
/// (`depends_on`, a service's `restart_on` / `reload_on`, a file's `triggers`).
///
/// A resource whose own id is the finding is named by its position, since its id is
/// what can't be trusted to name it.
#[must_use]
pub fn unusable_resource_ids(resources: &[Resource]) -> Vec<String> {
    const NOT_A_NAME: &str = "is not a name zap can use for a resource: write a letter, a \
        digit or `_`, then letters, digits, or any of `_ . + : @ -` (e.g. `nginx`, \
        `app-env`, `postgresql@16`)";
    let mut errors = Vec::new();
    for (index, resource) in resources.iter().enumerate() {
        let subject = if resource.id.is_name() {
            format!("resource `{}`", resource.id.0)
        } else {
            errors.push(format!(
                "resource {}: `id` (`{}`) {NOT_A_NAME}",
                index + 1,
                resource.id.0
            ));
            format!("resource {}", index + 1)
        };
        let mut named: Vec<(&str, &[ResourceId])> = vec![("depends_on", &resource.depends_on)];
        match &resource.kind {
            ResourceKind::Service(service) => {
                named.push((
                    "restart_on",
                    service.restart_on.as_deref().unwrap_or_default(),
                ));
                named.push((
                    "reload_on",
                    service.reload_on.as_deref().unwrap_or_default(),
                ));
            }
            ResourceKind::File(file) => {
                named.push(("triggers", file.triggers.as_deref().unwrap_or_default()));
            }
            _ => {}
        }
        for (field, ids) in named {
            for (at, id) in ids.iter().enumerate() {
                if !id.is_name() {
                    errors.push(format!(
                        "{subject}: `{field}[{at}]` (`{}`) {NOT_A_NAME}",
                        id.0
                    ));
                }
            }
        }
    }
    errors
}

/// What a string field must be, beyond being text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Form {
    /// Nothing more.
    Text,
    /// An absolute path, or one that begins at the target's home (`~`, `$HOME`).
    Path,
    /// An absolute path, used as written.
    AbsolutePath,
    /// An absolute path written inside a root shell's double quotes.
    QuotedPath,
    /// An absolute path that is one field of an `/etc/fstab` line.
    FstabPath,
    /// A word a command takes as an operand: not one that begins with `-`.
    Operand,
    /// A URL zap fetches, or hands to a tool that does ([`crate::fetch_url`]).
    Url(FetchSide),
    /// One line of an `authorized_keys` file: a public key.
    KeyLine,
}

/// How [`unusable_strings`] holds one string field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Held {
    /// Not at all: another validator or the field's type holds it, or it is free text.
    Free,
    /// A command: not blank, and any number of lines.
    Command,
    /// One line of text, not blank, in a form.
    Line(Form),
    /// One line of text in a form; a blank one is another validator's finding.
    LineOrBlank(Form),
}

/// The string fields held to something other than [`DEFAULT_HELD`]: the resource kind
/// (`None`: any resource, or — for a path that begins `target.` or `deploy.` — the
/// config's own blocks), the field's path as [`path_matches`] reads it, and the rule.
/// The first row that matches decides.
///
/// A field in no row is one line of text that names something, so a field added to the
/// schema is held by default and is listed here only to be held to more, or to less.
/// Each `Free` row says who holds the field instead.
const HELD: &[(Option<&str>, &str, Held)] = &[
    // ids are names (`unusable_resource_ids`)
    (None, "id", Held::Free),
    (None, "depends_on[]", Held::Free),
    (Some("service"), "restart_on[]", Held::Free),
    (Some("service"), "reload_on[]", Held::Free),
    (Some("file"), "triggers[]", Held::Free),
    // a file's bytes: any text, an empty file included
    (Some("file"), "content.content", Held::Free),
    (Some("file"), "content.template", Held::Free),
    (Some("file"), "content.vars.**", Held::Free),
    // an environment variable's value: any text, the empty string included
    (Some("script"), "env.*", Held::Free),
    (Some("build"), "env.*", Held::Free),
    (Some("pipeline"), "env.*", Held::Free),
    (Some("pipeline"), "steps[].env.*", Held::Free),
    // text looked for in a command's output, which may span lines
    (Some("verify"), "assertions[].expect", Held::Free),
    // a `pg_hba.conf` rule line's fields (`unusable_pg_hba_fields`)
    (Some("database"), "database_name", Held::Free),
    (Some("database"), "username", Held::Free),
    (Some("database"), "auth.hosts[]", Held::Free),
    // sudoers command specs (`SudoCommands`), shared file names (`unusable_deploy_shared`)
    (Some("user"), "sudo.commands[]", Held::Free),
    (None, "deploy.shared[]", Held::Free),
    // commands
    (Some("script"), "check", Held::Command),
    (Some("script"), "run", Held::Command),
    (Some("package"), "check", Held::Command),
    (Some("verify"), "assertions[].run", Held::Command),
    (Some("pipeline"), "steps[].run", Held::Command),
    (Some("build"), "run", Held::Command),
    (None, "deploy.build", Held::Command),
    (None, "deploy.prepare[]", Held::Command),
    // a blank `validate` is `unsupported_file_validate`'s, and it is a command
    (Some("file"), "validate", Held::Free),
    // an entry is one line of `authorized_keys`
    (Some("user"), "ssh_keys.keys[]", Held::Line(Form::KeyLine)),
    // paths zap reads or writes, home-relative ones resolved against the target
    (Some("file"), "path", Held::Line(Form::Path)),
    (Some("file"), "content.path", Held::Line(Form::Path)),
    (Some("directory"), "path", Held::Line(Form::Path)),
    (Some("link"), "path", Held::Line(Form::Path)),
    (Some("installer"), "check", Held::Line(Form::Path)),
    (Some("build"), "output", Held::Line(Form::Path)),
    // paths used as written
    (Some("apt_repo"), "key_path", Held::Line(Form::QuotedPath)),
    (Some("apt_repo"), "list_file", Held::Line(Form::QuotedPath)),
    (Some("swap"), "path", Held::Line(Form::FstabPath)),
    (None, "target.home", Held::Line(Form::AbsolutePath)),
    // `~` isn't expanded, and a relative path names another file on each connection
    (
        Some("verify"),
        "assertions[].path",
        Held::Line(Form::AbsolutePath),
    ),
    // joined onto `https://<domain>`: without a leading `/` it would change the host
    (None, "deploy.health.path", Held::Line(Form::AbsolutePath)),
    // not absolute, or blank, is `unusable_working_directories`' and
    // `unusable_deploy_path`'s finding
    (Some("script"), "cwd", Held::LineOrBlank(Form::Text)),
    (None, "deploy.path", Held::LineOrBlank(Form::Text)),
    // blank is `blank_health_domain`'s
    (None, "deploy.health.domain", Held::LineOrBlank(Form::Text)),
    // operands of `ln`, `curl`, `test`, `cd`, `ssh`, `tar`, `ufw`: a leading `-` is an
    // option; a URL is held to more (`crate::fetch_url`)
    (Some("link"), "target", Held::Line(Form::Operand)),
    (Some("firewall"), "allow[]", Held::Line(Form::Operand)),
    (
        Some("apt_repo"),
        "key_url",
        Held::Line(Form::Url(FetchSide::Operator)),
    ),
    (
        Some("installer"),
        "url",
        Held::Line(Form::Url(FetchSide::Target)),
    ),
    (
        Some("file"),
        "content.url",
        Held::Line(Form::Url(FetchSide::Operator)),
    ),
    (
        Some("build"),
        "source.url",
        Held::Line(Form::Url(FetchSide::Operator)),
    ),
    (
        Some("build"),
        "source.verify.signature_url",
        Held::Line(Form::Url(FetchSide::Operator)),
    ),
    (Some("build"), "cwd", Held::Line(Form::Operand)),
    (None, "target.host", Held::Line(Form::Operand)),
    (None, "target.user", Held::Line(Form::Operand)),
    (None, "target.bootstrap_user", Held::Line(Form::Operand)),
    (None, "target.key_path", Held::Line(Form::Operand)),
    // a leading `-` is `unusable_deploy_artifacts`' finding
    (None, "deploy.artifacts[]", Held::Line(Form::Text)),
];

/// How a string field in no row of [`HELD`] is held.
const DEFAULT_HELD: Held = Held::Line(Form::Text);

const BLANK: &str = "is blank (empty, or only whitespace), so it names nothing; write its \
     value, or leave the field out if it has a default";
const BLANK_COMMAND: &str = "is blank (empty, or only whitespace); an empty command \
     succeeds having done nothing, so zap would read it as a check that passed or a step \
     that ran";
const CONTROL: &str = "holds a control character (a line break and a tab are each one); \
     the field is one line of text";
const KEY_ENDS_WITH_LINE_BREAK: &str = "ends with a line break, as text read from a key \
     file does; an entry is the key alone — write it without the line break (`.trim()` what \
     was read from the file)";
const KEY_HOLDS_LINE_BREAK: &str = "holds a line break or another control character; an \
     entry is one key on one line of `authorized_keys` — list each key as an entry of its \
     own";
const NOT_ABSOLUTE: &str = "is not an absolute path; write the full path, from `/`";
const NOT_ABSOLUTE_OR_HOME: &str = "is not an absolute path; write the full path, or begin \
     it with `~` or `$HOME` for the target's home";
const OPTION: &str = "begins with `-`, which the command it is handed to would read as an option";
const NOT_QUOTABLE: &str = "holds a character zap can't carry in this path (`\"`, `$`, a \
     backtick, `\\`, or whitespace): it is written inside a root shell's double quotes";
const FSTAB_BLANK: &str = "holds whitespace, which would split its `/etc/fstab` entry into \
     more fields";

/// What is wrong with the value a seam field resolved to — said as the rest of a
/// sentence about it — or `None`.
///
/// A `database`'s names are held to what a `pg_hba.conf` rule line reads as itself
/// ([`pg_hba_field_problem`]). A path zap reads or writes (`Form::Path`, with its home
/// already resolved) is absolute and one line; a link's `target` may be relative, and
/// is one line that is not blank and no option. A written path, an `output`, or a
/// link's target is not at or under `/var/lib/zap` ([`crate::claim::is_zap_state_path`]).
/// The rules [`unusable_strings`] holds the same fields to as written, applied where a
/// reference has resolved.
#[must_use]
pub fn resolved_field_problem(field: ResolvedField, value: &str) -> Option<&'static str> {
    let form = match field {
        ResolvedField::DatabaseName => return pg_hba_field_problem(value, PgHbaField::Database),
        ResolvedField::Username => return pg_hba_field_problem(value, PgHbaField::Role),
        ResolvedField::Target => Form::Operand,
        ResolvedField::Check | ResolvedField::Output | ResolvedField::Path => Form::AbsolutePath,
    };
    if value.trim().is_empty() {
        return Some(BLANK);
    }
    if value.chars().any(char::is_control) {
        return Some(CONTROL);
    }
    // A path zap would write, or a link's target, that resolved into zap's own state.
    if matches!(
        field,
        ResolvedField::Path | ResolvedField::Output | ResolvedField::Target
    ) && crate::claim::is_zap_state_path(value)
    {
        return Some(crate::claim::ZAP_STATE_PROBLEM);
    }
    form_problem(form, Some(value), &[value], true)
}

/// What is wrong with a text as `form`: `leading` is what it begins with when that is
/// written out (`None`: it begins with a reference, and how it begins is known only
/// once that resolves), `literals` everything written of it, and `whole` whether that
/// is all of it — no reference in it.
fn form_problem(
    form: Form,
    leading: Option<&str>,
    literals: &[&str],
    whole: bool,
) -> Option<&'static str> {
    let begins = |prefix: &str| leading.is_none_or(|leading| leading.starts_with(prefix));
    let absolute = begins("/");
    match form {
        Form::Text | Form::KeyLine => None,
        Form::Path => {
            (!absolute && !begins("~") && !begins("$HOME")).then_some(NOT_ABSOLUTE_OR_HOME)
        }
        Form::AbsolutePath => (!absolute).then_some(NOT_ABSOLUTE),
        Form::QuotedPath => {
            if !absolute {
                Some(NOT_ABSOLUTE)
            } else if literals.iter().any(|text| {
                text.chars()
                    .any(|c| c.is_whitespace() || matches!(c, '"' | '$' | '`' | '\\'))
            }) {
                Some(NOT_QUOTABLE)
            } else {
                None
            }
        }
        Form::FstabPath => {
            if !absolute {
                Some(NOT_ABSOLUTE)
            } else if literals
                .iter()
                .any(|text| text.chars().any(char::is_whitespace))
            {
                Some(FSTAB_BLANK)
            } else {
                None
            }
        }
        Form::Operand => leading
            .is_some_and(|leading| leading.starts_with('-'))
            .then_some(OPTION),
        Form::Url(side) => match leading {
            Some(url) if whole => fetch_url_problem(url, side),
            _ => written_fetch_url_problem(leading, literals, side),
        },
    }
}

/// String fields that can't be what they are for, one finding each.
///
/// A blank name, path, url or command; a line break or another control character in a
/// field that is one line; a path that must be absolute and isn't; an operand that
/// begins with `-`.
///
/// Every string of every resource, of the `target` and of the `deploy` block is held,
/// by where it sits (`HELD`); a field the table doesn't list is one line of text that
/// is not blank. A field that takes a reference is held by what is written of it: one
/// that is only a reference is not blank, a control character in the text around a
/// reference is one, and how a path begins is checked when it begins with text — a path
/// that begins with a reference is held once it resolves ([`resolved_field_problem`]).
/// A NUL is [`nul_bytes`]' finding and is not repeated here.
///
/// The sharp case is an empty `check`: it is a command that succeeds, so the script
/// would read as applied on every run and never run.
#[must_use]
pub fn unusable_strings(config: &ZapConfig) -> Vec<String> {
    let mut errors = Vec::new();
    let unreadable = |what: &str| format!("{what} couldn't be checked for unusable text");
    for resource in &config.resources {
        let subject = format!("resource `{}`", resource.id.0);
        let Ok(value) = serde_json::to_value(resource) else {
            errors.push(unreadable(&subject));
            continue;
        };
        let kind = resource.kind().as_str();
        let mut found = Vec::new();
        walk_strings(&value, "", Some(kind), &mut found);
        errors.extend(
            found
                .into_iter()
                .map(|(field, problem)| format!("{subject}: `{field}` {problem}")),
        );
    }
    let mut found = Vec::new();
    match serde_json::to_value(&config.target) {
        Ok(value) => walk_strings(&value, "target", None, &mut found),
        Err(_) => errors.push(unreadable("`target`")),
    }
    if let Some(deploy) = &config.deploy {
        match serde_json::to_value(deploy) {
            Ok(value) => walk_strings(&value, "deploy", None, &mut found),
            Err(_) => errors.push(unreadable("`deploy`")),
        }
    }
    errors.extend(
        found
            .into_iter()
            .map(|(field, problem)| format!("`{field}` {problem}")),
    );
    errors
}

/// How the string field at `path` of a resource of `kind` is held.
fn held(kind: Option<&str>, path: &str) -> Held {
    HELD.iter()
        .find(|(row_kind, pattern, _)| {
            (row_kind.is_none() || *row_kind == kind) && path_matches(pattern, path)
        })
        .map_or(DEFAULT_HELD, |(.., held)| *held)
}

/// Add to `found` the path and the problem of each string under `value` that its rule
/// refuses.
fn walk_strings(
    value: &serde_json::Value,
    path: &str,
    kind: Option<&str>,
    found: &mut Vec<(String, &'static str)>,
) {
    use serde_json::Value;
    if let Some(literals) = wire_literals(value) {
        // What the text begins with, when that is written out and not a reference.
        let leading = match value {
            Value::String(text) => Some(text.as_str()),
            Value::Object(map) => map
                .get(TEXT_KEY)
                .and_then(|pieces| pieces.get(0))
                .and_then(Value::as_str),
            _ => None,
        };
        let blank = matches!(value, Value::String(text) if text.trim().is_empty());
        let control = literals
            .iter()
            .any(|text| text.chars().any(|c| c.is_control() && c != '\0'));
        let problem = match held(kind, path) {
            Held::Free => None,
            Held::Command => blank.then_some(BLANK_COMMAND),
            Held::Line(_) if blank => Some(BLANK),
            Held::LineOrBlank(_) if blank => None,
            Held::Line(Form::KeyLine) if control => {
                let ends_only = literals.iter().all(|text| {
                    !text
                        .trim_end_matches(['\n', '\r'])
                        .chars()
                        .any(char::is_control)
                });
                Some(if ends_only {
                    KEY_ENDS_WITH_LINE_BREAK
                } else {
                    KEY_HOLDS_LINE_BREAK
                })
            }
            Held::Line(_) | Held::LineOrBlank(_) if control => Some(CONTROL),
            Held::Line(form) | Held::LineOrBlank(form) => {
                form_problem(form, leading, &literals, value.is_string())
            }
        };
        if let Some(problem) = problem {
            found.push((path.to_owned(), problem));
        }
        return;
    }
    match value {
        Value::Array(items) => {
            for (index, item) in items.iter().enumerate() {
                walk_strings(item, &format!("{path}[{index}]"), kind, found);
            }
        }
        Value::Object(fields) => {
            for (key, field) in fields {
                let at = if path.is_empty() {
                    key.clone()
                } else {
                    format!("{path}.{key}")
                };
                // A template's variables are JSON as it was written, at any depth.
                if held(kind, &at) != Held::Free || wire_literals(field).is_some() {
                    walk_strings(field, &at, kind, found);
                }
            }
        }
        _ => {}
    }
}

/// A `database`'s `database_name`, `username` and `auth.hosts` entries that a
/// `pg_hba.conf` rule line wouldn't read as themselves, one finding each.
///
/// zap writes the three into the line as they are, separated by blanks
/// ([`pg_hba_rule_line`](crate::postgres::pg_hba_rule_line)), so a blank, `#`, `"` or `,`
/// in one changes the rule — `hosts: ['0.0.0.0/0 trust #']` is a rule that trusts every
/// address — and a database or a role named as a keyword (`all`) is a rule for more
/// than that name. A field that holds a reference is checked for what is written of it
/// here, and as a whole where it resolves.
#[must_use]
pub fn unusable_pg_hba_fields(resources: &[Resource]) -> Vec<String> {
    let mut errors = Vec::new();
    for resource in resources {
        let ResourceKind::Database(database) = &resource.kind else {
            continue;
        };
        let mut fields = vec![
            (
                "database_name".to_owned(),
                &database.database_name,
                PgHbaField::Database,
            ),
            ("username".to_owned(), &database.username, PgHbaField::Role),
        ];
        if database
            .auth
            .as_ref()
            .is_some_and(|auth| auth.hosts.is_empty())
        {
            errors.push(format!(
                "resource `{}`: `auth` declares no hosts, so zap writes no pg_hba rule; name \
                 the hosts a rule admits, or drop `auth`",
                resource.id.0
            ));
        }
        for (index, host) in database.auth_hosts().iter().enumerate() {
            fields.push((format!("auth.hosts[{index}]"), host, PgHbaField::Host));
        }
        for (field, text, kind) in fields {
            if let Some(problem) = pg_hba_written_problem(text, kind) {
                errors.push(format!("resource `{}`: `{field}` {problem}", resource.id.0));
            }
        }
    }
    errors
}

/// A `deploy.releases` below two, as a finding.
///
/// The release script keeps `releases` releases counting the live one, and prunes as
/// soon as it has swapped — before the restart and the health check. With one (or none,
/// which the script reads the same way) the release a failed deploy would roll back to
/// is already removed.
#[must_use]
pub fn unusable_deploy_releases(deploy: Option<&DeploySpec>) -> Vec<String> {
    match deploy {
        Some(deploy) if deploy.releases < 2 => vec![format!(
            "`deploy.releases` is {}; zap keeps that many releases counting the live one \
             and prunes before the health check, so fewer than 2 leaves a failed deploy \
             no release to roll back to; keep at least 2",
            deploy.releases
        )],
        _ => Vec::new(),
    }
}

/// A remote target that declares no `host`, as a finding.
///
/// A target is this machine (`local: true`) or one zap connects to, and the second has
/// to be named: with no `host` there is nothing to connect to, and nothing but the
/// connection would say so.
#[must_use]
pub fn missing_target_host(target: &Target) -> Vec<String> {
    if target.is_local() || target.host().is_some() {
        return Vec::new();
    }
    vec![
        "the target declares no `host`; name the machine zap connects to (`host` on \
         `zap.target`), or declare `local: true` for this machine"
            .to_owned(),
    ]
}

/// Whether `name` could only have been written as a placeholder: an identifier, with
/// no blank beside it.
fn is_placeholder_name(name: &str) -> bool {
    crate::scalar::is_env_var_name(name)
}

/// A template's placeholders with no variable, and its variables with no placeholder,
/// one finding each.
///
/// A `{{name}}` in the body whose `name` is an identifier and no variable's is a
/// placeholder nothing fills: the file would be written with the braces in it. A
/// variable no placeholder names is a value that reaches no file — a renamed
/// placeholder, a misspelled key. Braces around anything else (`{{ .Values.port }}`,
/// `{{a.b}}`) are text; the text `{{name}}` itself is written by passing it as a
/// variable's value, which is never read for placeholders.
#[must_use]
pub fn unmatched_template_vars(resources: &[Resource]) -> Vec<String> {
    let mut errors = Vec::new();
    for resource in resources {
        let ResourceKind::File(file) = &resource.kind else {
            continue;
        };
        let FileContent::Template(template) = &file.content else {
            continue;
        };
        let id = &resource.id.0;
        let braced: BTreeSet<&str> = template
            .pieces()
            .into_iter()
            .filter_map(|piece| match piece {
                TemplatePiece::Braced(name) => Some(name),
                TemplatePiece::Text(_) => None,
            })
            .collect();
        for name in &braced {
            if is_placeholder_name(name) && !template.vars.contains_key(*name) {
                errors.push(format!(
                    "resource `{id}`: `content.template` holds the placeholder `{{{{{name}}}}}`, \
                     and `content.vars` has no `{name}`; add the variable — or, for the text \
                     `{{{{{name}}}}}` itself, pass that text as a variable's value"
                ));
            }
        }
        for name in template.vars.keys() {
            if !braced.contains(name.as_str()) {
                errors.push(format!(
                    "resource `{id}`: `content.vars.{name}` is used nowhere: the template \
                     holds no `{{{{{name}}}}}` (a placeholder is the variable's name between \
                     doubled braces, with no blanks); remove the variable, or write the \
                     placeholder"
                ));
            }
        }
    }
    errors
}

/// A template's `kinds` that name no variable, and its variables written without a
/// reference whose value isn't the kind they declare, one finding each.
///
/// A value that holds a reference is checked once it resolves: detection holds the
/// file, and the wetrun preflight and the executor refuse its write. One written out is
/// known now, so it is refused when the config is read. A non-string value is checked
/// as the compact JSON text it is written as (`8080` is a port).
#[must_use]
pub fn unfit_template_values(resources: &[Resource]) -> Vec<String> {
    let mut errors = Vec::new();
    for resource in resources {
        let ResourceKind::File(file) = &resource.kind else {
            continue;
        };
        let FileContent::Template(template) = &file.content else {
            continue;
        };
        let id = &resource.id.0;
        for (name, kind) in &template.kinds {
            let Some(var) = template.vars.get(name) else {
                errors.push(format!(
                    "resource `{id}`: `content.kinds.{name}` names no variable: \
                     `content.vars` has no `{name}`; remove the kind, or add the variable"
                ));
                continue;
            };
            let written = match var {
                crate::schema::TemplateVar::Text(text) => text.as_literal().map(str::to_owned),
                crate::schema::TemplateVar::Json(json) => Some(json.to_string()),
            };
            if let Some(problem) = written.and_then(|value| kind.problem(&value)) {
                errors.push(format!(
                    "resource `{id}`: `content.vars.{name}` {problem}, which its kind `{}` \
                     refuses",
                    kind.as_str()
                ));
            }
        }
    }
    errors
}

#[cfg(test)]
mod tests {
    use super::{
        blank_health_domain, config_nul_bytes, duplicate_resource_ids,
        missing_firewall_persistence, missing_service_manager, nul_bytes, unresolved_references,
        unsupported_file_validate, unsupported_firewall_rules, unsupported_pipeline_features,
    };
    use crate::fetch_url::FetchSide;
    use crate::schema::{DeploySpec, Resource, ResourceId, ServiceManager};
    use crate::text::Text;

    fn res_json(value: serde_json::Value) -> Resource {
        serde_json::from_value(value).unwrap()
    }

    /// A trigger on a service kept stopped would never act, so each declaration of one is
    /// a finding; a running or unmanaged service's triggers are clean.
    #[test]
    fn a_trigger_on_a_stopped_service_is_rejected() {
        let resources = |running: serde_json::Value| {
            [
                res_json(
                    serde_json::json!({"id": "conf", "type": "file", "path": "/etc/x",
                    "content": {"type": "inline", "content": ""}, "triggers": ["svc"]}),
                ),
                res_json(
                    serde_json::json!({"id": "svc", "type": "service", "service": "svc",
                    "running": running, "restart_on": ["conf"], "reload_on": []}),
                ),
            ]
        };
        assert_eq!(
            super::triggers_on_stopped_services(&resources(serde_json::json!(false))),
            [
                "file `conf` triggers service `svc`, which sets `running: false`: a trigger \
                 restarts or reloads only a running service",
                "service `svc` sets `restart_on` but `running: false`: a trigger restarts or \
                 reloads only a running service",
            ]
        );
        for running in [serde_json::json!(true), serde_json::Value::Null] {
            assert_eq!(
                super::triggers_on_stopped_services(&resources(running)),
                Vec::<String>::new()
            );
        }
    }

    /// An `env` name in zap's own `__zap_` namespace is a finding naming the resource
    /// and the key, in every `env` map; any other name is clean.
    #[test]
    fn an_env_name_in_the_wrapper_namespace_is_rejected() {
        let source = serde_json::json!(
            {"type": "remote", "url": "https://h/x.tar.gz", "extract": {"type": "tar.gz"}}
        );
        let resources = |name: &str| {
            [
                res_json(
                    serde_json::json!({"id": "s", "type": "script", "check": "c",
                    "run": "r", "env": {name: "v", "FINE": "v"}}),
                ),
                res_json(
                    serde_json::json!({"id": "b", "type": "build", "source": source,
                    "run": "make", "output": "/opt/x", "env": {name: "v"}}),
                ),
                res_json(
                    serde_json::json!({"id": "p", "type": "pipeline", "env": {name: "v"},
                    "steps": [{"id": "one", "run": "x"}, {"id": "two", "run": "y", "env": {name: "v"}}]}),
                ),
            ]
        };
        for clean in ["_zap_script", "ZAP", "__ZAP_X", "x__zap_script"] {
            assert_eq!(
                super::reserved_env_names(&resources(clean)),
                Vec::<String>::new()
            );
        }
        let findings = super::reserved_env_names(&resources("__zap_script"));
        let starts = [
            "resource `s`: `env.__zap_script` uses a name beginning with `__zap_`",
            "resource `b`: `env.__zap_script` uses",
            "resource `p`: `env.__zap_script` uses",
            "resource `p`: `steps[1].env.__zap_script` uses",
        ];
        assert_eq!(findings.len(), starts.len(), "{findings:#?}");
        for (finding, start) in findings.iter().zip(starts) {
            assert!(finding.starts_with(start), "{finding}");
        }
    }

    /// A `script`'s `cwd` that isn't an absolute path is a finding naming the resource;
    /// an absolute one is clean, whatever text it holds, and a `build`'s is not this
    /// gate's.
    #[test]
    fn a_script_cwd_must_be_absolute() {
        let script = |id: &str, cwd: Option<&str>| {
            res_json(serde_json::json!({"id": id, "type": "script", "check": "c",
                "run": "r", "cwd": cwd}))
        };
        let build = |id: &str, cwd: Option<&str>| {
            res_json(serde_json::json!({"id": id, "type": "build", "run": "make",
                "output": "/opt/x", "cwd": cwd,
                "source": {"type": "remote", "url": "https://h/x.tar.gz",
                    "extract": {"type": "tar.gz"}}}))
        };
        let clean = [
            script("a", None),
            script("b", Some("/srv/my app")),
            script("c", Some("/")),
            script("d", Some("/srv/$HOME/$x")),
            script("e", Some("/srv/$$APP$$")),
            build("f", None),
            build("g", Some("sub/dir")),
            build("h", Some("/opt/src")),
        ];
        assert_eq!(
            super::unusable_working_directories(&clean),
            Vec::<String>::new()
        );
        let findings = super::unusable_working_directories(&[
            script("rel", Some("srv/app")),
            script("home", Some("~/app")),
            script("empty", Some("")),
            script("dash", Some("-")),
            script("dollars", Some("$$ROOT$$/app")),
        ]);
        let expected = ["rel", "home", "empty", "dash", "dollars"];
        assert_eq!(findings.len(), expected.len(), "{findings:#?}");
        for (finding, id) in findings.iter().zip(expected) {
            assert!(
                finding.starts_with(&format!(
                    "resource `{id}`: `cwd` is not an absolute path; the check and the `run`"
                )),
                "{finding}"
            );
        }
    }

    #[test]
    fn an_ssh_keys_list_with_no_key_is_rejected() {
        let user = |ssh_keys: serde_json::Value| {
            res_json(
                serde_json::json!({"id": "u", "type": "user", "username": "deploy",
                "ssh_keys": ssh_keys}),
            )
        };
        for keys in [serde_json::json!([]), serde_json::json!(["", "  \n"])] {
            let findings = super::empty_ssh_keys(&[user(serde_json::json!({"keys": keys}))]);
            assert_eq!(findings.len(), 1, "{findings:?}");
            assert!(findings[0].contains("user `u`"), "{}", findings[0]);
        }
        assert!(super::empty_ssh_keys(&[user(serde_json::json!({"keys": ["k1"]}))]).is_empty());
        // A `copy_from` source is read at detection; an empty one reads missing there.
        assert!(
            super::empty_ssh_keys(&[user(serde_json::json!({"copy_from": "root"}))]).is_empty()
        );
    }

    #[test]
    fn a_user_named_root_is_refused() {
        let user = |username: &str, extra: serde_json::Value| {
            let mut json = serde_json::json!({"id": "u", "type": "user", "username": username});
            json.as_object_mut()
                .unwrap()
                .extend(extra.as_object().unwrap().clone());
            res_json(json)
        };
        // Whatever it declares: root's home is `/root`, never `/home/root`.
        for extra in [
            serde_json::json!({}),
            serde_json::json!({"shell": "/bin/sh"}),
            serde_json::json!({"home_mode": "700", "ssh_keys": {"keys": ["k1"]}}),
        ] {
            assert_eq!(
                super::managed_root_user(&[user("root", extra)]),
                [
                    "user `u` declares `username: 'root'`, whose home is /root, but zap manages \
                  a user's home as /home/<name>, so it can't manage root (manage root's files \
                  with `file` and `directory` resources)"
                ]
            );
        }
        for name in ["deploy", "rootless", "root2"] {
            assert!(
                super::managed_root_user(&[user(name, serde_json::json!({"home_mode": "700"}))])
                    .is_empty(),
                "{name}"
            );
        }
        // A `copy_from` naming root reads root's own home from /etc/passwd: no finding.
        assert!(
            super::managed_root_user(&[user(
                "deploy",
                serde_json::json!({"ssh_keys": {"copy_from": "root"}})
            )])
            .is_empty()
        );
    }

    #[test]
    fn missing_service_manager_flags_every_intent_source_when_undeclared() {
        let resources = vec![
            res("dir"),
            res_json(serde_json::json!({"id": "nginx", "type": "service", "service": "nginx"})),
            res_json(
                serde_json::json!({"id": "conf", "type": "file", "path": "/etc/x",
                "content": {"type": "inline", "content": ""}, "triggers": ["nginx"]}),
            ),
        ];
        let deploy: DeploySpec = serde_json::from_value(serde_json::json!({
            "artifacts": ["build"], "path": "/srv/app", "service": "app"
        }))
        .unwrap();

        let findings = missing_service_manager(&resources, Some(&deploy), None);
        assert_eq!(findings.len(), 1, "one consolidated finding: {findings:?}");
        for needle in [
            "service `nginx`",
            "`triggers` `conf`",
            "`deploy.service` `app`",
        ] {
            assert!(
                findings[0].contains(needle),
                "missing {needle}: {}",
                findings[0]
            );
        }
        // A declared manager — supported or not — satisfies the check (launchd is the
        // planner's Note case, not a gate error).
        assert!(
            missing_service_manager(&resources, Some(&deploy), Some(ServiceManager::Systemd))
                .is_empty()
        );
        assert!(
            missing_service_manager(&resources, Some(&deploy), Some(ServiceManager::Launchd))
                .is_empty()
        );
        // No intent, no finding: a local build box with no manager is fine, and so is a
        // `database`, whose `pg_hba` rule reloads through the server itself.
        let inert = vec![
            res("dir"),
            res_json(
                serde_json::json!({"id": "db", "type": "database", "engine": "postgresql",
                "database_name": "app", "username": "app"}),
            ),
            res_json(
                serde_json::json!({"id": "conf", "type": "file", "path": "/etc/x",
                "content": {"type": "inline", "content": ""}, "triggers": []}),
            ),
        ];
        assert!(missing_service_manager(&inert, None, None).is_empty());
    }

    fn config_of(resources: &serde_json::Value) -> crate::schema::ZapConfig {
        serde_json::from_value(serde_json::json!({
            "target": {"host": "h.example", "service_manager": "systemd"},
            "resources": resources,
        }))
        .unwrap()
    }

    /// The one finding `unusable_strings` has for a resource `x` whose `field` — a path
    /// into `resource` — is set to `value`, with the resource and field cut off.
    fn string_finding(
        mut resource: serde_json::Value,
        pointer: &str,
        value: serde_json::Value,
    ) -> Option<String> {
        *resource.pointer_mut(pointer).unwrap() = value;
        let found = super::unusable_strings(&config_of(&serde_json::json!([resource])));
        assert!(found.len() <= 1, "{found:#?}");
        found.into_iter().next()
    }

    /// An id is a name, wherever a config writes one: the resource's own, and each it
    /// names another resource by. A finding names the resource — by position when its
    /// own id is the one refused — and the field.
    #[test]
    fn a_resource_id_is_a_name() {
        let named = |id: &str| ResourceId(id.to_owned()).is_name();
        for ok in [
            "nginx",
            "app-env",
            "postgresql@16",
            "a.b+c:d",
            "_x",
            "9",
            "Zig_0.15",
        ] {
            assert!(named(ok), "{ok}");
        }
        for bad in [
            "", " ", "-x", ".x", "..", "a b", "a/b", "a\nb", "a\tb", "x$(id)", "a`b`", "a\"b",
            "a\\b", "a'b", "a;b", "a|b", "a&b", "a*", "a#b", "a=b", "a,b", "é",
        ] {
            assert!(!named(bad), "{bad:?}");
        }
        let resources = [
            res_json(serde_json::json!({"id": "x$(id)", "type": "apt_repo",
                "key_url": "https://e.x/k", "source": "deb https://e.x stable main",
                "depends_on": ["ok", "a b"]})),
            res_json(
                serde_json::json!({"id": "svc", "type": "service", "service": "nginx",
                "restart_on": ["../f"], "reload_on": ["ok", ""]}),
            ),
            res_json(serde_json::json!({"id": "f", "type": "file", "path": "/f",
                "content": {"type": "inline", "content": ""}, "triggers": ["svc", "-s"]})),
        ];
        let found = super::unusable_resource_ids(&resources);
        let starts = [
            "resource 1: `id` (`x$(id)`) is not a name zap can use for a resource: write a \
             letter, a digit or `_`, then letters, digits, or any of `_ . + : @ -`",
            "resource 1: `depends_on[1]` (`a b`) is not a name",
            "resource `svc`: `restart_on[0]` (`../f`) is not a name",
            "resource `svc`: `reload_on[1]` (``) is not a name",
            "resource `f`: `triggers[1]` (`-s`) is not a name",
        ];
        assert_eq!(found.len(), starts.len(), "{found:#?}");
        for (finding, start) in found.iter().zip(starts) {
            assert!(finding.starts_with(start), "{finding}");
        }
        assert!(super::unusable_resource_ids(&[res("a"), res("b.c")]).is_empty());
    }

    /// A field that names something or is run is not blank; a field that is one line
    /// holds no control character; a command may span lines; and what is free text —
    /// a file's content, an `env` value, an `expect` — may be anything.
    #[test]
    fn a_string_is_held_by_where_it_sits() {
        let script = || {
            serde_json::json!({"id": "x", "type": "script", "check": "c", "run": "r",
            "name": "n", "cwd": "/srv", "env": {"K": "v"}})
        };
        let file = || {
            serde_json::json!({"id": "x", "type": "file", "path": "/etc/x",
            "content": {"type": "template", "template": "t", "vars": {"a": "b", "c": {"d": ["e"]}}}})
        };
        let user = || {
            serde_json::json!({"id": "x", "type": "user", "username": "deploy",
            "shell": "/bin/sh", "ssh_keys": {"keys": ["ssh-ed25519 AAAA a"]}})
        };
        let verify = || {
            serde_json::json!({"id": "x", "type": "verify", "assertions": [
            {"type": "command", "run": "true", "expect": "ok"},
            {"type": "path_exists", "path": "/srv"}]})
        };
        let swap =
            || serde_json::json!({"id": "x", "type": "swap", "size": "1G", "path": "/swapfile"});
        let build = || {
            serde_json::json!({"id": "x", "type": "build", "run": "make",
            "output": "/opt/x", "cwd": "sub",
            "source": {"type": "remote", "url": "https://e.x/a.tgz",
                       "verify": {"scheme": "minisign", "public_key": "RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3"}}})
        };
        let text = |value: &str| serde_json::json!(value);
        for (resource, pointer, value, expected) in [
            (script(), "/check", text(""), Some(super::BLANK_COMMAND)),
            (
                script(),
                "/check",
                text(" \n\t"),
                Some(super::BLANK_COMMAND),
            ),
            (script(), "/run", text(""), Some(super::BLANK_COMMAND)),
            (
                script(),
                "/check",
                text("test -e /x &&\n\ttest -e /y"),
                None,
            ),
            (
                script(),
                "/check",
                serde_json::json!(Text::reference("CHECK")),
                None,
            ),
            (script(), "/name", text(" "), Some(super::BLANK)),
            (script(), "/name", text("two\nlines"), Some(super::CONTROL)),
            (script(), "/env/K", text(""), None),
            (script(), "/env/K", text("a\nb"), None),
            // not absolute, or blank, is `unusable_working_directories`' finding
            (script(), "/cwd", text(""), None),
            (script(), "/cwd", text("/srv/a\nb"), Some(super::CONTROL)),
            (file(), "/content/template", text(""), None),
            (file(), "/content/vars/a", text("\u{1}"), None),
            (file(), "/content/vars/c/d/0", text(""), None),
            (
                file(),
                "/content",
                serde_json::json!({"type": "inline", "content": ""}),
                None,
            ),
            (
                file(),
                "/content",
                serde_json::json!({"type": "source", "path": ""}),
                Some(super::BLANK),
            ),
            (
                file(),
                "/content",
                serde_json::json!({"type": "remote", "url": " "}),
                Some(super::BLANK),
            ),
            (user(), "/shell", text(""), Some(super::BLANK)),
            (
                user(),
                "/ssh_keys/keys/0",
                text("ssh-ed25519 AAAA a\nssh-ed25519 BBBB b"),
                Some(super::KEY_HOLDS_LINE_BREAK),
            ),
            (
                user(),
                "/ssh_keys/keys/0",
                text("ssh-ed25519 AAAA a\n"),
                Some(super::KEY_ENDS_WITH_LINE_BREAK),
            ),
            (
                user(),
                "/ssh_keys/keys/0",
                text("ssh-ed25519 AAAA a\r\n"),
                Some(super::KEY_ENDS_WITH_LINE_BREAK),
            ),
            (
                user(),
                "/ssh_keys/keys/0",
                text("ssh-ed25519 AAAA a\n\nssh-ed25519 BBBB b\n"),
                Some(super::KEY_HOLDS_LINE_BREAK),
            ),
            (
                user(),
                "/ssh_keys/keys/0",
                text("ssh-ed25519\tAAAA"),
                Some(super::KEY_HOLDS_LINE_BREAK),
            ),
            (
                user(),
                "/ssh_keys/keys/0",
                text(" ssh-ed25519 AAAA a "),
                None,
            ),
            (
                verify(),
                "/assertions/0/run",
                text(""),
                Some(super::BLANK_COMMAND),
            ),
            (verify(), "/assertions/0/expect", text(""), None),
            (verify(), "/assertions/0/expect", text("a\nb"), None),
            (verify(), "/assertions/1/path", text(""), Some(super::BLANK)),
            (
                verify(),
                "/assertions/1/path",
                text("-d"),
                Some(super::NOT_ABSOLUTE),
            ),
            (
                verify(),
                "/assertions/1/path",
                text("relative/x"),
                Some(super::NOT_ABSOLUTE),
            ),
            (
                verify(),
                "/assertions/1/path",
                text("~/x"),
                Some(super::NOT_ABSOLUTE),
            ),
            (verify(), "/assertions/1/path", text("/srv/x"), None),
            (swap(), "/size", text(""), Some(super::BLANK)),
            (swap(), "/size", text("1G\n"), Some(super::CONTROL)),
            (swap(), "/path", text("swapfile"), Some(super::NOT_ABSOLUTE)),
            (
                swap(),
                "/path",
                text("~/swapfile"),
                Some(super::NOT_ABSOLUTE),
            ),
            (
                swap(),
                "/path",
                text("/swap file"),
                Some(super::FSTAB_BLANK),
            ),
            (swap(), "/path", text("/swap\tfile"), Some(super::CONTROL)),
            (build(), "/run", text(""), Some(super::BLANK_COMMAND)),
            (build(), "/output", text(""), Some(super::BLANK)),
            (build(), "/cwd", text("-C"), Some(super::OPTION)),
            (
                build(),
                "/source/url",
                text("--output=/etc/x"),
                crate::fetch_url::fetch_url_problem("-o", FetchSide::Operator),
            ),
        ] {
            let found = string_finding(resource.clone(), pointer, value.clone());
            let field = pointer[1..].replace('/', ".");
            match expected {
                None => assert_eq!(found, None, "{pointer} = {value}"),
                Some(problem) => {
                    let found = found.unwrap_or_else(|| panic!("{pointer} = {value}: no finding"));
                    assert!(
                        found.starts_with("resource `x`: `") && found.ends_with(problem),
                        "{field} = {value}: {found}"
                    );
                }
            }
        }
        // The field is named by its path in the resource.
        assert_eq!(
            string_finding(user(), "/ssh_keys/keys/0", text("")),
            Some(format!("resource `x`: `ssh_keys.keys[0]` {}", super::BLANK))
        );
        assert_eq!(
            string_finding(verify(), "/assertions/0/run", text(" ")),
            Some(format!(
                "resource `x`: `assertions[0].run` {}",
                super::BLANK_COMMAND
            ))
        );
    }

    /// A path zap reads or writes is absolute, or begins at the target's home; one that
    /// begins with a reference is held when it resolves; and an operand never begins
    /// with `-`. The paths written into a root shell's quotes and into `/etc/fstab`
    /// are held to more.
    #[test]
    fn a_path_is_absolute_and_an_operand_is_no_option() {
        use crate::var_ref::Segment::{Ref, Text as Lit};
        let reference = |pieces: &[crate::var_ref::Segment<'_>]| {
            serde_json::json!(Text::of_pieces(pieces.iter().copied()))
        };
        let directory = || serde_json::json!({"id": "x", "type": "directory", "path": "/srv"});
        let link = || serde_json::json!({"id": "x", "type": "link", "path": "/a", "target": "b"});
        let apt = || {
            serde_json::json!({"id": "x", "type": "apt_repo", "key_url": "https://e.x/k",
            "source": "deb https://e.x $VERSION_CODENAME main",
            "key_path": "/usr/share/keyrings/x.asc", "list_file": "/etc/apt/sources.list.d/x.list"})
        };
        let installer = || {
            serde_json::json!({"id": "x", "type": "installer",
            "url": "https://e.x/install.sh", "check": "~/.local/bin/x"})
        };
        let text = |value: &str| serde_json::json!(value);
        for (resource, pointer, value, expected) in [
            (directory(), "/path", text("/srv/app"), None),
            (directory(), "/path", text("~/app"), None),
            (directory(), "/path", text("~"), None),
            (directory(), "/path", text("$HOME/app"), None),
            (
                directory(),
                "/path",
                reference(&[Ref("ROOT"), Lit("/app")]),
                None,
            ),
            (directory(), "/path", reference(&[Ref("ROOT")]), None),
            (
                directory(),
                "/path",
                reference(&[Lit("/srv/"), Ref("APP")]),
                None,
            ),
            (
                directory(),
                "/path",
                text("srv/app"),
                Some(super::NOT_ABSOLUTE_OR_HOME),
            ),
            (
                directory(),
                "/path",
                text("./app"),
                Some(super::NOT_ABSOLUTE_OR_HOME),
            ),
            (
                directory(),
                "/path",
                text("-m777"),
                Some(super::NOT_ABSOLUTE_OR_HOME),
            ),
            (
                directory(),
                "/path",
                reference(&[Lit("srv/"), Ref("APP")]),
                Some(super::NOT_ABSOLUTE_OR_HOME),
            ),
            (
                directory(),
                "/path",
                reference(&[Lit("/srv/a\nb/"), Ref("APP")]),
                Some(super::CONTROL),
            ),
            (
                directory(),
                "/path",
                text("/srv/a\rb"),
                Some(super::CONTROL),
            ),
            (
                link(),
                "/path",
                text("a"),
                Some(super::NOT_ABSOLUTE_OR_HOME),
            ),
            (link(), "/target", text("../shared/b"), None),
            (
                link(),
                "/target",
                text("-t/etc/cron.d"),
                Some(super::OPTION),
            ),
            (
                link(),
                "/target",
                reference(&[Lit("-t"), Ref("DIR")]),
                Some(super::OPTION),
            ),
            (link(), "/target", reference(&[Ref("DIR"), Lit("-t")]), None),
            (link(), "/target", text(""), Some(super::BLANK)),
            (
                installer(),
                "/check",
                text("bin/x"),
                Some(super::NOT_ABSOLUTE_OR_HOME),
            ),
            (
                installer(),
                "/url",
                text("--output=/etc/cron.d/x"),
                crate::fetch_url::fetch_url_problem("-o", FetchSide::Target),
            ),
            (
                installer(),
                "/url",
                text("https://e.x/a\nb"),
                Some(super::CONTROL),
            ),
            (
                apt(),
                "/key_url",
                text("-o/etc/x"),
                crate::fetch_url::fetch_url_problem("-o", FetchSide::Operator),
            ),
            (apt(), "/key_url", text(""), Some(super::BLANK)),
            (
                apt(),
                "/key_path",
                text("keyrings/x.asc"),
                Some(super::NOT_ABSOLUTE),
            ),
            (
                apt(),
                "/key_path",
                text("~/x.asc"),
                Some(super::NOT_ABSOLUTE),
            ),
            (
                apt(),
                "/key_path",
                text("/k/$(id).asc"),
                Some(super::NOT_QUOTABLE),
            ),
            (
                apt(),
                "/key_path",
                text("/k/a\"b.asc"),
                Some(super::NOT_QUOTABLE),
            ),
            (
                apt(),
                "/key_path",
                text("/k/a`b`.asc"),
                Some(super::NOT_QUOTABLE),
            ),
            (
                apt(),
                "/key_path",
                text("/k/a\\b.asc"),
                Some(super::NOT_QUOTABLE),
            ),
            (
                apt(),
                "/key_path",
                text("/k/a b.asc"),
                Some(super::NOT_QUOTABLE),
            ),
            (apt(), "/key_path", text("/k/a'b;c&d.asc"), None),
            (
                apt(),
                "/list_file",
                text("x.list"),
                Some(super::NOT_ABSOLUTE),
            ),
            (
                apt(),
                "/list_file",
                text("/l/$x.list"),
                Some(super::NOT_QUOTABLE),
            ),
            (
                apt(),
                "/source",
                text("deb https://e.x stable main\ndeb https://evil stable main"),
                Some(super::CONTROL),
            ),
            (apt(), "/source", text(""), Some(super::BLANK)),
        ] {
            let found = string_finding(resource.clone(), pointer, value.clone());
            match expected {
                None => assert_eq!(found, None, "{pointer} = {value}"),
                Some(problem) => assert_eq!(
                    found,
                    Some(format!("resource `x`: `{}` {problem}", &pointer[1..])),
                    "{pointer} = {value}"
                ),
            }
        }
    }

    /// A ufw profile's name is the operand of `ufw allow`, which reads its own arguments
    /// and takes no `--`: one that begins with `-` is refused here.
    #[test]
    fn a_firewall_profile_name_is_no_option() {
        let firewall = || {
            serde_json::json!({
                "id": "x", "type": "firewall", "backend": "ufw", "allow": ["OpenSSH"],
            })
        };
        assert_eq!(
            string_finding(firewall(), "/allow/0", serde_json::json!("Nginx Full")),
            None
        );
        assert_eq!(
            string_finding(firewall(), "/allow/0", serde_json::json!("--force")),
            Some(format!("resource `x`: `allow[0]` {}", super::OPTION))
        );
    }

    /// The `target`'s and the `deploy` block's strings are held too, named by their
    /// path; and a finding another validator owns is not repeated.
    #[test]
    fn the_target_and_deploy_strings_are_held() {
        let config =
            |target: serde_json::Value, deploy: serde_json::Value| -> crate::schema::ZapConfig {
                serde_json::from_value(serde_json::json!({"target": target, "resources": [],
                "deploy": deploy}))
                .unwrap()
            };
        let clean = config(
            serde_json::json!({"host": Text::reference("HOST"), "user": "deploy",
                "key_path": "~/.ssh/id", "home": "/home/deploy"}),
            serde_json::json!({"artifacts": ["build/"], "path": "/srv/app", "build": "gro build",
                "prepare": ["a &&\n b"], "shared": [".env"],
                "health": {"domain": "a.example", "path": "/health"}}),
        );
        assert_eq!(super::unusable_strings(&clean), Vec::<String>::new());
        let found = super::unusable_strings(&config(
            serde_json::json!({"host": "-oProxyCommand=x", "user": "", "bootstrap_user": "a\nb",
                "key_path": "-i", "home": "home/deploy"}),
            serde_json::json!({"artifacts": ["", "-C"], "path": "", "build": " ",
                "prepare": ["ok", ""], "shared": ["", "a\nb"],
                "health": {"domain": "", "path": ""}}),
        ));
        assert_eq!(
            found,
            [
                format!("`target.bootstrap_user` {}", super::CONTROL),
                format!("`target.home` {}", super::NOT_ABSOLUTE),
                format!("`target.host` {}", super::OPTION),
                format!("`target.key_path` {}", super::OPTION),
                format!("`target.user` {}", super::BLANK),
                format!("`deploy.artifacts[0]` {}", super::BLANK),
                format!("`deploy.build` {}", super::BLANK_COMMAND),
                format!("`deploy.health.path` {}", super::BLANK),
                format!("`deploy.prepare[1]` {}", super::BLANK_COMMAND),
            ]
        );
        // The health path is polled against the domain, so it begins with `/`.
        let found = super::unusable_strings(&config(
            serde_json::json!({"host": "a.example", "user": "deploy"}),
            serde_json::json!({"artifacts": ["build/"], "path": "/srv/app",
                "health": {"domain": "a.example", "path": "health"}}),
        ));
        assert_eq!(
            found,
            [format!("`deploy.health.path` {}", super::NOT_ABSOLUTE)]
        );
    }

    /// A resolved path is absolute and one line; a link's target is any one line that
    /// is no option; a `database`'s names are what a `pg_hba.conf` rule line reads as
    /// itself.
    #[test]
    fn a_resolved_field_is_held_to_its_fields_form() {
        use crate::postgres::{PgHbaField, pg_hba_field_problem};
        use crate::schema::ResolvedField::{Check, DatabaseName, Output, Path, Target, Username};
        let keyword = pg_hba_field_problem("all", PgHbaField::Role);
        assert!(keyword.is_some());
        let spaced = pg_hba_field_problem("a b", PgHbaField::Database);
        assert!(spaced.is_some());
        for (field, value, expected) in [
            (Check, "/usr/local/bin/x", None),
            (Check, "bin/x", Some(super::NOT_ABSOLUTE)),
            (Output, "out", Some(super::NOT_ABSOLUTE)),
            (Username, "app", None),
            (Username, "all", keyword),
            (
                DatabaseName,
                "/srv",
                pg_hba_field_problem("/srv", PgHbaField::Database),
            ),
            (DatabaseName, "a b", spaced),
            (Path, "/srv/app", None),
            (Path, "srv/app", Some(super::NOT_ABSOLUTE)),
            (Path, "-m777", Some(super::NOT_ABSOLUTE)),
            (Path, "~/app", Some(super::NOT_ABSOLUTE)),
            (Path, "", Some(super::BLANK)),
            (Path, "/srv/a\nb", Some(super::CONTROL)),
            (Path, "a", Some(super::NOT_ABSOLUTE)),
            (Target, "../b", None),
            (Target, "/b", None),
            (Target, "-t/etc/cron.d", Some(super::OPTION)),
            (Target, " ", Some(super::BLANK)),
            (Target, "a\tb", Some(super::CONTROL)),
        ] {
            assert_eq!(
                super::resolved_field_problem(field, value),
                expected,
                "{field} = {value:?}"
            );
        }
    }

    /// A `database`'s names and hosts are fields of a `pg_hba.conf` rule line: each
    /// that the line wouldn't read as itself is a finding naming it.
    #[test]
    fn a_pg_hba_field_is_one_the_rule_line_reads_as_itself() {
        use crate::postgres::{PgHbaField, pg_hba_field_problem};
        use crate::var_ref::Segment::{Ref, Text as Lit};
        let database =
            |name: serde_json::Value, user: serde_json::Value, hosts: serde_json::Value| {
                let mut resource = serde_json::json!({"id": "db", "type": "database",
                    "engine": "postgresql", "database_name": name, "username": user});
                // no hosts: no `auth`, which would have to name one
                if hosts != serde_json::json!([]) {
                    resource["auth"] = serde_json::json!({"hosts": hosts});
                }
                res_json(resource)
            };
        let text = |value: &str| serde_json::json!(value);
        let clean = [
            database(
                text("app"),
                text("app_user"),
                serde_json::json!([
                    "127.0.0.1/32",
                    "::1/128",
                    "10.0.0.0/8",
                    "0.0.0.0/0",
                    Text::reference("DB_HOST")
                ]),
            ),
            database(
                serde_json::json!(Text::reference("USER")),
                serde_json::json!(Text::of_pieces([Lit("app_"), Ref("ENV")])),
                serde_json::json!([]),
            ),
        ];
        assert_eq!(super::unusable_pg_hba_fields(&clean), Vec::<String>::new());
        let found = super::unusable_pg_hba_fields(&[database(
            text("all"),
            text("app user"),
            serde_json::json!([
                "0.0.0.0/0 trust #",
                "",
                "10.0.0.0/8,::/0",
                "ok\n",
                Text::of_pieces([Ref("NET"), Lit(" trust")])
            ]),
        )]);
        assert_eq!(
            found,
            [
                "resource `db`: `database_name` is a word `pg_hba.conf` reads as a keyword in \
                 its database column, not a database's name (`all`, `sameuser`, `samerole`, \
                 `samegroup`, `replication`)",
                "resource `db`: `username` holds a character that changes what a `pg_hba.conf` \
                 rule line means (whitespace, `#`, `\"`, `,`, or a control character)",
                "resource `db`: `auth.hosts[0]` holds a character that changes what a \
                 `pg_hba.conf` rule line means (whitespace, `#`, `\"`, `,`, or a control character)",
                "resource `db`: `auth.hosts[1]` is empty, and a `pg_hba.conf` rule line would \
                 read the next field in its place",
                "resource `db`: `auth.hosts[2]` holds a character that changes what a \
                 `pg_hba.conf` rule line means (whitespace, `#`, `\"`, `,`, or a control character)",
                "resource `db`: `auth.hosts[3]` holds a character that changes what a \
                 `pg_hba.conf` rule line means (whitespace, `#`, `\"`, `,`, or a control character)",
                "resource `db`: `auth.hosts[4]` holds a character that changes what a \
                 `pg_hba.conf` rule line means (whitespace, `#`, `\"`, `,`, or a control character)",
            ]
        );
        for (name, problem) in [
            (
                "all",
                "is `all`, which `pg_hba.conf` reads as a keyword in its user column — every \
                 role — not a role's name",
            ),
            ("+admins", "begins with `+`, `@` or `/`"),
            ("@names", "begins with `+`"),
            ("/^db\\d+$", "begins with `+`"),
            ("-x", "begins with `-`, which `createuser`"),
            ("", "is empty"),
            ("a#b", "holds a character"),
            ("a\"b", "holds a character"),
            ("a,b", "holds a character"),
        ] {
            let found = super::unusable_pg_hba_fields(&[database(
                text("app"),
                text(name),
                serde_json::json!([]),
            )]);
            assert_eq!(found.len(), 1, "{name}: {found:?}");
            assert!(
                found[0].starts_with(&format!("resource `db`: `username` {problem}")),
                "{}",
                found[0]
            );
        }
        // An `auth` that names no host writes no rule, which is never what it means.
        for auth in [
            serde_json::json!({"method": "md5"}),
            serde_json::json!({"hosts": []}),
        ] {
            let resource = res_json(serde_json::json!({"id": "db", "type": "database",
                "engine": "postgresql", "database_name": "app", "username": "app", "auth": auth}));
            assert_eq!(
                super::unusable_pg_hba_fields(&[resource]),
                [
                    "resource `db`: `auth` declares no hosts, so zap writes no pg_hba rule; name \
                  the hosts a rule admits, or drop `auth`"
                ]
            );
        }
        let absent = res_json(serde_json::json!({"id": "db", "type": "database",
            "engine": "postgresql", "database_name": "app", "username": "app"}));
        assert_eq!(
            super::unusable_pg_hba_fields(&[absent]),
            Vec::<String>::new()
        );
        // The address is an IP address with its prefix length, never a keyword (a set of
        // addresses) or a host name.
        for host in [
            "all",
            "samehost",
            "samenet",
            ".example.com",
            "db.example.com",
            "127.0.0.1",
            "127.0.0.1/33",
            "::1/129",
            "127.0.0.1/",
            "127.0.0.1/+8",
            "fe80::1%eth0/64",
        ] {
            let found = super::unusable_pg_hba_fields(&[database(
                text("app"),
                text("app"),
                serde_json::json!([host]),
            )]);
            assert_eq!(found.len(), 1, "{host}: {found:?}");
            assert!(
                found[0].starts_with(
                    "resource `db`: `auth.hosts[0]` is not an IP address with a prefix length"
                ),
                "{}",
                found[0]
            );
        }
        // Each column has its own keywords: the database column's are names a role can
        // have, and refused as a database's.
        for word in ["sameuser", "samerole", "samegroup", "replication"] {
            assert_eq!(
                super::unusable_pg_hba_fields(&[database(
                    text("app"),
                    text(word),
                    serde_json::json!([])
                )]),
                Vec::<String>::new(),
                "{word}"
            );
            let found = super::unusable_pg_hba_fields(&[database(
                text(word),
                text("app"),
                serde_json::json!([]),
            )]);
            assert_eq!(found.len(), 1, "{word}: {found:?}");
            assert!(
                found[0].starts_with(
                    "resource `db`: `database_name` is a word `pg_hba.conf` reads as a keyword \
                     in its database column"
                ),
                "{}",
                found[0]
            );
        }
        // What is written around a reference is held where it is written.
        let found = super::unusable_pg_hba_fields(&[database(
            serde_json::json!(Text::of_pieces([Lit("+"), Ref("GROUP")])),
            serde_json::json!(Text::of_pieces([Ref("NAME"), Lit("+all")])),
            serde_json::json!([]),
        )]);
        assert_eq!(found.len(), 1, "{found:?}");
        assert!(
            found[0].starts_with("resource `db`: `database_name` begins with `+`"),
            "{}",
            found[0]
        );
        // The resolved value is held to the same rule.
        for (value, field, refused) in [
            ("app", PgHbaField::Database, false),
            ("app", PgHbaField::Role, false),
            ("all", PgHbaField::Database, true),
            ("all", PgHbaField::Role, true),
            ("all", PgHbaField::Host, true),
            ("samehost", PgHbaField::Host, true),
            ("samenet", PgHbaField::Host, true),
            ("10.0.0.0/8", PgHbaField::Host, false),
            ("::1/128", PgHbaField::Host, false),
            ("replication", PgHbaField::Database, true),
            ("replication", PgHbaField::Role, false),
            ("sameuser", PgHbaField::Role, false),
            ("a b", PgHbaField::Role, true),
            ("+g", PgHbaField::Role, true),
            ("+g", PgHbaField::Host, true),
            ("0.0.0.0/0 trust #", PgHbaField::Host, true),
            ("", PgHbaField::Host, true),
        ] {
            assert_eq!(
                pg_hba_field_problem(value, field).is_some(),
                refused,
                "{value:?} as {field:?}"
            );
        }
    }

    /// A deploy keeps at least two releases; a remote target names its host.
    #[test]
    fn a_deploy_keeps_a_release_to_roll_back_to_and_a_remote_target_names_its_host() {
        let deploy = |releases: Option<u32>| -> DeploySpec {
            let mut deploy = serde_json::json!({"artifacts": ["build/"], "path": "/srv/app"});
            if let Some(releases) = releases {
                deploy["releases"] = releases.into();
            }
            serde_json::from_value(deploy).unwrap()
        };
        assert!(super::unusable_deploy_releases(None).is_empty());
        for kept in [None, Some(2), Some(5), Some(100)] {
            assert!(
                super::unusable_deploy_releases(Some(&deploy(kept))).is_empty(),
                "{kept:?}"
            );
        }
        for kept in [0, 1] {
            let found = super::unusable_deploy_releases(Some(&deploy(Some(kept))));
            assert_eq!(found.len(), 1);
            assert!(
                found[0].starts_with(&format!("`deploy.releases` is {kept}; zap keeps that many")),
                "{}",
                found[0]
            );
        }

        let target = |target: serde_json::Value| -> crate::schema::Target {
            serde_json::from_value(target).unwrap()
        };
        for named in [
            serde_json::json!({"local": true}),
            serde_json::json!({"host": "h.example"}),
            serde_json::json!({"host": Text::reference("HOST"), "local": false}),
        ] {
            assert!(
                super::missing_target_host(&target(named.clone())).is_empty(),
                "{named}"
            );
        }
        for nameless in [
            serde_json::json!({}),
            serde_json::json!({"local": false}),
            serde_json::json!({"user": "deploy", "package_manager": "apt"}),
        ] {
            let found = super::missing_target_host(&target(nameless.clone()));
            assert_eq!(found.len(), 1, "{nameless}");
            assert!(
                found[0].starts_with("the target declares no `host`;"),
                "{}",
                found[0]
            );
        }
    }

    /// A template's kinds name its variables, and a variable written out is held to its
    /// kind when the config is read; one carrying a reference waits until it resolves.
    #[test]
    fn a_templates_written_values_are_held_to_their_kinds() {
        use crate::var_ref::Segment::{Ref, Text as Lit};
        let template = |vars: serde_json::Value, kinds: serde_json::Value| {
            res_json(serde_json::json!({"id": "t", "type": "file", "path": "/t",
                "content": {"type": "template", "template": "{{domain}} {{port}} {{root}}",
                    "vars": vars, "kinds": kinds}}))
        };
        let kinds = serde_json::json!({"domain": "hostname", "port": "port", "root": "path"});
        assert_eq!(
            super::unfit_template_values(&[template(
                serde_json::json!({"domain": "app.example.com", "port": 4040, "root": "/srv/app"}),
                kinds.clone(),
            )]),
            Vec::<String>::new()
        );
        let referenced = serde_json::json!(Text::of_pieces([Ref("D"), Lit("; }")]));
        assert_eq!(
            super::unfit_template_values(&[template(
                serde_json::json!({"domain": referenced, "port": "4040", "root": "/srv/app"}),
                kinds,
            )]),
            Vec::<String>::new(),
            "a reference is checked once it resolves"
        );
        assert_eq!(
            super::unfit_template_values(&[template(
                serde_json::json!({"domain": "app.example.com;", "port": 0, "root": "/srv/../etc"}),
                serde_json::json!({"domain": "hostname", "port": "port", "root": "path",
                    "missing": "email"}),
            )]),
            [
                format!(
                    "resource `t`: `content.vars.domain` {}, which its kind `hostname` refuses",
                    crate::schema::TemplateKind::Hostname.problem(";").unwrap()
                ),
                "resource `t`: `content.kinds.missing` names no variable: `content.vars` has \
                 no `missing`; remove the kind, or add the variable"
                    .to_owned(),
                format!(
                    "resource `t`: `content.vars.port` {}, which its kind `port` refuses",
                    crate::schema::TemplateKind::Port.problem("0").unwrap()
                ),
                format!(
                    "resource `t`: `content.vars.root` {}, which its kind `path` refuses",
                    crate::schema::TemplateKind::Path.problem("..").unwrap()
                ),
            ]
        );
        // an unknown kind fails the parse
        assert!(
            serde_json::from_value::<Resource>(serde_json::json!({"id": "t", "type": "file",
                "path": "/t", "content": {"type": "template", "template": "{{a}}",
                    "vars": {"a": "x"}, "kinds": {"a": "url"}}}))
            .is_err()
        );
    }

    /// A template's placeholders and its variables match: a placeholder nothing fills
    /// and a variable nothing uses are each a finding naming the resource and the
    /// variable; braces around what is no identifier are text.
    #[test]
    fn a_templates_placeholders_and_variables_match() {
        let template = |body: &str, vars: serde_json::Value| {
            res_json(serde_json::json!({"id": "t", "type": "file", "path": "/t",
                "content": {"type": "template", "template": body, "vars": vars}}))
        };
        for (body, vars) in [
            ("{{a}} {{b}} {{a}}", serde_json::json!({"a": "1", "b": 2})),
            ("no placeholders", serde_json::json!({})),
            (
                "{{ .Values.port }} {{a.b}} {{}} {{ a }} {{1a}} {{a-b}} }} {{",
                serde_json::json!({}),
            ),
            ("{{{a}}} ${{a}}", serde_json::json!({"a": "x"})),
            (
                "{{a.b}}",
                serde_json::json!({"a.b": "odd names are substituted too"}),
            ),
        ] {
            assert_eq!(
                super::unmatched_template_vars(&[template(body, vars.clone())]),
                Vec::<String>::new(),
                "{body}"
            );
        }
        assert_eq!(
            super::unmatched_template_vars(&[template(
                "{{port}} {{domian}} {{port}} {{ spaced }}",
                serde_json::json!({"port": 1, "domain": "x", "spaced": "y"}),
            )]),
            [
                "resource `t`: `content.template` holds the placeholder `{{domian}}`, and \
                 `content.vars` has no `domian`; add the variable — or, for the text \
                 `{{domian}}` itself, pass that text as a variable's value",
                "resource `t`: `content.vars.domain` is used nowhere: the template holds no \
                 `{{domain}}` (a placeholder is the variable's name between doubled braces, \
                 with no blanks); remove the variable, or write the placeholder",
                "resource `t`: `content.vars.spaced` is used nowhere: the template holds no \
                 `{{spaced}}` (a placeholder is the variable's name between doubled braces, \
                 with no blanks); remove the variable, or write the placeholder",
            ]
        );
        // Inline content is no template.
        assert!(
            super::unmatched_template_vars(&[res_json(serde_json::json!({
            "id": "f", "type": "file", "path": "/f",
            "content": {"type": "inline", "content": "{{a}}"}}))])
            .is_empty()
        );
    }

    /// What the target fetches is https and nothing else — a `file:` URL to a path on
    /// the target is refused for an `installer` — and what zap fetches (a `remote`
    /// file, an `apt_repo` key) is plain `http` only from a loopback host, never from
    /// another machine on the network, and never a `file:` URL.
    #[test]
    fn a_file_url_on_the_target_and_plain_http_off_this_machine_are_refused() {
        let found = super::unusable_strings(&config_of(&serde_json::json!([
            {"id": "installer", "type": "installer",
             "url": "file:///opt/tool/installer.sh", "check": "/opt/tool/marker"},
            {"id": "repo", "type": "apt_repo", "key_url": "file:///srv/repo/key.asc",
             "source": "deb https://e.x/apt stable main"},
            {"id": "blob", "type": "file", "path": "/opt/blob",
             "content": {"type": "remote", "url": "http://192.168.122.1:8080/blob.bin",
                         "blake3": "ab".repeat(32)}},
            {"id": "near", "type": "file", "path": "/opt/near",
             "content": {"type": "remote", "url": "http://127.0.0.1:8080/blob.bin",
                         "blake3": "ab".repeat(32)}},
        ])));
        let on_target = crate::fetch_url::fetch_url_problem("file:///x", FetchSide::Target);
        let by_zap = crate::fetch_url::fetch_url_problem("http://e.x/x", FetchSide::Operator);
        assert_eq!(
            found,
            [
                format!("resource `installer`: `url` {}", on_target.unwrap()),
                format!("resource `repo`: `key_url` {}", by_zap.unwrap()),
                format!("resource `blob`: `content.url` {}", by_zap.unwrap()),
            ]
        );
    }

    /// A URL zap fetches is held to the one rule for them ([`crate::fetch_url`]): whole
    /// when it is written out, and by what is written of it around a reference.
    #[test]
    fn a_fetched_url_is_held_at_the_gate() {
        use crate::var_ref::Segment::{Ref, Text as Lit};
        let scheme = crate::fetch_url::fetch_url_problem("ftp://e.x", FetchSide::Operator);
        let on_target = crate::fetch_url::fetch_url_problem("ftp://e.x", FetchSide::Target);
        let userinfo = crate::fetch_url::fetch_url_problem("https://u:p@e.x", FetchSide::Target);
        assert!(scheme.is_some() && on_target.is_some() && userinfo.is_some());
        assert!(scheme != on_target && scheme != userinfo && on_target != userinfo);
        let remote = |url: serde_json::Value| {
            serde_json::json!({"id": "x", "type": "file", "path": "/opt/x",
                "content": {"type": "remote", "url": url}})
        };
        let build = |url: serde_json::Value, signature: serde_json::Value| {
            serde_json::json!({"id": "x", "type": "build", "run": "make", "output": "/opt/x",
                "source": {"type": "remote", "url": url,
                    "verify": {"scheme": "minisign", "public_key": "RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3",
                               "signature_url": signature}}})
        };
        let installer = |url: serde_json::Value| serde_json::json!({"id": "x", "type": "installer", "url": url, "check": "/opt/x"});
        let apt = |url: serde_json::Value| {
            serde_json::json!({"id": "x", "type": "apt_repo", "key_url": url,
                "source": "deb https://e.x stable main"})
        };
        let text = |value: &str| serde_json::json!(value);
        let mixed = |pieces: &[crate::var_ref::Segment<'_>]| {
            serde_json::json!(Text::of_pieces(pieces.iter().copied()))
        };
        let ok = "https://e.x/a.tar.gz";
        for (resource, field, expected) in [
            (remote(text(ok)), "content.url", None),
            (remote(text("http://127.0.0.1:8080/a")), "content.url", None),
            (remote(text("http://e.x/a")), "content.url", scheme),
            (remote(text("file:///srv/a")), "content.url", scheme),
            (remote(text("https://u:p@e.x/a")), "content.url", userinfo),
            (
                remote(mixed(&[Ref("BASE"), Lit("/a.tar.gz")])),
                "content.url",
                None,
            ),
            (
                remote(mixed(&[Lit("https://e.x/"), Ref("V")])),
                "content.url",
                None,
            ),
            (
                remote(mixed(&[Lit("file://"), Ref("PATH")])),
                "content.url",
                scheme,
            ),
            (build(text("http://e.x/a"), text(ok)), "source.url", scheme),
            (
                build(text(ok), text("http://e.x/a.minisig")),
                "source.verify.signature_url",
                scheme,
            ),
            (build(text(ok), text(ok)), "source.url", None),
            (installer(text("http://e.x/install.sh")), "url", on_target),
            (installer(text("https://u@e.x/install.sh")), "url", userinfo),
            // the target fetches these two: loopback there is no exception
            (
                installer(text("http://localhost/install.sh")),
                "url",
                on_target,
            ),
            (installer(text("https://localhost/install.sh")), "url", None),
            (apt(text("http://127.0.0.1/key.asc")), "key_url", None),
            (apt(text("http://e.x/key.asc")), "key_url", scheme),
            (
                remote(text("https://e.x:99999/a")),
                "content.url",
                crate::fetch_url::fetch_url_problem("https://e.x:0/", FetchSide::Operator),
            ),
            (apt(text("file:///etc/key.asc")), "key_url", scheme),
            (apt(text("https://e.x/key.asc")), "key_url", None),
        ] {
            let found = super::unusable_strings(&config_of(&serde_json::json!([resource])));
            match expected {
                None => assert_eq!(found, Vec::<String>::new(), "{resource}"),
                Some(problem) => {
                    assert_eq!(
                        found,
                        [format!("resource `x`: `{field}` {problem}")],
                        "{resource}"
                    );
                }
            }
        }
    }

    fn res(id: &str) -> Resource {
        serde_json::from_value(serde_json::json!({"id": id, "type": "directory", "path": "/x"}))
            .unwrap()
    }

    fn from(json: serde_json::Value) -> Resource {
        serde_json::from_value(json).unwrap()
    }

    #[test]
    fn unique_ids_have_no_duplicates() {
        let resources = [res("a"), res("b"), res("c")];
        assert!(duplicate_resource_ids(&resources).is_empty());
    }

    /// A `deploy.path` that isn't absolute is a finding; an absolute path is clean,
    /// whatever text it holds.
    #[test]
    fn a_deploy_path_must_be_absolute() {
        let deploy = |path: &str| -> DeploySpec {
            serde_json::from_value(serde_json::json!({"artifacts": ["build/"], "path": path}))
                .unwrap()
        };
        let findings = |path: &str| super::unusable_deploy_path(Some(&deploy(path)));
        assert!(super::unusable_deploy_path(None).is_empty());
        for path in [
            "/srv/app",
            "/srv/it's an app",
            "/srv/a$b",
            "/srv/app$$",
            "/srv/$$APP$$",
        ] {
            assert!(findings(path).is_empty(), "{path}");
        }
        for path in ["app", "./app", "~/app", "$HOME/app", "", "~/$$APP$$"] {
            let found = findings(path);
            assert_eq!(found.len(), 1, "{path}: {found:?}");
            assert!(
                found[0].starts_with("`deploy.path` is not an absolute path;"),
                "{path}: {found:?}"
            );
        }
    }

    /// A `deploy.shared` entry is a relative path that names a file: each entry that
    /// isn't is one finding, naming it and saying why; a nested path and a name with a
    /// space, a quote of either kind, a `$`, a backtick, a backslash, or a glob are
    /// clean — the release script quotes an entry wherever it stands.
    #[test]
    fn a_deploy_shared_entry_must_name_a_file_under_shared() {
        const CONTROL: &str = "holds a control character, which a file's name in a preview \
            and in the release script's messages can't show; rename the file";
        const DOTS: &str = "holds a `..` component, which would name a file outside the \
            app's `shared/` directory and link it outside the release";
        const ABSOLUTE: &str =
            "is an absolute path; a shared file is named relative to the app's `shared/` directory";
        const DIRECTORY: &str = "names a directory, not a file (it ends in `/` or `.`); a \
            shared entry is a file linked into each release";
        let deploy = |shared: &[&str]| -> DeploySpec {
            serde_json::from_value(serde_json::json!(
                {"artifacts": ["build/"], "path": "/srv/app", "shared": shared}
            ))
            .unwrap()
        };
        let findings = |shared: &[&str]| super::unusable_deploy_shared(Some(&deploy(shared)));
        assert!(super::unusable_deploy_shared(None).is_empty());
        assert!(findings(&[]).is_empty());
        assert_eq!(
            findings(&[
                ".env.production",
                "config/app.env",
                "my file.env",
                "it's.env",
                "a*b?[c].env",
                "a;b&c|d>e(f)#g~h!.env",
                "..env",
                "a..b/c...d",
                "./local.env",
                "-n",
                "ünïcode.env",
                "a\"; rm -rf /; echo \"",
                "$(id)",
                "$HOME/.env",
                "`id`",
                "a\\b",
            ]),
            Vec::<String>::new()
        );
        for (entry, reason) in [
            (
                "",
                "is empty; it names a file under the app's `shared/` directory",
            ),
            ("/etc/passwd", ABSOLUTE),
            ("/", ABSOLUTE),
            (".", DIRECTORY),
            ("a/", DIRECTORY),
            ("config/.", DIRECTORY),
            ("../", DIRECTORY),
            ("..", DOTS),
            ("../other/.env", DOTS),
            ("config/../../x", DOTS),
            ("config/..", DOTS),
            ("a\nb", CONTROL),
            ("a\rb", CONTROL),
            ("a\tb", CONTROL),
            ("a\u{1b}[2Kb", CONTROL),
            ("a\u{7f}", CONTROL),
            ("a\u{85}b", CONTROL),
        ] {
            assert_eq!(
                findings(&["ok.env", entry]),
                [format!("`deploy.shared[1]` (`{entry}`) {reason}")],
                "{entry:?}"
            );
        }
        // One finding an entry, each with its own index; a NUL is the NUL gate's.
        assert_eq!(findings(&["../a", "ok", "b/"]).len(), 2);
        assert!(findings(&["../a", "ok", "b/"])[1].starts_with("`deploy.shared[2]` (`b/`) "));
        assert!(findings(&["a\0b"]).is_empty());
        let nul = deploy(&["a\0b"]);
        assert_eq!(
            config_nul_bytes(&crate::schema::Target::local(), Some(&nul)).len(),
            1
        );
    }

    /// A `deploy.artifacts` entry that begins with `-` is a finding: `tar` would read it
    /// as an option. Any other path is clean.
    #[test]
    fn a_deploy_artifact_must_not_read_as_a_tar_option() {
        let findings = |artifacts: &[&str]| {
            let deploy: DeploySpec = serde_json::from_value(serde_json::json!(
                {"artifacts": artifacts, "path": "/srv/app"}
            ))
            .unwrap();
            super::unusable_deploy_artifacts(Some(&deploy))
        };
        assert!(super::unusable_deploy_artifacts(None).is_empty());
        assert!(
            findings(&[
                "build/",
                "package.json",
                "./-odd",
                "a-b",
                "dist/-x",
                "./@scope",
                "a@b"
            ])
            .is_empty()
        );
        assert_eq!(
            findings(&["build/", "--checkpoint-action=exec=id", "-C", "@scope"]),
            [
                "`deploy.artifacts[1]` (`--checkpoint-action=exec=id`) begins with `-`, which \
                 `tar` would read as an option; write the path with a leading `./`",
                "`deploy.artifacts[2]` (`-C`) begins with `-`, which `tar` would read as an \
                 option; write the path with a leading `./`",
                "`deploy.artifacts[3]` (`@scope`) begins with `@`, which a BSD `tar` would \
                 read as an archive to copy entries from; write the path with a leading `./`",
            ]
        );
    }

    /// The deploy block's health domain: blank literals are rejected, references and real
    /// hosts pass, and a deploy with no health gate (or no deploy block) has nothing to
    /// check.
    #[test]
    fn blank_health_domain_rejects_only_an_empty_literal() {
        let deploy = |domain: Option<Text>| -> DeploySpec {
            let health =
                domain.map(|domain| serde_json::json!({"domain": domain, "path": "/ready"}));
            serde_json::from_value(serde_json::json!({
                "artifacts": ["build/"], "path": "/srv/app", "health": health,
            }))
            .unwrap()
        };
        // Blank / whitespace-only → one finding naming the path it could never poll.
        let findings = blank_health_domain(Some(&deploy(Some(Text::literal("")))));
        assert_eq!(findings.len(), 1);
        assert!(findings[0].contains("/ready"), "{}", findings[0]);
        assert_eq!(
            blank_health_domain(Some(&deploy(Some(Text::literal("   "))))).len(),
            1
        );
        // A literal host and an unresolved reference both pass — an *unset* reference is
        // the env preflight's job, not this gate's.
        assert!(blank_health_domain(Some(&deploy(Some(Text::literal("example.com"))))).is_empty());
        assert!(
            blank_health_domain(Some(&deploy(Some(Text::reference("DEPLOY_DOMAIN"))))).is_empty()
        );
        // No health gate declared, and no deploy block at all.
        assert!(blank_health_domain(Some(&deploy(None))).is_empty());
        assert!(blank_health_domain(None).is_empty());
    }

    /// `validate` is accepted on text content and rejected when blank or on `remote`.
    #[test]
    fn unsupported_file_validate_rejects_blank_and_remote() {
        let file = |content: serde_json::Value, validate: Option<&str>| {
            from(serde_json::json!({
                "id": "f", "type": "file", "path": "/etc/x", "content": content,
                "validate": validate,
            }))
        };
        let inline = serde_json::json!({"type": "inline", "content": "y"});
        let remote = |extract: &str| {
            serde_json::json!({"type": "remote", "url": "https://x/y",
                "extract": {"type": extract}})
        };
        assert!(unsupported_file_validate(&[file(inline.clone(), None)]).is_empty());
        assert!(unsupported_file_validate(&[file(inline.clone(), Some("nginx -t"))]).is_empty());
        let blank = unsupported_file_validate(&[file(inline, Some("  "))]);
        assert_eq!(blank.len(), 1);
        assert!(blank[0].contains("empty `validate`"), "{}", blank[0]);
        for extract in ["none", "tar.xz"] {
            let findings = unsupported_file_validate(&[file(remote(extract), Some("nginx -t"))]);
            assert_eq!(findings.len(), 1, "{extract}");
            assert!(findings[0].contains("`remote` content"), "{}", findings[0]);
        }
    }

    #[test]
    fn repeated_id_is_reported_once() {
        let resources = [res("a"), res("b"), res("a"), res("a")];
        assert_eq!(
            duplicate_resource_ids(&resources),
            vec![ResourceId("a".to_owned())]
        );
    }

    #[test]
    fn resolved_references_have_no_errors() {
        let resources = [
            from(
                serde_json::json!({"id": "f", "type": "file", "path": "/etc/x", "content": {"type": "inline", "content": "y"}, "triggers": ["svc"]}),
            ),
            from(
                serde_json::json!({"id": "svc", "type": "service", "service": "x", "enabled": true, "restart_on": ["f"]}),
            ),
            from(
                serde_json::json!({"id": "d", "type": "directory", "path": "/d", "depends_on": ["svc"]}),
            ),
        ];
        assert!(unresolved_references(&resources).is_empty());
    }

    #[test]
    fn dangling_depends_on_is_an_error() {
        let resources = [from(
            serde_json::json!({"id": "d", "type": "directory", "path": "/d", "depends_on": ["ghost"]}),
        )];
        let errors = unresolved_references(&resources);
        assert_eq!(errors.len(), 1);
        assert!(errors[0].contains("`d` depends_on unknown resource `ghost`"));
    }

    /// An id that is no name is `unusable_resource_ids`' finding alone — wherever it is
    /// written, a file's `triggers` included — while an id that is a name and names no
    /// resource is still reported unknown beside it.
    #[test]
    fn an_id_that_is_no_name_is_not_also_reported_unknown() {
        let resources = [
            from(
                serde_json::json!({"id": "d", "type": "directory", "path": "/d",
                "depends_on": ["no such", "ghost"]}),
            ),
            from(
                serde_json::json!({"id": "svc", "type": "service", "service": "x",
                "restart_on": ["a/b"], "reload_on": ["-x", "phantom"]}),
            ),
            from(serde_json::json!({"id": "f", "type": "file", "path": "/f",
                "content": {"type": "inline", "content": ""},
                "triggers": ["not a name", "wraith"]})),
        ];
        let errors = unresolved_references(&resources);
        assert_eq!(errors.len(), 3, "{errors:#?}");
        assert!(errors[0].contains("`d` depends_on unknown resource `ghost`"));
        assert!(errors[1].contains("`svc` reload_on references unknown resource `phantom`"));
        assert!(errors[2].contains("file `f` triggers unknown resource `wraith`"));
        assert_eq!(super::unusable_resource_ids(&resources).len(), 4);
    }

    #[test]
    fn dangling_restart_on_is_an_error() {
        let resources = [from(
            serde_json::json!({"id": "svc", "type": "service", "service": "x", "enabled": true, "restart_on": ["ghost"]}),
        )];
        let errors = unresolved_references(&resources);
        assert_eq!(errors.len(), 1);
        assert!(errors[0].contains("`svc` restart_on references unknown resource `ghost`"));
    }

    #[test]
    fn trigger_of_unknown_and_non_service_are_errors() {
        let resources = [
            from(
                serde_json::json!({"id": "f", "type": "file", "path": "/etc/x", "content": {"type": "inline", "content": "y"}, "triggers": ["ghost", "d"]}),
            ),
            from(serde_json::json!({"id": "d", "type": "directory", "path": "/d"})),
        ];
        let errors = unresolved_references(&resources);
        assert_eq!(errors.len(), 2);
        assert!(
            errors
                .iter()
                .any(|e| e.contains("triggers unknown resource `ghost`"))
        );
        assert!(
            errors
                .iter()
                .any(|e| e.contains("triggers non-service resource `d`"))
        );
    }

    #[test]
    fn duplicate_pipeline_step_ids_are_errors() {
        let pipeline = |id: &str, steps: &[&str]| {
            let steps: Vec<_> = steps
                .iter()
                .map(|step| serde_json::json!({"id": step, "run": "true"}))
                .collect();
            res_json(serde_json::json!({"id": id, "type": "pipeline", "steps": steps}))
        };
        // Each repeated id once per pipeline, however often it repeats; ids repeat only
        // within a pipeline, so two pipelines may share one.
        assert_eq!(
            super::duplicate_pipeline_step_ids(&[
                pipeline("p", &["a", "b", "a", "c", "b", "a"]),
                pipeline("q", &["c", "z"]),
                pipeline("r", &["x", "x"]),
            ]),
            [
                "pipeline `p` has more than one step with the id `a`; each step's id must be \
                 unique within its pipeline",
                "pipeline `p` has more than one step with the id `b`; each step's id must be \
                 unique within its pipeline",
                "pipeline `r` has more than one step with the id `x`; each step's id must be \
                 unique within its pipeline",
            ]
        );
        assert!(
            super::duplicate_pipeline_step_ids(&[pipeline("p", &["a", "b"]), pipeline("q", &[])])
                .is_empty()
        );
    }

    #[test]
    fn supported_pipeline_has_no_errors() {
        let resources = [from(serde_json::json!({
            "id": "p", "type": "pipeline",
            "steps": [{"id": "s1", "run": "echo a"}, {"id": "s2", "run": "echo b", "name": "second"}],
        }))];
        assert!(unsupported_pipeline_features(&resources).is_empty());
    }

    #[test]
    fn dropped_pipeline_fields_are_errors() {
        let resources = [from(serde_json::json!({
            "id": "p", "type": "pipeline",
            "env": {"SHARED": "1"},
            "max_concurrency": 4,
            "steps": [{"id": "s1", "run": "echo a", "cwd": "/tmp", "env": {"X": "1"}, "depends_on": ["s0"]}],
        }))];
        let errors = unsupported_pipeline_features(&resources);
        // pipeline env + max_concurrency + the step's cwd/env/depends_on (one combined line)
        assert_eq!(errors.len(), 3);
        assert_eq!(
            errors,
            [
                "pipeline `p` sets `env`, which the sequential executor doesn't apply (inline \
                 the vars into each step's `run`)",
                "pipeline `p` sets `max_concurrency` > 1, but the executor runs steps one at a \
                 time (remove it)",
                "pipeline `p` step `s1` sets cwd / env / depends_on, which the sequential \
                 executor doesn't apply (inline a `cd` and the vars into the step's `run`; \
                 steps run in declared order, so order them instead of `depends_on`)",
            ]
        );

        // Each step's message names only the fields it sets.
        let resources = [from(serde_json::json!({
            "id": "p", "type": "pipeline",
            "steps": [
                {"id": "a", "run": "echo a", "env": {"X": "1"}},
                {"id": "b", "run": "echo b", "depends_on": ["a"]},
            ],
        }))];
        assert_eq!(
            unsupported_pipeline_features(&resources),
            [
                "pipeline `p` step `a` sets env, which the sequential executor doesn't apply \
                 (inline the vars into the step's `run`)",
                "pipeline `p` step `b` sets depends_on, which the sequential executor doesn't \
                 apply (steps run in declared order, so order them instead of `depends_on`)",
            ]
        );
    }

    #[test]
    fn nftables_firewall_requires_a_companion_persistence_service() {
        let fw = serde_json::json!({
            "id": "fw", "type": "firewall", "backend": "nftables",
            "allow": [{"port": 22, "proto": "tcp"}]
        });

        // nftables firewall, no companion service → error.
        assert_eq!(missing_firewall_persistence(&[from(fw.clone())]).len(), 1);

        // ufw self-persists, so it needs no companion service.
        let ufw = [from(serde_json::json!({
            "id": "fw", "type": "firewall", "backend": "ufw", "allow": ["OpenSSH"]
        }))];
        assert!(missing_firewall_persistence(&ufw).is_empty());

        // nftables firewall + an enabled nftables service → ok.
        let with_service = [
            from(fw.clone()),
            from(serde_json::json!({
                "id": "nft-svc", "type": "service", "service": "nftables", "enabled": true
            })),
        ];
        assert!(missing_firewall_persistence(&with_service).is_empty());

        // a *disabled* nftables service doesn't load at boot → still an error.
        let disabled = [
            from(fw),
            from(serde_json::json!({
                "id": "nft-svc", "type": "service", "service": "nftables", "enabled": false
            })),
        ];
        assert_eq!(missing_firewall_persistence(&disabled).len(), 1);
    }

    #[test]
    fn nftables_named_rule_is_an_error_but_ports_and_ufw_named_are_ok() {
        // A named profile under nftables → hard error (no app profiles).
        let nft_named = [from(serde_json::json!({
            "id": "fw", "type": "firewall", "backend": "nftables",
            "allow": ["OpenSSH", {"port": 22, "proto": "tcp"}]
        }))];
        let errors = unsupported_firewall_rules(&nft_named);
        assert_eq!(errors.len(), 1);
        assert!(errors[0].contains("`fw` uses the named profile `OpenSSH`"));

        // Port rules under nftables are fine; named profiles under ufw are fine.
        let ok = [
            from(serde_json::json!({
                "id": "nft", "type": "firewall", "backend": "nftables",
                "allow": [{"port": 22, "proto": "tcp"}, {"port": 80}]
            })),
            from(serde_json::json!({
                "id": "ufw", "type": "firewall", "backend": "ufw",
                "allow": ["OpenSSH", "Nginx Full"]
            })),
        ];
        assert!(unsupported_firewall_rules(&ok).is_empty());
    }

    /// A NUL in any string a shell or a path probe would see is a finding, named by its
    /// field; a `file`'s inline content, template body, and template vars — written as
    /// bytes — may hold one.
    /// A field that takes a reference is one field to the NUL gate, whatever its wire
    /// form: a NUL in a literal piece beside a reference is named by the field.
    #[test]
    fn a_nul_beside_a_reference_is_named_by_its_field() {
        use crate::var_ref::Segment::{Ref, Text as Lit};
        let resources = [
            res_json(serde_json::json!({"id": "s", "type": "script",
                "check": Text::of_pieces([Lit("test -d /e\u{0}tc/"), Ref("DIR")]),
                "run": Text::of_pieces([Ref("TOOL"), Lit(" --flag")]),
                "env": {"K": Text::of_pieces([Ref("V"), Lit("\u{0}")])}})),
            res_json(serde_json::json!({"id": "f", "type": "file", "path": "/f",
                "content": {"type": "template", "template": "{{v}}",
                    "vars": {"v": Text::of_pieces([Lit("bytes\u{0}"), Ref("V")])}}})),
        ];
        assert_eq!(
            nul_bytes(&resources),
            [
                format!("resource `s`: `check` {}", super::NUL_FINDING),
                format!("resource `s`: `env.K` {}", super::NUL_FINDING),
            ]
        );
        let target: crate::schema::Target = serde_json::from_value(serde_json::json!({
            "host": Text::of_pieces([Lit("h\u{0}."), Ref("DOMAIN")]),
        }))
        .unwrap();
        assert_eq!(
            config_nul_bytes(&target, None),
            [format!("`target.host` {}", super::NUL_FINDING)]
        );
    }

    #[test]
    fn nul_bytes_are_rejected_wherever_a_shell_or_path_would_see_them() {
        let cases = [
            (
                serde_json::json!({"id": "s", "type": "script", "check": "test -d /e\u{0}tc", "run": "true"}),
                "check",
            ),
            (
                serde_json::json!({"id": "s", "type": "script", "check": "true", "run": "true", "cwd": "/sr\u{0}v"}),
                "cwd",
            ),
            (
                serde_json::json!({"id": "s", "type": "script", "check": "true", "run": "true", "env": {"K": "v\u{0}"}}),
                "env.K",
            ),
            (
                serde_json::json!({"id": "v", "type": "verify", "assertions": [
                    {"type": "path_exists", "path": "/ok"},
                    {"type": "command", "run": "id\u{0}", "expect": "x"}]}),
                "assertions[1].run",
            ),
            (
                serde_json::json!({"id": "v", "type": "verify", "assertions": [
                    {"type": "command", "run": "id", "expect": "o\u{0}ps"}]}),
                "assertions[0].expect",
            ),
            (
                serde_json::json!({"id": "v", "type": "verify", "assertions": [
                    {"type": "path_exists", "path": "/e\u{0}tc"}]}),
                "assertions[0].path",
            ),
            (
                serde_json::json!({"id": "p", "type": "package", "from": {"apt": "jq"}, "check": "command -v jq\u{0}"}),
                "check",
            ),
            (
                serde_json::json!({"id": "d", "type": "directory", "path": "/opt/\u{0}x"}),
                "path",
            ),
            (
                serde_json::json!({"id": "l", "type": "link", "path": "/a", "target": "/b\u{0}"}),
                "target",
            ),
            (
                serde_json::json!({"id": "f", "type": "file", "path": "/etc/\u{0}x",
                    "content": {"type": "inline", "content": "x"}}),
                "path",
            ),
            (
                serde_json::json!({"id": "f", "type": "file", "path": "/etc/x",
                    "content": {"type": "source", "path": "/src\u{0}"}}),
                "content.path",
            ),
            (
                serde_json::json!({"id": "i", "type": "installer", "url": "https://x", "check": "/x\u{0}"}),
                "check",
            ),
            (
                serde_json::json!({"id": "sw", "type": "swap", "path": "/swap\u{0}", "size": "1G"}),
                "path",
            ),
        ];
        for (json, field) in cases {
            let findings = nul_bytes(&[res_json(json.clone())]);
            assert_eq!(findings.len(), 1, "{json}: {findings:?}");
            assert!(
                findings[0].contains(&format!("`{field}` contains a NUL byte")),
                "{json}: {findings:?}"
            );
        }
        // File content is written as bytes: a NUL there is data.
        let content = [
            serde_json::json!({"id": "f", "type": "file", "path": "/etc/x",
                "content": {"type": "inline", "content": "a\u{0}b"}}),
            serde_json::json!({"id": "f", "type": "file", "path": "/etc/x",
                "content": {"type": "template", "template": "{{x}}\u{0}", "vars": {"x": "\u{0}"}}}),
        ];
        for json in content {
            assert_eq!(
                nul_bytes(&[res_json(json.clone())]),
                Vec::<String>::new(),
                "{json}"
            );
        }
        // Nothing to find in a clean resource.
        assert!(
            nul_bytes(&[res_json(
                serde_json::json!({"id": "d", "type": "directory", "path": "/x"})
            )])
            .is_empty()
        );
    }

    /// The `target`'s strings and the `deploy` block's reach `ssh`'s argv, remote paths,
    /// and the deploy scripts: a NUL in any is a finding, named by its field.
    #[test]
    fn nul_bytes_in_the_target_and_deploy_block_are_rejected() {
        let target: crate::schema::Target = serde_json::from_value(
            serde_json::json!({"host": "h", "user": "ops", "home": "/home/o\u{0}ps"}),
        )
        .unwrap();
        assert_eq!(
            config_nul_bytes(&target, None),
            [
                "`target.home` contains a NUL byte, which no shell command or path can carry (a \
              shell would drop it and run a different command)"
            ]
        );
        let host: crate::schema::Target =
            serde_json::from_value(serde_json::json!({"host": "h\u{0}", "user": "ops"})).unwrap();
        assert!(config_nul_bytes(&host, None)[0].starts_with("`target.host` contains a NUL"));
        let deploy: DeploySpec = serde_json::from_value(serde_json::json!({
            "artifacts": ["build"], "path": "/srv/a\u{0}pp", "service": "app",
        }))
        .unwrap();
        let clean: crate::schema::Target =
            serde_json::from_value(serde_json::json!({"local": true})).unwrap();
        assert_eq!(config_nul_bytes(&clean, None), Vec::<String>::new());
        let findings = config_nul_bytes(&clean, Some(&deploy));
        assert_eq!(findings.len(), 1, "{findings:?}");
        assert!(
            findings[0].starts_with("`deploy.path` contains a NUL"),
            "{findings:?}"
        );
    }
}
