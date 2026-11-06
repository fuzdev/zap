//! The `zap plan --diff` join — pairs an observed [`CurrentState`] with the desired
//! config to produce `current → desired` lines per drifted attribute.
//!
//! This is the bridge the detection typing was building toward. [`CurrentState`]
//! deliberately carries the observed side **only**; the desired side is read here from
//! the plan fact's `Change.desired` (the resource *as authored*, with each reference still
//! **inert**). The join is pure and IO-free — it never resolves a reference, so no
//! secret value can surface (the same posture as the dry-run preview, which prints
//! inert refs verbatim). `zap_core` walks the [`DiffLine`]s into the rendered text.
//!
//! Lives in its own module — not in [`detected`](crate::detected) — so the detection
//! result stays free of any dependency on the desired-config [`schema`](crate::schema);
//! the join is the one place the two halves legitimately meet.

use crate::config_hash::{build_provenance, extract_provenance};
use crate::detected::{
    AptRepoDrift, CurrentState, DatabaseDrift, FileDrift, FirewallDrift, ShadowPasswordDrift,
    SshKeysDrift, SudoDrift, UserDrift, short_pin,
};
use crate::schema::{
    BuildResource, BuildSource, DatabaseResource, DirectoryResource, FileContent, FileResource,
    FirewallBackend, FirewallPolicy, FirewallResource, RemoteContent, RemoteSource, ResourceKind,
    ServiceResource, SshKeys, TemplateContent, UserResource, UserSudo, normalize_mode,
};

/// One rendered attribute difference between observed and desired state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiffLine {
    /// The attribute name (`shell`, `content pin`, `allow`, …).
    pub label: String,
    /// How it changes.
    pub change: DiffChange,
}

/// The shape of one attribute's change — chosen by whether an observed value exists.
///
/// [`Update`](Self::Update) when both sides have a representable value;
/// [`Replace`](Self::Replace) when the attribute is present but its observed value
/// isn't representable (file content bytes are never persisted; an unreadable file);
/// [`Add`](Self::Add) for a desired-only fact with no observed counterpart (a missing
/// firewall/`pg_hba` rule, absent SSH keys); [`Remove`](Self::Remove) when desired
/// state removes something present.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DiffChange {
    /// Observed `from` differs from desired `to`.
    Update {
        /// The observed value.
        from: String,
        /// The desired value (inert — never resolved).
        to: String,
    },
    /// The attribute differs but the observed value isn't representable — `differs → to`.
    Replace {
        /// The desired value (inert — never resolved).
        to: String,
    },
    /// Desired-only: no observed counterpart to show.
    Add {
        /// The desired value (inert — never resolved).
        to: String,
    },
    /// Desired state removes what is present.
    Remove {
        /// What is removed.
        detail: String,
    },
}

/// Join an observed [`CurrentState`] with the desired [`ResourceKind`] into the
/// `--diff` attribute lines.
///
/// Pure and IO-free: every desired value comes from `desired` verbatim (inert
/// a reference included), and nothing is resolved. A mismatched pairing (a `current` and
/// `desired` for different kinds — impossible for one resource) yields no lines.
#[must_use]
pub fn diff_view(current: &CurrentState, desired: &ResourceKind) -> Vec<DiffLine> {
    let mut lines = Vec::new();
    // Exhaustive on `CurrentState`: adding an observed-state variant is a compile error
    // here until its `--diff` join is written — the hand-sync with the detectors becomes
    // a type obligation, not a convention. The inner `if let` covers the one impossible
    // case (a `current`/`desired` for different kinds — never happens for one resource):
    // it falls through to no lines rather than a wrong diff.
    match current {
        CurrentState::Directory { mode, owner, group } => {
            if let ResourceKind::Directory(d) = desired {
                push_meta(&mut lines, (mode, owner, group), meta_of_directory(d));
            }
        }
        CurrentState::File { drift } => {
            if let ResourceKind::File(file) = desired {
                file_lines(&mut lines, drift, file);
            }
        }
        CurrentState::Build { observed } => {
            if let ResourceKind::Build(build) = desired {
                lines.push(update(
                    "provenance",
                    short_pin(observed),
                    desired_build_provenance(build),
                ));
            }
        }
        CurrentState::Link { points_to } => {
            if let ResourceKind::Link(link) = desired {
                lines.push(update(
                    "target",
                    points_to.clone(),
                    link.target.as_inert().to_owned(),
                ));
            }
        }
        CurrentState::Service {
            is_running,
            is_enabled,
        } => {
            if let ResourceKind::Service(service) = desired {
                service_lines(&mut lines, (*is_running, *is_enabled), service);
            }
        }
        CurrentState::Swap {
            is_active,
            in_fstab,
        } => {
            if matches!(desired, ResourceKind::Swap(_)) {
                if !*is_active {
                    lines.push(update("active", bool_str(false), bool_str(true)));
                }
                if !*in_fstab {
                    lines.push(update("in_fstab", bool_str(false), bool_str(true)));
                }
            }
        }
        CurrentState::Firewall { drift } => {
            if let ResourceKind::Firewall(fw) = desired {
                firewall_lines(&mut lines, drift, fw);
            }
        }
        CurrentState::Database { drift } => {
            if let ResourceKind::Database(db) = desired {
                database_lines(&mut lines, drift, db);
            }
        }
        CurrentState::User { drift } => {
            if let ResourceKind::User(user) = desired {
                user_lines(&mut lines, drift, user);
            }
        }
        CurrentState::AptRepo { drift } => {
            if let ResourceKind::AptRepo(repo) = desired {
                match drift {
                    AptRepoDrift::KeyDiffers => {
                        let pin = repo
                            .key_blake3
                            .as_ref()
                            .map_or_else(String::new, |pin| format!("blake3 {pin}"));
                        lines.push(replace("signing key", pin));
                    }
                    AptRepoDrift::ListContentDiffers => {
                        lines.push(replace("sources list", repo.source.clone()));
                    }
                    AptRepoDrift::ListMissing => {
                        lines.push(add("sources list", repo.source.clone()));
                    }
                }
            }
        }
    }
    lines
}

/// The desired `(mode, owner, group)` of a directory, each as an `Option<&str>`.
fn meta_of_directory(d: &DirectoryResource) -> (Option<&str>, Option<&str>, Option<&str>) {
    (d.mode.as_deref(), d.owner.as_deref(), d.group.as_deref())
}

/// Push a `mode`/`owner`/`group` diff for each *managed* (desired `Some`) attribute
/// whose observed value differs. Shared by `directory` and a `file`'s metadata drift.
fn push_meta(
    lines: &mut Vec<DiffLine>,
    observed: (&String, &String, &String),
    desired: (Option<&str>, Option<&str>, Option<&str>),
) {
    let (om, oo, og) = observed;
    let (dm, do_, dg) = desired;
    // Compare modes by normalized octal (so `"0755"` vs `"755"` isn't a spurious diff —
    // the same normalization the detector's drift decision uses), but render the raw
    // values so the operator sees what they actually wrote / what's on disk.
    if let Some(d) = dm
        && normalize_mode(d) != normalize_mode(om)
    {
        lines.push(update("mode", om.clone(), d.to_owned()));
    }
    if let Some(d) = do_
        && d != oo
    {
        lines.push(update("owner", oo.clone(), d.to_owned()));
    }
    if let Some(d) = dg
        && d != og
    {
        lines.push(update("group", og.clone(), d.to_owned()));
    }
}

/// Lines for a drifted `file`, dispatched on what diverged.
fn file_lines(lines: &mut Vec<DiffLine>, drift: &FileDrift, file: &FileResource) {
    match drift {
        // No observed bytes are persisted — show the desired *source*, never content.
        FileDrift::Content => lines.push(replace("content", content_descriptor(&file.content))),
        FileDrift::Metadata { mode, owner, group } => push_meta(
            lines,
            (mode, owner, group),
            (
                file.mode.as_deref(),
                file.owner.as_deref(),
                file.group.as_deref(),
            ),
        ),
        FileDrift::Pin { observed } => lines.push(update(
            "content pin",
            short_pin(observed),
            desired_content_pin(&file.content),
        )),
        FileDrift::Provenance { observed } => lines.push(update(
            "provenance",
            short_pin(observed),
            desired_extract_provenance(&file.content),
        )),
        // The observed SHA-512 isn't comparable to a blake3 pin, so it isn't shown as one.
        FileDrift::Digest { .. } => {
            lines.push(replace("content pin", desired_content_pin(&file.content)));
        }
    }
}

/// A terse description of a desired file's content *source* — never the bytes.
fn content_descriptor(content: &FileContent) -> String {
    match content {
        FileContent::Inline { content } => format!("inline ({} bytes)", content.len()),
        FileContent::Template(TemplateContent { vars, .. }) => {
            format!("template ({} vars)", vars.len())
        }
        FileContent::Source { path } => format!("copied from {}", path.as_inert()),
        FileContent::Remote(RemoteContent { url, .. }) => {
            format!("fetched from {}", url.as_inert())
        }
    }
}

/// The desired content pin of a `remote` file. Normally the resolved pin: vendored
/// (declared `blake3`) or, for a tracked file, the lock pin that `plan`'s `diff` folds
/// into `Change.desired`. The `pinned by zap.lock` fallback only shows for an *unfolded*
/// plan (built without a lock — e.g. a tracked file whose pin isn't yet resolved).
fn desired_content_pin(content: &FileContent) -> String {
    match content {
        FileContent::Remote(RemoteContent {
            blake3: Some(hash), ..
        }) => short_pin(hash),
        _ => "pinned by zap.lock".to_owned(),
    }
}

/// The desired provenance of an extracted `remote` file — over the resolved (vendored or
/// folded-lock) pin; `pinned by zap.lock` only for an unfolded plan. See
/// [`desired_content_pin`].
fn desired_extract_provenance(content: &FileContent) -> String {
    match content {
        FileContent::Remote(RemoteContent {
            blake3: Some(hash),
            extract,
            ..
        }) => short_pin(&extract_provenance(hash.as_str(), *extract)),
        _ => "pinned by zap.lock".to_owned(),
    }
}

/// The desired provenance of a `build` — over the resolved (vendored or folded-lock)
/// pin; `pinned by zap.lock` only for an unfolded plan. See [`desired_content_pin`].
fn desired_build_provenance(build: &BuildResource) -> String {
    match &build.source {
        BuildSource::Remote(RemoteSource {
            blake3: Some(hash), ..
        }) => short_pin(&build_provenance(hash.as_str(), build)),
        BuildSource::Remote(RemoteSource { blake3: None, .. }) => "pinned by zap.lock".to_owned(),
    }
}

/// Lines for a drifted `service` — only the attributes the config manages and that
/// actually differ. The service-stop footgun is warned separately in the planner.
fn service_lines(lines: &mut Vec<DiffLine>, observed: (bool, bool), service: &ServiceResource) {
    let (is_running, is_enabled) = observed;
    if is_enabled != service.enabled {
        lines.push(update(
            "enabled",
            bool_str(is_enabled),
            bool_str(service.enabled),
        ));
    }
    if let Some(running) = service.running
        && is_running != running
    {
        lines.push(update("running", bool_str(is_running), bool_str(running)));
    }
}

/// Lines for a drifted `database`: the owning role (observed → desired) and each
/// desired `pg_hba` rule found missing (an addition — no observed counterpart).
fn database_lines(lines: &mut Vec<DiffLine>, drift: &DatabaseDrift, db: &DatabaseResource) {
    if let Some(owner) = &drift.owner {
        lines.push(update(
            "owner",
            owner.clone(),
            db.username.as_inert().to_owned(),
        ));
    }
    for rule in &drift.pg_hba_missing {
        lines.push(add("pg_hba", format!("{} for {}", rule.method, rule.host)));
    }
}

/// Lines for a drifted `firewall`: each default policy that drifted (observed →
/// desired) and each desired allow rule found missing (an addition — no observed
/// counterpart). The desired policy is rendered in the **same space** the observed verb
/// was parsed in — ufw's policy name (`allow`/`deny`/`reject`) or nftables' effective
/// policy (`accept`/`drop`/`reject`, a `reject` being a `drop` chain with a trailing
/// `reject` rule) — so the `from → to` pair compares like with like.
fn firewall_lines(lines: &mut Vec<DiffLine>, drift: &FirewallDrift, fw: &FirewallResource) {
    let desired_policy = |policy: FirewallPolicy| match fw.backend {
        FirewallBackend::Ufw => policy.as_str(),
        FirewallBackend::Nftables => policy.nft_effective_policy(),
    };
    if let Some(incoming) = &drift.default_incoming {
        lines.push(update(
            "default incoming",
            incoming.clone(),
            desired_policy(fw.default_incoming).to_owned(),
        ));
    }
    if let Some(outgoing) = &drift.default_outgoing {
        lines.push(update(
            "default outgoing",
            outgoing.clone(),
            desired_policy(fw.default_outgoing).to_owned(),
        ));
    }
    for rule in &drift.missing_rules {
        lines.push(add("allow", rule.clone()));
    }
}

/// Lines for a drifted `user`. Observed-valued attributes (`shell`, `home mode`)
/// render `from → to`; absent-state markers (`ssh_keys`, a missing `sudo` policy)
/// render as additions; a `sudo` that should be removed renders as a removal.
fn user_lines(lines: &mut Vec<DiffLine>, drift: &UserDrift, user: &UserResource) {
    if let Some(shell) = &drift.shell {
        lines.push(update(
            "shell",
            shell.clone(),
            desired_managed_value(user.shell.as_deref()),
        ));
    }
    if let Some(mode) = &drift.home_mode {
        lines.push(update(
            "home mode",
            mode.clone(),
            desired_managed_value(user.home_mode.as_deref()),
        ));
    }
    if let Some(ssh) = &drift.ssh_keys {
        let descriptor = ssh_keys_descriptor(user.ssh_keys.as_ref());
        match ssh {
            SshKeysDrift::MissingOrEmpty => lines.push(add("ssh keys", descriptor)),
            SshKeysDrift::ContentDiffers | SshKeysDrift::Unreadable => {
                lines.push(replace("ssh keys", descriptor));
            }
        }
    }
    if let Some(sudo) = &drift.sudo {
        match sudo {
            SudoDrift::ShouldBeAbsent => lines.push(remove("sudoers", "access removed".to_owned())),
            SudoDrift::Missing => lines.push(add("sudoers", sudo_descriptor(user))),
            SudoDrift::ContentDiffers | SudoDrift::Unreadable => {
                lines.push(replace("sudoers", sudo_descriptor(user)));
            }
        }
    }
    if let Some(shadow_password) = &drift.shadow_password {
        match shadow_password {
            // The shadow field isn't the disabled `*` (it's `!`-locked, empty, or carries
            // a hash); re-converge it to `*` (no password, not locked) so sshd accepts
            // pubkey login. A state marker with no observed value (the value could be a
            // password hash — a secret — and must never render), so it shows as an
            // addition like a missing `ssh_keys`.
            ShadowPasswordDrift::NotDisabled => {
                lines.push(add("shadow password", "disable to '*'".to_owned()));
            }
        }
    }
    if !drift.groups.is_empty() {
        // Desired-only facts (config-derived group names): the user must be added to
        // these groups, so they render as additions like a missing `ssh_keys`.
        lines.push(add("groups", drift.groups.join(", ")));
    }
}

/// The desired value of a drifted, managed `user` attribute. The detector only flags
/// `shell` / `home_mode` when the config *sets* them (it never compares an unmanaged
/// attribute against a system default), so a drift implies the config carries a value;
/// `None` is an internal detector/config desync, surfaced as `(unset)` rather than a
/// blank or a misleading `(default)`.
fn desired_managed_value(value: Option<&str>) -> String {
    value.map_or_else(|| "(unset)".to_owned(), str::to_owned)
}

/// A terse description of a desired user's SSH-key source.
fn ssh_keys_descriptor(keys: Option<&SshKeys>) -> String {
    match keys {
        Some(SshKeys::CopyFrom { copy_from }) => format!("copy from {copy_from}"),
        Some(SshKeys::Keys { keys }) => format!("{} key(s)", keys.len()),
        None => "managed".to_owned(),
    }
}

/// A terse description of a desired user's sudo grant (mode + command scope).
fn sudo_descriptor(user: &UserResource) -> String {
    // The caller renders this only for a `sudo` drift, which the detector raises only
    // for a managed `sudo`, so a grant is expected; `Disabled` falls back to "granted".
    let Some((mode, scope)) = user.sudo.as_ref().and_then(UserSudo::grant) else {
        return "granted".to_owned();
    };
    format!("{}, {}", mode.as_str(), scope.sudoers_spec())
}

/// `"true"` / `"false"` for a rendered boolean attribute.
fn bool_str(value: bool) -> String {
    if value { "true" } else { "false" }.to_owned()
}

fn update(label: &str, from: String, to: String) -> DiffLine {
    DiffLine {
        label: label.to_owned(),
        change: DiffChange::Update { from, to },
    }
}

fn replace(label: &str, to: String) -> DiffLine {
    DiffLine {
        label: label.to_owned(),
        change: DiffChange::Replace { to },
    }
}

fn add(label: &str, to: String) -> DiffLine {
    DiffLine {
        label: label.to_owned(),
        change: DiffChange::Add { to },
    }
}

fn remove(label: &str, detail: String) -> DiffLine {
    DiffLine {
        label: label.to_owned(),
        change: DiffChange::Remove { detail },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detected::PgHbaMissing;
    use crate::schema::Resource;
    use serde_json::{Value, json};

    /// Build a desired `ResourceKind` from a JSON resource (the same shape `zap.ts`
    /// emits), so tests exercise the real schema parse rather than hand-built structs.
    fn kind(json: Value) -> ResourceKind {
        let resource: Resource = serde_json::from_value(json).unwrap();
        resource.kind
    }

    fn updated(label: &str, from: &str, to: &str) -> DiffLine {
        update(label, from.to_owned(), to.to_owned())
    }

    #[test]
    fn user_shell_and_home_mode_render_current_to_desired() {
        let current = CurrentState::User {
            drift: UserDrift {
                shell: Some("/bin/sh".to_owned()),
                home_mode: Some("755".to_owned()),
                ..UserDrift::default()
            },
        };
        let desired = kind(json!({
            "id": "u", "type": "user", "username": "u",
            "shell": "/bin/bash", "home_mode": "711"
        }));
        assert_eq!(
            diff_view(&current, &desired),
            vec![
                updated("shell", "/bin/sh", "/bin/bash"),
                updated("home mode", "755", "711"),
            ]
        );
    }

    #[test]
    fn user_ssh_keys_and_sudo_render_as_additions() {
        let current = CurrentState::User {
            drift: UserDrift {
                ssh_keys: Some(SshKeysDrift::MissingOrEmpty),
                sudo: Some(SudoDrift::Missing),
                ..UserDrift::default()
            },
        };
        let desired = kind(json!({
            "id": "u", "type": "user", "username": "u",
            "ssh_keys": {"copy_from": "root"},
            "sudo": "nopasswd"
        }));
        assert_eq!(
            diff_view(&current, &desired),
            vec![
                add("ssh keys", "copy from root".to_owned()),
                add("sudoers", "nopasswd, ALL".to_owned()),
            ]
        );
    }

    #[test]
    fn user_groups_render_as_additions() {
        let current = CurrentState::User {
            drift: UserDrift {
                groups: vec!["docker".to_owned(), "www-data".to_owned()],
                ..UserDrift::default()
            },
        };
        let desired = kind(json!({
            "id": "u", "type": "user", "username": "u",
            "groups": ["docker", "www-data"]
        }));
        assert_eq!(
            diff_view(&current, &desired),
            vec![add("groups", "docker, www-data".to_owned())]
        );
    }

    #[test]
    fn user_ssh_keys_content_differs_renders_a_replace() {
        let current = CurrentState::User {
            drift: UserDrift {
                ssh_keys: Some(SshKeysDrift::ContentDiffers),
                ..UserDrift::default()
            },
        };
        let desired = kind(json!({
            "id": "u", "type": "user", "username": "u",
            "ssh_keys": {"keys": ["ssh-ed25519 AAAA deploy"]}
        }));
        assert_eq!(
            diff_view(&current, &desired),
            vec![replace("ssh keys", "1 key(s)".to_owned())]
        );
    }

    #[test]
    fn user_sudo_should_be_absent_renders_a_removal() {
        let current = CurrentState::User {
            drift: UserDrift {
                sudo: Some(SudoDrift::ShouldBeAbsent),
                ..UserDrift::default()
            },
        };
        let desired = kind(json!({
            "id": "u", "type": "user", "username": "u", "sudo": false
        }));
        assert_eq!(
            diff_view(&current, &desired),
            vec![remove("sudoers", "access removed".to_owned())]
        );
    }

    #[test]
    fn user_shadow_password_renders_a_disable_addition() {
        let current = CurrentState::User {
            drift: UserDrift {
                shadow_password: Some(ShadowPasswordDrift::NotDisabled),
                ..UserDrift::default()
            },
        };
        let desired = kind(json!({
            "id": "u", "type": "user", "username": "u",
            "ssh_keys": {"keys": ["ssh-ed25519 AAAA deploy"]}
        }));
        assert_eq!(
            diff_view(&current, &desired),
            vec![add("shadow password", "disable to '*'".to_owned())]
        );
    }

    #[test]
    fn file_content_shows_the_source_descriptor_never_the_bytes() {
        let secret_body = "TOP-SECRET-DATA-DO-NOT-LEAK";
        let current = CurrentState::File {
            drift: FileDrift::Content,
        };
        let desired = kind(json!({
            "id": "f", "type": "file", "path": "/etc/x",
            "content": {"type": "inline", "content": secret_body}
        }));
        let lines = diff_view(&current, &desired);
        // The descriptor reports only a byte count — the content bytes never appear.
        assert_eq!(
            lines,
            vec![replace(
                "content",
                format!("inline ({} bytes)", secret_body.len())
            )]
        );
        let rendered = format!("{lines:?}");
        assert!(
            !rendered.contains(secret_body),
            "content bytes must never render"
        );
    }

    #[test]
    fn file_metadata_diff_covers_only_managed_attrs() {
        let current = CurrentState::File {
            drift: FileDrift::Metadata {
                mode: "644".to_owned(),
                owner: "root".to_owned(),
                group: "root".to_owned(),
            },
        };
        // Only `mode` and `owner` are managed; `group` is unmanaged (no desired value).
        let desired = kind(json!({
            "id": "f", "type": "file", "path": "/etc/x",
            "content": {"type": "inline", "content": "x"},
            "mode": "600", "owner": "app"
        }));
        assert_eq!(
            diff_view(&current, &desired),
            vec![
                updated("mode", "644", "600"),
                updated("owner", "root", "app")
            ]
        );
    }

    #[test]
    fn leading_zero_mode_difference_is_not_a_spurious_diff() {
        // The detector decides drift on the *normalized* mode, so a directory that
        // drifts on owner while its config mode (`0755`) matches the observed (`755`)
        // modulo a leading zero must NOT render a phantom `mode` line — only the owner.
        let current = CurrentState::Directory {
            mode: "755".to_owned(),
            owner: "root".to_owned(),
            group: "root".to_owned(),
        };
        let desired = kind(json!({
            "id": "d", "type": "directory", "path": "/p",
            "mode": "0755", "owner": "app"
        }));
        assert_eq!(
            diff_view(&current, &desired),
            vec![updated("owner", "root", "app")]
        );
    }

    #[test]
    fn file_pin_shows_short_observed_and_vendored_desired() {
        let observed = "a".repeat(64);
        let declared = "b".repeat(64);
        let current = CurrentState::File {
            drift: FileDrift::Pin {
                observed: observed.clone(),
            },
        };
        let desired = kind(json!({
            "id": "f", "type": "file", "path": "/opt/x",
            "content": {"type": "remote", "url": "https://h/x", "blake3": declared, "extract": {"type": "none"}}
        }));
        assert_eq!(
            diff_view(&current, &desired),
            vec![updated(
                "content pin",
                &short_pin(&observed),
                &short_pin(&"b".repeat(64))
            )]
        );
    }

    #[test]
    fn file_digest_drift_never_renders_the_sha512_as_a_pin() {
        let declared = "b".repeat(64);
        let current = CurrentState::File {
            drift: FileDrift::Digest {
                sha512: "c".repeat(128),
            },
        };
        let desired = kind(json!({
            "id": "f", "type": "file", "path": "/opt/x",
            "content": {"type": "remote", "url": "https://h/x", "blake3": declared, "extract": {"type": "none"}}
        }));
        let lines = diff_view(&current, &desired);
        assert_eq!(
            lines,
            vec![DiffLine {
                label: "content pin".to_owned(),
                change: DiffChange::Replace {
                    to: short_pin(&"b".repeat(64)),
                },
            }]
        );
    }

    #[test]
    fn tracked_file_pin_points_at_the_lock() {
        let observed = "a".repeat(64);
        let current = CurrentState::File {
            drift: FileDrift::Pin {
                observed: observed.clone(),
            },
        };
        // No declared `blake3` → tracked: the desired pin lives in zap.lock, not config.
        let desired = kind(json!({
            "id": "f", "type": "file", "path": "/opt/x",
            "content": {"type": "remote", "url": "https://h/x"}
        }));
        assert_eq!(
            diff_view(&current, &desired),
            vec![updated(
                "content pin",
                &short_pin(&observed),
                "pinned by zap.lock"
            )]
        );
    }

    #[test]
    fn build_provenance_shows_short_observed_and_vendored_desired() {
        let observed = "a".repeat(64);
        let declared = "b".repeat(64);
        let current = CurrentState::Build {
            observed: observed.clone(),
        };
        let desired = kind(json!({
            "id": "b", "type": "build", "output": "/opt/x/bin/x", "run": "make",
            "source": {"type": "remote", "url": "https://h/x", "extract": {"type": "tar.xz"}, "blake3": declared}
        }));
        let ResourceKind::Build(build) = &desired else {
            unreachable!()
        };
        assert_eq!(
            diff_view(&current, &desired),
            vec![updated(
                "provenance",
                &short_pin(&observed),
                &short_pin(&build_provenance(&declared, build))
            )]
        );
    }

    #[test]
    fn tracked_build_provenance_points_at_the_lock() {
        let observed = "a".repeat(64);
        let current = CurrentState::Build {
            observed: observed.clone(),
        };
        // No declared `blake3` → tracked: the desired pin lives in zap.lock, not config.
        let desired = kind(json!({
            "id": "b", "type": "build", "output": "/opt/x/bin/x", "run": "make",
            "source": {"type": "remote", "url": "https://h/x", "extract": {"type": "tar.xz"}}
        }));
        assert_eq!(
            diff_view(&current, &desired),
            vec![updated(
                "provenance",
                &short_pin(&observed),
                "pinned by zap.lock"
            )]
        );
    }

    /// Safety invariant: a `template` content descriptor reports only a var **count** —
    /// the var *values* (which may resolve to secrets) never enter the rendered diff.
    #[test]
    fn template_content_descriptor_shows_only_a_var_count_never_values() {
        let secret_value = "TOP-SECRET-TOKEN-DO-NOT-LEAK";
        let current = CurrentState::File {
            drift: FileDrift::Content,
        };
        let desired = kind(json!({
            "id": "f", "type": "file", "path": "/etc/x",
            "content": {
                "type": "template",
                "template": "/tmp/x.tmpl",
                "vars": {"api_key": secret_value, "host": "h"}
            }
        }));
        let lines = diff_view(&current, &desired);
        assert_eq!(
            lines,
            vec![replace("content", "template (2 vars)".to_owned())]
        );
        let rendered = format!("{lines:?}");
        assert!(
            !rendered.contains(secret_value),
            "template var values must never render"
        );
    }

    #[test]
    fn firewall_missing_rules_render_as_additions() {
        let current = CurrentState::Firewall {
            drift: FirewallDrift {
                missing_rules: vec!["OpenSSH".to_owned(), "443/tcp".to_owned()],
                ..FirewallDrift::default()
            },
        };
        let desired = kind(json!({
            "id": "fw", "type": "firewall", "backend": "ufw",
            "allow": ["OpenSSH", {"port": 443}]
        }));
        assert_eq!(
            diff_view(&current, &desired),
            vec![
                add("allow", "OpenSSH".to_owned()),
                add("allow", "443/tcp".to_owned()),
            ]
        );
    }

    #[test]
    fn firewall_ufw_default_policy_drift_renders_observed_to_desired() {
        // An out-of-band `ufw default allow incoming` against a config wanting `deny`:
        // observed `allow` → desired `deny` (ufw policy-name space), plus a missing rule.
        let current = CurrentState::Firewall {
            drift: FirewallDrift {
                default_incoming: Some("allow".to_owned()),
                missing_rules: vec!["443/tcp".to_owned()],
                ..FirewallDrift::default()
            },
        };
        let desired = kind(json!({
            "id": "fw", "type": "firewall", "backend": "ufw",
            "allow": [{"port": 443}]
        }));
        assert_eq!(
            diff_view(&current, &desired),
            vec![
                updated("default incoming", "allow", "deny"),
                add("allow", "443/tcp".to_owned()),
            ]
        );
    }

    #[test]
    fn firewall_nftables_default_policy_drift_renders_in_chain_verb_space() {
        // A flipped input chain `policy accept;` against a config wanting `deny`: the
        // desired side renders in nftables' base-chain verb space (`drop`), not the ufw
        // name (`deny`), so observed `accept` → desired `drop` compares like with like.
        let current = CurrentState::Firewall {
            drift: FirewallDrift {
                default_incoming: Some("accept".to_owned()),
                ..FirewallDrift::default()
            },
        };
        let desired = kind(json!({
            "id": "fw", "type": "firewall", "backend": "nftables",
            "allow": [{"port": 22, "proto": "tcp"}]
        }));
        assert_eq!(
            diff_view(&current, &desired),
            vec![updated("default incoming", "accept", "drop")]
        );
    }

    #[test]
    fn firewall_nftables_reject_renders_in_effective_policy_space() {
        // A desired `reject` against a plain `policy drop;` chain: the detector compares
        // effective policies, so the line must read `drop → reject`, not `drop → drop`.
        let current = CurrentState::Firewall {
            drift: FirewallDrift {
                default_incoming: Some("drop".to_owned()),
                ..FirewallDrift::default()
            },
        };
        let desired = kind(json!({
            "id": "fw", "type": "firewall", "backend": "nftables",
            "default_incoming": "reject", "allow": [{"port": 22, "proto": "tcp"}]
        }));
        assert_eq!(
            diff_view(&current, &desired),
            vec![updated("default incoming", "drop", "reject")]
        );
    }

    #[test]
    fn database_owner_updates_and_pg_hba_adds() {
        let current = CurrentState::Database {
            drift: DatabaseDrift {
                owner: Some("postgres".to_owned()),
                pg_hba_missing: vec![PgHbaMissing {
                    host: "127.0.0.1/32".to_owned(),
                    method: "scram-sha-256".to_owned(),
                }],
            },
        };
        let desired = kind(json!({
            "id": "db", "type": "database", "engine": "postgresql",
            "database_name": "app", "username": "appuser"
        }));
        assert_eq!(
            diff_view(&current, &desired),
            vec![
                updated("owner", "postgres", "appuser"),
                add("pg_hba", "scram-sha-256 for 127.0.0.1/32".to_owned()),
            ]
        );
    }

    #[test]
    fn service_diff_covers_enabled_and_running() {
        let current = CurrentState::Service {
            is_running: true,
            is_enabled: false,
        };
        let desired = kind(json!({
            "id": "svc", "type": "service", "service": "x",
            "enabled": true, "running": false
        }));
        assert_eq!(
            diff_view(&current, &desired),
            vec![
                updated("enabled", "false", "true"),
                updated("running", "true", "false"),
            ]
        );
    }

    #[test]
    fn link_and_directory_and_swap_and_apt_repo() {
        let link = diff_view(
            &CurrentState::Link {
                points_to: "/old".to_owned(),
            },
            &kind(json!({"id": "l", "type": "link", "path": "/p", "target": "/new"})),
        );
        assert_eq!(link, vec![updated("target", "/old", "/new")]);

        let dir = diff_view(
            &CurrentState::Directory {
                mode: "755".to_owned(),
                owner: "root".to_owned(),
                group: "root".to_owned(),
            },
            &kind(json!({"id": "d", "type": "directory", "path": "/p", "mode": "700"})),
        );
        assert_eq!(dir, vec![updated("mode", "755", "700")]);

        let swap = diff_view(
            &CurrentState::Swap {
                is_active: false,
                in_fstab: true,
            },
            &kind(json!({"id": "s", "type": "swap", "size": "2G"})),
        );
        assert_eq!(swap, vec![updated("active", "false", "true")]);

        let repo_present = diff_view(
            &CurrentState::AptRepo {
                drift: AptRepoDrift::ListContentDiffers,
            },
            &kind(json!({"id": "r", "type": "apt_repo", "key_url": "u", "source": "deb x"})),
        );
        assert_eq!(
            repo_present,
            vec![replace("sources list", "deb x".to_owned())]
        );
        let repo_missing = diff_view(
            &CurrentState::AptRepo {
                drift: AptRepoDrift::ListMissing,
            },
            &kind(json!({"id": "r", "type": "apt_repo", "key_url": "u", "source": "deb x"})),
        );
        assert_eq!(repo_missing, vec![add("sources list", "deb x".to_owned())]);
    }

    /// Safety invariant: a desired reference is shown **verbatim** — the join
    /// never resolves it, so a secret can't surface in the diff (the dry-run posture).
    #[test]
    fn desired_var_references_are_rendered_inert_never_resolved() {
        let current = CurrentState::Link {
            points_to: "/old".to_owned(),
        };
        let desired = kind(json!({
            "id": "l", "type": "link", "path": "/p",
            "target": crate::text::Text::reference("SECRET_TARGET")
        }));
        assert_eq!(
            diff_view(&current, &desired),
            vec![updated(
                "target",
                "/old",
                &crate::var_ref::marker("SECRET_TARGET")
            )]
        );
    }

    /// A `current`/`desired` pairing for different kinds (impossible for one resource)
    /// yields no lines rather than a wrong diff.
    #[test]
    fn mismatched_kinds_yield_no_lines() {
        let current = CurrentState::Link {
            points_to: "/old".to_owned(),
        };
        let desired = kind(json!({"id": "d", "type": "directory", "path": "/p", "mode": "700"}));
        assert!(diff_view(&current, &desired).is_empty());
    }
}
