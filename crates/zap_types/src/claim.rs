//! Claims — the things a resource manages that no other resource may.
//!
//! Two resources that write one path, manage one account, or each rewrite the whole
//! firewall take turns undoing each other: every run finds one of them drifted, and
//! which declaration the machine ends up in depends on their order. So each kind states
//! what it manages exclusively ([`claims`]), and a thing claimed by two resources is a
//! finding ([`conflicting_claims`]) at the structural gate.
//!
//! A claim is compared as it is written. A path or a name that holds a reference is
//! compared by its text — two resources that write the same reference collide, and two
//! that would only resolve to the same value don't, since what a reference resolves to
//! isn't known where a config is checked.

use std::collections::BTreeMap;
use std::fmt;

use crate::observe::build::SIDECAR_SUFFIX;
use crate::schema::{
    AptRepoResource, BuildResource, DatabaseResource, DirectoryResource, FileResource,
    FirewallBackend, FirewallResource, InstallerResource, LinkResource, NFTABLES_RULESET_PATH,
    PackageResource, PipelineResource, Resource, ResourceKind, ScriptResource, ServiceResource,
    SwapResource, UserResource, VerifyResource, authorized_keys_path, sudoers_path, user_ssh_dir,
};

/// One thing a resource manages exclusively.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum Claim {
    /// A path on the target that the resource creates or writes, normalized
    /// ([`normalized_path`]).
    Path(String),
    /// A Unix account.
    Account(String),
    /// A service, by the name its manager knows it by.
    Service(String),
    /// A database, by name.
    Database(String),
    /// The host firewall: a `firewall` resource sets the default policy and, under
    /// nftables, writes the whole ruleset (and claims its file), so a machine has one.
    Firewall,
}

impl fmt::Display for Claim {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Path(path) => write!(f, "the path `{path}`"),
            Self::Account(name) => write!(f, "the account `{name}`"),
            Self::Service(name) => write!(f, "the service `{name}`"),
            Self::Database(name) => write!(f, "the database `{name}`"),
            Self::Firewall => f.write_str("the host's firewall"),
        }
    }
}

/// `path` as a claim compares it.
///
/// Runs of `/` are one, `/./` is `/`, a trailing `/` is dropped (but for the root's), and
/// a leading `$HOME` is `~`. Nothing that needs the filesystem — a `..`, a symlink — is
/// resolved, so two spellings this leaves apart are not found.
#[must_use]
pub fn normalized_path(path: &str) -> String {
    let path = path
        .strip_prefix("$HOME")
        .filter(|rest| rest.is_empty() || rest.starts_with('/'))
        .map_or_else(|| path.to_owned(), |rest| format!("~{rest}"));
    let absolute = path.starts_with('/');
    let components: Vec<&str> = path
        .split('/')
        .filter(|component| !component.is_empty() && *component != ".")
        .collect();
    let joined = components.join("/");
    if absolute {
        format!("/{joined}")
    } else {
        joined
    }
}

/// What `resource` manages exclusively.
///
/// Every kind is destructured in full, so a kind or a field added to the schema doesn't
/// compile until it is placed: claimed, or left unclaimed here with the reason.
#[must_use]
// Each kind is its own arm, destructured in full, though several claim alike.
#[allow(clippy::match_same_arms)]
pub fn claims(resource: &Resource) -> Vec<Claim> {
    let path = |path: &str| Claim::Path(normalized_path(path));
    match &resource.kind {
        ResourceKind::File(FileResource {
            path: at,
            // What a file holds, and what its write notifies, belong to no one else's
            // path; a `source` is read, not written.
            content: _,
            mode: _,
            owner: _,
            group: _,
            triggers: _,
            validate: _,
        }) => vec![path(at.as_inert())],
        ResourceKind::Directory(DirectoryResource {
            path: at,
            mode: _,
            owner: _,
            group: _,
        }) => vec![path(at.as_inert())],
        // The link is the resource's; what it points at is someone else's.
        ResourceKind::Link(LinkResource {
            path: at,
            target: _,
        }) => vec![path(at.as_inert())],
        ResourceKind::User(UserResource {
            username,
            shell: _,
            home_mode: _,
            ssh_keys,
            sudo,
            groups: _,
        }) => {
            let mut claimed = vec![Claim::Account(username.as_str().to_owned())];
            // The two files a `user` writes, so a `file` at either is a second writer,
            // and the `.ssh` directory the keys set to 700, so a `directory` there is a
            // second writer.
            if ssh_keys.is_some() {
                claimed.push(path(&user_ssh_dir(username)));
                claimed.push(path(&authorized_keys_path(username)));
            }
            if sudo.is_some() {
                claimed.push(path(&sudoers_path(username)));
            }
            claimed
        }
        ResourceKind::Service(ServiceResource {
            service,
            enabled: _,
            running: _,
            restart_on: _,
            reload_on: _,
        }) => vec![Claim::Service(service.as_str().to_owned())],
        // The role is not claimed: its creation is guarded, so several databases owned
        // by one role is a config that converges.
        ResourceKind::Database(DatabaseResource {
            engine: _,
            database_name,
            username: _,
            auth: _,
        }) => vec![Claim::Database(database_name.as_inert().to_owned())],
        ResourceKind::Swap(SwapResource { size: _, path: at }) => vec![path(at)],
        // Under nftables the firewall also writes its ruleset file whole.
        ResourceKind::Firewall(FirewallResource {
            backend,
            default_incoming: _,
            default_outgoing: _,
            allow: _,
        }) => match backend {
            FirewallBackend::Nftables => vec![Claim::Firewall, path(NFTABLES_RULESET_PATH)],
            FirewallBackend::Ufw => vec![Claim::Firewall],
        },
        ResourceKind::AptRepo(
            repo @ AptRepoResource {
                key_url: _,
                key_blake3: _,
                key_path: _,
                source: _,
                list_file: _,
            },
        ) => {
            let (key, list) = crate::observe::apt_repo::paths(&resource.id.0, repo);
            vec![path(&key), path(&list)]
        }
        ResourceKind::Build(BuildResource {
            source: _,
            run: _,
            output,
            cwd: _,
            env: _,
        }) => {
            let output = normalized_path(output.as_inert());
            vec![
                Claim::Path(format!("{output}{SIDECAR_SUFFIX}")),
                Claim::Path(output),
            ]
        }
        // Installing a package twice is installing it once: both resources read the
        // same query and neither undoes the other.
        ResourceKind::Package(PackageResource { from: _, check: _ }) => Vec::new(),
        // An installer's `check` is a path it reads; what its script writes is the
        // script's own business.
        ResourceKind::Installer(InstallerResource {
            url: _,
            check: _,
            shell: _,
        }) => Vec::new(),
        // Commands: what they change isn't declared.
        ResourceKind::Script(ScriptResource {
            check: _,
            run: _,
            cwd: _,
            env: _,
        }) => Vec::new(),
        ResourceKind::Pipeline(PipelineResource {
            env: _,
            steps: _,
            max_concurrency: _,
        }) => Vec::new(),
        // Assertions change nothing.
        ResourceKind::Verify(VerifyResource { assertions: _ }) => Vec::new(),
    }
}

/// The directory on the target zap keeps its own state in (the pending-trigger markers
/// under `pending/`). zap claims it, and everything under it.
pub const ZAP_STATE_DIR: &str = "/var/lib/zap";

/// What a `link` whose target leads at or under [`ZAP_STATE_DIR`], or to a directory
/// above it, is, said as the rest of a sentence about its target.
pub const ZAP_STATE_LINK_PROBLEM: &str = "leads into `/var/lib/zap`, where zap keeps its own \
     state, or to a directory above it, through which a path below the link reaches it; \
     point it elsewhere";

/// What a `link` placed at a directory above [`ZAP_STATE_DIR`] (`/`, `/var`, `/var/lib`)
/// is, said as the rest of a sentence about its path.
pub const ZAP_STATE_ANCESTOR_LINK_PROBLEM: &str = "is a directory above `/var/lib/zap`, where \
     zap keeps its own state, which the link would replace; put the link elsewhere";

/// What a path zap would manage at or under [`ZAP_STATE_DIR`] is, said as the rest of a
/// sentence about it.
pub const ZAP_STATE_PROBLEM: &str =
    "is at or under `/var/lib/zap`, where zap keeps its own state; manage a path outside it";

/// Each declaration that would manage a path at or under [`ZAP_STATE_DIR`] as written, as
/// a finding: a resource's path, a `link` whose target leads there, and `deploy.path`.
///
/// zap writes and reads its state there as root; a resource that wrote, linked, or
/// re-moded a path there could hide or forge a record zap acts on. A path is compared
/// with `.` and `..` components taken lexically ([`is_zap_state_path`]), so
/// `/var/lib/x/../zap` is found too. A home-rooted path (`~`, `$HOME`) with a `..`
/// component is a finding as well, since the home it climbs out of isn't known here. A
/// path that begins with a reference is checked once it resolves (detection and the
/// wetrun hold or refuse it, `validate::resolved_field_problem`), and so is a `link`'s.
#[must_use]
pub fn zap_state_claims(resources: &[Resource], deploy_path: Option<&str>) -> Vec<String> {
    let mut findings = Vec::new();
    for resource in resources {
        let id = &resource.id.0;
        for claim in claims(resource) {
            let Claim::Path(path) = &claim else {
                continue;
            };
            if is_zap_state_path(path) {
                findings.push(format!(
                    "resource `{id}` manages {claim}, which {ZAP_STATE_PROBLEM}"
                ));
            } else if path.starts_with('~') && path.split('/').any(|component| component == "..") {
                findings.push(format!(
                    "resource `{id}` manages {claim}, a home-rooted path with a `..` component, \
                     which could climb out of the home into `{ZAP_STATE_DIR}`; write it without \
                     `..`"
                ));
            }
        }
        if let ResourceKind::Link(LinkResource { path, target }) = &resource.kind {
            if link_reaches_zap_state(path.as_inert(), target.as_inert()) {
                findings.push(format!(
                    "link `{id}` points at `{}`, which {ZAP_STATE_LINK_PROBLEM}",
                    target.as_inert()
                ));
            }
            // At or inside zap's state the path claim above already finds it.
            if is_zap_state_ancestor(path.as_inert()) {
                findings.push(format!(
                    "link `{id}` is at `{}`, which {ZAP_STATE_ANCESTOR_LINK_PROBLEM}",
                    path.as_inert()
                ));
            }
        }
    }
    if let Some(path) = deploy_path
        && is_zap_state_path(path)
    {
        findings.push(format!("`deploy.path` {ZAP_STATE_PROBLEM}"));
    }
    findings
}

/// Whether the absolute `path`, its `.` and `..` components resolved lexically, is
/// [`ZAP_STATE_DIR`] or under it. A path that isn't absolute is not.
#[must_use]
pub fn is_zap_state_path(path: &str) -> bool {
    lexical_components(path).is_some_and(|parts| parts.starts_with(&zap_state_components()))
}

/// Whether the absolute `path`, taken lexically as [`is_zap_state_path`] takes it, is a
/// directory above [`ZAP_STATE_DIR`] — `/`, `/var`, `/var/lib`. A link there leads into
/// zap's state through the names below it.
fn is_zap_state_ancestor(path: &str) -> bool {
    lexical_components(path).is_some_and(|parts| {
        let state = zap_state_components();
        parts.len() < state.len() && state.starts_with(&parts)
    })
}

/// The components of the absolute `path` with `.` and `..` taken lexically, or `None`
/// for a path that isn't absolute.
fn lexical_components(path: &str) -> Option<Vec<&str>> {
    if !path.starts_with('/') {
        return None;
    }
    let mut parts: Vec<&str> = Vec::new();
    for component in path.split('/') {
        match component {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            name => parts.push(name),
        }
    }
    Some(parts)
}

/// [`ZAP_STATE_DIR`]'s components.
fn zap_state_components() -> Vec<&'static str> {
    ZAP_STATE_DIR.split('/').filter(|c| !c.is_empty()).collect()
}

/// Whether a link placed at `path` would replace a directory above [`ZAP_STATE_DIR`]
/// (`/`, `/var`, `/var/lib`), taken lexically.
#[must_use]
pub fn link_replaces_zap_state_ancestor(path: &str) -> bool {
    is_zap_state_ancestor(path)
}

/// Whether a link at `path` to `target` leads at or under [`ZAP_STATE_DIR`], or above it.
///
/// A link to a directory above it reaches it through the names below the link. An
/// absolute target is taken by itself, a relative one from the link's directory (when
/// `path` is absolute).
#[must_use]
pub fn link_reaches_zap_state(path: &str, target: &str) -> bool {
    let reaches = |target: &str| is_zap_state_path(target) || is_zap_state_ancestor(target);
    if target.starts_with('/') {
        return reaches(target);
    }
    path.starts_with('/')
        && path
            .rsplit_once('/')
            .is_some_and(|(dir, _)| reaches(&format!("{dir}/{target}")))
}

/// Each thing more than one resource claims, as a finding naming the resources and the
/// thing.
#[must_use]
pub fn conflicting_claims(resources: &[Resource]) -> Vec<String> {
    let mut claimants: BTreeMap<Claim, Vec<&str>> = BTreeMap::new();
    for resource in resources {
        let mut claimed = claims(resource);
        claimed.sort();
        claimed.dedup();
        for claim in claimed {
            claimants.entry(claim).or_default().push(&resource.id.0);
        }
    }
    claimants
        .into_iter()
        .filter(|(_, ids)| ids.len() > 1)
        .map(|(claim, ids)| {
            let ids: Vec<String> = ids.iter().map(|id| format!("`{id}`")).collect();
            format!(
                "resources {} each manage {claim}; a thing is managed by one resource, or \
                 each run undoes the other's change — merge them, or remove all but one",
                ids.join(" and ")
            )
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{Claim, claims, conflicting_claims, normalized_path, zap_state_claims};
    use crate::schema::Resource;
    use crate::text::Text;

    fn resources(json: serde_json::Value) -> Vec<Resource> {
        serde_json::from_value(json).unwrap()
    }

    /// zap's own state directory is no resource's: a path-bearing resource at or under
    /// it is a finding, however the path is spelled; one beside it is clean.
    #[test]
    fn a_path_under_zaps_state_directory_is_refused() {
        let link = |id: &str, target: &str| {
            format!(
                "link `{id}` points at `{target}`, which {}",
                super::ZAP_STATE_LINK_PROBLEM
            )
        };
        let placed = |id: &str, path: &str| {
            format!(
                "link `{id}` is at `{path}`, which {}",
                super::ZAP_STATE_ANCESTOR_LINK_PROBLEM
            )
        };
        let found = zap_state_claims(
            &resources(json!([
                {"id": "markers", "type": "directory", "path": "/var/lib/zap/pending/"},
                {"id": "state", "type": "link", "path": "/var/lib/x/../zap", "target": "/tmp"},
                {"id": "marker", "type": "file", "path": "/var/lib//zap/pending/nginx",
                 "content": {"type": "inline", "content": ""}},
                {"id": "climb", "type": "file", "path": "~/../var/lib/zap/x",
                 "content": {"type": "inline", "content": ""}},
                {"id": "into", "type": "link", "path": "/srv/state", "target": "/var/lib/zap"},
                {"id": "up", "type": "link", "path": "/var/lib/up", "target": "zap/pending"},
                {"id": "beside", "type": "directory", "path": "/var/lib/zapper"},
                {"id": "parent", "type": "directory", "path": "/var/lib"},
                {"id": "away", "type": "link", "path": "/var/lib/zap-x", "target": "../zapper"},
                {"id": "lib", "type": "link", "path": "/srv/l", "target": "/var/lib"},
                {"id": "under-lib", "type": "file", "path": "/srv/l/zap/pending/nginx",
                 "content": {"type": "inline", "content": ""}},
                {"id": "root", "type": "link", "path": "/srv/r", "target": "/"},
                {"id": "under-root", "type": "directory", "path": "/srv/r/var/lib/zap/pending"},
                {"id": "var", "type": "link", "path": "/srv/v", "target": "../var"},
                {"id": "over-lib", "type": "link", "path": "/var/lib", "target": "/srv/lib"},
                {"id": "over-var", "type": "link", "path": "/var/./", "target": "/srv/var"},
                {"id": "in-state", "type": "link", "path": "/var/lib/zap/x", "target": "/srv"},
            ])),
            Some("/var/lib/zap/app"),
        );
        assert_eq!(
            found,
            [
                "resource `markers` manages the path `/var/lib/zap/pending`, which is at or \
                 under `/var/lib/zap`, where zap keeps its own state; manage a path outside it",
                "resource `state` manages the path `/var/lib/x/../zap`, which is at or under \
                 `/var/lib/zap`, where zap keeps its own state; manage a path outside it",
                "resource `marker` manages the path `/var/lib/zap/pending/nginx`, which is at \
                 or under `/var/lib/zap`, where zap keeps its own state; manage a path \
                 outside it",
                "resource `climb` manages the path `~/../var/lib/zap/x`, a home-rooted path \
                 with a `..` component, which could climb out of the home into \
                 `/var/lib/zap`; write it without `..`",
                link("into", "/var/lib/zap").as_str(),
                link("up", "zap/pending").as_str(),
                link("lib", "/var/lib").as_str(),
                link("root", "/").as_str(),
                link("var", "../var").as_str(),
                placed("over-lib", "/var/lib").as_str(),
                placed("over-var", "/var/./").as_str(),
                "resource `in-state` manages the path `/var/lib/zap/x`, which is at or under \
                 `/var/lib/zap`, where zap keeps its own state; manage a path outside it",
                "`deploy.path` is at or under `/var/lib/zap`, where zap keeps its own state; \
                 manage a path outside it",
            ]
        );
    }

    #[test]
    fn a_path_is_compared_normalized() {
        for (written, normalized) in [
            ("/etc/x", "/etc/x"),
            ("/etc/x/", "/etc/x"),
            ("//etc///x", "/etc/x"),
            ("/etc/./x/.", "/etc/x"),
            ("/", "/"),
            ("~/x/", "~/x"),
            ("$HOME/x", "~/x"),
            ("$HOME", "~"),
            ("$HOMEDIR/x", "$HOMEDIR/x"),
            ("/etc/../x", "/etc/../x"),
            ("rel/./x", "rel/x"),
        ] {
            assert_eq!(normalized_path(written), normalized, "{written}");
        }
    }

    /// What each kind claims: the paths it writes, the account, service or database it
    /// manages, the firewall — and nothing for the kinds that only run or check.
    #[test]
    fn each_kind_claims_what_it_manages() {
        let path = |path: &str| Claim::Path(path.to_owned());
        let source = json!({"type": "remote", "url": "https://e.x/a.tgz"});
        for (resource, expected) in [
            (
                json!({"id": "f", "type": "file", "path": "/etc//x/",
                       "content": {"type": "source", "path": "/src"}}),
                vec![path("/etc/x")],
            ),
            (
                json!({"id": "d", "type": "directory", "path": "$HOME/d"}),
                vec![path("~/d")],
            ),
            (
                json!({"id": "l", "type": "link", "path": "/a", "target": "/b"}),
                vec![path("/a")],
            ),
            (
                json!({"id": "u", "type": "user", "username": "deploy"}),
                vec![Claim::Account("deploy".to_owned())],
            ),
            (
                json!({"id": "u", "type": "user", "username": "deploy", "sudo": false,
                       "ssh_keys": {"copy_from": "root"}}),
                vec![
                    Claim::Account("deploy".to_owned()),
                    path("/home/deploy/.ssh"),
                    path("/home/deploy/.ssh/authorized_keys"),
                    path("/etc/sudoers.d/deploy"),
                ],
            ),
            (
                json!({"id": "s", "type": "service", "service": "nginx"}),
                vec![Claim::Service("nginx".to_owned())],
            ),
            (
                json!({"id": "db", "type": "database", "engine": "postgresql",
                       "database_name": "app", "username": "owner"}),
                vec![Claim::Database("app".to_owned())],
            ),
            (
                json!({"id": "sw", "type": "swap", "size": "1G"}),
                vec![path("/swapfile")],
            ),
            (
                json!({"id": "fw", "type": "firewall", "backend": "ufw", "allow": []}),
                vec![Claim::Firewall],
            ),
            (
                json!({"id": "fw", "type": "firewall", "backend": "nftables", "allow": []}),
                vec![Claim::Firewall, path("/etc/nftables.nft")],
            ),
            (
                json!({"id": "repo", "type": "apt_repo", "key_url": "https://e.x/k",
                       "source": "deb https://e.x stable main"}),
                vec![
                    path("/usr/share/keyrings/repo.asc"),
                    path("/etc/apt/sources.list.d/repo.list"),
                ],
            ),
            (
                json!({"id": "repo", "type": "apt_repo", "key_url": "https://e.x/k",
                       "source": "deb https://e.x stable main", "key_path": "/k/x.asc",
                       "list_file": "/l/x.list"}),
                vec![path("/k/x.asc"), path("/l/x.list")],
            ),
            (
                json!({"id": "b", "type": "build", "source": source, "run": "make",
                       "output": "/opt/b"}),
                vec![path("/opt/b.zap-build"), path("/opt/b")],
            ),
            (
                json!({"id": "p", "type": "package", "from": {"apt": "curl"}}),
                vec![],
            ),
            (
                json!({"id": "i", "type": "installer", "url": "https://e.x/i", "check": "/opt/b"}),
                vec![],
            ),
            (
                json!({"id": "s", "type": "script", "check": "c", "run": "r"}),
                vec![],
            ),
            (json!({"id": "pl", "type": "pipeline", "steps": []}), vec![]),
            (
                json!({"id": "v", "type": "verify", "assertions": []}),
                vec![],
            ),
        ] {
            let parsed: Resource = serde_json::from_value(resource.clone()).unwrap();
            assert_eq!(claims(&parsed), expected, "{resource}");
        }
    }

    /// A thing two resources claim is a finding naming both and the thing; what only
    /// looks alike — a directory and a file in it, a package twice, two databases of
    /// one role — is none.
    #[test]
    fn a_thing_claimed_twice_is_a_finding() {
        const TAIL: &str = "; a thing is managed by one resource, or each run undoes the \
            other's change — merge them, or remove all but one";
        let inline = json!({"type": "inline", "content": "x"});
        let clean = resources(json!([
            {"id": "dir", "type": "directory", "path": "/etc/app"},
            {"id": "conf", "type": "file", "path": "/etc/app/conf", "content": inline},
            {"id": "curl", "type": "package", "from": {"apt": "curl"}},
            {"id": "curl-again", "type": "package", "from": {"apt": "curl"}},
            {"id": "db1", "type": "database", "engine": "postgresql", "database_name": "one",
             "username": "owner"},
            {"id": "db2", "type": "database", "engine": "postgresql", "database_name": "two",
             "username": "owner"},
            {"id": "u", "type": "user", "username": "deploy", "sudo": "nopasswd"},
            {"id": "keys-dir", "type": "directory", "path": "/home/deploy/.ssh"},
            {"id": "a", "type": "directory", "path": Text::reference("A")},
            {"id": "b", "type": "directory", "path": Text::reference("B")},
            {"id": "s1", "type": "script", "check": "c", "run": "r"},
            {"id": "s2", "type": "script", "check": "c", "run": "r"},
        ]));
        assert_eq!(conflicting_claims(&clean), Vec::<String>::new());

        let found = conflicting_claims(&resources(json!([
            {"id": "fw1", "type": "firewall", "backend": "nftables", "allow": []},
            {"id": "fw2", "type": "firewall", "backend": "ufw", "allow": []},
            {"id": "f", "type": "file", "path": "/etc/x", "content": inline},
            {"id": "d", "type": "directory", "path": "/etc/x/"},
            {"id": "l", "type": "link", "path": "//etc/./x", "target": "/y"},
            {"id": "u1", "type": "user", "username": "deploy", "sudo": "nopasswd"},
            {"id": "u2", "type": "user", "username": "deploy"},
            {"id": "sudoers", "type": "file", "path": "/etc/sudoers.d/deploy", "content": inline},
            {"id": "n1", "type": "service", "service": "nginx"},
            {"id": "n2", "type": "service", "service": "nginx", "enabled": false},
            {"id": "db1", "type": "database", "engine": "postgresql", "database_name": "app",
             "username": "one"},
            {"id": "db2", "type": "database", "engine": "postgresql", "database_name": "app",
             "username": "two"},
            {"id": "h1", "type": "directory", "path": "~/data"},
            {"id": "h2", "type": "directory", "path": "$HOME/data"},
        ])));
        assert_eq!(
            found,
            [
                format!(
                    "resources `u1` and `sudoers` each manage the path `/etc/sudoers.d/deploy`{TAIL}"
                ),
                format!("resources `f` and `d` and `l` each manage the path `/etc/x`{TAIL}"),
                format!("resources `h1` and `h2` each manage the path `~/data`{TAIL}"),
                format!("resources `u1` and `u2` each manage the account `deploy`{TAIL}"),
                format!("resources `n1` and `n2` each manage the service `nginx`{TAIL}"),
                format!("resources `db1` and `db2` each manage the database `app`{TAIL}"),
                format!("resources `fw1` and `fw2` each manage the host's firewall{TAIL}"),
            ]
        );

        // The same reference is the same claim; a reference is shown by its name where
        // the finding is printed.
        let found = conflicting_claims(&resources(json!([
            {"id": "a", "type": "directory", "path": Text::reference("DATA")},
            {"id": "b", "type": "file", "path": Text::reference("DATA"), "content": inline},
        ])));
        assert_eq!(found.len(), 1, "{found:?}");
        assert!(
            found[0].starts_with("resources `a` and `b` each manage the path `"),
            "{}",
            found[0]
        );
    }
}
