//! Every kind's observe → interpret form, and the one path it detects through.
//!
//! Each kind's queries and verdict are pure (`zap_types::observe`); this module maps a
//! resource to them and applies the rule that belongs to the runner rather than any one
//! kind: a lane whose whole batch failed holds **every** resource with a query in it,
//! even one whose verdict wouldn't have read that answer. `detect_all` gathers every
//! resource's queries into one [`Connection::observe`] call; `detect_resource` runs the
//! same queries alone — one detector either way. A `pipeline` reads nothing: it always
//! runs.

use std::path::Path;

use zap_types::config_hash::build_provenance;
use zap_types::detected::Detection;
use zap_types::lock::LockEntry;
use zap_types::observe::build::BuildDesired;
use zap_types::observe::package::PackageCheck;
use zap_types::observe::script::ScriptCheck;
use zap_types::observe::service::ServiceCheck;
use zap_types::observe::{self, Query, QueryError, QueryResult};
use zap_types::postgres::{PgHbaField, pg_hba_field_problem};
use zap_types::scalar::ContentHash;
use zap_types::schema::{
    AptRepoResource, BuildSource, DatabaseResource, DeclaredPackageCheck, DirectoryResource,
    FirewallResource, MissingResolvedField, ResolvedField, ResolvedFields, Resource, ResourceKind,
    ScriptResource, ServiceResource, Target, UserResource, VerifyResource,
};

use super::file::FileCheck;
use crate::connection::Connection;
use crate::resolve::{UnsafeValue, resolve_command, resolve_env_value, resolve_field};

/// A resource that detects by typed queries, with its resolved fields.
#[derive(Debug)]
pub(super) enum Observed<'a> {
    /// An `apt_repo`, with its resource id (which names its default key and list) and
    /// the pin its key must hash to.
    AptRepo {
        /// The resource id.
        id: &'a str,
        /// The declared resource.
        repo: &'a AptRepoResource,
        /// The key's pin: the declared `key_blake3`, else the lock's.
        pin: Option<ContentHash>,
    },
    /// A `build` at its resolved output, with the provenance digest it must record.
    Build {
        /// The resolved output path.
        output: String,
        /// The desired provenance.
        desired: BuildDesired,
    },
    /// A `database`, with its seam-resolved role and database names — the same
    /// identifiers the hash captured and the mutation runs with (a `zap.env('USER')` role is
    /// the operator's user).
    Database {
        /// The declared resource (its `pg_hba` rules).
        database: &'a DatabaseResource,
        /// The resolved role name.
        user: String,
        /// The resolved database name.
        db: String,
        /// The declared `pg_hba` hosts, references resolved as the mutation's
        /// command runner resolves them.
        hosts: Vec<String>,
    },
    /// A `directory` at its resolved path.
    Directory {
        /// The declared resource (its managed mode/owner/group).
        dir: &'a DirectoryResource,
        /// The resolved path.
        path: String,
    },
    /// A `file`, with its desired side.
    File(FileCheck<'a>),
    /// A `firewall`.
    Firewall(&'a FirewallResource),
    /// An `installer`, by its resolved `check` path.
    Installer {
        /// The resolved check path.
        check: String,
    },
    /// A `link` at its resolved path, with the resolved desired target.
    Link {
        /// The resolved path.
        path: String,
        /// The resolved desired target.
        target: String,
    },
    /// A `package` checked by path, by command, or by the target's package manager.
    Package(PackageCheck),
    /// A `pipeline`, which reads nothing — it always runs.
    Pipeline,
    /// A `script`, by its check composed with its `cwd` and `env`.
    Script(ScriptCheck),
    /// A resource whose desired side couldn't be built — a reference resolves to a value
    /// its command text, or a name its probe reads by, can't take. It reads nothing and
    /// holds, with the reason.
    Unresolvable {
        /// Why, naming the variable and never its value.
        reason: String,
    },
    /// A `service`, with the target service manager's probes.
    Service {
        /// The declared resource (its desired enabled/running state).
        service: &'a ServiceResource,
        /// Its probes.
        check: ServiceCheck,
    },
    /// A `swap` file at its (verbatim) path.
    Swap {
        /// The declared path.
        path: &'a str,
    },
    /// A `user`.
    User(&'a UserResource),
    /// A `verify`, by its assertions.
    Verify(&'a VerifyResource),
}

impl<'a> Observed<'a> {
    /// The observe → interpret form of `resource` on `target`, given its seam-resolved
    /// fields. A `file`, a `build`, and an `apt_repo` also take their lock entry (a
    /// tracked pin); a
    /// `file` the `~/.zap` root whose content cache supplies a `remote` file's desired
    /// digest.
    ///
    /// A field its kind reads that `resolved` lacks holds the resource
    /// ([`MissingResolvedField`]), as execution fails the change: it is never probed
    /// as `""`.
    pub(super) async fn for_resource(
        conn: &Connection,
        target: &Target,
        resource: &'a Resource,
        resolved: ResolvedFields,
        lock_entry: Option<&LockEntry>,
        zap_home: Option<&Path>,
    ) -> Self {
        Self::from_resolved(conn, target, resource, resolved, lock_entry, zap_home)
            .await
            .unwrap_or_else(|missing| Self::Unresolvable {
                reason: missing.to_string(),
            })
    }

    /// [`for_resource`](Self::for_resource), short of a field `resolved` lacks.
    async fn from_resolved(
        conn: &Connection,
        target: &Target,
        resource: &'a Resource,
        mut resolved: ResolvedFields,
        lock_entry: Option<&LockEntry>,
        zap_home: Option<&Path>,
    ) -> Result<Self, MissingResolvedField> {
        let lock_pin = lock_entry.and_then(LockEntry::pin).map(ContentHash::as_str);
        Ok(match &resource.kind {
            ResourceKind::AptRepo(repo) => Self::AptRepo {
                id: &resource.id.0,
                repo,
                pin: repo
                    .key_blake3
                    .clone()
                    .or_else(|| lock_entry.and_then(LockEntry::pin).cloned()),
            },
            ResourceKind::Build(build) => {
                let BuildSource::Remote(remote) = &build.source;
                let desired = remote.blake3.as_deref().or(lock_pin).map_or_else(
                    || BuildDesired::Unpinned {
                        id: resource.id.0.clone(),
                    },
                    |pin| BuildDesired::Pinned {
                        provenance: build_provenance(pin, build),
                    },
                );
                Self::Build {
                    output: resolved.take(ResolvedField::Output)?,
                    desired,
                }
            }
            ResourceKind::Database(database) => {
                let hosts: Result<Vec<String>, _> = database
                    .auth_hosts()
                    .iter()
                    .enumerate()
                    .map(|(index, host)| {
                        UnsafeValue::held_to(
                            &format!("auth.hosts[{index}]"),
                            resolve_field(host)?,
                            |host| pg_hba_field_problem(host, PgHbaField::Host),
                        )
                    })
                    .collect();
                match hosts {
                    Ok(hosts) => Self::Database {
                        database,
                        user: resolved.take(ResolvedField::Username)?,
                        db: resolved.take(ResolvedField::DatabaseName)?,
                        hosts,
                    },
                    // A refusal that names its field reads as the seam's own do.
                    Err(error @ UnsafeValue::Field { .. }) => Self::Unresolvable {
                        reason: error.to_string(),
                    },
                    Err(error) => Self::Unresolvable {
                        reason: format!("detection failed: auth.hosts: {error}"),
                    },
                }
            }
            ResourceKind::Directory(dir) => Self::Directory {
                dir,
                path: resolved.take(ResolvedField::Path)?,
            },
            ResourceKind::File(file) => Self::File(
                FileCheck::new(
                    conn,
                    file,
                    &resource.id,
                    resolved.take(ResolvedField::Path)?,
                    lock_pin,
                    zap_home,
                )
                .await,
            ),
            ResourceKind::Firewall(firewall) => Self::Firewall(firewall),
            ResourceKind::Installer(_) => Self::Installer {
                check: resolved.take(ResolvedField::Check)?,
            },
            ResourceKind::Link(_) => Self::Link {
                path: resolved.take(ResolvedField::Path)?,
                target: resolved.take(ResolvedField::Target)?,
            },
            ResourceKind::Package(package) => Self::Package(match &package.check {
                // A command `check` is an operator command, verbatim. The variant is the
                // one `config_hash` hashes by, so the two can't disagree on a
                // `$HOME`-prefixed check.
                Some(DeclaredPackageCheck::Command(check)) => PackageCheck::Command {
                    check: check.clone(),
                },
                Some(DeclaredPackageCheck::Path(check)) => match conn.apply_home(check) {
                    Ok(path) => PackageCheck::Path { path },
                    Err(error) => PackageCheck::Unreadable {
                        reason: format!("detection failed: {error}"),
                    },
                },
                None => PackageCheck::from_manager(package, target.package_manager),
            }),
            ResourceKind::Pipeline(_) => Self::Pipeline,
            ResourceKind::Script(script) => match script_check(script) {
                Ok(check) => Self::Script(check),
                Err(reason) => Self::Unresolvable { reason },
            },
            ResourceKind::Service(service) => Self::Service {
                service,
                check: ServiceCheck::new(service, target.service_manager),
            },
            ResourceKind::Swap(swap) => Self::Swap { path: &swap.path },
            ResourceKind::User(user) => Self::User(user),
            ResourceKind::Verify(verify) => Self::Verify(verify),
        })
    }

    /// The target reads this resource's verdict depends on.
    pub(super) fn queries(&self) -> Vec<Query> {
        match self {
            Self::AptRepo { id, repo, .. } => observe::apt_repo::queries(id, repo),
            Self::Build { output, desired } => observe::build::queries(output, desired),
            Self::Database {
                database,
                user,
                db,
                hosts,
            } => observe::database::queries(database, user, db, hosts),
            Self::Directory { dir, path } => observe::directory::queries(dir, path),
            Self::File(check) => observe::file::queries(check.file, &check.path, &check.desired),
            Self::Firewall(firewall) => observe::firewall::queries(firewall),
            Self::Installer { check } => observe::installer::queries(check),
            Self::Link { path, .. } => observe::link::queries(path),
            Self::Package(check) => observe::package::queries(check),
            Self::Pipeline | Self::Unresolvable { .. } => Vec::new(),
            Self::Script(check) => observe::script::queries(check),
            Self::Service { check, .. } => observe::service::queries(check),
            Self::Swap { path } => observe::swap::queries(path),
            Self::User(user) => observe::user::queries(user),
            Self::Verify(verify) => observe::verify::queries(verify),
        }
    }

    /// The verdict from the answers to [`queries`](Self::queries), in order. A `file`
    /// whose content the batch can't settle reads the target's bytes over `conn` first.
    pub(super) async fn conclude(&self, conn: &Connection, results: &[QueryResult]) -> Detection {
        if let Some(failed) = results.iter().find_map(|result| {
            result
                .as_ref()
                .err()
                .filter(|e| matches!(e, QueryError::Batch { .. }))
        }) {
            return observe::undetermined(failed);
        }
        match self {
            Self::AptRepo { id, pin, .. } => {
                observe::apt_repo::interpret(id, pin.as_ref(), results)
            }
            Self::Build { output, desired } => observe::build::interpret(output, desired, results),
            Self::Database { database, user, .. } => {
                observe::database::interpret(database, user, results)
            }
            Self::Directory { dir, path } => observe::directory::interpret(dir, path, results),
            Self::File(check) => check.conclude(conn, results).await,
            Self::Firewall(firewall) => observe::firewall::interpret(firewall, results),
            Self::Installer { .. } => observe::installer::interpret(results),
            Self::Link { target, .. } => observe::link::interpret(target, results),
            Self::Package(check) => observe::package::interpret(check, results),
            // Imperative: its steps always run, so it never converges.
            Self::Pipeline => Detection::Absent,
            Self::Script(_) => observe::script::interpret(results),
            Self::Unresolvable { reason } => super::undetermined(reason.clone()),
            Self::Service { service, check } => {
                observe::service::interpret(service, check, results)
            }
            Self::Swap { .. } => observe::swap::interpret(results),
            Self::User(user) => observe::user::interpret(user, results),
            Self::Verify(verify) => observe::verify::interpret(verify, results),
        }
    }

    /// Detect this resource alone — its queries as their own batch (none for a resource
    /// that reads nothing). A pass that can't reach the target holds it.
    pub(super) async fn detect_alone(&self, conn: &Connection) -> Detection {
        let queries = self.queries();
        if queries.is_empty() {
            return self.conclude(conn, &[]).await;
        }
        match conn.observe(&queries).await {
            Ok(answers) => {
                super::conclude_span(self, conn, &queries, 0..queries.len(), &answers.results).await
            }
            Err(error) => super::undetermined(format!("detection failed: {error}")),
        }
    }
}

/// A script's check, composed with its `cwd` and `env` — the same snippet for every
/// connection ([`ScriptCheck::new`]): the line that enters the `cwd` and exports the
/// `env`, then the check. The check's references resolve here — into the batch, never
/// an argv — as command text (`resolve_command`); an `env` value's resolve before it is
/// quoted, so it carries any value; `cwd` is verbatim, as the script's `run` takes it.
///
/// # Errors
/// The held reason, when a reference resolves to a value its place can't take.
fn script_check(script: &ScriptResource) -> Result<ScriptCheck, String> {
    let unresolvable = |error| format!("detection failed: the check was not run: {error}");
    let check = resolve_command(&script.check).map_err(unresolvable)?;
    let env = script
        .env
        .iter()
        .flatten()
        .map(|(name, value)| resolve_env_value(value).map(|value| (name.as_str(), value)))
        .collect::<Result<Vec<_>, _>>()
        .map_err(unresolvable)?;
    let env: Vec<(&str, &str)> = env
        .iter()
        .map(|(name, value)| (*name, value.as_str()))
        .collect();
    Ok(ScriptCheck::new(&check, script.cwd.as_deref(), &env))
}

#[cfg(test)]
mod tests {
    use zap_types::detected::Detection;
    use zap_types::observe::{Lane, Observation, PathObservation, QueryError};
    use zap_types::schema::{ResolvedField, ResolvedFields, Resource, ResourceKind, Target};
    use zap_types::text::Text;
    use zap_types::var_ref::Segment::{Ref, Text as Lit};
    use zap_types::var_ref::shown;

    use super::{Observed, script_check};
    use crate::connection::{Connection, MockConnection, SshConnection};

    fn script(check: impl serde::Serialize, cwd: Option<&str>) -> Resource {
        serde_json::from_value(serde_json::json!({
            "id": "s", "type": "script", "check": check, "run": "true", "cwd": cwd,
            "env": {"ZAP_B": "it's b", "ZAP_A": "a"},
        }))
        .unwrap()
    }

    /// A script's check is one snippet whatever the connection: the line that enters the
    /// `cwd` and exports the `env`, then the check with its references resolved.
    #[tokio::test]
    async fn a_script_check_is_composed_the_same_for_every_connection() {
        let ssh = Connection::Ssh(SshConnection {
            host: "host.example".to_owned(),
            user: "ops".to_owned(),
            port: None,
            key_path: None,
            home: None,
        });
        let mock = Connection::Mock(MockConnection::new("host.example"));
        let env = r"export ZAP_A='a' ZAP_B='it'\''s b'";
        let check = r#"test "zap_core" = zap_core"#;
        for (cwd, composed) in [
            (None, format!("{env}\n{check}")),
            (
                Some("/srv/my app"),
                format!("CDPATH= cd -P -- '/srv/my app' >/dev/null 2>&1 || exit; {env}\n{check}"),
            ),
        ] {
            let resource = script(
                Text::of_pieces([Lit("test \""), Ref("CARGO_PKG_NAME"), Lit("\" = zap_core")]),
                cwd,
            );
            for conn in [&ssh, &mock, &Connection::Local] {
                let observed = Observed::for_resource(
                    conn,
                    &Target::local(),
                    &resource,
                    ResolvedFields::default(),
                    None,
                    None,
                )
                .await;
                let queries = observed.queries();
                let [zap_types::observe::Query::Command { snippet, .. }] = queries.as_slice()
                else {
                    panic!("one command");
                };
                assert_eq!(snippet, &composed, "{cwd:?}");
            }
        }
    }

    /// A reference in a `pg_hba` host reaches the detection snippet resolved, as the
    /// mutation's command runner resolves it — never the literal reference, which no
    /// `pg_hba.conf` line matches.
    #[tokio::test]
    async fn a_database_host_reference_is_resolved_in_the_snippet() {
        let _env = crate::resolve::test_env::set(&[("ZAP_T_DB_HOST", "10.1.2.0/24")]);
        let resource: Resource = serde_json::from_value(serde_json::json!({
            "id": "db", "type": "database", "engine": "postgresql", "database_name": "app",
            "username": "app", "auth": {"method": "scram-sha-256", "hosts": [Text::reference("ZAP_T_DB_HOST")]},
        }))
        .unwrap();
        let conn = Connection::Mock(MockConnection::new("host.example"));
        let resolved = [
            (ResolvedField::Username, "app".to_owned()),
            (ResolvedField::DatabaseName, "app".to_owned()),
        ]
        .into_iter()
        .collect();
        let observed =
            Observed::for_resource(&conn, &Target::local(), &resource, resolved, None, None).await;
        let queries = observed.queries();
        let [zap_types::observe::Query::Command { snippet, .. }] = queries.as_slice() else {
            panic!("one command");
        };
        assert!(snippet.contains(r"\s+10\.1\.2\.0/24\s+"), "{snippet}");
        assert!(!snippet.contains("ZAP_T_DB_HOST"), "{snippet}");
    }

    /// A `pg_hba` host reference that resolves to an address keyword (a set of
    /// addresses) or a host name holds the resource: no detection read is made with it.
    #[tokio::test]
    async fn a_database_host_reference_resolving_to_a_keyword_or_name_is_held() {
        for value in ["samenet", "all", "db.example.com"] {
            let _env = crate::resolve::test_env::set(&[("ZAP_T_DB_HOST", value)]);
            let resource: Resource = serde_json::from_value(serde_json::json!({
                "id": "db", "type": "database", "engine": "postgresql", "database_name": "app",
                "username": "app", "auth": {"hosts": [Text::reference("ZAP_T_DB_HOST")]},
            }))
            .unwrap();
            let conn = Connection::Mock(MockConnection::new("host.example"));
            let resolved = [
                (ResolvedField::Username, "app".to_owned()),
                (ResolvedField::DatabaseName, "app".to_owned()),
            ]
            .into_iter()
            .collect();
            let observed =
                Observed::for_resource(&conn, &Target::local(), &resource, resolved, None, None)
                    .await;
            assert!(observed.queries().is_empty(), "{value}");
            let Observed::Unresolvable { reason } = &observed else {
                panic!("{value}: held");
            };
            assert!(
                reason.contains("auth.hosts[0]")
                    && reason.contains("is not an IP address with a prefix length"),
                "{value}: {reason}"
            );
        }
    }

    /// A `package` check that is a path is probed where it resolves — its reference from
    /// the operator's environment, its `~` against the target's home — and one that is a
    /// command runs as written, a `$$` in it included.
    #[tokio::test]
    async fn a_package_path_check_is_resolved_and_a_command_check_is_not() {
        let _env = crate::resolve::test_env::set(&[("ZAP_T_TOOL", "tool")]);
        let package = |check: serde_json::Value| -> Resource {
            serde_json::from_value(serde_json::json!({
                "id": "p", "type": "package", "from": {"apt": "tool"}, "check": check,
            }))
            .unwrap()
        };
        let conn = Connection::Mock(MockConnection::new("host.example").with_home("/home/op"));
        let queries = |resource: Resource| {
            let conn = &conn;
            async move {
                Observed::for_resource(
                    conn,
                    &Target::local(),
                    &resource,
                    ResolvedFields::default(),
                    None,
                    None,
                )
                .await
                .queries()
            }
        };
        let path = queries(package(serde_json::json!(Text::of_pieces([
            Lit("~/.local/"),
            Ref("ZAP_T_TOOL"),
            Lit("/bin"),
        ]))))
        .await;
        let [zap_types::observe::Query::Path { path, .. }] = path.as_slice() else {
            panic!("one path read: {path:?}");
        };
        assert_eq!(path, "/home/op/.local/tool/bin");
        let command = queries(package(serde_json::json!("tool --version || kill $$"))).await;
        let [zap_types::observe::Query::Command { snippet, .. }] = command.as_slice() else {
            panic!("one command: {command:?}");
        };
        assert_eq!(snippet, "tool --version || kill $$");
    }

    /// A check whose reference resolves to a value holding a single quote isn't run: the
    /// script reads nothing and holds, the reason naming the variable and never the value.
    #[tokio::test]
    async fn a_script_check_that_cannot_take_a_value_holds_unread() {
        let _env = crate::resolve::test_env::set(&[("ZAP_T_QUOTE", "it's secret")]);
        let resource = script(
            Text::of_pieces([Lit("test \""), Ref("ZAP_T_QUOTE"), Lit("\" = x")]),
            None,
        );
        let mock = MockConnection::new("host.example");
        for conn in [Connection::Local, Connection::Mock(mock)] {
            let observed = Observed::for_resource(
                &conn,
                &Target::local(),
                &resource,
                ResolvedFields::default(),
                None,
                None,
            )
            .await;
            assert!(observed.queries().is_empty());
            let Detection::Undetermined { reason } = observed.detect_alone(&conn).await else {
                panic!("held");
            };
            assert!(
                reason.contains(&format!("`{}`", shown("ZAP_T_QUOTE"))),
                "{reason}"
            );
            assert!(reason.contains("was not run"), "{reason}");
            assert!(!reason.contains("secret"), "{reason}");
        }
    }

    /// A script's `env` value resolves its references and then is quoted, so it carries
    /// any value — a single quote included — to the check, run through a real shell.
    #[tokio::test]
    async fn a_script_env_value_resolves_and_reaches_the_check_byte_exact() {
        let value = "it's '' a `$HOME` \"q\" ; \\ value";
        let _env = crate::resolve::test_env::set(&[("ZAP_T_VALUE", value)]);
        let resource: Resource = serde_json::from_value(serde_json::json!({
            "id": "s", "type": "script", "run": "true",
            "check": "sh -c 'printf \"%s\" \"$ZAP_T_GIVEN\"'",
            "env": {"ZAP_T_GIVEN": Text::of_pieces([Lit("<"), Ref("ZAP_T_VALUE"), Lit(">")])},
        }))
        .unwrap();
        let ResourceKind::Script(declared) = &resource.kind else {
            unreachable!()
        };
        let check = script_check(declared).unwrap();
        let ran = Connection::Local.run_default(&check.snippet).await.unwrap();
        assert_eq!(ran.stdout, format!("<{value}>"), "{}", check.snippet);
    }

    /// A script `env` value that resolves to something no environment can carry (a NUL)
    /// holds the script unread too, naming the variable.
    #[tokio::test]
    async fn a_script_env_value_that_cannot_be_carried_holds_unread() {
        let _env = crate::resolve::test_env::set(&[("ZAP_T_NUL", "a\0secret")]);
        let resource: Resource = serde_json::from_value(serde_json::json!({
            "id": "s", "type": "script", "run": "true", "check": "true",
            "env": {"ZAP_T_GIVEN": Text::reference("ZAP_T_NUL")},
        }))
        .unwrap();
        let conn = Connection::Local;
        let observed = Observed::for_resource(
            &conn,
            &Target::local(),
            &resource,
            ResolvedFields::default(),
            None,
            None,
        )
        .await;
        assert!(observed.queries().is_empty());
        let Detection::Undetermined { reason } = observed.detect_alone(&conn).await else {
            panic!("held");
        };
        assert!(
            reason.contains(&format!("`{}`", shown("ZAP_T_NUL"))),
            "{reason}"
        );
        assert!(!reason.contains("secret"), "{reason}");
    }

    /// On a local target the check sees its `env` throughout and runs in its `cwd`, and a
    /// `cwd` that can't be entered reads as not applied, like a check that failed there —
    /// through a real local batch.
    #[tokio::test]
    async fn a_local_script_check_runs_in_its_cwd_with_its_env() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("marker"), "").unwrap();
        let cwd = dir.path().to_string_lossy().into_owned();
        let check = r#"test "$ZAP_B" = "it's b" && test "$ZAP_A" = a && test -f marker"#;
        let detect = |resource: Resource| async move {
            super::super::detect_resource(
                &Connection::Local,
                &Target::local(),
                &resource,
                None,
                None,
            )
            .await
        };
        assert_eq!(
            detect(script(check, Some(&cwd))).await,
            Detection::Converged
        );
        assert_eq!(
            detect(script("test -f absent-marker", Some(&cwd))).await,
            Detection::Absent
        );
        let gone = dir.path().join("gone").to_string_lossy().into_owned();
        assert_eq!(detect(script("true", Some(&gone))).await, Detection::Absent);
    }

    #[tokio::test]
    async fn a_failed_lane_holds_the_resource_even_when_its_verdict_would_not_read_it() {
        let resource: Resource = serde_json::from_value(
            serde_json::json!({"id": "d", "type": "directory", "path": "/d", "mode": "755"}),
        )
        .unwrap();
        let conn = Connection::Mock(MockConnection::new("mock"));
        let observed = Observed::for_resource(
            &conn,
            &Target::default(),
            &resource,
            std::iter::once((ResolvedField::Path, "/d".to_owned())).collect(),
            None,
            None,
        )
        .await;
        // Absent by its existence read alone — but the root lane failed as a whole.
        let results = [
            Ok(Observation::Path(PathObservation::Failed)),
            Err(QueryError::Batch {
                lane: Lane::Root,
                reason: "it exited 1".to_owned(),
            }),
        ];
        assert_eq!(
            observed.conclude(&conn, &results).await,
            Detection::Undetermined {
                reason: "detection failed: the root batch failed: it exited 1".to_owned(),
            }
        );
    }
}
