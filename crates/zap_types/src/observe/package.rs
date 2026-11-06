//! `package` — installed or not, by its `check` (a path, or a command) or the target
//! package manager's query.
//!
//! A package never drifts: it is installed (`Converged`) or missing (`Absent`), so it has
//! no `CurrentState`. A `check` that is a *command* (not path-like) is an operator
//! command ([`Query::operator_command`]), read by its exit status: 0 installed, anything
//! else not. The manager query answers 0 or 1, and any other status is a read that
//! failed, which holds.

use super::{
    PathFacet, Privilege, Query, QueryError, QueryResult, command_answer, exists_answer,
    succeeded_answer, undetermined,
};
use crate::detected::Detection;
use crate::package_managers;
use crate::schema::{PackageManager, PackageResource};

/// Index of the one read in [`queries`].
const READ: usize = 0;

/// How a package's installation is read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PackageCheck {
    /// A path `check`, resolved: installed iff the path exists.
    Path {
        /// The resolved path.
        path: String,
    },
    /// The target package manager's query: installed if it exits 0, missing if it exits
    /// 1, and held on any other status.
    Manager {
        /// The query command ([`package_managers::query`]).
        query: String,
    },
    /// A command `check`, verbatim: installed iff it exits 0.
    Command {
        /// The check command.
        check: String,
    },
    /// Nothing can be read — held with `reason`.
    Unreadable {
        /// Why the package can't be read.
        reason: String,
    },
}

impl PackageCheck {
    /// The manager query for a package with no `check`: the target's `manager`, the
    /// package's name for it, and that manager's query — or why one of them is missing.
    #[must_use]
    pub fn from_manager(package: &PackageResource, manager: Option<PackageManager>) -> Self {
        let Some(manager) = manager else {
            return Self::unreadable(
                "package_manager not set in target (required to query a package)",
            );
        };
        let Some(name) = package.from.get(&manager) else {
            let available: Vec<&str> = package.from.keys().map(|k| k.as_str()).collect();
            return Self::unreadable(format!(
                "package not defined for `{}` (have: {})",
                manager.as_str(),
                available.join(", ")
            ));
        };
        package_managers::query(manager, name).map_or_else(
            || {
                Self::unreadable(format!(
                    "no detection backend for package manager `{}`",
                    manager.as_str()
                ))
            },
            |query| Self::Manager { query },
        )
    }

    fn unreadable(reason: impl Into<String>) -> Self {
        Self::Unreadable {
            reason: reason.into(),
        }
    }
}

/// A package's one read:
///
/// - a path `check` — the [`Kind`](PathFacet::Kind) of the resolved path, at
///   [`Elevated`](Privilege::Elevated) (`test -e` semantics, as zap's own reads of a
///   path run);
/// - the manager query — a [`Query::login_command`], as the connecting user;
/// - a command `check` — a [`Query::operator_command`], as the connecting user.
///
/// Nothing for a package that can't be read.
#[must_use]
pub fn queries(check: &PackageCheck) -> Vec<Query> {
    match check {
        PackageCheck::Path { path } => {
            vec![Query::path(path, PathFacet::Kind, Privilege::Elevated)]
        }
        PackageCheck::Manager { query } => vec![Query::login_command(query)],
        PackageCheck::Command { check } => vec![Query::operator_command(check)],
        PackageCheck::Unreadable { .. } => Vec::new(),
    }
}

/// The verdict for a package from the answers to [`queries`].
///
/// `Converged` when the path exists or the query or command `check` exits 0. A command
/// `check` that exits anything else reads `Absent`, as its exit status is its whole
/// answer; the manager query reads `Absent` only on 1, its "not installed", and holds on
/// any other status — `dpkg-query` or `apk` failing to read is no answer.
#[must_use]
pub fn interpret(check: &PackageCheck, results: &[QueryResult]) -> Detection {
    let installed = match check {
        PackageCheck::Path { .. } => exists_answer(results, READ),
        PackageCheck::Manager { .. } => {
            command_answer(results, READ).and_then(|answer| match answer.code {
                0 => Ok(true),
                1 => Ok(false),
                code => Err(undetermined(&QueryError::Exited { code })),
            })
        }
        PackageCheck::Command { .. } => succeeded_answer(results, READ),
        PackageCheck::Unreadable { reason } => {
            return Detection::Undetermined {
                reason: reason.clone(),
            };
        }
    };
    match installed {
        Ok(true) => Detection::Converged,
        Ok(false) => Detection::Absent,
        Err(held) => held,
    }
}

#[cfg(test)]
mod tests {
    use super::{PackageCheck, interpret, queries};
    use crate::detected::Detection;
    use crate::observe::{
        CommandObservation, FileKind, Observation, PathObservation, Privilege, Query, QueryError,
    };
    use crate::schema::{PackageManager, PackageResource};

    fn package(from: &serde_json::Value) -> PackageResource {
        serde_json::from_value(serde_json::json!({"from": from})).unwrap()
    }

    fn exited(code: i32) -> Observation {
        Observation::Command(CommandObservation {
            code,
            stdout: Vec::new(),
            stderr: Vec::new(),
        })
    }

    #[test]
    fn a_path_check_reads_elevated_and_the_query_as_the_login_user() {
        let path = PackageCheck::Path {
            path: "/usr/bin/jq".to_owned(),
        };
        assert_eq!(queries(&path)[0].privilege(), Privilege::Elevated);
        let manager = PackageCheck::from_manager(
            &package(&serde_json::json!({"apk": "jq"})),
            Some(PackageManager::Apk),
        );
        assert_eq!(queries(&manager), [Query::login_command("apk info -e jq")]);
        let command = PackageCheck::Command {
            check: "command -v jq".to_owned(),
        };
        assert_eq!(
            queries(&command),
            [Query::operator_command("command -v jq")]
        );
    }

    #[test]
    fn a_command_check_exit_status_is_the_answer() {
        let check = PackageCheck::Command {
            check: "c".to_owned(),
        };
        assert_eq!(interpret(&check, &[Ok(exited(0))]), Detection::Converged);
        // Any failing exit reads missing — a check's own 124 or 143 included.
        for code in [1, 2, 124, 127, 143] {
            assert_eq!(interpret(&check, &[Ok(exited(code))]), Detection::Absent);
        }
    }

    /// The manager query answers 0 or 1; a query that exits anything else failed to
    /// read — `dpkg-query` with its database unreadable, a missing tool — and holds,
    /// never reading missing.
    #[test]
    fn the_manager_query_answers_by_0_or_1_and_holds_otherwise() {
        let check = PackageCheck::Manager {
            query: "q".to_owned(),
        };
        assert_eq!(interpret(&check, &[Ok(exited(0))]), Detection::Converged);
        assert_eq!(interpret(&check, &[Ok(exited(1))]), Detection::Absent);
        for code in [
            crate::package_managers::QUERY_FAILED_EXIT,
            3,
            124,
            126,
            127,
            143,
            -1,
        ] {
            assert_eq!(
                interpret(&check, &[Ok(exited(code))]),
                Detection::Undetermined {
                    reason: format!("detection failed: the probe exited {code}")
                },
                "{code}"
            );
        }
    }

    #[test]
    fn an_unanswered_command_holds() {
        for check in [
            PackageCheck::Manager {
                query: "q".to_owned(),
            },
            PackageCheck::Command {
                check: "c".to_owned(),
            },
        ] {
            assert!(matches!(
                interpret(
                    &check,
                    &[Err(QueryError::TimedOut {
                        secs: crate::observe::COMMAND_TIMEOUT
                    })]
                ),
                Detection::Undetermined { .. }
            ));
        }
    }

    #[test]
    fn a_path_check_is_existence() {
        let check = PackageCheck::Path {
            path: "/x".to_owned(),
        };
        assert_eq!(
            interpret(
                &check,
                &[Ok(Observation::Path(PathObservation::Kind(
                    FileKind::Directory
                )))]
            ),
            Detection::Converged
        );
        assert_eq!(
            interpret(&check, &[Ok(Observation::Path(PathObservation::Failed))]),
            Detection::Absent
        );
        assert!(matches!(
            interpret(&check, &[Err(QueryError::Exited { code: 2 })]),
            Detection::Undetermined { .. }
        ));
    }

    #[test]
    fn a_package_the_target_cant_query_holds_without_reading() {
        let jq = package(&serde_json::json!({"apt": "jq"}));
        for (manager, reason) in [
            (
                None,
                "package_manager not set in target (required to query a package)",
            ),
            (
                Some(PackageManager::Apk),
                "package not defined for `apk` (have: apt)",
            ),
        ] {
            let check = PackageCheck::from_manager(&jq, manager);
            assert!(queries(&check).is_empty());
            assert_eq!(
                interpret(&check, &[]),
                Detection::Undetermined {
                    reason: reason.to_owned()
                }
            );
        }
        let brew = package(&serde_json::json!({"brew": "jq"}));
        assert_eq!(
            interpret(
                &PackageCheck::from_manager(&brew, Some(PackageManager::Brew)),
                &[]
            ),
            Detection::Undetermined {
                reason: "no detection backend for package manager `brew`".to_owned()
            }
        );
    }
}
