//! `verify` — whether every assertion holds.
//!
//! Each assertion is one command as the connecting user: a `path_exists` runs the `test`
//! / `stat` chain [`path_exists_check`] builds, a `command` its operator-authored `run`
//! ([`Query::operator_command`]). All pass → `Converged` (the verify is met); any failure
//! → `Absent`, so the plan runs the verify, whose execution re-runs the same assertions
//! and aborts. Execution runs each assertion on its own, from the same
//! [`path_exists_check`] text and the same [`assertion_failure`] reading of its result,
//! so detection and execution can't disagree about what an assertion means.
//!
//! A `path_exists` reads as the connecting user, so a path under a directory that user
//! can't search fails the assertion (the same privilege execution checks it under).

use super::{Query, QueryResult, command_answer};
use crate::detected::Detection;
use crate::schema::{
    CommandAssertion, FileType, PathExistsAssertion, VerifyAssertion, VerifyResource,
    normalize_mode,
};
use crate::shell::single_quote;

/// The shell a `path_exists` assertion runs — exit 0 iff the assertion holds.
///
/// `test -d` / `-f` / `-e` for its type, then, as declared, `test -s` (not empty) and a
/// `stat -L -c %a` / `%U` compare for its mode and owner, joined with `&&`. `stat`
/// follows a link as `test` does, and the mode is compared as `stat` prints it
/// ([`normalize_mode`]: `0644` is `644`).
#[must_use]
pub fn path_exists_check(assertion: &PathExistsAssertion) -> String {
    let PathExistsAssertion {
        path,
        file_type,
        mode,
        owner,
        not_empty,
    } = assertion;
    let path = single_quote(path);
    let mut checks = vec![match file_type {
        Some(FileType::Directory) => format!("test -d {path}"),
        Some(FileType::File) => format!("test -f {path}"),
        None => format!("test -e {path}"),
    }];
    if *not_empty {
        checks.push(format!("test -s {path}"));
    }
    if let Some(mode) = mode {
        checks.push(format!(
            "test \"$(stat -L -c %a -- {path})\" = {}",
            single_quote(normalize_mode(mode))
        ));
    }
    if let Some(owner) = owner {
        checks.push(format!(
            "test \"$(stat -L -c %U -- {path})\" = {}",
            single_quote(owner)
        ));
    }
    checks.join(" && ")
}

/// The command one assertion runs: [`path_exists_check`]'s chain, or a `command`'s `run`
/// verbatim.
#[must_use]
pub fn assertion_command(assertion: &VerifyAssertion) -> String {
    match assertion {
        VerifyAssertion::PathExists(path_exists) => path_exists_check(path_exists),
        VerifyAssertion::Command(CommandAssertion { run, .. }) => run.clone(),
    }
}

/// Why `assertion` failed, given its command's exit `code` and `stdout` — `None` when it
/// holds.
///
/// A `path_exists` holds iff its chain exited 0; a `command` iff its `run` exited 0 and,
/// with an `expect`, its stdout (read as UTF-8, invalid bytes replaced) contains it.
#[must_use]
pub fn assertion_failure(assertion: &VerifyAssertion, code: i32, stdout: &[u8]) -> Option<String> {
    match assertion {
        VerifyAssertion::PathExists(PathExistsAssertion { path, .. }) => {
            (code != 0).then(|| format!("path_exists: {path}"))
        }
        VerifyAssertion::Command(CommandAssertion { run, expect }) => {
            if code != 0 {
                Some(format!("command: '{run}' exited {code}"))
            } else if let Some(expect) = expect
                && !String::from_utf8_lossy(stdout).contains(expect.as_str())
            {
                Some(format!("command: '{run}' stdout missing '{expect}'"))
            } else {
                None
            }
        }
    }
}

/// A verify's reads: one command per assertion, in order — a `path_exists` chain as one
/// of zap's own commands, a `command`'s `run` as an operator command, both as the
/// connecting user.
#[must_use]
pub fn queries(verify: &VerifyResource) -> Vec<Query> {
    verify
        .assertions
        .iter()
        .map(|assertion| match assertion {
            VerifyAssertion::PathExists(path_exists) => {
                Query::login_command(path_exists_check(path_exists))
            }
            VerifyAssertion::Command(CommandAssertion { run, .. }) => {
                Query::operator_command(run.clone())
            }
        })
        .collect()
}

/// The verdict from the answers to [`queries`]: `Converged` when every assertion holds,
/// `Absent` when any fails ([`assertion_failure`]) — or held when an assertion's command
/// didn't run to an exit status.
#[must_use]
pub fn interpret(verify: &VerifyResource, results: &[QueryResult]) -> Detection {
    let mut failed = false;
    for (index, assertion) in verify.assertions.iter().enumerate() {
        let answer = match command_answer(results, index) {
            Ok(answer) => answer,
            Err(held) => return held,
        };
        failed |= assertion_failure(assertion, answer.code, &answer.stdout).is_some();
    }
    // Imperative: any failed assertion means the verify must (re-)run — a create, not
    // drift. All passing is converged (skip).
    if failed {
        Detection::Absent
    } else {
        Detection::Converged
    }
}

#[cfg(test)]
mod tests {
    use super::{assertion_failure, interpret, path_exists_check, queries};
    use crate::detected::Detection;
    use crate::observe::testing::exited;
    use crate::observe::{Query, QueryError};
    use crate::schema::{PathExistsAssertion, VerifyAssertion, VerifyResource};

    fn verify(json: &serde_json::Value) -> VerifyResource {
        serde_json::from_value(serde_json::json!({ "assertions": json })).unwrap()
    }

    #[test]
    fn a_path_exists_chain_tests_the_type_then_each_declared_gate() {
        let full: PathExistsAssertion = serde_json::from_value(serde_json::json!({
            "path": "/etc/it's.conf", "file_type": "file", "mode": "600", "owner": "app",
            "not_empty": true,
        }))
        .unwrap();
        assert_eq!(
            path_exists_check(&full),
            r#"test -f '/etc/it'\''s.conf' && test -s '/etc/it'\''s.conf' && test "$(stat -L -c %a -- '/etc/it'\''s.conf')" = '600' && test "$(stat -L -c %U -- '/etc/it'\''s.conf')" = 'app'"#
        );
        let bare: PathExistsAssertion =
            serde_json::from_value(serde_json::json!({"path": "/d", "file_type": "directory"}))
                .unwrap();
        assert_eq!(path_exists_check(&bare), "test -d '/d'");
        let any: PathExistsAssertion =
            serde_json::from_value(serde_json::json!({"path": "/x"})).unwrap();
        assert_eq!(path_exists_check(&any), "test -e '/x'");
    }

    #[test]
    fn a_leading_zero_mode_is_compared_as_stat_prints_it() {
        // `stat -c %a` prints `644`, never `0644`: a declared `0644` must compare as `644`.
        let zero: PathExistsAssertion =
            serde_json::from_value(serde_json::json!({"path": "/x", "mode": "0644"})).unwrap();
        assert_eq!(
            path_exists_check(&zero),
            r#"test -e '/x' && test "$(stat -L -c %a -- '/x')" = '644'"#
        );
    }

    #[test]
    fn a_path_exists_is_a_zap_command_and_a_command_an_operator_one() {
        let verify = verify(&serde_json::json!([
            {"type": "path_exists", "path": "/x"},
            {"type": "command", "run": "id -un", "expect": "ops"},
        ]));
        assert_eq!(
            queries(&verify),
            [
                Query::login_command("test -e '/x'"),
                Query::operator_command("id -un"),
            ]
        );
    }

    #[test]
    fn every_assertion_must_hold() {
        let verify = verify(&serde_json::json!([
            {"type": "path_exists", "path": "/x"},
            {"type": "command", "run": "id -un", "expect": "ops"},
        ]));
        assert_eq!(
            interpret(&verify, &[exited(0, ""), exited(0, "ops\n")]),
            Detection::Converged
        );
        for results in [
            [exited(1, ""), exited(0, "ops\n")],
            [exited(0, ""), exited(0, "root\n")],
            [exited(0, ""), exited(124, "ops\n")],
        ] {
            assert_eq!(interpret(&verify, &results), Detection::Absent);
        }
        // An assertion that didn't run to an exit status holds the verify, even when
        // another already failed.
        let timed_out = Err(QueryError::TimedOut {
            secs: crate::observe::COMMAND_TIMEOUT,
        });
        assert!(matches!(
            interpret(&verify, &[exited(1, ""), timed_out]),
            Detection::Undetermined { .. }
        ));
    }

    #[test]
    fn a_failure_names_the_assertion_as_execution_reports_it() {
        let [path, command]: [VerifyAssertion; 2] = serde_json::from_value(serde_json::json!([
            {"type": "path_exists", "path": "/x"},
            {"type": "command", "run": "cat /f", "expect": "yes"},
        ]))
        .unwrap();
        assert_eq!(assertion_failure(&path, 0, b""), None);
        assert_eq!(
            assertion_failure(&path, 1, b""),
            Some("path_exists: /x".to_owned())
        );
        assert_eq!(assertion_failure(&command, 0, b"oh yes\n"), None);
        assert_eq!(
            assertion_failure(&command, 3, b"yes"),
            Some("command: 'cat /f' exited 3".to_owned())
        );
        assert_eq!(
            assertion_failure(&command, 0, b"no\xff"),
            Some("command: 'cat /f' stdout missing 'yes'".to_owned())
        );
    }
}
