//! `script` — whether a script is already applied, by its operator-authored `check`.
//!
//! The `check` is an operator command ([`Query::operator_command`]): exit 0 means the
//! script is applied (`Converged`), anything else that it needs running (`Absent`, which
//! the planner turns into a create). A script never drifts.
//!
//! The check runs in the script's `cwd` with its `env` exported, composed into its
//! snippet ([`ScriptCheck`]) the same way on every connection — the check text and the
//! `env` values, their references resolved by the caller, travel inside the
//! batch, never on an argv. An `env` value is quoted here, after it resolved, so it can
//! hold any text; the check is the operator's own command text.
//!
//! A `cwd` that can't be entered is a check that failed, like a check naming the same
//! path inline: the script reads as not applied. Its `run` enters the same `cwd` the
//! same way and fails with nothing run when it can't.

use super::{Query, QueryResult, command_answer};
use crate::detected::Detection;
use crate::shell::{CdMessage, run_context};

/// Index of the one read in [`queries`].
const READ: usize = 0;

/// A script's check, composed with its `cwd` and `env`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScriptCheck {
    /// The snippet the check runs as.
    pub snippet: String,
}

impl ScriptCheck {
    /// Compose `check` and `env` (their references already resolved) with `cwd`
    /// (verbatim): the line [`run_context`] makes of them — the one a script's `run` is
    /// composed with, the `cd`'s output discarded — and the check on the line after.
    ///
    /// ```text
    /// CDPATH= cd -P -- '<cwd>' >/dev/null 2>&1 || exit; export K='v' …
    /// <check>
    /// ```
    ///
    /// A `cd` that fails ends the snippet with its nonzero status before the check runs.
    /// With neither a `cwd` nor `env`, the snippet is the check alone.
    #[must_use]
    pub fn new(check: &str, cwd: Option<&str>, env: &[(&str, &str)]) -> Self {
        let mut snippet = run_context(cwd, env.iter().copied(), CdMessage::Discarded);
        snippet.push_str(check);
        Self { snippet }
    }
}

/// A script's one read — its check, as an operator command.
#[must_use]
pub fn queries(check: &ScriptCheck) -> Vec<Query> {
    vec![Query::operator_command(check.snippet.clone())]
}

/// The verdict from the answer to [`queries`].
///
/// `Converged` when the snippet exited 0, `Absent` for any other exit — the check's own,
/// or the `cd`'s into a `cwd` that couldn't be entered — and held when it didn't run to
/// an exit status.
#[must_use]
pub fn interpret(results: &[QueryResult]) -> Detection {
    let answer = match command_answer(results, READ) {
        Ok(answer) => answer,
        Err(held) => return held,
    };
    // Imperative: the check passing means "already applied"; failing means "needs run",
    // which the planner treats as a create. Never drifts.
    if answer.succeeded() {
        Detection::Converged
    } else {
        Detection::Absent
    }
}

#[cfg(test)]
mod tests {
    use super::{ScriptCheck, interpret, queries};
    use crate::detected::Detection;
    use crate::observe::{
        COMMAND_TIMEOUT, CommandObservation, CommandOrigin, Observation, Privilege, Query,
        QueryError,
    };

    fn answer(code: i32, stdout: &[u8]) -> Vec<crate::observe::QueryResult> {
        vec![Ok(Observation::Command(CommandObservation {
            code,
            stdout: stdout.to_vec(),
            stderr: Vec::new(),
        }))]
    }

    #[test]
    fn the_check_follows_the_line_that_enters_its_cwd_and_exports_its_env() {
        let env = [("TOKEN", "a b"), ("MODE", "it's")];
        assert_eq!(
            ScriptCheck::new("test -f x", Some("/srv/my app"), &env).snippet,
            "CDPATH= cd -P -- '/srv/my app' >/dev/null 2>&1 || exit; export TOKEN='a b' \
             MODE='it'\\''s'\ntest -f x"
        );
    }

    #[test]
    fn each_of_cwd_and_env_composes_alone_and_neither_leaves_the_check_bare() {
        assert_eq!(
            ScriptCheck::new("test -f x", Some("/srv/app"), &[]).snippet,
            "CDPATH= cd -P -- '/srv/app' >/dev/null 2>&1 || exit\ntest -f x"
        );
        assert_eq!(
            ScriptCheck::new("test -f x", None, &[("TOKEN", "a b")]).snippet,
            "export TOKEN='a b'\ntest -f x"
        );
        assert_eq!(
            ScriptCheck::new("test -f x", None, &[]).snippet,
            "test -f x"
        );
    }

    #[test]
    fn the_check_is_one_operator_command() {
        let check = ScriptCheck::new("test -f x", None, &[]);
        assert_eq!(
            queries(&check),
            [Query::Command {
                snippet: "test -f x".to_owned(),
                privilege: Privilege::Login,
                timeout_secs: COMMAND_TIMEOUT,
                origin: CommandOrigin::Operator,
            }]
        );
    }

    #[test]
    fn exit_zero_is_applied_and_any_other_exit_needs_running() {
        // Whatever the snippet printed: only its exit is read.
        for stdout in [&b""[..], b"+", b"noise\n"] {
            assert_eq!(interpret(&answer(0, stdout)), Detection::Converged);
            // A check's own 124 or 143 is its exit, not a timeout.
            for code in [1, 2, 124, 127, 143] {
                assert_eq!(interpret(&answer(code, stdout)), Detection::Absent);
            }
        }
        let timed_out = [Err(QueryError::TimedOut {
            secs: COMMAND_TIMEOUT,
        })];
        assert_eq!(
            interpret(&timed_out),
            Detection::Undetermined {
                reason: "detection failed: timed out after 60s".to_owned(),
            }
        );
    }
}
