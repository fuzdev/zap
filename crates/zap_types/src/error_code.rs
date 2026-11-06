//! Execution error taxonomy — classifying a failed command into a triage category.
//!
//! A failed change carries an [`ErrorCode`] beside its message ([`crate::event::
//! ChangeOutcome::Failed`]) so operators (and, at fleet scale, aggregators) can triage
//! without parsing stderr: *retry this* (`Transient`) vs *fix your config*
//! (`Permission` / `NotFound` / `Conflict`) vs *fix the code* (`Permanent`). The
//! category also shapes downstream policy — exit codes and (later) retry — but those
//! consumers are enabled by carrying the code, not implemented here.
//!
//! [`classify_error`] is the pure classifier — a matrix of stderr substring patterns
//! plus the shell exit codes 126 / 127. Pattern **order matters** — the first match wins — so the arms stay in a
//! fixed order. No `regex` dep: lowercase substring checks.

use serde::{Deserialize, Serialize};

/// Triage category for a failed change.
///
/// Serialized `snake_case` (`transient`,
/// `not_found`, …) — the wire shape carried on the event stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    /// SSH timeout, network blip, temporary unavailability — should retry.
    Transient,
    /// Sudo needed, wrong user, insufficient privileges — needs a config change.
    Permission,
    /// Package / resource / file doesn't exist — needs a different name or path.
    NotFound,
    /// Port in use, file locked, resource already exists — needs coordination.
    Conflict,
    /// Not implemented, invalid config, SSH host-key mismatch — needs a code/config fix.
    Permanent,
    /// Generic execution failure — the fallback when no pattern matches.
    ExecutionFailed,
}

/// Sentinel for "no shell exit code".
///
/// Passed by callers classifying a non-shell failure that is only text (what `ssh`
/// said, zap's own reason, an io error whose kind says nothing). Chosen so the `126` /
/// `127` arms (which are meaningful only for an actual command exit) never fire; the
/// stderr/message substring patterns still apply.
pub const NO_EXIT_CODE: i32 = -1;

/// What `sudo` says, lowercased, when it refuses to run a command — each a stable part
/// of a message of its `sudoers` policy:
///
/// - `Sorry, user U is not allowed to execute 'C' as R on H.`
/// - `U is not in the sudoers file.`
/// - `Sorry, user U may not run sudo on H.` / `U is not allowed to run sudo on H.`
/// - `sudo: a password is required` (under `-n`)
/// - `sudo: a terminal is required to read the password; …`
/// - `sudo: sorry, you must have a tty to run sudo` (`requiretty`)
/// - `sudo: N incorrect password attempt(s)`
///
/// `sudo` translates its messages, so a command run in another locale isn't matched.
const SUDO_REFUSALS: [&str; 8] = [
    "is not allowed to execute",
    "is not in the sudoers file",
    "may not run sudo on",
    "is not allowed to run sudo on",
    "a password is required",
    "a terminal is required to read the password",
    "you must have a tty to run sudo",
    "incorrect password attempt",
];

/// Classify a failed command's `stderr` + `exit_code` into an [`ErrorCode`].
///
/// Lowercase substring matches in a fixed order (`Permission` → `NotFound` → `Conflict` → `Transient` → `Permanent`),
/// with the shell exit codes `126` (cannot execute → `Permission`) and `127` (command
/// not found → `NotFound`) checked first within their groups. Returns
/// [`ErrorCode::ExecutionFailed`] when nothing matches.
///
/// Callers with no real exit code (connection errors, a failure that is only words) pass
/// [`NO_EXIT_CODE`]. A native io error isn't classified here: the engine reads its kind
/// and OS code, and comes here only for a kind that says nothing to triage by.
#[must_use]
pub fn classify_error(stderr: &str, exit_code: i32) -> ErrorCode {
    let lower = stderr.to_lowercase();

    // Permission (exit 126 = found but cannot execute). The last group is `sudo`'s own
    // refusals, as its `sudoers` policy words them in the C locale: a command or a user
    // the policy doesn't cover, and a password it can't ask for or didn't get.
    if exit_code == 126
        || lower.contains("permission denied")
        || lower.contains("operation not permitted")
        || lower.contains("access denied")
        || lower.contains("authentication failure")
        || lower.contains("insufficient privileges")
        || SUDO_REFUSALS.iter().any(|refusal| lower.contains(refusal))
    {
        return ErrorCode::Permission;
    }

    // Not found (exit 127 = command not found).
    if exit_code == 127
        || lower.contains("no such file or directory")
        || lower.contains("package not found")
        || lower.contains("unable to locate package")
        || lower.contains("target not found")
        || lower.contains("no matching packages")
        || lower.contains("command not found")
        || lower.contains("unit not found")
    {
        return ErrorCode::NotFound;
    }

    // Conflict.
    if lower.contains("already in use")
        || lower.contains("already exists")
        || lower.contains("resource busy")
        || lower.contains("no space left on device")
        || lower.contains("lock file")
        || lower.contains("is locked")
    {
        return ErrorCode::Conflict;
    }

    // Transient.
    if lower.contains("connection refused")
        || lower.contains("connection timed out")
        || lower.contains("connection reset")
        || lower.contains("temporary failure")
        || lower.contains("network is unreachable")
        || lower.contains("could not resolve")
        || lower.contains("failed to fetch")
    {
        return ErrorCode::Transient;
    }

    // SSH host-key errors — a permanent config issue, not transient.
    if lower.contains("host key verification failed")
        || lower.contains("remote host identification has changed")
    {
        return ErrorCode::Permanent;
    }

    ErrorCode::ExecutionFailed
}

#[cfg(test)]
mod tests {
    use super::{ErrorCode, NO_EXIT_CODE, classify_error};

    // Each case pins one (stderr, exit_code) → ErrorCode arm of the matrix.

    #[test]
    fn exit_126_is_permission_and_127_is_not_found() {
        assert_eq!(classify_error("", 126), ErrorCode::Permission);
        assert_eq!(classify_error("", 127), ErrorCode::NotFound);
    }

    #[test]
    fn permission_patterns() {
        for s in [
            "Permission denied",
            "Operation not permitted",
            "Access denied",
            "authentication failure",
            "insufficient privileges",
        ] {
            assert_eq!(classify_error(s, 1), ErrorCode::Permission, "{s}");
        }
    }

    /// Each of `sudo`'s refusals is a permission failure, as `sudo` words it — whatever
    /// else the line says, a phrase of another group included.
    #[test]
    fn sudo_refusals_are_permission() {
        for s in [
            "Sorry, user deploy is not allowed to execute '/usr/bin/systemctl restart app' \
             as root on web1.",
            "deploy is not in the sudoers file.",
            "Sorry, user deploy may not run sudo on web1.",
            "deploy is not allowed to run sudo on web1.",
            "sudo: a password is required",
            "sudo: a terminal is required to read the password; either use the -S option to \
             read from standard input or configure an askpass helper",
            "sudo: sorry, you must have a tty to run sudo",
            "sudo: 3 incorrect password attempts",
            "sudo: 1 incorrect password attempt",
            // The first match wins: a not-found phrase after a refusal doesn't.
            "Sorry, user deploy is not allowed to execute '/bin/cat /srv/no such file or \
             directory' as root on web1.",
        ] {
            assert_eq!(classify_error(s, 1), ErrorCode::Permission, "{s}");
        }
        // A word of a refusal alone is none.
        for s in ["sudo: unable to resolve host web1", "a password"] {
            assert_eq!(classify_error(s, 1), ErrorCode::ExecutionFailed, "{s}");
        }
    }

    #[test]
    fn not_found_patterns() {
        for s in [
            "No such file or directory",
            "Package not found",
            "Unable to locate package foo",
            "Target not found",
            "No matching packages",
            "bash: foo: command not found",
            "Unit not found",
        ] {
            assert_eq!(classify_error(s, 1), ErrorCode::NotFound, "{s}");
        }
    }

    #[test]
    fn conflict_patterns() {
        for s in [
            "address already in use",
            "file already exists",
            "resource busy",
            "No space left on device",
            "could not get lock file",
            "database is locked",
        ] {
            assert_eq!(classify_error(s, 1), ErrorCode::Conflict, "{s}");
        }
    }

    #[test]
    fn transient_patterns() {
        for s in [
            "Connection refused",
            "Connection timed out",
            "Connection reset by peer",
            "Temporary failure in name resolution",
            "Network is unreachable",
            "Could not resolve host",
            "failed to fetch",
        ] {
            assert_eq!(classify_error(s, 1), ErrorCode::Transient, "{s}");
        }
    }

    #[test]
    fn ssh_host_key_is_permanent_not_transient() {
        assert_eq!(
            classify_error("Host key verification failed.", 255),
            ErrorCode::Permanent
        );
        assert_eq!(
            classify_error("REMOTE HOST IDENTIFICATION HAS CHANGED!", 255),
            ErrorCode::Permanent
        );
    }

    #[test]
    fn unmatched_falls_back_to_execution_failed() {
        assert_eq!(
            classify_error("something weird happened", 1),
            ErrorCode::ExecutionFailed
        );
        assert_eq!(classify_error("", 1), ErrorCode::ExecutionFailed);
    }

    #[test]
    fn ordering_permission_wins_over_later_groups() {
        // A message that contains both a permission phrase and a conflict phrase
        // classifies as permission — permission is checked first.
        assert_eq!(
            classify_error("permission denied; resource busy", 1),
            ErrorCode::Permission
        );
    }

    #[test]
    fn no_exit_code_sentinel_does_not_trip_126_127() {
        // A non-shell failure with NO_EXIT_CODE classifies purely by substring.
        assert_eq!(
            classify_error("Permission denied (os error 13)", NO_EXIT_CODE),
            ErrorCode::Permission
        );
        assert_eq!(
            classify_error("plain failure", NO_EXIT_CODE),
            ErrorCode::ExecutionFailed
        );
    }

    #[test]
    fn serializes_snake_case() {
        assert_eq!(
            serde_json::to_string(&ErrorCode::NotFound).unwrap(),
            r#""not_found""#
        );
        assert_eq!(
            serde_json::to_string(&ErrorCode::ExecutionFailed).unwrap(),
            r#""execution_failed""#
        );
    }
}
