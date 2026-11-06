//! Pending-trigger markers — the target-side record of a service restart/reload an
//! apply fired but hasn't completed.
//!
//! A trigger only fires when its source changes in the current plan, so without a
//! record a failed reload is lost: the next plan reads the source as converged (its
//! bytes match) and the service as running (on the old config), and never retries.
//! The executor writes a marker **before** the first source change runs and removes
//! it only after the service's own change completes, so an apply that fails or dies
//! anywhere in between leaves it; the next plan reads it — [`read_query`], answered in
//! the same batch as the plan's detection reads — and re-fires the action
//! (`zap_types::plan::Trigger::pending`).
//!
//! The marker lives on the target, not in the operator's `~/.zap`: that state is
//! advisory by design (any failure degrades to a miss) and per operator machine, and the
//! lock records intent, not host state. On the host, it survives a different operator
//! machine and a second config that manages the same service. Markers are keyed by
//! service **name** (the unit, which is host-global), not resource id (config-local).
//!
//! The cost of write-ahead is at-least-once: a run that fails after recording the
//! marker but before any source changed still re-fires the action next time — one
//! redundant reload or restart, never a lost one.

use std::collections::BTreeMap;

use zap_types::claim::ZAP_STATE_DIR;
use zap_types::observe::{Observation, Query, QueryResult};
use zap_types::plan::TriggerKind;
use zap_types::put::FileAttrs;
use zap_types::schema::{Resource, ResourceKind};
use zap_types::shell::single_quote;

use crate::connection::Connection;
use crate::error::{Error, FailureCause, Result};

/// The target directory holding one marker file per service with a pending action.
pub const PENDING_DIR: &str = "/var/lib/zap/pending";

/// The marker file name for `service` — the name with anything outside
/// `[A-Za-z0-9@._-]` replaced by `_`, and a leading `.` too, so a unit name can
/// neither leave the directory nor hide as a dotfile.
#[must_use]
pub fn marker_stem(service: &str) -> String {
    service
        .chars()
        .enumerate()
        .map(|(index, c)| {
            let allowed = c.is_ascii_alphanumeric() || matches!(c, '@' | '_' | '-' | '.');
            if allowed && !(index == 0 && c == '.') {
                c
            } else {
                '_'
            }
        })
        .collect()
}

/// The path of `service`'s marker.
fn marker_path(service: &str) -> String {
    format!("{PENDING_DIR}/{}", marker_stem(service))
}

/// The shell command [`read_query`] runs: one `<stem> <kind>` line per marker, and
/// nothing (exit 0) when nothing is at the directory's path.
///
/// Anything else that can't be read fails the read (exit 1), so it holds rather than
/// reading as "no markers": a path that isn't a directory, or a directory that can't be
/// listed. A listing that succeeded and still leaves the glob unexpanded holds no
/// marker (markers are never dotfiles). A marker that is a symbolic link or not a
/// regular file is skipped, and only a marker's first bytes are read — enough for its
/// kind.
pub(crate) fn read_command() -> String {
    let dir = single_quote(PENDING_DIR);
    format!(
        "d={dir}; if [ ! -e \"$d\" ] && [ ! -L \"$d\" ]; then exit 0; fi; \
         [ -d \"$d\" ] && [ ! -L \"$d\" ] || {{ echo \"$d is not a directory\" >&2; exit 1; }}; \
         ls -A -- \"$d\" >/dev/null || exit 1; \
         for f in \"$d\"/*; do [ -f \"$f\" ] && [ ! -L \"$f\" ] || continue; \
         k=$(head -c 16 -- \"$f\") || exit 1; printf '%s %s\\n' \"${{f##*/}}\" \"$k\"; done"
    )
}

/// Whether `resources` declare a trigger — a `file.triggers`, `restart_on`, or
/// `reload_on`. Nothing else can write a marker, so a config without one never reads
/// them.
#[must_use]
pub fn declares_trigger(resources: &[Resource]) -> bool {
    resources.iter().any(|resource| match &resource.kind {
        ResourceKind::File(file) => file.triggers.as_ref().is_some_and(|t| !t.is_empty()),
        ResourceKind::Service(service) => {
            service
                .restart_on
                .as_ref()
                .is_some_and(|ids| !ids.is_empty())
                || service
                    .reload_on
                    .as_ref()
                    .is_some_and(|ids| !ids.is_empty())
        }
        _ => false,
    })
}

/// The query that reads every pending marker: `read_command`, as root — the account
/// that writes them — so a marker directory only root can list is read, never taken
/// for one holding none.
#[must_use]
pub fn read_query() -> Query {
    Query::root_command(read_command())
}

/// Every pending marker, keyed by marker stem (see [`marker_stem`]), from the answer to
/// [`read_query`].
///
/// A marker whose content isn't a known kind reads as a restart — the stronger action,
/// so an unreadable record is never under-honored.
///
/// # Errors
/// [`Error::ReadFile`] when the read exited non-zero (carrying its stderr and exit
/// status) or has no answer (carrying why).
pub fn from_answer(answer: Option<&QueryResult>) -> Result<BTreeMap<String, TriggerKind>> {
    let failed = |message: String| Error::ReadFile {
        path: PENDING_DIR.to_owned(),
        cause: FailureCause::Text(message),
    };
    match answer {
        Some(Ok(Observation::Command(output))) if output.succeeded() => {
            Ok(parse_pending(&String::from_utf8_lossy(&output.stdout)))
        }
        Some(Ok(Observation::Command(output))) => Err(Error::ReadFile {
            path: PENDING_DIR.to_owned(),
            cause: FailureCause::Exited {
                stderr: String::from_utf8_lossy(&output.stderr).trim().to_owned(),
                code: output.code,
            },
        }),
        Some(Err(error)) => Err(failed(error.to_string())),
        Some(Ok(Observation::Path(_))) | None => {
            Err(failed("the marker read has no answer".to_owned()))
        }
    }
}

/// Parse [`read_command`] output into stem → kind.
fn parse_pending(stdout: &str) -> BTreeMap<String, TriggerKind> {
    stdout
        .lines()
        .filter_map(|line| {
            let (stem, kind) = line.split_once(' ').unwrap_or((line, ""));
            (!stem.is_empty()).then(|| {
                (
                    stem.to_owned(),
                    TriggerKind::parse(kind.trim()).unwrap_or(TriggerKind::Restart),
                )
            })
        })
        .collect()
}

/// Record that `service` owes a `kind` action. Overwrites any existing marker; the
/// planner already folded an existing marker's kind into `kind` (the stronger wins).
///
/// The directories are given mode `755` and the marker `644` explicitly, whatever the
/// umask of the account that writes them: what is recorded stays readable.
///
/// # Errors
/// The directory can't be created or the marker can't be written.
pub async fn record_pending(conn: &Connection, service: &str, kind: TriggerKind) -> Result<()> {
    conn.make_dir(PENDING_DIR).await?;
    for dir in [ZAP_STATE_DIR, PENDING_DIR] {
        conn.set_dir_attrs(dir, FileAttrs::mode("755")).await?;
    }
    conn.write_file(
        &marker_path(service),
        &format!("{}\n", kind.as_str()),
        FileAttrs::mode("644"),
    )
    .await
}

/// Remove `service`'s marker once its action has completed. Absent is success.
///
/// # Errors
/// The marker exists and can't be removed.
pub async fn clear_pending(conn: &Connection, service: &str) -> Result<()> {
    conn.remove_file(&marker_path(service)).await
}

#[cfg(test)]
mod tests {
    use super::{from_answer, marker_stem, parse_pending, read_command, read_query};
    use crate::error::Error;
    use zap_types::observe::{
        CommandObservation, Observation, PathObservation, Privilege, QueryError,
    };
    use zap_types::plan::TriggerKind;

    #[test]
    fn marker_stem_keeps_unit_names_and_neutralizes_the_rest() {
        assert_eq!(marker_stem("nginx"), "nginx");
        assert_eq!(marker_stem("postgresql@16-main"), "postgresql@16-main");
        assert_eq!(marker_stem("../etc/passwd"), "_._etc_passwd");
        assert_eq!(marker_stem(".hidden"), "_hidden");
        assert_eq!(marker_stem("a b/c"), "a_b_c");
    }

    #[test]
    fn parse_pending_reads_each_marker_and_defaults_unknown_kinds_to_restart() {
        let parsed = parse_pending("nginx reload\napp restart\nodd ???\n\n");
        assert_eq!(parsed.get("nginx"), Some(&TriggerKind::Reload));
        assert_eq!(parsed.get("app"), Some(&TriggerKind::Restart));
        assert_eq!(parsed.get("odd"), Some(&TriggerKind::Restart));
        assert_eq!(parsed.len(), 3);
    }

    #[test]
    fn the_read_runs_as_root_and_a_failed_one_is_an_error() {
        assert_eq!(read_query().privilege(), Privilege::Root);
        let answer = |code: i32, stdout: &str, stderr: &str| {
            Ok(Observation::Command(CommandObservation {
                code,
                stdout: stdout.as_bytes().to_vec(),
                stderr: stderr.as_bytes().to_vec(),
            }))
        };
        let read = from_answer(Some(&answer(0, "nginx reload\n", ""))).unwrap();
        assert_eq!(read.get("nginx"), Some(&TriggerKind::Reload));
        assert!(from_answer(Some(&answer(0, "", ""))).unwrap().is_empty());
        let message = |result: crate::error::Result<_>| match result {
            Err(Error::ReadFile { path, cause }) => {
                assert_eq!(path, super::PENDING_DIR);
                cause.to_string()
            }
            other => panic!("{other:?}"),
        };
        assert_eq!(
            message(from_answer(Some(&answer(1, "", "cat: denied\n")))),
            "cat: denied"
        );
        // The exit status is kept: a missing tool reads as missing.
        assert_eq!(
            from_answer(Some(&answer(127, "", "sh: head: not found\n")))
                .unwrap_err()
                .error_code(),
            zap_types::error_code::ErrorCode::NotFound
        );
        assert_eq!(
            message(from_answer(Some(&Err(QueryError::Unrecorded)))),
            "no observation recorded for the query"
        );
        assert_eq!(
            message(from_answer(Some(&Ok(Observation::Path(
                PathObservation::Failed
            ))))),
            "the marker read has no answer"
        );
        assert_eq!(message(from_answer(None)), "the marker read has no answer");
    }

    /// [`read_command`] against `dir` in a real shell: its exit status and stdout.
    fn run_read(dir: &std::path::Path) -> (bool, String) {
        let cmd = read_command().replace(
            &format!("'{}'", super::PENDING_DIR),
            &format!("'{}'", dir.display()),
        );
        let output = std::process::Command::new("sh")
            .args(["-c", &cmd])
            .output()
            .unwrap();
        (
            output.status.success(),
            String::from_utf8(output.stdout).unwrap(),
        )
    }

    #[test]
    fn read_command_lists_markers_through_a_real_shell() {
        // The loop's quoting is the risky part: run it against a real directory by
        // swapping the fixed path for a tempdir.
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("nginx"), "reload\n").unwrap();
        std::fs::write(dir.path().join("app"), "restart\n").unwrap();
        // A link is no marker, and what it points at isn't read.
        std::os::unix::fs::symlink(dir.path().join("app"), dir.path().join("linked")).unwrap();
        let (ok, stdout) = run_read(dir.path());
        assert!(ok);
        let parsed = parse_pending(&stdout);
        assert_eq!(parsed.get("nginx"), Some(&TriggerKind::Reload));
        assert_eq!(parsed.get("app"), Some(&TriggerKind::Restart));
        assert_eq!(parsed.len(), 2, "{stdout}");
        // A missing directory is no markers, not an error.
        assert_eq!(
            run_read(std::path::Path::new("/nonexistent/zap-pending")),
            (true, String::new())
        );
        // So is a listed directory whose glob stays unexpanded: it holds only dotfiles.
        let dotted = tempfile::tempdir().unwrap();
        std::fs::write(dotted.path().join(".x"), "restart\n").unwrap();
        assert_eq!(run_read(dotted.path()), (true, String::new()));
    }

    /// What can't be read is a failed read, never "no markers": a path that is no
    /// directory, and a directory that can't be listed.
    #[test]
    fn an_unreadable_marker_directory_fails_the_read() {
        use std::os::unix::fs::PermissionsExt as _;

        let file = tempfile::NamedTempFile::new().unwrap();
        assert!(!run_read(file.path()).0);
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("nginx"), "reload\n").unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o300)).unwrap();
        let unlistable = run_read(dir.path());
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        // Root lists any directory; the check is only meaningful for another account.
        if !running_as_root() {
            assert!(!unlistable.0, "{unlistable:?}");
        }
    }

    /// A marker's directories and the marker itself get explicit modes, so a root umask
    /// of `077` can't leave what zap records unreadable.
    #[tokio::test]
    async fn a_recorded_marker_is_given_its_modes() {
        use zap_types::put::{
            FileAttrs, PutCheck, RunAs, dir_attrs_command, file_put_command, make_dirs_command,
        };

        use crate::connection::mock::MockConnection;
        use crate::connection::{CommandOutput, Connection};

        let ok = CommandOutput {
            success: true,
            code: 0,
            stdout: String::new(),
            stderr: String::new(),
        };
        let marker = "/var/lib/zap/pending/nginx";
        let mut mock = MockConnection::new("m")
            .with(
                make_dirs_command(RunAs::Caller, super::PENDING_DIR),
                ok.clone(),
            )
            .with(
                file_put_command(
                    RunAs::Caller,
                    marker,
                    FileAttrs::mode("644"),
                    PutCheck::None,
                ),
                ok.clone(),
            );
        for dir in ["/var/lib/zap", super::PENDING_DIR] {
            mock = mock.with(
                dir_attrs_command(RunAs::Caller, dir, FileAttrs::mode("755")),
                ok.clone(),
            );
        }
        super::record_pending(&Connection::Mock(mock), "nginx", TriggerKind::Reload)
            .await
            .unwrap();
    }

    /// Whether the suite runs as root.
    fn running_as_root() -> bool {
        std::process::Command::new("id")
            .arg("-u")
            .output()
            .is_ok_and(|output| output.stdout.trim_ascii() == b"0")
    }
}
