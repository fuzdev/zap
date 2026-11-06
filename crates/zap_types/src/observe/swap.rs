//! `swap` — the swap file exists, is active (`/proc/swaps`), and is persisted
//! (`/etc/fstab`).
//!
//! The path is used verbatim (no `~` expansion), which is why `swap` contributes no field
//! to the shared `resolved_fields` seam.

use super::{Query, QueryResult, command_answer, succeeded_answer};
use crate::detected::{CurrentState, Detection};
use crate::schema::table_lists_path;
use crate::shell::single_quote;

/// The kernel's active-swap table.
const PROC_SWAPS: &str = "/proc/swaps";
/// The table a persisted swap file is listed in.
pub const FSTAB_PATH: &str = "/etc/fstab";

/// Index of the existence probe in [`queries`].
const EXISTS: usize = 0;
/// Index of the active-swap probe in [`queries`].
const ACTIVE: usize = 1;
/// Index of the `/etc/fstab` probe in [`queries`].
const FSTAB: usize = 2;

/// A swap file's reads, each a [`Query::login_command`] (as the connecting user — both
/// tables are world-readable):
///
/// - existence — `test -f` (a regular file, following symlinks; a path the user can't
///   reach reads as absent);
/// - active — the path as the first field of a line of the kernel's active-swap table,
///   `/proc/swaps` (the source `swapon --show` reads, without its util-linux long
///   options, which `BusyBox` lacks);
/// - persisted — the path as the first field of a line of `/etc/fstab` (a host with no
///   `/etc/fstab` persists nothing: exit 1).
///
/// Both table reads are [`table_lists_path`] — the planner's `/etc/fstab` guard too — so
/// a declared `/swap` isn't read active or persisted from a `/swapfile` line.
#[must_use]
pub fn queries(path: &str) -> Vec<Query> {
    vec![
        Query::login_command(format!("test -f {}", single_quote(path))),
        Query::login_command(table_lists_path(PROC_SWAPS, path)),
        Query::login_command(format!(
            "test -e {FSTAB_PATH} || exit 1; {}",
            table_lists_path(FSTAB_PATH, path)
        )),
    ]
}

/// The verdict for a swap file from the answers to [`queries`].
///
/// `Absent` when the file isn't there (its other answers unread), `Converged` when it is
/// active and in `/etc/fstab`, else `Drifted` with both observed states. Each probe's
/// answer is its exit status; a table read exiting anything but 0 (listed) or 1 (not
/// listed) couldn't read its table, and holds.
#[must_use]
pub fn interpret(results: &[QueryResult]) -> Detection {
    match succeeded_answer(results, EXISTS) {
        Ok(true) => {}
        Ok(false) => return Detection::Absent,
        Err(held) => return held,
    }
    let listed = |index, table: &str| match command_answer(results, index)?.code {
        0 => Ok(true),
        1 => Ok(false),
        _ => Err(Detection::Undetermined {
            reason: format!("detection failed: couldn't read {table}"),
        }),
    };
    let (is_active, in_fstab) = match (listed(ACTIVE, PROC_SWAPS), listed(FSTAB, FSTAB_PATH)) {
        (Ok(active), Ok(fstab)) => (active, fstab),
        (Err(held), _) | (_, Err(held)) => return held,
    };
    if is_active && in_fstab {
        Detection::Converged
    } else {
        Detection::Drifted {
            current: CurrentState::Swap {
                is_active,
                in_fstab,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{interpret, queries};
    use crate::detected::{CurrentState, Detection};
    use crate::observe::testing::exited;
    use crate::observe::{Query, QueryError};

    #[test]
    fn the_probes_are_the_login_users_quoted_commands() {
        assert_eq!(
            queries("/swap file"),
            [
                Query::login_command("test -f '/swap file'"),
                Query::login_command(
                    "P='/swap file' awk '$1 == ENVIRON[\"P\"] { found = 1 } END { exit !found }' /proc/swaps"
                ),
                Query::login_command(
                    "test -e /etc/fstab || exit 1; P='/swap file' awk '$1 == ENVIRON[\"P\"] { found = 1 } END { exit !found }' /etc/fstab"
                ),
            ]
        );
    }

    #[test]
    fn a_missing_file_is_absent_whatever_the_tables_say() {
        let unanswered = Err(QueryError::Unrecorded);
        assert_eq!(
            interpret(&[exited(1, ""), unanswered.clone(), unanswered]),
            Detection::Absent
        );
    }

    #[test]
    fn the_tables_decide_convergence() {
        assert_eq!(
            interpret(&[exited(0, ""), exited(0, ""), exited(0, "")]),
            Detection::Converged
        );
        assert_eq!(
            interpret(&[exited(0, ""), exited(1, ""), exited(1, "")]),
            Detection::Drifted {
                current: CurrentState::Swap {
                    is_active: false,
                    in_fstab: false,
                },
            }
        );
        // `awk` exits 2 on a table it can't read: not "not listed" — it holds.
        assert!(matches!(
            interpret(&[exited(0, ""), exited(0, ""), exited(2, "")]),
            Detection::Undetermined { .. }
        ));
        assert!(matches!(
            interpret(&[
                exited(0, ""),
                exited(0, ""),
                Err(QueryError::TimedOut {
                    secs: crate::observe::COMMAND_TIMEOUT
                })
            ]),
            Detection::Undetermined { .. }
        ));
    }
}
