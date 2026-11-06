//! The batch wire format — one lane's queries as one POSIX `sh` script, and its output
//! back to per-query answers.
//!
//! [`render`] turns a lane's queries into a script; the runner delivers it on the
//! target shell's **stdin**, run by [`BATCH_SHELL`] (under `sudo` for the root lane), so
//! the script is slurped whole before anything runs and no probe can read the unread tail
//! of the batch as its own input.
//! [`read`] parses what the script printed.
//!
//! The script is a prelude plus one line per query:
//!
//! - `echo "pgid $$"` prints the batch's **process-group record** before anything else
//!   runs: the batch shell's pid, which the SSH runner's `setsid` wrapper makes the id of
//!   the batch's own process group and session. A runner that must stop the batch at its
//!   deadline kills that group on the target ([`kill_snippet`]); [`read`] requires the
//!   record as the output's first line ([`split_pgid`]).
//! - The batch shell's own stderr goes to `/dev/null`: every probe's stderr is framed
//!   into its records, so nothing the batch prints on stderr — which a runner may read
//!   back as a transport failure's diagnostics — can carry a probe's text or output.
//! - A tool check: a target missing any tool the framing or the batch's probes use —
//!   `sha512sum` only when the batch reads a digest, `ls` only when it reads whether a
//!   directory is empty, `setsid` and `sleep` only when it runs a command — or whose
//!   `stat` doesn't take the `-L -c` form they use, exits [`TOOL_MISSING_EXIT`] before
//!   running a probe, failing the whole batch rather than reading every probe as a
//!   failed read. So does a batch with a content read on a target without
//!   `/proc/self/fd` (`[ -d /proc/self/fd ] || exit 97`), through which a content read
//!   checks what it opened.
//! - `h` hex-encodes its stdin (`od` + `tr`), so a record is one ASCII line whatever
//!   the probe printed — NULs, newlines, and a missing trailing newline included.
//! - `p IDX SECS TEXT` runs a path probe and `q IDX SECS ORIGIN TEXT` a command probe.
//!   `TEXT` reaches a child `sh` over a pipe, so the probe's text is on no process's argv
//!   (the commands it runs still have their own); the child reads it, detaches its stdin
//!   to `/dev/null`, and `eval`s it, under `timeout SECS`. Each prints two records:
//!   `IDX O <hex(stdout)>` and `IDX E <hex(stderr)> <status tags>`, the stderr cut to
//!   [`STDERR_LIMIT`] bytes (the rest is drained, so a chatty probe isn't killed by a
//!   closed pipe).
//! - `end N` closes the output; it is how a truncated run is told from a finished one.
//!
//! **Locale.** zap's own probes — every path probe and a command of
//! [`CommandOrigin::Zap`] — run under `LC_ALL=C`, so the output they are parsed by is
//! the same on every target. An operator's command ([`CommandOrigin::Operator`]) runs in
//! the target's own locale, as it would run by hand.
//!
//! **Exit statuses.** A record's status tags come from outside the probe, on descriptors
//! it doesn't hold, so nothing the probe or its descendants write to its output streams —
//! which they inherit — can forge them (a command that deliberately wrote to its
//! reporter's descriptor through `/proc` could, but would gain nothing `exit 0` doesn't
//! give it):
//!
//! - `s<N>` — always: the exit status of the probe's `timeout`, written by the batch
//!   shell after `timeout` returned.
//! - `r<N>` — command probes only: the exit status of the command itself. A command runs
//!   under a *reporter* shell (the process `timeout` runs): the reporter starts the
//!   command's shell in a session and process group of its own (`setsid`), waits for it,
//!   and writes `r<N>` on a descriptor the command's shell is started without — so it is
//!   written exactly when the command finished on its own. At the timeout the reporter is
//!   signalled (`BusyBox` `timeout` signals only the process it runs), stops the command's
//!   whole group — `SIGTERM`, then `SIGKILL` a second later — and exits without a report.
//!
//! So a command that exits 124 or 143 itself reads as that exit, and a probe `timeout`
//! stopped reads [`QueryError::TimedOut`]: a command probe with no report whose `timeout`
//! exited 124 (GNU) or 143 (`BusyBox`, the reporter's `SIGTERM` exit), and a path probe
//! whose status is one of those — a path probe `exec`s its tool, which exits neither on
//! its own. A command that signals its reporter itself (`kill $PPID`) reads timed out
//! too: the reporter can't tell that `SIGTERM` from its timeout's. A command probe with no
//! report and another status (its reporter was killed some other way) is a
//! [`QueryError::Exited`]. Because the command runs in its own session, nothing it
//! signals as a group — a cleanup trap's `kill 0` — reaches its reporter or the batch.
//!
//! The probe gets none of the batch's own file descriptors (`3>&- 4>&- 5>&- 6>&-`), so it
//! can't write the record stream — and `BusyBox` `timeout`, which leaves a watchdog
//! process holding every inherited descriptor above 2 for up to a second after the probe
//! exits, can't hold a record's pipe open: the reporter's descriptor is the one it does
//! hold, and the batch reads that one line by line, never waiting for its end once the
//! status arrived. `BusyBox` needs to be 1.30 or newer (`timeout SECS`, without `-t`).
//!
//! **What `timeout` bounds.** `timeout` signals the probe's own process: a path probe's
//! tool, or a command's reporter, which stops the command's whole process group — its
//! grandchildren included, under `BusyBox` too — and kills it a second later if it is
//! still there (a command that ignores `SIGTERM`). What escapes: anything that leaves the
//! command's process group itself, and anything a command backgrounds and leaves running
//! after it exits (a background writer's late output lands in the probe's stdout, never
//! in its status) — which keeps the record's pipes open until it ends. The runner
//! therefore also bounds the whole batch ([`lane_deadline_secs`]) and fails the lane when
//! it expires.
//!
//! For a path facet, exit 1 is `stat`'s and `readlink`'s one failure status (GNU and
//! `BusyBox` alike), read as [`PathObservation::Failed`]; the content reads
//! ([`Digest`](PathFacet::Digest), [`Read`](PathFacet::Read)) open the path with a
//! redirect that exits 1 when it can't be opened (`command exec <path || exit 1` — a bare
//! `exec <path` makes `dash` exit 2), and `sha512sum` / `head` exit 1 on a read error, so
//! they share the status. Before the open they exit [`NOT_REGULAR_EXIT`] for a name that
//! is a symbolic link or anything but a regular file, read as
//! [`PathObservation::NotRegular`]: nothing is opened through a link, nor a device or a
//! fifo. The [`Empty`](PathFacet::Empty) read's tests exit 1 for
//! anything but a directory it may list, and a failing `ls` holds either way. Any other
//! failure status is a [`QueryError::Exited`], and a success whose output doesn't parse
//! is a [`QueryError::Unparseable`].

use std::fmt::Write as _;

use super::{
    CommandObservation, CommandOrigin, FileKind, Lane, Observation, PathFacet, PathMetadata,
    PathObservation, Query, QueryError, QueryResult,
};
use crate::shell::single_quote;

/// The shell program a batch runs under: read the whole script from stdin, detach stdin,
/// then run it — so no probe can consume the unread tail of the script as its own input.
///
/// Its variable is the first one `PRELUDE_HEAD` unsets, so the script's text never
/// reaches a probe's environment.
pub const BATCH_SHELL: &str = r#"__zap_script=$(cat) && exec </dev/null && eval "$__zap_script""#;

/// The most stderr a record carries, in bytes.
pub const STDERR_LIMIT: usize = 4096;

/// The exit status of a batch whose target lacks a tool it needs.
pub const TOOL_MISSING_EXIT: i32 = 97;

/// Seconds a lane's batch may run past the sum of its probes' timeouts before the runner
/// kills it — slack for the batch's own overhead.
pub const LANE_DEADLINE_MARGIN_SECS: u64 = 30;

/// The most stdout a runner reads from one batch, in bytes.
///
/// Past it the runner stops reading, stops the batch, and fails its lane
/// ([`STDOUT_LIMIT_REASON`]): a probe that prints without bound (hex-framed, so twice its
/// output) mustn't grow zap's memory without bound.
pub const STDOUT_LIMIT: usize = 64 * 1024 * 1024;

/// The fixed reason a lane fails when its batch's stdout passes [`STDOUT_LIMIT`].
pub const STDOUT_LIMIT_REASON: &str = "its output passed the 64 MiB limit";

/// The `stat` format the [`Lstat`](PathFacet::Lstat) facet reads: raw mode (hex, for the
/// file type), permission bits (octal), owner name, group name.
const METADATA_FORMAT: &str = "%f %a %U %G";

/// The tools every batch needs: the framing's, and the path probes'.
const TOOLS: &str = "timeout od tr head cat stat readlink";

/// The tool a batch with a [`Digest`](PathFacet::Digest) read needs besides [`TOOLS`].
const DIGEST_TOOL: &str = "sha512sum";

/// The tool a batch with an [`Empty`](PathFacet::Empty) read needs besides [`TOOLS`].
const LIST_TOOL: &str = "ls";

/// The tools a batch with a [`Query::Command`] needs besides [`TOOLS`]: the reporter
/// starts each command in a session of its own, and gives a stopped one a second to go
/// before it is killed.
const COMMAND_TOOLS: &str = "setsid sleep";

/// The first line of every script: the process-group record, then the batch shell's own
/// stderr to `/dev/null`, the record stream's descriptor, and the batch's own variables
/// dropped from the environment it passes on (see [`PRELUDE`]).
const PRELUDE_HEAD: &str = "echo \"pgid $$\"; exec 2>/dev/null 3>&1; unset __zap_script __zap_c __zap_e __zap_g __zap_p __zap_r __zap_s __zap_t __zap_x\n";

/// The tag of the process-group record, the first line of a batch's output.
const PGID_TAG: &str = "pgid ";

/// The rest of the script's shared prelude after the tool list: the `stat -L -c` check,
/// the probe shell (`__zap_g`) and the command reporter (`__zap_r`), and the `h` / `p` /
/// `q` functions (see the module docs).
///
/// - `__zap_g` reads the probe's text from its stdin, detaches stdin, drops the text's
///   variable, and `eval`s the text.
/// - `__zap_r` is the reporter a command probe runs under `timeout`. It starts
///   `__zap_g` (its `$1`) in the background, under `setsid` — a session and process group
///   of the command's own, so nothing the command signals (a `kill 0` in a cleanup trap)
///   reaches the reporter or the batch, and so the whole of the command can be stopped —
///   with the text on its stdin (an explicit redirect: a background job's stdin is
///   otherwise `/dev/null`) and without descriptors 7 and 8, waits for it, and writes
///   `r<status>` on descriptor 7. A background job is no process-group leader, so
///   `setsid` runs the command's shell in place, as the reporter's own child: `$!` and
///   `wait` track the command itself. `SIGTERM` (the timeout) stops the command's whole
///   group — `SIGTERM`, a second's grace, then `SIGKILL` — and the reporter exits 143
///   without a report; one that arrives before the command's pid is known is remembered
///   (`__zap_t`) and acted on once it is. The `SIGTERM` falls back to the command's pid
///   alone, for the moment before `setsid` has made its group; the `SIGKILL` goes to the
///   group only — the command's shell may have exited and been reaped during the grace,
///   and its pid can then name another process (as root, in the root lane).
/// - `p` and `q` frame one probe's records. The status tags travel on a descriptor of
///   their own — `6` for a path probe, whose `s<status>` the batch writes itself; `7`
///   for a command, where the reporter's `r<status>` and then the batch's `s<status>`
///   are read line by line, stopping at the `s` line. They are captured in `__zap_t`
///   and printed after the stderr, whose writers all hold descriptor 6 until they are
///   done.
///
/// Every variable the batch assigns is named `__zap_*` — the runner's own
/// `__zap_script` included — so a probe's environment is the login environment as it
/// came: an operator's `c` or `t` passes through. They are unset first
/// ([`PRELUDE_HEAD`]).
const PRELUDE: &str = r#"; do command -v "$__zap_t" >/dev/null 2>&1 || exit 97; done
stat -L -c %f -- / >/dev/null 2>&1 || exit 97
__zap_g='__zap_c=$(cat) && exec </dev/null && eval "unset __zap_c; $__zap_c"'
__zap_r='exec 8<&0 </dev/null; __zap_t=; trap "__zap_t=1" TERM; setsid sh -c "$1" <&8 7>&- 8<&- & __zap_p=$!; exec 8<&-; __zap_s="kill -TERM -$__zap_p 2>/dev/null || kill -TERM $__zap_p 2>/dev/null; sleep 1; kill -KILL -$__zap_p 2>/dev/null; exit 143"; trap "$__zap_s" TERM; [ -z "$__zap_t" ] || eval "$__zap_s"; wait $__zap_p; echo "r$?" >&7'
h() { od -An -v -tx1 | tr -d ' \n'; }
p() {
printf '%s O ' "$1"
__zap_e=$( { __zap_t=$( { { { printf '%s' "$3" | LC_ALL=C timeout "$2" sh -c "$__zap_g" 2>&1 1>&4 3>&- 4>&- 5>&- 6>&-; printf ' s%s' "$?" >&6; } | { head -c 4096; cat >/dev/null; } | h >&5; } 4>&1 | h >&3; } 6>&1 ); printf '%s' "$__zap_t"; } 5>&1 )
printf '\n%s E %s\n' "$1" "$__zap_e"
}
q() {
printf '%s O ' "$1"
__zap_e=$( { __zap_t=$( { { { { printf '%s' "$4" | if [ "$3" = o ]; then timeout "$2" sh -c "$__zap_r" sh "$__zap_g"; else LC_ALL=C timeout "$2" sh -c "$__zap_r" sh "$__zap_g"; fi 2>&1 1>&4 3>&- 4>&- 5>&- 6>&-; printf 's%s\n' "$?" >&7; } | { head -c 4096; cat >/dev/null; } | h >&5; } 4>&1 | h >&3; } 7>&1 | { while read -r __zap_x; do printf ' %s' "$__zap_x"; [ "${__zap_x#s}" = "$__zap_x" ] || break; done; }; } 6>&1 ); printf '%s' "$__zap_t"; } 5>&1 )
printf '\n%s E %s\n' "$1" "$__zap_e"
}
"#;

/// The shell snippet that answers `query` — what [`render`] runs for it.
///
/// A path read `exec`s its tool, so the tool *is* the process `timeout` signals: a hung
/// `stat` is killed at its timeout rather than outliving the shell that started it.
/// Command snippets run as written.
#[must_use]
fn probe_snippet(query: &Query) -> String {
    match query {
        Query::Path { path, facet, .. } => {
            let path = single_quote(path);
            match facet {
                PathFacet::Kind => format!("exec stat -L -c %f -- {path}"),
                PathFacet::Lstat => format!("exec stat -c '{METADATA_FORMAT}' -- {path}"),
                PathFacet::LinkTarget => format!("exec readlink -- {path}"),
                // The file is opened by the shell, so no name reaches `sha512sum`'s
                // output (`-` stands in for it) and none needs escaping.
                PathFacet::Digest => format!("{} exec sha512sum", open_regular(&path)),
                // One byte past `max`, so the answer can tell a file of exactly `max`
                // bytes from a longer one.
                PathFacet::Read { max } => {
                    format!(
                        "{} exec head -c {}",
                        open_regular(&path),
                        u64::from(*max) + 1
                    )
                }
                // Anything but a directory this privilege may list is the facet's
                // "found nothing", as a native read's denial is.
                PathFacet::Empty => {
                    format!("[ -d {path} ] && [ -r {path} ] || exit 1; exec ls -A -- {path}")
                }
            }
        }
        Query::Command { snippet, .. } => snippet.clone(),
    }
}

/// Open the (already quoted) `path` as the probe's stdin when it is a regular file of
/// its own, exiting [`NOT_REGULAR_EXIT`] — before anything is opened — when the name is
/// a symbolic link (dangling or not) or names anything but a regular file (a directory,
/// a device, a fifo), and 1 — the path facets' "found nothing" status — when there is
/// nothing there or it can't be opened.
///
/// A content read runs as root over SSH, so what it opens matters: opening a device
/// can act on the machine (a watchdog's), a fifo holds the open waiting for a writer,
/// and a link reaches whatever it names. Once open, the descriptor must be a regular
/// file and the name itself — not followed — the file held open (same device and
/// inode, read through `/proc/self/fd`, which a batch with a content read requires), or
/// the probe exits [`NOT_REGULAR_EXIT`] before a byte is read; a regular file with more
/// than one hard link, its count read from the descriptor, exits [`HARD_LINKED_EXIT`]
/// ([`HARD_LINK_REFUSAL`](crate::put::HARD_LINK_REFUSAL)). What the tests can't
/// close is the instant between them and the open, as with `FILE_SNAPSHOT`: a name
/// swapped there to a link is opened through, then refused; a link to a fifo holds the
/// open until the probe's `timeout`. `command` keeps a failed redirect from making the
/// shell exit with its own status (`dash` exits 2).
fn open_regular(quoted_path: &str) -> String {
    format!(
        "[ ! -L {quoted_path} ] || exit {NOT_REGULAR_EXIT}; \
         [ ! -e {quoted_path} ] || [ -f {quoted_path} ] || exit {NOT_REGULAR_EXIT}; \
         command exec <{quoted_path} || exit 1; \
         __zap_i=$(stat -L -c %d:%i:%h /proc/self/fd/0) && [ -f /proc/self/fd/0 ] && \
         [ \"$(stat -c %d:%i -- {quoted_path})\" = \"${{__zap_i%:*}}\" ] || exit {NOT_REGULAR_EXIT}; \
         [ \"${{__zap_i##*:}}\" = 1 ] || exit {HARD_LINKED_EXIT};"
    )
}

/// The status a content read exits with when the regular file it opened has more than
/// one hard link ([`QueryError::HardLinked`]).
///
/// It exits before a byte is read, with a status neither `sha512sum` nor `head` exits
/// with, nor `timeout`.
pub const HARD_LINKED_EXIT: i32 = 4;

/// The status a content read ([`Digest`](PathFacet::Digest), [`Read`](PathFacet::Read))
/// exits with when the path is not a regular file of its own
/// ([`PathObservation::NotRegular`]) — a status neither `sha512sum` nor `head` exits
/// with, nor `timeout`.
pub const NOT_REGULAR_EXIT: i32 = 3;

/// Render one lane's queries as a batch script. Records are numbered by position in
/// `queries`, which is the order [`read`] returns answers in.
#[must_use]
pub fn render(queries: &[&Query]) -> String {
    let digests = queries.iter().any(|query| {
        matches!(
            query,
            Query::Path {
                facet: PathFacet::Digest,
                ..
            }
        )
    });
    let lists = queries.iter().any(|query| {
        matches!(
            query,
            Query::Path {
                facet: PathFacet::Empty,
                ..
            }
        )
    });
    let commands = queries
        .iter()
        .any(|query| matches!(query, Query::Command { .. }));
    let contents = digests
        || queries.iter().any(|query| {
            matches!(
                query,
                Query::Path {
                    facet: PathFacet::Read { .. },
                    ..
                }
            )
        });
    let mut script = format!("{PRELUDE_HEAD}for __zap_t in {TOOLS}");
    if digests {
        let _ = write!(script, " {DIGEST_TOOL}");
    }
    if lists {
        let _ = write!(script, " {LIST_TOOL}");
    }
    if commands {
        let _ = write!(script, " {COMMAND_TOOLS}");
    }
    script.push_str(PRELUDE);
    if contents {
        // A content read checks what it opened through `/proc/self/fd` (`open_regular`).
        let _ = writeln!(script, "[ -d /proc/self/fd ] || exit {TOOL_MISSING_EXIT}");
    }
    for (index, query) in queries.iter().enumerate() {
        let secs = query.timeout_secs();
        let text = single_quote(&probe_snippet(query));
        let _ = match query {
            Query::Path { .. } => writeln!(script, "p {index} {secs} {text}"),
            Query::Command { origin, .. } => {
                let origin = match origin {
                    CommandOrigin::Zap => 'z',
                    CommandOrigin::Operator => 'o',
                };
                writeln!(script, "q {index} {secs} {origin} {text}")
            }
        };
    }
    let _ = writeln!(script, "echo end {}", queries.len());
    script
}

/// Seconds the reporter gives a timed-out command's group between `SIGTERM` and
/// `SIGKILL` — part of a command probe's worst case.
pub const COMMAND_KILL_GRACE_SECS: u64 = 1;

/// How long the runner lets one lane's batch run before it kills it and fails the lane.
///
/// The sum of its queries' worst cases — a timeout, plus [`COMMAND_KILL_GRACE_SECS`] for a
/// command — plus [`LANE_DEADLINE_MARGIN_SECS`].
///
/// The probes run one after another, each bounded by its own timeout (and a command by
/// its reporter's grace) when `timeout` can stop it, so the sum is the longest a batch of
/// well-behaved probes can take — even if every probe runs to its limit. The deadline
/// fires only on a probe `timeout` failed to stop (see the module docs).
#[must_use]
pub fn lane_deadline_secs(queries: &[&Query]) -> u64 {
    let worst: u64 = queries
        .iter()
        .map(|query| {
            let grace = match query {
                Query::Command { .. } => COMMAND_KILL_GRACE_SECS,
                Query::Path { .. } => 0,
            };
            u64::from(query.timeout_secs().get()) + grace
        })
        .sum();
    worst + LANE_DEADLINE_MARGIN_SECS
}

/// The process group a batch reported in its first output `line` (without its newline).
///
/// The line is `pgid N`, where `N` is a decimal id from 2 to `i32::MAX` — so a garbled
/// record can never name group 0 (the killer's own) or 1 (`init`'s), read as "every
/// process", or wrap to a negative id (a Linux pid never exceeds `pid_max`, at most
/// 2^22).
#[must_use]
pub fn parse_pgid(line: &[u8]) -> Option<u32> {
    let digits = line.strip_prefix(PGID_TAG.as_bytes())?;
    if digits.is_empty() || !digits.iter().all(u8::is_ascii_digit) {
        return None;
    }
    std::str::from_utf8(digits)
        .ok()?
        .parse::<u32>()
        .ok()
        .filter(|&pgid| pgid >= 2 && i32::try_from(pgid).is_ok())
}

/// Split a batch's output into its process-group record and the record lines after it.
///
/// # Errors
/// [`BatchError::MissingPgid`] when the output doesn't start with a well-formed
/// `pgid N` line.
pub fn split_pgid(output: &[u8]) -> Result<(u32, &[u8]), BatchError> {
    let end = output
        .iter()
        .position(|&byte| byte == b'\n')
        .ok_or(BatchError::MissingPgid)?;
    let pgid = parse_pgid(&output[..end]).ok_or(BatchError::MissingPgid)?;
    Ok((pgid, &output[end + 1..]))
}

/// The shell that kills a batch whose record said `pgid`, run on the target.
///
/// It runs as root, over a connection of its own. It first stops (`SIGSTOP`) every
/// process in the batch's session — which `setsid` made the same id — so nothing in it
/// forks while it is looked at; then lists the children of those processes (a running
/// command leads a session of its own: its reporter started it under `setsid`, and its
/// reporter could be killed before it is, reparenting it away); then kills the batch's
/// process group and its whole session — which also reaches the process groups GNU
/// `timeout` makes within it — and finally each listed child's session: a command's
/// shell leads its own, whose id is its pid, and any other child leads none, so its kill
/// finds nothing. `pgrep` / `pkill` do the session work, where installed (`procps` or
/// `BusyBox`). All best-effort; the snippet exits 0.
#[must_use]
pub fn kill_snippet(pgid: u32) -> String {
    format!(
        "pkill -STOP -s {pgid} 2>/dev/null; \
         k=; for q in $(pgrep -s {pgid} 2>/dev/null); do k=\"$k $(pgrep -P $q 2>/dev/null)\"; done; \
         kill -KILL -{pgid} 2>/dev/null; pkill -KILL -s {pgid} 2>/dev/null; \
         for q in $k; do pkill -KILL -s $q 2>/dev/null; done; exit 0"
    )
}

/// One probe's raw result, decoded from its two records.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawRecord {
    /// The exit status of the probe's `timeout` (its `s` tag).
    pub status: i32,
    /// The exit status a command probe's reporter saw the command exit with (its `r`
    /// tag) — `None` when the command didn't finish on its own, and always for a path
    /// probe.
    pub report: Option<i32>,
    /// Standard output, byte-exact.
    pub stdout: Vec<u8>,
    /// Standard error (at most [`STDERR_LIMIT`] bytes).
    pub stderr: Vec<u8>,
}

/// Why the batch output as a whole can't be trusted — every query in the lane goes
/// unanswered.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum BatchError {
    /// The output doesn't start with the process-group record.
    #[error("the output has no process-group record")]
    MissingPgid,
    /// The output isn't ASCII text (the records are hex, so it always is).
    #[error("the output is not text")]
    NotText,
    /// A line that is neither a record for one of the queries nor the end marker.
    #[error("unexpected output on line {line}")]
    UnexpectedLine {
        /// The 1-based line number.
        line: usize,
    },
    /// The output stops without an `end` line — the batch didn't finish.
    #[error("the output was truncated (no end marker)")]
    MissingEnd,
    /// The `end` line counts a different number of probes than were rendered.
    #[error("the end marker counts {found} probes, expected {expected}")]
    EndMismatch {
        /// The count the marker carried.
        found: usize,
        /// The number of queries rendered.
        expected: usize,
    },
}

/// Why one query's records are unusable — only that query goes unanswered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum RecordError {
    /// The output has no record for the query.
    #[error("the batch output has no record for the probe")]
    Missing,
    /// The output has two records of the same kind for the query.
    #[error("the batch output has a duplicate record for the probe")]
    Duplicate,
    /// A record for the query isn't valid hex, or its status tags don't parse.
    #[error("the batch output has a garbled record for the probe")]
    Garbled,
}

/// One record slot: unseen, seen once (its payload), or seen twice.
#[derive(Debug, Clone, Copy, Default)]
enum Slot<'a> {
    #[default]
    Unseen,
    Seen(&'a str),
    Duplicate,
}

impl<'a> Slot<'a> {
    const fn fill(&mut self, payload: &'a str) {
        *self = match self {
            Self::Unseen => Self::Seen(payload),
            Self::Seen(_) | Self::Duplicate => Self::Duplicate,
        };
    }

    const fn take(self) -> Result<&'a str, RecordError> {
        match self {
            Self::Unseen => Err(RecordError::Missing),
            Self::Duplicate => Err(RecordError::Duplicate),
            Self::Seen(payload) => Ok(payload),
        }
    }
}

/// Parse a batch's stdout into `count` raw records (by index).
///
/// # Errors
/// A [`BatchError`] when the output as a whole is untrustworthy: not text, a line that
/// belongs to no query, or a missing or wrong `end` marker.
pub fn parse(
    output: &[u8],
    count: usize,
) -> Result<Vec<Result<RawRecord, RecordError>>, BatchError> {
    let text = std::str::from_utf8(output).map_err(|_| BatchError::NotText)?;
    let mut lines: Vec<&str> = text.split('\n').collect();
    if lines.last() == Some(&"") {
        lines.pop();
    }
    let end = lines.pop().ok_or(BatchError::MissingEnd)?;
    let found = end
        .strip_prefix("end ")
        .and_then(|n| n.parse::<usize>().ok())
        .ok_or(BatchError::MissingEnd)?;
    if found != count {
        return Err(BatchError::EndMismatch {
            found,
            expected: count,
        });
    }

    let mut slots: Vec<(Slot<'_>, Slot<'_>)> = vec![(Slot::Unseen, Slot::Unseen); count];
    for (number, line) in lines.iter().enumerate() {
        let unexpected = BatchError::UnexpectedLine { line: number + 1 };
        let mut parts = line.splitn(3, ' ');
        let (Some(index), Some(tag), Some(payload)) = (parts.next(), parts.next(), parts.next())
        else {
            return Err(unexpected);
        };
        let slot = index
            .parse::<usize>()
            .ok()
            .filter(|_| !index.starts_with('+'))
            .and_then(|index| slots.get_mut(index))
            .ok_or_else(|| unexpected.clone())?;
        match tag {
            "O" => slot.0.fill(payload),
            "E" => slot.1.fill(payload),
            _ => return Err(unexpected),
        }
    }

    Ok(slots
        .into_iter()
        .map(|(out, err)| {
            let stdout = super::decode_hex(out.take()?).ok_or(RecordError::Garbled)?;
            // The stderr's hex, then its status tags, each after a space.
            let err = err.take()?;
            let (stderr, tags) = err
                .find(' ')
                .map(|at| err.split_at(at))
                .ok_or(RecordError::Garbled)?;
            let stderr = super::decode_hex(stderr).ok_or(RecordError::Garbled)?;
            let (status, report) = parse_tags(tags).ok_or(RecordError::Garbled)?;
            Ok(RawRecord {
                status,
                report,
                stdout,
                stderr,
            })
        })
        .collect())
}

/// An `E` record's status tags — an optional `r<N>`, then `s<N>`, each after one space,
/// and nothing else — as `(status, report)`.
fn parse_tags(tags: &str) -> Option<(i32, Option<i32>)> {
    let tag = |text: &str, prefix: char| {
        let digits = text.strip_prefix(prefix)?;
        (!digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit()))
            .then(|| digits.parse::<i32>().ok())
            .flatten()
    };
    let words: Vec<&str> = tags.strip_prefix(' ')?.split(' ').collect();
    match words.as_slice() {
        [status] => Some((tag(status, 's')?, None)),
        [report, status] => Some((tag(status, 's')?, Some(tag(report, 'r')?))),
        _ => None,
    }
}

/// The status `stat` and `readlink` exit with when the read finds nothing (absent,
/// unreachable, not a symlink) — GNU coreutils and `BusyBox` alike.
const PATH_FAILED_EXIT: i32 = 1;

/// Turn one probe's raw record into its query's answer.
///
/// # Errors
/// - [`QueryError::TimedOut`] for a probe its `timeout` stopped: a path probe whose
///   status is a timeout status (124 or 143), or a command with no report whose status is;
/// - [`QueryError::Exited`] for a command with no report and any other status, and for a
///   path facet's failure status other than `stat`'s / `readlink`'s own;
/// - [`QueryError::Unparseable`] for a path facet's success whose output isn't the
///   facet's shape;
/// - [`QueryError::Record`] for a path probe's record that carries a report (the path
///   probe has no reporter).
pub fn decode(query: &Query, record: RawRecord) -> QueryResult {
    // 124 is GNU `timeout`'s expiry status, 143 BusyBox's (the probe's SIGTERM).
    let timed_out = matches!(record.status, 124 | 143);
    match query {
        Query::Path { facet, .. } => match (record.report, record.status) {
            (Some(_), _) => Err(QueryError::Record(RecordError::Garbled)),
            (None, _) if timed_out => Err(QueryError::TimedOut {
                secs: query.timeout_secs(),
            }),
            (None, 0) => decode_path(*facet, record.stdout).map(Observation::Path),
            (None, PATH_FAILED_EXIT) => Ok(Observation::Path(PathObservation::Failed)),
            (None, NOT_REGULAR_EXIT) if facet.reads_content() => {
                Ok(Observation::Path(PathObservation::NotRegular))
            }
            (None, HARD_LINKED_EXIT) if facet.reads_content() => Err(QueryError::HardLinked),
            (None, code) => Err(QueryError::Exited { code }),
        },
        Query::Command { .. } => match record.report {
            Some(code) => Ok(Observation::Command(CommandObservation {
                code,
                stdout: record.stdout,
                stderr: record.stderr,
            })),
            None if timed_out => Err(QueryError::TimedOut {
                secs: query.timeout_secs(),
            }),
            None => Err(QueryError::Exited {
                code: record.status,
            }),
        },
    }
}

/// A successful path probe's output as its facet's observation.
fn decode_path(facet: PathFacet, stdout: Vec<u8>) -> Result<PathObservation, QueryError> {
    match facet {
        PathFacet::Kind => parse_kind(&stdout)
            .map(PathObservation::Kind)
            .ok_or(QueryError::Unparseable),
        PathFacet::Lstat => parse_metadata(&stdout)
            .map(PathObservation::Metadata)
            .ok_or(QueryError::Unparseable),
        PathFacet::LinkTarget => {
            let mut target = stdout;
            if target.last() == Some(&b'\n') {
                target.pop();
            }
            Ok(PathObservation::LinkTarget(target))
        }
        PathFacet::Digest => parse_digest(&stdout)
            .map(PathObservation::Digest)
            .ok_or(QueryError::Unparseable),
        PathFacet::Read { max } => Ok(contents(stdout, max)),
        PathFacet::Empty => Ok(PathObservation::Empty(stdout.is_empty())),
    }
}

/// The length of a SHA-512 digest in hex digits.
const SHA512_HEX_LEN: usize = 128;

/// Parse one `sha512sum` line over stdin (`<digest>  -`): the digest, if it is exactly
/// 128 lowercase hex digits.
fn parse_digest(stdout: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(stdout).ok()?;
    let digest = text.split_whitespace().next()?;
    (digest.len() == SHA512_HEX_LEN
        && digest
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')))
    .then(|| digest.to_owned())
}

/// A [`Read`](PathFacet::Read) answer from up to `max + 1` bytes: the first `max`, and
/// whether there were more.
#[must_use]
pub fn contents(mut bytes: Vec<u8>, max: u32) -> PathObservation {
    let max = usize::try_from(max).unwrap_or(usize::MAX);
    let truncated = bytes.len() > max;
    bytes.truncate(max);
    PathObservation::Contents { bytes, truncated }
}

/// Parse one `stat -L -c %f` line — the raw mode in hex.
fn parse_kind(stdout: &[u8]) -> Option<FileKind> {
    let text = std::str::from_utf8(stdout).ok()?;
    let raw = text.strip_suffix('\n').unwrap_or(text);
    Some(FileKind::from_mode(u32::from_str_radix(raw, 16).ok()?))
}

/// Parse one `stat -c '%f %a %U %G'` line; `None` unless it has exactly those four
/// whitespace-separated fields (a name containing whitespace doesn't parse).
fn parse_metadata(stdout: &[u8]) -> Option<PathMetadata> {
    let text = String::from_utf8_lossy(stdout);
    let parts: Vec<&str> = text.split_whitespace().collect();
    let [raw, mode, owner, group] = parts.as_slice() else {
        return None;
    };
    Some(PathMetadata {
        kind: FileKind::from_mode(u32::from_str_radix(raw, 16).ok()?),
        mode: (*mode).to_owned(),
        owner: (*owner).to_owned(),
        group: (*group).to_owned(),
    })
}

/// Answer a lane's queries from its batch output.
///
/// [`split_pgid`], [`parse`] the records after it, then [`decode`] each — or, when the
/// output as a whole can't be trusted, the same [`QueryError::Batch`] for every query.
#[must_use]
pub fn read(lane: Lane, queries: &[&Query], output: &[u8]) -> Vec<QueryResult> {
    match split_pgid(output).and_then(|(_, records)| parse(records, queries.len())) {
        Ok(records) => queries
            .iter()
            .zip(records)
            .map(|(query, record)| decode(query, record?))
            .collect(),
        Err(error) => fail_lane(lane, queries.len(), &error.to_string()),
    }
}

/// `count` copies of the lane-failure answer — the shape of a batch that couldn't run
/// or whose output can't be trusted.
#[must_use]
pub fn fail_lane(lane: Lane, count: usize, reason: &str) -> Vec<QueryResult> {
    vec![
        Err(QueryError::Batch {
            lane,
            reason: reason.to_owned(),
        });
        count
    ]
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroU32;

    use super::{
        BatchError, Lane, Observation, PathFacet, PathObservation, Query, QueryError, RawRecord,
        RecordError, STDERR_LIMIT, decode, kill_snippet, lane_deadline_secs, parse, parse_pgid,
        read, render, split_pgid,
    };
    use crate::observe::{CommandObservation, CommandOrigin, FileKind, PathMetadata, Privilege};

    fn secs(n: u32) -> NonZeroU32 {
        NonZeroU32::new(n).unwrap()
    }

    fn hex(bytes: &[u8]) -> String {
        use std::fmt::Write as _;
        bytes.iter().fold(String::new(), |mut hex, byte| {
            let _ = write!(hex, "{byte:02x}");
            hex
        })
    }

    /// The two records `p` prints for one path probe that exited `status`.
    fn records(index: usize, stdout: &[u8], status: i32, stderr: &[u8]) -> String {
        format!(
            "{index} O {}\n{index} E {} s{status}\n",
            hex(stdout),
            hex(stderr)
        )
    }

    /// The two records `q` prints for one command whose reporter saw it exit `report`.
    fn command_records(index: usize, stdout: &[u8], report: i32, stderr: &[u8]) -> String {
        format!(
            "{index} O {}\n{index} E {} r{report} s0\n",
            hex(stdout),
            hex(stderr)
        )
    }

    /// A raw record with `status`, `report`, and no output.
    const fn raw(status: i32, report: Option<i32>) -> RawRecord {
        RawRecord {
            status,
            report,
            stdout: Vec::new(),
            stderr: Vec::new(),
        }
    }

    fn path(facet: PathFacet) -> Query {
        Query::Path {
            path: "/opt/it's here".to_owned(),
            facet,
            privilege: Privilege::Elevated,
        }
    }

    fn command(snippet: &str) -> Query {
        Query::Command {
            snippet: snippet.to_owned(),
            privilege: Privilege::Login,
            timeout_secs: secs(5),
            origin: CommandOrigin::Zap,
        }
    }

    #[test]
    fn renders_one_quoted_probe_per_query_and_the_end_count() {
        let (lstat, link, echo, kind, check) = (
            path(PathFacet::Lstat),
            path(PathFacet::LinkTarget),
            command("echo 'x' | cat"),
            path(PathFacet::Kind),
            Query::operator_command("test -f x"),
        );
        let script = render(&[&lstat, &link, &echo, &kind, &check]);
        let probes: Vec<&str> = script
            .lines()
            .filter(|l| l.starts_with("p ") || l.starts_with("q "))
            .collect();
        assert_eq!(
            probes,
            [
                r"p 0 30 'exec stat -c '\''%f %a %U %G'\'' -- '\''/opt/it'\''\'\'''\''s here'\'''",
                r"p 1 10 'exec readlink -- '\''/opt/it'\''\'\'''\''s here'\'''",
                r"q 2 5 z 'echo '\''x'\'' | cat'",
                r"p 3 10 'exec stat -L -c %f -- '\''/opt/it'\''\'\'''\''s here'\'''",
                r"q 4 60 o 'test -f x'",
            ]
        );
        assert!(
            script.starts_with(
                "echo \"pgid $$\"; exec 2>/dev/null 3>&1; unset __zap_script __zap_c __zap_e __zap_g __zap_p __zap_r __zap_s __zap_t __zap_x\n"
            )
        );
        assert!(script.ends_with("echo end 5\n"));
    }

    #[test]
    fn content_reads_open_the_path_on_stdin_and_a_digest_batch_checks_for_sha512sum() {
        let (digest, read, kind) = (
            path(PathFacet::Digest),
            path(PathFacet::Read { max: 64 }),
            path(PathFacet::Kind),
        );
        let script = render(&[&digest, &read]);
        let probes: Vec<&str> = script.lines().filter(|l| l.starts_with("p ")).collect();
        assert_eq!(
            probes,
            [
                r#"p 0 60 '[ ! -L '\''/opt/it'\''\'\'''\''s here'\'' ] || exit 3; [ ! -e '\''/opt/it'\''\'\'''\''s here'\'' ] || [ -f '\''/opt/it'\''\'\'''\''s here'\'' ] || exit 3; command exec <'\''/opt/it'\''\'\'''\''s here'\'' || exit 1; __zap_i=$(stat -L -c %d:%i:%h /proc/self/fd/0) && [ -f /proc/self/fd/0 ] && [ "$(stat -c %d:%i -- '\''/opt/it'\''\'\'''\''s here'\'')" = "${__zap_i%:*}" ] || exit 3; [ "${__zap_i##*:}" = 1 ] || exit 4; exec sha512sum'"#,
                r#"p 1 10 '[ ! -L '\''/opt/it'\''\'\'''\''s here'\'' ] || exit 3; [ ! -e '\''/opt/it'\''\'\'''\''s here'\'' ] || [ -f '\''/opt/it'\''\'\'''\''s here'\'' ] || exit 3; command exec <'\''/opt/it'\''\'\'''\''s here'\'' || exit 1; __zap_i=$(stat -L -c %d:%i:%h /proc/self/fd/0) && [ -f /proc/self/fd/0 ] && [ "$(stat -c %d:%i -- '\''/opt/it'\''\'\'''\''s here'\'')" = "${__zap_i%:*}" ] || exit 3; [ "${__zap_i##*:}" = 1 ] || exit 4; exec head -c 65'"#,
            ]
        );
        let tools = |script: &str| {
            script
                .lines()
                .find(|l| l.starts_with("for __zap_t in "))
                .map(ToOwned::to_owned)
                .unwrap()
        };
        assert!(
            tools(&script)
                .starts_with("for __zap_t in timeout od tr head cat stat readlink sha512sum; do")
        );
        // A batch with no digest doesn't need `sha512sum` on the target.
        assert!(
            tools(&render(&[&read, &kind]))
                .starts_with("for __zap_t in timeout od tr head cat stat readlink; do")
        );
        // A batch with an emptiness read needs `ls`, which lists a directory only.
        let empty = path(PathFacet::Empty);
        let script = render(&[&empty]);
        assert!(
            tools(&script)
                .starts_with("for __zap_t in timeout od tr head cat stat readlink ls; do")
        );
        assert_eq!(
            script
                .lines()
                .filter(|l| l.starts_with("p "))
                .collect::<Vec<_>>(),
            [
                r"p 0 10 '[ -d '\''/opt/it'\''\'\'''\''s here'\'' ] && [ -r '\''/opt/it'\''\'\'''\''s here'\'' ] || exit 1; exec ls -A -- '\''/opt/it'\''\'\'''\''s here'\'''"
            ]
        );
        assert_eq!(
            decode(
                &empty,
                RawRecord {
                    stdout: Vec::new(),
                    ..raw(0, None)
                }
            ),
            Ok(Observation::Path(PathObservation::Empty(true)))
        );
        assert_eq!(
            decode(
                &empty,
                RawRecord {
                    stdout: b".zap_remote_hash\n".to_vec(),
                    ..raw(0, None)
                }
            ),
            Ok(Observation::Path(PathObservation::Empty(false)))
        );
        // A batch with a command needs `setsid` and `sleep` for its reporter.
        let check = Query::operator_command("true");
        assert!(
            tools(&render(&[&read, &check])).starts_with(
                "for __zap_t in timeout od tr head cat stat readlink setsid sleep; do"
            )
        );
    }

    #[test]
    fn decodes_the_content_facets() {
        let ok = |stdout: &[u8]| RawRecord {
            stdout: stdout.to_vec(),
            ..raw(0, None)
        };
        let digest = "0123456789abcdef".repeat(8);
        assert_eq!(
            decode(
                &path(PathFacet::Digest),
                ok(format!("{digest}  -\n").as_bytes())
            ),
            Ok(Observation::Path(PathObservation::Digest(digest.clone())))
        );
        for bad in [
            &b""[..],
            b"0123  -\n",
            digest.to_uppercase().as_bytes(),
            format!("{digest}0  -\n").as_bytes(),
        ] {
            assert_eq!(
                decode(&path(PathFacet::Digest), ok(bad)),
                Err(QueryError::Unparseable),
                "{bad:?}"
            );
        }
        let read = path(PathFacet::Read { max: 4 });
        assert_eq!(
            decode(&read, ok(b"ab\n")),
            Ok(Observation::Path(PathObservation::Contents {
                bytes: b"ab\n".to_vec(),
                truncated: false,
            }))
        );
        assert_eq!(
            decode(&read, ok(b"abcd")),
            Ok(Observation::Path(PathObservation::Contents {
                bytes: b"abcd".to_vec(),
                truncated: false,
            }))
        );
        // The probe reads one byte past `max`: a fifth byte means the file held more.
        assert_eq!(
            decode(&read, ok(b"abcde")),
            Ok(Observation::Path(PathObservation::Contents {
                bytes: b"abcd".to_vec(),
                truncated: true,
            }))
        );
        // A path that can't be opened or read exits 1, like `stat`.
        let failed = RawRecord {
            stderr: b"sh: can't open".to_vec(),
            ..raw(1, None)
        };
        assert_eq!(
            decode(&path(PathFacet::Digest), failed),
            Ok(Observation::Path(PathObservation::Failed))
        );
    }

    #[test]
    fn round_trips_nul_newlines_and_a_missing_trailing_newline() {
        let payload = b"a\0b\n\nc";
        let output = format!("{}end 1\n", command_records(0, payload, 3, b"oops\n"));
        let parsed = parse(output.as_bytes(), 1).unwrap();
        assert_eq!(
            parsed,
            vec![Ok(RawRecord {
                stdout: payload.to_vec(),
                stderr: b"oops\n".to_vec(),
                ..raw(0, Some(3))
            })]
        );
    }

    #[test]
    fn an_empty_probe_and_empty_stderr_parse() {
        let output = format!("{}end 1\n", records(0, b"", 0, b""));
        assert_eq!(output, "0 O \n0 E  s0\nend 1\n");
        assert_eq!(parse(output.as_bytes(), 1).unwrap()[0], Ok(raw(0, None)));
    }

    #[test]
    fn a_missing_record_affects_only_its_query() {
        let output = format!("{}0 E \nend 2\n", records(1, b"x", 0, b""));
        let parsed = parse(output.as_bytes(), 2).unwrap();
        assert_eq!(parsed[0], Err(RecordError::Missing));
        assert!(parsed[1].is_ok());
    }

    #[test]
    fn a_duplicate_record_affects_only_its_query() {
        let output = format!(
            "{}{}{}end 2\n",
            records(0, b"x", 0, b""),
            records(0, b"y", 0, b""),
            records(1, b"z", 0, b"")
        );
        let parsed = parse(output.as_bytes(), 2).unwrap();
        assert_eq!(parsed[0], Err(RecordError::Duplicate));
        assert!(parsed[1].is_ok());
    }

    #[test]
    fn garbled_records_affect_only_their_query() {
        let (good_out, good_err) = ("0 O 41", "0 E 42 s0");
        for (out, err) in [
            ("0 O 6", good_err),
            ("0 O zz", good_err),
            ("0 O 4A", good_err),
            (good_out, "0 E 4 s0"),
            (good_out, "0 E 42"),
            (good_out, "0 E 42 "),
            (good_out, "0 E 42 s"),
            (good_out, "0 E 42 s+1"),
            (good_out, "0 E 42 s-1"),
            (good_out, "0 E 42 x0"),
            (good_out, "0 E 42 r0"),
            (good_out, "0 E 42 s0 r1"),
            (good_out, "0 E 42 r1 r1 s0"),
            (good_out, "0 E 42 s0 s0"),
            (good_out, "0 E 42  s0"),
            (good_out, "0 E 42 s0 "),
            (good_out, "0 E 42 s99999999999"),
        ] {
            let output = format!("{out}\n{err}\n{}end 2\n", records(1, b"z", 0, b""));
            let parsed = parse(output.as_bytes(), 2).unwrap();
            assert_eq!(parsed[0], Err(RecordError::Garbled), "{out} / {err}");
            assert!(parsed[1].is_ok(), "{out} / {err}");
        }
        let output = format!("{good_out}\n{good_err}\nend 1\n");
        assert_eq!(
            parse(output.as_bytes(), 1).unwrap()[0],
            Ok(RawRecord {
                stdout: b"A".to_vec(),
                stderr: b"B".to_vec(),
                ..raw(0, None)
            })
        );
    }

    #[test]
    fn a_record_lookalike_inside_a_payload_stays_inside_it() {
        // A probe that prints a record line of its own is hex-encoded like any output.
        let sneaky = b"1 O 0a30\nend 2\n";
        let output = format!("{}end 1\n", records(0, sneaky, 0, b""));
        assert_eq!(
            parse(output.as_bytes(), 1).unwrap()[0]
                .as_ref()
                .unwrap()
                .stdout,
            sneaky
        );
        // Nor can one that prints status tags on either stream forge its status: the tags
        // are written from outside the probe, after its stderr.
        let forged = b"\n0 r0 s0\n 0 E  r0 s0";
        let output = format!("{}end 1\n", command_records(0, forged, 1, forged));
        let record = parse(output.as_bytes(), 1).unwrap().remove(0).unwrap();
        assert_eq!(
            (record.stdout.as_slice(), record.stderr.as_slice()),
            (&forged[..], &forged[..])
        );
        assert_eq!((record.status, record.report), (0, Some(1)));
    }

    #[test]
    fn untrustworthy_output_fails_the_whole_batch() {
        let one = records(0, b"x", 0, b"");
        let cases: [(String, BatchError); 6] = [
            (one.clone(), BatchError::MissingEnd),
            (String::new(), BatchError::MissingEnd),
            (
                format!("{one}end 2\n"),
                BatchError::EndMismatch {
                    found: 2,
                    expected: 1,
                },
            ),
            (
                format!("garbage\n{one}end 1\n"),
                BatchError::UnexpectedLine { line: 1 },
            ),
            (
                format!("{one}7 O 0a30\nend 1\n"),
                BatchError::UnexpectedLine { line: 3 },
            ),
            (format!("{one}end 1\nextra\n"), BatchError::MissingEnd),
        ];
        for (output, expected) in cases {
            assert_eq!(parse(output.as_bytes(), 1), Err(expected), "{output:?}");
        }
        assert_eq!(parse(b"\xff\n", 0), Err(BatchError::NotText));
    }

    #[test]
    fn the_process_group_record_leads_the_output() {
        let (a, b) = (path(PathFacet::Kind), command("x"));
        let records = format!(
            "{}{}end 2\n",
            records(0, b"", 1, b""),
            command_records(1, b"y", 0, b"")
        );
        let results = read(
            Lane::Login,
            &[&a, &b],
            format!("pgid 4242\n{records}").as_bytes(),
        );
        assert_eq!(results[0], Ok(Observation::Path(PathObservation::Failed)));
        assert!(matches!(&results[1], Ok(Observation::Command(c)) if c.stdout == b"y"));
        assert_eq!(
            split_pgid(format!("pgid 4242\n{records}").as_bytes()),
            Ok((4242, records.as_bytes()))
        );
        // Without the record first, the whole output is untrustworthy.
        for output in [
            records.clone(),
            format!("{records}pgid 4242\n"),
            "pgid 4242".to_owned(),
        ] {
            assert_eq!(
                split_pgid(output.as_bytes()),
                Err(BatchError::MissingPgid),
                "{output:?}"
            );
            assert!(matches!(
                read(Lane::Login, &[&a, &b], output.as_bytes())[0],
                Err(QueryError::Batch { .. })
            ));
        }
    }

    #[test]
    fn a_process_group_record_never_names_a_group_a_kill_must_not_reach() {
        assert_eq!(parse_pgid(b"pgid 2"), Some(2));
        assert_eq!(parse_pgid(b"pgid 4194304"), Some(4_194_304));
        assert_eq!(parse_pgid(b"pgid 2147483647"), Some(2_147_483_647));
        for bad in [
            &b"pgid 0"[..],
            b"pgid 1",
            b"pgid -1",
            b"pgid +5",
            b"pgid 5 ",
            b"pgid ",
            b"pgid 2147483648",
            b"pgid 4294967295",
            b"pgid 4294967296",
            b"pgid 12\r",
            b"PGID 12",
            b"12",
        ] {
            assert_eq!(parse_pgid(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn the_kill_reaches_the_group_and_the_session() {
        assert_eq!(
            kill_snippet(4242),
            "pkill -STOP -s 4242 2>/dev/null; \
             k=; for q in $(pgrep -s 4242 2>/dev/null); do k=\"$k $(pgrep -P $q 2>/dev/null)\"; done; \
             kill -KILL -4242 2>/dev/null; pkill -KILL -s 4242 2>/dev/null; \
             for q in $k; do pkill -KILL -s $q 2>/dev/null; done; exit 0"
        );
    }

    #[test]
    fn a_failed_batch_answers_every_query_with_the_lane_failure() {
        let (a, b) = (path(PathFacet::Kind), path(PathFacet::Lstat));
        let results = read(Lane::Root, &[&a, &b], b"");
        assert_eq!(results.len(), 2);
        for result in results {
            assert!(matches!(
                result,
                Err(QueryError::Batch {
                    lane: Lane::Root,
                    ..
                })
            ));
        }
    }

    #[test]
    fn a_timeout_status_reads_timed_out_only_when_nothing_reported_an_exit() {
        for status in [124, 143] {
            let record = RawRecord {
                stderr: b"Terminated\n".to_vec(),
                ..raw(status, None)
            };
            assert_eq!(
                decode(&command("sleep 9"), record.clone()),
                Err(QueryError::TimedOut { secs: secs(5) })
            );
            assert_eq!(
                decode(&path(PathFacet::Kind), record),
                Err(QueryError::TimedOut { secs: secs(10) })
            );
            // A command that exited 124 or 143 itself reads as that exit — whatever its
            // `timeout` then exited (a report and a timeout status together: the
            // command finished just as its time ran out).
            for timeout_status in [0, status] {
                assert_eq!(
                    decode(&command("exit 124"), raw(timeout_status, Some(status))),
                    Ok(Observation::Command(CommandObservation {
                        code: status,
                        stdout: Vec::new(),
                        stderr: Vec::new(),
                    }))
                );
            }
        }
        // A command whose reporter died some other way established nothing.
        assert_eq!(
            decode(&command("x"), raw(137, None)),
            Err(QueryError::Exited { code: 137 })
        );
        assert_eq!(
            decode(&command("x"), raw(0, None)),
            Err(QueryError::Exited { code: 0 })
        );
        // A path probe has no reporter: a report on its record is garbled.
        assert_eq!(
            decode(&path(PathFacet::Kind), raw(0, Some(0))),
            Err(QueryError::Record(RecordError::Garbled))
        );
    }

    #[test]
    fn decodes_path_facets() {
        let ok = |stdout: &[u8]| RawRecord {
            stdout: stdout.to_vec(),
            ..raw(0, None)
        };
        assert_eq!(
            decode(&path(PathFacet::Lstat), ok(b"41ed 755 root wheel\n")),
            Ok(Observation::Path(PathObservation::Metadata(PathMetadata {
                kind: FileKind::Directory,
                mode: "755".to_owned(),
                owner: "root".to_owned(),
                group: "wheel".to_owned(),
            })))
        );
        assert_eq!(
            decode(&path(PathFacet::Kind), ok(b"a1ff\n")),
            Ok(Observation::Path(PathObservation::Kind(FileKind::Symlink)))
        );
        // A success whose output isn't the facet's shape is never a failed read: a group
        // name with a space gives five fields, a garbled kind no hex.
        for (facet, stdout) in [
            (PathFacet::Lstat, &b"41ed 755 root domain users\n"[..]),
            (PathFacet::Lstat, b"755 root root\n"),
            (PathFacet::Kind, b"41ed 755\n"),
            (PathFacet::Kind, b""),
        ] {
            assert_eq!(
                decode(&path(facet), ok(stdout)),
                Err(QueryError::Unparseable),
                "{facet:?} {stdout:?}"
            );
        }
        // `readlink`'s one trailing newline is not part of the target.
        assert_eq!(
            decode(&path(PathFacet::LinkTarget), ok(b"/a b\n\n")),
            Ok(Observation::Path(PathObservation::LinkTarget(
                b"/a b\n".to_vec()
            )))
        );
        let failed = RawRecord {
            stderr: b"readlink: not a link".to_vec(),
            ..raw(1, None)
        };
        assert_eq!(
            decode(&path(PathFacet::LinkTarget), failed),
            Ok(Observation::Path(PathObservation::Failed))
        );
    }

    #[test]
    fn only_the_documented_failure_status_reads_as_a_failed_read() {
        // 126/127 (couldn't run), 137 (killed), 2 (usage): the read established nothing.
        for code in [2, 126, 127, 137] {
            for facet in [
                PathFacet::Kind,
                PathFacet::Lstat,
                PathFacet::LinkTarget,
                PathFacet::Digest,
                PathFacet::Read { max: 8 },
                PathFacet::Empty,
            ] {
                assert_eq!(
                    decode(&path(facet), raw(code, None)),
                    Err(QueryError::Exited { code }),
                    "{facet:?} {code}"
                );
            }
        }
    }

    /// A content read's not-a-regular-file status is its own observation; the same
    /// status from any other facet established nothing.
    #[test]
    fn a_content_read_of_no_regular_file_reads_as_one() {
        for facet in [PathFacet::Digest, PathFacet::Read { max: 8 }] {
            assert_eq!(
                decode(&path(facet), raw(super::NOT_REGULAR_EXIT, None)),
                Ok(Observation::Path(PathObservation::NotRegular)),
                "{facet:?}"
            );
        }
        for facet in [
            PathFacet::Kind,
            PathFacet::Lstat,
            PathFacet::LinkTarget,
            PathFacet::Empty,
        ] {
            assert_eq!(
                decode(&path(facet), raw(super::NOT_REGULAR_EXIT, None)),
                Err(QueryError::Exited {
                    code: super::NOT_REGULAR_EXIT
                }),
                "{facet:?}"
            );
        }
    }

    /// The script text spells out values the runner reads by name; each must agree.
    #[test]
    fn the_script_text_agrees_with_the_named_constants() {
        assert!(super::BATCH_SHELL.starts_with("__zap_script=$(cat) "));
        assert!(super::PRELUDE_HEAD.contains("; unset __zap_script "));
        let tool_missing = format!("|| exit {}", super::TOOL_MISSING_EXIT);
        assert_eq!(super::PRELUDE.matches(&tool_missing).count(), 2);
        assert!(!super::PRELUDE.replace(&tool_missing, "").contains("exit 9"));
        let stderr_cut = format!("head -c {STDERR_LIMIT};");
        assert_eq!(super::PRELUDE.matches(&stderr_cut).count(), 2);
        assert_eq!(super::PRELUDE.matches("head -c").count(), 2);
        assert!(super::STDOUT_LIMIT_REASON.contains(&format!(
            "the {} MiB limit",
            super::STDOUT_LIMIT / (1024 * 1024)
        )));
    }

    #[test]
    fn the_lane_deadline_is_the_sum_of_the_timeouts_plus_a_margin() {
        let (a, b, c) = (path(PathFacet::Kind), path(PathFacet::Lstat), command("x"));
        // The reporter's grace is the one the deadline counts.
        assert!(super::PRELUDE.contains(&format!(
            "sleep {}; kill -KILL",
            super::COMMAND_KILL_GRACE_SECS
        )));
        // A command's worst case adds its reporter's second of grace.
        assert_eq!(lane_deadline_secs(&[&a, &b, &c]), 10 + 30 + (5 + 1) + 30);
        assert_eq!(lane_deadline_secs(&[&c]), 5 + 1 + 30);
        assert_eq!(lane_deadline_secs(&[]), 30);
    }

    #[test]
    fn decodes_a_command_with_its_streams() {
        let record = RawRecord {
            stdout: b"out".to_vec(),
            stderr: vec![b'e'; STDERR_LIMIT],
            ..raw(0, Some(2))
        };
        assert_eq!(
            decode(&command("x"), record),
            Ok(Observation::Command(CommandObservation {
                code: 2,
                stdout: b"out".to_vec(),
                stderr: vec![b'e'; STDERR_LIMIT],
            }))
        );
    }
}
