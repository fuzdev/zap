//! Observe → interpret — detection as typed, read-only queries plus a pure verdict.
//!
//! A kind that detects this way splits its detector in two:
//!
//! - **`queries`** — the target reads its detection needs, built from the resource and
//!   its resolved fields alone (no connection) as a list of [`Query`]s.
//! - **`interpret`** — a pure function from the answers ([`QueryResult`]s, in the same
//!   order) to a [`Detection`]. It takes no connection, so a detector cannot read
//!   anything it didn't declare: the query list *is* its read set.
//!
//! A runner in `zap_core` answers the queries. Over SSH every query of a [`Lane`] runs
//! in one shell script ([`batch`]), so a detection pass costs one round-trip per lane
//! however many resources it covers.
//!
//! Each query carries the [`Privilege`] its read runs under — the least the read needs;
//! moving a read between privileges is a reviewed decision. Privilege is a claim about what the read can
//! see (a root-only directory hides its entries from [`Privilege::Login`]), so it is
//! chosen per read, never per kind. See [`Privilege`] for the three levels and how each
//! connection honors them.
//!
//! Answers that couldn't be established are [`QueryError`]s, never a guessed
//! observation: a timed-out probe, one that failed some other way than "the read found
//! nothing", output that doesn't parse, a missing or garbled batch record, or a lane
//! whose whole batch failed. `interpret` reads only the answers it needs, so an error on
//! an answer the verdict doesn't depend on doesn't hold the resource.
//!
//! Kinds: [`apt_repo`], [`build`], [`database`], [`directory`], [`file`](mod@file),
//! [`firewall`], [`installer`], [`link`], [`package`], [`script`], [`service`], [`swap`],
//! [`user`], [`verify`] — every kind but `pipeline`, which reads nothing (it always runs).
//!
//! A read that depends on another read's answer — the `pg_hba.conf` path `PostgreSQL`
//! reports, a `copy_from` user's home — is composed in the target shell, inside one
//! [`Query::Command`] snippet, so every query is still known from the config alone.

pub mod apt_repo;
pub mod batch;
pub mod build;
pub mod database;
pub mod directory;
pub mod file;
pub mod firewall;
pub mod installer;
pub mod link;
pub mod package;
pub mod script;
pub mod service;
pub mod swap;
pub mod user;
pub mod verify;

use std::num::NonZeroU32;

use serde::{Deserialize, Serialize};

use crate::detected::{CurrentState, Detection};
use crate::schema::normalize_mode;

/// Seconds one of zap's own path reads (`stat`, `readlink`) may run before it times out.
///
/// Its `timeout` then kills it and its query reads [`QueryError::TimedOut`]. Short: a
/// healthy read takes milliseconds, so one this slow is a hung mount.
pub const PATH_TIMEOUT: NonZeroU32 = NonZeroU32::MIN.saturating_add(9);

/// Seconds an [`Lstat`](PathFacet::Lstat) read may run — longer than
/// [`PATH_TIMEOUT`], because it is the one path read that resolves owner and group
/// names, which may go through a network name service.
pub const PATH_NAMES_TIMEOUT: NonZeroU32 = NonZeroU32::MIN.saturating_add(29);

/// Seconds a [`Digest`](PathFacet::Digest) read may run — longer than [`PATH_TIMEOUT`],
/// because it reads the whole file, which for a large binary on a slow disk takes
/// seconds rather than milliseconds.
pub const PATH_DIGEST_TIMEOUT: NonZeroU32 = NonZeroU32::MIN.saturating_add(59);

/// The default timeout for a [`Query::Command`] — longer than a path read's, since a
/// command probe may do real work (a package query, a `psql` round-trip).
pub const COMMAND_TIMEOUT: NonZeroU32 = NonZeroU32::MIN.saturating_add(59);

/// The privilege a query's read runs under.
///
/// Three levels:
///
/// - [`Login`](Self::Login) — as the connecting user, unprivileged, on every
///   connection.
/// - [`Root`](Self::Root) — always as root, on every connection (a tool that needs root
///   to answer at all, like `ufw status`): a local target answers it through a
///   `sudo sh` batch.
/// - [`Elevated`](Self::Elevated) — the privilege of zap's reads of the paths it manages:
///   as root over SSH, where the login user isn't assumed to own what zap manages; on a
///   local target, as the operator first, answered natively, and — when that read fails
///   any other way than "not found" (a permission denial, a root-only parent) — again as
///   root, through a `sudo sh` batch — the same two-tier escalation `zap_core`'s single
///   file reads (`exists`, `read_bytes`, `snapshot`) use on a local target.
///
/// Over SSH, `Root` and `Elevated` reads share the root [`Lane`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Privilege {
    /// Unprivileged, as the connecting user.
    Login,
    /// As root on every connection.
    Root,
    /// As root over SSH; on a local target as the operator, escalating to root when the
    /// operator's read fails for any reason but "not found".
    Elevated,
}

impl Privilege {
    /// The lane this read batches into over SSH.
    #[must_use]
    pub const fn remote_lane(self) -> Lane {
        match self {
            Self::Login => Lane::Login,
            Self::Root | Self::Elevated => Lane::Root,
        }
    }

    /// The lane this read batches into on a local target. `Elevated` reads as the
    /// operator there first, so it shares the login lane (a path read in it is answered
    /// natively, without a batch); the runner re-asks a read the operator couldn't make
    /// in the root lane.
    #[must_use]
    pub const fn local_lane(self) -> Lane {
        match self {
            Self::Root => Lane::Root,
            Self::Login | Self::Elevated => Lane::Login,
        }
    }
}

/// One batch's worth of reads — the unit a runner executes as one script.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Lane {
    /// Run as root (`sudo sh`).
    Root,
    /// Run as the connecting user (`sh`).
    Login,
}

impl Lane {
    /// The lane's wire name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Root => "root",
            Self::Login => "login",
        }
    }
}

impl std::fmt::Display for Lane {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One read-only question about the target.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Query {
    /// A fact about one path, answered by a [`PathObservation`].
    Path {
        /// The resolved (target-side) path.
        path: String,
        /// Which fact to read.
        facet: PathFacet,
        /// The privilege the read runs under.
        privilege: Privilege,
    },
    /// A shell snippet, answered by a [`CommandObservation`]. Its text reaches the
    /// target shell over a pipe, never an argv.
    Command {
        /// The snippet, run by `sh` with stdin at `/dev/null`.
        snippet: String,
        /// The privilege the snippet runs under.
        privilege: Privilege,
        /// Seconds before the snippet is killed and the query reads timed out.
        timeout_secs: NonZeroU32,
        /// Whose command it is — which decides the locale it runs in.
        #[serde(default, skip_serializing_if = "CommandOrigin::is_zap")]
        origin: CommandOrigin,
    },
}

/// Whose command a [`Query::Command`] runs, which decides the locale it runs in.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CommandOrigin {
    /// One of zap's own probes, whose output is parsed: it runs under `LC_ALL=C`, so the
    /// output is the same on every target.
    #[default]
    Zap,
    /// An operator's command — a `script` check, a `verify` command, a `package` check —
    /// read by its exit status (and a `verify` command by its stdout): it runs in the
    /// target's own locale, as it would run by hand.
    Operator,
}

impl CommandOrigin {
    /// Whether this is [`Zap`](Self::Zap) — the wire default, left off a serialized query.
    #[must_use]
    pub const fn is_zap(&self) -> bool {
        matches!(self, Self::Zap)
    }
}

impl Query {
    /// A [`Query::Path`] read of `facet` at `path`, under `privilege`.
    #[must_use]
    pub fn path(path: impl Into<String>, facet: PathFacet, privilege: Privilege) -> Self {
        Self::Path {
            path: path.into(),
            facet,
            privilege,
        }
    }

    /// A zap-owned [`Query::Command`] run as the connecting user under
    /// [`COMMAND_TIMEOUT`].
    #[must_use]
    pub fn login_command(snippet: impl Into<String>) -> Self {
        Self::Command {
            snippet: snippet.into(),
            privilege: Privilege::Login,
            timeout_secs: COMMAND_TIMEOUT,
            origin: CommandOrigin::Zap,
        }
    }

    /// An operator's command — a [`Query::Command`] of [`CommandOrigin::Operator`], run as
    /// the connecting user under [`COMMAND_TIMEOUT`], in the target's own locale.
    #[must_use]
    pub fn operator_command(snippet: impl Into<String>) -> Self {
        Self::Command {
            snippet: snippet.into(),
            privilege: Privilege::Login,
            timeout_secs: COMMAND_TIMEOUT,
            origin: CommandOrigin::Operator,
        }
    }

    /// A zap-owned [`Query::Command`] run as root under [`COMMAND_TIMEOUT`] — its snippet
    /// written without `sudo`; the lane supplies root.
    #[must_use]
    pub fn root_command(snippet: impl Into<String>) -> Self {
        Self::Command {
            snippet: snippet.into(),
            privilege: Privilege::Root,
            timeout_secs: COMMAND_TIMEOUT,
            origin: CommandOrigin::Zap,
        }
    }

    /// The privilege this query's read runs under.
    #[must_use]
    pub const fn privilege(&self) -> Privilege {
        match self {
            Self::Path { privilege, .. } | Self::Command { privilege, .. } => *privilege,
        }
    }

    /// Seconds before this query's probe is killed.
    #[must_use]
    pub const fn timeout_secs(&self) -> NonZeroU32 {
        match self {
            Self::Path { facet, .. } => facet.timeout_secs(),
            Self::Command { timeout_secs, .. } => *timeout_secs,
        }
    }
}

impl PathFacet {
    /// Whether this facet reads the file's bytes ([`Digest`](Self::Digest),
    /// [`Read`](Self::Read)): the reads that open only a regular file of its own, and
    /// answer [`PathObservation::NotRegular`] for anything else.
    #[must_use]
    pub const fn reads_content(self) -> bool {
        matches!(self, Self::Digest | Self::Read { .. })
    }

    /// Seconds a read of this facet may run: [`PATH_NAMES_TIMEOUT`] for the one that
    /// resolves names, [`PATH_DIGEST_TIMEOUT`] for the one that reads a whole file,
    /// [`PATH_TIMEOUT`] otherwise.
    #[must_use]
    pub const fn timeout_secs(self) -> NonZeroU32 {
        match self {
            Self::Lstat => PATH_NAMES_TIMEOUT,
            Self::Digest => PATH_DIGEST_TIMEOUT,
            Self::Kind | Self::LinkTarget | Self::Read { .. } | Self::Empty => PATH_TIMEOUT,
        }
    }
}

/// The fact a [`Query::Path`] reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PathFacet {
    /// The type of what the path resolves to, following symlinks (`stat -L -c %f`).
    /// Reads nothing else — no owner or group names, so no name-service lookup — and
    /// fails exactly when `test -e` does: an absent path, a dangling symlink, or a path
    /// the read's privilege can't traverse.
    Kind,
    /// The path's own type and ownership metadata — a symlink is not followed
    /// (`stat -c '%f %a %U %G'`).
    Lstat,
    /// A symlink's target (`readlink`). Fails for a path that isn't a symlink, is absent,
    /// or can't be reached at the read's privilege.
    LinkTarget,
    /// The SHA-512 of the bytes of the regular file at the path (`sha512sum` over the
    /// opened file on its stdin, so no file name reaches its output). Only the digest
    /// crosses the wire, however large the file. A symbolic link at the path is not
    /// followed, and nothing but a regular file is opened: either is
    /// [`PathObservation::NotRegular`]. Fails for a path that is absent, can't be opened
    /// at the read's privilege, or can't be read.
    Digest,
    /// At most `max` bytes of the regular file at the path (`head -c`), for a small file
    /// read whole — an extract sentinel. Opens and fails like [`Digest`](Self::Digest).
    /// The read says whether the file held more ([`PathObservation::Contents`]).
    Read {
        /// The most bytes the answer carries.
        max: u32,
    },
    /// Whether the directory the path resolves to holds nothing (`ls -A` lists nothing),
    /// following symlinks as `ls` does — the extract script's own test of a
    /// destination's emptiness. Fails for a path that is absent, isn't a directory, or
    /// can't be reached or listed at the read's privilege.
    Empty,
}

/// An answered query.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Observation {
    /// The answer to a [`Query::Path`].
    Path(PathObservation),
    /// The answer to a [`Query::Command`].
    Command(CommandObservation),
}

/// What a [`Query::Path`] saw.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PathObservation {
    /// The file type a [`Kind`](PathFacet::Kind) read.
    Kind(FileKind),
    /// The metadata an [`Lstat`](PathFacet::Lstat) read.
    Metadata(PathMetadata),
    /// A symlink's target bytes, exactly as stored.
    LinkTarget(Vec<u8>),
    /// The SHA-512 a [`Digest`](PathFacet::Digest) read, as 128 lowercase hex digits.
    Digest(String),
    /// What a [`Read`](PathFacet::Read) read.
    Contents {
        /// The first `max` bytes (all of them, when `truncated` is false).
        bytes: Vec<u8>,
        /// Whether the file held more than `max` bytes.
        truncated: bool,
    },
    /// Whether an [`Empty`](PathFacet::Empty) read found the directory empty.
    Empty(bool),
    /// The read found nothing at its privilege: the path is absent, can't be reached,
    /// or isn't what the facet reads (a [`LinkTarget`](PathFacet::LinkTarget) of a
    /// non-link). This is the probe's documented failure exit (`stat`, `readlink`, and
    /// the content reads all exit 1); any other failure is a [`QueryError`], never this.
    Failed,
    /// A content read ([`Digest`](PathFacet::Digest), [`Read`](PathFacet::Read)) found
    /// something at the path that is not a regular file of its own — a symbolic link
    /// (whatever it names), a directory, a device, a fifo — and opened nothing. What it
    /// means is each kind's to say: drift where the write would replace it, a hold where
    /// it wouldn't.
    NotRegular,
}

/// A path's type and ownership metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathMetadata {
    /// The file type.
    pub kind: FileKind,
    /// The permission bits in octal, without leading zeros (`stat -c %a`).
    pub mode: String,
    /// The owning user's name, or `UNKNOWN` for an id with none (`stat -c %U`).
    pub owner: String,
    /// The owning group's name, or `UNKNOWN` for an id with none (`stat -c %G`).
    pub group: String,
}

/// A path's file type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileKind {
    /// A regular file.
    Regular,
    /// A directory.
    Directory,
    /// A symbolic link.
    Symlink,
    /// Anything else (a device, fifo, or socket).
    Other,
}

impl FileKind {
    /// The type encoded in a raw `st_mode` (`stat -c %f`, or `MetadataExt::mode`).
    #[must_use]
    pub const fn from_mode(mode: u32) -> Self {
        match mode & 0o170_000 {
            0o100_000 => Self::Regular,
            0o040_000 => Self::Directory,
            0o120_000 => Self::Symlink,
            _ => Self::Other,
        }
    }
}

/// What a [`Query::Command`] produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandObservation {
    /// The snippet's exit status.
    pub code: i32,
    /// Its standard output, byte-exact.
    pub stdout: Vec<u8>,
    /// Its standard error, truncated to [`batch::STDERR_LIMIT`] bytes.
    pub stderr: Vec<u8>,
}

impl CommandObservation {
    /// Whether the snippet exited 0 — the exit-code contract every zap-owned command probe
    /// answers by (the state holds iff it exits 0).
    #[must_use]
    pub const fn succeeded(&self) -> bool {
        self.code == 0
    }
}

/// Why a query has no answer.
///
/// The messages name no probe output, so an `Undetermined` reason built from one can't
/// carry a secret.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum QueryError {
    /// The probe exited with its timeout's status (see [`batch`]).
    #[error("timed out after {secs}s")]
    TimedOut {
        /// The timeout it exceeded.
        secs: NonZeroU32,
    },
    /// The probe failed some other way than its documented "found nothing" exit — it
    /// couldn't run, was killed, or hit an error the verdict can't read as absence.
    #[error("the probe exited {code}")]
    Exited {
        /// Its exit status.
        code: i32,
    },
    /// A content read found a regular file with more than one hard link and read none
    /// of it ([`HARD_LINK_REFUSAL`](crate::put::HARD_LINK_REFUSAL)).
    #[error("{}", crate::put::HARD_LINK_REFUSAL)]
    HardLinked,
    /// The probe succeeded but its output doesn't have the shape its facet reads.
    #[error("the probe's output didn't parse")]
    Unparseable,
    /// The batch output had no usable record for this query.
    #[error("{0}")]
    Record(#[from] batch::RecordError),
    /// The lane's whole batch failed, so none of its queries were answered.
    #[error("the {lane} batch failed: {reason}")]
    Batch {
        /// The lane that failed.
        lane: Lane,
        /// What went wrong — a fixed phrase, never the batch's output.
        reason: String,
    },
    /// A test double had no answer recorded for the query.
    #[error("no observation recorded for the query")]
    Unrecorded,
}

/// One query's answer, or why there is none.
pub type QueryResult = Result<Observation, QueryError>;

/// What one lane batch was — its lane and how many queries it answered — kept in the
/// last-run report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BatchRecord {
    /// The lane the batch ran in.
    pub lane: Lane,
    /// How many queries it answered.
    pub queries: usize,
}

/// A path's answer from `results[index]`, or the resource's `Undetermined` verdict.
///
/// The verdict covers an answer that is missing, is an error, or isn't a path
/// observation. The shared first step of every path-reading `interpret`.
///
/// # Errors
/// The `Undetermined` [`Detection`] to return in place of a verdict.
pub fn path_answer(results: &[QueryResult], index: usize) -> Result<&PathObservation, Detection> {
    match results.get(index) {
        Some(Ok(Observation::Path(observation))) => Ok(observation),
        Some(Err(error)) => Err(undetermined(error)),
        Some(Ok(Observation::Command(_))) | None => Err(unexpected_answer(index)),
    }
}

/// A command's answer from `results[index]`, or the resource's `Undetermined` verdict —
/// [`path_answer`]'s counterpart for a [`Query::Command`].
///
/// # Errors
/// The `Undetermined` [`Detection`] to return in place of a verdict.
pub fn command_answer(
    results: &[QueryResult],
    index: usize,
) -> Result<&CommandObservation, Detection> {
    match results.get(index) {
        Some(Ok(Observation::Command(observation))) => Ok(observation),
        Some(Err(error)) => Err(undetermined(error)),
        Some(Ok(Observation::Path(_))) | None => Err(unexpected_answer(index)),
    }
}

/// Whether the [`Kind`](PathFacet::Kind) read at `results[index]` found the path — the
/// `test -e` answer: anything there (following symlinks) exists, and the read's
/// "found nothing" exit is absence.
///
/// # Errors
/// The `Undetermined` [`Detection`] for an answer that is missing, an error, or not a
/// kind.
pub fn exists_answer(results: &[QueryResult], index: usize) -> Result<bool, Detection> {
    match path_answer(results, index)? {
        PathObservation::Kind(_) => Ok(true),
        PathObservation::Failed => Ok(false),
        PathObservation::Metadata(_)
        | PathObservation::LinkTarget(_)
        | PathObservation::Digest(_)
        | PathObservation::Contents { .. }
        | PathObservation::Empty(_)
        | PathObservation::NotRegular => Err(unexpected_answer(index)),
    }
}

/// A content read's answer from `results[index]`.
///
/// A read that found nothing at its privilege, or whose probe failed, holds with
/// `unreadable()` as the reason: the path was already found to exist, so a failed read is
/// not absence.
///
/// # Errors
/// The `Undetermined` [`Detection`] to return in place of a verdict.
pub fn readable_answer(
    results: &[QueryResult],
    index: usize,
    unreadable: impl FnOnce() -> String,
) -> Result<&PathObservation, Detection> {
    match results.get(index) {
        Some(Ok(Observation::Path(PathObservation::Failed)) | Err(QueryError::Exited { .. })) => {
            Err(Detection::Undetermined {
                reason: unreadable(),
            })
        }
        _ => path_answer(results, index),
    }
}

/// A bounded [`Read`](PathFacet::Read)'s bytes and whether the file held more — a
/// [`readable_answer`] that must be [`Contents`](PathObservation::Contents).
///
/// # Errors
/// The `Undetermined` [`Detection`] to return in place of a verdict.
pub fn contents_answer(
    results: &[QueryResult],
    index: usize,
    unreadable: impl FnOnce() -> String,
) -> Result<(&[u8], bool), Detection> {
    match readable_answer(results, index, unreadable)? {
        PathObservation::Contents { bytes, truncated } => Ok((bytes, *truncated)),
        _ => Err(unexpected_answer(index)),
    }
}

/// The metadata an [`Lstat`](PathFacet::Lstat) read at `results[index]` found. A read
/// that found nothing holds: a managed mode nobody read is not "converged".
///
/// # Errors
/// The `Undetermined` [`Detection`] to return in place of a verdict.
pub fn metadata_answer<'a>(
    results: &'a [QueryResult],
    index: usize,
    path: &str,
) -> Result<&'a PathMetadata, Detection> {
    match path_answer(results, index)? {
        PathObservation::Metadata(metadata) => Ok(metadata),
        PathObservation::Failed => Err(Detection::Undetermined {
            reason: format!("failed to read the mode/owner/group of {path}"),
        }),
        PathObservation::Kind(_)
        | PathObservation::LinkTarget(_)
        | PathObservation::Digest(_)
        | PathObservation::Contents { .. }
        | PathObservation::Empty(_)
        | PathObservation::NotRegular => Err(unexpected_answer(index)),
    }
}

/// Whether the command at `results[index]` exited 0 — the answer every exit-code probe
/// gives.
///
/// # Errors
/// The `Undetermined` [`Detection`] to return in place of a verdict.
pub fn succeeded_answer(results: &[QueryResult], index: usize) -> Result<bool, Detection> {
    command_answer(results, index).map(CommandObservation::succeeded)
}

/// The reason a tracked `what` (a remote file, a build source) with no usable pin holds.
///
/// Either none was ever minted, or the read-only commands withheld one that no longer
/// answers for the config. `zap update` mints *and* advances, so it's the fix in both.
#[must_use]
pub fn unpinned_reason(what: &str, id: &impl std::fmt::Display) -> String {
    format!(
        "{what} has no usable pin — run `zap update {id}` to mint or advance it (or declare \
         a `blake3` to vendor it)"
    )
}

/// The `Undetermined` verdict for an unanswered query.
#[must_use]
pub fn undetermined(error: &QueryError) -> Detection {
    Detection::Undetermined {
        reason: format!("detection failed: {error}"),
    }
}

/// The `Undetermined` verdict for an answer whose shape doesn't match its query — a
/// runner bug, held rather than guessed.
#[must_use]
pub fn unexpected_answer(index: usize) -> Detection {
    Detection::Undetermined {
        reason: format!("detection failed: an unexpected answer to query {index}"),
    }
}

/// The `Undetermined` verdict for an `interpret` handed answers laid out for another
/// desired state than the one it reads them against — a caller bug, held rather than
/// guessed.
#[must_use]
pub fn layout_mismatch() -> Detection {
    Detection::Undetermined {
        reason: "detection failed: the answers don't match the resource's reads".to_owned(),
    }
}

/// `Drifted` when `current` carries real divergence, else `Converged`.
///
/// The verdict gateway for the kinds whose drift is open-ended (`user`, `database`,
/// `firewall`): [`CurrentState::has_drift`] decides, so an empty `Drifted` can't be
/// built.
#[must_use]
pub fn drifted_or_converged(current: CurrentState) -> Detection {
    if current.has_drift() {
        Detection::Drifted { current }
    } else {
        Detection::Converged
    }
}

/// Whether an observed `(mode, owner, group)` diverges from the declared-desired
/// values, each compared only when managed (`Some`).
///
/// Mode comparison normalizes octal (`normalize_mode`); owner/group compare exactly
/// against the observed names. A *numeric* uid/gid would mismatch the observed name
/// forever, so it is rejected at config-eval by the `AccountName` newtype — names are
/// the only representable form, which makes the exact comparison sound.
#[must_use]
pub fn metadata_mismatch(
    want_mode: Option<&str>,
    want_owner: Option<&str>,
    want_group: Option<&str>,
    observed: &PathMetadata,
) -> bool {
    let mode_mismatch =
        want_mode.is_some_and(|want| normalize_mode(&observed.mode) != normalize_mode(want));
    let owner_mismatch = want_owner.is_some_and(|want| observed.owner != want);
    let group_mismatch = want_group.is_some_and(|want| observed.group != want);
    mode_mismatch || owner_mismatch || group_mismatch
}

/// Lowercase hex → bytes; `None` for anything else (odd length, other characters).
fn decode_hex(hex: &str) -> Option<Vec<u8>> {
    let digit = |byte: u8| match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    };
    let bytes = hex.as_bytes();
    if !bytes.len().is_multiple_of(2) {
        return None;
    }
    bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|&[high, low]| Some(digit(high)? << 4 | digit(low)?))
        .collect()
}

/// Answers the per-kind tests build.
#[cfg(test)]
pub(crate) mod testing {
    use super::{CommandObservation, FileKind, Observation, PathObservation, QueryResult};

    /// A command's answer: its exit status and stdout, with nothing on stderr.
    #[expect(
        clippy::unnecessary_wraps,
        reason = "builds the answer type `interpret` reads, which is always a `Result`"
    )]
    pub fn exited(code: i32, stdout: &str) -> QueryResult {
        Ok(Observation::Command(CommandObservation {
            code,
            stdout: stdout.as_bytes().to_vec(),
            stderr: Vec::new(),
        }))
    }

    /// A path's answer: a regular file when `yes`, else the probe failed.
    #[expect(
        clippy::unnecessary_wraps,
        reason = "builds the answer type `interpret` reads, which is always a `Result`"
    )]
    pub fn exists(yes: bool) -> QueryResult {
        Ok(Observation::Path(if yes {
            PathObservation::Kind(FileKind::Regular)
        } else {
            PathObservation::Failed
        }))
    }

    /// A path's answer: the contents read, cut short when `truncated`.
    #[expect(
        clippy::unnecessary_wraps,
        reason = "builds the answer type `interpret` reads, which is always a `Result`"
    )]
    pub fn contents(bytes: &str, truncated: bool) -> QueryResult {
        Ok(Observation::Path(PathObservation::Contents {
            bytes: bytes.as_bytes().to_vec(),
            truncated,
        }))
    }

    /// A path's answer: the probe failed.
    #[expect(
        clippy::unnecessary_wraps,
        reason = "builds the answer type `interpret` reads, which is always a `Result`"
    )]
    pub const fn failed() -> QueryResult {
        Ok(Observation::Path(PathObservation::Failed))
    }
}

#[cfg(test)]
mod tests {
    use super::{
        COMMAND_TIMEOUT, FileKind, Lane, PATH_DIGEST_TIMEOUT, PATH_NAMES_TIMEOUT, PATH_TIMEOUT,
        PathFacet, Privilege, Query,
    };

    #[test]
    fn file_kind_reads_the_type_bits() {
        assert_eq!(FileKind::from_mode(0o040_755), FileKind::Directory);
        assert_eq!(FileKind::from_mode(0o100_644), FileKind::Regular);
        assert_eq!(FileKind::from_mode(0o120_777), FileKind::Symlink);
        assert_eq!(FileKind::from_mode(0o020_620), FileKind::Other);
    }

    #[test]
    fn path_reads_time_out_after_ten_seconds_names_thirty_digests_and_commands_sixty() {
        assert_eq!(PATH_TIMEOUT.get(), 10);
        assert_eq!(PATH_NAMES_TIMEOUT.get(), 30);
        assert_eq!(PATH_DIGEST_TIMEOUT.get(), 60);
        assert_eq!(COMMAND_TIMEOUT.get(), 60);
        assert_eq!(PathFacet::Kind.timeout_secs(), PATH_TIMEOUT);
        assert_eq!(PathFacet::LinkTarget.timeout_secs(), PATH_TIMEOUT);
        assert_eq!(PathFacet::Read { max: 64 }.timeout_secs(), PATH_TIMEOUT);
        assert_eq!(PathFacet::Lstat.timeout_secs(), PATH_NAMES_TIMEOUT);
        assert_eq!(PathFacet::Digest.timeout_secs(), PATH_DIGEST_TIMEOUT);
    }

    #[test]
    fn privileges_map_to_lanes_per_connection() {
        use Privilege::{Elevated, Login, Root};
        let lanes = |p: Privilege| (p.remote_lane(), p.local_lane());
        assert_eq!(lanes(Login), (Lane::Login, Lane::Login));
        assert_eq!(lanes(Root), (Lane::Root, Lane::Root));
        // Elevated is root over SSH, the operator locally.
        assert_eq!(lanes(Elevated), (Lane::Root, Lane::Login));
    }

    #[test]
    fn a_query_round_trips_through_its_wire_shape() {
        let query = Query::Path {
            path: "/opt/x".to_owned(),
            facet: PathFacet::Lstat,
            privilege: Privilege::Elevated,
        };
        let json = serde_json::to_value(&query).unwrap();
        assert_eq!(
            json,
            serde_json::json!({"type": "path", "path": "/opt/x", "facet": "lstat", "privilege": "elevated"})
        );
        assert_eq!(serde_json::from_value::<Query>(json).unwrap(), query);

        let read = Query::Path {
            path: "/s".to_owned(),
            facet: PathFacet::Read { max: 4096 },
            privilege: Privilege::Elevated,
        };
        let json = serde_json::to_value(&read).unwrap();
        assert_eq!(
            json,
            serde_json::json!({"type": "path", "path": "/s", "facet": {"read": {"max": 4096}}, "privilege": "elevated"})
        );
        assert_eq!(serde_json::from_value::<Query>(json).unwrap(), read);
    }
}
