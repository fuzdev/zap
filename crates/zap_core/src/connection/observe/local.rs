//! The Local runner: `Login` and `Elevated` path queries answered natively (`std::fs`)
//! as the operator, and everything else — `Root` path queries and all command queries —
//! run as a local batch per lane (`sudo sh` for the root lane). An `Elevated` read the
//! operator can't make for any reason but "not found" is asked again in the root lane's
//! batch: native first, `sudo` only when denied. A content read of something that isn't
//! a regular file or a directory (a fifo, a device) goes to the login batch, where its
//! probe's timeout bounds it.

use std::os::unix::ffi::OsStringExt as _;
use std::os::unix::fs::MetadataExt as _;
use std::process::Stdio;
use std::time::Duration;

use nix::unistd::{Gid, Group, Uid, User};
use tokio::process::Command;
use zap_types::observe::batch::{self, BATCH_SHELL};
use zap_types::observe::{
    FileKind, Lane, Observation, PathFacet, PathMetadata, PathObservation, Privilege, Query,
    QueryError, QueryResult,
};

use super::process::{BatchProcess, finish_batch};
use super::{Answers, BatchFailure, in_order, run_lanes};
use crate::digest::Sha512;

/// The Local runner: `Login` / `Elevated` path queries natively, the rest as local
/// batches — plus, as a second round, the `Elevated` reads the operator couldn't make,
/// in the root lane.
///
/// An operator command runs without a terminal here, as over SSH — in a session of its
/// own, with stdin at `/dev/null` — so a `sudo` in it that needs a password fails at
/// once (it can't prompt), and the check reads as failed.
pub(super) async fn observe_local(queries: &[Query]) -> Answers {
    let (mut answered, batched) = route_local(queries).await;
    // A local batch never fails as unreachable: that is `ssh`'s failure alone.
    let (batch_answers, batches, _) = run_lanes(&batched, run_local_batch).await;
    answered.extend(batch_answers);
    Answers {
        results: in_order(queries.len(), answered),
        batches,
    }
}

/// The queries the Local runner answered natively, and the rest with the lane each
/// batches into.
pub(super) async fn route_local(
    queries: &[Query],
) -> (Vec<(usize, QueryResult)>, Vec<(usize, &Query, Lane)>) {
    let mut answered = Vec::with_capacity(queries.len());
    let mut batched = Vec::new();
    for (index, query) in queries.iter().enumerate() {
        match query {
            Query::Path {
                path,
                facet,
                privilege,
            } if privilege.local_lane() == Lane::Login => {
                match observe_path(path, *facet, *privilege).await {
                    Native::Answer(result) => answered.push((index, result)),
                    Native::Escalate => batched.push((index, query, Lane::Root)),
                }
            }
            Query::Path { .. } | Query::Command { .. } => {
                batched.push((index, query, query.privilege().local_lane()));
            }
        }
    }
    (answered, batched)
}

/// How the Local runner answers one path query it can read natively.
#[derive(Debug)]
pub(super) enum Native {
    /// Read natively.
    Answer(QueryResult),
    /// An `Elevated` read the operator couldn't make: ask again as root.
    Escalate,
}

/// Read one path fact natively, as the operator — with the shell probe's semantics. A
/// `Login` read's error (absent, denied, not a symlink) is the probe's failure exit,
/// [`PathObservation::Failed`]; an `Elevated` read's is too when the path isn't there,
/// and any other error asks for the read as root. Metadata whose names the probe's
/// output couldn't carry is [`QueryError::Unparseable`].
pub(super) async fn observe_path(path: &str, facet: PathFacet, privilege: Privilege) -> Native {
    let read = match facet {
        PathFacet::Kind => tokio::fs::metadata(path)
            .await
            .map(|m| Ok(PathObservation::Kind(FileKind::from_mode(m.mode())))),
        PathFacet::Lstat => tokio::fs::symlink_metadata(path)
            .await
            .map(|m| native_metadata(&m).map(PathObservation::Metadata)),
        PathFacet::LinkTarget => tokio::fs::read_link(path).await.map(|target| {
            Ok(PathObservation::LinkTarget(
                target.into_os_string().into_vec(),
            ))
        }),
        PathFacet::Empty => read_empty(path).await.map(Ok),
        PathFacet::Digest | PathFacet::Read { .. } => read_content(path, facet).await,
    };
    match read {
        Ok(result) => Native::Answer(result.map(Observation::Path)),
        Err(error) if privilege == Privilege::Elevated && !is_not_found(&error) => Native::Escalate,
        Err(_) => Native::Answer(Ok(Observation::Path(PathObservation::Failed))),
    }
}

/// Whether a native read found nothing at the path — the one failure an `Elevated` read
/// doesn't escalate.
fn is_not_found(error: &std::io::Error) -> bool {
    error.kind() == std::io::ErrorKind::NotFound
}

/// Read an [`Empty`](PathFacet::Empty) natively, as the probe does: what `path` resolves
/// to (following a link, as `ls` does) must be a directory, else the read found nothing;
/// a directory is empty when listing it yields no entry (`read_dir` lists no `.` or
/// `..`, as `ls -A` doesn't).
async fn read_empty(path: &str) -> std::io::Result<PathObservation> {
    if !tokio::fs::metadata(path).await?.is_dir() {
        return Ok(PathObservation::Failed);
    }
    let mut entries = tokio::fs::read_dir(path).await?;
    Ok(PathObservation::Empty(
        entries.next_entry().await?.is_none(),
    ))
}

/// Read a [`Digest`](PathFacet::Digest) or [`Read`](PathFacet::Read) natively, as the
/// probe does: a name that is a symbolic link, or anything but a regular file, is
/// [`PathObservation::NotRegular`] and nothing is opened. A regular file is opened with
/// no link followed and without blocking (`O_NOFOLLOW | O_NONBLOCK`), and read only
/// when what was opened is a regular file — so a name swapped between the look and the
/// open is refused too, which the probe can't do — of one hard link (more is
/// [`QueryError::HardLinked`], as the probe's), then hashed or read, the digest
/// streamed, never the whole file in memory.
async fn read_content(
    path: &str,
    facet: PathFacet,
) -> std::io::Result<Result<PathObservation, QueryError>> {
    use tokio::io::AsyncReadExt as _;

    if !tokio::fs::symlink_metadata(path).await?.is_file() {
        return Ok(Ok(PathObservation::NotRegular));
    }
    let opened = tokio::fs::OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NONBLOCK | nix::libc::O_NOFOLLOW)
        .open(path)
        .await;
    let mut file = match opened {
        Ok(file) => file,
        // `O_NOFOLLOW`'s refusal of a link swapped in since the look
        Err(error) if error.raw_os_error() == Some(nix::libc::ELOOP) => {
            return Ok(Ok(PathObservation::NotRegular));
        }
        Err(error) => return Err(error),
    };
    let opened = file.metadata().await?;
    if FileKind::from_mode(opened.mode()) != FileKind::Regular {
        return Ok(Ok(PathObservation::NotRegular));
    }
    if opened.nlink() != 1 {
        return Ok(Err(QueryError::HardLinked));
    }
    if let PathFacet::Read { max } = facet {
        let mut bytes = Vec::new();
        (&mut file)
            .take(u64::from(max) + 1)
            .read_to_end(&mut bytes)
            .await?;
        return Ok(Ok(batch::contents(bytes, max)));
    }
    let mut sha512 = Sha512::new();
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = file.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        sha512.update(&buf[..n]);
    }
    Ok(Ok(PathObservation::Digest(sha512.finish_hex())))
}

/// [`PathMetadata`] from a native stat — the same fields `stat -c '%f %a %U %G'` prints,
/// with `UNKNOWN` for an id that has no name (as `stat` does). A name containing
/// whitespace is [`QueryError::Unparseable`], as it is from the probe, whose
/// space-separated line it would split.
fn native_metadata(metadata: &std::fs::Metadata) -> Result<PathMetadata, QueryError> {
    let owner = User::from_uid(Uid::from_raw(metadata.uid()))
        .ok()
        .flatten()
        .map_or_else(|| "UNKNOWN".to_owned(), |user| user.name);
    let group = Group::from_gid(Gid::from_raw(metadata.gid()))
        .ok()
        .flatten()
        .map_or_else(|| "UNKNOWN".to_owned(), |group| group.name);
    if [&owner, &group]
        .iter()
        .any(|name| name.is_empty() || name.contains(char::is_whitespace))
    {
        return Err(QueryError::Unparseable);
    }
    Ok(PathMetadata {
        kind: FileKind::from_mode(metadata.mode()),
        mode: format!("{:o}", metadata.mode() & 0o7777),
        owner,
        group,
    })
}

/// Run one lane's batch on the local machine, the script on stdin, within `deadline`.
///
/// - Login lane: `sh`, as the leader of its own process group. The deadline kills that
///   group and every process group a descendant of the batch leads — a command's own
///   session (its reporter starts it under `setsid`), and the group GNU `timeout` moves
///   itself into — listed from `/proc` before the kill.
/// - Root lane: first [`sudo_validate`], with no deadline — it may prompt for a password
///   on the terminal, and a person typing it mustn't spend the batch's deadline — then
///   `sudo -n sh`, which never prompts. Both stay in zap's process group: in a background
///   group `sudo` would stop on its prompt, and Ctrl-C wouldn't reach it. A failed
///   authentication fails the lane ([`SUDO_AUTH_FAILED`]) before any probe runs. The deadline
///   sends `sudo` `SIGTERM`, which it relays to the root shell, then `SIGKILL`.
///
/// What bounds a hung root probe: each probe runs under a `timeout` the root shell
/// started, so it runs as root and can signal the probe. GNU `timeout` signals the
/// probe's whole process group at the probe's limit (a `psql` under `sudo -u postgres`
/// included — `sudo` relays the signal), so on a GNU host the deadline is reached only by
/// a probe that survives `SIGTERM`. `BusyBox` `timeout` signals the probe's shell alone,
/// so a hung descendant there outlives its timeout and holds the record open until the
/// deadline.
///
/// TODO: at the deadline, the `SIGTERM` `sudo` relays reaches the root shell only; the
/// probe still running under it isn't signaled, and this user can't signal it — zap stops
/// waiting and the root process stays. A root-side kill (the SSH runner's
/// `batch::kill_snippet`, run through `sudo -n`) would close it.
pub(super) async fn run_local_batch(
    lane: Lane,
    script: String,
    deadline: Duration,
) -> Result<Vec<u8>, BatchFailure> {
    let (mut command, process) = match lane {
        Lane::Root => {
            sudo_validate().await.map_err(BatchFailure::Lane)?;
            let mut command = Command::new("sudo");
            command.args(["-n", "sh"]);
            (command, BatchProcess::LocalRoot)
        }
        Lane::Login => {
            let mut command = Command::new("sh");
            command.process_group(0);
            (command, BatchProcess::LocalLogin)
        }
    };
    let child = command
        .arg("-c")
        .arg(BATCH_SHELL)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .map_err(|error| BatchFailure::Lane(format!("it could not start: {error}")))?;
    finish_batch(child, &script, deadline, process, None).await
}

/// The fixed reason a Local root lane fails when `sudo` won't authenticate.
const SUDO_AUTH_FAILED: &str = "sudo authentication failed";

/// Make sure the root lane's `sudo -n sh` won't need a password, before its deadline
/// starts: first `sudo -n sh -c true`, silently — it succeeds when the rule is `NOPASSWD`
/// or a credential is cached, and the batch runs with no prompt at all — and only when
/// that fails, `sudo -v` on zap's terminal, with no deadline, so a password prompt is
/// answered off the batch's clock. (`sudo -v` alone isn't the check: under the default
/// `verifypw` it prompts unless *every* sudoers entry for the user is `NOPASSWD`, even
/// when the one that grants `sh` is.) Neither's output ever reaches a reason.
async fn sudo_validate() -> Result<(), String> {
    let ready = Command::new("sudo")
        .args(["-n", "sh", "-c", "true"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .await
        .is_ok_and(|status| status.success());
    if ready {
        return Ok(());
    }
    match Command::new("sudo").arg("-v").status().await {
        Ok(status) if status.success() => Ok(()),
        Ok(_) | Err(_) => Err(SUDO_AUTH_FAILED.to_owned()),
    }
}
