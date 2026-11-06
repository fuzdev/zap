//! A spawned batch process: which process a batch runs as ([`BatchProcess`]) — which
//! decides what its exit statuses mean and how it is stopped at its deadline — and
//! [`finish_batch`], which feeds it its script and collects its stdout, within its
//! deadline and [`batch::STDOUT_LIMIT`].

use std::sync::{Arc, OnceLock};
use std::time::Duration;

use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use zap_types::observe::Lane;
use zap_types::observe::batch::{self, TOOL_MISSING_EXIT};

use super::BatchFailure;
use super::master_gate::{MasterState, mark};
use super::ssh::{SSH_FAILED_EXIT, SSH_FAILED_REASON};
use super::stop::stop;
use crate::connection::SshConnection;

/// The most of a batch's stderr kept — only ever read when `ssh` itself failed, where it
/// is `ssh`'s own diagnostics (the batch's probes write their stderr into the records).
const STDERR_KEPT: u64 = 64 * 1024;

/// How long zap waits for `ssh`'s stderr to close once it has exited 255.
const STDERR_WAIT: Duration = Duration::from_secs(1);

/// The longest first line that could still be a process-group record (`pgid ` and a
/// `u32`); past it the reader stops looking.
const PGID_LINE_MAX: usize = 32;

/// Which process a batch runs as — which decides what its exit statuses mean and how
/// it is stopped at its deadline.
#[derive(Debug, Clone, Copy)]
pub(super) enum BatchProcess<'a> {
    /// The local `ssh` client, running `lane`'s batch on `conn`'s target. To stop it, zap
    /// kills the batch's process group and session on the target (the id the batch
    /// reported first, [`batch::kill_snippet`]) over a connection of its own, then kills
    /// the client, which closes the channel.
    Ssh {
        /// The target the batch runs on.
        conn: &'a SshConnection,
        /// The lane it runs in — the privilege the target-side kill needs.
        lane: Lane,
    },
    /// A local `sh`, leader of its own process group. At the deadline the whole group is
    /// killed.
    LocalLogin,
    /// A local `sudo sh`, left in zap's process group so `sudo` can prompt on the
    /// terminal. At the deadline `sudo` gets `SIGTERM`, which it relays to the shell it
    /// started (running as root, beyond this user's signals), then `SIGKILL` after
    /// [`ROOT_TERM_GRACE`].
    LocalRoot,
}

/// How long a local root batch gets to exit after `SIGTERM` before `sudo` is killed.
pub(super) const ROOT_TERM_GRACE: Duration = Duration::from_secs(2);

/// The fixed reason a batch process failed, from its exit status — never its output,
/// which could carry a secret.
pub(super) fn exit_reason(code: Option<i32>, process: BatchProcess<'_>) -> String {
    match code {
        Some(TOOL_MISSING_EXIT) => {
            "the target is missing a tool or the `/proc/self/fd` the batch needs".to_owned()
        }
        Some(SSH_FAILED_EXIT) if matches!(process, BatchProcess::Ssh { .. }) => {
            SSH_FAILED_REASON.to_owned()
        }
        Some(code) => format!("it exited {code}"),
        None => "it was killed by a signal".to_owned(),
    }
}

/// How reading a batch's stdout ended.
pub(super) enum Stdout {
    /// Read to its end.
    Done(Vec<u8>),
    /// It passed [`batch::STDOUT_LIMIT`]; reading stopped there. Carries the pipe, still
    /// open, so the batch isn't killed by a closed stdout (orphaning what it started)
    /// before [`stop`] reaches it.
    OverLimit(tokio::process::ChildStdout),
}

/// How a batch ended short of its deadline.
enum Finished {
    /// Its output passed the limit while it ran; the pipe is still open.
    OverLimit(tokio::process::ChildStdout),
    /// It exited, and its output was read to the end (or the read failed).
    Exited {
        /// Its output, or why it couldn't be read.
        stdout: Result<Vec<u8>, BatchFailure>,
        /// Its exit status, or why it couldn't be read.
        status: std::io::Result<std::process::ExitStatus>,
    },
}

/// Read a batch's stdout to its end or to [`batch::STDOUT_LIMIT`], recording the process
/// group its first line reports in `pgid` as soon as that line arrives — so a batch
/// stopped mid-run can still be killed by it — and, for a cold pass's leading `ssh`,
/// marking its [`MasterGate`](super::master_gate::MasterGate) up at the first byte.
pub(super) async fn read_stdout(
    mut stdout: tokio::process::ChildStdout,
    pgid: Arc<OnceLock<u32>>,
    leader: Option<Arc<tokio::sync::watch::Sender<MasterState>>>,
) -> std::io::Result<Stdout> {
    let mut bytes = Vec::new();
    let mut chunk = vec![0u8; 64 * 1024];
    // Whether the first line is still to be looked for — only in the new bytes, and only
    // while it could still be a record, so a newline-free flood isn't rescanned.
    let mut first_line_pending = true;
    loop {
        let n = stdout.read(&mut chunk).await?;
        if n == 0 {
            return Ok(Stdout::Done(bytes));
        }
        if bytes.len() + n > batch::STDOUT_LIMIT {
            return Ok(Stdout::OverLimit(stdout));
        }
        if let Some(gate) = &leader {
            mark(gate, MasterState::Up);
        }
        let start = bytes.len();
        bytes.extend_from_slice(&chunk[..n]);
        if first_line_pending {
            if let Some(end) = bytes[start..].iter().position(|&byte| byte == b'\n') {
                first_line_pending = false;
                if let Some(id) = batch::parse_pgid(&bytes[..start + end]) {
                    let _ = pgid.set(id);
                }
            } else if bytes.len() > PGID_LINE_MAX {
                first_line_pending = false;
            }
        }
    }
}

/// Feed `script` to a spawned batch process (stdin, stdout, and stderr piped) and collect
/// its stdout, within `deadline` and [`batch::STDOUT_LIMIT`].
///
/// The output is read to its end *before* the child is reaped, so while zap waits the
/// child is at worst an unreaped zombie: its process ID — and so a local login batch's
/// process-group ID — can't be reused. At the deadline, or once the output passes its
/// limit, the batch is stopped per [`BatchProcess`] while the child is still held, then
/// reaped; zap stops waiting on any descendant still holding the pipes.
pub(super) async fn finish_batch(
    mut child: tokio::process::Child,
    script: &str,
    deadline: Duration,
    process: BatchProcess<'_>,
    leader: Option<Arc<tokio::sync::watch::Sender<MasterState>>>,
) -> Result<Vec<u8>, BatchFailure> {
    let (Some(mut stdin), Some(stdout), Some(mut stderr)) =
        (child.stdin.take(), child.stdout.take(), child.stderr.take())
    else {
        return Err(BatchFailure::Lane(
            "it could not run: its pipes were not set up".to_owned(),
        ));
    };
    // Concurrent writer and readers: a batch that writes while it reads can't deadlock
    // on a full pipe. Dropping `stdin` after the write closes it, so the batch reads EOF.
    let payload = script.as_bytes().to_vec();
    let writer = tokio::spawn(async move {
        let _ = stdin.write_all(&payload).await;
    });
    let pgid = Arc::new(OnceLock::new());
    let mut out_reader = tokio::spawn(read_stdout(stdout, Arc::clone(&pgid), leader));
    // Drained, and never evidence: the head is kept only for a failed `ssh`, whose own
    // diagnostics it is.
    let mut err_reader = tokio::spawn(async move {
        let mut kept = Vec::new();
        let _ = (&mut stderr).take(STDERR_KEPT).read_to_end(&mut kept).await;
        let _ = tokio::io::copy(&mut stderr, &mut tokio::io::sink()).await;
        kept
    });

    let could_not_run =
        |error: &dyn std::fmt::Display| BatchFailure::Lane(format!("it could not run: {error}"));
    let expiry = tokio::time::sleep(deadline);
    tokio::pin!(expiry);
    let finished = tokio::select! {
        biased;
        finished = async {
            // A reader task that failed to join and a read that failed are the same
            // outcome.
            let stdout = match (&mut out_reader).await {
                // Past the limit, stop now: the batch is still running, and nothing more
                // of its output will be read.
                Ok(Ok(Stdout::OverLimit(held))) => return Finished::OverLimit(held),
                Ok(Ok(Stdout::Done(stdout))) => Ok(stdout),
                Ok(Err(error)) => Err(could_not_run(&error)),
                Err(error) => Err(could_not_run(&error)),
            };
            Finished::Exited {
                stdout,
                status: child.wait().await,
            }
        } => Some(finished),
        () = &mut expiry => None,
    };
    let result = match finished {
        None => {
            stop(&mut child, process, pgid.get().copied()).await;
            out_reader.abort();
            Err(BatchFailure::Lane(format!(
                "it ran past its {}s deadline",
                deadline.as_secs()
            )))
        }
        // `_held` keeps the pipe open until the batch is stopped.
        Some(Finished::OverLimit(_held)) => {
            stop(&mut child, process, pgid.get().copied()).await;
            Err(BatchFailure::Lane(batch::STDOUT_LIMIT_REASON.to_owned()))
        }
        Some(Finished::Exited {
            status: Err(error), ..
        }) => Err(could_not_run(&error)),
        Some(Finished::Exited {
            stdout: Err(failure),
            ..
        }) => Err(failure),
        Some(Finished::Exited {
            stdout: Ok(stdout),
            status: Ok(status),
        }) if status.success() => Ok(stdout),
        Some(Finished::Exited {
            status: Ok(status), ..
        }) => {
            if matches!(process, BatchProcess::Ssh { .. }) && status.code() == Some(SSH_FAILED_EXIT)
            {
                let kept = tokio::time::timeout(STDERR_WAIT, &mut err_reader)
                    .await
                    .ok()
                    .and_then(Result::ok)
                    .unwrap_or_default();
                Err(BatchFailure::Unreachable(
                    String::from_utf8_lossy(&kept).into_owned(),
                ))
            } else {
                Err(BatchFailure::Lane(exit_reason(status.code(), process)))
            }
        }
    };
    writer.abort();
    err_reader.abort();
    result
}
