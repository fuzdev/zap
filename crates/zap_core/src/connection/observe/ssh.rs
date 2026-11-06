//! The Ssh runner: each lane's queries rendered as one batch script
//! ([`zap_types::observe::batch`]) and run as one `ssh` command on its own multiplexed
//! channel (`Login` → the login lane, `Root` and `Elevated` → the root lane). The script
//! travels on the channel's **stdin** to a constant wrapper — `BATCH_SHELL` in a session
//! of its own (`setsid`), under `sudo` for the root lane — so ssh's argv carries no probe
//! text, and stdout comes back as raw bytes. A batch `ssh` can't run at all (it can't
//! start, or exits 255) fails the whole pass as
//! [`Error::Connectivity`](crate::error::Error::Connectivity): the batches are the
//! pass's connectivity check.

use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::AsyncWriteExt as _;
use zap_types::observe::Lane;
use zap_types::observe::batch::{self, BATCH_SHELL, TOOL_MISSING_EXIT};

use super::BatchFailure;
use super::master_gate::{GateRole, MasterState, settle, take_turn};
use super::process::{BatchProcess, finish_batch};
use crate::connection::SshConnection;
use crate::connection::delivery::{Delivery, ssh_remote_arg};

/// The exit status `ssh` reports for its own failure (connection, authentication).
pub(super) const SSH_FAILED_EXIT: i32 = 255;

/// The fixed reason a lane fails when its `ssh` couldn't reach the target.
pub(super) const SSH_FAILED_REASON: &str = "the ssh connection failed";

/// How long zap waits for the target-side kill of a batch it is stopping.
const REMOTE_KILL_TIMEOUT: Duration = Duration::from_secs(10);

/// The remote command one lane's batch runs as: `BATCH_SHELL` in a session — and so a
/// process group — of its own, under `sudo` for the root lane.
///
/// `setsid` is run as a *child* of the wrapping shell (the trailing `exit $?` keeps the
/// shell from `exec`ing it), so it never leads a process group. That matters: `sshd` makes
/// the session command a group leader, and a `setsid` that leads one forks, and — with no
/// `-w`, which `BusyBox` lacks — exits 0 at once, losing the batch's exit status. Run as a
/// non-leader, `setsid` `exec`s the batch shell in place, whose pid is then the id of its
/// group and session, the id it reports first. A target without `setsid` exits
/// [`TOOL_MISSING_EXIT`], like one missing a tool the batch itself needs.
///
/// `BATCH_SHELL` rides as the wrapper's positional parameter (`"$1"`) rather than quoted
/// inside it, so single quotes nest only once below the `sh -c` the remote login shell
/// parses: no single-quoted segment of what that shell reads holds a backslash, which a
/// login shell that treats `\'` inside single quotes as an escape (`fish`) would misread.
pub(super) fn remote_batch_command(lane: Lane) -> String {
    let session = format!(
        "command -v setsid >/dev/null 2>&1 || exit {TOOL_MISSING_EXIT}; setsid sh -c \"$1\"; exit $?"
    );
    let wrapper = format!(
        "sh -c {} sh {}",
        zap_types::shell::single_quote(&session),
        zap_types::shell::single_quote(BATCH_SHELL)
    );
    match lane {
        Lane::Root => format!("sudo {wrapper}"),
        Lane::Login => wrapper,
    }
}

/// The remote command that kills the batch that reported `pgid` in `lane`.
///
/// The root lane's kill runs under `sudo`, like its batch. The login lane's runs under
/// `sudo -n` too — its operator commands may have started processes as root, which only
/// root can signal — and, where `sudo` won't run without a password, falls back to the
/// login user's own kill, which still reaches everything the batch started as itself.
/// Over SSH, zap needs `sudo` on the target anyway (the root lane runs under it), so the
/// login lane's kill asks for no privilege the connection doesn't already hold.
pub(super) fn remote_kill_command(lane: Lane, pgid: u32) -> String {
    let kill = zap_types::shell::single_quote(&batch::kill_snippet(pgid));
    match lane {
        Lane::Root => format!("sudo sh -c {kill}"),
        Lane::Login => format!("sudo -n sh -c {kill} 2>/dev/null || sh -c {kill}"),
    }
}

impl SshConnection {
    /// Run one lane's batch script over `ssh`: the constant [`remote_batch_command`] as
    /// the remote command, the script on its stdin, the stdout captured as raw bytes,
    /// within `deadline`. A nonzero exit, the deadline passing, or the output passing its
    /// limit is the whole batch's failure, reported without any of its output; an `ssh`
    /// that can't start, or exits 255, is [`BatchFailure::Unreachable`].
    ///
    /// To stop the batch, zap kills its process group and session on the target — the id
    /// the batch reported first — before it kills the local `ssh` client, which closes the
    /// channel (`sshd` signals nothing to a session without a terminal, so closing it
    /// alone would leave the probe in flight running). A batch stopped before it reported
    /// its group only has its client killed.
    pub(super) async fn run_batch(
        &self,
        lane: Lane,
        script: String,
        deadline: Duration,
        gate: Option<GateRole>,
    ) -> Result<Vec<u8>, BatchFailure> {
        let leader = take_turn(gate).await?;
        let result = self
            .spawn_batch(lane, &script, deadline, leader.clone())
            .await;
        if let Some(gate) = leader {
            settle(&gate, &result);
        }
        result
    }

    /// Spawn one lane's batch `ssh` and finish it ([`finish_batch`]).
    async fn spawn_batch(
        &self,
        lane: Lane,
        script: &str,
        deadline: Duration,
        leader: Option<Arc<tokio::sync::watch::Sender<MasterState>>>,
    ) -> Result<Vec<u8>, BatchFailure> {
        let mut args = self.ssh_args();
        args.push(ssh_remote_arg(&remote_batch_command(lane)));
        let child = super::super::ssh::client_command()
            .args(&args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .map_err(|error| {
                BatchFailure::Unreachable(format!("failed to execute ssh: {error}"))
            })?;
        let process = BatchProcess::Ssh { conn: self, lane };
        finish_batch(child, script, deadline, process, leader).await
    }

    /// Kill the batch that reported `pgid` in `lane` — [`batch::kill_snippet`] — over a
    /// connection of its own, within [`REMOTE_KILL_TIMEOUT`]. The kill travels on that
    /// connection's stdin like any command, so the client's argv is constant.
    /// Best-effort: nothing it prints is read, and a kill that can't run leaves only the
    /// client to kill.
    ///
    /// It runs as root for either lane ([`remote_kill_command`]): an operator command in
    /// the login lane may have started a process as root (`sudo …`), which a kill as the
    /// login user can't reach.
    pub(super) async fn kill_batch(&self, lane: Lane, pgid: u32) {
        let Ok(delivery) = Delivery::of(&remote_kill_command(lane, pgid), None) else {
            return;
        };
        let Ok(mut child) = self
            .delivery_command(&delivery)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()
        else {
            return;
        };
        let killed = async {
            if let Some(mut stdin) = child.stdin.take() {
                let _ = stdin.write_all(&delivery.stdin).await;
            }
            child.wait().await
        };
        if tokio::time::timeout(REMOTE_KILL_TIMEOUT, killed)
            .await
            .is_err()
        {
            let _ = child.kill().await;
        }
    }
}
