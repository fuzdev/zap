//! The cold-pass gate: a pass authenticates at most once. When the connection's
//! `ControlMaster` socket isn't live, the login lane's `ssh` waits for the root lane's to
//! be under way (its first output, which comes after the master is up) before it starts
//! — two cold clients started together would each authenticate (see [`MasterGate`]).

use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use zap_types::observe::Lane;

use super::BatchFailure;
use super::ssh::SSH_FAILED_REASON;
use crate::connection::SshConnection;

/// Where a cold pass's first `ssh` is, as the second one waits on it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum MasterState {
    /// Not yet under way.
    Pending,
    /// Under way — it printed output, so the control master is up — or finished.
    Up,
    /// It couldn't reach the target.
    Unreachable,
}

/// Orders a cold pass's two lane `ssh` clients so only one authenticates.
///
/// Without a live control master, two `ssh` clients started together would both find no
/// socket, both authenticate, and the loser print "`ControlSocket` … already exists,
/// disabling multiplexing" — two handshakes, so two hardware-key touches or passphrase
/// prompts. So the root lane's client goes first (the *leader*: with `ControlMaster=auto`
/// it becomes the master) and marks the gate [`Up`](MasterState::Up) at its first output
/// byte — the batch can only print once the connection is authenticated and the master
/// listening — or when it ends. The login lane's client (the *follower*) starts only
/// then, and multiplexes. A leader that couldn't reach the target marks the gate
/// [`Unreachable`](MasterState::Unreachable), and the follower doesn't try at all: the
/// pass already fails as unreachable. With a live master both start at once, so a warm
/// pass pays nothing for the gate.
#[derive(Debug)]
pub(super) struct MasterGate {
    state: Arc<tokio::sync::watch::Sender<MasterState>>,
}

/// A lane's part in a cold pass's [`MasterGate`].
#[derive(Debug, Clone)]
pub(super) enum GateRole {
    /// Starts at once, and marks the gate.
    Leader(Arc<tokio::sync::watch::Sender<MasterState>>),
    /// Starts once the gate is marked.
    Follower(tokio::sync::watch::Receiver<MasterState>),
}

impl MasterGate {
    pub(super) fn new() -> Self {
        Self {
            state: Arc::new(tokio::sync::watch::Sender::new(MasterState::Pending)),
        }
    }

    /// The root lane leads; the login lane follows.
    pub(super) fn role(&self, lane: Lane) -> GateRole {
        match lane {
            Lane::Root => GateRole::Leader(Arc::clone(&self.state)),
            Lane::Login => GateRole::Follower(self.state.subscribe()),
        }
    }
}

/// Wait for this lane's turn under a cold pass's gate: a follower waits for the leader to
/// be under way. Returns the leader's handle on the gate, to mark it.
///
/// # Errors
/// A lane failure (the fixed `ssh` reason) for a follower whose leader couldn't reach the
/// target: the pass fails as unreachable from the leader's failure, so this lane doesn't
/// authenticate a second time.
pub(super) async fn take_turn(
    gate: Option<GateRole>,
) -> Result<Option<Arc<tokio::sync::watch::Sender<MasterState>>>, BatchFailure> {
    match gate {
        Some(GateRole::Follower(mut state)) => {
            let marked = state
                .wait_for(|state| *state != MasterState::Pending)
                .await
                .map(|state| *state);
            if matches!(marked, Ok(MasterState::Unreachable)) {
                return Err(BatchFailure::Lane(SSH_FAILED_REASON.to_owned()));
            }
            Ok(None)
        }
        Some(GateRole::Leader(state)) => Ok(Some(state)),
        None => Ok(None),
    }
}

/// How long the check for a live control master may take before the pass treats the
/// master as cold.
const LIVE_CHECK_TIMEOUT: Duration = Duration::from_secs(2);

/// Whether a listener accepts connections on the Unix socket at `path` — a live control
/// master; a stale socket file refuses. The `connect` runs on a detached thread: one to
/// a stopped listener with a full backlog blocks, and a blocked task on the runtime's
/// blocking pool would hold up the runtime's shutdown. A caller that stops waiting (the
/// [`LIVE_CHECK_TIMEOUT`]) leaves at most that one thread, which ends when its `connect`
/// returns or with the process.
pub(super) async fn socket_is_live(path: std::path::PathBuf) -> bool {
    let (sender, receiver) = tokio::sync::oneshot::channel();
    let spawned = std::thread::Builder::new()
        .name("zap-control-socket-check".to_owned())
        .spawn(move || {
            let _ = sender.send(std::os::unix::net::UnixStream::connect(path).is_ok());
        });
    spawned.is_ok() && receiver.await.unwrap_or(false)
}

/// Mark a cold pass's gate once its leading `ssh` is done: unreachable, or else up —
/// whatever else became of the batch (a deadline, a failure), the follower may start.
pub(super) fn settle(
    gate: &tokio::sync::watch::Sender<MasterState>,
    result: &Result<Vec<u8>, BatchFailure>,
) {
    let state = if matches!(result, Err(BatchFailure::Unreachable(_))) {
        MasterState::Unreachable
    } else {
        MasterState::Up
    };
    mark(gate, state);
}

/// Move a gate still [`Pending`](MasterState::Pending) to `state`; a marked gate stays as
/// it is.
pub(super) fn mark(gate: &tokio::sync::watch::Sender<MasterState>, state: MasterState) {
    gate.send_if_modified(|current| {
        let pending = *current == MasterState::Pending;
        if pending {
            *current = state;
        }
        pending
    });
}

impl SshConnection {
    /// Whether this connection's `ControlMaster` socket is live — found with `ssh -G`,
    /// which resolves the `ControlPath` tokens without touching the network, and probed
    /// with a local `connect` ([`socket_is_live`]). Anything that can't be established
    /// within [`LIVE_CHECK_TIMEOUT`] reads as not live, the cold case, which only orders
    /// the lanes: `ssh -G` runs the user's `Match exec` commands, and a `connect` to a
    /// stopped master with a full backlog blocks, so neither may hold the pass. An
    /// `ssh -G` still running at the timeout is killed.
    pub(super) async fn master_is_live(&self) -> bool {
        tokio::time::timeout(LIVE_CHECK_TIMEOUT, async {
            let Some(path) = self.control_path().await else {
                return false;
            };
            socket_is_live(path).await
        })
        .await
        .unwrap_or(false)
    }

    /// This connection's resolved `ControlPath` (`ssh -G`), or `None` when it has none or
    /// it can't be read. The `ssh -G` child is killed if the caller stops waiting.
    async fn control_path(&self) -> Option<std::path::PathBuf> {
        let mut args = vec!["-G".to_owned()];
        args.extend(self.ssh_args());
        let output = super::super::ssh::client_command()
            .args(&args)
            .stdin(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .output()
            .await
            .ok()?;
        String::from_utf8_lossy(&output.stdout)
            .lines()
            .find_map(|line| line.strip_prefix("controlpath "))
            .filter(|path| *path != "none" && !path.contains('%'))
            .map(std::path::PathBuf::from)
    }
}
