//! [`Connection::observe`] — the runners that answer typed detection queries.
//!
//! Every query carries a [`Privilege`]; each connection maps it to a [`Lane`] (one batch)
//! or answers it natively:
//!
//! - **Ssh** renders each lane's queries as one batch script
//!   ([`zap_types::observe::batch`]) and runs the two lanes concurrently, each as one
//!   `ssh` command on its own multiplexed channel (`Login` → the login lane, `Root` and
//!   `Elevated` → the root lane). The script travels on the channel's **stdin** to a
//!   constant wrapper — `BATCH_SHELL` in a session of its own (`setsid`), under `sudo`
//!   for the root lane — so ssh's argv carries no probe text, and stdout comes back as
//!   raw bytes. A batch `ssh` can't run at all (it can't start, or exits 255) fails the
//!   whole pass as [`Error::Connectivity`](crate::error::Error::Connectivity): the batches are the pass's connectivity check.
//!   A pass authenticates at most once: when the connection's `ControlMaster` socket isn't
//!   live, the login lane's `ssh` waits for the root lane's to be under way (its first
//!   output, which comes after the master is up) before it starts — two cold clients
//!   started together would each authenticate (see `MasterGate`).
//! - **Local** answers `Login` and `Elevated` path queries natively (`std::fs`) as the
//!   operator, and runs everything else — `Root` path queries and all command queries —
//!   as a local batch per lane (`sudo sh` for the root lane). An `Elevated` read the
//!   operator can't make for any reason but "not found" is asked again in the root
//!   lane's batch: native first, `sudo` only when denied. A content read of something
//!   that isn't a regular file or a directory (a fifo, a device) goes to the login
//!   batch, where its probe's timeout bounds it.
//! - **Mock** answers each query from its recorded observations, so a golden pins the
//!   queries a detector issues, not their shell text.
//!
//! Every batch runs under a deadline ([`batch::lane_deadline_secs`]): a probe `timeout`
//! couldn't stop — its descendants holding its output open — would otherwise stall the
//! pass. Its stdout is read up to [`batch::STDOUT_LIMIT`]. Past either, the batch is
//! stopped (see `BatchProcess`: over SSH its process group and session killed on the
//! target, then the ssh client; a local login batch's process group killed; a local root
//! batch's `sudo` sent `SIGTERM` then `SIGKILL`) and every query in the lane fails with a
//! fixed reason. A lane's failure reason is always a fixed phrase or an exit status,
//! never the batch's output.
//!
//! Every batch that runs yields a [`BatchRecord`] (its lane and query count), carried on
//! the detection result beside the answers.

mod local;
mod master_gate;
mod process;
mod ssh;
mod stop;
#[cfg(test)]
mod tests;

use std::future::Future;
use std::time::Duration;

use zap_types::observe::batch::{self, RecordError};
use zap_types::observe::{BatchRecord, Lane, Privilege, Query, QueryError, QueryResult};

use self::local::observe_local;
use self::master_gate::MasterGate;
use self::ssh::SSH_FAILED_REASON;
use super::Connection;
use crate::error::Result as ZapResult;

/// The answers to a list of queries, in query order, plus a record of each batch that
/// ran to produce them.
#[derive(Debug, Clone, Default)]
pub struct Answers {
    /// One answer per query, in the order the queries were given.
    pub results: Vec<QueryResult>,
    /// The batches that ran (none for answers read natively or from a mock).
    pub batches: Vec<BatchRecord>,
}

impl Connection {
    /// Answer `queries` — see the module docs for how each connection does it. A query
    /// that couldn't be answered carries its own [`QueryError`], and the detector holds
    /// its resource.
    ///
    /// # Errors
    /// - [`Error::Connectivity`](crate::error::Error::Connectivity) when an SSH batch
    ///   can't reach the target — `ssh` couldn't start or exited 255 — with the same
    ///   label, message, and host-key advice as [`Connection::check_connectivity`], or
    ///   when the operator's `ssh` config leaves host keys unchecked.
    /// - [`Error::Command`](crate::error::Error::Command) when a query's path or command
    ///   still holds a reference delimiter: every reference a read takes is resolved
    ///   before the query is built, so the read would be of something no config
    ///   declared, and nothing is read.
    pub async fn observe(&self, queries: &[Query]) -> ZapResult<Answers> {
        for query in queries {
            match query {
                Query::Path { path, .. } => super::delivery::refuse_delimiter_in_path(path),
                Query::Command { snippet, .. } => super::delivery::refuse_delimiter(snippet),
            }
            .map_err(crate::error::Error::Command)?;
        }
        match self {
            Self::Ssh(ssh) => {
                ssh.host_keys_checked().await?;
                let lanes = by_privilege(queries, Privilege::remote_lane);
                let both = [Lane::Root, Lane::Login]
                    .iter()
                    .all(|lane| lanes.iter().any(|(_, _, l)| l == lane));
                let gate = (both && !ssh.master_is_live().await).then(MasterGate::new);
                let (answered, batches, unreachable) =
                    run_lanes(&lanes, |lane, script, deadline| {
                        let role = gate.as_ref().map(|gate| gate.role(lane));
                        ssh.run_batch(lane, script, deadline, role)
                    })
                    .await;
                if let Some(stderr) = unreachable {
                    return Err(ssh.connectivity_error(&stderr));
                }
                Ok(Answers {
                    results: in_order(queries.len(), answered),
                    batches,
                })
            }
            Self::Local => Ok(observe_local(queries).await),
            Self::Mock(mock) => {
                mock.rendezvous().await;
                Ok(Answers {
                    results: queries.iter().map(|query| mock.answer(query)).collect(),
                    batches: Vec::new(),
                })
            }
        }
    }
}

/// Why a lane's batch left no output to read.
#[derive(Debug, Clone, PartialEq, Eq)]
enum BatchFailure {
    /// The batch failed: every query in its lane fails with this fixed reason.
    Lane(String),
    /// `ssh` couldn't reach the target — it couldn't start, or exited 255. Carries its
    /// stderr (or the spawn error), which becomes the pass's connectivity error.
    Unreachable(String),
}

impl BatchFailure {
    /// The fixed reason every query in the failed lane carries.
    fn lane_reason(&self) -> &str {
        match self {
            Self::Lane(reason) => reason,
            Self::Unreachable(_) => SSH_FAILED_REASON,
        }
    }
}

/// Place `(index, answer)` pairs into a `count`-long list; a slot nothing answered reads
/// as a missing record rather than a guess.
fn in_order(count: usize, answered: Vec<(usize, QueryResult)>) -> Vec<QueryResult> {
    let mut results: Vec<Option<QueryResult>> = vec![None; count];
    for (index, result) in answered {
        if let Some(slot) = results.get_mut(index) {
            *slot = Some(result);
        }
    }
    results
        .into_iter()
        .map(|slot| slot.unwrap_or(Err(QueryError::Record(RecordError::Missing))))
        .collect()
}

/// Pair each of `queries` with its index and the lane `lane_of` its privilege maps to.
fn by_privilege(queries: &[Query], lane_of: fn(Privilege) -> Lane) -> Vec<(usize, &Query, Lane)> {
    queries
        .iter()
        .enumerate()
        .map(|(index, query)| (index, query, lane_of(query.privilege())))
        .collect()
}

/// Run `queries` (each paired with its index in the caller's list and its lane) as one
/// batch per lane, the lanes concurrently. `run` executes one lane's script under its
/// deadline and returns its stdout, or why the batch failed as a whole. Also returns the
/// stderr of an `ssh` that couldn't reach the target, when a lane's did.
async fn run_lanes<F, Fut>(
    queries: &[(usize, &Query, Lane)],
    run: F,
) -> (Vec<(usize, QueryResult)>, Vec<BatchRecord>, Option<String>)
where
    F: Fn(Lane, String, Duration) -> Fut + Sync,
    Fut: Future<Output = Result<Vec<u8>, BatchFailure>> + Send,
{
    let lane = |lane: Lane| {
        let members: Vec<(usize, &Query)> = queries
            .iter()
            .filter(|(_, _, query_lane)| *query_lane == lane)
            .map(|(index, query, _)| (*index, *query))
            .collect();
        let started = (!members.is_empty()).then(|| {
            let lane_queries: Vec<&Query> = members.iter().map(|(_, query)| *query).collect();
            let script = batch::render(&lane_queries);
            let record = BatchRecord {
                lane,
                queries: lane_queries.len(),
            };
            let deadline = Duration::from_secs(batch::lane_deadline_secs(&lane_queries));
            (members, lane_queries, record, run(lane, script, deadline))
        });
        async move {
            let (members, lane_queries, record, running) = started?;
            let (results, unreachable) = match running.await {
                Ok(output) => (batch::read(lane, &lane_queries, &output), None),
                Err(failure) => (
                    batch::fail_lane(lane, lane_queries.len(), failure.lane_reason()),
                    match failure {
                        BatchFailure::Unreachable(stderr) => Some(stderr),
                        BatchFailure::Lane(_) => None,
                    },
                ),
            };
            let answered: Vec<(usize, QueryResult)> = members
                .iter()
                .map(|(index, _)| *index)
                .zip(results)
                .collect();
            Some((answered, record, unreachable))
        }
    };
    let lanes: [_; 2] = tokio::join!(lane(Lane::Root), lane(Lane::Login)).into();
    let mut answered = Vec::new();
    let mut batches = Vec::new();
    let mut unreachable = None;
    for (lane_answered, record, lane_unreachable) in lanes.into_iter().flatten() {
        answered.extend(lane_answered);
        batches.push(record);
        unreachable = unreachable.or(lane_unreachable);
    }
    (answered, batches, unreachable)
}
