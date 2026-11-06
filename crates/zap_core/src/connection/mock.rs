//! `MockConnection` — a test double that replays recorded command output.
//!
//! It answers `run` by looking the exact command string up in a recorded map; an
//! unrecorded command is a loud error (so code under test that issues an unexpected
//! command fails the test rather than silently passing). It answers typed detection
//! queries ([`Connection::observe`](super::Connection::observe)) the same way, from
//! recorded `(query → answer)` pairs; an unrecorded query answers
//! [`QueryError::Unrecorded`], which holds any resource whose verdict needs it. This is
//! the seam the golden-fixture detection tests drive: a fixture pairs recorded
//! `(cmd → output)` and `(query → observation)` with the expected `Detection`.
//!
//! TODO: when a second crate needs shared test helpers, this moves to a
//! `zap_testing` crate (kept out of production binaries via the
//! `cargo xtask check-release` pattern). Until then it lives here, always
//! compiled — it's just the `Mock` arm of the always-present `Connection` enum.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use zap_types::observe::{Observation, Query, QueryError, QueryResult};

use super::CommandOutput;

/// A recorded command double. Construct from `(command, output)` pairs (typically
/// loaded from a golden fixture) and hand it to [`super::Connection::Mock`].
#[derive(Debug, Clone)]
pub struct MockConnection {
    /// The host label this mock reports.
    pub host: String,
    /// The connecting user this mock reports (empty unless declared).
    pub user: String,
    /// The declared target home, if any — the `Mock` arm of `apply_home` uses it the
    /// way `Ssh` uses `target.home`. `None` means a home-referencing path errors
    /// (and a home-free path passes through), so fixtures stay deterministic.
    pub home: Option<String>,
    /// Recorded command → output. Keyed on the exact command string.
    pub responses: BTreeMap<String, CommandOutput>,
    /// Recorded query → answer, matched by equality (the query is the whole key — its
    /// path, facet, and lane).
    pub answers: Vec<(Query, QueryResult)>,
    /// Every command looked up (issued) on this mock, in order — recorded *and*
    /// unrecorded ones alike (an unrecorded lookup still logs here before erroring at
    /// the call site). Lets a test assert that a **best-effort** command whose result
    /// the code swallows (a cleanup `rm -rf`) was actually issued. `Arc`-shared so a
    /// clone observes the same log.
    call_log: Arc<Mutex<Vec<String>>>,
    /// Every query answered on this mock, in order, recorded or not. `Arc`-shared like
    /// `call_log`.
    query_log: Arc<Mutex<Vec<Query>>>,
    /// A barrier the first detection read on this mock waits at, and whether it has
    /// ([`with_rendezvous`](Self::with_rendezvous)).
    rendezvous: Option<(Arc<tokio::sync::Barrier>, Arc<AtomicBool>)>,
}

impl MockConnection {
    /// A mock reporting `host` with no recorded commands.
    #[must_use]
    pub fn new(host: impl Into<String>) -> Self {
        Self {
            host: host.into(),
            user: String::new(),
            home: None,
            responses: BTreeMap::new(),
            answers: Vec::new(),
            call_log: Arc::new(Mutex::new(Vec::new())),
            query_log: Arc::new(Mutex::new(Vec::new())),
            rendezvous: None,
        }
    }

    /// Make the first detection read on this mock wait at `barrier` (builder-style):
    /// runs over mocks that share one barrier all reach their first read before any of
    /// them goes past it — a deterministic interleaving for a test of concurrent runs.
    /// Later reads don't wait. The logs stay shared with the mock this is built from.
    #[must_use]
    pub fn with_rendezvous(mut self, barrier: Arc<tokio::sync::Barrier>) -> Self {
        self.rendezvous = Some((barrier, Arc::new(AtomicBool::new(false))));
        self
    }

    /// Wait at the rendezvous, if this mock has one and hasn't waited yet.
    pub(super) async fn rendezvous(&self) {
        if let Some((barrier, met)) = &self.rendezvous
            && !met.swap(true, Ordering::SeqCst)
        {
            barrier.wait().await;
        }
    }

    /// Declare the connecting user (builder-style) — what [`Connection::user`] reports.
    ///
    /// [`Connection::user`]: super::Connection::user
    #[must_use]
    pub fn with_user(mut self, user: impl Into<String>) -> Self {
        self.user = user.into();
        self
    }

    /// Declare a target home (builder-style), to exercise `apply_home` resolution.
    #[must_use]
    pub fn with_home(mut self, home: impl Into<String>) -> Self {
        self.home = Some(home.into());
        self
    }

    /// Record one command's output (builder-style).
    #[must_use]
    pub fn with(mut self, cmd: impl Into<String>, output: CommandOutput) -> Self {
        self.responses.insert(cmd.into(), output);
        self
    }

    /// Record one query's observation (builder-style).
    #[must_use]
    pub fn with_observation(self, query: Query, observation: Observation) -> Self {
        self.with_answer(query, Ok(observation))
    }

    /// Record one query's answer — an observation or a query error (builder-style).
    #[must_use]
    pub fn with_answer(mut self, query: Query, answer: QueryResult) -> Self {
        self.answers.push((query, answer));
        self
    }

    /// The recorded answer to `query` ([`QueryError::Unrecorded`] if none), logging it
    /// for [`issued_queries`](Self::issued_queries).
    pub(super) fn answer(&self, query: &Query) -> QueryResult {
        if let Ok(mut log) = self.query_log.lock() {
            log.push(query.clone());
        }
        self.answers
            .iter()
            .find(|(recorded, _)| recorded == query)
            .map_or(Err(QueryError::Unrecorded), |(_, answer)| answer.clone())
    }

    /// Every query answered on this mock so far, in order.
    #[must_use]
    pub fn issued_queries(&self) -> Vec<Query> {
        self.query_log
            .lock()
            .map(|log| log.clone())
            .unwrap_or_default()
    }

    /// The recorded output for `cmd`, if any — logging the lookup (every dispatch path
    /// composes `run` / `run_with_stdin` / `run_raw_stdout` through here) so
    /// [`issued`](Self::issued) can later confirm a swallowed best-effort command ran.
    pub(super) fn lookup(&self, cmd: &str) -> Option<&CommandOutput> {
        if let Ok(mut log) = self.call_log.lock() {
            log.push(cmd.to_owned());
        }
        self.responses.get(cmd)
    }

    /// Whether `cmd` was issued (looked up) on this mock — the assertion seam for a
    /// best-effort command whose `Result` the code discards (e.g. a cleanup `rm -rf`
    /// that runs on both the success and failure paths).
    #[must_use]
    pub fn issued(&self, cmd: &str) -> bool {
        self.call_log
            .lock()
            .is_ok_and(|log| log.iter().any(|c| c == cmd))
    }

    /// Every command issued on this mock so far, in order — the whole log, for a test
    /// that asserts over *what* a code path touched rather than one known command.
    #[must_use]
    pub fn issued_commands(&self) -> Vec<String> {
        self.call_log
            .lock()
            .map(|log| log.clone())
            .unwrap_or_default()
    }
}
