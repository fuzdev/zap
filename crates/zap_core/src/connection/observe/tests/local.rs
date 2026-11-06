use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;
use std::time::{Duration, Instant};

use zap_types::observe::batch::{self, BATCH_SHELL};
use zap_types::observe::{
    CommandOrigin, Lane, Observation, PathFacet, PathObservation, Privilege, Query, QueryError,
};

use super::support::{elevated, path_query, running, running_pids};
use crate::connection::observe::local::{
    Native, observe_local, observe_path, route_local, run_local_batch,
};
use crate::connection::observe::process::{BatchProcess, ROOT_TERM_GRACE, finish_batch};
use crate::connection::observe::{BatchFailure, by_privilege, in_order, run_lanes};

/// How long a killed process may still read as running: polled, so only a ceiling,
/// generous for a loaded machine.
const GONE_WITHIN: Duration = Duration::from_secs(30);

/// An `Elevated` read on a Local connection: answered natively when the operator can
/// make it, final when the path isn't there, and asked again as root when it fails
/// any other way — while a `Login` read never escalates.
#[tokio::test]
async fn an_elevated_local_read_escalates_only_when_denied() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("file");
    std::fs::write(&file, "x").unwrap();
    let locked = dir.path().join("locked");
    std::fs::create_dir(&locked).unwrap();
    std::fs::write(locked.join("inside"), "x").unwrap();
    std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000)).unwrap();
    let at = |path: &Path| path.to_string_lossy().into_owned();
    let inside = at(&locked.join("inside"));
    let root = nix::unistd::geteuid().is_root();

    let mut routed = Vec::new();
    for facet in [
        PathFacet::Kind,
        PathFacet::Lstat,
        PathFacet::Digest,
        PathFacet::Read { max: 4 },
    ] {
        assert!(matches!(
            observe_path(&at(&file), facet, Privilege::Elevated).await,
            Native::Answer(Ok(_))
        ));
        assert!(matches!(
            observe_path(&at(&dir.path().join("absent")), facet, Privilege::Elevated).await,
            Native::Answer(Ok(Observation::Path(PathObservation::Failed)))
        ));
        if !root {
            assert!(
                matches!(
                    observe_path(&inside, facet, Privilege::Elevated).await,
                    Native::Escalate
                ),
                "{facet:?}"
            );
            assert!(matches!(
                observe_path(&inside, facet, Privilege::Login).await,
                Native::Answer(Ok(Observation::Path(PathObservation::Failed)))
            ));
        }
        routed.push(elevated(&inside, facet));
        routed.push(path_query(&inside, facet));
    }
    // Escalated reads batch into the root lane; the login reads stay native.
    let (answered, batched) = route_local(&routed).await;
    std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o700)).unwrap();
    if !root {
        assert_eq!(answered.len(), 4);
        assert!(answered.iter().all(|(index, _)| index % 2 == 1));
        assert_eq!(batched.len(), 4);
        assert!(
            batched
                .iter()
                .all(|(index, _, lane)| index % 2 == 0 && *lane == Lane::Root)
        );
    }
}

/// A content read of a fifo is answered natively without opening it — it is no
/// regular file — so nothing blocks waiting for a writer, at either privilege.
#[tokio::test]
async fn a_content_read_of_a_fifo_opens_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let fifo = dir.path().join("fifo");
    let made = std::process::Command::new("mkfifo")
        .arg(&fifo)
        .status()
        .is_ok_and(|status| status.success());
    if !made {
        return;
    }
    let fifo = fifo.to_string_lossy().into_owned();
    for privilege in [Privilege::Login, Privilege::Elevated] {
        let query = Query::Path {
            path: fifo.clone(),
            facet: PathFacet::Digest,
            privilege,
        };
        let (answered, batched) = route_local(std::slice::from_ref(&query)).await;
        assert!(batched.is_empty());
        assert_eq!(
            answered,
            [(0, Ok(Observation::Path(PathObservation::NotRegular)))]
        );
    }
}

#[tokio::test]
async fn a_failed_lane_answers_every_query_in_it_and_no_other() {
    let (a, b, c) = (
        path_query("/a", PathFacet::Kind),
        Query::Path {
            path: "/b".to_owned(),
            facet: PathFacet::Lstat,
            privilege: Privilege::Elevated,
        },
        path_query("/c", PathFacet::LinkTarget),
    );
    let queries = [a.clone(), b, c.clone()];
    let login_script = batch::render(&[&a, &c]);
    let (answered, batches, unreachable) = run_lanes(
        &by_privilege(&queries, Privilege::remote_lane),
        |lane, script, _deadline| {
            let expected = login_script.clone();
            async move {
                match lane {
                    Lane::Root => Err(BatchFailure::Lane("it exited 1".to_owned())),
                    Lane::Login => {
                        assert_eq!(script, expected);
                        Ok(b"pgid 42\n0 O \n0 E  s1\n1 O \n1 E  s1\nend 2\n".to_vec())
                    }
                }
            }
        },
    )
    .await;
    let results = in_order(3, answered);
    assert_eq!(results[0], Ok(Observation::Path(PathObservation::Failed)));
    assert_eq!(
        results[1],
        Err(QueryError::Batch {
            lane: Lane::Root,
            reason: "it exited 1".to_owned(),
        })
    );
    assert_eq!(results[2], Ok(Observation::Path(PathObservation::Failed)));
    assert_eq!(unreachable, None);
    // Each batch that ran is recorded, with its lane and query count.
    assert_eq!(batches.len(), 2);
    let login = batches.iter().find(|b| b.lane == Lane::Login).unwrap();
    assert_eq!(login.queries, 2);
}

#[test]
fn an_elevated_read_is_a_root_batch_over_ssh_and_native_locally() {
    // Over SSH, Elevated joins the root lane; locally it is answered natively, so a
    // Local pass with only Login/Elevated path reads runs no batch at all.
    assert_eq!(Privilege::Elevated.remote_lane(), Lane::Root);
    assert_eq!(Privilege::Elevated.local_lane(), Lane::Login);
}

#[tokio::test]
async fn a_local_pass_of_path_reads_runs_no_batch() {
    let queries = [
        path_query("/", PathFacet::Kind),
        Query::Path {
            path: "/".to_owned(),
            facet: PathFacet::Lstat,
            privilege: Privilege::Elevated,
        },
    ];
    let answers = observe_local(&queries).await;
    assert!(answers.batches.is_empty());
    assert!(answers.results.iter().all(Result::is_ok));
}

/// A probe whose descendant holds its output open outlives its own `timeout`; the
/// lane deadline is what stops the wait, long before the descendant would end.
#[tokio::test]
async fn the_lane_deadline_stops_a_batch_its_probes_timeout_cannot() {
    let probe = Query::Command {
        snippet: "sleep 120 &".to_owned(),
        privilege: Privilege::Login,
        timeout_secs: std::num::NonZeroU32::MIN,
        origin: CommandOrigin::Zap,
    };
    let started = Instant::now();
    let result = tokio::time::timeout(
        Duration::from_secs(60),
        run_local_batch(
            Lane::Login,
            batch::render(&[&probe]),
            Duration::from_millis(500),
        ),
    )
    .await;
    let elapsed = started.elapsed();
    // The descendant runs in a session of its own, which the lane's group kill
    // doesn't reach: kill it here, so a run leaves nothing behind.
    for pid in running_pids("sleep 120") {
        let _ = nix::sys::signal::kill(
            nix::unistd::Pid::from_raw(pid),
            nix::sys::signal::Signal::SIGKILL,
        );
    }
    let result = result.expect("the lane deadline never stopped the wait");
    assert_eq!(
        result,
        Err(BatchFailure::Lane("it ran past its 0s deadline".to_owned()))
    );
    assert!(elapsed < Duration::from_secs(60), "{elapsed:?}");
}

/// On expiry a local batch's whole process group dies, not just its shell — a
/// backgrounded child of the batch included.
#[tokio::test]
async fn a_local_deadline_kills_the_batch_process_group() {
    let dir = tempfile::tempdir().unwrap();
    let pid_file = dir.path().join("pid");
    let script = format!(
        "sleep 30 & echo $! > {}; wait",
        zap_types::shell::single_quote(&pid_file.to_string_lossy())
    );
    let result = run_local_batch(Lane::Login, script, Duration::from_millis(500)).await;
    assert_eq!(
        result,
        Err(BatchFailure::Lane("it ran past its 0s deadline".to_owned()))
    );
    let pid: i32 = std::fs::read_to_string(&pid_file)
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    let pid = nix::unistd::Pid::from_raw(pid);
    // Gone within a moment of the kill. The child's state is read from one `stat` read:
    // `None` once it is reaped, and a zombie (`Z`) or a task being reaped (`X`) is dead.
    // (Probing with `kill(pid, 0)` and then reading `stat` races the reaper: a zombie
    // reaped between the two has no `stat` left, and read as alive.)
    let state = || {
        let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
        let (_, rest) = stat.rsplit_once(')')?;
        rest.trim_start().chars().next()
    };
    let running = |state: Option<char>| state.is_some_and(|s| !matches!(s, 'Z' | 'X' | 'x'));
    let started = Instant::now();
    while running(state()) && started.elapsed() < GONE_WITHIN {
        std::thread::sleep(Duration::from_millis(20));
    }
    let last = state();
    assert!(
        !running(last),
        "the batch's background child survived the deadline (state {last:?})"
    );
}

/// At a local deadline, a command still running — in a session of its own, which the
/// batch's group kill doesn't reach — is killed too.
#[tokio::test]
async fn a_local_deadline_kills_a_running_commands_own_session() {
    let probe = Query::operator_command("sleep 3721");
    let result = run_local_batch(
        Lane::Login,
        batch::render(&[&probe]),
        Duration::from_millis(500),
    )
    .await;
    assert_eq!(
        result,
        Err(BatchFailure::Lane("it ran past its 0s deadline".to_owned()))
    );
    let started = Instant::now();
    while running("sleep 3721") && started.elapsed() < GONE_WITHIN {
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(!running("sleep 3721"), "the command survived the deadline");
}

/// A local root batch (`sudo`) is stopped with `SIGTERM` first — which `sudo` relays
/// to the shell it started — and `SIGKILL`ed only if it outlives the grace period.
/// Driven with a plain `sh` standing in for `sudo`, in zap's own process group as the
/// root lane's is.
#[tokio::test]
async fn a_root_batch_is_terminated_before_it_is_killed() {
    let dir = tempfile::tempdir().unwrap();
    let marker = dir.path().join("terminated");
    let spawn = || {
        tokio::process::Command::new("sh")
            .args(["-c", BATCH_SHELL])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .unwrap()
    };
    // Honors SIGTERM: stopped within the grace period, having seen the TERM.
    let script = format!(
        "trap 'echo term > {}; exit 0' TERM; sleep 5 </dev/null >/dev/null 2>&1 & wait",
        zap_types::shell::single_quote(&marker.to_string_lossy())
    );
    let started = Instant::now();
    let result = finish_batch(
        spawn(),
        &script,
        Duration::from_millis(300),
        BatchProcess::LocalRoot,
        None,
    )
    .await;
    assert!(result.is_err());
    assert!(
        started.elapsed() < ROOT_TERM_GRACE,
        "{:?}",
        started.elapsed()
    );
    assert_eq!(std::fs::read_to_string(&marker).unwrap(), "term\n");

    // Ignores SIGTERM: killed once the grace period is up.
    let started = Instant::now();
    let result = finish_batch(
        spawn(),
        "trap '' TERM; while :; do sleep 1; done",
        Duration::from_millis(300),
        BatchProcess::LocalRoot,
        None,
    )
    .await;
    assert!(result.is_err());
    let elapsed = started.elapsed();
    assert!(
        elapsed >= ROOT_TERM_GRACE && elapsed < ROOT_TERM_GRACE + Duration::from_secs(10),
        "{elapsed:?}"
    );
}

/// A batch stopped at its output limit is stopped while it still runs: its stdout stays
/// open until the kill, so a closed pipe can't end the batch first and orphan what it
/// started — here a process in a session of its own, which only the kill's walk of the
/// batch's descendants reaches.
#[tokio::test]
async fn a_batch_past_its_output_limit_is_stopped_with_what_it_started() {
    let result = run_local_batch(
        Lane::Login,
        "setsid sleep 3137 & cat /dev/zero".to_owned(),
        Duration::from_secs(60),
    )
    .await;
    assert_eq!(
        result,
        Err(BatchFailure::Lane(batch::STDOUT_LIMIT_REASON.to_owned()))
    );
    let started = Instant::now();
    while running("sleep 3137") && started.elapsed() < GONE_WITHIN {
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(
        !running("sleep 3137"),
        "the batch's own-session child survived the output limit"
    );
}
