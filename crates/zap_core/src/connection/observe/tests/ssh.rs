use std::time::{Duration, Instant};

use zap_types::observe::batch::{self, BATCH_SHELL};
use zap_types::observe::{Lane, PathFacet, Privilege, Query, QueryError};

use super::support::{backslash_in_single_quotes, path_query, ssh_target};
use crate::connection::delivery::ssh_remote_arg;
use crate::connection::observe::local::run_local_batch;
use crate::connection::observe::process::{self, BatchProcess, exit_reason, finish_batch};
use crate::connection::observe::ssh::{remote_batch_command, remote_kill_command};
use crate::connection::observe::{BatchFailure, by_privilege, in_order, run_lanes};

#[test]
fn a_batch_failure_reason_is_fixed_by_its_exit_status() {
    let conn = ssh_target();
    let ssh = BatchProcess::Ssh {
        conn: &conn,
        lane: Lane::Root,
    };
    assert_eq!(
        exit_reason(Some(97), ssh),
        "the target is missing a tool or the `/proc/self/fd` the batch needs"
    );
    assert_eq!(exit_reason(Some(255), ssh), "the ssh connection failed");
    assert_eq!(
        exit_reason(Some(255), BatchProcess::LocalLogin),
        "it exited 255"
    );
    assert_eq!(exit_reason(Some(1), ssh), "it exited 1");
    assert_eq!(
        exit_reason(None, BatchProcess::LocalLogin),
        "it was killed by a signal"
    );
}

/// An `ssh` that can't reach the target fails its lane like any batch failure — and
/// hands its stderr up, which `observe` turns into the pass's connectivity error.
#[tokio::test]
async fn an_unreachable_lane_reports_the_ssh_stderr() {
    let queries = [
        path_query("/a", PathFacet::Kind),
        Query::Path {
            path: "/b".to_owned(),
            facet: PathFacet::Lstat,
            privilege: Privilege::Elevated,
        },
    ];
    let (answered, _, unreachable) = run_lanes(
        &by_privilege(&queries, Privilege::remote_lane),
        |lane, _script, _deadline| async move {
            match lane {
                Lane::Root => Err(BatchFailure::Unreachable(
                    "ssh: connect to host h port 22: No route to host\n".to_owned(),
                )),
                Lane::Login => Ok(b"pgid 42\n0 O 0a31\n0 E \nend 1\n".to_vec()),
            }
        },
    )
    .await;
    assert_eq!(
        unreachable.as_deref(),
        Some("ssh: connect to host h port 22: No route to host\n")
    );
    assert_eq!(
        in_order(2, answered)[1],
        Err(QueryError::Batch {
            lane: Lane::Root,
            reason: "the ssh connection failed".to_owned(),
        })
    );
}

/// Both lanes' target-side kill runs as root — the login lane's under `sudo -n`, so a
/// root process an operator command started is reached — and the login lane's falls
/// back to the login user's own kill where `sudo` needs a password.
#[test]
fn the_target_side_kill_runs_as_root_in_either_lane() {
    let kill = zap_types::shell::single_quote(&batch::kill_snippet(4242));
    assert_eq!(
        remote_kill_command(Lane::Root, 4242),
        format!("sudo sh -c {kill}")
    );
    assert_eq!(
        remote_kill_command(Lane::Login, 4242),
        format!("sudo -n sh -c {kill} 2>/dev/null || sh -c {kill}")
    );
}

#[test]
fn the_remote_batch_runs_in_a_session_of_its_own() {
    let login = remote_batch_command(Lane::Login);
    assert_eq!(
        login,
        r#"sh -c 'command -v setsid >/dev/null 2>&1 || exit 97; setsid sh -c "$1"; exit $?' sh '__zap_script=$(cat) && exec </dev/null && eval "$__zap_script"'"#
    );
    assert_eq!(remote_batch_command(Lane::Root), format!("sudo {login}"));
}

/// What the target's login shell parses reads the same in `fish` as in a POSIX shell:
/// no single-quoted segment of it holds a backslash, in either lane — nor does the
/// target-side kill's.
#[test]
fn the_login_shell_parses_no_backslash_in_single_quotes() {
    for lane in [Lane::Login, Lane::Root] {
        let arg = ssh_remote_arg(&remote_batch_command(lane));
        assert!(!backslash_in_single_quotes(&arg), "{lane}: {arg}");
        let kill = remote_kill_command(lane, 4242);
        assert!(!backslash_in_single_quotes(&ssh_remote_arg(&kill)));
    }
    // The check sees the three-deep nesting the positional parameter avoids.
    let nested = format!(
        "sudo sh -c {}",
        zap_types::shell::single_quote(&format!(
            "setsid sh -c {}; exit $?",
            zap_types::shell::single_quote(BATCH_SHELL)
        ))
    );
    assert!(backslash_in_single_quotes(&ssh_remote_arg(&nested)));
}

/// The whole remote command of each lane, as a login shell that leads its own process
/// group runs it (`sshd` makes the session command one) — under `sh`, and under `fish`
/// when it is installed: `setsid` runs as a non-leader, so the batch keeps its exit status and its
/// stdout, and the id it reports is its own session and process group.
#[tokio::test]
async fn the_session_wrapper_keeps_the_exit_status_and_reports_its_group() {
    let installed = |tool: &str| {
        std::process::Command::new("sh")
            .args(["-c", &format!("command -v {tool}")])
            .output()
            .is_ok_and(|output| output.status.success())
    };
    if !installed("setsid") {
        return;
    }
    // The root lane's with `sudo` swapped for `env`: the same parse, no privilege.
    let args = [Lane::Login, Lane::Root]
        .map(|lane| ssh_remote_arg(&remote_batch_command(lane).replacen("sudo ", "env ", 1)));
    // `fish` without the running user's config, whose output isn't the wrapper's.
    let mut login_shells: Vec<&[&str]> = vec![&["sh"]];
    if installed("fish") {
        login_shells.push(&["fish", "--no-config"]);
    }
    for (shell, arg) in login_shells
        .iter()
        .flat_map(|shell| args.iter().map(move |arg| (shell, arg)))
    {
        let child = tokio::process::Command::new(shell[0])
            .args(&shell[1..])
            .arg("-c")
            .arg(arg)
            .process_group(0)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        let output = crate::connection::pipe_stdin_and_wait(
            child,
            b"echo \"pgid $$\"\nread -r _ _ _ _ g s _ </proc/$$/stat\necho \"$g $s\"\nexit 3\n",
        )
        .await
        .unwrap();
        assert_eq!(output.status.code(), Some(3), "{shell:?} {arg}: {output:?}");
        let stdout = String::from_utf8(output.stdout).unwrap();
        let mut lines = stdout.lines();
        let pgid = batch::parse_pgid(lines.next().unwrap().as_bytes()).unwrap();
        assert_eq!(
            lines.next(),
            Some(format!("{pgid} {pgid}").as_str()),
            "{shell:?} {arg}"
        );
    }
}

/// A cold pass's login lane starts only once the root lane is under way — at its first
/// output byte — and not at all when the root lane couldn't reach the target.
#[tokio::test]
async fn a_cold_pass_starts_its_second_ssh_after_the_first_is_up() {
    use crate::connection::observe::master_gate::{MasterGate, MasterState, mark, take_turn};

    let gate = MasterGate::new();
    let leader = take_turn(Some(gate.role(Lane::Root)))
        .await
        .unwrap()
        .unwrap();
    let follower = tokio::spawn(take_turn(Some(gate.role(Lane::Login))));
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(!follower.is_finished(), "the follower waits for the leader");
    // The leader's first output byte marks the gate up.
    let mut child = tokio::process::Command::new("sh")
        .args(["-c", "echo 'pgid 42'"])
        .stdout(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    process::read_stdout(
        child.stdout.take().unwrap(),
        std::sync::Arc::new(std::sync::OnceLock::new()),
        Some(std::sync::Arc::clone(&leader)),
    )
    .await
    .unwrap();
    let _ = child.wait().await;
    assert!(matches!(follower.await.unwrap(), Ok(None)));
    // Marked once: a later mark doesn't move it.
    mark(&leader, MasterState::Unreachable);
    assert_eq!(*leader.borrow(), MasterState::Up);

    let gate = MasterGate::new();
    let leader = take_turn(Some(gate.role(Lane::Root)))
        .await
        .unwrap()
        .unwrap();
    mark(&leader, MasterState::Unreachable);
    assert!(matches!(
        take_turn(Some(gate.role(Lane::Login))).await,
        Err(BatchFailure::Lane(reason)) if reason == "the ssh connection failed"
    ));
    // A warm pass has no gate: both lanes start at once.
    assert!(matches!(take_turn(None).await, Ok(None)));
}

/// A control master is live when a listener accepts on its socket; a stale socket
/// file (its master gone) or no file at all is cold.
#[tokio::test]
async fn a_control_socket_is_live_only_while_a_listener_accepts() {
    use crate::connection::observe::master_gate::socket_is_live;

    // Under `/tmp`, not `$TMPDIR`: a socket path must fit `sun_path` (108 bytes).
    let dir = tempfile::Builder::new().tempdir_in("/tmp").unwrap();
    let live = dir.path().join("live");
    let _listener = std::os::unix::net::UnixListener::bind(&live).unwrap();
    assert!(socket_is_live(live).await);

    let stale = dir.path().join("stale");
    drop(std::os::unix::net::UnixListener::bind(&stale).unwrap());
    assert!(stale.exists(), "the socket file outlives its listener");
    // Another test thread may fork while the listener exists: its child holds a copy
    // of the listening descriptor until it `exec`s (close-on-exec closes it only
    // then), so for a few milliseconds the socket still accepts. The stale socket
    // must read not-live once no process holds it — polled, within a bound no
    // forked child's `exec` comes near.
    let deadline = Instant::now() + Duration::from_secs(30);
    while socket_is_live(stale.clone()).await {
        assert!(
            Instant::now() < deadline,
            "a socket whose listener is gone still reads live after 30s"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    assert!(!socket_is_live(dir.path().join("absent")).await);
}

/// A cold pass's leader that runs past its deadline — so never printed — still lets
/// the follower start once it is stopped.
#[tokio::test]
async fn a_leader_past_its_deadline_releases_the_follower() {
    use crate::connection::observe::master_gate::{MasterGate, MasterState, settle, take_turn};

    let gate = MasterGate::new();
    let leader = take_turn(Some(gate.role(Lane::Root)))
        .await
        .unwrap()
        .unwrap();
    let follower = tokio::spawn(take_turn(Some(gate.role(Lane::Login))));
    let child = tokio::process::Command::new("sh")
        .args(["-c", BATCH_SHELL])
        .process_group(0)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let result = finish_batch(
        child,
        "sleep 5",
        Duration::from_secs(1),
        BatchProcess::LocalLogin,
        Some(std::sync::Arc::clone(&leader)),
    )
    .await;
    assert_eq!(
        result,
        Err(BatchFailure::Lane("it ran past its 1s deadline".to_owned()))
    );
    assert!(
        !follower.is_finished(),
        "nothing printed: the gate is still shut"
    );
    settle(&leader, &result);
    assert_eq!(*leader.borrow(), MasterState::Up);
    assert!(matches!(follower.await.unwrap(), Ok(None)));
}

/// The first output line's process group is recorded as soon as it arrives; a
/// first line that isn't the record records nothing.
#[tokio::test]
async fn the_reader_records_the_reported_group() {
    for (script, expected) in [
        ("echo 'pgid 4242'; echo more", Some(4242)),
        ("echo 'nope 4242'; echo 'pgid 4242'", None),
    ] {
        let mut child = tokio::process::Command::new("sh")
            .args(["-c", script])
            .stdout(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        let pgid = std::sync::Arc::new(std::sync::OnceLock::new());
        let read = process::read_stdout(
            child.stdout.take().unwrap(),
            std::sync::Arc::clone(&pgid),
            None,
        )
        .await
        .unwrap();
        assert!(matches!(read, process::Stdout::Done(_)));
        assert_eq!(pgid.get().copied(), expected, "{script}");
        let _ = child.wait().await;
    }
}

/// Past the stdout limit the reader stops, the batch is stopped, and the lane fails
/// with a fixed reason — never the output.
#[tokio::test]
async fn a_batch_past_its_output_limit_is_stopped() {
    let started = Instant::now();
    let result = run_local_batch(
        Lane::Login,
        "exec cat /dev/zero".to_owned(),
        Duration::from_secs(60),
    )
    .await;
    assert_eq!(
        result,
        Err(BatchFailure::Lane(batch::STDOUT_LIMIT_REASON.to_owned()))
    );
    assert!(
        started.elapsed() < Duration::from_secs(30),
        "{:?}",
        started.elapsed()
    );
}

/// The kill is delivered like any command: its text on the client's stdin — closed after
/// it, so the wrapper's read ends — and the client's argv the constant wrapper.
#[tokio::test]
async fn the_kill_travels_on_the_clients_stdin() {
    use crate::connection::delivery::Delivery;
    use crate::connection::ssh::test_client::{self, Remote};

    let dir = tempfile::tempdir().unwrap();
    let client = test_client::set(dir.path(), Remote::Record);
    let conn = ssh_target();
    for lane in [Lane::Login, Lane::Root] {
        conn.kill_batch(lane, 4242).await;
        assert_eq!(
            client.stdin(),
            Delivery::of(&remote_kill_command(lane, 4242), None)
                .unwrap()
                .stdin,
            "{lane:?}"
        );
        let argv = client.argv();
        assert!(
            argv.ends_with(&format!(
                "{}\n",
                ssh_remote_arg(crate::connection::delivery::COMMAND_SHELL)
            )),
            "{argv}"
        );
        assert!(!argv.contains("4242"), "{argv}");
    }
}
