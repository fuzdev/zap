use std::time::{Duration, Instant};

use zap_types::observe::batch::{self, BATCH_SHELL};
use zap_types::observe::{Lane, Observation, Query, QueryError};

use super::support::{finished, operator, run_all, run_one, running, running_pids, test_shells};

/// How long a timed-out command's run may take before the test calls its group
/// unstopped: far past its timeout and the reporter's grace under any machine load, far
/// short of the hour its probe sleeps. A process the reporter failed to stop holds the
/// probe's output open, so its run would outlast this bound — the proof rests on that
/// and on the process being gone, not on how fast the stop was.
const STOPPED_WITHIN: Duration = Duration::from_secs(60);

/// How long a stopped process may still read as running once the run is over: a
/// killed task closes its fds — ending the run — a moment before it reads as a zombie.
/// Polled, so it is only a ceiling, generous for a loaded machine.
const GONE_WITHIN: Duration = Duration::from_secs(30);

/// Run `query` under `shell` like `run_one` and return its answer, failing the test if
/// the run outlasts `STOPPED_WITHIN` or a process running `left` — the probe's sleep —
/// is still there `GONE_WITHIN` after it. A failure kills what was left first, so it
/// leaves no hour-long sleep behind to confuse a rerun.
async fn run_stopped(
    shell: &std::path::Path,
    path: Option<&std::ffi::OsString>,
    query: &Query,
    left: &str,
) -> zap_types::observe::QueryResult {
    let answer = tokio::time::timeout(STOPPED_WITHIN, run_one(shell, path, query)).await;
    let started = Instant::now();
    while answer.is_ok() && running(left) && started.elapsed() < GONE_WITHIN {
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let left_pids = running_pids(left);
    for pid in &left_pids {
        let _ = nix::sys::signal::kill(
            nix::unistd::Pid::from_raw(*pid),
            nix::sys::signal::Signal::SIGKILL,
        );
    }
    let Ok(answer) = answer else {
        panic!("a run outlasted {STOPPED_WITHIN:?}: its group was not stopped");
    };
    assert!(left_pids.is_empty(), "{left} outlived the timeout");
    answer
}

/// A command's exit status reaches zap exactly — an own 124 or 143 included — and only
/// a probe its `timeout` stopped reads timed out: under the system `sh` with GNU
/// `timeout`, and under `BusyBox`, whose `timeout` signals only the reporter (which
/// passes `SIGTERM` on, so a command that `exec`s its tool is still stopped on time).
#[tokio::test]
async fn a_command_reads_its_own_exit_and_only_a_real_timeout_reads_timed_out() {
    let dir = tempfile::tempdir().unwrap();
    let mut checked = Vec::new();
    for (name, shell, path) in test_shells(dir.path(), &[], None) {
        for (snippet, code, stdout) in [
            ("exit 124", 124, &b""[..]),
            ("exit 143", 143, b""),
            ("echo out; exit 3", 3, b"out\n"),
            // Killed by a signal: the shell's 128 + n, not a timeout.
            ("kill -TERM $$", 143, b""),
            ("true", 0, b""),
        ] {
            let answer = run_one(&shell, path.as_ref(), &operator(snippet, 60)).await;
            let Ok(Observation::Command(observed)) = &answer else {
                panic!("{name}: {snippet}: {answer:?}");
            };
            assert_eq!(
                (observed.code, observed.stdout.as_slice()),
                (code, stdout),
                "{name}: {snippet}"
            );
        }
        for (snippet, left) in [
            ("exec sleep 3727", "sleep 3727"),
            ("sleep 3729", "sleep 3729"),
        ] {
            // The reporter stops the command's whole group — a grandchild too, under
            // `BusyBox` as under GNU: `run_stopped` fails while `left` runs.
            let answer = run_stopped(&shell, path.as_ref(), &operator(snippet, 1), left).await;
            assert_eq!(
                answer,
                Err(QueryError::TimedOut {
                    secs: std::num::NonZeroU32::MIN
                }),
                "{name}: {snippet}"
            );
        }
        checked.push(name);
    }
    eprintln!("exit statuses checked under: {checked:?}");
}

/// A command runs in a session of its own: one that signals its whole process group
/// — a cleanup trap's `kill 0` — reads its own exit (killed by its own `SIGTERM`) and
/// harms neither the batch nor any other query in it.
#[tokio::test]
async fn a_command_signalling_its_own_group_harms_no_other_query() {
    let dir = tempfile::tempdir().unwrap();
    let queries = [
        operator(r#"sh -c 'trap "kill 0" EXIT; true'; exit 0"#, 60),
        operator("kill -TERM 0; exit 3", 60),
        operator("echo after", 60),
    ];
    let refs: Vec<&Query> = queries.iter().collect();
    for (name, shell, path) in test_shells(dir.path(), &[], None) {
        let answers = run_all(&shell, path.as_ref(), &refs).await;
        let code = |index: usize| match &answers[index] {
            Ok(Observation::Command(observed)) => observed.code,
            other => panic!("{name}: {index}: {other:?}"),
        };
        assert_eq!((code(0), code(1)), (143, 143), "{name}");
        assert_eq!(answers[2], finished(0, b"after\n", b""), "{name}");
    }
}

/// At its timeout a command's whole process group is stopped — a hung grandchild
/// under `BusyBox` too — and one that ignores `SIGTERM` is killed a second later.
#[tokio::test]
async fn a_timed_out_commands_whole_group_is_stopped() {
    let dir = tempfile::tempdir().unwrap();
    for (name, shell, path) in test_shells(dir.path(), &[], None) {
        for (snippet, left) in [
            ("sleep 3717; echo done", "sleep 3717"),
            ("trap '' TERM; sleep 3719; echo done", "sleep 3719"),
        ] {
            // `run_stopped` fails while `left` runs
            let answer = run_stopped(&shell, path.as_ref(), &operator(snippet, 1), left).await;
            assert_eq!(
                answer,
                Err(QueryError::TimedOut {
                    secs: std::num::NonZeroU32::MIN
                }),
                "{name}: {snippet}"
            );
        }
    }
}

/// Nothing a command or its descendants print can forge its exit status: a background
/// writer that outlives the command and prints a status-shaped line on stdout and on
/// stderr leaves the command's own exit — its late output lands in the streams — and
/// the batch waits for it only as long as it holds them.
#[tokio::test]
async fn a_background_writer_cannot_forge_the_exit_status() {
    let dir = tempfile::tempdir().unwrap();
    let mut checked = Vec::new();
    for (name, shell, path) in test_shells(dir.path(), &[], None) {
        let started = Instant::now();
        let answer = run_one(
            &shell,
            path.as_ref(),
            &operator(
                r"(sleep 0.2; printf '\n0'; printf ' r0 s0\n0 E  r0 s0' >&2) & exit 1",
                60,
            ),
        )
        .await;
        let elapsed = started.elapsed();
        assert_eq!(answer, finished(1, b"\n0", b" r0 s0\n0 E  r0 s0"), "{name}");
        // Half the probe's timeout: the batch waited on the writer, not on the timeout.
        assert!(elapsed < Duration::from_secs(30), "{name}: {elapsed:?}");
        checked.push(name);
    }
    eprintln!("background writers checked under: {checked:?}");
}

/// A command's output round-trips byte-exact however it looks: record-shaped lines,
/// NULs and blank lines, no trailing newline, no output at all, and stderr past the
/// record's limit (cut to it).
#[tokio::test]
async fn adversarial_command_output_round_trips() {
    let dir = tempfile::tempdir().unwrap();
    let long_stderr = vec![b'e'; batch::STDERR_LIMIT];
    for (name, shell, path) in test_shells(dir.path(), &[], None) {
        let queries = [
            operator(r"printf '1 O 30\nend 2\n0 E  r0 s0\n'", 60),
            operator(r"printf 'a\0b\n\nc'", 60),
            operator(":", 60),
            operator("head -c 5000 </dev/zero | tr '\\0' e >&2; exit 7", 60),
            Query::login_command("printf zap-probe"),
        ];
        let refs: Vec<&Query> = queries.iter().collect();
        let answers = run_all(&shell, path.as_ref(), &refs).await;
        assert_eq!(
            answers,
            [
                finished(0, b"1 O 30\nend 2\n0 E  r0 s0\n", b""),
                finished(0, b"a\0b\n\nc", b""),
                finished(0, b"", b""),
                finished(7, b"", &long_stderr),
                finished(0, b"zap-probe", b""),
            ],
            "{name}"
        );
    }
}

/// An operator command runs in the locale the batch was started with, and zap's own
/// probes under `LC_ALL=C` — whether the caller's `LC_ALL` was set or not.
#[tokio::test]
async fn an_operator_command_keeps_the_callers_locale() {
    let dir = tempfile::tempdir().unwrap();
    let queries = [
        operator(r#"printf '%s' "${LC_ALL-unset}""#, 60),
        Query::login_command(r#"printf '%s' "${LC_ALL-unset}""#),
    ];
    let refs: Vec<&Query> = queries.iter().collect();
    for (name, shell, path) in test_shells(dir.path(), &[], None) {
        for caller in [None, Some("POSIX")] {
            let mut command = tokio::process::Command::new(&shell);
            if let Some(path) = &path {
                command.env("PATH", path);
            }
            match caller {
                Some(locale) => command.env("LC_ALL", locale),
                None => command.env_remove("LC_ALL"),
            };
            let child = command
                .args(["-c", BATCH_SHELL])
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .spawn()
                .unwrap();
            let output =
                crate::connection::pipe_stdin_and_wait(child, batch::render(&refs).as_bytes())
                    .await
                    .unwrap();
            let answers = batch::read(Lane::Login, &refs, &output.stdout);
            let own = caller.unwrap_or("unset");
            assert_eq!(
                answers,
                [finished(0, own.as_bytes(), b""), finished(0, b"C", b"")],
                "{name}: {caller:?}"
            );
        }
    }
}

/// A command that reads its stdin reads nothing — not the unread tail of a batch past
/// 100 KiB — and every probe after it is still answered.
#[tokio::test]
async fn a_stdin_reading_command_cannot_swallow_a_large_batch() {
    let dir = tempfile::tempdir().unwrap();
    let filler = format!(": '{}'", "x".repeat(150 * 1024));
    let queries = [
        operator("wc -c", 60),
        operator(&filler, 60),
        operator("echo last", 60),
    ];
    let refs: Vec<&Query> = queries.iter().collect();
    assert!(batch::render(&refs).len() > 100 * 1024);
    for (name, shell, path) in test_shells(dir.path(), &["wc"], None) {
        let answers = run_all(&shell, path.as_ref(), &refs).await;
        let Ok(Observation::Command(counted)) = &answers[0] else {
            panic!("{name}: {:?}", answers[0]);
        };
        assert_eq!(
            String::from_utf8_lossy(&counted.stdout).trim(),
            "0",
            "{name}"
        );
        assert_eq!(answers[1], finished(0, b"", b""), "{name}");
        assert_eq!(answers[2], finished(0, b"last\n", b""), "{name}");
    }
}

/// While a command runs, its text — and a value in it — is on no process's argv: the
/// batch travels on stdin and each probe's text to its shell over a pipe, so only the
/// commands it runs show their own arguments.
#[tokio::test]
async fn a_command_text_is_on_no_argv_while_it_runs() {
    let dir = tempfile::tempdir().unwrap();
    // Made at run time, so no other process's argv (the test runner's own, say) holds it.
    let sentinel = format!(
        "zap-argv-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    let probe = operator(
        &format!("s='{sentinel}'; ZAP_ENV_VALUE='{sentinel}-env' sleep 1; test -n \"$s\""),
        60,
    );
    for (name, shell, path) in test_shells(dir.path(), &[], None) {
        let run = run_one(&shell, path.as_ref(), &probe);
        tokio::pin!(run);
        let mut seen = Vec::new();
        let answer = loop {
            tokio::select! {
                answer = &mut run => break answer,
                () = tokio::time::sleep(Duration::from_millis(50)) => {
                    for entry in std::fs::read_dir("/proc").unwrap().flatten() {
                        let cmdline = std::fs::read(entry.path().join("cmdline")).unwrap_or_default();
                        if String::from_utf8_lossy(&cmdline).contains(&sentinel) {
                            seen.push(String::from_utf8_lossy(&cmdline).replace('\0', " "));
                        }
                    }
                }
            }
        };
        assert_eq!(answer, finished(0, b"", b""), "{name}");
        assert!(seen.is_empty(), "{name}: on an argv: {seen:?}");
    }
}

/// The batch shell prints nothing on its own stderr — which a runner reads back only
/// as a failed `ssh`'s diagnostics — whatever a command does: its stderr, and the
/// error its shell reports for text that doesn't parse, are framed into its record.
#[tokio::test]
async fn nothing_reaches_the_batch_shells_own_stderr() {
    let dir = tempfile::tempdir().unwrap();
    let queries = [
        operator("echo zap-stderr-sentinel >&2", 60),
        operator("if zap-syntax-sentinel; then", 60),
        operator("(sleep 0.1; echo zap-late-sentinel >&2) &", 60),
    ];
    let refs: Vec<&Query> = queries.iter().collect();
    for (name, shell, path) in test_shells(dir.path(), &[], None) {
        let mut command = tokio::process::Command::new(&shell);
        if let Some(path) = &path {
            command.env("PATH", path);
        }
        let child = command
            .args(["-c", BATCH_SHELL])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        let output = crate::connection::pipe_stdin_and_wait(child, batch::render(&refs).as_bytes())
            .await
            .unwrap();
        assert!(output.status.success(), "{name}");
        assert_eq!(
            String::from_utf8_lossy(&output.stderr),
            "",
            "{name}: the batch shell's own stderr"
        );
        let answers = batch::read(Lane::Login, &refs, &output.stdout);
        let stderr = |index: usize| match &answers[index] {
            Ok(Observation::Command(observed)) => {
                String::from_utf8_lossy(&observed.stderr).into_owned()
            }
            other => panic!("{name}: {other:?}"),
        };
        assert!(stderr(0).contains("zap-stderr-sentinel"), "{name}");
        assert!(
            stderr(1).contains("then") || !stderr(1).is_empty(),
            "{name}"
        );
        assert!(stderr(2).contains("zap-late-sentinel"), "{name}");
    }
}
