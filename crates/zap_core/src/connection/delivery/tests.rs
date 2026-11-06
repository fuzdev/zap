//! The delivery against real shells: the system `sh` through [`Connection::Local`]
//! itself, and `BusyBox` `ash` with only its applets on `PATH` (when installed).

use std::ffi::OsString;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};
use std::process::Output;
use std::time::Duration;

use super::{COMMAND_SHELL, DETACH, Delivery, UNSET, ssh_remote_arg};
use crate::connection::{Connection, RunOptions, SshConnection};

/// The wrapper's exit status for a stdin that isn't a whole frame.
const FRAME_EXIT: i32 = 98;

/// A shell a delivery runs under.
enum Shell {
    /// The system `sh`, through `Connection::Local`'s own methods.
    System,
    /// `BusyBox` `ash`, with this directory of its applets as the whole `PATH`.
    BusyBox(PathBuf),
}

/// The system shell, and `BusyBox` when it is installed — its applets (`extra` among
/// them) linked into `dir`.
fn shells(dir: &Path, extra: &[&str]) -> Vec<(&'static str, Shell)> {
    let mut shells = vec![("sh", Shell::System)];
    let busybox = std::env::var_os("PATH").and_then(|path| {
        std::env::split_paths(&path)
            .map(|dir| dir.join("busybox"))
            .find(|candidate| candidate.is_file())
    });
    if let Some(busybox) = busybox {
        let applets = dir.join("busybox-applets");
        std::fs::create_dir(&applets).unwrap();
        for applet in std::iter::once(&"sh").chain(extra) {
            symlink(&busybox, applets.join(applet)).unwrap();
        }
        shells.push(("busybox", Shell::BusyBox(applets)));
    }
    shells
}

/// What a finished command reported.
#[derive(Debug, PartialEq, Eq)]
struct Ran {
    code: i32,
    stdout: String,
    stderr: String,
}

impl From<Output> for Ran {
    fn from(output: Output) -> Self {
        Self {
            code: output.status.code().unwrap_or(-1),
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        }
    }
}

/// Run `script` under `shell` with `options`, and `payload` as its commands' stdin.
async fn run(shell: &Shell, script: &str, options: &RunOptions, payload: Option<&[u8]>) -> Ran {
    match shell {
        Shell::System => {
            let output = match payload {
                None => Connection::Local.run(script, options).await.unwrap(),
                Some(payload) => {
                    assert!(options.cwd.is_none() && options.env.is_empty());
                    Connection::Local
                        .run_with_stdin(script, payload)
                        .await
                        .unwrap()
                }
            };
            Ran {
                code: output.code,
                stdout: output.stdout,
                stderr: output.stderr,
            }
        }
        Shell::BusyBox(applets) => {
            let delivery = Delivery::of(script, payload).unwrap();
            let mut command = delivery.local_command(applets.join("sh"), options);
            command.env("PATH", applets);
            delivery.run(command).await.unwrap().into()
        }
    }
}

/// A string made at run time, so no other process's argv (the test runner's own, say)
/// holds it.
fn sentinel(label: &str) -> String {
    format!(
        "zap-{label}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    )
}

/// Every argv on this machine that holds `needle`, right now.
fn argvs_holding(needle: &str) -> Vec<String> {
    std::fs::read_dir("/proc")
        .unwrap()
        .flatten()
        .filter_map(|entry| std::fs::read(entry.path().join("cmdline")).ok())
        .map(|cmdline| String::from_utf8_lossy(&cmdline).replace('\0', " "))
        .filter(|cmdline| cmdline.contains(needle))
        .collect()
}

/// Bytes of every value, in an order no script could be mistaken for, `len` long.
fn noise(len: usize) -> Vec<u8> {
    let mut state = 0x2545_f491_u32;
    (0..len)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            state.to_le_bytes()[0]
        })
        .collect()
}

/// While a command runs, its text, an `env` value, and its `cwd` are on no process's
/// argv — with and without a stdin payload.
#[tokio::test]
async fn a_commands_text_env_and_cwd_are_on_no_argv_while_it_runs() {
    let dir = tempfile::tempdir().unwrap();
    let sentinel = sentinel("argv");
    let cwd = dir.path().join(format!("{sentinel}-cwd"));
    std::fs::create_dir(&cwd).unwrap();
    let script = format!(
        "s='{sentinel}-text'; cat >/dev/null; sleep 1; test -n \"$s\" && \
         test \"$ZAP_DELIVERED\" = '{sentinel}-env' && test \"${{PWD##*/}}\" = '{sentinel}-cwd'"
    );
    let with_env = RunOptions {
        cwd: Some(cwd),
        env: vec![("ZAP_DELIVERED".to_owned(), format!("{sentinel}-env"))],
    };
    // A payload rides the bare command (no `cwd` / `env`), so that leg checks the text.
    let with_payload = format!("s='{sentinel}-text'; cat >/dev/null; sleep 1; test -n \"$s\"");
    for (name, shell) in shells(dir.path(), &["sleep", "cat"]) {
        for (script, options, payload) in [
            (&script, &with_env, None),
            (&with_payload, &RunOptions::default(), Some(&b"payload"[..])),
        ] {
            let running = run(&shell, script, options, payload);
            tokio::pin!(running);
            let mut seen = Vec::new();
            let ran = loop {
                tokio::select! {
                    ran = &mut running => break ran,
                    () = tokio::time::sleep(Duration::from_millis(50)) => {
                        seen.extend(argvs_holding(&sentinel));
                    }
                }
            };
            assert_eq!(ran.code, 0, "{name}: {ran:?}");
            assert!(seen.is_empty(), "{name}: on an argv: {seen:?}");
        }
    }
}

/// A command's stdout, stderr, and exit status come back as it left them — across a
/// script of several lines, a here-document at its end, and trailing newlines.
#[tokio::test]
async fn stdout_stderr_and_the_exit_status_round_trip() {
    let dir = tempfile::tempdir().unwrap();
    let none = RunOptions::default();
    for (name, shell) in shells(dir.path(), &["cat"]) {
        let ran = run(&shell, "printf out; printf err >&2; exit 7", &none, None).await;
        assert_eq!(
            (ran.code, ran.stdout.as_str(), ran.stderr.as_str()),
            (7, "out", "err"),
            "{name}"
        );
        let ran = run(&shell, "a=1\nb=2\necho \"$a $b\"\n\n", &none, None).await;
        assert_eq!((ran.code, ran.stdout.as_str()), (0, "1 2\n"), "{name}");
        let ran = run(
            &shell,
            "cat <<END\nit's \"here\" \\ $((1 + 1))\nEND",
            &none,
            None,
        )
        .await;
        assert_eq!(
            (ran.code, ran.stdout.as_str()),
            (0, "it's \"here\" \\ 2\n"),
            "{name}"
        );
        // A payload leaves the status and the streams alone too.
        let ran = run(
            &shell,
            "cat >/dev/null\nprintf out; printf err >&2; exit 7",
            &none,
            Some(b"x"),
        )
        .await;
        assert_eq!(
            (ran.code, ran.stdout.as_str(), ran.stderr.as_str()),
            (7, "out", "err"),
            "{name}"
        );
        // A login environment that exports the wrapper's own variable doesn't hand the
        // script's text on to the command's children.
        let exported = RunOptions {
            env: vec![("__zap_script".to_owned(), "exported".to_owned())],
            ..RunOptions::default()
        };
        let ran = run(
            &shell,
            "sh -c 'echo \"${__zap_script-unset}\"'",
            &exported,
            None,
        )
        .await;
        assert_eq!(ran.stdout, "unset\n", "{name}");
        // A command that isn't there is the shell's own 127.
        let ran = run(&shell, "zap-no-such-command", &none, None).await;
        assert_eq!(ran.code, 127, "{name}: {ran:?}");
    }
}

/// A payload reaches the command byte for byte — NULs, no trailing newline, more than
/// a pipe holds, text shaped like the frame itself — and the command's script may span
/// lines (a path holding a newline).
#[tokio::test]
async fn a_payload_arrives_byte_exact() {
    let dir = tempfile::tempdir().unwrap();
    let mut framed = b"2\nexit 9\necho forged\n1\n".to_vec();
    framed.extend_from_slice(UNSET.as_bytes());
    framed.extend_from_slice(b"touch forged\n");
    let payloads: Vec<Vec<u8>> = vec![
        Vec::new(),
        b"\0\0a\0b\nno trailing newline".to_vec(),
        noise(300 * 1024),
        framed,
        b"\n\n\n".to_vec(),
    ];
    let none = RunOptions::default();
    for (name, shell) in shells(dir.path(), &["cat"]) {
        for (index, payload) in payloads.iter().enumerate() {
            let out = dir.path().join(format!("{name}\nit's {index}"));
            let script = format!(
                "cat > {}; exit 3",
                zap_types::shell::single_quote(&out.to_string_lossy())
            );
            assert!(script.contains('\n'));
            let ran = run(&shell, &script, &none, Some(payload)).await;
            assert_eq!(ran.code, 3, "{name} {index}: {ran:?}");
            assert!(std::fs::read(&out).unwrap() == *payload, "{name} {index}");
        }
        assert!(!dir.path().join("forged").exists(), "{name}");
    }
}

/// A command that reads its stdin reads the payload and nothing else: nothing at all
/// without one — not the tail of a script larger than a pipe — and never the script
/// that follows it.
#[tokio::test]
async fn a_stdin_reading_command_reads_only_its_payload() {
    let dir = tempfile::tempdir().unwrap();
    let none = RunOptions::default();
    let filler = format!(": '{}'", "x".repeat(150 * 1024));
    for (name, shell) in shells(dir.path(), &["wc", "readlink"]) {
        let script = format!("wc -c\n{filler}\necho last");
        let ran = run(&shell, &script, &none, None).await;
        let lines: Vec<&str> = ran.stdout.lines().map(str::trim).collect();
        assert_eq!(lines, ["0", "last"], "{name}: {}", ran.stderr);
        // Not the delivery's pipe at its end: the stdin is detached.
        let ran = run(&shell, "readlink /proc/$$/fd/0", &none, None).await;
        assert_eq!(ran.stdout.trim(), "/dev/null", "{name}: {}", ran.stderr);

        let ran = run(&shell, &script, &none, Some(&noise(70_000))).await;
        let lines: Vec<&str> = ran.stdout.lines().map(str::trim).collect();
        assert_eq!(lines, ["70000", "last"], "{name}: {}", ran.stderr);
    }
}

/// Start `shell` on the wrapper with exactly `stdin`, in `dir`, and return its status.
async fn feed(shell: &Shell, dir: &Path, stdin: &[u8]) -> Option<i32> {
    let program: OsString = match shell {
        Shell::System => "sh".into(),
        Shell::BusyBox(applets) => applets.join("sh").into(),
    };
    let delivery = Delivery {
        wrapper: COMMAND_SHELL,
        stdin: stdin.to_vec(),
    };
    let mut command = tokio::process::Command::new(&program);
    command.args(["-c", COMMAND_SHELL]).current_dir(dir);
    if let Shell::BusyBox(applets) = shell {
        command.env("PATH", applets);
    }
    delivery.run(command).await.unwrap().status.code()
}

/// A stdin that isn't a whole frame runs none of it and exits the frame status: no
/// count, a zero or negative one, one too long to be a count (which a shell's integer
/// test would choke on), a count past the script's end, a count with no newline, nothing.
#[tokio::test]
async fn a_stream_that_is_not_a_frame_runs_nothing() {
    let dir = tempfile::tempdir().unwrap();
    for (name, shell) in shells(dir.path(), &["touch"]) {
        for stdin in [
            "touch ran\n",
            "x\ntouch ran\n",
            "\ntouch ran\n",
            "0\ntouch ran\n",
            "00\ntouch ran\n",
            "01\ntouch ran\n",
            "010\ntouch ran\n",
            "+1\ntouch ran\n",
            " 1\ntouch ran\n",
            "1 \ntouch ran\n",
            "1\t\ntouch ran\n",
            "1\r\ntouch ran\n",
            "0x1\ntouch ran\n",
            "-1\ntouch ran\n",
            "1x\ntouch ran\n",
            "1 -o 1\ntouch ran\n",
            "1234567890\ntouch ran\n",
            "00000000000000000000000001\ntouch ran\n",
            "99999999999999999999999999\ntouch ran\n",
            "3\ntouch ran\n",
            "1\ntouch ran",
            "1",
            "",
        ] {
            assert_eq!(
                feed(&shell, dir.path(), stdin.as_bytes()).await,
                Some(FRAME_EXIT),
                "{name}: {stdin:?}"
            );
            assert!(!dir.path().join("ran").exists(), "{name}: {stdin:?}");
        }
        // The same shell and tools do run a whole frame — with no `cat` on the path.
        assert_eq!(
            feed(&shell, dir.path(), b"1\ntouch ran\n").await,
            Some(0),
            "{name}"
        );
        assert!(dir.path().join("ran").exists(), "{name}");
        std::fs::remove_file(dir.path().join("ran")).unwrap();
    }
}

/// A command is never run in part: a real delivery's stdin cut anywhere before its end
/// exits the frame status with nothing run — whichever line the cut falls in — and the
/// whole of it runs every line.
#[tokio::test]
async fn a_truncated_command_runs_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let whole = Delivery::of("touch first\ntouch second\ntouch third", None)
        .unwrap()
        .stdin;
    for (name, shell) in shells(dir.path(), &["touch"]) {
        for cut in 0..whole.len() {
            assert_eq!(
                feed(&shell, dir.path(), &whole[..cut]).await,
                Some(FRAME_EXIT),
                "{name}: cut at {cut}"
            );
            for made in ["first", "second", "third"] {
                assert!(!dir.path().join(made).exists(), "{name}: cut at {cut}");
            }
        }
        assert_eq!(feed(&shell, dir.path(), &whole).await, Some(0), "{name}");
        for made in ["first", "second", "third"] {
            std::fs::remove_file(dir.path().join(made)).unwrap();
        }
    }
}

/// What a push sends over SSH is the put command with **no** `sudo` — it runs as the
/// connecting user — framed, then the content's digest as a line, then the content, and
/// nothing of either on the `ssh` argv.
#[tokio::test]
async fn an_ssh_push_sends_the_put_as_the_connecting_user() {
    use zap_types::put::{FileAttrs, PutCheck, RunAs, file_put_command};

    use crate::connection::ssh::test_client::{self, Remote};

    let dir = tempfile::tempdir().unwrap();
    let client = test_client::set(dir.path(), Remote::Record);
    let conn = Connection::Ssh(ssh_target());
    let content = b"\0release archive bytes, no newline at the end";
    let attrs = FileAttrs::mode("600");
    let remote = "/srv/it's an app/.zap-deploy-deploy-abc1234.tar.gz";
    let digest = crate::digest::sha512_hex(content);
    let script = file_put_command(RunAs::Caller, remote, attrs, PutCheck::None);
    assert!(script.starts_with("sh -c '") && script.ends_with("' '600' '' '' ''"));
    let mut payload = format!("{digest}\n").into_bytes();
    payload.extend_from_slice(content);

    conn.push_bytes(remote, content, attrs).await.unwrap();
    assert_eq!(
        client.stdin(),
        Delivery::of(&script, Some(&payload)).unwrap().stdin
    );
    assert!(!client.argv().contains(&digest) && !client.argv().contains("sudo"));
}

/// What a write sends over SSH is the put command under `sudo`, framed, then the
/// content's digest as a line, then the content — and nothing of either on the `ssh`
/// argv. A place sends the same for a file's bytes.
#[tokio::test]
async fn an_ssh_write_sends_the_put_then_the_digest_line_then_the_bytes() {
    use zap_types::put::{FileAttrs, PutCheck, RunAs, file_put_command};

    use crate::connection::ssh::test_client::{self, Remote};

    let dir = tempfile::tempdir().unwrap();
    let client = test_client::set(dir.path(), Remote::Record);
    let conn = Connection::Ssh(ssh_target());
    let secret = sentinel("ssh-write");
    let content = format!("TOKEN={secret}\0\nno newline at the end");
    let attrs = FileAttrs {
        mode: Some("600"),
        owner: Some("app"),
        group: Some("www"),
        ..FileAttrs::NONE
    };
    let digest = crate::digest::sha512_hex(content.as_bytes());
    let expected = |path: &str| {
        let script = file_put_command(RunAs::Root, path, attrs, PutCheck::None);
        assert!(script.starts_with("sudo sh -c '") && script.ends_with("' '600' 'app:www' '' ''"));
        let mut payload = format!("{digest}\n").into_bytes();
        payload.extend_from_slice(content.as_bytes());
        Delivery::of(&script, Some(&payload)).unwrap().stdin
    };

    conn.write_bytes("/srv/app/.env", content.as_bytes(), attrs)
        .await
        .unwrap();
    assert_eq!(client.stdin(), expected("/srv/app/.env"));
    assert!(!client.argv().contains(&secret) && !client.argv().contains(&digest));

    let local = dir.path().join("artifact");
    std::fs::write(&local, &content).unwrap();
    conn.place_file(&local, "/opt/it's/tool", attrs)
        .await
        .unwrap();
    assert_eq!(client.stdin(), expected("/opt/it's/tool"));
    assert!(!client.argv().contains(&secret) && !client.argv().contains(&digest));
}

/// The applets the put script runs, for the `BusyBox` leg.
const PUT_APPLETS: &[&str] = &[
    "cat",
    "sha512sum",
    "mktemp",
    "rm",
    "chmod",
    "chown",
    "sync",
    "stat",
    "mv",
    "id",
    "ls",
];

/// A delivered put — the script, then a payload of the digest line and `content`.
fn put_delivery(path: &Path, content: &[u8]) -> (Delivery, usize) {
    use zap_types::put::{FileAttrs, PutCheck, RunAs, file_put_command};

    let script = file_put_command(
        RunAs::Caller,
        &path.to_string_lossy(),
        FileAttrs::mode("600"),
        PutCheck::None,
    );
    let mut payload = format!("{}\n", crate::digest::sha512_hex(content)).into_bytes();
    payload.extend_from_slice(content);
    let delivery = Delivery::of(&script, Some(&payload)).unwrap();
    let frame = delivery.stdin.len() - payload.len();
    (delivery, frame)
}

/// A file write is all or nothing wherever its stream is cut: in the count or the script
/// nothing runs (the frame status); in the digest line or the content the put runs and
/// refuses. Either way the file is as it was and no staged file is left — only the whole
/// stream installs.
#[tokio::test]
async fn a_put_cut_anywhere_installs_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let content = b"TOKEN=one\nNEXT=two";
    for (name, shell) in shells(dir.path(), PUT_APPLETS) {
        let case = tempfile::tempdir_in(dir.path()).unwrap();
        let conf = case.path().join("app.env");
        std::fs::write(&conf, "OLD").unwrap();
        let (delivery, frame) = put_delivery(&conf, content);
        let whole = delivery.stdin;
        let digest_end = frame + 129;
        // Every region: the count, the script (sampled, and its ends), the digest line
        // (sampled, and its ends), and every byte of the content.
        let cuts = (0..4)
            .chain((4..frame).step_by(41))
            .chain(frame - 2..frame + 3)
            .chain((frame + 3..digest_end - 2).step_by(11))
            .chain(digest_end - 2..whole.len());
        for cut in cuts {
            let code = feed(&shell, dir.path(), &whole[..cut]).await;
            if cut < frame {
                assert_eq!(code, Some(FRAME_EXIT), "{name}: cut at {cut}");
            } else {
                assert!(
                    matches!(code, Some(code) if code != 0 && code != FRAME_EXIT),
                    "{name}: cut at {cut}: {code:?}"
                );
            }
            assert_eq!(
                std::fs::read(&conf).unwrap(),
                b"OLD",
                "{name}: cut at {cut}"
            );
            assert_eq!(
                std::fs::read_dir(case.path()).unwrap().count(),
                1,
                "{name}: cut at {cut}: a staged file is left"
            );
        }
        assert_eq!(feed(&shell, dir.path(), &whole).await, Some(0), "{name}");
        assert_eq!(std::fs::read(&conf).unwrap(), content, "{name}");
        assert_eq!(std::fs::read_dir(case.path()).unwrap().count(), 1, "{name}");
    }
}

/// While a put is under way — its content half arrived — neither the content nor its
/// digest is on any process's argv.
#[tokio::test]
async fn a_puts_content_and_digest_are_on_no_argv_while_it_runs() {
    use tokio::io::AsyncWriteExt as _;

    let dir = tempfile::tempdir().unwrap();
    let secret = sentinel("put");
    let content = format!("TOKEN={secret}\n{}", "x".repeat(4096));
    let digest = crate::digest::sha512_hex(content.as_bytes());
    for (name, shell) in shells(dir.path(), PUT_APPLETS) {
        let conf = dir.path().join(format!("{name}.env"));
        let (delivery, frame) = put_delivery(&conf, content.as_bytes());
        let program: OsString = match &shell {
            Shell::System => "sh".into(),
            Shell::BusyBox(applets) => applets.join("sh").into(),
        };
        let mut command = tokio::process::Command::new(&program);
        command
            .args(["-c", COMMAND_SHELL])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());
        if let Shell::BusyBox(applets) = &shell {
            command.env("PATH", applets);
        }
        let mut child = command.spawn().unwrap();
        let mut stdin = child.stdin.take().unwrap();
        // The script, the digest, and the secret's line — then hold the stream open, so
        // the put is waiting on the rest.
        let held = frame + 129 + secret.len() + 16;
        stdin.write_all(&delivery.stdin[..held]).await.unwrap();
        stdin.flush().await.unwrap();
        let started = || {
            std::fs::read_dir(dir.path())
                .unwrap()
                .flatten()
                .any(|entry| entry.file_name().to_string_lossy().starts_with(".zap."))
        };
        // poll until the put's temp file exists, so a loaded machine can't outrun a
        // fixed wait, then read the argvs a few more times while the stream is held
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        let mut seen = Vec::new();
        let mut after = 0;
        while after < 4 {
            tokio::time::sleep(Duration::from_millis(20)).await;
            seen.extend(argvs_holding(&secret));
            seen.extend(argvs_holding(&digest));
            if started() {
                after += 1;
            } else {
                assert!(
                    std::time::Instant::now() < deadline,
                    "{name}: the put never got under way"
                );
            }
        }
        stdin.write_all(&delivery.stdin[held..]).await.unwrap();
        drop(stdin);
        let output = child.wait_with_output().await.unwrap();
        assert!(output.status.success(), "{name}: {output:?}");
        assert!(seen.is_empty(), "{name}: on an argv: {seen:?}");
        assert_eq!(std::fs::read(&conf).unwrap(), content.as_bytes(), "{name}");
        let said = String::from_utf8_lossy(&output.stderr);
        assert!(
            !said.contains(&secret) && !said.contains(&digest),
            "{name}: {said}"
        );
    }
}

/// A script holding a reference delimiter — a whole marker, or half of one — is refused
/// where a delivery is built, whoever builds it: every reference is resolved before a
/// script is delivered, so one still there names nothing a shell could read. A payload
/// may hold one.
#[test]
fn a_script_holding_a_reference_delimiter_is_refused() {
    use zap_types::var_ref::{CLOSE, OPEN, marker};

    for script in [
        format!("echo {}", marker("ZAP_T_UNRESOLVED")),
        format!("echo {OPEN}"),
        format!("echo {CLOSE}"),
    ] {
        for payload in [None, Some(b"x".as_slice())] {
            let error = Delivery::of(&script, payload).unwrap_err();
            assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
            assert!(
                error.to_string()
                    == "the command holds a reference delimiter (U+FDD0 or U+FDD1) — an \
                        unresolved reference, or a value containing one — which no shell \
                        can read; it was not run",
                "{error}"
            );
        }
    }
    assert!(Delivery::of("cat", Some(marker("ZAP_T_UNRESOLVED").as_bytes())).is_ok());
}

/// A script holding a NUL is refused — a shell would drop the byte and run different
/// text — as an error, on the local arm too; a payload may hold one.
#[tokio::test]
async fn a_script_holding_a_nul_is_refused() {
    let error = Delivery::of("tee '/srv/a\0b/x'", None).unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
    let error = Delivery::of("tee '/srv/a\0b/x'", Some(b"x")).unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
    assert!(Delivery::of("cat", Some(b"a\0b")).is_ok());

    let dir = tempfile::tempdir().unwrap();
    let made = dir.path().join("made");
    let script = format!("touch '{}' '\0'", made.display());
    for ran in [
        Connection::Local.run_default(&script).await.map(|_| ()),
        Connection::Local.run_raw_stdout(&script).await.map(|_| ()),
        Connection::Local
            .run_with_stdin(&script, b"x")
            .await
            .map(|_| ()),
    ] {
        assert!(
            matches!(ran, Err(crate::error::Error::Command(_))),
            "{ran:?}"
        );
    }
    assert!(!made.exists());

    // Over SSH too it is an error, not a failed run a caller could read as a finding —
    // and nothing reaches the client.
    let client = crate::connection::ssh::test_client::set(
        dir.path(),
        crate::connection::ssh::test_client::Remote::Run,
    );
    let ssh = ssh_target();
    let none = RunOptions::default();
    assert!(matches!(
        ssh.run(&script, &none).await,
        Err(crate::error::Error::Command(_))
    ));
    assert!(matches!(
        ssh.run_with_stdin(&script, b"x").await,
        Err(crate::error::Error::Command(_))
    ));
    assert!(matches!(
        ssh.run_raw_stdout(&script).await,
        Err(crate::error::Error::Command(_))
    ));
    assert!(matches!(
        Connection::Ssh(ssh_target()).exists("/srv/a\0b").await,
        Err(crate::error::Error::Command(_))
    ));
    assert!(!made.exists());
    assert!(!dir.path().join("ssh.sh.argv").exists());
    drop(client);
}

/// A remote command's `env` reaches every command of a compound, as a local command's
/// does, and a `cwd` that can't be entered runs none of it — the composed script, under
/// both shells.
#[tokio::test]
async fn a_remote_commands_env_covers_the_whole_command() {
    let dir = tempfile::tempdir().unwrap();
    let none = RunOptions::default();
    let print = "sh -c 'printf \"%s,\" \"$ZAP_GIVEN\"'";
    let compound = format!("{print} && {print}; {print}");
    // A relative `cwd`, and a `CDPATH` in the `env` that would lead a `cd` elsewhere: the
    // `env` is exported after the `cd`, so it can't steer it.
    let from = RunOptions {
        cwd: Some(dir.path().to_path_buf()),
        ..RunOptions::default()
    };
    let elsewhere = dir.path().join("elsewhere");
    std::fs::create_dir_all(elsewhere.join("it's here")).unwrap();
    std::fs::create_dir(dir.path().join("it's here")).unwrap();
    std::fs::write(dir.path().join("it's here/marker"), "").unwrap();
    let options = RunOptions {
        cwd: Some("it's here".into()),
        env: vec![
            ("ZAP_GIVEN".to_owned(), "it's v".to_owned()),
            (
                "CDPATH".to_owned(),
                elsewhere.to_string_lossy().into_owned(),
            ),
        ],
    };
    let script = SshConnection::wrap_remote(&format!("{compound}; test -f marker"), &options);
    let gone = RunOptions {
        cwd: Some(dir.path().join("gone")),
        ..RunOptions::default()
    };
    let unentered = SshConnection::wrap_remote("echo ran; echo ran again", &gone);
    for (name, shell) in shells(dir.path(), &[]) {
        let ran = run(&shell, &script, &from, None).await;
        assert_eq!(
            (ran.code, ran.stdout.as_str()),
            (0, "it's v,it's v,it's v,"),
            "{name}: {}",
            ran.stderr
        );
        let ran = run(&shell, &unentered, &none, None).await;
        assert_ne!(ran.code, 0, "{name}");
        assert_eq!(ran.stdout, "", "{name}");
    }
}

/// A delivered command stays in the caller's session and process group, so a `sudo` in
/// it can prompt on the terminal zap runs in (a background group would be stopped on
/// the read).
#[tokio::test]
async fn a_local_command_stays_in_the_callers_process_group() {
    let ran = Connection::Local
        .run_default("cut -d' ' -f5,6 /proc/$$/stat")
        .await
        .unwrap();
    let own = std::fs::read_to_string("/proc/self/stat").unwrap();
    let own: Vec<&str> = own.rsplit_once(')').unwrap().1.split_whitespace().collect();
    assert_eq!(ran.stdout.trim(), format!("{} {}", own[2], own[3]));
}

fn ssh_target() -> SshConnection {
    SshConnection {
        host: "host.example".to_owned(),
        user: "ops".to_owned(),
        port: Some(2222),
        key_path: Some("/k/id".to_owned()),
        home: None,
    }
}

/// The `ssh` argv is the transport options, the target, and the constant wrapper,
/// whatever the command, its `env`, its `cwd`, or its payload — all of which are in the
/// stdin instead.
#[test]
fn the_ssh_argv_is_constant_whatever_the_command() {
    let ssh = ssh_target();
    let sentinel = sentinel("ssh");
    let options = RunOptions {
        cwd: Some(format!("/srv/{sentinel}-cwd").into()),
        env: vec![("TOKEN".to_owned(), format!("{sentinel}-env"))],
    };
    let script = SshConnection::wrap_remote(&format!("deploy '{sentinel}-text'"), &options);
    for part in ["-text", "-env", "-cwd"] {
        assert!(script.contains(&format!("{sentinel}{part}")), "{script}");
    }
    let argv = |delivery: &Delivery| -> Vec<String> {
        let command = ssh.delivery_command(delivery);
        assert_eq!(command.as_std().get_program(), "ssh");
        command
            .as_std()
            .get_args()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect()
    };
    let constant = |wrapper: &str| {
        let mut args = ssh.ssh_args();
        args.push(format!("sh -c '{wrapper}'"));
        args
    };

    let plain = Delivery::of(&script, None).unwrap();
    assert_eq!(argv(&plain), constant(COMMAND_SHELL));
    assert_eq!(
        argv(&Delivery::of("true", None).unwrap()),
        constant(COMMAND_SHELL)
    );
    let stdin = String::from_utf8(plain.stdin).unwrap();
    // The run context is a line of its own, ahead of the command's.
    assert_eq!(script.lines().count(), 2);
    assert_eq!(stdin, format!("2\n{UNSET}{DETACH}{script}\n"));

    let payload = format!("{sentinel}-payload");
    let framed = Delivery::of(&script, Some(payload.as_bytes())).unwrap();
    assert_eq!(argv(&framed), constant(COMMAND_SHELL));
    assert_eq!(
        String::from_utf8(framed.stdin).unwrap(),
        format!("2\n{UNSET}{script}\n{payload}")
    );
    let args = constant(COMMAND_SHELL);
    assert!(!args.iter().any(|arg| arg.contains(&sentinel)), "{args:?}");
}

/// The wrapper is one line and holds no single quote, backslash, or `!`, so the one
/// quoted word of the remote command reads the same to a `fish` login shell as to a
/// POSIX one (and has nothing a csh-family one would act on); and every script starts by
/// unsetting each variable the wrapper used.
#[test]
fn the_wrapper_quotes_as_one_plain_word() {
    assert!(
        !COMMAND_SHELL.contains(['\'', '\\', '!', '\n']),
        "{COMMAND_SHELL}"
    );
    assert_eq!(
        ssh_remote_arg(COMMAND_SHELL),
        format!("sh -c '{COMMAND_SHELL}'")
    );
    assert!(COMMAND_SHELL.contains(&format!("exit {FRAME_EXIT}")));
    for variable in ["__zap_script", "__zap_n", "__zap_l", "__zap_nl"] {
        assert!(UNSET.contains(&format!(" {variable}")), "{variable}");
    }
    let named: std::collections::BTreeSet<&str> = COMMAND_SHELL
        .split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .filter(|word| word.starts_with("__zap_"))
        .collect();
    let unset: std::collections::BTreeSet<&str> = UNSET
        .split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .filter(|word| word.starts_with("__zap_"))
        .collect();
    assert_eq!(named, unset);
}

/// The remote command, as the target's login shell runs it (`<shell> -c <command>`) —
/// under `sh`, and under `fish` when it is installed: the script runs, its payload
/// arrives, and its exit status comes back.
#[tokio::test]
async fn a_login_shell_runs_the_remote_command() {
    let installed = |tool: &str| {
        std::process::Command::new("sh")
            .args(["-c", &format!("command -v {tool}")])
            .output()
            .is_ok_and(|output| output.status.success())
    };
    let mut login_shells: Vec<&[&str]> = vec![&["sh"]];
    if installed("fish") {
        login_shells.push(&["fish", "--no-config"]);
    }
    let script = SshConnection::wrap_remote(
        "sh -c 'printf \"%s|\" \"$ZAP_DELIVERED\"; cat; exit 5'",
        &RunOptions {
            env: vec![("ZAP_DELIVERED".to_owned(), "it's \\ here".to_owned())],
            ..RunOptions::default()
        },
    );
    for login in login_shells {
        for (payload, printed) in [
            (None, "it's \\ here|"),
            (Some(&b"a\0b"[..]), "it's \\ here|a\0b"),
        ] {
            let delivery = Delivery::of(&script, payload).unwrap();
            let mut command = tokio::process::Command::new(login[0]);
            command
                .args(&login[1..])
                .arg("-c")
                .arg(ssh_remote_arg(delivery.wrapper));
            let output = delivery.run(command).await.unwrap();
            assert_eq!(output.status.code(), Some(5), "{login:?}");
            assert_eq!(
                String::from_utf8_lossy(&output.stdout),
                printed,
                "{login:?}"
            );
        }
    }
}

/// The script is read a line at a time: each line arrives as written — its leading and
/// trailing blanks kept.
#[tokio::test]
async fn a_framed_script_line_keeps_its_blanks() {
    let dir = tempfile::tempdir().unwrap();
    let none = RunOptions::default();
    for (name, shell) in shells(dir.path(), &["cat"]) {
        let ran = run(
            &shell,
            "cat >/dev/null; printf '%s|' 'a\n  \tb \t \n'",
            &none,
            Some(b"x"),
        )
        .await;
        assert_eq!(
            (ran.code, ran.stdout.as_str()),
            (0, "a\n  \tb \t \n|"),
            "{name}: {ran:?}"
        );
    }
}

/// A login environment that exports any of the wrapper's variables doesn't hand the
/// script's text on to the command's children — with a payload or without.
#[tokio::test]
async fn no_wrapper_variable_reaches_a_commands_children() {
    let dir = tempfile::tempdir().unwrap();
    let exported = RunOptions {
        env: ["__zap_script", "__zap_n", "__zap_l", "__zap_nl"]
            .iter()
            .map(|name| ((*name).to_owned(), "exported".to_owned()))
            .collect(),
        ..RunOptions::default()
    };
    let script = "cat >/dev/null\nsh -c 'echo \"${__zap_script-unset} ${__zap_n-unset} ${__zap_l-unset} ${__zap_nl-unset}\"'";
    for (name, shell) in shells(dir.path(), &["cat"]) {
        for payload in [None, Some(&b"x"[..])] {
            let delivery = Delivery::of(script, payload).unwrap();
            let program: OsString = match &shell {
                Shell::System => "sh".into(),
                Shell::BusyBox(applets) => applets.join("sh").into(),
            };
            let mut command = delivery.local_command(program, &exported);
            if let Shell::BusyBox(applets) = &shell {
                command.env("PATH", applets);
            }
            let ran: Ran = delivery.run(command).await.unwrap().into();
            assert_eq!(
                ran.stdout, "unset unset unset unset\n",
                "{name} {payload:?}"
            );
        }
    }
}

/// A command that writes more than a pipe holds before it reads its payload — itself
/// more than a pipe holds — finishes: the payload is written while the output is read.
#[tokio::test]
async fn output_ahead_of_a_large_payload_does_not_deadlock() {
    let dir = tempfile::tempdir().unwrap();
    let none = RunOptions::default();
    let payload = noise(300 * 1024);
    for (name, shell) in shells(dir.path(), &["head", "wc"]) {
        let ran = tokio::time::timeout(
            Duration::from_secs(30),
            run(
                &shell,
                "head -c 300000 /dev/zero; wc -c >&2",
                &none,
                Some(&payload),
            ),
        )
        .await
        .unwrap_or_else(|_| panic!("{name}: deadlocked"));
        assert_eq!(ran.code, 0, "{name}");
        assert_eq!(ran.stdout.len(), 300_000, "{name}");
        assert_eq!(ran.stderr.trim(), (300 * 1024).to_string(), "{name}");
    }
}

/// Every way the SSH connection runs a command goes through the delivery:
/// against a stand-in `ssh` that runs the remote command as a login shell would, the
/// command runs with its `cwd` and `env`, a payload arrives byte for byte, raw stdout
/// comes back exact — and none of it is on the client's argv.
#[tokio::test]
async fn the_ssh_connection_delivers_every_command() {
    use crate::connection::ssh::test_client::{self, Remote};

    let dir = tempfile::tempdir().unwrap();
    let client = test_client::set(dir.path(), Remote::Run);
    let ssh = ssh_target();
    let sentinel = sentinel("via-ssh");

    let cwd = dir.path().join(format!("{sentinel}-cwd"));
    std::fs::create_dir(&cwd).unwrap();
    let options = RunOptions {
        cwd: Some(cwd),
        env: vec![("ZAP_DELIVERED".to_owned(), format!("{sentinel}-it's env"))],
    };
    let ran = ssh
        .run(
            "sh -c 'printf \"%s|%s\" \"$ZAP_DELIVERED\" \"${PWD##*/}\"; exit 6'",
            &options,
        )
        .await
        .unwrap();
    assert_eq!(ran.code, 6, "{}", ran.stderr);
    assert_eq!(ran.stdout, format!("{sentinel}-it's env|{sentinel}-cwd"));
    assert!(!client.argv().contains(&sentinel), "{}", client.argv());

    let out = dir.path().join(format!("{sentinel}-out"));
    let payload = noise(100 * 1024);
    let ran = ssh
        .run_with_stdin(
            &format!(
                "cat > {}",
                zap_types::shell::single_quote(&out.to_string_lossy())
            ),
            &payload,
        )
        .await
        .unwrap();
    assert!(ran.success, "{}", ran.stderr);
    assert_eq!(std::fs::read(&out).unwrap(), payload);
    assert!(!client.argv().contains(&sentinel), "{}", client.argv());

    let raw = ssh
        .run_raw_stdout(&format!(
            "cat {}",
            zap_types::shell::single_quote(&out.to_string_lossy())
        ))
        .await
        .unwrap();
    assert!(raw.success && raw.stdout == payload);
    assert!(!client.argv().contains(&sentinel), "{}", client.argv());
}

/// Over SSH every read and every composed write runs under `sudo`: a root-owned target
/// may be unreadable as the login user, and a file op writes as root.
#[tokio::test]
async fn an_ssh_read_and_composed_write_run_under_sudo() {
    use crate::connection::ssh::test_client::{self, Remote};

    let dir = tempfile::tempdir().unwrap();
    let client = test_client::set(dir.path(), Remote::Record);
    let conn = Connection::Ssh(ssh_target());
    let sent = || String::from_utf8(client.stdin()).unwrap();

    let _ = conn.exists("/srv/a").await;
    assert!(
        sent().contains(
            "sudo sh -c 'if test -e \"$1\"; then echo present; else echo absent; fi' sh '/srv/a'"
        ),
        "{}",
        sent()
    );
    let _ = conn.read_bytes("/srv/b").await;
    assert!(
        sent().contains(&zap_types::put::file_bytes_command("sudo ", "/srv/b")),
        "{}",
        sent()
    );
    conn.remove_file("/srv/c").await.unwrap();
    assert!(sent().contains("sudo rm -f -- '/srv/c'"), "{}", sent());
    conn.make_symlink("/srv/target", "/srv/link").await.unwrap();
    assert!(
        sent().contains(&zap_types::put::link_put_command(
            "sudo ",
            "/srv/link",
            "/srv/target"
        )),
        "{}",
        sent()
    );
}
