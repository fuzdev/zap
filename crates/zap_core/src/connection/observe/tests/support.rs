use std::ffi::OsString;
use std::os::unix::fs::symlink;
use std::path::Path;
use std::time::Duration;

use zap_types::observe::batch::{self, BATCH_SHELL};
use zap_types::observe::{
    CommandOrigin, Lane, Observation, PathFacet, Privilege, Query, QueryResult,
};

use crate::connection::SshConnection;
use crate::connection::observe::{BatchFailure, in_order, run_lanes};

pub(super) fn path_query(path: &str, facet: PathFacet) -> Query {
    Query::Path {
        path: path.to_owned(),
        facet,
        privilege: Privilege::Login,
    }
}

/// Run one lane's script under `shell` on this machine (no sudo), with `path` as its
/// `PATH` when given.
pub(super) async fn run_under(
    shell: &Path,
    path: Option<OsString>,
    script: String,
) -> Result<Vec<u8>, BatchFailure> {
    let mut command = tokio::process::Command::new(shell);
    if let Some(path) = path {
        command.env("PATH", path);
    }
    let child = command
        .args(["-c", BATCH_SHELL])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|error| BatchFailure::Lane(error.to_string()))?;
    let output = crate::connection::pipe_stdin_and_wait(child, script.as_bytes())
        .await
        .map_err(|error| BatchFailure::Lane(error.to_string()))?;
    if output.status.success() {
        Ok(output.stdout)
    } else {
        Err(BatchFailure::Lane(format!(
            "exit {:?}",
            output.status.code()
        )))
    }
}

/// A directory of `BusyBox` applet links for every tool the batch runs, to put alone
/// on `PATH` — so the `BusyBox` leg exercises `BusyBox`'s own `stat`, `readlink`,
/// `timeout`, `od`, …, not the host's coreutils. `None` without `busybox`, and only
/// then: a link that can't be made — a name of `extra` the list already holds — is a
/// panic, never a leg left out.
pub(super) fn busybox_applets(dir: &Path, extra: &[&str]) -> Option<std::path::PathBuf> {
    let busybox = std::env::var_os("PATH").and_then(|path| {
        std::env::split_paths(&path)
            .map(|dir| dir.join("busybox"))
            .find(|candidate| candidate.is_file())
    })?;
    let applets = dir.join("busybox-applets");
    std::fs::create_dir(&applets).expect("the applet directory is made once per test");
    for applet in [
        "sh",
        "stat",
        "readlink",
        "timeout",
        "od",
        "tr",
        "head",
        "cat",
        "sha512sum",
        "setsid",
        "sleep",
    ]
    .iter()
    .chain(extra)
    {
        symlink(&busybox, applets.join(applet))
            .unwrap_or_else(|error| panic!("no applet link for {applet}: {error}"));
    }
    Some(applets)
}

/// The shells a snippet test runs under: the system `sh` with `PATH` led by `bin`
/// (when given), and `BusyBox` with only its applets — `extra` among them — then
/// `bin`, when `busybox` is installed.
pub(super) fn test_shells(
    dir: &Path,
    extra: &[&str],
    bin: Option<&Path>,
) -> Vec<(&'static str, std::path::PathBuf, Option<OsString>)> {
    let lead = |rest: Vec<std::path::PathBuf>| {
        let mut dirs: Vec<std::path::PathBuf> = bin.iter().map(|b| b.to_path_buf()).collect();
        dirs.extend(rest);
        std::env::join_paths(dirs).ok()
    };
    let system = std::env::var_os("PATH")
        .map(|path| std::env::split_paths(&path).collect())
        .unwrap_or_default();
    let mut shells = vec![("sh", "sh".into(), lead(system))];
    if let Some(applets) = busybox_applets(dir, extra) {
        shells.push(("busybox", applets.join("sh"), lead(vec![applets])));
    }
    shells
}

/// Run one query through a real batch under `shell` (no sudo, whatever its
/// privilege) and return its answer.
pub(super) async fn run_one(shell: &Path, path: Option<&OsString>, query: &Query) -> QueryResult {
    let run =
        |_lane: Lane, script: String, _deadline: Duration| run_under(shell, path.cloned(), script);
    let (answered, _, _) = run_lanes(&[(0, query, Lane::Login)], run).await;
    in_order(1, answered).remove(0)
}

/// Run `queries` as one batch under `shell` (no sudo) and read their answers.
pub(super) async fn run_all(
    shell: &Path,
    path: Option<&OsString>,
    queries: &[&Query],
) -> Vec<QueryResult> {
    let output = run_under(shell, path.cloned(), batch::render(queries))
        .await
        .unwrap();
    batch::read(Lane::Login, queries, &output)
}

/// A command probe of `snippet` under a `secs` timeout — an operator's command.
pub(super) fn operator(snippet: &str, secs: u32) -> Query {
    Query::Command {
        snippet: snippet.to_owned(),
        privilege: Privilege::Login,
        timeout_secs: std::num::NonZeroU32::new(secs).unwrap(),
        origin: CommandOrigin::Operator,
    }
}

/// A finished command's answer.
#[expect(
    clippy::unnecessary_wraps,
    reason = "compared with the `QueryResult`s `batch::read` returns, some of them errors"
)]
pub(super) fn finished(code: i32, stdout: &[u8], stderr: &[u8]) -> QueryResult {
    Ok(Observation::Command(
        zap_types::observe::CommandObservation {
            code,
            stdout: stdout.to_vec(),
            stderr: stderr.to_vec(),
        },
    ))
}

/// Whether a process runs whose argv is exactly `argv` (NUL-joined, as `/proc` holds
/// it) — a zombie counts as gone.
pub(super) fn running(argv: &str) -> bool {
    !running_pids(argv).is_empty()
}

/// The pids of the processes [`running`] finds for `argv`.
pub(super) fn running_pids(argv: &str) -> Vec<i32> {
    std::fs::read_dir("/proc")
        .unwrap()
        .flatten()
        .filter(|entry| {
            std::fs::read(entry.path().join("cmdline"))
                .is_ok_and(|cmdline| cmdline == format!("{argv}\0").replace(' ', "\0").as_bytes())
                && std::fs::read_to_string(entry.path().join("stat")).is_ok_and(|stat| {
                    stat.rsplit_once(')')
                        .and_then(|(_, rest)| rest.trim_start().chars().next())
                        .is_some_and(|state| !matches!(state, 'Z' | 'X' | 'x'))
                })
        })
        .filter_map(|entry| entry.file_name().to_str()?.parse().ok())
        .collect()
}

pub(super) fn elevated(path: &str, facet: PathFacet) -> Query {
    Query::Path {
        path: path.to_owned(),
        facet,
        privilege: Privilege::Elevated,
    }
}

pub(super) fn ssh_target() -> SshConnection {
    SshConnection {
        host: "host.example".to_owned(),
        user: "ops".to_owned(),
        port: None,
        key_path: None,
        home: None,
    }
}

/// Whether a single-quoted segment of `text` (as a POSIX shell splits it) holds a
/// backslash — which `fish` reads as an escape inside single quotes, where POSIX
/// shells read it literally.
pub(super) fn backslash_in_single_quotes(text: &str) -> bool {
    let mut quoted = false;
    let mut escaped = false;
    for c in text.chars() {
        match (quoted, escaped, c) {
            (true, _, '\'') => quoted = false,
            (true, _, '\\') => return true,
            (false, true, _) => escaped = false,
            (false, false, '\\') => escaped = true,
            (false, false, '\'') => quoted = true,
            _ => {}
        }
    }
    false
}
