//! `Connection` — the execution abstraction (where and how commands run).
//!
//! A closed enum over `Local` / `Ssh` / `Mock` (Container later): static dispatch,
//! no `async_trait`, exhaustive matching, and `Mock` is just a variant. `run` is
//! the required primitive; `exists` is a *provided* method composing `run`
//! (`test -e`), with the `Local` arm short-circuiting to native `std::fs`.
//!
//! A command's text never rides an argv: `Local` and `Ssh` hand it to a constant shell
//! wrapper on the child's stdin (the private `delivery` module), framed so it runs
//! whole or not at all, with any data the command reads behind it. A mock keys on the
//! command text itself, above that seam.
//!
//! Detection reads through [`observe`](Connection::observe): typed queries answered in
//! one batch per privilege lane (see [`observe`]). The single-read
//! methods — `read_source` / `read_bytes` / `snapshot` / `exists` — serve execution and
//! the one detection read a batch can't carry (an uncached `remote` file's raw bytes).
//! On `Local` they try as the operator first, with a `sudo` retry (the per-op two-tier
//! escalation); other connections run a constant script (`FILE_BYTES`, `FILE_SNAPSHOT`)
//! or compose `test -e`.
//!
//! Execution-phase methods (the native-fs file/dir/link executor): `write_file` /
//! `write_bytes` / `place_file` install a file with its mode and owner in one act —
//! natively on `Local` (the private `local_put` module), else through the constant put
//! script (`zap_types::put::FILE_PUT`), the content piped over stdin behind its
//! digest, never the argv, so a secret-bearing file can't surface in the target's `ps`.
//! Either way the file is staged under a new name in its own directory, given its owner
//! and mode there, and renamed into place: it never exists at its path with another
//! mode or owner, and no name is followed through a symbolic link. `remove_file`
//! (`remove_file` / `sudo rm -f`), `make_dir` (directories made with their ancestor's
//! owner and group — natively, else through `zap_types::put::MAKE_DIRS`),
//! `make_symlink` (a link made under a fresh name and renamed over its path — natively,
//! else through `zap_types::put::LINK_PUT`), and `set_dir_attrs` (a
//! directory's mode and owner — natively, else through `zap_types::put::DIR_ATTRS`)
//! are the rest;
//! `copy_file` is the unprivileged staging primitive (into a private directory), and
//! `push_bytes` the unprivileged install (the put, as the caller). The per-op privilege
//! model: native first, fall back to a privileged shell op only when the operator can't
//! perform the op directly — a root-owned target needs `sudo` even from a writable
//! parent, so privilege is decided per operation, not per path. For a write and a
//! directory change, "can't" is exactly "was not permitted": any other failure is
//! reported, never retried as root.
//!
//! `Ssh` runs over the `ssh` subprocess (see [`ssh`]). It carries the resolved
//! target and runs the file helpers under `sudo` (the login user isn't assumed to
//! own the target).
//! Path resolution is target-categorized: callers hand connection IO methods the
//! **home-literal** path (only references resolved) and finish home resolution via
//! [`Connection::apply_home`] — operator `$HOME` for `Local`, the declared
//! `target.home` for `Ssh` (a remote path referencing the home with no `target.home`
//! is a clear error, not a guess).

mod delivery;
mod local_put;
pub mod mock;
pub mod observe;
pub mod ssh;

pub use mock::MockConnection;
pub use observe::Answers;
pub use ssh::SshConnection;

use tokio::io::AsyncWriteExt as _;
use zap_types::put::{
    FileAttrs, PutCheck, REFUSED_EXIT, RunAs, SCRIPT_TIMEOUT_SECS, Snapshot, dir_attrs_command,
    file_bytes_command, file_put_command, file_snapshot_command, make_dirs_command, parse_snapshot,
    script_timed_out,
};
use zap_types::shell::single_quote;

use self::delivery::Delivery;
use self::local_put::{LocalSource, Native};
use crate::error::{Error, FailureCause, Result};
use crate::resolve::{expand_runtime_path, expand_with_home, references_home, resolve_field};

/// Options for running a command on a connection.
///
/// Its `Debug` shows each variable's name, never its value: an `env` value is resolved,
/// and a secret's among them.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct RunOptions {
    /// Working directory for the command.
    pub cwd: Option<std::path::PathBuf>,
    /// Extra environment variables (name, value).
    pub env: Vec<(String, String)>,
}

impl std::fmt::Debug for RunOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let names: Vec<&str> = self.env.iter().map(|(name, _)| name.as_str()).collect();
        f.debug_struct("RunOptions")
            .field("cwd", &self.cwd)
            .field("env_names", &names)
            .finish_non_exhaustive()
    }
}

/// The result of running a command.
#[derive(Debug, Clone)]
pub struct CommandOutput {
    /// Whether the command exited successfully.
    pub success: bool,
    /// The process exit code.
    pub code: i32,
    /// Captured standard output.
    pub stdout: String,
    /// Captured standard error.
    pub stderr: String,
}

impl CommandOutput {
    /// A synthetic failure with code 1 and no captured stdout — for a failure *before*
    /// the command ran (a spawn/transport error), where there is no process status to
    /// read. The remote arms degrade an unspawnable `ssh` to one of these (a failed run,
    /// not an `Err`), mirroring how a non-zero remote exit is a failed-but-`Ok` result.
    fn failed(stderr: impl Into<String>) -> Self {
        Self {
            success: false,
            code: 1,
            stdout: String::new(),
            stderr: stderr.into(),
        }
    }
}

impl From<std::process::Output> for CommandOutput {
    /// Map a finished process's captured output — the one definition every spawn site
    /// (local/remote, with or without piped stdin) shares. A signal-killed process has
    /// no exit code, recorded as `-1`.
    fn from(output: std::process::Output) -> Self {
        Self {
            success: output.status.success(),
            code: output.status.code().unwrap_or(-1),
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        }
    }
}

/// A command's **raw** output — `stdout` as bytes, not the lossy `String` of
/// [`CommandOutput`]. The binary-safe read path ([`Connection::read_bytes`]) captures
/// through this so a binary file fetched over SSH isn't corrupted by `from_utf8_lossy`.
/// `stderr` stays a `String` (it is only ever rendered into an error message).
struct RawOutput {
    /// Whether the command exited successfully.
    success: bool,
    /// The exit code; `-1` when there was none (killed by a signal, or never run).
    code: i32,
    /// Captured standard output, byte-exact.
    stdout: Vec<u8>,
    /// Captured standard error (lossy — error text only).
    stderr: String,
}

impl RawOutput {
    /// A synthetic failure for a spawn/transport error before the command ran — the
    /// raw-output analogue of [`CommandOutput::failed`].
    fn failed(stderr: impl Into<String>) -> Self {
        Self {
            success: false,
            code: -1,
            stdout: Vec::new(),
            stderr: stderr.into(),
        }
    }

    /// Reinterpret a recorded [`CommandOutput`] as raw bytes — the `Mock` arm of the
    /// raw read (fixtures record text, so the round-trip through `String` is lossless
    /// for them).
    fn from_command_output(output: CommandOutput) -> Self {
        Self {
            success: output.success,
            code: output.code,
            stdout: output.stdout.into_bytes(),
            stderr: output.stderr,
        }
    }
}

impl From<std::process::Output> for RawOutput {
    /// Map a finished process's captured output, keeping stdout byte-exact (the one
    /// raw-capture definition the local `sh` and remote `ssh` arms share).
    fn from(output: std::process::Output) -> Self {
        Self {
            success: output.status.success(),
            code: output.status.code().unwrap_or(-1),
            stdout: output.stdout,
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        }
    }
}

/// Where and how commands run. `Ssh` carries its resolved target; `Mock` carries its
/// recorded command map (and an optional test home).
#[derive(Debug)]
pub enum Connection {
    /// The local machine — native `std::fs`, and child `sh` processes that read their
    /// command on stdin.
    Local,
    /// A remote host over the `ssh` subprocess.
    Ssh(SshConnection),
    /// A test double that replays recorded command outputs.
    Mock(MockConnection),
}

impl Connection {
    /// The host label — `local` for the local machine, the resolved remote host for
    /// SSH, the mock's host for a mock.
    #[must_use]
    pub fn host(&self) -> &str {
        match self {
            Self::Local => "local",
            Self::Ssh(ssh) => &ssh.host,
            Self::Mock(mock) => &mock.host,
        }
    }

    /// The resolved connecting user for the SSH arm, a mock's declared one, and empty
    /// for `Local`. Deploy is remote-only, so this is consumed only for a remote target
    /// (it is part of the uploaded release archive's name).
    #[must_use]
    pub const fn user(&self) -> &str {
        match self {
            Self::Ssh(ssh) => ssh.user.as_str(),
            Self::Mock(mock) => mock.user.as_str(),
            Self::Local => "",
        }
    }

    /// Resolve a config path field's `~` / `$HOME` against **this connection's**
    /// target home — the IO-boundary half of target-categorized resolution. A reference
    /// is resolved either way (operator env). The caller hands a home-literal path
    /// (or a raw field); the returned string is concrete and safe to `single_quote`.
    ///
    /// - `Local`: the operator's `$HOME` (the operator *is* the target).
    /// - `Ssh` / `Mock`: the declared `target.home` if set; absent, a path that
    ///   references the home is a config error (no guessing), while a home-free path
    ///   passes through reference-resolved.
    ///
    /// # Errors
    /// [`Error::RemoteHomeUnset`] when a remote path references `~` / `$HOME` but no
    /// `target.home` is declared; [`Error::LocalHomeUnset`] / [`Error::HomeNotAbsolute`]
    /// when a local one does and `HOME` is unset, empty, or relative.
    pub fn apply_home(&self, path: &str) -> Result<String> {
        match self {
            Self::Local => expand_runtime_path(path),
            Self::Ssh(ssh) => resolve_with_target_home(path, ssh.home.as_deref()),
            Self::Mock(mock) => resolve_with_target_home(path, mock.home.as_deref()),
        }
    }

    /// Verify the connection can execute commands — deploy's up-front check, and a
    /// detection pass with no queries to batch (a batch is its own connectivity check).
    /// Local is always connected; a mock is too. SSH runs `ssh true`.
    ///
    /// # Errors
    /// [`Error::Connectivity`] if an SSH host can't be reached.
    pub async fn check_connectivity(&self) -> Result<()> {
        match self {
            Self::Local | Self::Mock(_) => Ok(()),
            Self::Ssh(ssh) => ssh.check_connectivity().await,
        }
    }

    /// Run a command and capture its output. Never panics; a non-zero exit is a
    /// successful call with `success == false`.
    ///
    /// # Errors
    /// - [`Error::Command`] if the local subprocess can't be spawned/awaited, or if
    ///   `cmd` holds a NUL byte.
    /// - [`Error::MockCommand`] if a mock has no recording for `cmd`.
    pub async fn run(&self, cmd: &str, options: &RunOptions) -> Result<CommandOutput> {
        delivery::refuse_delimiter(cmd).map_err(Error::Command)?;
        match self {
            Self::Local => run_local(cmd, options).await,
            Self::Ssh(ssh) => ssh.run(cmd, options).await,
            Self::Mock(mock) => mock
                .lookup(cmd)
                .cloned()
                .ok_or_else(|| Error::MockCommand(cmd.to_owned())),
        }
    }

    /// Run `cmd` as the one script `SshConnection::wrap_remote` composes from it and
    /// `options` — the `cd`, the exported `env`, then the command — on every arm, with
    /// nothing of `options` set on a process. So a local command and a remote one are
    /// the same text under the same shell: a `cwd` that can't be entered ends either
    /// with `cd`'s status and message, and no `env` value (a `PATH`) can keep the shell
    /// from starting. A mock is asked for the composed text.
    ///
    /// # Errors
    /// As [`run`](Self::run).
    pub async fn run_composed(&self, cmd: &str, options: &RunOptions) -> Result<CommandOutput> {
        let script = SshConnection::wrap_remote(cmd, options);
        self.run_default(&script).await
    }

    /// Run a command with default options (no sudo, cwd, or env). Callers that
    /// customize options (sudo, cwd, env) call [`run`](Self::run) or
    /// [`run_composed`](Self::run_composed) directly, so a customizing call stays
    /// visible against the plain form.
    ///
    /// # Errors
    /// As [`run`](Self::run).
    pub async fn run_default(&self, cmd: &str) -> Result<CommandOutput> {
        self.run(cmd, &RunOptions::default()).await
    }

    /// Run `cmd`, feeding `content` to its **stdin** — the delivery channel for data that
    /// must not appear in the argv (and thus a target's `ps`). The privileged put takes a
    /// file's digest and bytes this way. `Local` / `Ssh` write `cmd` and then `content`
    /// to the child / `ssh` process stdin as one frame (the private `delivery` module):
    /// the wrapper shell takes exactly the command, and the command reads exactly
    /// `content`. `Mock` ignores the content and replays the recording keyed on `cmd`, so
    /// a fixture records the bare, content-independent command.
    ///
    /// # Errors
    /// - [`Error::Command`] if a local subprocess can't be spawned.
    /// - [`Error::MockCommand`] if a mock has no recording for `cmd`.
    pub(crate) async fn run_with_stdin(&self, cmd: &str, content: &[u8]) -> Result<CommandOutput> {
        match self {
            Self::Local => spawn_sh_stdin(cmd, content).await,
            Self::Ssh(ssh) => ssh.run_with_stdin(cmd, content).await,
            Self::Mock(mock) => mock
                .lookup(cmd)
                .cloned()
                .ok_or_else(|| Error::MockCommand(cmd.to_owned())),
        }
    }

    /// Whether a path exists on the target. Provided method: composes `run`
    /// (`test -e`, its answer said on stdout, so a `sudo` that refused the probe is an
    /// error rather than a read of "absent"), except `Local` short-circuits to a native
    /// `std::fs` stat (no subprocess). `metadata` (not `symlink_metadata`) follows
    /// symlinks to match `test -e`'s semantics, so a dangling symlink reads `false` on
    /// every arm rather than diverging local-vs-remote.
    ///
    /// Two-tier on `Local`: a native `NotFound` (or `NotADirectory`, or a symbolic link
    /// loop, which `test -e` reads as nothing there too) is a genuine absence and
    /// answers `false` without escalating; a permission denial (a root-owned,
    /// non-traversable parent under umask 077) is retried as the probe under `sudo` —
    /// the stat-side twin of `read_bytes`'s `sudo` fallback. Reading a denied stat
    /// as "absent" would plan a *create* over state that exists (or, for a sudo-written
    /// extract sentinel, re-extract on every apply). Any other failure is an error.
    ///
    /// # Errors
    /// Propagates `run` errors for non-local connections, a local stat failure that is
    /// neither an absence nor a denial, or a spawn failure of the local privileged
    /// probe.
    pub async fn exists(&self, path: &str) -> Result<bool> {
        refuse_unresolved_path("stat", path)?;
        match self {
            Self::Local => match tokio::fs::metadata(path).await {
                Ok(_) => Ok(true),
                // a link loop (`ELOOP`) names nothing, as `test -e` reads it over SSH
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory
                    ) || error.raw_os_error() == Some(nix::libc::ELOOP) =>
                {
                    Ok(false)
                }
                Err(error) if error.kind() != std::io::ErrorKind::PermissionDenied => {
                    Err(file_op("stat", path, error))
                }
                Err(_) => read_exists(
                    path,
                    &run_local(&exists_command("sudo ", path), &RunOptions::default()).await?,
                ),
            },
            // SSH reads under `sudo` (a root-owned target may be unstattable as the
            // login user); a mock composes the bare probe it recorded.
            _ => read_exists(
                path,
                &self
                    .run_default(&exists_command(self.read_sudo(), path))
                    .await?,
            ),
        }
    }

    /// Read the bytes of a `file`'s `source`: the regular file at `path`, through the
    /// validated write's snapshot script ([`snapshot`](Self::snapshot)), so a symbolic
    /// link at `path` is refused rather than read through (a link to a file only root
    /// may read would be copied out with the declared mode), as is anything that isn't a
    /// regular file (a device read whole would never end) and a file larger than
    /// `SNAPSHOT_MAX_BYTES`, which is held in memory. The bytes are captured raw, never
    /// as text, so a binary source arrives whole. Detection reads the same file the
    /// same way: its digest read refuses what this refuses but the size.
    ///
    /// # Errors
    /// [`Error::ReadFile`] when there is nothing at `path`, and as
    /// [`snapshot`](Self::snapshot) fails.
    pub async fn read_source(&self, path: &str) -> Result<Vec<u8>> {
        match self.snapshot(path).await? {
            Snapshot::File { bytes, .. } => Ok(bytes),
            Snapshot::Absent => Err(read_failed(
                path,
                std::io::Error::new(std::io::ErrorKind::NotFound, "there is no file there"),
            )),
        }
    }

    /// Read the raw bytes of the regular file at `path` — binary-safe (zig/ghostty are
    /// binaries). Detection uses it only for a `remote` file whose pinned bytes aren't in
    /// the content cache (a warm cache compares a target-side SHA-512 instead); a
    /// validated write's snapshot is [`snapshot`](Self::snapshot).
    ///
    /// A symbolic link at `path` and anything that isn't a regular file are refused
    /// before anything is opened, as the content reads of a detection batch refuse
    /// them. `Local` reads natively — no link followed (`O_NOFOLLOW`), never blocking on
    /// a fifo, and only what it opened is a regular file — and retries through `sudo`
    /// on a permission denial; others run `zap_types::put::FILE_BYTES` and capture its
    /// stdout as **raw bytes** (`run_raw_stdout`), never the lossy `String` of
    /// [`CommandOutput`] — `ssh` forwards the remote stdout over an 8-bit-clean pipe.
    ///
    /// # Errors
    /// [`Error::ReadFile`] if the file can't be read or isn't a regular file of its own.
    pub async fn read_bytes(&self, path: &str) -> Result<Vec<u8>> {
        refuse_unresolved_path("read", path)?;
        if matches!(self, Self::Local) {
            // Native first; only a permission denial (a root-owned file) retries under
            // `sudo`, through the binary-safe raw capture.
            return match read_regular_local(path).await {
                Ok(bytes) => Ok(bytes),
                Err(error) if error.kind() != std::io::ErrorKind::PermissionDenied => {
                    Err(read_failed(path, error))
                }
                Err(_) => bytes_read(
                    path,
                    spawn_sh_raw(&file_bytes_command("sudo ", path)).await?,
                ),
            };
        }
        let output = self
            .run_raw_stdout(&file_bytes_command(self.read_sudo(), path))
            .await?;
        bytes_read(path, output)
    }

    /// Read what is at `path` for a validated write's rollback — its bytes, mode, owner,
    /// and group, or that nothing is there — in one run of the constant snapshot script
    /// (`zap_types::put::FILE_SNAPSHOT`), under `timeout`. The script reads everything
    /// through one descriptor and refuses a symbolic link at `path`, anything that isn't
    /// a regular file, and a file larger than `SNAPSHOT_MAX_BYTES`; stdout is captured
    /// byte-exact.
    ///
    /// Per-op privilege, as for a write: as root over SSH; locally as the operator, then
    /// under `sudo` when that attempt failed — unless the failure was the script's own
    /// refusal or its timeout, which more privilege wouldn't change — or answered
    /// `absent` where the operator's own lookup of the path doesn't find it missing
    /// (`local_snapshot_escalates`); a mock records the caller's form.
    ///
    /// # Errors
    /// [`Error::ReadFile`] when the script refuses or fails (carrying what it printed,
    /// which names the path, never the content), runs past `SCRIPT_TIMEOUT_SECS`, or its
    /// answer doesn't parse.
    pub async fn snapshot(&self, path: &str) -> Result<Snapshot> {
        refuse_unresolved_path("snapshot", path)?;
        let command = |run_as| file_snapshot_command(run_as, path);
        let output = match self {
            Self::Local => {
                snapshot_local(
                    path,
                    |run_as| async move { self.run_raw_stdout(&command(run_as)).await },
                    |path| std::fs::symlink_metadata(path).map(|_| ()),
                )
                .await?
            }
            _ => self.run_raw_stdout(&command(self.script_run_as())).await?,
        };
        if script_timed_out(output.code) {
            return Err(read_failed(
                path,
                FailureCause::TimedOut(format!(
                    "the snapshot did not finish within {SCRIPT_TIMEOUT_SECS} seconds (timed \
                     out or was terminated); nothing was written"
                )),
            ));
        }
        if !output.success {
            return Err(read_failed(
                path,
                FailureCause::Exited {
                    stderr: output.stderr.trim().to_owned(),
                    code: output.code,
                },
            ));
        }
        parse_snapshot(&output.stdout).ok_or_else(|| {
            read_failed(
                path,
                FailureCause::Text("the snapshot script's answer doesn't parse".to_owned()),
            )
        })
    }

    /// Run `cmd` and capture its **raw** stdout bytes — the binary-safe counterpart to
    /// [`run_default`](Self::run_default), used by [`read_bytes`](Self::read_bytes).
    /// `Local` runs it under `sh` and captures raw (`read_bytes` reads `Local` natively
    /// first); `Ssh` captures the `ssh` subprocess stdout (an
    /// 8-bit-clean pipe); `Mock` replays its recorded stdout as bytes.
    ///
    /// # Errors
    /// - [`Error::Command`] if a local subprocess can't be spawned.
    /// - [`Error::MockCommand`] if a mock has no recording for `cmd`.
    async fn run_raw_stdout(&self, cmd: &str) -> Result<RawOutput> {
        delivery::refuse_delimiter(cmd).map_err(Error::Command)?;
        match self {
            Self::Local => spawn_sh_raw(cmd).await,
            Self::Ssh(ssh) => ssh.run_raw_stdout(cmd).await,
            Self::Mock(mock) => mock
                .lookup(cmd)
                .cloned()
                .map(RawOutput::from_command_output)
                .ok_or_else(|| Error::MockCommand(cmd.to_owned())),
        }
    }

    /// Run `cmd` and return its stdout **byte-exact** when it succeeds — the binary-safe
    /// counterpart to [`run_default`](Self::run_default), for a caller that hashes what a
    /// command prints. A failed run comes back as its [`CommandOutput`] (stdout lossy,
    /// as error text only), for the caller's error.
    ///
    /// # Errors
    /// As [`run_raw_stdout`](Self::run_raw_stdout).
    pub(crate) async fn run_stdout_bytes(
        &self,
        cmd: &str,
    ) -> Result<std::result::Result<Vec<u8>, CommandOutput>> {
        let raw = self.run_raw_stdout(cmd).await?;
        Ok(if raw.success {
            Ok(raw.stdout)
        } else {
            Err(CommandOutput {
                success: false,
                code: raw.code,
                stdout: String::from_utf8_lossy(&raw.stdout).into_owned(),
                stderr: raw.stderr,
            })
        })
    }

    /// Install `content` at `path` with `attrs` — the native-fs file executor's content
    /// write.
    ///
    /// The bytes are staged under a new name in `path`'s own directory, given their
    /// owner and mode there, flushed to disk, and renamed over `path`. So a crash leaves
    /// the old file or the new one, `path` never exists with another mode or owner (a
    /// secret is never readable at its path for the length of a second command), and
    /// neither the stage nor the rename follows a symbolic link someone planted. The
    /// stage's name is new each time: a leftover from an interrupted run is not reused,
    /// and not removed.
    ///
    /// What `attrs` leave out is `attrs.unset`'s: a fresh file's (`0666` less the umask of
    /// whoever writes it, and the writer's owner and group), or what the path has
    /// (`Unset::Keep`: an existing file's owner, group, and mode less any set-id or
    /// sticky bit; a new file's directory's owner and group). Locally, a kept owner or
    /// group the operator may not give is denied natively, so the privileged put keeps it.
    ///
    /// Per-op privilege: `Local` installs natively (the private `local_put` module), and
    /// on a `PermissionDenied` — a directory the operator can't write, an owner only root
    /// may set — falls back to the privileged put. Every other connection, and that
    /// fallback, runs the constant put script (`zap_types::put::FILE_PUT`) under
    /// `write_sudo()` (`sudo` for SSH and `Local`, none for a mock) in **one** delivery:
    /// the content's SHA-512 as a line, then the content, on the command's stdin. The
    /// script installs nothing unless the bytes it received digest to that line, so a
    /// stream cut short leaves `path` as it was.
    ///
    /// The command's text is the same for any content (`file_put_command`), so a mock
    /// keys on it, and neither the content nor its digest is on an argv, in an error, or
    /// in a recorded command.
    ///
    /// # Errors
    /// [`Error::FileOp`] if neither the native write nor the privileged fallback succeeds.
    pub async fn write_file(&self, path: &str, content: &str, attrs: FileAttrs<'_>) -> Result<()> {
        self.write_bytes(path, content.as_bytes(), attrs).await
    }

    /// [`write_file`](Self::write_file) for raw bytes. The file executor's `validate`
    /// rollback restores a snapshot through it, since the replaced file need not have
    /// been text.
    ///
    /// # Errors
    /// [`Error::FileOp`] if neither the native write nor the privileged fallback succeeds.
    pub async fn write_bytes(
        &self,
        path: &str,
        content: &[u8],
        attrs: FileAttrs<'_>,
    ) -> Result<()> {
        refuse_unresolved_path("write", path)?;
        if matches!(self, Self::Local) {
            match Native::of(
                local_put::put(path, LocalSource::Bytes(content.to_vec()), attrs).await,
            ) {
                Native::Done => return Ok(()),
                Native::Denied => {}
                Native::Failed(error) => {
                    return Err(file_op("write", path, error));
                }
            }
        }
        self.put_scripted(self.script_run_as(), "write", path, content, attrs)
            .await
    }

    /// Install `content` at `path` with `attrs` **as the connecting user** — the
    /// unprivileged sibling of [`write_bytes`](Self::write_bytes), which never asks for
    /// `sudo`. Deploy uploads its release archive with it, into the app path the
    /// connecting user writes.
    ///
    /// The install is the same one: staged under a new name in `path`'s directory,
    /// checked against the content's SHA-512, given its mode, and renamed into place, so
    /// a transfer cut short installs nothing and a link at `path` is replaced, never
    /// written through. `Local` installs natively; every other connection runs the put
    /// script (`zap_types::put::FILE_PUT`) as the caller, the digest and the bytes on its
    /// stdin. The content is held in memory for the length of the transfer.
    ///
    /// # Errors
    /// [`Error::FileOp`] when the install fails — a directory the connecting user can't
    /// write included; nothing is retried with more privilege.
    pub async fn push_bytes(&self, path: &str, content: &[u8], attrs: FileAttrs<'_>) -> Result<()> {
        refuse_unresolved_path("push", path)?;
        if matches!(self, Self::Local) {
            return local_put::put(path, LocalSource::Bytes(content.to_vec()), attrs)
                .await
                .map_err(|error| file_op("push", path, error));
        }
        self.put_scripted(RunAs::Caller, "push", path, content, attrs)
            .await
    }

    /// Remove the file at `path`; an already-absent path is success (`rm -f`
    /// semantics). `Local` removes natively, falling back to `sudo rm -f` on a
    /// permission error; others compose `rm -f` under
    /// `write_sudo`. The file executor's `validate` rollback uses
    /// it to drop a newly created file that failed its check.
    ///
    /// # Errors
    /// [`Error::FileOp`] if the file exists and can't be removed.
    pub async fn remove_file(&self, path: &str) -> Result<()> {
        refuse_unresolved_path("remove", path)?;
        if matches!(self, Self::Local) {
            match tokio::fs::remove_file(path).await {
                Ok(()) => return Ok(()),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
                Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {}
                Err(error) => return Err(file_op("remove", path, error)),
            }
        }
        let sudo = self.write_sudo();
        let cmd = format!("{sudo}rm -f -- {}", single_quote(path));
        self.expect_success("remove", path, &cmd).await
    }

    /// Install `content` at `path` with `attrs` through the constant put script
    /// (`zap_types::put::FILE_PUT`) run as `run_as`: one delivery whose stdin is the
    /// content's SHA-512 line and then the content. The scripted half shared by
    /// [`write_bytes`](Self::write_bytes), [`place_file`](Self::place_file), and
    /// [`push_bytes`](Self::push_bytes). Binary-safe.
    ///
    /// # Errors
    /// [`Error::FileOp`] for `op` on `path` when the script exits nonzero, carrying what
    /// it printed — which names the path, never the content or the digest.
    async fn put_scripted(
        &self,
        run_as: RunAs<'_>,
        op: &'static str,
        path: &str,
        content: &[u8],
        attrs: FileAttrs<'_>,
    ) -> Result<()> {
        let command = file_put_command(run_as, path, attrs, PutCheck::None);
        let output = self.run_put(&command, content).await?;
        success_or_file_op(op, path, &output)
    }

    /// Run `command` — a `zap_types::put::file_put_command` — with `content` on its
    /// stdin behind the content's SHA-512 line ([`put_payload`]): a plan's put step.
    ///
    /// The put is the scripted one on every arm. A plan's put names who it runs as and
    /// the check it must pass, which are the command's; `Local` has no native form of
    /// it. The result is the command's own, exit status and all, as a step's is.
    ///
    /// # Errors
    /// As [`run_with_stdin`](Self::run_with_stdin).
    pub(crate) async fn run_put(&self, command: &str, content: &[u8]) -> Result<CommandOutput> {
        self.run_with_stdin(command, &put_payload(content)).await
    }

    /// Create `path` and its missing parents, each directory made given the owner and
    /// group of the nearest one that was already there — anywhere below a directory with
    /// its sticky bit set or that every account may write (`/tmp`), the creator's own; an
    /// existing directory is success and is never changed. The mode of each is the
    /// creator's default (`0777` less its umask).
    ///
    /// Per-op privilege, as for a write: `Local` makes them natively (the private
    /// `local_put` module) when the operator may give that owner and group, and
    /// otherwise — or when it may not make them — runs the constant
    /// `zap_types::put::MAKE_DIRS` script under `sudo`, as every other connection does
    /// (none for a mock). Both make each directory by name in the one before it, held
    /// open, so a symbolic link swapped in for one is refused, nothing made through it,
    /// and give an owner only to the empty directory the creator just made, so one
    /// renamed over it is refused, given nothing.
    ///
    /// Neither form makes a directory through a symbolic link at `path` itself: a
    /// dangling one fails the create with nothing made where it points, and a link to a
    /// directory is "already there" — left as it is, for the caller to refuse where it
    /// must ([`set_dir_attrs`](Self::set_dir_attrs) does). A symbolic link in a
    /// component above the missing ones is followed, as `mkdir -p` follows it.
    ///
    /// # Errors
    /// [`Error::FileOp`] if the directories can't be made.
    pub async fn make_dir(&self, path: &str) -> Result<()> {
        refuse_unresolved_path("mkdir", path)?;
        if matches!(self, Self::Local) {
            match Native::of(local_put::make_dirs(path).await) {
                Native::Done => return Ok(()),
                Native::Denied => {}
                Native::Failed(error) => return Err(file_op("mkdir", path, error)),
            }
        }
        let command = make_dirs_command(self.script_run_as(), path);
        let output = self.run_default(&command).await?;
        if script_timed_out(output.code) {
            return Err(file_op(
                "mkdir",
                path,
                FailureCause::TimedOut(format!(
                    "it did not finish within {SCRIPT_TIMEOUT_SECS} seconds (timed out or was \
                     terminated)"
                )),
            ));
        }
        success_or_file_op("mkdir", path, &output)
    }

    /// Create (or replace) the symlink at `path` pointing to `target`: made under a
    /// fresh name beside `path` and renamed over it, so what stands there is replaced
    /// in one step, except that a real directory at `path` fails the step (`ln -sfn`
    /// would create the link *inside* it and exit 0, leaving the resource residual on
    /// every run). `Local` does it natively, falling back to the shell form
    /// ([`LINK_PUT`](zap_types::put::LINK_PUT)) under `sudo` on a permission error;
    /// others run the shell form.
    ///
    /// # Errors
    /// [`Error::FileOp`] if the symlink can't be created.
    pub async fn make_symlink(&self, target: &str, path: &str) -> Result<()> {
        refuse_unresolved_path("symlink", path)?;
        refuse_unresolved_path("symlink", target)?;
        if matches!(self, Self::Local) {
            match symlink_local(target, path).await {
                Ok(()) => return Ok(()),
                Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {}
                Err(error) => return Err(file_op("symlink", path, error)),
            }
        }
        let sudo = self.write_sudo();
        let cmd = zap_types::put::link_put_command(sudo, path, target);
        self.expect_success("symlink", path, &cmd).await
    }

    /// Copy a local file to a **staging** destination — the *unprivileged* transfer
    /// primitive. It never escalates, and it writes by name, so every `dest` must be in
    /// a directory only the connecting user can write: a resource's archive staging
    /// inside a per-run private `mktemp -d` dir (`0700`, connecting-user-owned) — via
    /// `extract_archive`, for both `remote` files and `build` sources. `Local` is a
    /// native `std::fs` copy; `Ssh` is a plain `scp`; `Mock` is a no-op — sound because
    /// every `dest` is such a staging path, so the no-op can't hide a privileged write.
    ///
    /// For a **final** destination that may be root-owned (a `remote` file's declared
    /// `path`), use [`place_file`](Self::place_file), which escalates per the two-tier
    /// file-op rule; for a destination in a directory others may write, use
    /// [`push_bytes`](Self::push_bytes), which follows no link there.
    ///
    /// # Errors
    /// [`Error::FileOp`] if the copy/`scp` fails; [`Error::Command`] if `scp` can't be
    /// spawned.
    pub async fn copy_file(&self, local: &std::path::Path, dest: &str) -> Result<()> {
        refuse_unresolved_path("copy", dest)?;
        match self {
            Self::Local => tokio::fs::copy(local, dest)
                .await
                .map(|_| ())
                .map_err(|error| file_op("copy", dest, error)),
            Self::Ssh(ssh) => ssh.copy_file(local, dest).await,
            Self::Mock(_) => Ok(()),
        }
    }

    /// Place a resolved local file at its **final** `dest` with `attrs`, escalating per
    /// the two-tier file-op rule — the privileged sibling of
    /// [`copy_file`](Self::copy_file) for a `remote` file's declared destination (often
    /// root-owned, e.g. `/opt/zig`). The install is [`write_bytes`](Self::write_bytes)'s:
    /// staged beside `dest`, owner and mode set, renamed into place.
    ///
    /// - `Local`: natively first, the file streamed from disk; on a `PermissionDenied`
    ///   it falls back to the privileged put.
    /// - `Ssh` (always) and the local fallback: read the local bytes and hand them to
    ///   the put script under `sudo` — no `/tmp` staging hop, and the bytes ride stdin so
    ///   they never enter the argv. Binary-safe.
    /// - `Mock`: looks the put command up in its `responses` map (a loud `MockCommand`
    ///   on an unrecorded command), unlike `copy_file`'s silent no-op.
    ///
    /// # Errors
    /// [`Error::FileOp`] if the local read fails, or neither the native install nor the
    /// privileged put succeeds.
    pub async fn place_file(
        &self,
        local: &std::path::Path,
        dest: &str,
        attrs: FileAttrs<'_>,
    ) -> Result<()> {
        refuse_unresolved_path("place", dest)?;
        if matches!(self, Self::Local) {
            match Native::of(
                local_put::put(dest, LocalSource::File(local.to_path_buf()), attrs).await,
            ) {
                Native::Done => return Ok(()),
                Native::Denied => {}
                Native::Failed(error) => {
                    return Err(file_op("place", dest, error));
                }
            }
        }
        let content = tokio::fs::read(local)
            .await
            .map_err(|error| file_op("place", &local.to_string_lossy(), error))?;
        self.put_scripted(self.script_run_as(), "place", dest, &content, attrs)
            .await
    }

    /// Set the directory at `path` to `attrs`' mode, owner, and group — each only when
    /// given; with none it does nothing.
    ///
    /// The directory is held open and changed through the handle, and a symbolic link at
    /// `path` is refused rather than followed — `chmod` and `chown` by name would change
    /// whatever the link points at. A regular file's mode and owner are never set this
    /// way: they are part of its write.
    ///
    /// Per-op privilege, as for a write: `Local` changes it natively (the private
    /// `local_put` module), and only an operation the operator was not permitted falls
    /// back to the privileged script. A refusal — a link, a file, nothing there — is the
    /// answer and is not tried again under `sudo`. Every other connection, and that
    /// fallback, runs the constant `zap_types::put::DIR_ATTRS` script once (`sudo` for
    /// SSH and `Local`, none for a mock).
    ///
    /// # Errors
    /// [`Error::FileOp`] when `path` isn't a directory (a link included) or the change
    /// fails.
    pub async fn set_dir_attrs(&self, path: &str, attrs: FileAttrs<'_>) -> Result<()> {
        refuse_unresolved_path("set the mode and owner of", path)?;
        if attrs.is_empty() {
            return Ok(());
        }
        let op = "set the mode and owner of";
        if matches!(self, Self::Local) {
            match Native::of(local_put::set_dir_attrs(path, attrs).await) {
                Native::Done => return Ok(()),
                Native::Denied => {}
                Native::Failed(error) => {
                    return Err(file_op(op, path, error));
                }
            }
        }
        let command = dir_attrs_command(self.script_run_as(), path, attrs);
        let output = self.run_default(&command).await?;
        if script_timed_out(output.code) {
            return Err(file_op(
                op,
                path,
                FailureCause::TimedOut(format!(
                    "it did not finish within {SCRIPT_TIMEOUT_SECS} seconds (timed out or was \
                     terminated); left unchanged"
                )),
            ));
        }
        success_or_file_op(op, path, &output)
    }

    /// Who a privileged script (`zap_types::put`) runs as: root on a real target — over
    /// SSH always, on `Local` once the native attempt was denied — and the caller for a
    /// mock, which records the bare command.
    const fn script_run_as(&self) -> RunAs<'static> {
        match self {
            Self::Local | Self::Ssh(_) => RunAs::Root,
            Self::Mock(_) => RunAs::Caller,
        }
    }

    /// `sudo ` prefix for the composed *read* helpers (`exists` / `read_bytes`): SSH
    /// reads as root (a root-owned target may be unreadable as the login user); a mock
    /// reads the bare command it recorded. (`Local` reads natively first and composes
    /// its own `sudo` retry.)
    pub(crate) const fn read_sudo(&self) -> &'static str {
        match self {
            Self::Ssh(_) => "sudo ",
            Self::Local | Self::Mock(_) => "",
        }
    }

    /// `sudo ` prefix for the composed *write* helpers (`remove_file` /
    /// `make_symlink`). `Local` reaches the shell branch only as a permission
    /// fallback (sudo correct); `Ssh` always writes as root; a mock records the bare
    /// command for deterministic fixtures.
    const fn write_sudo(&self) -> &'static str {
        match self {
            Self::Local | Self::Ssh(_) => "sudo ",
            Self::Mock(_) => "",
        }
    }

    /// Run `cmd` and map a non-zero exit to an [`Error::FileOp`] for `op` on `path`.
    async fn expect_success(&self, op: &'static str, path: &str, cmd: &str) -> Result<()> {
        let output = self.run_default(cmd).await?;
        success_or_file_op(op, path, &output)
    }
}

/// Resolve a path against an optional declared target home (the `Ssh` / `Mock` arm
/// of [`Connection::apply_home`]). A reference is always resolved; `~` / `$HOME` is
/// substituted when a home is given, errors when a home-referencing path has none,
/// and otherwise passes through unchanged.
fn resolve_with_target_home(path: &str, home: Option<&str>) -> Result<String> {
    let Some(home) = home else {
        // No declared home: a home-referencing path can't be resolved (don't guess);
        // a home-free path passes through reference-resolved.
        let resolved = resolve_field(path).map_err(Error::UnusableValue)?;
        return if references_home(&resolved) {
            Err(Error::RemoteHomeUnset {
                path: path.to_owned(),
            })
        } else {
            Ok(resolved)
        };
    };
    expand_with_home(path, home).map_err(Error::UnusableValue)
}

/// The local snapshot: `run` the snapshot as the operator, then under `sudo` when
/// [`local_snapshot_escalates`] says so, with `native` the operator's own lookup of
/// `path` (`symlink_metadata`). The `Local` arm of [`Connection::snapshot`], with the run
/// and the lookup passed in so a test can stand in for `sudo`.
async fn snapshot_local<F, Fut>(
    path: &str,
    run: F,
    native: impl FnOnce(&str) -> std::io::Result<()>,
) -> Result<RawOutput>
where
    F: Fn(RunAs<'static>) -> Fut,
    Fut: Future<Output = Result<RawOutput>>,
{
    let plain = run(RunAs::Caller).await?;
    if local_snapshot_escalates(&plain, || native(path)) {
        run(RunAs::Root).await
    } else {
        Ok(plain)
    }
}

/// Whether the operator's own snapshot attempt is tried again under `sudo`: past a
/// failure root could change ([`snapshot_retries_as_root`]), and past an `absent` the
/// operator's own lookup doesn't confirm — `native` must answer `NotFound`. A shell's
/// view of what it may look up can be wrong (`BusyBox`'s `test -x` reads the mode bits,
/// not an access list or a security module's rule), and an `absent` taken on trust
/// would have a failed check's rollback remove what is there.
fn local_snapshot_escalates(
    attempt: &RawOutput,
    native: impl FnOnce() -> std::io::Result<()>,
) -> bool {
    if snapshot_retries_as_root(attempt) {
        return true;
    }
    let reads_absent = attempt.success && parse_snapshot(&attempt.stdout) == Some(Snapshot::Absent);
    reads_absent && !matches!(native(), Err(error) if error.kind() == std::io::ErrorKind::NotFound)
}

/// Whether a local snapshot the operator's own attempt didn't read is tried again under
/// `sudo`: when it failed, and not by the script's own refusal (`REFUSED_EXIT`: a link,
/// something that isn't a regular file, a file past the limit) or its timeout — verdicts
/// root would be given too, and a stall root would wait out again.
const fn snapshot_retries_as_root(attempt: &RawOutput) -> bool {
    !attempt.success && attempt.code != REFUSED_EXIT && !script_timed_out(attempt.code)
}

/// The stdin the put script (`zap_types::put::FILE_PUT`) reads: `content`'s SHA-512 as a
/// line of lowercase hex, then `content` itself. The digest is of the bytes zap holds, so
/// the script installs them or nothing.
pub(crate) fn put_payload(content: &[u8]) -> Vec<u8> {
    let digest = crate::digest::sha512_hex(content);
    let mut payload = Vec::with_capacity(digest.len() + 1 + content.len());
    payload.extend_from_slice(digest.as_bytes());
    payload.push(b'\n');
    payload.extend_from_slice(content);
    payload
}

/// Refuse a path that holds a reference delimiter: a reference in a path is resolved
/// before the path gets here, and a value holding a delimiter is refused where it
/// resolves ([`resolve_field`]), so one that is still there was missed — and the path
/// names nothing the config declared. The last line of defence, which says only what
/// it can see.
fn refuse_unresolved_path(op: &'static str, path: &str) -> Result<()> {
    if zap_types::var_ref::holds_delimiter(path) {
        return Err(file_op(
            op,
            path,
            FailureCause::Text(delivery::PATH_HOLDS_DELIMITER.to_owned()),
        ));
    }
    Ok(())
}

/// Build an [`Error::FileOp`].
fn file_op(op: &'static str, path: &str, cause: impl Into<FailureCause>) -> Error {
    Error::FileOp {
        op,
        path: path.to_owned(),
        cause: cause.into(),
    }
}

/// A `FILE_BYTES` run's bytes, or why it read none: its `timeout` expiry, or what it
/// printed.
fn bytes_read(path: &str, output: RawOutput) -> Result<Vec<u8>> {
    if output.success {
        return Ok(output.stdout);
    }
    Err(read_failed(
        path,
        if script_timed_out(output.code) {
            FailureCause::TimedOut(format!(
                "the read did not finish within {SCRIPT_TIMEOUT_SECS} seconds (timed out or \
                 was terminated)"
            ))
        } else {
            FailureCause::Exited {
                stderr: output.stderr.trim().to_owned(),
                code: output.code,
            }
        },
    ))
}

/// Build an [`Error::ReadFile`].
fn read_failed(path: &str, cause: impl Into<FailureCause>) -> Error {
    Error::ReadFile {
        path: path.to_owned(),
        cause: cause.into(),
    }
}

/// `Ok(())` on success, else an [`Error::FileOp`] carrying the command's exit status and
/// stderr ([`FailureCause::Exited`]), which it classifies by.
fn success_or_file_op(op: &'static str, path: &str, output: &CommandOutput) -> Result<()> {
    if output.success {
        Ok(())
    } else {
        Err(file_op(
            op,
            path,
            FailureCause::Exited {
                stderr: output.stderr.trim().to_owned(),
                code: output.code,
            },
        ))
    }
}

/// The probe [`Connection::exists`] runs: `test -e`'s answer, said on stdout. `test`
/// takes no `--`, and needs none: with two arguments the second is the operand,
/// whatever it begins with.
const EXISTS_PROBE: &str = r#"if test -e "$1"; then echo present; else echo absent; fi"#;

/// The command [`EXISTS_PROBE`] runs in for `path`, under `sudo` (`sudo ` or empty).
fn exists_command(sudo: &str, path: &str) -> String {
    format!(
        "{sudo}sh -c {} sh {}",
        single_quote(EXISTS_PROBE),
        single_quote(path)
    )
}

/// What an [`EXISTS_PROBE`] run says of `path`. Only the probe's own answer counts: a
/// run that failed or said anything else — `sudo` refused, the shell didn't start — is
/// an error, never a read of "absent", which would plan over state that is there.
fn read_exists(path: &str, output: &CommandOutput) -> Result<bool> {
    match output.stdout.trim() {
        "present" if output.success => Ok(true),
        "absent" if output.success => Ok(false),
        _ => Err(file_op(
            "stat",
            path,
            FailureCause::Exited {
                stderr: output.stderr.trim().to_owned(),
                code: output.code,
            },
        )),
    }
}

/// Create `target ← path` natively, as [`LINK_PUT`](zap_types::put::LINK_PUT) does: the
/// link is made under a fresh name beside `path` and renamed over it, so what stands at
/// `path` is replaced in one step and never reads as missing, and a real directory there
/// is refused — before, and by the rename, which refuses one put there after the check.
/// A `NotFound` while stat-ing means there's nothing to replace (fine); other stat
/// errors surface.
async fn symlink_local(target: &str, path: &str) -> std::io::Result<()> {
    use std::sync::atomic::{AtomicU64, Ordering};

    /// Tells this process's fresh names apart.
    static FRESH: AtomicU64 = AtomicU64::new(0);
    let is_a_directory = || {
        std::io::Error::new(
            std::io::ErrorKind::IsADirectory,
            "is a directory, not a link",
        )
    };
    match tokio::fs::symlink_metadata(path).await {
        Ok(metadata) if metadata.is_dir() => return Err(is_a_directory()),
        Err(error) if error.kind() != std::io::ErrorKind::NotFound => return Err(error),
        _ => {}
    }
    let parent = std::path::Path::new(path)
        .parent()
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidInput, "no parent"))?;
    // A name already taken — an earlier run's, or anything placed there — is never
    // reused: `symlink` makes a new entry or fails, and the next name is tried.
    let mut attempts = 0;
    let fresh = loop {
        let fresh = parent.join(format!(
            ".zap-link.{}.{}",
            std::process::id(),
            FRESH.fetch_add(1, Ordering::Relaxed)
        ));
        match tokio::fs::symlink(target, &fresh).await {
            Ok(()) => break fresh,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists && attempts < 8 => {
                attempts += 1;
            }
            Err(error) => return Err(error),
        }
    };
    match tokio::fs::rename(&fresh, path).await {
        Ok(()) => Ok(()),
        Err(error) => {
            let _ = tokio::fs::remove_file(&fresh).await;
            if error.raw_os_error() == Some(nix::libc::EISDIR) {
                Err(is_a_directory())
            } else {
                Err(error)
            }
        }
    }
}

/// Run a command locally under `sh`, honoring `cwd` / `env`.
async fn run_local(cmd: &str, options: &RunOptions) -> Result<CommandOutput> {
    spawn_sh(cmd, options).await
}

/// Read the regular file at `path` natively: a symbolic link at the name or anything
/// that isn't a regular file is refused (`InvalidInput`, naming why) and nothing is
/// opened through it; the open follows no link and never blocks, and what it opened
/// must be a regular file too, of one hard link
/// ([`HARD_LINK_REFUSAL`](zap_types::put::HARD_LINK_REFUSAL)).
async fn read_regular_local(path: &str) -> std::io::Result<Vec<u8>> {
    use tokio::io::AsyncReadExt as _;

    let refused = |why: &str| std::io::Error::new(std::io::ErrorKind::InvalidInput, why);
    let own = tokio::fs::symlink_metadata(path).await?;
    if own.file_type().is_symlink() {
        return Err(refused("a symbolic link is not read through"));
    }
    if !own.is_file() {
        return Err(refused("not a regular file"));
    }
    let mut file = tokio::fs::OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NONBLOCK | nix::libc::O_NOFOLLOW)
        .open(path)
        .await?;
    let opened = file.metadata().await?;
    if !opened.is_file() {
        return Err(refused("not a regular file"));
    }
    if std::os::unix::fs::MetadataExt::nlink(&opened) != 1 {
        return Err(refused(zap_types::put::HARD_LINK_REFUSAL));
    }
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes).await?;
    Ok(bytes)
}

/// Run `cmd` under a local `sh` — its text on the shell's stdin, never its argv — with
/// `options`' `cwd` and `env`, and collect its output into a [`CommandOutput`].
async fn spawn_sh(cmd: &str, options: &RunOptions) -> Result<CommandOutput> {
    let delivery = Delivery::of(cmd, None).map_err(Error::Command)?;
    let command = delivery.local_command("sh", options);
    let output = delivery.run(command).await.map_err(Error::Command)?;
    Ok(output.into())
}

/// Run `cmd` under a local `sh` and capture its raw stdout bytes — the local arm of the
/// binary-safe capture. Mirrors [`spawn_sh`] but keeps stdout as `Vec<u8>` instead of
/// the lossy `String`, so a binary-emitting command round-trips exactly.
async fn spawn_sh_raw(cmd: &str) -> Result<RawOutput> {
    let delivery = Delivery::of(cmd, None).map_err(Error::Command)?;
    let command = delivery.local_command("sh", &RunOptions::default());
    let output = delivery.run(command).await.map_err(Error::Command)?;
    Ok(output.into())
}

/// Run `cmd` under a local `sh` with `content` as the stdin its commands read,
/// collecting its output. Used for the privileged put (content off the argv).
async fn spawn_sh_stdin(cmd: &str, content: &[u8]) -> Result<CommandOutput> {
    let delivery = Delivery::of(cmd, Some(content)).map_err(Error::Command)?;
    let command = delivery.local_command("sh", &RunOptions::default());
    let output = delivery.run(command).await.map_err(Error::Command)?;
    Ok(output.into())
}

/// Feed `input` to an already-spawned child's stdin, then collect its output — the
/// shared stdin-write path for the local (`sh`) and remote (`ssh`) arms.
///
/// The write runs in a **concurrent** task rather than inline-before-the-wait: a command
/// that interleaves reading its input with writing output would otherwise deadlock —
/// blocked writing stdin while its stdout pipe fills with nothing draining it.
/// `wait_with_output` drains stdout/stderr while the task writes; dropping the task's
/// `stdin` closes the pipe so the child reads EOF. (`stdin` is always `Some` here — the
/// callers pipe it — so a missing handle just skips the write rather than erroring.)
///
/// TODO: `wait_with_output` buffers both pipes with no byte ceiling — the
/// same shape `fuz_eval` replaced with `fuz_sys::capture`'s capped reads.
/// These are trusted local/remote commands, so it's a hardening nicety, not a
/// live exposure; adopt the capped capture when touching this path.
async fn pipe_stdin_and_wait(
    mut child: tokio::process::Child,
    input: impl Into<Vec<u8>>,
) -> std::io::Result<std::process::Output> {
    let Some(mut stdin) = child.stdin.take() else {
        return child.wait_with_output().await;
    };
    let input = input.into();
    let writer = tokio::spawn(async move {
        let _ = stdin.write_all(&input).await;
        // dropping `stdin` closes the pipe so the child reads EOF
    });
    let output = child.wait_with_output().await;
    let _ = writer.await;
    output
}

#[cfg(test)]
mod tests {
    use zap_types::put::{FileAttrs, PutCheck, RunAs, dir_attrs_command, file_put_command};

    use super::{
        CommandOutput, Connection, MockConnection, RunOptions, SshConnection, exists_command,
    };
    use crate::error::Error;

    fn ok_output() -> CommandOutput {
        CommandOutput {
            success: true,
            code: 0,
            stdout: String::new(),
            stderr: String::new(),
        }
    }

    fn ssh(home: Option<&str>) -> Connection {
        Connection::Ssh(SshConnection {
            host: "h".to_owned(),
            user: "u".to_owned(),
            port: None,
            key_path: None,
            home: home.map(str::to_owned),
        })
    }

    /// A probe that didn't answer — `sudo` refused it — is an error naming the path,
    /// never a read of "absent"; the probe's own answers read as they say.
    #[tokio::test]
    async fn a_denied_existence_probe_is_an_error_not_an_absence() {
        let answer = |success: bool, stdout: &str, stderr: &str| CommandOutput {
            success,
            code: i32::from(!success),
            stdout: stdout.to_owned(),
            stderr: stderr.to_owned(),
        };
        let probe = exists_command("", "/srv/a");
        for (output, read) in [
            (answer(true, "present\n", ""), Some(true)),
            (answer(true, "absent\n", ""), Some(false)),
            (answer(false, "", "sudo: a password is required"), None),
            (answer(true, "", ""), None),
        ] {
            let conn = Connection::Mock(MockConnection::new("mock").with(&probe, output));
            match (conn.exists("/srv/a").await, read) {
                (Ok(found), Some(read)) => assert_eq!(found, read),
                (
                    Err(Error::FileOp {
                        op: "stat", path, ..
                    }),
                    None,
                ) => assert_eq!(path, "/srv/a"),
                (other, read) => panic!("{read:?}: {other:?}"),
            }
        }
    }

    /// A run's `Debug` names its variables and shows none of their values.
    #[test]
    fn run_options_debug_shows_no_env_value() {
        let options = RunOptions {
            cwd: Some("/srv/app".into()),
            env: vec![("TOKEN".to_owned(), "hunter2-s3cret".to_owned())],
        };
        let shown = format!("{options:?} {options:#?}");
        assert!(
            shown.contains("TOKEN") && shown.contains("/srv/app"),
            "{shown}"
        );
        assert!(!shown.contains("hunter2"), "{shown}");
    }

    #[test]
    fn host_reports_resolved_remote_host() {
        assert_eq!(ssh(None).host(), "h");
        assert_eq!(Connection::Local.host(), "local");
    }

    /// A symbolic link loop names nothing: locally `exists` answers `false`, as the
    /// `test -e` an SSH target runs does, for the link and for a path through it, and
    /// asks no `sudo`.
    #[tokio::test]
    async fn a_link_loop_does_not_exist_locally_as_test_e_reads_it() {
        let dir = tempfile::tempdir().unwrap();
        let (a, b) = (dir.path().join("a"), dir.path().join("b"));
        std::os::unix::fs::symlink(&b, &a).unwrap();
        std::os::unix::fs::symlink(&a, &b).unwrap();
        for path in [a.clone(), a.join("x")] {
            let text = path.to_string_lossy().into_owned();
            assert!(!Connection::Local.exists(&text).await.unwrap(), "{text}");
            let shell = std::process::Command::new("sh")
                .args(["-c", "test -e \"$1\"", "sh", &text])
                .status()
                .unwrap();
            assert!(!shell.success(), "{text}: `test -e` reads it the same");
        }
        assert!(
            Connection::Local
                .exists(&dir.path().to_string_lossy())
                .await
                .unwrap()
        );
    }

    /// Text that still holds a reference — whole, or a delimiter of one — reaches no
    /// shell and names no path, on any connection: the command is refused before
    /// anything is spawned or looked up, a read reads nothing, and a write creates
    /// nothing.
    #[tokio::test]
    async fn text_holding_an_unresolved_reference_reaches_nothing() {
        use zap_types::observe::{PathFacet, Privilege, Query};
        use zap_types::var_ref::{CLOSE, OPEN, marker};

        let dir = tempfile::tempdir().unwrap();
        let ran = dir.path().join("ran");
        let unresolved = [
            marker("ZAP_T_UNRESOLVED"),
            format!("half{OPEN}"),
            format!("half{CLOSE}"),
        ];
        // A mock that would answer anything it was asked.
        let recorded =
            |command: &str| Connection::Mock(MockConnection::new("h").with(command, ok_output()));
        for text in &unresolved {
            let command = format!("touch '{}' # {text}", ran.display());
            for conn in [Connection::Local, recorded(&command)] {
                for result in [
                    conn.run_default(&command).await,
                    conn.run(&command, &RunOptions::default()).await,
                    conn.run_composed(&command, &RunOptions::default()).await,
                ] {
                    let error = result.unwrap_err();
                    assert!(matches!(error, Error::Command(_)), "{error:?}");
                    assert!(
                        error.to_string().ends_with(
                            "the command holds a reference delimiter (U+FDD0 or U+FDD1) — an unresolved \
                             reference, or a value containing one — which no shell can read; it \
                             was not run"
                        ),
                        "{error}"
                    );
                }
                let error = conn.run_raw_stdout(&command).await.map(|_| ()).unwrap_err();
                assert!(matches!(error, Error::Command(_)), "{error:?}");
                let error = conn
                    .observe(&[Query::login_command(command.clone())])
                    .await
                    .unwrap_err();
                assert!(matches!(error, Error::Command(_)), "{error:?}");
                assert!(error.to_string().contains("the command holds"), "{error}");

                let path = format!("{}/{text}", dir.path().display());
                let error = conn
                    .observe(&[Query::path(path.clone(), PathFacet::Kind, Privilege::Login)])
                    .await
                    .unwrap_err();
                assert!(matches!(error, Error::Command(_)), "{error:?}");
                // A path read is refused as a path, not as a command.
                assert!(
                    error
                        .to_string()
                        .contains("the path holds a reference delimiter"),
                    "{error}"
                );
                for error in [
                    conn.exists(&path).await.map(|_| ()).unwrap_err(),
                    conn.read_source(&path).await.map(|_| ()).unwrap_err(),
                    conn.read_bytes(&path).await.map(|_| ()).unwrap_err(),
                    conn.write_file(&path, "x", FileAttrs::default())
                        .await
                        .unwrap_err(),
                    conn.push_bytes(&path, b"x", FileAttrs::default())
                        .await
                        .unwrap_err(),
                    conn.make_dir(&path).await.unwrap_err(),
                    conn.make_symlink("/etc/hostname", &path).await.unwrap_err(),
                    conn.make_symlink(&path, &format!("{}/link", dir.path().display()))
                        .await
                        .unwrap_err(),
                    conn.remove_file(&path).await.unwrap_err(),
                    conn.copy_file(std::path::Path::new("/etc/hostname"), &path)
                        .await
                        .unwrap_err(),
                    conn.place_file(
                        std::path::Path::new("/etc/hostname"),
                        &path,
                        FileAttrs::default(),
                    )
                    .await
                    .unwrap_err(),
                    conn.set_dir_attrs(&path, FileAttrs::mode("700"))
                        .await
                        .unwrap_err(),
                ] {
                    assert!(matches!(error, Error::FileOp { .. }), "{error:?}");
                    assert!(
                        error.to_string().ends_with(
                            "the path holds a reference delimiter (U+FDD0 or U+FDD1) — an unresolved \
                             reference, or a value containing one; nothing was read or written"
                        ),
                        "{error}"
                    );
                }
            }
        }
        assert!(!ran.exists());
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
        // The same command, its reference resolved, runs.
        let resolved = format!("touch '{}'", ran.display());
        assert!(
            Connection::Local
                .run_default(&resolved)
                .await
                .unwrap()
                .success
        );
        assert!(ran.exists());
    }

    #[test]
    fn apply_home_absolute_path_passes_through_on_every_arm() {
        // No home reference, so no home needed — local, remote-with-home, and
        // remote-without-home all agree.
        assert_eq!(
            Connection::Local.apply_home("/etc/app").ok().as_deref(),
            Some("/etc/app")
        );
        assert_eq!(
            ssh(Some("/home/deploy"))
                .apply_home("/etc/app")
                .ok()
                .as_deref(),
            Some("/etc/app")
        );
        assert_eq!(
            ssh(None).apply_home("/etc/app").ok().as_deref(),
            Some("/etc/app")
        );
    }

    #[test]
    fn apply_home_remote_uses_declared_target_home() {
        let conn = ssh(Some("/home/deploy"));
        assert_eq!(
            conn.apply_home("~/app").ok().as_deref(),
            Some("/home/deploy/app")
        );
        assert_eq!(
            conn.apply_home("$HOME/x").ok().as_deref(),
            Some("/home/deploy/x")
        );
        assert_eq!(conn.apply_home("~").ok().as_deref(), Some("/home/deploy"));
    }

    #[test]
    fn apply_home_remote_without_target_home_errors_on_home_reference() {
        let conn = ssh(None);
        assert!(matches!(
            conn.apply_home("~/app"),
            Err(Error::RemoteHomeUnset { .. })
        ));
        assert!(matches!(
            conn.apply_home("$HOME/x"),
            Err(Error::RemoteHomeUnset { .. })
        ));
    }

    /// The put command a mock is asked for: the script run as the caller.
    fn put(path: &str, attrs: FileAttrs<'_>) -> String {
        file_put_command(RunAs::Caller, path, attrs, PutCheck::None)
    }

    #[tokio::test]
    async fn a_write_is_one_put_command_holding_neither_content_nor_digest() {
        // A non-local write is the put script and nothing else: one command, the same
        // text for any content, with the mode and owner as its arguments. The bytes and
        // their digest travel on stdin, so a secret in the content can't reach `ps` — a
        // mock keys on the exact command, and logs every one it is asked for.
        let attrs = FileAttrs {
            mode: Some("600"),
            owner: Some("app"),
            group: None,
            ..FileAttrs::NONE
        };
        let secret = "SECRET_TOKEN=hunter2\n";
        let conn = Connection::Mock(
            MockConnection::new("m").with(put("/etc/app.conf", attrs), ok_output()),
        );
        conn.write_file("/etc/app.conf", secret, attrs)
            .await
            .expect("the write is the recorded put");
        let Connection::Mock(mock) = &conn else {
            unreachable!()
        };
        let issued = mock.issued_commands();
        assert_eq!(issued, [put("/etc/app.conf", attrs)]);
        assert!(issued[0].ends_with("sh '/etc/app.conf' '600' 'app' '' ''"));
        let digest = crate::digest::sha512_hex(secret.as_bytes());
        assert!(!issued[0].contains("hunter2") && !issued[0].contains(&digest));
    }

    /// A privileged script runs as root on a real target — `Local` included, which
    /// reaches it only once the native attempt was denied — and as the caller on a mock.
    #[test]
    fn a_privileged_script_runs_as_root_on_a_real_target() {
        assert_eq!(Connection::Local.script_run_as(), RunAs::Root);
        assert_eq!(ssh(None).script_run_as(), RunAs::Root);
        assert_eq!(
            Connection::Mock(MockConnection::new("m")).script_run_as(),
            RunAs::Caller
        );
    }

    /// A push is the put as the connecting user on every connection that scripts it: a
    /// mock is asked for the one `sudo`-less command, and nothing is tried again with
    /// more privilege when it fails.
    #[tokio::test]
    async fn a_push_is_the_put_as_the_caller_and_never_escalates() {
        let attrs = FileAttrs::mode("600");
        let command = put("/srv/app/.zap-deploy-deploy-abc.tar.gz", attrs);
        assert!(command.starts_with("sh -c '"), "{command}");
        let conn = Connection::Mock(MockConnection::new("m").with(command.clone(), ok_output()));
        conn.push_bytes(
            "/srv/app/.zap-deploy-deploy-abc.tar.gz",
            b"\0archive",
            attrs,
        )
        .await
        .expect("the push is the recorded put");
        let Connection::Mock(mock) = &conn else {
            unreachable!()
        };
        assert_eq!(mock.issued_commands(), std::slice::from_ref(&command));

        let denied = CommandOutput {
            success: false,
            code: 1,
            stdout: String::new(),
            stderr: "sh: can't create ./.zap.Ab12Cd: Permission denied\n".to_owned(),
        };
        let conn = Connection::Mock(MockConnection::new("m").with(command.clone(), denied));
        let error = conn
            .push_bytes("/srv/app/.zap-deploy-deploy-abc.tar.gz", b"x", attrs)
            .await
            .expect_err("a denied push fails");
        assert!(error.to_string().contains("Permission denied"), "{error}");
        let Connection::Mock(mock) = &conn else {
            unreachable!()
        };
        assert_eq!(mock.issued_commands(), [command]);
    }

    /// On this machine a push installs natively, as the operator: the bytes at mode
    /// `600`, a link at the name replaced and what it pointed at untouched, and a
    /// directory the operator can't write a failure — never a `sudo`.
    #[tokio::test]
    async fn a_local_push_installs_natively_and_follows_no_link() {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = tempfile::tempdir().unwrap();
        let victim = dir.path().join("victim");
        std::fs::write(&victim, "ORIGINAL").unwrap();
        let dest = dir.path().join("archive.tar.gz");
        std::os::unix::fs::symlink(&victim, &dest).unwrap();
        Connection::Local
            .push_bytes(&dest.to_string_lossy(), b"\0bytes", FileAttrs::mode("600"))
            .await
            .unwrap();
        assert!(std::fs::symlink_metadata(&dest).unwrap().is_file());
        assert_eq!(std::fs::read(&dest).unwrap(), b"\0bytes");
        assert_eq!(
            std::fs::metadata(&dest).unwrap().permissions().mode() & 0o7777,
            0o600
        );
        assert_eq!(std::fs::read(&victim).unwrap(), b"ORIGINAL");

        // A directory that isn't there fails as itself. (An unwritable one would be
        // `PermissionDenied`, which this never hands to `sudo`: the arm returns before
        // any script is composed.)
        let missing = dir.path().join("absent").join("a");
        let error = Connection::Local
            .push_bytes(&missing.to_string_lossy(), b"x", FileAttrs::mode("600"))
            .await
            .expect_err("no directory to stage in");
        assert!(matches!(error, Error::FileOp { op: "push", .. }), "{error}");
    }

    /// Natively, a link at the path — to a directory, dangling — and a plain file are
    /// replaced by the link, and nothing of the fresh name it was made under is left
    /// beside it, nor after a refusal.
    #[tokio::test]
    async fn a_native_link_leaves_no_fresh_name_behind() {
        let dir = tempfile::tempdir().unwrap();
        let at = |name: &str| dir.path().join(name);
        std::fs::create_dir(at("real")).unwrap();
        std::os::unix::fs::symlink(at("real"), at("to_dir")).unwrap();
        std::fs::write(at("plain"), "x").unwrap();
        std::os::unix::fs::symlink(at("nowhere"), at("dangling")).unwrap();
        let names = || {
            let mut names: Vec<String> = std::fs::read_dir(dir.path())
                .unwrap()
                .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
                .collect();
            names.sort();
            names
        };
        let before = names();
        for name in ["to_dir", "plain", "dangling", "fresh"] {
            Connection::Local
                .make_symlink("/etc/hostname", &at(name).to_string_lossy())
                .await
                .unwrap();
            assert_eq!(
                std::fs::read_link(at(name)).unwrap(),
                std::path::Path::new("/etc/hostname"),
                "{name}"
            );
        }
        Connection::Local
            .make_symlink("/etc/hostname", &at("real").to_string_lossy())
            .await
            .unwrap_err();
        let mut want = before;
        want.push("fresh".to_owned());
        want.sort();
        assert_eq!(names(), want, "no `.zap-link.*` is left");
    }

    /// A real directory where a link is declared fails the step, natively and through
    /// the shell form, with nothing made inside it; a link there (even to a directory)
    /// and a regular file are replaced.
    #[tokio::test]
    async fn a_link_never_lands_inside_a_directory_at_its_path() {
        let dir = tempfile::tempdir().unwrap();
        let at = |name: &str| dir.path().join(name).to_string_lossy().into_owned();
        std::fs::create_dir(at("real")).unwrap();
        let error = Connection::Local
            .make_symlink("/etc/hostname", &at("real"))
            .await
            .expect_err("a directory at the path");
        assert!(error.to_string().contains("is a directory"), "{error}");
        assert_eq!(std::fs::read_dir(at("real")).unwrap().count(), 0);

        let shell = |path: String, target: &str| {
            std::process::Command::new("sh")
                .args(["-c", zap_types::put::LINK_PUT, "sh", &path, target])
                .output()
                .unwrap()
        };
        let refused = shell(at("real"), "/etc/hostname");
        assert!(!refused.status.success());
        assert!(String::from_utf8_lossy(&refused.stderr).contains("is a directory"));
        assert_eq!(std::fs::read_dir(at("real")).unwrap().count(), 0);

        std::os::unix::fs::symlink(at("real"), at("to_dir")).unwrap();
        std::fs::write(at("plain"), "x").unwrap();
        for name in ["to_dir", "plain"] {
            assert!(shell(at(name), "/etc/hostname").status.success(), "{name}");
            assert_eq!(
                std::fs::read_link(at(name)).unwrap(),
                std::path::Path::new("/etc/hostname")
            );
        }
        assert_eq!(std::fs::read_dir(at("real")).unwrap().count(), 0);
    }

    /// A directory is never made through a symbolic link at its own name: a dangling
    /// one fails the create — natively, and as a failure that isn't "not permitted", so
    /// no `sudo` follows — with nothing made where it points; one to a directory is that
    /// directory already, and nothing is made. A link in a component above is followed.
    #[tokio::test]
    async fn a_directory_is_not_made_through_a_link_at_its_name() {
        let dir = tempfile::tempdir().unwrap();
        let at = |name: &str| dir.path().join(name);
        std::os::unix::fs::symlink(at("nowhere"), at("dangling")).unwrap();
        let error = Connection::Local
            .make_dir(&at("dangling").to_string_lossy())
            .await
            .expect_err("a dangling link is not a directory to make");
        assert!(
            matches!(error, Error::FileOp { op: "mkdir", .. }),
            "{error}"
        );
        assert!(!at("nowhere").exists());

        std::fs::create_dir(at("real")).unwrap();
        std::os::unix::fs::symlink(at("real"), at("alias")).unwrap();
        Connection::Local
            .make_dir(&at("alias").to_string_lossy())
            .await
            .unwrap();
        assert!(std::fs::symlink_metadata(at("alias")).unwrap().is_symlink());
        assert_eq!(std::fs::read_dir(at("real")).unwrap().count(), 0);

        Connection::Local
            .make_dir(&at("alias").join("sub").to_string_lossy())
            .await
            .unwrap();
        assert!(at("real").join("sub").is_dir());
    }

    #[tokio::test]
    async fn a_failed_put_reports_the_scripts_words_and_nothing_of_the_content() {
        let secret = "SECRET_TOKEN=hunter2\n";
        let refused = CommandOutput {
            success: false,
            code: 1,
            stdout: String::new(),
            stderr: "zap: /etc/app.conf: the bytes received are not the bytes sent; left \
                     unchanged\n"
                .to_owned(),
        };
        let conn = Connection::Mock(
            MockConnection::new("m").with(put("/etc/app.conf", FileAttrs::NONE), refused),
        );
        let error = conn
            .write_file("/etc/app.conf", secret, FileAttrs::NONE)
            .await
            .unwrap_err()
            .to_string();
        assert!(error.contains("left unchanged"), "{error}");
        let digest = crate::digest::sha512_hex(secret.as_bytes());
        assert!(
            !error.contains("hunter2") && !error.contains(&digest),
            "{error}"
        );
    }

    /// A scripted file operation that fails classifies by its exit status beside its
    /// words, as a command does: 126 is permission, 127 not found, and the script's own
    /// refusal (`REFUSED_EXIT`) by its words alone. The message is the script's words,
    /// whatever its status.
    #[tokio::test]
    async fn a_failed_file_op_classifies_by_its_exit_status() {
        use zap_types::error_code::ErrorCode as C;
        use zap_types::put::REFUSED_EXIT;

        for (code, stderr, expected) in [
            (126, "sh: 1: rm: nope\n", C::Permission),
            (127, "sh: 1: rm: nope\n", C::NotFound),
            (1, "sh: 1: rm: nope\n", C::ExecutionFailed),
            (
                REFUSED_EXIT,
                "zap: /srv/x: a directory is in the way; left unchanged\n",
                C::ExecutionFailed,
            ),
            (
                REFUSED_EXIT,
                "zap: /srv/x: Permission denied; left unchanged\n",
                C::Permission,
            ),
        ] {
            let failed = CommandOutput {
                success: false,
                code,
                stdout: String::new(),
                stderr: stderr.to_owned(),
            };
            let conn = Connection::Mock(
                MockConnection::new("m")
                    .with("rm -f -- '/srv/x'", failed.clone())
                    .with(put("/srv/x", FileAttrs::NONE), failed),
            );
            for (op, error) in [
                ("remove", conn.remove_file("/srv/x").await.unwrap_err()),
                (
                    "write",
                    conn.write_file("/srv/x", "x", FileAttrs::NONE)
                        .await
                        .unwrap_err(),
                ),
            ] {
                assert_eq!(error.error_code(), expected, "{code}: {error}");
                assert_eq!(
                    error.to_string(),
                    format!("failed to {op} /srv/x: {}", stderr.trim()),
                    "{code}"
                );
            }
        }
    }

    /// A local snapshot the operator couldn't read is tried again under `sudo` — but not
    /// past the script's own refusal or its timeout, which root would meet the same way.
    #[test]
    fn a_local_snapshot_escalates_only_past_a_failure_root_could_change() {
        let attempt = |success, code| super::RawOutput {
            success,
            code,
            stdout: Vec::new(),
            stderr: String::new(),
        };
        assert!(!super::snapshot_retries_as_root(&attempt(true, 0)));
        for code in [zap_types::put::REFUSED_EXIT, 124, 143] {
            assert!(
                !super::snapshot_retries_as_root(&attempt(false, code)),
                "{code}"
            );
        }
        // a denied open (the shell's redirection error), a tool's failure, no exit code
        for code in [2, 1, -1] {
            assert!(
                super::snapshot_retries_as_root(&attempt(false, code)),
                "{code}"
            );
        }
    }

    /// The operator's `absent` is taken only when the operator's own lookup finds the
    /// name missing: a lookup that is denied, finds something, or fails otherwise sends
    /// the snapshot to `sudo`, so a shell that misjudges what it may search can't have a
    /// rollback remove what is there.
    #[test]
    fn a_local_absent_is_taken_only_when_the_lookup_finds_nothing() {
        use std::io::{Error as IoError, ErrorKind};

        let attempt = |success, code, stdout: &[u8]| super::RawOutput {
            success,
            code,
            stdout: stdout.to_vec(),
            stderr: String::new(),
        };
        let absent = attempt(true, 0, b"absent\n");
        let lookup =
            |kind: Option<ErrorKind>| move || kind.map_or(Ok(()), |kind| Err(IoError::from(kind)));
        assert!(!super::local_snapshot_escalates(
            &absent,
            lookup(Some(ErrorKind::NotFound))
        ));
        for kind in [
            Some(ErrorKind::PermissionDenied),
            None,
            Some(ErrorKind::Other),
        ] {
            assert!(
                super::local_snapshot_escalates(&absent, lookup(kind)),
                "{kind:?}"
            );
        }
        // A file it read, or a refusal, is the answer whatever the lookup says.
        let read = attempt(true, 0, b"file 644 0 0 1\nx");
        let refused = attempt(false, zap_types::put::REFUSED_EXIT, b"");
        for answer in [&read, &refused] {
            assert!(!super::local_snapshot_escalates(
                answer,
                lookup(Some(ErrorKind::PermissionDenied))
            ));
        }
    }

    /// On this machine the snapshot is the operator's own read first: a file the
    /// operator may read is read without `sudo`, and the script's refusal of a link is
    /// the answer, not a reason to escalate.
    #[tokio::test]
    async fn a_local_snapshot_reads_as_the_operator() {
        use std::os::unix::fs::PermissionsExt as _;
        use zap_types::put::Snapshot;

        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("it's.conf");
        std::fs::write(&file, b"old\n").unwrap();
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o640)).unwrap();
        let path = file.to_string_lossy().into_owned();
        assert_eq!(
            Connection::Local.snapshot(&path).await.unwrap(),
            Snapshot::File {
                mode: 0o640,
                uid: nix::unistd::geteuid().as_raw(),
                gid: nix::unistd::getegid().as_raw(),
                bytes: b"old\n".to_vec(),
            }
        );
        let absent = dir.path().join("absent").to_string_lossy().into_owned();
        assert_eq!(
            Connection::Local.snapshot(&absent).await.unwrap(),
            Snapshot::Absent
        );
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&file, &link).unwrap();
        let refused = Connection::Local
            .snapshot(&link.to_string_lossy())
            .await
            .unwrap_err();
        assert!(
            matches!(&refused, Error::ReadFile { cause, .. }
                if cause.to_string().ends_with("a symbolic link is not read through; left unchanged")),
            "{refused:?}"
        );
    }

    /// A snapshot or a directory change that runs past its `timeout` — GNU's 124 or
    /// `BusyBox`'s 143 — fails with that said, not as an answer that doesn't parse or a
    /// bare exit, and classified as the timeout it is.
    #[tokio::test]
    async fn a_script_past_its_timeout_says_so() {
        let timed_out = |code| CommandOutput {
            success: false,
            code,
            stdout: String::new(),
            stderr: String::new(),
        };
        let says_so = |error: &Error| {
            assert!(
                error
                    .to_string()
                    .contains("did not finish within 300 seconds"),
                "{error}"
            );
            // a timeout, whatever its words: a retry may finish
            assert_eq!(
                error.error_code(),
                zap_types::error_code::ErrorCode::Transient,
                "{error}"
            );
        };
        for code in [124, 143] {
            let snapshot = zap_types::put::file_snapshot_command(RunAs::Caller, "/etc/x");
            let attrs = dir_attrs_command(RunAs::Caller, "/srv/d", FileAttrs::mode("750"));
            let mkdirs = zap_types::put::make_dirs_command(RunAs::Caller, "/srv/e");
            let conn = Connection::Mock(
                MockConnection::new("m")
                    .with(snapshot, timed_out(code))
                    .with(attrs, timed_out(code))
                    .with(mkdirs, timed_out(code)),
            );
            says_so(&conn.make_dir("/srv/e").await.unwrap_err());
            says_so(&conn.snapshot("/etc/x").await.unwrap_err());
            says_so(
                &conn
                    .set_dir_attrs("/srv/d", FileAttrs::mode("750"))
                    .await
                    .unwrap_err(),
            );
        }
    }

    #[tokio::test]
    async fn local_write_round_trips_natively() {
        // The `Local` arm writes via `std::fs` (no shell, no argv exposure at all).
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("f.conf");
        Connection::Local
            .write_file(&path.to_string_lossy(), "line\n", FileAttrs::mode("640"))
            .await
            .unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "line\n");
        assert_eq!(
            std::os::unix::fs::MetadataExt::mode(&std::fs::metadata(&path).unwrap()) & 0o7777,
            0o640
        );
    }

    #[tokio::test]
    async fn place_file_local_installs_natively() {
        // The `Local` arm places natively when the operator can write `dest` (no shell,
        // no argv exposure) — binary bytes round-trip exactly, over what was there.
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("src.bin");
        let dest = dir.path().join("dest.bin");
        std::fs::write(&src, b"\x00\x01\x02payload").unwrap();
        std::fs::write(&dest, b"old").unwrap();
        Connection::Local
            .place_file(&src, &dest.to_string_lossy(), FileAttrs::NONE)
            .await
            .unwrap();
        assert_eq!(std::fs::read(&dest).unwrap(), b"\x00\x01\x02payload");
    }

    #[tokio::test]
    async fn place_file_shell_path_is_the_one_put_command() {
        // A non-local place reads the local bytes and hands them to the same put as
        // `write_file` — the (binary) bytes ride stdin, never the argv. An unrecorded
        // command would fail the place.
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("artifact");
        std::fs::write(&src, b"\x7fELF\x00binary").unwrap();
        let attrs = FileAttrs::mode("755");
        let conn = Connection::Mock(
            MockConnection::new("m").with(put("/opt/bin/zap", attrs), ok_output()),
        );
        conn.place_file(&src, "/opt/bin/zap", attrs)
            .await
            .expect("the place is the recorded put");
        let Connection::Mock(mock) = &conn else {
            unreachable!()
        };
        assert_eq!(mock.issued_commands(), [put("/opt/bin/zap", attrs)]);
    }

    #[tokio::test]
    async fn dir_attrs_is_one_command_and_none_when_nothing_is_set() {
        let attrs = FileAttrs {
            mode: Some("750"),
            owner: None,
            group: Some("www"),
            ..FileAttrs::NONE
        };
        let command = dir_attrs_command(RunAs::Caller, "/srv/app", attrs);
        let conn = Connection::Mock(MockConnection::new("m").with(command.clone(), ok_output()));
        conn.set_dir_attrs("/srv/app", attrs).await.unwrap();
        conn.set_dir_attrs("/srv/app", FileAttrs::NONE)
            .await
            .unwrap();
        let Connection::Mock(mock) = &conn else {
            unreachable!()
        };
        assert_eq!(mock.issued_commands(), [command]);
    }

    #[tokio::test]
    async fn spawn_sh_raw_preserves_non_utf8_bytes() {
        // `printf '\377\376'` emits bytes 0xFF 0xFE — invalid UTF-8. The raw-capture path
        // (the binary-safe SSH read's mechanism, exercised here over local `sh`) must
        // return them verbatim; the lossy `String` path it replaced would have mangled
        // them into the U+FFFD replacement char, so this proves binary-exactness.
        let output = super::spawn_sh_raw("printf '\\377\\376'").await.unwrap();
        assert!(output.success);
        assert_eq!(output.stdout, vec![0xFF, 0xFE]);
    }

    #[tokio::test]
    async fn read_bytes_routes_through_the_raw_path() {
        // A non-local `read_bytes` runs `FILE_BYTES` for the path (a mock adds no `sudo`
        // prefix) and routes it through `run_raw_stdout`; the mock replays its recorded
        // stdout as bytes, so a recording + a successful read prove the raw dispatch is
        // wired.
        let conn = Connection::Mock(MockConnection::new("m").with(
            zap_types::put::file_bytes_command("", "/opt/bin"),
            CommandOutput {
                success: true,
                code: 0,
                stdout: "ELF-ish".to_owned(),
                stderr: String::new(),
            },
        ));
        assert_eq!(conn.read_bytes("/opt/bin").await.unwrap(), b"ELF-ish");
    }

    /// A read that fails keeps its exit status, so a tool the target lacks (`127`) is
    /// classified as missing however the shell words it.
    #[tokio::test]
    async fn a_failed_read_is_classified_by_its_exit_status() {
        let missing = || CommandOutput {
            success: false,
            code: 127,
            stdout: String::new(),
            stderr: "sh: head: not found\n".to_owned(),
        };
        let conn = Connection::Mock(
            MockConnection::new("m")
                .with(
                    zap_types::put::file_bytes_command("", "/opt/bin"),
                    missing(),
                )
                .with(
                    zap_types::put::file_snapshot_command(RunAs::Caller, "/etc/x"),
                    missing(),
                ),
        );
        for error in [
            conn.read_bytes("/opt/bin").await.unwrap_err(),
            conn.snapshot("/etc/x").await.unwrap_err(),
        ] {
            assert_eq!(
                error.error_code(),
                zap_types::error_code::ErrorCode::NotFound,
                "{error}"
            );
            assert!(error.to_string().contains("sh: head: not found"), "{error}");
        }
    }

    /// A regular file with a second hard link is read by no root read path: the native
    /// read, the bytes script, and the snapshot script each refuse it, naming the fix,
    /// and the snapshot doesn't escalate to `sudo` over its refusal.
    #[tokio::test]
    async fn every_read_refuses_a_hard_linked_file() {
        let dir = crate::test_scratch::tempdir();
        let path = dir.path().join("linked");
        std::fs::write(&path, "x").unwrap();
        std::fs::hard_link(&path, dir.path().join("twin")).unwrap();
        let path = path.to_string_lossy().into_owned();
        let says_so = |error: &Error| {
            assert!(
                error
                    .to_string()
                    .contains(zap_types::put::HARD_LINK_REFUSAL),
                "{error}"
            );
        };
        says_so(&Connection::Local.read_bytes(&path).await.unwrap_err());
        says_so(&Connection::Local.snapshot(&path).await.unwrap_err());
        let scripted = super::bytes_read(
            &path,
            super::spawn_sh_raw(&zap_types::put::file_bytes_command("", &path))
                .await
                .unwrap(),
        );
        says_so(&scripted.unwrap_err());
        // One link again: each reads it.
        std::fs::remove_file(dir.path().join("twin")).unwrap();
        assert_eq!(Connection::Local.read_bytes(&path).await.unwrap(), b"x");
        assert!(Connection::Local.snapshot(&path).await.is_ok());
    }

    /// A local `read_bytes` reads a regular file's bytes raw and refuses, with nothing
    /// opened, a symbolic link to one, a fifo (which would block an open), and a device;
    /// none of them reaches `sudo`.
    #[tokio::test]
    async fn a_local_raw_read_opens_only_a_regular_file() {
        let dir = crate::test_scratch::tempdir();
        let at = |name: &str| dir.path().join(name).to_string_lossy().into_owned();
        std::fs::write(at("bin"), b"\0\xffELF").unwrap();
        std::os::unix::fs::symlink(at("bin"), at("link")).unwrap();
        assert_eq!(
            Connection::Local.read_bytes(&at("bin")).await.unwrap(),
            b"\0\xffELF"
        );
        let mut refused = vec![(at("link"), "a symbolic link is not read through")];
        if std::process::Command::new("mkfifo")
            .arg(at("fifo"))
            .status()
            .is_ok_and(|status| status.success())
        {
            refused.push((at("fifo"), "not a regular file"));
        }
        refused.push(("/dev/zero".to_owned(), "not a regular file"));
        for (path, why) in refused {
            let error = Connection::Local.read_bytes(&path).await.unwrap_err();
            assert!(error.to_string().ends_with(why), "{path}: {error}");
        }
    }
}
