//! The libvirt VMs the differential runs against, and the `virsh` / `ssh`
//! operations on them. The VMs and their `pristine` snapshots are set up by hand
//! (see `docs/testing.md`); this module only starts, reverts, snapshots, and
//! reaches them.

use std::fmt;
use std::path::Path;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use super::process::{self, Captured};

/// The libvirt connection URI (the system daemon, reachable without root).
const LIBVIRT_URI: &str = "qemu:///system";
/// The libvirt `default` network's host-side address — how a VM reaches a
/// listener on the dev machine.
pub const LIBVIRT_GATEWAY: &str = "192.168.122.1";
/// The SSH user on every harness VM (NOPASSWD sudo).
pub const SSH_USER: &str = "ops";
/// The hand-made clean-slate snapshot every base build starts from.
pub const PRISTINE: &str = "pristine";
/// The harness-owned snapshot of a converged kitchen sink.
pub const BASE: &str = "differential-base";

/// `ssh` options for the harness's own connections — never multiplexed, so they
/// can't collide with (or keep alive) the `ControlMaster` zap uses.
const SSH_OPTIONS: &[&str] = &[
    "-o",
    "BatchMode=yes",
    "-o",
    "StrictHostKeyChecking=accept-new",
    "-o",
    "ConnectTimeout=5",
    "-o",
    "ControlPath=none",
];

/// The most bytes a `ZAP_HOME` may have for the zap run under it to multiplex its
/// SSH connections: past it the control socket's path would not fit a Unix socket
/// address, and zap runs every command over a connection of its own. zap's own
/// arithmetic (`zap_core::connection::ssh`), restated here because the harness holds
/// the oracle to the same socket (`runner::refuse_stale_oracle`).
pub const ZAP_HOME_MAX: usize = 38;

/// The `ControlPath` a zap run under `zap_home` gives `ssh` — `<zap_home>/ssh/cm-%C`,
/// quoted, a `%` doubled — or `None` when it gives none (a home too long for a
/// socket path, or one `ssh` would not read back the same). Spelled as zap spells it
/// (`zap_core::connection::ssh`'s `control_path`): the two must name one socket.
pub fn zap_control_path(zap_home: &Path) -> Option<String> {
    let home = zap_home.to_str()?;
    let plain = !home.contains(|c: char| c == '"' || c == '\\' || c.is_control());
    (plain && home.len() <= ZAP_HOME_MAX)
        .then(|| format!("\"{}/ssh/cm-%C\"", home.replace('%', "%%")))
}

/// A harness VM, one per supported distro family.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Distro {
    Alpine,
    Debian,
}

impl Distro {
    pub const ALL: [Self; 2] = [Self::Alpine, Self::Debian];

    pub const fn name(self) -> &'static str {
        match self {
            Self::Alpine => "alpine",
            Self::Debian => "debian",
        }
    }

    pub fn parse(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|d| d.name() == name)
    }

    /// The libvirt domain name.
    pub const fn domain(self) -> &'static str {
        match self {
            Self::Alpine => "alpine-zap",
            Self::Debian => "debian-zap",
        }
    }

    /// The VM's static address on the libvirt `default` network.
    pub const fn host(self) -> &'static str {
        match self {
            Self::Alpine => "192.168.122.10",
            Self::Debian => "192.168.122.11",
        }
    }

    /// Whether the local-connection suite runs on this VM (it needs the dev
    /// machine's glibc binaries to run there).
    pub const fn has_local_suite(self) -> bool {
        matches!(self, Self::Debian)
    }
}

impl fmt::Display for Distro {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// Run `virsh -c qemu:///system <args>`. The first call after idle can time out
/// while libvirt socket-activates, so a failed call is retried once.
pub fn virsh(args: &[&str]) -> Result<String, String> {
    let attempt = || {
        let mut command = Command::new("virsh");
        command.arg("-c").arg(LIBVIRT_URI).args(args);
        process::run(command, None, Duration::from_secs(120))
            .map_err(|error| format!("failed to run virsh: {error}"))
    };
    let output = match attempt()? {
        output if output.success() => output,
        _ => attempt()?,
    };
    if output.success() {
        Ok(output.stdout)
    } else {
        Err(format!(
            "`virsh {}` failed ({})",
            args.join(" "),
            output.describe_failure()
        ))
    }
}

/// The domain's state as `virsh domstate` prints it (`running`, `shut off`, …).
pub fn domain_state(distro: Distro) -> Result<String, String> {
    Ok(virsh(&["domstate", distro.domain()])?.trim().to_owned())
}

/// Start the domain if it isn't running, then wait for SSH.
pub fn ensure_running(distro: Distro) -> Result<(), String> {
    let state = domain_state(distro)?;
    if state != "running" {
        println!("  starting {} (was {state})", distro.domain());
        virsh(&["start", distro.domain()])?;
    }
    wait_for_ssh(distro, Duration::from_secs(180))
}

/// Poll `ssh … true` until it succeeds or `timeout` passes.
pub fn wait_for_ssh(distro: Distro, timeout: Duration) -> Result<(), String> {
    let deadline = Instant::now() + timeout;
    loop {
        let reached = ssh(distro, "true", None, Duration::from_secs(15));
        match reached {
            Ok(output) if output.success() => return Ok(()),
            Ok(output) if Instant::now() >= deadline => {
                return Err(format!(
                    "{} unreachable over ssh: {}",
                    distro.host(),
                    output.describe_failure()
                ));
            }
            Err(error) if Instant::now() >= deadline => return Err(error),
            _ => thread::sleep(Duration::from_secs(2)),
        }
    }
}

/// Revert to `snapshot`, wait until the guest answers again, and set its clock,
/// returning how long that took.
///
/// A resumed guest drops packets for a few seconds, so reachability is polled with
/// a short-timeout ping rather than left to the next ssh's SYN retransmits (which
/// would round the wait up to the backoff schedule). The guest also resumes with the
/// clock it had when the snapshot was taken; left there, apt rejects any repository
/// signature made since ("created after the --not-after date").
pub fn revert(distro: Distro, snapshot: &str) -> Result<Duration, String> {
    let started = Instant::now();
    virsh(&["snapshot-revert", distro.domain(), snapshot])?;
    let deadline = Instant::now() + Duration::from_secs(20);
    while Instant::now() < deadline && !answers_ping(distro) {
        thread::sleep(Duration::from_millis(50));
    }
    set_clock(distro)?;
    Ok(started.elapsed())
}

/// Set the guest's clock to the host's (`date -u -s @<epoch>`, which coreutils and
/// busybox both accept).
fn set_clock(distro: Distro) -> Result<(), String> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|error| format!("the host clock is before 1970: {error}"))?
        .as_secs();
    let command = format!("sudo date -u -s @{now} >/dev/null");
    let output = ssh(distro, &command, None, Duration::from_secs(60))?;
    if output.success() {
        Ok(())
    } else {
        Err(format!(
            "setting the guest clock failed: {}",
            output.describe_failure()
        ))
    }
}

/// One ping with a 200 ms deadline.
fn answers_ping(distro: Distro) -> bool {
    Command::new("ping")
        .args(["-n", "-q", "-c", "1", "-W", "0.2", distro.host()])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

/// The description of `snapshot`, or `None` when it doesn't exist.
pub fn snapshot_description(distro: Distro, snapshot: &str) -> Result<Option<String>, String> {
    let list = virsh(&["snapshot-list", distro.domain(), "--name"])?;
    if !list.lines().any(|line| line.trim() == snapshot) {
        return Ok(None);
    }
    let xml = virsh(&["snapshot-dumpxml", distro.domain(), snapshot])?;
    Ok(Some(
        xml_element_text(&xml, "description").unwrap_or_default(),
    ))
}

/// The `creationTime` of `snapshot` — its identity, since a re-made snapshot keeps
/// its name.
pub fn snapshot_created(distro: Distro, snapshot: &str) -> Result<String, String> {
    let xml = virsh(&["snapshot-dumpxml", distro.domain(), snapshot])?;
    xml_element_text(&xml, "creationTime").ok_or_else(|| {
        format!(
            "snapshot `{snapshot}` of {} has no creationTime",
            distro.domain()
        )
    })
}

/// Replace `snapshot` (if present) with a snapshot of the current running state.
pub fn replace_snapshot(distro: Distro, snapshot: &str, description: &str) -> Result<(), String> {
    if snapshot_description(distro, snapshot)?.is_some() {
        virsh(&["snapshot-delete", distro.domain(), snapshot])?;
    }
    virsh(&[
        "snapshot-create-as",
        "--domain",
        distro.domain(),
        "--name",
        snapshot,
        "--description",
        description,
    ])?;
    Ok(())
}

/// The text of the first `<tag>…</tag>` in `xml`, with the five predefined
/// entities decoded (libvirt escapes the description).
pub fn xml_element_text(xml: &str, tag: &str) -> Option<String> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let start = xml.find(&open)? + open.len();
    let end = start + xml[start..].find(&close)?;
    Some(
        xml[start..end]
            .replace("&lt;", "<")
            .replace("&gt;", ">")
            .replace("&quot;", "\"")
            .replace("&apos;", "'")
            .replace("&amp;", "&"),
    )
}

/// Run `command` on the VM as the SSH user, with `input` on stdin.
pub fn ssh(
    distro: Distro,
    command: &str,
    input: Option<&[u8]>,
    timeout: Duration,
) -> Result<Captured, String> {
    ssh_as(distro, SSH_USER, command, input, timeout)
}

/// Run `command` on the VM as `user`, with `input` on stdin: [`ssh`] for an account
/// other than the SSH user, such as one a scenario made, which the harness's key also
/// reaches.
pub fn ssh_as(
    distro: Distro,
    user: &str,
    command: &str,
    input: Option<&[u8]>,
    timeout: Duration,
) -> Result<Captured, String> {
    let mut ssh = Command::new("ssh");
    ssh.args(SSH_OPTIONS)
        .arg(format!("{user}@{}", distro.host()))
        .arg(command);
    process::run(ssh, input, timeout).map_err(|error| format!("failed to run ssh: {error}"))
}

/// The shell wrapper a script runs in: the script arrives on stdin and is read *whole*
/// before it runs, then stdin is detached. A shell reading a script from stdin
/// (`sh -s`) reads it in blocks, so a command inside that reads stdin would swallow the
/// unread rest of the script.
const SHELL: &str = "sh -c 'script=$(cat) && exec </dev/null && eval \"$script\"'";

/// `script` as the shell wrapper runs it: `set -eu`, from `/`.
fn shell_script(script: &str) -> String {
    format!("set -eu\ncd /\n{script}\n")
}

/// Run `script` as root on the VM (`set -eu`, from `/`).
pub fn root_shell(distro: Distro, script: &str, timeout: Duration) -> Result<Captured, String> {
    root_shell_as(distro, SSH_USER, script, timeout)
}

/// Run `script` as root on the VM, reached through `user`'s login and its `sudo`
/// (`set -eu`, from `/`).
pub fn root_shell_as(
    distro: Distro,
    user: &str,
    script: &str,
    timeout: Duration,
) -> Result<Captured, String> {
    let script = shell_script(script);
    ssh_as(
        distro,
        user,
        &format!("sudo {SHELL}"),
        Some(script.as_bytes()),
        timeout,
    )
}

/// Run `script` on the VM as `user` itself, unprivileged (`set -eu`, from `/`).
pub fn shell_as(
    distro: Distro,
    user: &str,
    script: &str,
    timeout: Duration,
) -> Result<Captured, String> {
    let script = shell_script(script);
    ssh_as(distro, user, SHELL, Some(script.as_bytes()), timeout)
}

/// Copy the tar stream `archive` into `dir` on the VM (created if missing).
pub fn push_tar(distro: Distro, dir: &str, archive: &[u8]) -> Result<(), String> {
    let command = format!("mkdir -p {dir} && tar -C {dir} -xf -");
    let output = ssh(distro, &command, Some(archive), Duration::from_secs(120))?;
    if output.success() {
        Ok(())
    } else {
        Err(format!(
            "copying into {dir} failed: {}",
            output.describe_failure()
        ))
    }
}

/// The `ssh` invocations that ask each `ControlMaster` a zap run under `zap_home` left
/// for this VM to exit: one per control socket in `<zap_home>/ssh` (`cm-…`, a socket),
/// each named by its own path. None when the run left none, or opened none
/// ([`zap_control_path`]).
///
/// The socket is named by the file, not by zap's `cm-%C`: `%C` hashes the remote user
/// with the host, so the template names the right socket only for the user the run
/// connected as, which the config's target decides (its `user`, or its `bootstrap_user`
/// under `--bootstrap`). Read from the directory, each master the run left is closed,
/// whoever it logged in as. A literal path holds no `%` token for `ssh` to expand, so
/// the destination only fills `ssh`'s argument.
fn close_master_commands(distro: Distro, zap_home: &Path) -> Vec<Command> {
    use std::os::unix::fs::FileTypeExt as _;

    if zap_control_path(zap_home).is_none() {
        return Vec::new();
    }
    let Ok(entries) = std::fs::read_dir(zap_home.join("ssh")) else {
        return Vec::new();
    };
    let mut sockets: Vec<_> = entries
        .flatten()
        .filter(|entry| entry.file_name().to_string_lossy().starts_with("cm-"))
        .filter(|entry| entry.file_type().is_ok_and(|kind| kind.is_socket()))
        .map(|entry| entry.path())
        .collect();
    sockets.sort();
    sockets
        .iter()
        .filter_map(|socket| {
            let path = socket.to_str()?;
            let mut ssh = Command::new("ssh");
            ssh.args([
                "-o",
                &format!("ControlPath=\"{}\"", path.replace('%', "%%")),
                "-O",
                "exit",
                distro.host(),
            ]);
            Some(ssh)
        })
        .collect()
}

/// Close every `ControlMaster` a zap run under `zap_home` left for this VM
/// ([`close_master_commands`]). Best-effort: with no master there is nothing to close.
///
/// zap keeps a master warm after it exits. The harness closes it behind every host
/// run, so none outlives its run — and so none is still up when a snapshot is
/// reverted: the reverted guest has no memory of the TCP connection, and a master
/// that survived would wedge the next zap run to share its home.
pub fn close_zap_master(distro: Distro, zap_home: &Path) {
    for mut ssh in close_master_commands(distro, zap_home) {
        let _ = ssh
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::{Distro, ZAP_HOME_MAX, close_master_commands, xml_element_text, zap_control_path};

    #[test]
    fn distro_names_round_trip() {
        for distro in Distro::ALL {
            assert_eq!(Distro::parse(distro.name()), Some(distro));
        }
        assert_eq!(Distro::parse("arch"), None);
    }

    /// The control path is zap's own spelling of it — the same example
    /// `zap_core::connection::ssh`'s test pins — and a home zap gives no socket has
    /// none to close.
    #[test]
    fn the_control_path_is_the_one_zap_uses() {
        assert_eq!(
            zap_control_path(Path::new("/home/op/.zap")).as_deref(),
            Some("\"/home/op/.zap/ssh/cm-%C\"")
        );
        assert_eq!(
            zap_control_path(Path::new("/srv/100%/z")).as_deref(),
            Some("\"/srv/100%%/z/ssh/cm-%C\"")
        );
        let fits = format!("/{}", "h".repeat(ZAP_HOME_MAX - 1));
        assert!(zap_control_path(Path::new(&fits)).is_some());
        assert_eq!(zap_control_path(Path::new(&format!("{fits}h"))), None);
        for unquotable in ["/srv/a\"b", "/srv/a\\b", "/srv/a\nb"] {
            assert_eq!(zap_control_path(Path::new(unquotable)), None);
        }
        // the bound socket path — `%C` as its 40 characters, the 17 `ssh` appends while
        // binding, the NUL — is the 104 bytes the smallest socket address holds
        assert_eq!(ZAP_HOME_MAX + "/ssh/cm-".len() + 40 + 17 + 1, 104);
    }

    /// Each master a run left is closed by its own socket's path, whichever user it
    /// logged in as (`%C` hashes the user, so the template would name only one user's
    /// socket), and nothing that isn't a control socket is sent a command.
    #[test]
    fn every_master_a_run_left_is_closed_by_its_own_socket() {
        use std::os::unix::net::UnixListener;

        let scratch = tempfile::tempdir().expect("tempdir");
        let home = scratch.path().join("h3");
        let dir = home.join("ssh");
        std::fs::create_dir_all(&dir).expect("mkdir");
        // one master as the login user, one as another user the config named
        let _ops = UnixListener::bind(dir.join("cm-aaaa")).expect("bind");
        let _next = UnixListener::bind(dir.join("cm-bbbb")).expect("bind");
        // not a control socket: a regular file of the name, and a socket of another
        std::fs::write(dir.join("cm-cccc"), b"").expect("write");
        let _other = UnixListener::bind(dir.join("agent")).expect("bind");
        for distro in Distro::ALL {
            let commands = close_master_commands(distro, &home);
            let argvs: Vec<Vec<String>> = commands
                .iter()
                .map(|command| {
                    assert_eq!(command.get_program(), "ssh");
                    command
                        .get_args()
                        .map(|arg| arg.to_string_lossy().into_owned())
                        .collect()
                })
                .collect();
            let close = |name: &str| {
                vec![
                    "-o".to_owned(),
                    format!("ControlPath=\"{}\"", dir.join(name).display()),
                    "-O".to_owned(),
                    "exit".to_owned(),
                    distro.host().to_owned(),
                ]
            };
            assert_eq!(argvs, [close("cm-aaaa"), close("cm-bbbb")]);
        }
        // a run that left no socket directory, and a home zap gives no socket, close
        // nothing
        assert!(close_master_commands(Distro::Alpine, &scratch.path().join("h4")).is_empty());
        let long = format!("/{}", "h".repeat(ZAP_HOME_MAX));
        assert!(close_master_commands(Distro::Alpine, Path::new(&long)).is_empty());
    }

    #[test]
    fn xml_element_text_decodes_entities() {
        let xml = "<domainsnapshot>\n  <name>differential-base</name>\n  \
                   <description>fixture=abc &amp; &lt;more&gt;</description>\n</domainsnapshot>";
        assert_eq!(
            xml_element_text(xml, "description").as_deref(),
            Some("fixture=abc & <more>")
        );
        assert_eq!(xml_element_text(xml, "parent"), None);
    }
}
