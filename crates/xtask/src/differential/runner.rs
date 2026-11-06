//! Running the two binaries: the three read-only commands per binary, a bounded
//! worker pool, the oracle well-formedness gate, the checks on the candidate's own
//! output, and the comparison.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;
use std::time::Duration;

use super::compare::{self, Level, Observed};
use super::process::{self, Captured};
use super::reviewed::{one_plan_hash, plan_hashes};
use super::vm::{self, Distro};

/// The three read-only commands compared per scenario.
pub const COMMANDS: [(&str, &[&str]); 3] = [
    ("detect", &["detect", "--no-cache"]),
    ("plan-diff", &["plan", "--no-cache", "--diff"]),
    ("plan", &["plan", "--no-cache"]),
];

/// At most this many zap runs at once — each holds ssh sessions on the target
/// (sshd's `MaxSessions` defaults to 10 per connection).
const POOL_WIDTH: usize = 3;

pub const ZAP_TIMEOUT: Duration = Duration::from_secs(300);

/// Where the local suite lives on the VM (outside every fixture path).
pub const REMOTE_HARNESS_DIR: &str = "/home/ops/.zapdiff-harness";

/// One of the two binaries under comparison.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Side {
    Oracle,
    Candidate,
}

impl Side {
    /// Both sides, in the order every per-side array and job list uses.
    pub const BOTH: [Self; 2] = [Self::Oracle, Self::Candidate];

    pub const fn name(self) -> &'static str {
        match self {
            Self::Oracle => "oracle",
            Self::Candidate => "candidate",
        }
    }

    pub fn parse(name: &str) -> Option<Self> {
        Self::BOTH.into_iter().find(|side| side.name() == name)
    }

    /// This side's index in a `[T; 2]` laid out as [`Side::BOTH`].
    pub const fn index(self) -> usize {
        match self {
            Self::Oracle => 0,
            Self::Candidate => 1,
        }
    }
}

/// An operator env override: `Some` sets, `None` unsets.
pub type EnvOverride<'a> = (&'a str, Option<&'a str>);

/// One binary's run of one command.
#[derive(Debug)]
pub struct Run {
    pub captured: Captured,
    pub observed: Observed,
}

/// One command's oracle and candidate runs.
#[derive(Debug)]
pub struct Pair {
    pub command: &'static str,
    pub oracle: Run,
    pub candidate: Run,
}

/// A unit of work for [`run_pool`].
pub type Job<'a, T> = Box<dyn FnOnce() -> T + Send + 'a>;

/// Run `jobs` on at most [`POOL_WIDTH`] threads, results in job order.
pub fn run_pool<T: Send>(jobs: Vec<Job<'_, T>>) -> Vec<T> {
    let count = jobs.len();
    let queue: Mutex<Vec<Option<Job<'_, T>>>> = Mutex::new(jobs.into_iter().map(Some).collect());
    let results: Mutex<Vec<Option<T>>> = Mutex::new((0..count).map(|_| None).collect());
    let next = AtomicUsize::new(0);
    thread::scope(|scope| {
        for _ in 0..POOL_WIDTH.min(count) {
            scope.spawn(|| {
                loop {
                    let index = next.fetch_add(1, Ordering::AcqRel);
                    if index >= count {
                        break;
                    }
                    let job = queue.lock().ok().and_then(|mut q| q[index].take());
                    if let Some(job) = job {
                        let result = job();
                        if let Ok(mut slots) = results.lock() {
                            slots[index] = Some(result);
                        }
                    }
                }
            });
        }
    });
    results
        .into_inner()
        .unwrap_or_default()
        .into_iter()
        .flatten()
        .collect()
}

/// Everything a host-side (SSH suite) zap run needs. `config` and `cwd` are one
/// binary's own: its staged fixture tree, with the `zap.lock` it minted.
#[derive(Debug, Clone, Copy)]
pub struct HostRun<'a> {
    pub distro: Distro,
    pub config: &'a Path,
    /// The root of the binary's staged tree.
    pub cwd: &'a Path,
    /// What `ZAPDIFF_CONTENT` resolves to: where this zap fetches `remote` content.
    pub content_url: &'a str,
    /// What `ZAPDIFF_ORIGIN` resolves to: where the target fetches for itself.
    pub origin_url: &'a str,
    /// The `fgro` build both binaries evaluate with, passed as `--fgro`.
    pub fgro: &'a Path,
    pub env: &'a [EnvOverride<'a>],
}

/// Where the host-side zap runs keep their `ZAP_HOME`s: one short directory on the
/// real disk, made for the run and removed with it.
///
/// A zap multiplexes its SSH connections only when its home's path leaves room for a
/// control socket's ([`vm::ZAP_HOME_MAX`]), which a home under the scratch directory
/// never does. So each home is `<root>/h<n>`, with the root `~/.cache/zd-<pid>` — not
/// the temp directory, which is no place for a content cache. When even that is too
/// long (a long `HOME`), the homes are still used and the runs go unmultiplexed, each
/// command over a connection of its own.
#[derive(Debug)]
pub struct HostHomes {
    root: PathBuf,
    /// The home each name was given, in the order asked for.
    issued: Mutex<Vec<(String, PathBuf)>>,
}

impl HostHomes {
    /// A fresh root under the operator's cache directory.
    ///
    /// # Errors
    /// When `HOME` is unset, or the root can't be made.
    pub fn create() -> Result<Self, String> {
        let home = std::env::var_os("HOME")
            .filter(|home| !home.is_empty())
            .ok_or("HOME is unset: the host runs' ZAP_HOMEs have nowhere to go")?;
        let homes = Self::under(Self::root_for(Path::new(&home), std::process::id()));
        let _ = std::fs::remove_dir_all(&homes.root);
        std::fs::create_dir_all(&homes.root)
            .map_err(|error| format!("creating {} failed: {error}", homes.root.display()))?;
        if !homes.multiplexes() {
            println!(
                "  NOTE: {} leaves no room for an ssh control socket under it — the host \
                 runs open a connection per command",
                homes.root.display()
            );
        }
        Ok(homes)
    }

    /// The root for a harness run by process `pid` of the operator whose home is
    /// `home`.
    fn root_for(home: &Path, pid: u32) -> PathBuf {
        home.join(".cache").join(format!("zd-{pid}"))
    }

    const fn under(root: PathBuf) -> Self {
        Self {
            root,
            issued: Mutex::new(Vec::new()),
        }
    }

    /// The `ZAP_HOME` named `name`: the same directory each time the name is asked
    /// for, and one of its own for every other name. Not created.
    pub fn home(&self, name: &str) -> PathBuf {
        let mut issued = self
            .issued
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some((_, home)) = issued.iter().find(|(known, _)| known == name) {
            return home.clone();
        }
        let home = self.root.join(format!("h{}", issued.len()));
        issued.push((name.to_owned(), home.clone()));
        home
    }

    /// Whether a home here is short enough for its zap to multiplex — judged for a
    /// four-digit home number, more than a run asks for.
    fn multiplexes(&self) -> bool {
        vm::zap_control_path(&self.root.join("h9999")).is_some()
    }
}

impl Drop for HostHomes {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

/// Run a zap binary on the dev machine against the SSH fixture, under the `ZAP_HOME`
/// `home` (a [`HostHomes`] one), then close every SSH master the run left for the VM
/// ([`vm::close_zap_master`]) — whether or not the run succeeded.
pub fn run_host_zap(
    run: HostRun<'_>,
    binary: &Path,
    home: &Path,
    args: &[&str],
    timeout: Duration,
) -> Result<Captured, String> {
    std::fs::create_dir_all(home)
        .map_err(|error| format!("creating {} failed: {error}", home.display()))?;
    let ran = process::run(host_zap_command(run, binary, home, args), None, timeout)
        .map_err(|error| format!("failed to run {}: {error}", binary.display()));
    vm::close_zap_master(run.distro, home);
    ran
}

/// The command a host-side zap run is: `<binary> <args> --fgro <fgro> <config>` from the binary's
/// staged tree, under `home`, with every variable the fixtures reference — the VM's
/// address and user, the user the bootstrap-replace scenario puts in its place, the
/// loopback content server, the https origin the target fetches
/// from, and the value the `script-var` check compares — then the run's own overrides.
fn host_zap_command(run: HostRun<'_>, binary: &Path, home: &Path, args: &[&str]) -> Command {
    let mut command = Command::new(binary);
    command
        .args(args)
        .arg("--fgro")
        .arg(run.fgro)
        .arg(run.config)
        .current_dir(run.cwd)
        .env("ZAP_HOME", home)
        .env("ZAPDIFF_HOST", run.distro.host())
        .env("ZAPDIFF_USER", vm::SSH_USER)
        .env(super::bootstrap::NEXT_USER_VAR, super::bootstrap::NEXT_USER)
        .env("ZAPDIFF_CONTENT", run.content_url)
        .env("ZAPDIFF_ORIGIN", run.origin_url)
        .env(
            super::scenarios::EXPECT_VAR.0,
            super::scenarios::EXPECT_VAR.1,
        )
        // the eval-cache mode must not differ between the two binaries' runs
        .env_remove("ZAP_EVAL_CACHE")
        .env_remove("ZAP_EVAL_CACHE_LOG");
    for (name, value) in run.env {
        match value {
            Some(value) => command.env(name, value),
            None => command.env_remove(name),
        };
    }
    command
}

/// Why the `ControlPath`s a zap gave `ssh` — the `recorded` argv, one argument a line —
/// are not the one the harness manages for its `ZAP_HOME` (`expected`:
/// [`vm::zap_control_path`], `None` for a home with no socket), if any of them isn't.
///
/// A zap that keeps its control socket somewhere else — the literal `~/.zap/ssh` of a
/// binary that predates per-home sockets — leaves a master the harness never closes:
/// it would outlive its run and a snapshot revert, and wedge the next run to share it.
fn foreign_control_path<'a>(recorded: &'a str, expected: Option<&str>) -> Option<&'a str> {
    recorded
        .lines()
        .filter_map(|argument| argument.strip_prefix("ControlPath="))
        .find(|given| Some(*given) != expected)
}

/// Refuse a `side` binary that predates config evaluation through `fgro`: it takes no
/// `--fgro` and reads no toolchain pin, so it can't evaluate the staged fixtures the
/// way the other side does, and every run of it would fail as a config error rather
/// than be compared. Read from `zap config validate --help`.
///
/// # Errors
/// The binary's help doesn't offer `--fgro`, or it can't be run.
pub fn refuse_pre_fgro(side: Side, binary: &Path) -> Result<(), String> {
    let mut command = Command::new(binary);
    command.args(["config", "validate", "--help"]);
    let help = process::run(command, None, Duration::from_secs(10))
        .map_err(|error| format!("failed to run {}: {error}", binary.display()))?;
    if offers_fgro(&help.stdout) || offers_fgro(&help.stderr) {
        Ok(())
    } else {
        Err(format!(
            "the {} {} takes no --fgro: it predates config evaluation through fgro, and \
             reads neither the fixtures' toolchain pin nor the fgro the harness runs both \
             sides with — use a {} built from a tree that evaluates through fgro",
            side.name(),
            binary.display(),
            side.name()
        ))
    }
}

/// Whether a `--help` text lists the `--fgro` option.
fn offers_fgro(help: &str) -> bool {
    help.lines()
        .any(|line| line.trim_start().starts_with("--fgro"))
}

/// Stop before any VM run if the oracle keeps its `ssh` control socket anywhere but
/// under its `ZAP_HOME`.
///
/// (A zap that predates `fgro` is refused before this, by [`refuse_pre_fgro`].)
///
/// The oracle runs `detect` once with a stand-in `ssh` first on its `PATH`: a script
/// that records its arguments and refuses the connection, so nothing is reached. The
/// `ControlPath` among them is the oracle's own answer. A run that never starts `ssh`
/// says nothing, and passes.
///
/// # Errors
/// When the oracle names a control socket the harness doesn't manage
/// ([`foreign_control_path`]), or the probe can't be set up.
pub fn refuse_stale_oracle(
    run: HostRun<'_>,
    oracle: &Path,
    homes: &HostHomes,
) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt as _;

    let stub = tempfile::Builder::new()
        .prefix("zap-differential-ssh-")
        .tempdir()
        .map_err(|error| format!("creating a temp dir failed: {error}"))?;
    let script = stub.path().join("ssh");
    let recorded = stub.path().join("argv");
    std::fs::write(
        &script,
        format!(
            "#!/bin/sh\nprintf '%s\\n' \"$@\" >> '{}'\nexit 255\n",
            recorded.display()
        ),
    )
    .and_then(|()| std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)))
    .map_err(|error| format!("writing {} failed: {error}", script.display()))?;
    let path = format!(
        "{}:{}",
        stub.path().display(),
        std::env::var("PATH").unwrap_or_default()
    );
    let env: Vec<EnvOverride<'_>> = run
        .env
        .iter()
        .copied()
        .chain([("PATH", Some(path.as_str()))])
        .collect();
    let home = homes.home("oracle-ssh-probe");
    run_host_zap(
        HostRun { env: &env, ..run },
        oracle,
        &home,
        &["detect", "--no-cache"],
        ZAP_TIMEOUT,
    )?;
    let recorded = std::fs::read_to_string(&recorded).unwrap_or_default();
    let expected = vm::zap_control_path(&home);
    foreign_control_path(&recorded, expected.as_deref()).map_or(Ok(()), |given| {
        Err(format!(
            "the oracle {} keeps its ssh control socket at {given}, not under its ZAP_HOME: \
             it predates per-home control sockets, and the harness neither opens nor \
             closes a master there — rebuild the oracle from a newer tree",
            oracle.display()
        ))
    })
}

/// One binary's half of an SSH-suite comparison: which side it is, the binary, and
/// its run against its own staged tree.
pub type SshSide<'a> = (Side, &'a Path, HostRun<'a>);

/// Run all three commands for both binaries over SSH, each against its own staged
/// tree (`sides`, laid out as [`Side::BOTH`]) and under a `ZAP_HOME` of its own — the
/// one `homes` gives `<label>/<side>-<command>`. With `seed`, each fresh `ZAP_HOME`
/// first gets a warm content cache of those files.
pub fn compare_ssh(
    sides: [SshSide<'_>; 2],
    homes: &HostHomes,
    label: &str,
    seed: Option<&BTreeMap<String, Vec<u8>>>,
) -> Result<Vec<Pair>, String> {
    let mut jobs: Vec<Job<'_, Result<Run, String>>> = Vec::new();
    for (command, args) in COMMANDS {
        for (side, binary, run) in sides {
            let home: PathBuf = homes.home(&format!("{label}/{}-{command}", side.name()));
            jobs.push(Box::new(move || {
                if let Some(files) = seed {
                    super::content::seed_content_cache(files, &home)
                        .map_err(|error| format!("seeding the content cache: {error}"))?;
                }
                let captured = run_host_zap(run, binary, &home, args, ZAP_TIMEOUT)?;
                let observed = compare::normalize(
                    &captured,
                    &home.to_string_lossy(),
                    &binary.to_string_lossy(),
                    &run.cwd.to_string_lossy(),
                );
                Ok(Run { captured, observed })
            }));
        }
    }
    pairs_from(run_pool(jobs).into_iter().collect::<Result<Vec<_>, _>>()?)
}

/// What a VM-side run's `ZAP_HOME` holds when zap starts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VmHome {
    /// Emptied first: nothing an earlier run left.
    Fresh,
    /// Emptied first, then given the bundle's seeded content cache.
    Warm,
    /// Left as the previous run with the same home left it — its last-run report
    /// included, which is what a wetrun binds to.
    Kept,
}

/// A VM-side (local suite) zap run: `bin/<side>` on the VM, as the SSH user, against
/// the local fixture, with the `ZAP_HOME` named `<side>-<home>`.
#[derive(Debug, Clone, Copy)]
pub struct VmRun<'a> {
    pub distro: Distro,
    pub side: Side,
    pub home: &'a str,
    /// What `ZAPDIFF_CONTENT` resolves to on the VM: the https origin on the libvirt
    /// gateway address. This zap fetches for itself from another machine, so plain
    /// `http` is not open to it; it trusts the origin through the guest's trust store,
    /// which the base holds the test CA in.
    pub content_url: &'a str,
    pub state: VmHome,
}

impl VmRun<'_> {
    /// The run's `ZAP_HOME` on the VM.
    fn zap_home(&self) -> String {
        format!(
            "{REMOTE_HARNESS_DIR}/homes/{}-{}",
            self.side.name(),
            self.home
        )
    }

    /// The remote shell command for `zap <args> --fgro <the bundle's fgro> <the local
    /// fixture>`.
    fn command(&self, args: &[&str]) -> String {
        let home = self.zap_home();
        let config = format!(
            "{REMOTE_HARNESS_DIR}/{}",
            super::fixture::local_config_relative()
        );
        let prepare = match self.state {
            VmHome::Fresh => format!("rm -rf {home} && mkdir -p {home}"),
            VmHome::Warm => format!(
                "rm -rf {home} && mkdir -p {home} && cp -a {REMOTE_HARNESS_DIR}/seed/. {home}/"
            ),
            VmHome::Kept => format!("mkdir -p {home}"),
        };
        format!(
            "cd {REMOTE_HARNESS_DIR} && {prepare} && \
             ZAP_HOME={home} ZAPDIFF_CONTENT={} ./bin/{} {} --fgro {REMOTE_HARNESS_DIR}/{} \
             {config} </dev/null",
            self.content_url,
            self.side.name(),
            args.join(" "),
            super::fixture::BUNDLE_FGRO,
        )
    }
}

/// Run zap on the VM (see [`VmRun`]).
pub fn run_vm_zap(run: VmRun<'_>, args: &[&str], timeout: Duration) -> Result<Captured, String> {
    vm::ssh(run.distro, &run.command(args), None, timeout)
}

/// Run all three commands for both binaries on the VM. They share the one fixture
/// tree the bundle carries: the local fixture's `zap.lock` holds the toolchain pin of
/// the bundle's `fgro` and no entry.
pub fn compare_local(distro: Distro, content_url: &str, warm: bool) -> Result<Vec<Pair>, String> {
    let state = if warm { VmHome::Warm } else { VmHome::Fresh };
    let mut jobs: Vec<Job<'_, Result<Run, String>>> = Vec::new();
    for (command, args) in COMMANDS {
        for side in Side::BOTH {
            jobs.push(Box::new(move || {
                let run = VmRun {
                    distro,
                    side,
                    home: command,
                    content_url,
                    state,
                };
                let captured = run_vm_zap(run, args, ZAP_TIMEOUT)?;
                let observed = compare::normalize(
                    &captured,
                    &run.zap_home(),
                    &format!("./bin/{}", side.name()),
                    "",
                );
                Ok(Run { captured, observed })
            }));
        }
    }
    pairs_from(run_pool(jobs).into_iter().collect::<Result<Vec<_>, _>>()?)
}

/// Regroup `[o0, c0, o1, c1, …]` (the job order) into per-command pairs.
fn pairs_from(runs: Vec<Run>) -> Result<Vec<Pair>, String> {
    let mut iter = runs.into_iter();
    COMMANDS
        .iter()
        .map(|(command, _)| {
            let oracle = iter.next().ok_or("a run went missing")?;
            let candidate = iter.next().ok_or("a run went missing")?;
            Ok(Pair {
                command,
                oracle,
                candidate,
            })
        })
        .collect()
}

/// Problems that make a pair unusable as evidence: a timeout on either side, or an
/// oracle result that isn't a well-formed report (so two binaries failing the same
/// way can't pass as "identical"). Empty when the pair can be compared.
pub fn evidence_problems(pair: &Pair, resources: usize) -> Vec<String> {
    let mut problems = Vec::new();
    for (side, run) in [("oracle", &pair.oracle), ("candidate", &pair.candidate)] {
        if run.captured.timed_out {
            problems.push(format!("{side} `{}` timed out", pair.command));
        }
    }
    if let Err(problem) = well_formed(pair.command, &pair.oracle.captured, resources) {
        problems.push(format!(
            "the oracle's `{}` isn't a well-formed report ({problem}): {}",
            pair.command,
            pair.oracle.captured.describe_failure()
        ));
    }
    problems
}

/// Whether `captured` looks like a real report for `command`: an exit code in the
/// command's contract (0, or 1 for an unverifiable / undetermined verdict), and the
/// report's anchor lines — `detect`'s header and a resource count equal to the
/// fixture's, a plan's `plan_hash:`.
pub fn well_formed(command: &str, captured: &Captured, resources: usize) -> Result<(), String> {
    if !matches!(captured.code, Some(0 | 1)) {
        return Err(format!("exit code {:?} is outside 0/1", captured.code));
    }
    let lines: Vec<&str> = captured.stdout.lines().collect();
    if command == "detect" {
        if !lines
            .iter()
            .any(|l| l.starts_with("detected live state — target "))
        {
            return Err("no `detected live state` header".to_owned());
        }
        let count = format!("{resources} resource(s):");
        if !lines.iter().any(|l| *l == count) {
            return Err(format!("no `{count}` line"));
        }
    } else if !lines.iter().any(|l| l.starts_with("plan_hash: ")) {
        return Err("no `plan_hash:` line".to_owned());
    }
    Ok(())
}

/// The resources the oracle's `detect` reported as anything but `ok`, as
/// `(id, mark)` sorted (`pipeline`, `absent` by construction, is left out).
pub fn moved_resources(pairs: &[Pair]) -> Vec<(String, String)> {
    pairs
        .iter()
        .find(|pair| pair.command == "detect")
        .map(|pair| detect_movers(&pair.oracle.captured.stdout))
        .unwrap_or_default()
}

/// Parse `detect`'s resource lines (`  <mark> <id>  <kind>  — <message>`, after the
/// `N resource(s):` line — verdict banners come before it) for non-`ok` marks. A
/// resource line is indented exactly two spaces; a continuation line of a multi-line
/// message stands further in and is no resource, whatever it says.
pub fn detect_movers(stdout: &str) -> Vec<(String, String)> {
    let mut moved: Vec<(String, String)> = stdout
        .lines()
        .skip_while(|line| !compare::is_count_line(line))
        .skip(1)
        .filter(|line| compare::has_two_space_indent(line) && line.contains(" — "))
        .filter(|line| compare::banner_name(line).is_none())
        .filter_map(|line| {
            let mut fields = line.split_whitespace();
            let (mark, id, kind) = (fields.next()?, fields.next()?, fields.next()?);
            (mark != "ok" && kind != "pipeline").then(|| (id.to_owned(), mark.to_owned()))
        })
        .collect();
    moved.sort_unstable();
    moved
}

/// The machine an SSH-suite plan is for: what its `host:` and `user:` lines must say.
#[derive(Debug, Clone, Copy)]
pub struct Machine<'a> {
    pub host: &'a str,
    pub user: &'a str,
}

/// What is wrong with the candidate's own output for one target state, whatever the
/// oracle printed (empty when nothing is):
///
/// - its `plan` and `plan --diff` name different `plan_hash`es, or one names several;
/// - a plan that has a header doesn't say, directly under it, what it is for — with
///   `machine` (the SSH suite) `  host: <the address>` and `  user: <the user>`,
///   without it (the local suite) a `  user: ` and a `  home: ` line, and in either
///   suite a `  target: ` line;
/// - a line of any command's stdout or stderr holds a control character. zap writes
///   those out as `<U+XXXX>` and a TAB as spaces, so a newline is the only one its
///   output has.
pub fn candidate_problems(pairs: &[Pair], machine: Option<Machine<'_>>) -> Vec<String> {
    let mut problems = Vec::new();
    let mut hashes: Vec<(&str, Option<&str>)> = Vec::new();
    for pair in pairs {
        let captured = &pair.candidate.captured;
        let command = pair.command;
        for (stream, text) in [("stdout", &captured.stdout), ("stderr", &captured.stderr)] {
            if let Some(found) = control_character(text) {
                problems.push(format!(
                    "the candidate's `{command}` {stream} holds {found}"
                ));
            }
        }
        if command == "detect" {
            continue;
        }
        match plan_hashes(&captured.stdout).as_slice() {
            [] => hashes.push((command, None)),
            [hash] => hashes.push((command, Some(hash))),
            several => problems.push(format!(
                "the candidate's `{command}` prints {} `plan_hash:` lines",
                several.len()
            )),
        }
        if let Some(problem) = plan_subject_problem(command, &captured.stdout, machine) {
            problems.push(problem);
        }
    }
    if let [(first, hash), rest @ ..] = hashes.as_slice() {
        for (command, other) in rest {
            if other != hash {
                problems.push(format!(
                    "the candidate's plans of one state disagree: `{first}` has plan_hash {}, \
                     `{command}` has {}",
                    hash.unwrap_or("none"),
                    other.unwrap_or("none")
                ));
            }
        }
    }
    problems
}

/// The candidate's `plan_hash` for this state, when its `plan` prints exactly one.
pub fn candidate_plan_hash(pairs: &[Pair]) -> Option<String> {
    let plan = pairs.iter().find(|pair| pair.command == "plan")?;
    one_plan_hash(&plan.candidate.captured.stdout).map(str::to_owned)
}

/// The first control character in `text` other than a newline, described with the
/// line it is on.
fn control_character(text: &str) -> Option<String> {
    text.split('\n').enumerate().find_map(|(index, line)| {
        let found = line.chars().find(|c| c.is_control())?;
        Some(format!(
            "a raw U+{:04X} on line {}: {:?}",
            u32::from(found),
            index + 1,
            line
        ))
    })
}

/// What the candidate's `command` plan's subject lines lack ([`subject_problem`]).
/// `None` when they are all there, and for output with no plan header (not a plan: the
/// comparison shows that).
fn plan_subject_problem(
    command: &str,
    stdout: &str,
    machine: Option<Machine<'_>>,
) -> Option<String> {
    let header = if command == "plan-diff" {
        PLAN_DIFF_HEADER
    } else {
        PLAN_HEADER
    };
    subject_problem(header, stdout, machine)
        .map(|problem| format!("the candidate's `{command}` {problem}"))
}

/// Where a `plan` report's header line starts.
pub const PLAN_HEADER: &str = "plan — target ";
/// Where a `plan --diff` report's header line starts.
const PLAN_DIFF_HEADER: &str = "plan diff — target ";
/// Where an `apply` report's header line starts, dry or wet.
pub const APPLY_HEADER: &str = "apply — target ";

/// What a report's subject lines — the ones directly under its first line starting
/// `header` — lack: with `machine` (the SSH suite) `  host: <the address>` and
/// `  user: <the user>`, without it (the local suite) a `  user: ` and a `  home: `
/// line, then in either suite a `  target: ` line. `None` when they are all there, and
/// for output with no such header.
pub fn subject_problem(header: &str, stdout: &str, machine: Option<Machine<'_>>) -> Option<String> {
    let mut lines = stdout.lines().skip_while(|line| !line.starts_with(header));
    lines.next()?;
    // over SSH the exact address and user; locally the user zap runs as and its home,
    // whatever they are on the VM
    let expected: Vec<(String, bool)> = machine.map_or_else(
        || {
            vec![
                ("  user: ".to_owned(), false),
                ("  home: ".to_owned(), false),
            ]
        },
        |machine| {
            vec![
                (format!("  host: {}", machine.host), true),
                (format!("  user: {}", machine.user), true),
            ]
        },
    );
    for (want, exact) in expected {
        let got = lines.next().unwrap_or_default();
        let named = if exact {
            got == want
        } else {
            got.starts_with(&want)
        };
        if !named {
            return Some(format!(
                "doesn't name its machine: expected {want:?} under the header, found {got:?}"
            ));
        }
    }
    let got = lines.next().unwrap_or_default();
    (!got.starts_with("  target: {")).then(|| {
        format!(
            "doesn't print its declared target: expected a `  target: ` line under the \
             header, found {got:?}"
        )
    })
}

/// `pair`'s divergence at `level`, rendered under a `[variant]` tag (empty when there
/// is none).
pub fn divergence(level: Level, variant: &str, pair: &Pair) -> String {
    use std::fmt::Write as _;
    let mut report = String::new();
    let oracle = compare::at_level(level, pair.command, &pair.oracle.observed);
    let candidate = compare::at_level(level, pair.command, &pair.candidate.observed);
    if let Some(diff) = compare::compare(&oracle, &candidate) {
        let _ = writeln!(report, "  [{variant}] {}:", pair.command);
        for line in diff.lines() {
            let _ = writeln!(report, "    {line}");
        }
    }
    report
}

#[cfg(test)]
mod tests {
    use super::{
        HostHomes, HostRun, Job, Machine, Pair, Run, Side, VmHome, VmRun, candidate_plan_hash,
        candidate_problems, detect_movers, foreign_control_path, host_zap_command, offers_fgro,
        run_pool, well_formed,
    };
    use crate::differential::compare;
    use crate::differential::process::Captured;
    use crate::differential::vm::Distro;

    /// A name keeps its home, every other name gets one of its own, and a home under
    /// an ordinary operator's cache directory is short enough for zap to multiplex —
    /// while one under a long root is still a home, only not a multiplexing one.
    #[test]
    fn host_homes_are_short_and_one_per_name() {
        use std::path::{Path, PathBuf};

        use crate::differential::vm::{ZAP_HOME_MAX, zap_control_path};

        let root = HostHomes::root_for(Path::new("/home/operator"), 4_194_304);
        assert_eq!(root, PathBuf::from("/home/operator/.cache/zd-4194304"));
        let homes = HostHomes::under(root.clone());
        assert!(homes.multiplexes());
        let first = homes.home("alpine/ssh/drift/cold/oracle-plan");
        let second = homes.home("alpine/ssh/drift/cold/candidate-plan");
        assert_eq!((&first, &second), (&root.join("h0"), &root.join("h1")));
        assert_eq!(homes.home("alpine/ssh/drift/cold/oracle-plan"), first);
        assert_eq!(homes.home("alpine/base"), root.join("h2"));
        for home in [&first, &second, &root.join("h9999")] {
            assert!(home.as_os_str().len() <= ZAP_HOME_MAX, "{}", home.display());
            assert_eq!(
                zap_control_path(home),
                Some(format!("\"{}/ssh/cm-%C\"", home.display()))
            );
        }
        // nothing was made, and dropping the homes leaves what isn't theirs alone
        assert!(!root.exists());

        let long = HostHomes::under(PathBuf::from(
            "/home/a-rather-long-operator-name/.cache/zd-1",
        ));
        assert!(!long.multiplexes());
        assert_eq!(zap_control_path(&long.home("x")), None);
    }

    /// An oracle is judged by the `ControlPath` it hands `ssh`: the one under its own
    /// `ZAP_HOME` passes, as does none at all, and the literal `~/.zap/ssh` of a binary
    /// that predates per-home sockets — or any other — is named.
    #[test]
    fn an_oracle_with_its_socket_outside_its_home_is_found() {
        let expected = "\"/c/zd-7/h3/ssh/cm-%C\"";
        let argv = |control_path: &str| {
            format!(
                "-o\nBatchMode=yes\n-o\nControlMaster=auto\n-o\nControlPath={control_path}\n-o\n\
                 ControlPersist=300\nops@10.0.0.2\nsh -c 'x'\n"
            )
        };
        assert_eq!(foreign_control_path(&argv(expected), Some(expected)), None);
        assert_eq!(
            foreign_control_path("-o\nBatchMode=yes\nops@h\n", Some(expected)),
            None
        );
        assert_eq!(foreign_control_path("", None), None);
        let old = argv("~/.zap/ssh/cm-%C");
        assert_eq!(
            foreign_control_path(&old, Some(expected)),
            Some("~/.zap/ssh/cm-%C")
        );
        // A home with no socket of its own expects no `ControlPath` at all.
        assert_eq!(foreign_control_path(&old, None), Some("~/.zap/ssh/cm-%C"));
        // Every invocation is read: one stray among the oracle's own is enough.
        let mixed = format!("{}{old}", argv(expected));
        assert_eq!(
            foreign_control_path(&mixed, Some(expected)),
            Some("~/.zap/ssh/cm-%C")
        );
    }

    fn captured(code: i32, stdout: &str) -> Captured {
        Captured {
            code: Some(code),
            stdout: stdout.to_owned(),
            stderr: String::new(),
            timed_out: false,
        }
    }

    const DETECT: &str = "  LOCK — the pin ledger does not answer for 1 resource(s):\n      \
        blob — missing\n\
        detected live state — target x (pkg: apk, service: openrc)\n\
        4 resource(s):\n  ok     curl  package  — converged\n  \
        drift  inline  file  — drifted (content differs)\n  \
        absent pipeline  pipeline  — absent\n  \
        ?      private-file  file  — undetermined: failed\n";

    #[test]
    fn detect_movers_lists_non_ok_resources_except_pipeline() {
        assert_eq!(
            detect_movers(DETECT),
            [
                ("inline".to_owned(), "drift".to_owned()),
                ("private-file".to_owned(), "?".to_owned())
            ]
        );
    }

    /// A row is indented exactly two spaces: a continuation line of a multi-line
    /// message — and a banner after the rows — is no resource, whatever it says.
    #[test]
    fn detect_movers_reads_only_two_space_rows() {
        let detect = "detected live state — target x (pkg: apk, service: openrc)\n\
            2 resource(s):\n  \
            ?      verify  verify  — undetermined: the command said:\n                               \
            drift  ghost  file  — not a row\n   \
            absent three  spaces  — not a row\n\
            drift  column0  file  — not a row\n  \
            ok     curl  package  — converged\n  \
            UNRECORDED — no last run is kept for this target\n";
        assert_eq!(
            detect_movers(detect),
            [("verify".to_owned(), "?".to_owned())]
        );
    }

    #[test]
    fn a_well_formed_detect_needs_the_header_and_the_fixture_count() {
        assert_eq!(well_formed("detect", &captured(0, DETECT), 4), Ok(()));
        assert!(well_formed("detect", &captured(0, DETECT), 5).is_err());
        assert!(well_formed("detect", &captured(2, DETECT), 4).is_err());
        assert!(well_formed("detect", &captured(1, "error: config\n"), 4).is_err());
    }

    #[test]
    fn a_well_formed_plan_needs_a_plan_hash() {
        let plan = "plan — target x (0 change(s))\n  (no changes — converged)\nplan_hash: ab\n";
        assert_eq!(well_formed("plan", &captured(0, plan), 4), Ok(()));
        assert_eq!(well_formed("plan-diff", &captured(1, plan), 4), Ok(()));
        assert!(well_formed("plan", &captured(0, "plan — target x\n"), 4).is_err());
        let mut timed_out = captured(0, plan);
        timed_out.code = None;
        assert!(well_formed("plan", &timed_out, 4).is_err());
    }

    #[test]
    fn the_pool_keeps_job_order() {
        let mut jobs: Vec<Job<'_, usize>> = Vec::new();
        for i in 0..7_usize {
            jobs.push(Box::new(move || i * 10));
        }
        assert_eq!(run_pool(jobs), [0, 10, 20, 30, 40, 50, 60]);
    }

    #[test]
    fn sides_round_trip_and_index_in_order() {
        for (index, side) in Side::BOTH.into_iter().enumerate() {
            assert_eq!(Side::parse(side.name()), Some(side));
            assert_eq!(side.index(), index);
        }
        assert_eq!(Side::parse("both"), None);
    }

    /// A host run is given every variable the fixtures reference, the eval-cache
    /// mode is taken out of its hands, and a scenario's override wins.
    #[test]
    fn a_host_run_is_given_every_variable_the_fixtures_reference() {
        use std::ffi::OsStr;
        use std::path::Path;

        let run = HostRun {
            distro: Distro::Alpine,
            config: Path::new("/stage/oracle/fixtures/alpine/zap.ts"),
            cwd: Path::new("/stage/oracle"),
            content_url: "http://127.0.0.1:4001",
            origin_url: "https://192.168.122.1:4002",
            fgro: Path::new("/opt/fgro"),
            env: &[],
        };
        let command = host_zap_command(
            run,
            Path::new("/bin/zap"),
            Path::new("/c/zd-1/h0"),
            &["plan", "--no-cache"],
        );
        assert_eq!(command.get_program(), "/bin/zap");
        let args: Vec<_> = command.get_args().collect();
        assert_eq!(
            args,
            [
                "plan",
                "--no-cache",
                "--fgro",
                "/opt/fgro",
                "/stage/oracle/fixtures/alpine/zap.ts"
            ]
        );
        assert_eq!(command.get_current_dir(), Some(Path::new("/stage/oracle")));
        let env = |command: &std::process::Command| -> Vec<(String, Option<String>)> {
            let mut env: Vec<_> = command
                .get_envs()
                .map(|(name, value)| {
                    (
                        name.to_string_lossy().into_owned(),
                        value.map(|value| value.to_string_lossy().into_owned()),
                    )
                })
                .collect();
            env.sort();
            env
        };
        let set = |name: &str, value: &str| (name.to_owned(), Some(value.to_owned()));
        let unset = |name: &str| (name.to_owned(), None);
        assert_eq!(
            env(&command),
            [
                set("ZAPDIFF_CONTENT", "http://127.0.0.1:4001"),
                set("ZAPDIFF_EXPECT", "expected-value"),
                set("ZAPDIFF_HOST", "192.168.122.10"),
                set("ZAPDIFF_NEXT_USER", "zapnext"),
                set("ZAPDIFF_ORIGIN", "https://192.168.122.1:4002"),
                set("ZAPDIFF_USER", "ops"),
                unset("ZAP_EVAL_CACHE"),
                unset("ZAP_EVAL_CACHE_LOG"),
                set("ZAP_HOME", "/c/zd-1/h0"),
            ]
        );
        // every `ZAPDIFF_*` name the fixtures reference is one the run sets
        for fixture in [
            include_str!("../../fixtures/differential/common.ts"),
            include_str!("../../fixtures/differential/alpine/zap.ts"),
            include_str!("../../fixtures/differential/debian/zap.ts"),
            include_str!("../../fixtures/differential/debian-local/zap.ts"),
            include_str!("../../fixtures/bootstrap/common.ts"),
            include_str!("../../fixtures/bootstrap/provision/zap.ts"),
            include_str!("../../fixtures/bootstrap/retired/zap.ts"),
        ] {
            for (_, rest) in fixture
                .match_indices("zap.env('")
                .map(|(at, open)| (at, &fixture[at + open.len()..]))
            {
                let name = rest.split('\'').next().unwrap_or_default();
                assert!(
                    command
                        .get_envs()
                        .any(|(set, value)| set == OsStr::new(name) && value.is_some()),
                    "{name} is referenced and not set"
                );
            }
        }

        let overrides = [("ZAPDIFF_EXPECT", None), ("PATH", Some("/stub"))];
        let overridden = host_zap_command(
            HostRun {
                env: &overrides,
                ..run
            },
            Path::new("/bin/zap"),
            Path::new("/c/zd-1/h0"),
            &["detect"],
        );
        let env = env(&overridden);
        assert!(env.contains(&unset("ZAPDIFF_EXPECT")));
        assert!(env.contains(&set("PATH", "/stub")));
    }

    /// A zap that evaluates through `fgro` lists `--fgro`; one that predates it doesn't,
    /// and a mention elsewhere in the text isn't an option.
    #[test]
    fn a_pre_fgro_zap_is_told_apart_by_its_help() {
        let post = "Usage: zap config validate [--fgro <fgro>] [--env-file <env-file>]\n\n\
                    Options:\n  --fgro            the fgro binary that evaluates the config\n  \
                    --env-file        load operator env vars\n";
        let pre = "Usage: zap config validate [--env-file <env-file>] [--] [<config>]\n\n\
                   Options:\n  --env-file        load operator env vars (not --fgro)\n";
        assert!(offers_fgro(post));
        assert!(!offers_fgro(pre));
    }

    #[test]
    fn a_vm_run_empties_its_home_unless_it_keeps_it() {
        let run = |state| VmRun {
            distro: Distro::Debian,
            side: Side::Candidate,
            home: "base",
            content_url: "https://192.168.122.1:9",
            state,
        };
        let home = "/home/ops/.zapdiff-harness/homes/candidate-base";
        let fresh = run(VmHome::Fresh).command(&["apply", "--no-cache"]);
        assert!(fresh.contains(&format!(
            "rm -rf {home} && mkdir -p {home} && ZAP_HOME={home} "
        )));
        assert!(fresh.contains(&format!(
            " ZAP_HOME={home} ZAPDIFF_CONTENT=https://192.168.122.1:9 ./bin/candidate apply \
             --no-cache --fgro /home/ops/.zapdiff-harness/bin/fgro /home/ops/.zapdiff-harness/"
        )));
        // the local fixture names no target-side fetch, so the run is given no origin
        assert!(!fresh.contains("ZAPDIFF_ORIGIN"));
        assert!(fresh.ends_with("debian-local/zap.ts </dev/null"));
        let warm = run(VmHome::Warm).command(&["plan"]);
        assert!(warm.contains(&format!("rm -rf {home} && ")));
        assert!(warm.contains(&format!(
            "cp -a /home/ops/.zapdiff-harness/seed/. {home}/ && ZAP_HOME="
        )));
        let kept = run(VmHome::Kept).command(&["apply", "--wetrun"]);
        assert!(!kept.contains("rm -rf"), "{kept}");
        assert!(kept.contains(&format!("&& mkdir -p {home} && ZAP_HOME={home} ")));
    }

    fn run_of(stdout: &str, stderr: &str) -> Run {
        let captured = Captured {
            code: Some(0),
            stdout: stdout.to_owned(),
            stderr: stderr.to_owned(),
            timed_out: false,
        };
        let observed = compare::normalize(&captured, "", "", "");
        Run { captured, observed }
    }

    /// Pairs whose candidate printed `candidate` for (detect, plan-diff, plan).
    fn pairs(candidate: [&str; 3]) -> Vec<Pair> {
        ["detect", "plan-diff", "plan"]
            .into_iter()
            .zip(candidate)
            .map(|(command, stdout)| Pair {
                command,
                oracle: run_of("an oracle with \t and \r in it\n", ""),
                candidate: run_of(stdout, ""),
            })
            .collect()
    }

    const MACHINE: Machine<'static> = Machine {
        host: "192.168.122.10",
        user: "ops",
    };

    fn plan(header: &str, subject: &str, hash: &str) -> String {
        format!(
            "{header} — target {{env:ZAPDIFF_HOST}} (0 change(s): +0 ~0)\n{subject}  (no changes — converged)\n{hash}"
        )
    }

    const SUBJECT: &str = "  host: 192.168.122.10\n  user: ops\n  target: {\"local\":false}\n";
    const DETECT_OK: &str =
        "detected live state — target x (pkg: apk, service: openrc)\n0 resource(s):\n";

    #[test]
    fn a_consistent_candidate_has_no_problems() {
        let good = pairs([
            DETECT_OK,
            &plan("plan diff", SUBJECT, "plan_hash: ab\n"),
            &plan("plan", SUBJECT, "plan_hash: ab\n"),
        ]);
        assert_eq!(
            candidate_problems(&good, Some(MACHINE)),
            Vec::<String>::new()
        );
        assert_eq!(candidate_plan_hash(&good).as_deref(), Some("ab"));
        // the local suite's plans name the user zap runs as and its home, then the target
        let local = "  user: ops\n  home: /home/ops\n  target: {\"local\":true}\n";
        let good = pairs([
            DETECT_OK,
            &plan("plan diff", local, "plan_hash: ab\n"),
            &plan("plan", local, "plan_hash: ab\n"),
        ]);
        assert_eq!(candidate_problems(&good, None), Vec::<String>::new());
        // output that is no plan is the comparison's to report, and has no hash
        let failed = pairs([DETECT_OK, "", ""]);
        assert_eq!(
            candidate_problems(&failed, Some(MACHINE)),
            Vec::<String>::new()
        );
        assert_eq!(candidate_plan_hash(&failed), None);
    }

    #[test]
    fn plans_of_one_state_must_agree_on_one_plan_hash() {
        let differing = pairs([
            DETECT_OK,
            &plan("plan diff", SUBJECT, "plan_hash: ab\n"),
            &plan("plan", SUBJECT, "plan_hash: cd\n"),
        ]);
        let problems = candidate_problems(&differing, Some(MACHINE));
        assert_eq!(problems.len(), 1, "{problems:?}");
        assert!(problems[0].contains("`plan-diff` has plan_hash ab, `plan` has cd"));

        let missing = pairs([
            DETECT_OK,
            &plan("plan diff", SUBJECT, "plan_hash: ab\n"),
            &plan("plan", SUBJECT, ""),
        ]);
        let problems = candidate_problems(&missing, Some(MACHINE));
        assert_eq!(problems.len(), 1, "{problems:?}");
        assert!(problems[0].contains("`plan` has none"));
        assert_eq!(candidate_plan_hash(&missing), None);

        let doubled = pairs([
            DETECT_OK,
            &plan("plan diff", SUBJECT, "plan_hash: ab\n"),
            &plan("plan", SUBJECT, "plan_hash: ab\nplan_hash: ab\n"),
        ]);
        let problems = candidate_problems(&doubled, Some(MACHINE));
        assert_eq!(problems.len(), 1, "{problems:?}");
        assert!(problems[0].contains("`plan` prints 2 `plan_hash:` lines"));
        assert_eq!(candidate_plan_hash(&doubled), None);
        // an indented one is a step's text, not the plan's
        let inside = plan("plan", SUBJECT, "        plan_hash: zz\nplan_hash: ab\n");
        let fine = pairs([
            DETECT_OK,
            &plan("plan diff", SUBJECT, "plan_hash: ab\n"),
            &inside,
        ]);
        assert_eq!(
            candidate_problems(&fine, Some(MACHINE)),
            Vec::<String>::new()
        );
    }

    #[test]
    fn an_ssh_plan_must_name_its_machine_and_target_under_the_header() {
        let hash = "plan_hash: ab\n";
        let good = plan("plan diff", SUBJECT, hash);
        for (subject, expected) in [
            ("", "expected \"  host: 192.168.122.10\""),
            (
                "  host: 192.168.122.11\n  user: ops\n  target: {}\n",
                "expected \"  host: 192.168.122.10\"",
            ),
            (
                "  host: 192.168.122.10\n  user: root\n  target: {}\n",
                "expected \"  user: ops\"",
            ),
            (
                "  user: ops\n  host: 192.168.122.10\n  target: {}\n",
                "expected \"  host: 192.168.122.10\"",
            ),
            (
                "  host: 192.168.122.10\n  user: ops\n",
                "doesn't print its declared target",
            ),
            (
                "  host: 192.168.122.10\n  user: ops\n  target: local\n",
                "doesn't print its declared target",
            ),
        ] {
            let bad = pairs([DETECT_OK, &good, &plan("plan", subject, hash)]);
            let problems = candidate_problems(&bad, Some(MACHINE));
            assert_eq!(problems.len(), 1, "{subject:?}: {problems:?}");
            assert!(
                problems[0].contains("the candidate's `plan` "),
                "{problems:?}"
            );
            assert!(problems[0].contains(expected), "{subject:?}: {problems:?}");
        }
        // banners lead the header; the subject is read under the header itself
        let led = format!("  LOCK — x:\n      blob — y\n{good}");
        let fine = pairs([DETECT_OK, &led, &plan("plan", SUBJECT, hash)]);
        assert_eq!(
            candidate_problems(&fine, Some(MACHINE)),
            Vec::<String>::new()
        );
        // a local plan with no target line
        let local = "  user: ops\n  home: /home/ops\n";
        let bare = pairs([
            DETECT_OK,
            &plan("plan diff", local, hash),
            &plan("plan", &format!("{local}  target: {{}}\n"), hash),
        ]);
        let problems = candidate_problems(&bare, None);
        assert_eq!(problems.len(), 1, "{problems:?}");
        assert!(
            problems[0].contains("the candidate's `plan-diff` doesn't print its declared target")
        );
        // a local plan that doesn't name the user it runs as and its home
        for (subject, expected) in [
            ("  target: {}\n", "expected \"  user: \""),
            ("  user: ops\n  target: {}\n", "expected \"  home: \""),
            (
                "  home: /home/ops\n  user: ops\n  target: {}\n",
                "expected \"  user: \"",
            ),
        ] {
            let unnamed = pairs([
                DETECT_OK,
                &plan("plan diff", &format!("{local}  target: {{}}\n"), hash),
                &plan("plan", subject, hash),
            ]);
            let problems = candidate_problems(&unnamed, None);
            assert_eq!(problems.len(), 1, "{subject:?}: {problems:?}");
            assert!(
                problems[0].contains("the candidate's `plan` doesn't name its machine"),
                "{problems:?}"
            );
            assert!(problems[0].contains(expected), "{subject:?}: {problems:?}");
        }
    }

    #[test]
    fn no_candidate_line_holds_a_control_character() {
        let hash = "plan_hash: ab\n";
        let good_diff = plan("plan diff", SUBJECT, hash);
        let good_plan = plan("plan", SUBJECT, hash);
        for (control, code) in [
            ('\t', "U+0009"),
            ('\r', "U+000D"),
            ('\u{1b}', "U+001B"),
            ('\u{9b}', "U+009B"),
            ('\0', "U+0000"),
        ] {
            let detect = format!("{DETECT_OK}  ok     a{control}b  file  — converged\n");
            let bad = pairs([&detect, &good_diff, &good_plan]);
            let problems = candidate_problems(&bad, Some(MACHINE));
            assert_eq!(problems.len(), 1, "{code}: {problems:?}");
            assert!(
                problems[0].starts_with(&format!(
                    "the candidate's `detect` stdout holds a raw {code} on line 3: "
                )),
                "{problems:?}"
            );
        }
        // stderr is checked too, per command
        let mut bad = pairs([DETECT_OK, &good_diff, &good_plan]);
        bad[2].candidate = run_of(&good_plan, "warning: x\r\n");
        let problems = candidate_problems(&bad, Some(MACHINE));
        assert_eq!(problems.len(), 1, "{problems:?}");
        assert!(
            problems[0].starts_with("the candidate's `plan` stderr holds a raw U+000D on line 1")
        );
        // what zap writes in a control character's place is text
        let escaped = format!("{DETECT_OK}  ok     a<U+000D>b        c  file  — converged\n");
        let fine = pairs([&escaped, &good_diff, &good_plan]);
        assert_eq!(
            candidate_problems(&fine, Some(MACHINE)),
            Vec::<String>::new()
        );
    }
}
