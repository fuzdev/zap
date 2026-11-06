//! `cargo xtask differential` — run a trusted **oracle** zap and a **candidate**
//! zap against the same real target states and fail on any difference in what
//! they report.
//!
//! Per distro VM: revert to a converged kitchen-sink snapshot (built once from
//! `pristine` by one of the two binaries — `--base-by` — through previewed applies,
//! and reused while the fixture and the builder are unchanged), put the target in one
//! scenario's state (a root shell mutation, and/or an operator-side edit), then run
//! both binaries — each with a fresh `ZAP_HOME`, its own staged copy of the fixtures,
//! and the `zap.lock` it minted there — over `detect --no-cache`,
//! `plan --no-cache --diff`, and `plan --no-cache`, and compare exit codes, stdout,
//! and stderr at the run's level (`--compare`): byte for byte, or after a semantic
//! projection (`compare::project_lines`). The SSH suite drives the VM from the dev
//! machine; on Debian a local suite also runs both binaries *on* the VM against a
//! `local: true` fixture, covering the Local connection path. Scenarios with `remote`
//! resources also run with a warm content cache.
//!
//! What the runs fetch is served from inside the harness (`content`): plain HTTP on
//! loopback for the dev machine's own zap runs, and — for everything a guest reaches,
//! the `curl` of an `installer` and the zap runs inside the guest —
//! an https **origin** on the libvirt gateway address, under a test CA kept on this
//! machine (`pki`) that the kitchen sinks install in each guest's trust store.
//!
//! A scenario only counts as evidence when it is well-formed: the oracle's output is
//! a real report, the oracle saw exactly the resources move that the scenario
//! expects, nothing timed out, the runs neither fetched content nor wrote to the
//! target, and the candidate's own output is consistent
//! (`runner::candidate_problems`). Anything else is an `ERROR`, never a pass. A
//! divergence the `intended` table records — exact lines, with the reason — is
//! accepted and reported as `INTENDED`; a table entry that no longer matches its run
//! is an `ERROR`.
//!
//! A scenario that carries a probe then **reconverges** (`reconverge`): on the state
//! the read-only phase just compared, the candidate alone applies it back through its
//! review gate, its own `detect` and a further preview must read it converged, and the
//! probe — a root shell snippet that never goes through zap, read on the base and
//! after the mutation — must read the base again. A failure there is an `ERROR` tagged
//! `[reconverge]`. `--keep` skips the phase, leaving the VM drifted.
//!
//! One scenario is of its own kind (`bootstrap`): the candidate alone replaces the VM's
//! bootstrap user in place — provisions a new user with `--bootstrap`, proves it stands
//! on its own, retires `ops` over the new user's login, and plans as it. It compares
//! nothing, and changes the machine on purpose; the revert after it brings `ops` back.
//! `--keep` stops it before the retire.
//!
//! See `docs/differential.md` for how to run it and read a divergence, and
//! `docs/testing.md` for the VMs.

mod args;
mod audit;
mod base;
mod bootstrap;
mod compare;
mod content;
mod fixture;
mod intended;
mod oracle;
mod pki;
mod process;
#[cfg(test)]
mod real_captures;
mod reconverge;
mod reviewed;
mod runner;
mod scenarios;
mod vm;

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};
use std::sync::Arc;
use std::time::{Duration, Instant};

use args::Parsed;
use compare::Level;
use content::{Connections, ContentServer};
use fixture::{Generated, Staged};
use intended::{Intended, RunKey, Variant};
use runner::{EnvOverride, HostRun, Pair, Side};
use scenarios::{Anchor, Kind, Operator, Scenario, Suite};
use vm::Distro;

const MUTATION_TIMEOUT: Duration = Duration::from_secs(120);

/// Entry point for `cargo xtask differential <args>`.
pub fn main(raw: &[String]) -> ExitCode {
    let args = match args::parse(raw) {
        Ok(Parsed::Help) => {
            print!("{}", args::USAGE);
            return ExitCode::SUCCESS;
        }
        Ok(Parsed::Run(args)) => args,
        Err(message) => {
            eprintln!("error: {message}\n");
            eprint!("{}", args::USAGE);
            return ExitCode::from(2);
        }
    };
    let unknown = scenarios::unknown_names(&args.distros, &args.scenarios);
    if !unknown.is_empty() {
        eprintln!(
            "error: no such scenario on the selected distros: {}",
            unknown.join(", ")
        );
        for distro in &args.distros {
            let names: Vec<_> = scenarios::scenarios(*distro)
                .iter()
                .map(|s| s.name)
                .collect();
            eprintln!("  {distro}: {}", names.join(", "));
        }
        return ExitCode::from(2);
    }
    match run(&args) {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::FAILURE,
        Err(message) => {
            eprintln!("error: {message}");
            ExitCode::FAILURE
        }
    }
}

/// Everything a distro run needs.
struct Context {
    repo: PathBuf,
    oracle: PathBuf,
    candidate: PathBuf,
    /// The `fgro` build both binaries evaluate with (`ZAP_FGRO`), shipped to the VM in
    /// the local bundle.
    fgro: PathBuf,
    /// Its blake3: the toolchain pin every staged config's lock starts with.
    fgro_blake3: String,
    scratch: PathBuf,
    /// The host-side runs' `ZAP_HOME`s.
    homes: runner::HostHomes,
    /// Each binary's staged fixture tree, laid out as [`Side::BOTH`].
    staged: [Staged; 2],
    files: Arc<BTreeMap<String, Vec<u8>>>,
    pins: String,
    /// Plain HTTP on loopback: what the dev machine's zap runs fetch from.
    loopback: ContentServer,
    /// TLS on the libvirt gateway address: what a guest fetches from.
    origin: ContentServer,
    /// What both servers accepted between them.
    connections: Connections,
    /// The identity of the test CA the origin is served under.
    ca_fingerprint: String,
    intended: Vec<Intended>,
    level: Level,
    base_by: Side,
    keep: bool,
    rebase: bool,
}

impl Context {
    fn binary(&self, side: Side) -> &Path {
        match side {
            Side::Oracle => &self.oracle,
            Side::Candidate => &self.candidate,
        }
    }

    const fn staged(&self, side: Side) -> &Staged {
        &self.staged[side.index()]
    }

    /// What `ZAPDIFF_CONTENT` resolves to for a zap run of `suite`.
    fn content_url(&self, suite: Suite) -> String {
        content_url_for(suite, &self.loopback.base_url(), &self.origin.base_url()).to_owned()
    }
}

/// What a run found, across its distros.
#[derive(Debug, Default)]
struct Findings {
    reports: Vec<ScenarioReport>,
    /// Distros whose two `zap.lock`s differ at the run's level, each with the
    /// difference rendered.
    locks: Vec<(Distro, String)>,
}

/// One scenario's outcome.
#[derive(Debug)]
enum Verdict {
    Pass,
    Diverged(String),
    Error(String),
}

#[derive(Debug)]
struct ScenarioReport {
    distro: Distro,
    label: String,
    verdict: Verdict,
    trace: Trace,
    total: Duration,
}

/// Phase timings of one scenario, and what the oracle saw move.
#[derive(Debug, Default)]
struct Trace {
    revert: Duration,
    mutate: Duration,
    runs: Duration,
    audit: Duration,
    reconverge: Reconverged,
    moved: Vec<(String, String)>,
    /// The accepted intended divergences, rendered.
    intended: Vec<String>,
    /// A scenario of its own kind's phases, timed in order: reported in place of the
    /// revert, zap runs, and audit of a compared one.
    phases: Vec<(&'static str, Duration)>,
    /// What such a scenario established, for the report, in place of what the
    /// oracle's `detect` moved.
    notes: Vec<String>,
}

/// What became of a scenario's reconverge phase.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
enum Reconverged {
    /// The scenario carries no probe.
    #[default]
    NotFlagged,
    /// `--keep`: the VM stays in the drifted state.
    Skipped,
    /// The phase ran.
    Ran { took: Duration, passed: bool },
}

/// Run the whole matrix; `Ok(true)` when every scenario passed.
fn run(args: &args::Args) -> Result<bool, String> {
    let started = Instant::now();
    let repo = repo_root()?;
    let oracle = match &args.oracle {
        oracle::OracleSource::Binary(path) => std::fs::canonicalize(path)
            .map_err(|error| format!("oracle {}: {error}", path.display()))?,
        oracle::OracleSource::Rev(rev) => {
            let built = oracle::ensure(&repo, rev, &home_dir()?, &cache_dir()?)?;
            println!("{}", built.describe());
            built.path
        }
    };
    let candidate = match &args.candidate {
        Some(path) => std::fs::canonicalize(path)
            .map_err(|error| format!("candidate {}: {error}", path.display()))?,
        None => build_candidate(&repo)?,
    };
    let oracle_hash = file_blake3(&oracle)?;
    let candidate_hash = file_blake3(&candidate)?;
    println!(
        "oracle     {}  blake3 {}",
        oracle.display(),
        &oracle_hash[..16]
    );
    println!(
        "candidate  {}  blake3 {}",
        candidate.display(),
        &candidate_hash[..16]
    );
    for (side, binary) in [(Side::Oracle, &oracle), (Side::Candidate, &candidate)] {
        runner::refuse_pre_fgro(side, binary)?;
    }
    let fgro = fgro_from_env()?;
    let fgro_blake3 = file_blake3(&fgro)?;
    println!(
        "fgro       {}  blake3 {}",
        fgro.display(),
        &fgro_blake3[..16]
    );
    let lock = fixture::toolchain_lock(&fgro_blake3);
    if oracle_hash == candidate_hash {
        println!(
            "\n  WARNING: the oracle and candidate are byte-identical — this run checks the \
             harness and the targets,\n  but proves nothing about a change.\n"
        );
    }

    let scratch_dir = fixture::create_run_dir(&cache_dir()?.join(fixture::RUNS_DIR))?;
    let scratch = scratch_dir.path().to_path_buf();

    let artifacts = content::Artifacts::generate(&scratch)?;
    let pins = artifacts.pins_module();
    let files = Arc::new(artifacts.files);
    let connections = Connections::default();
    let loopback = ContentServer::start(
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        Arc::clone(&files),
        &connections,
    )
    .map_err(|error| format!("binding the content server failed: {error}"))?;
    let pki = pki::Pki::ensure(
        &pki::Pki::default_dir()?,
        Path::new("openssl"),
        &pki::server_names(),
    )?;
    if let Some(replaced) = pki.replaced() {
        println!("test CA    {replaced}");
    }
    let ca_fingerprint = pki.ca_fingerprint();
    let gateway: IpAddr = vm::LIBVIRT_GATEWAY
        .parse()
        .map_err(|error| format!("bad gateway address: {error}"))?;
    let origin = start_origin(&pki, &files, gateway, &connections)?;
    let ca_module = pki.ca_module();
    let generated = Generated {
        pins: &pins,
        origin_ca: &ca_module,
        lock: &lock,
    };
    let stage = scratch.join("stage");
    let staged = [
        Staged::create(&repo, &stage.join(Side::Oracle.name()), generated)?,
        Staged::create(&repo, &stage.join(Side::Candidate.name()), generated)?,
    ];
    println!(
        "content    {} (blob {})",
        loopback.base_url(),
        &artifacts.blob_blake3[..16]
    );
    println!(
        "origin     {} (test CA {}, kept in {})",
        origin.base_url(),
        &ca_fingerprint[..16],
        pki.dir().display()
    );
    println!(
        "compare    {}; base built by the {}",
        args.level.name(),
        args.base_by.name()
    );
    if args.level == Level::Semantic {
        println!(
            "\n  NOTE: a semantic run compares what was decided, not how it is rendered: the \
             lines under a change\n  (what it declares, its steps), each plan's machine block, \
             and the value of plan_hash are not compared.\n"
        );
    }

    let context = Context {
        repo,
        oracle,
        candidate,
        fgro,
        fgro_blake3,
        scratch,
        homes: runner::HostHomes::create()?,
        staged,
        files,
        pins,
        loopback,
        origin,
        connections,
        ca_fingerprint,
        intended: intended::table(),
        level: args.level,
        base_by: args.base_by,
        keep: args.keep,
        rebase: args.rebase,
    };

    let mut findings = Findings::default();
    let mut distro_errors = Vec::new();
    for &distro in &args.distros {
        println!("\n== {distro} ({})", distro.domain());
        if let Err(message) = run_distro(&context, distro, &args.scenarios, &mut findings) {
            println!("  ERROR  {message}");
            distro_errors.push(distro);
        }
    }
    let Findings { reports, locks } = findings;

    let (mut passed, mut diverged, mut errored) = (0, locks.len(), distro_errors.len());
    let mut intended = 0;
    for report in &reports {
        intended += report.trace.intended.len();
        match report.verdict {
            Verdict::Pass => passed += 1,
            Verdict::Diverged(_) => diverged += 1,
            Verdict::Error(_) => errored += 1,
        }
    }
    println!(
        "\ndifferential: {passed} passed, {diverged} diverged, {errored} error(s) in {} \
         ({intended} intended divergence line(s) accepted)",
        seconds(started.elapsed())
    );
    for distro in &distro_errors {
        println!("  ERROR     {distro} (see above)");
    }
    for (distro, _) in &locks {
        println!("  DIVERGED  {distro}/zap.lock");
    }
    for report in &reports {
        let kind = match report.verdict {
            Verdict::Pass => continue,
            Verdict::Diverged(_) => "DIVERGED",
            Verdict::Error(_) => "ERROR",
        };
        println!("  {kind:<9} {}/{}", report.distro, report.label);
    }
    Ok(diverged == 0 && errored == 0)
}

/// Run one distro, then leave its VM tidy whatever happened: at `differential-base`
/// (else `pristine`), and shut down again if it was found shut off.
fn run_distro(
    context: &Context,
    distro: Distro,
    filter: &[String],
    findings: &mut Findings,
) -> Result<(), String> {
    let initial_state = vm::domain_state(distro)?;
    let result = run_distro_matrix(context, distro, filter, findings);
    if context.keep {
        println!("  --keep: left as the run left it");
        return result;
    }
    let tidy = vm::snapshot_description(distro, vm::BASE).and_then(|base| {
        let snapshot = if base.is_some() {
            vm::BASE
        } else {
            vm::PRISTINE
        };
        vm::revert(distro, snapshot)?;
        if initial_state == "shut off" {
            println!(
                "  shutting {} down again (it was shut off)",
                distro.domain()
            );
            vm::virsh(&["shutdown", distro.domain()])?;
        }
        Ok(())
    });
    match (result, tidy) {
        (Err(error), _) => Err(error),
        (Ok(()), Err(error)) => Err(format!("leaving the VM tidy failed: {error}")),
        (Ok(()), Ok(())) => Ok(()),
    }
}

fn run_distro_matrix(
    context: &Context,
    distro: Distro,
    filter: &[String],
    findings: &mut Findings,
) -> Result<(), String> {
    // before a VM is touched: an oracle whose ssh master the harness can't manage
    let oracle_config = context.staged(Side::Oracle).ssh_config(distro);
    let content_url = context.content_url(Suite::Ssh);
    let origin_url = context.origin.base_url();
    runner::refuse_stale_oracle(
        HostRun {
            distro,
            config: &oracle_config,
            cwd: &context.staged(Side::Oracle).root,
            content_url: &content_url,
            origin_url: &origin_url,
            fgro: &context.fgro,
            env: &[],
        },
        &context.oracle,
        &context.homes,
    )?;
    vm::ensure_running(distro)?;

    let pristine = vm::snapshot_created(distro, vm::PRISTINE)?;
    let builder = context.base_by;
    let hash = fixture::base_hash(
        &context.repo,
        (builder.name(), context.binary(builder)),
        &context.pins,
        &pristine,
        &base::prepare_script(distro),
        &context.ca_fingerprint,
        &context.fgro_blake3,
    )?;
    let existing = vm::snapshot_description(distro, vm::BASE)?;
    let reusable = existing
        .as_deref()
        .is_some_and(|d| fixture::description_matches(d, &hash));
    if reusable && !context.rebase {
        println!("  base     reusing `{}` (fixture={hash})", vm::BASE);
    } else {
        let why = if context.rebase {
            "--rebase"
        } else if existing.is_some() {
            "the base's hash changed"
        } else {
            "no base yet"
        };
        println!("  base     building from `{}` ({why})", vm::PRISTINE);
        let started = Instant::now();
        let served_before = context.origin.requests();
        base::build_base(context, distro, &hash)?;
        // a base whose guest fetched nothing from the origin was not built from it
        println!(
            "  base     built in {} ({} connection(s) to the origin)",
            seconds(started.elapsed()),
            context.origin.requests() - served_before
        );
    }

    let distro_dir = context.scratch.join(distro.name());
    let ssh_configs = Side::BOTH.map(|side| context.staged(side).ssh_config(distro));
    let runs = Side::BOTH.map(|side| HostRun {
        distro,
        config: &ssh_configs[side.index()],
        cwd: &context.staged(side).root,
        content_url: &content_url,
        origin_url: &origin_url,
        fgro: &context.fgro,
        env: &[],
    });
    // the tracked pins live in `zap.lock`, which a staged tree doesn't carry between
    // runs (and whose entries hash this run's content url): each binary mints its own
    // in its own tree, so neither reads a lock the other addressed
    for side in Side::BOTH {
        let locked = runner::run_host_zap(
            runs[side.index()],
            context.binary(side),
            &context
                .homes
                .home(&format!("{}/lock-{}", distro.name(), side.name())),
            &["lock"],
            runner::ZAP_TIMEOUT,
        )?;
        if !locked.success() {
            return Err(format!(
                "the {}'s `zap lock` failed: {}",
                side.name(),
                locked.describe_failure()
            ));
        }
    }
    if let Some(difference) = lock_difference(context.level, &ssh_configs)? {
        findings.locks.push((distro, difference));
    }

    let oracle_run = runs[Side::Oracle.index()];
    let ssh_resources = resource_count(context, oracle_run, oracle_run.config)?;
    let local = if distro.has_local_suite() {
        let config = oracle_run.cwd.join(fixture::local_config_relative());
        let count = resource_count(context, oracle_run, &config)?;
        let bundle = fixture::local_bundle(
            &context.repo,
            &distro_dir,
            &context.pins,
            &fixture::toolchain_lock(&context.fgro_blake3),
            &[
                ("bin/oracle", &context.oracle),
                ("bin/candidate", &context.candidate),
                (fixture::BUNDLE_FGRO, &context.fgro),
            ],
            Some(&context.files),
        )?;
        Some(LocalSuite {
            bundle,
            resources: count,
        })
    } else {
        None
    };
    println!(
        "  fixture  ssh {ssh_resources} resource(s){}",
        local
            .as_ref()
            .map_or_else(String::new, |l| format!(", local {}", l.resources))
    );

    let setup = DistroSetup {
        distro,
        runs,
        ssh_resources,
        local: local.as_ref(),
        dir: &distro_dir,
    };
    for scenario in scenarios::select(distro, filter) {
        let label = format!("{}/{}", scenario.suite.name(), scenario.name);
        let started = Instant::now();
        let mut trace = Trace::default();
        let verdict = match scenario.kind {
            Kind::Compare => run_scenario(context, &setup, &scenario, &mut trace),
            Kind::ReplaceBootstrap => bootstrap::run(context, &setup, &mut trace),
        }
        .unwrap_or_else(Verdict::Error);
        let total = started.elapsed();
        print_verdict(&label, &scenario, &verdict, &trace, total);
        findings.reports.push(ScenarioReport {
            distro,
            label,
            verdict,
            trace,
            total,
        });
    }
    print_timing(distro, &findings.reports);
    Ok(())
}

/// Compare the two `zap.lock`s minted beside `configs` (laid out as [`Side::BOTH`]),
/// printing what was found. `Ok(Some(_))` is a divergence at `level`: the two locks
/// address a config differently, which `Exact` compares and `Semantic` only reports.
///
/// # Errors
/// A lock can't be read or parsed, or the two pin different things — then no
/// comparison of what the binaries read through them means anything.
fn lock_difference(level: Level, configs: &[PathBuf; 2]) -> Result<Option<String>, String> {
    let read = |side: Side| {
        let path = configs[side.index()].with_file_name("zap.lock");
        std::fs::read(&path).map_err(|error| {
            format!(
                "reading the {}'s {} failed: {error}",
                side.name(),
                path.display()
            )
        })
    };
    let comparison = audit::compare_locks(&read(Side::Oracle)?, &read(Side::Candidate)?)?;
    if !comparison.pins.is_empty() {
        return Err(format!(
            "the two binaries' zap.lock pin different things:\n  {}",
            comparison.pins.join("\n  ")
        ));
    }
    if comparison.addresses.is_empty() {
        println!("  lock     both binaries minted the same zap.lock entries");
        return Ok(None);
    }
    let rendered = comparison.addresses.join("\n           ");
    Ok(match level {
        Level::Exact => {
            println!("  DIVERGED zap.lock: the same pins, addressed differently");
            println!("           {rendered}");
            Some(rendered)
        }
        Level::Semantic => {
            println!(
                "  lock     the same pins, addressed differently (not compared at this level)"
            );
            println!("           {rendered}");
            None
        }
    })
}

/// The Debian local suite's per-run pieces.
struct LocalSuite {
    bundle: Vec<u8>,
    resources: usize,
}

/// Per-distro inputs shared by every scenario.
struct DistroSetup<'a> {
    distro: Distro,
    /// Each binary's SSH-suite run, laid out as [`Side::BOTH`].
    runs: [HostRun<'a>; 2],
    ssh_resources: usize,
    local: Option<&'a LocalSuite>,
    dir: &'a Path,
}

/// `zap config validate`'s resource count for `config` — what a well-formed
/// `detect` must report.
fn resource_count(context: &Context, run: HostRun<'_>, config: &Path) -> Result<usize, String> {
    let home = context.homes.home("validate");
    let run = HostRun { config, ..run };
    let output = runner::run_host_zap(
        run,
        &context.oracle,
        &home,
        &["config", "validate"],
        runner::ZAP_TIMEOUT,
    )?;
    parse_resource_count(&output.stdout).ok_or_else(|| {
        format!(
            "`zap config validate {}` gave no count: {}",
            config.display(),
            output.describe_failure()
        )
    })
}

/// `ok: 42 resource(s)` → 42.
fn parse_resource_count(stdout: &str) -> Option<usize> {
    stdout
        .lines()
        .find_map(|line| line.strip_prefix("ok: ")?.strip_suffix(" resource(s)"))
        .and_then(|count| count.trim().parse().ok())
}

/// Revert, mutate, run, and judge one scenario.
fn run_scenario(
    context: &Context,
    setup: &DistroSetup<'_>,
    scenario: &Scenario,
    trace: &mut Trace,
) -> Result<Verdict, String> {
    let distro = setup.distro;
    trace.revert = vm::revert(distro, vm::BASE)?;

    let started = Instant::now();
    // before the stamp: the push writes under /home/ops, which the audit covers
    if scenario.suite == Suite::Local {
        let local = setup.local.ok_or("no local suite for this distro")?;
        vm::push_tar(distro, runner::REMOTE_HARNESS_DIR, &local.bundle)?;
    }
    let script = mutation_script(scenario);
    let mutated = vm::root_shell(distro, &script, MUTATION_TIMEOUT)?;
    if !mutated.success() {
        return Err(format!(
            "the mutation failed: {}",
            mutated.describe_failure()
        ));
    }
    let runtime_before = audit::sections(&mutated.stdout);
    let mut env: Vec<EnvOverride<'_>> = Vec::new();
    // both binaries' locks get the edit; each is restored when its edit drops
    let mut lock_edits = Vec::new();
    match scenario.operator {
        Operator::None => {}
        Operator::Env(name, value) => env.push((name, value)),
        Operator::Lock { drop, stale } => {
            for run in &setup.runs {
                let lock = run.config.with_file_name("zap.lock");
                lock_edits.push(audit::LockEdit::apply(&lock, drop, stale)?);
            }
        }
    }
    trace.mutate = started.elapsed();

    let started = Instant::now();
    let fetched_before = fetch_count(context);
    let variants: &[Variant] = if scenario.remote {
        &[Variant::Cold, Variant::Warm]
    } else {
        &[Variant::Cold]
    };
    let mut problems = Vec::new();
    let mut report = String::new();
    let mut cold_plan_hash = None;
    for &variant_kind in variants {
        let (variant, warm) = (variant_kind.name(), variant_kind == Variant::Warm);
        let (pairs, resources, tag, machine) = match scenario.suite {
            Suite::Ssh => {
                let sides = Side::BOTH.map(|side| {
                    let run = HostRun {
                        env: &env,
                        ..setup.runs[side.index()]
                    };
                    (side, context.binary(side), run)
                });
                let dir = setup
                    .dir
                    .join(scenario.suite.name())
                    .join(scenario.name)
                    .join(variant);
                let seed = warm.then_some(context.files.as_ref());
                let pairs =
                    runner::compare_ssh(sides, &context.homes, &dir.to_string_lossy(), seed)?;
                let machine = runner::Machine {
                    host: distro.host(),
                    user: vm::SSH_USER,
                };
                (
                    pairs,
                    setup.ssh_resources,
                    variant.to_owned(),
                    Some(machine),
                )
            }
            Suite::Local => {
                let local = setup.local.ok_or("no local suite for this distro")?;
                let url = context.content_url(Suite::Local);
                let pairs = runner::compare_local(distro, &url, warm)?;
                (pairs, local.resources, format!("local {variant}"), None)
            }
        };
        for pair in &pairs {
            for problem in runner::evidence_problems(pair, resources) {
                problems.push(format!("[{tag}] {problem}"));
            }
        }
        for problem in runner::candidate_problems(&pairs, machine) {
            problems.push(format!("[{tag}] {problem}"));
        }
        // the target is the same for both variants, so the candidate's plan of it is too
        let plan_hash = runner::candidate_plan_hash(&pairs);
        if warm {
            if plan_hash != cold_plan_hash {
                problems.push(format!(
                    "[{tag}] the candidate's plan_hash differs between cold and warm: {} vs {}",
                    cold_plan_hash.as_deref().unwrap_or("none"),
                    plan_hash.as_deref().unwrap_or("none")
                ));
            }
        } else {
            cold_plan_hash = plan_hash;
        }
        for pair in &pairs {
            let key = RunKey {
                distro,
                suite: scenario.suite,
                scenario: scenario.name,
                variant: variant_kind,
                command: pair.command,
            };
            let judged = intended::judge(
                &context.intended,
                &key,
                context.level,
                &pair.oracle.observed,
                &pair.candidate.observed,
            );
            trace.intended.extend(
                judged
                    .accepted
                    .iter()
                    .map(|entry| intended::render(&tag, entry)),
            );
            problems.extend(judged.stale.iter().map(|stale| format!("[{tag}] {stale}")));
            if judged.unaccepted {
                report.push_str(&runner::divergence(context.level, &tag, pair));
            }
        }
        if !warm {
            trace.moved = runner::moved_resources(&pairs);
            problems.extend(plan_expectation_problems(scenario, &pairs));
        }
        check_warm_matches_cold(&pairs, trace, warm, &tag, &mut problems);
    }
    let fetched = fetch_count(context) - fetched_before;
    trace.runs = started.elapsed();
    drop(lock_edits);
    if fetched > 0 {
        problems.push(format!(
            "the read-only commands fetched remote content {fetched} time(s)"
        ));
    }

    let started = Instant::now();
    let runtime_after = audit::run_audit(distro)?;
    trace.audit = started.elapsed();
    problems.extend(audit::anchor_problems(
        &runtime_before,
        anchors(distro, scenario),
    ));
    problems.extend(audit::judge(&runtime_before, &runtime_after));

    let expected: Vec<(String, String)> = scenario
        .expect
        .iter()
        .map(|(id, mark)| ((*id).to_owned(), (*mark).to_owned()))
        .collect();
    if trace.moved != expected {
        problems.push(format!(
            "the oracle saw a different state than the scenario expects\n  \
             expected: {}\n  observed: {}",
            render_moved(&expected),
            render_moved(&trace.moved)
        ));
    }

    // only now, with the read-only phase judged: the apply changes what it audited
    if let Some(probe) = scenario.reconverge.as_deref() {
        if context.keep {
            trace.reconverge = Reconverged::Skipped;
        } else {
            let started = Instant::now();
            let outcome = reconverge::run(context, setup, scenario, probe, &mutated.stdout);
            trace.reconverge = Reconverged::Ran {
                took: started.elapsed(),
                passed: outcome.is_ok(),
            };
            if let Err(problem) = outcome {
                problems.push(format!("[reconverge] {problem}"));
            }
        }
    }

    Ok(if !problems.is_empty() {
        let mut message = problems.join("\n");
        if !report.is_empty() {
            message.push_str("\n(divergences, for context)\n");
            message.push_str(&report);
        }
        Verdict::Error(message)
    } else if report.is_empty() {
        Verdict::Pass
    } else {
        Verdict::Diverged(report)
    })
}

/// The root shell script that puts the base in `scenario`'s state: its mutation, then
/// the audit's stamp and runtime digest (`audit::after_mutation`). A reconverging
/// scenario's probe reads the base before the mutation and the drifted state after
/// it, ahead of the stamp, so nothing it does can read as a zap run's write.
fn mutation_script(scenario: &Scenario) -> String {
    let stamp = audit::after_mutation();
    scenario.reconverge.as_deref().map_or_else(
        || format!("{}\n{stamp}", scenario.mutation),
        |probe| {
            format!(
                "{}\n{}\n{}\n{stamp}",
                reconverge::probe_script(reconverge::ON_BASE, probe),
                scenario.mutation,
                reconverge::probe_script(reconverge::DRIFTED, probe),
            )
        },
    )
}

/// The runtime-digest anchors for `scenario` on `distro`: the sleeper's live
/// identity, the firewall's (ufw status on Debian; on Alpine, where ufw also runs,
/// zap's nftables table), and the postgres role, unless the scenario removes them on
/// purpose.
fn anchors(distro: Distro, scenario: &Scenario) -> audit::Anchors {
    let firewall = match distro {
        Distro::Debian => "Status: active",
        Distro::Alpine => "table inet filter",
    };
    audit::Anchors {
        sleeper: !scenario.without.contains(&Anchor::Sleeper),
        firewall: (!scenario.without.contains(&Anchor::Firewall)).then_some(firewall),
        postgres: !scenario.without.contains(&Anchor::Postgres),
    }
}

/// The scenario's `expect_plan` checks against the oracle's `plan` output.
fn plan_expectation_problems(scenario: &Scenario, pairs: &[Pair]) -> Vec<String> {
    let Some(plan) = pairs.iter().find(|pair| pair.command == "plan") else {
        return vec!["no `plan` run to check".to_owned()];
    };
    let stdout = &plan.oracle.captured.stdout;
    scenario
        .expect_plan
        .iter()
        .filter(|(text, present)| stdout.contains(text) != *present)
        .map(|(text, present)| {
            let wanted = if *present {
                "to contain"
            } else {
                "not to contain"
            };
            format!("expected the oracle's `plan` {wanted} {text:?}")
        })
        .collect()
}

/// The warm variant must see the same target the cold one did.
fn check_warm_matches_cold(
    pairs: &[Pair],
    trace: &Trace,
    warm: bool,
    tag: &str,
    problems: &mut Vec<String>,
) {
    if warm {
        let moved = runner::moved_resources(pairs);
        if moved != trace.moved {
            problems.push(format!(
                "[{tag}] the oracle's detect differs between cold and warm: {} vs {}",
                render_moved(&trace.moved),
                render_moved(&moved)
            ));
        }
    }
}

/// Connections seen by every server a run can reach — the loopback one the dev
/// machine's zap runs fetch from, and the origin the guests do: the one count both
/// were started with.
fn fetch_count(context: &Context) -> usize {
    context.connections.count()
}

/// What `ZAPDIFF_CONTENT` resolves to for a zap run of `suite`: where that zap fetches
/// its `remote` content from. A run on the dev machine reads the `loopback` server,
/// over the plain `http` zap takes from a loopback host alone. A run inside the guest
/// can't reach that address — its own loopback is the guest — so it reads the https
/// `origin`.
const fn content_url_for<'a>(suite: Suite, loopback: &'a str, origin: &'a str) -> &'a str {
    match suite {
        Suite::Ssh => loopback,
        Suite::Local => origin,
    }
}

/// Start the https origin on `address` — the libvirt gateway address, in a run —
/// serving the `remote` content (for a zap run inside a guest) and what a target
/// fetches for itself, and prove a client that trusts the test CA is answered there.
fn start_origin(
    pki: &pki::Pki,
    content: &BTreeMap<String, Vec<u8>>,
    address: IpAddr,
    connections: &Connections,
) -> Result<ContentServer, String> {
    let targets = content::target_files();
    let probe = targets
        .keys()
        .next()
        .cloned()
        .ok_or("the origin serves no target file")?;
    let mut served = content.clone();
    served.extend(targets);
    let config = pki.server_config()?;
    let origin = ContentServer::start_tls(address, Arc::new(served), config, connections).map_err(
        |error| {
            format!(
                "binding the https origin on {address} failed: {error} — the guests reach the \
                 dev machine at the libvirt `default` network's address, so that network must \
                 be active (`virsh -c qemu:///system net-start default`)"
            )
        },
    )?;
    let trusting = pki.client_config()?;
    origin.check_tls(trusting, &probe).map_err(|error| {
        format!(
            "the https origin does not answer a client that trusts the test CA in {}: {error}{}",
            pki.dir().display(),
            pki.remedy()
        )
    })?;
    Ok(origin)
}

fn render_moved(moved: &[(String, String)]) -> String {
    if moved.is_empty() {
        "nothing".to_owned()
    } else {
        moved
            .iter()
            .map(|(id, mark)| format!("{id}({mark})"))
            .collect::<Vec<_>>()
            .join(" ")
    }
}

/// `cargo build --release -p zap`; the executable cargo reports it built.
fn build_candidate(repo: &Path) -> Result<PathBuf, String> {
    println!("building the candidate (cargo build --release -p zap)…");
    let output = Command::new("cargo")
        .args([
            "build",
            "--release",
            "--package",
            "zap",
            "--message-format=json-render-diagnostics",
        ])
        .current_dir(repo)
        .stderr(std::process::Stdio::inherit())
        .output()
        .map_err(|error| format!("failed to run cargo: {error}"))?;
    if !output.status.success() {
        return Err(format!("the candidate build failed ({})", output.status));
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    built_executable(&stdout, "zap").ok_or_else(|| "cargo reported no `zap` executable".to_owned())
}

/// The `executable` of the last `compiler-artifact` message for binary `name` in
/// cargo's JSON message stream.
fn built_executable(messages: &str, name: &str) -> Option<PathBuf> {
    messages
        .lines()
        .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
        .filter(|message| {
            message["reason"] == "compiler-artifact" && message["target"]["name"] == name
        })
        .filter_map(|message| message["executable"].as_str().map(PathBuf::from))
        .next_back()
}

/// The `fgro` build the run evaluates with: `ZAP_FGRO`, an absolute path to a file.
/// Both binaries are given it as `--fgro` and the VM gets a copy, so the comparison
/// never turns on which build either side found.
///
/// # Errors
/// `ZAP_FGRO` is unset, relative, or names nothing.
fn fgro_from_env() -> Result<PathBuf, String> {
    let fgro = std::env::var_os("ZAP_FGRO").map(PathBuf::from).ok_or(
        "ZAP_FGRO is unset: name the fgro build both binaries evaluate the fixtures with, \
         by absolute path",
    )?;
    if !fgro.is_absolute() {
        return Err(format!(
            "ZAP_FGRO {} is not an absolute path",
            fgro.display()
        ));
    }
    if !fgro.is_file() {
        return Err(format!("ZAP_FGRO {} is not a file", fgro.display()));
    }
    Ok(fgro)
}

fn file_blake3(path: &Path) -> Result<String, String> {
    let bytes =
        std::fs::read(path).map_err(|error| format!("reading {}: {error}", path.display()))?;
    Ok(blake3::hash(&bytes).to_hex().to_string())
}

/// What the harness keeps on this machine: `~/.cache/zap-differential`, holding the
/// test CA (`pki`), each run's scratch tree ([`fixture::RUNS_DIR`]), and an oracle's
/// build directory while it builds ([`oracle`]).
///
/// # Errors
/// `HOME` is unset, empty, or not an absolute path.
fn cache_dir() -> Result<PathBuf, String> {
    Ok(home_dir()?.join(".cache").join("zap-differential"))
}

/// `HOME`, which must be an absolute path.
fn home_dir() -> Result<PathBuf, String> {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .filter(|home| home.is_absolute())
        .ok_or_else(|| {
            "HOME is not an absolute path: the harness has nowhere to keep its test CA, runs, \
             and oracle builds"
                .to_owned()
        })
}

/// The repo root (two levels above this crate).
fn repo_root() -> Result<PathBuf, String> {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    std::fs::canonicalize(manifest.join("../.."))
        .map_err(|error| format!("locating the repo root failed: {error}"))
}

fn print_verdict(
    label: &str,
    scenario: &Scenario,
    verdict: &Verdict,
    trace: &Trace,
    total: Duration,
) {
    let status = match verdict {
        Verdict::Pass => "PASS",
        Verdict::Diverged(_) => "DIVERGED",
        Verdict::Error(_) => "ERROR",
    };
    let reconverge = match trace.reconverge {
        Reconverged::Ran { took, .. } => format!(", reconverge {}", seconds(took)),
        Reconverged::NotFlagged | Reconverged::Skipped => String::new(),
    };
    let phases = if scenario.kind == Kind::Compare {
        format!(
            "revert {}, zap runs {}, audit {}{reconverge}",
            seconds(trace.revert),
            seconds(trace.runs),
            seconds(trace.audit)
        )
    } else {
        std::iter::once(("revert", trace.revert))
            .chain(trace.phases.iter().copied())
            .map(|(name, took)| format!("{name} {}", seconds(took)))
            .collect::<Vec<_>>()
            .join(", ")
    };
    println!(
        "  {status:<8} {label:<30} {:>6}  ({phases})",
        seconds(total)
    );
    println!("           {}", scenario.about);
    if scenario.kind == Kind::Compare {
        println!(
            "           oracle detect moved: {}",
            render_moved(&trace.moved)
        );
    }
    for note in &trace.notes {
        println!("           {note}");
    }
    match trace.reconverge {
        Reconverged::Ran { passed: true, .. } => {
            println!("           candidate reconverged it: the probe reads the base again");
        }
        Reconverged::Skipped => println!("           reconverge skipped (--keep)"),
        Reconverged::Ran { passed: false, .. } | Reconverged::NotFlagged => {}
    }
    for accepted in &trace.intended {
        print!("{accepted}");
    }
    match verdict {
        Verdict::Pass => {}
        Verdict::Diverged(report) => print!("{report}"),
        Verdict::Error(message) => {
            for line in message.lines() {
                println!("      {line}");
            }
        }
    }
}

fn print_timing(distro: Distro, reports: &[ScenarioReport]) {
    let timed: Vec<_> = reports.iter().filter(|r| r.distro == distro).collect();
    if timed.is_empty() {
        return;
    }
    let count = u32::try_from(timed.len()).unwrap_or(u32::MAX);
    let sum = |f: fn(&ScenarioReport) -> Duration| -> Duration { timed.iter().map(|r| f(r)).sum() };
    let total = sum(|r| r.total);
    println!(
        "  timing   {} scenario(s) in {}; mean {} per scenario \
         (revert {}, mutate {}, zap runs {}, audit {})",
        timed.len(),
        seconds(total),
        seconds(total / count),
        seconds(sum(|r| r.trace.revert) / count),
        seconds(sum(|r| r.trace.mutate) / count),
        seconds(sum(|r| r.trace.runs) / count),
        seconds(sum(|r| r.trace.audit) / count),
    );
}

fn seconds(duration: Duration) -> String {
    format!("{:.1}s", duration.as_secs_f64())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::net::{IpAddr, Ipv4Addr};
    use std::path::PathBuf;
    use std::sync::Arc;

    use super::content::{Connections, ContentServer};
    use super::pki::tests::openssl;
    use super::pki::{Pki, server_names};
    use super::scenarios::Suite;
    use super::{built_executable, content, content_url_for, parse_resource_count, start_origin};

    const LOOPBACK: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

    /// The origin serves the `remote` content and the target's own files alike, over
    /// https, and has answered its own check before it is handed back.
    #[test]
    fn the_origin_serves_content_and_target_files_over_https() {
        let Some(openssl) = openssl() else { return };
        let scratch = tempfile::tempdir().expect("tempdir");
        let pki = Pki::ensure(scratch.path(), &openssl, &server_names()).expect("a pki");
        let mut remote = BTreeMap::new();
        remote.insert("/blob.bin".to_owned(), b"blob".to_vec());
        let connections = Connections::default();
        let origin = start_origin(&pki, &remote, LOOPBACK, &connections).expect("an origin");
        assert!(origin.base_url().starts_with("https://127.0.0.1:"));
        // the check it ran on itself, counted where the run reads
        assert_eq!((origin.requests(), connections.count()), (1, 1));
        let client = pki.client_config().expect("a client config");
        for path in content::target_files().keys().chain(remote.keys()) {
            assert_eq!(
                origin.check_tls(Arc::clone(&client), path),
                Ok(()),
                "{path}"
            );
        }
        assert!(origin.check_tls(client, "/pins.ts").is_err());
        let served = content::target_files().len() + remote.len() + 2;
        assert_eq!(connections.count(), served);
    }

    /// A zap run on the dev machine is given the loopback server and one inside the
    /// guest the origin — never the other way: the guest's loopback is the guest, and
    /// zap takes plain `http` from no other machine.
    #[test]
    fn a_guest_run_fetches_from_the_origin_and_a_host_run_from_loopback() {
        let connections = Connections::default();
        let loopback = ContentServer::start(LOOPBACK, Arc::new(BTreeMap::new()), &connections)
            .expect("bind loopback");
        let loopback = loopback.base_url();
        let origin = "https://192.168.122.1:40443";
        assert_eq!(content_url_for(Suite::Ssh, &loopback, origin), loopback);
        assert!(loopback.starts_with("http://127.0.0.1:"), "{loopback}");
        let guest = content_url_for(Suite::Local, &loopback, origin);
        assert_eq!(guest, origin);
        assert!(guest.starts_with("https://"), "{guest}");
        assert!(!guest.contains("127.0.0.1"), "{guest}");
    }

    /// A kept certificate that doesn't name the address the origin is bound to stops
    /// the run at startup, with the directory to remove.
    #[test]
    fn an_origin_its_own_ca_does_not_vouch_for_stops_the_run() {
        let Some(openssl) = openssl() else { return };
        let scratch = tempfile::tempdir().expect("tempdir");
        let elsewhere = ["IP:192.0.2.7".to_owned(), "DNS:elsewhere.test".to_owned()];
        let pki = Pki::ensure(scratch.path(), &openssl, &elsewhere).expect("a pki");
        let error = start_origin(&pki, &BTreeMap::new(), LOOPBACK, &Connections::default())
            .expect_err("a refusal");
        assert!(
            error.starts_with(&format!(
                "the https origin does not answer a client that trusts the test CA in {}: ",
                scratch.path().display()
            )),
            "{error}"
        );
        assert!(error.ends_with(&pki.remedy()), "{error}");
    }

    #[test]
    fn resource_count_parses_config_validate() {
        assert_eq!(parse_resource_count("ok: 42 resource(s)\n"), Some(42));
        assert_eq!(parse_resource_count("error: bad config\n"), None);
    }

    #[test]
    fn built_executable_reads_cargo_messages() {
        let messages = r#"{"reason":"compiler-artifact","target":{"name":"zap_core"},"executable":null}
{"reason":"compiler-artifact","target":{"name":"zap"},"executable":"/r/target/release/zap"}
{"reason":"build-finished","success":true}"#;
        assert_eq!(
            built_executable(messages, "zap"),
            Some(PathBuf::from("/r/target/release/zap"))
        );
        assert_eq!(built_executable(messages, "nope"), None);
    }
}
