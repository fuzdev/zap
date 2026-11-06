//! zap — convergent machine-state management.
//!
//! Describe what a machine should be in a TypeScript config; Zap detects the
//! current state, plans the diff, applies idempotent changes, and emits
//! structured events:
//!
//! **Describe → Detect → Plan → Apply → Observe**
//!
//! This binary is the thin CLI shell: it parses arguments with `argh` and
//! delegates each verb to a command core in [`zap_core::commands`], then maps
//! engine errors to exit codes. The convergence engine — config eval through a
//! pinned `fgro eval`, the resource/state model, the lock file,
//! `Connection`-based local/SSH execution, and package/service backends — lives
//! in `zap_core` (over the pure `zap_types` plan)
//! and is exposed through the verbs `detect` (live probe), `plan` (detect +
//! diff to the plan fact), `status` (the last run, offline), `apply` (converge,
//! dry-run by default), `deploy` (release-push), `config validate` (eval +
//! schema-parse the config, machine-free), and the lock verbs (`lock` /
//! `lock --check` / `update`). Command cores return data; this binary renders
//! it.

use std::io::IsTerminal as _;
use std::sync::Arc;

use argh::FromArgs;
use zap_core::commands::Prompt;
use zap_core::error::Error;
use zap_core::escape::{escape_join, escape_line};

/// zap — convergent machine-state management.
///
/// Describe → Detect → Plan → Apply → Observe.
#[derive(FromArgs, Debug)]
struct TopLevel {
    #[argh(subcommand)]
    nested: Option<Subcommand>,
}

#[derive(FromArgs, Debug)]
#[argh(subcommand)]
enum Subcommand {
    Detect(Detect),
    Plan(Plan),
    Apply(Apply),
    Deploy(Deploy),
    Status(Status),
    Config(Config),
    Lock(Lock),
    Update(Update),
    Version(Version),
}

/// Detect: inspect the current state of the target machine (no diff).
#[derive(FromArgs, Debug)]
#[argh(subcommand, name = "detect")]
struct Detect {
    /// path to the zap.ts config (default: zap.ts)
    #[argh(positional)]
    config: Option<String>,
    /// re-evaluate the config instead of serving it from the eval cache
    #[argh(switch)]
    no_cache: bool,
    /// connect as the target's `bootstrap_user` (for the initial provisioning run, before SSH hardening creates the primary user)
    #[argh(switch)]
    bootstrap: bool,
    /// the fgro binary that evaluates the config, by absolute path (overrides `ZAP_FGRO`)
    #[argh(option)]
    fgro: Option<String>,
    /// load operator env vars from a file of NAME=VALUE lines (a strict subset of
    /// dotenv) before resolving
    #[argh(option)]
    env_file: Option<String>,
}

/// Plan: diff the desired state (from `zap.ts`) against the detected state.
#[derive(FromArgs, Debug)]
#[argh(subcommand, name = "plan")]
struct Plan {
    /// path to the zap.ts config (default: zap.ts)
    #[argh(positional)]
    config: Option<String>,
    /// add per-resource current → desired attribute diffs above the step commands
    #[argh(switch)]
    diff: bool,
    /// re-evaluate the config instead of serving it from the eval cache
    #[argh(switch)]
    no_cache: bool,
    /// connect as the target's `bootstrap_user` (for the initial provisioning run, before SSH hardening creates the primary user)
    #[argh(switch)]
    bootstrap: bool,
    /// the fgro binary that evaluates the config, by absolute path (overrides `ZAP_FGRO`)
    #[argh(option)]
    fgro: Option<String>,
    /// load operator env vars from a file of NAME=VALUE lines (a strict subset of
    /// dotenv) before resolving
    #[argh(option)]
    env_file: Option<String>,
}

/// Apply: converge the machine to the desired state (dry-run by default).
// A flat bundle of CLI switches — `excessive_bools` targets domain types that encode
// hidden state, not a 1:1 mirror of command-line flags.
#[allow(clippy::struct_excessive_bools)]
#[derive(FromArgs, Debug)]
#[argh(subcommand, name = "apply")]
struct Apply {
    /// path to the zap.ts config (default: zap.ts)
    #[argh(positional)]
    config: Option<String>,
    /// actually execute changes instead of dry-running
    #[argh(switch)]
    wetrun: bool,
    /// execute only if the plan hash is exactly this one (a wetrun otherwise binds to the last preview on the host)
    #[argh(option)]
    expect_plan: Option<String>,
    /// stream structured events as JSON-lines to stdout (during a wetrun)
    #[argh(switch)]
    json: bool,
    /// skip the lock's tracked pins: no reads, writes, or cold-start resolution (offline; the toolchain pin is still read)
    #[argh(switch)]
    no_lock: bool,
    /// re-evaluate the config instead of serving it from the eval cache
    #[argh(switch)]
    no_cache: bool,
    /// connect as the target's `bootstrap_user` (for the initial provisioning run, before SSH hardening creates the primary user)
    #[argh(switch)]
    bootstrap: bool,
    /// the fgro binary that evaluates the config, by absolute path (overrides `ZAP_FGRO`)
    #[argh(option)]
    fgro: Option<String>,
    /// load operator env vars from a file of NAME=VALUE lines (a strict subset of
    /// dotenv) before resolving
    #[argh(option)]
    env_file: Option<String>,
}

/// Deploy: release a new version to a remote target (dry-run by default).
// A flat bundle of CLI switches — `excessive_bools` targets domain types, not a 1:1
// mirror of command-line flags.
#[allow(clippy::struct_excessive_bools)]
#[derive(FromArgs, Debug)]
#[argh(subcommand, name = "deploy")]
struct Deploy {
    /// path to the zap.ts config (default: zap.ts)
    #[argh(positional)]
    config: Option<String>,
    /// actually execute the deploy instead of dry-running
    #[argh(switch)]
    wetrun: bool,
    /// execute only if the deploy plan hash is exactly this one (a wetrun otherwise binds to the last deploy preview on the host)
    #[argh(option)]
    expect_plan: Option<String>,
    /// deploy an unchanged server version, and version a dirty tree `<hash>-dirty-<id>` (a dirty tree is refused without it)
    #[argh(switch)]
    force: bool,
    /// skip the local build step
    #[argh(switch)]
    skip_build: bool,
    /// skip the pre-deploy drift preflight
    #[argh(switch)]
    skip_preflight: bool,
    /// connect as the target's `bootstrap_user` (for the initial provisioning run, before SSH hardening creates the primary user)
    #[argh(switch)]
    bootstrap: bool,
    /// stream structured events as JSON-lines to stdout (during a wetrun)
    #[argh(switch)]
    json: bool,
    /// re-evaluate the config instead of serving it from the eval cache
    #[argh(switch)]
    no_cache: bool,
    /// the fgro binary that evaluates the config, by absolute path (overrides `ZAP_FGRO`)
    #[argh(option)]
    fgro: Option<String>,
    /// load operator env vars from a file of NAME=VALUE lines (a strict subset of
    /// dotenv) before resolving
    #[argh(option)]
    env_file: Option<String>,
}

/// Status: show the last run's verdicts, offline (no connection to the target).
#[derive(FromArgs, Debug)]
#[argh(subcommand, name = "status")]
struct Status {
    /// path to the zap.ts config (default: zap.ts)
    #[argh(positional)]
    config: Option<String>,
    /// the fgro binary that evaluates the config, by absolute path (overrides `ZAP_FGRO`)
    #[argh(option)]
    fgro: Option<String>,
    /// load operator env vars from a file of NAME=VALUE lines (a strict subset of
    /// dotenv) before resolving
    #[argh(option)]
    env_file: Option<String>,
}

/// Config: inspect the `zap.ts` config itself (machine-free).
#[derive(FromArgs, Debug)]
#[argh(subcommand, name = "config")]
struct Config {
    #[argh(subcommand)]
    nested: ConfigSub,
}

#[derive(FromArgs, Debug)]
#[argh(subcommand)]
enum ConfigSub {
    Validate(ConfigValidate),
}

/// Validate: eval `zap.ts` and parse it against the schema (no target bound).
#[derive(FromArgs, Debug)]
#[argh(subcommand, name = "validate")]
struct ConfigValidate {
    /// path to the zap.ts config (default: zap.ts)
    #[argh(positional)]
    config: Option<String>,
    /// the fgro binary that evaluates the config, by absolute path (overrides `ZAP_FGRO`)
    #[argh(option)]
    fgro: Option<String>,
    /// load operator env vars from a file of NAME=VALUE lines (a strict subset of
    /// dotenv) before resolving
    #[argh(option)]
    env_file: Option<String>,
}

/// Lock: pin the `fgro` build and re-baseline `zap.lock` from upstream, or (`--check`) verify config↔lock.
#[derive(FromArgs, Debug)]
#[argh(subcommand, name = "lock")]
struct Lock {
    /// path to the zap.ts config (default: zap.ts)
    #[argh(positional)]
    config: Option<String>,
    /// only check config↔lock consistency (no network, no detection)
    #[argh(switch)]
    check: bool,
    /// the fgro binary that evaluates the config, by absolute path (overrides `ZAP_FGRO`)
    #[argh(option)]
    fgro: Option<String>,
    /// load operator env vars from a file of NAME=VALUE lines (a strict subset of
    /// dotenv) before resolving
    #[argh(option)]
    env_file: Option<String>,
}

/// Update: re-fetch and advance lock pins (all eligible, or the named ids).
#[derive(FromArgs, Debug)]
#[argh(subcommand, name = "update")]
struct Update {
    /// resource ids to advance (default: all eligible)
    #[argh(positional)]
    ids: Vec<String>,
    /// path to the zap.ts config (default: zap.ts)
    #[argh(option)]
    config: Option<String>,
    /// the fgro binary that evaluates the config, by absolute path (overrides `ZAP_FGRO`)
    #[argh(option)]
    fgro: Option<String>,
    /// load operator env vars from a file of NAME=VALUE lines (a strict subset of
    /// dotenv) before resolving
    #[argh(option)]
    env_file: Option<String>,
}

/// Version: print the zap version.
#[derive(FromArgs, Debug)]
#[argh(subcommand, name = "version")]
struct Version {}

fn main() -> std::process::ExitCode {
    match run() {
        Ok(code) => std::process::ExitCode::from(code),
        Err(e) => {
            // The one place an error is printed: `Error::render` escapes whatever the
            // message quotes.
            eprint!("{}", e.render());
            std::process::ExitCode::from(e.exit_code())
        }
    }
}

/// Dispatch a verb and return its process exit code — derived from each verb's report
/// (the bin maps, it doesn't decide): see `ApplyReport::exit_code` and its siblings on
/// the plan / detect / status / deploy / lock reports.
#[tokio::main]
async fn run() -> Result<u8, Error> {
    // Parse explicitly rather than `argh::from_env`, which hard-exits `1` on any parse
    // failure — a usage error is `2` by shell convention ("fix the invocation"). A
    // help/version request (`EarlyExit { status: Ok }`) prints to stdout and exits 0.
    let raw: Vec<String> = std::env::args().collect();
    let cmd: TopLevel = match parse_args(&raw) {
        Ok(cmd) => cmd,
        Err(early_exit) => {
            // `status: Ok` = a help/version request (stdout, exit 0); `Err` = a usage
            // error (stderr, exit 2 — `from_env` would exit 1).
            return Ok(if early_exit.status.is_ok() {
                println!("{}", early_exit.output);
                0
            } else {
                eprintln!("{}", early_exit.output);
                2
            });
        }
    };
    // The `minisign` a signature check runs, read here so the engine reads no
    // configuration-bearing env var; its value is checked where it is used.
    zap_core::resolver::set_minisign_setting(std::env::var_os(zap_core::resolver::MINISIGN_VAR));
    // No subcommand → print the convergence loop and a usage hint.
    let Some(sub) = cmd.nested else {
        print_overview();
        return Ok(0);
    };
    match sub {
        Subcommand::Detect(args) => cmd_detect(&args).await,
        Subcommand::Plan(args) => cmd_plan(&args).await,
        Subcommand::Apply(args) => cmd_apply(&args).await,
        Subcommand::Deploy(args) => cmd_deploy(&args).await,
        Subcommand::Status(args) => cmd_status(&args).await,
        Subcommand::Config(args) => cmd_config(&args).await,
        Subcommand::Lock(args) => cmd_lock(&args).await,
        Subcommand::Update(args) => cmd_update(&args).await,
        Subcommand::Version(_) => cmd_version(),
    }
}

/// Parse the command line (`raw`, the program name first).
///
/// The text of an early exit — the help, or a usage error — quotes the command line: the
/// program name, an argument it didn't recognize. It is taken from a second parse of the
/// arguments as [`escape_line`] shows them, so an argument can't act on the terminal or
/// add a line to the message. An escaped argument still starts with a `-` or doesn't,
/// and a control character never made one a flag or a command, so the second parse ends
/// where the first did; if it ever didn't, the first one's text is shown line by line.
fn parse_args(raw: &[String]) -> Result<TopLevel, argh::EarlyExit> {
    fn parse(args: &[&str]) -> Result<TopLevel, argh::EarlyExit> {
        let (bin, rest) = args.split_first().unwrap_or((&"zap", &[]));
        TopLevel::from_args(&[bin], rest)
    }
    let args: Vec<&str> = raw.iter().map(String::as_str).collect();
    parse(&args).map_err(|early_exit| {
        let shown: Vec<_> = raw.iter().map(|arg| escape_line(arg)).collect();
        let shown: Vec<&str> = shown.iter().map(AsRef::as_ref).collect();
        match parse(&shown) {
            Err(shown) if shown.status == early_exit.status => shown,
            _ => argh::EarlyExit {
                output: escape_join(early_exit.output.split('\n'), "\n"),
                status: early_exit.status,
            },
        }
    })
}

fn print_overview() {
    println!("zap — convergent machine-state management");
    println!();
    println!("  describe   declare desired state in a TypeScript config (zap.ts)");
    println!("  detect     inspect what the machine actually looks like now");
    println!("  plan       diff desired against actual — the dry run");
    println!("  apply      converge the machine idempotently");
    println!("  observe    structured events, not log soup");
    println!();
    println!("run `zap --help` for the command list");
}

/// Install the `--env-file` overlay (if given) before any config resolution, so its
/// `NAME=VALUE` pairs back the reference and secret reads, and print the warning for a
/// file that holds secrets other users can read. A no-op when unset.
fn load_env_file(env_file: Option<&str>) -> Result<(), Error> {
    if let Some(path) = env_file {
        let loaded = zap_core::resolve::install_env_file(std::path::Path::new(path))?;
        if let Some(warning) = loaded.warning {
            eprintln!("{}", escape_line(&warning));
        }
    }
    Ok(())
}

/// Where an `apply` / `deploy` text report goes.
///
/// Under `--json --wetrun` stdout is a JSON-lines channel and nothing else is written
/// to it. A run that streamed its events has said everything there. One that ended
/// before any event — a refusal, a preflight bail, a target already at the version —
/// has said nothing, so its report goes to stderr: the exit code alone doesn't say why.
/// `--json` on a dry run is a no-op (nothing executes), so the preview goes to stdout.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReportTo {
    Stdout,
    Stderr,
    Nowhere,
}

impl ReportTo {
    /// `json_wetrun`: the run was asked to stream events. `streamed`: it emitted some.
    const fn of(json_wetrun: bool, streamed: bool) -> Self {
        match (json_wetrun, streamed) {
            (false, _) => Self::Stdout,
            (true, false) => Self::Stderr,
            (true, true) => Self::Nowhere,
        }
    }

    fn write(self, rendered: &str) {
        match self {
            Self::Stdout => print!("{rendered}"),
            Self::Stderr => eprint!("{rendered}"),
            Self::Nowhere => {}
        }
    }
}

/// The prompt a wetrun with no review asks on: this process's terminal, never under
/// `--json` (`json`).
fn terminal_prompt(json: bool) -> Option<Arc<dyn Prompt>> {
    let prompt: Arc<dyn Prompt> = Arc::new(TerminalPrompt);
    (!json).then_some(prompt)
}

/// The operator's terminal: the question on standard error, the answer from standard
/// input.
#[derive(Debug)]
struct TerminalPrompt;

impl Prompt for TerminalPrompt {
    fn interactive(&self) -> bool {
        std::io::stdin().is_terminal() && std::io::stderr().is_terminal()
    }

    fn ask(&self, text: &str) -> Option<String> {
        // `text` is a render's return: escaped where it was built.
        let mut stderr = std::io::stderr();
        let mut stdin = zap_core::commands::prompt::StdinTerminal;
        zap_core::commands::prompt::ask_on(&mut stderr, &mut stdin, text)
    }
}

async fn cmd_detect(args: &Detect) -> Result<u8, Error> {
    load_env_file(args.env_file.as_deref())?;
    let path = std::path::Path::new(args.config.as_deref().unwrap_or("zap.ts"));
    let fgro = zap_core::config::fgro::fgro_setting(args.fgro.as_deref())?;
    let report =
        zap_core::commands::run_detect(path, fgro.as_deref(), args.no_cache, args.bootstrap)
            .await?;
    print!("{}", zap_core::commands::render_detect(&report));
    Ok(report.exit_code())
}

async fn cmd_plan(args: &Plan) -> Result<u8, Error> {
    load_env_file(args.env_file.as_deref())?;
    let path = std::path::Path::new(args.config.as_deref().unwrap_or("zap.ts"));
    let fgro = zap_core::config::fgro::fgro_setting(args.fgro.as_deref())?;
    let report =
        zap_core::commands::run_plan(path, fgro.as_deref(), args.no_cache, args.bootstrap).await?;
    let rendered = if args.diff {
        zap_core::commands::render_plan_diff(&report)
    } else {
        zap_core::commands::render_plan(&report)
    };
    print!("{rendered}");
    Ok(report.exit_code())
}

async fn cmd_apply(args: &Apply) -> Result<u8, Error> {
    load_env_file(args.env_file.as_deref())?;
    let path = std::path::Path::new(args.config.as_deref().unwrap_or("zap.ts"));
    let fgro = zap_core::config::fgro::fgro_setting(args.fgro.as_deref())?;
    let options = zap_core::commands::ApplyOptions {
        wetrun: args.wetrun,
        expect_plan: args.expect_plan.clone(),
        emit_json: args.json,
        no_lock: args.no_lock,
        bootstrap: args.bootstrap,
        no_cache: args.no_cache,
        prompt: terminal_prompt(args.json),
    };
    let report = zap_core::commands::run_apply(path, fgro.as_deref(), options).await?;
    let to = ReportTo::of(args.json && args.wetrun, report.streamed());
    to.write(&zap_core::commands::render_apply(&report));
    Ok(report.exit_code())
}

async fn cmd_deploy(args: &Deploy) -> Result<u8, Error> {
    load_env_file(args.env_file.as_deref())?;
    let path = std::path::Path::new(args.config.as_deref().unwrap_or("zap.ts"));
    let fgro = zap_core::config::fgro::fgro_setting(args.fgro.as_deref())?;
    let options = zap_core::commands::DeployOptions {
        wetrun: args.wetrun,
        expect_plan: args.expect_plan.clone(),
        force: args.force,
        skip_build: args.skip_build,
        skip_preflight: args.skip_preflight,
        bootstrap: args.bootstrap,
        emit_json: args.json,
        no_cache: args.no_cache,
        prompt: terminal_prompt(args.json),
    };
    let report = zap_core::commands::run_deploy(path, fgro.as_deref(), &options).await?;
    let to = ReportTo::of(args.json && args.wetrun, report.streamed());
    to.write(&zap_core::commands::render_deploy(&report));
    Ok(report.exit_code())
}

async fn cmd_status(args: &Status) -> Result<u8, Error> {
    load_env_file(args.env_file.as_deref())?;
    let path = std::path::Path::new(args.config.as_deref().unwrap_or("zap.ts"));
    let fgro = zap_core::config::fgro::fgro_setting(args.fgro.as_deref())?;
    let report = zap_core::commands::run_status(path, fgro.as_deref()).await?;
    print!("{}", zap_core::commands::render_status(&report));
    Ok(report.exit_code())
}

async fn cmd_config(args: &Config) -> Result<u8, Error> {
    match &args.nested {
        ConfigSub::Validate(validate) => cmd_config_validate(validate).await,
    }
}

/// Eval `zap.ts` and parse it against the schema, machine-free — no target binding,
/// no detection, no network. The `?` surfaces a parse/eval failure as a nonzero exit
/// with its message, like every engine error.
async fn cmd_config_validate(args: &ConfigValidate) -> Result<u8, Error> {
    load_env_file(args.env_file.as_deref())?;
    let path = std::path::Path::new(args.config.as_deref().unwrap_or("zap.ts"));
    let fgro = zap_core::config::fgro::fgro_setting(args.fgro.as_deref())?;
    // Run the full machine-free gate (eval + secret + structural integrity), not just a
    // bare eval — `config validate` is the pre-flight an operator/CI runs to catch a
    // hardcoded secret, a dangling reference, or a cycle before a real plan/apply.
    let count = zap_core::commands::run_config_validate(path, fgro.as_deref()).await?;
    println!("ok: {count} resource(s)");
    Ok(0)
}

async fn cmd_lock(args: &Lock) -> Result<u8, Error> {
    load_env_file(args.env_file.as_deref())?;
    let path = std::path::Path::new(args.config.as_deref().unwrap_or("zap.ts"));
    let fgro = zap_core::config::fgro::fgro_setting(args.fgro.as_deref())?;
    if args.check {
        let report = zap_core::commands::run_lock_check(path, fgro.as_deref()).await?;
        print!("{}", zap_core::commands::render_lock_check(&report));
        Ok(report.exit_code())
    } else {
        let report = zap_core::commands::run_lock(path, fgro.as_deref()).await?;
        print!("{}", zap_core::commands::render_lock(&report));
        Ok(0)
    }
}

async fn cmd_update(args: &Update) -> Result<u8, Error> {
    load_env_file(args.env_file.as_deref())?;
    let path = std::path::Path::new(args.config.as_deref().unwrap_or("zap.ts"));
    let fgro = zap_core::config::fgro::fgro_setting(args.fgro.as_deref())?;
    let report = zap_core::commands::run_update(path, fgro.as_deref(), &args.ids).await?;
    print!("{}", zap_core::commands::render_update(&report));
    Ok(report.exit_code())
}

// Uniform `Result`-returning handler signature across all dispatch arms; the
// other handlers delegate to the engine, while this one prints locally.
#[allow(clippy::unnecessary_wraps)]
fn cmd_version() -> Result<u8, Error> {
    println!("zap {}", env!("CARGO_PKG_VERSION"));
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::{ReportTo, parse_args};

    fn args(args: &[&str]) -> Vec<String> {
        args.iter().map(|&arg| arg.to_owned()).collect()
    }

    /// An ordinary command line parses as it always has, and its usage error reads the
    /// same.
    #[test]
    fn an_ordinary_command_line_parses() {
        assert!(parse_args(&args(&["zap", "plan", "site/zap.ts", "--diff"])).is_ok());
        let usage = parse_args(&args(&["zap", "plan", "--nope"])).unwrap_err();
        assert!(usage.status.is_err());
        assert_eq!(usage.output, "Unrecognized argument: --nope\n");
        let help = parse_args(&args(&["zap", "--help"])).unwrap_err();
        assert!(help.status.is_ok());
        assert!(
            help.output.starts_with("Usage: zap [<command>]"),
            "{}",
            help.output
        );
    }

    /// An argument the parser quotes back — one it doesn't recognize, the program's own
    /// name in the help — is shown escaped: it can't erase the message or add a line to
    /// it.
    #[test]
    fn a_usage_error_shows_a_hostile_argument_escaped() {
        let usage =
            parse_args(&args(&["zap", "plan", "--x\r\u{1b}[2K\nerror: forged"])).unwrap_err();
        assert!(usage.status.is_err());
        assert_eq!(
            usage.output,
            "Unrecognized argument: --x<U+000D><U+001B>[2K<U+000A>error: forged\n"
        );
        let help = parse_args(&args(&["z\u{1b}[1Aap\nUsage: forged", "--help"])).unwrap_err();
        assert!(help.status.is_ok());
        assert!(
            help.output
                .starts_with("Usage: z<U+001B>[1Aap<U+000A>Usage: forged [<command>]"),
            "{}",
            help.output
        );
        assert_eq!(
            help.output.matches("\nUsage:").count(),
            0,
            "{}",
            help.output
        );
    }

    /// The binary prints an error only through `Error::render`, which escapes it: no
    /// other print in this file takes an error's own `Display`.
    #[test]
    fn the_binary_prints_an_error_only_through_its_render() {
        let source = include_str!("main.rs");
        let (code, _tests) = source.split_once("#[cfg(test)]").unwrap();
        assert_eq!(code.matches("e.render()").count(), 1);
        for raw in ["{e}", "{e:", "{error}", "{err}", "to_string()"] {
            assert!(!code.contains(raw), "main.rs prints `{raw}`");
        }
    }

    /// stdout carries the text report or the event stream, never both; a `--json`
    /// wetrun that emitted no event still says why, on stderr.
    #[test]
    fn a_json_wetrun_that_streamed_nothing_reports_on_stderr() {
        assert_eq!(ReportTo::of(false, false), ReportTo::Stdout);
        assert_eq!(ReportTo::of(false, true), ReportTo::Stdout);
        assert_eq!(ReportTo::of(true, true), ReportTo::Nowhere);
        assert_eq!(ReportTo::of(true, false), ReportTo::Stderr);
    }

    /// Every line of the binary that prints something other than a string literal is
    /// one of these: a render's return, the early exit's text ([`parse_args`] escaped
    /// it), a count, the version. A new one fails here until what it prints is looked
    /// at.
    #[test]
    fn the_binary_prints_only_what_is_listed() {
        const PRINTS: &[&str] = &["print!(", "println!(", "eprint!(", "eprintln!("];
        const LISTED: &[&str] = &[
            r#"eprint!("{}", e.render());"#,
            r#"eprint!("{text}");"#,
            r#"println!("{}", early_exit.output);"#,
            r#"eprintln!("{}", early_exit.output);"#,
            r#"Self::Stdout => print!("{rendered}"),"#,
            r#"Self::Stderr => eprint!("{rendered}"),"#,
            r#"print!("{}", zap_core::commands::render_detect(&report));"#,
            r#"print!("{rendered}");"#,
            r#"print!("{}", zap_core::commands::render_status(&report));"#,
            r#"println!("ok: {count} resource(s)");"#,
            r#"print!("{}", zap_core::commands::render_lock_check(&report));"#,
            r#"print!("{}", zap_core::commands::render_lock(&report));"#,
            r#"print!("{}", zap_core::commands::render_update(&report));"#,
            r#"println!("zap {}", env!("CARGO_PKG_VERSION"));"#,
            r#"eprintln!("{}", escape_line(&warning));"#,
        ];
        let source = include_str!("main.rs");
        let (code, _tests) = source.split_once("#[cfg(test)]\nmod tests").unwrap();
        let unlisted: Vec<&str> = code
            .lines()
            .map(str::trim)
            .filter(|line| !line.starts_with("//"))
            .filter(|line| PRINTS.iter().any(|print| line.contains(print)))
            // A print of a literal alone interpolates nothing.
            .filter(|line| line.contains('{'))
            .filter(|line| !LISTED.contains(line))
            .collect();
        assert!(unlisted.is_empty(), "main.rs prints: {unlisted:#?}");
    }
}
