//! `cargo xtask` — dev automation for the zap workspace.
//!
//! Invoked via the `[alias] xtask = "run --package xtask --"` entry in
//! `.cargo/config.toml`, so `cargo xtask <subcommand>` runs this binary.
//!
//! - `install` — build the release `zap` for the host and install it to
//!   `~/.zap/bin/zap` (the on-`PATH` location), so the global binary matches the
//!   working tree. The copy goes
//!   through a temp file + rename so a currently-running `zap` doesn't make the
//!   write fail with `ETXTBSY`.
//! - `build-musl` — build a statically-linked release `zap` for the musl targets
//!   via `cargo-zigbuild`, so the binary runs on any Linux host (Alpine included)
//!   with no glibc dependency. ring is the TLS provider precisely so this build
//!   has no `aws-lc-sys` C library / `cmake` to cross-compile (see
//!   `zap_core::tls`). This is a build step, not release packaging
//!   (artifact collection / checksums / signing).
//! - `check-release` — the shared dep-graph audit (`fuz_audit`) that proves no
//!   production binary links the test/audit crates. Since this xtask has its own
//!   subcommand router, it calls `fuz_audit::run_check_release_cli()` from the
//!   dispatch arm rather than `fuz_audit::xtask_main()` (the entry for an xtask
//!   with that one subcommand).
//! - `differential` — run a trusted oracle `zap` and a candidate `zap` against the
//!   same states of the libvirt test VMs and fail on any difference in their
//!   `detect` / `plan` output (see `differential/mod.rs` and `docs/differential.md`).

mod differential;

use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};

/// Default targets for `build-musl` — a static binary per supported architecture.
const MUSL_TARGETS: &[&str] = &["x86_64-unknown-linux-musl", "aarch64-unknown-linux-musl"];

const USAGE: &str = "\
cargo xtask — dev automation for the zap workspace

Usage:
  cargo xtask <subcommand>

Subcommands:
  install                   build the release `zap` and install it to ~/.zap/bin/zap
  build-musl [<target>...]  build a static release `zap` for each musl target
                            (default: x86_64 + aarch64 linux-musl) via cargo-zigbuild
  check-release             audit that production binaries don't link test/audit crates
  differential [options]    compare an oracle zap (by default a build of
                            origin/main) and a candidate zap over the VM
                            scenario matrix (`cargo xtask differential --help`)

Prerequisites for `build-musl`:
  zig             on PATH (https://ziglang.org/download/)
  cargo-zigbuild  `cargo install cargo-zigbuild`
The musl rustup targets are added automatically per build (a no-op once present).
";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        None | Some("help" | "-h" | "--help") => {
            print!("{USAGE}");
            ExitCode::SUCCESS
        }
        Some("install") => install(),
        Some("build-musl") => build_musl(&args[1..]),
        Some("check-release") => fuz_audit::run_check_release_cli(),
        Some("differential") => differential::main(&args[1..]),
        Some(other) => {
            eprintln!("error: unknown subcommand `{other}`");
            print!("{USAGE}");
            ExitCode::FAILURE
        }
    }
}

/// Build the host release `zap` and install it to `~/.zap/bin/zap`.
///
/// The copy lands as `zap.tmp` then renames over the destination: a plain
/// overwrite of a currently-running binary fails with `ETXTBSY`, and the rename
/// keeps the swap atomic. Warns (non-fatally) when `~/.zap/bin` isn't on `PATH`.
fn install() -> ExitCode {
    let built = Command::new("cargo")
        .args(["build", "--release", "--package", "zap"])
        .status();
    match built {
        Ok(status) if status.success() => {}
        Ok(status) => {
            eprintln!("error: release build failed ({status})");
            return ExitCode::FAILURE;
        }
        Err(error) => {
            eprintln!("error: failed to run `cargo build`: {error}");
            return ExitCode::FAILURE;
        }
    }
    let Some(home) = std::env::var_os("HOME") else {
        eprintln!("error: $HOME is not set — can't locate ~/.zap/bin");
        return ExitCode::FAILURE;
    };
    let bin_dir = PathBuf::from(home).join(".zap").join("bin");
    let source = Path::new("target/release/zap");
    let staged = bin_dir.join("zap.tmp");
    let dest = bin_dir.join("zap");
    let installed = std::fs::create_dir_all(&bin_dir)
        .and_then(|()| std::fs::copy(source, &staged))
        .and_then(|_| std::fs::rename(&staged, &dest));
    if let Err(error) = installed {
        eprintln!("error: failed to install to {}: {error}", dest.display());
        return ExitCode::FAILURE;
    }
    match std::fs::metadata(&dest) {
        Ok(meta) => println!("installed {}  ({} bytes)", dest.display(), meta.len()),
        Err(_) => println!("installed {}", dest.display()),
    }
    if !dir_on_path(&bin_dir) {
        eprintln!(
            "    warning: {} is not on PATH — the installed zap won't be found",
            bin_dir.display()
        );
    }
    ExitCode::SUCCESS
}

/// Whether `dir` is one of the entries in the current `PATH`.
fn dir_on_path(dir: &Path) -> bool {
    std::env::var_os("PATH").is_some_and(|path| std::env::split_paths(&path).any(|p| p == dir))
}

/// Build a static release `zap` for each requested musl target (default: all of
/// [`MUSL_TARGETS`]) via `cargo zigbuild`.
fn build_musl(args: &[String]) -> ExitCode {
    if let Err(message) = check_prereqs() {
        eprintln!("error: {message}\n");
        print!("{USAGE}");
        return ExitCode::FAILURE;
    }
    let targets: Vec<&str> = if args.is_empty() {
        MUSL_TARGETS.to_vec()
    } else {
        args.iter().map(String::as_str).collect()
    };
    for target in &targets {
        println!("\n==> building zap for {target}");
        ensure_target(target);
        let built = Command::new("cargo")
            .args([
                "zigbuild",
                "--release",
                "--package",
                "zap",
                "--target",
                target,
            ])
            .status();
        match built {
            Ok(status) if status.success() => report_artifact(target),
            Ok(status) => {
                eprintln!("error: build failed for {target} ({status})");
                return ExitCode::FAILURE;
            }
            Err(error) => {
                eprintln!("error: failed to run `cargo zigbuild`: {error}");
                return ExitCode::FAILURE;
            }
        }
    }
    println!("\nbuild-musl complete: {} target(s)", targets.len());
    ExitCode::SUCCESS
}

/// Verify the `build-musl` toolchain is present, with an actionable message if not.
fn check_prereqs() -> Result<(), String> {
    if !tool_ok("zig", &["version"]) {
        return Err("`zig` not found on PATH — install Zig and add it to PATH".to_owned());
    }
    if !tool_ok("cargo", &["zigbuild", "--help"]) {
        return Err("`cargo-zigbuild` not found — run `cargo install cargo-zigbuild`".to_owned());
    }
    Ok(())
}

/// Best-effort `rustup target add <target>` so the musl std is present before the
/// cross-compile, self-provisioning what was a manual setup step. Idempotent (a
/// no-op once installed); a failure (no rustup, or the std is supplied another
/// way) is non-fatal — the following `cargo zigbuild` surfaces a missing-std
/// error if it actually matters. Output inherits so a first-time download is
/// visible.
fn ensure_target(target: &str) {
    let status = Command::new("rustup")
        .args(["target", "add", target])
        .status();
    if !matches!(status, Ok(s) if s.success()) {
        eprintln!(
            "    note: `rustup target add {target}` unavailable; assuming the std is present"
        );
    }
}

/// Whether `program args…` runs and exits successfully (output discarded).
fn tool_ok(program: &str, args: &[&str]) -> bool {
    Command::new(program)
        .args(args)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

/// Print the built binary's path, size, and (best-effort) linkage line.
fn report_artifact(target: &str) {
    let path = format!("target/{target}/release/zap");
    match std::fs::metadata(&path) {
        Ok(meta) => println!("    {path}  ({} bytes)", meta.len()),
        Err(error) => {
            eprintln!("    warning: built but artifact missing at {path}: {error}");
            return;
        }
    }
    if let Some(linkage) = describe_linkage(&path) {
        println!("    {linkage}");
    }
}

/// Best-effort one-line linkage description: `file(1)` if present (works for a
/// cross-arch binary too), else `ldd` (host-arch only — a static binary reports
/// "not a dynamic executable"). `None` when neither yields anything useful.
fn describe_linkage(path: &str) -> Option<String> {
    if let Ok(output) = Command::new("file").arg(path).output()
        && let Ok(text) = String::from_utf8(output.stdout)
        && let Some((_, description)) = text.split_once(':')
    {
        return Some(description.trim().to_owned());
    }
    if let Ok(output) = Command::new("ldd").arg(path).output() {
        // ldd writes the verdict to stdout for a static binary, stderr for a
        // cross-arch one it can't load; prefer whichever is non-empty.
        let text = if output.stdout.is_empty() {
            output.stderr
        } else {
            output.stdout
        };
        if let Ok(text) = String::from_utf8(text)
            && let Some(line) = text.lines().next()
            && !line.trim().is_empty()
        {
            return Some(line.trim().to_owned());
        }
    }
    None
}
