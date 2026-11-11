//! A stream that can't take what zap writes, driven through the built `zap` binary
//! (`CARGO_BIN_EXE_zap`) with standard output or standard error on `/dev/full`: every
//! write fails with no space left, and zap exits with a code, never by aborting.
//!
//! An answer that never arrived exits 1, and says so on standard error when standard
//! error works; an error, or a usage error, keeps its own code. The apply cases are
//! gated on `ZAP_FGRO` (config eval) and run against a local target managing one
//! directory in a temp dir, `ZAP_HOME` / `HOME` in a temp dir.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;
mod scratch;

use std::path::Path;
use std::process::{Command, Output, Stdio};

use common::fgro_available;

/// Which of the binary's streams goes to `/dev/full`.
#[derive(Clone, Copy)]
enum Full {
    Stdout,
    Stderr,
    Both,
}

fn dev_full() -> Stdio {
    std::fs::OpenOptions::new()
        .write(true)
        .open("/dev/full")
        .expect("/dev/full")
        .into()
}

/// `zap args` run in `dir`, with `home` its `ZAP_HOME` / `HOME`, and `full` on
/// `/dev/full`.
fn zap_in(dir: &Path, home: &Path, args: &[&str], full: Full) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_zap"));
    command
        .args(args)
        .current_dir(dir)
        .env("ZAP_HOME", home.join(".zap"))
        .env("HOME", home)
        .stdin(Stdio::null());
    match full {
        Full::Stdout => command.stdout(dev_full()),
        Full::Stderr => command.stderr(dev_full()),
        Full::Both => command.stdout(dev_full()).stderr(dev_full()),
    };
    command.output().expect("failed to spawn the zap binary")
}

/// `zap args` in a fresh temp dir, which is also its home.
fn zap(args: &[&str], full: Full) -> Output {
    let home = tempfile::tempdir().unwrap();
    zap_in(home.path(), home.path(), args, full)
}

const LOST: &str = "error: the report could not be written: No space left on device";

/// An answer the binary writes itself — the version, the help, the overview — exits 1
/// when it can't be written, and says why on standard error.
#[test]
fn an_answer_that_could_not_be_written_exits_1() {
    for args in [&["version"][..], &["--help"], &[]] {
        let output = zap(args, Full::Stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert_eq!(output.status.code(), Some(1), "{args:?}: {stderr}");
        assert!(stderr.starts_with(LOST), "{args:?}: {stderr}");
    }
    // Nothing can be said when standard error is full too: the code still says it.
    assert_eq!(zap(&["version"], Full::Both).status.code(), Some(1));
}

/// A usage error, and an engine error, on a standard error that can't take them keep
/// their own codes.
#[test]
fn an_error_that_could_not_be_written_keeps_its_code() {
    let usage = zap(&["plan", "--nope"], Full::Stderr);
    assert_eq!(usage.status.code(), Some(2));
    assert!(usage.stdout.is_empty());
    // A dry run rejects `--expect-plan` before any config is read: an engine error.
    let error = zap(
        &["deploy", "missing.ts", "--expect-plan", "abc123"],
        Full::Stderr,
    );
    assert_eq!(error.status.code(), Some(2));
    assert!(error.stdout.is_empty());
}

/// An `apply` wetrun that ran its changes is described by its own code whether or not
/// its report arrived; one with nothing to do only answered, so its lost report fails
/// it.
#[test]
fn a_lost_apply_report_fails_only_a_wetrun_that_changed_nothing() {
    if !fgro_available() {
        eprintln!("skipping the lost apply report test: ZAP_FGRO not set");
        return;
    }
    let proj = scratch::tempdir().unwrap();
    let home = scratch::tempdir().unwrap();
    let managed = proj.path().join("managed");
    scratch::write_config(
        proj.path().join("zap.ts"),
        format!(
            "export default (zap) => {{\n    zap.target({{local: true}});\n    \
             zap.directory({{id: 'managed', path: {:?}}});\n}};\n",
            managed.to_string_lossy()
        ),
    )
    .unwrap();
    let run = |args: &[&str], full| zap_in(proj.path(), home.path(), args, full);

    let preview = run(&["apply"], Full::Stderr);
    assert_eq!(preview.status.code(), Some(2));
    let ran = run(&["apply", "--wetrun"], Full::Stdout);
    let stderr = String::from_utf8_lossy(&ran.stderr);
    assert_eq!(ran.status.code(), Some(0), "{stderr}");
    assert!(stderr.contains(LOST), "{stderr}");
    assert!(managed.is_dir());

    let converged = run(&["apply", "--wetrun"], Full::Stdout);
    let stderr = String::from_utf8_lossy(&converged.stderr);
    assert_eq!(converged.status.code(), Some(1), "{stderr}");
    assert!(stderr.contains(LOST), "{stderr}");
}

/// A preview whose report couldn't be written is withdrawn: the next wetrun without
/// `--expect-plan` has nothing to bind to, refuses, and runs nothing. A preview whose
/// report was written and thrown away (`>/dev/null`) is no lost report, and binds.
#[test]
fn a_preview_whose_report_never_arrived_binds_no_wetrun() {
    if !fgro_available() {
        eprintln!("skipping the withdrawn preview test: ZAP_FGRO not set");
        return;
    }
    let proj = scratch::tempdir().unwrap();
    let home = scratch::tempdir().unwrap();
    let managed = proj.path().join("managed");
    scratch::write_config(
        proj.path().join("zap.ts"),
        format!(
            "export default (zap) => {{\n    zap.target({{local: true}});\n    \
             zap.directory({{id: 'managed', path: {:?}}});\n}};\n",
            managed.to_string_lossy()
        ),
    )
    .unwrap();
    let run = |args: &[&str], full| zap_in(proj.path(), home.path(), args, full);
    let run_quietly = |args: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_zap"))
            .args(args)
            .current_dir(proj.path())
            .env("ZAP_HOME", home.path().join(".zap"))
            .env("HOME", home.path())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .output()
            .expect("failed to spawn the zap binary")
    };

    for (preview, code) in [(&["apply"][..], 2), (&["plan"][..], 1)] {
        let lost = run(preview, Full::Stdout);
        let stderr = String::from_utf8_lossy(&lost.stderr);
        assert_eq!(lost.status.code(), Some(code), "{preview:?}: {stderr}");
        assert!(stderr.contains(LOST), "{preview:?}: {stderr}");
        assert!(
            stderr.contains("its preview was withdrawn"),
            "{preview:?}: {stderr}"
        );

        let refused = run(&["apply", "--wetrun"], Full::Stderr);
        let stdout = String::from_utf8_lossy(&refused.stdout);
        assert_eq!(refused.status.code(), Some(2), "{preview:?}: {stdout}");
        assert!(stdout.contains("REFUSED"), "{preview:?}: {stdout}");
        assert!(!managed.exists(), "{preview:?}");
    }

    // written whole, then discarded: the preview stands, and the wetrun binds to it
    assert_eq!(run_quietly(&["apply"]).status.code(), Some(2));
    let ran = run(&["apply", "--wetrun"], Full::Stderr);
    assert_eq!(
        ran.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&ran.stdout)
    );
    assert!(managed.is_dir());
}
