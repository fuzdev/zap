//! `zap deploy`, driven through the built `zap` binary (`CARGO_BIN_EXE_zap`).
//!
//! `--expect-plan` parses and reaches the command core: hermetic and evaluation-free, since a
//! dry run rejects it before the config is read, so the config path names no file and
//! nothing is evaluated or contacted.
//!
//! A wetrun from a dirty checkout without `--force` is refused before the target is
//! contacted: gated on `ZAP_FGRO` (config eval) and `git`, against an unreachable
//! `.invalid` host, so a refusal that came after the connection would read as a
//! connectivity error instead.

#![expect(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test helpers outside `#[test]` fns panic on a failed setup or check"
)]

mod common;
mod scratch;

use std::path::Path;
use std::process::Command;

use common::fgro_available;

fn zap(args: &[&str]) -> std::process::Output {
    let home = tempfile::tempdir().unwrap();
    Command::new(env!("CARGO_BIN_EXE_zap"))
        .args(args)
        .current_dir(home.path())
        .env("ZAP_HOME", home.path().join(".zap"))
        .env("HOME", home.path())
        .output()
        .expect("failed to spawn the zap binary")
}

#[test]
fn deploy_rejects_expect_plan_on_a_dry_run() {
    let output = zap(&["deploy", "missing.ts", "--expect-plan", "abc123"]);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(2), "{stderr}");
    // The core's refusal, not a usage error (also exit 2) and not a missing config.
    assert!(
        stderr.contains("--expect-plan binds a wetrun to a reviewed plan"),
        "{stderr}"
    );
    assert!(output.stdout.is_empty());
}

/// Is `git` available? The dirty-checkout test requires it and checks nothing
/// without it; `required_programs.rs` is the test that fails there.
fn git_available() -> bool {
    Command::new("git")
        .arg("--version")
        .output()
        .is_ok_and(|o| o.status.success())
}

/// `git` in `dir`, reading no configuration of the developer's own.
fn git(dir: &Path, args: &[&str]) {
    let output = Command::new("git")
        .args([
            "-c",
            "user.name=zap",
            "-c",
            "user.email=zap@example.invalid",
        ])
        .args(args)
        .current_dir(dir)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .output()
        .unwrap();
    assert!(output.status.success(), "git {args:?}: {output:?}");
}

#[test]
fn a_dirty_wetrun_without_force_is_refused_before_the_target() {
    if !fgro_available() || !git_available() {
        eprintln!("skipping a_dirty_wetrun_without_force_is_refused_before_the_target");
        return;
    }
    let proj = scratch::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();
    scratch::write_config(
        proj.path().join("zap.ts"),
        "export default (zap) => {
\tzap.target({host: 'zap-test.invalid', user: 'deploy'});
\tzap.deploy({artifacts: ['build/'], path: '/srv/app'});
};
",
    )
    .unwrap();
    git(proj.path(), &["init", "-q"]);
    git(proj.path(), &["add", "zap.ts"]);
    git(proj.path(), &["commit", "-q", "-m", "init"]);
    std::fs::write(proj.path().join("uncommitted.txt"), "x").unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_zap"))
        .args(["deploy", "--wetrun", "zap.ts"])
        .current_dir(proj.path())
        .env("HOME", home.path())
        .env("ZAP_HOME", home.path().join(".zap"))
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env_remove("XDG_CACHE_HOME")
        .output()
        .expect("failed to spawn the zap binary");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(2), "{stderr}");
    assert!(
        stderr.contains("uncommitted changes or untracked files"),
        "{stderr}"
    );
    assert!(stderr.contains("--force"), "{stderr}");
    assert!(stderr.contains("<hash>-dirty-<id>"), "{stderr}");
    assert!(stderr.contains("nothing ran"), "{stderr}");
    assert!(output.stdout.is_empty());
}
