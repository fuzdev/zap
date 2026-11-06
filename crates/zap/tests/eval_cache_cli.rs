//! End-to-end smoke test for the L0 eval-cache CLI bust surface, driven through the
//! built `zap` binary (`CARGO_BIN_EXE_zap`).
//!
//! Covers the wiring the library/integration tests can't reach: that
//! `ZAP_EVAL_CACHE=skip` actually serves a spawn-free hit end to end, that `--no-cache`
//! forces a fresh eval over that posture, and that an unknown flag is a usage error
//! (exit 2). Requires `ZAP_FGRO` (config eval); checks nothing without it, where
//! `required_programs.rs` fails.
//! `ZAP_EVAL_CACHE_LOG=1` makes the L0 verdict observable on stderr.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;
mod scratch;

use std::path::Path;
use std::process::{Command, Output};

use common::fgro_available;

/// Run `zap plan <config>` with `home` as its `HOME`, its working directory and the
/// parent of its `ZAP_HOME` — nothing of the developer's own — the L0 log on, and the
/// given extra args / `ZAP_EVAL_CACHE` value.
fn run_plan(home: &Path, config: &Path, eval_cache: &str, extra: &[&str]) -> Output {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_zap"));
    cmd.arg("plan")
        .arg(config)
        .args(extra)
        .current_dir(home)
        .env("HOME", home)
        .env("ZAP_HOME", home.join(".zap"))
        .env("ZAP_EVAL_CACHE", eval_cache)
        .env("ZAP_EVAL_CACHE_LOG", "1");
    cmd.output().expect("failed to spawn the zap binary")
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

#[test]
fn no_cache_busts_the_l0_skip_hit() {
    if !fgro_available() {
        eprintln!("skipping no_cache_busts_the_l0_skip_hit: ZAP_FGRO not set");
        return;
    }
    let proj = scratch::tempdir().unwrap();
    let home = scratch::tempdir().unwrap();
    let config = proj.path().join("zap.ts");
    // A converged local directory (the temp project dir exists) — plan succeeds and the
    // run exercises the full eval → detect → diff path the cache fronts.
    scratch::write_config(
        &config,
        format!(
            r"
export default (zap) => {{
    zap.target({{local: true}});
    zap.directory({{id: 'proj', path: {path:?}}});
}};
",
            path = proj.path().to_string_lossy()
        ),
    )
    .unwrap();

    // Run 1 (skip, cold): a miss — eval'd and persisted; no skipped-eval line yet.
    let cold = run_plan(home.path(), &config, "skip", &[]);
    assert!(cold.status.success(), "cold plan failed: {}", stderr(&cold));
    assert!(
        !stderr(&cold).contains("skipped eval"),
        "a cold run can't skip: {}",
        stderr(&cold)
    );

    // Run 2 (skip, warm): the manifest still holds → a genuine spawn-free hit.
    let warm = run_plan(home.path(), &config, "skip", &[]);
    assert!(warm.status.success(), "warm plan failed: {}", stderr(&warm));
    assert!(
        stderr(&warm).contains("HIT (skipped eval)"),
        "an unchanged warm skip run should serve the cache: {}",
        stderr(&warm)
    );

    // Run 3 (skip + --no-cache): the bust wins over the Skip posture — a fresh eval,
    // never the spawn-free hit, even though the manifest would have validated.
    let busted = run_plan(home.path(), &config, "skip", &["--no-cache"]);
    assert!(
        busted.status.success(),
        "--no-cache plan failed: {}",
        stderr(&busted)
    );
    assert!(
        !stderr(&busted).contains("skipped eval"),
        "--no-cache must force a fresh eval: {}",
        stderr(&busted)
    );
}

/// Neither a `deno.lock` nor a `deno.json` is an input of the evaluation — `fgro` reads
/// neither — so an edit to either leaves a hit a hit, one that doesn't parse included.
#[test]
fn a_lockfile_or_deno_json_edit_keeps_the_hit() {
    if !fgro_available() {
        eprintln!("skipping a_lockfile_or_deno_json_edit_keeps_the_hit: ZAP_FGRO not set");
        return;
    }
    let proj = scratch::tempdir().unwrap();
    let home = scratch::tempdir().unwrap();
    let config = proj.path().join("zap.ts");
    scratch::write_config(
        &config,
        "export default (zap) => { zap.target({local: true}); };",
    )
    .unwrap();
    // In the working directory, where Deno would look for both.
    let deno_json = home.path().join("deno.json");
    let deno_lock = home.path().join("deno.lock");
    std::fs::write(&deno_json, "{}").unwrap();
    std::fs::write(&deno_lock, r#"{"version": "5"}"#).unwrap();

    let cold = run_plan(home.path(), &config, "skip", &[]);
    assert!(cold.status.success(), "cold plan failed: {}", stderr(&cold));
    let warm = run_plan(home.path(), &config, "skip", &[]);
    assert!(
        stderr(&warm).contains("HIT (skipped eval)"),
        "an unchanged warm run should serve the cache: {}",
        stderr(&warm)
    );

    // Not even a lockfile that doesn't parse: it is never read.
    std::fs::write(&deno_lock, "not a lockfile").unwrap();
    let relocked = run_plan(home.path(), &config, "skip", &[]);
    assert!(
        relocked.status.success(),
        "plan failed: {}",
        stderr(&relocked)
    );
    assert!(
        stderr(&relocked).contains("HIT (skipped eval)"),
        "a lockfile edit is no input: {}",
        stderr(&relocked)
    );

    for edit in [r#"{"imports": {"x/": "./elsewhere/"}}"#, "not a config"] {
        std::fs::write(&deno_json, edit).unwrap();
        let reconfigured = run_plan(home.path(), &config, "skip", &[]);
        assert!(
            reconfigured.status.success(),
            "plan failed: {}",
            stderr(&reconfigured)
        );
        assert!(
            stderr(&reconfigured).contains("HIT (skipped eval)"),
            "a `deno.json` edit is no input: {}",
            stderr(&reconfigured)
        );
    }
    // And the evaluation itself doesn't read it: a fresh eval succeeds beside the one
    // doesn't parse.
    let fresh = run_plan(home.path(), &config, "skip", &["--no-cache"]);
    assert!(fresh.status.success(), "plan failed: {}", stderr(&fresh));
    assert!(
        !stderr(&fresh).contains("skipped eval"),
        "{}",
        stderr(&fresh)
    );
}

#[test]
fn an_unknown_flag_is_a_usage_error() {
    // No fgro needed — argument parsing fails before anything spawns.
    let proj = scratch::tempdir().unwrap();
    let home = scratch::tempdir().unwrap();
    let config = proj.path().join("zap.ts");
    scratch::write_config(
        &config,
        "export default (zap) => { zap.target({local: true}); };",
    )
    .unwrap();

    let output = run_plan(home.path(), &config, "shadow", &["--no-such-flag"]);
    assert_eq!(
        output.status.code(),
        Some(2),
        "an unknown flag is a usage error (exit 2)"
    );
    assert!(
        stderr(&output).contains("--no-such-flag"),
        "stderr should name the unknown flag: {}",
        stderr(&output)
    );
}
