//! `--json --wetrun` keeps stdout a JSON-lines channel, driven through the built `zap`
//! binary (`CARGO_BIN_EXE_zap`): a wetrun that ends before any event still says why, on
//! stderr.
//!
//! Hermetic: a local target managing one directory in a temp dir, `ZAP_HOME` / `HOME`
//! in a temp dir. Requires `ZAP_FGRO` (config eval); skips cleanly without it.

mod common;
mod scratch;

use std::process::Command;

use common::fgro_available;

#[test]
fn a_refused_json_wetrun_reports_on_stderr_and_leaves_stdout_empty() {
    if !fgro_available() {
        eprintln!("skipping the refused --json wetrun test: ZAP_FGRO not set");
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
    let zap = |args: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_zap"))
            .args(args)
            .current_dir(proj.path())
            .env("ZAP_HOME", home.path().join(".zap"))
            .env("HOME", home.path())
            .output()
            .expect("failed to spawn the zap binary")
    };

    // Nothing was previewed on this host, so the wetrun refuses before any event.
    let refused = zap(&["apply", "--wetrun", "--json"]);
    let stderr = String::from_utf8_lossy(&refused.stderr);
    assert_eq!(refused.status.code(), Some(2), "{stderr}");
    assert!(
        refused.stdout.is_empty(),
        "{}",
        String::from_utf8_lossy(&refused.stdout)
    );
    assert!(stderr.contains("(wetrun, refused)"), "{stderr}");
    assert!(stderr.contains("REFUSED"), "{stderr}");
    assert!(stderr.contains("plan_hash: "), "{stderr}");
    assert!(!managed.exists());

    // The refusal was the preview: the next wetrun executes, streams its events, and
    // writes no text report anywhere.
    let ran = zap(&["apply", "--wetrun", "--json"]);
    let stdout = String::from_utf8_lossy(&ran.stdout);
    assert_eq!(ran.status.code(), Some(0), "{stdout}");
    assert!(stdout.lines().all(|line| line.starts_with('{')), "{stdout}");
    assert!(stdout.contains("\"run_started\""), "{stdout}");
    assert!(
        !String::from_utf8_lossy(&ran.stderr).contains("plan_hash"),
        "{}",
        String::from_utf8_lossy(&ran.stderr)
    );
    assert!(managed.is_dir());
}
