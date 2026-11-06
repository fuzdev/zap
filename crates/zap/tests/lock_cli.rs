//! End-to-end check of `zap lock` on a config named by its file name alone, driven
//! through the built `zap` binary (`CARGO_BIN_EXE_zap`) from a temp working directory.
//!
//! The default config path is the bare `zap.ts`, so its lock is the bare `zap.lock`:
//! a path with no directory component, written into the working directory. Hermetic:
//! no tracked resource (so no fetch), a local target that is never contacted, and
//! `ZAP_HOME` / `HOME` in a temp dir. Requires `ZAP_FGRO` (config eval), which the
//! binary reads too; skips cleanly without it.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;
mod scratch;

use std::process::Command;

use common::fgro_available;

#[test]
fn lock_writes_beside_a_config_named_by_its_file_name() {
    if !fgro_available() {
        eprintln!("skipping lock_writes_beside_a_config_named_by_its_file_name: ZAP_FGRO not set");
        return;
    }
    let proj = scratch::tempdir().unwrap();
    let home = scratch::tempdir().unwrap();
    // No tracked resource: `zap lock` writes an empty lock and fetches nothing.
    scratch::write_config(
        proj.path().join("zap.ts"),
        "export default (zap) => {\n    zap.target({local: true});\n};\n",
    )
    .unwrap();

    for args in [&["lock"][..], &["lock", "zap.ts"][..]] {
        let output = Command::new(env!("CARGO_BIN_EXE_zap"))
            .args(args)
            .current_dir(proj.path())
            // zap's state and anything a child keeps under the home go to scratch.
            .env("ZAP_HOME", home.path().join(".zap"))
            .env("HOME", home.path())
            .output()
            .expect("failed to spawn the zap binary");
        assert!(
            output.status.success(),
            "zap {args:?} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let lock = std::fs::read_to_string(proj.path().join("zap.lock")).unwrap();
        assert!(lock.contains("\"entries\": {}"), "{lock}");
        assert!(
            lock.contains("\"toolchain\": {\n    \"fgro_blake3\": \""),
            "{lock}"
        );
        std::fs::remove_file(proj.path().join("zap.lock")).unwrap();
        let mut names: Vec<String> = std::fs::read_dir(proj.path())
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        assert_eq!(
            names,
            ["package.json", "zap.ts"],
            "no temp file left behind"
        );
    }
}
