//! The toolchain pin end to end: `zap lock` records the blake3 of the `fgro` it
//! evaluates with, every other command evaluates only through a binary that hashes to
//! the lock's pin, and `zap lock --check` reports a pin the binary moved off.
//!
//! Requires `ZAP_FGRO` (config eval); checks nothing without it, where
//! `required_programs.rs` fails.

#![expect(
    clippy::unwrap_used,
    reason = "test helpers outside `#[test]` fns panic on a failed setup or check"
)]

mod common;
mod scratch;

use std::path::{Path, PathBuf};

use common::{fgro, fgro_available, toolchain};
use zap_core::commands::lock::{render_lock, render_lock_check, run_lock_check_in, run_lock_in};
use zap_core::commands::update::run_update_in;
use zap_core::commands::{run_config_validate_in, status::run_status_in};
use zap_core::error::Error;
use zap_core::lock::{lock_path_for, read_zap_lock};
use zap_types::lock::LOCK_VERSION;
use zap_types::scalar::ContentHash;

const CONFIG: &str = "export default (zap) => {\n    zap.target({local: true});\n};\n";

/// A scratch project with a config in it and no lock.
fn project() -> (tempfile::TempDir, PathBuf) {
    let dir = scratch::tempdir().unwrap();
    let path = dir.path().join("zap.ts");
    scratch::write_config(&path, CONFIG).unwrap();
    std::fs::remove_file(lock_path_for(&path)).unwrap();
    (dir, path)
}

/// Write a lock beside `config` pinning `pin`.
fn pin_lock(config: &Path, pin: &str) {
    std::fs::write(
        lock_path_for(config),
        format!(r#"{{"version": {LOCK_VERSION}, "toolchain": {{"fgro_blake3": "{pin}"}}, "entries": {{}}}}"#),
    )
    .unwrap();
}

/// No `fgro` named refuses before the lock is read, and a missing pin — no lock, or a
/// lock with none — refuses naming the lock, before anything is evaluated.
#[tokio::test]
async fn an_eval_needs_an_fgro_and_a_pin() {
    if !fgro_available() {
        eprintln!("skipping an_eval_needs_an_fgro_and_a_pin: ZAP_FGRO not set");
        return;
    }
    let home = scratch::tempdir().unwrap();
    let (_dir, config) = project();
    let error = run_config_validate_in(Some(home.path()), None, &config)
        .await
        .unwrap_err();
    assert!(matches!(error, Error::FgroUnset), "{error:?}");
    assert_eq!(error.exit_code(), 2);

    let lock = lock_path_for(&config).display().to_string();
    for unpinned in [None, Some(r#"{"version": 1, "entries": {}}"#)] {
        if let Some(text) = unpinned {
            std::fs::write(lock_path_for(&config), text).unwrap();
        }
        for error in [
            run_config_validate_in(Some(home.path()), fgro(), &config)
                .await
                .unwrap_err(),
            run_status_in(Some(home.path()), fgro(), &config)
                .await
                .unwrap_err(),
            run_lock_check_in(Some(home.path()), fgro(), &config)
                .await
                .unwrap_err(),
            run_update_in(Some(home.path()), fgro(), &config, &[])
                .await
                .unwrap_err(),
        ] {
            let Error::ToolchainUnpinned { lock: named } = &error else {
                panic!("expected an unpinned toolchain: {error:?}");
            };
            assert_eq!(named, &lock);
            assert!(
                error.render().contains("Run `zap lock`"),
                "{}",
                error.render()
            );
        }
    }
}

/// `zap lock` pins the binary it evaluated with, through the pin cache under `~/.zap`,
/// whatever the lock held — nothing, or another build's pin — and every command then
/// evaluates.
#[tokio::test]
async fn zap_lock_pins_the_fgro_it_evaluated_with() {
    if !fgro_available() {
        eprintln!("skipping zap_lock_pins_the_fgro_it_evaluated_with: ZAP_FGRO not set");
        return;
    }
    let home = scratch::tempdir().unwrap();
    let (_dir, config) = project();
    let expected = toolchain().unwrap().fgro_blake3;
    for before in [None, Some("a".repeat(64))] {
        if let Some(pin) = &before {
            pin_lock(&config, pin);
        }
        let report = run_lock_in(Some(home.path()), fgro(), &config)
            .await
            .unwrap();
        assert_eq!(report.toolchain, expected);
        // a moved pin is reported with what it was; a first pin has none to report
        assert_eq!(
            report.previous_toolchain.as_ref().map(ContentHash::as_str),
            before.as_deref()
        );
        let rendered = render_lock(&report);
        match &before {
            Some(was) => assert!(
                rendered.starts_with(&format!("pinned fgro {} (was {was})\n", expected.as_str())),
                "{rendered}"
            ),
            None => assert!(
                rendered.starts_with(&format!("pinned fgro {}\n", expected.as_str())),
                "{rendered}"
            ),
        }
        let lock = read_zap_lock(&lock_path_for(&config)).unwrap().unwrap();
        assert_eq!(lock.toolchain.unwrap().fgro_blake3, expected);
        assert_eq!(
            run_config_validate_in(Some(home.path()), fgro(), &config)
                .await
                .unwrap(),
            0
        );
    }
    assert!(home.path().join("cache/fgro_pins").is_dir());
}

/// A binary that doesn't hash to the lock's pin refuses every eval but `zap lock`'s,
/// with the fix in the hint; `zap lock --check` reports the stale pin (exit 1) without
/// evaluating the config, and `zap update` doesn't re-pin it.
#[tokio::test]
async fn a_stale_pin_refuses_and_lock_check_reports_it() {
    if !fgro_available() {
        eprintln!("skipping a_stale_pin_refuses_and_lock_check_reports_it: ZAP_FGRO not set");
        return;
    }
    let home = scratch::tempdir().unwrap();
    let (_dir, config) = project();
    let stale = ContentHash::new("b".repeat(64)).unwrap();
    pin_lock(&config, stale.as_str());

    let error = run_config_validate_in(Some(home.path()), fgro(), &config)
        .await
        .unwrap_err();
    assert!(matches!(error, Error::FgroPinMismatch { .. }), "{error:?}");
    assert_eq!(error.exit_code(), 2);
    let rendered = error.render();
    assert!(rendered.contains("run `zap lock` to pin it"), "{rendered}");

    let error = run_update_in(Some(home.path()), fgro(), &config, &[])
        .await
        .unwrap_err();
    assert!(matches!(error, Error::FgroPinMismatch { .. }), "{error:?}");
    assert_eq!(
        read_zap_lock(&lock_path_for(&config))
            .unwrap()
            .unwrap()
            .toolchain
            .unwrap()
            .fgro_blake3,
        stale
    );

    // The config is broken: an eval would fail. The check reports the pin and stops.
    scratch::write_config(&config, "export default () => { throw new Error('x'); };\n").unwrap();
    let check = run_lock_check_in(Some(home.path()), fgro(), &config)
        .await
        .unwrap();
    assert_eq!(check.exit_code(), 1);
    let stale_toolchain = check.stale_toolchain.as_ref().unwrap();
    assert_eq!(stale_toolchain.pinned, stale);
    assert_eq!(stale_toolchain.current, toolchain().unwrap().fgro_blake3);
    let rendered = render_lock_check(&check);
    assert!(
        rendered.starts_with("error: the toolchain pin is stale — fgro ")
            && rendered.contains(&format!("the lock pins {}", stale.as_str()))
            && rendered.contains("its entries were not checked"),
        "{rendered}"
    );
    assert_eq!(rendered.lines().count(), 1, "{rendered}");
}
