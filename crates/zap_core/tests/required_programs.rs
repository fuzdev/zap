//! The programs this crate's tests run. A test that needs one checks nothing where it
//! is absent, so `cargo test` runs on a machine without it — and this test fails there,
//! so a suite that skipped those tests can't pass unnoticed. Setting a program's
//! variable to `1` accepts its absence.
//!
//! `fgro` is not looked up on `PATH`: the tests that evaluate a config run the build
//! `ZAP_FGRO` names, as `zap` itself does, so that is what is checked.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::Path;
use std::process::{Command, Stdio};

/// A program, an argument it runs with, and the variable that accepts its absence.
const PROGRAMS: &[(&str, &str, &str)] = &[
    ("busybox", "true", "ZAP_TEST_ALLOW_NO_BUSYBOX"),
    ("git", "--version", "ZAP_TEST_ALLOW_NO_GIT"),
    ("setfacl", "--version", "ZAP_TEST_ALLOW_NO_SETFACL"),
    ("getfacl", "--version", "ZAP_TEST_ALLOW_NO_GETFACL"),
];

#[test]
fn the_programs_the_gated_tests_run_are_installed() {
    let missing: Vec<String> = PROGRAMS
        .iter()
        .filter(|(program, argument, allow)| {
            let found = Command::new(program)
                .arg(argument)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .is_ok();
            !found && std::env::var_os(allow).is_none_or(|value| value != "1")
        })
        .map(|(program, _, allow)| format!("`{program}` (or set {allow}=1)"))
        .collect();
    assert!(
        missing.is_empty(),
        "not on PATH, so the tests that run them checked nothing — install: {}",
        missing.join(", ")
    );
}

#[test]
fn the_fgro_the_eval_tests_run_is_named() {
    let named = std::env::var_os("ZAP_FGRO").filter(|path| Path::new(path).is_absolute());
    let runs = named.as_ref().is_some_and(|fgro| {
        Command::new(fgro)
            .arg("--version")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok_and(|status| status.success())
    });
    let allowed = std::env::var_os("ZAP_TEST_ALLOW_NO_FGRO").is_some_and(|value| value == "1");
    assert!(
        runs || allowed,
        "ZAP_FGRO doesn't name an fgro build by an absolute path, so the tests that evaluate \
         a config checked nothing — set it (or ZAP_TEST_ALLOW_NO_FGRO=1)"
    );
}
