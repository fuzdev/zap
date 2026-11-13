//! The programs this crate's tests run. A test that needs one checks nothing where it
//! is absent, so `cargo test` runs on a machine without it — and this test fails there,
//! so a suite that skipped those tests can't pass unnoticed. Setting a program's
//! variable to `1` accepts its absence.

use std::process::{Command, Stdio};

/// A program, an argument it runs with, and the variable that accepts its absence.
const PROGRAMS: &[(&str, &str, &str)] = &[
    ("openssl", "version", "ZAP_TEST_ALLOW_NO_OPENSSL"),
    ("curl", "--version", "ZAP_TEST_ALLOW_NO_CURL"),
    ("busybox", "true", "ZAP_TEST_ALLOW_NO_BUSYBOX"),
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
