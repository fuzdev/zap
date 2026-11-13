//! End-to-end test of `--env-file` through the built `zap` binary
//! (`CARGO_BIN_EXE_zap`): a file zap doesn't read is a startup error that names the
//! file, the line and the variable and no value, and a file other users can write — or
//! read, when it holds a secret — is warned about on stderr.
//!
//! The file is loaded before the config is evaluated, so no test here needs `fgro`:
//! each names a config that doesn't exist.

#![expect(
    clippy::expect_used,
    reason = "test helpers outside `#[test]` fns panic on a failed setup or check"
)]

use std::path::Path;
use std::process::{Command, Output};

/// Run `zap config validate` on a config that doesn't exist with `env_file`, under a
/// scratch home.
fn validate_with(scratch: &Path, env_file: &Path) -> Output {
    Command::new(env!("CARGO_BIN_EXE_zap"))
        .args(["config", "validate"])
        .arg(scratch.join("missing.zap.ts"))
        .arg("--env-file")
        .arg(env_file)
        .env("HOME", scratch)
        .env("ZAP_HOME", scratch.join("zap-home"))
        .output()
        .expect("failed to spawn the zap binary")
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

#[test]
fn a_line_zap_does_not_read_is_a_startup_error_naming_no_value() {
    let scratch = tempfile::tempdir().unwrap();
    let env_file = scratch.path().join("zap.env");
    for (contents, finding) in [
        (
            "DEPLOY_HOST=h.example\nAPI_TOKEN=tok-12345678 # prod\n",
            "line 2: `API_TOKEN` has an unquoted value holding a `#`",
        ),
        (
            "TLS_KEY=\"-----BEGIN PRIVATE KEY-----\ntok-12345678=\n\"\n",
            "line 1: `TLS_KEY` has a quoted value with no closing quote on its line",
        ),
        (
            "API_TOKEN=tok-12345678\nAPI_TOKEN=tok-12345678\n",
            "line 2: `API_TOKEN` is already assigned on line 1",
        ),
        (
            "tok-12345678\n",
            "line 1: not a blank line, a `#` comment, or a `NAME=VALUE` assignment",
        ),
    ] {
        std::fs::write(&env_file, contents).unwrap();
        let output = validate_with(scratch.path(), &env_file);
        let stderr = stderr(&output);
        assert_eq!(output.status.code(), Some(2), "{stderr}");
        assert!(
            stderr.starts_with(&format!(
                "error: failed to read env file {}: {finding}",
                env_file.display()
            )),
            "{stderr}"
        );
        assert!(!stderr.contains("tok-12345678"), "{stderr}");
        assert!(!stderr.contains("prod"), "{stderr}");
    }
}

#[cfg(unix)]
#[test]
fn an_env_file_other_users_can_reach_is_warned_about() {
    use std::os::unix::fs::PermissionsExt as _;

    let scratch = tempfile::tempdir().unwrap();
    let env_file = scratch.path().join("zap.env");
    for (contents, mode, found) in [
        (
            "API_TOKEN=tok-12345678\n",
            0o644,
            Some("holds secrets and is readable by everyone (mode 644)"),
        ),
        (
            "API_TOKEN=tok-12345678\n",
            0o664,
            Some("holds secrets and is readable by everyone and writable by its group (mode 664)"),
        ),
        (
            "DEPLOY_HOST=h.example\n",
            0o664,
            Some("is writable by its group (mode 664)"),
        ),
        ("API_TOKEN=tok-12345678\n", 0o600, None),
        ("DEPLOY_HOST=h.example\n", 0o644, None),
    ] {
        std::fs::write(&env_file, contents).unwrap();
        std::fs::set_permissions(&env_file, std::fs::Permissions::from_mode(mode)).unwrap();
        let output = validate_with(scratch.path(), &env_file);
        let stderr = stderr(&output);
        // The file loads; the config it was given for doesn't exist.
        assert_eq!(output.status.code(), Some(2), "{stderr}");
        match found {
            Some(found) => assert!(
                stderr.starts_with(&format!(
                    "warning: env file {} {found} — run `chmod 600` on it\nerror: ",
                    env_file.display()
                )),
                "{stderr}"
            ),
            None => assert!(stderr.starts_with("error: "), "{stderr}"),
        }
        assert!(!stderr.contains("tok-12345678"), "{stderr}");
    }
}
