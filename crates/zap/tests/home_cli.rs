//! End-to-end test of where the built `zap` binary (`CARGO_BIN_EXE_zap`) keeps its
//! state: `ZAP_HOME` and `HOME` are absolute or refused, an empty `ZAP_HOME` is an unset
//! one, nothing lands under the current directory, a state directory that isn't zap's
//! own is refused before the config is read, and a config that has its own lock's name
//! is refused too.
//!
//! Every refusal here comes before the config is evaluated, so those cases need no
//! `fgro`; the one that evaluates a config skips cleanly without `ZAP_FGRO`.

#![expect(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test helpers outside `#[test]` fns panic on a failed setup or check"
)]

mod common;
mod scratch;

use std::path::Path;
use std::process::{Command, Output};

use common::fgro_available;

/// Run `zap config validate <config>` in `cwd` with exactly this `HOME` / `ZAP_HOME`
/// (`None`: unset).
fn validate(cwd: &Path, config: &str, home: Option<&str>, zap_home: Option<&str>) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_zap"));
    command
        .args(["config", "validate", config])
        .current_dir(cwd)
        .env_remove("HOME")
        .env_remove("ZAP_HOME");
    if let Some(home) = home {
        command.env("HOME", home);
    }
    if let Some(zap_home) = zap_home {
        command.env("ZAP_HOME", zap_home);
    }
    command.output().expect("failed to spawn the zap binary")
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

/// The names in `dir`, sorted.
fn names(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

/// Write a config into `dir`, pinned to `0755`: zap refuses one in a directory every
/// user can write, which `dir` is when made under `umask 000`.
fn write_config(dir: &Path) {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o755)).unwrap();
    scratch::write_config(
        dir.join("zap.ts"),
        "export default (zap) => {\n    zap.target({local: true});\n};\n",
    )
    .unwrap();
}

#[test]
fn a_relative_home_is_refused_by_name_and_nothing_lands_in_the_cwd() {
    let scratch = scratch::tempdir().unwrap();
    let cwd = scratch.path().join("cwd");
    std::fs::create_dir(&cwd).unwrap();
    write_config(&cwd);
    let written = names(&cwd);
    let home = scratch.path().join("home");
    let home = home.to_str().unwrap();
    for (given_home, zap_home, named) in [
        (Some(home), Some("rel-zap-home"), "ZAP_HOME"),
        (Some(home), Some("./rel-zap-home"), "ZAP_HOME"),
        (Some(home), Some("."), "ZAP_HOME"),
        (Some("rel-home"), None, "HOME"),
        (Some("rel-home"), Some(""), "HOME"),
    ] {
        let output = validate(&cwd, "zap.ts", given_home, zap_home);
        let stderr = stderr(&output);
        assert_eq!(output.status.code(), Some(2), "{stderr}");
        assert_eq!(
            stderr,
            format!(
                "error: `{named}` is set to a relative path, which would name a directory \
                 under wherever zap is run — set it to an absolute path\n"
            )
        );
        assert_eq!(names(&cwd), written, "state was kept under the cwd");
    }
    assert!(!Path::new(home).exists());
}

#[test]
fn an_empty_zap_home_is_an_unset_one() {
    if !fgro_available() {
        eprintln!("skipping an_empty_zap_home_is_an_unset_one: ZAP_FGRO not set");
        return;
    }
    let scratch = scratch::tempdir().unwrap();
    let cwd = scratch.path().join("cwd");
    std::fs::create_dir(&cwd).unwrap();
    write_config(&cwd);
    let home = scratch.path().join("home");
    std::fs::create_dir(&home).unwrap();

    // Empty: the state goes under `$HOME/.zap`, never the current directory.
    let output = validate(&cwd, "zap.ts", home.to_str(), Some(""));
    assert!(output.status.success(), "{}", stderr(&output));
    assert_eq!(names(&cwd), ["zap.lock", "zap.ts"]);
    assert_eq!(names(&home), [".zap"]);
    assert_eq!(names(&home.join(".zap")), ["cache"]);

    // Neither set, or `HOME` empty too: no state directory, and still nothing in the
    // current one.
    std::fs::remove_dir_all(home.join(".zap")).unwrap();
    for (given_home, zap_home) in [(None, None), (Some(""), Some("")), (Some(""), None)] {
        let output = validate(&cwd, "zap.ts", given_home, zap_home);
        assert!(output.status.success(), "{}", stderr(&output));
        assert_eq!(names(&cwd), ["zap.lock", "zap.ts"]);
        assert_eq!(names(&home), [""; 0]);
    }
}

#[cfg(unix)]
#[test]
fn a_state_directory_that_is_not_zaps_own_is_refused_before_the_config_is_read() {
    use std::os::unix::fs::PermissionsExt as _;

    let scratch = scratch::tempdir().unwrap();
    let cwd = scratch.path().join("cwd");
    std::fs::create_dir(&cwd).unwrap();
    // No config: a refusal that came after the read would be a missing-config error.
    let elsewhere = scratch.path().join("elsewhere");
    std::fs::create_dir(&elsewhere).unwrap();
    std::fs::set_permissions(&elsewhere, std::fs::Permissions::from_mode(0o755)).unwrap();

    for linked in ["", "cache"] {
        let zap_home = scratch.path().join(format!("zap-home-{linked}"));
        let at = if linked.is_empty() {
            zap_home.clone()
        } else {
            std::fs::create_dir(&zap_home).unwrap();
            zap_home.join(linked)
        };
        std::os::unix::fs::symlink(&elsewhere, &at).unwrap();
        let output = validate(&cwd, "zap.ts", None, zap_home.to_str());
        let stderr = stderr(&output);
        assert_eq!(output.status.code(), Some(2), "{stderr}");
        assert_eq!(
            stderr,
            format!(
                "error: zap keeps its state in directories of its own, and {} is a symbolic \
                 link — zap doesn't follow a link there: replace the link with a directory, \
                 or — when the link is zap's home itself — set `ZAP_HOME` to the directory \
                 it points to\n",
                at.display()
            )
        );
    }
    assert_eq!(names(&elsewhere), [""; 0]);
    assert_eq!(
        std::fs::metadata(&elsewhere).unwrap().permissions().mode() & 0o777,
        0o755
    );
}

#[test]
fn a_config_with_its_own_locks_name_is_refused() {
    let scratch = scratch::tempdir().unwrap();
    let config = "export default (zap) => {\n    zap.target({local: true});\n};\n";
    std::fs::write(scratch.path().join("prod.lock"), config).unwrap();
    let zap_home = scratch.path().join("zap-home");
    let output = validate(scratch.path(), "prod.lock", None, zap_home.to_str());
    let stderr = stderr(&output);
    assert_eq!(output.status.code(), Some(2), "{stderr}");
    assert!(
        stderr.starts_with("error: the config `prod.lock` has the name its own"),
        "{stderr}"
    );
    assert_eq!(
        std::fs::read_to_string(scratch.path().join("prod.lock")).unwrap(),
        config
    );
}
