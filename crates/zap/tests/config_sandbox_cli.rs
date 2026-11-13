//! End-to-end tests of the evaluation's walls, driven through the built `zap` binary
//! (`CARGO_BIN_EXE_zap`): a config sees no `Deno`, whatever a `deno.json` in the
//! working directory enables; a package planted in a `node_modules` above a project
//! that installs none is never found, so it never runs; and the trust root's refusals —
//! a world-writable config or directory, a walk stopped below a world-writable
//! directory — exit 2 with the advice for their cause.
//!
//! Requires `ZAP_FGRO` (config eval), which the binary reads too; checks nothing
//! without it, where `required_programs.rs` fails.

#![expect(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test helpers outside `#[test]` fns panic on a failed setup or check"
)]

mod common;
mod scratch;

use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Command, Output};
use std::time::{Duration, Instant};

use common::fgro_available;

/// Run `zap config validate <config>` in `cwd`, with `home` as its `HOME` and the parent
/// of its `ZAP_HOME` — nothing of the developer's own.
fn validate(cwd: &Path, home: &Path, config: &Path) -> Output {
    Command::new(env!("CARGO_BIN_EXE_zap"))
        .args(["config", "validate"])
        .arg(config)
        .current_dir(cwd)
        .env("HOME", home)
        .env("ZAP_HOME", home.join(".zap"))
        .output()
        .expect("failed to spawn the zap binary")
}

/// Every file under `dir`, at any depth.
fn files_under(dir: &Path) -> Vec<String> {
    let mut found = Vec::new();
    let mut pending = vec![dir.to_path_buf()];
    while let Some(next) = pending.pop() {
        let Ok(entries) = std::fs::read_dir(&next) else {
            continue;
        };
        for entry in entries {
            let path = entry.unwrap().path();
            if path.is_dir() {
                pending.push(path);
            } else {
                found.push(path.to_string_lossy().into_owned());
            }
        }
    }
    found
}

/// A config that counts its own evaluations in `Deno.openKv()` fails each time, from a
/// directory whose `deno.json` enables `kv`: the evaluation has no `Deno`, reads no
/// `deno.json`, and makes no database. With a store open, the second evaluation would
/// declare something the first didn't.
#[test]
fn a_working_directory_deno_json_gives_no_deno() {
    if !fgro_available() {
        eprintln!("skipping a_working_directory_deno_json_gives_no_deno: ZAP_FGRO not set");
        return;
    }
    let cwd = scratch::tempdir().unwrap();
    let home = scratch::tempdir().unwrap();
    std::fs::write(cwd.path().join("deno.json"), r#"{"unstable": ["kv"]}"#).unwrap();
    let config = cwd.path().join("zap.ts");
    scratch::write_config(
        &config,
        r"
export default async (zap) => {
    const kv = await Deno.openKv();
    const runs = ((await kv.get(['runs'])).value ?? 0) + 1;
    await kv.set(['runs'], runs);
    kv.close();
    zap.target({local: true});
    zap.directory({id: 'runs', path: `/tmp/run-${runs}`});
};
",
    )
    .unwrap();

    for run in ["first", "second"] {
        let output = validate(cwd.path(), home.path(), &config);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert_eq!(output.status.code(), Some(2), "the {run} run: {stderr}");
        assert!(
            stderr.contains("ReferenceError: Deno is not defined"),
            "the {run} run: {stderr}"
        );
    }
    let stores: Vec<String> = files_under(home.path())
        .into_iter()
        .chain(files_under(cwd.path()))
        .filter(|path| path.contains("kv.sqlite"))
        .collect();
    assert!(stores.is_empty(), "{stores:?}");
}

/// A package planted in a `node_modules` above a project that links none of its own
/// is what Node resolution would find for the config's bare import. The resolution
/// stops at the project's `package.json`, so the import doesn't resolve and the planted
/// module — which loops forever — never runs: the failure comes well inside the eval's
/// timeout, with exit 2 and the advice for an import that doesn't resolve.
#[test]
fn a_package_planted_above_the_project_is_refused_before_it_runs() {
    if !fgro_available() {
        eprintln!(
            "skipping a_package_planted_above_the_project_is_refused_before_it_runs: ZAP_FGRO \
             not set"
        );
        return;
    }
    let root = scratch::tempdir().unwrap();
    let home = scratch::tempdir().unwrap();
    let planted = root.path().join("above/node_modules/@fuzdev/zap");
    let project = root.path().join("above/project");
    std::fs::create_dir_all(&planted).unwrap();
    std::fs::create_dir_all(&project).unwrap();
    // Pinned, so the config's directory isn't refused as world-writable under
    // `umask 000` before the planted package is reached.
    for dir in [root.path().join("above"), project.clone()] {
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    std::fs::write(
        planted.join("package.json"),
        r#"{"name":"@fuzdev/zap","type":"module","exports":{"./*.js":"./*.js"}}"#,
    )
    .unwrap();
    std::fs::write(
        planted.join("recipe.js"),
        "for (;;) {}\nexport const recipe = 1;\n",
    )
    .unwrap();
    std::fs::write(
        project.join("package.json"),
        r#"{"name":"site","type":"module"}"#,
    )
    .unwrap();
    let config = project.join("zap.ts");
    scratch::write_config(
        &config,
        "import {recipe} from '@fuzdev/zap/recipe.js';\n\
         export default (zap) => { zap.target({local: true}); void recipe; };\n",
    )
    .unwrap();

    let start = Instant::now();
    let output = validate(project.as_path(), home.path(), &config);
    let elapsed = start.elapsed();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(2), "{stderr}");
    assert!(
        stderr.starts_with("error: config evaluation failed for ")
            && stderr.contains("(resolve): cannot resolve '@fuzdev/zap/recipe.js' from file://")
            && stderr.contains("no package '@fuzdev/zap' is installed"),
        "{stderr}"
    );
    assert!(
        stderr.contains("\nEvery static import must resolve from the config's project"),
        "{stderr}"
    );
    assert!(
        elapsed < Duration::from_secs(20),
        "refused before the planted loop ran, not after the eval timed out: {elapsed:?}"
    );
}

/// A config in a directory every user can write is refused before its graph is read,
/// even when what sits beside it would load: anyone could have put it there. The
/// refusal exits 2, names the directory and its mode, and says what to change.
#[test]
fn a_config_in_a_world_writable_directory_is_refused() {
    if !fgro_available() {
        eprintln!("skipping a_config_in_a_world_writable_directory_is_refused: ZAP_FGRO not set");
        return;
    }
    let root = scratch::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();
    let shared = root.path().join("shared");
    let planted = shared.join("node_modules/@fuzdev/zap");
    std::fs::create_dir_all(&planted).unwrap();
    std::fs::write(
        planted.join("package.json"),
        r#"{"name":"@fuzdev/zap","type":"module","exports":{"./*.js":"./*.js"}}"#,
    )
    .unwrap();
    std::fs::write(planted.join("recipe.js"), "export const recipe = 1;\n").unwrap();
    let config = shared.join("zap.ts");
    scratch::write_config(
        &config,
        "import {recipe} from '@fuzdev/zap/recipe.js';\n\
         export default (zap) => { zap.target({local: true}); void recipe; };\n",
    )
    .unwrap();
    std::fs::set_permissions(&shared, std::fs::Permissions::from_mode(0o1777)).unwrap();

    let output = validate(root.path(), home.path(), &config);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(2), "{stderr}");
    let shared = std::fs::canonicalize(&shared).unwrap();
    assert!(
        stderr.starts_with("error: refused to evaluate ")
            && stderr.contains(&format!(
                "its directory {} is writable by every user (mode 1777)",
                shared.display()
            )),
        "{stderr}"
    );
    assert!(stderr.contains("`chmod o-w`"), "{stderr}");
}

/// A config file every user can write is refused before its graph is read, whoever
/// can write its directory: anyone could have changed what it declares. The refusal
/// exits 2, names the file and its mode, and says what to change.
#[test]
fn a_world_writable_config_file_is_refused() {
    if !fgro_available() {
        eprintln!("skipping a_world_writable_config_file_is_refused: ZAP_FGRO not set");
        return;
    }
    let root = scratch::tempdir().unwrap();
    let home = scratch::tempdir().unwrap();
    let config = root.path().join("zap.ts");
    scratch::write_config(
        &config,
        "export default (zap) => { zap.target({local: true}); };\n",
    )
    .unwrap();
    let passed = validate(root.path(), home.path(), &config);
    assert!(
        passed.status.success(),
        "{}",
        String::from_utf8_lossy(&passed.stderr)
    );
    std::fs::set_permissions(&config, std::fs::Permissions::from_mode(0o666)).unwrap();

    let output = validate(root.path(), home.path(), &config);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(2), "{stderr}");
    let config = std::fs::canonicalize(&config).unwrap();
    assert!(
        stderr.starts_with("error: refused to evaluate ")
            && stderr.contains(&format!(
                "the config file {} is writable by every user (mode 0666)",
                config.display()
            )),
        "{stderr}"
    );
    assert!(
        stderr.contains("`chmod o-w` on the config file the message names"),
        "{stderr}"
    );
}

/// A project directory every user can write stops the walk up from the config below
/// it, before the project's `package.json`, so the config has no project and is
/// refused before `fgro` runs: the message names where the walk stopped, and the advice
/// ends with how to let it through.
#[test]
fn a_refusal_after_a_stopped_walk_names_where_it_stopped() {
    if !fgro_available() {
        eprintln!(
            "skipping a_refusal_after_a_stopped_walk_names_where_it_stopped: ZAP_FGRO not set"
        );
        return;
    }
    let root = scratch::tempdir().unwrap();
    let home = scratch::tempdir().unwrap();
    let project = root.path().join("project");
    let deploy = project.join("deploy");
    std::fs::create_dir_all(project.join("node_modules")).unwrap();
    std::fs::create_dir_all(&deploy).unwrap();
    std::fs::set_permissions(&deploy, std::fs::Permissions::from_mode(0o755)).unwrap();
    std::fs::write(
        project.join("package.json"),
        r#"{"name":"site","type":"module"}"#,
    )
    .unwrap();
    let config = deploy.join("zap.ts");
    scratch::write_config(
        &config,
        "export default (zap) => { zap.target({local: true}); };\n",
    )
    .unwrap();
    std::fs::set_permissions(&project, std::fs::Permissions::from_mode(0o777)).unwrap();

    let output = validate(&deploy, home.path(), &config);
    std::fs::set_permissions(&project, std::fs::Permissions::from_mode(0o755)).unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(2), "{stderr}");
    let project = std::fs::canonicalize(&project).unwrap();
    assert!(
        stderr.starts_with("error: refused to evaluate ")
            && stderr.contains(&format!(
                "sets its project below {}, where the walk up from it stopped because every \
                 user can write it",
                project.display()
            )),
        "{stderr}"
    );
    assert!(
        stderr.trim_end().ends_with("`chmod o-w` it if it's yours."),
        "{stderr}"
    );
}
