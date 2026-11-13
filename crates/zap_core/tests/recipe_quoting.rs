//! The shipped certbot recipes through zap's own path: a config importing them is
//! evaluated in the sandbox, each `script`'s `check` and `run` is resolved the way a
//! command is ([`resolve_command`], over the `--env-file` overlay), and the result runs
//! under `sh` with a stand-in `sudo` first on `PATH`, so nothing reaches the real one.
//!
//! The values are an operator's environment: one that would run code where a shell
//! read it, one that would turn the certificate check into a check that always passes,
//! and one holding a single quote, which zap refuses to substitute into a command. The
//! DNS preflight each `run` leads with refuses the first two as names, and an address
//! that would run code, before anything runs; a well-formed name and address, which a
//! stand-in `getent` resolves, let the command run with the hostile email as one word.
//!
//! Requires `ZAP_FGRO` (config eval); checks nothing without it, where
//! `required_programs.rs` fails.

mod common;
mod scratch;

use std::collections::HashMap;
use std::os::unix::fs::PermissionsExt as _;
use std::path::PathBuf;
use std::process::{Command, Stdio};

use common::{fgro_available, pinned};
use zap_core::config::eval_config;
use zap_core::resolve::{UnsafeValue, resolve_command, set_env_overlay};
use zap_types::schema::ResourceKind;

/// A domain that runs `touch canary` where a shell reads it as code.
const RUNS_CODE: &str = "x/f; touch canary; :";

/// A domain that makes `test -f <live>/fullchain.pem` a test that always passes.
const PASSES_THE_CHECK: &str = "x/fullchain.pem -o -e / -o -f /nonexistent";

#[tokio::test]
async fn a_recipe_command_takes_a_referenced_value_as_one_word() {
    if !fgro_available() {
        eprintln!("skipping the recipe quoting test: ZAP_FGRO not set");
        return;
    }
    assert!(set_env_overlay(HashMap::from([
        ("RUNS_CODE".to_owned(), RUNS_CODE.to_owned()),
        ("PASSES_THE_CHECK".to_owned(), PASSES_THE_CHECK.to_owned()),
        ("HOLDS_A_QUOTE".to_owned(), "it's".to_owned()),
        ("EMAIL".to_owned(), "a@b.c; touch canary".to_owned()),
        ("GOOD_DOMAIN".to_owned(), "example.org".to_owned()),
        ("GOOD_ADDRESS".to_owned(), "203.0.113.7".to_owned()),
        (
            "ADDRESS_RUNS_CODE".to_owned(),
            "203.0.113.7; touch canary".to_owned()
        ),
    ])));

    // A project that links this checkout in as `@fuzdev/zap`, as a consumer's
    // `npm install` of the path dependency does: zap evaluates a config only from its
    // project and the packages the project links.
    let repo =
        std::fs::canonicalize(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")).unwrap();
    let dir = scratch::tempdir().unwrap();
    std::fs::write(
        dir.path().join("package.json"),
        r#"{"name":"site","type":"module"}"#,
    )
    .unwrap();
    std::fs::create_dir_all(dir.path().join("node_modules/@fuzdev")).unwrap();
    std::os::unix::fs::symlink(repo, dir.path().join("node_modules/@fuzdev/zap")).unwrap();
    let config = dir.path().join("zap.ts");
    scratch::write_config(
        &config,
        r"
import {env_ref} from '@fuzdev/zap/env_ref.ts';
import {certbot_webroot_switch} from '@fuzdev/zap/recipe_certbot.ts';
import {debian_certbot_standalone_issue} from '@fuzdev/zap/recipe_debian_certbot.ts';

export default (zap) => {
    zap.target({local: true});
    const email = env_ref('EMAIL');
    const deploy_hook = {path: '/etc/letsencrypt/renewal-hooks/deploy/reload-nginx'};
    const host = [env_ref('DEPLOY_HOST')];
    for (const name of ['RUNS_CODE', 'PASSES_THE_CHECK', 'HOLDS_A_QUOTE']) {
        const domain = env_ref(name);
        zap.script({id: `issue-${name}`, ...debian_certbot_standalone_issue({domain, email, expected_addresses: host})});
        zap.script({id: `webroot-${name}`, ...certbot_webroot_switch({domain, email, deploy_hook, expected_addresses: host})});
    }
    const domain = env_ref('GOOD_DOMAIN');
    for (const address of ['GOOD_ADDRESS', 'ADDRESS_RUNS_CODE']) {
        const expected_addresses = [env_ref(address)];
        zap.script({id: `issue-${address}`, ...debian_certbot_standalone_issue({domain, email, expected_addresses})});
        zap.script({id: `webroot-${address}`, ...certbot_webroot_switch({domain, email, deploy_hook, expected_addresses})});
    }
};
",
    )
    .unwrap();
    let config = eval_config(&config, pinned()).await.unwrap();

    // The stand-in records each call's arguments, one per line after a `--` line, and
    // runs only `test` and `grep`, so a check's verdict is the shell's.
    let bin = dir.path().join("bin");
    std::fs::create_dir(&bin).unwrap();
    let log = dir.path().join("sudo.log");
    std::fs::write(
        bin.join("sudo"),
        "#!/bin/sh\n{ echo --; for a; do printf '%s\\n' \"$a\"; done; } >> \"$SUDO_LOG\"\n\
         case $1 in test | grep) exec \"$@\" ;; esac\nexit 0\n",
    )
    .unwrap();
    std::fs::set_permissions(bin.join("sudo"), std::fs::Permissions::from_mode(0o755)).unwrap();
    // The preflight's lookups (`ahosts` and `hosts`): every name resolves to
    // `GOOD_ADDRESS`'s value alone.
    std::fs::write(
        bin.join("getent"),
        "#!/bin/sh\nprintf '%s STREAM %s\\n' 203.0.113.7 \"$2\"\n",
    )
    .unwrap();
    std::fs::set_permissions(bin.join("getent"), std::fs::Permissions::from_mode(0o755)).unwrap();
    let path = format!("{}:{}", bin.display(), std::env::var("PATH").unwrap());
    let run = |text: &str| {
        std::fs::write(&log, "").unwrap();
        let status = Command::new("sh")
            .arg("-c")
            .arg(text)
            .current_dir(dir.path())
            .env("PATH", &path)
            .env("SUDO_LOG", &log)
            .stderr(Stdio::null())
            .status()
            .unwrap();
        assert!(
            !dir.path().join("canary").exists(),
            "a value ran as code: {text}"
        );
        (status.success(), std::fs::read_to_string(&log).unwrap())
    };

    let mut ran = 0;
    for resource in &config.resources {
        let ResourceKind::Script(script) = &resource.kind else {
            panic!("only scripts are declared");
        };
        let id = resource.id.0.as_str();
        if id.ends_with("HOLDS_A_QUOTE") {
            assert_eq!(
                resolve_command(script.check.as_inert()),
                Err(UnsafeValue::SingleQuote {
                    name: "HOLDS_A_QUOTE".to_owned()
                }),
                "{id}"
            );
            continue;
        }
        let domain = if id.ends_with("ADDRESS") || id.ends_with("ADDRESS_RUNS_CODE") {
            "example.org"
        } else if id.ends_with("RUNS_CODE") {
            RUNS_CODE
        } else {
            PASSES_THE_CHECK
        };
        let (passed, calls) = run(&resolve_command(script.check.as_inert()).unwrap());
        assert!(
            !passed,
            "{id}: no certificate was issued, so the check fails"
        );
        if id.starts_with("issue") {
            assert_eq!(
                calls,
                format!("--\ntest\n-f\n/etc/letsencrypt/live/{domain}/fullchain.pem\n"),
                "{id}"
            );
        }
        let (passed, calls) = run(&resolve_command(script.run.as_inert()).unwrap());
        if !id.ends_with("GOOD_ADDRESS") {
            // a name or an address the preflight refuses: nothing runs
            assert!(!passed, "{id}: refused");
            assert_eq!(calls, "", "{id}: nothing ran");
            ran += 1;
            continue;
        }
        assert!(passed, "{id}");
        if id.starts_with("issue") {
            // the stop, then the request, in the one guarded `run`
            assert_eq!(
                calls,
                format!(
                    "--\nsystemctl\nstop\nnginx\n--\ncertbot\ncertonly\n--standalone\n-d\n{domain}\n--non-interactive\n\
                     --agree-tos\n--email\na@b.c; touch canary\n"
                ),
                "{id}"
            );
        }
        if id.starts_with("webroot") {
            assert!(
                calls.ends_with("--\n--\n/etc/letsencrypt/renewal-hooks/deploy/reload-nginx\n"),
                "{id}: the deploy hook runs after certonly: {calls}"
            );
        }
        ran += 1;
    }
    assert_eq!(ran, 8);
}
