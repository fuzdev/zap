//! `zap deploy` command-core guards — the machine-free gates that must reject a
//! misconfigured deploy *before* any IO (no SSH, no build, no upload).
//!
//! Both gates are pure functions of the evaluated config plus the operator env, so
//! they run ahead of `check_connectivity` — which is what lets these tests assert
//! them against an unreachable `.invalid` host without ever touching the network.
//! Gated on `ZAP_FGRO` (config eval), like the other command-core e2e tests.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;
mod scratch;

use std::path::Path;

use common::{fgro, fgro_available};
use zap_core::commands::deploy::{DeployOptions, run_deploy_in};
use zap_core::error::Error;

/// Write a `zap.ts` with a remote (unreachable) target plus `body`, and return the
/// project dir holding it. The host is `.invalid` on purpose: a gate that lets a run
/// reach the connection surfaces as a connectivity error, not a false pass.
fn write_config(dir: &Path, body: &str) -> std::path::PathBuf {
    let config_path = dir.join("zap.ts");
    scratch::write_config(
        &config_path,
        format!(
            "export default (zap) => {{
	zap.target({{host: 'zap-test.invalid', user: 'deploy'}});
{body}
}};
"
        ),
    )
    .unwrap();
    config_path
}

/// A wetrun deploy must reject a config whose references are unset — the
/// same fail-fast preflight `apply` runs. Without it, every reference silently
/// resolves to the empty string and the run ships against a half-resolved config.
///
/// The health domain rides this gate like any other declared field, which is the point
/// of it being a declared field: no separate check, no `DEPLOY_DOMAIN` special case.
#[tokio::test]
async fn deploy_wetrun_rejects_unresolved_env_refs() {
    if !fgro_available() {
        eprintln!("skipping deploy_wetrun_rejects_unresolved_env_refs: ZAP_FGRO not set");
        return;
    }

    let proj = scratch::tempdir().unwrap();
    let config_path = write_config(
        proj.path(),
        r"	zap.file({
		id: 'app-env',
		path: '/srv/app/shared/.env',
		content: {
			type: 'template',
			template: 'DOMAIN={{domain}}',
			vars: {domain: zap.env('ZAP_TEST_UNSET_DOMAIN')},
		},
	});
	zap.deploy({
		artifacts: ['build/'],
		path: '/srv/app',
		health: {domain: zap.env('ZAP_TEST_UNSET_HEALTH_DOMAIN'), path: '/ready'},
	});",
    );
    let home = scratch::tempdir().unwrap();

    let result = run_deploy_in(
        Some(home.path()),
        fgro(),
        &config_path,
        &DeployOptions {
            wetrun: true,
            ..DeployOptions::default()
        },
    )
    .await;

    let Err(Error::WetrunRefused(message)) = &result else {
        panic!(
            "a wetrun deploy must reject the unset `ZAP_TEST_UNSET_DOMAIN` reference; got {result:?}"
        );
    };
    assert!(message.contains("unset or empty"), "{message}");
    assert!(message.contains("ZAP_TEST_UNSET_DOMAIN"), "{message}");
    assert!(
        message.contains("ZAP_TEST_UNSET_HEALTH_DOMAIN"),
        "{message}"
    );
}

/// A health gate with nothing to poll is **unrepresentable**, not merely rejected:
/// `domain` lives inside the health block, so a config that declares the gate without a
/// host fails at the config boundary — no run reaches the planner in that state.
#[tokio::test]
async fn a_health_gate_without_a_domain_fails_to_parse() {
    if !fgro_available() {
        eprintln!("skipping a_health_gate_without_a_domain_fails_to_parse: ZAP_FGRO not set");
        return;
    }

    let proj = scratch::tempdir().unwrap();
    let home = scratch::tempdir().unwrap();
    let config_path = write_config(
        proj.path(),
        r"	zap.deploy({artifacts: ['build/'], path: '/srv/app', health: {path: '/ready'}});",
    );

    let result =
        zap_core::commands::run_config_validate_in(Some(home.path()), fgro(), &config_path).await;
    let Err(error) = &result else {
        panic!("a health block with no `domain` must not parse; got {result:?}");
    };
    assert!(
        error
            .to_string()
            .ends_with("zap.ts): missing field `domain`"),
        "{error}"
    );
}

/// The one bad state the type still permits — a blank `domain` literal — is caught by
/// the **machine-free** structural gate, so `zap config validate` finds it with no
/// network, no target, and no secrets. That's the payoff of the domain being declared
/// config rather than ambient env: CI can check it.
#[tokio::test]
async fn a_blank_health_domain_is_caught_by_config_validate() {
    if !fgro_available() {
        eprintln!("skipping a_blank_health_domain_is_caught_by_config_validate: ZAP_FGRO not set");
        return;
    }

    let proj = scratch::tempdir().unwrap();
    let home = scratch::tempdir().unwrap();
    let config_path = write_config(
        proj.path(),
        r"	zap.deploy({
		artifacts: ['build/'],
		path: '/srv/app',
		health: {domain: '', path: '/ready'},
	});",
    );

    let result =
        zap_core::commands::run_config_validate_in(Some(home.path()), fgro(), &config_path).await;
    let Err(Error::Config(message)) = &result else {
        panic!("a blank health domain must be a structural error; got {result:?}");
    };
    assert!(message.contains("deploy.health.domain"), "{message}");
}
