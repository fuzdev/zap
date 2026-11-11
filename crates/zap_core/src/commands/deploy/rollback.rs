//! Post-failure auto-rollback — re-point `current` at the previous release and
//! restart when a deploy fails *after* the atomic swap, so a broken release
//! doesn't sit live until a manual rollback. The re-point is a compare-and-swap under
//! the app's deploy lock (`zap_types::deploy::rollback_swap_command`), and a deploy
//! planned before this one's swap stops at the script's check of `current`, so a
//! rollback never undoes a newer deploy — except a `--force` redeploy of the same
//! version planned after this one's swap, which writes the same `current`.

use zap_types::deploy::{
    DeployAction, DeployPlan, DeployStepId, RollbackSwap, rollback_swap_command,
};
use zap_types::event::{Event, StepOutcome};

use super::RollbackOutcome;
use super::health::http_health_check;
use super::walk::run_captured;
use crate::connection::Connection;
use crate::event::EventHandler;

/// Whether the atomic `current` swap completed: the `extract_swap` step completed,
/// which it does once the script printed `SWAPPED_LINE`, even when its housekeeping
/// after the swap then failed. A failure before this point never moved `current`, so
/// there's nothing to roll back.
pub(super) fn extract_swap_succeeded(outcomes: &[StepOutcome]) -> bool {
    outcomes
        .iter()
        .any(|outcome| matches!(outcome, StepOutcome::Completed { step, .. } if step == DeployStepId::ExtractSwap.as_str()))
}

/// The restart command from the plan's `restart` step, if any — reused to restart the
/// rolled-back release.
fn plan_restart_command(plan: &DeployPlan) -> Option<&str> {
    plan.steps.iter().find_map(|step| match &step.action {
        DeployAction::Restart { command } => Some(command.as_str()),
        _ => None,
    })
}

/// The health-check parameters from the plan's `health` step, if any — reused to
/// confirm the rolled-back release is actually serving.
fn plan_health(plan: &DeployPlan) -> Option<(&str, u32, u64)> {
    plan.steps.iter().find_map(|step| match &step.action {
        DeployAction::Health {
            url,
            attempts,
            interval_ms,
            ..
        } => Some((url.as_str(), *attempts, *interval_ms)),
        _ => None,
    })
}

/// Recover from a post-swap deploy failure by re-pointing `current` at the previous
/// release and restarting, then re-checking health. Emits `rollback` step events and
/// returns how it left the target, or `None` when it never started (nothing to return
/// to); a rollback that went wrong or was skipped also says
/// why in `warnings`, telling the operator what needs a hand. Best-effort: a failed
/// rollback is a warning, never an error.
///
/// Only a `current` that still names `version`, the release this deploy swapped in, is
/// re-pointed (`zap_types::deploy::rollback_swap_command`), and only at a previous
/// release still on the host: when another deploy holds the app's lock or has replaced
/// the release since, when `current` names nothing, or when the previous release is
/// gone, the rollback is skipped with a warning, nothing is restarted, and the deploy
/// still fails.
pub(super) async fn attempt_rollback(
    target: &Connection,
    app_path: &str,
    plan: &DeployPlan,
    previous: Option<&str>,
    version: &str,
    handler: &EventHandler,
    warnings: &mut Vec<String>,
) -> Option<RollbackOutcome> {
    // With nothing to swap back to, the rollback is skipped, and says so on the event
    // stream as well as in the warnings: a `--json` run prints no warning, and its
    // consumer must still learn that a broken release was left live.
    let skip = |reason: String, warnings: &mut Vec<String>| {
        handler.emit(&Event::StepSkipped {
            step: DeployStepId::Rollback.to_string(),
            reason: reason.clone(),
        });
        warnings.push(reason);
    };
    let Some(previous) = previous else {
        skip(
            "deploy failed after the symlink swap and no previous release is known — \
             `current` is left at the failed release; manual rollback required"
                .to_owned(),
            warnings,
        );
        return None;
    };
    if previous == version {
        // A forced redeploy of the version already serving: `current` points at the
        // release we just broke, and the "previous" release *is* it, so there is nothing
        // to swap back to. Same outcome as the no-previous branch above — a broken release
        // left live — so it gets the same warning rather than returning silently.
        skip(
            format!(
                "deploy failed after the symlink swap and the previous release is this same \
                 version ({version}, a --force redeploy) — `current` is left at the failed \
                 release; manual rollback required"
            ),
            warnings,
        );
        return None;
    }

    handler.emit(&Event::StepStarted {
        step: DeployStepId::Rollback.to_string(),
        name: format!("Roll back to {previous}"),
    });

    let swap = rollback_swap_command(app_path, version, previous);
    let skipped = match run_captured(target, &swap)
        .await
        .and_then(|stdout| RollbackSwap::parse(&stdout))
    {
        Ok(RollbackSwap::RolledBack) => None,
        Ok(RollbackSwap::Replaced) => Some(format!(
            "deploy failed after the symlink swap, but `current` no longer names its release \
             ({version}): a newer deploy replaced it, or it was re-pointed by hand, so no \
             rollback was done and `current` is left as it is"
        )),
        Ok(RollbackSwap::Busy) => Some(format!(
            "deploy failed after the symlink swap, but the rollback to {previous} was \
             skipped: another deploy is running for this app, and it decides what \
             `current` names; if that deploy fails before its swap, `current` stays at \
             the failed release ({version}) — check it and roll back by hand"
        )),
        Ok(RollbackSwap::Absent) => Some(format!(
            "deploy failed after the symlink swap, and the rollback to {previous} was \
             skipped: `current` is no longer a symlink — `current` names nothing; manual \
             intervention required"
        )),
        Ok(RollbackSwap::Gone) => Some(format!(
            "deploy failed after the symlink swap, and the rollback was skipped: the \
             previous release ({previous}) is no longer on the host, so `current` is left \
             at the failed release ({version}); manual intervention required"
        )),
        Err(error) => {
            handler.emit(&Event::StepFailed {
                step: DeployStepId::Rollback.to_string(),
                error: error.clone(),
            });
            warnings.push(format!(
                "rollback FAILED (could not re-point `current` to {previous}): {error} — \
                 the host may be serving a broken release; manual intervention required"
            ));
            return Some(RollbackOutcome::Failed);
        }
    };
    if let Some(reason) = skipped {
        skip(reason, warnings);
        return Some(RollbackOutcome::NotDone);
    }

    if let Some(restart) = plan_restart_command(plan)
        && let Err(error) = run_captured(target, restart).await
    {
        handler.emit(&Event::StepFailed {
            step: DeployStepId::Rollback.to_string(),
            error: error.clone(),
        });
        warnings.push(format!(
            "rolled `current` back to {previous} but the restart FAILED: {error} — \
             manual intervention required"
        ));
        return Some(RollbackOutcome::Unconfirmed);
    }

    let health_checked = plan_health(plan).is_some();
    let summary = if let Some((url, attempts, interval_ms)) = plan_health(plan) {
        match http_health_check(url, attempts, interval_ms).await {
            Ok(_) => {
                format!("deploy failed — rolled back to {previous} and restarted (health OK)")
            }
            Err(error) => {
                // The rollback ran and the release it restored isn't serving: the step
                // failed, which a completed event would say it hadn't.
                let failure = format!(
                    "rolled back to {previous} and restarted, but its health check ALSO \
                     failed: {error} — manual intervention required"
                );
                handler.emit(&Event::StepFailed {
                    step: DeployStepId::Rollback.to_string(),
                    error: failure.clone(),
                });
                warnings.push(failure);
                return Some(RollbackOutcome::Unconfirmed);
            }
        }
    } else {
        format!("deploy failed — rolled back `current` to {previous} and restarted")
    };
    // The report's rollback row says this; the stream's event carries it.
    handler.emit(&Event::StepCompleted {
        step: DeployStepId::Rollback.to_string(),
        output: summary,
    });
    Some(RollbackOutcome::RolledBack { health_checked })
}

#[cfg(test)]
mod tests {
    use zap_types::deploy::{DeployContext, DeployPlan, plan_deploy};
    use zap_types::event::StepOutcome;
    use zap_types::schema::{DeployHealth, DeploySpec, ServiceManager, Target};
    use zap_types::text::Text;

    use super::{attempt_rollback, extract_swap_succeeded, plan_health, plan_restart_command};
    use crate::commands::deploy::RollbackOutcome;
    use crate::connection::{CommandOutput, Connection, MockConnection};
    use crate::event::EventHandler;

    fn deploy_spec() -> DeploySpec {
        DeploySpec {
            build: Some("gro build".to_owned()),
            artifacts: vec!["build/".to_owned()],
            path: "/root/app".to_owned(),
            releases: 5,
            service: Some(zap_types::scalar::ServiceName::new("app").unwrap()),
            shared: vec![".env.production".to_owned()],
            prepare: vec![],
            health: None,
        }
    }

    fn ctx() -> DeployContext {
        DeployContext {
            references: std::collections::BTreeMap::new(),
            version: "abc1234".to_owned(),
            target_user: "deploy".to_owned(),
            deployed_by: "op@box".to_owned(),
            previous_version: Some("def5678".to_owned()),
            target_host: "host.example".to_owned(),
            health_domain: "app.example".to_owned(),
            dirty: false,
            skip_build: false,
            preflight: zap_types::deploy::DriftPreflight::Checks {
                resources: 1,
                digest: "d1".to_owned(),
            },
        }
    }

    fn plan() -> DeployPlan {
        let target = Target {
            service_manager: Some(ServiceManager::Systemd),
            ..Target::default()
        };
        // `deploy_spec()` declares no `health`, so this plan has no health step.
        plan_deploy(&deploy_spec(), &target, &ctx())
    }

    #[test]
    fn extract_swap_succeeded_only_on_a_completed_swap() {
        let completed = vec![StepOutcome::Completed {
            step: "extract_swap".to_owned(),
            output: String::new(),
        }];
        assert!(extract_swap_succeeded(&completed));

        let failed = vec![StepOutcome::Failed {
            step: "extract_swap".to_owned(),
            error: "boom".to_owned(),
        }];
        assert!(!extract_swap_succeeded(&failed));

        // A pre-swap failure (upload) never reached the swap.
        let pre_swap = vec![
            StepOutcome::Completed {
                step: "upload".to_owned(),
                output: String::new(),
            },
            StepOutcome::Failed {
                step: "extract_swap".to_owned(),
                error: "boom".to_owned(),
            },
        ];
        assert!(!extract_swap_succeeded(&pre_swap));
    }

    #[test]
    fn plan_helpers_extract_restart_and_health() {
        // plan() has a systemd service (restart) and no health.
        let p = plan();
        assert!(plan_restart_command(&p).is_some_and(|cmd| cmd.contains("restart app")));
        assert_eq!(plan_health(&p), None);

        // A plan with a health step exposes its parameters.
        let with_health = {
            let deploy = DeploySpec {
                health: Some(DeployHealth {
                    domain: Text::literal("example.com"),
                    path: "/health".to_owned(),
                    attempts: std::num::NonZeroU32::new(9).unwrap(),
                    interval_ms: 1500,
                }),
                ..deploy_spec()
            };
            let target = Target {
                service_manager: Some(ServiceManager::Systemd),
                ..Target::default()
            };
            plan_deploy(&deploy, &target, &ctx())
        };
        assert_eq!(
            plan_health(&with_health),
            Some(("https://example.com/health", 9, 1500))
        );
    }

    /// The rollback re-points and restarts only when its swap found `current` still at
    /// this deploy's release; otherwise it warns why it did nothing and restarts nothing
    /// (the mock has no restart recorded, so a restart would be a warning of its own).
    /// What it returns is what the deploy's report says of the target, and a rollback
    /// that went as planned leaves no warning: its row in the report says so.
    #[tokio::test]
    async fn a_rollback_restarts_only_what_it_rolled_back() {
        let plan = plan();
        let swap = zap_types::deploy::rollback_swap_command("/root/app", "abc1234", "def5678");
        let restart = plan_restart_command(&plan).unwrap().to_owned();
        let said = |stdout: &str| CommandOutput {
            success: true,
            code: 0,
            stdout: stdout.to_owned(),
            stderr: String::new(),
        };
        let rolled_back = RollbackOutcome::RolledBack {
            health_checked: false,
        };
        for (stdout, restarts, warned, left) in [
            ("rolled_back\n", true, None, rolled_back),
            (
                "replaced\n",
                false,
                Some("no longer names its release (abc1234)"),
                RollbackOutcome::NotDone,
            ),
            (
                "busy\n",
                false,
                Some("another deploy is running for this app"),
                RollbackOutcome::NotDone,
            ),
            (
                "absent\n",
                false,
                Some("`current` names nothing; manual intervention required"),
                RollbackOutcome::NotDone,
            ),
            (
                "gone\n",
                false,
                Some("(def5678) is no longer on the host"),
                RollbackOutcome::NotDone,
            ),
            (
                "what\n",
                false,
                Some("rollback FAILED"),
                RollbackOutcome::Failed,
            ),
        ] {
            let mut mock = MockConnection::new("host").with(swap.clone(), said(stdout));
            if restarts {
                mock = mock.with(restart.clone(), said(""));
            }
            let mut warnings = Vec::new();
            let outcome = attempt_rollback(
                &Connection::Mock(mock),
                "/root/app",
                &plan,
                Some("def5678"),
                "abc1234",
                &EventHandler::Null,
                &mut warnings,
            )
            .await;
            assert_eq!(outcome, Some(left), "{stdout:?}");
            match (warned, warnings.as_slice()) {
                (None, []) => {}
                (Some(warned), [warning]) => {
                    assert!(warning.contains(warned), "{stdout:?}: {warning}");
                }
                _ => panic!("{stdout:?}: {warnings:?}"),
            }
        }
    }

    /// A rollback with nothing to swap back to — no previous release, or a `--force`
    /// redeploy of the live one — runs nothing on the host, and reports the step as
    /// skipped with the warning's own words, so a `--json` stream says a broken release
    /// was left live.
    #[tokio::test]
    async fn a_rollback_with_nothing_to_return_to_is_a_skipped_step() {
        use zap_types::event::Event;

        for previous in [None, Some("abc1234")] {
            let events = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
            let mut warnings = Vec::new();
            let outcome = attempt_rollback(
                &Connection::Mock(MockConnection::new("host")),
                "/root/app",
                &plan(),
                previous,
                "abc1234",
                &EventHandler::Capture(std::sync::Arc::clone(&events)),
                &mut warnings,
            )
            .await;
            // it never started, so it reports no outcome of a run
            assert_eq!(outcome, None, "{previous:?}");
            let [warning] = warnings.as_slice() else {
                panic!("{previous:?}: {warnings:?}");
            };
            assert!(warning.contains("manual rollback required"), "{warning}");
            let events = events.lock().unwrap();
            assert!(
                matches!(
                    events.as_slice(),
                    [Event::StepSkipped { step, reason }] if step == "rollback" && reason == warning
                ),
                "{previous:?}: {events:?}"
            );
        }
    }

    /// A rollback whose restored release fails its health check reports the step as
    /// failed, never completed, and says so in its one warning; a healthy one is
    /// completed. Nothing listens on the loopback port the failing plan polls.
    #[tokio::test]
    async fn a_rollback_that_fails_its_health_check_is_a_failed_step() {
        use zap_types::event::Event;

        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let deploy = DeploySpec {
            health: Some(DeployHealth {
                domain: Text::literal(&format!("127.0.0.1:{port}")),
                path: "/health".to_owned(),
                attempts: std::num::NonZeroU32::new(1).unwrap(),
                interval_ms: 0,
            }),
            ..deploy_spec()
        };
        let target = Target {
            service_manager: Some(ServiceManager::Systemd),
            ..Target::default()
        };
        let plan = plan_deploy(&deploy, &target, &ctx());
        let said = |stdout: &str| CommandOutput {
            success: true,
            code: 0,
            stdout: stdout.to_owned(),
            stderr: String::new(),
        };
        let mock = MockConnection::new("host")
            .with(
                zap_types::deploy::rollback_swap_command("/root/app", "abc1234", "def5678"),
                said("rolled_back\n"),
            )
            .with(plan_restart_command(&plan).unwrap().to_owned(), said(""));
        let events = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let mut warnings = Vec::new();
        attempt_rollback(
            &Connection::Mock(mock),
            "/root/app",
            &plan,
            Some("def5678"),
            "abc1234",
            &EventHandler::Capture(std::sync::Arc::clone(&events)),
            &mut warnings,
        )
        .await;
        let [warning] = warnings.as_slice() else {
            panic!("{warnings:?}");
        };
        assert!(warning.contains("health check ALSO failed"), "{warning}");
        let events = events.lock().unwrap();
        let last = events.last().unwrap();
        assert!(
            matches!(last, Event::StepFailed { step, error } if step == "rollback" && error == warning),
            "{events:?}"
        );
        assert!(
            !events
                .iter()
                .any(|event| matches!(event, Event::StepCompleted { .. })),
            "{events:?}"
        );
    }

    /// A loopback server answering `503` to its first `failing` connections and `200`
    /// to every one after, each response closing its connection: its
    /// `http://127.0.0.1:<port>` origin, and the count of connections it accepted.
    fn recovering_server(
        failing: usize,
    ) -> (String, std::sync::Arc<std::sync::atomic::AtomicUsize>) {
        use std::io::{Read as _, Write as _};
        use std::sync::atomic::Ordering;

        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        let accepted = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counter = std::sync::Arc::clone(&accepted);
        std::thread::spawn(move || {
            for sock in listener.incoming() {
                let Ok(mut sock) = sock else { return };
                let seen = counter.fetch_add(1, Ordering::SeqCst);
                let mut buf = [0u8; 2048];
                let _ = sock.read(&mut buf);
                let response: &[u8] = if seen < failing {
                    b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                } else {
                    b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"
                };
                let _ = sock.write_all(response);
            }
        });
        (origin, accepted)
    }

    /// A rollback whose restored release passes its health check completes: it swaps
    /// back, restarts, polls the plan's health check within the plan's own attempt
    /// budget (a `503`, then a `200`), and reports the step completed, with no warning:
    /// nothing needs a hand. The plan's health URL is pointed at a plain-HTTP loopback server,
    /// which a planned `https` URL can't reach.
    #[tokio::test]
    async fn a_rollback_whose_restored_release_is_healthy_is_a_completed_step() {
        use zap_types::deploy::DeployAction;
        use zap_types::event::Event;

        let (origin, accepted) = recovering_server(1);
        let deploy = DeploySpec {
            health: Some(DeployHealth {
                domain: Text::literal("app.example"),
                path: "/health".to_owned(),
                attempts: std::num::NonZeroU32::new(2).unwrap(),
                interval_ms: 0,
            }),
            ..deploy_spec()
        };
        let target = Target {
            service_manager: Some(ServiceManager::Systemd),
            ..Target::default()
        };
        let mut plan = plan_deploy(&deploy, &target, &ctx());
        for step in &mut plan.steps {
            if let DeployAction::Health { url, .. } = &mut step.action {
                *url = format!("{origin}/health");
            }
        }
        let said = |stdout: &str| CommandOutput {
            success: true,
            code: 0,
            stdout: stdout.to_owned(),
            stderr: String::new(),
        };
        let swap = zap_types::deploy::rollback_swap_command("/root/app", "abc1234", "def5678");
        let restart = plan_restart_command(&plan).unwrap().to_owned();
        let mock = MockConnection::new("host")
            .with(swap.clone(), said("rolled_back\n"))
            .with(restart.clone(), said(""));
        let events = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let mut warnings = Vec::new();
        let outcome = attempt_rollback(
            &Connection::Mock(mock.clone()),
            "/root/app",
            &plan,
            Some("def5678"),
            "abc1234",
            &EventHandler::Capture(std::sync::Arc::clone(&events)),
            &mut warnings,
        )
        .await;
        assert_eq!(
            outcome,
            Some(RollbackOutcome::RolledBack {
                health_checked: true
            })
        );
        assert!(warnings.is_empty(), "{warnings:?}");
        assert_eq!(mock.issued_commands(), [swap, restart]);
        assert_eq!(accepted.load(std::sync::atomic::Ordering::SeqCst), 2);
        let events = events.lock().unwrap();
        assert!(
            matches!(
                events.as_slice(),
                [
                    Event::StepStarted { step: started, name },
                    Event::StepCompleted { step: completed, output },
                ] if started == "rollback"
                    && name == "Roll back to def5678"
                    && completed == "rollback"
                    && output == "deploy failed — rolled back to def5678 and restarted (health OK)"
            ),
            "{events:?}"
        );
    }
}
