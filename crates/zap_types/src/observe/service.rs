//! `service` — the target service manager's active/enabled state against the desired one.
//!
//! Each probe is read by the manager's own reading ([`service_managers::read_active`],
//! [`service_managers::read_enabled`]): what the manager reports as running or not, enabled
//! or not, and any other answer holds — a probe that failed is no evidence of a stopped or
//! disabled service.

use super::{Query, QueryResult, command_answer};
use crate::detected::{CurrentState, Detection};
use crate::schema::{ServiceManager, ServiceResource};
use crate::service_managers;

/// The exit `rc-service <svc> status` gives an unsupervised service — one whose
/// `supervise-daemon` died, leaving its daemon possibly running — which
/// [`service_managers::read_active`] holds; its hold names the state and the way out.
const OPENRC_UNSUPERVISED: i32 = 64;

/// Index of the `is_active` probe in [`queries`].
const ACTIVE: usize = 0;
/// Index of the `is_enabled` probe in [`queries`].
const ENABLED: usize = 1;

/// How a service's state is read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServiceCheck {
    /// The manager's two probes.
    Manager {
        /// The manager, whose readings interpret the probes.
        manager: ServiceManager,
        /// Reads whether the service is running.
        is_active: String,
        /// Reads whether the service is enabled at boot.
        is_enabled: String,
    },
    /// Nothing can be read — held with `reason`.
    Unreadable {
        /// Why the service can't be read.
        reason: String,
    },
}

impl ServiceCheck {
    /// The probes for `service` under the target's `manager`, or why there are none.
    #[must_use]
    pub fn new(service: &ServiceResource, manager: Option<ServiceManager>) -> Self {
        let Some(manager) = manager else {
            return Self::Unreadable {
                reason: "service_manager not set in target (required for service resources)"
                    .to_owned(),
            };
        };
        match (
            service_managers::is_active(manager, &service.service),
            service_managers::is_enabled(manager, &service.service),
        ) {
            (Some(is_active), Some(is_enabled)) => Self::Manager {
                manager,
                is_active,
                is_enabled,
            },
            _ => Self::Unreadable {
                reason: format!("unsupported service manager: {}", manager.as_str()),
            },
        }
    }
}

/// A service's reads: the `is_active` and `is_enabled` probes, each a
/// [`Query::login_command`] — as the connecting user. Nothing for a service that can't
/// be read.
#[must_use]
pub fn queries(check: &ServiceCheck) -> Vec<Query> {
    match check {
        ServiceCheck::Manager {
            is_active,
            is_enabled,
            ..
        } => vec![
            Query::login_command(is_active),
            Query::login_command(is_enabled),
        ],
        ServiceCheck::Unreadable { .. } => Vec::new(),
    }
}

/// The verdict for a service from the answers to [`queries`].
///
/// `Converged` when the enabled state matches (always managed) and the running state
/// does (when `running` is set), else `Drifted` with both observed states.
#[must_use]
pub fn interpret(
    service: &ServiceResource,
    check: &ServiceCheck,
    results: &[QueryResult],
) -> Detection {
    let manager = match check {
        ServiceCheck::Unreadable { reason } => {
            return Detection::Undetermined {
                reason: reason.clone(),
            };
        }
        ServiceCheck::Manager { manager, .. } => *manager,
    };
    let unread = |what: &str, code: i32| Detection::Undetermined {
        reason: format!(
            "detection failed: couldn't read whether `{}` is {what} (the probe exited {code})",
            service.service.as_str()
        ),
    };
    let is_running = match command_answer(results, ACTIVE) {
        Ok(output) => match service_managers::read_active(manager, output.code) {
            Some(running) => running,
            None if manager == ServiceManager::Openrc && output.code == OPENRC_UNSUPERVISED => {
                return Detection::Undetermined {
                    reason: format!(
                        "detection failed: `{0}` is unsupervised (the probe exited 64): its \
                         supervisor died and its daemon may still run; check for it and \
                         `rc-service {0} zap` by hand",
                        service.service.as_str()
                    ),
                };
            }
            None => return unread("running", output.code),
        },
        Err(held) => return held,
    };
    let is_enabled = match command_answer(results, ENABLED) {
        Ok(output) => match service_managers::read_enabled(
            manager,
            output.code,
            &String::from_utf8_lossy(&output.stdout),
            &String::from_utf8_lossy(&output.stderr),
        ) {
            Some(enabled) => enabled,
            None => return unread("enabled", output.code),
        },
        Err(held) => return held,
    };
    // `running: None` means the runtime state isn't managed (enable-only).
    if service.enabled == is_enabled && service.running.is_none_or(|want| want == is_running) {
        Detection::Converged
    } else {
        Detection::Drifted {
            current: CurrentState::Service {
                is_running,
                is_enabled,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{ServiceCheck, interpret, queries};
    use crate::detected::{CurrentState, Detection};
    use crate::observe::testing::exited;
    use crate::observe::{Query, QueryError};
    use crate::schema::{ServiceManager, ServiceResource};

    fn service(running: Option<bool>) -> ServiceResource {
        serde_json::from_value(
            serde_json::json!({"service": "nginx", "enabled": true, "running": running}),
        )
        .unwrap()
    }

    #[test]
    fn both_probes_run_as_the_login_user() {
        let check = ServiceCheck::new(&service(Some(true)), Some(ServiceManager::Openrc));
        assert_eq!(
            queries(&check),
            [
                Query::login_command(
                    "rc-service --exists nginx; case $? in 0) ;; 1) exit 3;; *) exit 2;; esac; \
                     rc-service nginx status"
                ),
                Query::login_command(
                    "[ -d /etc/runlevels ] && [ -r /etc/runlevels ] && [ -x /etc/runlevels ] || \
                     exit 2; for r in /etc/runlevels/*/nginx; do [ -e \"$r\" ] && exit 0; done; \
                     exit 1"
                ),
            ]
        );
    }

    #[test]
    fn exit_statuses_decide_the_state() {
        let check = ServiceCheck::new(&service(Some(true)), Some(ServiceManager::Systemd));
        assert_eq!(
            interpret(
                &service(Some(true)),
                &check,
                &[exited(0, ""), exited(0, "enabled\n")]
            ),
            Detection::Converged
        );
        assert_eq!(
            interpret(
                &service(Some(true)),
                &check,
                &[exited(3, ""), exited(0, "static\n")]
            ),
            Detection::Drifted {
                current: CurrentState::Service {
                    is_running: false,
                    is_enabled: true,
                },
            }
        );
        // Unmanaged runtime state: a stopped service converges on its enablement.
        assert_eq!(
            interpret(&service(None), &check, &[exited(3, ""), exited(0, "")]),
            Detection::Converged
        );
    }

    /// A probe that failed to read is no evidence of a stopped or disabled service: only
    /// the codes and states each manager reports for one read so, and anything else holds
    /// — a `running: false` / `enabled: false` desire is never taken as converged on it.
    #[test]
    fn only_a_reported_state_reads_as_stopped_or_disabled() {
        let stopped: ServiceResource = serde_json::from_value(
            serde_json::json!({"service": "nginx", "enabled": false, "running": false}),
        )
        .unwrap();
        let systemd = ServiceCheck::new(&stopped, Some(ServiceManager::Systemd));
        let openrc = ServiceCheck::new(&stopped, Some(ServiceManager::Openrc));
        let read =
            |check: &ServiceCheck, active, enabled| interpret(&stopped, check, &[active, enabled]);
        // What each manager reports for a stopped, disabled service converges it.
        for (active, enabled) in [(3, "disabled\n"), (4, "not-found\n"), (3, "masked\n")] {
            assert_eq!(
                read(&systemd, exited(active, ""), exited(1, enabled)),
                Detection::Converged,
                "{active} {enabled}"
            );
        }
        assert_eq!(
            read(&openrc, exited(3, ""), exited(1, "")),
            Detection::Converged
        );
        assert_eq!(
            read(&openrc, exited(32, ""), exited(1, "")),
            Detection::Converged
        );
        // A failed read — no bus, a missing tool, an unreadable runlevel directory — holds.
        for (check, active, enabled) in [
            (&systemd, exited(1, ""), exited(1, "disabled\n")),
            (&systemd, exited(3, ""), exited(1, "")),
            (&systemd, exited(3, ""), exited(1, "bad\n")),
            (&openrc, exited(1, ""), exited(1, "")),
            (&openrc, exited(127, ""), exited(1, "")),
            // `rc-service --exists` that couldn't run (no `rc-service`) exits 2.
            (&openrc, exited(2, ""), exited(1, "")),
            (&openrc, exited(3, ""), exited(2, "")),
            (&openrc, exited(64, ""), exited(0, "")),
        ] {
            assert!(
                matches!(
                    read(check, active.clone(), enabled.clone()),
                    Detection::Undetermined { .. }
                ),
                "{check:?} {active:?} {enabled:?}"
            );
        }
        // An unsupervised OpenRC service's hold names the state and the way out.
        assert_eq!(
            read(&openrc, exited(64, ""), exited(0, "")),
            Detection::Undetermined {
                reason: "detection failed: `nginx` is unsupervised (the probe exited 64): its \
                         supervisor died and its daemon may still run; check for it and \
                         `rc-service nginx zap` by hand"
                    .to_owned()
            }
        );
    }

    /// Older systemd reads a missing unit as an error on stderr with nothing on stdout:
    /// that is no unit, so not enabled, and a `enabled: false` service converges, while an
    /// error that isn't a missing unit still holds. (Recorded from systemd 249/252.)
    #[test]
    fn older_systemd_reads_a_missing_unit_as_not_enabled() {
        let errored = |stderr: &str| {
            Ok(crate::observe::Observation::Command(
                crate::observe::CommandObservation {
                    code: 1,
                    stdout: Vec::new(),
                    stderr: stderr.as_bytes().to_vec(),
                },
            ))
        };
        let disabled: ServiceResource =
            serde_json::from_value(serde_json::json!({"service": "app", "enabled": false}))
                .unwrap();
        let check = ServiceCheck::new(&disabled, Some(ServiceManager::Systemd));
        for missing in [
            "Failed to get unit file state for app.service: No such file or directory\n",
            "Failed to get unit file state for app.service: Unit app.service not found.\n",
        ] {
            assert_eq!(
                interpret(&disabled, &check, &[exited(4, ""), errored(missing)]),
                Detection::Converged,
                "{missing}"
            );
        }
        assert!(matches!(
            interpret(
                &disabled,
                &check,
                &[
                    exited(4, ""),
                    errored("Failed to connect to bus: No such file or directory\n")
                ]
            ),
            Detection::Undetermined { .. }
        ));
    }

    #[test]
    fn an_unanswered_probe_holds_and_an_unreadable_service_reads_nothing() {
        let check = ServiceCheck::new(&service(None), Some(ServiceManager::Systemd));
        assert!(matches!(
            interpret(
                &service(None),
                &check,
                &[exited(0, ""), Err(QueryError::Unrecorded)]
            ),
            Detection::Undetermined { .. }
        ));
        let none = ServiceCheck::new(&service(None), None);
        assert!(queries(&none).is_empty());
        assert_eq!(
            interpret(&service(None), &none, &[]),
            Detection::Undetermined {
                reason: "service_manager not set in target (required for service resources)"
                    .to_owned(),
            }
        );
        let launchd = ServiceCheck::new(&service(None), Some(ServiceManager::Launchd));
        assert_eq!(
            interpret(&service(None), &launchd, &[]),
            Detection::Undetermined {
                reason: "unsupported service manager: launchd".to_owned(),
            }
        );
    }
}
