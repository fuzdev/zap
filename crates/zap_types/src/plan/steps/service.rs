//! `service` step builder — daemon-reload, enable/disable, then start/stop.

use crate::plan::PlanStep;
use crate::schema::{ServiceResource, Target};
use crate::service_managers;

/// Lifecycle steps for a `service`, or a preview `Note` when the manager is
/// unconfigured / unsupported.
///
/// Reloads the manager's unit definitions first so a changed unit file takes effect
/// before the subsequent enable/restart — systemd otherwise restarts the stale
/// in-memory unit. The order is daemon-reload → enable/disable → start/stop.
pub(super) fn service_steps(service: &ServiceResource, target: &Target) -> Vec<PlanStep> {
    let Some(sm) = target.service_manager else {
        return vec![PlanStep::note("service manager not configured")];
    };
    let lifecycle = if service.enabled {
        service_managers::enable(sm, &service.service)
    } else {
        service_managers::disable(sm, &service.service)
    };
    let Some(lifecycle) = lifecycle else {
        return vec![PlanStep::note(format!(
            "unsupported service manager: {}",
            sm.as_str()
        ))];
    };
    let mut steps = Vec::new();
    if let Some(reload) = service_managers::daemon_reload(sm) {
        steps.push(PlanStep::run(format!("sudo {reload}")));
    }
    steps.push(PlanStep::run(format!("sudo {lifecycle}")));
    match service.running {
        Some(true) => {
            if let Some(cmd) = service_managers::start(sm, &service.service) {
                steps.push(PlanStep::run(format!("sudo {cmd}")));
            }
        }
        Some(false) => {
            if let Some(cmd) = service_managers::stop(sm, &service.service) {
                steps.push(PlanStep::run(format!("sudo {cmd}")));
            }
        }
        None => {}
    }
    steps
}

#[cfg(test)]
mod tests {
    use super::service_steps;
    use crate::plan::PlanStep;
    use crate::schema::{ServiceManager, ServiceResource, Target};

    fn service(json: serde_json::Value) -> ServiceResource {
        serde_json::from_value(json).expect("valid service json")
    }

    /// A local target with the given `service_manager` (or none).
    fn target(sm: Option<&str>) -> Target {
        let mut obj = serde_json::Map::new();
        obj.insert("local".to_owned(), serde_json::Value::Bool(true));
        if let Some(sm) = sm {
            obj.insert(
                "service_manager".to_owned(),
                serde_json::Value::String(sm.to_owned()),
            );
        }
        serde_json::from_value(serde_json::Value::Object(obj)).expect("valid target")
    }

    #[test]
    fn enabled_running_service_reloads_enables_then_starts() {
        // daemon-reload leads (so a changed unit takes effect), then enable at boot, then
        // start now.
        let steps = service_steps(
            &service(serde_json::json!({"service": "nginx", "enabled": true, "running": true})),
            &target(Some("systemd")),
        );
        assert_eq!(
            steps,
            vec![
                PlanStep::run("sudo systemctl daemon-reload"),
                PlanStep::run("sudo systemctl enable nginx"),
                PlanStep::run("sudo systemctl start nginx"),
            ]
        );
    }

    #[test]
    fn running_false_stops_after_enabling() {
        let steps = service_steps(
            &service(serde_json::json!({"service": "nginx", "enabled": true, "running": false})),
            &target(Some("systemd")),
        );
        assert_eq!(
            steps,
            vec![
                PlanStep::run("sudo systemctl daemon-reload"),
                PlanStep::run("sudo systemctl enable nginx"),
                PlanStep::run("sudo systemctl stop nginx"),
            ]
        );
    }

    #[test]
    fn disabled_service_with_unmanaged_runtime_only_disables() {
        // `enabled: false` → disable; `running` omitted → runtime unmanaged, so no
        // start/stop step is appended.
        let steps = service_steps(
            &service(serde_json::json!({"service": "nginx", "enabled": false})),
            &target(Some("systemd")),
        );
        assert_eq!(
            steps,
            vec![
                PlanStep::run("sudo systemctl daemon-reload"),
                PlanStep::run("sudo systemctl disable nginx"),
            ]
        );
    }

    #[test]
    fn no_service_manager_is_a_preview_note() {
        // The manager-unset guard fronts everything else (even before `enabled`).
        let steps = service_steps(
            &service(serde_json::json!({"service": "nginx", "enabled": true, "running": true})),
            &target(None),
        );
        assert_eq!(
            steps,
            vec![PlanStep::note("service manager not configured")]
        );
    }

    #[test]
    fn lifecycle_dispatches_per_manager() {
        // systemd and OpenRC emit the real lifecycle through `service_managers`;
        // launchd (no backend) yields the unsupported Note. OpenRC has no
        // daemon-reload (`daemon_reload` is `None`), so its sequence has no leading
        // reload step — just enable then start.
        for sm in [
            ServiceManager::Systemd,
            ServiceManager::Openrc,
            ServiceManager::Launchd,
        ] {
            let steps = service_steps(
                &service(serde_json::json!({"service": "nginx", "enabled": true, "running": true})),
                &target(Some(sm.as_str())),
            );
            match sm {
                ServiceManager::Systemd => assert_eq!(
                    steps,
                    vec![
                        PlanStep::run("sudo systemctl daemon-reload"),
                        PlanStep::run("sudo systemctl enable nginx"),
                        PlanStep::run("sudo systemctl start nginx"),
                    ],
                    "manager {}",
                    sm.as_str()
                ),
                ServiceManager::Openrc => assert_eq!(
                    steps,
                    vec![
                        PlanStep::run("sudo rc-update add nginx default"),
                        PlanStep::run(format!(
                            "sudo sh -c '{}' sh nginx",
                            r#"rc-service "$1" status >/dev/null 2>&1; [ $? -ne 32 ] || rc-service "$1" zap || exit; exec rc-service "$1" start"#
                        )),
                    ],
                    "manager {}",
                    sm.as_str()
                ),
                ServiceManager::Launchd => assert_eq!(
                    steps,
                    vec![PlanStep::note(format!(
                        "unsupported service manager: {}",
                        sm.as_str()
                    ))],
                    "manager {}",
                    sm.as_str()
                ),
            }
        }
    }
}
