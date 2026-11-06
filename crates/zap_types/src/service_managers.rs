//! Service-manager command templates (pure).
//!
//! **systemd** and `OpenRC` (Alpine) are implemented (the supported hosts are
//! Debian/Ubuntu and Alpine); `launchd` has no backend
//! (its arms return `None`). Each is a pure
//! command-string builder, consumed two ways: detection reads `is_active` /
//! `is_enabled`; the planner reads the lifecycle verbs (`enable` / `disable` /
//! `start` / `stop`) and a trigger's (`try_restart` / `try_reload`) to populate
//! `Change.steps`; `deploy` reads `restart`.
//!
//! Each probe (`is_active` / `is_enabled`) has its reading beside it (`read_active` /
//! `read_enabled`), which maps what the manager reports to running / not running (or
//! enabled / not) and **anything else to no answer**: a probe that failed to read — no
//! bus, no permission, a state in between — holds the service rather than reading as
//! stopped or disabled, which would take a `running: false` or `enabled: false` desire
//! as converged on a failed read.
//!
//! Commands carry **no** `sudo` — the planner adds it (detection's queries don't
//! need it). One home for the per-manager knowledge, shared by planner and detector.
//!
//! TODO: as `launchd` appears, add backend arms to these matches (the typed
//! `ServiceManager` enum forces each builder to handle every variant).

use crate::plan::{PlanStep, TriggerKind};
use crate::schema::ServiceManager;

/// Command that reloads the manager's own config to pick up changed unit
/// definitions (systemd `daemon-reload`).
///
/// Returned as the first step in a service change so a subsequent `enable`/`restart`
/// acts on the new unit file, not the stale in-memory one. `None` for a manager that
/// needs no such reload (launchd / openrc) or has no backend.
#[must_use]
pub fn daemon_reload(sm: ServiceManager) -> Option<String> {
    match sm {
        ServiceManager::Systemd => Some("systemctl daemon-reload".to_owned()),
        ServiceManager::Launchd | ServiceManager::Openrc => None,
    }
}

/// Command that reads whether `service` is running under `sm`, its exit status read by
/// [`read_active`]. `None` for a manager without a backend.
///
/// systemd: `is-active --quiet` exits 0 active, 3 inactive or failed, 4 for a unit that
/// doesn't exist. `OpenRC`: `rc-service <svc> status` exits 0 started, 3 stopped, 32
/// crashed (the daemon died; [`start`] clears it), 64 unsupervised (a `supervise-daemon`
/// service whose supervisor died, its daemon possibly still running), and 1 for a script
/// that doesn't exist, which the `--exists` check ahead of it turns into 3 (`--exists`
/// exits 1 for a missing script) — so a 1 is the read failing, not a stopped service.
/// Any other `--exists` exit (127: no `rc-service`) exits 2, which holds. So does 64:
/// neither a `start` (which does nothing) nor a `restart` (which starts a second copy
/// beside an orphaned daemon) is safe to guess.
#[must_use]
pub fn is_active(sm: ServiceManager, service: &str) -> Option<String> {
    match sm {
        ServiceManager::Systemd => Some(format!("systemctl is-active --quiet {service}")),
        ServiceManager::Openrc => Some(format!(
            "rc-service --exists {service}; case $? in 0) ;; 1) exit 3;; *) exit 2;; esac; \
             rc-service {service} status"
        )),
        ServiceManager::Launchd => None,
    }
}

/// Whether [`is_active`]'s exit `code` says the service is running.
///
/// `Some(true)`, `Some(false)` for a service known not to be running (stopped, failed,
/// crashed, or not there), and `None` for any other exit — a read that failed (no bus,
/// no permission, a state in between), which holds rather than reading as stopped.
#[must_use]
pub const fn read_active(sm: ServiceManager, code: i32) -> Option<bool> {
    match (sm, code) {
        (ServiceManager::Systemd | ServiceManager::Openrc, 0) => Some(true),
        (ServiceManager::Systemd, 3 | 4) | (ServiceManager::Openrc, 3 | 32) => Some(false),
        _ => None,
    }
}

/// The states `systemctl is-enabled` prints, exiting non-zero, for a unit that isn't
/// enabled. Any other non-zero exit is a read that failed.
const SYSTEMD_NOT_ENABLED: [&str; 6] = [
    "disabled",
    "masked",
    "masked-runtime",
    "linked",
    "linked-runtime",
    "not-found",
];

/// Command that reads whether `service` is enabled at boot under `sm`, read by
/// [`read_enabled`]. `None` for a manager without a backend.
///
/// systemd: `is-enabled` exits 0 for a unit enabled in any form (enabled, static,
/// indirect, alias, …) and prints its state. `OpenRC` reads the runlevel symlinks
/// directly — enabled in **any** runlevel, as `rc-update add <svc> <runlevel>` makes it
/// — exiting 0 enabled, 1 not, 2 when `/etc/runlevels` can't be read. `-e` follows the
/// link, so a dangling enable re-converges.
#[must_use]
pub fn is_enabled(sm: ServiceManager, service: &str) -> Option<String> {
    match sm {
        ServiceManager::Systemd => Some(format!("systemctl is-enabled {service}")),
        ServiceManager::Openrc => Some(format!(
            "[ -d /etc/runlevels ] && [ -r /etc/runlevels ] && [ -x /etc/runlevels ] || exit 2; \
             for r in /etc/runlevels/*/{service}; do [ -e \"$r\" ] && exit 0; done; exit 1"
        )),
        ServiceManager::Launchd => None,
    }
}

/// Whether [`is_enabled`]'s exit `code`, `stdout`, and `stderr` say the service is
/// enabled.
///
/// `Some(true)`, `Some(false)` for one known not to be (systemd printing a
/// `SYSTEMD_NOT_ENABLED` state, `OpenRC` exiting 1), and `None` for anything else — a
/// read that failed, which holds rather than reading as disabled.
///
/// Older systemd (before it printed `not-found`) reads a unit that doesn't exist as an
/// error: nothing on stdout, exit 1, and `Failed to get unit file state for <unit>: No
/// such file or directory` on stderr. That is a missing unit, not a failed read, so it is
/// not enabled — holding it would hold the unit file that creates it, which would then
/// never converge.
#[must_use]
pub fn read_enabled(sm: ServiceManager, code: i32, stdout: &str, stderr: &str) -> Option<bool> {
    match (sm, code) {
        (ServiceManager::Systemd | ServiceManager::Openrc, 0) => Some(true),
        (ServiceManager::Systemd, 1) if stdout.trim().is_empty() && unit_missing(stderr) => {
            Some(false)
        }
        (ServiceManager::Systemd, _) => {
            let state = stdout.lines().next().unwrap_or_default().trim();
            SYSTEMD_NOT_ENABLED.contains(&state).then_some(false)
        }
        (ServiceManager::Openrc, 1) => Some(false),
        _ => None,
    }
}

/// Whether older systemd's `is-enabled` `stderr` says the unit file doesn't exist.
fn unit_missing(stderr: &str) -> bool {
    stderr.lines().any(|line| {
        line.starts_with("Failed to get unit file state for ")
            && (line.ends_with(": No such file or directory") || line.ends_with(" not found."))
    })
}

/// Command that enables `service` at boot under `sm`. `None` for a manager without
/// a backend.
#[must_use]
pub fn enable(sm: ServiceManager, service: &str) -> Option<String> {
    match sm {
        ServiceManager::Systemd => Some(format!("systemctl enable {service}")),
        ServiceManager::Openrc => Some(format!("rc-update add {service} default")),
        ServiceManager::Launchd => None,
    }
}

/// Command that disables `service` at boot under `sm`. `None` for a manager without
/// a backend.
///
/// `OpenRC` removes it from each runlevel it is in — the runlevels [`is_enabled`] reads
/// — and from no other: `rc-update del` exits non-zero for a runlevel the service isn't
/// in, so deleting from a fixed one (or `-a`, every one) would fail the step for a
/// service that was never enabled there.
#[must_use]
pub fn disable(sm: ServiceManager, service: &str) -> Option<String> {
    match sm {
        ServiceManager::Systemd => Some(format!("systemctl disable {service}")),
        ServiceManager::Openrc => Some(format!(
            "sh -c {} sh {service}",
            crate::shell::single_quote(OPENRC_DISABLE)
        )),
        ServiceManager::Launchd => None,
    }
}

/// The script [`disable`] runs under `OpenRC`, the service name its `$1`: `rc-update del`
/// from each runlevel holding an entry for it, a dangling link included.
const OPENRC_DISABLE: &str = r#"for r in /etc/runlevels/*/"$1"; do [ -e "$r" ] || [ -L "$r" ] || continue; l=${r%/*}; rc-update del "$1" "${l##*/}" || exit; done"#;

/// Command that starts `service` now under `sm`. `None` for a manager without a
/// backend.
///
/// `OpenRC` first clears a crashed state, the one [`is_active`] reads as exit 32 (the
/// daemon died while the service is still marked started): a plain `start` of a crashed
/// service warns that it has already been started, exits 0, and leaves it crashed.
/// `rc-service <svc> zap` resets it to stopped, and the `start` after it runs the daemon.
/// The status check, the reset, and the start run as one `sh -c`, so the step's single
/// `sudo` covers all three; a failed reset fails the step without starting.
#[must_use]
pub fn start(sm: ServiceManager, service: &str) -> Option<String> {
    match sm {
        ServiceManager::Systemd => Some(format!("systemctl start {service}")),
        ServiceManager::Openrc => Some(format!(
            "sh -c {} sh {service}",
            crate::shell::single_quote(OPENRC_START)
        )),
        ServiceManager::Launchd => None,
    }
}

/// The script [`start`] runs under `OpenRC`, the service name its `$1`: `rc-service zap`
/// when the status reads crashed (32), then `rc-service start`.
const OPENRC_START: &str = r#"rc-service "$1" status >/dev/null 2>&1; [ $? -ne 32 ] || rc-service "$1" zap || exit; exec rc-service "$1" start"#;

/// Command that stops `service` now under `sm`. `None` for a manager without a
/// backend.
#[must_use]
pub fn stop(sm: ServiceManager, service: &str) -> Option<String> {
    match sm {
        ServiceManager::Systemd => Some(format!("systemctl stop {service}")),
        ServiceManager::Openrc => Some(format!("rc-service {service} stop")),
        ServiceManager::Launchd => None,
    }
}

/// Command that restarts `service` under `sm`. `None` for a manager without a
/// backend.
#[must_use]
pub fn restart(sm: ServiceManager, service: &str) -> Option<String> {
    match sm {
        ServiceManager::Systemd => Some(format!("systemctl restart {service}")),
        ServiceManager::Openrc => Some(format!("rc-service {service} restart")),
        ServiceManager::Launchd => None,
    }
}

/// Command that restarts `service` under `sm` **only if it is running** — a trigger's
/// restart. `None` for a manager without a backend.
///
/// A trigger owes a running service the new state; a stopped one picks it up when it
/// next starts, so starting it here would run what the config doesn't ask to run (a
/// service whose binary isn't there yet, on a first deploy). systemd `try-restart` and
/// `OpenRC`'s `rc-service --ifstarted` both exit 0 without acting on a stopped service.
#[must_use]
pub fn try_restart(sm: ServiceManager, service: &str) -> Option<String> {
    match sm {
        ServiceManager::Systemd => Some(format!("systemctl try-restart {service}")),
        ServiceManager::Openrc => Some(format!("rc-service --ifstarted {service} restart")),
        ServiceManager::Launchd => None,
    }
}

/// Command that reloads `service` under `sm` **only if it is running** — a trigger's
/// reload, which, like [`try_restart`], leaves a stopped service alone. `None` for a
/// manager without a backend.
///
/// systemd decides reload-vs-restart from the unit itself: `try-reload-or-restart`
/// restarts a unit that declares no `ExecReload`, and a unit that *has* one but whose
/// reload command fails leaves the running service alone and fails the job.
///
/// `OpenRC` has no equivalent verb and no way to ask an init script whether it defines
/// `reload`, so this arm reloads and propagates the result. It deliberately does **not**
/// fall back to `restart` on a failed reload: from the shell there is nothing to
/// distinguish "this script has no reload action" from "the daemon rejected the new
/// config", and restarting on the second is how a rejected config becomes an outage —
/// reload leaves the old workers serving, restart stops them and then fails to come
/// back. A service that genuinely cannot reload belongs in `restart_on`, not
/// `reload_on`; that choice is the author's to make, not something to infer from an
/// exit code that means two different things.
#[must_use]
pub fn try_reload(sm: ServiceManager, service: &str) -> Option<String> {
    match sm {
        ServiceManager::Systemd => Some(format!("systemctl try-reload-or-restart {service}")),
        ServiceManager::Openrc => Some(format!("rc-service --ifstarted {service} reload")),
        ServiceManager::Launchd => None,
    }
}

/// Restart command for an *optional* manager.
///
/// `Some` when the target declares a manager with a restart verb, `None` when it
/// declares none or the declared one (`launchd`) has no backend. No `sudo` — the
/// caller prepends it. No fallback is fabricated. The undeclared case can't reach a planner — the
/// structural gate (`validate::missing_service_manager`) rejects service intent on a
/// manager-less target — and the unsupported case plans a visible
/// [`manager_step`] `Note` in place of the verb, so an OpenRC-or-nothing host never
/// receives a guessed `systemctl`. `deploy`'s post-swap restart routes through here
/// rather than re-spelling the verb, so it can't drift from [`restart`].
#[must_use]
pub fn restart_for(sm: Option<ServiceManager>, service: &str) -> Option<String> {
    sm.and_then(|sm| restart(sm, service))
}

/// A trigger's command for an *optional* manager: [`try_restart`] or [`try_reload`],
/// by `kind`. No `sudo`; no fabricated fallback (as [`restart_for`]).
#[must_use]
pub fn trigger_for(sm: Option<ServiceManager>, kind: TriggerKind, service: &str) -> Option<String> {
    sm.and_then(|sm| match kind {
        TriggerKind::Restart => try_restart(sm, service),
        TriggerKind::Reload => try_reload(sm, service),
    })
}

/// A manager verb as a plan step.
///
/// The `sudo`-prefixed command, or — when the target can't honor it — the same
/// unsupported-manager `Note` the `service` step builder emits, so the gap is visible
/// in the plan instead of a guessed command.
#[must_use]
pub fn manager_step(
    command: Option<String>,
    sm: Option<ServiceManager>,
    verb: &str,
    service: &str,
) -> PlanStep {
    command.map_or_else(
        || PlanStep::note(unsupported_note(sm, verb, service)),
        |cmd| PlanStep::run(format!("sudo {cmd}")),
    )
}

/// The `Note` text standing in for a manager verb the target can't honor.
#[must_use]
fn unsupported_note(sm: Option<ServiceManager>, verb: &str, service: &str) -> String {
    sm.map_or_else(
        || format!("service manager not configured (no `{verb}` for `{service}`)"),
        |sm| {
            format!(
                "unsupported service manager: {} (no `{verb}` for `{service}`)",
                sm.as_str()
            )
        },
    )
}

#[cfg(test)]
mod tests {
    use super::{manager_step, restart_for, trigger_for};
    use crate::plan::{PlanStep, TriggerKind};
    use crate::schema::ServiceManager;

    #[test]
    fn restart_for_routes_per_manager_and_never_fabricates() {
        assert_eq!(
            restart_for(Some(ServiceManager::Systemd), "nginx").as_deref(),
            Some("systemctl restart nginx")
        );
        assert_eq!(
            restart_for(Some(ServiceManager::Openrc), "nginx").as_deref(),
            Some("rc-service nginx restart")
        );
        // No declared manager, or one with no restart verb: nothing is guessed.
        assert_eq!(restart_for(None, "nginx"), None);
        assert_eq!(restart_for(Some(ServiceManager::Launchd), "nginx"), None);
    }

    #[test]
    fn a_trigger_acts_only_on_a_running_service() {
        let trigger = |sm, kind| trigger_for(Some(sm), kind, "nginx");
        assert_eq!(
            trigger(ServiceManager::Systemd, TriggerKind::Restart).as_deref(),
            Some("systemctl try-restart nginx")
        );
        assert_eq!(
            trigger(ServiceManager::Systemd, TriggerKind::Reload).as_deref(),
            Some("systemctl try-reload-or-restart nginx")
        );
        assert_eq!(
            trigger(ServiceManager::Openrc, TriggerKind::Restart).as_deref(),
            Some("rc-service --ifstarted nginx restart")
        );
        // OpenRC reloads and propagates the result — no restart fallback, which would
        // turn a config the daemon rejected into a stop it can't come back from.
        assert_eq!(
            trigger(ServiceManager::Openrc, TriggerKind::Reload).as_deref(),
            Some("rc-service --ifstarted nginx reload")
        );
        assert_eq!(trigger(ServiceManager::Launchd, TriggerKind::Restart), None);
        assert_eq!(trigger_for(None, TriggerKind::Reload, "nginx"), None);
    }

    /// `OpenRC`'s disable deletes from each runlevel the service is in and from no other:
    /// a stub `rc-update` that fails for a runlevel without the entry, as the real one
    /// does, sees only the runlevels holding it, and a service in none succeeds.
    #[test]
    fn openrc_disable_deletes_only_from_the_runlevels_holding_the_service() {
        use std::os::unix::fs::PermissionsExt as _;

        let root = std::env::temp_dir().join(format!("zap-openrc-disable-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let levels = root.join("runlevels");
        for level in ["boot", "default", "shutdown"] {
            std::fs::create_dir_all(levels.join(level)).unwrap();
        }
        std::os::unix::fs::symlink("/nonexistent", levels.join("boot/nginx")).unwrap();
        std::os::unix::fs::symlink("/nonexistent", levels.join("default/nginx")).unwrap();
        let bin = root.join("bin");
        std::fs::create_dir_all(&bin).unwrap();
        let stub = bin.join("rc-update");
        std::fs::write(
            &stub,
            format!(
                "#!/bin/sh\necho \"$*\" >>{log}\nrm {levels}/\"$3\"/\"$2\" 2>/dev/null || exit 1\n",
                log = root.join("log").display(),
                levels = levels.display(),
            ),
        )
        .unwrap();
        std::fs::set_permissions(&stub, std::fs::Permissions::from_mode(0o755)).unwrap();
        let script = super::OPENRC_DISABLE.replace("/etc/runlevels", &levels.to_string_lossy());
        let run = |service: &str| {
            std::process::Command::new("sh")
                .args(["-c", &script, "sh", service])
                .env(
                    "PATH",
                    format!("{}:{}", bin.display(), std::env::var("PATH").unwrap()),
                )
                .status()
                .unwrap()
                .success()
        };
        assert!(run("nginx"));
        assert!(run("sshd"));
        let log = std::fs::read_to_string(root.join("log")).unwrap();
        std::fs::remove_dir_all(&root).unwrap();
        assert_eq!(log, "del nginx boot\ndel nginx default\n");
        assert_eq!(
            super::disable(ServiceManager::Openrc, "nginx").unwrap(),
            format!(
                "sh -c '{}' sh nginx",
                super::OPENRC_DISABLE.replace('\'', r"'\''")
            )
        );
    }

    /// The `OpenRC` running probe in a real shell: a missing script reads stopped (3), but
    /// a host without `rc-service` exits 2, which holds, never stopped.
    #[test]
    fn openrc_is_active_holds_without_rc_service() {
        use std::os::unix::fs::PermissionsExt as _;

        let root = std::env::temp_dir().join(format!("zap-openrc-active-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let probe = super::is_active(ServiceManager::Openrc, "nginx").unwrap();
        let run = |path: &std::path::Path| {
            std::process::Command::new("/bin/sh")
                .args(["-c", &probe])
                .env("PATH", path)
                .status()
                .unwrap()
                .code()
        };
        assert_eq!(run(&root), Some(2), "no rc-service");
        let stub = root.join("rc-service");
        // `--exists` exits 1 for a script that isn't there, as `OpenRC`'s does.
        std::fs::write(
            &stub,
            "#!/bin/sh\n[ \"$1\" = --exists ] && exit 1\nexit 0\n",
        )
        .unwrap();
        std::fs::set_permissions(&stub, std::fs::Permissions::from_mode(0o755)).unwrap();
        let missing = run(&root);
        std::fs::remove_dir_all(&root).unwrap();
        assert_eq!(missing, Some(3), "no such script");
        assert_eq!(super::read_active(ServiceManager::Openrc, 2), None);
        assert_eq!(super::read_active(ServiceManager::Openrc, 3), Some(false));
    }

    /// The `OpenRC` start in a real shell: a crashed service (status 32) is reset with
    /// `zap` before `start`, any other status starts directly, and a failed reset fails
    /// the step without starting.
    #[test]
    fn openrc_start_resets_a_crashed_service_first() {
        use std::os::unix::fs::PermissionsExt as _;

        let root = std::env::temp_dir().join(format!("zap-openrc-start-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let bin = root.join("bin");
        std::fs::create_dir_all(&bin).unwrap();
        let log = root.join("log");
        let stub = bin.join("rc-service");
        // `status` exits `$STATUS`, `zap` exits `$ZAP_EXIT`, and `start` exits 7, so the
        // step's exit shows which command it ended on.
        std::fs::write(
            &stub,
            format!(
                "#!/bin/sh\necho \"$*\" >>{log}\ncase $2 in status) exit \"$STATUS\";; \
                 zap) exit \"$ZAP_EXIT\";; start) exit 7;; esac\nexit 1\n",
                log = log.display(),
            ),
        )
        .unwrap();
        std::fs::set_permissions(&stub, std::fs::Permissions::from_mode(0o755)).unwrap();
        let command = super::start(ServiceManager::Openrc, "nginx").unwrap();
        let run = |status: i32, zap_exit: i32| {
            let _ = std::fs::remove_file(&log);
            let code = std::process::Command::new("/bin/sh")
                .args(["-c", &command])
                .env(
                    "PATH",
                    format!("{}:{}", bin.display(), std::env::var("PATH").unwrap()),
                )
                .env("STATUS", status.to_string())
                .env("ZAP_EXIT", zap_exit.to_string())
                .status()
                .unwrap()
                .code();
            (code, std::fs::read_to_string(&log).unwrap())
        };
        let crashed = run(32, 0);
        let crashed_reset_fails = run(32, 5);
        let started = run(0, 0);
        let stopped = run(3, 0);
        std::fs::remove_dir_all(&root).unwrap();
        assert_eq!(
            crashed,
            (Some(7), "nginx status\nnginx zap\nnginx start\n".to_owned())
        );
        assert_eq!(
            crashed_reset_fails,
            (Some(5), "nginx status\nnginx zap\n".to_owned())
        );
        assert_eq!(started, (Some(7), "nginx status\nnginx start\n".to_owned()));
        assert_eq!(stopped, (Some(7), "nginx status\nnginx start\n".to_owned()));
        assert_eq!(
            command,
            format!(
                "sh -c '{}' sh nginx",
                super::OPENRC_START.replace('\'', r"'\''")
            )
        );
    }

    #[test]
    fn manager_step_runs_the_verb_or_notes_the_gap() {
        assert_eq!(
            manager_step(
                Some("systemctl restart nginx".to_owned()),
                Some(ServiceManager::Systemd),
                "restart",
                "nginx"
            ),
            PlanStep::run("sudo systemctl restart nginx")
        );
        assert_eq!(
            manager_step(None, Some(ServiceManager::Launchd), "restart", "nginx"),
            PlanStep::note("unsupported service manager: launchd (no `restart` for `nginx`)")
        );
        assert_eq!(
            manager_step(None, None, "reload", "nginx"),
            PlanStep::note("service manager not configured (no `reload` for `nginx`)")
        );
    }
}
