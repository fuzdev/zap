//! `script` step builder — the resource's own `run` command, verbatim.

use crate::plan::PlanStep;
use crate::schema::ScriptResource;

/// The single `run` command a `script` executes. Its `cwd` and `env` aren't part of
/// the step: execution reads them from the change's desired resource, which the plan
/// carries and hashes whole.
pub(super) fn script_steps(script: &ScriptResource) -> Vec<PlanStep> {
    vec![PlanStep::run(script.run.as_inert())]
}

#[cfg(test)]
mod tests {
    use super::script_steps;
    use crate::plan::PlanStep;
    use crate::schema::ScriptResource;

    fn script(json: serde_json::Value) -> ScriptResource {
        serde_json::from_value(json).expect("valid script json")
    }

    #[test]
    fn emits_the_run_command_verbatim() {
        let steps = script_steps(&script(serde_json::json!({
            "check": "test -f /opt/app/ready",
            "run": "mkdir -p /opt/app && touch /opt/app/ready"
        })));
        assert_eq!(
            steps,
            vec![PlanStep::run("mkdir -p /opt/app && touch /opt/app/ready")]
        );
    }

    #[test]
    fn run_with_shell_metacharacters_is_passed_through_untouched() {
        // `script.run` is operator-authored and runs verbatim (the same `sh -c` trust
        // model as the config eval): the planner neither quotes nor escapes it, so a
        // pipe / redirect / glob survives exactly as written.
        let steps = script_steps(&script(serde_json::json!({
            "check": "false",
            "run": "echo \"$HOME\" | tee /tmp/x && rm -rf /tmp/y/*"
        })));
        assert_eq!(
            steps,
            vec![PlanStep::run(
                "echo \"$HOME\" | tee /tmp/x && rm -rf /tmp/y/*"
            )]
        );
    }

    #[test]
    fn check_cwd_and_env_are_not_part_of_the_step() {
        // `check` drives detection; `cwd` / `env` shape how the check and the step run,
        // read from the desired resource — only `run` becomes the step's command.
        let steps = script_steps(&script(serde_json::json!({
            "check": "test -d /srv",
            "run": "install -d /srv",
            "cwd": "/tmp",
            "env": {"APP_ENV": "production"}
        })));
        assert_eq!(steps, vec![PlanStep::run("install -d /srv")]);
    }
}
