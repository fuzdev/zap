//! `pipeline` step builder — one command per step.

use crate::plan::PlanStep;
use crate::schema::PipelineResource;

// TODO: a step's `cwd` / `env` / `depends_on` are rejected at `zap plan` by the
// structural gate (not silently dropped), pending the scheduler that will thread them.
/// One `run` command per `pipeline` step, in declared order. A step's `id` and `name`
/// are not in its command: the plan's render prints them from the change's `desired`.
pub(super) fn pipeline_steps(pipeline: &PipelineResource) -> Vec<PlanStep> {
    pipeline
        .steps
        .iter()
        .map(|step| PlanStep::run(step.run.as_inert()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::pipeline_steps;
    use crate::plan::PlanStep;
    use crate::schema::PipelineResource;

    fn pipeline(json: serde_json::Value) -> PipelineResource {
        serde_json::from_value(json).expect("valid pipeline json")
    }

    #[test]
    fn one_run_command_per_step_in_declared_order() {
        let steps = pipeline_steps(&pipeline(serde_json::json!({
            "steps": [
                {"id": "fetch", "run": "git fetch --all"},
                {"id": "build", "run": "make"},
                {"id": "install", "run": "make install"}
            ]
        })));
        assert_eq!(
            steps,
            vec![
                PlanStep::run("git fetch --all"),
                PlanStep::run("make"),
                PlanStep::run("make install"),
            ]
        );
    }

    #[test]
    fn step_name_is_dropped_only_run_becomes_the_command() {
        // A step's `name` is rendered from the change's `desired` — it never enters the
        // emitted command, which is the step's `run` verbatim.
        let steps = pipeline_steps(&pipeline(serde_json::json!({
            "steps": [{"id": "s1", "name": "Compile the world", "run": "cargo build --release"}]
        })));
        assert_eq!(steps, vec![PlanStep::run("cargo build --release")]);
    }

    #[test]
    fn empty_pipeline_emits_no_steps() {
        let steps = pipeline_steps(&pipeline(serde_json::json!({"steps": []})));
        assert!(steps.is_empty());
    }
}
