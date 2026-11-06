//! `build` step builder — the build command as the dry-run preview.

use crate::plan::PlanStep;
use crate::schema::BuildResource;

/// The `build` command, as the preview. Execution wraps it with source resolve +
/// extract + the provenance-sidecar write (those aren't shell steps the planner
/// bakes — like `file remote`'s fetch/extract).
pub(super) fn build_steps(build: &BuildResource) -> Vec<PlanStep> {
    vec![PlanStep::run(build.run.as_inert())]
}

#[cfg(test)]
mod tests {
    use super::build_steps;
    use crate::plan::PlanStep;
    use crate::schema::BuildResource;

    fn build(json: serde_json::Value) -> BuildResource {
        serde_json::from_value(json).expect("valid build json")
    }

    #[test]
    fn emits_only_the_build_command() {
        // The single baked step is `run`, verbatim. Source resolve / verify / extract /
        // the provenance-sidecar write are execution-time IO (zap_core), not planner
        // steps — so `$HOME` stays for the target shell, unquoted and unexpanded here.
        let steps = build_steps(&build(serde_json::json!({
            "source": {
                "type": "remote",
                "url": "https://h/ghostty.tar.gz",
                "extract": {"type": "tar.gz", "strip_components": 1}
            },
            "run": "zig build -p $HOME/.local -Doptimize=ReleaseFast",
            "output": "/opt/ghostty/bin/ghostty"
        })));
        assert_eq!(
            steps,
            vec![PlanStep::run(
                "zig build -p $HOME/.local -Doptimize=ReleaseFast"
            )]
        );
    }

    #[test]
    fn source_extract_and_output_do_not_appear_in_the_step() {
        // `extract` / `strip_components` / `output` / `cwd` / `env` shape execution (the
        // target-side `tar --strip-components=N` lives in zap_core), never the planner's
        // step — which is the build command and nothing else.
        let steps = build_steps(&build(serde_json::json!({
            "source": {
                "type": "remote",
                "url": "https://h/src.tar.xz",
                "extract": {"type": "tar.xz"},
                "blake3": "a".repeat(64)
            },
            "run": "make install",
            "output": "/usr/local/bin/tool",
            "cwd": "/tmp/src",
            "env": {"CC": "clang"}
        })));
        assert_eq!(steps, vec![PlanStep::run("make install")]);
    }
}
