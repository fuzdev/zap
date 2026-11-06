//! `verify` step builder — assertion descriptions for the dry-run preview.

use crate::plan::PlanStep;
use crate::schema::{CommandAssertion, PathExistsAssertion, VerifyAssertion, VerifyResource};

/// Preview `Note`s describing a `verify`'s assertions. The executor re-runs the
/// real assertion checks (as the detector does), not these strings.
pub(super) fn verify_steps(verify: &VerifyResource) -> Vec<PlanStep> {
    verify
        .assertions
        .iter()
        .map(|a| PlanStep::note(describe_assertion(a)))
        .collect()
}

/// Human-readable preview of a verify assertion.
fn describe_assertion(assertion: &VerifyAssertion) -> String {
    match assertion {
        VerifyAssertion::PathExists(PathExistsAssertion {
            path,
            file_type,
            mode,
            owner,
            not_empty,
        }) => {
            let mut parts = vec![format!("check {path} exists")];
            if let Some(file_type) = file_type {
                parts.push(format!("({})", file_type.as_str()));
            }
            if let Some(mode) = mode {
                parts.push(format!("mode={mode}"));
            }
            if let Some(owner) = owner {
                parts.push(format!("owner={owner}"));
            }
            if *not_empty {
                parts.push("not_empty".to_owned());
            }
            parts.join(" ")
        }
        VerifyAssertion::Command(CommandAssertion { run, expect }) => expect.as_ref().map_or_else(
            || format!("run: {run}"),
            |expect| format!("run: {run} (expect: {expect})"),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::verify_steps;
    use crate::plan::PlanStep;
    use crate::schema::VerifyResource;

    fn verify(json: serde_json::Value) -> VerifyResource {
        serde_json::from_value(json).expect("valid verify json")
    }

    fn notes(verify: &VerifyResource) -> Vec<String> {
        verify_steps(verify)
            .into_iter()
            .filter_map(|s| match s {
                PlanStep::Note(n) => Some(n),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn verify_emits_only_preview_notes_never_runnable_steps() {
        // The executor re-runs the real assertion checks (the same code the detector
        // runs); the planner only previews them, so no `Run` step is ever emitted.
        let steps = verify_steps(&verify(serde_json::json!({
            "assertions": [
                {"type": "command", "run": "systemctl is-active nginx"},
                {"type": "path_exists", "path": "/etc/nginx/nginx.conf"}
            ]
        })));
        assert!(!steps.iter().any(|s| matches!(s, PlanStep::Run(_))));
        assert_eq!(steps.len(), 2);
    }

    #[test]
    fn path_exists_description_includes_each_present_gate() {
        // Every set optional gate (type / mode / owner / not_empty) joins the clause in
        // order, so a reader sees exactly which constraints the assertion enforces.
        let notes = notes(&verify(serde_json::json!({
            "assertions": [{
                "type": "path_exists", "path": "/etc/app.conf",
                "file_type": "file", "mode": "640", "owner": "app", "not_empty": true
            }]
        })));
        assert_eq!(
            notes,
            vec!["check /etc/app.conf exists (file) mode=640 owner=app not_empty"]
        );
    }

    #[test]
    fn path_exists_description_omits_absent_gates() {
        // A bare path check is just the existence clause — no spurious type/mode/owner.
        let notes = notes(&verify(serde_json::json!({
            "assertions": [{"type": "path_exists", "path": "/srv/data", "file_type": "directory"}]
        })));
        assert_eq!(notes, vec!["check /srv/data exists (directory)"]);
    }

    #[test]
    fn command_description_with_and_without_expect() {
        let notes = notes(&verify(serde_json::json!({
            "assertions": [
                {"type": "command", "run": "node --version"},
                {"type": "command", "run": "node --version", "expect": "v20"}
            ]
        })));
        assert_eq!(
            notes,
            vec![
                "run: node --version".to_owned(),
                "run: node --version (expect: v20)".to_owned()
            ]
        );
    }
}
