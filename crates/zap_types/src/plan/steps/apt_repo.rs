//! `apt_repo` step builder — write the `signed-by` source line, refresh the package
//! index. The signing key is zap's own write, ahead of these steps.

use crate::plan::{PlanStep, PutAs, PutCommand, PutMode, PutProducer, PutSource, PutStep};
use crate::put::PutCheck;
use crate::scalar::Mode;
use crate::schema::{AptRepoResource, ResourceId, inject_signed_by};

/// Steps to set up an `apt_repo`: write the sources-list with `signed-by` injected (and
/// `/etc/os-release` sourced so a distro-codename-templated source line resolves at
/// apply time — the same line the detector compares), then `apt-get update`.
///
/// The signing key is installed before these run, by `zap_core` and not by a step:
/// zap fetches it on the operator's machine, checks its blake3 against the pin the plan
/// holds (`key_blake3`, a tracked key's lock pin folded in), and installs those bytes
/// whole through the put script — staged beside the key path, checked against their
/// SHA-512, renamed over it — so the live key is replaced only by the pinned bytes, and
/// a fetch that doesn't match them changes nothing (`Change::native_commands` names the
/// script). A failed install fails the change before the list is written.
///
/// The list is installed whole by a [`PutStep`] at mode `644` — staged, checked, renamed
/// — so a run cut short or a full disk leaves the old list or none, never part of a
/// line `apt` would then refuse to parse. Its content is what the source line prints on
/// the target, where the distro codename in it expands.
pub(super) fn apt_repo_steps(repo: &AptRepoResource, resource_id: &ResourceId) -> Vec<PlanStep> {
    let (key_path, list_file) = crate::observe::apt_repo::paths(&resource_id.0, repo);
    vec![
        // The source line stays inside double quotes — unquoted by design: a distro-
        // codename-templated source line (`$VERSION_CODENAME` from `/etc/os-release`) must
        // expand at apply time. The producer prints it through `apt_source_command`, the
        // one definition the `apt_repo` detector also builds its expected line from, so
        // probe↔mutation parity is structural.
        PlanStep::Put(PutStep {
            path: list_file,
            run_as: PutAs::Root,
            check: PutCheck::None,
            source: PutSource::Command(PutCommand {
                mode: PutMode::Set(Mode::fixed("644")),
                producer: PutProducer::AptSourceLine {
                    line: inject_signed_by(&repo.source, &key_path),
                },
            }),
        }),
        PlanStep::run("sudo apt-get update"),
    ]
}

#[cfg(test)]
mod tests {
    use super::apt_repo_steps;
    use crate::observe::Query;
    use crate::plan::{
        PlanStep, PutAs, PutCommand, PutMode, PutProducer, PutSource, PutStep, StepExecution,
    };
    use crate::put::{FileAttrs, PutCheck, RunAs, put_text_step};
    use crate::scalar::Mode;
    use crate::schema::{AptRepoResource, ResourceId, apt_source_command, inject_signed_by};

    /// The shell text each step runs.
    fn runs(steps: &[PlanStep]) -> Vec<String> {
        steps
            .iter()
            .filter_map(PlanStep::execution)
            .map(|execution| execution.text().to_owned())
            .collect()
    }

    fn repo(json: serde_json::Value) -> AptRepoResource {
        serde_json::from_value(json).expect("valid apt_repo json")
    }

    /// The command snippets among a detector's reads.
    fn snippets(queries: &[Query]) -> Vec<&str> {
        queries
            .iter()
            .filter_map(|query| match query {
                Query::Command { snippet, .. } => Some(snippet.as_str()),
                Query::Path { .. } => None,
            })
            .collect()
    }

    /// The list the step installs is what the detector's own read prints: one command,
    /// built once, is the detector's query and the step's producer.
    #[test]
    fn the_list_is_produced_by_the_detectors_read_of_the_line() {
        let declared = repo(serde_json::json!({
            "key_url": "https://example.com/key.asc",
            "source": "deb https://example.com/apt $VERSION_CODENAME main",
            "key_path": "/k/it's.asc",
        }));
        let command = apt_source_command(&inject_signed_by(&declared.source, "/k/it's.asc"));
        let queries = crate::observe::apt_repo::queries("pgdg", &declared);
        assert_eq!(snippets(&queries), [command.as_str()]);
        let steps = apt_repo_steps(&declared, &ResourceId("pgdg".to_owned()));
        assert!(
            runs(&steps)[0].starts_with(&format!("zap_c=$({command} && echo .) || exit 1; ")),
            "{}",
            runs(&steps)[0]
        );
    }

    #[test]
    fn writes_signed_by_line_to_default_paths() {
        let steps = apt_repo_steps(
            &repo(serde_json::json!({
                "key_url": "https://example.com/key.asc",
                "source": "deb https://example.com/apt stable main"
            })),
            &ResourceId("pgdg".to_owned()),
        );
        // The list is what the resolved source line prints, put whole at `644`: the step
        // holds the line, with `signed-by` injected, and names the command that prints it.
        let line =
            "deb [signed-by=/usr/share/keyrings/pgdg.asc] https://example.com/apt stable main";
        let producer = ". /etc/os-release && printf '%s\\n' \"deb [signed-by=/usr/share/keyrings/pgdg.asc] \
                        https://example.com/apt stable main\"";
        assert_eq!(
            steps[0],
            PlanStep::Put(PutStep {
                path: "/etc/apt/sources.list.d/pgdg.list".to_owned(),
                run_as: PutAs::Root,
                check: PutCheck::None,
                source: PutSource::Command(PutCommand {
                    mode: PutMode::Set(Mode::new("644").unwrap()),
                    producer: PutProducer::AptSourceLine {
                        line: line.to_owned(),
                    },
                }),
            })
        );
        assert_eq!(
            steps[0].execution(),
            Some(StepExecution::Command(put_text_step(
                producer,
                RunAs::Root,
                "/etc/apt/sources.list.d/pgdg.list",
                FileAttrs::mode("644"),
                PutCheck::None,
            )))
        );
        let runs = runs(&steps);
        // Nothing writes the list in place.
        assert!(!runs.iter().any(|c| c.contains("tee ")));
        // No step fetches the key: zap installs the pinned bytes itself, ahead of these.
        assert!(
            !runs
                .iter()
                .any(|c| c.contains("curl") || c.contains("keyrings/pgdg.asc'"))
        );
        assert_eq!(runs[1], "sudo apt-get update");
        assert!(!steps.iter().any(|s| matches!(s, PlanStep::Note(_))));
    }

    #[test]
    fn honors_explicit_key_and_list_paths() {
        let steps = apt_repo_steps(
            &repo(serde_json::json!({
                "key_url": "https://example.com/key.asc",
                "source": "deb https://example.com/apt stable main",
                "key_path": "/custom/key.gpg",
                "list_file": "/custom/repo.list"
            })),
            &ResourceId("pgdg".to_owned()),
        );
        assert!(runs(&steps).iter().any(|c| {
            c.contains("signed-by=/custom/key.gpg")
                && c.ends_with(" sh '/custom/repo.list' '644' '' '' ''")
        }));
    }
}
