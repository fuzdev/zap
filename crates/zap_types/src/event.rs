//! Event taxonomy + run summary — the one schema shared by the CLI render and
//! (later) the rolling run log.
//!
//! These *shapes* are pure; emission (and the wall-clock that stamps them) is
//! `zap_core`. [`ChangeOutcome`] is the execution-state sibling of `plan::Change`,
//! keyed by the same `resource_id` and kept out of the plan fact. A run's
//! [`RunSummary`] is *derived* from the outcome vector rather than tallied by hand.

use serde::{Deserialize, Serialize};

use crate::error_code::ErrorCode;
use crate::plan::ChangeAction;
use crate::schema::{ResourceId, ResourceType};

/// One structured event in a run's lifecycle — the **single schema** shared by the
/// stdout JSON-lines stream and (later) the rolling run log.
///
/// Emitted live as `zap apply --wetrun` executes (the "structured events instead of
/// log soup" promise), not just batched into the final report. Pure data: the
/// emission (and the wall-clock that would stamp a log) is `zap_core`'s. The
/// per-change arms mirror [`ChangeOutcome`]; [`Event::from_outcome`] is the one
/// mapping, so the stream and the [`RunSummary`]-bearing report can't disagree on
/// what an outcome means.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum Event {
    /// A run began — emitted once, before any change.
    RunStarted {
        /// Target location label (`local`, or a host).
        target: String,
        /// Whether changes are actually executed (`--wetrun`) or only previewed.
        wetrun: bool,
        /// Content address of the whole plan.
        plan_hash: String,
        /// Total changes in the plan.
        total: u32,
    },
    /// A change is about to run — emitted only for changes actually attempted (not
    /// for ones skipped after an earlier failure).
    ChangeStarted {
        /// Which change.
        resource_id: ResourceId,
        /// Create or update.
        action: ChangeAction,
        /// The resource kind (`directory`, `service`, …).
        kind: ResourceType,
    },
    /// A change ran to completion (mirrors [`ChangeOutcome::Completed`]).
    ChangeCompleted {
        /// Which change.
        resource_id: ResourceId,
        /// Captured stdout / a short summary of what was done.
        output: String,
    },
    /// A change failed (mirrors [`ChangeOutcome::Failed`]).
    ChangeFailed {
        /// Which change.
        resource_id: ResourceId,
        /// Why it failed.
        error: String,
        /// Triage category (retry / fix-config / fix-code), for machine consumers.
        code: ErrorCode,
    },
    /// A change was skipped after an earlier failure (mirrors
    /// [`ChangeOutcome::Skipped`]).
    ChangeSkipped {
        /// Which change.
        resource_id: ResourceId,
        /// Why it was skipped.
        reason: String,
    },
    /// A named imperative step is about to run — the step counterpart to
    /// [`Event::ChangeStarted`], for `deploy` (and, later, the `pipeline` resource).
    /// Steps aren't resource mutations, so they carry no `action` / `kind`.
    StepStarted {
        /// Step identifier within the run.
        step: String,
        /// Human-readable step label.
        name: String,
    },
    /// A step ran to completion (mirrors [`StepOutcome::Completed`]).
    StepCompleted {
        /// Which step.
        step: String,
        /// Captured stdout / a short summary.
        output: String,
    },
    /// A step failed (mirrors [`StepOutcome::Failed`]).
    StepFailed {
        /// Which step.
        step: String,
        /// Why it failed.
        error: String,
    },
    /// A step was skipped after an earlier failure (mirrors [`StepOutcome::Skipped`]).
    StepSkipped {
        /// Which step.
        step: String,
        /// Why it was skipped.
        reason: String,
    },
    /// The run finished — emitted once, with the derived counts.
    RunFinished {
        /// The run's tallied outcomes.
        summary: RunSummary,
    },
}

impl Event {
    /// This event with every free-text field passed through `f`: the target label, a
    /// step's name, and what a change or a step printed, failed with, or was skipped
    /// for. The closed-set and structural fields — the event tag, a resource or step
    /// id, the action, kind and error code, the plan hash, the counts — are kept as
    /// they are.
    ///
    /// How an event is masked for the stream: a typed map with no serialized form in
    /// between, so there is nothing that can fail and hand back the event unmapped, and
    /// a field added to an event doesn't compile until it is placed here.
    #[must_use]
    pub fn map_text(&self, f: impl Fn(&str) -> String) -> Self {
        match self {
            Self::RunStarted {
                target,
                wetrun,
                plan_hash,
                total,
            } => Self::RunStarted {
                target: f(target),
                wetrun: *wetrun,
                plan_hash: plan_hash.clone(),
                total: *total,
            },
            Self::ChangeStarted {
                resource_id,
                action,
                kind,
            } => Self::ChangeStarted {
                resource_id: resource_id.clone(),
                action: *action,
                kind: *kind,
            },
            Self::ChangeCompleted {
                resource_id,
                output,
            } => Self::ChangeCompleted {
                resource_id: resource_id.clone(),
                output: f(output),
            },
            Self::ChangeFailed {
                resource_id,
                error,
                code,
            } => Self::ChangeFailed {
                resource_id: resource_id.clone(),
                error: f(error),
                code: *code,
            },
            Self::ChangeSkipped {
                resource_id,
                reason,
            } => Self::ChangeSkipped {
                resource_id: resource_id.clone(),
                reason: f(reason),
            },
            Self::StepStarted { step, name } => Self::StepStarted {
                step: step.clone(),
                name: f(name),
            },
            Self::StepCompleted { step, output } => Self::StepCompleted {
                step: step.clone(),
                output: f(output),
            },
            Self::StepFailed { step, error } => Self::StepFailed {
                step: step.clone(),
                error: f(error),
            },
            Self::StepSkipped { step, reason } => Self::StepSkipped {
                step: step.clone(),
                reason: f(reason),
            },
            Self::RunFinished { summary } => Self::RunFinished { summary: *summary },
        }
    }

    /// The per-change event for an outcome — the single mapping from execution state
    /// to the wire stream, so the stream and the report stay consistent.
    #[must_use]
    pub fn from_outcome(outcome: &ChangeOutcome) -> Self {
        match outcome {
            ChangeOutcome::Completed {
                resource_id,
                output,
            } => Self::ChangeCompleted {
                resource_id: resource_id.clone(),
                output: output.clone(),
            },
            ChangeOutcome::Failed {
                resource_id,
                error,
                code,
            } => Self::ChangeFailed {
                resource_id: resource_id.clone(),
                error: error.clone(),
                code: *code,
            },
            ChangeOutcome::Skipped {
                resource_id,
                reason,
            } => Self::ChangeSkipped {
                resource_id: resource_id.clone(),
                reason: reason.clone(),
            },
        }
    }

    /// The per-step event for a [`StepOutcome`] — the single mapping for imperative
    /// runs (`deploy`), mirroring [`Event::from_outcome`] on the change side.
    #[must_use]
    pub fn from_step_outcome(outcome: &StepOutcome) -> Self {
        match outcome {
            StepOutcome::Completed { step, output } => Self::StepCompleted {
                step: step.clone(),
                output: output.clone(),
            },
            StepOutcome::Failed { step, error } => Self::StepFailed {
                step: step.clone(),
                error: error.clone(),
            },
            StepOutcome::Skipped { step, reason } => Self::StepSkipped {
                step: step.clone(),
                reason: reason.clone(),
            },
        }
    }
}

/// Execution outcome for one imperative step — the step counterpart to
/// [`ChangeOutcome`].
///
/// Keyed by a step id rather than a `resource_id`. Same three-arm typed-result
/// discipline (a completed step *has* output, a failed one *has* an error, a skipped
/// one *has* a reason).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum StepOutcome {
    /// The step ran to completion.
    Completed {
        /// Which step this outcome is for.
        step: String,
        /// Captured stdout / a short summary.
        output: String,
    },
    /// The step failed — execution halts after recording this (stop-on-first).
    Failed {
        /// Which step this outcome is for.
        step: String,
        /// Why it failed.
        error: String,
    },
    /// The step never ran — a prior step failed and the run was aborted.
    Skipped {
        /// Which step this outcome is for.
        step: String,
        /// Why it was skipped.
        reason: String,
    },
}

impl StepOutcome {
    /// This outcome with its free text — the output, error, or reason — passed through
    /// `f`, its step id kept ([`Event::map_text`] states the rule).
    #[must_use]
    pub fn map_text(&self, f: impl Fn(&str) -> String) -> Self {
        match self {
            Self::Completed { step, output } => Self::Completed {
                step: step.clone(),
                output: f(output),
            },
            Self::Failed { step, error } => Self::Failed {
                step: step.clone(),
                error: f(error),
            },
            Self::Skipped { step, reason } => Self::Skipped {
                step: step.clone(),
                reason: f(reason),
            },
        }
    }

    /// Whether this outcome is a failure (drives the run's exit code).
    #[must_use]
    pub const fn is_failure(&self) -> bool {
        matches!(self, Self::Failed { .. })
    }
}

/// Execution outcome for one change — the runtime counterpart to `plan::Change`,
/// keyed by `resource_id`.
///
/// A three-arm enum rather than a status tag beside nullable `output` / `error`
/// fields: a completed change *has* output, a failed one *has* an error, a skipped
/// one *has* a reason — making the meaningless combinations (failed-with-output,
/// completed-with-error) unrepresentable, the same typed-result discipline as the
/// detection outcome enum.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum ChangeOutcome {
    /// The change ran to completion. `output` is its captured stdout (possibly
    /// empty), or a short human summary for native-fs changes.
    Completed {
        /// Which change this outcome is for.
        resource_id: ResourceId,
        /// Captured stdout / a short summary of what was done.
        output: String,
    },
    /// The change failed — execution halts after recording this (stop-on-first).
    Failed {
        /// Which change this outcome is for.
        resource_id: ResourceId,
        /// Why it failed (a command's stderr, or a verify assertion summary).
        error: String,
        /// Triage category classified from the failure: `zap_core` populates it from
        /// the engine error's structure (`Error::error_code`; a native io error by its
        /// kind, `io_error_code`), and from text through
        /// [`classify_error`](crate::error_code::classify_error).
        code: ErrorCode,
    },
    /// The change never ran — a prior change failed and the plan was aborted.
    Skipped {
        /// Which change this outcome is for.
        resource_id: ResourceId,
        /// Why it was skipped.
        reason: String,
    },
}

impl ChangeOutcome {
    /// This outcome with its free text — the output, error, or reason — passed through
    /// `f`, its resource id and error code kept ([`Event::map_text`] states the rule).
    #[must_use]
    pub fn map_text(&self, f: impl Fn(&str) -> String) -> Self {
        match self {
            Self::Completed {
                resource_id,
                output,
            } => Self::Completed {
                resource_id: resource_id.clone(),
                output: f(output),
            },
            Self::Failed {
                resource_id,
                error,
                code,
            } => Self::Failed {
                resource_id: resource_id.clone(),
                error: f(error),
                code: *code,
            },
            Self::Skipped {
                resource_id,
                reason,
            } => Self::Skipped {
                resource_id: resource_id.clone(),
                reason: f(reason),
            },
        }
    }

    /// The resource this outcome is for (the key it's tracked by).
    #[must_use]
    pub const fn resource_id(&self) -> &ResourceId {
        match self {
            Self::Completed { resource_id, .. }
            | Self::Failed { resource_id, .. }
            | Self::Skipped { resource_id, .. } => resource_id,
        }
    }

    /// Whether this outcome is a failure (drives the run's exit code).
    #[must_use]
    pub const fn is_failure(&self) -> bool {
        matches!(self, Self::Failed { .. })
    }
}

/// Summary of a run — counts shared by the CLI render and the rolling run log.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunSummary {
    /// Total changes in the plan.
    pub total: u32,
    /// Changes that completed successfully.
    pub completed: u32,
    /// Changes that failed.
    pub failed: u32,
    /// Changes that were skipped (aborted after an earlier failure).
    pub skipped: u32,
}

impl RunSummary {
    /// Derive the counts from a run's outcomes (the single tally path).
    #[must_use]
    pub fn from_outcomes(outcomes: &[ChangeOutcome]) -> Self {
        let mut summary = Self {
            total: 0,
            completed: 0,
            failed: 0,
            skipped: 0,
        };
        for outcome in outcomes {
            summary.total += 1;
            match outcome {
                ChangeOutcome::Completed { .. } => summary.completed += 1,
                ChangeOutcome::Failed { .. } => summary.failed += 1,
                ChangeOutcome::Skipped { .. } => summary.skipped += 1,
            }
        }
        summary
    }

    /// Derive the counts from an imperative run's step outcomes (the `deploy` tally
    /// path, mirroring [`RunSummary::from_outcomes`]).
    #[must_use]
    pub fn from_step_outcomes(outcomes: &[StepOutcome]) -> Self {
        let mut summary = Self {
            total: 0,
            completed: 0,
            failed: 0,
            skipped: 0,
        };
        for outcome in outcomes {
            summary.total += 1;
            match outcome {
                StepOutcome::Completed { .. } => summary.completed += 1,
                StepOutcome::Failed { .. } => summary.failed += 1,
                StepOutcome::Skipped { .. } => summary.skipped += 1,
            }
        }
        summary
    }
}

#[cfg(test)]
mod tests {
    use super::{ChangeOutcome, Event, RunSummary};
    use crate::error_code::ErrorCode;
    use crate::schema::ResourceId;

    fn id(name: &str) -> ResourceId {
        ResourceId(name.to_owned())
    }

    /// `map_text` reaches the free text of every event and outcome and nothing else:
    /// the tag, the ids, the action, kind and code, the plan hash and the counts are
    /// the same before and after, and an outcome maps as its event does.
    #[test]
    fn map_text_reaches_the_free_text_and_only_it() {
        use super::StepOutcome;
        use crate::plan::ChangeAction;
        use crate::schema::ResourceType;

        let wrap = |text: &str| format!("<{text}>");
        let text = || "text".to_owned();
        let step = || "restart".to_owned();
        let cases: [(Event, &[&str]); 10] = [
            (
                Event::RunStarted {
                    target: text(),
                    wetrun: true,
                    plan_hash: "ab12".to_owned(),
                    total: 2,
                },
                &["target"],
            ),
            (
                Event::ChangeStarted {
                    resource_id: id("svc"),
                    action: ChangeAction::Create,
                    kind: ResourceType::Directory,
                },
                &[],
            ),
            (
                Event::ChangeCompleted {
                    resource_id: id("svc"),
                    output: text(),
                },
                &["output"],
            ),
            (
                Event::ChangeFailed {
                    resource_id: id("svc"),
                    error: text(),
                    code: ErrorCode::Permission,
                },
                &["error"],
            ),
            (
                Event::ChangeSkipped {
                    resource_id: id("svc"),
                    reason: text(),
                },
                &["reason"],
            ),
            (
                Event::StepStarted {
                    step: step(),
                    name: text(),
                },
                &["name"],
            ),
            (
                Event::StepCompleted {
                    step: step(),
                    output: text(),
                },
                &["output"],
            ),
            (
                Event::StepFailed {
                    step: step(),
                    error: text(),
                },
                &["error"],
            ),
            (
                Event::StepSkipped {
                    step: step(),
                    reason: text(),
                },
                &["reason"],
            ),
            (
                Event::RunFinished {
                    summary: RunSummary {
                        total: 2,
                        completed: 1,
                        failed: 1,
                        skipped: 0,
                    },
                },
                &[],
            ),
        ];
        for (event, mapped_fields) in cases {
            let mut expected = serde_json::to_value(&event).unwrap();
            for field in mapped_fields {
                assert_eq!(expected[field], "text", "{event:?}");
                expected[field] = serde_json::json!("<text>");
            }
            assert_eq!(
                serde_json::to_value(event.map_text(wrap)).unwrap(),
                expected,
                "{event:?}"
            );
        }

        for outcome in [
            ChangeOutcome::Completed {
                resource_id: id("a"),
                output: text(),
            },
            ChangeOutcome::Failed {
                resource_id: id("a"),
                error: text(),
                code: ErrorCode::Transient,
            },
            ChangeOutcome::Skipped {
                resource_id: id("a"),
                reason: text(),
            },
        ] {
            assert_eq!(
                Event::from_outcome(&outcome.map_text(wrap)),
                Event::from_outcome(&outcome).map_text(wrap)
            );
        }
        for outcome in [
            StepOutcome::Completed {
                step: step(),
                output: text(),
            },
            StepOutcome::Failed {
                step: step(),
                error: text(),
            },
            StepOutcome::Skipped {
                step: step(),
                reason: text(),
            },
        ] {
            assert_eq!(
                Event::from_step_outcome(&outcome.map_text(wrap)),
                Event::from_step_outcome(&outcome).map_text(wrap)
            );
        }
    }

    #[test]
    fn event_serializes_as_one_tagged_json_line() {
        let event = Event::ChangeFailed {
            resource_id: id("svc"),
            error: "boom".to_owned(),
            code: ErrorCode::Permission,
        };
        let line = serde_json::to_string(&event).unwrap();
        // a single line (JSON-lines), tagged by `event`, no embedded newline.
        assert!(!line.contains('\n'));
        assert_eq!(
            line,
            r#"{"event":"change_failed","resource_id":"svc","error":"boom","code":"permission"}"#
        );
        // round-trips (the run-log / stream consumer reads it back).
        assert_eq!(serde_json::from_str::<Event>(&line).unwrap(), event);
    }

    #[test]
    fn from_outcome_maps_each_arm() {
        assert_eq!(
            Event::from_outcome(&ChangeOutcome::Completed {
                resource_id: id("a"),
                output: "ok".to_owned(),
            }),
            Event::ChangeCompleted {
                resource_id: id("a"),
                output: "ok".to_owned(),
            }
        );
        assert_eq!(
            Event::from_outcome(&ChangeOutcome::Skipped {
                resource_id: id("b"),
                reason: "aborted".to_owned(),
            }),
            Event::ChangeSkipped {
                resource_id: id("b"),
                reason: "aborted".to_owned(),
            }
        );
    }

    #[test]
    fn run_summary_counts_each_outcome_arm() {
        let outcomes = vec![
            ChangeOutcome::Completed {
                resource_id: id("a"),
                output: "ok".to_owned(),
            },
            ChangeOutcome::Completed {
                resource_id: id("b"),
                output: String::new(),
            },
            ChangeOutcome::Failed {
                resource_id: id("c"),
                error: "boom".to_owned(),
                code: ErrorCode::ExecutionFailed,
            },
            ChangeOutcome::Skipped {
                resource_id: id("d"),
                reason: "aborted".to_owned(),
            },
        ];
        let summary = RunSummary::from_outcomes(&outcomes);
        assert_eq!(summary.total, 4);
        assert_eq!(summary.completed, 2);
        assert_eq!(summary.failed, 1);
        assert_eq!(summary.skipped, 1);

        // `resource_id` / `is_failure` accessors read each arm correctly.
        assert_eq!(outcomes[2].resource_id().0, "c");
        assert!(outcomes[2].is_failure());
        assert!(!outcomes[0].is_failure());
    }

    #[test]
    fn run_summary_of_nothing_is_zero() {
        let summary = RunSummary::from_outcomes(&[]);
        assert_eq!(summary.total, 0);
    }
}
