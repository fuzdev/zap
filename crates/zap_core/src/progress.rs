//! Live progress — what a text-mode wetrun shows its operator as it runs.
//!
//! A wetrun's text report is written once it ends, so a long run would otherwise be
//! silent from the confirmation to the last line. Progress fills that gap with one
//! line per phase as the phase **starts**: the drift preflight, each deploy step, each
//! change, and the post-apply re-detect. A phase's outcome stays in the final report,
//! so on a terminal nothing is said twice, and the report remains the whole record of
//! the run when it is redirected to a file.
//!
//! The engine prints nothing here. A line is built by [`render_progress`] — masked
//! first, since it reaches the sink through the `mask_handler` decorator as every event
//! does, then escaped — and handed to a [`ProgressSink`] the binary supplies, which
//! writes it to standard error. The sink rides the closed `EventHandler` enum as its
//! `Progress` arm, so the event stream and the progress lines are one emission path,
//! masked at one boundary.
//!
//! A phase that is no event of the `--json` stream — the drift preflight, the
//! re-detect — is a [`Notice`]: the progress arm shows it, and the stream's sinks drop
//! it, so the stream carries the events it documents and nothing else.

use std::fmt::Debug;

use zap_types::event::Event;
use zap_types::plan::ChangeAction;

use crate::escape::escape_line;

/// Where a wetrun's progress lines go: the binary's standard error, or a test's list.
///
/// Object-safe: carried as `Arc<dyn ProgressSink>` on the command options and in the
/// handler arm.
pub trait ProgressSink: Debug + Send + Sync {
    /// Show one line, without its newline.
    ///
    /// Best-effort, and never a panic: it is called between the steps of a wetrun, where
    /// a panic would stop the run after `current` was swapped, with no restart and no
    /// rollback. A sink that can't write (a closed pipe, a full disk) drops the line.
    fn line(&self, line: &str);
}

/// A phase a run announces that is no event of the stream.
///
/// The masking decorator passes each notice through [`Notice::map_text`], as it does an
/// event through `Event::map_text`, so a text field added to one is masked there.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Notice {
    /// The deploy's drift preflight starts its detection pass over the apply-managed
    /// resources.
    DriftPreflight {
        /// How many resources it checks.
        resources: usize,
    },
    /// The post-apply re-detect starts: every declared resource read back to establish
    /// what the changes left.
    Redetect {
        /// How many resources it reads.
        resources: usize,
    },
}

impl Notice {
    /// This notice with every free-text field passed through `f`. A notice holds counts
    /// alone, so this is the notice itself; it is destructured in full, so a field added
    /// to one doesn't compile until it is placed here.
    #[must_use]
    pub fn map_text(self, f: impl Fn(&str) -> String) -> Self {
        let _ = f;
        match self {
            Self::DriftPreflight { resources } => Self::DriftPreflight { resources },
            Self::Redetect { resources } => Self::Redetect { resources },
        }
    }
}

/// What a run shows live: an event of the stream, or a [`Notice`].
#[derive(Debug, Clone, Copy)]
pub enum Progress<'a> {
    /// An event, as the stream emits it (masked).
    Event(&'a Event),
    /// A phase that is no event.
    Notice(Notice),
}

/// The progress line for `progress`, or `None` for one that starts no phase: an
/// outcome is the final report's to say. Text from the plan or the target is escaped
/// ([`escape_line`]).
#[must_use]
pub fn render_progress(progress: Progress<'_>) -> Option<String> {
    match progress {
        Progress::Notice(Notice::DriftPreflight { resources }) => Some(format!(
            "→ preflight: checking {} for drift",
            count(
                resources,
                "apply-managed resource",
                "apply-managed resources"
            )
        )),
        Progress::Notice(Notice::Redetect { resources }) => Some(format!(
            "→ re-detect: reading {} back to confirm what the changes left",
            count(resources, "declared resource", "declared resources")
        )),
        Progress::Event(Event::StepStarted { step, name }) => {
            Some(format!("→ {}: {}", escape_line(step), escape_line(name)))
        }
        Progress::Event(Event::ChangeStarted {
            resource_id,
            action,
            kind,
        }) => Some(format!(
            "→ {}: {} {}",
            escape_line(&resource_id.0),
            match action {
                ChangeAction::Create => "create",
                ChangeAction::Update => "update",
            },
            kind.as_str()
        )),
        Progress::Event(
            Event::RunStarted { .. }
            | Event::ChangeCompleted { .. }
            | Event::ChangeFailed { .. }
            | Event::ChangeSkipped { .. }
            | Event::StepCompleted { .. }
            | Event::StepFailed { .. }
            | Event::StepSkipped { .. }
            | Event::RunFinished { .. },
        ) => None,
    }
}

/// `n` with the noun that agrees with it: `1 resource`, `3 resources`. The one place a
/// count is worded for the operator, shared by the live lines here and the reports
/// that follow them.
#[must_use]
pub(crate) fn count(n: usize, one: &str, many: &str) -> String {
    format!("{n} {}", if n == 1 { one } else { many })
}

/// A test's sink: every line it is shown, in order.
#[cfg(test)]
#[derive(Debug, Default)]
pub(crate) struct RecordedProgress(std::sync::Mutex<Vec<String>>);

#[cfg(test)]
impl RecordedProgress {
    /// A sink to hand a run, and the handle that reads it back.
    pub(crate) fn new() -> std::sync::Arc<Self> {
        std::sync::Arc::default()
    }

    /// The lines shown so far.
    pub(crate) fn lines(&self) -> Vec<String> {
        self.0.lock().unwrap().clone()
    }
}

#[cfg(test)]
impl ProgressSink for RecordedProgress {
    fn line(&self, line: &str) {
        self.0.lock().unwrap().push(line.to_owned());
    }
}

#[cfg(test)]
mod tests {
    use zap_types::event::Event;
    use zap_types::plan::ChangeAction;
    use zap_types::schema::{ResourceId, ResourceType};

    use super::{Notice, Progress, count, render_progress};

    /// Each phase that starts says so on one line, and an outcome says nothing live.
    #[test]
    fn a_phase_that_starts_is_one_line_and_an_outcome_is_none() {
        assert_eq!(
            render_progress(Progress::Notice(Notice::DriftPreflight { resources: 12 })).unwrap(),
            "→ preflight: checking 12 apply-managed resources for drift"
        );
        assert_eq!(
            render_progress(Progress::Notice(Notice::DriftPreflight { resources: 1 })).unwrap(),
            "→ preflight: checking 1 apply-managed resource for drift"
        );
        assert_eq!(
            render_progress(Progress::Notice(Notice::Redetect { resources: 3 })).unwrap(),
            "→ re-detect: reading 3 declared resources back to confirm what the changes left"
        );
        assert_eq!(
            render_progress(Progress::Event(&Event::StepStarted {
                step: "build".to_owned(),
                name: "Build application".to_owned(),
            }))
            .unwrap(),
            "→ build: Build application"
        );
        assert_eq!(
            render_progress(Progress::Event(&Event::ChangeStarted {
                resource_id: ResourceId("notes".to_owned()),
                action: ChangeAction::Create,
                kind: ResourceType::Directory,
            }))
            .unwrap(),
            "→ notes: create directory"
        );
        assert_eq!(
            render_progress(Progress::Event(&Event::StepCompleted {
                step: "build".to_owned(),
                output: "built".to_owned(),
            })),
            None
        );
    }

    #[test]
    fn a_count_agrees_with_its_noun() {
        assert_eq!(count(0, "attempt", "attempts"), "0 attempts");
        assert_eq!(count(1, "attempt", "attempts"), "1 attempt");
        assert_eq!(count(2, "attempt", "attempts"), "2 attempts");
    }
}
