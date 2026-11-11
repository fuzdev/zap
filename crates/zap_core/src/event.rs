//! Event emission — the IO side of Observe.
//!
//! [`zap_types::event::Event`] is the pure wire schema; this module *emits* it. A
//! run streams events live as it executes (rather than only batching them into the
//! final report), so a long wetrun or deploy shows progress as it happens.
//!
//! Emission is modeled as a closed [`EventHandler`] enum (not a `dyn` trait — the
//! same reasoning that made `Connection` an enum: a small, known set, statically
//! dispatched, no `async_trait`). The arms compose:
//!
//! - [`EventHandler::Stdout`] — write each event as one JSON line (the required
//!   structured-output interface).
//! - [`EventHandler::Masking`] — the `mask_handler` decorator: mask the event with a
//!   [`SecretMasker`] (via [`Event::map_text`]), then forward
//!   to an inner handler. **Masking at the emission boundary** — `execute_plan` stays
//!   masking-unaware, exactly as `mask_outcomes` masks the batch report.
//! - [`EventHandler::Progress`] — show the operator each phase as it starts, one line
//!   to a [`ProgressSink`] the binary supplies (`crate::progress`): the text-mode
//!   wetrun's live output, where the engine itself prints nothing.
//! - [`EventHandler::Null`] — drop everything (the default for non-streaming runs and
//!   tests).
//!
//! A run also announces the phases that are no event of the stream, such as a deploy's
//! drift preflight, as a [`Notice`] ([`EventHandler::notice`]): only the progress arm
//! shows one, so the `--json` stream carries its documented events and nothing else.
//!
//! Emission is **best-effort**: a write failure is dropped, never surfaced — an
//! observability sink must not fail a convergence run.
//!
//! zap emits events and keeps none: there is no run log under `~/.zap`.

use std::io::Write as _;
use std::sync::Arc;

use zap_types::event::Event;

use crate::escape::escape_json_line;
use crate::progress::{Notice, Progress, ProgressSink, render_progress};
use crate::secret::SecretMasker;

/// A sink for run [`Event`]s — a closed, composable set (see the module docs).
#[derive(Debug)]
pub enum EventHandler {
    /// Drop every event.
    Null,
    /// Write each event as one JSON line to stdout (JSON-lines).
    Stdout,
    /// Mask each event through `masker`, then forward to `inner` — the `mask_handler`
    /// decorator. Wraps the rest of the chain so masking happens once, at the boundary.
    Masking {
        /// The frozen secret set (a cheap clone of the run's masker).
        masker: SecretMasker,
        /// The handler that receives the masked event.
        inner: Box<Self>,
    },
    /// Show each event and notice that starts a phase as one line of progress
    /// ([`render_progress`]) on the sink, and drop the rest: an outcome is the final
    /// report's.
    Progress(Arc<dyn ProgressSink>),
    /// Test-only sink that records every event it receives (the observable seam,
    /// mirroring `Connection::Mock`).
    #[cfg(test)]
    Capture(Arc<std::sync::Mutex<Vec<Event>>>),
}

impl EventHandler {
    /// The sink a wetrun emits to: the JSON-lines stream under `--json` (`emit_json`),
    /// else the operator's `progress` lines when there are any, else nothing.
    #[must_use]
    pub fn for_run(emit_json: bool, progress: Option<&Arc<dyn ProgressSink>>) -> Self {
        if emit_json {
            Self::Stdout
        } else {
            progress.map_or(Self::Null, |sink| Self::Progress(Arc::clone(sink)))
        }
    }

    /// Announce a phase that is no event ([`Notice`]). Only the progress arm shows it;
    /// the stream's sinks drop it. Best-effort, as [`emit`](Self::emit) is.
    pub fn notice(&self, notice: Notice) {
        match self {
            Self::Null | Self::Stdout => {}
            Self::Masking { masker, inner } => {
                inner.notice(notice.map_text(|text| masker.mask(text)));
            }
            Self::Progress(sink) => {
                if let Some(line) = render_progress(Progress::Notice(notice)) {
                    sink.line(&line);
                }
            }
            #[cfg(test)]
            Self::Capture(_) => {}
        }
    }

    /// Emit one event. Best-effort — a write error is silently dropped so emission
    /// never fails a run.
    pub fn emit(&self, event: &Event) {
        match self {
            Self::Null => {}
            Self::Stdout => {
                if let Some(line) = event_line(event) {
                    // Lock once and write the line + newline together so concurrent
                    // emitters can't interleave a half-line.
                    let mut out = std::io::stdout().lock();
                    let _ = writeln!(out, "{line}");
                }
            }
            Self::Masking { masker, inner } => {
                inner.emit(&event.map_text(|text| masker.mask(text)));
            }
            Self::Progress(sink) => {
                if let Some(line) = render_progress(Progress::Event(event)) {
                    sink.line(&line);
                }
            }
            #[cfg(test)]
            Self::Capture(events) => {
                if let Ok(mut events) = events.lock() {
                    events.push(event.clone());
                }
            }
        }
    }
}

/// One event as its line of the JSON stream, without the newline that ends it: its JSON,
/// with every character a terminal would act on or show nothing for respelled as a
/// `\uXXXX` escape ([`escape_json_line`]). A parser reads the event the JSON encodes;
/// a terminal the stream is watched on is sent no control, bidirectional, or invisible
/// character. `None` for an event that can't be serialized.
fn event_line(event: &Event) -> Option<String> {
    let json = serde_json::to_string(event).ok()?;
    Some(escape_json_line(&json).into_owned())
}

/// The `mask_handler` decorator — wrap `inner` to mask every event through `masker`.
///
/// The one place resolved secrets are stripped from the stream, built once per run
/// from the same `SecretMasker` the batch report uses, so the stream and the report
/// mask identically.
#[must_use]
pub fn mask_handler(masker: SecretMasker, inner: EventHandler) -> EventHandler {
    EventHandler::Masking {
        masker,
        inner: Box::new(inner),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use zap_types::event::Event;
    use zap_types::schema::ResourceId;

    use super::{EventHandler, mask_handler};
    use crate::progress::{Notice, ProgressSink, RecordedProgress};
    use crate::secret::SecretRegistry;

    fn capture() -> (EventHandler, Arc<Mutex<Vec<Event>>>) {
        let events = Arc::new(Mutex::new(Vec::new()));
        (EventHandler::Capture(Arc::clone(&events)), events)
    }

    #[test]
    fn mask_handler_masks_before_forwarding() {
        let mut registry = SecretRegistry::new();
        registry.register("SECRET_X", "tok-12345678");
        let masker = registry.freeze().unwrap();

        let (sink, events) = capture();
        let handler = mask_handler(masker, sink);

        handler.emit(&Event::ChangeFailed {
            resource_id: ResourceId("svc".to_owned()),
            error: "rejected tok-12345678".to_owned(),
            code: zap_types::error_code::ErrorCode::ExecutionFailed,
        });

        let recorded = events.lock().unwrap();
        assert_eq!(
            recorded[0],
            Event::ChangeFailed {
                resource_id: ResourceId("svc".to_owned()),
                error: "rejected [MASKED:SECRET_X]".to_owned(),
                code: zap_types::error_code::ErrorCode::ExecutionFailed,
            },
            "the inner sink received the masked event, not the raw secret"
        );
    }

    /// The stream's line for an event holding what a terminal would act on: none of it
    /// is on the line raw — a control, DEL, a C1 control, a separator, a bidirectional
    /// override, an invisible character, an astral one as a surrogate pair — and the
    /// line parses back to the event.
    #[test]
    fn an_event_line_holds_no_raw_control_and_parses_back_to_the_event() {
        let event = Event::ChangeFailed {
            resource_id: ResourceId("svc\u{202e}\u{200b}".to_owned()),
            error: "boom\r\u{1b}[2K\n\ttab\u{7f}\u{9b}2K\u{2028}\u{feff}\u{e0041} é 🚀".to_owned(),
            code: zap_types::error_code::ErrorCode::ExecutionFailed,
        };
        let line = super::event_line(&event).unwrap();
        assert_eq!(
            line,
            "{\"event\":\"change_failed\",\"resource_id\":\"svc\\u202e\\u200b\",\
             \"error\":\"boom\\r\\u001b[2K\\n\\ttab\\u007f\\u009b2K\\u2028\\ufeff\\udb40\\udc41 é 🚀\",\
             \"code\":\"execution_failed\"}"
        );
        assert!(
            !line.contains(|c: char| c.is_control()
                || matches!(
                    c,
                    '\u{2028}' | '\u{202e}' | '\u{200b}' | '\u{feff}' | '\u{e0041}'
                )),
            "{line:?}"
        );
        assert_eq!(serde_json::from_str::<Event>(&line).unwrap(), event);

        // An event with nothing to respell is its JSON, byte for byte.
        let plain = Event::RunFinished {
            summary: zap_types::event::RunSummary::from_outcomes(&[]),
        };
        assert_eq!(
            super::event_line(&plain).unwrap(),
            serde_json::to_string(&plain).unwrap()
        );
    }

    /// A progress line is masked at the same boundary an event is, then escaped: a
    /// secret or a control character in a step's name reaches the operator's terminal
    /// as its token and its respelling, never raw. An outcome shows nothing live, and a
    /// notice passes the mask to the sink.
    #[test]
    fn a_progress_line_is_masked_then_escaped() {
        let mut registry = SecretRegistry::new();
        registry.register("SECRET_X", "tok-12345678");
        let masker = registry.freeze().unwrap();
        let sink = RecordedProgress::new();
        let progress: Arc<dyn ProgressSink> = Arc::<RecordedProgress>::clone(&sink);
        let handler = mask_handler(masker, EventHandler::for_run(false, Some(&progress)));

        handler.notice(Notice::DriftPreflight { resources: 2 });
        handler.emit(&Event::StepStarted {
            step: "rollback".to_owned(),
            name: "Roll back to tok-12345678\r\u{1b}[2Kforged".to_owned(),
        });
        handler.emit(&Event::StepCompleted {
            step: "rollback".to_owned(),
            output: "done".to_owned(),
        });
        assert_eq!(
            sink.lines(),
            [
                "→ preflight: checking 2 apply-managed resources for drift",
                "→ rollback: Roll back to [MASKED:SECRET_X]<U+000D><U+001B>[2Kforged",
            ]
        );
    }

    /// `--json` streams events and shows no progress; a text run with a sink shows
    /// progress; one without shows nothing.
    #[test]
    fn a_run_streams_json_or_shows_progress() {
        let progress: Arc<dyn ProgressSink> = RecordedProgress::new();
        assert!(matches!(
            EventHandler::for_run(true, Some(&progress)),
            EventHandler::Stdout
        ));
        assert!(matches!(
            EventHandler::for_run(false, Some(&progress)),
            EventHandler::Progress(_)
        ));
        assert!(matches!(
            EventHandler::for_run(false, None),
            EventHandler::Null
        ));
    }

    #[test]
    fn null_drops_events() {
        // No sink, no panic — the default for non-streaming runs.
        EventHandler::Null.emit(&Event::RunFinished {
            summary: zap_types::event::RunSummary::from_outcomes(&[]),
        });
    }
}
