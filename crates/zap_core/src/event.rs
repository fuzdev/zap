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
//! - [`EventHandler::Null`] — drop everything (the default for non-streaming runs and
//!   tests).
//!
//! Emission is **best-effort**: a write failure is dropped, never surfaced — an
//! observability sink must not fail a convergence run.
//!
//! zap emits events and keeps none: there is no run log under `~/.zap`.

use std::io::Write as _;

use zap_types::event::Event;

use crate::escape::escape_json_line;
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
    /// Test-only sink that records every event it receives (the observable seam,
    /// mirroring `Connection::Mock`).
    #[cfg(test)]
    Capture(std::sync::Arc<std::sync::Mutex<Vec<Event>>>),
}

impl EventHandler {
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

    #[test]
    fn null_drops_events() {
        // No sink, no panic — the default for non-streaming runs.
        EventHandler::Null.emit(&Event::RunFinished {
            summary: zap_types::event::RunSummary::from_outcomes(&[]),
        });
    }
}
