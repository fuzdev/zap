//! References inside inert text — one scanner for every consumer.
//!
//! A config declares a reference with `zap.env('NAME')`, and the wire carries it as a
//! typed value ([`Text`](crate::text::Text)). Inside the engine a reference rides in text
//! as a **marker**: [`OPEN`], the variable's name, [`CLOSE`]. The two delimiters are
//! Unicode noncharacters, which no text a config declares may hold, so a marker can't
//! be spelled by accident and ordinary text — a `$$`, a `{env:X}` — is never one.
//!
//! The engine resolves references (`zap_core::resolve`), collects their names (the
//! secret registry, `lock --check`'s unverifiable set), and the last-run report rewrites
//! around them — all through [`segments`], so they agree about where a reference is.
//!
//! A delimiter that is no part of a well-formed marker is plain text to the scanner. It
//! can only come from a bug, and nothing downstream lets it pass: a `Text` can't be
//! built holding one, a command that still holds a delimiter after its references
//! resolve is refused, and a render writes it out as its code point.

use crate::scalar::is_env_var_name;

/// What opens a reference in inert text.
pub const OPEN: char = '\u{fdd0}';

/// What closes a reference in inert text.
pub const CLOSE: char = '\u{fdd1}';

/// The inert form of a reference to `name`.
///
/// The text [`segments`] reads back as [`Segment::Ref`] when `name` is an environment
/// variable's — the one spelling of a reference inside a [`Text`](crate::text::Text)
/// and inside composed command text.
#[must_use]
pub fn marker(name: &str) -> String {
    format!("{OPEN}{name}{CLOSE}")
}

/// A reference to `name` as a preview, a message, or an error names it to a person.
///
/// The notation is for reading, not an address: literal text can spell `{env:X}` too.
/// The declared `target:` line and the plan hash are the exact forms.
#[must_use]
pub fn shown(name: &str) -> String {
    format!("{{env:{name}}}")
}

/// Whether `text` holds either delimiter, in a marker or out of one.
#[must_use]
pub fn holds_delimiter(text: &str) -> bool {
    text.contains([OPEN, CLOSE])
}

/// Whether `text` holds a delimiter that is no part of a well-formed marker.
#[must_use]
pub fn holds_stray_delimiter(text: &str) -> bool {
    segments(text).any(|segment| matches!(segment, Segment::Text(text) if holds_delimiter(text)))
}

/// One piece of a string split at its references.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Segment<'a> {
    /// Text outside any reference, never empty.
    Text(&'a str),
    /// A reference's name, without its delimiters: an environment variable's name.
    Ref(&'a str),
}

/// Split `input` into its text and references, in order.
///
/// A reference is [`OPEN`], an environment variable's name, [`CLOSE`]. Any other
/// delimiter stays in the text around it.
#[must_use]
pub const fn segments(input: &str) -> Segments<'_> {
    Segments {
        rest: input,
        pending: None,
    }
}

/// The iterator [`segments`] returns.
#[derive(Debug, Clone)]
pub struct Segments<'a> {
    rest: &'a str,
    pending: Option<&'a str>,
}

impl<'a> Iterator for Segments<'a> {
    type Item = Segment<'a>;

    fn next(&mut self) -> Option<Segment<'a>> {
        if let Some(name) = self.pending.take() {
            return Some(Segment::Ref(name));
        }
        if self.rest.is_empty() {
            return None;
        }
        let rest = self.rest;
        let mut from = 0;
        while let Some(offset) = rest[from..].find(OPEN) {
            let start = from + offset;
            let after = &rest[start + OPEN.len_utf8()..];
            let name = after.find(CLOSE).map(|end| &after[..end]);
            if let Some(name) = name.filter(|name| is_env_var_name(name)) {
                self.rest = &after[name.len() + CLOSE.len_utf8()..];
                if start == 0 {
                    return Some(Segment::Ref(name));
                }
                self.pending = Some(name);
                return Some(Segment::Text(&rest[..start]));
            }
            from = start + OPEN.len_utf8();
        }
        self.rest = "";
        Some(Segment::Text(rest))
    }
}

/// The token a masked secret renders as — `[MASKED:NAME]`, naming the variable, never
/// its value. The one spelling shared by the engine's masker and the last-run report.
#[must_use]
pub fn masked_token(name: &str) -> String {
    format!("[MASKED:{name}]")
}

/// The names in the [`masked_token`]s `text` holds, in order, each once.
#[must_use]
pub fn masked_token_names(text: &str) -> Vec<String> {
    const OPEN: &str = "[MASKED:";
    let mut names: Vec<String> = Vec::new();
    let mut rest = text;
    while let Some(start) = rest.find(OPEN) {
        rest = &rest[start + OPEN.len()..];
        let Some(end) = rest.find(']') else {
            break;
        };
        let name = &rest[..end];
        if !name.is_empty() && !names.iter().any(|seen| seen == name) {
            names.push(name.to_owned());
        }
        rest = &rest[end + 1..];
    }
    names
}

/// `input` with each reference replaced by `resolve(name)`.
pub fn map_refs(input: &str, mut resolve: impl FnMut(&str) -> String) -> String {
    let mut out = String::with_capacity(input.len());
    for segment in segments(input) {
        match segment {
            Segment::Text(text) => out.push_str(text),
            Segment::Ref(name) => out.push_str(&resolve(name)),
        }
    }
    out
}

/// `input` with each run of text outside a reference replaced by `map(text)`, every
/// reference kept as it is — so no rewrite of the text can touch a reference's name.
pub fn map_literals(input: &str, mut map: impl FnMut(&str) -> String) -> String {
    let mut out = String::with_capacity(input.len());
    for segment in segments(input) {
        match segment {
            Segment::Text(text) => out.push_str(&map(text)),
            Segment::Ref(name) => out.push_str(&marker(name)),
        }
    }
    out
}

/// The names of `input`'s references, in order.
pub fn ref_names(input: &str) -> impl Iterator<Item = &str> {
    segments(input).filter_map(|segment| match segment {
        Segment::Ref(name) => Some(name),
        Segment::Text(_) => None,
    })
}

#[cfg(test)]
mod tests {
    use super::{
        CLOSE, OPEN, Segment, holds_delimiter, holds_stray_delimiter, map_literals, map_refs,
        marker, masked_token, masked_token_names, ref_names, segments, shown,
    };

    /// A marker is the text the scanner reads back as a reference to the same name,
    /// wherever it sits; the shown form names it too.
    #[test]
    fn a_marker_is_read_back_as_its_reference() {
        assert_eq!(
            segments(&marker("APP_DIR")).collect::<Vec<_>>(),
            [Segment::Ref("APP_DIR")]
        );
        let composed = format!("cd {}/releases/{}", marker("APP_DIR"), marker("VERSION"));
        assert_eq!(
            segments(&composed).collect::<Vec<_>>(),
            [
                Segment::Text("cd "),
                Segment::Ref("APP_DIR"),
                Segment::Text("/releases/"),
                Segment::Ref("VERSION"),
            ]
        );
        assert_eq!(
            map_refs(&composed, str::to_lowercase),
            "cd app_dir/releases/version"
        );
        assert!(shown("APP_DIR").contains("APP_DIR"));
        assert_ne!(shown("APP_DIR"), shown("VERSION"));
    }

    #[test]
    fn splits_text_and_references() {
        let input = format!("a{}b{}{}", marker("X"), marker("Y"), marker("Z"));
        assert_eq!(
            segments(&input).collect::<Vec<_>>(),
            [
                Segment::Text("a"),
                Segment::Ref("X"),
                Segment::Text("b"),
                Segment::Ref("Y"),
                Segment::Ref("Z"),
            ]
        );
        assert_eq!(segments("").count(), 0);
        assert_eq!(
            segments("plain").collect::<Vec<_>>(),
            [Segment::Text("plain")]
        );
    }

    /// The shown form is `{env:NAME}`, and neither it nor a `$$` is a reference: both
    /// are ordinary text to the scanner.
    #[test]
    fn only_a_marker_is_a_reference() {
        assert_eq!(shown("APP_DIR"), "{env:APP_DIR}");
        for text in ["{env:APP_DIR}", "$$APP_DIR$$", "a $$ b $$$$ c", "$$"] {
            assert_eq!(
                segments(text).collect::<Vec<_>>(),
                [Segment::Text(text)],
                "{text}"
            );
            assert!(!holds_delimiter(text));
            assert_eq!(map_refs(text, |_| unreachable!()), text);
        }
    }

    /// A delimiter that is no part of a well-formed marker — unclosed, unopened, around
    /// no name, or around text that is no variable's name — is text, and is found as a
    /// stray; a well-formed marker beside it is still read.
    #[test]
    fn a_malformed_marker_is_text_and_is_found() {
        let malformed = [
            format!("a{OPEN}X"),
            format!("a{CLOSE}b"),
            format!("{OPEN}{CLOSE}"),
            format!("{OPEN}not a name{CLOSE}"),
            format!("{OPEN}1X{CLOSE}"),
            format!("{OPEN}X-Y{CLOSE}"),
            format!("{CLOSE}X{OPEN}"),
        ];
        for text in &malformed {
            assert_eq!(
                segments(text).collect::<Vec<_>>(),
                [Segment::Text(text.as_str())],
                "{text:?}"
            );
            assert_eq!(ref_names(text).count(), 0);
            assert_eq!(&map_refs(text, |_| unreachable!()), text);
            assert!(holds_delimiter(text) && holds_stray_delimiter(text));
        }

        // An opening delimiter with no name of its own, ahead of a whole marker.
        let nested = format!("{OPEN}{}", marker("X"));
        assert_eq!(
            segments(&nested).collect::<Vec<_>>(),
            [Segment::Text("\u{fdd0}"), Segment::Ref("X")]
        );
        assert!(holds_stray_delimiter(&nested));

        let whole = format!("a{}b", marker("X"));
        assert!(holds_delimiter(&whole) && !holds_stray_delimiter(&whole));
    }

    /// The tokens a masked text holds are named once each, in order; text that only
    /// looks like the start of one names nothing.
    #[test]
    fn names_the_tokens_in_a_masked_text() {
        let text = format!(
            "db://{}:{}@h/{}",
            masked_token("USER_KEY"),
            masked_token("PW"),
            masked_token("USER_KEY")
        );
        assert_eq!(masked_token_names(&text), ["USER_KEY", "PW"]);
        assert_eq!(
            masked_token_names("plain.example.com"),
            Vec::<String>::new()
        );
        assert_eq!(
            masked_token_names("a [MASKED:] b [MASKED:OPEN"),
            Vec::<String>::new()
        );
    }

    #[test]
    fn maps_each_reference() {
        let input = format!("x={}, y={}$$", marker("A"), marker("B"));
        assert_eq!(map_refs(&input, str::to_lowercase), "x=a, y=b$$");
        assert_eq!(map_refs("keep $$ this", |_| unreachable!()), "keep $$ this");
    }

    /// Mapping the literals rewrites the text around each reference and leaves every
    /// name as it is, whatever the rewrite would have done to it.
    #[test]
    fn maps_the_text_around_each_reference() {
        let input = format!("key={}; KEY", marker("KEY"));
        assert_eq!(
            map_literals(&input, |text| text.replace("KEY", "[gone]").to_uppercase()),
            format!("KEY={}; [GONE]", marker("KEY"))
        );
        assert_eq!(map_literals("", |_| unreachable!()), "");
    }
}
