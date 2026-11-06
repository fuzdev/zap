//! Text on its way to a terminal.
//!
//! A report is reviewed by reading it, so what is printed has to be what is there. Every
//! string a render takes from a config, the environment, the command line, a file under
//! `~/.zap`, `zap.lock`, or the target goes through [`escape_line`] (one line) or
//! [`render_block`] (a text that may run to several) on its way out, and so does every
//! error ([`Error::render`](crate::error::Error::render)): no such text can move the
//! cursor, erase or overwrite output, hide a character, reorder what is shown, or start
//! a line of its own. What zap prints holds no cursor-moving character but the newlines
//! that end its lines.
//!
//! Beside the two: [`escape_join`] for a list on one line, [`strip_sgr`] for a tool's
//! colouring, and [`escape_json_line`] for the `--json` event stream, which keeps the
//! same characters off the wire without changing what a JSON parser reads.
//!
//! A reference a text holds inert — a [`var_ref::marker`] — is written in its shown
//! form, `{env:NAME}`, by each of them: this is the one place a marker becomes what a
//! person reads, so no render has to convert one and none can forget to. Any other
//! noncharacter of the delimiters' block is written out as its code point, so a marker
//! that isn't well-formed is visible rather than silent.
//!
//! Mask before escaping, never after: a registered secret that holds an escaped
//! character no longer matches once it is written out.

use std::borrow::Cow;
use std::fmt::Write as _;

use zap_types::var_ref::{self, Segment};

/// Whether `c` is written out as its code point: a character that could change how the
/// text around it reads on a terminal, or that takes up no room in it.
///
/// - **Controls**: C0 except TAB, DEL, and C1 — the cursor movement, erasure, and
///   escape sequences. A TAB is not written out as a code point — a tab-indented script
///   is ordinary text — but it doesn't reach the terminal either: [`escape_line`]
///   expands it to spaces.
/// - **Line and paragraph separators** (U+2028, U+2029), which end a line.
/// - **Bidirectional controls** (U+061C, U+200E, U+200F, U+202A–U+202E,
///   U+2066–U+2069), which reorder what is shown.
/// - **Invisible characters**: the code points Unicode gives the
///   `Default_Ignorable_Code_Point` property — soft hyphen, the zero-width space and
///   joiners, the word joiner and invisible operators, the Hangul and Khmer fillers,
///   the Mongolian and general variation selectors, the byte order mark, the shorthand
///   and musical format controls, and the tag block — plus the interlinear annotation
///   controls (U+FFF9–U+FFFB), which are format characters too. A rendering shows
///   nothing for these, so two texts that differ only by one read the same.
/// - **Noncharacters** U+FDD0–U+FDEF, the block a reference's delimiters come from. A
///   well-formed reference never reaches this test — it is written in its shown form —
///   so one of these is a delimiter out of place, or a character no text should hold.
///
/// The invisible set is escaped wherever it stands, with no look at its neighbours: an
/// emoji that is a sequence shows its zero-width joiners and variation selector, and
/// Persian or Indic text shows a zero-width non-joiner. A lone emoji, accented Latin,
/// CJK, and every other visible character are left as they are.
///
/// Not covered: characters that are visible but look like another — a no-break or
/// other wide space (general category `Zs`), a homoglyph — and combining marks, which
/// draw over their base. Those are a different text that reads alike, not a hidden one.
const fn is_escaped(c: char) -> bool {
    matches!(
        c,
        // C0 controls, less TAB
        '\u{0}'..='\u{8}' | '\u{a}'..='\u{1f}'
            // DEL and the C1 controls
            | '\u{7f}'..='\u{9f}'
            // line and paragraph separators
            | '\u{2028}' | '\u{2029}'
            // bidirectional controls outside the ranges below: the Arabic letter mark
            // and the embeddings and overrides
            | '\u{61c}' | '\u{202a}'..='\u{202e}'
            // Default_Ignorable_Code_Point, in code point order: soft hyphen
            | '\u{ad}'
            // combining grapheme joiner
            | '\u{34f}'
            // Hangul choseong and jungseong fillers
            | '\u{115f}'..='\u{1160}'
            // Khmer inherent vowels
            | '\u{17b4}'..='\u{17b5}'
            // Mongolian free variation selectors and vowel separator
            | '\u{180b}'..='\u{180f}'
            // zero-width space, non-joiner, joiner, and the left-to-right and
            // right-to-left marks
            | '\u{200b}'..='\u{200f}'
            // word joiner, invisible operators, the bidirectional isolates, and the
            // deprecated format characters
            | '\u{2060}'..='\u{206f}'
            // Hangul filler
            | '\u{3164}'
            // variation selectors 1–16
            | '\u{fe00}'..='\u{fe0f}'
            // zero-width no-break space (byte order mark)
            | '\u{feff}'
            // the noncharacters a reference's delimiters are two of
            | '\u{fdd0}'..='\u{fdef}'
            // halfwidth Hangul filler
            | '\u{ffa0}'
            // reserved default-ignorables, then the interlinear annotation controls
            | '\u{fff0}'..='\u{fffb}'
            // shorthand format controls
            | '\u{1bca0}'..='\u{1bca3}'
            // musical symbol format controls
            | '\u{1d173}'..='\u{1d17a}'
            // tags, variation selectors supplement, and the rest of the reserved block
            | '\u{e0000}'..='\u{e0fff}'
    )
}

/// The width of a tab stop, in characters.
const TAB_STOP: usize = 8;

/// `text` as one printable line.
///
/// Every character `is_escaped` names is written as `<U+XXXX>`, so none of it can
/// move the cursor, end the line, hide what precedes it, reorder what is shown, or
/// stand in the text unseen.
///
/// A TAB becomes spaces, up to the next multiple of `TAB_STOP` characters counted from
/// the start of `text` as it is written out — not from the terminal's column, which the
/// text's lead has already moved. Tab-indented lines of one block keep their alignment
/// with each other, and no tab reaches the terminal, where a run of them clamps at the
/// right margin and puts what follows at the start of the next row.
///
/// A reference the text holds inert is written in its shown form, `{env:NAME}`
/// ([`var_ref::shown`]).
///
/// Text without such a character is returned as it is. The notation is not itself
/// escaped — text that spells `<U+000D>` out prints the same as a carriage return, and
/// text that spells `{env:NAME}` the same as a reference — so escaping what is already
/// escaped changes nothing.
#[must_use]
pub fn escape_line(text: &str) -> Cow<'_, str> {
    if !text.contains(|c| c == '\t' || is_escaped(c)) {
        return Cow::Borrowed(text);
    }
    let mut out = String::with_capacity(text.len());
    let mut column = 0;
    for segment in var_ref::segments(text) {
        let literal = match segment {
            Segment::Text(literal) => literal,
            Segment::Ref(name) => {
                let shown = var_ref::shown(name);
                // A name is ASCII: a character a byte.
                column += shown.len();
                out.push_str(&shown);
                continue;
            }
        };
        for c in literal.chars() {
            let before = out.len();
            if c == '\t' {
                out.push_str(&" ".repeat(TAB_STOP - column % TAB_STOP));
            } else if is_escaped(c) {
                let _ = write!(out, "<U+{:04X}>", u32::from(c));
            } else {
                out.push(c);
                column += 1;
                continue;
            }
            // What was written in place of `c` is ASCII: a character a byte.
            column += out.len() - before;
        }
    }
    Cow::Owned(out)
}

/// A line of JSON with every character `is_escaped` names written as a `\uXXXX`
/// escape — a surrogate pair above U+FFFF.
///
/// A JSON encoder escapes the C0 controls and leaves the rest of the set as it is: DEL,
/// the C1 controls (U+009B is a control sequence introducer on some terminals), the line
/// and paragraph separators, the bidirectional controls, the invisible characters. In
/// valid JSON such a character can only stand inside a string, where the escape is
/// another spelling of it: a parser reads the same value from the rewritten line, and a
/// terminal the line is watched on is sent none of them.
///
/// The one rewrite that is not another spelling: a reference a string holds inert is
/// written in its shown form, `{env:NAME}` ([`var_ref::shown`]), as [`escape_line`]
/// writes it — a consumer of the stream reads the notation a person does, never the
/// engine's own marker.
#[must_use]
pub fn escape_json_line(json: &str) -> Cow<'_, str> {
    if !json.contains(is_escaped) {
        return Cow::Borrowed(json);
    }
    let mut out = String::with_capacity(json.len());
    let mut units = [0u16; 2];
    for segment in var_ref::segments(json) {
        let literal = match segment {
            Segment::Text(literal) => literal,
            Segment::Ref(name) => {
                out.push_str(&var_ref::shown(name));
                continue;
            }
        };
        for c in literal.chars() {
            if is_escaped(c) {
                for unit in c.encode_utf16(&mut units) {
                    let _ = write!(out, "\\u{unit:04x}");
                }
            } else {
                out.push(c);
            }
        }
    }
    Cow::Owned(out)
}

/// `items`, each through [`escape_line`], joined by `separator` — a list of ids or
/// variable names on one line.
pub fn escape_join<T: AsRef<str>>(items: impl IntoIterator<Item = T>, separator: &str) -> String {
    let mut out = String::new();
    for (index, item) in items.into_iter().enumerate() {
        if index > 0 {
            out.push_str(separator);
        }
        out.push_str(&escape_line(item.as_ref()));
    }
    out
}

/// `text` without its colour sequences: every complete SGR control sequence — `ESC [`,
/// parameters of digits, `;` and `:`, then `m` — is dropped.
///
/// For output coloured for a terminal (what a config printed while it was evaluated,
/// quoted when its evaluation fails): the colouring is the tool's presentation, not
/// text, and written out by [`escape_line`] it would bury the message. Only colour goes. Every other
/// sequence — cursor movement, erasure — and an `ESC [` that no `m` completes stays, to
/// be escaped where the text is printed; dropping a sequence shows the text it styled,
/// so nothing is hidden by it.
#[must_use]
pub fn strip_sgr(text: &str) -> Cow<'_, str> {
    if !text.contains("\u{1b}[") {
        return Cow::Borrowed(text);
    }
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(start) = rest.find("\u{1b}[") {
        let (before, sequence) = rest.split_at(start);
        out.push_str(before);
        let parameters = &sequence[2..];
        let end = parameters
            .find(|c: char| !(c.is_ascii_digit() || c == ';' || c == ':'))
            .unwrap_or(parameters.len());
        if parameters[end..].starts_with('m') {
            rest = &parameters[end + 1..];
        } else {
            out.push_str(&sequence[..2]);
            rest = parameters;
        }
    }
    out.push_str(rest);
    Cow::Owned(out)
}

/// `text` as a block under `lead`.
///
/// Line by line, each through [`escape_line`]: the first after `lead`, the rest
/// indented to its width — so a multi-line command, script, or message reads as one
/// block, and no line of it starts at a column zap's own lines start at. Split on `\n`
/// alone: a carriage return is shown, and a trailing newline is a last, empty line.
///
/// `lead` is printed as given: a caller that builds it from an id escapes the id.
pub fn render_block(out: &mut String, lead: &str, text: &str) {
    let rest = " ".repeat(lead.chars().count());
    for (index, line) in text.split('\n').enumerate() {
        let lead = if index == 0 { lead } else { &rest };
        let _ = writeln!(out, "{lead}{}", escape_line(line));
    }
}

#[cfg(test)]
mod tests {
    // `{env:NAME}` is the notation a reference is shown in, written out here as text.
    #![allow(clippy::literal_string_with_formatting_args)]

    use std::borrow::Cow;

    use zap_types::var_ref::marker;

    use super::{escape_join, escape_json_line, escape_line, is_escaped, render_block, strip_sgr};

    /// Each class of character that could change how a line reads, or that a line shows
    /// nothing for, is written out as its code point.
    #[test]
    fn escape_line_writes_out_every_escaped_class() {
        for (class, text, shown) in [
            ("a newline", "a\nb", "a<U+000A>b"),
            ("a carriage return", "evil\rgood", "evil<U+000D>good"),
            ("an escape sequence", "x\u{1b}[2Ky", "x<U+001B>[2Ky"),
            ("a NUL", "a\0b", "a<U+0000>b"),
            ("a backspace", "ab\u{8}c", "ab<U+0008>c"),
            ("a vertical tab", "a\u{b}b", "a<U+000B>b"),
            ("a form feed", "a\u{c}b", "a<U+000C>b"),
            ("the last C0 control", "a\u{1f}b", "a<U+001F>b"),
            ("DEL", "a\u{7f}b", "a<U+007F>b"),
            ("a C1 control (CSI)", "a\u{9b}2Kb", "a<U+009B>2Kb"),
            ("a C1 control (NEL)", "a\u{85}b", "a<U+0085>b"),
            ("a line separator", "a\u{2028}b", "a<U+2028>b"),
            ("a paragraph separator", "a\u{2029}b", "a<U+2029>b"),
            ("a bidi override", "a\u{202e}b", "a<U+202E>b"),
            ("a bidi embedding", "a\u{202a}b", "a<U+202A>b"),
            ("a bidi isolate", "a\u{2066}b\u{2069}", "a<U+2066>b<U+2069>"),
            (
                "a bidi mark",
                "a\u{200f}\u{200e}\u{61c}b",
                "a<U+200F><U+200E><U+061C>b",
            ),
            ("a soft hyphen", "a\u{ad}b", "a<U+00AD>b"),
            ("a combining grapheme joiner", "a\u{34f}b", "a<U+034F>b"),
            (
                "the Hangul fillers",
                "a\u{115f}\u{1160}\u{3164}\u{ffa0}b",
                "a<U+115F><U+1160><U+3164><U+FFA0>b",
            ),
            (
                "the Khmer inherent vowels",
                "a\u{17b4}\u{17b5}b",
                "a<U+17B4><U+17B5>b",
            ),
            (
                "the Mongolian selectors",
                "a\u{180b}\u{180e}\u{180f}b",
                "a<U+180B><U+180E><U+180F>b",
            ),
            (
                "a zero-width space, non-joiner, and joiner",
                "a\u{200b}\u{200c}\u{200d}b",
                "a<U+200B><U+200C><U+200D>b",
            ),
            (
                "a word joiner and an invisible operator",
                "a\u{2060}\u{2062}b",
                "a<U+2060><U+2062>b",
            ),
            (
                "the deprecated format characters",
                "a\u{206a}\u{206f}b",
                "a<U+206A><U+206F>b",
            ),
            (
                "the variation selectors",
                "a\u{fe00}\u{fe0f}b",
                "a<U+FE00><U+FE0F>b",
            ),
            ("a byte order mark", "\u{feff}ab", "<U+FEFF>ab"),
            (
                "the specials block's reserved and annotation characters",
                "a\u{fff0}\u{fff8}\u{fff9}\u{fffb}b",
                "a<U+FFF0><U+FFF8><U+FFF9><U+FFFB>b",
            ),
            (
                "the shorthand format controls",
                "a\u{1bca0}\u{1bca3}b",
                "a<U+1BCA0><U+1BCA3>b",
            ),
            (
                "the musical format controls",
                "a\u{1d173}\u{1d17a}b",
                "a<U+1D173><U+1D17A>b",
            ),
            (
                "the tag block",
                "a\u{e0000}\u{e0041}\u{e01ef}\u{e0fff}b",
                "a<U+E0000><U+E0041><U+E01EF><U+E0FFF>b",
            ),
        ] {
            assert_eq!(escape_line(text), shown, "{class}");
        }
    }

    /// The characters on either side of each escaped range are not escaped — the table
    /// names the ranges exactly.
    #[test]
    fn the_neighbours_of_each_escaped_range_are_left_alone() {
        for c in [
            '\t',
            ' ',
            '~',
            '\u{a0}',
            '\u{ac}',
            '\u{ae}',
            '\u{34e}',
            '\u{350}',
            '\u{61b}',
            '\u{61d}',
            '\u{115e}',
            '\u{1161}',
            '\u{17b3}',
            '\u{17b6}',
            '\u{180a}',
            '\u{1810}',
            '\u{200a}',
            '\u{2010}',
            '\u{2027}',
            '\u{202f}',
            '\u{205f}',
            '\u{2070}',
            '\u{3163}',
            '\u{3165}',
            '\u{fdcf}',
            '\u{fdf0}',
            '\u{fdff}',
            '\u{fe10}',
            '\u{fefe}',
            '\u{ff00}',
            '\u{ff9f}',
            '\u{ffa1}',
            '\u{ffef}',
            '\u{fffc}',
            '\u{fffd}',
            '\u{1bc9f}',
            '\u{1bca4}',
            '\u{1d172}',
            '\u{1d17b}',
            '\u{dffff}',
            '\u{e1000}',
        ] {
            assert!(!is_escaped(c), "U+{:04X}", u32::from(c));
        }
    }

    /// Ordinary text is returned as it is, borrowed: what a shell command is made of,
    /// and non-ASCII text — accents, CJK, Arabic, Devanagari, a lone emoji, a no-break
    /// space.
    #[test]
    fn escape_line_leaves_ordinary_text_alone() {
        for ordinary in [
            "printf '%s\\n' \"$HOME\" `date` | grep -vxF 'é — ü' > /tmp/x~ {} [] #",
            "naïve café — Ærøskøbing",
            "日本語のテキスト、한국어, 中文",
            "مرحبا بالعالم",
            "नमस्ते",
            "🚀 shipped ✓ → ±",
            "non\u{a0}breaking",
        ] {
            assert!(
                matches!(escape_line(ordinary), Cow::Borrowed(text) if text == ordinary),
                "{ordinary:?}"
            );
        }
    }

    /// An emoji that is a sequence shows what joins it: the invisible characters are
    /// written out wherever they stand.
    #[test]
    fn an_emoji_sequence_shows_its_joiners() {
        assert_eq!(
            escape_line("👨\u{200d}👩 ❤\u{fe0f}"),
            "👨<U+200D>👩 ❤<U+FE0F>"
        );
    }

    /// Escaping what is already escaped changes nothing, so a string that passes two
    /// renders on its way out reads the same as one that passes one.
    #[test]
    fn escape_line_is_idempotent() {
        let hostile = "a\nb\r\u{1b}[2K\u{202e}c\u{200b}\u{feff}d\u{e0041}\te<U+000D>";
        let once = escape_line(hostile).into_owned();
        assert_eq!(
            once,
            "a<U+000A>b<U+000D><U+001B>[2K<U+202E>c<U+200B><U+FEFF>d<U+E0041>        e<U+000D>"
        );
        assert!(matches!(escape_line(&once), Cow::Borrowed(_)));
    }

    /// A tab becomes spaces up to the next multiple of eight characters of the text as
    /// written — at least one — so no tab is printed: a run of them is a run of spaces,
    /// and an escaped character before a tab counts for the eight or nine it takes.
    #[test]
    fn escape_line_expands_a_tab_to_the_next_stop_of_the_text() {
        for (text, shown) in [
            ("\t", "        "),
            ("a\tb", "a       b"),
            ("1234567\tb", "1234567 b"),
            ("12345678\tb", "12345678        b"),
            ("\t\t\tx", "                        x"),
            ("é\tb", "é       b"),
            ("\r\tb", "<U+000D>        b"),
            ("\u{e0041}\tb", "<U+E0041>       b"),
            ("a\t\rb", "a       <U+000D>b"),
        ] {
            assert_eq!(escape_line(text), shown, "{text:?}");
            assert!(matches!(escape_line(shown), Cow::Borrowed(_)), "{text:?}");
        }
    }

    /// The JSON stream's line: each character of the escaped set becomes a `\u` escape
    /// — a surrogate pair above U+FFFF — so the line holds none of them and parses to
    /// the value it was written from.
    #[test]
    fn escape_json_line_respells_the_escaped_set() {
        let value = serde_json::json!({
            "error": "a\u{7f}b\u{9b}2K\u{2028}c\u{202e}d\u{200b}e\u{feff}f\u{e0041}g\u{1d173}h",
            "ordinary": "tab\there, é 日本 🚀 \"quoted\" back\\slash\nline\u{1b}",
        });
        let json = serde_json::to_string(&value).unwrap();
        let line = escape_json_line(&json);
        assert_eq!(
            line,
            "{\"error\":\"a\\u007fb\\u009b2K\\u2028c\\u202ed\\u200be\\ufefff\\udb40\\udc41g\\ud834\\udd73h\",\
             \"ordinary\":\"tab\\there, é 日本 🚀 \\\"quoted\\\" back\\\\slash\\nline\\u001b\"}"
        );
        assert!(!line.contains(is_escaped) && !line.contains(char::is_control));
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&line).unwrap(),
            value
        );
        assert!(matches!(
            escape_json_line("{\"a\":\"é 🚀\"}"),
            Cow::Borrowed(_)
        ));
    }

    /// A reference a text holds inert is written `{env:NAME}`, wherever it stands and
    /// however many there are; the column a later tab is expanded from counts it as
    /// written.
    #[test]
    fn a_reference_is_written_in_its_shown_form() {
        let (host, dir) = (marker("DEPLOY_HOST"), marker("APP_DIR"));
        for (text, shown) in [
            (host.clone(), "{env:DEPLOY_HOST}".to_owned()),
            (
                format!("scp x {host}:{dir}/releases"),
                "scp x {env:DEPLOY_HOST}:{env:APP_DIR}/releases".to_owned(),
            ),
            (
                format!("{host}{dir}"),
                "{env:DEPLOY_HOST}{env:APP_DIR}".to_owned(),
            ),
            (format!("{dir}\tx"), "{env:APP_DIR}   x".to_owned()),
            (format!("a\r{dir}"), "a<U+000D>{env:APP_DIR}".to_owned()),
        ] {
            assert_eq!(escape_line(&text), shown, "{text:?}");
            assert!(matches!(escape_line(&shown), Cow::Borrowed(_)));
        }
        let mut block = String::new();
        render_block(&mut block, "  > ", &format!("cd {dir}\nls {host}"));
        assert_eq!(block, "  > cd {env:APP_DIR}\n    ls {env:DEPLOY_HOST}\n");
        assert_eq!(
            escape_join([&host, "plain"], ", "),
            "{env:DEPLOY_HOST}, plain"
        );
    }

    /// The notation is for reading: literal text that spells `{env:NAME}` prints the
    /// same as a reference does. What tells them apart is the declared `target:` line
    /// and the plan hash, which hold the typed form.
    #[test]
    fn literal_text_can_spell_the_shown_form() {
        let reference = escape_line(&marker("HOME")).into_owned();
        let literal = escape_line("{env:HOME}").into_owned();
        assert_eq!(reference, literal);
        assert_ne!(marker("HOME"), "{env:HOME}");
    }

    /// A delimiter that is no part of a well-formed reference — and any other
    /// noncharacter of its block — is written out as its code point, never dropped and
    /// never printed raw, by every sink.
    #[test]
    fn a_delimiter_out_of_place_is_written_out() {
        for (text, shown) in [
            ("a\u{fdd0}b", "a<U+FDD0>b"),
            ("a\u{fdd1}b", "a<U+FDD1>b"),
            ("\u{fdd0}\u{fdd1}", "<U+FDD0><U+FDD1>"),
            ("\u{fdd0}not a name\u{fdd1}", "<U+FDD0>not a name<U+FDD1>"),
            ("\u{fdd0}aZ:NAME\u{fdd1}", "<U+FDD0>aZ:NAME<U+FDD1>"),
            ("\u{fdd1}NAME\u{fdd0}", "<U+FDD1>NAME<U+FDD0>"),
            ("\u{fdd0}\u{fdd0}X\u{fdd1}", "<U+FDD0>{env:X}"),
            ("a\u{fdd2}\u{fdef}b", "a<U+FDD2><U+FDEF>b"),
        ] {
            assert_eq!(escape_line(text), shown, "{text:?}");
            let json = serde_json::to_string(text).unwrap();
            let line = escape_json_line(&json);
            assert!(!line.contains(is_escaped), "{line}");
        }
        for c in ('\u{fdd0}'..='\u{fdef}').chain(['\u{202e}']) {
            let text = format!("x{c}y");
            assert!(!escape_line(&text).contains(c));
            let mut block = String::new();
            render_block(&mut block, "> ", &text);
            assert!(!block.contains(c));
            assert!(!escape_join([&text], ",").contains(c));
            assert!(!escape_json_line(&serde_json::to_string(&text).unwrap()).contains(c));
        }
    }

    /// The JSON stream shows a reference the way a person reads one, and respells a
    /// stray delimiter as the escape a parser reads back as that character.
    #[test]
    fn escape_json_line_shows_a_reference() {
        let value = serde_json::json!({"error": format!("`{}` was not run", marker("APP"))});
        let line = escape_json_line(&serde_json::to_string(&value).unwrap()).into_owned();
        assert_eq!(line, "{\"error\":\"`{env:APP}` was not run\"}");

        let stray = serde_json::json!({"error": "a\u{fdd0}b"});
        let line = escape_json_line(&serde_json::to_string(&stray).unwrap()).into_owned();
        assert_eq!(line, "{\"error\":\"a\\ufdd0b\"}");
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&line).unwrap(),
            stray
        );
    }

    #[test]
    fn escape_join_escapes_each_item() {
        assert_eq!(
            escape_join(["a", "b\nc", "d\u{1b}"], ", "),
            "a, b<U+000A>c, d<U+001B>"
        );
        assert_eq!(escape_join(Vec::<String>::new(), ", "), "");
        assert_eq!(escape_join(["one"], " "), "one");
    }

    /// Colour sequences are dropped whole; every other sequence, and an unfinished one,
    /// is left for the escape to show.
    #[test]
    fn strip_sgr_drops_colour_and_nothing_else() {
        for (text, stripped) in [
            ("plain", "plain"),
            (
                "\u{1b}[0m\u{1b}[1m\u{1b}[31merror\u{1b}[0m: boom",
                "error: boom",
            ),
            ("a\u{1b}[38;5;245mb\u{1b}[mc", "abc"),
            ("a\u{1b}[38:2::1:2:3mb", "ab"),
            ("up\u{1b}[1A erase\u{1b}[2K", "up\u{1b}[1A erase\u{1b}[2K"),
            ("cut \u{1b}[31", "cut \u{1b}[31"),
            ("end \u{1b}[", "end \u{1b}["),
            ("\u{1b}[\u{1b}[0mx", "\u{1b}[x"),
            ("osc \u{1b}]0;title\u{7}", "osc \u{1b}]0;title\u{7}"),
            ("é\u{1b}[1mü\u{1b}[0m日", "éü日"),
        ] {
            assert_eq!(strip_sgr(text), stripped, "{text:?}");
        }
        assert!(matches!(strip_sgr("plain"), Cow::Borrowed(_)));
    }

    /// A block keeps a multi-line text's lines under its lead — none starts at column
    /// zero — shows a carriage return instead of obeying it, and shows a trailing
    /// newline as a last, empty line.
    #[test]
    fn render_block_keeps_every_line_under_its_lead() {
        let render = |text: &str| {
            let mut out = String::new();
            render_block(&mut out, "    > ", text);
            out
        };
        assert_eq!(render("make"), "    > make\n");
        assert_eq!(
            render("set -e\nplan_hash: 0000\r\nmake\n"),
            "    > set -e\n      plan_hash: 0000<U+000D>\n      make\n      \n"
        );
        assert_eq!(render(""), "    > \n");
    }

    /// A tab-indented script keeps its shape: each line's tabs are stops of that line,
    /// so the lines stay aligned with each other under the lead, and no tab is printed.
    #[test]
    fn render_block_keeps_a_tab_indented_script_aligned() {
        let mut out = String::new();
        render_block(
            &mut out,
            "      > ",
            "if true; then\n\techo a\tb\n\t\tdeeper\nfi\t# done",
        );
        assert_eq!(
            out,
            "      > if true; then\n                echo a  b\n                        \
             deeper\n        fi      # done\n"
        );
        assert!(!out.contains('\t'));
    }

    /// A lead is measured in characters, not bytes: the continuation lines of a block
    /// under a non-ASCII lead line up with its first.
    #[test]
    fn render_block_indents_to_the_leads_width_in_characters() {
        let mut out = String::new();
        render_block(&mut out, "  é — ", "a\nb");
        assert_eq!(out, "  é — a\n      b\n");
    }
}
