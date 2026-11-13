//! Text that takes references — the type of every config field a consumer resolves.
//!
//! A config field is a [`Text`] when detection, execution, or a hash substitutes the
//! references in it, and a `String` when its text is used as written. So which fields
//! take a reference is a fact of the schema: the scanners that collect reference names
//! (the wetrun's env gate, the secret registry, the unverifiable scan) and the last-run
//! report's hashes read the `Text`s a config holds
//! ([`ZapConfig::for_each_text`](crate::schema::ZapConfig::for_each_text)), and a
//! reference declared in a `String` field does not parse
//! ([`ZapConfig::from_wire`](crate::schema::ZapConfig::from_wire)).
//!
//! A `Text` holds the **inert** form: the text as declared, each reference a
//! [`var_ref::marker`]. It derefs to that `str`, so a field composes into a command or
//! a path as a string does — the reference rides along and resolves where the composed
//! text does. It has no `Display`: a caller that formats one names which form it means
//! ([`as_inert`](Text::as_inert), or a [`resolve`](Text::resolve)d value).
//!
//! Every delimiter a `Text` holds is part of a well-formed marker. Each constructor
//! checks it, so text can't smuggle a reference in and no `Text` holds half of one.
//!
//! # The wire form
//!
//! A `Text` is typed on the wire, one form per value:
//!
//! | The text | Its JSON |
//! |---|---|
//! | no reference | `"text"` |
//! | one reference and nothing else | `{"$env": "NAME"}` |
//! | anything else | `{"$text": ["literal", {"$env": "NAME"}, …]}` |
//!
//! A `$text` holds at least two pieces, no empty literal, and no two literals in a row,
//! and a plain string holds no delimiter. Anything else is rejected, so a value has one
//! spelling and a hash over the wire form is a hash of the value.

use std::fmt;
use std::ops::Deref;

use serde::de::{self, MapAccess, SeqAccess, Visitor};
use serde::ser::{SerializeMap, SerializeSeq};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use thiserror::Error;

use crate::scalar::is_env_var_name;
use crate::var_ref::{self, Segment, Segments};

/// The wire key of a reference: `{"$env": "NAME"}`.
pub const ENV_KEY: &str = "$env";

/// The wire key of a text with a reference among other pieces: `{"$text": […]}`.
pub const TEXT_KEY: &str = "$text";

/// Why a [`Text`] can't be built from what it was given.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum InvalidText {
    /// A referenced name that isn't an environment variable's.
    #[error(
        "`{0}` is not a name a reference can take: expected a leading letter or `_` \
         followed by letters, digits, or `_` (e.g. `DEPLOY_HOST`)"
    )]
    Name(String),
    /// Text holding a reference delimiter outside a well-formed reference.
    #[error(
        "the text holds a reference delimiter (U+FDD0 or U+FDD1) that is no part of a \
         reference; a reference is declared with `zap.env`"
    )]
    Delimiter,
}

/// A config string whose references a consumer resolves. See the module docs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Text(String);

impl Text {
    /// The text that is one reference to `name`, and nothing else.
    ///
    /// # Panics
    ///
    /// When `name` isn't an environment variable's name. For a name the caller wrote;
    /// [`try_of_pieces`](Self::try_of_pieces) takes one it was given.
    #[must_use]
    pub fn reference(name: &str) -> Self {
        Self::of_pieces([Segment::Ref(name)])
    }

    /// The text `pieces` spell in order — the inverse of [`pieces`](Text::pieces).
    ///
    /// # Panics
    ///
    /// When [`try_of_pieces`](Self::try_of_pieces) would refuse them. For pieces the
    /// caller wrote.
    #[must_use]
    #[expect(
        clippy::panic,
        reason = "a caller's own constants; the fallible form takes input"
    )]
    pub fn of_pieces<'a>(pieces: impl IntoIterator<Item = Segment<'a>>) -> Self {
        Self::try_of_pieces(pieces).unwrap_or_else(|error| panic!("{error}"))
    }

    /// The text `pieces` spell in order.
    ///
    /// # Errors
    ///
    /// [`InvalidText::Name`] for a referenced name that isn't an environment variable's,
    /// and [`InvalidText::Delimiter`] for a literal piece that holds a delimiter.
    pub fn try_of_pieces<'a>(
        pieces: impl IntoIterator<Item = Segment<'a>>,
    ) -> Result<Self, InvalidText> {
        let mut inert = String::new();
        for piece in pieces {
            match piece {
                Segment::Text(text) => {
                    if var_ref::holds_delimiter(text) {
                        return Err(InvalidText::Delimiter);
                    }
                    inert.push_str(text);
                }
                Segment::Ref(name) => {
                    if !is_env_var_name(name) {
                        return Err(InvalidText::Name(name.to_owned()));
                    }
                    inert.push_str(&var_ref::marker(name));
                }
            }
        }
        Ok(Self(inert))
    }

    /// The text whose inert form is `inert`: each marker in it a reference, the rest
    /// literal.
    ///
    /// # Errors
    ///
    /// [`InvalidText::Delimiter`] when `inert` holds a delimiter that is no part of a
    /// well-formed marker.
    pub fn from_inert(inert: impl Into<String>) -> Result<Self, InvalidText> {
        let inert = inert.into();
        if var_ref::holds_stray_delimiter(&inert) {
            return Err(InvalidText::Delimiter);
        }
        Ok(Self(inert))
    }

    /// The text that is `text` and holds no reference. A delimiter in `text` — which
    /// only a bug could put there — is written out as its code point, so nothing in the
    /// result reads as a reference.
    #[must_use]
    pub fn literal(text: &str) -> Self {
        Self(spell_delimiters(text.to_owned()))
    }

    /// The text as declared, references unresolved — what a plan and a composed command
    /// carry. A render shows it through `zap_core::escape`, which writes each marker in
    /// its shown form.
    #[must_use]
    pub const fn as_inert(&self) -> &str {
        self.0.as_str()
    }

    /// The text split at its references, in order, as [`var_ref::segments`] reads it.
    #[must_use]
    pub const fn pieces(&self) -> Segments<'_> {
        var_ref::segments(self.0.as_str())
    }

    /// The names this text references, in order, as [`var_ref::ref_names`] reads them.
    pub fn ref_names(&self) -> impl Iterator<Item = &str> {
        var_ref::ref_names(&self.0)
    }

    /// The runs of text between this text's references, in order.
    pub fn literals(&self) -> impl Iterator<Item = &str> {
        self.pieces().filter_map(|piece| match piece {
            Segment::Text(text) => Some(text),
            Segment::Ref(_) => None,
        })
    }

    /// The whole text, when it holds no reference.
    #[must_use]
    pub fn as_literal(&self) -> Option<&str> {
        (!var_ref::holds_delimiter(&self.0)).then_some(self.0.as_str())
    }

    /// Whether the text is empty or only whitespace. A reference is neither, whatever
    /// it resolves to.
    #[must_use]
    pub fn is_blank(&self) -> bool {
        self.0.trim().is_empty()
    }

    /// This text with each reference replaced by `var(name)`.
    pub fn resolve(&self, var: impl FnMut(&str) -> String) -> String {
        var_ref::map_refs(&self.0, var)
    }

    /// This text with each literal run replaced by `map(text)` and every reference kept
    /// — how a masker rewrites a text without reaching a reference's name. A delimiter
    /// `map` returns is written out as its code point, so the result holds only the
    /// references this text does.
    #[must_use]
    pub fn map_literals(&self, mut map: impl FnMut(&str) -> String) -> Self {
        Self(var_ref::map_literals(&self.0, |text| {
            spell_delimiters(map(text))
        }))
    }
}

/// `text` with each delimiter written out as its code point.
fn spell_delimiters(text: String) -> String {
    if var_ref::holds_delimiter(&text) {
        text.replace(var_ref::OPEN, "<U+FDD0>")
            .replace(var_ref::CLOSE, "<U+FDD1>")
    } else {
        text
    }
}

impl Deref for Text {
    type Target = str;

    fn deref(&self) -> &str {
        &self.0
    }
}

/// The literal text of a wire value that is a text.
///
/// The string itself, the string pieces of a `$text`, none for a lone `$env`. `None`
/// for any other value — one that is no text, whose own strings a caller walks.
///
/// How a walk over serialized config JSON reads a field that takes a reference as one
/// field and never takes a reference's name for text.
#[must_use]
pub fn wire_literals(value: &serde_json::Value) -> Option<Vec<&str>> {
    use serde_json::Value;
    match value {
        Value::String(text) => Some(vec![text]),
        Value::Object(map) if map.len() == 1 => {
            if matches!(map.get(ENV_KEY), Some(Value::String(_))) {
                return Some(Vec::new());
            }
            match map.get(TEXT_KEY) {
                Some(Value::Array(pieces)) => {
                    Some(pieces.iter().filter_map(Value::as_str).collect())
                }
                _ => None,
            }
        }
        _ => None,
    }
}

/// One piece of a `$text` on the wire.
enum WirePiece {
    Literal(String),
    Reference(String),
}

/// A reference's name, checked.
fn checked_name<E: de::Error>(name: String) -> Result<String, E> {
    if is_env_var_name(&name) {
        Ok(name)
    } else {
        Err(E::custom(InvalidText::Name(name)))
    }
}

/// A plain wire string, checked: it holds no delimiter.
fn checked_literal<E: de::Error>(text: &str) -> Result<(), E> {
    if var_ref::holds_delimiter(text) {
        Err(E::custom(InvalidText::Delimiter))
    } else {
        Ok(())
    }
}

/// Read the one value of a typed node whose key was `key`, and require the node to end.
fn typed_node<'de, A: MapAccess<'de>>(key: &str, mut map: A) -> Result<Text, A::Error> {
    let text = match key {
        ENV_KEY => Text(var_ref::marker(&checked_name(map.next_value()?)?)),
        TEXT_KEY => {
            let pieces: Vec<WirePiece> = map.next_value()?;
            if pieces.len() < 2 {
                return Err(de::Error::custom(format!(
                    "a `{TEXT_KEY}` holds at least two pieces; a text with no reference is \
                     a string, and one reference alone is a `{ENV_KEY}`"
                )));
            }
            let mut inert = String::new();
            let mut after_literal = false;
            for piece in pieces {
                match piece {
                    WirePiece::Literal(text) => {
                        if text.is_empty() {
                            return Err(de::Error::custom(format!(
                                "a `{TEXT_KEY}` holds no empty piece"
                            )));
                        }
                        if after_literal {
                            return Err(de::Error::custom(format!(
                                "a `{TEXT_KEY}` holds no two strings in a row; they are one \
                                 piece"
                            )));
                        }
                        after_literal = true;
                        inert.push_str(&text);
                    }
                    WirePiece::Reference(name) => {
                        after_literal = false;
                        inert.push_str(&var_ref::marker(&name));
                    }
                }
            }
            Text(inert)
        }
        other => {
            return Err(de::Error::custom(format!(
                "unknown key `{other}`: a reference is `{{\"{ENV_KEY}\": \"NAME\"}}` or \
                 `{{\"{TEXT_KEY}\": [...]}}`"
            )));
        }
    };
    if let Some(extra) = map.next_key::<String>()? {
        return Err(de::Error::custom(format!(
            "a reference holds one key, `{key}`; found `{extra}` beside it"
        )));
    }
    Ok(text)
}

impl<'de> Deserialize<'de> for WirePiece {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct PieceVisitor;

        impl<'de> Visitor<'de> for PieceVisitor {
            type Value = WirePiece;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a string or a `$env` reference")
            }

            fn visit_str<E: de::Error>(self, text: &str) -> Result<WirePiece, E> {
                checked_literal(text)?;
                Ok(WirePiece::Literal(text.to_owned()))
            }

            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<WirePiece, A::Error> {
                match map.next_key::<String>()?.as_deref() {
                    Some(ENV_KEY) => {}
                    Some(other) => {
                        return Err(de::Error::custom(format!(
                            "unknown key `{other}`: a piece is a string or a `{ENV_KEY}` \
                             reference"
                        )));
                    }
                    None => return Err(de::Error::invalid_length(0, &self)),
                }
                let name = checked_name(map.next_value()?)?;
                if let Some(extra) = map.next_key::<String>()? {
                    return Err(de::Error::custom(format!(
                        "a reference holds one key, `{ENV_KEY}`; found `{extra}` beside it"
                    )));
                }
                Ok(WirePiece::Reference(name))
            }
        }

        deserializer.deserialize_any(PieceVisitor)
    }
}

impl Serialize for Text {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        /// A reference on the wire.
        struct Reference<'a>(&'a str);

        impl Serialize for Reference<'_> {
            fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                let mut map = serializer.serialize_map(Some(1))?;
                map.serialize_entry(ENV_KEY, self.0)?;
                map.end()
            }
        }

        /// The pieces of a `$text`, in order.
        struct Pieces<'a>(&'a Text);

        impl Serialize for Pieces<'_> {
            fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                let mut seq = serializer.serialize_seq(None)?;
                for piece in self.0.pieces() {
                    match piece {
                        Segment::Text(text) => seq.serialize_element(text)?,
                        Segment::Ref(name) => seq.serialize_element(&Reference(name))?,
                    }
                }
                seq.end()
            }
        }

        let mut pieces = self.pieces();
        match (pieces.next(), pieces.next()) {
            (None, _) => serializer.serialize_str(""),
            (Some(Segment::Text(text)), None) => serializer.serialize_str(text),
            (Some(Segment::Ref(name)), None) => Reference(name).serialize(serializer),
            (Some(_), Some(_)) => {
                let mut map = serializer.serialize_map(Some(1))?;
                map.serialize_entry(TEXT_KEY, &Pieces(self))?;
                map.end()
            }
        }
    }
}

impl<'de> Deserialize<'de> for Text {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct TextVisitor;

        impl<'de> Visitor<'de> for TextVisitor {
            type Value = Text;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a string or a reference")
            }

            fn visit_str<E: de::Error>(self, text: &str) -> Result<Text, E> {
                checked_literal(text)?;
                Ok(Text(text.to_owned()))
            }

            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Text, A::Error> {
                let Some(key) = map.next_key::<String>()? else {
                    return Err(de::Error::invalid_length(0, &self));
                };
                typed_node(&key, map)
            }

            // A sequence is named for what it is, so the error doesn't read as a map's.
            fn visit_seq<A: SeqAccess<'de>>(self, _seq: A) -> Result<Text, A::Error> {
                Err(de::Error::invalid_type(de::Unexpected::Seq, &self))
            }
        }

        deserializer.deserialize_any(TextVisitor)
    }
}

#[cfg(test)]
mod tests {
    #![expect(
        clippy::literal_string_with_formatting_args,
        reason = "`{env:NAME}` is the notation a reference is shown in, written out here as text"
    )]

    use serde_json::{Value, json};

    use super::{InvalidText, Text};
    use crate::var_ref::Segment::{self, Ref, Text as Lit};
    use crate::var_ref::{CLOSE, OPEN, marker};

    /// A text built from pieces is those pieces again, and its inert form is each
    /// literal as written with a marker where each reference is.
    #[test]
    fn a_text_built_from_pieces_reads_back_as_them() {
        let pieces = [Lit("/srv/"), Ref("APP"), Lit("/"), Ref("VERSION")];
        let text = Text::of_pieces(pieces);
        assert_eq!(text.pieces().collect::<Vec<Segment<'_>>>(), pieces);
        assert_eq!(
            text.as_inert(),
            format!("/srv/{}/{}", marker("APP"), marker("VERSION"))
        );
        assert_eq!(text.ref_names().collect::<Vec<_>>(), ["APP", "VERSION"]);
        assert_eq!(text.literals().collect::<Vec<_>>(), ["/srv/", "/"]);
        assert_eq!(text.as_literal(), None);

        let reference = Text::reference("APP");
        assert_eq!(reference.pieces().collect::<Vec<_>>(), [Ref("APP")]);
        assert_eq!(reference.as_inert(), marker("APP"));
        assert_eq!(reference, Text::from_inert(marker("APP")).unwrap());
        assert_eq!(
            Text::of_pieces([Lit("plain")]),
            Text::from_inert("plain").unwrap()
        );
        assert_eq!(Text::of_pieces([Lit("plain")]).as_literal(), Some("plain"));
    }

    /// No constructor builds a text holding a name that is no variable's, or a delimiter
    /// outside a reference.
    #[test]
    fn a_text_cannot_be_built_malformed() {
        for name in ["", "1X", "A-B", "a b", "$$X$$", "X\u{fdd1}"] {
            assert_eq!(
                Text::try_of_pieces([Ref(name)]),
                Err(InvalidText::Name(name.to_owned())),
                "{name:?}"
            );
        }
        for literal in [
            format!("a{OPEN}"),
            format!("{CLOSE}"),
            marker("X"),
            format!("{OPEN}not a name{CLOSE}"),
        ] {
            assert_eq!(
                Text::try_of_pieces([Lit(&literal)]),
                Err(InvalidText::Delimiter),
                "{literal:?}"
            );
        }
        for inert in [
            format!("a{OPEN}X"),
            format!("a{CLOSE}"),
            format!("{OPEN}{CLOSE}"),
            format!("{OPEN}{}", marker("X")),
            format!("{OPEN}x y{CLOSE}"),
        ] {
            assert_eq!(
                Text::from_inert(inert.clone()),
                Err(InvalidText::Delimiter),
                "{inert:?}"
            );
        }
        assert!(Text::from_inert(format!("a{}b", marker("X"))).is_ok());
    }

    /// Each value has one wire form, and reads back from it as itself.
    #[test]
    fn a_text_is_typed_on_the_wire() {
        let cases = [
            (Text::of_pieces([]), json!("")),
            (
                Text::of_pieces([Lit("/srv/app $$ {env:X}")]),
                json!("/srv/app $$ {env:X}"),
            ),
            (Text::reference("APP"), json!({"$env": "APP"})),
            (
                Text::of_pieces([Lit("/srv/"), Ref("APP"), Lit("/data")]),
                json!({"$text": ["/srv/", {"$env": "APP"}, "/data"]}),
            ),
            (
                Text::of_pieces([Ref("A"), Ref("B")]),
                json!({"$text": [{"$env": "A"}, {"$env": "B"}]}),
            ),
            (
                Text::of_pieces([Ref("A"), Lit("b")]),
                json!({"$text": [{"$env": "A"}, "b"]}),
            ),
            // Literal pieces a caller splits are one piece on the wire.
            (
                Text::of_pieces([Lit("a"), Lit("b"), Ref("C")]),
                json!({"$text": ["ab", {"$env": "C"}]}),
            ),
        ];
        for (text, wire) in cases {
            assert_eq!(serde_json::to_value(&text).unwrap(), wire);
            assert_eq!(serde_json::from_value::<Text>(wire.clone()).unwrap(), text);
            // From a string too, where the deserializer sees borrowed text.
            assert_eq!(
                serde_json::from_str::<Text>(&wire.to_string()).unwrap(),
                text
            );
        }
    }

    /// Every other spelling is rejected: a second form of a value some form already
    /// spells, a name that is no variable's, a piece that is no string, and a plain
    /// string holding a delimiter.
    #[test]
    fn a_text_has_no_second_wire_form() {
        let rejected: [(Value, &str); 20] = [
            (json!(5), "expected a string or a reference"),
            (json!(null), "expected a string or a reference"),
            (json!(true), "expected a string or a reference"),
            (json!(["a"]), "expected a string or a reference"),
            (json!({}), "expected a string or a reference"),
            (json!({"$text": []}), "at least two pieces"),
            (json!({"$text": ["only"]}), "at least two pieces"),
            (json!({"$text": [{"$env": "A"}]}), "at least two pieces"),
            (json!({"$text": ["a", "b"]}), "no two strings in a row"),
            (
                json!({"$text": ["a", "b", {"$env": "A"}]}),
                "no two strings in a row",
            ),
            (json!({"$text": ["", {"$env": "A"}]}), "no empty piece"),
            (json!({"$text": [{"$env": "A"}, 5]}), "a string or a `$env`"),
            (
                json!({"$text": [{"$env": "A"}, {"$text": ["a", {"$env": "B"}]}]}),
                "unknown key `$text`",
            ),
            (json!({"$env": "1X"}), "not a name a reference can take"),
            (json!({"$env": ""}), "not a name a reference can take"),
            (json!({"$env": 5}), "expected a string"),
            (
                json!({"$text": ["a", {"$env": "x y"}]}),
                "not a name a reference can take",
            ),
            (json!({"$env": "A", "extra": 1}), "found `extra` beside it"),
            (json!({"env": "A"}), "unknown key `env`"),
            (
                json!({"$text": ["a", {"$env": "A", "$text": []}]}),
                "beside it",
            ),
        ];
        for (wire, message) in rejected {
            let error = serde_json::from_value::<Text>(wire.clone())
                .expect_err(&wire.to_string())
                .to_string();
            assert!(error.contains(message), "{wire}: {error}");
        }
        for raw in [
            marker("X"),
            format!("a{OPEN}"),
            format!("{CLOSE}"),
            format!("/srv/{}/data", marker("APP")),
        ] {
            let error = serde_json::from_value::<Text>(json!(raw))
                .unwrap_err()
                .to_string();
            assert!(error.contains("reference delimiter"), "{error}");
            let piece = json!({"$text": [raw, {"$env": "A"}]});
            assert!(serde_json::from_value::<Text>(piece).is_err());
        }
    }

    #[test]
    fn a_text_names_and_resolves_its_references() {
        let text = Text::of_pieces([
            Ref("SCHEME"),
            Lit("://"),
            Ref("HOST"),
            Lit("/a$$$$b$$open {env:HOST}"),
        ]);
        assert_eq!(text.ref_names().collect::<Vec<_>>(), ["SCHEME", "HOST"]);
        assert_eq!(
            text.resolve(str::to_lowercase),
            "scheme://host/a$$$$b$$open {env:HOST}"
        );
        assert_eq!(&*Text::of_pieces([Lit("plain")]), "plain");
        assert!(Text::of_pieces([Lit(" \n")]).is_blank());
        assert!(!Text::reference("EMPTY").is_blank());
    }

    /// Mapping the literals leaves each reference's name alone, and a delimiter the
    /// mapping returns is written out rather than kept.
    #[test]
    fn mapping_a_texts_literals_keeps_its_references() {
        let text = Text::of_pieces([Lit("KEY at "), Ref("KEY"), Lit("/KEY")]);
        let mapped = text.map_literals(|literal| literal.replace("KEY", "[MASKED:X]"));
        assert_eq!(
            mapped,
            Text::of_pieces([Lit("[MASKED:X] at "), Ref("KEY"), Lit("/[MASKED:X]")])
        );
        let hostile = text.map_literals(|_| marker("OTHER"));
        assert_eq!(hostile.ref_names().collect::<Vec<_>>(), ["KEY"]);
        assert!(Text::from_inert(hostile.as_inert()).is_ok());
        assert!(hostile.as_inert().contains("<U+FDD0>OTHER<U+FDD1>"));

        assert_eq!(Text::literal("sh").as_literal(), Some("sh"));
        assert_eq!(
            Text::literal(&marker("X")).as_literal(),
            Some("<U+FDD0>X<U+FDD1>")
        );
    }
}
