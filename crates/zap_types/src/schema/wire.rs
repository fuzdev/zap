//! A config from its wire JSON — the one way an evaluated config is parsed.
//!
//! [`ZapConfig::from_wire`] is the strict parse plus the diagnosis serde can't give: a
//! reference in a field that takes none fails the parse with a message that names no
//! field (`invalid type: map, expected a string`), so on a failure the wire value is
//! searched for the reference that caused it, and the finding names the field and says
//! why it takes none ([`REASONS`]).
//!
//! Which fields take a reference is the schema's to say — a field that is a
//! [`Text`] — and the diagnosis asks the schema rather than keeping a list of its own:
//! each reference is swapped for a plain word, and the references whose word the parsed
//! config's walk ([`ZapConfig::for_each_text`]) doesn't visit are the misplaced ones.
//!
//! A parse that succeeds is held to the same question: the config must hold, in its
//! [`Text`]s, every reference the wire value declares. A reference where a map of free
//! names goes — a template's `vars` — parses as a variable named `$env`, so the strict
//! parse alone would take it for data.
//!
//! And to one more: each value must be written in the shape its field has. serde reads
//! a derived struct from an array, by position, so `content: ['inline', 'x']` parses;
//! the config it parses to serializes as an object, and a value whose shape differs
//! from the one its field serializes to is a finding ([`misshapen`]).
//!
//! Before any of it, a `null` is a finding ([`null_findings`]): serde reads one as an
//! optional field left out, which would drop a declared `sudo`, `mode` or pin without
//! a word, so the wire form has none — a field is written with its value or left off.
//! The one place a `null` is data is a template variable's value.

use std::collections::BTreeSet;
use std::mem;

use serde::Deserialize;
use serde_json::Value;
use thiserror::Error;

use super::{NESTED_VAR_REFERENCE, ZapConfig};
use crate::text::{ENV_KEY, TEXT_KEY, Text};
use crate::var_ref;

/// Why a config's wire JSON isn't a config.
#[derive(Debug, Error)]
pub enum WireError {
    /// The JSON doesn't parse, or doesn't match the schema.
    #[error("{0}")]
    Parse(#[source] serde_json::Error),
    /// A string holds a reference delimiter as text. A config's builder converts every
    /// reference to its typed form, so one can only arrive here by hand.
    #[error(
        "`{0}` holds a reference delimiter (U+FDD0 or U+FDD1) as text; a reference is \
         declared with `zap.env`"
    )]
    Delimiter(String),
    /// References in fields that take none, one finding each.
    #[error("{}", listed(.0, "references in fields that take none"))]
    Misplaced(Vec<String>),
    /// Values written in a shape their field doesn't have — an array where an object
    /// goes, a number where a name goes — one finding each.
    #[error("{}", listed(.0, "values in a shape their field doesn't take"))]
    Misshapen(Vec<String>),
    /// Values that are `null` where a field's value, or nothing, goes — one finding
    /// each.
    #[error("{}", listed(.0, "values that are null"))]
    Null(Vec<String>),
}

/// The findings as one message: a lone finding as it is, several as a counted list
/// under `heading`.
fn listed(findings: &[String], heading: &str) -> String {
    match findings {
        [finding] => finding.clone(),
        findings => format!(
            "{} {heading}:\n  - {}",
            findings.len(),
            findings.join("\n  - ")
        ),
    }
}

impl ZapConfig {
    /// The config `json` spells — the wire form a config's evaluation emits.
    ///
    /// # Errors
    ///
    /// - [`WireError::Delimiter`] for a string (or a key) holding a reference delimiter.
    /// - [`WireError::Null`] for a `null` anywhere but in a template variable's value,
    ///   each finding naming the field. It is found before the schema is consulted, so
    ///   a config that also holds a misplaced reference or a misshapen value reports its
    ///   `null`s first.
    /// - [`WireError::Misplaced`] for a reference in a field that takes none, each
    ///   finding naming the field and the reason.
    /// - [`WireError::Misshapen`] for a value written in a shape its field doesn't
    ///   have, each finding naming the field and both shapes.
    /// - [`WireError::Parse`] for JSON that doesn't parse or doesn't match the schema
    ///   any other way.
    pub fn from_wire(json: &str) -> Result<Self, WireError> {
        let wire: Value = serde_json::from_str(json).map_err(WireError::Parse)?;
        Self::from_wire_value(&wire)
    }

    /// [`from_wire`](Self::from_wire), from the parsed JSON.
    ///
    /// # Errors
    ///
    /// As [`from_wire`](Self::from_wire).
    pub fn from_wire_value(wire: &Value) -> Result<Self, WireError> {
        if let Some(path) = delimiter_path(wire, "") {
            return Err(WireError::Delimiter(path));
        }
        let nulls = null_findings(wire);
        if !nulls.is_empty() {
            return Err(WireError::Null(nulls));
        }
        let error = match Self::deserialize(wire) {
            Ok(config) if typed_nodes(wire) == config.typed_texts() => {
                let findings = misshapen(wire, &config);
                return if findings.is_empty() {
                    Ok(config)
                } else {
                    Err(WireError::Misshapen(findings))
                };
            }
            // It parses, and a reference in it was read as something other than a
            // reference.
            Ok(_) => None,
            Err(error) => Some(error),
        };
        Err(match (misplaced_references(wire), error) {
            (Diagnosis::Misplaced(findings), _) => WireError::Misplaced(findings),
            (Diagnosis::Other(other), _) => WireError::Parse(other),
            (Diagnosis::Nothing, Some(error)) => WireError::Parse(error),
            (Diagnosis::Nothing, None) => WireError::Misplaced(vec![UNLOCATED.to_owned()]),
        })
    }

    /// How many references this config's [`Text`]s hold, and how many of the texts are
    /// a reference among other pieces — what [`typed_nodes`] counts on the wire.
    fn typed_texts(&self) -> (usize, usize) {
        let (mut references, mut mixed) = (0, 0);
        self.for_each_text(|_, text| {
            let held = text.ref_names().count();
            references += held;
            mixed += usize::from(held > 0 && text.pieces().nth(1).is_some());
        });
        (references, mixed)
    }
}

/// The finding when a reference is known to sit where no field takes one and the field
/// can't be named.
const UNLOCATED: &str = "a reference sits where no field takes one";

/// How many objects under `value` hold a reference's key ([`ENV_KEY`]), and how many a
/// mixed text's ([`TEXT_KEY`]) — the references a wire value declares, wherever they
/// sit.
fn typed_nodes(value: &Value) -> (usize, usize) {
    match value {
        Value::Object(map) => map.values().map(typed_nodes).fold(
            (
                usize::from(map.contains_key(ENV_KEY)),
                usize::from(map.contains_key(TEXT_KEY)),
            ),
            |(references, mixed), (more, more_mixed)| (references + more, mixed + more_mixed),
        ),
        Value::Array(items) => items
            .iter()
            .map(typed_nodes)
            .fold((0, 0), |(references, mixed), (more, more_mixed)| {
                (references + more, mixed + more_mixed)
            }),
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => (0, 0),
    }
}

/// The `null`s of `wire`, one finding each, naming the field: every `null` but one in a
/// `file` template's variable — the variable's value, or anything within it — which is
/// substituted as JSON text ([`TemplateVar::Json`](super::TemplateVar::Json)) and is
/// the one position of the schema that holds JSON as it was written.
///
/// A reference's own node (`{"$env": …}`, `{"$text": […]}`) is not searched: it is a
/// reference or it is a parse error naming the field, and a `null` inside one is the
/// second.
fn null_findings(wire: &Value) -> Vec<String> {
    let mut paths = Vec::new();
    null_paths(wire, "", &mut paths);
    paths
        .into_iter()
        .filter(|path| {
            let in_template_var = kind_at(wire, path) == Some("file")
                && resource_index(path)
                    .is_some_and(|(_, field)| path_matches("content.vars.**", field));
            !in_template_var
        })
        .map(|path| {
            if path.is_empty() {
                return "the config is null; a config is an object".to_owned();
            }
            let (subject, field) = match located(wire, &path) {
                // A resource that is itself `null` has no field to name.
                (_, field) if field.is_empty() => (String::new(), path),
                named => named,
            };
            let what = if field.ends_with(']') {
                "item"
            } else {
                "field"
            };
            format!("{subject}`{field}` is null; leave the {what} out, or write its value")
        })
        .collect()
}

/// Add to `found` the path of every `null` under `value`, a reference's node aside.
fn null_paths(value: &Value, path: &str, found: &mut Vec<String>) {
    match value {
        Value::Null => found.push(path.to_owned()),
        Value::Array(items) => {
            for (index, item) in items.iter().enumerate() {
                null_paths(item, &format!("{path}[{index}]"), found);
            }
        }
        Value::Object(map) if map.contains_key(ENV_KEY) || map.contains_key(TEXT_KEY) => {}
        Value::Object(map) => {
            for (key, child) in map {
                null_paths(child, &join(path, key), found);
            }
        }
        Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
    }
}

/// What a finding calls a value's shape.
const fn shape_name(value: &Value) -> &'static str {
    match value {
        Value::Array(_) => "an array",
        Value::Object(_) => "an object",
        Value::String(_) => "a string",
        Value::Number(_) => "a number",
        Value::Bool(_) => "a boolean",
        Value::Null => "null",
    }
}

/// The finding when a config can't be serialized to compare its shape against.
const UNSHAPED: &str = "the config's shape couldn't be checked against its fields";

/// The values of `wire` written in a shape other than the one `config`, which `wire`
/// parsed to, has there — one finding each.
///
/// The strict parse reads more than the config's one wire form: a struct from an array
/// of its fields in order, an enum tagged by `type` from an array that begins with the
/// tag, and a closed set of names from an object with the name as its one key (and
/// `null` as its value, which [`null_findings`] refuses first). Each of those is a
/// config whose keys were never checked, since it had none. What the parse read is
/// `config`, and `config` serializes in the one form: so a value that is an array where
/// `config` serializes an object, or an object where it serializes a string, was read
/// by one of those routes.
///
/// A value's JSON type is what is compared — array, object, string, number, boolean —
/// so a number where `config` serializes a name is a difference too: the parse reads
/// the tag of a tagged enum (`type`, `scheme`) from its variant's index. A reference
/// where a string goes is an object on the wire and in `config` alike, compared key by
/// key. A template's `vars` serialize as they were written, at every depth, and so
/// never differ — a `null` in one included, the only `null` that reaches here.
///
/// A field `config` leaves off the wire — one at its default — has no serialized shape
/// to compare, and is refused only as a non-empty array: a list left off the wire is
/// empty, and it was written as `[]`, so an array with something in it was read as a
/// struct or an enum. An object there (`extract: {type: 'none'}`) is the field's own
/// form.
fn misshapen(wire: &Value, config: &ZapConfig) -> Vec<String> {
    let Ok(canonical) = serde_json::to_value(config) else {
        return vec![UNSHAPED.to_owned()];
    };
    let mut found = Vec::new();
    shape_differences(wire, Some(&canonical), "", &mut found);
    found
        .into_iter()
        .map(|(path, written, read)| {
            let (subject, field) = located(wire, &path);
            let field = if field.is_empty() {
                "the config".to_owned()
            } else {
                format!("`{field}`")
            };
            let advice = match (written, read) {
                ("an array", Some("an object")) => {
                    "; zap reads an object by its keys, never by position"
                }
                _ => "",
            };
            read.map_or_else(
                || format!("{subject}{field} is {written} where none goes"),
                |read| format!("{subject}{field} is {written} where {read} goes{advice}"),
            )
        })
        .collect()
}

/// Add to `found` the path of each value under `written` whose shape isn't the shape of
/// the value at the same path under `read` (`None`: nothing is serialized there), with
/// both shapes' names.
fn shape_differences(
    written: &Value,
    read: Option<&Value>,
    path: &str,
    found: &mut Vec<(String, &'static str, Option<&'static str>)>,
) {
    let Some(read) = read else {
        if matches!(written, Value::Array(items) if !items.is_empty()) {
            found.push((path.to_owned(), shape_name(written), None));
        }
        return;
    };
    match (written, read) {
        (Value::Array(written), Value::Array(read)) => {
            for (index, item) in written.iter().enumerate() {
                // A list serializes item for item; one that didn't has no item to
                // compare, and the item is held to the rule for a field left off.
                shape_differences(item, read.get(index), &format!("{path}[{index}]"), found);
            }
        }
        (Value::Object(written), Value::Object(read)) => {
            for (key, child) in written {
                shape_differences(child, read.get(key), &join(path, key), found);
            }
        }
        (written, read) if mem::discriminant(written) == mem::discriminant(read) => {}
        (written, read) => {
            found.push((path.to_owned(), shape_name(written), Some(shape_name(read))));
        }
    }
}

/// `path` extended by the object key `key`.
fn join(path: &str, key: &str) -> String {
    if path.is_empty() {
        key.to_owned()
    } else {
        format!("{path}.{key}")
    }
}

/// The path of the first string or object key under `value` that holds a delimiter.
fn delimiter_path(value: &Value, path: &str) -> Option<String> {
    match value {
        Value::String(text) => var_ref::holds_delimiter(text).then(|| path.to_owned()),
        Value::Array(items) => items
            .iter()
            .enumerate()
            .find_map(|(index, item)| delimiter_path(item, &format!("{path}[{index}]"))),
        Value::Object(map) => map.iter().find_map(|(key, child)| {
            let at = join(path, key);
            if var_ref::holds_delimiter(key) {
                return Some(format!(
                    "{} (its name)",
                    at.replace([var_ref::OPEN, var_ref::CLOSE], "?")
                ));
            }
            delimiter_path(child, &at)
        }),
        Value::Null | Value::Bool(_) | Value::Number(_) => None,
    }
}

/// A word stem no string of `wire` holds, so a word built on it is found only where the
/// diagnosis put it. Lowercase letters: a word is then also an account name and a
/// variable's name, and parses wherever a name does.
fn unused_stem(wire: &Value) -> String {
    let text = wire.to_string();
    let mut stem = "zapref".to_owned();
    while text.contains(&stem) {
        stem.push('q');
    }
    stem
}

/// The word standing for the reference numbered `index`.
fn probe_word(stem: &str, index: usize) -> String {
    format!("{stem}_{index}_")
}

/// The numbers of the probe words a text of `config` holds — the references that sit
/// in a field that takes one.
fn visited_words(config: &ZapConfig, stem: &str, count: usize) -> BTreeSet<usize> {
    let mut visited = BTreeSet::new();
    config.for_each_text(|_, text| {
        if text.contains(stem) {
            visited.extend((0..count).filter(|index| text.contains(&probe_word(stem, *index))));
        }
    });
    visited
}

/// What the search for a misplaced reference found.
enum Diagnosis {
    /// References in fields that take none, one finding each.
    Misplaced(Vec<String>),
    /// The config holds references and fails to parse for a reason that names none of
    /// them — the error it gives with a plain word in place of each, which is about
    /// the config rather than about a reference where a string was expected.
    Other(serde_json::Error),
    /// No reference explains the failure: the config holds none.
    Nothing,
}

/// Find the references in `wire` that sit in a field that takes none.
fn misplaced_references(wire: &Value) -> Diagnosis {
    let stem = unused_stem(wire);
    let mut lowered = wire.clone();
    let mut nodes = Vec::new();
    let mut malformed = Vec::new();
    lower(&mut lowered, "", &stem, &mut nodes, &mut malformed);
    if !malformed.is_empty() {
        return Diagnosis::Misplaced(
            malformed
                .into_iter()
                .map(|(path, error)| {
                    let (subject, field) = located(wire, &path);
                    format!("{subject}`{field}` is not a reference zap can read: {error}")
                })
                .collect(),
        );
    }
    if nodes.is_empty() {
        return Diagnosis::Nothing;
    }
    let finding = |path: &str| {
        let (subject, field) = located(wire, path);
        let reason = reason(kind_at(wire, path), &field);
        format!("{subject}`{field}` takes no reference: {reason}")
    };
    match ZapConfig::deserialize(&lowered) {
        // With a plain word where each reference was, the config parses: the misplaced
        // references are the ones in no field the walk visits.
        Ok(config) => {
            let visited = visited_words(&config, &stem, nodes.len());
            let findings: Vec<String> = nodes
                .iter()
                .enumerate()
                .filter(|(index, _)| !visited.contains(index))
                .map(|(_, path)| finding(path))
                .collect();
            if findings.is_empty() {
                Diagnosis::Nothing
            } else {
                Diagnosis::Misplaced(findings)
            }
        }
        // A field that is no string at all — a number, a flag, a closed set, a mode —
        // refuses the word too, and names it.
        Err(error) => {
            let message = error.to_string();
            nodes
                .iter()
                .enumerate()
                .find(|(index, _)| message.contains(&probe_word(&stem, *index)))
                .map_or(Diagnosis::Other(error), |(_, path)| {
                    Diagnosis::Misplaced(vec![finding(path)])
                })
        }
    }
}

/// Replace every typed node under `value` with the string it would be were each of its
/// references a plain word, recording the node's path; a node that isn't a well-formed
/// reference is recorded in `malformed` with the reason.
fn lower(
    value: &mut Value,
    path: &str,
    stem: &str,
    nodes: &mut Vec<String>,
    malformed: &mut Vec<(String, String)>,
) {
    match value {
        Value::Object(map) if map.contains_key(ENV_KEY) || map.contains_key(TEXT_KEY) => {
            match Text::deserialize(&*value) {
                Ok(text) => {
                    let word = probe_word(stem, nodes.len());
                    *value = Value::String(text.resolve(|_| word.clone()));
                    nodes.push(path.to_owned());
                }
                Err(error) => {
                    malformed.push((path.to_owned(), error.to_string()));
                    *value = Value::Null;
                }
            }
        }
        Value::Array(items) => {
            for (index, item) in items.iter_mut().enumerate() {
                lower(item, &format!("{path}[{index}]"), stem, nodes, malformed);
            }
        }
        Value::Object(map) => {
            for (key, child) in map {
                lower(child, &join(path, key), stem, nodes, malformed);
            }
        }
        _ => {}
    }
}

/// The resource a wire path sits in, by its index in `resources`.
fn resource_index(path: &str) -> Option<(usize, &str)> {
    let rest = path.strip_prefix("resources[")?;
    let (index, field) = rest.split_once(']')?;
    Some((
        index.parse().ok()?,
        field.strip_prefix('.').unwrap_or(field),
    ))
}

/// How a finding names the wire `path`: the resource it sits in (`` resource `id`: ``,
/// empty outside one) and the field within it — or the whole path for a field of the
/// target, the `deploy` block, or the config itself.
fn located(wire: &Value, path: &str) -> (String, String) {
    let Some((index, field)) = resource_index(path) else {
        return (String::new(), path.to_owned());
    };
    // No id to name it by when the id is the misplaced reference, or isn't a string.
    let subject = wire["resources"][index]["id"].as_str().map_or_else(
        || format!("resource {}: ", index + 1),
        |id| format!("resource `{id}`: "),
    );
    (subject, field.to_owned())
}

/// The kind of the resource a wire path sits in, when it sits in one that names its.
fn kind_at<'a>(wire: &'a Value, path: &str) -> Option<&'a str> {
    let (index, _) = resource_index(path)?;
    wire["resources"][index]["type"].as_str()
}

/// Why each field that takes no reference takes none: the resource kind (`None` for a
/// field outside a resource), the field's path — `[]` standing for any index and `*`
/// for any one key — and the reason. The first row that matches is the reason; a field
/// in no row is [`AS_WRITTEN`].
const REASONS: &[(Option<&str>, &str, &str)] = &[
    (Some("package"), "from.*", UNQUOTED),
    (Some("package"), "check", COMMAND_CHECK),
    (Some("service"), "service", UNQUOTED),
    (Some("apt_repo"), "source", UNQUOTED),
    (Some("apt_repo"), "key_path", UNQUOTED),
    (Some("apt_repo"), "list_file", AS_DECLARED),
    (Some("user"), "shell", AS_DECLARED),
    (Some("user"), "ssh_keys.keys[]", USER_FILE),
    (Some("user"), "sudo.commands[]", USER_FILE),
    (Some("swap"), "path", AS_DECLARED),
    (Some("firewall"), "allow[]", AS_DECLARED),
    (Some("script"), "cwd", WORKING_DIRECTORY),
    (Some("build"), "cwd", WORKING_DIRECTORY),
    (Some("file"), "content.content", TEMPLATE_VARS),
    (Some("file"), "content.template", TEMPLATE_VARS),
    (Some("file"), "content.vars", VARS_MAP),
    (Some("file"), "content.vars.**", NESTED_VAR_REFERENCE),
    (Some("verify"), "assertions[].run", SCRIPT_CHECK),
    (None, "deploy.service", UNQUOTED),
    (None, "deploy.path", DEPLOY_PATH),
    (None, "deploy.health.path", HEALTH_PATH),
];

const UNQUOTED: &str = "zap puts it into a command outside single quotes, where a shell \
     would read the resolved value, and detection reads the field as declared; write the \
     value out";

const AS_DECLARED: &str = "detection reads the field as declared, so the value a step \
     resolved it to could never read converged; write the value out";

const USER_FILE: &str = "zap installs the text as declared, and detection compares it as \
     declared; write the value out";

const WORKING_DIRECTORY: &str =
    "zap enters a working directory as declared and never resolves it; write the path out";

const DEPLOY_PATH: &str =
    "zap uses the app path as declared and never resolves it; write the path out";

const HEALTH_PATH: &str =
    "of a health gate's fields only `domain` resolves a reference; write the path out";

const TEMPLATE_VARS: &str = "the content is written as declared; put the value in a \
     template's `vars`, which resolve";

const VARS_MAP: &str = "`vars` is a map of variable names to values; a reference goes in a \
     variable's value";

const SCRIPT_CHECK: &str = "the command runs as written; use a `script`, whose `check` resolves";

const COMMAND_CHECK: &str = "only a path check — one that begins `/`, `~`, or `$HOME` — \
     resolves, and a command check runs as written; use a `script`, whose `check` resolves";

const AS_WRITTEN: &str = "this field is used as written";

/// The reason the field at `path` of a resource of `kind` takes no reference.
fn reason(kind: Option<&str>, path: &str) -> &'static str {
    REASONS
        .iter()
        .find(|(row_kind, pattern, _)| *row_kind == kind && path_matches(pattern, path))
        .map_or(AS_WRITTEN, |(.., reason)| reason)
}

/// Whether the field `path` is one `pattern` names: `[]` any index, `*` any one key,
/// and a trailing `**` anything beneath.
pub fn path_matches(pattern: &str, path: &str) -> bool {
    let (mut pattern, mut path) = (pattern, path);
    loop {
        if pattern == "**" {
            return !path.is_empty();
        }
        if let Some(rest) = pattern.strip_prefix("[]") {
            let Some(end) = path.strip_prefix('[').and_then(|after| after.find(']')) else {
                return false;
            };
            (pattern, path) = (rest, &path[end + 2..]);
        } else if let Some(rest) = pattern.strip_prefix('*') {
            let end = path.find(['.', '[']).unwrap_or(path.len());
            if end == 0 {
                return false;
            }
            (pattern, path) = (rest, &path[end..]);
        } else {
            let end = pattern.find(['[', '*']).unwrap_or(pattern.len());
            let Some(rest) = path.strip_prefix(&pattern[..end]) else {
                return false;
            };
            if end == 0 {
                return false;
            }
            (pattern, path) = (&pattern[end..], rest);
        }
        if pattern.is_empty() {
            return path.is_empty();
        }
    }
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};

    use super::{WireError, path_matches, reason};
    use crate::schema::ZapConfig;
    use crate::text::Text;
    use crate::var_ref::Segment::{Ref, Text as Lit};
    use crate::var_ref::marker;

    fn config(resources: &Value) -> Value {
        json!({"target": {"host": "h.example", "service_manager": "systemd"},
               "resources": resources})
    }

    fn findings(wire: &Value) -> Vec<String> {
        match ZapConfig::from_wire_value(wire) {
            Err(WireError::Misplaced(findings)) => findings,
            other => panic!("expected misplaced references, got {other:?}"),
        }
    }

    #[test]
    fn a_path_pattern_matches_its_fields() {
        for (pattern, path, matches) in [
            ("cwd", "cwd", true),
            ("cwd", "cwdx", false),
            ("cwd", "cw", false),
            ("from.*", "from.apt", true),
            ("from.*", "from", false),
            ("from.*", "from.apt.x", false),
            ("allow[]", "allow[0]", true),
            ("allow[]", "allow[12]", true),
            ("allow[]", "allow", false),
            ("ssh_keys.keys[]", "ssh_keys.keys[3]", true),
            ("assertions[].run", "assertions[1].run", true),
            ("assertions[].run", "assertions[1].expect", false),
            ("content.vars.**", "content.vars.a.b[0]", true),
            ("content.vars.**", "content.vars.a", true),
            ("content.vars.**", "content.vars", false),
            ("deploy.health.path", "deploy.health.path", true),
        ] {
            assert_eq!(path_matches(pattern, path), matches, "{pattern} ~ {path}");
        }
        assert!(reason(Some("script"), "cwd").contains("working directory"));
        assert_eq!(reason(Some("script"), "nope"), super::AS_WRITTEN);
        assert_eq!(reason(None, "cwd"), super::AS_WRITTEN);
    }

    /// A config whose references all sit in fields that take one parses, and is the
    /// config a direct parse gives.
    #[test]
    fn a_config_parses_from_its_wire_form() {
        let wire = config(&json!([
            {"id": "d", "type": "directory",
             "path": Text::of_pieces([Lit("/srv/"), Ref("APP")])},
            {"id": "p", "type": "package", "from": {"apt": "x"},
             "check": Text::of_pieces([Lit("~/bin/"), Ref("TOOL")])},
        ]));
        let parsed = ZapConfig::from_wire(&wire.to_string()).unwrap();
        assert_eq!(
            parsed,
            serde_json::from_value::<ZapConfig>(wire.clone()).unwrap()
        );
        assert_eq!(
            serde_json::to_value(&parsed).unwrap()["resources"],
            wire["resources"]
        );
    }

    /// A reference in a field that takes none is a finding naming the resource, the
    /// field, and why — one per reference, each with its field's own reason.
    #[test]
    fn a_reference_in_a_field_that_takes_none_is_named() {
        let reference = || json!(Text::reference("X"));
        let mixed = || json!(Text::of_pieces([Lit("a "), Ref("X"), Lit(" b")]));
        let found = findings(&config(&json!([
            {"id": "motd", "type": "file", "path": "/etc/motd",
             "content": {"type": "inline", "content": mixed()}},
            {"id": "tpl", "type": "file", "path": Text::reference("FINE"),
             "content": {"type": "template", "template": reference(),
                         "vars": {"ok": reference(), "nested": {"deep": [reference()]}}}},
            {"id": "s", "type": "script", "check": "c", "run": mixed(), "cwd": mixed()},
            {"id": "svc", "type": "service", "service": reference()},
            {"id": "pkg", "type": "package", "from": {"apt": reference()},
             "check": Text::of_pieces([Ref("BIN"), Lit("/tool")])},
            {"id": "fw", "type": "firewall", "backend": "ufw",
             "allow": [{"port": 22}, reference()]},
            {"id": "v", "type": "verify",
             "assertions": [{"type": "command", "run": mixed(), "expect": reference()}]},
            {"id": "u", "type": "user", "username": reference(), "shell": reference(),
             "ssh_keys": {"keys": ["ssh-ed25519 AAAA a", mixed()]},
             "sudo": {"mode": "nopasswd", "commands": [mixed()]}},
        ])));
        let expected = [
            "resource `motd`: `content.content` takes no reference: the content is written \
             as declared; put the value in a template's `vars`",
            "resource `tpl`: `content.template` takes no reference: the content is written",
            "resource `tpl`: `content.vars.nested.deep[0]` takes no reference: a reference \
             inside a non-string var is not supported; pass it as its own var",
            "resource `s`: `cwd` takes no reference: zap enters a working directory as \
             declared",
            "resource `svc`: `service` takes no reference: zap puts it into a command \
             outside single quotes",
            "resource `pkg`: `check` takes no reference: only a path check",
            "resource `pkg`: `from.apt` takes no reference: zap puts it into a command",
            "resource `fw`: `allow[1]` takes no reference: detection reads the field as \
             declared",
            "resource `v`: `assertions[0].expect` takes no reference: this field is used \
             as written",
            "resource `v`: `assertions[0].run` takes no reference: the command runs as \
             written; use a `script`, whose `check` resolves",
            "resource `u`: `shell` takes no reference: detection reads the field as declared",
            "resource `u`: `ssh_keys.keys[1]` takes no reference: zap installs the text as \
             declared",
            "resource `u`: `sudo.commands[0]` takes no reference: zap installs the text",
            "resource `u`: `username` takes no reference: this field is used as written",
        ];
        assert_eq!(found.len(), expected.len(), "{found:#?}");
        for (finding, start) in found.iter().zip(expected) {
            assert!(finding.starts_with(start), "{finding}\n  != {start}");
        }
    }

    /// A reference where a map of free names goes parses — as a variable named `$env` —
    /// and is a finding all the same: every reference the wire declares is one a text of
    /// the config holds.
    #[test]
    fn a_reference_where_a_map_of_names_goes_is_named() {
        let vars = |vars: Value| {
            config(&json!([
                {"id": "conf", "type": "file", "path": Text::reference("FINE"),
                 "content": {"type": "template", "template": "{{$env}} {{$text}}", "vars": vars}},
            ]))
        };
        let found = findings(&vars(json!(Text::reference("APP_VARS"))));
        assert_eq!(found.len(), 1, "{found:#?}");
        assert!(
            found[0].starts_with(
                "resource `conf`: `content.vars` takes no reference: `vars` is a map of \
                 variable names to values"
            ),
            "{}",
            found[0]
        );
        let found = findings(&vars(json!(Text::of_pieces([Lit("a"), Ref("APP_VARS")]))));
        assert!(
            found[0].starts_with("resource `conf`: `content.vars` takes no reference: "),
            "{found:#?}"
        );
        // A mixed text's key around no reference is no variable name either.
        assert!(matches!(
            ZapConfig::from_wire_value(&vars(json!({"$text": [1, 2]}))),
            Err(WireError::Misplaced(_))
        ));
        assert!(
            ZapConfig::from_wire_value(&vars(json!({"env": "APP_VARS", "text": [1, 2]}))).is_ok()
        );
    }

    /// Outside a resource the finding names the whole path; a resource's own id, when it
    /// is the reference, is named by position.
    #[test]
    fn a_misplaced_reference_outside_a_resources_fields_is_named() {
        let reference = || json!(Text::reference("X"));
        let mut wire = config(&json!([
            {"id": reference(), "type": "service", "service": "nginx"},
            {"id": "b", "type": "service", "service": "nginx", "depends_on": [reference()]},
        ]));
        wire["target"]["home"] = reference();
        wire["target"]["key_path"] = reference();
        wire["deploy"] = json!({
            "artifacts": ["dist"], "path": reference(), "service": reference(),
            "prepare": [reference()],
            "health": {"domain": reference(), "path": reference()},
        });
        wire["mask_vars"] = json!([reference()]);
        let found = findings(&wire);
        let expected = [
            "`deploy.health.path` takes no reference: of a health gate's fields only \
             `domain` resolves a reference",
            "`deploy.path` takes no reference: zap uses the app path as declared",
            "`deploy.prepare[0]` takes no reference: this field is used as written",
            "`deploy.service` takes no reference: zap puts it into a command outside",
            "`mask_vars[0]` takes no reference: this field is used as written",
            "resource 1: `id` takes no reference: this field is used as written",
            "resource `b`: `depends_on[0]` takes no reference: this field is used as written",
            "`target.home` takes no reference: this field is used as written",
            "`target.key_path` takes no reference: this field is used as written",
        ];
        assert_eq!(found.len(), expected.len(), "{found:#?}");
        for (finding, start) in found.iter().zip(expected) {
            assert!(finding.starts_with(start), "{finding}\n  != {start}");
        }
    }

    /// A reference where a field is no string at all — a number, a flag, a closed set, a
    /// mode, a pin — is a finding too.
    #[test]
    fn a_reference_in_a_field_that_is_no_string_is_named() {
        let reference = || json!(Text::reference("X"));
        for (resource, field) in [
            (
                json!({"id": "x", "type": "service", "service": "n", "enabled": reference()}),
                "enabled",
            ),
            (
                json!({"id": "x", "type": "directory", "path": "/d", "mode": reference()}),
                "mode",
            ),
            (
                json!({"id": "x", "type": "firewall", "backend": "ufw",
                       "allow": [{"port": reference()}]}),
                "allow[0].port",
            ),
            (
                json!({"id": "x", "type": "firewall", "backend": "ufw",
                       "default_incoming": reference(), "allow": []}),
                "default_incoming",
            ),
            (
                json!({"id": "x", "type": "file", "path": "/f",
                       "content": {"type": "remote", "url": "https://h/x", "blake3": reference()}}),
                "content.blake3",
            ),
        ] {
            let found = findings(&config(&json!([resource])));
            assert_eq!(found.len(), 1, "{found:#?}");
            assert!(
                found[0].starts_with(&format!(
                    "resource `x`: `{field}` takes no reference: this field is used as written"
                )),
                "{}",
                found[0]
            );
        }
        let mut wire = config(&json!([]));
        wire["target"]["port"] = reference();
        let found = findings(&wire);
        assert!(
            found[0].starts_with("`target.port` takes no reference"),
            "{found:#?}"
        );
    }

    /// One finding is the whole message; several are a counted list, one to a line.
    #[test]
    fn findings_are_listed_one_to_a_line() {
        let reference = || json!(Text::reference("X"));
        let one = config(&json!([{"id": "s", "type": "service", "service": reference()}]));
        let message = ZapConfig::from_wire_value(&one).unwrap_err().to_string();
        assert!(
            message.starts_with("resource `s`: `service` takes no reference: "),
            "{message}"
        );
        assert_eq!(message.lines().count(), 1);

        let two = config(&json!([
            {"id": "s", "type": "service", "service": reference()},
            {"id": "w", "type": "swap", "size": "1G", "path": reference()},
        ]));
        let message = ZapConfig::from_wire_value(&two).unwrap_err().to_string();
        let lines: Vec<&str> = message.lines().collect();
        assert_eq!(lines.len(), 3, "{message}");
        assert_eq!(lines[0], "2 references in fields that take none:");
        assert!(lines[1].starts_with("  - resource `s`: `service` takes no reference: "));
        assert!(lines[2].starts_with("  - resource `w`: `path` takes no reference: "));
    }

    /// A failure no reference explains is serde's own error; a malformed reference is
    /// named with its field; and a delimiter in a plain string never reaches the parse.
    #[test]
    fn other_failures_keep_their_own_error() {
        let unknown = config(&json!([
            {"id": "d", "type": "directory", "path": Text::reference("FINE"), "ownr": "x"},
        ]));
        match ZapConfig::from_wire_value(&unknown) {
            Err(WireError::Parse(error)) => {
                assert!(
                    error.to_string().contains("unknown field `ownr`"),
                    "{error}"
                );
            }
            other => panic!("{other:?}"),
        }
        // With a misplaced reference beside it, the config's own error is still the one
        // reported: it is what stands between the config and a reading of its fields.
        let both = config(&json!([
            {"id": "f", "type": "firewall", "allow": [Text::reference("PROFILE")]},
        ]));
        match ZapConfig::from_wire_value(&both) {
            Err(WireError::Parse(error)) => {
                assert!(
                    error.to_string().contains("missing field `backend`"),
                    "{error}"
                );
            }
            other => panic!("{other:?}"),
        }
        assert!(matches!(
            ZapConfig::from_wire("not json"),
            Err(WireError::Parse(_))
        ));

        let malformed = config(&json!([
            {"id": "d", "type": "directory", "path": {"$env": "not a name"}},
        ]));
        let found = findings(&malformed);
        assert_eq!(found.len(), 1);
        assert!(
            found[0].starts_with(
                "resource `d`: `path` is not a reference zap can read: `not a name` is not a \
                 name a reference can take"
            ),
            "{}",
            found[0]
        );

        for (raw, at) in [
            (
                config(&json!([{"id": "s", "type": "service", "service": marker("X")}])),
                "resources[0].service",
            ),
            (
                config(&json!([{"id": "d", "type": "directory", "path": marker("X")}])),
                "resources[0].path",
            ),
            (
                config(
                    &json!([{"id": "s", "type": "script", "check": "c", "run": "r",
                               "env": {marker("X"): "v"}}]),
                ),
                "resources[0].env.?X? (its name)",
            ),
        ] {
            match ZapConfig::from_wire_value(&raw) {
                Err(WireError::Delimiter(path)) => assert_eq!(path, at),
                other => panic!("{other:?}"),
            }
        }
    }

    fn misshapen(wire: &Value) -> Vec<String> {
        match ZapConfig::from_wire_value(wire) {
            Err(WireError::Misshapen(findings)) => findings,
            other => panic!("expected values in another shape, got {other:?}"),
        }
    }

    /// A value written as an array where its field is an object, or as an object where
    /// it is a name, parses — serde reads a struct by position and a closed set from a
    /// one-key object — and is a finding naming the field and both shapes.
    #[test]
    fn a_value_in_a_shape_its_field_does_not_have_is_named() {
        const BY_KEYS: &str = " is an array where an object goes; zap reads an object by \
                               its keys, never by position";
        let file = |content: Value| {
            config(&json!([{"id": "f", "type": "file", "path": "/f", "content": content}]))
        };
        let remote = |field: &str, value: Value| {
            let mut content = json!({"type": "remote", "url": "https://e.x/a"});
            content[field] = value;
            file(content)
        };
        let build = |source: Value| {
            config(
                &json!([{"id": "b", "type": "build", "source": source, "run": "make",
                            "output": "/usr/local/bin/b"}]),
            )
        };
        let verify = |assertions: Value| {
            config(&json!([{"id": "v", "type": "verify", "assertions": assertions}]))
        };
        let target = |target: Value| json!({"target": target, "resources": []});
        let deploy = |deploy: Value| {
            let mut wire = config(&json!([]));
            wire["deploy"] = deploy;
            wire
        };
        let by_keys = |at: &str| format!("{at}{BY_KEYS}");
        for (wire, expected) in [
            (
                file(json!(["inline", "x"])),
                by_keys("resource `f`: `content`"),
            ),
            (
                file(json!(["template", "hi", {}])),
                by_keys("resource `f`: `content`"),
            ),
            (
                file(json!(["source", "/etc/x"])),
                by_keys("resource `f`: `content`"),
            ),
            (
                file(json!(["remote", "https://e.x/a"])),
                by_keys("resource `f`: `content`"),
            ),
            (
                remote("auth", json!(["bearer", "t"])),
                by_keys("resource `f`: `content.auth`"),
            ),
            (
                remote("auth", json!(["bearer", Text::reference("TOKEN")])),
                by_keys("resource `f`: `content.auth`"),
            ),
            (
                build(json!(["remote", "https://e.x/a"])),
                by_keys("resource `b`: `source`"),
            ),
            (
                build(json!({"type": "remote", "url": "https://e.x/a",
                             "verify": ["minisign", "RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3"]})),
                by_keys("resource `b`: `source.verify`"),
            ),
            (
                verify(json!([["command", "true"]])),
                by_keys("resource `v`: `assertions[0]`"),
            ),
            (
                verify(json!([{"type": "command", "run": "true"}, ["path_exists", "/tmp"]])),
                by_keys("resource `v`: `assertions[1]`"),
            ),
            (target(json!([true])), by_keys("`target`")),
            (target(json!([false, "127.0.0.1"])), by_keys("`target`")),
            (
                deploy(json!(["gro build", ["dist"], "/srv/app"])),
                by_keys("`deploy`"),
            ),
            (
                deploy(json!({"artifacts": ["dist"], "path": "/srv/app",
                              "health": ["app.example", "/health"]})),
                by_keys("`deploy.health`"),
            ),
            (
                config(
                    &json!([{"id": "s", "type": "script", "check": "c", "run": "r",
                                "depends_on": []},
                               {"id": "d", "type": "database", "engine": "postgresql",
                                "database_name": "d", "username": "u",
                                "auth": ["scram-sha-256", ["10.0.0.0/8"]]},
                               {"id": "f", "type": "file", "path": "/f",
                                "content": {"type": 0, "content": "x"}}]),
                ),
                "2 values in a shape their field doesn't take:\n  \
                 - resource `d`: `auth` is an array where an object goes; zap reads an \
                 object by its keys, never by position\n  \
                 - resource `f`: `content.type` is a number where a string goes"
                    .to_owned(),
            ),
            (
                file(json!({"type": 0, "content": "x"})),
                "resource `f`: `content.type` is a number where a string goes".to_owned(),
            ),
            (
                config(&json!([{"id": "f", "type": 6, "path": "/f",
                                "content": {"type": "inline", "content": "x"}}])),
                "resource `f`: `type` is a number where a string goes".to_owned(),
            ),
            (
                remote("auth", json!({"scheme": 0, "token": "t"})),
                "resource `f`: `content.auth.scheme` is a number where a string goes".to_owned(),
            ),
            (
                verify(json!([{"type": 1, "run": "true"}])),
                "resource `v`: `assertions[0].type` is a number where a string goes".to_owned(),
            ),
            (
                json!([{"host": "h.example"}, []]),
                "the config is an array where an object goes; zap reads an object by its \
                 keys, never by position"
                    .to_owned(),
            ),
        ] {
            let message = ZapConfig::from_wire_value(&wire).map_or_else(
                |error| {
                    assert!(
                        matches!(error, WireError::Misshapen(_)),
                        "{wire}: {error:?}"
                    );
                    error.to_string()
                },
                |_| panic!("{wire} parsed"),
            );
            assert_eq!(message, expected, "{wire}");
        }
        assert_eq!(misshapen(&target(json!([true]))).len(), 1);
    }

    /// Every shape a field does take still parses: the forms a field has more than one
    /// of, a field at its default (left off the config's serialized form) written out,
    /// and a template's variables of any shape at any depth, a `null` among them.
    #[test]
    fn a_value_in_its_fields_own_shape_parses() {
        let mut wire = config(&json!([
            {"id": "u", "type": "user", "username": "deploy", "groups": [],
             "ssh_keys": {"keys": ["ssh-ed25519 AAAA a"]},
             "sudo": {"mode": "nopasswd", "commands": ["/bin/ls"]}},
            {"id": "u2", "type": "user", "username": "ops", "sudo": "password",
             "ssh_keys": {"copy_from": "root"}, "groups": ["adm"]},
            {"id": "u3", "type": "user", "username": "gone", "sudo": false},
            {"id": "fw", "type": "firewall", "backend": "nftables",
             "allow": ["OpenSSH", {"port": 53, "proto": "udp"}, {"port": 22}]},
            {"id": "p", "type": "package", "from": {"apt": "curl", "apk": "curl"},
             "check": Text::of_pieces([Lit("~/bin/"), Ref("TOOL")]), "depends_on": []},
            {"id": "p2", "type": "package", "from": {}, "check": "command -v curl"},
            {"id": "f", "type": "file", "path": "/f", "mode": "0644", "triggers": [],
             "content": {"type": "remote", "url": Text::reference("URL"),
                         "extract": {"type": "none"},
                         "auth": {"scheme": "bearer", "token": Text::reference("TOKEN")}}},
            {"id": "f2", "type": "file", "path": "/f2",
             "content": {"type": "remote", "url": "https://e.x/a.tar.gz",
                         "extract": {"type": "tar.gz", "strip_components": 0}}},
            {"id": "t", "type": "file", "path": "/t",
             "content": {"type": "template", "template": "{{a}}{{b}}{{c}}{{d}}{{e}}",
                         "vars": {"a": ["inline", "x"], "b": {"ufw": null}, "c": [],
                                  "d": [[{"k": [1, "two", null]}]], "e": null,
                                  "f": Text::reference("V"), "g": 8080, "h": {}}}},
            {"id": "v", "type": "verify",
             "assertions": [{"type": "path_exists", "path": "/tmp", "not_empty": false},
                            {"type": "command", "run": "true"}]},
            {"id": "s", "type": "script", "check": "c", "run": "r", "env": {}},
            {"id": "d", "type": "database", "engine": "postgresql", "database_name": "d",
             "username": "u", "auth": {"hosts": []}},
            {"id": "pl", "type": "pipeline", "steps": [], "env": {}},
        ]));
        wire["target"] = json!({"host": Text::reference("HOST"), "port": 22,
                                "package_manager": "apt", "service_manager": "systemd",
                                "local": false});
        wire["deploy"] = json!({"artifacts": [], "path": "/srv/app", "shared": [],
                                "prepare": []});
        wire["mask_vars"] = json!([]);
        ZapConfig::from_wire_value(&wire).unwrap();
        ZapConfig::from_wire_value(&json!({"target": {"local": true}, "resources": []})).unwrap();
    }

    /// A field the config leaves off its serialized form has no shape there to compare:
    /// an array with something in it is refused, and an empty one, an object and a
    /// scalar pass. In a list, an item past the serialized list's end is held to
    /// the same rule.
    #[test]
    fn a_field_left_off_the_serialized_form_takes_no_filled_array() {
        let differences = |written: Value, read: Option<Value>| {
            let mut found = Vec::new();
            super::shape_differences(&written, read.as_ref(), "", &mut found);
            found
        };
        assert_eq!(
            differences(json!({"extract": ["none"]}), Some(json!({}))),
            [("extract".to_owned(), "an array", None)]
        );
        for passes in [
            json!({"extract": {"type": "none"}}),
            json!({"depends_on": []}),
            json!({"not_empty": false}),
            json!({"strip_components": 0}),
        ] {
            assert_eq!(differences(passes, Some(json!({}))), []);
        }
        assert_eq!(
            differences(json!([1, ["x"], {}]), Some(json!([1]))),
            [("[1]".to_owned(), "an array", None)]
        );
        // A scalar is compared by its JSON type: a number is no name.
        assert_eq!(
            differences(
                json!({"a": 1, "b": "x", "c": 2, "d": "y", "e": false}),
                Some(json!({"a": "1", "b": true, "c": 3, "d": "z", "e": true}))
            ),
            [
                ("a".to_owned(), "a number", Some("a string")),
                ("b".to_owned(), "a string", Some("a boolean")),
            ]
        );
        assert_eq!(
            differences(json!("x"), Some(json!(["x"]))),
            [(String::new(), "a string", Some("an array"))]
        );
    }

    fn nulls(wire: &Value) -> Vec<String> {
        match ZapConfig::from_wire_value(wire) {
            Err(WireError::Null(findings)) => findings,
            other => panic!("expected null findings, got {other:?}"),
        }
    }

    /// A `null` is a finding naming its field, whatever the field is: one serde would
    /// read as an optional field left out, one a defaulted field refuses, a number, a
    /// list, a list's item, a key of the config itself.
    #[test]
    fn a_null_is_a_finding_naming_its_field() {
        const FIELD: &str = " is null; leave the field out, or write its value";
        const ITEM: &str = " is null; leave the item out, or write its value";
        let user = |field: &str, value: Value| {
            let mut user = json!({"id": "u", "type": "user", "username": "deploy"});
            user[field] = value;
            config(&json!([user]))
        };
        let file = |field: &str, value: Value| {
            let mut file = json!({"id": "app-env", "type": "file", "path": "/etc/app.env",
                                  "content": {"type": "inline", "content": "x"}});
            file[field] = value;
            config(&json!([file]))
        };
        let remote = |field: &str, value: Value| {
            let mut content = json!({"type": "remote", "url": "https://e.x/a.tar.gz"});
            content[field] = value;
            file("content", content)
        };
        let top = |key: &str| {
            let mut wire = config(&json!([]));
            wire[key] = Value::Null;
            wire
        };
        let deploy = |field: &str| {
            let mut wire = config(&json!([]));
            wire["deploy"] = json!({"artifacts": ["dist"], "path": "/srv/app"});
            wire["deploy"][field] = Value::Null;
            wire
        };
        for (wire, expected) in [
            // read as left out, were it parsed: a control dropped without a word
            (
                user("sudo", Value::Null),
                format!("resource `u`: `sudo`{FIELD}"),
            ),
            (
                user("ssh_keys", Value::Null),
                format!("resource `u`: `ssh_keys`{FIELD}"),
            ),
            (
                file("mode", Value::Null),
                format!("resource `app-env`: `mode`{FIELD}"),
            ),
            (
                file("owner", Value::Null),
                format!("resource `app-env`: `owner`{FIELD}"),
            ),
            (
                remote("blake3", Value::Null),
                format!("resource `app-env`: `content.blake3`{FIELD}"),
            ),
            (
                config(
                    &json!([{"id": "b", "type": "build", "run": "make", "output": "/o",
                    "source": {"type": "remote", "url": "https://e.x/a", "verify": null}}]),
                ),
                format!("resource `b`: `source.verify`{FIELD}"),
            ),
            (deploy("health"), format!("`deploy.health`{FIELD}")),
            (deploy("service"), format!("`deploy.service`{FIELD}")),
            (
                user(
                    "ssh_keys",
                    json!({"keys": ["ssh-ed25519 AAAA a"], "copy_from": null}),
                ),
                format!("resource `u`: `ssh_keys.copy_from`{FIELD}"),
            ),
            // refused by the parse, were it reached, with no field named
            (
                user("groups", Value::Null),
                format!("resource `u`: `groups`{FIELD}"),
            ),
            (
                user("depends_on", Value::Null),
                format!("resource `u`: `depends_on`{FIELD}"),
            ),
            (
                config(&json!([{"id": "s", "type": "service", "service": "x", "enabled": null}])),
                format!("resource `s`: `enabled`{FIELD}"),
            ),
            (
                config(
                    &json!([{"id": "fw", "type": "firewall", "backend": "ufw", "allow": [],
                                "default_incoming": null}]),
                ),
                format!("resource `fw`: `default_incoming`{FIELD}"),
            ),
            (
                config(&json!([{"id": "fw", "type": "firewall", "backend": "ufw",
                                "allow": [{"port": 53, "proto": null}]}])),
                format!("resource `fw`: `allow[0].proto`{FIELD}"),
            ),
            (
                config(
                    &json!([{"id": "d", "type": "database", "engine": "postgresql",
                                "database_name": "d", "username": "u", "auth": null}]),
                ),
                format!("resource `d`: `auth`{FIELD}"),
            ),
            (deploy("shared"), format!("`deploy.shared`{FIELD}")),
            (
                remote("extract", Value::Null),
                format!("resource `app-env`: `content.extract`{FIELD}"),
            ),
            (
                file(
                    "content",
                    json!({"type": "template", "template": "x", "vars": null}),
                ),
                format!("resource `app-env`: `content.vars`{FIELD}"),
            ),
            // a number: what `NaN` would be written as
            (
                remote(
                    "extract",
                    json!({"type": "tar.gz", "strip_components": null}),
                ),
                format!("resource `app-env`: `content.extract.strip_components`{FIELD}"),
            ),
            (
                json!({"target": {"host": "h.example", "port": null}, "resources": []}),
                format!("`target.port`{FIELD}"),
            ),
            (
                config(&json!([{"id": "fw", "type": "firewall", "backend": "ufw",
                                "allow": [{"port": null}]}])),
                format!("resource `fw`: `allow[0].port`{FIELD}"),
            ),
            // an item of a list
            (
                user("groups", json!(["adm", null])),
                format!("resource `u`: `groups[1]`{ITEM}"),
            ),
            (
                config(&json!([{"id": "fw", "type": "firewall", "backend": "ufw",
                                "allow": ["OpenSSH", null]}])),
                format!("resource `fw`: `allow[1]`{ITEM}"),
            ),
            // a one-key object around a name is read with `null` as its value
            (
                config(
                    &json!([{"id": "fw", "type": "firewall", "backend": {"ufw": null},
                                "allow": []}]),
                ),
                format!("resource `fw`: `backend.ufw`{FIELD}"),
            ),
            // the config's own keys
            (top("deploy"), format!("`deploy`{FIELD}")),
            (top("mask_vars"), format!("`mask_vars`{FIELD}")),
            (top("unmask_vars"), format!("`unmask_vars`{FIELD}")),
            (top("target"), format!("`target`{FIELD}")),
            (top("resources"), format!("`resources`{FIELD}")),
            (config(&json!([null])), format!("`resources[0]`{ITEM}")),
            (
                config(&json!([{"id": null, "type": "service", "service": "x"}])),
                format!("resource 1: `id`{FIELD}"),
            ),
            (
                Value::Null,
                "the config is null; a config is an object".to_owned(),
            ),
        ] {
            assert_eq!(nulls(&wire), [expected], "{wire}");
        }
    }

    /// Each `null` is one finding, listed one to a line; and `null`s are reported ahead
    /// of what the parse would say of the same config.
    #[test]
    fn every_null_is_listed_and_reported_first() {
        let mut wire = config(&json!([
            {"id": "u", "type": "user", "username": "deploy", "sudo": null, "shell": null,
             "ownr": "x"},
            {"id": "s", "type": "service", "service": Text::reference("NAME"), "running": null},
        ]));
        wire["deploy"] = Value::Null;
        let message = ZapConfig::from_wire_value(&wire).unwrap_err().to_string();
        assert_eq!(
            message,
            "4 values that are null:\n  \
             - `deploy` is null; leave the field out, or write its value\n  \
             - resource `u`: `shell` is null; leave the field out, or write its value\n  \
             - resource `u`: `sudo` is null; leave the field out, or write its value\n  \
             - resource `s`: `running` is null; leave the field out, or write its value"
        );
    }

    /// A template variable's value is JSON as it was written, substituted as JSON text:
    /// a `null` is data there — as the value, and at any depth within it — and nowhere
    /// else in a `file`, the `vars` map itself included.
    #[test]
    fn a_null_in_a_template_variables_value_is_data() {
        let template = |vars: Value| {
            config(&json!([{"id": "t", "type": "file", "path": "/t",
                "content": {"type": "template", "template": "{{a}}{{b}}", "vars": vars}}]))
        };
        let parsed = ZapConfig::from_wire_value(&template(json!({
            "a": null, "b": {"deep": [1, null, {"deeper": null}]}, "c": [null],
        })))
        .unwrap();
        assert_eq!(
            serde_json::to_value(&parsed).unwrap()["resources"][0]["content"]["vars"],
            json!({"a": null, "b": {"deep": [1, null, {"deeper": null}]}, "c": [null]})
        );
        assert_eq!(
            nulls(&template(Value::Null)),
            ["resource `t`: `content.vars` is null; leave the field out, or write its value"]
        );
        // The same path in a resource of another kind is no template variable.
        assert_eq!(
            nulls(&config(
                &json!([{"id": "s", "type": "script", "check": "c", "run": "r",
                "content": {"vars": {"a": null}}}])
            )),
            ["resource `s`: `content.vars.a` is null; leave the field out, or write its value"]
        );
    }

    /// A reference's own node is judged as a reference: a `null` inside one is a
    /// malformed reference, named with its field, and the `null` the diagnosis puts in
    /// a malformed node's place while it searches is never a finding of its own.
    #[test]
    fn a_null_inside_a_references_node_is_a_malformed_reference() {
        for node in [json!({"$env": null}), json!({"$text": [null, "x"]})] {
            let found = findings(&config(&json!([
                {"id": "d", "type": "directory", "path": node},
            ])));
            assert_eq!(found.len(), 1, "{found:#?}");
            assert!(
                found[0].starts_with("resource `d`: `path` is not a reference zap can read: "),
                "{}",
                found[0]
            );
        }
    }

    /// The config's own keys are a closed set: one it doesn't have fails the parse by
    /// name.
    #[test]
    fn a_key_the_config_does_not_have_is_rejected() {
        for key in ["deploy_config", "targets", "resource"] {
            let mut wire = config(&json!([]));
            wire[key] = json!({"domain": "example.com"});
            match ZapConfig::from_wire_value(&wire) {
                Err(WireError::Parse(error)) => assert!(
                    error
                        .to_string()
                        .starts_with(&format!("unknown field `{key}`, expected one of")),
                    "{error}"
                ),
                other => panic!("{key}: {other:?}"),
            }
        }
    }

    /// A database's auth has no `trust`: every rule zap writes is a TCP line, and a
    /// trusted one admits any account on the machine as the role. Nor a method that
    /// can't work on a plain `host` line with no options: `peer` is for `local` lines
    /// only, `cert` for `hostssl` lines, `ldap` and `radius` need options, and `sspi`
    /// and `bsd` aren't built on Linux. Declaring none writes no rule.
    #[test]
    fn a_database_rule_never_trusts_and_none_is_written_by_default() {
        let database = |auth: Option<Value>| {
            let mut resource = json!({"id": "d", "type": "database", "engine": "postgresql",
                                      "database_name": "d", "username": "u"});
            if let Some(auth) = auth {
                resource["auth"] = auth;
            }
            ZapConfig::from_wire_value(&config(&json!([resource])))
        };
        match database(Some(json!({"method": "trust"}))) {
            Err(WireError::Parse(error)) => assert!(
                error
                    .to_string()
                    .starts_with("unknown variant `trust`, expected one of"),
                "{error}"
            ),
            other => panic!("trust: {other:?}"),
        }
        for method in ["peer", "cert", "ldap", "radius", "sspi", "bsd"] {
            match database(Some(json!({"method": method, "hosts": ["127.0.0.1/32"]}))) {
                Err(WireError::Parse(error)) => assert!(
                    error
                        .to_string()
                        .starts_with(&format!("unknown variant `{method}`, expected one of")),
                    "{error}"
                ),
                other => panic!("{method}: {other:?}"),
            }
        }
        let parsed = database(None).unwrap();
        let crate::schema::ResourceKind::Database(declared) = &parsed.resources[0].kind else {
            panic!("a database");
        };
        assert!(declared.auth.is_none(), "{:?}", declared.auth);
        assert!(declared.auth_hosts().is_empty());
        assert_eq!(
            declared.auth_method(),
            crate::schema::PgAuthMethod::ScramSha256
        );
    }
}
