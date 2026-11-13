//! Secret masking — register resolved values, freeze, then mask them out
//! of rendered output at the **consumption** boundary (the apply report / run log),
//! never at emission.
//!
//! The registry + masking-handler model:
//!
//! - **Build** — collect the references in the config's reference-taking
//!   fields ([`scan_env_var_names`]), resolve each, and register the value of every one
//!   the config's [`SecretRule`] classifies as a secret, in each form it may surface
//!   in (`surface_forms`): as it is, trimmed, with its line breaks normalised or
//!   decoded, line by line for a multi-line value, the credential its own format sets
//!   apart, and each of those url-encoded, json-escaped, and single-quoted for a shell
//!   (a bare command stderr, a URL, JSON, a command zap delivers with the value in it,
//!   as a shell's trace or a tool echoing its command line prints it).
//! - **Freeze** — sort longest-value-first (so a longer secret masks before a
//!   shorter substring of it) and reject a value that holds a masking token, which
//!   masking leaves as it stands.
//! - **Mask** — literal matching only, never a regex over an unescaped secret; a
//!   masking token, once written, is never searched again.
//!
//! The plan fact holds inert *references* (the determinism guarantee), so
//! nothing is masked at plan time — only **resolved** values are, at apply time.
//! Masking decorates the report the operator sees, leaving `execute_plan` unchanged
//! (masking at consumption, not emission). The dry-run preview shows the inert
//! references verbatim, which is already safe.

use std::collections::BTreeSet;
use std::fmt::Write as _;

use serde_json::Value;
use zap_types::event::ChangeOutcome;
use zap_types::schema::{TextRole, ZapConfig};
use zap_types::secrecy::{Redacted, Secrecy, SecretReason, SecretRule, credential_parts};
use zap_types::text::wire_literals;
use zap_types::var_ref::{self, masked_token};

use crate::error::{Error, Result};

/// The fewest characters one line of a multi-line secret has to be registered on its
/// own.
///
/// A multi-line value (a PEM key) reaches output a line at a time — a tool echoing the
/// line it choked on — so each line is a secret too. A line this long is unlikely in
/// any other text: 24 characters of a key's base64 body are 144 bits of it. Shorter
/// lines (a body's last few characters, a brace, a blank) say little of the secret and
/// would mask ordinary output.
const LINE_MIN_CHARS: usize = 24;

/// The fewest characters the credential part of a value has to be registered on its
/// own ([`credential_parts`]: a URL's password, an authorization value's token).
///
/// A part is masked wherever it occurs, apart from its value, and a short password
/// (`app`, `dev`) occurs in ordinary output: masked, it would shred what a run prints.
/// A part shorter than this is masked only as part of the whole value, so a tool that
/// prints it alone, or prints the URL respelled, shows it. So is one its own value
/// shows to be an ordinary word, by holding it outside the credential's place too
/// ([`credential_parts`]): the `postgres` of `postgres://app:postgres@db/app` is the
/// scheme, and a command line's, and part of another variable's host name.
const PART_MIN_CHARS: usize = 8;

/// The fewest characters a secret's value has for the literal gate
/// ([`scan_config_literals`]) to look for it in a config.
///
/// The gate catches a secret pasted where a reference belongs. A value shorter than
/// this occurs in ordinary config text by chance (`us`, `60`, `app`), so finding it
/// there is no evidence of a paste, and rejecting on it refuses a valid config. It is
/// masked out of output all the same: masking has no such floor.
const GATE_MIN_CHARS: usize = 8;

/// A registered secret: the literal string to find and the token to replace it with.
///
/// Its `Debug` shows the variable, never the value.
#[derive(Clone)]
struct SecretEntry {
    /// The variable the value belongs to.
    name: String,
    /// The literal string to search for (one form of a resolved value).
    value: String,
    /// Whether the literal gate looks for this form in a config ([`Form::gated`]).
    gated: bool,
    /// The replacement, `[MASKED:VAR_NAME]`.
    replacement: String,
}

impl std::fmt::Debug for SecretEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecretEntry")
            .field("name", &self.name)
            .field("value", &Redacted)
            .field("gated", &self.gated)
            .field("replacement", &self.replacement)
            .finish()
    }
}

/// Mutable builder of secret entries.
///
/// Populated via [`SecretRegistry::register`], then consumed by
/// [`SecretRegistry::freeze`] into an immutable [`SecretMasker`] — the typestate
/// makes "mask before freeze" unrepresentable (no runtime guard). Its `Debug` shows
/// each entry's variable, never a value.
#[derive(Debug, Default)]
pub struct SecretRegistry {
    entries: Vec<SecretEntry>,
}

impl SecretRegistry {
    /// A fresh, empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a value as sensitive, in every form it may surface in
    /// (`surface_forms`), each with its url-encoded, json-escaped, and shell-quoted
    /// variants (only when they differ).
    ///
    /// An empty value is skipped — masking the empty string would insert the token
    /// between every character.
    pub fn register(&mut self, var_name: &str, value: &str) {
        self.register_at_least(var_name, value, 0);
    }

    /// [`register`](Self::register), leaving out each form (`surface_forms`) of fewer
    /// than `min_chars` characters, with its variants: a trimmed or decoded form can be
    /// shorter than the value it comes from.
    fn register_at_least(&mut self, var_name: &str, value: &str, min_chars: usize) {
        for Form { text, gated } in surface_forms(value) {
            if text.chars().count() < min_chars {
                continue;
            }
            self.add(var_name, &text, gated);
            let url_encoded = url_encode_component(&text);
            if url_encoded != text {
                self.add(var_name, &url_encoded, gated);
            }
            let json_escaped = json_escape(&text);
            if json_escaped != text {
                self.add(var_name, &json_escaped, gated);
            }
            let shell_quoted = shell_quote_body(&text);
            if shell_quoted != text {
                self.add(var_name, &shell_quoted, gated);
            }
        }
    }

    /// Freeze into an immutable masker: sort longest-value-first (then by token for
    /// determinism) and reject a value masking could not mask.
    ///
    /// # Errors
    /// [`Error::Secret`] if a registered value holds a masking token of this registry.
    /// Masking leaves a token as it stands — which is what keeps one from being
    /// rewritten by a secret whose value spells part of it — so such a value would
    /// print in part; the error names the variable it belongs to.
    pub fn freeze(mut self) -> Result<SecretMasker> {
        self.entries.sort_by(|a, b| {
            b.value
                .len()
                .cmp(&a.value.len())
                .then_with(|| a.replacement.cmp(&b.replacement))
        });
        let tokens: BTreeSet<String> = self
            .entries
            .iter()
            .map(|entry| entry.replacement.clone())
            .collect();
        for entry in &self.entries {
            if let Some(token) = tokens.iter().find(|token| entry.value.contains(*token)) {
                return Err(Error::Secret(format!(
                    "the value of `{}` holds the masking token `{token}`, which masking \
                     leaves as it stands, so the value can't be masked — change the value",
                    var_ref::shown(&entry.name)
                )));
            }
        }
        Ok(SecretMasker {
            entries: self.entries,
            tokens: tokens.into_iter().collect(),
        })
    }

    /// Whether nothing is registered.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Add one entry. A value already registered (under any var name) is kept as it
    /// is, gated if either registration is.
    fn add(&mut self, var_name: &str, value: &str, gated: bool) {
        if let Some(entry) = self.entries.iter_mut().find(|entry| entry.value == value) {
            entry.gated |= gated;
            return;
        }
        self.entries.push(SecretEntry {
            name: var_name.to_owned(),
            value: value.to_owned(),
            gated,
            replacement: masked_token(var_name),
        });
    }
}

/// One form a secret's value may surface in.
#[derive(Debug, PartialEq, Eq)]
struct Form {
    /// The text to mask.
    text: String,
    /// Whether the literal gate looks for it in a config: the value itself and the
    /// value trimmed — what a paste of the secret holds. Every other form is a piece or
    /// a respelling a tool may print, and a piece can be ordinary text (one line of a
    /// JSON credential is the same in every such file), so finding one in a config is
    /// no evidence the secret was pasted there.
    gated: bool,
}

/// The forms a secret's value may surface in, each to be masked:
///
/// - the value as it is, and with the whitespace around it trimmed (an env file's or a
///   `$(cat file)` value with a trailing newline, printed by a tool without it);
/// - the value with its CRLF line ends as LF, and with each literal `\n` / `\r\n` it
///   spells decoded to a line break (a key kept on one line of an env file, printed by
///   the tool that decoded it), each trimmed too;
/// - for a value of several lines — as it is or decoded — each line of at least
///   [`LINE_MIN_CHARS`] characters. A PEM armor line (`-----BEGIN …-----`) is not one:
///   it is the same in every key and certificate;
/// - the credential the value's format sets apart ([`credential_parts`]), when it has at
///   least [`PART_MIN_CHARS`] characters.
///
/// An empty value has no form.
fn surface_forms(value: &str) -> Vec<Form> {
    let mut forms: Vec<Form> = Vec::new();
    let mut push = |text: &str, gated: bool| {
        if !text.is_empty() && !forms.iter().any(|form| form.text == text) {
            forms.push(Form {
                text: text.to_owned(),
                gated,
            });
        }
    };
    push(value, true);
    push(value.trim(), true);
    let unix = value.replace("\r\n", "\n");
    let decoded = unix.replace("\\r\\n", "\n").replace("\\n", "\n");
    for whole in [&unix, &decoded] {
        push(whole, false);
        push(whole.trim(), false);
        if whole.trim().contains('\n') {
            for line in whole.lines().map(str::trim) {
                if line.chars().count() >= LINE_MIN_CHARS
                    && !(line.starts_with("-----") && line.ends_with("-----"))
                {
                    push(line, false);
                }
            }
        }
    }
    for part in credential_parts(value) {
        if part.chars().count() >= PART_MIN_CHARS {
            push(&part, false);
        }
    }
    forms
}

/// A run of text being masked: text still to be searched, or a masking token, which
/// is never searched.
#[derive(Debug, Clone, Copy)]
enum Piece<'a> {
    Text(&'a str),
    Token(&'a str),
}

/// Split every [`Piece::Text`] of `pieces` at each occurrence of `find`, putting
/// `token` in its place.
fn split_at<'a>(pieces: Vec<Piece<'a>>, find: &str, token: &'a str) -> Vec<Piece<'a>> {
    let mut out = Vec::with_capacity(pieces.len());
    for piece in pieces {
        match piece {
            Piece::Text(text) if text.contains(find) => {
                let mut parts = text.split(find);
                out.extend(parts.next().map(Piece::Text));
                for part in parts {
                    out.push(Piece::Token(token));
                    out.push(Piece::Text(part));
                }
            }
            kept => out.push(kept),
        }
    }
    out
}

/// Frozen, validated set of secret entries — the only thing that can mask. Entries
/// are sorted longest-value-first. Its `Debug` shows each entry's variable, never a
/// value.
#[derive(Debug, Clone)]
pub struct SecretMasker {
    entries: Vec<SecretEntry>,
    /// The distinct masking tokens of `entries`.
    tokens: Vec<String>,
}

impl SecretMasker {
    /// Whether there are no secrets to mask (every `mask` is then a no-op).
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Replace every registered secret value (in each registered form) in `text` with
    /// its `[MASKED:VAR]` token. Literal matching only — never a regex over an
    /// unescaped secret.
    ///
    /// A masking token is never searched: one already in `text`, and each one written
    /// here, stands as it is while the text around it is masked. So a secret whose
    /// value spells part of a token (`PASS` beside `[MASKED:ADMIN_PASSWORD]`) can't
    /// rewrite it, and masking a masked text again changes nothing.
    ///
    /// Otherwise the whole of `text` is searched, a reference it holds inert included:
    /// text a command printed is masked through here too, and nothing tells a marker a
    /// config declared from the same characters around a secret in that output. A secret
    /// whose value spells part of a declared reference's name therefore masks that part
    /// of the name where the text is shown. A typed value keeps its references whole
    /// ([`Text::map_literals`](zap_types::text::Text::map_literals)).
    #[must_use]
    pub fn mask(&self, text: &str) -> String {
        if text.is_empty() || !self.entries.iter().any(|entry| text.contains(&entry.value)) {
            return text.to_owned();
        }
        let mut pieces = vec![Piece::Text(text)];
        for token in &self.tokens {
            pieces = split_at(pieces, token, token);
        }
        for entry in &self.entries {
            pieces = split_at(pieces, &entry.value, &entry.replacement);
        }
        pieces
            .into_iter()
            .map(|piece| match piece {
                Piece::Text(text) | Piece::Token(text) => text,
            })
            .collect()
    }

    /// The variables with a gated form ([`Form::gated`]) of at least [`GATE_MIN_CHARS`]
    /// characters that occurs in `text` (sorted, each once) — what the literal gate asks
    /// of a config's text.
    fn secrets_in(&self, text: &str) -> BTreeSet<&str> {
        self.entries
            .iter()
            .filter(|entry| {
                entry.gated
                    && entry.value.chars().count() >= GATE_MIN_CHARS
                    && text.contains(&entry.value)
            })
            .map(|entry| entry.name.as_str())
            .collect()
    }
}

/// Build a frozen [`SecretMasker`] from a config.
///
/// Collects the config's references ([`scan_env_var_names`]), resolves each via the
/// injected `env_get`, and registers the value of every one the config's
/// [`SecretRule`] classifies as a secret — by its role, the config's `mask` / `unmask`,
/// its name, or the form of that value.
///
/// `env_get` is injected (not a direct `std::env` read) so the build is hermetic in
/// tests, mirroring `compute_config_hash`'s injected resolver. The production caller
/// passes `crate::resolve::env_var` — the same overlay-aware source `resolve_env_vars`
/// reads (honoring `--env-file`), so the registered values match the ones the executor
/// injects.
///
/// # Errors
/// [`Error::Secret`] if a registered value holds a masking token
/// ([`SecretRegistry::freeze`]).
pub fn build_registry<F>(config: &ZapConfig, env_get: F) -> Result<SecretMasker>
where
    F: Fn(&str) -> Option<String>,
{
    masker_of(
        &scan_env_var_names(config),
        &SecretRule::of(config),
        env_get,
        0,
    )
}

/// The fewest characters a secret's value has for a lock address to mask it inside a
/// plain value (the `min_chars` [`masker_of`] is given there).
///
/// Output masking has no floor: a short secret shown is a short secret leaked. In an
/// address, masking a short one would replace it wherever it occurs in an ordinary
/// value (`zig` in a download url), moving unrelated addresses with the secret's
/// value — whether a committed address moved would then say whether the url holds the
/// secret. A value this short is folded as it is: so few characters are guessable
/// whatever an address says.
pub(crate) const ADDRESS_MIN_CHARS: usize = GATE_MIN_CHARS;

/// The frozen [`SecretMasker`] of the variables `names`: each one `env_get` resolves and
/// `rule` classifies as a secret is registered — [`build_registry`] for a config's
/// references and its rule — in each of its forms of at least `min_chars` characters
/// (`SecretRegistry::register_at_least`).
///
/// # Errors
/// [`Error::Secret`] if a registered value holds a masking token
/// ([`SecretRegistry::freeze`]).
pub(crate) fn masker_of<F>(
    names: &BTreeSet<String>,
    rule: &SecretRule,
    env_get: F,
    min_chars: usize,
) -> Result<SecretMasker>
where
    F: Fn(&str) -> Option<String>,
{
    let mut registry = SecretRegistry::new();
    for name in names {
        if let Some(value) = env_get(name)
            && rule.classify(name, Some(&value)).is_secret()
        {
            registry.register_at_least(name, &value, min_chars);
        }
    }
    registry.freeze()
}

/// Build the masker **and** reject any literal secret hardcoded into the config — the
/// per-command secret gate.
///
/// Every command core that evals a config runs this, via the one `commands::target::config_gates`
/// seam, so a literal-secret config fails identically on every verb — a
/// config-well-formedness invariant, not a per-command behavior. Cores that render no
/// resolved value simply drop the masker; the *rejection* is what they all need. Rejection is **best-effort**: a secret is only caught when it
/// is both referenced and resolvable through `env_get`, so the check is a
/// no-op on a machine without the secrets set (no spurious failures) and strongest on
/// the machine that holds them (the deploy target).
///
/// `env_get` is injected (mirroring [`build_registry`]) so the gate is hermetically
/// testable; the command cores pass `crate::resolve::env_var` — the same overlay-aware
/// source (honoring `--env-file`) the rest of the engine's resolution reads.
///
/// A config that lists a fetch credential with `zap.unmask` is rejected here too: a
/// credential is a secret by its role, so the `unmask` could only be ignored, and a
/// statement the operator made is refused rather than dropped.
///
/// # Errors
/// [`Error::Secret`] if the config unmasks a fetch credential, a registered value holds
/// a masking token, or a resolved secret value appears as a literal in the config.
pub fn build_validated_masker<F>(config: &ZapConfig, env_get: F) -> Result<SecretMasker>
where
    F: Fn(&str) -> Option<String>,
{
    let unmasked: Vec<String> = SecretRule::of(config)
        .unmasked_credentials()
        .into_iter()
        .map(|name| format!("`zap.unmask('{name}')`"))
        .collect();
    if !unmasked.is_empty() {
        return Err(Error::Secret(format!(
            "{} names a variable the config uses as a fetch credential (an `auth` token), \
             which is a secret wherever it is used — remove the `unmask`",
            unmasked.join(", ")
        )));
    }
    let masker = build_registry(config, &env_get)?;
    scan_config_literals(config, &masker, env_get)?;
    Ok(masker)
}

/// Mask resolved secrets out of a run's outcomes — the consumption boundary for the
/// batch apply report. A no-op when nothing is registered.
///
/// Each outcome is mapped through [`ChangeOutcome::map_text`]: its free text is masked
/// and its resource id and error code are kept, with no serialized form in between.
#[must_use]
pub fn mask_outcomes(masker: &SecretMasker, outcomes: Vec<ChangeOutcome>) -> Vec<ChangeOutcome> {
    if masker.is_empty() {
        return outcomes;
    }
    outcomes
        .iter()
        .map(|outcome| outcome.map_text(|text| masker.mask(text)))
        .collect()
}

/// Reject a config that embeds a resolved secret value as a *literal*.
///
/// I.e. the operator hardcoded a secret instead of using a reference. Each finding
/// names the field and the variable whose value it holds, and nothing of the field's
/// text: an excerpt with the value masked in place would say where in the text the
/// value stands, and for a short value, what it is. A variable that is a secret only
/// by its name or its value's form (`env_get` resolves it for the rule) carries the way
/// out for one that isn't a secret at all: `zap.unmask`.
///
/// What is looked for is the value itself and the value trimmed, of at least
/// `GATE_MIN_CHARS` characters — not a line of it or the credential inside it, which
/// masking alone takes care of.
///
/// # Errors
/// [`Error::Secret`] listing each offending location if any literal secret is found.
pub fn scan_config_literals<F>(config: &ZapConfig, masker: &SecretMasker, env_get: F) -> Result<()>
where
    F: Fn(&str) -> Option<String>,
{
    if masker.is_empty() {
        return Ok(());
    }
    let value = serde_json::to_value(config)
        .map_err(|error| Error::Secret(format!("failed to scan config for secrets: {error}")))?;
    let mut offenders = Vec::new();
    scan_literals(&value, "config", masker, &mut offenders);
    if offenders.is_empty() {
        return Ok(());
    }
    let rule = SecretRule::of(config);
    let mut message = "secret value(s) appear as literals in the config — use a \
                       `zap.env('NAME')` reference instead:"
        .to_owned();
    for (path, name) in offenders {
        let shown = var_ref::shown(name);
        let _ = write!(message, "\n  at {path}: the value of `{shown}`");
        let by = match rule.classify(name, env_get(name).as_deref()) {
            Secrecy::Secret(SecretReason::Name) => "its name",
            Secrecy::Secret(SecretReason::Value(_)) => "the form of its value",
            Secrecy::Secret(SecretReason::Declared | SecretReason::Credential) | Secrecy::Plain => {
                continue;
            }
        };
        let _ = write!(
            message,
            " (a secret by {by} — call `zap.unmask('{name}')` if it is not one)"
        );
    }
    Err(Error::Secret(message))
}

/// Walk a JSON value, recording each string location that holds a registered secret's
/// value ([`SecretMasker::secrets_in`]) with the variable it belongs to — the field's
/// path and the name, never its text.
///
/// A field that takes a reference is one location, whatever its wire form: its literal
/// pieces are scanned each on its own, and a reference's name is not text — a secret
/// whose value spells a variable's name is not hardcoded by a reference to it.
fn scan_literals<'a>(
    value: &Value,
    path: &str,
    masker: &'a SecretMasker,
    offenders: &mut Vec<(String, &'a str)>,
) {
    if let Some(literals) = wire_literals(value) {
        let names: BTreeSet<&str> = literals
            .into_iter()
            .flat_map(|literal| masker.secrets_in(literal))
            .collect();
        offenders.extend(names.into_iter().map(|name| (path.to_owned(), name)));
        return;
    }
    match value {
        Value::Array(items) => {
            for (index, item) in items.iter().enumerate() {
                scan_literals(item, &format!("{path}[{index}]"), masker, offenders);
            }
        }
        Value::Object(map) => {
            for (key, child) in map {
                scan_literals(child, &format!("{path}.{key}"), masker, offenders);
            }
        }
        _ => {}
    }
}

/// The distinct variable names a config references: every name in every
/// [`Text`](zap_types::text::Text) it holds — the fields a consumer resolves
/// ([`ZapConfig::for_each_text`]), whatever their role.
///
/// No other field holds one: a reference in a `file`'s inline content, a template's
/// body, a `verify` command, or a `deploy` command is rejected when the config is
/// parsed, and text there that only spells one names nothing here.
#[must_use]
pub fn scan_env_var_names(config: &ZapConfig) -> BTreeSet<String> {
    let mut names = BTreeSet::new();
    config.for_each_text(|_, text| names.extend(text.ref_names().map(str::to_owned)));
    names
}

/// The variable names a **detection/diff comparison** resolves.
///
/// Every reference in a resource's [`Text`](zap_types::text::Text)s, minus a fetch
/// credential (a `remote` file's or a `build` source's `auth`), and in the target's:
/// `host`, `user`, and `bootstrap_user`.
///
/// The target's users are part of the comparison because the connecting user is who the
/// login-lane reads run as: unset, the run connects as whichever user `ssh` picks —
/// another identity's view of the machine. Both users count whichever the run connects
/// as, as they do for the wetrun's gate. The target's other strings (`home`,
/// `key_path`) are used as written and take no reference, so they are no part of this.
///
/// The scoped counterpart to [`scan_env_var_names`], which is deliberately blanket: an
/// executing wetrun bakes *any* unresolved reference into something it runs or writes, so
/// it must reject all of them. A **comparison** is narrower — it only lies about state it
/// actually resolved — and over-reporting there would block a dry run on a variable that
/// couldn't affect its answer.
///
/// Two exclusions, each a [`TextRole`]:
///
/// - **the `deploy` block** ([`TextRole::Deploy`]) — convergence never reads it (only
///   `zap deploy` does), so an unset `deploy.health.domain` reference can't make an
///   `apply` diff wrong.
/// - **fetch credentials** ([`TextRole::FetchCredential`]) — a bearer token is excluded
///   from the content address by design (see `config_hash`), so its being unset doesn't
///   make a hash unverifiable. This mirrors `crate::lock`'s `unresolved_hash_vars`,
///   which skips it for the same reason. The credential is the typed one
///   (`zap_types::schema::RemoteAuth`), never a field by its name: a `database`'s
///   `auth.hosts` and a template variable called `auth` are compared, and counted.
///
/// Scoping by **exclusion** rather than by enumerating comparison-feeding roles is
/// deliberate: a resource field that takes a reference counts as comparison-feeding
/// until someone says otherwise, so the failure mode is a spurious "can't verify" (loud,
/// cheap) instead of a silently trusted bad diff (quiet, expensive).
#[must_use]
pub fn scan_comparison_var_names(config: &ZapConfig) -> BTreeSet<String> {
    let mut names = BTreeSet::new();
    config.for_each_text(|role, text| match role {
        TextRole::TargetIdentity | TextRole::Resource => {
            names.extend(text.ref_names().map(str::to_owned));
        }
        TextRole::FetchCredential | TextRole::Deploy => {}
    });
    names
}

/// JS `encodeURIComponent`'s encoding: leave the unreserved set `A-Za-z0-9-_.!~*'()`
/// as-is, percent-encode every other byte (UTF-8) as `%XX`. Catches a secret that
/// surfaces url-encoded (e.g. inside a URL in command output).
fn url_encode_component(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        let is_unreserved = byte.is_ascii_alphanumeric()
            || matches!(
                byte,
                b'-' | b'_' | b'.' | b'!' | b'~' | b'*' | b'\'' | b'(' | b')'
            );
        if is_unreserved {
            out.push(byte as char);
        } else {
            let _ = write!(out, "%{byte:02X}");
        }
    }
    out
}

/// `value` as it stands between the quotes of a shell single-quoted word
/// ([`single_quote`](zap_types::shell::single_quote), how zap delivers a resolved value
/// in a command): each `'` written `'\''`. Catches a secret in a delivered command
/// that a shell's trace, or a tool echoing its command line, prints.
fn shell_quote_body(value: &str) -> String {
    value.replace('\'', r"'\''")
}

/// JSON-escape `value` the way it would appear inside a JSON string (the body of
/// `JSON.stringify(value)`, minus the surrounding quotes). Catches a secret that
/// surfaces in JSON-serialized output.
fn json_escape(value: &str) -> String {
    // `to_string` of a `&str` is infallible; the result is always `"…"` (len ≥ 2).
    let quoted = serde_json::to_string(value).unwrap_or_default();
    quoted
        .get(1..quoted.len().saturating_sub(1))
        .unwrap_or_default()
        .to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::resolve::var_names_in;
    use zap_types::text::Text;
    use zap_types::var_ref;
    use zap_types::var_ref::Segment::{Ref, Text as Lit};

    fn set(names: &[&str]) -> BTreeSet<String> {
        names.iter().map(|name| (*name).to_owned()).collect()
    }

    /// A typed value keeps each reference whole when it is masked — a secret whose
    /// value spells part of a variable's name leaves which variable is referenced
    /// alone — while flat text is masked whole: a secret is masked wherever it stands,
    /// between the two delimiters of a reference included, so text a command printed
    /// can't carry one out inside what reads as a reference's name.
    #[test]
    fn masking_keeps_a_typed_reference_and_masks_flat_text_whole() {
        let mut registry = SecretRegistry::new();
        registry.register("SECRET_WORD", "DEPLOY");
        registry.register("API_TOKEN", "hunter2SecretValue");
        let masker = registry.freeze().unwrap();

        let printed = format!(
            "denied: token {} for DEPLOY, half {}hunter2SecretValue",
            var_ref::marker("hunter2SecretValue"),
            var_ref::OPEN
        );
        let masked = masker.mask(&printed);
        assert!(!masked.contains("hunter2SecretValue"), "{masked:?}");
        assert_eq!(masked.matches("[MASKED:API_TOKEN]").count(), 2);
        assert!(masked.contains("for [MASKED:SECRET_WORD],"), "{masked:?}");

        let target: zap_types::schema::Target = serde_json::from_value(serde_json::json!({
            "host": Text::of_pieces([Lit("DEPLOY."), Ref("DEPLOY_HOST")]),
            "user": Text::reference("DEPLOY_USER"), "home": "/home/DEPLOY",
        }))
        .unwrap();
        let masked = target.map_text(|text| masker.mask(text));
        assert_eq!(
            serde_json::to_value(&masked).unwrap(),
            serde_json::json!({
                "local": false,
                "host": Text::of_pieces([Lit("[MASKED:SECRET_WORD]."), Ref("DEPLOY_HOST")]),
                "user": Text::reference("DEPLOY_USER"),
                "home": "/home/[MASKED:SECRET_WORD]",
            })
        );
    }

    /// The literal gate reads a field that takes a reference as one field: a literal
    /// piece that holds a secret is an offender named by the field, and a reference to
    /// a variable whose name the secret's value spells is not one.
    #[test]
    fn the_literal_gate_scans_literal_pieces_and_no_reference_name() {
        let mut registry = SecretRegistry::new();
        registry.register("SECRET_WORD", "DEPLOY_HOST");
        let masker = registry.freeze().unwrap();
        let config = |path: Text| -> ZapConfig {
            serde_json::from_value(serde_json::json!({
                "target": {"local": true},
                "resources": [{"id": "d", "type": "directory", "path": path}],
            }))
            .unwrap()
        };
        for clean in [
            Text::reference("DEPLOY_HOST"),
            Text::of_pieces([Lit("/srv/"), Ref("DEPLOY_HOST"), Lit("/data")]),
        ] {
            assert!(scan_config_literals(&config(clean), &masker, |_| None).is_ok());
        }
        for hardcoded in [
            Text::literal("/srv/DEPLOY_HOST/data"),
            Text::of_pieces([Lit("/srv/DEPLOY_HOST/"), Ref("DEPLOY_HOST")]),
        ] {
            let Err(Error::Secret(message)) =
                scan_config_literals(&config(hardcoded), &masker, |_| None)
            else {
                panic!("a hardcoded secret passed the gate");
            };
            assert_eq!(
                message,
                format!(
                    "secret value(s) appear as literals in the config — use a \
                     `zap.env('NAME')` reference instead:\n  at config.resources[0].path: the \
                     value of `{}` (a secret by its name — call `zap.unmask('SECRET_WORD')` \
                     if it is not one)",
                    var_ref::shown("SECRET_WORD")
                )
            );
        }
    }

    /// The gate's finding names the field and the variable and holds nothing of the
    /// field's text — not the value, and not where in the text it stands. A variable
    /// that is a secret only by how it looks carries `zap.unmask`; one the config made
    /// a secret doesn't.
    #[test]
    fn the_literal_gate_names_the_field_and_the_variable_only() {
        let config: ZapConfig = serde_json::from_value(serde_json::json!({
            "target": {"local": true},
            "mask_vars": ["DECLARED"],
            "resources": [
                {"id": "s", "type": "script",
                 "check": Text::of_pieces([
                     Lit("test -n "), Ref("API_TOKEN"), Ref("DATABASE_URL"), Ref("DECLARED"),
                 ]),
                 "run": "curl -H 'auth: tok-12345678' postgres://app:hunter2@db/app",
                 "env": {"A": "declared-12345678", "B": "before tok-12345678 after"}},
            ],
        }))
        .unwrap();
        let env = |name: &str| {
            Some(
                match name {
                    "API_TOKEN" => "tok-12345678",
                    "DATABASE_URL" => "postgres://app:hunter2@db/app",
                    "DECLARED" => "declared-12345678",
                    _ => return None,
                }
                .to_owned(),
            )
        };
        let Err(Error::Secret(message)) = build_validated_masker(&config, env) else {
            panic!("a hardcoded secret passed the gate");
        };
        let shown = var_ref::shown;
        assert_eq!(
            message,
            format!(
                "secret value(s) appear as literals in the config — use a `zap.env('NAME')` \
                 reference instead:\n  \
                 at config.resources[0].env.A: the value of `{declared}`\n  \
                 at config.resources[0].env.B: the value of `{token}` (a secret by its name \
                 — call `zap.unmask('API_TOKEN')` if it is not one)\n  \
                 at config.resources[0].run: the value of `{token}` (a secret by its name — \
                 call `zap.unmask('API_TOKEN')` if it is not one)\n  \
                 at config.resources[0].run: the value of `{url}` (a secret by the form of \
                 its value — call `zap.unmask('DATABASE_URL')` if it is not one)",
                declared = shown("DECLARED"),
                token = shown("API_TOKEN"),
                url = shown("DATABASE_URL"),
            )
        );
        for part in [
            "tok-12345678",
            "hunter2",
            "declared-12345678",
            "curl",
            "before",
            "after",
        ] {
            assert!(!message.contains(part), "{part}: {message}");
        }
    }

    /// A value too short to be evidence of a paste isn't looked for in the config — a
    /// one-character value under a secret-shaped name rejects nothing — and is masked
    /// out of output all the same.
    #[test]
    fn the_literal_gate_looks_for_no_short_value() {
        let config = |run: &str| -> ZapConfig {
            serde_json::from_value(serde_json::json!({
                "target": {"local": true},
                "resources": [
                    {"id": "s", "type": "script",
                     "check": Text::of_pieces([Lit("test -n "), Ref("SHORT_KEY")]),
                     "run": run},
                ],
            }))
            .unwrap()
        };
        for (value, gated) in [
            ("a", false),
            ("60", false),
            ("us", false),
            ("abcdefg", false),
            ("ábcdéfg", false),
            ("abcdefgh", true),
            ("ábcdéfgh", true),
        ] {
            let run = format!("echo false {value} n");
            let result = build_validated_masker(&config(&run), |name: &str| {
                (name == "SHORT_KEY").then(|| value.to_owned())
            });
            assert_eq!(result.is_err(), gated, "{value}");
            if let Ok(masker) = result {
                assert_eq!(
                    masker.mask(&format!("printed {value}.")),
                    "printed [MASKED:SHORT_KEY]."
                );
            }
        }
    }

    /// A value is registered trimmed too — a tool prints a file's trailing newline or
    /// not — and a value of several lines line by line, a line long enough to be the
    /// secret's and no other text's; the armor lines every key and certificate share
    /// are left alone.
    #[test]
    fn a_value_is_masked_trimmed_and_line_by_line() {
        let body = [
            "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSj",
            "x9Zk3mPq7RtUv2WyAb5CdEf8",
            "Lw==",
        ];
        let pem = format!(
            "-----BEGIN PRIVATE KEY-----\n{}\n{}\n{}\n-----END PRIVATE KEY-----\n",
            body[0], body[1], body[2]
        );
        let mut registry = SecretRegistry::new();
        registry.register("TLS_KEY", &pem);
        registry.register("API_TOKEN", "  tok-12345678\n");
        let masker = registry.freeze().unwrap();

        assert_eq!(masker.mask(&pem), "[MASKED:TLS_KEY]");
        assert_eq!(masker.mask(pem.trim_end()), "[MASKED:TLS_KEY]");
        assert_eq!(
            masker.mask(&format!("bad base64 at line 2: {}", body[0])),
            "bad base64 at line 2: [MASKED:TLS_KEY]"
        );
        assert_eq!(
            masker.mask(&format!("  {}\r\n", body[1])),
            "  [MASKED:TLS_KEY]\r\n"
        );
        // One character short of a line that is registered, the armor, and a short tail
        // are not the secret.
        for plain in [
            &body[1][1..],
            "-----BEGIN PRIVATE KEY-----",
            "-----END PRIVATE KEY-----",
            "-----BEGIN CERTIFICATE-----",
            body[2],
        ] {
            assert_eq!(masker.mask(plain), plain);
        }
        assert_eq!(body[1].len(), LINE_MIN_CHARS);

        assert_eq!(masker.mask("saw tok-12345678."), "saw [MASKED:API_TOKEN].");
        assert_eq!(
            masker.mask("saw   tok-12345678\n."),
            "saw [MASKED:API_TOKEN]."
        );
        // The trimmed form has its encodings too.
        let mut registry = SecretRegistry::new();
        registry.register("SECRET_X", "a/b+c\n");
        let masker = registry.freeze().unwrap();
        assert_eq!(masker.mask("u=a%2Fb%2Bc&"), "u=[MASKED:SECRET_X]&");
        // A value of whitespace alone has no trimmed form.
        let texts = |value: &str| -> Vec<String> {
            surface_forms(value)
                .into_iter()
                .map(|form| form.text)
                .collect()
        };
        assert_eq!(texts("  "), ["  "]);
        assert_eq!(texts(""), [""; 0]);
    }

    /// The credential inside a value is masked on its own too — a URL's password, as
    /// written and decoded, an authorization value's token and the password it encodes
    /// — so a tool that prints the URL respelled, or the password alone, shows neither.
    /// A part too short to be told from ordinary text is masked only inside its value.
    #[test]
    fn the_credential_inside_a_value_is_masked_alone() {
        let mut registry = SecretRegistry::new();
        registry.register("DATABASE_URL", "postgres://app:hunter2-s3cret@db/app");
        registry.register("QUEUE_URL", "amqp://u:p%40ssw0rd%2Fx@mq");
        registry.register("CACHE_URL", "redis://:dev@cache");
        registry.register("UPSTREAM", "Basic YWRtaW46Y29ycmVjdC1ob3JzZQ==");
        let masker = registry.freeze().unwrap();
        assert_eq!(
            masker.mask("connecting to postgres://app:hunter2-s3cret@db:5432/app/"),
            "connecting to postgres://app:[MASKED:DATABASE_URL]@db:5432/app/"
        );
        assert_eq!(
            masker.mask("password authentication failed (hunter2-s3cret)"),
            "password authentication failed ([MASKED:DATABASE_URL])"
        );
        assert_eq!(
            masker.mask("as written p%40ssw0rd%2Fx, decoded p@ssw0rd/x"),
            "as written [MASKED:QUEUE_URL], decoded [MASKED:QUEUE_URL]"
        );
        assert_eq!(
            masker.mask("token YWRtaW46Y29ycmVjdC1ob3JzZQ== is admin:correct-horse"),
            "token [MASKED:UPSTREAM] is admin:[MASKED:UPSTREAM]"
        );
        // Under the floor: masked in its value, left alone in other text.
        assert_eq!(
            masker.mask("dev build, redis://:dev@cache"),
            "dev build, [MASKED:CACHE_URL]"
        );
    }

    /// A password that is also its URL's scheme (or user, or host) is an ordinary word
    /// by the value's own evidence: the whole URL is masked, and the word alone is left
    /// in a command line, in a package name — and in another variable's value, which
    /// then still resolves by value. A password the URL holds nowhere else is masked
    /// alone, in each URL of a value that holds two.
    #[test]
    fn a_password_that_is_an_ordinary_word_of_its_url_is_not_masked_alone() {
        let config: ZapConfig = serde_json::from_value(serde_json::json!({
            "target": {"host": Text::reference("DEPLOY_HOST")},
            "resources": [
                {"id": "s", "type": "script", "check": "false", "run": "true",
                 "env": {"A": Text::reference("DATABASE_URL"),
                         "B": Text::reference("REPLICAS")}},
            ],
        }))
        .unwrap();
        let env = |name: &str| {
            Some(
                match name {
                    "DATABASE_URL" => "postgres://app:postgres@db/app",
                    "REPLICAS" => {
                        "postgres://ro:hunter2-s3cret@db1/app,postgres://ro:other-s3cret@db2/app"
                    }
                    "DEPLOY_HOST" => "postgres.internal",
                    _ => return None,
                }
                .to_owned(),
            )
        };
        let masker = build_validated_masker(&config, env).unwrap();
        for plain in [
            "sudo -u postgres psql -X -tAc 'select 1'",
            "postgresql-16 is already the newest version",
            "postgres.internal",
        ] {
            assert_eq!(masker.mask(plain), plain);
        }
        assert_eq!(
            masker.mask("could not connect to postgres://app:postgres@db/app"),
            "could not connect to [MASKED:DATABASE_URL]"
        );
        assert_eq!(
            masker.mask("db1 refused hunter2-s3cret, db2 refused other-s3cret"),
            "db1 refused [MASKED:REPLICAS], db2 refused [MASKED:REPLICAS]"
        );
        // The host that holds the word resolves by value: its plan can be bound.
        let var = crate::last_run::report_var_with(&config, &masker, env);
        assert_eq!(
            var("DEPLOY_HOST"),
            zap_types::last_run::ReportVar::Value("postgres.internal".to_owned())
        );
    }

    /// A multi-line value kept on one line with literal `\n`s, or with CRLF line ends,
    /// is masked as the tool that decoded it prints it: whole, and line by line.
    #[test]
    fn a_value_is_masked_with_its_line_breaks_decoded() {
        let body = [
            "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSj",
            "x9Zk3mPq7RtUv2WyAb5CdEf8",
        ];
        let lines = [
            "-----BEGIN PRIVATE KEY-----",
            body[0],
            body[1],
            "-----END PRIVATE KEY-----",
        ];
        for stored in [lines.join("\\n"), lines.join("\r\n"), lines.join("\\r\\n")] {
            let mut registry = SecretRegistry::new();
            registry.register("TLS_KEY", &stored);
            let masker = registry.freeze().unwrap();
            assert_eq!(masker.mask(&stored), "[MASKED:TLS_KEY]", "{stored:?}");
            assert_eq!(
                masker.mask(&lines.join("\n")),
                "[MASKED:TLS_KEY]",
                "{stored:?}"
            );
            for line in body {
                assert_eq!(
                    masker.mask(&format!("error near: {line}")),
                    "error near: [MASKED:TLS_KEY]",
                    "{stored:?}"
                );
            }
            assert_eq!(masker.mask(lines[0]), lines[0]);
        }
    }

    /// The literal gate looks for a secret's whole value, never a piece of it: a config
    /// literal equal to one line of a multi-line secret, or to the password inside a
    /// URL, is the config's own text — while the whole value pasted in is refused.
    #[test]
    fn the_literal_gate_looks_for_the_whole_value_only() {
        let line = r#""auth_uri": "https://accounts.example.com/o/oauth2/auth","#;
        let credentials = format!("{{\n  \"type\": \"service_account\",\n  {line}\n}}\n");
        let url = "postgres://app:hunter2-s3cret@db/app";
        let config = |content: &str| -> ZapConfig {
            serde_json::from_value(serde_json::json!({
                "target": {"local": true},
                "resources": [
                    {"id": "s", "type": "script", "check": "false", "run": "true",
                     "env": {"A": Text::reference("GCP_CREDENTIALS"),
                             "B": Text::reference("DATABASE_URL"), "C": content}},
                ],
            }))
            .unwrap()
        };
        let env = |name: &str| match name {
            "GCP_CREDENTIALS" => Some(credentials.clone()),
            "DATABASE_URL" => Some(url.to_owned()),
            _ => None,
        };
        for piece in [line, "hunter2-s3cret"] {
            let masker = build_validated_masker(&config(piece), env).unwrap();
            assert_ne!(masker.mask(piece), piece, "a piece is still masked");
        }
        for whole in [credentials.as_str(), credentials.trim(), url] {
            assert!(
                matches!(
                    build_validated_masker(&config(whole), env),
                    Err(Error::Secret(_))
                ),
                "{whole:?}"
            );
        }
    }

    /// A masking token is never searched: a secret whose value spells part of another
    /// variable's token masks its own occurrences and leaves the token whole, and
    /// masking a masked text again changes nothing.
    #[test]
    fn a_masking_token_is_never_rewritten() {
        let mut registry = SecretRegistry::new();
        registry.register("DB_PASSWORD", "PASS");
        registry.register("ADMIN_PASSWORD", "hunter2SecretValue");
        registry.register("API_TOKEN", "TOKEN");
        let masker = registry.freeze().unwrap();

        let once = masker.mask("PASS hunter2SecretValue TOKEN, MASKED: [MASKED:ADMIN_PASSWORD]");
        assert_eq!(
            once,
            "[MASKED:DB_PASSWORD] [MASKED:ADMIN_PASSWORD] [MASKED:API_TOKEN], MASKED: \
             [MASKED:ADMIN_PASSWORD]"
        );
        assert_eq!(masker.mask(&once), once);
        // A token of no registered variable is text like any other.
        assert_eq!(
            masker.mask("[MASKED:OTHER_PASSWORD]"),
            "[MASKED:OTHER_[MASKED:DB_PASSWORD]WORD]"
        );
    }

    #[test]
    fn masks_literal_and_encoding_variants() {
        let mut registry = SecretRegistry::new();
        // a value with chars that differ url-encoded (`/`, `+`) and json-escaped (`"`)
        registry.register("SECRET_X", "a/b+c\"d");
        let masker = registry.freeze().unwrap();

        // literal
        assert_eq!(
            masker.mask("got a/b+c\"d here"),
            "got [MASKED:SECRET_X] here"
        );
        // url-encoded form (a *distinct* string from the literal) is also caught
        let url = url_encode_component("a/b+c\"d");
        assert_ne!(url, "a/b+c\"d");
        assert_eq!(masker.mask(&format!("u={url}")), "u=[MASKED:SECRET_X]");
        // json-escaped form (also distinct) is also caught
        let json = json_escape("a/b+c\"d");
        assert_ne!(json, "a/b+c\"d");
        assert_eq!(masker.mask(&format!("j={json}")), "j=[MASKED:SECRET_X]");
    }

    /// No `Debug` rendering of the registry or the masker holds a registered value, in
    /// any of its forms.
    #[test]
    fn debug_shows_no_secret_value() {
        let mut registry = SecretRegistry::new();
        registry.register("API_TOKEN", "tok-1234567890/'x");
        let shown = format!("{registry:?}");
        assert!(
            shown.contains("API_TOKEN") && shown.contains("<redacted>"),
            "{shown}"
        );
        assert!(!shown.contains("tok-1234567890"), "{shown}");
        let masker = registry.freeze().unwrap();
        let shown = format!("{masker:?} {masker:#?}");
        assert!(shown.contains("API_TOKEN"), "{shown}");
        assert!(!shown.contains("tok-1234567890"), "{shown}");
    }

    /// A value holding a `'` is masked as zap's delivered command spells it, single-
    /// quoted for the shell, which a shell's trace or an echoed command line prints.
    #[test]
    fn masks_the_shell_quoted_variant() {
        let mut registry = SecretRegistry::new();
        registry.register("SECRET_X", "hunter2-it's");
        let masker = registry.freeze().unwrap();
        let delivered = format!(
            "+ export TOKEN={}",
            zap_types::shell::single_quote("Bearer hunter2-it's")
        );
        assert_eq!(delivered, r"+ export TOKEN='Bearer hunter2-it'\''s'");
        assert_eq!(
            masker.mask(&delivered),
            "+ export TOKEN='Bearer [MASKED:SECRET_X]'"
        );
    }

    #[test]
    fn url_encode_component_matches_encode_uri_component() {
        // unreserved set passes through unchanged
        assert_eq!(url_encode_component("aZ9-_.!~*'()"), "aZ9-_.!~*'()");
        // everything else is percent-encoded (uppercase hex), incl. multibyte UTF-8
        assert_eq!(url_encode_component("a b/c"), "a%20b%2Fc");
        assert_eq!(url_encode_component("p@ss:w+rd"), "p%40ss%3Aw%2Brd");
        assert_eq!(url_encode_component("é"), "%C3%A9"); // 2 UTF-8 bytes
    }

    #[test]
    fn json_escape_matches_json_stringify_body() {
        // the body of `JSON.stringify(value)` — quotes/backslashes/control chars
        assert_eq!(json_escape("plain"), "plain");
        assert_eq!(json_escape("a\"b"), "a\\\"b");
        assert_eq!(json_escape("a\\b"), "a\\\\b");
        assert_eq!(json_escape("a\nb"), "a\\nb");
    }

    #[test]
    fn empty_value_is_skipped() {
        let mut registry = SecretRegistry::new();
        registry.register("SECRET_EMPTY", "");
        assert!(registry.is_empty());
        let masker = registry.freeze().unwrap();
        assert_eq!(masker.mask("between every char"), "between every char");
    }

    #[test]
    fn longest_value_masks_first() {
        let mut registry = SecretRegistry::new();
        // a shorter secret is a substring of a longer one; longest must win so the
        // long secret is fully masked rather than partially shredded.
        registry.register("SECRET_LONG", "supersecretvalue");
        registry.register("SECRET_SHORT", "secret");
        let masker = registry.freeze().unwrap();
        assert_eq!(masker.mask("supersecretvalue"), "[MASKED:SECRET_LONG]");
        // the short one still masks on its own
        assert_eq!(masker.mask("a secret here"), "a [MASKED:SECRET_SHORT] here");
    }

    /// A value that holds a masking token can't be masked — the token would be left
    /// standing, and the rest of the value with it — so it is refused, naming the
    /// variable it belongs to.
    #[test]
    fn a_value_holding_a_masking_token_is_rejected() {
        for value in ["[MASKED:B]", "before [MASKED:B] after", "[MASKED:A]"] {
            let mut registry = SecretRegistry::new();
            registry.register("A", value);
            registry.register("B", "plain-value");
            let Err(Error::Secret(message)) = registry.freeze() else {
                panic!("{value} froze");
            };
            assert!(
                message.starts_with(&format!(
                    "the value of `{}` holds the masking token `[MASKED:",
                    var_ref::shown("A")
                )),
                "{message}"
            );
        }
        // A token of no registered variable is only text.
        let mut registry = SecretRegistry::new();
        registry.register("A", "[MASKED:C]");
        let masker = registry.freeze().unwrap();
        assert_eq!(masker.mask("saw [MASKED:C]."), "saw [MASKED:A].");
    }

    #[test]
    fn var_names_handle_edge_cases() {
        let mut names = BTreeSet::new();
        // Several references with literal text around them; text that only looks like
        // one, and a delimiter that opens nothing, name no variable (matching
        // `resolve_env_vars`).
        var_names_in(
            &format!(
                "a{}b$$$$c{}d$$OLD$$ {{env:SHOWN}} {}UNCLOSED",
                var_ref::marker("ONE"),
                var_ref::marker("TWO"),
                var_ref::OPEN,
            ),
            &mut names,
        );
        assert_eq!(
            names,
            ["ONE", "TWO"].iter().map(|n| (*n).to_owned()).collect()
        );
    }

    #[test]
    fn scan_finds_var_names_across_the_config() {
        let config: ZapConfig = serde_json::from_value(serde_json::json!({
            "target": {"local": true},
            "resources": [
                {"id": "s", "type": "script", "check": "false",
                 "run": Text::of_pieces([
                     Lit("echo "), Ref("SECRET_TOKEN"), Lit(" to "), Ref("DEPLOY_HOST"),
                 ])}
            ]
        }))
        .unwrap();
        let names = scan_env_var_names(&config);
        assert!(names.contains("SECRET_TOKEN"));
        assert!(names.contains("DEPLOY_HOST"));
    }

    /// Text that spells a reference — `{env:NAME}`, as one is shown, or `$$NAME$$` — is
    /// its field's own text, in a field that takes a reference and in one that takes
    /// none: no scan names it, and the masker registers no value for it — a wetrun
    /// isn't refused for a variable nothing would substitute.
    #[expect(
        clippy::literal_string_with_formatting_args,
        reason = "`{env:NAME}` is the notation a reference is shown in, written out here as text"
    )]
    #[test]
    fn text_that_spells_a_reference_names_no_variable() {
        let config: ZapConfig = serde_json::from_value(serde_json::json!({
            "target": {"host": "h.example", "home": "/home/$$SECRET_HOME$$",
                       "key_path": "~/.ssh/$$SECRET_KEY_PATH$$", "package_manager": "apt"},
            "resources": [
                {"id": "inline", "name": "motd $$SECRET_NAME$$", "type": "file",
                 "path": "/etc/motd",
                 "content": {"type": "inline", "content": "hello $$SECRET_INLINE$$\n"}},
                {"id": "body", "type": "file", "path": "/etc/app.conf",
                 "content": {"type": "template", "template": "$$SECRET_BODY$$ {{v}}",
                             "vars": {"v": "literal"}}},
                {"id": "verify", "type": "verify", "assertions": [
                    {"type": "path_exists", "path": "/srv/$$SECRET_VERIFY_PATH$$"},
                    {"type": "command", "run": "echo $$SECRET_VERIFY_RUN$$",
                     "expect": "$$SECRET_VERIFY_EXPECT$$"},
                ]},
                {"id": "pkg", "type": "package", "from": {"apt": "curl"},
                 "check": "command -v $$SECRET_CHECK$$"},
                {"id": "script", "type": "script", "check": "test -e /x/{env:SECRET_SHOWN}",
                 "run": "echo $$SECRET_RUN$$ {env:SECRET_RUN}",
                 "env": {"V": "$$SECRET_ENV$$"}},
                {"id": "dir", "type": "directory", "path": "/srv/{env:SECRET_DIR}"},
                {"id": "build", "type": "build", "run": "make", "output": "/opt/b",
                 "source": {"type": "remote", "url": "https://x/s.tgz",
                            "blake3": "ab".repeat(32),
                            "verify": {"scheme": "minisign",
                                       "public_key": "RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3"}}},
            ],
            "deploy": {"build": "make $$SECRET_BUILD$$", "artifacts": ["$$SECRET_ARTIFACT$$"],
                       "path": "/srv/app", "shared": ["$$SECRET_SHARED$$"],
                       "prepare": ["warm $$SECRET_PREPARE$$"]},
        }))
        .unwrap();
        assert_eq!(scan_env_var_names(&config), BTreeSet::new());
        assert_eq!(scan_comparison_var_names(&config), BTreeSet::new());
        // Every name is secret-shaped and set, and none is registered.
        let masker = build_registry(&config, |_| Some("value-12345678".to_owned())).unwrap();
        assert!(masker.is_empty());
        assert_eq!(masker.mask("ran value-12345678"), "ran value-12345678");
    }

    /// The scans read each role: the wetrun's gate every one, the comparison's all but a
    /// fetch credential and the `deploy` block.
    #[test]
    fn the_scans_read_the_roles_they_are_scoped_to() {
        let config: ZapConfig = serde_json::from_value(serde_json::json!({
            "target": {"host": Text::reference("T_HOST"), "user": Text::reference("T_USER"),
                       "bootstrap_user": Text::reference("T_BOOTSTRAP")},
            "resources": [
                {"id": "f", "type": "file", "path": Text::of_pieces([Lit("/opt/"), Ref("R_PATH")]),
                 "content": {"type": "remote",
                             "url": Text::of_pieces([Lit("https://x/"), Ref("R_URL")]),
                             "blake3": "ab".repeat(32),
                             "auth": {"scheme": "bearer", "token": Text::reference("A_TOKEN")}}},
                {"id": "pkg", "type": "package", "from": {"apt": "curl"},
                 "check": Text::of_pieces([Lit("$HOME/"), Ref("R_CHECK"), Lit("/bin/curl")])},
            ],
            "deploy": {"artifacts": ["dist"], "path": "/srv/app",
                       "health": {"domain": Text::reference("D_DOMAIN"), "path": "/health"}},
        }))
        .unwrap();
        assert_eq!(
            scan_env_var_names(&config),
            set(&[
                "A_TOKEN",
                "D_DOMAIN",
                "R_CHECK",
                "R_PATH",
                "R_URL",
                "T_BOOTSTRAP",
                "T_HOST",
                "T_USER"
            ])
        );
        assert_eq!(
            scan_comparison_var_names(&config),
            set(&[
                "R_CHECK",
                "R_PATH",
                "R_URL",
                "T_BOOTSTRAP",
                "T_HOST",
                "T_USER"
            ])
        );
    }

    /// The masker registers a secret reference whatever its role: a value that
    /// only a fetch, the `deploy` block, or the connection resolves is masked like one
    /// a resource compares.
    #[test]
    fn a_secret_is_registered_whatever_its_role() {
        let config: ZapConfig = serde_json::from_value(serde_json::json!({
            "target": {"host": "h.example", "user": Text::reference("T_USER_TOKEN")},
            "resources": [
                {"id": "f", "type": "file",
                 "path": Text::of_pieces([Lit("/opt/"), Ref("R_PATH_TOKEN")]),
                 "content": {"type": "remote", "url": "https://x/y",
                             "blake3": "ab".repeat(32),
                             "auth": {"scheme": "bearer", "token": Text::reference("A_FETCH_TOKEN")}}},
            ],
            "deploy": {"artifacts": ["dist"], "path": "/srv/app",
                       "health": {"domain": Text::reference("D_DOMAIN_TOKEN"), "path": "/health"}},
        }))
        .unwrap();
        let masker = build_registry(&config, |name| Some(format!("value-of-{name}"))).unwrap();
        for name in [
            "T_USER_TOKEN",
            "R_PATH_TOKEN",
            "A_FETCH_TOKEN",
            "D_DOMAIN_TOKEN",
        ] {
            assert_eq!(
                masker.mask(&format!("saw value-of-{name}.")),
                format!("saw [MASKED:{name}]."),
                "{name}"
            );
        }
    }

    /// The registry asks the config's one rule: a fetch credential is registered under
    /// any name, a value with a credential's form under any name, a `mask`ed name by the
    /// config's word — and an `unmask`ed one isn't, whatever its name or value.
    #[test]
    fn the_registry_registers_what_the_rule_calls_secret() {
        let config: ZapConfig = serde_json::from_value(serde_json::json!({
            "target": {"local": true},
            "mask_vars": ["DECLARED"],
            "unmask_vars": ["PUBLIC_KEY_NAME", "DOCS_URL"],
            "resources": [
                {"id": "f", "type": "file", "path": "/opt/f",
                 "content": {"type": "remote", "url": "https://x.example/f",
                             "blake3": "ab".repeat(32),
                             "auth": {"scheme": "bearer", "token": Text::reference("GH_PAT")}}},
                {"id": "s", "type": "script", "check": "false",
                 "run": Text::of_pieces([
                     Lit("use "), Ref("DATABASE_URL"), Lit(" "), Ref("DECLARED"), Lit(" "),
                     Ref("PUBLIC_KEY_NAME"), Lit(" "), Ref("DOCS_URL"), Lit(" "),
                     Ref("PLAIN"), Lit(" "), Ref("TLS_KEY_PEM"), Lit(" "), Ref("UPSTREAM"),
                 ])},
            ],
        }))
        .unwrap();
        let env = |name: &str| {
            Some(
                match name {
                    "GH_PAT" => "pat-12345678",
                    "DATABASE_URL" => "postgres://app:hunter2@db/app",
                    "DECLARED" => "declared-12345678",
                    "PUBLIC_KEY_NAME" => "deploy-key-name",
                    "DOCS_URL" => "https://docs:public@docs.example.com",
                    "PLAIN" => "plain-12345678",
                    "TLS_KEY_PEM" => {
                        "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASC"
                    }
                    "UPSTREAM" => "Bearer upstream-12345678",
                    _ => return None,
                }
                .to_owned(),
            )
        };
        let masker = build_validated_masker(&config, env).unwrap();
        let printed = "pat-12345678 | postgres://app:hunter2@db/app | declared-12345678 | \
                       deploy-key-name | https://docs:public@docs.example.com | \
                       plain-12345678 | Bearer upstream-12345678";
        assert_eq!(
            masker.mask(printed),
            "[MASKED:GH_PAT] | [MASKED:DATABASE_URL] | [MASKED:DECLARED] | deploy-key-name | \
             https://docs:public@docs.example.com | plain-12345678 | [MASKED:UPSTREAM]"
        );
        assert_eq!(
            masker.mask(&env("TLS_KEY_PEM").unwrap()),
            "[MASKED:TLS_KEY_PEM]"
        );
    }

    /// A config that lists a fetch credential with `unmask` is refused, naming the
    /// variable: the credential stays a secret, and the statement isn't dropped silently.
    #[test]
    fn an_unmasked_fetch_credential_is_refused() {
        let config: ZapConfig = serde_json::from_value(serde_json::json!({
            "target": {"local": true},
            "unmask_vars": ["GH_PAT", "PUBLIC_KEY_NAME"],
            "resources": [
                {"id": "b", "type": "build", "run": "make", "output": "/opt/b",
                 "source": {"type": "remote", "url": "https://x.example/s.tgz",
                            "blake3": "ab".repeat(32),
                            "auth": {"scheme": "bearer", "token": Text::reference("GH_PAT")}}},
            ],
        }))
        .unwrap();
        let Err(Error::Secret(message)) = build_validated_masker(&config, |_| None) else {
            panic!("an unmasked credential passed the gate");
        };
        assert_eq!(
            message,
            "`zap.unmask('GH_PAT')` names a variable the config uses as a fetch credential \
             (an `auth` token), which is a secret wherever it is used — remove the `unmask`"
        );
    }

    #[test]
    fn build_registry_registers_only_secret_shaped_resolved_vars() {
        let config: ZapConfig = serde_json::from_value(serde_json::json!({
            "target": {"local": true},
            "resources": [
                {"id": "s", "type": "script", "check": "false",
                 "run": Text::of_pieces([
                     Lit("use "), Ref("SECRET_TOKEN"), Lit(" and "), Ref("DEPLOY_HOST"),
                 ])}
            ]
        }))
        .unwrap();
        let env = |name: &str| match name {
            "SECRET_TOKEN" => Some("tok-12345678".to_owned()),
            "DEPLOY_HOST" => Some("example.com".to_owned()),
            _ => None,
        };
        let masker = build_registry(&config, env).unwrap();
        // the secret is masked; the ops var is left alone
        assert_eq!(masker.mask("ran tok-12345678"), "ran [MASKED:SECRET_TOKEN]");
        assert_eq!(masker.mask("host example.com"), "host example.com");
    }

    #[test]
    fn the_secret_gate_accepts_clean_and_rejects_literal() {
        // refs only, no literal — the gate passes (even with the secret resolvable).
        let clean: ZapConfig = serde_json::from_value(serde_json::json!({
            "target": {"local": true},
            "resources": [
                {"id": "s", "type": "script",
                 "check": Text::of_pieces([Lit("test -n "), Ref("SECRET_TOKEN")]),
                 "run": "echo ok"}
            ]
        }))
        .unwrap();
        let env = |name: &str| (name == "SECRET_TOKEN").then(|| "tok-12345678".to_owned());
        assert!(build_validated_masker(&clean, env).is_ok());

        // same secret referenced AND pasted as a literal elsewhere — the gate rejects.
        let leaky: ZapConfig = serde_json::from_value(serde_json::json!({
            "target": {"local": true},
            "resources": [
                {"id": "s", "type": "script",
                 "check": Text::of_pieces([Lit("test -n "), Ref("SECRET_TOKEN")]),
                 "run": "curl -H 'auth: tok-12345678'"}
            ]
        }))
        .unwrap();
        assert!(matches!(
            build_validated_masker(&leaky, env),
            Err(Error::Secret(_))
        ));
    }

    #[test]
    fn literal_secret_in_config_is_rejected() {
        let config: ZapConfig = serde_json::from_value(serde_json::json!({
            "target": {"local": true},
            "resources": [
                // references the var (so it registers) AND leaks it as a literal elsewhere
                {"id": "s", "type": "script",
                 "check": Text::of_pieces([Lit("test -n "), Ref("SECRET_TOKEN")]),
                 "run": "curl -H 'auth: tok-12345678'"}
            ]
        }))
        .unwrap();
        let env = |name: &str| (name == "SECRET_TOKEN").then(|| "tok-12345678".to_owned());
        let masker = build_registry(&config, env).unwrap();
        let error = scan_config_literals(&config, &masker, env).unwrap_err();
        // the finding names the variable, never the value
        let Error::Secret(message) = error else {
            panic!("expected Error::Secret");
        };
        assert!(message.contains(&var_ref::shown("SECRET_TOKEN")));
        assert!(!message.contains("tok-12345678"));
    }

    /// A secret whose value spells part of a tag, an error code, or an event's name is
    /// masked out of every free-text field all the same, and the structure around the
    /// text is left as it is — no outcome or event comes back unmasked.
    #[test]
    fn a_secret_that_spells_part_of_a_tag_is_still_masked() {
        use zap_types::error_code::ErrorCode;
        use zap_types::event::{Event, StepOutcome};
        use zap_types::schema::ResourceId;

        for tag_piece in ["fail", "change", "execution", "skipped", "e"] {
            let mut registry = SecretRegistry::new();
            registry.register("SECRET_SHORT", tag_piece);
            registry.register("SECRET_X", "tok-12345678");
            let masker = registry.freeze().unwrap();
            let id = ResourceId("svc".to_owned());

            let masked = mask_outcomes(
                &masker,
                vec![ChangeOutcome::Failed {
                    resource_id: id.clone(),
                    error: "auth rejected tok-12345678".to_owned(),
                    code: ErrorCode::ExecutionFailed,
                }],
            );
            let ChangeOutcome::Failed {
                resource_id,
                error,
                code,
            } = &masked[0]
            else {
                panic!("the outcome changed arm: {masked:?}");
            };
            assert_eq!((resource_id, *code), (&id, ErrorCode::ExecutionFailed));
            assert!(
                error.ends_with(" [MASKED:SECRET_X]"),
                "{tag_piece}: {error}"
            );
            assert!(!error.contains("tok-12345678"), "{tag_piece}: {error}");

            let events = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
            let handler = crate::event::mask_handler(
                masker.clone(),
                crate::event::EventHandler::Capture(std::sync::Arc::clone(&events)),
            );
            handler.emit(&Event::ChangeFailed {
                resource_id: id.clone(),
                error: "auth rejected tok-12345678".to_owned(),
                code: ErrorCode::ExecutionFailed,
            });
            handler.emit(&Event::from_step_outcome(&StepOutcome::Skipped {
                step: "restart".to_owned(),
                reason: "saw tok-12345678".to_owned(),
            }));
            let events = events.lock().unwrap();
            let shown = serde_json::to_string(&*events).unwrap();
            assert!(!shown.contains("tok-12345678"), "{tag_piece}: {shown}");
            assert!(
                shown.contains(r#""event":"change_failed""#)
                    && shown.contains(r#""code":"execution_failed""#)
                    && shown.contains(r#""event":"step_skipped""#)
                    && shown.contains(r#""step":"restart""#),
                "{tag_piece}: {shown}"
            );
        }
    }

    #[test]
    fn mask_outcomes_masks_each_arm() {
        let mut registry = SecretRegistry::new();
        registry.register("SECRET_X", "tok-12345678");
        let masker = registry.freeze().unwrap();
        let outcomes = vec![
            ChangeOutcome::Failed {
                resource_id: zap_types::schema::ResourceId("a".to_owned()),
                error: "command failed: tok-12345678".to_owned(),
                code: zap_types::error_code::ErrorCode::ExecutionFailed,
            },
            ChangeOutcome::Completed {
                resource_id: zap_types::schema::ResourceId("b".to_owned()),
                output: "wrote tok-12345678".to_owned(),
            },
        ];
        let masked = mask_outcomes(&masker, outcomes);
        let ChangeOutcome::Failed { error, .. } = &masked[0] else {
            panic!("expected Failed");
        };
        assert_eq!(error, "command failed: [MASKED:SECRET_X]");
        let ChangeOutcome::Completed { output, .. } = &masked[1] else {
            panic!("expected Completed");
        };
        assert_eq!(output, "wrote [MASKED:SECRET_X]");
    }
}
