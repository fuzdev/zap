//! Which references are secret — the one classifier every consumer asks.
//!
//! A reference is secret by what the config says about it, by where the config uses
//! it, by its name, or by the form of the value it resolves to. [`SecretRule`] is one
//! config's rule over all four, and [`SecretRule::classify`] the one question: the
//! masker's registry, the secret-literal gate, the last-run report's hashes, the
//! `zap.lock` entry address, and the plan's machine all ask it, with the value the
//! same operator environment resolves, so none can read a variable as secret where
//! another reads it plain.
//!
//! The order of the answer, first match wins:
//!
//! 1. **role** — a variable the config uses as a fetch credential
//!    ([`TextRole::FetchCredential`]) is secret, whatever else is said of it and
//!    wherever else it is used;
//! 2. **`zap.unmask('NAME')`** — the operator's statement that it is not a secret,
//!    over its name and its value alike;
//! 3. **`zap.mask('NAME')`** — the operator's statement that it is one;
//! 4. **name** — [`is_secret_var_name`];
//! 5. **value** — [`ValueShape::of`] the resolved value, when the variable is set.
//!
//! The last reads the value, and the name rule reads it for one thing: a variable
//! that is secret by its name alone is plain while its value is a switch
//! ([`is_switch_literal`]) — `ENABLE_AUTH=true` is a setting, and no credential is one
//! bit. So an unset variable is classified by the first four alone.

use std::collections::BTreeSet;

use crate::schema::{TextRole, ZapConfig};

/// Words that make a name a secret's wherever they occur in it.
const WORDS_ANYWHERE: [&str; 5] = ["SECRET", "PASSWORD", "TOKEN", "KEY", "CREDENTIAL"];

/// Words that make a name a secret's when its last segment ends with one
/// (`DB_PASS`, `PGPASS`, `MYSQL_PWD`, `GPG_PASSPHRASE`, `DOOR_PASSCODE`, `LDAP_BINDPW`,
/// `SLAPD_ROOTPW`).
const KIND_SUFFIXES: [&str; 7] = [
    "PASS",
    "PASSWD",
    "PASSPHRASE",
    "PASSCODE",
    "PWD",
    "BINDPW",
    "ROOTPW",
];

/// Words that make a name a secret's when they are its last segment (`SENTRY_DSN`,
/// `BASIC_AUTH`, `SSH_PRIVATE`, `HASH_SALT`, `SESSION_COOKIE`, `RAILS_SESSION`,
/// `ACCESS_JWT`, `GH_PAT`, `DB_PW`, `AWS_CRED`, `WIFI_PSK`, `SLACK_WEBHOOK`).
const KIND_WORDS: [&str; 12] = [
    "DSN", "AUTH", "PRIVATE", "SALT", "COOKIE", "SESSION", "JWT", "PAT", "PW", "CRED", "PSK",
    "WEBHOOK",
];

/// Kind words whose plural names a count or a setting more often than a set of secrets
/// (`MAX_SESSIONS`, `ACCEPT_COOKIES`, `MAX_WEBHOOKS`), so only the singular is a kind.
const SINGULAR_KINDS: [&str; 5] = ["AUTH", "PRIVATE", "SESSION", "COOKIE", "WEBHOOK"];

/// Segments after the kind word that say which copy of a secret the variable holds —
/// the environment it is for or its place in a rotation (`DB_PASS_PROD`,
/// `GH_PAT_OLD`, `DB_PASS_NEXT`) — and are passed over like a trailing number, as is a
/// version (`V` and digits: `DB_PASS_V2`).
const QUALIFIERS: [&str; 18] = [
    "PROD",
    "PRODUCTION",
    "STAGING",
    "STAGE",
    "DEV",
    "DEVELOPMENT",
    "TEST",
    "TESTING",
    "QA",
    "UAT",
    "OLD",
    "PREV",
    "PREVIOUS",
    "NEW",
    "NEXT",
    "CURRENT",
    "PRIMARY",
    "SECONDARY",
];

/// Ordinary words that end in `PASS` and name no password.
const PASS_WORDS: [&str; 6] = [
    "BYPASS",
    "COMPASS",
    "SURPASS",
    "TRESPASS",
    "OVERPASS",
    "UNDERPASS",
];

/// Whether a variable's name reads as a secret's (case-insensitive).
///
/// Two rules, either one enough:
///
/// - the name holds `SECRET`, `PASSWORD`, `TOKEN`, `KEY`, or `CREDENTIAL` anywhere
///   (`CLIENT_SECRET`, `PGPASSWORD`, `API_TOKEN`, `SECRET_COOKIE_KEYS`);
/// - its kind word — its last `_`-separated segment, passing over a trailing number
///   (`SMTP_PASS_2`, and one glued on, `DB_PASS2`, though `AUTH0` stays a name), a
///   version (`DB_PASS_V2`), and a qualifier naming an environment or a rotation
///   (`QUALIFIERS`: `DB_PASS_PROD`) — ends with `PASS`,
///   `PASSWD`, `PASSPHRASE`, `PASSCODE`, `PWD`, `BINDPW`, or `ROOTPW` (`DB_PASS`,
///   `PGPASS`, `DB_PWD`), or is `DSN`, `AUTH`, `PRIVATE`, `SALT`, `COOKIE`,
///   `SESSION`, `JWT`, `PAT`, `PW`, `CRED`, `PSK`, or `WEBHOOK`, or `WEBHOOK` followed
///   (or `WEBHOOKS`) by `URL` or `URI`. A plural reads as its singular (`DB_CREDS`,
///   `HASH_SALTS`), except for the kinds whose plural counts or switches something
///   (`SINGULAR_KINDS`: `MAX_SESSIONS`) and a word ending in `PASS`, whose plural
///   counts passes (`MAX_PASSES`).
///
/// The second rule reads the kind word alone because the same word earlier in a name
/// qualifies something else: `AUTH_HOST`, `PRIVATE_NETWORK_CIDR`, `SESSION_TIMEOUT`,
/// `COOKIE_DOMAIN`, and `JWT_ISSUER` are not secrets, and a host or user variable that
/// read as one would leave its plan with no machine to name. A kind word that is an
/// ordinary word ending in `PASS` (`BYPASS`, `COMPASS`) is no password, and neither is
/// the shell's own `PWD` / `OLDPWD`.
///
/// Permissive where it can be: a secret left unmasked is a disclosure, a plain value
/// masked is an inconvenience `zap.unmask` removes. A secret with a name neither rule
/// matches is declared with `zap.mask`.
#[must_use]
pub fn is_secret_var_name(name: &str) -> bool {
    let upper = name.to_ascii_uppercase();
    if WORDS_ANYWHERE.iter().any(|word| upper.contains(word)) {
        return true;
    }
    if upper == "PWD" {
        return false;
    }
    let mut words = upper
        .rsplit('_')
        .filter(|segment| !is_version(segment))
        .map(
            |segment| match segment.trim_end_matches(|c: char| c.is_ascii_digit()) {
                // `AUTH0` and `OAUTH2` are names, not a counted `AUTH`
                "AUTH" => segment,
                word => word,
            },
        )
        .filter(|word| !word.is_empty() && !QUALIFIERS.contains(word));
    let Some(kind) = words.next() else {
        return false;
    };
    if matches!(kind, "URL" | "URI") {
        return matches!(words.next(), Some("WEBHOOK" | "WEBHOOKS"));
    }
    is_secret_kind(kind)
        || [kind.strip_suffix("ES"), kind.strip_suffix('S')]
            .into_iter()
            .flatten()
            .any(|singular| {
                // a count of passes (`MAX_PASSES`) is no set of passwords
                !SINGULAR_KINDS.contains(&singular)
                    && !singular.ends_with("PASS")
                    && is_secret_kind(singular)
            })
}

/// Whether `segment` is a version qualifier: `V` and one or more digits.
fn is_version(segment: &str) -> bool {
    segment
        .strip_prefix('V')
        .is_some_and(|digits| !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit()))
}

/// Whether `word`, a name's kind word in the singular, names a secret
/// ([`is_secret_var_name`]'s second rule).
fn is_secret_kind(word: &str) -> bool {
    if KIND_WORDS.contains(&word) {
        return true;
    }
    if word == "OLDPWD" || PASS_WORDS.iter().any(|ordinary| word.ends_with(ordinary)) {
        return false;
    }
    KIND_SUFFIXES.iter().any(|suffix| word.ends_with(suffix))
}

/// Whether `value` is a switch: a boolean word (`true`, `false`, `yes`, `no`, `on`,
/// `off`, in any case) or a single digit, whatever whitespace stands around it.
///
/// A name that reads as a secret's also names settings about one (`ENABLE_AUTH`,
/// `IS_PRIVATE`, `REQUIRE_TOKEN`). Such a value is no credential — one bit guards
/// nothing — and masked, every `true` or `1` a command prints would turn into the
/// variable's token.
#[must_use]
pub fn is_switch_literal(value: &str) -> bool {
    const WORDS: [&str; 6] = ["true", "false", "yes", "no", "on", "off"];
    let value = value.trim();
    WORDS.iter().any(|word| value.eq_ignore_ascii_case(word))
        || matches!(value.as_bytes(), [digit] if digit.is_ascii_digit())
}

/// A form of value that declares a credential, whatever its variable is called.
///
/// Each is a format with a place for a secret in it, read by the format's own rule —
/// never a guess from how random a value looks or which vendor's prefix it carries. A
/// further shape is one variant, one line of [`ALL`](Self::ALL), and its predicate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValueShape {
    /// A URL whose authority carries a password, `scheme://user:password@host…`, or an
    /// `http` or `https` URL that carries any user, `https://<token>@host…`.
    UrlPassword,
    /// A PEM block of a private key: `-----BEGIN … PRIVATE KEY…-----`.
    PemPrivateKey,
    /// An HTTP `Authorization` value: `Bearer <token>` or `Basic <token>`.
    HttpAuthorization,
}

impl ValueShape {
    /// Every shape, in the order [`of`](Self::of) tries them.
    pub const ALL: [Self; 3] = [
        Self::UrlPassword,
        Self::PemPrivateKey,
        Self::HttpAuthorization,
    ];

    /// The shape `value` has, if it has one.
    #[must_use]
    pub fn of(value: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|shape| shape.matches(value))
    }

    /// Whether `value` has this shape.
    #[must_use]
    pub fn matches(self, value: &str) -> bool {
        match self {
            Self::UrlPassword => !url_credential_spans(value).is_empty(),
            Self::PemPrivateKey => holds_pem_private_key(value),
            Self::HttpAuthorization => http_authorization(value).is_some(),
        }
    }

    /// The shape as a message names it.
    #[must_use]
    pub const fn describe(self) -> &'static str {
        match self {
            Self::UrlPassword => "a URL holding a password",
            Self::PemPrivateKey => "a PEM private key",
            Self::HttpAuthorization => "an HTTP authorization value",
        }
    }
}

/// The credential a value's own format sets apart from the rest of it.
///
/// Wherever the format has such a part: the credential of each URL that holds one
/// (its password, or an `http` URL's user), as written and percent-decoded; the
/// token of an HTTP `Authorization` value, and for `Basic` the password it encodes
/// (when that is UTF-8 text).
///
/// What a tool is as likely to print as the whole value: a client that reports the URL
/// it normalised, or the password it was refused with, prints the part alone.
///
/// A part that also stands in its own value outside the credential's place is left
/// out — a URL password that is its scheme, user, host, or database too
/// (`postgres://app:postgres@db/app`), a `Basic` password that is its user. Such a
/// word is by the value's own evidence an ordinary one: masked alone it would be
/// masked wherever a command names the scheme or the user, and in every other
/// variable's value that holds it. It is still masked as part of the whole value. A
/// password that is an ordinary word not present in its own value (`changeme`) is a
/// part like any other, and is masked wherever it appears.
#[must_use]
pub fn credential_parts(value: &str) -> Vec<String> {
    let mut parts: Vec<String> = Vec::new();
    let spans = url_credential_spans(value);
    // The value around its passwords, as the runs between them: a part found in one
    // stands outside every credential's place.
    let mut around = Vec::with_capacity(spans.len() + 1);
    let mut from = 0;
    for span in &spans {
        around.push(&value[from..span.start]);
        from = span.end;
    }
    around.push(&value[from..]);
    for span in &spans {
        let password = &value[span.clone()];
        let decoded = percent_decoded(password).filter(|decoded| decoded != password);
        let forms: Vec<String> = std::iter::once(password.to_owned())
            .chain(decoded)
            .collect();
        // One password in two spellings: either one standing elsewhere says it is an
        // ordinary word.
        if forms
            .iter()
            .any(|form| around.iter().any(|run| run.contains(form.as_str())))
        {
            continue;
        }
        for form in forms {
            if !parts.contains(&form) {
                parts.push(form);
            }
        }
    }
    if let Some(authorization) = http_authorization(value) {
        parts.push(authorization.token.to_owned());
        parts.extend(
            authorization
                .password
                .filter(|password| !authorization.user.contains(password)),
        );
    }
    parts
}

/// Where in `value` the credential of each URL that carries one in its userinfo
/// stands, in order: its non-empty password, or for an `http` or `https` URL with
/// none, its non-empty user.
///
/// A URL is found wherever `://` follows a scheme — at the start of the value, after
/// an option's `=`, in a list of hosts, in a sentence. Its authority ends at the first
/// `/`, `?`, `#`, `"`, or whitespace, so an `@` in a path, a query, or a fragment — or
/// past the quote that closes the URL in a JSON value — is no userinfo; within it the
/// userinfo ends at the last `@`, as the readers that tolerate an unencoded `@` in a
/// password take it, and the password starts after the first `:`. A `'` and a `;` end
/// nothing: both are written in a userinfo as they are.
///
/// One exception to the authority's end: a `?` or `#` inside a password pasted
/// unencoded (`postgres://app:p#ss@db/app`, as libpq reads a connection URI). When no
/// `@` precedes the first `?` or `#`, the userinfo is read up to the first `@` after it,
/// before the first `/`, `"`, or whitespace, if that reading puts the `?` or `#` in the
/// password, not in the user, and what precedes it in the password is not a port
/// (`https://h.example:8443?to=a@b` is a host, a port, and a query). A URL with an `@`
/// before its `?` or `#` keeps the plain reading, so a query holding an address
/// (`https://u:tok@host?to=me@x.com`) doesn't widen the password. The user is held to
/// holding none of `?`, `#`, `[`, or `]`: no account name does, so
/// `https://example.com?next=u:p@host` and an IPv6 host (`https://[::1]:8080?to=a@b`)
/// stay URLs with no userinfo. An empty port followed by a query (`https://h:?a@b`)
/// reads as a password: of the two readings of a malformed URL, the masked one.
///
/// An `http` or `https` URL's user — or one under a scheme ending in `+http` or `+https`
/// (`git+https`) — is a credential by itself: HTTP reads a userinfo
/// only as one (it deprecates the form, and a client sends it as `Basic` credentials),
/// so a token is carried as the user alone (`https://<token>@git.example.com/o/r`).
/// Other schemes name an account there (`ssh://git@host`, `postgres://app@db/app`),
/// which is no secret.
///
/// Out of reach: a password a URL carries in its query (`?password=…`), one in a
/// connection string of `key=value` pairs (`host=db password=…`), and a capability
/// URL's secret in its path (a webhook's). None of these formats marks which part is
/// the secret; such a variable is named for what it is, or declared with `zap.mask`.
fn url_credential_spans(value: &str) -> Vec<std::ops::Range<usize>> {
    const MARK: &str = "://";
    fn userinfo_of(authority: &str) -> Option<&str> {
        authority.rsplit_once('@').map(|(userinfo, _)| userinfo)
    }
    value
        .match_indices(MARK)
        .filter_map(|(at, _)| {
            let is_scheme_char =
                |c: char| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.');
            let scheme = value[..at]
                .rsplit(|c: char| !is_scheme_char(c))
                .next()
                .unwrap_or_default()
                .trim_start_matches(|c: char| !c.is_ascii_alphabetic());
            if scheme.is_empty() {
                return None;
            }
            let start = at + MARK.len();
            let rest = &value[start..];
            let loose_end = rest
                .find(|c: char| matches!(c, '/' | '"') || c.is_whitespace())
                .unwrap_or(rest.len());
            let strict_end = rest[..loose_end].find(['?', '#']).unwrap_or(loose_end);
            let userinfo = userinfo_of(&rest[..strict_end]).or_else(|| {
                // No `@` before the first `?` or `#`: the userinfo may run past it, to
                // the first `@` after it.
                let at = strict_end + rest[strict_end..loose_end].find('@')?;
                Some(&rest[..at]).filter(|userinfo| {
                    let (user, password) = userinfo.split_once(':').unwrap_or((userinfo, ""));
                    !user.contains(['?', '#', '[', ']'])
                        && password.find(['?', '#']).is_some_and(|cut| {
                            let before = &password[..cut];
                            before.is_empty() || !before.bytes().all(|b| b.is_ascii_digit())
                        })
                })
            })?;
            match userinfo.split_once(':') {
                Some((user, password)) if !password.is_empty() => {
                    let password_at = start + user.len() + ":".len();
                    Some(password_at..password_at + password.len())
                }
                found => {
                    let user = found.map_or(userinfo, |(user, _)| user);
                    // `git+https` and its kind carry HTTP's userinfo
                    let base = scheme.rsplit('+').next().unwrap_or(scheme);
                    let is_http =
                        base.eq_ignore_ascii_case("http") || base.eq_ignore_ascii_case("https");
                    (is_http && !user.is_empty()).then(|| start..start + user.len())
                }
            }
        })
        .collect()
}

/// `text` with each `%XX` escape decoded, when it holds one and the result is UTF-8.
fn percent_decoded(text: &str) -> Option<String> {
    let hex = |byte: u8| {
        char::from(byte)
            .to_digit(16)
            .and_then(|d| u8::try_from(d).ok())
    };
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut at = 0;
    while at < bytes.len() {
        let escaped = match (bytes[at], bytes.get(at + 1), bytes.get(at + 2)) {
            (b'%', Some(&high), Some(&low)) => hex(high).zip(hex(low)),
            _ => None,
        };
        if let Some((high, low)) = escaped {
            out.push(high * 16 + low);
            at += 3;
        } else {
            out.push(bytes[at]);
            at += 1;
        }
    }
    String::from_utf8(out).ok()
}

/// Whether `value` holds the opening line of a PEM private-key block, anywhere in it:
/// `-----BEGIN `, a one-line label naming a `PRIVATE KEY`, `-----`.
fn holds_pem_private_key(value: &str) -> bool {
    const BEGIN: &str = "-----BEGIN ";
    value.match_indices(BEGIN).any(|(at, _)| {
        let after = &value[at + BEGIN.len()..];
        after.find("-----").is_some_and(|end| {
            let label = &after[..end];
            label.contains("PRIVATE KEY") && !label.contains(['\n', '\r'])
        })
    })
}

/// The fewest characters a `Bearer` token has to read as one.
///
/// The scheme defines no form for its token, so the words that follow `Bearer` in
/// ordinary text (`Bearer token`, `Bearer authentication`) are told from a credential
/// by length alone: a token meant to be unguessable is longer than any of them, and
/// one shorter than this guards little. A short token under a plain name is declared
/// with `zap.mask`.
const BEARER_MIN_CHARS: usize = 16;

/// An HTTP `Authorization` value, read.
struct HttpAuthorization<'a> {
    /// The token after the scheme.
    token: &'a str,
    /// The user a `Basic` token encodes: what precedes the first `:` of its bytes.
    /// Empty for `Bearer`.
    user: String,
    /// The password a `Basic` token encodes — what follows that `:` — when there is
    /// one and it is UTF-8 text.
    password: Option<String>,
}

/// `value` read as an HTTP `Authorization` value: the scheme `Bearer` or `Basic` (in
/// any case), then one token of the characters such a credential is written in
/// (`A-Za-z0-9-._~+/`, then any `=` padding) and nothing after it. The header line
/// that carries one reads the same: `Authorization:` or `Proxy-Authorization:` (in
/// any case) before the value.
///
/// Each scheme's token is held to what the scheme says of it, so that a plan's name
/// (`Basic Monthly`) is not a credential: a `Basic` token is base64 of bytes holding a
/// `:` — `user:password`, the scheme's definition, in whatever charset the two were
/// written — and a `Bearer` token has at least [`BEARER_MIN_CHARS`] characters.
fn http_authorization(value: &str) -> Option<HttpAuthorization<'_>> {
    let value = value.trim();
    let value = ["authorization:", "proxy-authorization:"]
        .into_iter()
        .find_map(|field| {
            value
                .get(..field.len())
                .filter(|name| name.eq_ignore_ascii_case(field))
                .map(|_| value[field.len()..].trim_start_matches([' ', '\t']))
        })
        .unwrap_or(value);
    let (scheme, token) = value.split_once([' ', '\t'])?;
    let token = token.trim_start_matches([' ', '\t']);
    let body = token.trim_end_matches('=');
    let is_token = !body.is_empty()
        && body.bytes().all(|b| {
            b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~' | b'+' | b'/')
        });
    if !is_token {
        return None;
    }
    if scheme.eq_ignore_ascii_case("bearer") {
        (token.chars().count() >= BEARER_MIN_CHARS).then_some(HttpAuthorization {
            token,
            user: String::new(),
            password: None,
        })
    } else if scheme.eq_ignore_ascii_case("basic") {
        let bytes = base64_decoded(body)?;
        let colon = bytes.iter().position(|byte| *byte == b':')?;
        let (user, password) = (&bytes[..colon], &bytes[colon + 1..]);
        Some(HttpAuthorization {
            token,
            user: String::from_utf8_lossy(user).into_owned(),
            password: std::str::from_utf8(password)
                .ok()
                .filter(|password| !password.is_empty())
                .map(str::to_owned),
        })
    } else {
        None
    }
}

/// The bytes `body` — standard base64 with its padding removed — encodes, or `None`
/// when it is not base64.
fn base64_decoded(body: &str) -> Option<Vec<u8>> {
    if body.len() % 4 == 1 {
        return None;
    }
    let mut out = Vec::with_capacity(body.len() * 3 / 4);
    let (mut bits, mut held) = (0_u32, 0_u32);
    for byte in body.bytes() {
        let six = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => return None,
        };
        bits = (bits << 6) | u32::from(six);
        held += 6;
        if held >= 8 {
            held -= 8;
            out.push(u8::try_from((bits >> held) & 0xff).ok()?);
        }
    }
    Some(out)
}

/// Why a reference is secret.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecretReason {
    /// The config uses the variable as a fetch credential.
    Credential,
    /// The config lists it with `zap.mask`.
    Declared,
    /// Its name reads as a secret's ([`is_secret_var_name`]).
    Name,
    /// The value it resolves to has a credential's form.
    Value(ValueShape),
}

impl SecretReason {
    /// Whether the variable is secret only by how it looks — its name or its value's
    /// form — which `zap.unmask` overrides. A credential and a `zap.mask` are the
    /// config's own statements.
    #[must_use]
    pub const fn by_shape(self) -> bool {
        matches!(self, Self::Name | Self::Value(_))
    }
}

/// What [`SecretRule::classify`] answers for one reference.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Secrecy {
    /// Not a secret: it resolves by value.
    Plain,
    /// A secret: its value is masked wherever it would print and stands as a fixed
    /// token wherever it would be hashed.
    Secret(SecretReason),
}

impl Secrecy {
    /// Whether the reference is secret.
    #[must_use]
    pub const fn is_secret(self) -> bool {
        matches!(self, Self::Secret(_))
    }

    /// A variable's secrecy by its name and value alone, as [`SecretRule::classify`]
    /// reads them where no config says more — an env file's pairs, before any config
    /// is evaluated.
    #[must_use]
    pub fn by_shape(name: &str, value: Option<&str>) -> Self {
        if is_secret_var_name(name) && !value.is_some_and(is_switch_literal) {
            Self::Secret(SecretReason::Name)
        } else if let Some(shape) = value.and_then(ValueShape::of) {
            Self::Secret(SecretReason::Value(shape))
        } else {
            Self::Plain
        }
    }
}

/// A `Debug` stand-in for a resolved value, which may be a secret's: it prints
/// `<redacted>`. The `Debug` of a type holding resolved values shows its shape and
/// names through it, never a value.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Redacted;

impl std::fmt::Debug for Redacted {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("<redacted>")
    }
}

/// One config's rule for which references are secret (see the module docs).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretRule {
    /// Names the config lists with `zap.mask`.
    mask: BTreeSet<String>,
    /// Names the config lists with `zap.unmask`.
    unmask: BTreeSet<String>,
    /// Names the config references in a fetch credential.
    credentials: BTreeSet<String>,
}

impl SecretRule {
    /// The rule `config` declares: its `mask` / `unmask` lists, and every variable one
    /// of its fetch credentials references.
    #[must_use]
    pub fn of(config: &ZapConfig) -> Self {
        let names = |vars: &Option<Vec<crate::scalar::EnvVarName>>| -> BTreeSet<String> {
            vars.iter().flatten().map(ToString::to_string).collect()
        };
        let mut credentials = BTreeSet::new();
        config.for_each_text(|role, text| match role {
            TextRole::FetchCredential => credentials.extend(text.ref_names().map(str::to_owned)),
            TextRole::TargetIdentity | TextRole::Resource | TextRole::Deploy => {}
        });
        Self {
            mask: names(&config.mask_vars),
            unmask: names(&config.unmask_vars),
            credentials,
        }
    }

    /// Whether a reference to `name` is a reference to a secret, and why. `value` is
    /// what the variable resolves to in the operator environment, `None` when it is
    /// unset; the value-shape rule reads it, and the name rule its being a switch
    /// ([`is_switch_literal`]). Neither a fetch credential nor a `zap.mask` depends on
    /// it.
    #[must_use]
    pub fn classify(&self, name: &str, value: Option<&str>) -> Secrecy {
        if self.credentials.contains(name) {
            Secrecy::Secret(SecretReason::Credential)
        } else if self.unmask.contains(name) {
            Secrecy::Plain
        } else if self.mask.contains(name) {
            Secrecy::Secret(SecretReason::Declared)
        } else {
            Secrecy::by_shape(name, value)
        }
    }

    /// The names the config both lists with `zap.unmask` and uses as a fetch
    /// credential (sorted). The two contradict: a credential is never shown, so the
    /// `unmask` could only be ignored.
    #[must_use]
    pub fn unmasked_credentials(&self) -> Vec<&str> {
        self.unmask
            .intersection(&self.credentials)
            .map(String::as_str)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::{
        Secrecy, SecretReason, SecretRule, ValueShape, credential_parts, is_secret_var_name,
        is_switch_literal,
    };
    use crate::schema::ZapConfig;
    use crate::text::Text;

    /// The name rule, both ways, over names a real environment holds.
    #[test]
    fn the_name_rule_reads_realistic_names() {
        for secret in [
            // a word anywhere
            "SECRET",
            "CLIENT_SECRET",
            "SECRET_FUZ_COOKIE_KEYS",
            "OAUTH_SECRET_ID",
            "secret_token",
            "DB_PASSWORD",
            "PGPASSWORD",
            "API_TOKEN",
            "AUTH_TOKEN",
            "COOKIE_KEY",
            "PRIVATE_KEY",
            "SESSION_SECRET",
            "AWS_CREDENTIAL_FILE",
            // a word anywhere, matched inside a longer one
            "PUBLIC_KEY_DESCRIPTION",
            "KEYBOARD_LAYOUT",
            "TOKEN_TTL",
            "SECRETED_AWAY",
            // the last segment ends with a password word
            "PASS",
            "DB_PASS",
            "PGPASS",
            "DBPASS",
            "SMTP_PASS_2",
            "db_pass",
            "MYSQL_PASSWD",
            "GPG_PASSPHRASE",
            "DOOR_PASSCODE",
            "DB_PWD",
            "MYSQL_PWD",
            "DBPWD",
            // the last segment is a kind of secret
            "DSN",
            "SENTRY_DSN",
            "AUTH",
            "BASIC_AUTH",
            "SSH_PRIVATE",
            "SALT",
            "HASH_SALT",
            "COOKIE",
            "SESSION_COOKIE",
            "SESSION",
            "RAILS_SESSION",
            "JWT",
            "ACCESS_JWT",
            "PAT",
            "GH_PAT",
            "GITHUB_PAT",
            "PW",
            "ADMIN_PW",
            "DB_PW",
            "AWS_CRED",
            "WIFI_PSK",
            "IPSEC_PSK",
            "LDAP_BINDPW",
            "BINDPW",
            "SLAPD_ROOTPW",
            "SLACK_WEBHOOK",
            "SLACK_WEBHOOK_URL",
            "DISCORD_WEBHOOK_URI",
            "WEBHOOK_URL",
            // a qualifier after the kind word
            "DB_PASS_PROD",
            "DB_PASS_PROD_2",
            "SMTP_PWD_STAGING",
            "SENTRY_DSN_DEV",
            "GH_PAT_OLD",
            "SLACK_WEBHOOK_URL_PROD",
            "DB_PASS_NEW",
            "DB_PASS_NEXT",
            "DB_PASS_CURRENT",
            "DB_PASS_PRIMARY",
            "DB_PASS_SECONDARY",
            "DB_PASS_V2",
            "DB_PASS_V2_PROD",
            "WEBHOOKS_URL",
            // a plural
            "DB_CREDS",
            "AWS_CREDS",
            "CREDS",
            "HASH_SALTS",
            "GH_PATS",
            "BACKUP_PASSPHRASES",
            "DB_PASSWDS",
            "SENTRY_DSNS",
        ] {
            assert!(is_secret_var_name(secret), "{secret} reads plain");
        }
        for plain in [
            "DEPLOY_HOST",
            "DEPLOY_DOMAIN",
            "DATABASE_URL",
            "PATH",
            "HOME",
            // a word that only ends like a kind
            "PATTERN",
            "DEPLOY_PATH",
            "COMPAT",
            "BPW",
            "PW_FILE",
            // a kind word that qualifies something else
            "AUTH_HOST",
            "AUTH_URL",
            "OAUTH_CLIENT_ID",
            "AUTHOR",
            "AUTHOR_NAME",
            "PRIVATE_NETWORK_CIDR",
            "PRIVATE_IP",
            "SESSION_TIMEOUT",
            "SESSION_COUNT",
            "COOKIE_DOMAIN",
            "JWT_ISSUER",
            "SALT_ROUNDS",
            "SALT_MASTER_HOST",
            "DSN_HOST",
            // a password word that isn't the kind
            "PASSENGER_HOST",
            "PASS_THROUGH_HOST",
            "PGPASSFILE",
            // ordinary words ending in one
            "BYPASS_CACHE",
            "CACHE_BYPASS",
            "COMPASS",
            "ENCOMPASS",
            // the shell's working directory
            "PWD",
            "OLDPWD",
            "OLDPWD2",
            "",
            "_",
            "_1",
            // a qualifier with no kind word before it, or before a plain one
            "PROD",
            "DEPLOY_HOST_PROD",
            "DB_TEST",
            "AUTH_URL_DEV",
            // a number glued to a word that is no kind
            "OAUTH2_CLIENT_ID",
            "GOOGLE_OAUTH2",
            "AWS_S3",
            "HTTP2",
            "BYPASS2",
            // a plural of a kind that counts or switches, or of no kind
            "MAX_SESSIONS",
            "ACCEPT_COOKIES",
            "MAX_WEBHOOKS",
            "IP_ADDRESSES",
            "CLASSES",
            "COMPASSES",
            "BYPASSES",
            "ACCESS",
            // a count of passes
            "MAX_PASSES",
            "NUM_PASSES",
            "RENDER_PASSES",
            "DB_PASSES",
            // a vendor's or protocol's name with a number in it
            "AUTH0",
            "USE_AUTH0",
            // a version with no kind word before it, and a bare `V`
            "API_V2",
            "DB_PASS_V",
            "V2",
            // a URL that is no webhook's, and a webhook's setting
            "AUTH_URL",
            "WEBHOOK_TIMEOUT",
            "WEBHOOK_HOST",
            "PSK_IDENTITY",
            "CRED_HELPER",
        ] {
            assert!(!is_secret_var_name(plain), "{plain} reads secret");
        }
    }

    #[test]
    fn a_url_with_a_password_is_a_secret() {
        for secret in [
            "postgres://app:hunter2@db.example.com:5432/app",
            "postgresql://app:hunter2@db/app?sslmode=require",
            "https://user:pw@example.com",
            "https://user:pw@example.com/a@b?c=d@e#f@g",
            "redis://:pw@cache.example.com:6379/0",
            "amqp://u:p%40ss@mq",
            "https://user:p@ss@example.com/",
            "jdbc:postgresql://app:pw@db/app",
            "git+ssh://deploy:pw@git.example.com/repo.git",
            "  postgres://app:pw@db/app\n",
            // the userinfo ends at the last `@`, so a `:` after an earlier one is its
            "https://user@corp:pw@example.com/",
            // a URL anywhere in the value
            "redis://h1,redis://:b@h2",
            "--db=postgres://u:p@h",
            "see https://user:pw@example.com for more",
            "1http://user:pw@example.com",
            "https://docs.example.com/x then amqp://u:p@mq",
            r#"{"url":"https://u:p@example.com","email":"a@c"}"#,
            "https://u:it's;p@example.com",
            // an http URL's user is a credential by itself
            "https://user@example.com",
            "https://user:@example.com",
            "HTTP://user@example.com",
            "see https://tok@h.example/x",
            "git+https://tok@git.example.com/o/r",
        ] {
            assert_eq!(
                ValueShape::of(secret),
                Some(ValueShape::UrlPassword),
                "{secret}"
            );
        }
        for plain in [
            "https://example.com",
            "https://@example.com",
            "https://:@example.com",
            "https://example.com/a:b@c",
            "https://example.com?next=u:p@host",
            "https://example.com#u:p@host",
            "https://example.com?next=u@host",
            "https://example.com:8443/x",
            // a port, then a query or fragment holding an `@`
            "https://h.example:8443?to=a@b",
            "https://h.example:8443#a@b",
            // another scheme's user names an account
            "ssh://git@github.com/o/r",
            "postgres://app@db/app",
            "ftp://anonymous@ftp.example.com",
            "git+ssh://git@github.com/o/r",
            // an IPv6 host, then a query holding an `@`
            "https://[::1]?a=b@c",
            "https://[::1]:8080?next=a@b.com",
            "https://[fe80::1%25eth0]:443?x=y@z",
            "postgres:///app",
            "mailto:user:pw@example.com",
            "user:pw@example.com",
            "://user:pw@example.com",
            "see https://example.com and write to a:b@c",
            "https://example.com, user:pw@host",
            "redis://h1,redis://h2",
            // a `"` ends a URL: what follows the quote is another value
            r#"{"url":"https://example.com","email":"a:b@c"}"#,
            "example.com",
            "",
        ] {
            assert_eq!(ValueShape::of(plain), None, "{plain}");
        }
    }

    #[test]
    fn a_pem_private_key_is_a_secret() {
        for secret in [
            "-----BEGIN PRIVATE KEY-----\nMIIE\n-----END PRIVATE KEY-----\n",
            "-----BEGIN RSA PRIVATE KEY-----\nMIIE",
            "-----BEGIN OPENSSH PRIVATE KEY-----",
            "-----BEGIN ENCRYPTED PRIVATE KEY-----",
            "-----BEGIN PGP PRIVATE KEY BLOCK-----",
            "-----BEGIN CERTIFICATE-----\nAA\n-----END CERTIFICATE-----\n\
             -----BEGIN EC PRIVATE KEY-----\nBB",
            "key: -----BEGIN PRIVATE KEY-----",
        ] {
            assert_eq!(
                ValueShape::of(secret),
                Some(ValueShape::PemPrivateKey),
                "{secret}"
            );
        }
        for plain in [
            "-----BEGIN CERTIFICATE-----\nAA\n-----END CERTIFICATE-----",
            "-----BEGIN PUBLIC KEY-----\nAA\n-----END PUBLIC KEY-----",
            "-----BEGIN \nPRIVATE KEY-----",
            "-----BEGIN PRIVATE KEY",
            "BEGIN PRIVATE KEY",
            "PRIVATE KEY",
        ] {
            assert_eq!(ValueShape::of(plain), None, "{plain}");
        }
    }

    #[test]
    fn an_http_authorization_value_is_a_secret() {
        for secret in [
            "Bearer eyJhbGciOi.eyJzdWIi.c2ln",
            "Authorization: Bearer abc123def456ghi7",
            "authorization:Bearer abc123def456ghi7",
            "Proxy-Authorization: Basic dXNlcjpwYXNz",
            "  AUTHORIZATION:\tbearer abc123def456ghi7\n",
            "bearer abc123def456ghi7",
            "BEARER abc/+~._-12345==",
            "Bearer   abc123def456ghi7",
            " Bearer abc123def456ghi7\n",
            // `user:pass`, `user:`, `:pass`, and unpadded `a:b`
            "Basic dXNlcjpwYXNz",
            "basic\tdXNlcjpwYXNz",
            "Basic dXNlcjo=",
            "Basic OnBhc3M=",
            "Basic YTpi",
            // bytes that are no UTF-8, with the `:` of `user:password` among them
            "Basic /zr/",
            "Basic dXNlcjr//w==",
        ] {
            assert_eq!(
                ValueShape::of(secret),
                Some(ValueShape::HttpAuthorization),
                "{secret}"
            );
        }
        for plain in [
            "Bearer",
            "Bearer ",
            "Basic",
            "Bearer a b",
            "Basic realm=\"x\"",
            "Bearer ab=cd",
            "Bearer ===",
            "Digest abc123",
            "Token abc123",
            "Bearerabc123",
            "x Bearer abc123def456ghi7",
            "Authorization: Bearer token",
            "Authorization: abc123def456ghi7xyz",
            "Authorization:",
            "X-Authorization: Bearer abc123def456ghi7",
            // a `Bearer` token shorter than a credential is
            "Bearer token",
            "Bearer authentication",
            "Bearer abc123def456ghi",
            // a `Basic` token that is no base64 of `user:password`
            "Basic Monthly",
            "Basic plan",
            "Basic auth",
            "Basic dXNlcnBhc3M=",
            "Basic dXNlcjpwYXNzX",
            "Basic user:pass",
            "Basic /w==",
            "Basic //8=",
        ] {
            assert_eq!(ValueShape::of(plain), None, "{plain}");
        }
    }

    /// The part of a value that is the credential itself: each URL's password, as
    /// written and decoded, and an authorization value's token and encoded password.
    #[test]
    fn the_credential_parts_of_a_value() {
        assert_eq!(
            credential_parts("postgres://app:hunter2@db:5432/app"),
            ["hunter2"]
        );
        assert_eq!(
            credential_parts("redis://h1,redis://:p%40ss%2Fw@h2 and amqp://u:plain@mq"),
            ["p%40ss%2Fw", "p@ss/w", "plain"]
        );
        // An escape that isn't one is kept as written.
        assert_eq!(credential_parts("https://u:100%zz@h"), ["100%zz"]);
        assert_eq!(
            credential_parts("Bearer abc123def456ghi7"),
            ["abc123def456ghi7"]
        );
        assert_eq!(
            credential_parts("Basic dXNlcjpwYXNz"),
            ["dXNlcjpwYXNz", "pass"]
        );
        assert_eq!(credential_parts("Basic dXNlcjo="), ["dXNlcjo="]);
        // A `Basic` password that is no UTF-8 text is no part; the token is.
        assert_eq!(credential_parts("Basic dXNlcjr//w=="), ["dXNlcjr//w=="]);

        // A part that also stands in its value outside the credential's place is an
        // ordinary word, and is no part: the scheme, the user, the host, the path —
        // as written and decoded — and a `Basic` user.
        for ordinary in [
            "postgres://app:postgres@db/app",
            "postgres://postgres:postgres@db/app",
            "https://ci:example@example.com/x",
            "https://ci:files@h.example/files/a",
            "https://ci:a%2Fb@h.example/?next=a%2Fb",
            "https://ci:a%2Fb@h.example/a/b",
        ] {
            assert_eq!(credential_parts(ordinary), [""; 0], "{ordinary}");
        }
        // `admin:admin`
        assert_eq!(
            credential_parts("Basic YWRtaW46YWRtaW4="),
            ["YWRtaW46YWRtaW4="]
        );
        // Each URL's password is judged against the value around every password: one
        // that only another URL's password repeats is still a part, once.
        assert_eq!(
            credential_parts("redis://:hunter2@h1,redis://:hunter2@h2"),
            ["hunter2"]
        );
        assert_eq!(
            credential_parts("amqp://mq:s3cret@h1 amqp://u:mq@h2"),
            ["s3cret"]
        );
        for none in [
            "https://example.com",
            "tok-12345678",
            "-----BEGIN PRIVATE KEY-----",
            "",
        ] {
            assert_eq!(credential_parts(none), [""; 0], "{none}");
        }
    }

    /// A switch is a boolean word or one digit, and a variable that is secret by its
    /// name alone is plain while its value is one. Unset it is still a secret's name,
    /// and what the config or another value's form says of it stands.
    #[test]
    fn a_secret_named_switch_is_plain() {
        for switch in [
            "true", "false", "TRUE", "False", "yes", "No", "on", "OFF", "0", "1", "7",
        ] {
            assert!(is_switch_literal(switch), "{switch}");
            for name in ["ENABLE_AUTH", "IS_PRIVATE", "REQUIRE_TOKEN", "USE_SESSION"] {
                assert_eq!(
                    Secrecy::by_shape(name, Some(switch)),
                    Secrecy::Plain,
                    "{name}"
                );
                assert_eq!(
                    Secrecy::by_shape(name, None),
                    Secrecy::Secret(SecretReason::Name)
                );
            }
        }
        for padded in [" true ", "TRUE\n", "\t1", "no\r\n"] {
            assert!(is_switch_literal(padded), "{padded:?}");
            assert_eq!(
                Secrecy::by_shape("ENABLE_AUTH", Some(padded)),
                Secrecy::Plain
            );
        }
        for value in [
            "",
            "10",
            "t",
            "y",
            "enabled",
            "tr ue",
            "truthy",
            "١",
            "tok-12345678",
        ] {
            assert!(!is_switch_literal(value), "{value}");
            assert_eq!(
                Secrecy::by_shape("ENABLE_AUTH", Some(value)),
                Secrecy::Secret(SecretReason::Name),
                "{value}"
            );
        }
        let declared = rule(&["ENABLE_AUTH"], &[], Some("REQUIRE_TOKEN"));
        assert_eq!(
            declared.classify("ENABLE_AUTH", Some("true")),
            Secrecy::Secret(SecretReason::Declared)
        );
        assert_eq!(
            declared.classify("REQUIRE_TOKEN", Some("1")),
            Secrecy::Secret(SecretReason::Credential)
        );
        assert_eq!(
            declared.classify("IS_PRIVATE", Some("true")),
            Secrecy::Plain
        );
    }

    fn rule(mask: &[&str], unmask: &[&str], credential: Option<&str>) -> SecretRule {
        let auth = credential
            .map(|name| serde_json::json!({"scheme": "bearer", "token": Text::reference(name)}));
        let mut content = serde_json::json!({
            "type": "remote", "url": "https://x.example/y", "blake3": "ab".repeat(32),
        });
        if let Some(auth) = auth {
            content["auth"] = auth;
        }
        let config: ZapConfig = serde_json::from_value(serde_json::json!({
            "target": {"local": true},
            "resources": [{"id": "f", "type": "file", "path": "/opt/y", "content": content}],
            "mask_vars": mask, "unmask_vars": unmask,
        }))
        .unwrap();
        SecretRule::of(&config)
    }

    /// The order of the answer: a credential, then `unmask`, then `mask`, then the
    /// name, then the value.
    #[test]
    fn the_rule_answers_in_order() {
        const DSN: &str = "postgres://app:hunter2@db/app";
        let plain = rule(&[], &[], None);
        assert_eq!(plain.classify("APP", None), Secrecy::Plain);
        assert_eq!(plain.classify("APP", Some("value")), Secrecy::Plain);
        assert_eq!(
            plain.classify("API_TOKEN", None),
            Secrecy::Secret(SecretReason::Name)
        );
        // A value's shape is read only when there is a value, and after the name.
        assert_eq!(plain.classify("DATABASE_URL", None), Secrecy::Plain);
        assert_eq!(
            plain.classify("DATABASE_URL", Some(DSN)),
            Secrecy::Secret(SecretReason::Value(ValueShape::UrlPassword))
        );
        assert_eq!(
            plain.classify("DB_SECRET_URL", Some(DSN)),
            Secrecy::Secret(SecretReason::Name)
        );

        // `mask` declares, `unmask` wins over the name, the value, and `mask`.
        let listed = rule(
            &["DEPLOY_HOST", "BOTH"],
            &["API_TOKEN", "DATABASE_URL", "BOTH"],
            None,
        );
        assert_eq!(
            listed.classify("DEPLOY_HOST", Some("h.example")),
            Secrecy::Secret(SecretReason::Declared)
        );
        assert_eq!(listed.classify("API_TOKEN", Some("t")), Secrecy::Plain);
        assert_eq!(listed.classify("DATABASE_URL", Some(DSN)), Secrecy::Plain);
        assert_eq!(listed.classify("BOTH", None), Secrecy::Plain);
        assert_eq!(listed.unmasked_credentials(), [""; 0]);

        // A fetch credential is a secret whatever its name, and whatever `unmask` says.
        let credential = rule(&[], &[], Some("GH_PAT"));
        assert_eq!(
            credential.classify("GH_PAT", None),
            Secrecy::Secret(SecretReason::Credential)
        );
        let unmasked = rule(&[], &["GH_PAT"], Some("GH_PAT"));
        assert_eq!(
            unmasked.classify("GH_PAT", Some("ghp")),
            Secrecy::Secret(SecretReason::Credential)
        );
        assert_eq!(unmasked.unmasked_credentials(), ["GH_PAT"]);
    }

    #[test]
    fn only_a_name_or_a_value_shape_is_secret_by_shape() {
        assert!(SecretReason::Name.by_shape());
        assert!(SecretReason::Value(ValueShape::PemPrivateKey).by_shape());
        assert!(!SecretReason::Declared.by_shape());
        assert!(!SecretReason::Credential.by_shape());
        assert_eq!(
            Secrecy::by_shape("PLAIN", Some("Bearer abc123def456ghi7")),
            Secrecy::Secret(SecretReason::Value(ValueShape::HttpAuthorization))
        );
        assert_eq!(Secrecy::by_shape("PLAIN", Some("abc123")), Secrecy::Plain);
    }

    /// A `?` or `#` in a password pasted unencoded is part of the password, and the
    /// URL is a credential's; the same characters as a query or fragment are not.
    #[test]
    fn a_url_password_holding_a_hash_or_question_mark_is_a_credential() {
        for value in [
            "postgres://app:p#ss@db/app",
            "postgres://app:pw?x@db/app",
            "postgres://app:?pw@db",
            "postgres://app:x12#ab@db/app?sslmode=require",
            "redis://:p#w@cache:6379/0",
        ] {
            assert_eq!(
                ValueShape::of(value),
                Some(ValueShape::UrlPassword),
                "{value}"
            );
        }
        assert_eq!(
            credential_parts("postgres://app:p#ss1234@db/app"),
            ["p#ss1234"]
        );
        assert_eq!(credential_parts("postgres://app:pw?x=1@db/app"), ["pw?x=1"]);
        assert_eq!(credential_parts("postgres://app:p#ss@db/app"), ["p#ss"]);
        assert_eq!(
            credential_parts("redis://:p#sswordlong@host"),
            ["p#sswordlong"]
        );
    }

    /// The `?` / `#` reading never widens a password: a URL with an `@` before its
    /// query or fragment reads plainly, and one read past its `?` or `#` ends its
    /// userinfo at the first `@` after it. An IPv6 host is no userinfo, and a
    /// `git+https` URL reads its user as HTTP does.
    #[test]
    fn a_query_or_fragment_holding_an_at_does_not_widen_the_password() {
        for value in [
            "https://user:tokentokentoken@host?redirect=me@x.com",
            "https://user:tokentokentoken@host#me@x.com",
        ] {
            assert_eq!(credential_parts(value), ["tokentokentoken"], "{value}");
        }
        assert_eq!(
            credential_parts("postgres://u:pw#12345678@db?x=a@b"),
            ["pw#12345678"]
        );
        for value in [
            "https://[::1]?a=b@c",
            "https://[::1]:8080?next=a@b.com",
            "https://[fe80::1%25eth0]:443?x=y@z",
        ] {
            assert_eq!(ValueShape::of(value), None, "{value}");
        }
        assert_eq!(
            credential_parts("git+https://ghp_abcdefghijklmnop@github.com/o/r"),
            ["ghp_abcdefghijklmnop"]
        );
    }

    /// A token carried as an `http` or `https` URL's user, with no `:`, is a
    /// credential; another scheme's user names an account.
    #[test]
    fn a_token_as_an_https_urls_user_is_a_credential() {
        const URL: &str = "https://ghp_abcdefghijklmnopqrstuvwxyz0123@github.com/o/r.git";
        assert_eq!(ValueShape::of(URL), Some(ValueShape::UrlPassword));
        assert_eq!(
            credential_parts(URL),
            ["ghp_abcdefghijklmnopqrstuvwxyz0123"]
        );
        // A user that stands elsewhere in its value is an ordinary word.
        assert_eq!(
            credential_parts("https://deploy@git.example.com/deploy/app.git"),
            [""; 0]
        );
        assert_eq!(ValueShape::of("ssh://git@github.com/o/r"), None);
    }

    /// The docs say a trailing number is ignored; one glued to the last word is too.
    #[test]
    fn a_number_glued_to_the_last_word_is_ignored() {
        for name in [
            "DB_PASS2",
            "PGPASS2",
            "PASSWD1",
            "ADMIN_PWD1",
            "GH_PAT2",
            "SENTRY_DSN2",
            "SMTP_PASS_2",
        ] {
            assert!(is_secret_var_name(name), "{name}");
        }
    }
}
