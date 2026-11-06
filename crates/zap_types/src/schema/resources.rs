//! The resource payloads — the 15 `*Resource` structs and sub-payloads, the
//! closed-set enums (`ResourceType`, the manager enums, `Protocol`, `FirewallPolicy`,
//! `PgAuthMethod`, …), and the serde-default helpers they reference.

use std::collections::BTreeMap;
use std::fmt;

use serde::de::{self, MapAccess, Visitor};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use std::num::{NonZeroU16, NonZeroU32};

use super::TemplateKind;
use crate::scalar::{
    AccountName, ContentHash, EnvVarName, MinisignKey, Mode, PackageName, ServiceName,
};
use crate::text::{ENV_KEY, TEXT_KEY, Text};
use crate::var_ref::{self, Segment};

/// The resource kinds — the lightweight `Copy` tag.
///
/// `target` is config-level (see `Target`), not a resource. The payload lives on
/// [`ResourceKind`](super::ResourceKind);
/// `Resource::kind` derives this tag from it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResourceType {
    Package,
    AptRepo,
    Script,
    Installer,
    User,
    Directory,
    File,
    Link,
    Service,
    Database,
    Swap,
    Firewall,
    Verify,
    Pipeline,
    Build,
}

impl ResourceType {
    /// Every resource kind. Lets tooling and the driver sync tests (`zap_core::config`) iterate
    /// the set exhaustively; a new variant also breaks `as_str`'s match (the
    /// compile-time forcing function) and `ResourceKind`'s.
    pub const ALL: [Self; 15] = [
        Self::Package,
        Self::AptRepo,
        Self::Script,
        Self::Installer,
        Self::User,
        Self::Directory,
        Self::File,
        Self::Link,
        Self::Service,
        Self::Database,
        Self::Swap,
        Self::Firewall,
        Self::Verify,
        Self::Pipeline,
        Self::Build,
    ];

    /// The `snake_case` wire name (matches the `type` discriminant the config eval
    /// emits and what serde (de)serializes).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Package => "package",
            Self::AptRepo => "apt_repo",
            Self::Script => "script",
            Self::Installer => "installer",
            Self::User => "user",
            Self::Directory => "directory",
            Self::File => "file",
            Self::Link => "link",
            Self::Service => "service",
            Self::Database => "database",
            Self::Swap => "swap",
            Self::Firewall => "firewall",
            Self::Verify => "verify",
            Self::Pipeline => "pipeline",
            Self::Build => "build",
        }
    }
}

/// Package managers a target may declare.
///
/// `apt` and `apk` have backend support (`package_managers`); `pacman` / `brew`
/// parse (a config using them is valid) but have no backend, so their resources
/// detect as `Undetermined`. An unknown value hard-fails parse.
///
/// `Ord` is derived so it can key a `package.from` map (`BTreeMap<PackageManager,
/// String>`); the ordering is declaration order and is irrelevant to the content
/// hash, which re-sorts object keys by their string form.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PackageManager {
    Apt,
    Pacman,
    Brew,
    Apk,
}

impl PackageManager {
    /// The wire/string name (the key used in a `package.from` mapping).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Apt => "apt",
            Self::Pacman => "pacman",
            Self::Brew => "brew",
            Self::Apk => "apk",
        }
    }
}

/// Service managers a target may declare.
/// `systemd` and `openrc` have backend support; `launchd` parses but has no backend,
/// so its resources detect as `Undetermined`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ServiceManager {
    Systemd,
    Launchd,
    Openrc,
}

impl ServiceManager {
    /// The wire/string name (used in operator-facing plan notes).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Systemd => "systemd",
            Self::Launchd => "launchd",
            Self::Openrc => "openrc",
        }
    }
}

/// `package` resource — a system package installed via a package manager.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackageResource {
    /// Package-manager → package-name mapping (e.g. `{apt: "curl"}`). Keyed by the
    /// typed [`PackageManager`] enum, so an unknown manager key (`{aptt: …}`) is
    /// rejected at config-eval with a precise `unknown variant` error. Valid keys
    /// (and the serialized JSON) are identical to the prior string-keyed form. A name
    /// takes no reference, and is one word of the manager's command line (see
    /// [`PackageName`]). An apt name `dpkg-query` would never find installed, and an apk
    /// name `apk info -e` would read installed whether or not it is, are refused at
    /// parse (`package_managers::apt_name_problem`, `package_managers::apk_name_problem`).
    #[serde(deserialize_with = "deserialize_package_names")]
    pub from: BTreeMap<PackageManager, PackageName>,
    /// Optional custom check (a path, or a command); defaults to the PM query.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub check: Option<DeclaredPackageCheck>,
}

/// A `package`'s `from` map, with its apt name refused when it is one the apt query
/// would never find installed — so the package could never converge — and its apk name
/// when it is one the apk query would read installed whether or not it is — so the
/// package would never be installed.
fn deserialize_package_names<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<BTreeMap<PackageManager, PackageName>, D::Error> {
    let names = BTreeMap::<PackageManager, PackageName>::deserialize(deserializer)?;
    if let Some(name) = names.get(&PackageManager::Apt)
        && let Some(problem) = crate::package_managers::apt_name_problem(name)
    {
        return Err(de::Error::custom(format!(
            "apt package `{name}` {problem}: `dpkg-query` would never find it installed"
        )));
    }
    if let Some(name) = names.get(&PackageManager::Apk)
        && let Some(problem) = crate::package_managers::apk_name_problem(name)
    {
        return Err(de::Error::custom(format!(
            "apk package `{name}` {problem}: `apk info -e` would read it installed whether \
             or not it is"
        )));
    }
    Ok(names)
}

/// A `package`'s declared `check`: a path that must exist, or a command that must exit 0.
///
/// One value on the wire, read by its first characters: a check that begins `/`, `~`,
/// or `$HOME` is a path, and anything else a command. Only a path takes a reference,
/// which is why they are two variants: a path's references resolve before it is probed
/// and hashed, and a command runs as written. A check that holds a reference and
/// doesn't begin as a path is rejected at parse.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeclaredPackageCheck {
    /// A path checked for existence (may carry a reference / `~`).
    Path(Text),
    /// A command run as written.
    Command(String),
}

/// Why a `package`'s `check` that holds a reference and isn't a path is rejected.
pub(super) const COMMAND_CHECK_REFERENCE: &str = "a command check takes no reference";

/// Whether a `package` check is a path (`/`… / `~`… / `$HOME`…) rather than a command.
fn is_path_like(value: &str) -> bool {
    value.starts_with('/') || value.starts_with('~') || value.starts_with("$HOME")
}

impl DeclaredPackageCheck {
    /// The check as declared, whichever it is.
    #[must_use]
    pub fn as_declared(&self) -> &str {
        match self {
            Self::Path(path) => path.as_inert(),
            Self::Command(command) => command,
        }
    }
}

impl Serialize for DeclaredPackageCheck {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::Path(path) => path.serialize(serializer),
            Self::Command(command) => serializer.serialize_str(command),
        }
    }
}

impl<'de> Deserialize<'de> for DeclaredPackageCheck {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let check = Text::deserialize(deserializer)?;
        // The text ahead of the first reference decides: a path that begins with a
        // reference has no first characters to read, and is no path.
        let leading = match check.pieces().next() {
            Some(Segment::Text(text)) => text,
            Some(Segment::Ref(_)) | None => "",
        };
        if is_path_like(leading) {
            return Ok(Self::Path(check));
        }
        check.as_literal().map_or_else(
            || Err(de::Error::custom(COMMAND_CHECK_REFERENCE)),
            |command| Ok(Self::Command(command.to_owned())),
        )
    }
}

/// File content source — the `content` field of a `file` resource.
///
/// The config eval emits `{type, ...}`; resolving `source` (read a file) and
/// `remote` (fetch the `url` + verify blake3) is apply-time IO and lives in `zap_core`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum FileContent {
    /// Literal content, used verbatim.
    Inline {
        /// The file's content.
        content: String,
    },
    /// A `{{key}}` template with per-variable substitution. Payload in
    /// [`TemplateContent`] so its optional `vars` can't be silently typo-dropped.
    Template(TemplateContent),
    /// Content copied from a file on the target at apply time: the regular file at the
    /// path, its bytes raw, never through a symbolic link at the path; at most the
    /// snapshot limit (`put::SNAPSHOT_MAX_BYTES`).
    Source {
        /// The source path on the target (may carry a reference / `~`).
        path: Text,
    },
    /// Content fetched from a URL, addressed by content hash. Resolution is
    /// **fetch-and-hash** (GET the `url`, compute blake3). A declared `blake3`
    /// *self-pins* (vendored — skips the lock); absent, the lock pins the resolved
    /// hash (tracked). Payload in [`RemoteContent`] so a misspelled optional field
    /// (`blake33` silently flipping vendored→tracked) is rejected at parse.
    Remote(RemoteContent),
}

/// The payload of [`FileContent::Template`] — a `{{key}}` template body plus the
/// per-variable substitutions. A `deny`-bearing struct so a typo'd optional field is
/// rejected rather than dropped.
///
/// A placeholder is `{{name}}`, written with nothing else between the braces — no
/// blanks — where `name` is a variable's name. The body is read once, left to right
/// ([`pieces`](Self::pieces)), and each placeholder replaced by its variable's value; a
/// value is never read for placeholders, so the text `{{name}}` is written into a file
/// by passing it as a variable's value. Braces around anything that is no variable's
/// name (`{{ .Values.port }}`) are text.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TemplateContent {
    /// The template body. Written as declared: it takes no reference.
    pub template: String,
    /// Variable values substituted for `{{key}}` (a string's references resolved).
    #[serde(default)]
    pub vars: BTreeMap<String, TemplateVar>,
    /// The kind of value each named variable must render to ([`TemplateKind`]). Every
    /// key names a variable. A variable not named here declares no kind: a reference in
    /// its value is still held to the [`TemplateKind::Text`] rule as it resolves, and a
    /// value written out is substituted unchecked.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub kinds: BTreeMap<String, TemplateKind>,
}

/// One stretch of a template body, as [`TemplateContent::pieces`] reads it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TemplatePiece<'a> {
    /// Text written as it is.
    Text(&'a str),
    /// `{{name}}`: the name between a `{{` and the first `}}` after it. A placeholder
    /// when `name` is a variable's, and otherwise the text it was written as.
    Braced(&'a str),
}

impl TemplateContent {
    /// The body as text and braced names, in order.
    ///
    /// A braced name runs from the last `{{` before a `}}` to that `}}`, so in `{{{a}}}`
    /// it is `a` with a brace of text on either side.
    #[must_use]
    pub fn pieces(&self) -> Vec<TemplatePiece<'_>> {
        let mut pieces = Vec::new();
        let mut rest = self.template.as_str();
        while let Some(close) = rest.find("}}") {
            let Some(open) = rest[..close].rfind("{{") else {
                let (text, after) = rest.split_at(close + 2);
                pieces.push(TemplatePiece::Text(text));
                rest = after;
                continue;
            };
            if open > 0 {
                pieces.push(TemplatePiece::Text(&rest[..open]));
            }
            pieces.push(TemplatePiece::Braced(&rest[open + 2..close]));
            rest = &rest[close + 2..];
        }
        if !rest.is_empty() {
            pieces.push(TemplatePiece::Text(rest));
        }
        pieces
    }
}

/// One template variable's value.
///
/// A string is substituted as text, and takes a reference. Any other JSON value is
/// substituted as its compact JSON text (`8080`, `true`, `{"a":1}`) and takes none: zap
/// writes that text's quoting, and a value resolved into it would have to be escaped as
/// JSON to stay the string it was. A reference inside one is rejected at parse; the
/// value it would resolve to is passed as a variable of its own.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TemplateVar {
    /// A string value.
    Text(Text),
    /// A number, a boolean, `null`, an array, or an object — never a string, and
    /// holding no reference.
    Json(Value),
}

/// Why a reference inside a non-string template variable is rejected.
pub(super) const NESTED_VAR_REFERENCE: &str =
    "a reference inside a non-string var is not supported; pass it as its own var";

impl TemplateVar {
    /// The text substituted for the variable: the string with each reference replaced
    /// by `resolve(name)`'s value — `resolve` takes the inert text — or the compact
    /// JSON text of any other value.
    #[must_use]
    pub fn render(&self, resolve: impl Fn(&str) -> String) -> String {
        match self {
            Self::Text(text) => resolve(text),
            Self::Json(value) => value.to_string(),
        }
    }
}

impl Serialize for TemplateVar {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::Text(text) => text.serialize(serializer),
            Self::Json(value) => value.serialize(serializer),
        }
    }
}

/// Whether `value` is, or holds at any depth, what only a reference may be: an object
/// with a reference's key, or a string holding a reference delimiter.
fn holds_reference(value: &Value) -> bool {
    match value {
        Value::String(text) => var_ref::holds_delimiter(text),
        Value::Array(items) => items.iter().any(holds_reference),
        Value::Object(map) => {
            map.contains_key(ENV_KEY)
                || map.contains_key(TEXT_KEY)
                || map.keys().any(|key| var_ref::holds_delimiter(key))
                || map.values().any(holds_reference)
        }
        Value::Null | Value::Bool(_) | Value::Number(_) => false,
    }
}

impl<'de> Deserialize<'de> for TemplateVar {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = Value::deserialize(deserializer)?;
        let typed = match &value {
            Value::String(_) => true,
            Value::Object(map) => map.contains_key(ENV_KEY) || map.contains_key(TEXT_KEY),
            _ => false,
        };
        if typed {
            return Text::deserialize(value)
                .map(Self::Text)
                .map_err(de::Error::custom);
        }
        if holds_reference(&value) {
            return Err(de::Error::custom(NESTED_VAR_REFERENCE));
        }
        Ok(Self::Json(value))
    }
}

/// The payload of [`FileContent::Remote`] — a fetch-and-hash content source.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RemoteContent {
    /// Fetch location; **may carry a reference**, resolved when zap fetches, e.g.
    /// `` `${zap.env('ZAP_BASE_URL')}/artifacts/zig.tar.xz` ``. A tracked file's lock
    /// entry is addressed by the resolved url — a secret reference as its
    /// `[MASKED:NAME]` token, never its value.
    pub url: Text,
    /// Vendored content pin (blake3 hex). `Some` self-pins and skips the lock;
    /// `None` defers the pin to the lock (tracked, advanced by `zap update`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub blake3: Option<ContentHash>,
    /// How the fetched bytes are materialized on the target. A tar variant carries
    /// its own `strip_components` (`tar --strip-components=N`, flattening a tarball's
    /// single top dir), so `none` can't carry one. Part of desired state (a non-zero
    /// strip folds into the hash), unlike the credential.
    #[serde(default, skip_serializing_if = "ExtractMode::is_none")]
    pub extract: ExtractMode,
    /// Optional fetch credential for a private byte-host. Operator-machine
    /// authority — resolved at the IO boundary (its token's reference reads operator
    /// env) and **never hashed** into the content address. Absent = an
    /// unauthenticated GET.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth: Option<RemoteAuth>,
}

/// A credential for fetching a `remote` file's bytes from a private host.
///
/// The credential is operator-machine authority, not declared desired state: its
/// token's reference resolves against operator env at fetch time and stays out of both
/// the schema (only the *reference* is stored) and the content address. One scheme
/// exists; another is a further variant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "scheme", rename_all = "snake_case", deny_unknown_fields)]
pub enum RemoteAuth {
    /// `Authorization: Bearer <token>`.
    Bearer {
        /// The bearer token; typically a reference (e.g. `zap.env('ZAP_TOKEN')`)
        /// resolved operator-side, never a literal.
        token: Text,
    },
}

impl RemoteAuth {
    /// The resolved `(header_name, header_value)` to attach to the fetch request, or
    /// `None` when the credential resolves empty (an unset token — the caller turns
    /// that into a clear error rather than sending an empty `Bearer`).
    ///
    /// `resolve` expands the credential's references against operator env. Pure here
    /// (the resolver is injected); the IO crate passes its `resolve_env_vars`.
    #[must_use]
    pub fn to_header(&self, resolve: impl Fn(&str) -> String) -> Option<(String, String)> {
        match self {
            Self::Bearer { token } => {
                let token = resolve(token);
                if token.is_empty() {
                    return None;
                }
                Some(("Authorization".to_owned(), format!("Bearer {token}")))
            }
        }
    }
}

/// How a fetched `remote` file is materialized on the target after fetch.
///
/// Read by hand, through the private `ExtractWire`: only an object is one, a key it
/// doesn't know is refused whichever `type` it sits beside, and so is a
/// `strip_components` beside `type: 'none'` — the derived form can refuse nothing on a
/// variant that has no fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ExtractMode {
    /// Write the fetched bytes verbatim (a file or binary).
    #[default]
    None,
    /// Extract an `.tar.xz` archive into the target path (a target-side `tar -xJf`).
    #[serde(rename = "tar.xz")]
    TarXz {
        /// Leading path components to strip on extraction (`tar --strip-components=N`) —
        /// e.g. `1` flattens a tarball's single top dir. `0` strips nothing.
        #[serde(skip_serializing_if = "u32_is_zero")]
        strip_components: u32,
    },
    /// Extract an `.tar.gz` archive into the target path (a target-side `tar -xzf`) —
    /// the form ghostty ships its source tarball in.
    #[serde(rename = "tar.gz")]
    TarGz {
        /// Leading path components to strip on extraction (`tar --strip-components=N`).
        /// `0` strips nothing.
        #[serde(skip_serializing_if = "u32_is_zero")]
        strip_components: u32,
    },
}

/// The wire form of [`ExtractMode`]: its `type`, and the strip count only a tar
/// archive takes. The `type` is read as a string and matched here: a derived set of
/// names would also be read from an object with the name as its one key.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ExtractWire {
    #[serde(rename = "type")]
    kind: String,
    #[serde(default)]
    strip_components: Option<u32>,
}

impl TryFrom<ExtractWire> for ExtractMode {
    type Error = String;

    fn try_from(wire: ExtractWire) -> Result<Self, Self::Error> {
        let strip_components = wire.strip_components;
        match wire.kind.as_str() {
            "none" if strip_components.is_some() => Err(
                "`strip_components` belongs to a tar archive (`type: 'tar.xz'` or \
                 `'tar.gz'`); `type: 'none'` writes the fetched bytes as they are and \
                 takes no other key"
                    .to_owned(),
            ),
            "none" => Ok(Self::None),
            "tar.xz" => Ok(Self::TarXz {
                strip_components: strip_components.unwrap_or(0),
            }),
            "tar.gz" => Ok(Self::TarGz {
                strip_components: strip_components.unwrap_or(0),
            }),
            other => Err(format!(
                "unknown variant `{other}`, expected one of `none`, `tar.xz`, `tar.gz`"
            )),
        }
    }
}

impl<'de> Deserialize<'de> for ExtractMode {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        /// Reads the object form only: a derived enum would also take an array, by
        /// position, and read `['tar.gz', 1]` as an archive with one component stripped.
        struct ExtractVisitor;

        impl<'de> Visitor<'de> for ExtractVisitor {
            type Value = ExtractMode;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(
                    "`extract` as an object with a `type` of `none`, `tar.xz`, or `tar.gz`",
                )
            }

            fn visit_map<A: MapAccess<'de>>(self, map: A) -> Result<ExtractMode, A::Error> {
                let wire = ExtractWire::deserialize(de::value::MapAccessDeserializer::new(map))?;
                ExtractMode::try_from(wire).map_err(de::Error::custom)
            }
        }

        deserializer.deserialize_any(ExtractVisitor)
    }
}

/// `skip_serializing_if` predicate: omit a zero `strip_components` so a strip-less tar
/// archive serializes without the field (and hashes like one that never had it).
#[allow(clippy::trivially_copy_pass_by_ref)] // serde requires the `&` signature
const fn u32_is_zero(n: &u32) -> bool {
    *n == 0
}

impl ExtractMode {
    /// The stable wire token (`"none"` / `"tar.xz"` / `"tar.gz"`). The content address
    /// hashes *this*, not the struct form, so folding `strip_components` into the tar
    /// variants moved no existing hash (no `RESOURCE_HASH_VERSION` bump).
    #[must_use]
    pub const fn format_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::TarXz { .. } => "tar.xz",
            Self::TarGz { .. } => "tar.gz",
        }
    }

    /// Leading path components to strip on extraction — `0` for [`None`](Self::None) or
    /// a tar archive with no strip set.
    #[must_use]
    pub const fn strip_components(self) -> u32 {
        match self {
            Self::None => 0,
            Self::TarXz { strip_components } | Self::TarGz { strip_components } => strip_components,
        }
    }

    /// Whether this extracts a tar archive (vs writing the bytes verbatim).
    #[must_use]
    pub const fn is_tar(self) -> bool {
        match self {
            Self::None => false,
            Self::TarXz { .. } | Self::TarGz { .. } => true,
        }
    }

    /// Whether this is the default no-extract mode — the `skip_serializing_if` predicate
    /// so an omitted `extract` round-trips omitted (byte-faithful), not materialized as
    /// `{"type":"none"}`. Takes `&self` because serde's `skip_serializing_if` calls it
    /// with a reference.
    #[must_use]
    pub const fn is_none(&self) -> bool {
        matches!(self, Self::None)
    }
}

impl TemplateContent {
    /// Render the template purely (no IO): each placeholder replaced by its variable's
    /// value, `resolve` expanding references in the variable *values*. (`inline`
    /// content is its own text, never resolved; `source` / `remote` resolve by IO, in
    /// `zap_core`.)
    ///
    /// `resolve` must be **env-only** (operator references, the `resolve_env_vars`
    /// category): a `~` / `$HOME` in rendered content is literal *content text*, not a
    /// target path, so it stays unexpanded. Every call site honors this: `zap_core`'s
    /// file detection and `execute_file` render through [`try_render`](Self::try_render)
    /// with its checked env-only resolve (`resolve_template`, which refuses a value that
    /// would add a line), so the bytes compared are the bytes written, and a content
    /// address (`config_hash::file_fields`) passes the env-only resolver it is computed
    /// with, so it stays machine-independent (no operator/target home baked in).
    #[must_use]
    pub fn render(&self, resolve: impl Fn(&str) -> String) -> String {
        self.render_values(|_, var| Ok::<_, std::convert::Infallible>(var.render(&resolve)))
            .unwrap_or_else(|never| match never {})
    }

    /// [`render`](Self::render) with a `resolve` that may refuse a value, and each
    /// variable's rendered value held to its declared [`kinds`](Self::kinds) entry: the
    /// first refusal, of a variable a placeholder names, is the render's — `resolve`'s
    /// own, or `unfit(name, kind, problem)` for a value that isn't its kind. A variable
    /// no placeholder names is never resolved (the structural gate rejects one anyway).
    ///
    /// # Errors
    /// What `resolve` returned for the first variable it refused, or what `unfit` made
    /// of the first value that isn't its kind.
    pub fn try_render<E>(
        &self,
        resolve: impl Fn(&str) -> Result<String, E>,
        unfit: impl Fn(&str, TemplateKind, &'static str) -> E,
    ) -> Result<String, E> {
        self.render_values(|name, var| {
            let value = match var {
                TemplateVar::Text(text) => resolve(text)?,
                TemplateVar::Json(json) => json.to_string(),
            };
            match self.kinds.get(name) {
                Some(&kind) => kind
                    .problem(&value)
                    .map_or(Ok(value), |problem| Err(unfit(name, kind, problem))),
                None => Ok(value),
            }
        })
    }

    /// The body with each placeholder replaced by `value(name, var)` for its variable,
    /// in one pass; braces around anything else stay text.
    fn render_values<E>(
        &self,
        mut value: impl FnMut(&str, &TemplateVar) -> Result<String, E>,
    ) -> Result<String, E> {
        let mut out = String::with_capacity(self.template.len());
        for piece in self.pieces() {
            match piece {
                TemplatePiece::Text(text) => out.push_str(text),
                TemplatePiece::Braced(name) => {
                    if let Some(var) = self.vars.get(name) {
                        out.push_str(&value(name, var)?);
                    } else {
                        out.push_str("{{");
                        out.push_str(name);
                        out.push_str("}}");
                    }
                }
            }
        }
        Ok(out)
    }
}

/// `file` resource — a file with managed content. Detection reads `path` +
/// `content`; `config_hash` additionally reads `mode` / `owner` / `group` /
/// `triggers`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileResource {
    /// Target path (may carry a reference / `~`).
    pub path: Text,
    /// Content source.
    pub content: FileContent,
    /// Desired octal mode, if managed. A non-octal value is rejected at parse (see
    /// [`Mode`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<Mode>,
    /// Desired owner, if managed. A purely-numeric uid is rejected at parse (see
    /// [`AccountName`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner: Option<AccountName>,
    /// Desired group, if managed. A purely-numeric gid is rejected at parse.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group: Option<AccountName>,
    /// Resource ids notified on change (hashed; not read by detection).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub triggers: Option<Vec<super::ResourceId>>,
    /// Command that must exit 0 after a write (e.g. `sudo nginx -t`), or the write is
    /// rolled back — the previous bytes, owner, group, and mode restored, less any set-id
    /// or sticky bit the declared `mode` lacks (or a newly created file removed) — and the
    /// change fails. Runs against the file in place, so it
    /// suits a file some larger config includes, which a standalone check can't parse.
    /// Apply-time behavior, not desired state: not hashed, not read by detection.
    /// Text content only — rejected on a `remote` file (see
    /// [`crate::validate::unsupported_file_validate`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub validate: Option<Text>,
}

/// `directory` resource — a directory with managed permissions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectoryResource {
    /// Directory path (may carry a reference / `~`, resolved at detection time).
    pub path: Text,
    /// Desired octal mode (e.g. `"755"`), if managed. A non-octal value is rejected at
    /// parse (see [`Mode`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<Mode>,
    /// Desired owner, if managed. A purely-numeric uid is rejected at parse (see
    /// [`AccountName`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner: Option<AccountName>,
    /// Desired group, if managed. A purely-numeric gid is rejected at parse.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group: Option<AccountName>,
}

/// `script` resource — an idempotent command (check / run).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScriptResource {
    /// Check command — exit 0 means the script is already applied (skip).
    pub check: Text,
    /// The command the planner emits when the check fails (the `Change.steps`).
    pub run: Text,
    /// Working directory for the check and for `run`: an absolute path, taken verbatim
    /// (no reference, no `~` expansion). A check that can't enter it reads as
    /// not applied; a `run` that can't enter it fails with nothing run.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cwd: Option<String>,
    /// Extra environment, exported to the check and to `run`. A value's
    /// references resolve before it is quoted, so it can hold any text but a NUL and the
    /// reference delimiters U+FDD0 and U+FDD1.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub env: Option<BTreeMap<EnvVarName, Text>>,
}

/// `service` resource — service lifecycle management.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceResource {
    /// Service name (interpreted by the target's service manager). Takes no
    /// reference, and is one word of the manager's command line (see [`ServiceName`]).
    pub service: ServiceName,
    /// Whether the service should be enabled at boot (default `true`).
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Whether the service should be running now; `None` = don't manage runtime.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub running: Option<bool>,
    /// Resource ids whose change triggers a restart of this service if it is running
    /// (pull model; `service_managers::try_restart`). A service with `running: false`
    /// takes none (`validate::triggers_on_stopped_services`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub restart_on: Option<Vec<super::ResourceId>>,
    /// Resource ids whose change triggers a reload of this service if it is running:
    /// `try-reload-or-restart` on systemd, `rc-service --ifstarted <svc> reload` on
    /// `OpenRC` (a service that can't reload fails the step).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reload_on: Option<Vec<super::ResourceId>>,
}

const fn default_true() -> bool {
    true
}

/// `link` resource — a symbolic link.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LinkResource {
    /// Symlink path (may carry a reference / `~`).
    pub path: Text,
    /// The target the symlink should point to (resolved the same way).
    pub target: Text,
}

/// `installer` resource — software installed via a curl-piped script.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstallerResource {
    /// The install script URL piped into `shell` (the `Change.steps`).
    pub url: Text,
    /// Path checked for existence to confirm installation (may carry `~`).
    pub check: Text,
    /// Shell the install script is piped into (default `sh`).
    #[serde(default = "default_shell")]
    pub shell: Text,
}

fn default_shell() -> Text {
    Text::literal("sh")
}

/// SSH key configuration for a `user` resource: copy another user's
/// `authorized_keys`, or supply explicit keys. Untagged — distinguished by which
/// field is present.
///
/// Read by hand: only an object is one, and it goes through the private `SshKeysWire`,
/// so declaring both, neither, or a key that is neither is an error that says so,
/// never one form with the other dropped.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(untagged)]
pub enum SshKeys {
    /// Copy `authorized_keys` from another user (e.g. `root`).
    CopyFrom {
        /// The user whose `authorized_keys` is copied. An [`AccountName`] (rejects a
        /// numeric uid; `single_quote`d into the [`passwd_field`](super::passwd_field) home
        /// read the probe and mutation share).
        copy_from: AccountName,
    },
    /// Explicit SSH public keys.
    Keys {
        /// The public-key lines written to `authorized_keys`. Every entry must be
        /// non-blank, and an empty list is rejected by the structural gate. A key takes no
        /// reference: it is a `String`.
        keys: Vec<String>,
    },
}

/// The wire form of [`SshKeys`]: its two keys, of which exactly one is declared.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SshKeysWire {
    #[serde(default)]
    copy_from: Option<AccountName>,
    #[serde(default)]
    keys: Option<Vec<String>>,
}

impl TryFrom<SshKeysWire> for SshKeys {
    type Error = &'static str;

    fn try_from(wire: SshKeysWire) -> Result<Self, Self::Error> {
        match (wire.copy_from, wire.keys) {
            (Some(copy_from), None) => Ok(Self::CopyFrom { copy_from }),
            (None, Some(keys)) => Ok(Self::Keys { keys }),
            (Some(_), Some(_)) => Err("`ssh_keys` takes `copy_from` or `keys`, not both"),
            (None, None) => Err("`ssh_keys` takes `copy_from` or `keys`"),
        }
    }
}

impl<'de> Deserialize<'de> for SshKeys {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        /// Reads the object form only: a derived struct would also take an array, by
        /// position, and read `['root']` as a copy from `root`.
        struct KeysVisitor;

        impl<'de> Visitor<'de> for KeysVisitor {
            type Value = SshKeys;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("an object with `copy_from` or `keys`")
            }

            fn visit_map<A: MapAccess<'de>>(self, map: A) -> Result<SshKeys, A::Error> {
                let wire = SshKeysWire::deserialize(de::value::MapAccessDeserializer::new(map))?;
                SshKeys::try_from(wire).map_err(de::Error::custom)
            }
        }

        deserializer.deserialize_any(KeysVisitor)
    }
}

/// Sudo access mode for a `user` resource (when sudo is granted).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SudoMode {
    /// Passwordless sudo (`NOPASSWD:`).
    Nopasswd,
    /// Password-required sudo.
    Password,
}

impl SudoMode {
    /// The wire name (`nopasswd` / `password`).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Nopasswd => "nopasswd",
            Self::Password => "password",
        }
    }
}

/// A `user` resource's `sudo` field: grant access (optionally command-restricted), or
/// `false` to remove it.
///
/// Untagged — the literal `false` parses to [`Disabled`](Self::Disabled), a bare mode
/// string to [`Mode`](Self::Mode), and a `{mode, commands}` object to
/// [`Restricted`](Self::Restricted).
/// The command list lives **inside** the granting `Restricted`
/// variant, so "restrict commands without granting sudo" is unrepresentable.
///
/// Hand-written serde: the wire forms are `false`, a mode string, and the `{mode,
/// commands}` object. `true` is **rejected** — a derived `bool` arm would accept it as
/// [`Disabled`](Self::Disabled) and silently *remove* the user's sudoers file, the
/// opposite of what the author meant (the builder's TypeScript types never admit
/// `true`; an untyped config could).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UserSudo {
    /// `false` — remove the user's sudoers file.
    Disabled,
    /// A bare mode string (`"nopasswd"` / `"password"`) — grant with no command
    /// restriction (the common case; restrict via [`Restricted`](Self::Restricted)).
    Mode(SudoMode),
    /// `{mode, commands}` — grant restricted to specific raw sudoers command specs.
    Restricted {
        /// The grant mode.
        mode: SudoMode,
        /// The sudoers command specs the grant is limited to: at least one. A spec
        /// takes no reference: it is a `String`.
        commands: SudoCommands,
    },
}

/// The command specs of a restricted sudo grant: at least one, none blank, none holding
/// a control character.
///
/// A list with no command in it restricts nothing, and what a sudoers line with no
/// command means is not a narrower grant — so the empty list is no value of this type,
/// and the unrestricted grant is spelled as what it is ([`UserSudo::Mode`]). A spec is
/// one entry of one sudoers line: a line break in it would begin a second line, and
/// every other control character — a tab included — is refused with it, so a spec's
/// words are separated by spaces.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct SudoCommands(Vec<String>);

/// Why a list of command specs is no [`SudoCommands`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InvalidSudoCommands {
    /// The list holds no spec.
    Empty,
    /// The spec at this index is empty or all whitespace.
    Blank(usize),
    /// The spec at this index holds a control character (a line break or a tab among
    /// them).
    Control(usize),
}

impl SudoCommands {
    /// The specs as a restricted grant's command list.
    ///
    /// # Errors
    ///
    /// [`InvalidSudoCommands`] for an empty list, or a spec that is blank or holds a
    /// control character.
    pub fn new(specs: Vec<String>) -> Result<Self, InvalidSudoCommands> {
        if specs.is_empty() {
            return Err(InvalidSudoCommands::Empty);
        }
        for (index, spec) in specs.iter().enumerate() {
            if spec.trim().is_empty() {
                return Err(InvalidSudoCommands::Blank(index));
            }
            if spec.chars().any(char::is_control) {
                return Err(InvalidSudoCommands::Control(index));
            }
        }
        Ok(Self(specs))
    }

    /// The specs, in the order declared.
    #[must_use]
    pub fn specs(&self) -> &[String] {
        &self.0
    }
}

impl InvalidSudoCommands {
    /// The finding for a `{mode, commands}` grant of `mode` whose list is refused:
    /// the field, what is wrong with it, and what to write.
    fn finding(self, mode: SudoMode) -> String {
        match self {
            Self::Empty => format!(
                "`sudo.commands` is empty: a grant limited to no command grants nothing, \
                 and zap does not read an empty list as every command; for a grant of \
                 every command write the mode alone (`sudo: '{}'`), or list the commands \
                 the grant covers",
                mode.as_str()
            ),
            Self::Blank(index) => format!(
                "`sudo.commands[{index}]` is blank; a command spec is a command's full \
                 path, with any arguments the grant is limited to"
            ),
            Self::Control(index) => format!(
                "`sudo.commands[{index}]` holds a control character (a tab and a line \
                 break are each one); a command spec is one stretch of one line of the \
                 sudoers file — separate its words with spaces"
            ),
        }
    }
}

/// The shape `UserSudo` serializes through: the three wire forms.
#[derive(Serialize)]
#[serde(untagged)]
enum UserSudoWire<'a> {
    Bool(bool),
    Mode(SudoMode),
    Restricted {
        mode: SudoMode,
        commands: &'a SudoCommands,
    },
}

/// The `{mode, commands}` wire form of a restricted grant.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RestrictedSudoWire {
    mode: SudoMode,
    commands: Vec<String>,
}

impl Serialize for UserSudo {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let wire = match self {
            Self::Disabled => UserSudoWire::Bool(false),
            Self::Mode(mode) => UserSudoWire::Mode(*mode),
            Self::Restricted { mode, commands } => UserSudoWire::Restricted {
                mode: *mode,
                commands,
            },
        };
        wire.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for UserSudo {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        /// Reads each wire form by its JSON type, so a value of the right type that is
        /// wrong — an unknown mode, a command that is no string — is named in the error.
        struct SudoVisitor;

        impl<'de> Visitor<'de> for SudoVisitor {
            type Value = UserSudo;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("`false`, a sudo mode, or `{mode, commands}`")
            }

            fn visit_bool<E: de::Error>(self, grant: bool) -> Result<UserSudo, E> {
                if grant {
                    return Err(E::custom(
                        "`sudo: true` grants nothing — grant with 'nopasswd', 'password', or \
                         {mode, commands}; `false` removes the user's sudoers file",
                    ));
                }
                Ok(UserSudo::Disabled)
            }

            fn visit_str<E: de::Error>(self, mode: &str) -> Result<UserSudo, E> {
                SudoMode::deserialize(de::value::StrDeserializer::new(mode)).map(UserSudo::Mode)
            }

            fn visit_map<A: MapAccess<'de>>(self, map: A) -> Result<UserSudo, A::Error> {
                let RestrictedSudoWire { mode, commands } =
                    RestrictedSudoWire::deserialize(de::value::MapAccessDeserializer::new(map))?;
                let commands = SudoCommands::new(commands)
                    .map_err(|invalid| de::Error::custom(invalid.finding(mode)))?;
                Ok(UserSudo::Restricted { mode, commands })
            }
        }

        deserializer.deserialize_any(SudoVisitor)
    }
}

/// What a sudo grant covers: every command, or the listed ones.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SudoScope<'a> {
    /// Every command — the bare-mode grant ([`UserSudo::Mode`]).
    All,
    /// The listed command specs ([`UserSudo::Restricted`]).
    Commands(&'a SudoCommands),
}

impl SudoScope<'_> {
    /// The scope as a sudoers line spells it: `ALL`, or the specs separated by `, `.
    #[must_use]
    pub fn sudoers_spec(self) -> String {
        match self {
            Self::All => "ALL".to_owned(),
            Self::Commands(commands) => commands.specs().join(", "),
        }
    }
}

impl UserSudo {
    /// The granted `(mode, scope)` when sudo is granted; `None` when
    /// [`Disabled`](Self::Disabled). The one accessor the detector, step builder, and
    /// `--diff` join read, so they treat the two granting shapes identically.
    #[must_use]
    pub const fn grant(&self) -> Option<(SudoMode, SudoScope<'_>)> {
        match self {
            Self::Mode(mode) => Some((*mode, SudoScope::All)),
            Self::Restricted { mode, commands } => Some((*mode, SudoScope::Commands(commands))),
            Self::Disabled => None,
        }
    }
}

/// `user` resource — a Unix user (shell, home mode, SSH keys, sudoers). Replaces
/// multi-line `script` user-creation patterns with a declared, idempotent resource.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserResource {
    /// Unix username to create/manage (compares against `id -u`, the name — see
    /// [`AccountName`]).
    pub username: AccountName,
    /// Login shell (e.g. `/bin/bash`); system default when absent. Takes no
    /// reference: it is a `String`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shell: Option<String>,
    /// Home-directory mode (e.g. `711`), if managed. A non-octal value is rejected at
    /// parse (see [`Mode`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub home_mode: Option<Mode>,
    /// SSH key configuration, if managed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ssh_keys: Option<SshKeys>,
    /// Sudo access: a grant (optionally command-restricted via the `{mode, commands}`
    /// form), or `false` to remove. Absent = unmanaged. Command restriction lives inside
    /// [`UserSudo::Restricted`], not a sibling field.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sudo: Option<UserSudo>,
    /// Supplementary groups the user must belong to (additive — `usermod -aG`; groups
    /// not listed are left untouched, so the primary and system groups are never
    /// stripped). Each is an [`AccountName`]. Empty = unmanaged.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub groups: Vec<AccountName>,
}

/// `swap` resource — a swap file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SwapResource {
    /// Swap size (e.g. `2G`); the planner needs it to emit `fallocate`. Required —
    /// a sizeless swap can't generate a `fallocate`, so it's rejected at config-eval.
    pub size: Text,
    /// Swap file path (default `/swapfile`). Used verbatim — no `~` expansion, and
    /// no reference: it is a `String`.
    #[serde(default = "default_swapfile")]
    pub path: String,
}

fn default_swapfile() -> String {
    "/swapfile".to_owned()
}

/// The transport protocol of a firewall port rule (the closed ufw set).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Protocol {
    /// TCP only.
    Tcp,
    /// UDP only.
    Udp,
    /// Either protocol (ufw omits the `/proto` suffix).
    Any,
}

impl Protocol {
    /// The wire/ufw name (`tcp` / `udp` / `any`).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
            Self::Any => "any",
        }
    }
}

/// A firewall allow rule: a named profile, or a port/proto pair.
///
/// Untagged on the wire — a string is a profile, an object a port rule. Read by hand,
/// by the value's JSON type, so a port rule that is wrong (an unknown protocol, a port
/// that is no number) is named in the error.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(untagged)]
pub enum FirewallAllowRule {
    /// A named ufw application profile (e.g. `OpenSSH`). Takes no reference: it is a
    /// `String`.
    Named(String),
    /// A port + protocol pair.
    PortProto {
        /// The port number: 1–65535 (port 0 names no port a rule can open).
        port: NonZeroU16,
        /// The protocol (default `tcp`).
        #[serde(default = "default_proto")]
        proto: Protocol,
    },
}

/// The `{port, proto}` wire form of a port rule.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PortProtoWire {
    port: NonZeroU16,
    #[serde(default = "default_proto")]
    proto: Protocol,
}

impl<'de> Deserialize<'de> for FirewallAllowRule {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct RuleVisitor;

        impl<'de> Visitor<'de> for RuleVisitor {
            type Value = FirewallAllowRule;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a profile name or a `{port, proto}` rule")
            }

            fn visit_str<E: de::Error>(self, name: &str) -> Result<FirewallAllowRule, E> {
                Ok(FirewallAllowRule::Named(name.to_owned()))
            }

            fn visit_map<A: MapAccess<'de>>(self, map: A) -> Result<FirewallAllowRule, A::Error> {
                let PortProtoWire { port, proto } =
                    PortProtoWire::deserialize(de::value::MapAccessDeserializer::new(map))?;
                Ok(FirewallAllowRule::PortProto { port, proto })
            }
        }

        deserializer.deserialize_any(RuleVisitor)
    }
}

const fn default_proto() -> Protocol {
    Protocol::Tcp
}

impl FirewallAllowRule {
    /// The ufw rule's target identity — the `ufw status` "To" column token, and the
    /// `ufw allow` argument: a bare `<port>` for an any-proto rule, `<port>/<proto>`
    /// for a typed one, or the profile name. One definition shared by the detector
    /// (the `missing_rules` needle + the whole-token presence match) and the step
    /// builder (the `ufw allow` target), so the probe and the mutation can't render
    /// the same rule differently.
    #[must_use]
    pub fn ufw_target(&self) -> String {
        match self {
            Self::Named(name) => name.clone(),
            Self::PortProto { port, proto } => match proto {
                Protocol::Any => port.to_string(),
                other => format!("{port}/{}", other.as_str()),
            },
        }
    }

    /// The nftables `inet filter` input-chain rule that accepts this allow rule's port
    /// (e.g. `tcp dport 22 accept`). `None` for a `Named` profile — nftables has no
    /// application-profile concept (a ufw-only feature), so a named rule has no nft
    /// form; the structural gate rejects `Named` under the nftables backend, and both
    /// the step builder and detector skip it defensively. The nftables counterpart of
    /// [`ufw_target`](Self::ufw_target): one definition shared by the step builder (the
    /// generated ruleset line) and the detector (the presence needle), so probe and
    /// mutation can't render a rule differently.
    #[must_use]
    pub fn nft_rule(&self) -> Option<String> {
        match self {
            Self::Named(_) => None,
            Self::PortProto { port, proto } => Some(match proto {
                Protocol::Tcp => format!("tcp dport {port} accept"),
                Protocol::Udp => format!("udp dport {port} accept"),
                // Any proto: match the transport-header dport across both tcp and udp.
                Protocol::Any => format!("meta l4proto {{ tcp, udp }} th dport {port} accept"),
            }),
        }
    }
}

/// The firewall backend — a typed closed set.
///
/// An enum, not a `String`: an unknown backend is rejected at config-eval (a precise
/// `unknown variant` error) rather than parsed and carried to a late detector guard.
/// The step builder and detector each `match` on it, so every backend handles every
/// variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FirewallBackend {
    /// Uncomplicated Firewall (Debian/Ubuntu) — app profiles + port rules.
    Ufw,
    /// nftables — the Alpine-idiomatic native backend: a declarative `inet filter`
    /// ruleset loaded with `nft -f`. Port/proto rules only (no application profiles).
    Nftables,
}

/// A ufw default-policy verdict (`ufw default <policy> {incoming,outgoing}`).
///
/// An enum, not a `String`: a typo in a *security* control (`"denyy"`, `"Deny"`) fails
/// at config-eval instead of reaching `ufw` — or, worse, silently setting an
/// unintended policy. The closed set is ufw's own (`allow` / `deny` / `reject`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FirewallPolicy {
    /// Permit the traffic.
    Allow,
    /// Drop the traffic silently.
    Deny,
    /// Drop the traffic with an ICMP rejection.
    Reject,
}

impl FirewallPolicy {
    /// The ufw policy name (`allow` / `deny` / `reject`).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Deny => "deny",
            Self::Reject => "reject",
        }
    }

    /// The nftables base-chain `policy` verb — `accept` for `allow`, `drop` for `deny`
    /// and `reject`. nftables' base-chain policy is binary (accept/drop); `reject`'s
    /// active ICMP rejection is an explicit trailing chain rule, not a policy, which the
    /// step builder appends.
    #[must_use]
    pub const fn nft_chain_policy(self) -> &'static str {
        match self {
            Self::Allow => "accept",
            Self::Deny | Self::Reject => "drop",
        }
    }

    /// The **effective** nftables policy this variant converges to — `accept` / `drop` /
    /// `reject`. The whole declared state, unlike [`nft_chain_policy`](Self::nft_chain_policy),
    /// which is only the base-chain verb.
    ///
    /// The distinction is load-bearing for detection: `deny` and `reject` share the
    /// `drop` policy line and differ only by the trailing bare `reject` rule, so a
    /// comparison run in the binary policy space cannot tell them apart and reports a
    /// silently-weakened firewall as converged. The detector parses the same three-valued
    /// space (`parse_nft_effective_policy`) and compares against this.
    #[must_use]
    pub const fn nft_effective_policy(self) -> &'static str {
        match self {
            Self::Allow => "accept",
            Self::Deny => "drop",
            Self::Reject => "reject",
        }
    }
}

/// `firewall` resource — host firewall configuration (ufw or nftables).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FirewallResource {
    /// Firewall backend (`ufw` or `nftables`).
    pub backend: FirewallBackend,
    /// Default policy for incoming traffic (default `deny`).
    #[serde(default = "default_deny")]
    pub default_incoming: FirewallPolicy,
    /// Default policy for outgoing traffic (default `allow`).
    #[serde(default = "default_allow")]
    pub default_outgoing: FirewallPolicy,
    /// Allow rules (named profiles or port/proto pairs).
    pub allow: Vec<FirewallAllowRule>,
}

const fn default_deny() -> FirewallPolicy {
    FirewallPolicy::Deny
}

const fn default_allow() -> FirewallPolicy {
    FirewallPolicy::Allow
}

/// The required type of a `path_exists` verify assertion's target.
///
/// An enum, not a `String`: a typo (`"fil"`) in a safety gate fails at config-eval
/// rather than quietly making the assertion test the wrong thing (`test -e` instead of
/// `test -f`). The set is the filesystem's, not user-extensible.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FileType {
    /// A regular file (`test -f`).
    File,
    /// A directory (`test -d`).
    Directory,
}

impl FileType {
    /// The token used in the assertion description (`file` / `directory`).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::File => "file",
            Self::Directory => "directory",
        }
    }
}

/// A verify assertion — a path-existence check or a command check.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum VerifyAssertion {
    /// Assert a path exists (optionally a specific type / mode / owner / non-empty).
    /// Payload in [`PathExistsAssertion`] so a misspelled optional gate (`ownr`,
    /// `not_emty`) — which would silently weaken the assertion — is rejected at parse.
    PathExists(PathExistsAssertion),
    /// Assert a command exits 0 (optionally with `expect` in its stdout). Payload in
    /// [`CommandAssertion`] so a typo'd `expect` can't silently drop the stdout check.
    Command(CommandAssertion),
}

/// The payload of [`VerifyAssertion::PathExists`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PathExistsAssertion {
    /// The path to check.
    pub path: String,
    /// Required type ([`File`](FileType::File) / [`Directory`](FileType::Directory));
    /// `None` accepts either.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file_type: Option<FileType>,
    /// Required octal mode. A non-octal value is rejected at parse (see [`Mode`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<Mode>,
    /// Required owner. A purely-numeric uid is rejected at parse (the assertion
    /// compares against `stat -c %U`, the name — see [`AccountName`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner: Option<AccountName>,
    /// Whether the path's size must be above zero (`test -s`). A directory's size depends
    /// on its filesystem, so this doesn't reliably check that a directory has entries.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub not_empty: bool,
}

/// The payload of [`VerifyAssertion::Command`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommandAssertion {
    /// The command to run.
    pub run: String,
    /// A substring that must appear in stdout.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expect: Option<String>,
}

/// `verify` resource — assertions checked at detection and again on a wetrun.
///
/// On a wetrun they are checked again at the verify's place in dependency order; one
/// still failing there fails the run: changes ordered before it have run, the rest are
/// skipped.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerifyResource {
    /// Assertions to check (all must pass for the resource to be met).
    pub assertions: Vec<VerifyAssertion>,
}

/// A `PostgreSQL` `pg_hba.conf` auth method — the closed set `PostgreSQL` documents.
///
/// An enum, not a `String`: zap writes this verbatim into a *security-sensitive*
/// `pg_hba.conf` line, so a misspelling (`"scram-sha256"`, `"tust"`) must fail at
/// config-eval, not land in the file and fail a late postgres reload (or, worse,
/// silently weaken auth). Every rule zap writes is a plain TCP `host` line with no
/// options, so the documented method set is modeled but for the methods that can't work
/// on one: `trust`, which on such a line lets any account on the machine (any service,
/// nginx included) connect as the role with no credential; `peer`, which `PostgreSQL`
/// accepts only on a `local` line; `cert`, only on a `hostssl` line; `ldap` and
/// `radius`, which need options (`ldapbasedn`, `radiusservers`, …) zap doesn't write;
/// and `sspi` and `bsd`, which `PostgreSQL` doesn't build on Linux. A `peer`, `cert`,
/// `ldap`, or `radius` line keeps `pg_hba.conf` from loading. A local service reaches
/// its database over the Unix socket instead, where the stock `local … peer` rule
/// admits the OS account named like the role. A new `PostgreSQL` method is a one-line
/// variant add.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PgAuthMethod {
    /// Unconditionally reject.
    Reject,
    /// SCRAM-SHA-256 challenge-response (the modern password method).
    #[serde(rename = "scram-sha-256")]
    ScramSha256,
    /// MD5-hashed password (legacy).
    Md5,
    /// Cleartext password.
    Password,
    /// GSSAPI.
    Gss,
    /// Ident server.
    Ident,
    /// PAM.
    Pam,
}

impl PgAuthMethod {
    /// The `pg_hba.conf` method token (`scram-sha-256` / `md5` / …).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Reject => "reject",
            Self::ScramSha256 => "scram-sha-256",
            Self::Md5 => "md5",
            Self::Password => "password",
            Self::Gss => "gss",
            Self::Ident => "ident",
            Self::Pam => "pam",
        }
    }
}

/// `PostgreSQL` auth config for a `database` resource's `pg_hba.conf` rules: one `host`
/// line per entry of `hosts`, each with `method`.
///
/// A `database` without one declares no rule, so the role is reached the way the stock
/// `pg_hba.conf` allows: over the Unix socket by the OS account of the same name
/// (`peer`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DatabaseAuth {
    /// Auth method (default `scram-sha-256`).
    #[serde(default = "default_auth_method")]
    pub method: PgAuthMethod,
    /// Allowed client addresses, each an address with its prefix length in CIDR
    /// notation (`127.0.0.1/32`). At least one, which validation holds a config to.
    #[serde(default)]
    pub hosts: Vec<Text>,
}

const fn default_auth_method() -> PgAuthMethod {
    PgAuthMethod::ScramSha256
}

/// The database engine — a typed closed set (only `postgresql`).
///
/// An enum, not a `String`: an unknown engine is rejected at config-eval, not carried
/// to a late detector guard. A second engine adds a variant the detector must handle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DatabaseEngine {
    /// `PostgreSQL`.
    Postgresql,
}

/// `database` resource (`PostgreSQL` only).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DatabaseResource {
    /// Database engine (only `postgresql`).
    pub engine: DatabaseEngine,
    /// Database name to create. Taken literally (never shell-expanded); a
    /// reference resolves on the operator's machine (the shared seam).
    pub database_name: Text,
    /// Role/user to create and own the database. Taken literally (never
    /// shell-expanded); `zap.env('USER')` declares "the operator's OS user".
    pub username: Text,
    /// `pg_hba.conf` auth config. Absent, no rule is written; present, it names at
    /// least one host (validation refuses an empty `hosts`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth: Option<DatabaseAuth>,
}

impl DatabaseResource {
    /// The hosts a `pg_hba` rule is written for: none when `auth` is absent.
    #[must_use]
    pub fn auth_hosts(&self) -> &[Text] {
        self.auth.as_ref().map_or(&[], |auth| auth.hosts.as_slice())
    }

    /// The method of the rules [`Self::auth_hosts`] are written with.
    #[must_use]
    pub fn auth_method(&self) -> PgAuthMethod {
        self.auth
            .as_ref()
            .map_or_else(default_auth_method, |auth| auth.method)
    }
}

/// `apt_repo` resource. `key_path` / `list_file` default from the resource id when
/// absent (the detector fills them).
///
/// The signing key is content zap fetches and pins, like a `remote` file's: fetched on
/// the operator's machine, checked against its blake3 pin, and installed whole. A
/// declared `key_blake3` self-pins it (vendored); absent, the lock pins it (tracked,
/// advanced by `zap update`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AptRepoResource {
    /// URL the GPG signing key is fetched from, by zap on the operator's machine; **may
    /// carry a reference**, resolved when zap fetches. A tracked key's lock entry is
    /// addressed by the resolved url.
    pub key_url: Text,
    /// Vendored key pin (blake3 hex). `Some` self-pins and skips the lock; `None` defers
    /// the pin to the lock (tracked).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_blake3: Option<ContentHash>,
    /// Where the GPG key is stored; default `/usr/share/keyrings/{id}.asc`. Takes no
    /// reference: it is a `String`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_path: Option<String>,
    /// The deb source line (`signed-by` is auto-injected from `key_path`). Takes no
    /// reference: it is a `String`.
    pub source: String,
    /// The `.list` file path; default `/etc/apt/sources.list.d/{id}.list`. Takes no
    /// reference: it is a `String`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub list_file: Option<String>,
}

/// One step in a `pipeline` resource.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PipelineStep {
    /// Identifier for this step, unique within the pipeline: a repeated one is refused
    /// by the structural gate
    /// ([`duplicate_pipeline_step_ids`](crate::validate::duplicate_pipeline_step_ids)).
    pub id: String,
    /// Human-readable name for the step, printed under its `id` in a plan; the plan's
    /// step is its `run` command.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// The command this step runs.
    pub run: Text,
    /// Working directory for this step.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cwd: Option<String>,
    /// Environment variables for this step.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub env: Option<BTreeMap<EnvVarName, String>>,
    /// Step ids this depends on (within the pipeline).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub depends_on: Option<Vec<String>>,
}

/// `pipeline` resource — imperative multi-step execution. Detection counts steps;
/// the planner emits one preview command per step.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PipelineResource {
    /// Environment variables shared across all steps.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub env: Option<BTreeMap<EnvVarName, String>>,
    /// The pipeline steps.
    pub steps: Vec<PipelineStep>,
    /// Max steps to run concurrently: at least one. Steps run sequentially, and a
    /// value above one is rejected at validation
    /// ([`unsupported_pipeline_features`](crate::validate::unsupported_pipeline_features)).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_concurrency: Option<NonZeroU32>,
}

/// `build` resource — fetch a verified source, build it, and install to `output`.
///
/// The **source pin** (blake3) is what the build is made from: (for a *tracked*
/// source) the lock pins it, and the executor records a digest of it and of how the
/// source is built (`extract`, `run`, `cwd`, `env`) in a sidecar (`<output>.zap-build`,
/// [`build_provenance`](crate::config_hash::build_provenance)). Detection compares the
/// recorded digest to the *desired* one — so bumping the declared source version, or
/// editing the build, rebuilds instead of reading a stale artifact as converged (the
/// silent-never-drift trap a bare `test -f output` would fall into).
/// Source fetch + verification reuses the `zap.file remote` resolver; the build
/// toolchain (zig, GTK deps, …) is the operator's to converge via sibling
/// `package` / `installer` resources and `depends_on` — not this resource's job.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BuildResource {
    /// Where the source comes from + how its integrity is verified.
    pub source: BuildSource,
    /// The build command (e.g. `zig build -p $HOME/.local -Doptimize=ReleaseFast`).
    pub run: Text,
    /// Path that exists iff the build is installed — the detection probe. Its
    /// sidecar (`<output>.zap-build`) records the provenance that produced it.
    pub output: Text,
    /// Working directory for `run`: absolute, or relative to the extracted source dir,
    /// which is the default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cwd: Option<String>,
    /// Build environment. Keys are POSIX names ([`EnvVarName`]); a name beginning with
    /// `__zap_` is rejected by the structural gate (zap's own wrapper variables). A
    /// value's references resolve before it is quoted, so it can hold any text but a NUL
    /// and the reference delimiters U+FDD0 and U+FDD1.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub env: Option<BTreeMap<EnvVarName, Text>>,
}

/// The source a `build` fetches + verifies.
///
/// One flavor exists, the **remote tarball** (version-pinned upstream, blake3-pinned,
/// optional minisign — zig/ghostty). A git-checkout flavor (commit-pinned) would be a
/// further variant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum BuildSource {
    /// A fetched source archive — the resolver fetches, verifies, and
    /// content-addresses it (the same path `zap.file remote` uses). Payload in
    /// [`RemoteSource`] so a misspelled optional field (a dropped `verify` /`auth`
    /// silently disabling signature-check / credential, or a `blake33` flip) is
    /// rejected at parse.
    Remote(RemoteSource),
}

/// The payload of [`BuildSource::Remote`] — a fetch-and-verify build source.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RemoteSource {
    /// Fetch location; **may carry a reference**, resolved when zap fetches. A tracked
    /// source's lock entry is addressed by the resolved url — a secret reference
    /// as its `[MASKED:NAME]` token, never its value. For a versioned upstream this is
    /// the version-substituted URL.
    pub url: Text,
    /// How the fetched source is unpacked before `run`. A tar variant carries its
    /// own `strip_components`, so `none` can't carry one.
    #[serde(default, skip_serializing_if = "ExtractMode::is_none")]
    pub extract: ExtractMode,
    /// Optional fetch credential for a private byte-host — operator-machine
    /// authority, resolved at the IO boundary and **never hashed**.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth: Option<RemoteAuth>,
    /// Optional upstream-signature verification, run when a fetch fills the content
    /// cache, before the bytes are pinned or built; a cache hit is re-hashed against
    /// the pin instead.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verify: Option<SourceVerify>,
    /// Vendored source pin (blake3 hex). `Some` self-pins and skips the lock;
    /// `None` defers the pin to the lock (tracked, advanced by `zap update`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub blake3: Option<ContentHash>,
}

/// Upstream-signature verification for a build source.
///
/// minisign against a pinned public key, verified by **shelling out to
/// `minisign`** at the IO boundary (zap adds no crypto dependency — it surfaces the
/// upstream's own trust mechanism).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "scheme", rename_all = "snake_case")]
pub enum SourceVerify {
    /// `minisign -V` against `public_key`; signature from `signature_url` or, by
    /// default, the source URL with `.minisig` appended to its path. Payload in [`MinisignVerify`]
    /// so a typo'd `signature_url` is rejected rather than silently using the default.
    Minisign(MinisignVerify),
}

/// The payload of [`SourceVerify::Minisign`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MinisignVerify {
    /// The pinned minisign public key (the `RW…` string), its form checked at parse.
    pub public_key: MinisignKey,
    /// Explicit signature URL; defaults to the source URL with `.minisig` appended to
    /// its path (before any query).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature_url: Option<Text>,
}

/// The `deploy()` release-management block — what `zap deploy` packages and ships.
///
/// Release-pushing is local→SSH: build locally, tarball the `artifacts`, scp to the
/// target's `path`, extract into `releases/<version>`, atomically swap the `current`
/// symlink, restart `service`, and prune to `releases` retained releases. Modeled
/// (not opaque-captured) since deploy consumes it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeploySpec {
    /// Build command run **locally** before packaging (e.g. `gro build`). Skipped
    /// when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub build: Option<String>,
    /// Files/directories (relative to the operator cwd) to package into the release
    /// tarball.
    pub artifacts: Vec<String>,
    /// Remote application root — holds `releases/`, `shared/`, and the `current`
    /// symlink.
    pub path: String,
    /// Number of releases to retain on the target (older ones are pruned).
    #[serde(default = "default_releases")]
    pub releases: u32,
    /// Service to restart after the symlink swap. Requires `target.service_manager`.
    /// Takes no reference, and is one word of the manager's command line (see
    /// [`ServiceName`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service: Option<ServiceName>,
    /// Files under the remote `shared/` directory to symlink into each release root
    /// (e.g. `.env.production` — an apply-managed shared file linked into the
    /// immutable release).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub shared: Vec<String>,
    /// Post-extract commands run **on the target, in the new release directory**
    /// before the symlink swap (e.g. warming dependencies), each in a shell of its own
    /// (`sh -ec`), so an `exit` ends that command, not the deploy. The release is still
    /// under its hidden staging name then, so a command shouldn't record its absolute
    /// path.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub prepare: Vec<String>,
    /// Optional post-restart HTTP health check.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub health: Option<DeployHealth>,
}

/// Default release retention (`deploy.releases`) — the documented schema default.
const fn default_releases() -> u32 {
    5
}

/// Post-restart HTTP health check for a deploy.
///
/// `domain` lives **inside** this struct rather than beside it on [`DeploySpec`]:
/// the host is meaningful only when a check is declared, so nesting it makes
/// "declared a health gate with nothing to poll" unrepresentable instead of a state
/// some validator has to catch. It is an ordinary declared field like any other —
/// typically `zap.env('DEPLOY_DOMAIN')`, resolved at the IO boundary — so the engine
/// reads no environment variable of its own, and an unset reference is caught by the
/// same preflight as every other unresolved ref.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeployHealth {
    /// Host polled over HTTPS (e.g. `app.example.com`, or a `DEPLOY_DOMAIN`
    /// reference resolved at execution).
    pub domain: Text,
    /// Request path polled over HTTPS against `domain` (e.g. `/health`).
    pub path: String,
    /// How many times to poll before failing the deploy: at least once (a gate that
    /// never polls fails every deploy).
    #[serde(default = "default_health_attempts")]
    pub attempts: NonZeroU32,
    /// Delay between poll attempts, in milliseconds.
    #[serde(default = "default_health_interval_ms")]
    pub interval_ms: u64,
}

/// Default health-check attempt count — the documented schema default.
const fn default_health_attempts() -> NonZeroU32 {
    const ATTEMPTS: NonZeroU32 = NonZeroU32::new(15).unwrap();
    ATTEMPTS
}

/// Default delay between health-check attempts — the documented schema default.
const fn default_health_interval_ms() -> u64 {
    2000
}
