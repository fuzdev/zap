//! Format-constrained scalar newtypes.
//!
//! Values with a closed *format* (not a closed *set*), validated at the config-eval
//! boundary so a malformed value fails at `zap plan` with a precise message instead of
//! late at apply or never.
//!
//! This is the set-valued schema rule (`#[serde(rename_all)]` enums reject an unknown
//! *variant*) applied one level down, to scalars that would otherwise be a
//! bare `String`. An [`AccountName`] can't be a numeric uid that never converges; a
//! [`Mode`] can't be a non-octal string that silently compares wrong.
//!
//! Each is a **transparent** newtype: it (de)serializes as its inner string — so the
//! wire shape the config-eval sidecar emits and the content hash are a plain
//! string's — and it derefs to `str`, so read sites use it as one (`.as_str()`,
//! `.as_deref()`, `format!`, `==` against a `&str`). The *parse* validates and the
//! *type* carries the name.
//!
//! Scope is **declared config only.** Observed machine state (the `stat`-derived
//! owner/mode on [`crate::detected::CurrentState`]) stays `String`: those are facts
//! read back from a target, not operator-authored values, so validating them at
//! deserialize would risk rejecting a state the engine itself observed.
//! The boundary these guard is the config the operator writes, not the world the
//! engine observes.

use std::fmt;
use std::ops::Deref;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use thiserror::Error;

/// A malformed scalar, surfaced at config-eval as a precise `unknown … ` style error.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ScalarError {
    /// An owner/group given as a purely-numeric uid/gid (see [`AccountName`]).
    #[error(
        "numeric owner/group `{0}` is not supported: zap compares ownership against \
         the name from `stat -c %U/%G`, so a numeric uid/gid would never converge (a \
         re-chown every apply). Declare the user/group name instead."
    )]
    NumericAccountName(String),
    /// An account name outside the portable Unix charset (see [`AccountName`]).
    #[error(
        "account name `{0}` is not a valid Unix user/group name: expected a lowercase \
         letter or `_` followed by lowercase letters, digits, `_` or `-` (optionally \
         ending in `$`), e.g. `deploy`, `www-data`, `_apt`"
    )]
    InvalidAccountName(String),
    /// An empty account name.
    #[error("owner/group must not be empty")]
    EmptyAccountName,
    /// A file mode that isn't a non-empty run of octal digits (see [`Mode`]).
    #[error(
        "file mode `{0}` is not octal: a mode is 1–5 octal digits (e.g. `755`, `0644`, `4755`)"
    )]
    NotOctalMode(String),
    /// A file mode above `7777` (see [`Mode`]).
    #[error(
        "file mode `{0}` is more than a mode holds: the permission bits and the set-id and \
         sticky bits are four octal digits, `7777` at most (e.g. `755`, `0644`, `4755`)"
    )]
    ModeOutOfRange(String),
    /// A package name outside what a package manager's command line takes as one name
    /// (see [`PackageName`]).
    #[error(
        "package name `{0}` is not a name zap can pass to a package manager: expected a \
         letter or digit followed by letters, digits, or any of `+ . _ : = ~ / @ -`, not \
         ending in `-` (e.g. `curl`, `g++`, `libssl-dev`, `nginx=1.24.0-1`, `postgresql-16`)"
    )]
    InvalidPackageName(String),
    /// A service name outside what a service manager's command line takes as one name
    /// (see [`ServiceName`]).
    #[error(
        "service name `{0}` is not a name zap can pass to a service manager: expected a \
         letter or digit followed by letters, digits, or any of `_ . @ : -` (e.g. `nginx`, \
         `postgresql@16-main`, `app.service`)"
    )]
    InvalidServiceName(String),
    /// A content pin that isn't a blake3 digest (see [`ContentHash`]).
    #[error(
        "content hash `{0}` is not a blake3 digest: expected exactly 64 lowercase hex characters"
    )]
    NotContentHash(String),
    /// A minisign public key that isn't one in minisign's own form (see
    /// [`MinisignKey`]).
    #[error(
        "minisign public key `{0}` is not one: expected the 56 base64 characters of a \
         minisign public key, beginning `RW` (the key line of a `.pub` file, without its \
         comment)"
    )]
    NotMinisignKey(String),
    /// An environment-variable name that isn't a portable shell identifier (see
    /// [`EnvVarName`]).
    #[error(
        "environment variable name `{0}` is not a valid identifier: expected a leading \
         letter or `_` followed by letters, digits, or `_` (e.g. `NODE_ENV`, `ZIG_CACHE`)"
    )]
    InvalidEnvVarName(String),
}

/// A Unix account (user or group) **name** — never a numeric uid/gid.
///
/// zap compares ownership against the *name* `stat -c %U/%G` reports, so a numeric
/// value (`owner: "1000"`) would mismatch the observed name forever — a re-chown every
/// apply that never converges. Rejecting it here (at config-eval) turns that silent
/// never-converge into a precise boundary error. A name that merely *contains* digits
/// (`user1`) is fine; only a purely-numeric value is rejected.
///
/// The charset is the portable one — `[a-z_][a-z0-9_-]*` with an optional trailing
/// `$`, the `useradd` default on Debian and Alpine — because the name reaches shell
/// positions where a stray character breaks out of the form: the `awk -v` argument in
/// `passwd_field`, the comma-joined `usermod -aG` list, a sudoers drop-in's content,
/// and the `/home/<name>` / `sudoers.d/<name>` path segments. A backslash, comma, `/`,
/// space, or newline is unrepresentable rather than a late shell surprise. Uppercase
/// is rejected too (fail closed; loosen only if a real host's account needs it).
///
/// The invariant lives in the type, so a new owner/group field can't be declared
/// without it.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AccountName(String);

impl AccountName {
    /// Parse and validate an account name. Rejects an empty or purely-numeric value,
    /// and anything outside the portable Unix charset.
    ///
    /// # Errors
    /// [`ScalarError::EmptyAccountName`] / [`ScalarError::NumericAccountName`] /
    /// [`ScalarError::InvalidAccountName`].
    pub fn new(name: impl Into<String>) -> Result<Self, ScalarError> {
        let name = name.into();
        if name.is_empty() {
            return Err(ScalarError::EmptyAccountName);
        }
        if name.bytes().all(|b| b.is_ascii_digit()) {
            return Err(ScalarError::NumericAccountName(name));
        }
        if !is_portable_account_name(&name) {
            return Err(ScalarError::InvalidAccountName(name));
        }
        Ok(Self(name))
    }

    /// The underlying name as a string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// The portable account-name charset: `[a-z_][a-z0-9_-]*` with an optional trailing
/// `$` (the Samba machine-account convention `useradd` accepts).
fn is_portable_account_name(name: &str) -> bool {
    let body = name.strip_suffix('$').unwrap_or(name);
    let mut chars = body.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    (first.is_ascii_lowercase() || first == '_')
        && chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-')
}

/// An octal file mode (`755`, `0644`, `4755`) — 1–5 octal digits, `7777` at most,
/// validated at parse.
///
/// A non-octal value (`75x`, `999`) is rejected at config-eval rather than carried to a
/// `chmod` that fails late or a comparison that quietly never matches, and so is a
/// value with a bit above the set-id and sticky bits (`17777`, `77777`), which `chmod`
/// refuses and no `stat` reports. A fifth digit is a leading zero (`01777`). The stored form
/// is the operator's verbatim string (so the content hash and fidelity round-trip are
/// unchanged); leading-zero normalization for *comparison* stays in
/// [`crate::schema::normalize_mode`], which reads through this type's `Deref<str>`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Mode(String);

impl Mode {
    /// Parse and validate an octal mode. Rejects an empty value, a non-octal digit,
    /// more than five digits, or a value above `7777`.
    ///
    /// # Errors
    /// [`ScalarError::NotOctalMode`] / [`ScalarError::ModeOutOfRange`].
    pub fn new(mode: impl Into<String>) -> Result<Self, ScalarError> {
        let mode = mode.into();
        let octal =
            !mode.is_empty() && mode.len() <= 5 && mode.bytes().all(|b| (b'0'..=b'7').contains(&b));
        if !octal {
            return Err(ScalarError::NotOctalMode(mode));
        }
        if mode.len() == 5 && !mode.starts_with('0') {
            return Err(ScalarError::ModeOutOfRange(mode));
        }
        Ok(Self(mode))
    }

    /// The mode as a string slice (the verbatim declared form, not normalized).
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// A mode zap names itself — a planner's own constant, octal by construction.
    pub(crate) fn fixed(mode: &'static str) -> Self {
        debug_assert!(Self::new(mode).is_ok(), "not an octal mode: {mode}");
        Self(mode.to_owned())
    }
}

/// A blake3 content pin — exactly 64 lowercase hex characters, validated at parse.
///
/// The content-trust primitive: it gates content trust (`zap.file remote` / `build`
/// vendoring), keys the content cache, and is folded between config and lock. As a
/// bare `String` it was the one load-bearing value the schema trusted unvalidated —
/// `deny_unknown_fields` catches a misspelled *field* (`blake33:`) but never a
/// malformed *value* (a truncated paste, an uppercase digest, a sha256). This type
/// rejects all of those at config-eval, the same boundary [`Mode`] guards a file mode.
///
/// Two constructors by provenance: [`new`](Self::new) validates an operator-authored
/// pin (the config-eval boundary); [`of_bytes`](Self::of_bytes) hashes bytes the engine
/// just read (a producer that is correct by construction, so it's infallible).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ContentHash(String);

impl ContentHash {
    /// Parse and validate an operator-authored content pin.
    ///
    /// # Errors
    /// [`ScalarError::NotContentHash`] if it isn't exactly 64 lowercase hex characters.
    pub fn new(hex: impl Into<String>) -> Result<Self, ScalarError> {
        let hex = hex.into();
        let valid = hex.len() == 64
            && hex
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
        if valid {
            Ok(Self(hex))
        } else {
            Err(ScalarError::NotContentHash(hex))
        }
    }

    /// Hash bytes into a content pin. Infallible — `blake3` emits 64 lowercase hex by
    /// construction, so this is the engine-side producer (a fetched body, a cached
    /// file) that needs no re-validation.
    #[must_use]
    pub fn of_bytes(bytes: &[u8]) -> Self {
        Self(blake3::hash(bytes).to_hex().to_string())
    }

    /// Wrap an already-finalized blake3 hash — the streaming producer's counterpart to
    /// [`of_bytes`](Self::of_bytes) (also infallible), for an engine that hashed a body
    /// incrementally rather than from one slice.
    #[must_use]
    pub fn of_hash(hash: blake3::Hash) -> Self {
        Self(hash.to_hex().to_string())
    }

    /// The pin as a string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A minisign public key in minisign's own text form, validated at parse.
///
/// The base64 of an Ed25519 key's algorithm tag (`Ed`), its 8-byte key id, and its 32
/// bytes: 56 standard base64 characters with no padding, beginning `RW`.
///
/// It is passed to `minisign -P` as one argument, so the shape also keeps it from being
/// read as an option. The shape says nothing of whose key it is: that is the
/// operator's to check against the upstream.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MinisignKey(String);

impl MinisignKey {
    /// Parse and validate a minisign public key.
    ///
    /// # Errors
    /// [`ScalarError::NotMinisignKey`] if it isn't 56 base64 characters beginning `RW`.
    pub fn new(key: impl Into<String>) -> Result<Self, ScalarError> {
        let key = key.into();
        let valid = key.len() == 56
            && key.starts_with("RW")
            && key
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'/');
        if valid {
            Ok(Self(key))
        } else {
            Err(ScalarError::NotMinisignKey(key))
        }
    }

    /// The key as a string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A portable environment-variable **name** — a leading letter or `_`, then letters,
/// digits, or `_` (POSIX `name`), validated at parse.
///
/// It keys the `env` maps on `script` (the check probe), `build` (the build command),
/// and `pipeline` steps. An `env` map is interpolated into a shell command — locally as
/// a real `Command::env` (safe), but over SSH as a `KEY=value` prefix the connection
/// string-builds, where the *key* is not shell-quoted (the value is). A name with shell
/// metacharacters (`FOO; rm -rf /`) would therefore behave differently local-vs-remote
/// and, on the remote, break out of the assignment. Constraining the name to an
/// identifier at config-eval makes that divergence unrepresentable — the
/// make-impossible-states rule applied to the one map key that reaches a raw shell
/// position. Real env names are already identifiers, so this is zero-churn for correct
/// configs.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EnvVarName(String);

/// Whether `name` is an environment variable's name: `[A-Za-z_][A-Za-z0-9_]*`.
///
/// The rule [`EnvVarName`] holds a name to, and the one a reference's name is read by
/// ([`var_ref::segments`](crate::var_ref::segments)).
#[must_use]
pub fn is_env_var_name(name: &str) -> bool {
    let mut bytes = name.bytes();
    bytes.next().is_some_and(|first| {
        (first.is_ascii_alphabetic() || first == b'_')
            && bytes.all(|b| b.is_ascii_alphanumeric() || b == b'_')
    })
}

impl EnvVarName {
    /// Parse and validate an environment-variable name (POSIX `name`: `[A-Za-z_][A-Za-z0-9_]*`).
    ///
    /// # Errors
    /// [`ScalarError::InvalidEnvVarName`] for an empty name, a leading digit, or any
    /// character outside `[A-Za-z0-9_]`.
    pub fn new(name: impl Into<String>) -> Result<Self, ScalarError> {
        let name = name.into();
        if is_env_var_name(&name) {
            Ok(Self(name))
        } else {
            Err(ScalarError::InvalidEnvVarName(name))
        }
    }

    /// The name as a string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A package's name as a package manager's command line takes it — one word, and
/// nothing a shell reads.
///
/// zap writes a name into `apt-get install` / `apk add` and into the query that
/// detection runs (`dpkg-query`, `apk info -e`) outside any quoting, so the name is the
/// one thing between a config and a shell: `'nginx; reboot'` would run at `zap plan`.
/// The charset is what the two managers' own syntax for one package uses — a leading
/// letter or digit, then letters, digits and `+ . _ -` (the name), `=` and `~` and `:`
/// (apt's `name=version`, an epoch, `name:arch`; apk's `name=version`), `/` (apt's
/// `name/suite`) and `@` (apk's `name@repository`). Everything else is out: whitespace
/// (a second word is a second package, or an option), a leading `-` (an option), a
/// trailing `-` (which `apt-get install` reads as *remove* the package), and every
/// character a shell acts on — `;` `&` `|` `<` `>` `(` `)` `$` a backtick `\` `'` `"`
/// `*` `?` `[` `]` `{` `}` `!` `#` — which also rules out apk's `name>=version`
/// constraints, since the `>` is a redirection where the name is written.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PackageName(String);

impl PackageName {
    /// Parse and validate a package name.
    ///
    /// # Errors
    /// [`ScalarError::InvalidPackageName`].
    pub fn new(name: impl Into<String>) -> Result<Self, ScalarError> {
        let name = name.into();
        let valid = begins_alphanumeric(&name)
            && !name.ends_with('-')
            && name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"+._:=~/@-".contains(&b));
        if valid {
            Ok(Self(name))
        } else {
            Err(ScalarError::InvalidPackageName(name))
        }
    }

    /// The name as a string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A service's name as a service manager's command line takes it — one word, and
/// nothing a shell reads.
///
/// zap writes a name into `systemctl` / `rc-service` / `rc-update` commands, into the
/// probes detection runs (`systemctl is-active`, `rc-service <name> status`), and into
/// a path (`/etc/runlevels/<runlevel>/<name>`), all outside any quoting. The charset is a
/// systemd unit name's — letters, digits, `_ . @ : -` — less the backslash of an escaped
/// unit name, which a shell would consume, and with a leading letter or digit, so a name
/// is never an option (`--now`) nor a path's `.` or `..`. An `OpenRC` service is a file
/// name under `/etc/init.d`, so `/` is out for it too.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ServiceName(String);

impl ServiceName {
    /// Parse and validate a service name.
    ///
    /// # Errors
    /// [`ScalarError::InvalidServiceName`].
    pub fn new(name: impl Into<String>) -> Result<Self, ScalarError> {
        let name = name.into();
        let valid = begins_alphanumeric(&name)
            && name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_.@:-".contains(&b));
        if valid {
            Ok(Self(name))
        } else {
            Err(ScalarError::InvalidServiceName(name))
        }
    }

    /// The name as a string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Whether `name` begins with an ASCII letter or digit (so it is not empty).
fn begins_alphanumeric(name: &str) -> bool {
    name.bytes()
        .next()
        .is_some_and(|first| first.is_ascii_alphanumeric())
}

// --- transparent (de)serialization + str ergonomics, shared shape per newtype ---

macro_rules! transparent_string_newtype {
    ($ty:ty) => {
        impl Deref for $ty {
            type Target = str;
            fn deref(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Display for $ty {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }

        impl Serialize for $ty {
            fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                serializer.serialize_str(&self.0)
            }
        }

        impl<'de> Deserialize<'de> for $ty {
            fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                let raw = String::deserialize(deserializer)?;
                Self::new(raw).map_err(serde::de::Error::custom)
            }
        }
    };
}

transparent_string_newtype!(AccountName);
transparent_string_newtype!(Mode);
transparent_string_newtype!(ContentHash);
transparent_string_newtype!(MinisignKey);
transparent_string_newtype!(EnvVarName);
transparent_string_newtype!(PackageName);
transparent_string_newtype!(ServiceName);

#[cfg(test)]
mod tests {
    use super::{
        AccountName, ContentHash, EnvVarName, MinisignKey, Mode, PackageName, ServiceName,
    };

    /// A minisign public key is minisign's own form, and nothing else: a key with its
    /// comment line, a truncated or padded one, another scheme's key, and an option all
    /// fail at parse.
    #[test]
    fn a_minisign_key_is_minisigns_own_form() {
        let key = "RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3";
        assert_eq!(MinisignKey::new(key).unwrap().as_str(), key);
        for bad in [
            "",
            "RW",
            &key[..55],
            &format!("{key}A"),
            &format!("{}=", &key[..55]),
            &format!("untrusted comment: minisign public key\n{key}"),
            &format!("-{}", &key[1..]),
            &format!("AA{}", &key[2..]),
            &format!("{}-_", &key[..54]),
        ] {
            assert!(MinisignKey::new(bad).is_err(), "{bad:?}");
        }
    }

    /// A package name is one word of a package manager's command line: the managers'
    /// own forms for one package parse, and nothing a shell or the manager would read
    /// as anything else does.
    #[test]
    fn a_package_name_is_one_word_no_shell_reads() {
        for ok in [
            "curl",
            "g++",
            "libssl-dev",
            "postgresql-16",
            "nginx=1.24.0-1~bookworm",
            "nginx=1:1.24.0-1",
            "libc6:amd64",
            "nginx/bookworm-backports",
            "nginx@edge",
            "python3.11",
            "7zip",
            "R",
            "a",
        ] {
            assert_eq!(PackageName::new(ok).unwrap().as_str(), ok);
        }
        for bad in [
            "",
            " ",
            "curl jq",
            "curl; rm -rf /",
            "nginx;reboot",
            "--now",
            "-y",
            "nginx-",
            ".hidden",
            "a$(id)",
            "a`id`",
            "a|b",
            "a&b",
            "a>b",
            "a<b",
            "a>=1.0",
            "a*",
            "a?",
            "a[b]",
            "a{b}",
            "a'b",
            "a\"b",
            "a\\b",
            "a\nb",
            "a\tb",
            "a#b",
            "a!b",
            "a(b)",
            "~root",
            "pâté",
        ] {
            assert!(PackageName::new(bad).is_err(), "{bad:?} should be rejected");
        }
        assert_eq!(
            serde_json::to_string(&PackageName::new("g++").unwrap()).unwrap(),
            "\"g++\""
        );
        let error = serde_json::from_str::<PackageName>("\"curl; reboot\"").unwrap_err();
        assert!(
            error.to_string().starts_with(
                "package name `curl; reboot` is not a name zap can pass to a package manager"
            ),
            "{error}"
        );
    }

    /// A service name is one word of a service manager's command line and one component
    /// of a path.
    #[test]
    fn a_service_name_is_one_word_no_shell_reads() {
        for ok in [
            "nginx",
            "postgresql@16-main",
            "app.service",
            "getty@tty1.service",
            "dev-disk-by:x.mount",
            "fuz_forge",
            "3proxy",
        ] {
            assert_eq!(ServiceName::new(ok).unwrap().as_str(), ok);
        }
        for bad in [
            "",
            " ",
            "nginx; reboot",
            "nginx reboot",
            "--now",
            "-nginx",
            ".",
            "..",
            ".hidden",
            "@a",
            "a/b",
            "a\\x2db",
            "a$b",
            "a`b`",
            "a|b",
            "a&b",
            "a*",
            "a'b",
            "a\nb",
            "a=b",
            "a+b",
            "sérvice",
        ] {
            assert!(ServiceName::new(bad).is_err(), "{bad:?} should be rejected");
        }
        let error = serde_json::from_str::<ServiceName>("\"api; reboot\"").unwrap_err();
        assert!(
            error.to_string().starts_with(
                "service name `api; reboot` is not a name zap can pass to a service manager"
            ),
            "{error}"
        );
    }

    #[test]
    fn env_var_name_requires_a_shell_identifier() {
        for ok in ["NODE_ENV", "_x", "ZIG_GLOBAL_CACHE_DIR", "A1", "x"] {
            assert!(EnvVarName::new(ok).is_ok(), "{ok} should parse");
        }
        for bad in ["", "1ABC", "A B", "FOO=bar", "FOO;rm", "A-B", "PA$$", "x.y"] {
            assert!(EnvVarName::new(bad).is_err(), "{bad} should be rejected");
        }
        // round-trips as a bare string (transparent) and validates at deserialize, so it
        // works as a JSON object key.
        let name: EnvVarName = serde_json::from_str("\"NODE_ENV\"").unwrap();
        assert_eq!(name.as_str(), "NODE_ENV");
        assert!(serde_json::from_str::<EnvVarName>("\"FOO;rm\"").is_err());
        let map: std::collections::BTreeMap<EnvVarName, String> =
            serde_json::from_str("{\"NODE_ENV\":\"test\"}").unwrap();
        assert!(map.contains_key(&EnvVarName::new("NODE_ENV").unwrap()));
    }

    #[test]
    fn account_name_rejects_numeric_and_empty() {
        assert!(AccountName::new("1000").is_err());
        assert!(AccountName::new("0").is_err());
        assert!(AccountName::new("").is_err());
        // Names with digits, or all-letter names, are fine.
        assert_eq!(AccountName::new("deploy").unwrap().as_str(), "deploy");
        assert!(AccountName::new("user1").is_ok());
    }

    #[test]
    fn account_name_requires_the_portable_charset() {
        for ok in [
            "deploy",
            "www-data",
            "_apt",
            "root",
            "user1",
            "fuz_forge",
            "host$",
        ] {
            assert!(AccountName::new(ok).is_ok(), "{ok} should parse");
        }
        // Each of these reaches an unquoted shell position somewhere (awk -v, the
        // `usermod -aG` comma join, a sudoers line, a `/home/<name>` path segment).
        for bad in [
            "Deploy", "a\\b", "a,b", "a/b", "a b", "a\nb", "-x", "1abc", "$", "a$b", "dépl",
        ] {
            assert!(AccountName::new(bad).is_err(), "{bad:?} should be rejected");
        }
    }

    #[test]
    fn mode_accepts_octal_rejects_the_rest() {
        for ok in ["0", "755", "0644", "4755", "01777"] {
            assert!(Mode::new(ok).is_ok(), "{ok} should parse");
        }
        for ok in ["7777", "07777", "00000", "0000"] {
            assert!(Mode::new(ok).is_ok(), "{ok} should parse");
        }
        for bad in ["", "75x", "999", "888", "0o755", "1234567", "007777"] {
            assert_eq!(
                Mode::new(bad),
                Err(super::ScalarError::NotOctalMode(bad.to_owned())),
                "{bad}"
            );
        }
        // A fifth digit that isn't a leading zero is a bit no mode has.
        for bad in ["10000", "17777", "77777", "10644"] {
            assert_eq!(
                Mode::new(bad),
                Err(super::ScalarError::ModeOutOfRange(bad.to_owned())),
                "{bad}"
            );
        }
    }

    #[test]
    fn content_hash_requires_64_lowercase_hex() {
        // `of_bytes` always produces a valid pin (64 lowercase hex).
        let pin = ContentHash::of_bytes(b"zap");
        assert_eq!(pin.as_str().len(), 64);
        assert!(ContentHash::new(pin.as_str().to_owned()).is_ok());
        // The realistic malformations all fail at the boundary.
        assert!(ContentHash::new("aa").is_err(), "too short");
        assert!(ContentHash::new("g".repeat(64)).is_err(), "non-hex");
        assert!(
            ContentHash::new(pin.as_str().to_uppercase()).is_err(),
            "uppercase"
        );
        assert!(ContentHash::new("").is_err(), "empty");
        // A sha256-length-but-blake3-shaped value still passes (same length/charset);
        // the type guards format, not provenance.
        assert!(ContentHash::new("a".repeat(64)).is_ok());
    }

    #[test]
    fn round_trips_through_json_as_a_bare_string() {
        // Transparent: a `Mode` serializes/deserializes as the verbatim string, so the
        // wire shape and content hash are unchanged by the newtype.
        let mode: Mode = serde_json::from_str("\"0755\"").unwrap();
        assert_eq!(mode.as_str(), "0755");
        assert_eq!(serde_json::to_string(&mode).unwrap(), "\"0755\"");
        // A non-octal value fails at deserialize (the config-eval boundary).
        assert!(serde_json::from_str::<Mode>("\"75x\"").is_err());
        // A numeric owner fails the same way.
        assert!(serde_json::from_str::<AccountName>("\"1000\"").is_err());
    }
}
