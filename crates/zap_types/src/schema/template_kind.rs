//! The kinds of value a `template` variable may be declared to hold
//! ([`TemplateKind`]), and the rule each holds its rendered value to.
//!
//! A template's text lands in a file whose grammar zap doesn't know: an nginx site, an
//! `EnvironmentFile`, a sudoers drop-in. A reference's value is refused a line break, a
//! NUL, or a reference delimiter (the `text` rule), which keeps it to the one line it
//! stands in, and every kind keeps that rule.
//! Within that line, what may appear is the file's grammar: `;`, `{` or `}` in an nginx
//! `server_name {{domain}}` would end the directive or the block. A kind says what the
//! value is — a host name, a port, a path, an address — and the value is then held to
//! that form, whose alphabet carries no character a config grammar reads as structure.
//!
//! The rule runs on the whole rendered value of a variable, references resolved:
//! detection holds the file on a refusal, the wetrun preflight and the executor refuse
//! its write, and a value written without a reference is checked when the config is
//! read. A variable that declares no kind is held to nothing more than its references'
//! `text` rule: a value it writes out is substituted unchecked.

use serde::{Deserialize, Serialize};

/// The kind of value a `template` variable renders to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TemplateKind {
    /// Any one line: no line break, NUL, or reference delimiter. Every kind keeps this
    /// rule, and a reference's value is held to it whether or not its variable declares
    /// a kind.
    Text,
    /// A DNS host name (RFC 1123): dot-separated labels of ASCII letters, digits, and
    /// `-`, each 1 to 63 bytes, neither starting nor ending with `-`, at most 253 bytes
    /// in all. No trailing dot: the same name is spliced into URLs and certificate paths,
    /// where `example.com.` names another thing than `example.com`. No wildcard, no `_`.
    Hostname,
    /// A TCP or UDP port: a decimal number from 1 to 65535, with no sign and no leading
    /// zero.
    Port,
    /// An absolute path: `/` and then `/`-separated names of ASCII letters, digits, `.`,
    /// `_`, `-`, `+`, and `@`, with no empty name (`//`) and no `.` or `..` name. A
    /// trailing `/` is allowed.
    Path,
    /// An email address: a local part of ASCII letters, digits, `.`, `_`, `%`, `+`, and
    /// `-` (1 to 64 bytes, no leading, trailing, or doubled `.`), an `@`, and a
    /// [`Hostname`](Self::Hostname); at most 254 bytes in all.
    Email,
    /// A value written inside single quotes in an env file (`KEY='{{value}}'`):
    /// [`Text`](Self::Text) with no `'`, which would end the quoting — systemd's
    /// `EnvironmentFile=` would read a different value, and `OpenRC`'s reader would refuse
    /// the line.
    EnvValue,
}

/// The rule [`TemplateKind::Hostname`] holds a value to, as the rest of a sentence.
const NOT_HOSTNAME: &str = "is not a host name: dot-separated labels of ASCII letters, \
     digits, and `-` (each 1 to 63 bytes, no leading or trailing `-`), at most 253 bytes, \
     with no trailing dot";
/// The rule [`TemplateKind::Port`] holds a value to.
const NOT_PORT: &str = "is not a port: a decimal number from 1 to 65535, with no sign or \
     leading zero";
/// The rule [`TemplateKind::Path`] holds a value to.
const NOT_PATH: &str = "is not an absolute path of ASCII letters, digits, `.`, `_`, `-`, \
     `+`, and `@`, with no empty, `.`, or `..` component";
/// The rule [`TemplateKind::Email`] holds a value to.
const NOT_EMAIL: &str = "is not an email address: a local part of ASCII letters, digits, \
     `.`, `_`, `%`, `+`, and `-` (no leading, trailing, or doubled `.`), an `@`, and a host \
     name";
/// The rule [`TemplateKind::EnvValue`] holds a value to.
const NOT_ENV_VALUE: &str = "holds a `'`, a line break (CR or LF), a NUL, or a reference \
     delimiter: inside an env file's single quotes it would end the value";
/// The rule [`TemplateKind::Text`] holds a value to (the one the others also keep).
const NOT_TEXT: &str = "holds a line break (CR or LF), a NUL, or a reference delimiter: it \
     would add a line to the file";

impl TemplateKind {
    /// The kind's name as a config writes it.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Text => "text",
            Self::Hostname => "hostname",
            Self::Port => "port",
            Self::Path => "path",
            Self::Email => "email",
            Self::EnvValue => "env_value",
        }
    }

    /// What is wrong with `value` as this kind, as the rest of a sentence about it
    /// ("… resolves to a value that {problem}") — or `None` when it is one.
    #[must_use]
    pub fn problem(self, value: &str) -> Option<&'static str> {
        let fits = match self {
            Self::Text => {
                !value.contains(['\n', '\r', '\0']) && !crate::var_ref::holds_delimiter(value)
            }
            Self::Hostname => is_hostname(value),
            Self::Port => is_port(value),
            Self::Path => is_path(value),
            Self::Email => is_email(value),
            Self::EnvValue => Self::Text.problem(value).is_none() && !value.contains('\''),
        };
        (!fits).then_some(match self {
            Self::Text => NOT_TEXT,
            Self::Hostname => NOT_HOSTNAME,
            Self::Port => NOT_PORT,
            Self::Path => NOT_PATH,
            Self::Email => NOT_EMAIL,
            Self::EnvValue => NOT_ENV_VALUE,
        })
    }
}

/// [`TemplateKind::Hostname`]'s rule.
fn is_hostname(value: &str) -> bool {
    value.len() <= 253
        && value.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
                && !label.starts_with('-')
                && !label.ends_with('-')
        })
}

/// [`TemplateKind::Port`]'s rule.
fn is_port(value: &str) -> bool {
    !value.starts_with('0')
        && value.bytes().all(|b| b.is_ascii_digit())
        && value.parse::<u16>().is_ok_and(|port| port > 0)
}

/// [`TemplateKind::Path`]'s rule.
fn is_path(value: &str) -> bool {
    let Some(rest) = value.strip_prefix('/') else {
        return false;
    };
    // `/` alone, and a trailing `/`, leave one empty name at the end
    let rest = rest.strip_suffix('/').unwrap_or(rest);
    rest.is_empty()
        || rest.split('/').all(|name| {
            !name.is_empty()
                && name != "."
                && name != ".."
                && name.bytes().all(|b| {
                    b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b'+' | b'@')
                })
        })
}

/// [`TemplateKind::Email`]'s rule.
fn is_email(value: &str) -> bool {
    let Some((local, domain)) = value.rsplit_once('@') else {
        return false;
    };
    value.len() <= 254
        && (1..=64).contains(&local.len())
        && local
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'%' | b'+' | b'-'))
        && !local.starts_with('.')
        && !local.ends_with('.')
        && !local.contains("..")
        && is_hostname(domain)
}

#[cfg(test)]
mod tests {
    use super::TemplateKind;

    fn fits(kind: TemplateKind, value: &str) -> bool {
        kind.problem(value).is_none()
    }

    #[test]
    fn a_hostname_is_rfc_1123_labels_with_no_trailing_dot() {
        for good in [
            "example.com",
            "www.example.com",
            "localhost",
            "a-b.c0",
            "192.168.1.1",
            "XN--BCHER-KVA.example",
            &format!("{}.com", "a".repeat(63)),
        ] {
            assert!(fits(TemplateKind::Hostname, good), "{good}");
        }
        for bad in [
            "",
            "example.com.",
            ".example.com",
            "a..b",
            "-a.com",
            "a-.com",
            "a_b.com",
            "*.example.com",
            "example.com;",
            "example.com { }",
            "exa mple.com",
            "example.com\n",
            &format!("{}.com", "a".repeat(64)),
            &["a"; 128].join("."),
        ] {
            assert!(!fits(TemplateKind::Hostname, bad), "{bad:?}");
        }
    }

    #[test]
    fn a_port_is_1_to_65535_in_plain_decimal() {
        for good in ["1", "80", "4040", "65535"] {
            assert!(fits(TemplateKind::Port, good), "{good}");
        }
        for bad in [
            "",
            "0",
            "65536",
            "080",
            "+80",
            "-1",
            "80;",
            " 80",
            "8o",
            "99999999999",
        ] {
            assert!(!fits(TemplateKind::Port, bad), "{bad:?}");
        }
    }

    #[test]
    fn a_path_is_absolute_with_plain_names() {
        for good in [
            "/",
            "/srv/app",
            "/srv/app/",
            "/opt/x-1.2_3+b@c",
            "/a/.hidden",
        ] {
            assert!(fits(TemplateKind::Path, good), "{good}");
        }
        for bad in [
            "",
            "srv/app",
            "~/app",
            "/srv//app",
            "/srv/../etc",
            "/srv/./app",
            "/srv/app;",
            "/srv/{app}",
            "/srv/a b",
            "/srv/$HOME",
            "/srv/'x'",
        ] {
            assert!(!fits(TemplateKind::Path, bad), "{bad:?}");
        }
    }

    #[test]
    fn an_email_is_a_plain_local_part_at_a_hostname() {
        for good in ["ops@example.com", "a.b+tag@mail.example.org", "x_y%z-1@h"] {
            assert!(fits(TemplateKind::Email, good), "{good}");
        }
        for bad in [
            "",
            "example.com",
            "@example.com",
            "ops@",
            ".ops@example.com",
            "ops.@example.com",
            "o..ps@example.com",
            "o'ps@example.com",
            "ops@example.com;",
            "ops@exa_mple.com",
            "{ops}@example.com",
            &format!("{}@example.com", "a".repeat(65)),
        ] {
            assert!(!fits(TemplateKind::Email, bad), "{bad:?}");
        }
    }

    #[test]
    fn text_refuses_only_what_would_add_a_line() {
        assert!(fits(TemplateKind::Text, "a; {b} 'c' $d"));
        for bad in ["a\nb", "a\rb", "a\0b", "a\u{FDD0}b", "a\u{FDD1}b"] {
            assert!(!fits(TemplateKind::Text, bad), "{bad:?}");
        }
    }

    #[test]
    fn an_env_value_refuses_a_single_quote_and_what_text_refuses() {
        assert!(fits(TemplateKind::EnvValue, "key1__key2; {x} \"y\" $z"));
        assert!(fits(TemplateKind::EnvValue, ""));
        for bad in ["it's", "'", "a\nb", "a\rb", "a\0b", "a\u{FDD0}b"] {
            assert!(!fits(TemplateKind::EnvValue, bad), "{bad:?}");
        }
    }

    #[test]
    fn kinds_are_written_by_their_names() {
        for kind in [
            TemplateKind::Text,
            TemplateKind::Hostname,
            TemplateKind::Port,
            TemplateKind::Path,
            TemplateKind::Email,
            TemplateKind::EnvValue,
        ] {
            assert_eq!(
                serde_json::to_value(kind).unwrap(),
                serde_json::json!(kind.as_str())
            );
        }
        assert!(serde_json::from_value::<TemplateKind>(serde_json::json!("url")).is_err());
    }
}
