//! The URLs zap fetches, or hands to a tool that fetches — one definition.
//!
//! What is fetched is installed or run as root, so it is fetched over a channel that
//! names its server: every such URL is `https://` and a host. No other scheme is taken:
//! a file on the target is a `file`'s `source`, and one on the operator's machine is
//! read by the config. A user or password before the host is refused, since a URL is
//! printed in every plan; a credential is a `remote` source's `auth`.
//!
//! Who fetches decides the one exception ([`FetchSide`]). zap itself fetches a `remote`
//! file's and a `build` source's `url`, a minisign `signature_url`, and an `apt_repo`'s
//! `key_url`, on the operator's machine, where `http://` to a loopback host
//! (`localhost`, `127.0.0.0/8`, `[::1]`) crosses no network — a local mirror, a test's
//! listener. An `installer`'s `url` is fetched by `curl` on the target, where loopback
//! is whoever holds that port on the target: it is `https://` alone.
//!
//! [`fetch_url_problem`] is the rule for a whole URL — a literal one, or one whose
//! references have resolved — and [`written_fetch_url_problem`] what can be said of one
//! that still holds a reference. It reads only as much of a URL as the rule needs, and
//! refuses what it doesn't recognize.

/// The `curl` a target-side fetch runs, up to its output option and URL.
///
/// `--proto` and `--proto-redir` hold the URL's own scheme and that of every redirect
/// `--location` follows to https, whatever the URL resolved to and wherever the server
/// sends the request next. `--fail` makes an HTTP error a failed step with nothing
/// kept, and `--silent --show-error` leaves an error on stderr and no progress meter.
/// The rule [`FetchSide::Target`] holds a URL to, enforced by the tool that fetches.
pub const TARGET_CURL: &str = "curl --proto '=https' --proto-redir '=https' -fsSL";

/// Where a URL is fetched from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FetchSide {
    /// By zap, on the operator's machine: `https`, or `http` to a loopback host.
    Operator,
    /// By a command on the target: `https` only.
    Target,
}

const NOT_HTTPS: &str = "is not an `https://` URL; zap fetches over https only, and takes \
     `http://` for a loopback host alone (`localhost`, `127.0.0.1`, `[::1]`)";
const NOT_A_URL_CHARACTER: &str =
    "holds whitespace, a control character or a backslash, which no URL does";
const USERINFO: &str = "holds a user or a password before its host (`user:pass@`), which \
     every plan would print; a fetch credential is declared as `auth`";
const NO_HOST: &str = "names no host";
const NOT_HTTPS_ON_TARGET: &str = "is not an `https://` URL; the target fetches it, over \
     https only";
const PORT: &str = "has a port that is not a number from 1 to 65535";

/// Whether `text` holds a character no URL is written with. A backslash is one: some
/// URL parsers read it as `/`, so a URL holding one names different hosts to different
/// readers.
fn holds_no_url_character(text: &str) -> bool {
    text.chars()
        .any(|c| c.is_whitespace() || c.is_control() || c == '\\')
}

/// `url` split at `://` into its scheme, lowercased, and the rest.
fn split_scheme(url: &str) -> Option<(String, &str)> {
    let (scheme, rest) = url.split_once("://")?;
    Some((scheme.to_ascii_lowercase(), rest))
}

/// Whether `host` — as a URL's authority spells it — is this machine: `localhost`, an
/// address in `127.0.0.0/8` written as four decimal numbers, or `[::1]`.
fn is_loopback(host: &str) -> bool {
    if host.eq_ignore_ascii_case("localhost") || host == "[::1]" {
        return true;
    }
    let octets: Vec<&str> = host.split('.').collect();
    octets.len() == 4
        && octets[0] == "127"
        && octets.iter().all(|octet| {
            !octet.is_empty()
                && octet.len() <= 3
                && octet.bytes().all(|b| b.is_ascii_digit())
                && octet.parse::<u8>().is_ok()
        })
}

/// The scheme finding for a URL fetched from `side`.
const fn not_https(side: FetchSide) -> &'static str {
    match side {
        FetchSide::Operator => NOT_HTTPS,
        FetchSide::Target => NOT_HTTPS_ON_TARGET,
    }
}

/// Whether `url` names this machine as its host, whatever its scheme — `false` for
/// anything that is no URL with a host.
#[must_use]
pub fn names_loopback(url: &str) -> bool {
    split_scheme(url).is_some_and(|(_, rest)| {
        let authority = &rest[..rest.find(['/', '?', '#']).unwrap_or(rest.len())];
        let host = if authority.starts_with('[') {
            authority
                .split_once(']')
                .map_or(authority, |(address, _)| &authority[..=address.len()])
        } else {
            authority
                .rsplit_once(':')
                .map_or(authority, |(host, _)| host)
        };
        !authority.contains('@') && is_loopback(host)
    })
}

/// What is wrong with `url` as one fetched from `side` — said as the rest of a sentence
/// about it — or `None`.
#[must_use]
pub fn fetch_url_problem(url: &str, side: FetchSide) -> Option<&'static str> {
    if holds_no_url_character(url) {
        return Some(NOT_A_URL_CHARACTER);
    }
    let Some((scheme, rest)) = split_scheme(url) else {
        return Some(not_https(side));
    };
    if scheme != "https" && scheme != "http" {
        return Some(not_https(side));
    }
    let authority = &rest[..rest.find(['/', '?', '#']).unwrap_or(rest.len())];
    if authority.contains('@') {
        return Some(USERINFO);
    }
    // The host, and what follows it: nothing, or `:` and a port.
    let (host, port) = if authority.starts_with('[') {
        match authority.split_once(']') {
            Some((address, "")) => (&authority[..=address.len()], None),
            Some((address, after)) => (&authority[..=address.len()], Some(after.strip_prefix(':'))),
            None => return Some(NO_HOST),
        }
    } else {
        match authority.rsplit_once(':') {
            Some((host, port)) => (host, Some(Some(port))),
            None => (authority, None),
        }
    };
    if host.is_empty() || host == "[]" {
        return Some(NO_HOST);
    }
    let numbered = |port: &str| {
        port.bytes().all(|b| b.is_ascii_digit()) && port.parse::<u16>().is_ok_and(|port| port != 0)
    };
    if port.is_some_and(|port| !port.is_some_and(numbered)) {
        return Some(PORT);
    }
    let plain_allowed = side == FetchSide::Operator && is_loopback(host);
    (scheme == "http" && !plain_allowed).then_some(not_https(side))
}

/// What is wrong with a URL as a config wrote it, when it holds a reference: `leading`
/// is the text it begins with (`None`: it begins with a reference), `literals` all the
/// text written of it.
///
/// What is written must already be a URL's: no character a URL can't hold, and — when
/// enough is written to tell — a scheme `side` takes. The whole rule is applied
/// where the references resolve.
#[must_use]
pub fn written_fetch_url_problem(
    leading: Option<&str>,
    literals: &[&str],
    side: FetchSide,
) -> Option<&'static str> {
    if literals.iter().any(|text| holds_no_url_character(text)) {
        return Some(NOT_A_URL_CHARACTER);
    }
    let leading = leading?.to_ascii_lowercase();
    let begins = |scheme: &str| leading.starts_with(scheme) || scheme.starts_with(&leading);
    let plain = side == FetchSide::Operator && begins("http://");
    (!begins("https://") && !plain).then_some(not_https(side))
}

#[cfg(test)]
mod tests {
    use super::FetchSide::{Operator, Target};
    use super::{
        NO_HOST, NOT_A_URL_CHARACTER, NOT_HTTPS, NOT_HTTPS_ON_TARGET, PORT, USERINFO,
        fetch_url_problem, names_loopback, written_fetch_url_problem,
    };

    #[test]
    fn a_fetched_url_is_https_and_a_host() {
        for ok in [
            "https://example.com",
            "https://example.com/",
            "https://example.com/a/b.tar.gz?x=1#frag",
            "HTTPS://Example.COM/a",
            "https://example.com:8443/a",
            "https://example.com:1/a",
            "https://example.com:65535/a",
            "https://[2001:db8::1]/a",
            "https://[2001:db8::1]:8443/a",
            "https://192.0.2.1/a",
            "https://example.com/a@b",
            "https://example.com/?next=http://other.example/",
            "https://localhost/a",
        ] {
            assert_eq!(fetch_url_problem(ok, Operator), None, "{ok}");
            assert_eq!(fetch_url_problem(ok, Target), None, "{ok}");
        }
        // Plain http to this machine: taken where zap fetches, never on the target.
        for loopback in [
            "http://localhost/a",
            "http://LOCALHOST:8080/a",
            "http://127.0.0.1:39211/a.tar.gz",
            "http://127.255.0.9/",
            "http://[::1]:8080/a",
        ] {
            assert_eq!(fetch_url_problem(loopback, Operator), None, "{loopback}");
            assert_eq!(
                fetch_url_problem(loopback, Target),
                Some(NOT_HTTPS_ON_TARGET),
                "{loopback}"
            );
            assert!(names_loopback(loopback), "{loopback}");
        }
        for (url, problem) in [
            ("http://example.com/a", NOT_HTTPS),
            ("http://127.0.0.1.example.com/a", NOT_HTTPS),
            ("http://127.1/a", NOT_HTTPS),
            ("http://0x7f.0.0.1/a", NOT_HTTPS),
            ("http://127.0.0.256/a", NOT_HTTPS),
            ("http://localhost.example.com/a", NOT_HTTPS),
            ("http://[::2]/a", NOT_HTTPS),
            ("http://10.0.0.1/a", NOT_HTTPS),
            ("file:///etc/passwd", NOT_HTTPS),
            ("ftp://example.com/a", NOT_HTTPS),
            ("ssh://example.com/a", NOT_HTTPS),
            ("data:text/plain,x", NOT_HTTPS),
            ("example.com/a", NOT_HTTPS),
            ("//example.com/a", NOT_HTTPS),
            ("/srv/a.tar.gz", NOT_HTTPS),
            ("https:/example.com", NOT_HTTPS),
            ("https:example.com", NOT_HTTPS),
            ("--output=/etc/cron.d/x", NOT_HTTPS),
            ("-o", NOT_HTTPS),
            ("", NOT_HTTPS),
            ("https://", NO_HOST),
            ("https:///a", NO_HOST),
            ("https://:443/a", NO_HOST),
            ("https://[]/a", NO_HOST),
            ("https://[::1/a", NO_HOST),
            ("https://?x", NO_HOST),
            ("https://user:pass@example.com/a", USERINFO),
            ("https://user@example.com/a", USERINFO),
            ("https://@example.com/a", USERINFO),
            ("http://example.com@127.0.0.1/a", USERINFO),
            ("https://example.com:port/a", PORT),
            ("https://example.com:/a", PORT),
            ("https://example.com:0/a", PORT),
            ("https://example.com:65536/a", PORT),
            ("https://example.com:99999/a", PORT),
            ("https://[::1]:0/a", PORT),
            ("https://[::1]x/a", PORT),
            ("https://example.com/a b", NOT_A_URL_CHARACTER),
            ("https://example.com/a\nb", NOT_A_URL_CHARACTER),
            ("https://example.com\\@evil.example/a", NOT_A_URL_CHARACTER),
            ("https:\\\\example.com", NOT_A_URL_CHARACTER),
            (" https://example.com", NOT_A_URL_CHARACTER),
            ("https://example.com/\u{7f}", NOT_A_URL_CHARACTER),
        ] {
            assert_eq!(fetch_url_problem(url, Operator), Some(problem), "{url:?}");
            let on_target = if problem == NOT_HTTPS {
                NOT_HTTPS_ON_TARGET
            } else {
                problem
            };
            assert_eq!(fetch_url_problem(url, Target), Some(on_target), "{url:?}");
        }
        assert!(names_loopback("https://localhost/a"));
        assert!(!names_loopback("http://example.com@127.0.0.1/a"));
        assert!(!names_loopback("https://example.com/"));
    }

    /// Around a reference, what is written is held: its characters, and its scheme
    /// when enough of it is written to tell.
    #[test]
    fn a_url_with_a_reference_is_held_by_what_is_written() {
        for (leading, literals) in [
            (None, &["/a.tar.gz"][..]),
            (None, &[]),
            (Some("https://"), &["https://", "/a"]),
            (Some("https://example.com/"), &["https://example.com/"]),
            (Some("http"), &["http", "://example.com"]),
            (Some("HTTPS://x/"), &["HTTPS://x/"]),
        ] {
            assert_eq!(
                written_fetch_url_problem(leading, literals, Operator),
                None,
                "{leading:?}"
            );
            assert_eq!(
                written_fetch_url_problem(leading, literals, Target),
                None,
                "{leading:?}"
            );
        }
        // A plain-http scheme written out is the operator side's to take.
        let plain = (Some("http://"), &["http://", ":8080/a"][..]);
        assert_eq!(written_fetch_url_problem(plain.0, plain.1, Operator), None);
        assert_eq!(
            written_fetch_url_problem(plain.0, plain.1, Target),
            Some(NOT_HTTPS_ON_TARGET)
        );
        for (leading, literals, problem) in [
            (Some("ftp://"), &["ftp://"][..], NOT_HTTPS),
            (Some("file:///srv/"), &["file:///srv/"], NOT_HTTPS),
            (Some("-o "), &["-o"], NOT_HTTPS),
            (Some("/srv/"), &["/srv/"], NOT_HTTPS),
            (Some("httpx://"), &["httpx://"], NOT_HTTPS),
            (None, &["/a b"], NOT_A_URL_CHARACTER),
            (
                Some("https://x/"),
                &["https://x/", "\\"],
                NOT_A_URL_CHARACTER,
            ),
        ] {
            assert_eq!(
                written_fetch_url_problem(leading, literals, Operator),
                Some(problem),
                "{leading:?} {literals:?}"
            );
        }
    }
}
