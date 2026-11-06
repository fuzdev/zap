//! Process-wide rustls crypto provider + HTTP client construction.
//!
//! `reqwest` is built with the `rustls-no-provider` feature, so the process must
//! install a [`rustls::crypto::CryptoProvider`] before any TLS client is
//! constructed. zap uses the `ring` provider: it drops the `aws-lc-sys` C library
//! and its `cmake` build step, so the binary cross-compiles cleanly to a static
//! musl target. Every client is built through [`build_http_client`] or
//! [`build_probe_client`], which install the provider first — so a new call site
//! can't forget it.
//!
//! A probe client ([`build_probe_client`], a deploy's health and `/ready` polls) follows
//! no redirect at all: its answer is the status, and a `3xx` is that answer. Every
//! other client follows a redirect only to an `https` URL
//! ([`zap_types::fetch_url`]). `reqwest`'s own policy follows a redirect from `https` to
//! `http` (dropping the `Authorization` header on the way), so bytes asked for over TLS
//! could arrive in the clear. Plain `http` to a loopback host is followed only by a
//! request whose every hop so far was to one: a remote server can't send a fetch, or a
//! health poll, to a plain-`http` port of the operator's own machine.

use std::sync::Once;
use std::time::Duration;

use reqwest::redirect::Policy;
use zap_types::fetch_url::{FetchSide, fetch_url_problem, names_loopback};

/// The most redirects one request follows — `reqwest`'s own default.
const MAX_REDIRECTS: usize = 10;

static INSTALL: Once = Once::new();

/// Build a `reqwest` client with the given request timeout, installing the `ring`
/// crypto provider as the process default first. The client refuses a redirect to a
/// URL zap wouldn't fetch ([`redirect_policy`]).
///
/// # Errors
/// Propagates a `reqwest` client-build error.
pub fn build_http_client(timeout: Duration) -> reqwest::Result<reqwest::Client> {
    ensure_crypto_provider();
    reqwest::Client::builder()
        .timeout(timeout)
        .redirect(redirect_policy())
        .build()
}

/// Build a `reqwest` client, as [`build_http_client`] does, that follows no redirect:
/// a probe whose answer is the status itself (a deploy's health and `/ready` polls), where
/// a `302` to a login page's `200` would read as healthy.
///
/// # Errors
/// Propagates a `reqwest` client-build error.
pub fn build_probe_client(timeout: Duration) -> reqwest::Result<reqwest::Client> {
    ensure_crypto_provider();
    reqwest::Client::builder()
        .timeout(timeout)
        .redirect(Policy::none())
        .build()
}

/// Follow a redirect only to an `https` URL — or, for a request that began on a
/// loopback host and has left it for no other, to plain `http` on one — each hop held
/// to the rule, and no more than [`MAX_REDIRECTS`] of them. The refusal says what is wrong with the location and
/// doesn't repeat it: it is the server's text.
fn redirect_policy() -> Policy {
    Policy::custom(|attempt| {
        // `previous` begins with the request's own URL, which is no redirect.
        if attempt.previous().len() > MAX_REDIRECTS {
            return attempt.error("too many redirects");
        }
        let previous = attempt.previous().iter().map(reqwest::Url::as_str);
        match hop_problem(previous, attempt.url().as_str()) {
            Some(problem) => attempt.error(format!("redirected to a URL that {problem}")),
            None => attempt.follow(),
        }
    })
}

/// Install the `ring` crypto provider as the process default, exactly once.
///
/// A provider already installed by another component is treated as success — the
/// provider is present either way, which is all the caller needs.
fn ensure_crypto_provider() {
    INSTALL.call_once(|| {
        // `install_default` errors only when a provider is already set; either
        // outcome leaves a usable provider installed, so the result is ignored.
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

/// What is wrong with `next` as a hop of a request that has been to `previous`, or
/// `None`.
///
/// Where the request has been says which rule the hop is held to: only one that set
/// out for this machine, and has been nowhere else since, may be sent on to plain
/// `http` here. A request with no hop behind it has been shown to set out for nowhere,
/// so it is held to `https` like one that left.
fn hop_problem<'a>(previous: impl Iterator<Item = &'a str>, next: &str) -> Option<&'static str> {
    let mut hops = 0_usize;
    let mut on_loopback = true;
    for hop in previous {
        hops += 1;
        on_loopback &= names_loopback(hop);
    }
    let side = if hops > 0 && on_loopback {
        FetchSide::Operator
    } else {
        FetchSide::Target
    };
    fetch_url_problem(next, side)
}

#[cfg(test)]
mod tests {
    use std::error::Error as _;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::time::Duration;

    use super::{build_http_client, hop_problem};

    /// Serve `responses` in order, one per connection, from a loopback listener, and
    /// return its `http://127.0.0.1:<port>` origin.
    fn serve(responses: Vec<String>) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        std::thread::spawn(move || {
            for response in responses {
                let Ok((mut stream, _)) = listener.accept() else {
                    return;
                };
                let mut request = [0_u8; 2048];
                let _ = stream.read(&mut request);
                let _ = stream.write_all(response.as_bytes());
            }
        });
        origin
    }

    fn redirect(location: &str) -> String {
        format!(
            "HTTP/1.1 302 Found\r\nLocation: {location}\r\nContent-Length: 0\r\n\
             Connection: close\r\n\r\n"
        )
    }

    /// The whole of an error's chain, as text.
    fn chain(error: &reqwest::Error) -> String {
        let mut text = error.to_string();
        let mut source = error.source();
        while let Some(cause) = source {
            text.push_str(": ");
            text.push_str(&cause.to_string());
            source = cause.source();
        }
        text
    }

    /// A redirect is followed to a URL zap would fetch — here another loopback one —
    /// and refused to any other, before a request is made to it: plain `http` on
    /// another host, a `file`, a location with a user in it.
    #[tokio::test]
    async fn a_redirect_is_followed_only_to_a_url_zap_would_fetch() {
        let client = build_http_client(Duration::from_secs(15)).unwrap();
        let ok = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok";

        let end = serve(vec![ok.to_owned()]);
        let start = serve(vec![redirect(&format!("{end}/end"))]);
        let response = client.get(format!("{start}/start")).send().await.unwrap();
        assert_eq!(response.text().await.unwrap(), "ok");

        for (location, problem) in [
            (
                "http://192.0.2.1/a",
                "redirected to a URL that is not an `https://` URL",
            ),
            (
                "ftp://127.0.0.1/a",
                "redirected to a URL that is not an `https://` URL",
            ),
            (
                "https://user:pass@192.0.2.1/a",
                "redirected to a URL that holds a user or a password before its host",
            ),
        ] {
            let start = serve(vec![redirect(location)]);
            let error = client
                .get(format!("{start}/start"))
                .send()
                .await
                .unwrap_err();
            assert!(error.is_redirect(), "{location}: {error:?}");
            let text = chain(&error);
            assert!(text.contains(problem), "{location}: {text}");
        }
    }

    /// A chain of redirects is followed for as many hops as the limit and no further,
    /// though every hop is to a URL zap would fetch.
    #[tokio::test]
    async fn a_chain_of_redirects_ends_at_the_limit() {
        // A listener that redirects to itself `redirects` times, then answers.
        let chain_of = |redirects: usize| {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let origin = format!("http://{}", listener.local_addr().unwrap());
            let again = redirect(&format!("{origin}/again"));
            let mut responses = vec![again; redirects];
            responses.push(
                "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok".to_owned(),
            );
            std::thread::spawn(move || {
                for response in responses {
                    let Ok((mut stream, _)) = listener.accept() else {
                        return;
                    };
                    let mut request = [0_u8; 2048];
                    let _ = stream.read(&mut request);
                    let _ = stream.write_all(response.as_bytes());
                }
            });
            origin
        };
        let client = build_http_client(Duration::from_secs(15)).unwrap();

        let origin = chain_of(super::MAX_REDIRECTS);
        let response = client.get(format!("{origin}/start")).send().await.unwrap();
        assert_eq!(response.text().await.unwrap(), "ok");

        let origin = chain_of(super::MAX_REDIRECTS + 1);
        let error = client
            .get(format!("{origin}/start"))
            .send()
            .await
            .unwrap_err();
        assert!(error.is_redirect(), "{error:?}");
        assert!(chain(&error).contains("too many redirects"), "{error:?}");
    }

    /// A hop to plain `http` on a loopback host is taken only by a request whose every
    /// hop so far was to a loopback host; every other hop is `https`, wherever the
    /// request has been.
    #[test]
    fn a_plain_http_hop_is_for_a_request_that_never_left_loopback() {
        const PUBLIC: &str = "https://example.com/a.tar.gz";
        const LOCAL: &str = "http://127.0.0.1:8080/a.tar.gz";
        for (previous, next, followed) in [
            (&[LOCAL][..], "http://localhost:9090/b", true),
            // no hop behind it: nothing says it began on this machine
            (&[], "http://localhost:9090/b", false),
            (&[], "http://127.0.0.1/b", false),
            (&[], "https://example.com/b", true),
            (&[LOCAL], "http://[::1]/b", true),
            (&[LOCAL], "https://example.com/b", true),
            (&[LOCAL], "http://example.com/b", false),
            (&[LOCAL, "http://localhost:9090/b"], "http://[::1]/c", true),
            (&["https://localhost/a"], "http://127.0.0.1/b", true),
            (&[PUBLIC], "https://cdn.example.com/b", true),
            (&[PUBLIC], "https://localhost/b", true),
            (&[PUBLIC], "http://localhost:9090/b", false),
            (&[PUBLIC], "http://127.0.0.1/b", false),
            (&[PUBLIC], "http://[::1]:8080/b", false),
            (&[PUBLIC], "http://example.com/a.tar.gz", false),
            (&[PUBLIC], "file:///etc/passwd", false),
            (
                &["https://127.0.0.1.example.com/a"],
                "http://127.0.0.1/b",
                false,
            ),
            // out to a public host and back: the way back is https or nothing
            (&[LOCAL, PUBLIC], "http://localhost:9090/c", false),
            (&[LOCAL, PUBLIC], "https://localhost/c", true),
            (
                &[PUBLIC, "https://localhost/b"],
                "http://localhost/c",
                false,
            ),
        ] {
            assert_eq!(
                hop_problem(previous.iter().copied(), next).is_none(),
                followed,
                "{previous:?} -> {next}"
            );
        }
    }
}
