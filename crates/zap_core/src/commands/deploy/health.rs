//! The deploy HTTP health/readiness subsystem — the post-restart liveness poll
//! and the `/ready` schema-drift gate.

use std::time::Duration;

use crate::resolve::resolve_env_vars;
use crate::tls::build_probe_client;

/// Poll `url` over HTTPS until it returns a success status or the attempt budget runs
/// out — gates deploy completion on the daemon actually serving (a `systemctl
/// restart` returns at fork, not at ready). `Ok` on the first 2xx; `Err` if the
/// budget is exhausted. A redirect is not followed: a `3xx` is not healthy, however
/// healthy the page it points at (a broken release's `302` to a login page).
///
/// Resolves `url`'s references itself — the deploy plan carries them inert
/// (the health domain is a declared config field), and there is more than one caller, so
/// resolving here rather than at each call site is what keeps a caller from forgetting.
pub(super) async fn http_health_check(
    url: &str,
    attempts: u32,
    interval_ms: u64,
) -> Result<String, String> {
    let resolved = resolve_env_vars(url);
    let client = build_probe_client(Duration::from_secs(5))
        .map_err(|error| format!("failed to build HTTP client: {error}"))?;
    // The last attempt's answer, for the failure message: a status, or why none came
    // with the last status any attempt got, which a later transport failure doesn't
    // erase (a `502` then a refused connection is a service that answered badly).
    let mut last = String::from("no attempt ran");
    let mut last_status: Option<u16> = None;
    for attempt in 1..=attempts {
        match client.get(&resolved).send().await {
            Ok(response) if response.status().is_success() => {
                return Ok(format!("healthy after {attempt} attempt(s)"));
            }
            Ok(response) => {
                let status = response.status().as_u16();
                last_status = Some(status);
                last = format!("HTTP {status}{}", redirect_note(status));
            }
            Err(error) => {
                let failure = connection_failure(&error);
                last = last_status.map_or_else(
                    || failure.to_owned(),
                    |status| format!("{failure} (last HTTP status {status})"),
                );
            }
        }
        if attempt < attempts {
            tokio::time::sleep(Duration::from_millis(interval_ms)).await;
        }
    }
    // The resolved URL: the declared one carries its references' inert markers.
    Err(format!(
        "service did not become healthy at {resolved} within {attempts} attempt(s) (last: {last})"
    ))
}

/// What a probe's failure message adds to a `3xx`: that zap didn't follow it.
const fn redirect_note(status: u16) -> &'static str {
    if status >= 300 && status < 400 {
        ", a redirect, which a probe doesn't follow"
    } else {
        ""
    }
}

/// What kind of transport failure `error` was, as a few stable words rather than
/// `reqwest`'s text, a chain of causes that varies with the platform and the library's
/// version. A TLS failure is a connection failure here.
fn connection_failure(error: &reqwest::Error) -> &'static str {
    if error.is_timeout() {
        "timed out"
    } else if error.is_connect() {
        "connection failed"
    } else {
        "request failed"
    }
}

/// The tri-state outcome of the `/ready` schema-drift deploy gate.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum ReadinessOutcome {
    /// `2xx` — the live DB schema covers the running code's expected columns.
    Ready,
    /// A persistent `404` — `/ready` isn't served (the backend doesn't mount it,
    /// or nginx doesn't proxy it). NOT a deploy failure: readiness is a
    /// schema-drift gate, and its absence is a misconfiguration to warn about,
    /// not a reason to roll back an otherwise-healthy release.
    Absent,
    /// `503` (schema drift / DB unreachable), another non-success status, or a
    /// persistent connection failure after the budget — the running code can't
    /// trust the live schema. Fail the deploy → rollback.
    NotReady(String),
}

/// Poll the `/ready` schema-drift deploy gate, following no redirect (a `3xx` is
/// not ready). A `2xx` short-circuits to
/// [`Ready`](ReadinessOutcome::Ready); otherwise the LAST HTTP status observed
/// classifies the result — `404` → [`Absent`](ReadinessOutcome::Absent) (warn,
/// don't fail), `503`/other → [`NotReady`](ReadinessOutcome::NotReady) (fail →
/// rollback). A connection error doesn't erase an earlier HTTP status: a real
/// `503` followed by a trailing connection blip still reads as drift rather than
/// being downgraded to a misleading "unreachable". Only when NO attempt ever got
/// an HTTP response at all is the result "unreachable".
///
/// Resolves `url`'s references itself, as [`http_health_check`] does.
pub(super) async fn http_readiness_check(
    url: &str,
    attempts: u32,
    interval_ms: u64,
) -> ReadinessOutcome {
    let url = &resolve_env_vars(url);
    let client = match build_probe_client(Duration::from_secs(5)) {
        Ok(client) => client,
        Err(error) => {
            return ReadinessOutcome::NotReady(format!("failed to build HTTP client: {error}"));
        }
    };
    let mut last_status: Option<u16> = None;
    for attempt in 1..=attempts {
        match client.get(url).send().await {
            Ok(response) if response.status().is_success() => return ReadinessOutcome::Ready,
            Ok(response) => last_status = Some(response.status().as_u16()),
            // Connection error — the service likely isn't up yet; keep polling.
            // Don't reset `last_status`: an HTTP status we already saw (a `503`
            // drift, a `404` absent) is a stronger signal than a late blip, so
            // it should still classify the outcome.
            Err(_) => {}
        }
        if attempt < attempts {
            tokio::time::sleep(Duration::from_millis(interval_ms)).await;
        }
    }
    classify_readiness(last_status, url, attempts)
}

/// Classify the terminal poll status once the readiness budget is spent without
/// a `2xx` (a `2xx` short-circuits to [`Ready`](ReadinessOutcome::Ready) in the
/// loop, so it never reaches here). Pure, so the tri-state mapping — the logic
/// the whole deploy gate hinges on — is unit-testable independent of the HTTP +
/// timing loop. `404` is the *absent* gate (warn, don't fail); every other
/// status, and no-status-at-all, is *not ready* (fail → rollback). `503` (the
/// spine's documented drift / DB-unreachable code) is named as such; any other
/// non-success code is reported verbatim without that attribution, so an
/// unexpected status isn't mislabeled as schema drift.
fn classify_readiness(last_status: Option<u16>, url: &str, attempts: u32) -> ReadinessOutcome {
    match last_status {
        Some(404) => ReadinessOutcome::Absent,
        Some(503) => ReadinessOutcome::NotReady(format!(
            "{url} returned HTTP 503 (schema drift or DB unreachable) within {attempts} attempt(s)"
        )),
        Some(code) => ReadinessOutcome::NotReady(format!(
            "{url} returned an unexpected HTTP {code}{} within {attempts} attempt(s)",
            redirect_note(code)
        )),
        None => {
            ReadinessOutcome::NotReady(format!("{url} unreachable within {attempts} attempt(s)"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{ReadinessOutcome, classify_readiness, http_health_check, http_readiness_check};

    /// Every poller resolves its own URL, so no call site can forget. The deploy plan
    /// carries the health URL with its domain reference inert, and there is more
    /// than one caller — the step executor *and* the post-failure rollback's
    /// confirmation poll. A caller that skipped resolution would poll a literal
    /// the reference's own marker, fail every attempt, and report a healthy rollback as
    /// needing manual intervention.
    #[tokio::test]
    async fn health_check_resolves_its_url_before_polling() {
        // Unset reference → resolves to an empty host, which can't be polled. The error
        // must name the *resolved* URL: proof the poll wasn't aimed at the literal.
        let unset = zap_types::var_ref::marker("ZAP_TEST_UNSET_HEALTH_HOST");
        let error = http_health_check(&format!("https://{unset}/x"), 1, 0)
            .await
            .expect_err("an empty host can't be healthy");
        assert!(error.contains("https:///x"), "{error}");
        assert!(!error.contains(&unset), "{error}");
    }

    /// A transport failure after an HTTP status keeps the status in the failure: a
    /// `502` and then a refused connection is a service that answered badly, not one
    /// that never answered.
    #[tokio::test]
    async fn a_later_transport_failure_keeps_the_last_http_status() {
        use std::io::{Read as _, Write as _};

        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/health", listener.local_addr().unwrap());
        let served = std::thread::spawn(move || {
            let (mut sock, _) = listener.accept().unwrap();
            let mut buf = [0u8; 1024];
            let _ = sock.read(&mut buf);
            sock.write_all(
                b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            )
            .unwrap();
            // the listener closes here: the next attempt's connection is refused
        });
        let error = http_health_check(&url, 2, 300)
            .await
            .expect_err("a 502, then nothing, is not healthy");
        served.join().unwrap();
        // refused, or timed out if the listener's close comes late
        assert!(
            error.ends_with("within 2 attempt(s) (last: connection failed (last HTTP status 502))")
                || error.ends_with("within 2 attempt(s) (last: timed out (last HTTP status 502))"),
            "{error}"
        );
    }

    /// A loopback server that answers `302` to `/ok` for every path but `/ok`, which is
    /// `200`, a connection a request; the URL of its redirecting path.
    fn redirecting_server() -> String {
        use std::io::{Read as _, Write as _};

        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let location = format!("{base}/ok");
        std::thread::spawn(move || {
            for sock in listener.incoming() {
                let Ok(mut sock) = sock else { return };
                let mut buf = [0u8; 2048];
                let n = sock.read(&mut buf).unwrap_or(0);
                let response = if buf[..n].starts_with(b"GET /ok ") {
                    "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok".to_owned()
                } else {
                    format!(
                        "HTTP/1.1 302 Found\r\nLocation: {location}\r\nContent-Length: 0\r\n\
                         Connection: close\r\n\r\n"
                    )
                };
                let _ = sock.write_all(response.as_bytes());
            }
        });
        format!("{base}/health")
    }

    /// A probe follows no redirect: a `302` to a page that answers `200` is neither
    /// healthy nor ready, and the failure names the status.
    #[tokio::test]
    async fn a_redirect_is_neither_healthy_nor_ready() {
        let url = redirecting_server();
        let error = http_health_check(&url, 1, 0)
            .await
            .expect_err("a redirect is not healthy");
        assert!(
            error.ends_with("(last: HTTP 302, a redirect, which a probe doesn't follow)"),
            "{error}"
        );
        let ReadinessOutcome::NotReady(message) = http_readiness_check(&url, 1, 0).await else {
            panic!("a redirect is not ready");
        };
        assert!(
            message.contains(
                "returned an unexpected HTTP 302, a redirect, which a probe doesn't follow"
            ),
            "{message}"
        );
    }

    #[test]
    fn readiness_persistent_404_is_absent() {
        // A `/ready` that 404s through the whole budget is an unwired gate —
        // warn the operator, but ship on liveness (never roll back a healthy
        // release because the schema-drift probe is merely absent).
        assert_eq!(
            classify_readiness(Some(404), "https://example.com/ready", 3),
            ReadinessOutcome::Absent
        );
    }

    #[test]
    fn readiness_503_is_not_ready_and_names_drift() {
        // `503` = schema drift / DB unreachable — the running code can't trust
        // the live schema; fail the deploy so the post-swap rollback fires, and
        // name the cause for the operator.
        let ReadinessOutcome::NotReady(msg) =
            classify_readiness(Some(503), "https://example.com/ready", 3)
        else {
            panic!("503 must classify as NotReady");
        };
        assert!(msg.contains("503"));
        assert!(msg.contains("schema drift"));
    }

    #[test]
    fn readiness_unexpected_status_is_not_ready_without_false_attribution() {
        // A non-404 non-503 code (e.g. `500`) still fails the gate, but must NOT
        // be mislabeled as schema drift — only `503` carries that attribution.
        let ReadinessOutcome::NotReady(msg) =
            classify_readiness(Some(500), "https://example.com/ready", 3)
        else {
            panic!("500 must classify as NotReady");
        };
        assert!(msg.contains("500"));
        assert!(!msg.contains("schema drift"));
    }

    #[test]
    fn readiness_unreachable_is_not_ready() {
        // No status ever observed (connection failures throughout the budget) —
        // fail the deploy rather than ship blind.
        assert!(matches!(
            classify_readiness(None, "https://example.com/ready", 3),
            ReadinessOutcome::NotReady(_)
        ));
    }
}
