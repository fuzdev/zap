//! Detection over a [`Connection`]: the [`detect_all`] pass and the per-resource
//! [`detect_resource`] dispatcher.
//!
//! Each detector reads the target read-only and returns a [`Detection`] — the typed
//! outcome enum (no untyped `current` blob). A read that fails becomes a failed detection
//! for its resource rather than aborting the whole run; `detect_all` returns one outcome
//! per resource, in config order.
//!
//! Every kind detects **observe → interpret** (see `observed`): the kind declares typed
//! queries and a pure verdict (`zap_types::observe`). `detect_all` gathers every
//! resource's queries — and, when asked, the pending-trigger read — and answers them in
//! one [`Connection::observe`] call: one batch per privilege lane over SSH, however many
//! resources, which is also the pass's connectivity check. It then interprets each.
//! The operator commands — a `script`'s check, a `verify`'s assertions, a `package`'s
//! command `check` — are queries like any other, answered in the same batch. Nothing is
//! cached: every pass reads every resource.

mod file;
mod observed;

use std::collections::BTreeMap;
use std::ops::Range;
use std::path::Path;

use zap_types::detected::Detection;
use zap_types::lock::{LockEntry, ZapLock};
use zap_types::observe::{BatchRecord, Query, QueryResult};
use zap_types::plan::TriggerKind;
use zap_types::schema::{Resource, Target};

use crate::connection::{Answers, Connection};
use crate::error::Result;

use self::observed::Observed;

/// One detection pass: an outcome per resource, plus the batches that answered its
/// queries, and the pending-trigger markers when the pass read them.
#[derive(Debug, Clone)]
pub struct DetectionPass {
    /// One detection per resource, in config order.
    pub detections: Vec<Detection>,
    /// Each query batch the pass ran (its lane and query count) — recorded in the
    /// last-run report.
    pub batches: Vec<BatchRecord>,
    /// The pending-trigger markers on the target, keyed by marker stem — empty when the
    /// pass didn't read them ([`Markers::Skip`]).
    pub pending: BTreeMap<String, TriggerKind>,
}

/// Whether a detection pass also reads the target's pending-trigger markers
/// ([`super::pending`]) — in the same batch as the detection reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Markers {
    /// Read them.
    Read,
    /// Don't: nothing in the config can have written one, or the caller doesn't plan.
    Skip,
}

/// How [`detect_all`] concludes one resource.
enum Route<'a> {
    /// From its answers: the resource and its span of the pass's query list.
    Observed(Observed<'a>, Range<usize>),
    /// Already concluded: its fields didn't resolve, so there was nothing to read.
    Concluded(Detection),
}

/// Detect every resource.
///
/// Every resource's queries — plus the pending-trigger read, with [`Markers::Read`] — are
/// answered in one [`Connection::observe`] call (one batch per lane over SSH) before
/// anything else touches the target, so that call is also the connectivity check; a
/// pass with no queries runs [`Connection::check_connectivity`] instead. Each resource is
/// concluded from its answers. Nothing is read from an earlier pass: detection has no
/// cache.
///
/// `zap_home` is the `~/.zap` root whose content cache a `remote` file's desired
/// digest is derived from (`None`: the target's bytes are compared to the pin directly).
///
/// # Errors
/// Returns [`crate::error::Error::Connectivity`] if the target can't be reached, or the
/// pending-marker read's failure (see [`super::pending::from_answer`]).
pub async fn detect_all(
    conn: &Connection,
    target: &Target,
    resources: &[Resource],
    zap_home: Option<&Path>,
    lock: Option<&ZapLock>,
    markers: Markers,
) -> Result<DetectionPass> {
    // Gather every resource's queries into one list. A resource whose fields don't
    // resolve (a remote path with an undeclared home) reads nothing and holds.
    let mut queries: Vec<Query> = Vec::new();
    let mut routes: Vec<Route<'_>> = Vec::with_capacity(resources.len());
    for resource in resources {
        let resolved = match super::resolve_kind_fields(conn, &resource.kind) {
            Ok(resolved) => resolved,
            Err(error) => {
                routes.push(Route::Concluded(undetermined(error.to_string())));
                continue;
            }
        };
        let lock_entry = lock.and_then(|l| l.entries.get(&resource.id));
        let observed =
            Observed::for_resource(conn, target, resource, resolved, lock_entry, zap_home).await;
        let start = queries.len();
        queries.extend(observed.queries());
        routes.push(Route::Observed(observed, start..queries.len()));
    }
    let pending_read = (markers == Markers::Read).then(|| {
        queries.push(super::pending::read_query());
        queries.len() - 1
    });

    let answers = if queries.is_empty() {
        conn.check_connectivity().await?;
        Answers::default()
    } else {
        conn.observe(&queries).await?
    };

    let mut detections = Vec::with_capacity(resources.len());
    for route in routes {
        detections.push(match route {
            Route::Observed(observed, span) => {
                conclude_span(&observed, conn, &queries, span, &answers.results).await
            }
            Route::Concluded(detection) => detection,
        });
    }

    let pending = pending_markers(&answers.results, &queries, pending_read)?;
    Ok(DetectionPass {
        detections,
        batches: answers.batches,
        pending,
    })
}

/// Detect one resource — its queries as their own batch, the same queries and verdict
/// [`detect_all`] batches, so there is one detector.
///
/// Each kind gets its typed payload, so there is no fallible `view` / "invalid config"
/// path — the schema validated at parse. `lock_entry` supplies a tracked pin;
/// `zap_home` is the `~/.zap` root whose content cache a `remote` file's desired
/// digest comes from (`None`: the target's bytes are compared to the pin directly).
pub async fn detect_resource(
    conn: &Connection,
    target: &Target,
    resource: &Resource,
    lock_entry: Option<&LockEntry>,
    zap_home: Option<&Path>,
) -> Detection {
    // Resolve the kind's path fields once, through the shared seam, then finish the
    // target-home half per-connection (operator `$HOME` local, declared `target.home`
    // remote). A remote path that references the home with none declared can't be
    // resolved → the resource is `Undetermined` (the planner holds, never guesses).
    let resolved = match super::resolve_kind_fields(conn, &resource.kind) {
        Ok(resolved) => resolved,
        Err(error) => return undetermined(error.to_string()),
    };
    Observed::for_resource(conn, target, resource, resolved, lock_entry, zap_home)
        .await
        .detect_alone(conn)
        .await
}

/// Conclude `observed` from its `span` of the answers to `queries`.
///
/// The answers must line up with the queries one for one: a runner returns an answer per
/// query, a missing one as its own error. An answer set of any other length is a layout
/// mismatch, so no answer in it can be placed against its read, and every resource with
/// a read holds ([`unplaced`]) — it is never concluded from an empty or shifted slice.
/// A resource with no reads concludes as it would from any answers.
async fn conclude_span(
    observed: &Observed<'_>,
    conn: &Connection,
    queries: &[Query],
    span: Range<usize>,
    answers: &[QueryResult],
) -> Detection {
    if span.is_empty() {
        return observed.conclude(conn, &[]).await;
    }
    match answers.get(span.clone()) {
        Some(results) if answers.len() == queries.len() => observed.conclude(conn, results).await,
        _ => unplaced(queries, &span, answers.len()),
    }
}

/// The answer to `queries[index]`, when the answers line up with the queries one for
/// one — none from a mismatched set, as [`conclude_span`] places none.
fn placed<'a>(
    answers: &'a [QueryResult],
    queries: &[Query],
    index: usize,
) -> Option<&'a QueryResult> {
    answers
        .get(index)
        .filter(|_| answers.len() == queries.len())
}

/// The pending markers from the marker read at `queries[index]`, when the pass read
/// them.
///
/// A failed marker read fails the pass: the plan can't know what it owes. An answer set
/// that doesn't line up with the queries is no failed read: it places no answer, so every
/// resource with a read — each service among them — already holds ([`conclude_span`]),
/// and a held service is owed nothing this pass. Its markers wait, unread, for a pass
/// whose answers can be placed.
///
/// # Errors
/// The marker read's failure ([`super::pending::from_answer`]).
fn pending_markers(
    answers: &[QueryResult],
    queries: &[Query],
    index: Option<usize>,
) -> Result<BTreeMap<String, TriggerKind>> {
    let Some(index) = index else {
        return Ok(BTreeMap::new());
    };
    if answers.len() != queries.len() {
        return Ok(BTreeMap::new());
    }
    super::pending::from_answer(placed(answers, queries, index))
}

/// The `Undetermined` verdict for a resource whose reads (`span` of `queries`) a
/// mismatched answer set can't answer: `answered` answers came back for the pass's
/// queries. Names the first of the resource's reads that can't be placed against its
/// answer — a path by its path, a command by its position alone, since its text can
/// carry a resolved value.
fn unplaced(queries: &[Query], span: &Range<usize>, answered: usize) -> Detection {
    let index = if answered < span.end {
        span.start.max(answered)
    } else {
        span.start
    };
    let probe = match queries.get(index) {
        Some(Query::Path { path, .. }) => format!("the read of {path}"),
        Some(Query::Command { .. }) | None => "a command probe".to_owned(),
    };
    undetermined(format!(
        "detection failed: a layout mismatch: the target returned {answered} answer(s) to \
         {} query(ies), so query {index} ({probe}) can't be placed against its answer",
        queries.len(),
    ))
}

/// Detection couldn't determine the state (IO failure, unsupported target, an
/// unresolvable path). The planner holds rather than creating; never persisted.
fn undetermined(reason: impl Into<String>) -> Detection {
    Detection::Undetermined {
        reason: reason.into(),
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use zap_types::detected::{CurrentState, Detection, FileDrift};
    use zap_types::observe::{
        CommandObservation, FileKind, Observation, PathFacet, PathObservation, Privilege, Query,
        QueryResult,
    };
    use zap_types::scalar::ContentHash;
    use zap_types::schema::{ResolvedField, Resource, Target};

    use super::observed::Observed;
    use super::{conclude_span, detect_resource, pending_markers, placed};
    use crate::connection::{CommandOutput, Connection, MockConnection};
    use crate::digest::sha512_hex;

    fn ok_out(stdout: &str) -> CommandOutput {
        CommandOutput {
            success: true,
            code: 0,
            stdout: stdout.to_owned(),
            stderr: String::new(),
        }
    }

    /// A command probe's answer: its exit status and stdout.
    fn exited(code: i32, stdout: &str) -> Observation {
        Observation::Command(CommandObservation {
            code,
            stdout: stdout.as_bytes().to_vec(),
            stderr: Vec::new(),
        })
    }

    fn blake3_hex(bytes: &[u8]) -> String {
        blake3::hash(bytes).to_hex().to_string()
    }

    fn remote_file(blake3: Option<&str>, extract: &str) -> Resource {
        let mut content = serde_json::json!({
            "type": "remote",
            "url": "https://host/artifacts/ghostty",
            "extract": {"type": extract},
        });
        if let Some(pin) = blake3 {
            content["blake3"] = serde_json::Value::String(pin.to_owned());
        }
        serde_json::from_value(serde_json::json!({
            "id": "ghostty", "type": "file", "path": "/opt/ghostty", "content": content,
        }))
        .unwrap()
    }

    fn elevated(path: &str, facet: PathFacet) -> Query {
        Query::Path {
            path: path.to_owned(),
            facet,
            privilege: Privilege::Elevated,
        }
    }

    const fn path(observation: PathObservation) -> Observation {
        Observation::Path(observation)
    }

    /// A mock whose target has (`Some`) or lacks (`None`) the file at `/opt/ghostty`,
    /// answering the existence read, the digest read, and the raw `cat`.
    fn target_with(body: Option<&[u8]>) -> MockConnection {
        let mock = MockConnection::new("mock");
        match body {
            None => mock.with_observation(
                elevated("/opt/ghostty", PathFacet::Kind),
                path(PathObservation::Failed),
            ),
            Some(body) => mock
                .with_observation(
                    elevated("/opt/ghostty", PathFacet::Kind),
                    path(PathObservation::Kind(FileKind::Regular)),
                )
                .with_observation(
                    elevated("/opt/ghostty", PathFacet::Digest),
                    path(PathObservation::Digest(sha512_hex(body))),
                )
                .with(
                    zap_types::put::file_bytes_command("", "/opt/ghostty"),
                    ok_out(std::str::from_utf8(body).unwrap()),
                ),
        }
    }

    async fn detect(conn: &Connection, resource: &Resource) -> Detection {
        detect_resource(conn, &Target::default(), resource, None, None).await
    }

    async fn detect_cached(conn: &Connection, resource: &Resource, home: &Path) -> Detection {
        detect_resource(conn, &Target::default(), resource, None, Some(home)).await
    }

    /// Detect with a tracked lock pin (a `remote_file` entry) in hand.
    async fn detect_with_pin(conn: &Connection, resource: &Resource, pin: &str) -> Detection {
        let entry = zap_types::lock::LockEntry::RemoteFile {
            config_hash: String::new(),
            blake3: ContentHash::new(pin.to_owned()).unwrap(),
        };
        detect_resource(conn, &Target::default(), resource, Some(&entry), None).await
    }

    fn issued(conn: &Connection) -> (Vec<Query>, Vec<String>) {
        let Connection::Mock(mock) = conn else {
            unreachable!()
        };
        (mock.issued_queries(), mock.issued_commands())
    }

    /// Seed `home`'s content cache the way the resolver lays it out.
    fn seed_cache(home: &Path, pin: &str, body: &[u8]) {
        let dir = home.join("cache/files").join(pin);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("ghostty"), body).unwrap();
    }

    /// A template whose value would add a line to the file holds it, naming the
    /// variable and not the value, and reads nothing of the target.
    #[tokio::test]
    async fn a_template_with_a_line_break_in_a_value_holds_and_reads_nothing() {
        let _env = crate::resolve::test_env::set(&[("ZAP_T_DET_LF", "a\nEXTRA=1")]);
        let resource: Resource = serde_json::from_value(serde_json::json!({
            "id": "env", "type": "file", "path": "/etc/app.env",
            "content": {"type": "template", "template": "DOMAIN={{d}}\n",
                "vars": {"d": {"$env": "ZAP_T_DET_LF"}}},
        }))
        .unwrap();
        let conn = Connection::Mock(MockConnection::new("mock"));
        let Detection::Undetermined { reason } = detect(&conn, &resource).await else {
            panic!("a template value with a line break must hold");
        };
        assert!(reason.contains("line break"), "{reason}");
        assert!(!reason.contains("EXTRA"), "{reason}");
        assert_eq!(issued(&conn), (Vec::new(), Vec::new()));
    }

    /// A template value that isn't its variable's declared kind holds the file — an
    /// nginx `server_name` value carrying `;` and `}` — naming the variable and the
    /// kind, not the value, and reads nothing of the target.
    #[tokio::test]
    async fn a_template_value_that_is_not_its_kind_holds_and_reads_nothing() {
        let _env = crate::resolve::test_env::set(&[("ZAP_T_DET_HOST", "a.example; } x {")]);
        let resource: Resource = serde_json::from_value(serde_json::json!({
            "id": "site", "type": "file", "path": "/etc/nginx/site",
            "content": {"type": "template", "template": "server_name {{d}};\n",
                "vars": {"d": {"$env": "ZAP_T_DET_HOST"}}, "kinds": {"d": "hostname"}},
        }))
        .unwrap();
        let conn = Connection::Mock(MockConnection::new("mock"));
        let Detection::Undetermined { reason } = detect(&conn, &resource).await else {
            panic!("a value that is not its kind must hold");
        };
        assert!(reason.contains("`content.vars.d`"), "{reason}");
        assert!(reason.contains("`hostname`"), "{reason}");
        assert!(!reason.contains("x {"), "{reason}");
        assert_eq!(issued(&conn), (Vec::new(), Vec::new()));
    }

    #[tokio::test]
    async fn remote_none_converges_when_target_hash_matches_pin() {
        let body = b"ghostty-bytes\n";
        let pin = blake3_hex(body);
        let conn = Connection::Mock(target_with(Some(body)));
        assert_eq!(
            detect(&conn, &remote_file(Some(&pin), "none")).await,
            Detection::Converged
        );
        // No content cache: the target's bytes are read raw, after the batch.
        let (queries, commands) = issued(&conn);
        assert_eq!(queries, [elevated("/opt/ghostty", PathFacet::Kind)]);
        assert_eq!(
            commands,
            [zap_types::put::file_bytes_command("", "/opt/ghostty")]
        );
    }

    #[tokio::test]
    async fn remote_none_drifts_when_target_hash_differs() {
        let pin = blake3_hex(b"desired-bytes");
        let conn = Connection::Mock(target_with(Some(b"actual-bytes")));
        assert_eq!(
            detect(&conn, &remote_file(Some(&pin), "none")).await,
            Detection::Drifted {
                current: CurrentState::File {
                    drift: FileDrift::Pin {
                        observed: blake3_hex(b"actual-bytes"),
                    },
                },
            }
        );
    }

    #[tokio::test]
    async fn remote_none_absent_when_target_missing() {
        let conn = Connection::Mock(target_with(None));
        assert_eq!(
            detect(&conn, &remote_file(Some(&blake3_hex(b"missing")), "none")).await,
            Detection::Absent
        );
    }

    /// With the pinned bytes cached, only the target's digest is read — no raw transfer.
    #[tokio::test]
    async fn a_cached_remote_compares_digests_and_reads_no_bytes() {
        let home = tempfile::tempdir().unwrap();
        let body = b"ghostty-bytes\n";
        let pin = blake3_hex(body);
        seed_cache(home.path(), &pin, body);

        let conn = Connection::Mock(target_with(Some(body)));
        assert_eq!(
            detect_cached(&conn, &remote_file(Some(&pin), "none"), home.path()).await,
            Detection::Converged
        );
        let (queries, commands) = issued(&conn);
        assert_eq!(
            queries,
            [
                elevated("/opt/ghostty", PathFacet::Kind),
                elevated("/opt/ghostty", PathFacet::Digest)
            ]
        );
        assert!(commands.is_empty(), "{commands:?}");

        // A differing target drifts with its SHA-512 — never rendered as a pin.
        let conn = Connection::Mock(target_with(Some(b"other")));
        assert_eq!(
            detect_cached(&conn, &remote_file(Some(&pin), "none"), home.path()).await,
            Detection::Drifted {
                current: CurrentState::File {
                    drift: FileDrift::Digest {
                        sha512: sha512_hex(b"other"),
                    },
                },
            }
        );
    }

    /// A cold cache falls back to the raw read, and a read whose bytes match the pin
    /// warms it; one that doesn't leaves it cold.
    #[tokio::test]
    async fn a_matching_raw_read_warms_the_content_cache() {
        let home = tempfile::tempdir().unwrap();
        let body = b"ghostty-bytes\n";
        let pin = blake3_hex(body);
        let cached = home.path().join("cache/files").join(&pin).join("ghostty");

        let conn = Connection::Mock(target_with(Some(b"drifted")));
        assert!(matches!(
            detect_cached(&conn, &remote_file(Some(&pin), "none"), home.path()).await,
            Detection::Drifted { .. }
        ));
        assert!(!cached.exists());

        let conn = Connection::Mock(target_with(Some(body)));
        assert_eq!(
            detect_cached(&conn, &remote_file(Some(&pin), "none"), home.path()).await,
            Detection::Converged
        );
        assert_eq!(std::fs::read(&cached).unwrap(), body);
        assert_eq!(
            issued(&conn).1,
            [zap_types::put::file_bytes_command("", "/opt/ghostty")]
        );

        // Warm now: the next pass reads the digest, not the bytes.
        let conn = Connection::Mock(target_with(Some(body)));
        assert_eq!(
            detect_cached(&conn, &remote_file(Some(&pin), "none"), home.path()).await,
            Detection::Converged
        );
        assert!(issued(&conn).1.is_empty());
    }

    /// Cached bytes that don't hash to the pin are never trusted: the raw read decides.
    #[tokio::test]
    async fn a_corrupt_cache_entry_falls_back_to_the_raw_read() {
        let home = tempfile::tempdir().unwrap();
        let body = b"ghostty-bytes\n";
        let pin = blake3_hex(body);
        seed_cache(home.path(), &pin, b"corrupted");
        let conn = Connection::Mock(target_with(Some(body)));
        assert_eq!(
            detect_cached(&conn, &remote_file(Some(&pin), "none"), home.path()).await,
            Detection::Converged
        );
        assert_eq!(
            issued(&conn).1,
            [zap_types::put::file_bytes_command("", "/opt/ghostty")]
        );
    }

    #[tokio::test]
    async fn remote_tar_xz_compares_the_sentinel_to_the_provenance() {
        let pin = blake3_hex(b"tarball-bytes");
        let provenance = zap_types::config_hash::extract_provenance(
            &pin,
            zap_types::schema::ExtractMode::TarXz {
                strip_components: 0,
            },
        );
        let sentinel = "/opt/ghostty/.zap_remote_hash";
        let conn = Connection::Mock(
            MockConnection::new("mock")
                .with_observation(
                    elevated("/opt/ghostty", PathFacet::Lstat),
                    path(metadata_of(FileKind::Directory)),
                )
                .with_observation(
                    elevated(sentinel, PathFacet::Lstat),
                    path(metadata_of(FileKind::Regular)),
                )
                .with_observation(
                    elevated(sentinel, PathFacet::Read { max: 4096 }),
                    path(PathObservation::Contents {
                        bytes: format!("{provenance}\n").into_bytes(),
                        truncated: false,
                    }),
                )
                .with_observation(
                    elevated("/opt/ghostty", PathFacet::Empty),
                    path(PathObservation::Empty(false)),
                ),
        );
        assert_eq!(
            detect(&conn, &remote_file(Some(&pin), "tar.xz")).await,
            Detection::Converged
        );
    }

    /// With no sentinel, an empty tree is replaced (`Absent`) and one holding anything is
    /// held with the extract script's own refusal; no tree at all is `Absent`.
    #[tokio::test]
    async fn remote_tar_xz_without_a_sentinel_is_absent_only_when_empty() {
        let sentinel = "/opt/ghostty/.zap_remote_hash";
        let conn = |own: PathObservation, empty: bool| {
            Connection::Mock(
                MockConnection::new("mock")
                    .with_observation(elevated("/opt/ghostty", PathFacet::Lstat), path(own))
                    .with_observation(
                        elevated(sentinel, PathFacet::Lstat),
                        path(PathObservation::Failed),
                    )
                    .with_observation(
                        elevated(sentinel, PathFacet::Read { max: 4096 }),
                        path(PathObservation::Failed),
                    )
                    .with_observation(
                        elevated("/opt/ghostty", PathFacet::Empty),
                        path(PathObservation::Empty(empty)),
                    ),
            )
        };
        let resource = remote_file(Some(&blake3_hex(b"missing")), "tar.xz");
        assert_eq!(
            detect(&conn(PathObservation::Failed, true), &resource).await,
            Detection::Absent
        );
        assert_eq!(
            detect(&conn(metadata_of(FileKind::Directory), true), &resource).await,
            Detection::Absent
        );
        assert_eq!(
            detect(&conn(metadata_of(FileKind::Directory), false), &resource).await,
            Detection::Undetermined {
                reason: format!("/opt/ghostty: {}", zap_types::extract::UNMARKED_REFUSAL),
            }
        );
    }

    fn metadata_of(kind: FileKind) -> PathObservation {
        PathObservation::Metadata(zap_types::observe::PathMetadata {
            kind,
            mode: "755".to_owned(),
            owner: "root".to_owned(),
            group: "root".to_owned(),
        })
    }

    #[tokio::test]
    async fn tracked_remote_without_a_pin_is_undetermined() {
        // No declared blake3 and no lock pin in hand → the planner must hold, and
        // nothing is read.
        let conn = Connection::Mock(MockConnection::new("mock"));
        assert!(matches!(
            detect(&conn, &remote_file(None, "none")).await,
            Detection::Undetermined { .. }
        ));
        assert_eq!(issued(&conn), (Vec::new(), Vec::new()));
    }

    fn ufw_firewall() -> Resource {
        serde_json::from_value(serde_json::json!({
            "id": "ufw-firewall", "type": "firewall", "backend": "ufw",
            "allow": [{"port": 22, "proto": "tcp"}],
        }))
        .unwrap()
    }

    #[tokio::test]
    async fn ufw_probe_failure_reads_absent() {
        // A failed `ufw status verbose` probe means the firewall needs setting up —
        // dominantly "the `ufw` package isn't installed yet" on the fresh-host bring-up
        // path, where the same config installs it (`depends_on` orders execution only,
        // so the probe can never see it on the first pass). sudo maps command-not-found
        // to exit 1 (sudo(8) EXIT VALUE), the same code as an auth failure, so the
        // causes are indistinguishable — and `absent` is safe for all of them: the ufw
        // steps are idempotent and detection-independent, so a create either converges
        // or fails loudly at execution. Holding here left the firewall unconfigured by
        // the first `apply --wetrun` of every fresh Debian bring-up.
        let conn = Connection::Mock(MockConnection::new("mock").with_observation(
            Query::root_command("exec ufw status verbose"),
            exited(1, ""),
        ));
        assert_eq!(detect(&conn, &ufw_firewall()).await, Detection::Absent);
    }

    #[tokio::test]
    async fn ufw_inactive_reads_absent() {
        // Installed but inactive: the whole firewall needs setting up — create.
        let conn = Connection::Mock(MockConnection::new("mock").with_observation(
            Query::root_command("exec ufw status verbose"),
            exited(0, "Status: inactive\n"),
        ));
        assert_eq!(detect(&conn, &ufw_firewall()).await, Detection::Absent);
    }

    #[tokio::test]
    async fn nftables_probe_failure_reads_absent() {
        // The sibling backend's long-standing semantics, pinned: a nonzero
        // `nft list table inet filter` is "not set up", not "couldn't tell".
        let conn = Connection::Mock(MockConnection::new("mock").with_observation(
            Query::root_command("exec nft list table inet filter"),
            exited(1, ""),
        ));
        let firewall: Resource = serde_json::from_value(serde_json::json!({
            "id": "nft-firewall", "type": "firewall", "backend": "nftables",
            "allow": [{"port": 22, "proto": "tcp"}],
        }))
        .unwrap();
        assert_eq!(detect(&conn, &firewall).await, Detection::Absent);
    }

    /// An answer set that doesn't line up with the pass's queries places no answer: each
    /// resource with a read holds as a layout mismatch naming the first of its reads that
    /// can't be placed, including one whose own answers all came back, and is never
    /// concluded from an empty or shifted slice.
    #[tokio::test]
    async fn a_mismatched_answer_set_holds_every_read_as_a_layout_mismatch() {
        async fn observe<'a>(conn: &Connection, resource: &'a Resource) -> Observed<'a> {
            let at = resource.id.0.clone();
            let resolved = std::iter::once((ResolvedField::Path, at)).collect();
            Observed::for_resource(conn, &Target::default(), resource, resolved, None, None).await
        }
        let conn = Connection::Mock(MockConnection::new("mock"));
        let directory = |path: &str| -> Resource {
            serde_json::from_value(serde_json::json!({
                "id": path, "type": "directory", "path": path, "mode": "755",
            }))
            .unwrap()
        };
        let (a, b) = (directory("/a"), directory("/b"));
        let (a, b) = (observe(&conn, &a).await, observe(&conn, &b).await);
        let queries: Vec<Query> = a.queries().into_iter().chain(b.queries()).collect();
        let (span_a, span_b) = (0..a.queries().len(), a.queries().len()..queries.len());
        // A missing directory reads absent from its existence read alone.
        let absent: QueryResult = Ok(path(PathObservation::Failed));
        let aligned = vec![absent; queries.len()];
        for (observed, span) in [(&a, &span_a), (&b, &span_b)] {
            assert_eq!(
                conclude_span(observed, &conn, &queries, span.clone(), &aligned).await,
                Detection::Absent
            );
        }

        let held = |answered: usize, index: usize, at: &str| Detection::Undetermined {
            reason: format!(
                "detection failed: a layout mismatch: the target returned {answered} \
                 answer(s) to {} query(ies), so query {index} (the read of {at}) can't be \
                 placed against its answer",
                queries.len()
            ),
        };
        // Short: `/a`'s answers and `/b`'s first came back, and both hold — `/b` naming
        // its first read without one.
        assert!(span_b.len() > 1, "{queries:?}");
        let short = &aligned[..=span_b.start];
        assert_eq!(
            conclude_span(&a, &conn, &queries, span_a.clone(), short).await,
            held(short.len(), 0, "/a")
        );
        assert_eq!(
            conclude_span(&b, &conn, &queries, span_b.clone(), short).await,
            held(short.len(), span_b.start + 1, "/b")
        );
        // A resource with no reads names no read of another's: it concludes as ever.
        assert_eq!(
            conclude_span(&Observed::Pipeline, &conn, &queries, 0..0, short).await,
            Detection::Absent
        );
        // Long: every slot is there, but none can be placed.
        let long = vec![Ok(path(PathObservation::Failed)); queries.len() + 1];
        assert_eq!(
            conclude_span(&b, &conn, &queries, span_b.clone(), &long).await,
            held(long.len(), span_b.start, "/b")
        );
        // Nor is the pending-marker read's answer — and the pass, its services held,
        // goes on with no markers rather than failing.
        assert!(placed(&aligned, &queries, 0).is_some());
        assert!(placed(short, &queries, 0).is_none());
        assert!(placed(&long, &queries, 0).is_none());
        let with_markers: Vec<Query> = queries
            .iter()
            .cloned()
            .chain([crate::resource::pending::read_query()])
            .collect();
        let marker = with_markers.len() - 1;
        let longer = vec![Ok(path(PathObservation::Failed)); with_markers.len() + 1];
        for answers in [short, &longer[..]] {
            assert!(
                pending_markers(answers, &with_markers, Some(marker))
                    .unwrap()
                    .is_empty()
            );
        }
        // An aligned set whose marker read failed still fails the pass.
        let mut failed = vec![Ok(path(PathObservation::Failed)); with_markers.len()];
        failed[marker] = Ok(exited(1, ""));
        assert!(pending_markers(&failed, &with_markers, Some(marker)).is_err());
    }

    #[tokio::test]
    async fn tracked_remote_with_lock_pin_compares_against_it() {
        // A tracked file (no in-config blake3) detects against the lock entry's pin,
        // exactly as a vendored file detects against its declared pin.
        let body = b"ghostty-bytes\n";
        let pin = blake3_hex(body);
        let conn = Connection::Mock(target_with(Some(body)));
        assert_eq!(
            detect_with_pin(&conn, &remote_file(None, "none"), &pin).await,
            Detection::Converged
        );
    }
}
