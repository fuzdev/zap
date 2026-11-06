//! Tests for detection (every kind).
//!
//! Layers:
//! - **Golden fixtures** under `fixtures/detection/`: each case pairs a resource +
//!   the recorded target — `(query → observation)` for every typed query, plus
//!   `(cmd → output)` for an uncached `remote` file's raw read — + the expected
//!   `Detection`. A `MockConnection` replays
//!   the recordings, so the detectors are validated without touching a real system. A
//!   case may seed the content cache (`content_cache`) and name the entry a detection
//!   should leave in it (`warms`). A reference in a fixture reads a variable cargo sets
//!   for every test run (`CARGO_PKG_NAME` is `zap_core`), since tests can't set
//!   their own. Fixtures are hand-authored.
//! - **End-to-end** (fgro-gated): `run_detect_in` against the local machine with
//!   `~/.zap` pointed at a tempdir, proving eval → detect → the last-run report, and
//!   that detection never reads a report back.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;
mod scratch;

use std::collections::BTreeMap;

use common::{fgro, fgro_available};
use serde::Deserialize;

use zap_core::connection::{CommandOutput, Connection, MockConnection};
use zap_core::last_run::{read_last_run, write_last_run};
use zap_core::resource::detect_resource;
use zap_types::detected::Detection;
use zap_types::last_run::{LAST_RUN_VERSION, LastRun, ResourceRecord, RunCommand, Verdict};
use zap_types::observe::{
    CommandObservation, FileKind, Observation, PathMetadata, PathObservation, Query,
};
use zap_types::schema::{Resource, ResourceId, Target};

/// A recorded command result in a fixture (deserialized into a `CommandOutput`).
#[derive(Deserialize)]
struct RecordedOutput {
    success: bool,
    code: i32,
    stdout: String,
    stderr: String,
}

impl From<RecordedOutput> for CommandOutput {
    fn from(r: RecordedOutput) -> Self {
        Self {
            success: r.success,
            code: r.code,
            stdout: r.stdout,
            stderr: r.stderr,
        }
    }
}

/// A recorded observation in a fixture — the JSON face of an [`Observation`]: a
/// [`PathObservation`], or a command's exit status and output.
#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum RecordedObservation {
    /// The read found nothing.
    Failed,
    /// A `stat -L` file type.
    Kind(RecordedKind),
    /// `stat` metadata.
    Metadata {
        kind: RecordedKind,
        mode: String,
        owner: String,
        group: String,
    },
    /// A symlink's target (UTF-8 in fixtures).
    LinkTarget(String),
    /// A SHA-512, lowercase hex.
    Digest(String),
    /// A bounded read's bytes (UTF-8 in fixtures).
    Contents { bytes: String, truncated: bool },
    /// Whether a directory listing found nothing.
    Empty(bool),
    /// A command's exit status and output (UTF-8 in fixtures).
    Command {
        code: i32,
        stdout: String,
        stderr: String,
    },
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum RecordedKind {
    Regular,
    Directory,
    Symlink,
}

impl From<RecordedKind> for FileKind {
    fn from(kind: RecordedKind) -> Self {
        match kind {
            RecordedKind::Regular => Self::Regular,
            RecordedKind::Directory => Self::Directory,
            RecordedKind::Symlink => Self::Symlink,
        }
    }
}

impl From<RecordedObservation> for Observation {
    fn from(recorded: RecordedObservation) -> Self {
        Self::Path(match recorded {
            RecordedObservation::Command {
                code,
                stdout,
                stderr,
            } => {
                return Self::Command(CommandObservation {
                    code,
                    stdout: stdout.into_bytes(),
                    stderr: stderr.into_bytes(),
                });
            }
            RecordedObservation::Failed => PathObservation::Failed,
            RecordedObservation::Kind(kind) => PathObservation::Kind(kind.into()),
            RecordedObservation::Metadata {
                kind,
                mode,
                owner,
                group,
            } => PathObservation::Metadata(PathMetadata {
                kind: kind.into(),
                mode,
                owner,
                group,
            }),
            RecordedObservation::LinkTarget(target) => {
                PathObservation::LinkTarget(target.into_bytes())
            }
            RecordedObservation::Digest(digest) => PathObservation::Digest(digest),
            RecordedObservation::Empty(empty) => PathObservation::Empty(empty),
            RecordedObservation::Contents { bytes, truncated } => PathObservation::Contents {
                bytes: bytes.into_bytes(),
                truncated,
            },
        })
    }
}

/// One recorded query and what the target answered.
#[derive(Deserialize)]
struct RecordedQuery {
    query: Query,
    observation: RecordedObservation,
}

/// One self-contained detection golden.
#[derive(Deserialize)]
struct Case {
    resource: Resource,
    target: Target,
    #[serde(default)]
    recorded: BTreeMap<String, RecordedOutput>,
    #[serde(default)]
    observed: Vec<RecordedQuery>,
    /// Content-cache entries to seed, `<blake3>/<name>` → content.
    #[serde(default)]
    content_cache: BTreeMap<String, String>,
    /// A content-cache entry (`<blake3>/<name>`) the detection must leave behind.
    #[serde(default)]
    warms: Option<String>,
    expected: Detection,
}

/// Replay every `fixtures/detection/*.json` golden through `detect_resource` over
/// a `MockConnection` and assert the produced state matches `expected` — and that the
/// queries the detector issued are exactly the recorded ones, in order, so a fixture pins
/// the detector's whole read set: a read it stops making or starts making fails here.
/// Each case gets its own content cache, seeded from the fixture.
#[tokio::test]
async fn detection_goldens() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/detection");
    let mut ran = 0;
    let mut unused = Vec::new();
    for entry in std::fs::read_dir(&dir).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        let name = path.file_stem().unwrap().to_string_lossy().into_owned();
        let bytes = std::fs::read(&path).unwrap();
        let case: Case =
            serde_json::from_slice(&bytes).unwrap_or_else(|e| panic!("parse {name}: {e}"));

        let home = scratch::tempdir().unwrap();
        let files = home.path().join("cache/files");
        for (entry, content) in &case.content_cache {
            let cached = files.join(entry);
            std::fs::create_dir_all(cached.parent().unwrap()).unwrap();
            std::fs::write(cached, content).unwrap();
        }

        let recorded_commands: Vec<String> = case.recorded.keys().cloned().collect();
        let mut mock = MockConnection::new("mock");
        for (cmd, output) in case.recorded {
            mock = mock.with(cmd, output.into());
        }
        let recorded_queries: Vec<Query> = case.observed.iter().map(|r| r.query.clone()).collect();
        for recorded in case.observed {
            mock = mock.with_observation(recorded.query, recorded.observation.into());
        }
        let conn = Connection::Mock(mock);

        let detected =
            detect_resource(&conn, &case.target, &case.resource, None, Some(home.path())).await;
        assert_eq!(detected, case.expected, "fixture {name}");
        let Connection::Mock(mock) = &conn else {
            unreachable!()
        };
        assert_eq!(
            mock.issued_queries(),
            recorded_queries,
            "fixture {name}: issued queries"
        );
        // Every recorded command was issued: an unused recording is a read the detector
        // no longer makes, and would otherwise sit in the fixture unnoticed.
        for command in &recorded_commands {
            if !mock.issued(command) {
                unused.push(format!("{name}: {command}"));
            }
        }
        if let Some(warms) = case.warms {
            assert!(
                files.join(&warms).is_file(),
                "fixture {name}: the content cache holds no {warms}"
            );
        }
        ran += 1;
    }
    assert!(
        unused.is_empty(),
        "recorded commands never issued:\n{}",
        unused.join("\n")
    );
    assert!(ran >= 75, "expected the authored goldens to run, got {ran}");
}

#[tokio::test]
async fn run_detect_in_local_end_to_end() {
    if !fgro_available() {
        eprintln!("skipping run_detect_in_local_end_to_end: ZAP_FGRO not set");
        return;
    }
    let proj = scratch::tempdir().unwrap();
    let config_path = proj.path().join("zap.ts");
    // A directory that surely exists locally, a package, and a package whose `check` is
    // a command — a path read, a manager query, and an operator command, end-to-end
    // against the real local machine.
    scratch::write_config(
        &config_path,
        r"
export default (zap) => {
    zap.target({local: true, package_manager: 'apt'});
    zap.directory({id: 'tmp', name: 'tmp', path: '/tmp'});
    zap.pkg({id: 'definitely-not-installed-xyz', name: 'nope', from: {apt: 'definitely-not-installed-xyz'}});
    zap.pkg({id: 'sh-check', name: 'sh', from: {apt: 'dash'}, check: 'command -v sh'});
};
",
    )
    .unwrap();

    // A report claiming everything converged, as a run long ago might have left it:
    // detection never reads it, so the pass below reads the target and replaces it.
    let home = scratch::tempdir().unwrap();
    let stale = LastRun {
        version: LAST_RUN_VERSION,
        ran_at: "2026-01-01T00:00:00Z".to_owned(),
        command: RunCommand::Plan,
        host: "local".to_owned(),
        target_hash: None,
        unverifiable: Vec::new(),
        plan_hash: None,
        resources: ["tmp", "definitely-not-installed-xyz", "sh-check"]
            .into_iter()
            .map(|id| {
                (
                    ResourceId(id.to_owned()),
                    ResourceRecord {
                        verdict: Verdict::Converged,
                        desired_hash: None,
                        references_secret: false,
                    },
                )
            })
            .collect(),
        batches: Vec::new(),
    };
    write_last_run(home.path(), &config_path, &stale).unwrap();
    let report = zap_core::commands::detect::run_detect_in(
        Some(home.path()),
        fgro(),
        &config_path,
        false,
        false,
    )
    .await
    .unwrap();

    assert_eq!(report.target, "local");
    assert_eq!(report.resources.len(), 3);
    let tmp = report
        .resources
        .iter()
        .find(|r| r.resource_id.0 == "tmp")
        .unwrap();
    assert!(
        tmp.detection.exists(),
        "/tmp should exist: {:?}",
        tmp.detection
    );

    let missing = report
        .resources
        .iter()
        .find(|r| r.resource_id.0 == "definitely-not-installed-xyz")
        .unwrap();
    assert_eq!(missing.detection, Detection::Absent);

    let sh = report
        .resources
        .iter()
        .find(|r| r.resource_id.0 == "sh-check")
        .unwrap();
    assert_eq!(sh.detection, Detection::Converged);

    // The pass recorded what it read, replacing the stale report.
    let last = read_last_run(home.path(), &config_path, "local").unwrap();
    assert_eq!(last.command, RunCommand::Detect);
    assert_ne!(last.ran_at, stale.ran_at);
    let verdict = |id: &str| last.resources[&ResourceId(id.to_owned())].verdict;
    assert_eq!(verdict("tmp"), Verdict::Converged);
    assert_eq!(verdict("definitely-not-installed-xyz"), Verdict::Absent);
    assert_eq!(verdict("sh-check"), Verdict::Converged);
    assert!(
        last.resources
            .values()
            .all(|record| record.desired_hash.is_some())
    );
    // The operator command ran in a local login batch, recorded by its masked digest.
    assert!(!last.batches.is_empty(), "{:?}", last.batches);
}
