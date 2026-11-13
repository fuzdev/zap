//! `file` — existence, then the content (a digest compare, or an extracted `remote`'s
//! sentinel), then the managed mode/owner/group.
//!
//! The desired side ([`FileDesired`]) is built by `zap_core` before the queries run: it
//! renders inline/template content and hashes it, resolves a `source` path, and looks a
//! `remote` pin's bytes up in the content cache. Every read here is
//! [`Elevated`](Privilege::Elevated) — the privilege of zap's own reads of the paths it
//! manages.
//!
//! One variant can't finish from the batch alone: a `remote` file (`extract: none`)
//! whose pinned bytes aren't cached locally has no SHA-512 to compare, so
//! [`interpret`] asks the caller to read the target's bytes and compare their blake3 to
//! the pin ([`FileStep::CompareBytes`], then [`interpret_pin`]).

use super::{
    FileKind, PathFacet, PathObservation, Privilege, Query, QueryResult, contents_answer,
    exists_answer, layout_mismatch, metadata_answer, metadata_mismatch, path_answer,
    readable_answer, unexpected_answer, unpinned_reason,
};
use crate::detected::{CurrentState, Detection, FileDrift};
use crate::extract::{LINK_REFUSAL, NOT_A_DIRECTORY_REFUSAL, UNMARKED_REFUSAL};
use crate::schema::FileResource;

/// The file an extracted `remote` tree records its provenance in, inside the tree: the
/// [`extract_provenance`](crate::config_hash::extract_provenance) of the tarball's pin
/// and the extract strategy.
pub const REMOTE_HASH_SENTINEL: &str = ".zap_remote_hash";

/// The most bytes of an extract sentinel detection reads. A digest is 64 hex digits; a
/// sentinel longer than this can't record one.
pub const SENTINEL_READ_MAX: u32 = 4096;

/// What a `file`'s content is compared against.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FileDesired {
    /// Inline or template content: the SHA-512 of the rendered bytes.
    Rendered {
        /// Lowercase hex SHA-512.
        sha512: String,
    },
    /// `source` content: the digest of this resolved target path, read in the same
    /// batch.
    Source {
        /// The resolved source path.
        path: String,
    },
    /// `source` content whose path couldn't be resolved — held once the target is known
    /// to exist and be readable.
    SourceUnresolved {
        /// Why the path didn't resolve.
        error: String,
    },
    /// A `remote` file (`extract: none`) whose pinned bytes are in the content cache.
    Remote {
        /// Lowercase hex SHA-512 of the pinned bytes.
        sha512: String,
    },
    /// A `remote` file (`extract: none`) with no cached bytes for its pin: the caller
    /// reads the target's bytes and compares their blake3 to `pin`.
    RemoteUncached {
        /// The blake3 pin.
        pin: String,
    },
    /// An extracted `remote` file (`tar.*`): its sentinel must record `provenance`.
    Extracted {
        /// The [`extract_provenance`](crate::config_hash::extract_provenance) of the
        /// tarball's pin and the extract strategy.
        provenance: String,
    },
    /// A tracked `remote` file with no usable pin — held before anything is read.
    Unpinned {
        /// The resource id, for the `zap update` hint.
        id: String,
    },
    /// A template whose values couldn't be rendered into bytes zap would write (a value
    /// that would add a line to the file) — held before anything is read.
    Unrenderable {
        /// Why, naming the variable, never its value.
        reason: String,
    },
}

/// What the answers to [`queries`] settle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FileStep {
    /// The verdict.
    Done(Detection),
    /// The target file exists, and its bytes' blake3 decides the content — read them and
    /// finish with [`interpret_pin`]. Only for [`FileDesired::RemoteUncached`].
    CompareBytes,
}

/// A file's reads and where each sits in them — built once, by [`Reads::of`], for both
/// [`queries`] and the verdict, so a read's position has one source of truth.
#[derive(Debug, Clone)]
struct Reads {
    /// The reads, in order.
    queries: Vec<Query>,
    /// The existence read: the target's [`Kind`](PathFacet::Kind), or an extracted
    /// tree's own [`Lstat`](PathFacet::Lstat).
    exists: usize,
    /// The content read (a digest, or the sentinel's bytes).
    content: Option<usize>,
    /// An extracted tree's sentinel's own [`Lstat`](PathFacet::Lstat): whether the tree
    /// is marked.
    marker: Option<usize>,
    /// An extracted tree's [`Empty`](PathFacet::Empty) read, for a tree with no sentinel.
    empty: Option<usize>,
    /// The `source` path's digest.
    source: Option<usize>,
    /// The managed metadata read.
    metadata: Option<usize>,
    /// What the path itself must be: a directory for an extracted tree, else a regular
    /// file.
    kind: FileKind,
}

/// Whether any of mode/owner/group is managed — the only case the metadata is read.
const fn manages_metadata(file: &FileResource) -> bool {
    file.mode.is_some() || file.owner.is_some() || file.group.is_some()
}

impl Reads {
    /// The reads for `desired` at the resolved `path` (see [`queries`]), or `None` when
    /// it reads nothing (a tracked `remote` file with no pin).
    fn of(file: &FileResource, path: &str, desired: &FileDesired) -> Option<Self> {
        let mut queries = Vec::new();
        let mut read = |path: &str, facet: PathFacet| {
            queries.push(Query::Path {
                path: path.to_owned(),
                facet,
                privilege: Privilege::Elevated,
            });
            queries.len() - 1
        };
        let managed = manages_metadata(file);
        let (exists, content, source) = match desired {
            FileDesired::Unpinned { .. } | FileDesired::Unrenderable { .. } => return None,
            FileDesired::Extracted { .. } => {
                let sentinel = sentinel_path(path);
                let exists = read(path, PathFacet::Lstat);
                let marker = read(&sentinel, PathFacet::Lstat);
                let content = read(
                    &sentinel,
                    PathFacet::Read {
                        max: SENTINEL_READ_MAX,
                    },
                );
                let empty = read(path, PathFacet::Empty);
                return Some(Self {
                    queries,
                    exists,
                    content: Some(content),
                    source: None,
                    marker: Some(marker),
                    empty: Some(empty),
                    // The tree's own metadata is the existence read.
                    metadata: managed.then_some(exists),
                    kind: FileKind::Directory,
                });
            }
            FileDesired::RemoteUncached { .. } => (read(path, PathFacet::Kind), None, None),
            FileDesired::Rendered { .. }
            | FileDesired::SourceUnresolved { .. }
            | FileDesired::Remote { .. } => {
                let exists = read(path, PathFacet::Kind);
                (exists, Some(read(path, PathFacet::Digest)), None)
            }
            FileDesired::Source { path: source } => {
                let exists = read(path, PathFacet::Kind);
                let content = read(path, PathFacet::Digest);
                (exists, Some(content), Some(read(source, PathFacet::Digest)))
            }
        };
        let metadata = managed.then(|| read(path, PathFacet::Lstat));
        Some(Self {
            queries,
            exists,
            content,
            source,
            marker: None,
            empty: None,
            metadata,
            kind: FileKind::Regular,
        })
    }
}

/// The sentinel path inside an extracted tree at `path`.
#[must_use]
pub fn sentinel_path(path: &str) -> String {
    format!("{path}/{REMOTE_HASH_SENTINEL}")
}

/// A file's reads, for its resolved `path`, in order:
///
/// - existence — the [`Kind`](PathFacet::Kind) of what `path` resolves to (`test -e`
///   semantics);
/// - content — the target's [`Digest`](PathFacet::Digest); none for an uncached
///   `remote` file, whose bytes the caller reads itself;
/// - for `source` content, the source path's digest;
/// - when mode, owner, or group is managed, the path's own [`Lstat`](PathFacet::Lstat) —
///   of a symbolic link itself when `path` is one, never of what it points at: execution
///   installs a regular file, so a link there is not the declared file.
///
/// An extracted tree reads what the extract script's guard reads: the tree's own
/// [`Lstat`](PathFacet::Lstat) (existence, its type, and the managed metadata), the
/// sentinel's own `Lstat` (a sentinel is a regular file, not a link — the guard's
/// `[ -f ] && [ ! -L ]`), the sentinel's bytes ([`Read`](PathFacet::Read), at most
/// [`SENTINEL_READ_MAX`]), and whether the tree is [`Empty`](PathFacet::Empty) (the
/// guard's `ls -A`).
///
/// All at [`Elevated`](Privilege::Elevated). A tracked `remote` file with no pin, and a
/// template that couldn't be rendered, read nothing.
#[must_use]
pub fn queries(file: &FileResource, path: &str, desired: &FileDesired) -> Vec<Query> {
    Reads::of(file, path, desired).map_or_else(Vec::new, |reads| reads.queries)
}

/// The verdict for a file from the answers to [`queries`] — or, for an uncached
/// `remote` file that exists, [`FileStep::CompareBytes`].
///
/// In order:
///
/// 1. A tracked `remote` file with no pin holds, and so does a template that couldn't be
///    rendered.
/// 2. Nothing at the path → `Absent`. An extracted tree is read as the extract script
///    would treat it: a symbolic link or anything but a directory at the path holds, as
///    a tree with no sentinel does unless it is empty (`Absent`, which the extraction
///    replaces) — each with the reason the script refuses it for, so the plan never
///    offers what the wetrun refuses.
/// 3. The content: a path that exists but can't be read holds — reading it as absent
///    would plan a create over content nobody read. A digest that differs drifts
///    (content, or for a `remote` file the observed SHA-512); a sentinel that doesn't
///    record the provenance (compared with surrounding whitespace trimmed, as it is written)
///    drifts with what it records. The content reads open only a regular file of its
///    own ([`PathObservation::NotRegular`] for anything else): a symbolic link at the
///    path to a regular file drifts, since the write replaces the link, and anything
///    else there that isn't a regular file holds. A `source` whose path didn't resolve,
///    can't be read, or is not a regular file of its own (a link included, which the
///    write's read of it refuses too) holds, before the target's content is judged.
/// 4. The managed mode/owner/group, when the content matches: `Drifted` with the observed
///    triple on a mismatch — or when the path itself is not a regular file, a symbolic
///    link to the right content included — and held
///    when the read found nothing: a managed mode nobody read is not "converged".
#[must_use]
pub fn interpret(
    file: &FileResource,
    path: &str,
    desired: &FileDesired,
    results: &[QueryResult],
) -> FileStep {
    step(file, path, desired, results).unwrap_or_else(FileStep::Done)
}

/// [`interpret`], with every early verdict as the `Err` side.
fn step(
    file: &FileResource,
    path: &str,
    desired: &FileDesired,
    results: &[QueryResult],
) -> Result<FileStep, Detection> {
    let Some(layout) = Reads::of(file, path, desired) else {
        return Err(match desired {
            FileDesired::Unpinned { id } => Detection::Undetermined {
                reason: format!("{}: {path}", unpinned_reason("tracked remote file", id)),
            },
            FileDesired::Unrenderable { reason } => Detection::Undetermined {
                reason: reason.clone(),
            },
            _ => layout_mismatch(),
        });
    };

    if let FileDesired::Extracted { provenance } = desired {
        return extracted(file, path, provenance, &layout, results).map(FileStep::Done);
    }
    if !exists_answer(results, layout.exists)? {
        return Err(Detection::Absent);
    }

    // The SHA-512 a content read at `index` answered, holding `unreadable` when the read
    // found nothing or failed; `None` when what is at the path is no regular file of its
    // own, which opened nothing.
    let digest = |index: Option<usize>, unreadable: String| -> Result<Option<&str>, Detection> {
        let index = index.ok_or_else(layout_mismatch)?;
        match readable_answer(results, index, || unreadable)? {
            PathObservation::Digest(digest) => Ok(Some(digest)),
            PathObservation::NotRegular => Ok(None),
            _ => Err(unexpected_answer(index)),
        }
    };
    // The target's own digest. A link there, to a regular file (what the existence read
    // found), is drift: the write replaces the link with the file. Anything else that
    // isn't a regular file — a directory, a device, a link to one — the write can't
    // replace, so it holds.
    let target = |unreadable: String| -> Result<&str, Detection> {
        digest(layout.content, unreadable)?.ok_or_else(|| {
            if matches!(
                path_answer(results, layout.exists),
                Ok(PathObservation::Kind(FileKind::Regular))
            ) {
                drifted(FileDrift::Content)
            } else {
                Detection::Undetermined {
                    reason: format!("{path} is not a regular file"),
                }
            }
        })
    };

    match desired {
        FileDesired::Unpinned { .. }
        | FileDesired::Unrenderable { .. }
        | FileDesired::Extracted { .. } => Err(layout_mismatch()),
        FileDesired::RemoteUncached { .. } => Ok(FileStep::CompareBytes),
        FileDesired::Rendered { sha512 } | FileDesired::Remote { sha512 } => {
            let remote = matches!(desired, FileDesired::Remote { .. });
            let unreadable = if remote {
                format!("failed to read remote file: {path}")
            } else {
                format!("failed to read file: {path}")
            };
            let observed = target(unreadable)?;
            if observed != sha512 {
                return Err(drifted(if remote {
                    FileDrift::Digest {
                        sha512: observed.to_owned(),
                    }
                } else {
                    FileDrift::Content
                }));
            }
            Ok(FileStep::Done(metadata_verdict(
                file, path, &layout, results,
            )))
        }
        FileDesired::Source { path: source } => {
            let wanted = digest(
                layout.source,
                format!("failed to read the content source: {source}"),
            )?
            .ok_or_else(|| Detection::Undetermined {
                reason: format!(
                    "the content source {source} is not a regular file (a symbolic link \
                     is not read through)"
                ),
            })?;
            let observed = target(format!("failed to read file: {path}"))?;
            if observed != wanted {
                return Err(drifted(FileDrift::Content));
            }
            Ok(FileStep::Done(metadata_verdict(
                file, path, &layout, results,
            )))
        }
        FileDesired::SourceUnresolved { error } => {
            digest(layout.content, format!("failed to read file: {path}"))?;
            Err(Detection::Undetermined {
                reason: format!("failed to resolve source path: {error}"),
            })
        }
    }
}

/// The verdict for an extracted tree (see [`interpret`]).
fn extracted(
    file: &FileResource,
    path: &str,
    provenance: &str,
    layout: &Reads,
    results: &[QueryResult],
) -> Result<Detection, Detection> {
    let refused = |why: &str| Detection::Undetermined {
        reason: format!("{path}: {why}"),
    };
    match path_answer(results, layout.exists)? {
        PathObservation::Failed => return Err(Detection::Absent),
        PathObservation::Metadata(own) => match own.kind {
            FileKind::Directory => {}
            FileKind::Symlink => return Err(refused(LINK_REFUSAL)),
            FileKind::Regular | FileKind::Other => return Err(refused(NOT_A_DIRECTORY_REFUSAL)),
        },
        _ => return Err(unexpected_answer(layout.exists)),
    }
    let marker = layout.marker.ok_or_else(layout_mismatch)?;
    let marked = match path_answer(results, marker)? {
        PathObservation::Metadata(sentinel) => sentinel.kind == FileKind::Regular,
        PathObservation::Failed => false,
        _ => return Err(unexpected_answer(marker)),
    };
    if !marked {
        let index = layout.empty.ok_or_else(layout_mismatch)?;
        return match readable_answer(results, index, || format!("failed to list {path}"))? {
            PathObservation::Empty(true) => Err(Detection::Absent),
            PathObservation::Empty(false) => Err(refused(UNMARKED_REFUSAL)),
            _ => Err(unexpected_answer(index)),
        };
    }
    let index = layout.content.ok_or_else(layout_mismatch)?;
    let (bytes, truncated) = contents_answer(results, index, || {
        format!("failed to read remote sentinel: {}", sentinel_path(path))
    })?;
    let recorded = String::from_utf8_lossy(bytes);
    let recorded = recorded.trim();
    // A truncated sentinel holds more than a digest could, whatever its prefix says.
    if truncated || recorded != provenance {
        return Err(drifted(FileDrift::Provenance {
            observed: recorded.to_owned(),
        }));
    }
    Ok(metadata_verdict(file, path, layout, results))
}

const fn drifted(drift: FileDrift) -> Detection {
    Detection::Drifted {
        current: CurrentState::File { drift },
    }
}

/// The verdict for an uncached `remote` file once the caller has read the target's bytes.
///
/// `desired` is the [`FileDesired::RemoteUncached`] the queries were built from, and
/// `observed` the bytes' blake3, or `None` when the read failed (which holds). A blake3
/// that differs from the pin drifts; one that matches goes on to the metadata.
#[must_use]
pub fn interpret_pin(
    file: &FileResource,
    path: &str,
    desired: &FileDesired,
    observed: Option<&str>,
    results: &[QueryResult],
) -> Detection {
    let (FileDesired::RemoteUncached { pin }, Some(reads)) =
        (desired, Reads::of(file, path, desired))
    else {
        return layout_mismatch();
    };
    match observed {
        None => Detection::Undetermined {
            reason: format!("failed to read remote file: {path}"),
        },
        Some(observed) if observed != pin => drifted(FileDrift::Pin {
            observed: observed.to_owned(),
        }),
        Some(_) => metadata_verdict(file, path, &reads, results),
    }
}

/// The managed mode/owner/group verdict for a file whose content matched.
///
/// `Converged` when nothing is managed or everything matches; `Drifted` with the
/// observed triple on a mismatch, or when the path itself is another kind of thing than
/// the write installs (a symbolic link, whatever it points at); `Undetermined` when the
/// metadata read found nothing — a managed mode nobody read is not "converged".
fn metadata_verdict(
    file: &FileResource,
    path: &str,
    layout: &Reads,
    results: &[QueryResult],
) -> Detection {
    let Some(index) = layout.metadata else {
        return Detection::Converged;
    };
    let observed = match metadata_answer(results, index, path) {
        Ok(observed) => observed,
        Err(held) => return held,
    };
    if observed.kind != layout.kind
        || metadata_mismatch(
            file.mode.as_deref(),
            file.owner.as_deref(),
            file.group.as_deref(),
            observed,
        )
    {
        drifted(FileDrift::Metadata {
            mode: observed.mode.clone(),
            owner: observed.owner.clone(),
            group: observed.group.clone(),
        })
    } else {
        Detection::Converged
    }
}

#[cfg(test)]
mod tests {
    use super::{
        FileDesired, FileStep, SENTINEL_READ_MAX, interpret, interpret_pin, queries, sentinel_path,
    };
    use crate::detected::{CurrentState, Detection, FileDrift};
    use crate::observe::testing::failed;
    use crate::observe::{
        FileKind, Observation, PathFacet, PathMetadata, PathObservation, Privilege, Query,
        QueryError, QueryResult,
    };
    use crate::schema::FileResource;

    fn file(mode: Option<&str>) -> FileResource {
        serde_json::from_value(serde_json::json!({
            "path": "/f", "mode": mode, "content": {"type": "inline", "content": "x"},
        }))
        .unwrap()
    }

    fn sha(c: char) -> String {
        c.to_string().repeat(128)
    }

    fn rendered() -> FileDesired {
        FileDesired::Rendered { sha512: sha('a') }
    }

    #[expect(
        clippy::unnecessary_wraps,
        reason = "builds the answer type `interpret` reads, which is always a `Result`"
    )]
    fn path(observation: PathObservation) -> QueryResult {
        Ok(Observation::Path(observation))
    }

    fn exists() -> QueryResult {
        path(PathObservation::Kind(FileKind::Regular))
    }

    fn digest(c: char) -> QueryResult {
        path(PathObservation::Digest(sha(c)))
    }

    fn metadata(mode: &str) -> QueryResult {
        metadata_of(FileKind::Regular, mode)
    }

    fn metadata_of(kind: FileKind, mode: &str) -> QueryResult {
        path(PathObservation::Metadata(PathMetadata {
            kind,
            mode: mode.to_owned(),
            owner: "root".to_owned(),
            group: "root".to_owned(),
        }))
    }

    fn sentinel(bytes: &[u8], truncated: bool) -> QueryResult {
        path(PathObservation::Contents {
            bytes: bytes.to_vec(),
            truncated,
        })
    }

    /// An extracted tree's answers: the tree's own metadata, its sentinel's, the
    /// sentinel's bytes, and its emptiness.
    fn tree(own: QueryResult, marker: QueryResult, content: QueryResult) -> [QueryResult; 4] {
        [own, marker, content, path(PathObservation::Empty(false))]
    }

    fn a_dir() -> QueryResult {
        metadata_of(FileKind::Directory, "755")
    }

    fn marked() -> QueryResult {
        metadata_of(FileKind::Regular, "644")
    }

    fn done(file: &FileResource, desired: &FileDesired, results: &[QueryResult]) -> Detection {
        match interpret(file, "/f", desired, results) {
            FileStep::Done(detection) => detection,
            FileStep::CompareBytes => panic!("expected a verdict"),
        }
    }

    fn reads(file: &FileResource, desired: &FileDesired) -> Vec<(String, PathFacet)> {
        queries(file, "/f", desired)
            .into_iter()
            .map(|query| match query {
                Query::Path {
                    path,
                    facet,
                    privilege,
                } => {
                    assert_eq!(privilege, Privilege::Elevated);
                    (path, facet)
                }
                Query::Command { .. } => unreachable!(),
            })
            .collect()
    }

    #[test]
    fn every_read_is_elevated_and_metadata_is_read_only_when_managed() {
        let at = |p: &str, facet| (p.to_owned(), facet);
        assert_eq!(
            reads(&file(None), &rendered()),
            [at("/f", PathFacet::Kind), at("/f", PathFacet::Digest)]
        );
        assert_eq!(
            reads(
                &file(Some("644")),
                &FileDesired::Source {
                    path: "/src".to_owned()
                }
            ),
            [
                at("/f", PathFacet::Kind),
                at("/f", PathFacet::Digest),
                at("/src", PathFacet::Digest),
                at("/f", PathFacet::Lstat),
            ]
        );
        assert_eq!(
            reads(
                &file(Some("755")),
                &FileDesired::Extracted {
                    provenance: "p".to_owned()
                }
            ),
            [
                at("/f", PathFacet::Lstat),
                at(&sentinel_path("/f"), PathFacet::Lstat),
                at(
                    &sentinel_path("/f"),
                    PathFacet::Read {
                        max: SENTINEL_READ_MAX
                    }
                ),
                at("/f", PathFacet::Empty),
            ]
        );
        // Unmanaged, the tree's own `Lstat` is still read: its type decides.
        assert_eq!(
            reads(
                &file(None),
                &FileDesired::Extracted {
                    provenance: "p".to_owned()
                }
            )
            .len(),
            4
        );
        assert_eq!(
            reads(
                &file(Some("755")),
                &FileDesired::RemoteUncached {
                    pin: "p".to_owned()
                }
            ),
            [at("/f", PathFacet::Kind), at("/f", PathFacet::Lstat)]
        );
        assert!(
            reads(
                &file(Some("755")),
                &FileDesired::Unpinned { id: "x".to_owned() }
            )
            .is_empty()
        );
    }

    #[test]
    fn an_unpinned_remote_holds_before_reading() {
        assert_eq!(
            done(
                &file(None),
                &FileDesired::Unpinned {
                    id: "blob".to_owned()
                },
                &[]
            ),
            Detection::Undetermined {
                reason: "tracked remote file has no usable pin — run `zap update blob` to mint \
                         or advance it (or declare a `blake3` to vendor it): /f"
                    .to_owned(),
            }
        );
    }

    #[test]
    fn absent_unreadable_differing_and_matching_content() {
        let f = file(None);
        assert_eq!(
            done(&f, &rendered(), &[failed(), failed()]),
            Detection::Absent
        );
        for unreadable in [failed(), Err(QueryError::Exited { code: 2 })] {
            assert_eq!(
                done(&f, &rendered(), &[exists(), unreadable]),
                Detection::Undetermined {
                    reason: "failed to read file: /f".to_owned(),
                }
            );
        }
        assert_eq!(
            done(&f, &rendered(), &[exists(), digest('b')]),
            Detection::Drifted {
                current: CurrentState::File {
                    drift: FileDrift::Content,
                },
            }
        );
        assert_eq!(
            done(&f, &rendered(), &[exists(), digest('a')]),
            Detection::Converged
        );
        // A timeout isn't a read failure: it holds with its own reason.
        assert_eq!(
            done(
                &f,
                &rendered(),
                &[
                    exists(),
                    Err(QueryError::TimedOut {
                        secs: crate::observe::PATH_DIGEST_TIMEOUT
                    })
                ]
            ),
            Detection::Undetermined {
                reason: "detection failed: timed out after 60s".to_owned(),
            }
        );
    }

    #[test]
    fn a_cached_remote_drifts_with_the_observed_sha512() {
        let desired = FileDesired::Remote { sha512: sha('a') };
        assert_eq!(
            done(&file(None), &desired, &[exists(), digest('c')]),
            Detection::Drifted {
                current: CurrentState::File {
                    drift: FileDrift::Digest { sha512: sha('c') },
                },
            }
        );
        assert_eq!(
            done(&file(None), &desired, &[exists(), failed()]),
            Detection::Undetermined {
                reason: "failed to read remote file: /f".to_owned(),
            }
        );
    }

    #[test]
    fn source_content_compares_two_digests_and_holds_on_an_unreadable_source() {
        let desired = FileDesired::Source {
            path: "/src".to_owned(),
        };
        let f = file(None);
        assert_eq!(
            done(&f, &desired, &[exists(), digest('a'), digest('a')]),
            Detection::Converged
        );
        assert!(matches!(
            done(&f, &desired, &[exists(), digest('a'), digest('b')]),
            Detection::Drifted { .. }
        ));
        assert_eq!(
            done(&f, &desired, &[exists(), digest('a'), failed()]),
            Detection::Undetermined {
                reason: "failed to read the content source: /src".to_owned(),
            }
        );
        // The target's own state is established first.
        assert_eq!(
            done(&f, &desired, &[failed(), failed(), failed()]),
            Detection::Absent
        );
        let unresolved = FileDesired::SourceUnresolved {
            error: "no home".to_owned(),
        };
        assert_eq!(
            done(&f, &unresolved, &[exists(), digest('a')]),
            Detection::Undetermined {
                reason: "failed to resolve source path: no home".to_owned(),
            }
        );
        assert_eq!(
            done(&f, &unresolved, &[exists(), failed()]),
            Detection::Undetermined {
                reason: "failed to read file: /f".to_owned(),
            }
        );
    }

    /// A template that couldn't be rendered reads nothing and holds, saying why.
    #[test]
    fn an_unrenderable_template_reads_nothing_and_holds() {
        let desired = FileDesired::Unrenderable {
            reason: "the template was not rendered".to_owned(),
        };
        assert!(queries(&file(Some("644")), "/f", &desired).is_empty());
        assert_eq!(
            done(&file(None), &desired, &[]),
            Detection::Undetermined {
                reason: "the template was not rendered".to_owned(),
            }
        );
    }

    /// A hard-linked file — the target or a `source` — is read by no root read, so the
    /// file holds, saying how to fix it.
    #[test]
    fn a_hard_linked_file_holds_with_the_fix() {
        let hard_linked = || Err(QueryError::HardLinked);
        let held = Detection::Undetermined {
            reason: format!("detection failed: {}", crate::put::HARD_LINK_REFUSAL),
        };
        let f = file(None);
        assert_eq!(done(&f, &rendered(), &[exists(), hard_linked()]), held);
        let source = FileDesired::Source {
            path: "/src".to_owned(),
        };
        assert!(matches!(
            done(&f, &source, &[exists(), digest('a'), hard_linked()]),
            Detection::Undetermined { reason } if reason.contains(crate::put::HARD_LINK_REFUSAL)
        ));
    }

    /// A content read that found no regular file of its own opened nothing. At the
    /// target, a link to a regular file is drift — the write replaces the link — and
    /// anything else (a directory, a device) holds; a `source` that is one holds before
    /// the target is judged, as the write's read of it refuses it.
    #[test]
    fn a_path_that_is_no_regular_file_drifts_or_holds_by_what_the_write_can_do() {
        let not_regular = || path(PathObservation::NotRegular);
        let content = Detection::Drifted {
            current: CurrentState::File {
                drift: FileDrift::Content,
            },
        };
        let f = file(None);
        assert_eq!(done(&f, &rendered(), &[exists(), not_regular()]), content);
        for kind in [FileKind::Directory, FileKind::Other] {
            assert_eq!(
                done(
                    &f,
                    &rendered(),
                    &[path(PathObservation::Kind(kind)), not_regular()]
                ),
                Detection::Undetermined {
                    reason: "/f is not a regular file".to_owned(),
                },
                "{kind:?}"
            );
        }
        let remote = FileDesired::Remote { sha512: sha('a') };
        assert_eq!(done(&f, &remote, &[exists(), not_regular()]), content);
        let source = FileDesired::Source {
            path: "/src".to_owned(),
        };
        assert_eq!(
            done(&f, &source, &[exists(), not_regular(), digest('a')]),
            content
        );
        let source_refused = Detection::Undetermined {
            reason: "the content source /src is not a regular file (a symbolic link is not \
                     read through)"
                .to_owned(),
        };
        for target in [digest('a'), not_regular(), failed()] {
            assert_eq!(
                done(&f, &source, &[exists(), target.clone(), not_regular()]),
                source_refused,
                "{target:?}"
            );
        }
    }

    #[test]
    fn the_sentinel_compares_trimmed_and_a_truncated_one_drifts() {
        let pin = "p".repeat(64);
        let desired = FileDesired::Extracted {
            provenance: pin.clone(),
        };
        let f = file(None);
        assert_eq!(
            done(&f, &desired, &tree(failed(), failed(), failed())),
            Detection::Absent
        );
        assert_eq!(
            done(
                &f,
                &desired,
                &tree(
                    a_dir(),
                    marked(),
                    sentinel(format!("{pin}\n\n").as_bytes(), false)
                )
            ),
            Detection::Converged
        );
        assert_eq!(
            done(
                &f,
                &desired,
                &tree(a_dir(), marked(), sentinel(b"other\n", false))
            ),
            Detection::Drifted {
                current: CurrentState::File {
                    drift: FileDrift::Provenance {
                        observed: "other".to_owned(),
                    },
                },
            }
        );
        assert_eq!(
            done(
                &f,
                &desired,
                &tree(a_dir(), marked(), sentinel(pin.as_bytes(), true))
            ),
            Detection::Drifted {
                current: CurrentState::File {
                    drift: FileDrift::Provenance { observed: pin },
                },
            }
        );
        assert_eq!(
            done(&f, &desired, &tree(a_dir(), marked(), failed())),
            Detection::Undetermined {
                reason: "failed to read remote sentinel: /f/.zap_remote_hash".to_owned(),
            }
        );
    }

    /// A tree is read as the extract script treats it, so what the plan offers the wetrun
    /// does: a tree with no sentinel — none there, or a link or a directory at its name,
    /// which the script doesn't take for one — is replaced only when empty, and held
    /// otherwise, as a link or a file at the tree's own path is, with the script's reason.
    #[test]
    fn an_unmarked_tree_is_absent_only_when_empty_and_held_otherwise() {
        let desired = FileDesired::Extracted {
            provenance: "p".repeat(64),
        };
        let f = file(None);
        let held = |why: &str| Detection::Undetermined {
            reason: format!("/f: {why}"),
        };
        let unmarked = [
            failed(),
            metadata_of(FileKind::Symlink, "777"),
            metadata_of(FileKind::Directory, "755"),
        ];
        for marker in unmarked {
            let [own, marker, content, _] = tree(a_dir(), marker, sentinel(b"p", false));
            assert_eq!(
                done(
                    &f,
                    &desired,
                    &[
                        own.clone(),
                        marker.clone(),
                        content.clone(),
                        path(PathObservation::Empty(true))
                    ]
                ),
                Detection::Absent,
                "{marker:?}"
            );
            assert_eq!(
                done(
                    &f,
                    &desired,
                    &[
                        own.clone(),
                        marker.clone(),
                        content.clone(),
                        path(PathObservation::Empty(false))
                    ]
                ),
                held(crate::extract::UNMARKED_REFUSAL),
                "{marker:?}"
            );
            for unlisted in [failed(), Err(QueryError::Exited { code: 2 })] {
                assert_eq!(
                    done(
                        &f,
                        &desired,
                        &[own.clone(), marker.clone(), content.clone(), unlisted]
                    ),
                    Detection::Undetermined {
                        reason: "failed to list /f".to_owned(),
                    },
                    "{marker:?}"
                );
            }
        }
        // The tree's own path: never followed, never anything but a directory.
        for (kind, why) in [
            (FileKind::Symlink, crate::extract::LINK_REFUSAL),
            (FileKind::Regular, crate::extract::NOT_A_DIRECTORY_REFUSAL),
            (FileKind::Other, crate::extract::NOT_A_DIRECTORY_REFUSAL),
        ] {
            assert_eq!(
                done(
                    &f,
                    &desired,
                    &tree(metadata_of(kind, "755"), marked(), sentinel(b"p", false))
                ),
                held(why),
                "{kind:?}"
            );
        }
    }

    #[test]
    fn metadata_is_checked_after_matching_content_for_every_variant() {
        let f = file(Some("644"));
        assert_eq!(
            done(&f, &rendered(), &[exists(), digest('a'), metadata("600")]),
            Detection::Drifted {
                current: CurrentState::File {
                    drift: FileDrift::Metadata {
                        mode: "600".to_owned(),
                        owner: "root".to_owned(),
                        group: "root".to_owned(),
                    },
                },
            }
        );
        assert_eq!(
            done(&f, &rendered(), &[exists(), digest('a'), failed()]),
            Detection::Undetermined {
                reason: "failed to read the mode/owner/group of /f".to_owned(),
            }
        );
        // Content drift wins; the metadata isn't consulted.
        assert_eq!(
            done(&f, &rendered(), &[exists(), digest('b'), failed()]),
            Detection::Drifted {
                current: CurrentState::File {
                    drift: FileDrift::Content,
                },
            }
        );
        let pin = "p".repeat(64);
        assert_eq!(
            done(
                &f,
                &FileDesired::Extracted {
                    provenance: pin.clone(),
                },
                &tree(
                    metadata_of(FileKind::Directory, "644"),
                    marked(),
                    sentinel(pin.as_bytes(), false)
                )
            ),
            Detection::Converged
        );
        assert_eq!(
            done(
                &f,
                &FileDesired::Extracted {
                    provenance: pin.clone(),
                },
                &tree(
                    metadata_of(FileKind::Directory, "755"),
                    marked(),
                    sentinel(pin.as_bytes(), false)
                )
            ),
            Detection::Drifted {
                current: CurrentState::File {
                    drift: FileDrift::Metadata {
                        mode: "755".to_owned(),
                        owner: "root".to_owned(),
                        group: "root".to_owned(),
                    },
                },
            }
        );
    }

    #[test]
    fn a_path_that_is_not_the_kind_a_write_installs_drifts_whatever_its_mode() {
        // The content read follows a link, so a link to the declared bytes matches on
        // content; the path's own metadata says what is really there. A write installs
        // a regular file, so anything else drifts even when the mode and owner read as
        // declared. (An extracted tree's path that isn't a directory holds: see
        // `an_unmarked_tree_is_absent_only_when_empty_and_held_otherwise`.)
        let drift = |mode: &str| Detection::Drifted {
            current: CurrentState::File {
                drift: FileDrift::Metadata {
                    mode: mode.to_owned(),
                    owner: "root".to_owned(),
                    group: "root".to_owned(),
                },
            },
        };
        for (declared, kind) in [("777", FileKind::Symlink), ("644", FileKind::Directory)] {
            let f = file(Some(declared));
            assert_eq!(
                done(
                    &f,
                    &rendered(),
                    &[exists(), digest('a'), metadata_of(kind, declared)]
                ),
                drift(declared),
                "{kind:?}"
            );
        }
    }

    #[test]
    fn an_uncached_remote_asks_for_the_bytes_then_compares_the_pin() {
        let f = file(Some("644"));
        let desired = FileDesired::RemoteUncached {
            pin: "p".to_owned(),
        };
        let results = [exists(), metadata("600")];
        assert_eq!(
            interpret(&f, "/f", &desired, &results),
            FileStep::CompareBytes
        );
        assert_eq!(
            interpret(&f, "/f", &desired, &[failed(), failed()]),
            FileStep::Done(Detection::Absent)
        );
        assert_eq!(
            interpret_pin(&f, "/f", &desired, Some("q"), &results),
            Detection::Drifted {
                current: CurrentState::File {
                    drift: FileDrift::Pin {
                        observed: "q".to_owned(),
                    },
                },
            }
        );
        assert!(matches!(
            interpret_pin(&f, "/f", &desired, Some("p"), &results),
            Detection::Drifted {
                current: CurrentState::File {
                    drift: FileDrift::Metadata { .. }
                }
            }
        ));
        assert_eq!(
            interpret_pin(&f, "/f", &desired, None, &results),
            Detection::Undetermined {
                reason: "failed to read remote file: /f".to_owned(),
            }
        );
    }

    #[test]
    fn an_unanswered_existence_read_holds() {
        assert_eq!(
            done(
                &file(None),
                &rendered(),
                &[Err(QueryError::Exited { code: 127 }), digest('a')]
            ),
            Detection::Undetermined {
                reason: "detection failed: the probe exited 127".to_owned(),
            }
        );
        assert!(matches!(
            done(&file(None), &rendered(), &[]),
            Detection::Undetermined { .. }
        ));
    }
}
