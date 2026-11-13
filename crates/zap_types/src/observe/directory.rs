//! `directory` — existence, then the managed mode/owner/group.

use super::{
    FileKind, PathFacet, PathObservation, Privilege, Query, QueryResult, metadata_answer,
    metadata_mismatch, path_answer, unexpected_answer,
};
use crate::detected::{CurrentState, Detection};
use crate::schema::DirectoryResource;

/// Index of the existence read in [`queries`].
const EXISTS: usize = 0;
/// Index of the metadata read in [`queries`], present only when metadata is managed.
const METADATA: usize = 1;

/// Whether any of mode/owner/group is managed — the only case the metadata is read.
const fn manages_metadata(dir: &DirectoryResource) -> bool {
    dir.mode.is_some() || dir.owner.is_some() || dir.group.is_some()
}

/// A directory's reads, for its resolved `path`:
///
/// - existence — the [`Kind`](PathFacet::Kind) of what `path` resolves to, at
///   [`Login`](Privilege::Login): `test -d` semantics, following a symlink, reading no
///   names, and finding nothing where the connecting user can't traverse to the path;
/// - when mode, owner, or group is managed, the path's own
///   [`Lstat`](PathFacet::Lstat), at [`Elevated`](Privilege::Elevated), so a directory
///   under a root-only parent still has readable metadata once it exists.
#[must_use]
pub fn queries(dir: &DirectoryResource, path: &str) -> Vec<Query> {
    let mut queries = vec![Query::Path {
        path: path.to_owned(),
        facet: PathFacet::Kind,
        privilege: Privilege::Login,
    }];
    if manages_metadata(dir) {
        queries.push(Query::Path {
            path: path.to_owned(),
            facet: PathFacet::Lstat,
            privilege: Privilege::Elevated,
        });
    }
    queries
}

/// The verdict for a directory from the answers to [`queries`].
///
/// Not a directory (or not reachable) → `Absent`. With nothing managed, existence is
/// the whole desired state → `Converged`. Otherwise the metadata decides: managed
/// attributes that differ drift — as does a path that is itself a symbolic link to a
/// directory, whose mode and owner execution refuses to set through the link — and
/// metadata the read found nothing for is `Undetermined`: "converged" would be a claim
/// about a mode nobody read.
#[must_use]
pub fn interpret(dir: &DirectoryResource, path: &str, results: &[QueryResult]) -> Detection {
    let exists = match path_answer(results, EXISTS) {
        Ok(PathObservation::Kind(kind)) => *kind == FileKind::Directory,
        Ok(PathObservation::Failed) => false,
        Ok(
            PathObservation::Metadata(_)
            | PathObservation::LinkTarget(_)
            | PathObservation::Digest(_)
            | PathObservation::Contents { .. }
            | PathObservation::Empty(_)
            | PathObservation::NotRegular,
        ) => {
            return unexpected_answer(EXISTS);
        }
        Err(held) => return held,
    };
    if !exists {
        return Detection::Absent;
    }
    if !manages_metadata(dir) {
        return Detection::Converged;
    }

    let observed = match metadata_answer(results, METADATA, path) {
        Ok(observed) => observed,
        Err(held) => return held,
    };
    if observed.kind != FileKind::Directory
        || metadata_mismatch(
            dir.mode.as_deref(),
            dir.owner.as_deref(),
            dir.group.as_deref(),
            observed,
        )
    {
        Detection::Drifted {
            current: CurrentState::Directory {
                mode: observed.mode.clone(),
                owner: observed.owner.clone(),
                group: observed.group.clone(),
            },
        }
    } else {
        Detection::Converged
    }
}

#[cfg(test)]
mod tests {
    use super::{interpret, queries};
    use crate::detected::{CurrentState, Detection};
    use crate::observe::testing::failed;
    use crate::observe::{
        FileKind, Observation, PathFacet, PathMetadata, PathObservation, Privilege, Query,
        QueryError, QueryResult,
    };
    use crate::schema::DirectoryResource;

    fn dir(mode: Option<&str>) -> DirectoryResource {
        serde_json::from_value(serde_json::json!({"path": "/d", "mode": mode})).unwrap()
    }

    #[expect(
        clippy::unnecessary_wraps,
        reason = "builds the answer type `interpret` reads, which is always a `Result`"
    )]
    fn kind(kind: FileKind) -> QueryResult {
        Ok(Observation::Path(PathObservation::Kind(kind)))
    }

    #[expect(
        clippy::unnecessary_wraps,
        reason = "builds the answer type `interpret` reads, which is always a `Result`"
    )]
    fn metadata(kind: FileKind, mode: &str) -> QueryResult {
        Ok(Observation::Path(PathObservation::Metadata(PathMetadata {
            kind,
            mode: mode.to_owned(),
            owner: "root".to_owned(),
            group: "root".to_owned(),
        })))
    }

    #[test]
    fn existence_reads_as_the_login_user_and_managed_metadata_elevated() {
        let reads = |dir: &DirectoryResource| -> Vec<(PathFacet, Privilege)> {
            queries(dir, "/d")
                .iter()
                .map(|query| match query {
                    Query::Path {
                        facet, privilege, ..
                    } => (*facet, *privilege),
                    Query::Command { .. } => unreachable!(),
                })
                .collect()
        };
        assert_eq!(
            reads(&dir(Some("755"))),
            [
                (PathFacet::Kind, Privilege::Login),
                (PathFacet::Lstat, Privilege::Elevated)
            ]
        );
        // Nothing managed: existence is the whole question, so metadata isn't read.
        assert_eq!(reads(&dir(None)), [(PathFacet::Kind, Privilege::Login)]);
    }

    #[test]
    fn a_missing_or_non_directory_path_is_absent_whatever_the_metadata_says() {
        let timed_out = Err(QueryError::TimedOut {
            secs: crate::observe::PATH_TIMEOUT,
        });
        for exists in [failed(), kind(FileKind::Regular)] {
            assert_eq!(
                interpret(&dir(Some("755")), "/d", &[exists, timed_out.clone()]),
                Detection::Absent
            );
        }
    }

    #[test]
    fn an_unmanaged_directory_converges_on_existence() {
        assert_eq!(
            interpret(&dir(None), "/d", &[kind(FileKind::Directory)]),
            Detection::Converged
        );
    }

    #[test]
    fn managed_metadata_converges_or_drifts() {
        let exists = kind(FileKind::Directory);
        assert_eq!(
            interpret(
                &dir(Some("0755")),
                "/d",
                &[exists.clone(), metadata(FileKind::Directory, "755")]
            ),
            Detection::Converged
        );
        assert_eq!(
            interpret(
                &dir(Some("755")),
                "/d",
                &[exists, metadata(FileKind::Symlink, "777")]
            ),
            Detection::Drifted {
                current: CurrentState::Directory {
                    mode: "777".to_owned(),
                    owner: "root".to_owned(),
                    group: "root".to_owned(),
                },
            }
        );
        // A link whose own mode happens to be the declared one is still not the
        // directory: its mode is never what a `chmod` of the path would have set.
        assert!(matches!(
            interpret(
                &dir(Some("777")),
                "/d",
                &[
                    kind(FileKind::Directory),
                    metadata(FileKind::Symlink, "777")
                ]
            ),
            Detection::Drifted { .. }
        ));
    }

    #[test]
    fn managed_metadata_that_reads_nothing_holds() {
        assert_eq!(
            interpret(
                &dir(Some("755")),
                "/d",
                &[kind(FileKind::Directory), failed()]
            ),
            Detection::Undetermined {
                reason: "failed to read the mode/owner/group of /d".to_owned(),
            }
        );
    }

    #[test]
    fn an_unanswered_or_mismatched_query_it_needs_holds() {
        let unparseable: QueryResult = Err(QueryError::Unparseable);
        assert_eq!(
            interpret(&dir(None), "/d", &[Err(QueryError::Exited { code: 127 })]),
            Detection::Undetermined {
                reason: "detection failed: the probe exited 127".to_owned(),
            }
        );
        for results in [
            vec![kind(FileKind::Directory), unparseable],
            vec![metadata(FileKind::Directory, "755")],
            vec![kind(FileKind::Directory)],
            vec![],
        ] {
            assert!(
                matches!(
                    interpret(&dir(Some("755")), "/d", &results),
                    Detection::Undetermined { .. }
                ),
                "{results:?}"
            );
        }
    }
}
