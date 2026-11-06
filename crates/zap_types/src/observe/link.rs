//! `link` — the symlink's target against the desired one.

use super::{
    PathFacet, PathObservation, Privilege, Query, QueryResult, path_answer, unexpected_answer,
};
use crate::detected::{CurrentState, Detection};

/// Index of the target read in [`queries`].
const TARGET: usize = 0;

/// A link's one read: the [`LinkTarget`](PathFacet::LinkTarget) of its resolved
/// `path`, at [`Login`](Privilege::Login).
#[must_use]
pub fn queries(path: &str) -> Vec<Query> {
    vec![Query::Path {
        path: path.to_owned(),
        facet: PathFacet::LinkTarget,
        privilege: Privilege::Login,
    }]
}

/// The verdict for a link from the answers to [`queries`].
///
/// A target whose bytes are the desired one's converges; any other drifts, one that
/// differs only by a blank or a newline included (` /srv/app` is a relative path, and
/// `readlink`'s one line break is already off the answer). A read that finds nothing —
/// no symlink there, or one the connecting user can't reach — is `Absent`.
#[must_use]
pub fn interpret(target: &str, results: &[QueryResult]) -> Detection {
    match path_answer(results, TARGET) {
        Ok(PathObservation::LinkTarget(bytes)) => {
            if bytes.as_slice() == target.as_bytes() {
                Detection::Converged
            } else {
                Detection::Drifted {
                    current: CurrentState::Link {
                        points_to: String::from_utf8_lossy(bytes).into_owned(),
                    },
                }
            }
        }
        Ok(PathObservation::Failed) => Detection::Absent,
        Ok(
            PathObservation::Kind(_)
            | PathObservation::Metadata(_)
            | PathObservation::Digest(_)
            | PathObservation::Contents { .. }
            | PathObservation::Empty(_)
            | PathObservation::NotRegular,
        ) => unexpected_answer(TARGET),
        Err(held) => held,
    }
}

#[cfg(test)]
mod tests {
    use super::{interpret, queries};
    use crate::detected::{CurrentState, Detection};
    use crate::observe::{Observation, PathObservation, Privilege, QueryError, QueryResult};

    // Builds the answer type `interpret` reads, which is always a `Result`.
    #[allow(clippy::unnecessary_wraps)]
    fn target(bytes: &[u8]) -> QueryResult {
        Ok(Observation::Path(PathObservation::LinkTarget(
            bytes.to_vec(),
        )))
    }

    #[test]
    fn reads_as_the_login_user() {
        assert_eq!(queries("/l")[0].privilege(), Privilege::Login);
    }

    #[test]
    fn compares_the_target() {
        assert_eq!(interpret("/a b", &[target(b"/a b")]), Detection::Converged);
        assert_eq!(
            interpret("/a", &[target(b"/b")]),
            Detection::Drifted {
                current: CurrentState::Link {
                    points_to: "/b".to_owned(),
                },
            }
        );
    }

    /// A link is its target's bytes: one that differs from the declared target only by
    /// a blank or a line break is another link, and a target that really ends in a
    /// blank converges when that is the target declared.
    #[test]
    fn a_target_differing_only_in_blanks_drifts() {
        for bytes in [
            &b" /srv/app/v1"[..],
            b"/srv/app/v1 ",
            b"/srv/app/v1\n",
            b"/srv/app/v1\t",
            b"\n/srv/app/v1",
        ] {
            assert_eq!(
                interpret("/srv/app/v1", &[target(bytes)]),
                Detection::Drifted {
                    current: CurrentState::Link {
                        points_to: String::from_utf8_lossy(bytes).into_owned(),
                    },
                },
                "{bytes:?}"
            );
        }
        assert_eq!(
            interpret("/srv/app/v1 ", &[target(b"/srv/app/v1 ")]),
            Detection::Converged
        );
        assert!(matches!(
            interpret("/srv/app/v1 ", &[target(b"/srv/app/v1")]),
            Detection::Drifted { .. }
        ));
    }

    #[test]
    fn a_failed_read_is_absent_and_an_unanswered_one_holds() {
        assert_eq!(
            interpret("/a", &[Ok(Observation::Path(PathObservation::Failed))]),
            Detection::Absent
        );
        for error in [QueryError::Exited { code: 126 }, QueryError::Unparseable] {
            assert!(matches!(
                interpret("/a", &[Err(error)]),
                Detection::Undetermined { .. }
            ));
        }
    }
}
