//! `installer` — installed or not, by whether its `check` path exists.

use super::{PathFacet, Privilege, Query, QueryResult, exists_answer};
use crate::detected::Detection;

/// Index of the one read in [`queries`].
const EXISTS: usize = 0;

/// An installer's one read: the [`Kind`](PathFacet::Kind) of its resolved `check` path,
/// at [`Elevated`](Privilege::Elevated) (`test -e` semantics, as zap's own reads of a
/// path run).
#[must_use]
pub fn queries(check: &str) -> Vec<Query> {
    vec![Query::path(check, PathFacet::Kind, Privilege::Elevated)]
}

/// The verdict for an installer: `Converged` when the check path exists, `Absent` when
/// the read finds nothing. It never drifts.
#[must_use]
pub fn interpret(results: &[QueryResult]) -> Detection {
    match exists_answer(results, EXISTS) {
        Ok(true) => Detection::Converged,
        Ok(false) => Detection::Absent,
        Err(held) => held,
    }
}

#[cfg(test)]
mod tests {
    use super::{interpret, queries};
    use crate::detected::Detection;
    use crate::observe::{FileKind, Observation, PathObservation, Privilege, QueryError};

    #[test]
    fn reads_the_check_path_elevated() {
        assert_eq!(queries("/opt/x")[0].privilege(), Privilege::Elevated);
    }

    #[test]
    fn existence_is_the_verdict() {
        assert_eq!(
            interpret(&[Ok(Observation::Path(PathObservation::Kind(
                FileKind::Regular
            )))]),
            Detection::Converged
        );
        assert_eq!(
            interpret(&[Ok(Observation::Path(PathObservation::Failed))]),
            Detection::Absent
        );
        assert!(matches!(
            interpret(&[Err(QueryError::Exited { code: 2 })]),
            Detection::Undetermined { .. }
        ));
    }
}
