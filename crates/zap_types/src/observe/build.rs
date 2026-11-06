//! `build` — the provenance digest recorded in the output's sidecar
//! (`<output>.zap-build`) against the desired one.
//!
//! The digest is [`build_provenance`](crate::config_hash::build_provenance) over the
//! source pin (the declared, vendored `blake3`, else the lock's) and how the source is
//! built — the extract strategy, `run`, `cwd`, and `env`. The sidecar is what stops a
//! source-version bump or an edit to how it builds from reading the stale artifact as
//! converged (a bare existence check of the output would).

use super::{
    PathFacet, Privilege, Query, QueryResult, contents_answer, exists_answer, unpinned_reason,
};
use crate::detected::{CurrentState, Detection};

/// The suffix of an output's provenance sidecar, which records its provenance digest.
pub const SIDECAR_SUFFIX: &str = ".zap-build";

/// The most bytes of a sidecar detection reads. A digest is 64 hex digits; a sidecar
/// longer than this can't record one.
pub const SIDECAR_READ_MAX: u32 = 4096;

/// Index of the output's existence read in [`queries`].
const OUTPUT: usize = 0;
/// Index of the sidecar's existence read in [`queries`].
const SIDECAR: usize = 1;
/// Index of the sidecar's content read in [`queries`].
const RECORDED: usize = 2;

/// What a build is compared against.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BuildDesired {
    /// A pinned source: the sidecar must record this provenance digest.
    Pinned {
        /// The [`build_provenance`](crate::config_hash::build_provenance) digest.
        provenance: String,
    },
    /// A tracked source with no usable pin — held before anything is read.
    Unpinned {
        /// The resource id, for the `zap update` hint.
        id: String,
    },
}

/// The sidecar path of the build output at `output`.
#[must_use]
pub fn sidecar_path(output: &str) -> String {
    format!("{output}{SIDECAR_SUFFIX}")
}

/// A build's reads, for its resolved `output`, in order — all at
/// [`Elevated`](Privilege::Elevated):
///
/// - the output's and the sidecar's existence ([`Kind`](PathFacet::Kind), `test -e`
///   semantics);
/// - the sidecar's content — at most [`SIDECAR_READ_MAX`] bytes.
///
/// Nothing for a build with no pin.
#[must_use]
pub fn queries(output: &str, desired: &BuildDesired) -> Vec<Query> {
    match desired {
        BuildDesired::Unpinned { .. } => Vec::new(),
        BuildDesired::Pinned { .. } => {
            let sidecar = sidecar_path(output);
            vec![
                Query::path(output, PathFacet::Kind, Privilege::Elevated),
                Query::path(&sidecar, PathFacet::Kind, Privilege::Elevated),
                Query::path(
                    &sidecar,
                    PathFacet::Read {
                        max: SIDECAR_READ_MAX,
                    },
                    Privilege::Elevated,
                ),
            ]
        }
    }
}

/// The verdict for a build from the answers to [`queries`]:
///
/// 1. No usable pin holds (`zap update` mints or advances it).
/// 2. No output, or an output with no sidecar, → `Absent` ((re)build).
/// 3. A sidecar that can't be read holds.
/// 4. The recorded digest (surrounding whitespace trimmed, as it is written) equal to
///    the desired one converges; any other drifts with what it records — a sidecar
///    longer than [`SIDECAR_READ_MAX`] included.
#[must_use]
pub fn interpret(output: &str, desired: &BuildDesired, results: &[QueryResult]) -> Detection {
    verdict(output, desired, results).unwrap_or_else(|held| held)
}

/// [`interpret`], with every early verdict as the `Err` side.
fn verdict(
    output: &str,
    desired: &BuildDesired,
    results: &[QueryResult],
) -> Result<Detection, Detection> {
    let provenance = match desired {
        BuildDesired::Pinned { provenance } => provenance,
        BuildDesired::Unpinned { id } => {
            return Err(Detection::Undetermined {
                reason: unpinned_reason("build source", id),
            });
        }
    };
    if !exists_answer(results, OUTPUT)? || !exists_answer(results, SIDECAR)? {
        return Ok(Detection::Absent);
    }
    let (bytes, truncated) = contents_answer(results, RECORDED, || {
        format!("failed to read build provenance: {}", sidecar_path(output))
    })?;
    let recorded = String::from_utf8_lossy(bytes);
    let recorded = recorded.trim();
    Ok(if !truncated && recorded == provenance {
        Detection::Converged
    } else {
        // A provenance drift: the before-state is the sidecar's recorded digest.
        Detection::Drifted {
            current: CurrentState::Build {
                observed: recorded.to_owned(),
            },
        }
    })
}

#[cfg(test)]
mod tests {
    use super::{BuildDesired, SIDECAR_READ_MAX, interpret, queries};
    use crate::detected::{CurrentState, Detection};
    use crate::observe::testing::{contents, exists};
    use crate::observe::{
        Observation, PathFacet, PathObservation, Privilege, Query, QueryError, QueryResult,
    };

    fn pinned() -> BuildDesired {
        BuildDesired::Pinned {
            provenance: "ab".repeat(32),
        }
    }

    #[test]
    fn reads_the_output_and_its_sidecar_elevated() {
        assert_eq!(
            queries("/o", &pinned()),
            [
                Query::path("/o", PathFacet::Kind, Privilege::Elevated),
                Query::path("/o.zap-build", PathFacet::Kind, Privilege::Elevated),
                Query::path(
                    "/o.zap-build",
                    PathFacet::Read {
                        max: SIDECAR_READ_MAX
                    },
                    Privilege::Elevated
                ),
            ]
        );
    }

    #[test]
    fn compares_the_recorded_provenance() {
        let pin = "ab".repeat(32);
        let unanswered: QueryResult = Err(QueryError::Unrecorded);
        assert_eq!(
            interpret(
                "/o",
                &pinned(),
                &[exists(false), unanswered.clone(), unanswered.clone()]
            ),
            Detection::Absent
        );
        assert_eq!(
            interpret("/o", &pinned(), &[exists(true), exists(false), unanswered]),
            Detection::Absent
        );
        assert_eq!(
            interpret(
                "/o",
                &pinned(),
                &[
                    exists(true),
                    exists(true),
                    contents(&format!("{pin}\n"), false)
                ]
            ),
            Detection::Converged
        );
        assert_eq!(
            interpret(
                "/o",
                &pinned(),
                &[exists(true), exists(true), contents("00", false)]
            ),
            Detection::Drifted {
                current: CurrentState::Build {
                    observed: "00".to_owned()
                }
            }
        );
        // A sidecar past the read bound records more than a digest, whatever its prefix.
        assert_eq!(
            interpret(
                "/o",
                &pinned(),
                &[exists(true), exists(true), contents(&pin, true)]
            ),
            Detection::Drifted {
                current: CurrentState::Build { observed: pin }
            }
        );
    }

    #[test]
    fn an_unreadable_sidecar_or_a_missing_pin_holds() {
        assert_eq!(
            interpret(
                "/o",
                &pinned(),
                &[
                    exists(true),
                    exists(true),
                    Ok(Observation::Path(PathObservation::Failed))
                ]
            ),
            Detection::Undetermined {
                reason: "failed to read build provenance: /o.zap-build".to_owned()
            }
        );
        let unpinned = BuildDesired::Unpinned { id: "b".to_owned() };
        assert!(queries("/o", &unpinned).is_empty());
        assert!(matches!(
            interpret("/o", &unpinned, &[]),
            Detection::Undetermined { reason } if reason.contains("zap update b")
        ));
    }
}
