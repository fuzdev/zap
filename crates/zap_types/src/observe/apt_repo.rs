//! `apt_repo` — the signing key is its pin's bytes, and the sources `.list` exists and
//! holds the desired source line (with `signed-by` injected and `/etc/os-release`
//! variables expanded on the target).

use super::{
    CommandObservation, Observation, PathFacet, PathObservation, Privilege, Query, QueryError,
    QueryResult, command_answer, contents_answer, exists_answer,
};
use crate::detected::{AptRepoDrift, CurrentState, Detection};
use crate::scalar::ContentHash;
use crate::schema::{
    AptRepoResource, apt_keyring_path, apt_source_command, apt_sources_list_path, inject_signed_by,
};

/// The most bytes of a sources `.list` detection reads. The desired content is one
/// source line; a list longer than this can't hold only that line.
pub const LIST_READ_MAX: u32 = 64 * 1024;

/// The most bytes of a signing key detection reads. An armored or binary `OpenPGP`
/// public key is a few KiB; a key past this can't be compared against its pin, and
/// holds.
pub const KEY_READ_MAX: u32 = 1024 * 1024;

/// Why a key path that holds a symbolic link, a hard-linked file, or anything but a
/// regular file holds.
pub const NOT_SINGLE_LINK: &str = "the signing key path is not a single-link regular file \
     (a symbolic link, a hard link, or another kind of file): its bytes are not read";

/// Index of the key's existence read in [`queries`].
const KEY: usize = 0;
/// Index of the key's content read in [`queries`].
const KEY_CONTENT: usize = 1;
/// Index of the list's existence read in [`queries`].
const LIST: usize = 2;
/// Index of the list's content read in [`queries`].
const CONTENT: usize = 3;
/// Index of the source-line resolution in [`queries`].
const SOURCE: usize = 4;

/// The key and list paths of `repo` (declared `id`): the declared ones, else the defaults
/// under the keyring and sources directories. Used verbatim, as execution writes them.
#[must_use]
pub fn paths(id: &str, repo: &AptRepoResource) -> (String, String) {
    (
        repo.key_path
            .clone()
            .unwrap_or_else(|| apt_keyring_path(id)),
        repo.list_file
            .clone()
            .unwrap_or_else(|| apt_sources_list_path(id)),
    )
}

/// An `apt_repo`'s reads, for its resource `id`, in order:
///
/// - the key's existence — its [`Kind`](PathFacet::Kind), at
///   [`Elevated`](Privilege::Elevated) (`test -e` semantics) — and its content, at most
///   [`KEY_READ_MAX`] bytes, at `Elevated`;
/// - the list's existence, and its content, at most [`LIST_READ_MAX`] bytes, both at
///   `Elevated`;
/// - the desired source line, resolved on the target ([`apt_source_command`]), a
///   [`Query::login_command`].
#[must_use]
pub fn queries(id: &str, repo: &AptRepoResource) -> Vec<Query> {
    let (key, list) = paths(id, repo);
    vec![
        Query::path(&key, PathFacet::Kind, Privilege::Elevated),
        Query::path(
            &key,
            PathFacet::Read { max: KEY_READ_MAX },
            Privilege::Elevated,
        ),
        Query::path(&list, PathFacet::Kind, Privilege::Elevated),
        Query::path(
            &list,
            PathFacet::Read { max: LIST_READ_MAX },
            Privilege::Elevated,
        ),
        Query::login_command(apt_source_command(&inject_signed_by(&repo.source, &key))),
    ]
}

/// The verdict for the `apt_repo` declared `id`, whose key must be the bytes `pin` names
/// (its declared `key_blake3`, else its lock pin), from the answers to [`queries`], in
/// order:
///
/// 1. No pin holds: there is nothing to compare the key against.
/// 2. No key → `Absent` (the repo needs setting up).
/// 3. A key path that isn't a single-link regular file ([`NOT_SINGLE_LINK`]), a key that
///    can't be read, or one past [`KEY_READ_MAX`], holds; one whose blake3 isn't `pin` →
///    `Drifted` (`KeyDiffers`).
/// 4. No list → `Drifted` (`ListMissing`).
/// 5. A list that can't be read, or a source line that doesn't resolve, holds.
/// 6. The list's content against the resolved line, each with surrounding whitespace
///    trimmed: equal converges, anything else drifts (`ListContentDiffers`) — a list
///    longer than [`LIST_READ_MAX`] included.
#[must_use]
pub fn interpret(id: &str, pin: Option<&ContentHash>, results: &[QueryResult]) -> Detection {
    verdict(id, pin, results).unwrap_or_else(|held| held)
}

/// [`interpret`], with every early verdict as the `Err` side.
fn verdict(
    id: &str,
    pin: Option<&ContentHash>,
    results: &[QueryResult],
) -> Result<Detection, Detection> {
    let Some(pin) = pin else {
        return Err(Detection::Undetermined {
            reason: format!(
                "tracked signing key has no usable pin — run `zap update {id}` to mint or \
                 advance it (or declare a `key_blake3` to vendor it)"
            ),
        });
    };
    if !exists_answer(results, KEY)? {
        return Ok(Detection::Absent);
    }
    // A link at the key path, or a key file linked elsewhere too, is not the key's own
    // file: it is not read, and holds by saying so.
    if matches!(
        results.get(KEY_CONTENT),
        Some(Ok(Observation::Path(PathObservation::NotRegular)) | Err(QueryError::HardLinked))
    ) {
        return Err(Detection::Undetermined {
            reason: NOT_SINGLE_LINK.to_owned(),
        });
    }
    let (key, truncated) = contents_answer(results, KEY_CONTENT, || {
        "failed to read signing key".to_owned()
    })?;
    if truncated {
        return Err(Detection::Undetermined {
            reason: format!(
                "the signing key is larger than {KEY_READ_MAX} bytes, so it can't be compared \
                 against its pin"
            ),
        });
    }
    if ContentHash::of_bytes(key) != *pin {
        return Ok(drifted(AptRepoDrift::KeyDiffers));
    }
    if !exists_answer(results, LIST)? {
        return Ok(drifted(AptRepoDrift::ListMissing));
    }
    let (bytes, truncated) =
        contents_answer(results, CONTENT, || "failed to read list file".to_owned())?;
    let resolved: &CommandObservation = command_answer(results, SOURCE)?;
    if !resolved.succeeded() {
        return Err(Detection::Undetermined {
            reason: "failed to resolve source line".to_owned(),
        });
    }
    let current = String::from_utf8_lossy(bytes);
    let expected = String::from_utf8_lossy(&resolved.stdout);
    Ok(if !truncated && current.trim() == expected.trim() {
        Detection::Converged
    } else {
        drifted(AptRepoDrift::ListContentDiffers)
    })
}

const fn drifted(drift: AptRepoDrift) -> Detection {
    Detection::Drifted {
        current: CurrentState::AptRepo { drift },
    }
}

#[cfg(test)]
mod tests {
    use super::{KEY_READ_MAX, LIST_READ_MAX, interpret, queries};
    use crate::detected::{AptRepoDrift, CurrentState, Detection};
    use crate::observe::testing::{contents, exists};
    use crate::observe::{
        CommandObservation, Observation, PathFacet, PathObservation, Privilege, Query, QueryError,
        QueryResult,
    };
    use crate::scalar::ContentHash;
    use crate::schema::AptRepoResource;

    fn repo() -> AptRepoResource {
        serde_json::from_value(serde_json::json!({
            "key_url": "https://example.test/key.asc",
            "source": "deb https://example.test/apt ${VERSION_CODENAME} main",
        }))
        .unwrap()
    }

    #[expect(
        clippy::unnecessary_wraps,
        reason = "builds the answer type `interpret` reads, which is always a `Result`"
    )]
    fn resolved(code: i32, stdout: &str) -> QueryResult {
        Ok(Observation::Command(CommandObservation {
            code,
            stdout: stdout.as_bytes().to_vec(),
            stderr: Vec::new(),
        }))
    }

    const LINE: &str =
        "deb [signed-by=/usr/share/keyrings/r.asc] https://example.test/apt trixie main";
    const KEY: &str = "-----BEGIN PGP PUBLIC KEY BLOCK-----\nkey\n";

    fn pin() -> ContentHash {
        ContentHash::of_bytes(KEY.as_bytes())
    }

    /// The answers of a repo whose key is `key` and whose list is `list`.
    fn answers(key: &str, list: &str) -> Vec<QueryResult> {
        let line = format!("{LINE}\n");
        vec![
            exists(true),
            contents(key, false),
            exists(true),
            contents(list, false),
            resolved(0, &line),
        ]
    }

    #[test]
    fn reads_the_files_elevated_and_resolves_the_line_as_the_login_user() {
        let queries = queries("r", &repo());
        let reads: Vec<Privilege> = queries.iter().map(Query::privilege).collect();
        assert_eq!(
            reads,
            [
                Privilege::Elevated,
                Privilege::Elevated,
                Privilege::Elevated,
                Privilege::Elevated,
                Privilege::Login
            ]
        );
        assert_eq!(
            queries[1],
            Query::path(
                "/usr/share/keyrings/r.asc",
                PathFacet::Read { max: KEY_READ_MAX },
                Privilege::Elevated
            )
        );
        assert_eq!(
            queries[3],
            Query::path(
                "/etc/apt/sources.list.d/r.list",
                PathFacet::Read { max: LIST_READ_MAX },
                Privilege::Elevated
            )
        );
        assert_eq!(
            queries[4],
            Query::login_command(
                ". /etc/os-release && printf '%s\\n' \"deb [signed-by=/usr/share/keyrings/r.asc] https://example.test/apt ${VERSION_CODENAME} main\""
            )
        );
    }

    #[test]
    fn walks_key_then_list_then_content() {
        let unanswered: QueryResult = Err(QueryError::Unrecorded);
        let line = format!("{LINE}\n");
        assert_eq!(
            interpret(
                "r",
                Some(&pin()),
                &[
                    exists(false),
                    unanswered.clone(),
                    unanswered.clone(),
                    unanswered.clone(),
                    unanswered.clone()
                ]
            ),
            Detection::Absent
        );
        assert_eq!(
            interpret(
                "r",
                Some(&pin()),
                &[
                    exists(true),
                    contents(KEY, false),
                    exists(false),
                    unanswered.clone(),
                    unanswered
                ]
            ),
            Detection::Drifted {
                current: CurrentState::AptRepo {
                    drift: AptRepoDrift::ListMissing
                }
            }
        );
        assert_eq!(
            interpret("r", Some(&pin()), &answers(KEY, &line)),
            Detection::Converged
        );
        let drift = Detection::Drifted {
            current: CurrentState::AptRepo {
                drift: AptRepoDrift::ListContentDiffers,
            },
        };
        assert_eq!(
            interpret("r", Some(&pin()), &answers(KEY, "deb other\n")),
            drift
        );
        // A list past the read bound holds more than the one line, whatever its prefix.
        let mut long = answers(KEY, LINE);
        long[3] = contents(LINE, true);
        assert_eq!(interpret("r", Some(&pin()), &long), drift);
    }

    /// The key is compared by its bytes' blake3 against the pin: another key — a rotated
    /// upstream key, a key someone replaced — is drift, whatever the list holds, and
    /// the same bytes converge.
    #[test]
    fn a_key_whose_bytes_are_not_the_pin_drifts() {
        let line = format!("{LINE}\n");
        let key_drift = Detection::Drifted {
            current: CurrentState::AptRepo {
                drift: AptRepoDrift::KeyDiffers,
            },
        };
        for list in [line.as_str(), "deb other\n"] {
            assert_eq!(
                interpret("r", Some(&pin()), &answers("another key\n", list)),
                key_drift
            );
        }
        // a trailing byte is another key: keys compare exactly, not trimmed
        assert_eq!(
            interpret("r", Some(&pin()), &answers(&format!("{KEY}\n"), &line)),
            key_drift
        );
    }

    #[test]
    fn an_unpinned_unreadable_or_oversized_key_holds() {
        let line = format!("{LINE}\n");
        let Detection::Undetermined { reason } = interpret("r", None, &answers(KEY, &line)) else {
            panic!("an unpinned key holds");
        };
        assert!(reason.contains("zap update r"), "{reason}");
        assert!(reason.contains("key_blake3"), "{reason}");
        let mut unreadable = answers(KEY, &line);
        unreadable[1] = Ok(Observation::Path(PathObservation::Failed));
        assert_eq!(
            interpret("r", Some(&pin()), &unreadable),
            Detection::Undetermined {
                reason: "failed to read signing key".to_owned()
            }
        );
        for linked in [
            Ok(Observation::Path(PathObservation::NotRegular)),
            Err(QueryError::HardLinked),
        ] {
            let mut results = answers(KEY, &line);
            results[1] = linked;
            assert_eq!(
                interpret("r", Some(&pin()), &results),
                Detection::Undetermined {
                    reason: super::NOT_SINGLE_LINK.to_owned()
                }
            );
        }
        let mut oversized = answers(KEY, &line);
        oversized[1] = contents(KEY, true);
        assert!(matches!(
            interpret("r", Some(&pin()), &oversized),
            Detection::Undetermined { reason } if reason.contains("larger than")
        ));
    }

    #[test]
    fn an_unreadable_list_or_an_unresolved_line_holds() {
        for content in [
            Ok(Observation::Path(PathObservation::Failed)),
            Err(QueryError::Exited { code: 2 }),
        ] {
            let mut results = answers(KEY, LINE);
            results[3] = content;
            assert_eq!(
                interpret("r", Some(&pin()), &results),
                Detection::Undetermined {
                    reason: "failed to read list file".to_owned()
                }
            );
        }
        let mut results = answers(KEY, LINE);
        results[4] = resolved(2, "");
        assert_eq!(
            interpret("r", Some(&pin()), &results),
            Detection::Undetermined {
                reason: "failed to resolve source line".to_owned()
            }
        );
    }
}
