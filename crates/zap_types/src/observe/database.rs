//! `database` (`PostgreSQL`) — role and database existence, then the owner and the
//! `pg_hba.conf` auth rules.
//!
//! One read: a root command ([`snippet`]) that asks the catalog everything in one
//! `psql` query — whether the role exists, whether the database does, the database's
//! owner, and the `hba_file` setting — as the `postgres` system role (`sudo -u
//! postgres`, run from the root batch), then `grep`s the `pg_hba.conf` that query named
//! for each declared rule, as the `postgres` account too
//! ([`pg_hba_find_rules`]): the path is the server's answer, and root never opens it.
//! The `grep`s compose with the path in the target shell rather than waiting on a
//! second round-trip. The read stays in the root lane because becoming `postgres` takes
//! `sudo`; nothing in it runs as root but that.
//!
//! The SQL literals and the rule patterns come from [`crate::postgres`] — the helpers
//! the step builder's mutations use — so the probe and the mutation it guards name the
//! same identifiers byte for byte. The query runs as [`psql_query`]: `psql -X`, so no
//! `~/.psqlrc` of the `postgres` role adds output to the answer.
//!
//! With no `psql`, or no `postgres` account (a client-only host), there is no cluster
//! zap's probes and steps — which run as `postgres` — could reach: the snippet checks for
//! both first, in the same root environment the query's `sudo -u postgres psql` runs in, and
//! exits [`NO_POSTGRES_EXIT`], which reads `absent` — the fresh-host bring-up, where the
//! same config installs postgres, plans the create in one apply. (A cluster run under
//! another account name reads `absent` too; its create steps then fail loudly under
//! `sudo -u postgres`.) A query that **fails** with both present — the server stopped,
//! `postgres` unable to authenticate — holds the database: nothing was read, so it is
//! neither absent nor converged; so does output of any other shape (more than the one
//! row). A rule's `grep` that finds no line (exit 1) reads that rule as missing; one
//! that couldn't read the file the server named (any other failure) holds, as does a
//! status line with fewer statuses than rules — the `grep`s never ran.

use std::num::NonZeroU32;

use super::{Query, QueryError, QueryResult, command_answer, drifted_or_converged, undetermined};
use crate::detected::{CurrentState, DatabaseDrift, Detection, PgHbaMissing};
use crate::postgres::{pg_hba_find_rules, pg_hba_pattern, psql_query, sql_lit};
use crate::schema::DatabaseResource;

/// Index of the one read in [`queries`].
const READ: usize = 0;

/// The snippet's exit status when the target has no `PostgreSQL`.
///
/// No `psql`, or no `postgres` account. Checked before the query runs, and never the
/// query's own: a failed query that exits with this status is reported as exiting 1.
pub const NO_POSTGRES_EXIT: i32 = 96;

/// The snippet's exit status when the catalog query timed out ([`CATALOG_QUERY_TIMEOUT`]).
///
/// The query's own `timeout` exits 124 (GNU) or 143 (`BusyBox`); the snippet reports
/// either as this status, and a query that exits this status on its own as 1, so only an
/// expiry produces it — the command's own exit status reaches zap exactly, so a timeout
/// status left as it is would read as the query failing.
pub const CATALOG_TIMED_OUT_EXIT: i32 = 95;

/// Seconds the catalog query may run.
///
/// Its own `timeout` — inside the probe's
/// [`COMMAND_TIMEOUT`](super::COMMAND_TIMEOUT), leaving the `grep`s room — signals `sudo`,
/// which relays it to `psql`: the probe's `timeout` signals only the probe's shell under
/// `BusyBox`, and `psql` runs in a command substitution, not `exec`'d, so it would
/// outlive that. An expiry exits [`CATALOG_TIMED_OUT_EXIT`], which reads as timed out
/// after this many seconds.
pub const CATALOG_QUERY_TIMEOUT: NonZeroU32 = NonZeroU32::MIN.saturating_add(49);

/// The one catalog query: one row, `|`-separated — role exists (`t`/`f`), database
/// exists (`t`/`f`), the owner's name as hex UTF-8 (so no name can collide with the
/// separator; empty when the database doesn't exist), then the `hba_file` setting last,
/// which the snippet takes as everything after the third `|`.
fn catalog_sql(user: &str, db: &str) -> String {
    let (user, db) = (sql_lit(user), sql_lit(db));
    format!(
        "SELECT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='{user}'), \
         EXISTS (SELECT 1 FROM pg_database WHERE datname='{db}'), \
         encode(convert_to((SELECT pg_catalog.pg_get_userbyid(d.datdba) FROM pg_database d \
         WHERE d.datname='{db}'), 'UTF8'), 'hex'), \
         current_setting('hba_file')"
    )
}

/// The shell that reads a database's state (see the module docs).
///
/// `user`, `db`, and `hosts` arrive resolved — `hosts` being the declared `pg_hba` hosts
/// in declared order, their references resolved as the mutation's command
/// runner resolves them.
///
/// - It exits [`NO_POSTGRES_EXIT`] when `psql` or the `postgres` account is missing,
///   before running anything else.
/// - It exits with the query's status when the query fails, before any `grep` —
///   [`CATALOG_TIMED_OUT_EXIT`] when its `timeout` expired, and remapped to 1 if it is
///   [`NO_POSTGRES_EXIT`] or [`CATALOG_TIMED_OUT_EXIT`], so only the checks and the
///   expiry produce those statuses.
/// - When the query printed more than one line, it greps nothing and prints an empty
///   status line and the output, which the verdict holds on.
/// - Otherwise it prints one line of `grep` exit statuses — one per declared host, in
///   order, each preceded by a space, the `grep`s run as `postgres` — then the query's
///   row.
#[must_use]
pub fn snippet(database: &DatabaseResource, user: &str, db: &str, hosts: &[String]) -> String {
    let mut snippet = format!(
        "command -v psql >/dev/null 2>&1 || exit {NO_POSTGRES_EXIT}; \
         id -u postgres >/dev/null 2>&1 || exit {NO_POSTGRES_EXIT}; \
         out=$(timeout {CATALOG_QUERY_TIMEOUT} {}) || \
         {{ r=$?; case $r in 124|143) r={CATALOG_TIMED_OUT_EXIT};; \
         {CATALOG_TIMED_OUT_EXIT}|{NO_POSTGRES_EXIT}) r=1;; esac; exit \"$r\"; }}; \
         case $out in *'\n'*) printf '\\n%s\\n' \"$out\"; exit 0;; esac; \
         hba=${{out#*|*|*|}}; ",
        psql_query(&catalog_sql(user, db))
    );
    let method = database.auth_method().as_str();
    let patterns: Vec<String> = hosts
        .iter()
        .map(|host| pg_hba_pattern(db, user, host, method))
        .collect();
    if patterns.is_empty() {
        snippet.push_str("s=; ");
    } else {
        snippet.push_str("s=$(");
        snippet.push_str(&pg_hba_find_rules(&patterns));
        snippet.push_str("); ");
    }
    snippet.push_str("printf '%s\\n%s\\n' \"$s\" \"$out\"");
    snippet
}

/// A database's one read — [`snippet`], as root.
#[must_use]
pub fn queries(database: &DatabaseResource, user: &str, db: &str, hosts: &[String]) -> Vec<Query> {
    vec![Query::root_command(snippet(database, user, db, hosts))]
}

/// What the snippet's output says, once the query succeeded.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Catalog {
    role_exists: bool,
    db_exists: bool,
    /// The owner's name, trimmed.
    owner: String,
    /// Each declared rule's `grep` exit status, in declared order.
    greps: Vec<i32>,
}

/// Parse the snippet's output for `hosts` declared rules; `None` when it isn't that
/// shape — a status line with one status per rule, then exactly one row line.
fn parse(stdout: &[u8], hosts: usize) -> Option<Catalog> {
    let text = std::str::from_utf8(stdout).ok()?;
    let (greps, row) = text.split_once('\n')?;
    let row = row.strip_suffix('\n')?;
    if row.contains('\n') {
        return None;
    }
    let greps = greps
        .split_whitespace()
        .map(str::parse::<i32>)
        .collect::<Result<Vec<_>, _>>()
        .ok()
        .filter(|greps| greps.len() == hosts)?;
    let mut fields = row.splitn(4, '|');
    let flag = |field: Option<&str>| match field? {
        "t" => Some(true),
        "f" => Some(false),
        _ => None,
    };
    let role_exists = flag(fields.next())?;
    let db_exists = flag(fields.next())?;
    let owner = super::decode_hex(fields.next()?)?;
    // The `hba_file` setting, which only the `grep`s read.
    fields.next()?;
    Some(Catalog {
        role_exists,
        db_exists,
        owner: String::from_utf8_lossy(&owner).trim().to_owned(),
        greps,
    })
}

/// The `grep` exit status for "no such line" — the one failure that reads as a
/// missing rule.
const GREP_NO_MATCH: i32 = 1;

/// The verdict for a database from the answer to [`queries`] (see the module docs).
///
/// `Absent` when there is no `PostgreSQL` or the role or the database doesn't exist,
/// else converged or drifted on the owner and the `pg_hba` rules — or held when the
/// query failed, its output isn't one row, or a rule's `grep` couldn't read the file.
#[must_use]
pub fn interpret(database: &DatabaseResource, user: &str, results: &[QueryResult]) -> Detection {
    let answer = match command_answer(results, READ) {
        Ok(answer) => answer,
        Err(held) => return held,
    };
    // No `PostgreSQL`: nothing a create could clobber — create.
    if answer.code == NO_POSTGRES_EXIT {
        return Detection::Absent;
    }
    if answer.code == CATALOG_TIMED_OUT_EXIT {
        return undetermined(&QueryError::TimedOut {
            secs: CATALOG_QUERY_TIMEOUT,
        });
    }
    if !answer.succeeded() {
        return Detection::Undetermined {
            reason: format!(
                "detection failed: the PostgreSQL catalog query exited {}",
                answer.code
            ),
        };
    }
    let Some(catalog) = parse(&answer.stdout, database.auth_hosts().len()) else {
        return undetermined(&QueryError::Unparseable);
    };
    // No role / database yet → create. (A partial create is still a create; the steps
    // are idempotent.)
    if !catalog.role_exists || !catalog.db_exists {
        return Detection::Absent;
    }
    if catalog
        .greps
        .iter()
        .any(|status| !matches!(*status, 0 | GREP_NO_MATCH))
    {
        return Detection::Undetermined {
            reason: "detection failed: the pg_hba.conf file PostgreSQL reports (its hba_file setting) couldn't be read"
                .to_owned(),
        };
    }
    let method = database.auth_method().as_str();
    drifted_or_converged(CurrentState::Database {
        drift: DatabaseDrift {
            owner: (catalog.owner != user).then_some(catalog.owner),
            pg_hba_missing: database
                .auth_hosts()
                .iter()
                .zip(&catalog.greps)
                .filter(|(_, status)| **status == GREP_NO_MATCH)
                .map(|(host, _)| PgHbaMissing {
                    host: host.as_inert().to_owned(),
                    method: method.to_owned(),
                })
                .collect(),
        },
    })
}

#[cfg(test)]
mod tests {
    use super::{CATALOG_TIMED_OUT_EXIT, NO_POSTGRES_EXIT, interpret, queries, snippet};
    use crate::detected::{CurrentState, DatabaseDrift, Detection, PgHbaMissing};
    use crate::observe::{
        COMMAND_TIMEOUT, CommandObservation, Observation, Query, QueryError, QueryResult,
    };
    use crate::schema::DatabaseResource;

    fn database(hosts: &[&str]) -> DatabaseResource {
        serde_json::from_value(serde_json::json!({
            "engine": "postgresql",
            "database_name": "app",
            "username": "app",
            "auth": {"method": "scram-sha-256", "hosts": hosts},
        }))
        .unwrap()
    }

    /// The declared hosts as detection passes them, references resolved (none here).
    fn hosts(db: &DatabaseResource) -> Vec<String> {
        db.auth_hosts()
            .iter()
            .map(|host| host.as_inert().to_owned())
            .collect()
    }

    // Builds the answer type `interpret` reads, which is always a `Result`.
    #[allow(clippy::unnecessary_wraps)]
    fn exited(code: i32, stdout: &str) -> QueryResult {
        Ok(Observation::Command(CommandObservation {
            code,
            stdout: stdout.as_bytes().to_vec(),
            stderr: b"psql: error: connection to server failed".to_vec(),
        }))
    }

    fn missing(host: &str) -> PgHbaMissing {
        PgHbaMissing {
            host: host.to_owned(),
            method: "scram-sha-256".to_owned(),
        }
    }

    fn drifted(drift: DatabaseDrift) -> Detection {
        Detection::Drifted {
            current: CurrentState::Database { drift },
        }
    }

    fn unreadable_hba() -> Detection {
        Detection::Undetermined {
            reason: "detection failed: the pg_hba.conf file PostgreSQL reports (its hba_file setting) couldn't be read"
                .to_owned(),
        }
    }

    #[test]
    fn one_root_command_asks_the_catalog_then_greps_each_rule() {
        let db = database(&["127.0.0.1/32", "10.0.0.0/8"]);
        assert_eq!(
            snippet(&db, "app", "o'k", &hosts(&db)),
            "command -v psql >/dev/null 2>&1 || exit 96; \
             id -u postgres >/dev/null 2>&1 || exit 96; \
             out=$(timeout 50 sudo -u postgres psql -X -tAc 'SELECT EXISTS (SELECT 1 FROM \
             pg_roles WHERE rolname='\\''app'\\''), EXISTS (SELECT 1 FROM pg_database WHERE \
             datname='\\''o'\\'''\\''k'\\''), encode(convert_to((SELECT \
             pg_catalog.pg_get_userbyid(d.datdba) FROM pg_database d WHERE \
             d.datname='\\''o'\\'''\\''k'\\''), '\\''UTF8'\\''), '\\''hex'\\''), \
             current_setting('\\''hba_file'\\'')') || \
             { r=$?; case $r in 124|143) r=95;; 95|96) r=1;; esac; exit \"$r\"; }; \
             case $out in *'\n'*) printf '\\n%s\\n' \"$out\"; exit 0;; esac; \
             hba=${out#*|*|*|}; \
             s=$(sudo -u postgres sh -c 'f=$1; shift; for p in \"$@\"; do \
             grep -qE -e \"$p\" -- \"$f\"; printf \" %s\" \"$?\"; done' sh \"$hba\" \
             '^\\s*host\\s+o'\\''k\\s+app\\s+127\\.0\\.0\\.1/32\\s+scram-sha-256(\\s|$)' \
             '^\\s*host\\s+o'\\''k\\s+app\\s+10\\.0\\.0\\.0/8\\s+scram-sha-256(\\s|$)'); \
             printf '%s\\n%s\\n' \"$s\" \"$out\""
        );
        // With no declared rule nothing is read as `postgres` but the catalog.
        let none = database(&[]);
        assert!(
            snippet(&none, "app", "app", &[])
                .ends_with("hba=${out#*|*|*|}; s=; printf '%s\\n%s\\n' \"$s\" \"$out\"")
        );
        assert_eq!(
            queries(&db, "app", "app", &hosts(&db)),
            [Query::root_command(snippet(&db, "app", "app", &hosts(&db)))]
        );
    }

    #[test]
    fn no_postgres_is_absent_but_a_present_psql_that_fails_holds() {
        let db = database(&["127.0.0.1/32"]);
        assert_eq!(NO_POSTGRES_EXIT, 96);
        // Only the checks before the query exit 96 (the snippet remaps a query's own 96).
        assert_eq!(interpret(&db, "app", &[exited(96, "")]), Detection::Absent);
        for code in [1, 2, 3] {
            assert_eq!(
                interpret(&db, "app", &[exited(code, "")]),
                Detection::Undetermined {
                    reason: format!("detection failed: the PostgreSQL catalog query exited {code}"),
                },
            );
        }
        // The query's own timeout exits 95 (the snippet remaps a query's own 95 to 1):
        // held, as timed out after the query's 50 s.
        assert_eq!(CATALOG_TIMED_OUT_EXIT, 95);
        assert_eq!(
            interpret(&db, "app", &[exited(95, "")]),
            Detection::Undetermined {
                reason: "detection failed: timed out after 50s".to_owned(),
            }
        );
        // The probe's own timeout: held too.
        assert!(matches!(
            interpret(
                &db,
                "app",
                &[Err(QueryError::TimedOut {
                    secs: COMMAND_TIMEOUT
                })]
            ),
            Detection::Undetermined { .. }
        ));
    }

    #[test]
    fn a_missing_role_or_database_is_absent() {
        let db = database(&["127.0.0.1/32"]);
        for row in ["f|t|617070|/h", "t|f||/h", "f|f||/h"] {
            assert_eq!(
                interpret(&db, "app", &[exited(0, &format!(" 1\n{row}\n"))]),
                Detection::Absent,
                "{row}"
            );
        }
    }

    #[test]
    fn owner_and_rules_drift_independently() {
        let db = database(&["127.0.0.1/32", "10.0.0.0/8"]);
        assert_eq!(
            interpret(&db, "app", &[exited(0, " 0 0\nt|t|617070|/h\n")]),
            Detection::Converged
        );
        assert_eq!(
            interpret(&db, "app", &[exited(0, " 1 1\nt|t|706f737467726573|/h\n")]),
            drifted(DatabaseDrift {
                owner: Some("postgres".to_owned()),
                pg_hba_missing: vec![missing("127.0.0.1/32"), missing("10.0.0.0/8")],
            })
        );
        // An owner whose name holds the separator, and a `hba_file` path that does, parse
        // whole.
        assert_eq!(
            interpret(&db, "app", &[exited(0, " 0 1\nt|t|617c62|/a|b\n")]),
            drifted(DatabaseDrift {
                owner: Some("a|b".to_owned()),
                pg_hba_missing: vec![missing("10.0.0.0/8")],
            })
        );
    }

    #[test]
    fn a_grep_that_could_not_read_the_file_holds() {
        let db = database(&["127.0.0.1/32", "10.0.0.0/8"]);
        // Exit 2: the file the server named is missing or unreadable (an empty
        // `hba_file` included) — not evidence a rule is missing.
        for stdout in [
            " 2 2\nt|t|617070|\n",
            " 0 2\nt|t|617070|/h\n",
            " 1 126\nt|t|617070|/h\n",
        ] {
            assert_eq!(
                interpret(&db, "app", &[exited(0, stdout)]),
                unreadable_hba(),
                "{stdout:?}"
            );
        }
        // A missing role or database still reads absent: the greps aren't consulted.
        assert_eq!(
            interpret(&db, "app", &[exited(0, " 2 2\nt|f||/h\n")]),
            Detection::Absent
        );
    }

    #[test]
    fn output_of_any_other_shape_holds() {
        let db = database(&["127.0.0.1/32", "10.0.0.0/8"]);
        let none = database(&[]);
        let cases = [
            (&db, ""),
            (&db, " 0 0"),
            (&db, " 0 0\nt|t|617070|/h"),
            (&db, " 0\nt|t|617070|/h\n"),
            (&db, " 0 0 0\nt|t|617070|/h\n"),
            (&db, " 0 x\nt|t|617070|/h\n"),
            (&db, " 0 0\nyes|t|617070|/h\n"),
            (&db, " 0 0\nt|t|6170Z0|/h\n"),
            (&db, " 0 0\nt|t|61707|/h\n"),
            (&db, " 0 0\nt|t|617070\n"),
            // A `psqlrc` line after the row (`\timing`), or a newline in `hba_file`: the
            // row isn't one line.
            (&db, " 0 0\nt|t|617070|/h\nTime: 0.312 ms\n"),
            (&db, " 0 0\nt|t|617070|/h\n/i\n"),
            // What the snippet prints for a multi-line query output: no statuses.
            (&db, "\nt|t|617070|/h\nTime: 0.312 ms\n"),
            (&none, "\nt|t|617070|/h\nTime: 0.312 ms\n"),
        ];
        for (resource, stdout) in cases {
            assert_eq!(
                interpret(resource, "app", &[exited(0, stdout)]),
                Detection::Undetermined {
                    reason: "detection failed: the probe's output didn't parse".to_owned(),
                },
                "{stdout:?}"
            );
        }
        // No declared rules: an empty status line and one row is the right shape.
        assert_eq!(
            interpret(&none, "app", &[exited(0, "\nt|t|617070|/h\n")]),
            Detection::Converged
        );
    }
}
