//! `database` (`PostgreSQL`) step builder — guarded role/db creation, the owner,
//! GRANT, and per-host `pg_hba` rules.

use crate::plan::{PgHbaRuleStep, PlanStep};
use crate::postgres::{psql_query, sql_ident, sql_lit};
use crate::schema::DatabaseResource;
use crate::shell::single_quote;

/// Self-contained, idempotent steps for a `database` (run by the executor's generic
/// command-step runner): the create steps no-op when the role/db already exist (so an
/// update — e.g. only a `pg_hba` rule drifted — doesn't fail on a `createuser` /
/// `createdb` of an existing object), and each `pg_hba` rule is its own
/// [`PgHbaRuleStep`], which discovers `hba_file` inline and adds the rule once, only
/// if absent, reloading the server's configuration when it does. Nothing here needs a
/// restart, so no step goes through a service manager.
///
/// Identifiers and CIDR hosts route through the shared [`postgres`](crate::postgres)
/// helpers (`sql_lit` / `pg_hba_pattern` / `psql_query`, the detector's own query
/// form), so the idempotency probe and the mutation it guards quote identically. Every
/// `psql` here runs with `-X`: no step reads the `postgres` role's `~/.psqlrc`.
pub(super) fn database_steps(database: &DatabaseResource) -> Vec<PlanStep> {
    let (db, user) = (&database.database_name, &database.username);
    // The identifiers are shell-quoted in the mutations exactly as the probes quote
    // them (literal — never shell-expanded), so the probe and the mutation it guards
    // can't disagree about which role/database they name. An unquoted `createuser
    // $USER` would expand while its probe matched the literal `$USER`: created once,
    // then "role already exists" on every later run.
    let (user_q, db_q) = (single_quote(user), single_quote(db));
    let mut steps = vec![
        PlanStep::run(format!(
            "{} | grep -q 1 || sudo -u postgres createuser -- {user_q}",
            psql_query(&format!(
                "SELECT 1 FROM pg_roles WHERE rolname='{}'",
                sql_lit(user)
            ))
        )),
        PlanStep::run(format!(
            "{} | grep -q 1 || sudo -u postgres createdb -O {user_q} -- {db_q}",
            psql_query(&format!(
                "SELECT 1 FROM pg_database WHERE datname='{}'",
                sql_lit(db)
            ))
        )),
        // `createdb -O` sets the owner only at creation; this corrects an owner that
        // drifted on an existing database (a no-op when it already is the user's).
        PlanStep::run(format!(
            "sudo -u postgres psql -X -c {}",
            single_quote(&format!(
                "ALTER DATABASE {} OWNER TO {};",
                sql_ident(db),
                sql_ident(user)
            ))
        )),
        PlanStep::run(format!(
            "sudo -u postgres psql -X -c {}",
            single_quote(&format!(
                "GRANT ALL PRIVILEGES ON DATABASE {} TO {};",
                sql_ident(db),
                sql_ident(user)
            ))
        )),
    ];
    for host in database.auth_hosts() {
        steps.push(PlanStep::PgHbaRule(PgHbaRuleStep {
            database: db.as_inert().to_owned(),
            user: user.as_inert().to_owned(),
            host: host.as_inert().to_owned(),
            method: database.auth_method(),
        }));
    }
    steps
}

#[cfg(test)]
mod tests {
    use super::database_steps;
    use crate::plan::{PgHbaRuleStep, PlanStep};
    use crate::postgres::pg_hba_rule_step;
    use crate::schema::{DatabaseResource, PgAuthMethod};
    use crate::text::Text;
    use crate::var_ref::marker;

    fn database(json: serde_json::Value) -> DatabaseResource {
        serde_json::from_value(json).expect("valid database json")
    }

    fn runs(database: &DatabaseResource) -> Vec<String> {
        database_steps(database)
            .iter()
            .filter_map(PlanStep::execution)
            .map(|execution| execution.text().to_owned())
            .collect()
    }

    #[test]
    fn role_and_db_creation_are_guarded_and_idempotent() {
        let runs = runs(&database(serde_json::json!({
            "engine": "postgresql", "database_name": "app", "username": "app"
        })));
        assert!(runs.iter().any(
            |c| c.contains("pg_roles") && c.contains("|| sudo -u postgres createuser -- 'app'")
        ));
        assert!(runs.iter().any(|c| c.contains("pg_database")
            && c.contains("|| sudo -u postgres createdb -O 'app' -- 'app'")));
        assert!(
            runs.iter()
                .any(|c| c.contains("ALTER DATABASE \"app\" OWNER TO \"app\";"))
        );
        assert!(
            runs.iter()
                .any(|c| c.contains("GRANT ALL PRIVILEGES ON DATABASE \"app\" TO \"app\""))
        );
        // Nothing a database declares needs a restart: an added `pg_hba` rule reloads
        // the configuration inside its own step, and no step names a service manager.
        assert!(
            runs.iter()
                .all(|c| !c.contains("systemctl") && !c.contains("rc-service")),
            "{runs:?}"
        );
        assert_eq!(
            runs.len(),
            4,
            "role, database, owner, grant, and no rule: the default declares none"
        );
    }

    #[test]
    fn the_owner_is_corrected_after_the_create_and_before_the_grant() {
        let runs = runs(&database(serde_json::json!({
            "engine": "postgresql", "database_name": "we\"ird", "username": "o'brien"
        })));
        assert_eq!(
            runs[2],
            "sudo -u postgres psql -X -c 'ALTER DATABASE \"we\"\"ird\" OWNER TO \"o'\\''brien\";'"
        );
        assert!(runs[1].contains(" createdb -O "), "{runs:?}");
        assert!(
            runs[3].contains("GRANT ALL PRIVILEGES ON DATABASE"),
            "{runs:?}"
        );
    }

    #[test]
    fn mutations_quote_identifiers_like_their_probes() {
        // The probe takes the identifier literally (single-quoted through `psql_query`,
        // never shell-expanded), so the mutation must too: an unquoted `createuser
        // $USER` would expand while its guard matched the literal — created on the
        // first run, "role already exists" on every run after. Pinning the exact
        // step asserts the mutation's identifier is single-quoted alongside the probe.
        let runs = runs(&database(serde_json::json!({
            "engine": "postgresql", "database_name": "app", "username": "$USER"
        })));
        assert_eq!(
            runs[0],
            "sudo -u postgres psql -X -tAc 'SELECT 1 FROM pg_roles WHERE rolname='\\''$USER'\\''' \
             | grep -q 1 || sudo -u postgres createuser -- '$USER'"
        );
    }

    #[test]
    fn identifier_with_a_quote_is_routed_through_psql_query() {
        // A role name carrying `'` must be doubled in the SQL literal (`sql_lit`) and
        // the whole `psql` argument single-quoted (`psql_query`) so the probe can't
        // break out of its argument — and the mutation's argument must escape the
        // same `'` for the shell (`single_quote`) so it stays one word. Asserting the
        // exact first step pins both layers; the escaping primitives themselves are
        // unit-tested in `crate::postgres`.
        let runs = runs(&database(serde_json::json!({
            "engine": "postgresql", "database_name": "app", "username": "o'brien"
        })));
        assert_eq!(
            runs[0],
            "sudo -u postgres psql -X -tAc 'SELECT 1 FROM pg_roles WHERE rolname='\\''o'\\'''\\''brien'\\''' \
             | grep -q 1 || sudo -u postgres createuser -- 'o'\\''brien'"
        );
    }

    #[test]
    fn no_step_reads_the_psqlrc() {
        // Each guard decides on `psql`'s output (`grep -q 1`, the `hba_file` path), where
        // a `~/.psqlrc` line (`\timing` prints `Time: 0.1 ms`) would be read as the
        // answer; and the GRANT runs under whatever transaction settings one makes.
        let runs = runs(&database(serde_json::json!({
            "engine": "postgresql", "database_name": "app", "username": "app"
        })));
        let psql: Vec<&String> = runs.iter().filter(|c| c.contains("psql")).collect();
        assert_eq!(psql.len(), 4, "role, database, owner, grant");
        for command in psql {
            assert_eq!(
                command.matches("psql ").count(),
                command.matches("psql -X ").count(),
                "{command}"
            );
        }
        assert!(
            runs.contains(
                &r#"sudo -u postgres psql -X -c 'GRANT ALL PRIVILEGES ON DATABASE "app" TO "app";'"#
                    .to_owned()
            ),
            "{runs:?}"
        );
    }

    #[test]
    fn pg_hba_guard_keeps_env_refs_resolvable() {
        // The guard's grep pattern and the inserted line must both still carry the
        // reference after escaping/quoting, or apply-time resolution sees only one of
        // them and the rule is added again every run. They are the step's only
        // references, and it holds no delimiter outside them.
        let runs = runs(&database(serde_json::json!({
            "engine": "postgresql", "database_name": "app",
            "username": Text::reference("USER"),
            "auth": {"hosts": ["127.0.0.1/32", "::1/128"]}
        })));
        let hba: Vec<&String> = runs
            .iter()
            .filter(|c| c.contains("SHOW hba_file"))
            .collect();
        assert_eq!(hba.len(), 2, "one rule per declared host: {runs:?}");
        assert!(
            hba.iter()
                .all(
                    |c| crate::var_ref::ref_names(c).collect::<Vec<_>>() == ["USER", "USER"]
                        && c.matches(&marker("USER")).count() == 2
                        && !crate::var_ref::holds_stray_delimiter(c)
                ),
            "guard + insert must keep refs adjacent for apply-time resolution: {hba:?}"
        );
    }

    #[test]
    fn one_pg_hba_rule_per_host_with_ere_escaped_cidr() {
        let declared = database(serde_json::json!({
            "engine": "postgresql", "database_name": "app", "username": "app",
            "auth": {"method": "scram-sha-256", "hosts": ["127.0.0.1/32", "::1/128"]}
        }));
        let rule = |host: &str| {
            PlanStep::PgHbaRule(PgHbaRuleStep {
                database: "app".to_owned(),
                user: "app".to_owned(),
                host: host.to_owned(),
                method: PgAuthMethod::ScramSha256,
            })
        };
        let rules: Vec<PlanStep> = database_steps(&declared)
            .into_iter()
            .filter(|step| matches!(step, PlanStep::PgHbaRule(_)))
            .collect();
        assert_eq!(rules, [rule("127.0.0.1/32"), rule("::1/128")]);
        let runs = runs(&declared);
        let hba: Vec<&String> = runs
            .iter()
            .filter(|c| c.contains("SHOW hba_file"))
            .collect();
        assert_eq!(
            hba,
            [
                &pg_hba_rule_step("app", "app", "127.0.0.1/32", "scram-sha-256"),
                &pg_hba_rule_step("app", "app", "::1/128", "scram-sha-256"),
            ],
            "one rule per host, in order: {runs:?}"
        );
        // The CIDR's dots are ERE-escaped in the grep pattern (matching the detector),
        // and the line carries it as written.
        assert!(
            hba[0].contains(
                r#" sh "$hba" '^\s*host\s+app\s+app\s+127\.0\.0\.1/32\s+scram-sha-256(\s|$)' 'host    app    app    127.0.0.1/32    scram-sha-256') || exit; "#
            ),
            "{}",
            hba[0]
        );
    }
}
