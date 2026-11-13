//! The last-run report's IO: build one from a detection pass, write it under `~/.zap`,
//! and read it back for `zap status`. The shape is [`zap_types::last_run`].
//!
//! Latest-only, one file per config and host (`crate::home::last_run_path_for`), written
//! by every detection pass — except over a host whose label holds a masking token,
//! which names no one machine and so has no report — and never read by detection. A write is advisory: a failure is
//! swallowed like any other `~/.zap` write, and the report left in place still says when
//! it was taken, so it can't pass for a newer one.
//!
//! The host a file is named by, the target hash, and each resource's hash come from
//! [`report_var`]: every reference in a field that takes one resolved from the operator
//! env, a secret one to its fixed token instead, and every other value with each
//! registered secret in it masked — so none is a function of a registered secret's value,
//! and a changed secret value doesn't read as a changed config (`status` notes it beside
//! such a resource).
//! Of the pass's batches it keeps only each one's lane and query count.

use std::path::Path;

use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use zap_types::last_run::{
    LAST_RUN_VERSION, LastRun, ReportVar, ResourceRecord, RunCommand, Verdict, desired_hash,
    target_hash,
};
use zap_types::lock::ZapLock;
use zap_types::schema::ZapConfig;

use crate::home::{last_run_dir_for, last_run_file_name, last_run_path_for, write_atomic};
use crate::resolve::env_var;
use crate::resource::DetectionPass;
use zap_types::secrecy::{Secrecy, SecretRule};

use crate::secret::SecretMasker;

/// How the report resolves a reference for `config`, reading the operator env and
/// masking with the run's `masker`.
pub fn report_var<'a>(
    config: &ZapConfig,
    masker: &'a SecretMasker,
) -> impl Fn(&str) -> ReportVar + use<'a> {
    report_var_with(config, masker, env_var)
}

/// [`report_var`] with the env read injected (the hermetic test seam).
///
/// A reference is secret by the config's one rule ([`SecretRule::classify`]), which the
/// masker's registry asks too: its role, the config's `mask` / `unmask`, and its name
/// answer whether or not the variable is set, and the form of its value only when it
/// is — so a variable that is secret by its value alone resolves by value (empty) while
/// it is unset, where a comparison that depends on it is unverifiable anyway. Any other
/// name resolves to its value, empty when unset (as it does at a run), with every secret
/// `masker` holds masked out of it — a value carrying a registered password is
/// [`ReportVar::Masked`], so the hash can't test a guess at the password either (except
/// a short secret that also occurs inside a known non-secret value, whose masking then
/// depends on it). The masker is built from the env of the command at hand, so `status`
/// needs the writing run's env, secrets included, to recompute a masked value exactly;
/// without a secret it can't mask it, the hash differs, and the resource reads "config
/// changed since" — the fail-closed direction.
pub fn report_var_with<'a, F>(
    config: &ZapConfig,
    masker: &'a SecretMasker,
    env_get: F,
) -> impl Fn(&str) -> ReportVar + use<'a, F>
where
    F: Fn(&str) -> Option<String>,
{
    let rule = SecretRule::of(config);
    move |name| {
        let value = env_get(name);
        match rule.classify(name, value.as_deref()) {
            Secrecy::Secret(reason) => ReportVar::Secret(reason),
            Secrecy::Plain => {
                let value = value.unwrap_or_default();
                let masked = masker.mask(&value);
                if masked == value {
                    ReportVar::Value(value)
                } else {
                    ReportVar::Masked(masked)
                }
            }
        }
    }
}

/// Build the report for `pass`, a pass over `config` on `host` (a [`host_label`]).
///
/// Taken now: one record per resource, pairing the pass's detections with
/// `config.resources` by position (the `detect_all` contract), with the target's
/// [`target_hash`] and each resource hashed through `var` with the pin from `lock` — the **on-disk** lock as `status` reads it, so an
/// in-memory pin a dry run resolved but didn't write can't make the hash disagree with
/// `status`'s recompute. `unverifiable` is the pass's unresolved reference names;
/// `plan_hash` the plan the pass computed, when it planned.
///
/// [`host_label`]: zap_types::last_run::host_label
#[expect(
    clippy::too_many_arguments,
    reason = "each argument is a separate input the report is built from; a struct would re-spell `LastRun`'s own fields"
)]
#[must_use]
pub fn build_last_run(
    command: RunCommand,
    host: String,
    config: &ZapConfig,
    lock: Option<&ZapLock>,
    pass: &DetectionPass,
    var: impl Fn(&str) -> ReportVar,
    unverifiable: Vec<String>,
    plan_hash: Option<String>,
) -> LastRun {
    let resources = config
        .resources
        .iter()
        .zip(&pass.detections)
        .map(|(resource, detection)| {
            let lock_entry = lock.and_then(|l| l.entries.get(&resource.id));
            let hashed = desired_hash(resource, &var, lock_entry).ok();
            (
                resource.id.clone(),
                ResourceRecord {
                    verdict: Verdict::of(detection),
                    references_secret: hashed.as_ref().is_some_and(|h| h.references_secret),
                    desired_hash: hashed.map(|h| h.hash),
                },
            )
        })
        .collect();
    LastRun {
        version: LAST_RUN_VERSION,
        ran_at: now_rfc3339(),
        command,
        host,
        target_hash: target_hash(&config.target, &var).ok(),
        unverifiable,
        plan_hash,
        resources,
        batches: pass.batches.clone(),
    }
}

/// The current UTC time as RFC 3339, to the second — a report's `ran_at`.
#[must_use]
pub(crate) fn now_rfc3339() -> String {
    let now = OffsetDateTime::now_utc();
    now.replace_nanosecond(0)
        .unwrap_or(now)
        .format(&Rfc3339)
        .unwrap_or_default()
}

/// Write `report` as the config's last run on its host, replacing any earlier one.
///
/// # Errors
/// The underlying [`std::io::Error`] if the report can't be serialized or written.
/// Callers swallow it: the report is advisory.
pub fn write_last_run(
    zap_home: &Path,
    config_path: &Path,
    report: &LastRun,
) -> std::io::Result<()> {
    let json = serde_json::to_vec_pretty(report).map_err(std::io::Error::other)?;
    write_atomic(
        zap_home,
        &last_run_dir_for(zap_home, config_path),
        &last_run_file_name(&report.host),
        &json,
    )
}

/// The config's last run on `host` (a host label), or `None` when there is none — no file, an
/// unreadable one, or one that isn't a current-version report
/// ([`LastRun::parse`]).
#[must_use]
pub fn read_last_run(zap_home: &Path, config_path: &Path, host: &str) -> Option<LastRun> {
    read_last_run_file(&last_run_path_for(zap_home, config_path, host))
}

/// The report in the file at `path`, read as [`read_last_run`] reads one.
#[must_use]
pub(crate) fn read_last_run_file(path: &Path) -> Option<LastRun> {
    LastRun::parse(&std::fs::read(path).ok()?)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::path::Path;

    use zap_types::detected::{CurrentState, Detection, FileDrift};
    use zap_types::last_run::{RunCommand, Verdict};
    use zap_types::schema::{ResourceId, ZapConfig};

    use zap_types::last_run::{ReportVar, desired_hash};
    use zap_types::secrecy::{SecretReason, ValueShape};
    use zap_types::text::Text;
    use zap_types::var_ref::Segment::{Ref, Text as Lit};

    use super::{build_last_run, now_rfc3339, read_last_run, report_var_with, write_last_run};
    use crate::home::{config_dir_for, last_run_path_for};
    use crate::resource::DetectionPass;
    use crate::secret::{SecretMasker, SecretRegistry};

    /// A masker with nothing registered.
    fn no_secrets() -> SecretMasker {
        SecretRegistry::new().freeze().unwrap()
    }

    fn config() -> ZapConfig {
        serde_json::from_value(serde_json::json!({
            "target": {"local": true},
            "resources": [
                {"id": "d", "type": "directory", "path": "/srv"},
                {"id": "f", "type": "file", "path": "/etc/f",
                 "content": {"type": "inline", "content": "x"}},
            ],
        }))
        .unwrap()
    }

    fn drifted() -> Detection {
        Detection::Drifted {
            current: CurrentState::File {
                drift: FileDrift::Content,
            },
        }
    }

    #[test]
    fn a_written_report_reads_back() {
        let home = tempfile::tempdir().unwrap();
        let config_path = Path::new("/tmp/proj/zap.ts");
        let pass = DetectionPass {
            detections: vec![Detection::Converged, drifted()],
            batches: Vec::new(),
            pending: BTreeMap::new(),
        };
        let report = build_last_run(
            RunCommand::Plan,
            "local".to_owned(),
            &config(),
            None,
            &pass,
            report_var_with(&config(), &no_secrets(), |_| None),
            Vec::new(),
            None,
        );
        write_last_run(home.path(), config_path, &report).unwrap();
        let read = read_last_run(home.path(), config_path, "local").unwrap();
        assert_eq!(read, report);
        assert_eq!(
            read.resources[&ResourceId("f".to_owned())].verdict,
            Verdict::Drifted
        );
        // Another host has no report.
        assert_eq!(read_last_run(home.path(), config_path, "elsewhere"), None);
    }

    /// A file of another format — a map of per-resource entries — at the report's path is
    /// no report.
    #[test]
    fn a_file_of_another_format_reads_as_no_last_run() {
        let home = tempfile::tempdir().unwrap();
        let config_path = Path::new("/tmp/proj/zap.ts");
        let path = last_run_path_for(home.path(), config_path, "local");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(
            &path,
            br#"{"d": {"config_hash": "h", "detection": {"outcome": "converged"},
                       "detected_at": "2026-05-24T18:03:00Z"}}"#,
        )
        .unwrap();
        assert_eq!(read_last_run(home.path(), config_path, "local"), None);
        // Nor is a `<host>.json` beside the report directory.
        std::fs::write(
            config_dir_for(home.path(), config_path).join("local.json"),
            b"{}",
        )
        .unwrap();
        assert_eq!(read_last_run(home.path(), config_path, "local"), None);
    }

    /// A name, a `mask`, or a fetch credential makes a secret whether or not the variable
    /// is set, and `unmask` moves a name back across the line.
    #[test]
    fn report_var_follows_the_maskers_rule() {
        let config: ZapConfig = serde_json::from_value(serde_json::json!({
            "target": {"local": true},
            "mask_vars": ["DEPLOY_HOST"], "unmask_vars": ["PUBLIC_KEY_NAME"],
            "resources": [{"id": "f", "type": "file", "path": "/opt/f",
                           "content": {"type": "remote", "url": "https://x.example/f",
                                       "blake3": "ab".repeat(32),
                                       "auth": {"scheme": "bearer",
                                                "token": Text::reference("GH_PAT")}}}],
        }))
        .unwrap();
        let masker = no_secrets();
        let var = report_var_with(&config, &masker, |name| Some(format!("{name}-value")));
        assert_eq!(var("API_TOKEN"), ReportVar::Secret(SecretReason::Name));
        assert_eq!(
            var("DEPLOY_HOST"),
            ReportVar::Secret(SecretReason::Declared)
        );
        assert_eq!(var("GH_PAT"), ReportVar::Secret(SecretReason::Credential));
        assert_eq!(
            var("PUBLIC_KEY_NAME"),
            ReportVar::Value("PUBLIC_KEY_NAME-value".to_owned())
        );
        assert_eq!(var("APP"), ReportVar::Value("APP-value".to_owned()));
        // A switch under a secret's name is a setting: it resolves by value while it is
        // one, and by the name's token when it is unset or anything else.
        let switch = report_var_with(&config, &masker, |name| {
            Some(if name == "ENABLE_AUTH" { "true" } else { "1" }.to_owned())
        });
        assert_eq!(switch("ENABLE_AUTH"), ReportVar::Value("true".to_owned()));
        assert_eq!(switch("IS_PRIVATE"), ReportVar::Value("1".to_owned()));
        assert_eq!(
            switch("DEPLOY_HOST"),
            ReportVar::Secret(SecretReason::Declared)
        );
        assert_eq!(
            switch("GH_PAT"),
            ReportVar::Secret(SecretReason::Credential)
        );
        assert_eq!(var("ENABLE_AUTH"), ReportVar::Secret(SecretReason::Name));
        let unset = report_var_with(&config, &masker, |_| None);
        assert_eq!(unset("ENABLE_AUTH"), ReportVar::Secret(SecretReason::Name));
        assert_eq!(unset("API_TOKEN"), ReportVar::Secret(SecretReason::Name));
        assert_eq!(unset("GH_PAT"), ReportVar::Secret(SecretReason::Credential));
        assert_eq!(unset("APP"), ReportVar::Value(String::new()));
    }

    /// A value with a credential's form is a secret under any name: it resolves to its
    /// token, so two runs that differ only in the password record one hash — and a
    /// `status` run recomputes it from that variable alone. Unset, the variable has no
    /// form to read and resolves empty, as any plain one does.
    #[test]
    fn a_value_shaped_secret_resolves_to_its_token() {
        let config: ZapConfig = serde_json::from_value(serde_json::json!({
            "target": {"local": true},
            "resources": [{"id": "app", "type": "script",
                           "check": Text::of_pieces([
                               Lit("psql "), Ref("DATABASE_URL"), Lit(" -c 'select 1'"),
                           ]),
                           "run": "true"}],
        }))
        .unwrap();
        let masker = no_secrets();
        let hash = |value: Option<&str>| {
            let value = value.map(str::to_owned);
            let var = report_var_with(&config, &masker, |name| {
                value.clone().filter(|_| name == "DATABASE_URL")
            });
            assert_eq!(
                var("DATABASE_URL"),
                match &value {
                    Some(value) if value.contains('@') => {
                        ReportVar::Secret(SecretReason::Value(ValueShape::UrlPassword))
                    }
                    other => ReportVar::Value(other.clone().unwrap_or_default()),
                }
            );
            desired_hash(&config.resources[0], var, None).unwrap()
        };
        let one = hash(Some("postgres://app:hunter2@db/app"));
        assert_eq!(one, hash(Some("postgres://app:s3cr3t-too@db/app")));
        assert!(one.references_secret);
        for plain in [None, Some("postgres://db/app")] {
            let plain = hash(plain);
            assert_ne!(plain.hash, one.hash);
            assert!(!plain.references_secret);
        }
    }

    /// A plain variable carrying a registered secret's value (connection parameters
    /// holding the password) resolves with the secret masked out: two runs differing
    /// only in the password record the same hash, marked as referencing a secret.
    #[test]
    fn a_secret_inside_another_value_is_masked_out_of_the_hash() {
        let config: ZapConfig = serde_json::from_value(serde_json::json!({
            "target": {"local": true},
            "resources": [{"id": "app", "type": "script",
                           "check": Text::of_pieces([
                               Lit("psql "), Ref("PG_CONNECTION"), Lit(" -c 'select 1'"),
                           ]),
                           "run": "true"}],
        }))
        .unwrap();
        let hash = |password: &str| {
            let mut registry = SecretRegistry::new();
            registry.register("SECRET_DB_PASSWORD", password);
            let masker = registry.freeze().unwrap();
            let connection = format!("host=db user=app password={password}");
            let var = report_var_with(&config, &masker, |name| {
                (name == "PG_CONNECTION").then(|| connection.clone())
            });
            desired_hash(&config.resources[0], var, None).unwrap()
        };
        let one = hash("hunter2");
        assert_eq!(one, hash("s3cr3t-too"));
        assert!(one.references_secret);
        // Unmasked — a status run without the secret — the value moves the hash.
        let none = no_secrets();
        let unmasked = report_var_with(&config, &none, |name| {
            (name == "PG_CONNECTION").then(|| "host=db user=app password=hunter2".to_owned())
        });
        assert_ne!(
            one.hash,
            desired_hash(&config.resources[0], unmasked, None)
                .unwrap()
                .hash
        );
    }

    #[test]
    fn ran_at_is_rfc3339_to_the_second() {
        let ran_at = now_rfc3339();
        assert!(ran_at.ends_with('Z'), "{ran_at}");
        assert_eq!(ran_at.len(), "2026-09-28T12:00:00Z".len(), "{ran_at}");
    }
}
