//! What zap prints is what is there.
//!
//! Every render escapes the text it takes from a config, the environment, the command
//! line, a file on disk, or the target. [`every_render_escapes_what_it_prints`] feeds
//! each one a report whose every string is hostile — a reference, a newline followed by a
//! forged `plan_hash:` line, a carriage return, an escape sequence, a C1 control, DEL, a
//! line separator, a bidirectional override, invisible characters, and a reference's
//! delimiters out of place — and holds its output to four rules: no such character
//! reaches it, the forged line never stands where one of zap's own could, every hostile
//! string the report holds is either on screen or named as one that render leaves out,
//! and a reference is on screen only in the form a person reads, so no render prints a
//! character of the block a reference's delimiters come from.
//!
//! [`every_render_is_in_the_table`] reads the crate's source for its `render` functions
//! and fails for one the table doesn't know, so a new render is added here before it
//! ships; [`the_crate_prints_only_where_it_is_known_to`] does the same for a function
//! that prints for itself.
//!
//! The second half holds the previews to their hash: a change to a plan's target or
//! machine that moves `plan_hash` moves what `zap plan`, `zap plan --diff`, and
//! `zap apply` print.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;
mod scratch;

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};

use common::local_machine;
use zap_core::commands::apply::ApplyReport;
use zap_core::commands::deploy::{
    DeployOutcome, DeployReport, DeployRun, FailureState, Rollback, RollbackOutcome, StepRecord,
    StepSummary,
};
use zap_core::commands::detect::{DetectLine, DetectReport};
use zap_core::commands::plan::PlanReport;
use zap_core::commands::status::{LastRunInfo, ResourceStatus, Standing, StatusReport};
use zap_core::commands::update::UpdateOutcome;
use zap_core::commands::{
    Confirmation, LockCheckReport, LockReport, PlanAddress, REFERENCE_VALUE_SHOWN, UpdateReport,
    render_apply, render_deploy, render_detect, render_lock, render_lock_check, render_plan,
    render_plan_diff, render_status, render_update,
};
use zap_core::error::Error;
use zap_core::escape::render_block;
use zap_core::lock::{
    LockStanding, NameOnlyRef, NameOnlyRefs, UnverifiableEntry, render_name_only_refs,
};
use zap_core::progress::{Notice, Progress, render_progress};
use zap_types::deploy::{
    DeployAction, DeployPlan, DeployStep, DeployStepId, DriftPreflight, ReleaseSwap,
};
use zap_types::deploy_preview::DeployPreviewPass;
use zap_types::detected::{
    AptRepoDrift, CurrentState, DatabaseDrift, Detection, FileDrift, FirewallDrift, PgHbaMissing,
    UserDrift,
};
use zap_types::error_code::ErrorCode;
use zap_types::event::{ChangeOutcome, Event, RunSummary, StepOutcome};
use zap_types::last_run::{PlanUnreviewed, RunCommand, Verdict};
use zap_types::plan::{
    Change, ChangeAction, HeldResource, HoldCause, Machine, Plan, PlanStep, ReferenceValue,
    ResidualResource, ResidualState, Trigger, TriggerKind,
};
use zap_types::scalar::EnvVarName;
use zap_types::schema::{Resource, ResourceId, ResourceType, Target};
use zap_types::secrecy::{SecretReason, ValueShape};
use zap_types::text::Text;
use zap_types::var_ref::{marker, shown};

/// What follows a hostile string's forged line: a carriage return, a tab, an escape
/// sequence, a C1 control, DEL, a line separator, a bidirectional override, a zero-width
/// space, a byte order mark, and a tag character.
const CONTROLS: &str = "\r\t\u{1b}[2K\u{9b}\u{7f}\u{2028}\u{202e}\u{200b}\u{feff}\u{e0041}";

/// What ends a hostile string that no config declared — command output, an error, a
/// label: a reference's two delimiters, each where it is no part of a reference.
const STRAYS: &str = "\u{fdd1}\u{fdd0}";

/// The variable every hostile string references.
const REFERENCED: &str = "ZAP_RENDER_REF";

/// How a render shows the reference a hostile string holds.
const SHOWN: &str = "{env:ZAP_RENDER_REF}";

/// The line a hostile string tries to add to a report.
const FORGED: &str = "plan_hash: 0000";

thread_local! {
    /// The tags of the hostile strings built since the last [`take_tags`].
    static TAGS: RefCell<BTreeSet<String>> = const { RefCell::new(BTreeSet::new()) };
}

/// A hostile string, marked `‹tag›` so a render that prints it can be told from one
/// that doesn't. It holds a reference inert, as a plan's command text and an error
/// quoting a declared url do.
fn h(tag: &str) -> String {
    TAGS.with(|tags| tags.borrow_mut().insert(tag.to_owned()));
    format!("‹{tag}›{}\n{FORGED}{CONTROLS}{STRAYS}", marker(REFERENCED))
}

/// `json` as a config declares it: each hostile string in a field that takes a
/// reference is that field's typed value — its text with the reference in it — and each
/// in a field that takes none is its text alone, since nothing can declare a reference
/// there. A delimiter out of place is in neither: no config can hold one.
fn declared<T: serde::de::DeserializeOwned>(mut json: serde_json::Value) -> T {
    fn hostile(value: &serde_json::Value, pointer: &str, found: &mut Vec<String>) {
        match value {
            serde_json::Value::String(text) if zap_types::var_ref::holds_delimiter(text) => {
                found.push(pointer.to_owned());
            }
            serde_json::Value::Array(items) => {
                for (index, item) in items.iter().enumerate() {
                    hostile(item, &format!("{pointer}/{index}"), found);
                }
            }
            serde_json::Value::Object(map) => {
                for (key, item) in map {
                    let key = key.replace('~', "~0").replace('/', "~1");
                    hostile(item, &format!("{pointer}/{key}"), found);
                }
            }
            _ => {}
        }
    }
    let mut pointers = Vec::new();
    hostile(&json, "", &mut pointers);
    let mut typed = Vec::new();
    for pointer in &pointers {
        let leaf = json.pointer_mut(pointer).unwrap();
        let text = leaf.as_str().unwrap().replace(STRAYS, "");
        let reference = Text::from_inert(text.clone()).unwrap();
        *leaf = serde_json::Value::String(reference.literals().collect());
        typed.push(serde_json::json!(reference));
    }
    for (pointer, typed) in pointers.iter().zip(typed) {
        let plain = std::mem::replace(json.pointer_mut(pointer).unwrap(), typed);
        if serde_json::from_value::<T>(json.clone()).is_err() {
            *json.pointer_mut(pointer).unwrap() = plain;
        }
    }
    serde_json::from_value(json).unwrap()
}

fn take_tags() -> BTreeSet<String> {
    TAGS.with(|tags| std::mem::take(&mut *tags.borrow_mut()))
}

fn id(tag: &str) -> ResourceId {
    ResourceId(h(tag))
}

fn resource(json: serde_json::Value) -> Resource {
    declared(json)
}

/// One render over one hostile report.
struct Case {
    /// The render function, as [`every_render_is_in_the_table`] finds it in the source.
    render: &'static str,
    /// Which report this is, for a failure.
    name: &'static str,
    /// Build the report and render it.
    run: fn() -> String,
    /// The hostile strings the report holds that this render does not print, as lists
    /// to be read together. An entry ending in `.` names every tag that starts with it.
    unprinted: &'static [&'static [&'static str]],
}

/// Hold `rendered` to the three rules (module docs), returning each one it breaks.
fn broken_rules(case: &Case, rendered: &str, tags: &BTreeSet<String>) -> Vec<String> {
    let mut broken = Vec::new();
    let raw: BTreeSet<String> = rendered
        .chars()
        .filter(|&c| {
            c != '\n'
                && (c.is_control()
                    || matches!(
                        c,
                        '\u{2028}' | '\u{202e}' | '\u{200b}' | '\u{feff}' | '\u{e0041}'
                            // the block a reference's delimiters come from
                            | '\u{fdd0}'..='\u{fdef}'
                    ))
        })
        .map(|c| format!("U+{:04X}", u32::from(c)))
        .collect();
    if !raw.is_empty() {
        broken.push(format!("prints raw: {raw:?}"));
    }
    for line in rendered.lines().filter(|line| line.contains(FORGED)) {
        // On its text's own line, its newline written out — by the escape, or by the
        // JSON a target is printed as — or a continuation line of a block, which the
        // narrowest lead (`error: `) still indents past every column a line of zap's
        // own starts at.
        let escaped = line.contains(&format!("<U+000A>{FORGED}"));
        let json = line.contains(&format!("\\n{FORGED}"));
        let continuation = line.starts_with("       ") && line.trim_start().starts_with(FORGED);
        if !(escaped || json || continuation) {
            broken.push(format!("lets a value start a line: {line:?}"));
        }
    }
    let unprinted: BTreeSet<&str> = case.unprinted.iter().copied().flatten().copied().collect();
    let names = |entry: &str, tag: &str| {
        if entry.ends_with('.') {
            tag.starts_with(entry)
        } else {
            tag == entry
        }
    };
    let printed = |tag: &str| rendered.contains(&format!("‹{tag}›"));
    let missing: Vec<&String> = tags
        .iter()
        .filter(|tag| !unprinted.iter().any(|entry| names(entry, tag)) && !printed(tag))
        .collect();
    if !missing.is_empty() {
        broken.push(format!(
            "holds strings it neither prints nor lists as unprinted: {missing:?}"
        ));
    }
    let stale: Vec<&&str> = unprinted
        .iter()
        .filter(|entry| {
            let mut named = tags.iter().filter(|tag| names(entry, tag)).peekable();
            named.peek().is_none() || named.any(|tag| printed(tag))
        })
        .collect();
    if !stale.is_empty() {
        broken.push(format!(
            "lists as unprinted strings it prints, or its report doesn't hold: {stale:?}"
        ));
    }
    broken
}

// --- the hostile reports ---

fn lock_standing() -> LockStanding {
    LockStanding {
        missing: vec![h("lock.missing")],
        stale: vec![h("lock.stale")],
        unverifiable: vec![UnverifiableEntry {
            id: h("lock.unverifiable.id"),
            vars: vec![h("lock.unverifiable.var")],
        }],
        orphans: vec![h("lock.orphan")],
    }
}

fn name_only() -> Vec<NameOnlyRefs> {
    vec![NameOnlyRefs {
        id: h("name_only.id"),
        vars: vec![
            NameOnlyRef {
                name: h("name_only.var"),
                reason: SecretReason::Name,
            },
            NameOnlyRef {
                name: h("name_only.shaped"),
                reason: SecretReason::Value(ValueShape::UrlPassword),
            },
        ],
    }]
}

/// A resource detection couldn't read, one held behind it, and one held because its
/// change would restart a held service: every cause names hostile text.
fn held() -> Vec<HeldResource> {
    vec![
        HeldResource {
            resource_id: id("held.id"),
            trigger: None,
            cause: HoldCause::Undetermined {
                reason: h("held.reason"),
            },
        },
        HeldResource {
            resource_id: id("held.waiting"),
            trigger: None,
            cause: HoldCause::Waits {
                on: vec![id("held.waits_on")],
            },
        },
        HeldResource {
            resource_id: id("held.source"),
            trigger: None,
            cause: HoldCause::Triggers {
                service: id("held.service"),
                kind: TriggerKind::Restart,
            },
        },
    ]
}

/// A remote target with hostile text in every free-text field.
fn target() -> Target {
    declared(serde_json::json!({
        "host": h("target.host"), "user": h("target.user"),
        "bootstrap_user": h("target.bootstrap_user"), "port": 2222,
        "key_path": h("target.key_path"), "home": h("target.home"),
        "package_manager": "apt", "service_manager": "systemd",
    }))
}

fn machine() -> Machine {
    Machine::Remote {
        host: h("machine.host"),
        user: Some(h("machine.user")),
    }
}

/// The observed states a drift can carry text in, one resource each.
fn observed() -> Vec<(&'static str, ResourceType, CurrentState)> {
    vec![
        (
            "directory",
            ResourceType::Directory,
            CurrentState::Directory {
                mode: h("observed.dir.mode"),
                owner: h("observed.dir.owner"),
                group: h("observed.dir.group"),
            },
        ),
        (
            "link",
            ResourceType::Link,
            CurrentState::Link {
                points_to: h("observed.link.points_to"),
            },
        ),
        (
            "user",
            ResourceType::User,
            CurrentState::User {
                drift: UserDrift {
                    shell: Some(h("observed.user.shell")),
                    home_mode: Some(h("observed.user.home_mode")),
                    groups: vec![h("observed.user.group")],
                    ..UserDrift::default()
                },
            },
        ),
        (
            "firewall",
            ResourceType::Firewall,
            CurrentState::Firewall {
                drift: FirewallDrift {
                    default_incoming: Some(h("observed.firewall.incoming")),
                    default_outgoing: Some(h("observed.firewall.outgoing")),
                    missing_rules: vec![h("observed.firewall.rule")],
                },
            },
        ),
        (
            "database",
            ResourceType::Database,
            CurrentState::Database {
                drift: DatabaseDrift {
                    owner: Some(h("observed.database.owner")),
                    pg_hba_missing: vec![PgHbaMissing {
                        host: h("observed.pg_hba.host"),
                        method: h("observed.pg_hba.method"),
                    }],
                },
            },
        ),
        (
            "file",
            ResourceType::File,
            CurrentState::File {
                drift: FileDrift::Metadata {
                    mode: h("observed.file.mode"),
                    owner: h("observed.file.owner"),
                    group: h("observed.file.group"),
                },
            },
        ),
        (
            "pinned",
            ResourceType::File,
            CurrentState::File {
                drift: FileDrift::Pin {
                    observed: h("observed.file.pin"),
                },
            },
        ),
        (
            "build",
            ResourceType::Build,
            CurrentState::Build {
                observed: h("observed.build.pin"),
            },
        ),
    ]
}

fn detect_report() -> DetectReport {
    let mut resources: Vec<DetectLine> = observed()
        .into_iter()
        .map(|(name, kind, current)| DetectLine {
            resource_id: id(&format!("detect.{name}.id")),
            detection: Detection::Drifted { current },
            kind,
        })
        .collect();
    resources.push(DetectLine {
        resource_id: id("detect.undetermined.id"),
        detection: Detection::Undetermined {
            reason: h("detect.undetermined.reason"),
        },
        kind: ResourceType::Script,
    });
    resources.push(DetectLine {
        resource_id: id("detect.converged.id"),
        detection: Detection::Converged,
        kind: ResourceType::Package,
    });
    resources.push(DetectLine {
        resource_id: id("detect.absent.id"),
        detection: Detection::Absent,
        kind: ResourceType::Package,
    });
    DetectReport {
        target: h("report.target"),
        package_manager: Some(h("report.package_manager")),
        service_manager: Some(h("report.service_manager")),
        resources,
        unverifiable: vec![h("unverifiable.var")],
        lock_standing: lock_standing(),
        unrecorded: Some(h("unrecorded")),
    }
}

fn status_report(host: Option<String>, last_run: Option<LastRunInfo>) -> StatusReport {
    StatusReport {
        target: h("report.target"),
        package_manager: Some(h("report.package_manager")),
        service_manager: Some(h("report.service_manager")),
        host,
        unidentified: None,
        last_run,
        unverifiable: vec![h("unverifiable.var")],
        target_changed: true,
        resources: vec![
            ResourceStatus {
                id: id("status.read.id"),
                kind: Some(ResourceType::Directory),
                standing: Standing::Read(Verdict::Converged),
                references_secret: true,
            },
            ResourceStatus {
                id: id("status.changed.id"),
                kind: Some(ResourceType::File),
                standing: Standing::ChangedSince(Verdict::Drifted),
                references_secret: false,
            },
            ResourceStatus {
                id: id("status.unread.id"),
                kind: Some(ResourceType::Script),
                standing: Standing::NotInLastRun,
                references_secret: false,
            },
            ResourceStatus {
                id: id("status.orphan.id"),
                kind: None,
                standing: Standing::Orphaned(Verdict::Absent),
                references_secret: false,
            },
        ],
        lock_standing: lock_standing(),
    }
}

fn last_run(command: RunCommand) -> LastRunInfo {
    LastRunInfo {
        ran_at: h("last_run.ran_at"),
        command,
        plan_hash: Some(h("last_run.plan_hash")),
        unverifiable: vec![h("last_run.unverifiable")],
    }
}

/// A typed step of each kind and shape — a put of text the plan holds, a put of each
/// producer's output, a directory, a `pg_hba` rule, an installer — every free-text
/// field hostile. A mode and an account name are held to their formats where a plan is
/// read, so neither can be.
fn typed_steps() -> Vec<PlanStep> {
    [
        serde_json::json!({"put": {
            "path": h("step.put.text.path"), "run_as": {"user": "app"}, "check": "sudoers",
            "source": {"text": {"mode": "440", "content": h("step.put.text.content")}},
        }}),
        serde_json::json!({"put": {
            "path": h("step.put.command.path"), "run_as": "root", "check": "none",
            "source": {"command": {
                "mode": {"keep": {"if_new": "644"}},
                "producer": {"fstab_swap_entry": {"path": h("step.put.fstab.path")}},
            }},
        }}),
        serde_json::json!({"put": {
            "path": h("step.put.apt.path"), "run_as": "root", "check": "none",
            "source": {"command": {
                "mode": {"set": "644"},
                "producer": {"apt_source_line": {"line": h("step.put.apt.line")}},
            }},
        }}),
        serde_json::json!({"put": {
            "path": h("step.put.keys.path"), "run_as": {"user": "app"}, "check": "none",
            "source": {"command": {
                "mode": {"set": "600"},
                "producer": {"authorized_keys_of": {"account": "ops"}},
            }},
        }}),
        serde_json::json!({"installer": {
            "url": h("step.installer.url"), "shell": h("step.installer.shell"),
        }}),
        serde_json::json!({"dir": {
            "path": h("step.dir.path"), "mode": "700", "owner": "app", "group": "www",
        }}),
        serde_json::json!({"pg_hba_rule": {
            "database": h("step.pg_hba_rule.database"), "user": h("step.pg_hba_rule.user"),
            "host": h("step.pg_hba_rule.host"), "method": "scram-sha-256",
        }}),
    ]
    .into_iter()
    .map(|step| serde_json::from_value(step).unwrap())
    .collect()
}

/// A script change that declares where and with what it runs, with a step of each kind.
fn script_change() -> Change {
    Change {
        resource_id: id("change.script.id"),
        action: ChangeAction::Create,
        steps: [PlanStep::Run(h("step.run")), PlanStep::Note(h("step.note"))]
            .into_iter()
            .chain(typed_steps())
            .collect(),
        desired: resource(serde_json::json!({
            "id": h("desired.script.id"), "type": "script",
            "check": h("desired.script.check"), "run": h("desired.script.run"),
            "cwd": h("desired.script.cwd"), "env": {"KEY": h("desired.script.env")},
        })),
        depends_on: vec![id("change.script.depends_on")],
        trigger: None,
    }
}

/// An update of each kind whose `--diff` lines carry text: the desired resource, and
/// the observed state it is joined against.
fn drifted_changes() -> Vec<(Change, CurrentState)> {
    let update = |name: &str, desired: serde_json::Value, current: CurrentState| {
        (
            Change {
                resource_id: id(&format!("change.{name}.id")),
                action: ChangeAction::Update,
                steps: vec![PlanStep::Run(h(&format!("change.{name}.step")))],
                desired: resource(desired),
                depends_on: Vec::new(),
                trigger: None,
            },
            current,
        )
    };
    vec![
        update(
            "directory",
            serde_json::json!({
                "id": "d", "type": "directory", "path": h("desired.dir.path"),
                "mode": "700", "owner": "root", "group": "root",
            }),
            CurrentState::Directory {
                mode: h("observed.dir.mode"),
                owner: h("observed.dir.owner"),
                group: h("observed.dir.group"),
            },
        ),
        update(
            "link",
            serde_json::json!({
                "id": "l", "type": "link", "path": h("desired.link.path"),
                "target": h("desired.link.target"),
            }),
            CurrentState::Link {
                points_to: h("observed.link.points_to"),
            },
        ),
        update(
            "user",
            serde_json::json!({
                "id": "u", "type": "user", "username": "app",
                "shell": h("desired.user.shell"),
            }),
            CurrentState::User {
                drift: UserDrift {
                    shell: Some(h("observed.user.shell")),
                    groups: vec![h("observed.user.group")],
                    ..UserDrift::default()
                },
            },
        ),
        update(
            "apt_repo",
            serde_json::json!({
                "id": "r", "type": "apt_repo", "key_url": h("desired.apt_repo.key_url"),
                "source": h("desired.apt_repo.source"),
            }),
            CurrentState::AptRepo {
                drift: AptRepoDrift::ListMissing,
            },
        ),
        update(
            "file",
            serde_json::json!({
                "id": "f", "type": "file", "path": h("desired.file.path"),
                "content": {"type": "source", "path": h("desired.file.source")},
            }),
            CurrentState::File {
                drift: FileDrift::Content,
            },
        ),
    ]
}

/// A service update a trigger fired, with nothing observed to diff.
fn triggered_change() -> Change {
    Change {
        resource_id: id("change.service.id"),
        action: ChangeAction::Update,
        steps: vec![PlanStep::Run(h("change.service.step"))],
        desired: resource(serde_json::json!({
            "id": "svc", "type": "service", "service": "nginx",
            "enabled": true,
        })),
        depends_on: Vec::new(),
        trigger: Some(Trigger {
            kind: TriggerKind::Restart,
            sources: vec![id("trigger.source")],
            pending: true,
        }),
    }
}

/// A create of each kind `render_declared` prints lines for, every free-text field
/// hostile. A step here is a stand-in, so what a real plan carries in its steps — a
/// build's or a pipeline step's `run`, a package's names, an installer's url and shell
/// — is in no step, and tagged `desired.unshown.`; so is a credential's literal text,
/// which no preview prints.
fn declared_changes() -> Vec<Change> {
    let pin = "ab".repeat(32);
    let create = |name: &str, desired: serde_json::Value| Change {
        resource_id: id(&format!("change.declared.{name}.id")),
        action: ChangeAction::Create,
        steps: vec![PlanStep::Run(h(&format!("step.declared.{name}")))],
        desired: resource(desired),
        depends_on: Vec::new(),
        trigger: None,
    };
    vec![
        create(
            "file.inline",
            serde_json::json!({
                "id": "f", "name": h("desired.declared.file.name"), "type": "file",
                "path": h("desired.declared.file.path"),
                "content": {"type": "inline", "content": h("desired.unshown.file.content")},
                "mode": "640", "owner": "app", "group": "www",
                "triggers": [h("desired.declared.file.trigger")],
                "validate": h("desired.declared.file.validate"),
            }),
        ),
        create(
            "file.template",
            serde_json::json!({
                "id": "t", "type": "file", "path": "/t",
                "content": {"type": "template", "template": h("desired.unshown.template.text"),
                    "vars": {h("desired.declared.template.var"): h("desired.declared.template.value")},
                    "kinds": {h("desired.declared.template.var"): "text"}},
            }),
        ),
        create(
            "file.remote",
            serde_json::json!({
                "id": "r", "type": "file", "path": "/r",
                "content": {"type": "remote", "url": h("desired.declared.remote.url"),
                    "blake3": pin, "extract": {"type": "tar.gz", "strip_components": 1},
                    "auth": {"scheme": "bearer", "token": h("desired.unshown.remote.token")}},
            }),
        ),
        create(
            "build",
            serde_json::json!({
                "id": "b", "type": "build", "run": h("desired.unshown.build.run"),
                "output": h("desired.declared.build.output"),
                "cwd": h("desired.declared.build.cwd"),
                "env": {"CC": h("desired.declared.build.env")},
                "source": {"type": "remote", "url": h("desired.declared.build.url"),
                    "blake3": pin, "extract": {"type": "tar.xz", "strip_components": 2},
                    "auth": {"scheme": "bearer", "token": h("desired.unshown.build.token")},
                    "verify": {"scheme": "minisign",
                        "public_key": "RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3",
                        "signature_url": h("desired.declared.build.signature_url")}},
            }),
        ),
        create(
            "installer",
            serde_json::json!({
                "id": "i", "type": "installer", "url": h("desired.unshown.installer.url"),
                "check": h("desired.declared.installer.check"),
                "shell": h("desired.unshown.installer.shell"),
            }),
        ),
        create(
            "package",
            serde_json::json!({
                "id": "p", "type": "package", "from": {"apt": "curl"},
                "check": h("desired.declared.package.check"),
            }),
        ),
        create(
            "service",
            serde_json::json!({
                "id": "s", "type": "service", "service": "nginx",
                "enabled": true,
                "restart_on": [h("desired.declared.service.restart_on")],
                "reload_on": [h("desired.declared.service.reload_on")],
            }),
        ),
        create(
            "pipeline",
            serde_json::json!({
                "id": "pl", "name": h("desired.declared.pipeline.name"), "type": "pipeline",
                "steps": [
                    {"id": h("desired.declared.pipeline.step.id"),
                        "name": h("desired.declared.pipeline.step.name"),
                        "run": h("desired.unshown.pipeline.run")},
                    {"id": h("desired.declared.pipeline.unnamed.id"),
                        "run": h("desired.unshown.pipeline.unnamed.run")},
                ],
            }),
        ),
    ]
}

/// What a plan's references resolved to: a hostile value, a secret, an unset variable.
fn references(tag: &str) -> BTreeMap<EnvVarName, ReferenceValue> {
    let name = |name: &str| EnvVarName::new(name).unwrap();
    [
        (name("ZAP_T_PLAIN"), ReferenceValue::Value(h(tag))),
        (name("ZAP_T_SECRET"), ReferenceValue::Secret),
        (name("ZAP_T_UNSET"), ReferenceValue::Unset),
    ]
    .into()
}

fn plan_report(plan_hash: PlanAddress) -> PlanReport {
    let mut changes = vec![script_change()];
    let mut detected = BTreeMap::new();
    for (change, current) in drifted_changes() {
        detected.insert(change.resource_id.clone(), Detection::Drifted { current });
        changes.push(change);
    }
    changes.push(triggered_change());
    changes.extend(declared_changes());
    PlanReport {
        target: h("report.target"),
        plan: Plan {
            references: references("plan.reference"),
            changes,
            target: target(),
            machine: machine(),
        },
        plan_hash,
        unrecorded: Some(h("unrecorded")),
        warnings: vec![h("warning")],
        detected,
        unverifiable: vec![h("unverifiable.var")],
        held: held(),
        lock_standing: lock_standing(),
    }
}

/// What these hostile plans hold that no preview prints: a change's dependencies, what
/// fired its trigger, the desired resource's own copy of the id, and the fields a
/// planned change carries in its steps (these plans' steps are stand-ins, so a script's
/// `run` and a service's unit are in no step here —
/// [`the_previews_print_what_a_change_declares`] holds real plans to them).
const NO_PREVIEW_PRINTS: &[&str] = &[
    "desired.unshown.",
    "change.script.depends_on",
    "desired.script.id",
    "desired.script.run",
    "trigger.source",
];

/// What the step views (`zap plan`, `zap apply`) leave out besides: everything observed,
/// and the desired attributes only `--diff` joins it against.
const STEP_VIEW_LEAVES_OUT: &[&str] = &[
    "desired.user.shell",
    "desired.apt_repo.source",
    "observed.dir.mode",
    "observed.dir.owner",
    "observed.dir.group",
    "observed.link.points_to",
    "observed.user.shell",
    "observed.user.group",
];

/// The `LOCK` banner is silent about orphans (`zap lock --check` reports them).
const ORPHANS: &[&str] = &["lock.orphan"];

/// `zap apply` carries no lock standing: a pin its ledger doesn't answer for is an
/// error there, not a banner.
const LOCK_STANDING: &[&str] = &[
    "lock.missing",
    "lock.stale",
    "lock.unverifiable.id",
    "lock.unverifiable.var",
    "lock.orphan",
];

fn apply_report(wetrun: bool, refused: Option<PlanUnreviewed>, hash: PlanAddress) -> ApplyReport {
    let plan = plan_report(hash);
    let executed = wetrun && refused.is_none();
    ApplyReport {
        target: plan.target,
        wetrun,
        plan: plan.plan,
        plan_hash: plan.plan_hash,
        unrecorded: plan.unrecorded,
        warnings: plan.warnings,
        outcomes: if executed {
            vec![
                ChangeOutcome::Completed {
                    resource_id: id("outcome.completed.id"),
                    output: h("outcome.completed.output"),
                },
                ChangeOutcome::Failed {
                    resource_id: id("outcome.failed.id"),
                    error: h("outcome.failed.error"),
                    code: ErrorCode::ExecutionFailed,
                },
                ChangeOutcome::Skipped {
                    resource_id: id("outcome.skipped.id"),
                    reason: h("outcome.skipped.reason"),
                },
            ]
        } else {
            Vec::new()
        },
        summary: executed.then_some(RunSummary {
            total: 3,
            completed: 1,
            failed: 1,
            skipped: 1,
        }),
        auto_locked: vec![h("auto_locked")],
        unverifiable: plan.unverifiable,
        held: plan.held,
        residual: Vec::new(),
        post_detect_error: None,
        refused,
        confirmation: None,
    }
}

/// An executed wetrun's report, with what its re-detection left: residual resources, or
/// the error it failed with.
fn executed_report(redetected: bool) -> ApplyReport {
    let mut report = apply_report(true, None, PlanAddress::Hash("deadbeef".to_owned()));
    if redetected {
        report.residual = observed()
            .into_iter()
            .map(|(name, _, current)| ResidualResource {
                resource_id: id(&format!("residual.{name}.id")),
                state: ResidualState::Drifted { current },
            })
            .collect();
        report.residual.push(ResidualResource {
            resource_id: id("residual.undetermined.id"),
            state: ResidualState::Undetermined {
                reason: h("residual.undetermined.reason"),
            },
        });
        report.residual.push(ResidualResource {
            resource_id: id("residual.absent.id"),
            state: ResidualState::Absent,
        });
    } else {
        report.post_detect_error = Some(h("post_detect_error"));
    }
    report
}

/// What an executed wetrun's report leaves out: the changes it ran, shown as their
/// outcomes, and a completed change's output.
const OUTCOME_VIEW_LEAVES_OUT: &[&str] = &[
    "change.",
    "step.",
    "desired.",
    "trigger.",
    "outcome.completed.output",
];

/// A pin is abbreviated to its head, which stops short of the tag's end.
const ABBREVIATED: &[&str] = &["observed.file.pin", "observed.build.pin"];

fn deploy_plan() -> DeployPlan {
    let step = |id, name: &str, action| DeployStep {
        id,
        name: h(name),
        action,
    };
    DeployPlan {
        references: references("deploy.body.reference"),
        version: h("deploy.version"),
        subject: h("deploy.body.subject"),
        previous: Some(h("deploy.previous")),
        target: target(),
        host: h("deploy.host"),
        user: Some(h("deploy.body.user")),
        deployed_by: h("deploy.body.deployed_by"),
        dirty: true,
        preflight: DriftPreflight::Checks {
            resources: 1,
            digest: h("deploy.body.digest"),
        },
        steps: vec![
            step(
                DeployStepId::Build,
                "deploy.body.build.name",
                DeployAction::Build {
                    command: h("deploy.body.build.command"),
                },
            ),
            step(
                DeployStepId::Tarball,
                "deploy.body.tarball.name",
                DeployAction::Tarball {
                    command: h("deploy.body.tarball.command"),
                },
            ),
            step(
                DeployStepId::Upload,
                "deploy.body.upload.name",
                DeployAction::Upload {
                    remote: h("deploy.body.upload.remote"),
                },
            ),
            step(
                DeployStepId::ExtractSwap,
                "deploy.body.extract_swap.name",
                DeployAction::ExtractSwap(ReleaseSwap {
                    app: h("deploy.body.extract_swap.app"),
                    keep: 5,
                    shared: vec![h("deploy.body.extract_swap.shared")],
                    prepare: vec![h("deploy.body.extract_swap.prepare")],
                }),
            ),
            step(
                DeployStepId::Restart,
                "deploy.body.restart.name",
                DeployAction::Restart {
                    command: h("deploy.body.restart.command"),
                },
            ),
            step(
                DeployStepId::Health,
                "deploy.body.health.name",
                DeployAction::Health {
                    url: h("deploy.body.health.url"),
                    url_label: h("deploy.body.health.url_label"),
                    attempts: 3,
                    interval_ms: 100,
                    timeout_ms: 5000,
                },
            ),
            step(
                DeployStepId::Readiness,
                "deploy.body.readiness.name",
                DeployAction::Readiness {
                    url: h("deploy.body.readiness.url"),
                    url_label: h("deploy.body.readiness.url_label"),
                    attempts: 3,
                    interval_ms: 100,
                    timeout_ms: 5000,
                },
            ),
        ],
        warnings: vec![h("deploy.plan.warning")],
    }
}

fn deploy_report(outcome: DeployOutcome) -> DeployReport {
    let wetrun = !matches!(
        outcome,
        DeployOutcome::DryRun | DeployOutcome::DryRunUnbindable(_) | DeployOutcome::DryRunDirty
    );
    let stepped = outcome.run().is_some();
    DeployReport {
        target: h("report.target"),
        wetrun,
        recorded: match outcome {
            DeployOutcome::DryRun => Some(DeployPreviewPass::DryRun),
            DeployOutcome::Refused(_) => Some(DeployPreviewPass::RefusedWetrun),
            _ => None,
        },
        outcome,
        version: h("report.version"),
        plan: deploy_plan(),
        plan_hash: "deadbeef".to_owned(),
        step_outcomes: if stepped {
            vec![
                StepOutcome::Completed {
                    step: h("step_outcome.completed.step"),
                    output: h("step_outcome.completed.output"),
                },
                StepOutcome::Failed {
                    step: h("step_outcome.failed.step"),
                    error: h("step_outcome.failed.error"),
                },
                StepOutcome::Skipped {
                    step: h("step_outcome.skipped.step"),
                    reason: h("step_outcome.skipped.reason"),
                },
            ]
        } else {
            Vec::new()
        },
        warnings: vec![h("warning")],
        held: held(),
        lock_standing: lock_standing(),
        confirmation: None,
    }
}

/// What a hostile wetrun measured: its preflight and its total, and `steps`.
fn deploy_run(steps: Vec<StepRecord>) -> DeployRun {
    let second = std::time::Duration::from_secs(1);
    DeployRun {
        preflight: Some(second),
        steps,
        total: second * 2,
    }
}

/// A wetrun that failed after its swap and whose rollback was not done, so the report
/// has a rollback row and a verdict to say it in.
fn failed_after_swap() -> DeployOutcome {
    DeployOutcome::Failed {
        run: deploy_run(Vec::new()),
        left: FailureState::AfterSwap(Rollback::Ran {
            outcome: RollbackOutcome::NotDone,
            took: std::time::Duration::from_secs(1),
        }),
    }
}

/// What no deploy render prints: the report's own copy of the version (the render reads
/// the plan's).
const DEPLOY_NEVER_PRINTS: &[&str] = &["report.version"];

/// The plan's body — the host, the declared target, the preflight digest, and the steps
/// — which a deploy preview prints and a render without one leaves out.
const DEPLOY_PLAN_BODY: &[&str] = &["deploy.body.", "target."];

/// A completed step's output, which the outcome lines leave out unless the step's
/// action has a summary.
const STEP_OUTPUT: &[&str] = &["step_outcome.completed.output"];

/// The host the plan names, which a preview and a wetrun's verdict print and a
/// preflight bail leaves out.
const DEPLOY_HOST: &[&str] = &["deploy.host"];

fn hashed() -> PlanAddress {
    PlanAddress::Hash("deadbeef".to_owned())
}

/// Every render, each over reports that between them reach every branch that prints
/// text. A report is a full struct literal, so a field added to one is a compile error
/// here until it is given a hostile value.
const CASES: &[Case] = &[
    Case {
        render: "escape::render_block",
        name: "a block",
        run: || {
            let mut out = String::new();
            render_block(&mut out, "  lead — ", &h("block.text"));
            out
        },
        unprinted: &[],
    },
    Case {
        render: "error::render",
        name: "an error quoting a path and a command's stderr",
        run: || {
            Error::ConfigEval {
                path: h("error.path"),
                kind: fuz_eval::EvalErrorKind::ModuleThrew,
                message: h("error.report"),
                fgro_hint: Some(h("error.fgro_hint")),
                stderr: h("error.stderr"),
            }
            .render()
        },
        unprinted: &[],
    },
    Case {
        render: "error::render",
        name: "an error quoting a target and what ssh said",
        run: || {
            Error::Connectivity {
                target: h("error.target"),
                message: h("error.message"),
                changed_host_key: None,
            }
            .render()
        },
        unprinted: &[],
    },
    Case {
        render: "lock::render_name_only_refs",
        name: "a note",
        run: || {
            let mut out = String::new();
            render_name_only_refs(&mut out, &name_only());
            out
        },
        unprinted: &[],
    },
    Case {
        render: "commands::lock::render_lock",
        name: "pins written",
        run: || {
            render_lock(&LockReport {
                path: h("lock.path"),
                toolchain: zap_types::scalar::ContentHash::of_bytes(b"fgro"),
                previous_toolchain: Some(zap_types::scalar::ContentHash::of_bytes(b"old")),
                locked: vec![h("lock.locked")],
                name_only: name_only(),
            })
        },
        unprinted: &[],
    },
    Case {
        render: "commands::lock::render_lock",
        name: "nothing eligible",
        run: || {
            render_lock(&LockReport {
                path: h("lock.path"),
                toolchain: zap_types::scalar::ContentHash::of_bytes(b"fgro"),
                previous_toolchain: Some(zap_types::scalar::ContentHash::of_bytes(b"old")),
                locked: Vec::new(),
                name_only: Vec::new(),
            })
        },
        unprinted: &[],
    },
    Case {
        render: "commands::lock::render_lock_check",
        name: "every standing",
        run: || {
            render_lock_check(&LockCheckReport {
                stale_toolchain: None,
                standing: lock_standing(),
                name_only: name_only(),
            })
        },
        unprinted: &[],
    },
    Case {
        render: "commands::lock::render_lock_check",
        name: "a stale toolchain pin",
        run: || {
            render_lock_check(&LockCheckReport {
                stale_toolchain: Some(zap_core::commands::lock::StaleToolchain {
                    fgro: h("lock.fgro"),
                    pinned: zap_types::scalar::ContentHash::of_bytes(b"pinned"),
                    current: zap_types::scalar::ContentHash::of_bytes(b"current"),
                }),
                ..LockCheckReport::default()
            })
        },
        unprinted: &[],
    },
    Case {
        render: "commands::update::render_update",
        name: "every outcome",
        run: || {
            render_update(&UpdateReport {
                outcomes: vec![
                    UpdateOutcome::Advanced {
                        id: h("update.advanced.id"),
                        from: Some(h("update.advanced.from")),
                        to: h("update.advanced.to"),
                    },
                    UpdateOutcome::Refreshed {
                        id: h("update.refreshed.id"),
                        pin: h("update.refreshed.pin"),
                    },
                    UpdateOutcome::Unchanged {
                        id: h("update.unchanged.id"),
                    },
                    UpdateOutcome::Failed {
                        id: h("update.failed.id"),
                        error: h("update.failed.error"),
                        class: zap_core::commands::update::FailureClass::NeedsAction,
                    },
                ],
                name_only: name_only(),
            })
        },
        // An unchanged pin is counted, not named.
        unprinted: &[&["update.unchanged.id"]],
    },
    Case {
        render: "commands::update::render_update",
        name: "nothing to advance",
        run: || {
            render_update(&UpdateReport {
                outcomes: vec![UpdateOutcome::Unchanged {
                    id: h("update.unchanged.id"),
                }],
                name_only: name_only(),
            })
        },
        unprinted: &[&["update.unchanged.id"]],
    },
    Case {
        render: "commands::detect::render_detect",
        name: "every detection",
        run: || render_detect(&detect_report()),
        unprinted: &[ORPHANS, ABBREVIATED],
    },
    Case {
        render: "commands::status::render_status",
        name: "a last run that previewed a plan",
        run: || {
            render_status(&status_report(
                Some(h("status.host")),
                Some(last_run(RunCommand::Plan)),
            ))
        },
        unprinted: &[ORPHANS],
    },
    Case {
        render: "commands::status::render_status",
        name: "a last run that previewed none",
        run: || {
            render_status(&status_report(
                Some(h("status.host")),
                Some(last_run(RunCommand::Detect)),
            ))
        },
        unprinted: &[ORPHANS],
    },
    Case {
        render: "commands::status::render_status",
        name: "no last run",
        run: || render_status(&status_report(Some(h("status.host")), None)),
        unprinted: &[ORPHANS],
    },
    Case {
        render: "commands::status::render_status",
        name: "a host that doesn't resolve",
        run: || render_status(&status_report(None, None)),
        unprinted: &[ORPHANS],
    },
    Case {
        render: "commands::status::render_status",
        name: "a host that names no one machine",
        run: || {
            render_status(&StatusReport {
                unidentified: Some(h("status.unidentified")),
                ..status_report(Some(h("status.host")), None)
            })
        },
        unprinted: &[ORPHANS, &["status.host"]],
    },
    Case {
        render: "commands::plan::render_plan",
        name: "a plan",
        run: || render_plan(&plan_report(hashed())),
        unprinted: &[NO_PREVIEW_PRINTS, STEP_VIEW_LEAVES_OUT, ORPHANS],
    },
    Case {
        render: "commands::plan::render_plan",
        name: "a plan that names no one machine",
        run: || render_plan(&plan_report(PlanAddress::Unbindable(h("unbindable")))),
        unprinted: &[NO_PREVIEW_PRINTS, STEP_VIEW_LEAVES_OUT, ORPHANS],
    },
    Case {
        render: "commands::plan::render_plan_diff",
        name: "a plan",
        run: || render_plan_diff(&plan_report(hashed())),
        unprinted: &[NO_PREVIEW_PRINTS, ORPHANS],
    },
    Case {
        render: "commands::plan::render_plan_diff",
        name: "a plan that names no one machine",
        run: || render_plan_diff(&plan_report(PlanAddress::Unbindable(h("unbindable")))),
        unprinted: &[NO_PREVIEW_PRINTS, ORPHANS],
    },
    Case {
        render: "commands::apply::render_apply",
        name: "a dry run",
        run: || render_apply(&apply_report(false, None, hashed())),
        unprinted: &[NO_PREVIEW_PRINTS, STEP_VIEW_LEAVES_OUT, LOCK_STANDING],
    },
    Case {
        render: "commands::apply::render_apply",
        name: "a dry run of a plan that names no one machine",
        run: || {
            render_apply(&apply_report(
                false,
                None,
                PlanAddress::Unbindable(h("unbindable")),
            ))
        },
        unprinted: &[NO_PREVIEW_PRINTS, STEP_VIEW_LEAVES_OUT, LOCK_STANDING],
    },
    Case {
        render: "commands::apply::render_apply",
        name: "a wetrun refused for the hash it was given",
        run: || {
            render_apply(&apply_report(
                true,
                Some(PlanUnreviewed::Expected {
                    expected: h("refused.expected"),
                }),
                hashed(),
            ))
        },
        unprinted: &[NO_PREVIEW_PRINTS, STEP_VIEW_LEAVES_OUT, LOCK_STANDING],
    },
    Case {
        render: "commands::apply::render_apply",
        name: "a wetrun refused for a preview that moved",
        run: || {
            render_apply(&apply_report(
                true,
                Some(PlanUnreviewed::Changed {
                    reviewed: h("refused.reviewed"),
                    command: RunCommand::Apply,
                    ran_at: h("refused.ran_at"),
                }),
                hashed(),
            ))
        },
        unprinted: &[NO_PREVIEW_PRINTS, STEP_VIEW_LEAVES_OUT, LOCK_STANDING],
    },
    Case {
        render: "commands::apply::render_apply",
        name: "a wetrun asking to confirm a plan whose preview moved",
        run: || {
            let mut report = apply_report(
                true,
                Some(PlanUnreviewed::Changed {
                    reviewed: h("refused.reviewed"),
                    command: RunCommand::Apply,
                    ran_at: h("refused.ran_at"),
                }),
                hashed(),
            );
            report.confirmation = Some(Confirmation::Asking);
            render_apply(&report)
        },
        unprinted: &[NO_PREVIEW_PRINTS, STEP_VIEW_LEAVES_OUT, LOCK_STANDING],
    },
    Case {
        render: "commands::apply::render_apply",
        name: "a wetrun declined at the prompt",
        run: || {
            let mut report = apply_report(
                true,
                Some(PlanUnreviewed::Changed {
                    reviewed: h("refused.reviewed"),
                    command: RunCommand::Apply,
                    ran_at: h("refused.ran_at"),
                }),
                hashed(),
            );
            report.confirmation = Some(Confirmation::Declined);
            render_apply(&report)
        },
        unprinted: &[NO_PREVIEW_PRINTS, STEP_VIEW_LEAVES_OUT, LOCK_STANDING],
    },
    Case {
        render: "commands::apply::render_apply",
        name: "a wetrun confirmed at the prompt",
        run: || {
            let mut report = executed_report(true);
            report.confirmation = Some(Confirmation::Accepted);
            render_apply(&report)
        },
        unprinted: &[OUTCOME_VIEW_LEAVES_OUT, &["observed."], LOCK_STANDING],
    },
    Case {
        render: "commands::apply::render_apply",
        name: "a wetrun whose re-detection read residual state",
        run: || render_apply(&executed_report(true)),
        // A residual resource reads `drifted`, without what was observed.
        unprinted: &[OUTCOME_VIEW_LEAVES_OUT, &["observed."], LOCK_STANDING],
    },
    Case {
        render: "commands::apply::render_apply",
        name: "a wetrun whose re-detection failed",
        run: || render_apply(&executed_report(false)),
        // The report holds nothing observed: these are the plan report's, dropped.
        unprinted: &[OUTCOME_VIEW_LEAVES_OUT, &["observed."], LOCK_STANDING],
    },
    Case {
        render: "commands::deploy::render::render_deploy",
        name: "a dry run",
        run: || render_deploy(&deploy_report(DeployOutcome::DryRun)),
        unprinted: &[DEPLOY_NEVER_PRINTS, ORPHANS],
    },
    Case {
        render: "commands::deploy::render::render_deploy",
        name: "a dry run of a plan that names no one machine",
        run: || {
            render_deploy(&deploy_report(DeployOutcome::DryRunUnbindable(h(
                "unbindable",
            ))))
        },
        unprinted: &[DEPLOY_NEVER_PRINTS, ORPHANS],
    },
    Case {
        render: "commands::deploy::render::render_deploy",
        name: "a dry run of a dirty tree without --force",
        run: || render_deploy(&deploy_report(DeployOutcome::DryRunDirty)),
        unprinted: &[DEPLOY_NEVER_PRINTS, ORPHANS],
    },
    Case {
        render: "commands::deploy::render::render_deploy",
        name: "a wetrun refused for the hash it was given",
        run: || {
            render_deploy(&deploy_report(DeployOutcome::Refused(
                PlanUnreviewed::Expected {
                    expected: h("refused.expected"),
                },
            )))
        },
        unprinted: &[DEPLOY_NEVER_PRINTS, ORPHANS],
    },
    Case {
        render: "commands::deploy::render::render_deploy",
        name: "a wetrun refused for a preview that moved",
        run: || {
            render_deploy(&deploy_report(DeployOutcome::Refused(
                PlanUnreviewed::Changed {
                    reviewed: h("refused.reviewed"),
                    command: DeployPreviewPass::DryRun,
                    ran_at: h("refused.ran_at"),
                },
            )))
        },
        unprinted: &[DEPLOY_NEVER_PRINTS, ORPHANS],
    },
    Case {
        render: "commands::deploy::render::render_deploy",
        name: "a wetrun asking to confirm a plan whose preview moved",
        run: || {
            let mut report = deploy_report(DeployOutcome::Refused(PlanUnreviewed::Changed {
                reviewed: h("refused.reviewed"),
                command: DeployPreviewPass::DryRun,
                ran_at: h("refused.ran_at"),
            }));
            report.confirmation = Some(Confirmation::Asking);
            render_deploy(&report)
        },
        unprinted: &[DEPLOY_NEVER_PRINTS, ORPHANS],
    },
    Case {
        render: "commands::deploy::render::render_deploy",
        name: "a wetrun declined at the prompt",
        run: || {
            let mut report = deploy_report(DeployOutcome::Refused(PlanUnreviewed::Changed {
                reviewed: h("refused.reviewed"),
                command: DeployPreviewPass::DryRun,
                ran_at: h("refused.ran_at"),
            }));
            report.confirmation = Some(Confirmation::Declined);
            render_deploy(&report)
        },
        unprinted: &[DEPLOY_NEVER_PRINTS, ORPHANS],
    },
    Case {
        render: "commands::deploy::render::render_deploy",
        name: "a wetrun that failed a step",
        run: || render_deploy(&deploy_report(failed_after_swap())),
        unprinted: &[DEPLOY_NEVER_PRINTS, DEPLOY_PLAN_BODY, STEP_OUTPUT, ORPHANS],
    },
    Case {
        render: "commands::deploy::render::render_deploy",
        name: "a wetrun that stopped at its preflight",
        run: || render_deploy(&deploy_report(DeployOutcome::PreflightUndetermined)),
        unprinted: &[DEPLOY_NEVER_PRINTS, DEPLOY_PLAN_BODY, DEPLOY_HOST, ORPHANS],
    },
    Case {
        render: "commands::deploy::render::render_deploy",
        name: "a deployed wetrun whose health check says how it went",
        run: || {
            // the summary's first line holds the controls: only it is shown
            let summary = h("step_record.health.summary").replace(&format!("\n{FORGED}"), "");
            let mut report = deploy_report(DeployOutcome::Deployed(deploy_run(vec![StepRecord {
                id: DeployStepId::Health,
                took: std::time::Duration::from_secs(1),
                summary: Some(StepSummary::Said(summary)),
            }])));
            report.step_outcomes = vec![StepOutcome::Completed {
                step: DeployStepId::Health.as_str().to_owned(),
                output: h("step_outcome.health.output"),
            }];
            render_deploy(&report)
        },
        unprinted: &[
            DEPLOY_NEVER_PRINTS,
            DEPLOY_PLAN_BODY,
            ORPHANS,
            // a step's output, and the outcomes this report's replaced
            &["step_outcome."],
        ],
    },
    Case {
        render: "progress::render_progress",
        name: "the lines a wetrun shows as its phases start",
        run: || {
            let step = Event::StepStarted {
                step: h("progress.step.step"),
                name: h("progress.step.name"),
            };
            let change = Event::ChangeStarted {
                resource_id: ResourceId(h("progress.change.resource_id")),
                action: ChangeAction::Update,
                kind: ResourceType::Service,
            };
            let outcome = Event::StepCompleted {
                step: h("progress.outcome.step"),
                output: h("progress.outcome.output"),
            };
            [
                Progress::Notice(Notice::DriftPreflight { resources: 2 }),
                Progress::Event(&step),
                Progress::Event(&change),
                Progress::Event(&outcome),
                Progress::Notice(Notice::Redetect { resources: 1 }),
            ]
            .into_iter()
            .filter_map(render_progress)
            .map(|line| line + "\n")
            .collect()
        },
        unprinted: &[&["progress.outcome."]],
    },
];

/// `zap plan --diff` prints every line `zap plan` does, in its order, for drifted
/// updates as for creates: the attribute diff is added to a change's lines, never put
/// in place of its steps, so what didn't drift is on screen in both views that print
/// the hash a wetrun binds to.
#[test]
fn the_diff_view_prints_every_line_the_plan_does() {
    let report = plan_report(hashed());
    assert!(
        report.plan.changes.iter().any(|change| {
            !change.steps.is_empty()
                && matches!(
                    report.detected.get(&change.resource_id),
                    Some(Detection::Drifted { .. })
                )
        }),
        "the report holds no drifted update with steps to hold --diff to"
    );
    let plan = render_plan(&report);
    let diff = render_plan_diff(&report);
    // the headers name the view
    let mut diff_lines = diff
        .lines()
        .filter(|line| !line.starts_with("plan diff — "));
    for line in plan.lines().filter(|line| !line.starts_with("plan — ")) {
        assert!(
            diff_lines.any(|other| other == line),
            "`zap plan --diff` leaves out, or reorders, a line `zap plan` prints: \
             {line:?}\n{diff}"
        );
    }
}

#[test]
fn every_render_escapes_what_it_prints() {
    let mut failures = Vec::new();
    for case in CASES {
        take_tags();
        let rendered = (case.run)();
        let tags = take_tags();
        let mut broken = broken_rules(case, &rendered, &tags);
        // Each report holds a reference somewhere it is printed, so the rule that none
        // is printed raw is a rule about something.
        if !rendered.contains(SHOWN) {
            broken.push(format!("shows no reference as `{SHOWN}`"));
        }
        if !broken.is_empty() {
            failures.push(format!(
                "{} ({}):\n  {}\n{rendered}",
                case.render,
                case.name,
                broken.join("\n  ")
            ));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n\n"));
}

/// The `render` functions that are not entry points: each is reached through a render
/// in [`CASES`], whose hostile report gives it the text it prints.
const HELPERS: &[&str] = &[
    "commands::render::render_trigger",
    "commands::render::render_change",
    "commands::render::render_change_header",
    "commands::render::render_steps",
    "commands::render::render_typed_step",
    "commands::render::render_declared",
    "commands::render::render_content",
    "commands::render::render_fetched",
    "commands::render::render_machine",
    "commands::render::render_native_puts",
    "commands::render::render_target",
    "commands::render::render_plan_subject",
    "commands::render::render_references",
    "commands::render::render_unbindable",
    "commands::render::render_unrecorded",
    "commands::render::render_address",
    "commands::checks::render_unverifiable",
    "commands::checks::render_refused",
    "commands::checks::render_warnings",
    "commands::checks::render_lock_standing",
    "commands::checks::render_undetermined",
    "commands::apply::render_preview",
    "commands::apply::render_refused",
    "commands::apply::render_residual",
    "commands::apply::render_outcomes",
    "commands::plan::render_change_diff",
    "commands::status::render_run_unverifiable",
    "commands::deploy::render::render_plan_preview",
    "commands::deploy::render::render_recap",
    "commands::deploy::render::render_action",
    "commands::deploy::render::render_swap",
    "commands::deploy::render::render_poll",
    "commands::deploy::render::render_run",
    "commands::deploy::render::render_rows",
    "commands::deploy::render::render_summary",
    "commands::deploy::render::render_verdict",
];

/// Where a file's own inline test module starts: the first `#[cfg(test)]` — or
/// `#[cfg(all(test, …))]` — attribute on a `mod <name> {` with a body. Not a file's
/// first `#[cfg(test)]`, which may sit on an import, an enum variant, or the
/// declaration of a test module kept in a file of its own (`mod tests;`), each with
/// shipped code after it.
fn inline_tests_start(source: &str) -> Option<usize> {
    let mut from = 0;
    while let Some(found) = source[from..].find("#[cfg(") {
        let at = from + found;
        let (attribute, after) = source[at..].split_once('\n')?;
        from = at + attribute.len();
        let is_test = attribute == "#[cfg(test)]"
            || (attribute.starts_with("#[cfg(all(test,") && attribute.ends_with(")]"));
        let declares_inline = after.strip_prefix("mod ").is_some_and(|rest| {
            rest.lines()
                .next()
                .is_some_and(|line| line.trim_end().ends_with('{'))
        });
        if is_test && declares_inline {
            return Some(at);
        }
    }
    None
}

/// The source of every module of the crate outside its tests, as
/// `(path under src/, code)`: files and directories named `tests` are left out, and a
/// file is cut where its own inline test module starts ([`inline_tests_start`]).
fn shipped_source() -> Vec<(String, String)> {
    fn walk(dir: &std::path::Path, root: &std::path::Path, found: &mut Vec<(String, String)>) {
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            let stem = path.file_stem().unwrap().to_str().unwrap().to_owned();
            if stem == "tests" || stem.ends_with("_tests") {
                continue;
            }
            if path.is_dir() {
                walk(&path, root, found);
            } else if path.extension().is_some_and(|extension| extension == "rs") {
                let source = std::fs::read_to_string(&path).unwrap();
                let code =
                    inline_tests_start(&source).map_or(source.as_str(), |tests| &source[..tests]);
                let relative = path.strip_prefix(root).unwrap().to_str().unwrap();
                found.push((relative.to_owned(), code.to_owned()));
            }
        }
    }
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut found = Vec::new();
    walk(&root, &root, &mut found);
    found.sort();
    found
}

/// Whether `line` holds `needle` as a whole macro or path — `print!(` not as the tail of
/// `eprint!(`.
fn holds(line: &str, needle: &str) -> bool {
    line.match_indices(needle).any(|(at, _)| {
        !line[..at]
            .chars()
            .next_back()
            .is_some_and(|before| before.is_alphanumeric() || before == '_')
    })
}

/// zap writes to the terminal in a known set of places: the binary prints what a render
/// returned, and the crate itself writes only the eval-cache log lines, the one line
/// that says SSH multiplexing is off, and the `--json` event stream. A print added anywhere else in the crate fails here by file and line,
/// so the text it prints is looked at — a render that returns a `String` is covered by
/// [`every_render_is_in_the_table`]; a function that prints for itself is covered by
/// nothing else.
#[test]
fn the_crate_prints_only_where_it_is_known_to() {
    const PRINTS: &[&str] = &[
        "print!(",
        "println!(",
        "eprint!(",
        "eprintln!(",
        "dbg!(",
        "io::stdout()",
        "io::stderr()",
        "stdout()",
        "stderr()",
    ];
    // (file, the line that prints): each prints a line a function built and a test
    // reads — `skipped_line`, `observation_line`, `event_line`, `multiplexing_for`'s
    // notice.
    const KNOWN: &[(&str, &str)] = &[
        (
            "connection/ssh.rs",
            r#"eprintln!("{}", escape_line(&notice));"#,
        ),
        (
            "config/eval_cache.rs",
            r#"eprintln!("{}", skipped_line(config_path));"#,
        ),
        ("config/eval_cache.rs", r#"eprintln!("{line}");"#),
        ("event.rs", "let mut out = std::io::stdout().lock();"),
    ];
    let mut known: Vec<(&str, &str)> = KNOWN.to_vec();
    let mut unlisted = Vec::new();
    for (path, code) in shipped_source() {
        for (number, line) in code.lines().enumerate() {
            let line = line.trim();
            if line.starts_with("//") || !PRINTS.iter().any(|needle| holds(line, needle)) {
                continue;
            }
            match known
                .iter()
                .position(|&(file, text)| file == path && text == line)
            {
                Some(listed) => drop(known.remove(listed)),
                None => unlisted.push(format!("src/{path}:{}: {line}", number + 1)),
            }
        }
    }
    assert!(
        unlisted.is_empty(),
        "src/ prints where it isn't known to — escape what a new print writes, then list \
         it:\n{}",
        unlisted.join("\n")
    );
    assert!(
        known.is_empty(),
        "listed prints that src/ no longer holds: {known:?}"
    );
}

/// Every function of the crate whose name starts with `render`, however it is declared
/// (`const`, `async`, `pub(in …)`, an attribute on the same line), as
/// `(module::name, whether it is `pub`)`. A drop-in for `renders_in_source`.
fn renders_in_shipped_source() -> BTreeSet<(String, bool)> {
    let mut found = BTreeSet::new();
    for (path, code) in shipped_source() {
        let module = path
            .trim_end_matches(".rs")
            .split('/')
            .filter(|part| *part != "mod")
            .collect::<Vec<_>>()
            .join("::");
        for line in code.lines() {
            let line = line.trim_start();
            if line.starts_with("//") {
                continue;
            }
            let Some((before, rest)) = line.split_once("fn render") else {
                continue;
            };
            // A definition: `fn` starts the line or follows a space (not `my_fn render`).
            if !(before.is_empty() || before.ends_with(' ')) {
                continue;
            }
            let name: String = rest
                .chars()
                .take_while(|c| c.is_alphanumeric() || *c == '_')
                .collect();
            let public = before.split_whitespace().any(|word| word == "pub");
            found.insert((format!("{module}::render{name}"), public));
        }
    }
    found
}

/// A render is in the table before it ships: every public `render` function in the
/// crate has a case in [`CASES`], and every other one is listed in [`HELPERS`]. Adding
/// one fails here until it is — and adding it means giving it a hostile report.
#[test]
fn every_render_is_in_the_table() {
    let source = renders_in_shipped_source();
    let public: BTreeSet<&str> = source
        .iter()
        .filter(|(_, public)| *public)
        .map(|(name, _)| name.as_str())
        .collect();
    let helpers: BTreeSet<&str> = source
        .iter()
        .filter(|(_, public)| !*public)
        .map(|(name, _)| name.as_str())
        .collect();
    let cases: BTreeSet<&str> = CASES.iter().map(|case| case.render).collect();
    assert_eq!(
        public, cases,
        "the public renders in src/ (left) are not the ones `CASES` covers (right)"
    );
    assert_eq!(
        helpers,
        HELPERS.iter().copied().collect(),
        "the other renders in src/ (left) are not the ones `HELPERS` lists (right)"
    );
}

// --- the previews show what the hash covers ---

/// A remote target that declares every field, as `zap.target` wrote it.
fn declared_target() -> serde_json::Value {
    serde_json::json!({
        "host": Text::reference("HOST"), "user": Text::reference("DEPLOY_USER"),
        "bootstrap_user": "root",
        "port": 2222, "key_path": "~/.ssh/deploy", "home": "/home/deploy",
        "package_manager": "apt", "service_manager": "systemd",
    })
}

fn a_change() -> Change {
    Change {
        resource_id: ResourceId("notes".to_owned()),
        action: ChangeAction::Create,
        steps: vec![PlanStep::Run("mkdir -p /srv/notes".to_owned())],
        desired: resource(serde_json::json!({
            "id": "notes", "type": "directory", "path": "/srv/notes", "mode": "755",
        })),
        depends_on: Vec::new(),
        trigger: None,
    }
}

/// `plan` under the header a target with a referenced host has, as each preview renders it.
fn previews(plan: &Plan) -> [(&'static str, String); 3] {
    let report = PlanReport {
        target: marker("HOST"),
        plan: plan.clone(),
        plan_hash: PlanAddress::Hash("deadbeef".to_owned()),
        unrecorded: None,
        warnings: Vec::new(),
        detected: BTreeMap::new(),
        unverifiable: Vec::new(),
        held: Vec::new(),
        lock_standing: LockStanding::default(),
    };
    let applied = ApplyReport {
        target: report.target.clone(),
        wetrun: false,
        plan: plan.clone(),
        plan_hash: report.plan_hash.clone(),
        unrecorded: None,
        warnings: Vec::new(),
        outcomes: Vec::new(),
        summary: None,
        auto_locked: Vec::new(),
        unverifiable: Vec::new(),
        held: Vec::new(),
        residual: Vec::new(),
        post_detect_error: None,
        refused: None,
        confirmation: None,
    };
    [
        ("zap plan", render_plan(&report)),
        ("zap plan --diff", render_plan_diff(&report)),
        ("zap apply", render_apply(&applied)),
    ]
}

/// The previews of a remote and of a local plan: the machine's lines, then the declared
/// target as one line of JSON, between the header and the changes.
#[test]
fn the_previews_print_the_declared_target() {
    // The `target:` line prints each reference as the JSON it is declared as.
    let declared = |name: &str| serde_json::to_string(&Text::reference(name)).unwrap();
    let remote_lines = format!(
        "  host: a.example.com\n  user: deploy\n  target: \
         {{\"local\":false,\"host\":{},\"user\":{},\
         \"bootstrap_user\":\"root\",\"port\":2222,\"key_path\":\"~/.ssh/deploy\",\
         \"home\":\"/home/deploy\",\"package_manager\":\"apt\",\"service_manager\":\"systemd\"}}\n  [+] notes  (directory)\n      path: /srv/notes\n      mode: 755\n      > mkdir -p /srv/notes\n",
        declared("HOST"),
        declared("DEPLOY_USER")
    );
    let host = shown("HOST");
    let remote = Plan {
        references: BTreeMap::new(),
        changes: vec![a_change()],
        target: serde_json::from_value(declared_target()).unwrap(),
        machine: Machine::Remote {
            host: "a.example.com".to_owned(),
            user: Some("deploy".to_owned()),
        },
    };
    let [(_, plan), (_, diff), (_, apply)] = previews(&remote);
    assert_eq!(
        plan,
        format!("plan — target {host} (1 change(s): +1 ~0)\n{remote_lines}plan_hash: deadbeef\n")
    );
    assert_eq!(
        diff,
        format!(
            "plan diff — target {host} (1 change(s): +1 ~0)\n{remote_lines}plan_hash: deadbeef\n"
        )
    );
    assert_eq!(
        apply,
        format!(
            "apply — target {host} (dry-run)\n{remote_lines}  (dry-run — re-run with --wetrun to \
             apply)\nplan_hash: deadbeef\n"
        )
    );

    let local = Plan {
        references: BTreeMap::new(),
        changes: Vec::new(),
        target: serde_json::from_value(serde_json::json!({
            "local": true, "package_manager": "apk", "service_manager": "openrc",
        }))
        .unwrap(),
        machine: local_machine(),
    };
    for (preview, rendered) in previews(&local) {
        assert!(
            rendered.contains(
                "\n  target: {\"local\":true,\"package_manager\":\"apk\",\
                 \"service_manager\":\"openrc\"}\n  (no changes — converged)\n"
            ),
            "{preview}:\n{rendered}"
        );
    }
    let bare = Plan {
        target: Target::local(),
        ..local
    };
    for (preview, rendered) in previews(&bare) {
        assert!(
            rendered.contains("\n  target: {\"local\":true}\n"),
            "{preview}:\n{rendered}"
        );
    }
}

/// Everything of a plan's target and machine that its hash covers is on screen: each
/// single change to one — every field the target declares, the resolved host, the
/// connecting user — that moves `plan_hash` moves what each preview prints. The header's
/// own label stays put, so the move is in the lines under it.
#[test]
fn every_change_to_a_plans_target_or_machine_that_moves_its_hash_moves_its_previews() {
    use zap_types::config_hash::plan_hash;

    let with_target = |edit: &dyn Fn(&mut serde_json::Value)| -> Target {
        let mut target = declared_target();
        edit(&mut target);
        serde_json::from_value(target).unwrap()
    };
    let field = |name: &'static str, value: serde_json::Value| {
        with_target(&move |target: &mut serde_json::Value| target[name] = value.clone())
    };
    let without = |name: &'static str| {
        with_target(&move |target: &mut serde_json::Value| {
            target.as_object_mut().unwrap().remove(name);
        })
    };
    let named = |references: &[(&str, ReferenceValue)]| -> BTreeMap<EnvVarName, ReferenceValue> {
        references
            .iter()
            .map(|(name, value)| (EnvVarName::new(*name).unwrap(), value.clone()))
            .collect()
    };
    // Two values that agree for as long as a preview shows one.
    let long = format!("{}a", "a".repeat(REFERENCE_VALUE_SHOWN + 40));
    let base = Plan {
        references: named(&[("APP_DIR", ReferenceValue::Value("/srv/a".to_owned()))]),
        changes: vec![a_change()],
        target: serde_json::from_value(declared_target()).unwrap(),
        machine: Machine::Remote {
            host: "a.example.com".to_owned(),
            user: Some("deploy".to_owned()),
        },
    };
    let target = |target: Target| Plan {
        target,
        ..base.clone()
    };
    let referencing = |references: &[(&str, ReferenceValue)]| Plan {
        references: named(references),
        ..base.clone()
    };
    let machine = |machine: Machine| Plan {
        machine,
        ..base.clone()
    };
    let remote = |host: &str, user: Option<&str>| Machine::Remote {
        host: host.to_owned(),
        user: user.map(str::to_owned),
    };
    let mutations: Vec<(&str, Plan)> = vec![
        ("target.host", target(field("host", "b.example.com".into()))),
        ("target.user", target(field("user", "deploy".into()))),
        ("target.user removed", target(without("user"))),
        (
            "target.bootstrap_user",
            target(field("bootstrap_user", "admin".into())),
        ),
        (
            "target.bootstrap_user removed",
            target(without("bootstrap_user")),
        ),
        ("target.port", target(field("port", 22.into()))),
        ("target.port removed", target(without("port"))),
        (
            "target.key_path",
            target(field("key_path", "~/.ssh/other".into())),
        ),
        ("target.key_path removed", target(without("key_path"))),
        ("target.home", target(field("home", "/root".into()))),
        ("target.home removed", target(without("home"))),
        (
            "target.package_manager",
            target(field("package_manager", "apk".into())),
        ),
        (
            "target.package_manager removed",
            target(without("package_manager")),
        ),
        (
            "target.service_manager",
            target(field("service_manager", "openrc".into())),
        ),
        (
            "target.service_manager removed",
            target(without("service_manager")),
        ),
        (
            "target made local",
            target(
                serde_json::from_value(serde_json::json!({
                    "local": true, "package_manager": "apt", "service_manager": "systemd",
                }))
                .unwrap(),
            ),
        ),
        (
            "machine.host",
            machine(remote("b.example.com", Some("deploy"))),
        ),
        (
            "machine.host, the declared text",
            machine(remote(&marker("HOST"), Some("deploy"))),
        ),
        (
            "machine.user",
            machine(remote("a.example.com", Some("root"))),
        ),
        ("machine.user, none", machine(remote("a.example.com", None))),
        ("machine made local", machine(local_machine())),
        (
            "references, a value",
            referencing(&[("APP_DIR", ReferenceValue::Value("/srv/b".to_owned()))]),
        ),
        (
            "references, a value past what a preview shows",
            referencing(&[(
                "APP_DIR",
                ReferenceValue::Value(format!("{}b", "a".repeat(REFERENCE_VALUE_SHOWN + 40))),
            )]),
        ),
        (
            "references, a value that reads like an unset one",
            referencing(&[(
                "APP_DIR",
                ReferenceValue::Value(
                    "is unset or empty: a wetrun stops before any change until it is set"
                        .to_owned(),
                ),
            )]),
        ),
        (
            "references, a secret",
            referencing(&[("APP_DIR", ReferenceValue::Secret)]),
        ),
        (
            "references, unset",
            referencing(&[("APP_DIR", ReferenceValue::Unset)]),
        ),
        ("references, none", referencing(&[])),
        (
            "references, another name",
            referencing(&[("APP_DIRS", ReferenceValue::Value("/srv/a".to_owned()))]),
        ),
        (
            "references, one more",
            referencing(&[
                ("APP_DIR", ReferenceValue::Value("/srv/a".to_owned())),
                ("STAGE", ReferenceValue::Value("prod".to_owned())),
            ]),
        ),
    ];

    // A value cut short in a preview still reads apart from one that differs past the cut.
    let cut = referencing(&[("APP_DIR", ReferenceValue::Value(long))]);
    let (_, other) = mutations
        .iter()
        .find(|(what, _)| *what == "references, a value past what a preview shows")
        .unwrap();
    for ((preview, one), (_, other)) in previews(&cut).iter().zip(previews(other)) {
        assert_ne!(*one, other, "`{preview}` prints two long values alike");
    }

    let hash = plan_hash(&base).unwrap();
    let shown = previews(&base);
    for (what, mutated) in &mutations {
        assert_ne!(
            plan_hash(mutated).unwrap(),
            hash,
            "{what} is a change the hash doesn't cover — not a case for this test"
        );
        for ((preview, before), (_, after)) in shown.iter().zip(previews(mutated)) {
            assert_ne!(
                *before, after,
                "{what} moves the plan's hash but not what `{preview}` prints:\n{after}"
            );
        }
    }
}

/// What of a change the hash covers and a preview doesn't print, pinned view by view:
/// each single change to a `Change` that moves `plan_hash`, and which of `zap plan`,
/// `zap plan --diff`, and `zap apply` print differently for it. A `false` is a field
/// that view reviews by hash alone.
#[test]
fn the_change_fields_each_preview_prints() {
    use zap_types::config_hash::plan_hash;

    let service = || Change {
        resource_id: ResourceId("web".to_owned()),
        action: ChangeAction::Update,
        steps: vec![PlanStep::Run("sudo systemctl restart nginx".to_owned())],
        desired: resource(serde_json::json!({
            "id": "web", "type": "service", "service": "nginx", "enabled": true,
        })),
        depends_on: vec![ResourceId("notes".to_owned())],
        trigger: Some(Trigger {
            kind: TriggerKind::Restart,
            sources: vec![ResourceId("notes".to_owned())],
            pending: false,
        }),
    };
    // A change whose steps are the typed ones, each as JSON so one field can be edited.
    let typed_steps = [
        serde_json::json!({"put": {
            "path": "/etc/sudoers.d/deploy", "run_as": "root", "check": "sudoers",
            "source": {"text": {"mode": "440", "content": "deploy ALL=(ALL) ALL\n"}},
        }}),
        serde_json::json!({"put": {
            "path": "/etc/fstab", "run_as": {"user": "app"}, "check": "none",
            "source": {"command": {
                "mode": {"keep": {"if_new": "644"}},
                "producer": {"fstab_swap_entry": {"path": "/swapfile"}},
            }},
        }}),
        serde_json::json!({"dir": {
            "path": "/home/deploy/.ssh", "mode": "700", "owner": "deploy", "group": "deploy",
        }}),
        serde_json::json!({"pg_hba_rule": {
            "database": "app", "user": "app", "host": "::1/128", "method": "scram-sha-256",
        }}),
        serde_json::json!({"put": {
            "path": "/etc/apt/sources.list.d/x.list", "run_as": "root", "check": "none",
            "source": {"command": {
                "mode": {"set": "644"},
                "producer": {"apt_source_line": {"line": "deb https://e.x/apt stable main"}},
            }},
        }}),
        serde_json::json!({"put": {
            "path": "/home/deploy/.ssh/authorized_keys", "run_as": {"user": "deploy"},
            "check": "none",
            "source": {"command": {
                "mode": {"set": "600"},
                "producer": {"authorized_keys_of": {"account": "ops"}},
            }},
        }}),
        serde_json::json!({"installer": {"url": "https://e.x/i.sh", "shell": "sh"}}),
    ];
    let steps_of = |steps: &[serde_json::Value]| -> Vec<PlanStep> {
        steps
            .iter()
            .map(|step| serde_json::from_value(step.clone()).unwrap())
            .collect()
    };
    let typed = Change {
        resource_id: ResourceId("deploy".to_owned()),
        action: ChangeAction::Create,
        steps: steps_of(&typed_steps),
        desired: resource(serde_json::json!({
            "id": "deploy", "type": "user", "username": "deploy",
        })),
        depends_on: Vec::new(),
        trigger: None,
    };
    let base = Plan {
        references: BTreeMap::new(),
        changes: vec![a_change(), service(), typed],
        target: Target::local(),
        machine: local_machine(),
    };
    let edit = |edit: &dyn Fn(&mut Vec<Change>)| {
        let mut plan = base.clone();
        edit(&mut plan.changes);
        plan
    };
    // The plan with one field of one typed step set to `value`.
    let typed_field = |index: usize, pointer: &str, value: serde_json::Value| {
        let mut steps = typed_steps.clone();
        *steps[index]
            .pointer_mut(pointer)
            .unwrap_or_else(|| panic!("no {pointer}")) = value;
        let steps = steps_of(&steps);
        edit(&move |changes: &mut Vec<Change>| changes[2].steps.clone_from(&steps))
    };
    let desired = |json: serde_json::Value| {
        edit(&move |changes: &mut Vec<Change>| changes[0].desired = resource(json.clone()))
    };
    let trigger = |trigger: Option<Trigger>| {
        edit(&move |changes: &mut Vec<Change>| changes[1].trigger.clone_from(&trigger))
    };
    let source = |id: &str| vec![ResourceId(id.to_owned())];
    // (the change, whether `zap plan`, `zap plan --diff`, `zap apply` print it)
    let mutations: Vec<(&str, Plan, [bool; 3])> = vec![
        (
            "resource_id",
            edit(&|changes| changes[0].resource_id = ResourceId("other".to_owned())),
            [true, true, true],
        ),
        (
            "action",
            edit(&|changes| changes[0].action = ChangeAction::Update),
            [true, true, true],
        ),
        (
            "steps (a command edited)",
            edit(&|changes| changes[0].steps = vec![PlanStep::Run("mkdir /srv/notes".to_owned())]),
            [true, true, true],
        ),
        (
            "steps (a command made a note)",
            edit(&|changes| {
                changes[0].steps = vec![PlanStep::Note("mkdir -p /srv/notes".to_owned())];
            }),
            [true, true, true],
        ),
        (
            "steps (one added)",
            edit(&|changes| changes[0].steps.push(PlanStep::Run("true".to_owned()))),
            [true, true, true],
        ),
        (
            "the order of the changes",
            edit(&|changes| changes.swap(0, 1)),
            [true, true, true],
        ),
        (
            "desired, its kind",
            desired(serde_json::json!({
                "id": "notes", "type": "link", "path": "/srv/notes", "target": "/srv/other",
            })),
            [true, true, true],
        ),
        (
            "desired.path",
            desired(serde_json::json!({
                "id": "notes", "type": "directory", "path": "/srv/other", "mode": "755",
            })),
            [true, true, true],
        ),
        (
            "desired.mode",
            desired(serde_json::json!({
                "id": "notes", "type": "directory", "path": "/srv/notes", "mode": "700",
            })),
            [true, true, true],
        ),
        (
            "desired.owner",
            desired(serde_json::json!({
                "id": "notes", "type": "directory", "path": "/srv/notes", "mode": "755",
                "owner": "root",
            })),
            [true, true, true],
        ),
        (
            "desired.name",
            desired(serde_json::json!({
                "id": "notes", "name": "Notes", "type": "directory", "path": "/srv/notes",
                "mode": "755",
            })),
            [true, true, true],
        ),
        (
            "desired.id",
            desired(serde_json::json!({
                "id": "other", "type": "directory", "path": "/srv/notes", "mode": "755",
            })),
            [false, false, false],
        ),
        (
            "desired.depends_on",
            desired(serde_json::json!({
                "id": "notes", "type": "directory", "path": "/srv/notes", "mode": "755",
                "depends_on": ["web"],
            })),
            [false, false, false],
        ),
        (
            "depends_on",
            edit(&|changes| changes[1].depends_on.clear()),
            [false, false, false],
        ),
        // Every field of a typed step is on its line in every preview.
        (
            "a text put's path",
            typed_field(0, "/put/path", serde_json::json!("/etc/sudoers.d/other")),
            [true, true, true],
        ),
        (
            "a text put's run_as",
            typed_field(0, "/put/run_as", serde_json::json!({"user": "deploy"})),
            [true, true, true],
        ),
        (
            "a text put's check",
            typed_field(0, "/put/check", serde_json::json!("none")),
            [true, true, true],
        ),
        (
            "a text put's mode",
            typed_field(0, "/put/source/text/mode", serde_json::json!("400")),
            [true, true, true],
        ),
        (
            "a text put's content",
            typed_field(
                0,
                "/put/source/text/content",
                serde_json::json!("deploy ALL=(ALL) NOPASSWD: ALL\n"),
            ),
            [true, true, true],
        ),
        (
            "a text put's content (its final newline alone)",
            typed_field(
                0,
                "/put/source/text/content",
                serde_json::json!("deploy ALL=(ALL) ALL"),
            ),
            [true, true, true],
        ),
        (
            "a command put's path",
            typed_field(1, "/put/path", serde_json::json!("/etc/fstab2")),
            [true, true, true],
        ),
        (
            "a command put's run_as",
            typed_field(1, "/put/run_as", serde_json::json!("root")),
            [true, true, true],
        ),
        (
            "a command put's check",
            typed_field(1, "/put/check", serde_json::json!("sudoers")),
            [true, true, true],
        ),
        (
            "a command put's mode (set, not kept)",
            typed_field(
                1,
                "/put/source/command/mode",
                serde_json::json!({"set": "644"}),
            ),
            [true, true, true],
        ),
        (
            "a command put's mode for a new file",
            typed_field(
                1,
                "/put/source/command/mode/keep/if_new",
                serde_json::json!("600"),
            ),
            [true, true, true],
        ),
        (
            "a command put's producer",
            typed_field(
                1,
                "/put/source/command/producer",
                serde_json::json!({"apt_source_line": {"line": "/swapfile none swap sw 0 0"}}),
            ),
            [true, true, true],
        ),
        (
            "a fstab producer's path",
            typed_field(
                1,
                "/put/source/command/producer/fstab_swap_entry/path",
                serde_json::json!("/swapfile2"),
            ),
            [true, true, true],
        ),
        (
            "an apt producer's line",
            typed_field(
                4,
                "/put/source/command/producer/apt_source_line/line",
                serde_json::json!("deb https://e.x/apt testing main"),
            ),
            [true, true, true],
        ),
        (
            "a key producer's account",
            typed_field(
                5,
                "/put/source/command/producer/authorized_keys_of/account",
                serde_json::json!("admin"),
            ),
            [true, true, true],
        ),
        (
            "an installer's url",
            typed_field(6, "/installer/url", serde_json::json!("https://e.x/j.sh")),
            [true, true, true],
        ),
        (
            "an installer's shell",
            typed_field(6, "/installer/shell", serde_json::json!("bash")),
            [true, true, true],
        ),
        (
            "a dir's path",
            typed_field(2, "/dir/path", serde_json::json!("/home/deploy/.ssh2")),
            [true, true, true],
        ),
        (
            "a dir's mode",
            typed_field(2, "/dir/mode", serde_json::json!("750")),
            [true, true, true],
        ),
        (
            "a dir's owner",
            typed_field(2, "/dir/owner", serde_json::json!("root")),
            [true, true, true],
        ),
        (
            "a dir's group",
            typed_field(2, "/dir/group", serde_json::json!("root")),
            [true, true, true],
        ),
        (
            "a pg_hba rule's database",
            typed_field(3, "/pg_hba_rule/database", serde_json::json!("other")),
            [true, true, true],
        ),
        (
            "a pg_hba rule's user",
            typed_field(3, "/pg_hba_rule/user", serde_json::json!("other")),
            [true, true, true],
        ),
        (
            "a pg_hba rule's host",
            typed_field(3, "/pg_hba_rule/host", serde_json::json!("127.0.0.1/32")),
            [true, true, true],
        ),
        (
            "a pg_hba rule's method",
            typed_field(3, "/pg_hba_rule/method", serde_json::json!("md5")),
            [true, true, true],
        ),
        ("trigger removed", trigger(None), [true, true, true]),
        (
            "trigger.kind",
            trigger(Some(Trigger {
                kind: TriggerKind::Reload,
                sources: source("notes"),
                pending: false,
            })),
            [true, true, true],
        ),
        (
            "trigger.pending",
            trigger(Some(Trigger {
                kind: TriggerKind::Restart,
                sources: source("notes"),
                pending: true,
            })),
            [true, true, true],
        ),
        (
            "trigger.sources (another)",
            trigger(Some(Trigger {
                kind: TriggerKind::Restart,
                sources: source("other"),
                pending: false,
            })),
            [false, false, false],
        ),
    ];

    let hash = plan_hash(&base).unwrap();
    let shown = previews(&base);
    for (what, mutated, prints) in &mutations {
        assert_ne!(
            plan_hash(mutated).unwrap(),
            hash,
            "{what} is a change the hash doesn't cover — not a case for this test"
        );
        for (((preview, before), (_, after)), printed) in
            shown.iter().zip(previews(mutated)).zip(prints)
        {
            assert_eq!(
                *before != after,
                *printed,
                "`{preview}` and {what}: the table says it {} this\n{after}",
                if *printed { "prints" } else { "doesn't print" }
            );
        }
    }
}

// --- the previews show what a change declares ---

/// One resource of each kind, declaring everything its kind takes, every free-text
/// value marked `‹…›` so a preview that prints it can be told from one that doesn't.
fn declared_resources() -> Vec<Resource> {
    let pin = "ab".repeat(32);
    [
        serde_json::json!({
            "id": "‹package.id›", "name": "‹package.name›", "type": "package",
            "from": {"apt": "package.apt.sentinel", "apk": "package.apk.sentinel"},
            "check": "‹package.check›",
        }),
        serde_json::json!({
            "id": "‹apt_repo.id›", "type": "apt_repo", "key_url": "‹apt_repo.key_url›",
            "key_path": "‹apt_repo.key_path›", "source": "‹apt_repo.source›",
            "list_file": "‹apt_repo.list_file›",
        }),
        serde_json::json!({
            "id": "‹script.id›", "type": "script", "check": "‹script.check›",
            "run": "‹script.run›", "cwd": "‹script.cwd›", "env": {"KEY": "‹script.env›"},
        }),
        serde_json::json!({
            "id": "‹installer.id›", "type": "installer", "url": "‹installer.url›",
            "check": "‹installer.check›", "shell": "‹installer.shell›",
        }),
        serde_json::json!({
            "id": "‹user.id›", "type": "user", "username": "app", "shell": "‹user.shell›",
            "home_mode": "750", "ssh_keys": {"keys": ["‹user.ssh_key›"]},
            "sudo": {"mode": "nopasswd", "commands": ["‹user.sudo_command›"]},
            "groups": ["docker"],
        }),
        serde_json::json!({
            "id": "‹directory.id›", "type": "directory", "path": "‹directory.path›",
            "mode": "750", "owner": "app", "group": "www",
        }),
        serde_json::json!({
            "id": "‹file.inline.id›", "type": "file", "path": "‹file.inline.path›",
            "content": {"type": "inline", "content": "‹file.inline.content›"},
            "mode": "640", "owner": "app", "group": "www",
            "triggers": ["‹service.id›"], "validate": "‹file.validate›",
        }),
        serde_json::json!({
            "id": "‹file.template.id›", "type": "file", "path": "‹file.template.path›",
            "content": {"type": "template", "template": "‹file.template.text›",
                "vars": {"‹file.template.var›": "‹file.template.value›"},
                "kinds": {"‹file.template.var›": "env_value"}},
        }),
        serde_json::json!({
            "id": "‹file.source.id›", "type": "file", "path": "‹file.source.path›",
            "content": {"type": "source", "path": "‹file.source.from›"},
        }),
        serde_json::json!({
            "id": "‹file.remote.id›", "type": "file", "path": "‹file.remote.path›",
            "content": {"type": "remote", "url": "‹file.remote.url›", "blake3": pin,
                "extract": {"type": "tar.gz", "strip_components": 1},
                "auth": {"scheme": "bearer", "token": "‹file.remote.token›"}},
        }),
        serde_json::json!({
            "id": "‹link.id›", "type": "link", "path": "‹link.path›",
            "target": "‹link.target›", "depends_on": ["‹directory.id›"],
        }),
        serde_json::json!({
            "id": "‹service.id›", "type": "service", "service": "service.unit.sentinel",
            "enabled": true, "running": true, "restart_on": ["‹file.source.id›"],
            "reload_on": ["‹file.template.id›"],
        }),
        serde_json::json!({
            "id": "‹database.id›", "type": "database", "engine": "postgresql",
            "database_name": "‹database.name›", "username": "‹database.username›",
            "auth": {"method": "scram-sha-256", "hosts": ["‹database.host›"]},
        }),
        serde_json::json!({
            "id": "‹swap.id›", "type": "swap", "size": "‹swap.size›", "path": "‹swap.path›",
        }),
        serde_json::json!({
            "id": "‹firewall.id›", "type": "firewall", "backend": "ufw",
            "default_incoming": "deny", "default_outgoing": "allow",
            "allow": ["‹firewall.profile›", {"port": 8443, "proto": "udp"}],
        }),
        serde_json::json!({
            "id": "‹verify.id›", "type": "verify", "assertions": [
                {"type": "path_exists", "path": "‹verify.path›", "file_type": "file",
                 "mode": "600", "owner": "app", "not_empty": true},
                {"type": "command", "run": "‹verify.run›", "expect": "‹verify.expect›"},
            ],
        }),
        serde_json::json!({
            "id": "‹pipeline.id›", "type": "pipeline", "env": {"A": "‹pipeline.env›"},
            // Above one is refused by the config gate, which the planner here doesn't
            // run: a value no other line of the plan holds is a leaf the check can see.
            "max_concurrency": 7319,
            "steps": [{"id": "‹pipeline.step.id›", "name": "‹pipeline.step.name›",
                "run": "‹pipeline.step.run›", "cwd": "‹pipeline.step.cwd›",
                "env": {"B": "‹pipeline.step.env›"}}],
        }),
        serde_json::json!({
            "id": "‹build.id›", "type": "build", "run": "‹build.run›",
            "output": "‹build.output›", "cwd": "‹build.cwd›", "env": {"CC": "‹build.env›"},
            "source": {"type": "remote", "url": "‹build.url›", "blake3": pin,
                "extract": {"type": "tar.xz", "strip_components": 2},
                "auth": {"scheme": "bearer", "token": "‹build.token›"},
                "verify": {"scheme": "minisign", "public_key": "RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3",
                    "signature_url": "‹build.signature_url›"}},
        }),
    ]
    .into_iter()
    .map(resource)
    .collect()
}

/// No preview prints a constant script: a typed step is its `=` line, whatever script
/// carries it out. Every kind's create, planned by the real planner — with the kinds
/// whose steps take another shape under another declaration (an nftables firewall, a
/// `copy_from` user) beside them — is rendered by each preview and held against every
/// statement of each script, and against the feeder a put of a command's output runs.
/// A plan of the three producers and an installer alone prints none of the shell text
/// they lower to either: each is its words and the config's own line.
#[test]
fn no_preview_prints_a_constant_script() {
    use zap_types::postgres::PG_HBA_ADD_RULE;
    use zap_types::put::{DIR_ATTRS, FILE_PUT};

    let mut resources = declared_resources();
    resources.push(resource(serde_json::json!({
        "id": "nft", "type": "firewall", "backend": "nftables",
        "allow": [{"port": 22, "proto": "tcp"}],
    })));
    resources.push(resource(serde_json::json!({
        "id": "copied", "type": "user", "username": "ops", "ssh_keys": {"copy_from": "root"},
        "sudo": "password",
    })));
    let target: Target = serde_json::from_value(serde_json::json!({
        "local": true, "package_manager": "apt", "service_manager": "systemd",
    }))
    .unwrap();
    let detected: BTreeMap<ResourceId, Detection> = resources
        .iter()
        .map(|resource| (resource.id.clone(), Detection::Absent))
        .collect();
    let plan = zap_types::plan::diff(zap_types::plan::DiffInputs {
        resources: &resources,
        detected: &detected,
        target: &target,
        machine: &local_machine(),
        lock: None,
        pending: &BTreeMap::new(),
        var: &zap_types::last_run::ReportVar::unset,
    })
    .plan;

    // The plan runs each script, through a step of each typed kind and shape.
    let ran: Vec<String> = plan
        .changes
        .iter()
        .flat_map(|change| &change.steps)
        .filter(|step| step.summary().is_some())
        .filter_map(PlanStep::execution)
        .map(|execution| execution.text().to_owned())
        .collect();
    for script in [FILE_PUT, DIR_ATTRS, PG_HBA_ADD_RULE] {
        assert!(ran.iter().any(|text| text.contains(script)));
    }
    assert!(ran.iter().any(|text| text.contains("zap_c=$(")));
    assert!(ran.iter().any(|text| text.contains("zap_m=$(stat")));

    let statements: BTreeSet<&str> = [FILE_PUT, DIR_ATTRS, PG_HBA_ADD_RULE]
        .into_iter()
        .flat_map(|script| script.split("; "))
        .map(str::trim)
        .filter(|statement| statement.len() >= 12)
        .collect();
    assert!(statements.len() > 40, "{}", statements.len());
    for (preview, rendered) in previews(&plan) {
        for statement in &statements {
            assert!(
                !rendered.contains(statement),
                "`{preview}` prints a script's `{statement}`:\n{rendered}"
            );
        }
        for feeder in [
            "zap_c=",
            "zap_h=",
            "zap_m=",
            "zap_s=",
            "sh -c '",
            "SHOW hba_file",
        ] {
            assert!(
                !rendered.contains(feeder),
                "`{preview}` prints `{feeder}`:\n{rendered}"
            );
        }
        // Each typed step is there as its own line instead.
        for line in [
            "      = dir /home/app/.ssh  (mode 700, owner app:app, as root, created if missing)",
            "      = put /home/app/.ssh/authorized_keys  (mode 600, as app; ",
            "      = put /etc/sudoers.d/app  (mode 440, as root, checked by visudo; ",
            "      = put ‹apt_repo.list_file›  (mode 644, as root)",
            "          from: the line below, as the target's shell reads it inside double quotes \
             after reading /etc/os-release: a variable in it expands and a $(…) in it runs, \
             at every plan too\n          line: ‹apt_repo.source›\n",
            "      = put /etc/fstab  (keeps its mode, 644 if new; as root)\n          \
             from: /etc/fstab as it reads, then the line below; skipped when it lists \
             ‹swap.path›\n          line: ‹swap.path› none swap sw 0 0\n",
            "      = put /etc/nftables.nft  (mode 600, as root; ",
            "      = put /home/ops/.ssh/authorized_keys  (mode 600, as ops)\n          \
             from: the authorized_keys of root, read as root\n",
            "      = run the script fetched from ‹installer.url›  (piped to ‹installer.shell›)\n",
            "      = pg_hba rule: host    ‹database.name›    ‹database.username›    \
             ‹database.host›    scram-sha-256  (as postgres, in the server's hba_file, above \
             its first host record, unless it is already there; an added rule reloads the \
             server's configuration)",
        ] {
            assert!(
                rendered.contains(line),
                "`{preview}` lacks {line}:\n{rendered}"
            );
        }
    }

    // The three producers and an installer, on their own: what each lowers to is shell
    // text of zap's, and no preview prints a word of it.
    let produced: Vec<Resource> = [
        serde_json::json!({
            "id": "pgdg", "type": "apt_repo", "key_url": "https://e.x/key.asc",
            "source": "deb https://e.x/apt $VERSION_CODENAME-pgdg main",
        }),
        serde_json::json!({"id": "swap", "type": "swap", "size": "1G", "path": "/swapfile"}),
        serde_json::json!({
            "id": "deploy", "type": "user", "username": "deploy",
            "ssh_keys": {"copy_from": "ops"},
        }),
        serde_json::json!({
            "id": "tool", "type": "installer", "url": "https://e.x/i.sh",
            "check": "/opt/tool", "shell": "sh -s -- --yes",
        }),
    ]
    .into_iter()
    .map(resource)
    .collect();
    let detected: BTreeMap<ResourceId, Detection> = produced
        .iter()
        .map(|resource| (resource.id.clone(), Detection::Absent))
        .collect();
    let plan = zap_types::plan::diff(zap_types::plan::DiffInputs {
        resources: &produced,
        detected: &detected,
        target: &target,
        machine: &local_machine(),
        lock: None,
        pending: &BTreeMap::new(),
        var: &zap_types::last_run::ReportVar::unset,
    })
    .plan;
    let ran: Vec<String> = plan
        .changes
        .iter()
        .flat_map(|change| &change.steps)
        .filter(|step| step.summary().is_some())
        .filter_map(PlanStep::execution)
        .map(|execution| execution.text().to_owned())
        .collect();
    let scripted = [
        "awk ",
        "ENVIRON",
        ". /etc/os-release",
        "SRC_HOME",
        "sudo -u",
        "printf '%s",
        "zap_s=",
        "echo 'zap: ",
        "|| exit",
    ];
    for text in scripted {
        assert!(
            ran.iter().any(|ran| ran.contains(text)),
            "no step runs `{text}`"
        );
    }
    for (preview, rendered) in previews(&plan) {
        for text in scripted {
            assert!(
                !rendered.contains(text),
                "`{preview}` prints `{text}`:\n{rendered}"
            );
        }
        for lines in [
            "      = put /etc/apt/sources.list.d/pgdg.list  (mode 644, as root)\n          \
             from: the line below, as the target's shell reads it inside double quotes \
             after reading /etc/os-release: a variable in it expands and a $(…) in it runs, \
             at every plan too\n          \
             line: deb [signed-by=/usr/share/keyrings/pgdg.asc] https://e.x/apt \
             $VERSION_CODENAME-pgdg main\n",
            "      = put /etc/fstab  (keeps its mode, 644 if new; as root)\n          \
             from: /etc/fstab as it reads, then the line below; skipped when it lists \
             /swapfile\n          line: /swapfile none swap sw 0 0\n",
            "      = put /home/deploy/.ssh/authorized_keys  (mode 600, as deploy)\n          \
             from: the authorized_keys of ops, read as ops\n",
            "      = run the script fetched from https://e.x/i.sh  (piped to sh -s -- --yes)\n",
        ] {
            assert!(
                rendered.contains(lines),
                "`{preview}` lacks {lines}:\n{rendered}"
            );
        }
    }
}

/// Every leaf of `value` as `(its path, its text)`, less the `type` and `scheme` tags
/// (a closed set, which a preview words its own way). A marked key of a free-form map
/// is a leaf too, under `‹key›`.
fn leaves(value: &serde_json::Value, path: &str, found: &mut Vec<(String, String)>) {
    match value {
        serde_json::Value::Object(map) => {
            for (key, value) in map {
                if key == "type" || key == "scheme" {
                    continue;
                }
                if key.starts_with('‹') {
                    found.push((format!("{path}.‹key›"), key.clone()));
                    leaves(value, &format!("{path}.‹key›"), found);
                } else {
                    leaves(value, &format!("{path}.{key}"), found);
                }
            }
        }
        serde_json::Value::Array(items) => {
            for item in items {
                leaves(item, &format!("{path}[]"), found);
            }
        }
        serde_json::Value::String(text) => found.push((path.to_owned(), text.clone())),
        serde_json::Value::Null => {}
        other => found.push((path.to_owned(), other.to_string())),
    }
}

/// What of each kind's desired resource no preview prints, by its path in the resource:
/// everything else a create declares is on screen in `zap plan`, `zap plan --diff`, and
/// `zap apply` alike. A field added to a resource kind shows up here until a preview
/// prints it or this list names it.
const DECLARED_BUT_NOT_PRINTED: &[(&str, &[&str])] = &[
    // The package names for managers the target doesn't use.
    ("‹package.id›", &["package.from.apk"]),
    ("‹apt_repo.id›", &[]),
    ("‹script.id›", &[]),
    ("‹installer.id›", &[]),
    ("‹user.id›", &[]),
    ("‹directory.id›", &[]),
    // Content is named by its length and digest, never printed.
    ("‹file.inline.id›", &["file.content.content"]),
    ("‹file.template.id›", &["file.content.template"]),
    ("‹file.source.id›", &[]),
    // A credential's literal text is `(literal)`; its references are printed.
    ("‹file.remote.id›", &["file.content.auth.token"]),
    // What a change waits on is not printed.
    ("‹link.id›", &["link.depends_on[]"]),
    ("‹service.id›", &[]),
    // The engine is the kind's one: `postgresql`, never restarted, so never named.
    ("‹database.id›", &["database.engine"]),
    ("‹swap.id›", &[]),
    ("‹firewall.id›", &[]),
    ("‹verify.id›", &[]),
    // What the config gate rejects before any plan.
    (
        "‹pipeline.id›",
        &[
            "pipeline.env.A",
            "pipeline.steps[].cwd",
            "pipeline.steps[].env.B",
        ],
    ),
    ("‹build.id›", &["build.source.auth.token"]),
];

/// Every preview prints what a change declares: for a create of each kind, planned by
/// the real planner from a resource declaring everything its kind takes, each value of
/// the desired resource is on screen — in the declared lines or in a step — except the
/// ones [`DECLARED_BUT_NOT_PRINTED`] names.
#[test]
fn the_previews_print_what_a_change_declares() {
    let resources = declared_resources();
    let target: Target = serde_json::from_value(serde_json::json!({
        "local": true, "package_manager": "apt", "service_manager": "systemd",
    }))
    .unwrap();
    let detected: BTreeMap<ResourceId, Detection> = resources
        .iter()
        .map(|resource| (resource.id.clone(), Detection::Absent))
        .collect();
    let result = zap_types::plan::diff(zap_types::plan::DiffInputs {
        resources: &resources,
        detected: &detected,
        target: &target,
        machine: &local_machine(),
        lock: None,
        pending: &BTreeMap::new(),
        var: &zap_types::last_run::ReportVar::unset,
    });
    assert!(result.held.is_empty(), "{:?}", result.held);
    let mut planned = BTreeSet::new();
    for change in &result.plan.changes {
        let Some((_, expected)) = DECLARED_BUT_NOT_PRINTED
            .iter()
            .find(|(id, _)| *id == change.resource_id.0)
        else {
            // A change the planner adds on its own (the package index refresh).
            continue;
        };
        planned.insert(change.resource_id.0.as_str());
        // Alone in its plan, so another change's lines can't stand in for its own.
        let plan = Plan {
            references: BTreeMap::new(),
            changes: vec![change.clone()],
            target: Target::local(),
            machine: local_machine(),
        };
        let kind = change.desired.kind().as_str();
        let mut found = Vec::new();
        leaves(
            &serde_json::to_value(&change.desired).unwrap(),
            kind,
            &mut found,
        );
        for (preview, rendered) in previews(&plan) {
            if kind == "apt_repo" {
                // the key, the pin its bytes must have, and where they are installed
                for line in [
                    "      key: fetched from ‹apt_repo.key_url›\n",
                    "      pin: none yet (tracked in zap.lock)\n",
                    "      = put ‹apt_repo.key_path›  (mode 644, owner root:root, as root)\n",
                ] {
                    assert!(rendered.contains(line), "`{preview}`: {line:?}\n{rendered}");
                }
            }
            let rendered = rendered.to_lowercase();
            let unprinted: BTreeSet<&str> = found
                .iter()
                .filter(|(_, text)| !rendered.contains(&text.to_lowercase()))
                .map(|(path, _)| path.as_str())
                .collect();
            assert_eq!(
                unprinted,
                expected.iter().copied().collect(),
                "`{preview}` and {}: what it leaves out (left) is not what the list names \
                 (right)\n{rendered}",
                change.resource_id.0
            );
        }
    }
    assert_eq!(
        planned,
        DECLARED_BUT_NOT_PRINTED.iter().map(|(id, _)| *id).collect(),
        "every listed resource is planned"
    );
}
