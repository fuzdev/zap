//! Plan-diff goldens — `config + detected → expected Plan / plan_hash`.
//!
//! Hand-authored. Each test asserts the *shape* of the
//! emitted changeset — action, command generation, batching, trigger injection,
//! topological order — plus `plan_hash` determinism. Skips are derived for display,
//! so a converged resource is asserted **absent** from the fact.

#![expect(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test helpers outside `#[test]` fns panic on a failed setup or check"
)]

mod common;

use std::collections::BTreeMap;

use common::{local_account, local_machine};
use zap_types::config_hash::plan_hash;
use zap_types::detected::{CurrentState, Detection, FileDrift};
use zap_types::plan::{
    Change, ChangeAction, DiffInputs, Machine, PlanStep, StepExecution, Trigger, TriggerKind, diff,
};
use zap_types::put::{FileAttrs, PutCheck, RunAs, file_put_command};
use zap_types::scalar::ContentHash;
use zap_types::schema::{Resource, ResourceId, ResourceType, Target};
use zap_types::text::Text;
use zap_types::var_ref::Segment::{Ref, Text as Lit};

/// Build a resource from its JSON config (the lenient `{id, type, ...}` shape).
fn res(json: serde_json::Value) -> Resource {
    serde_json::from_value(json).expect("valid resource json")
}

/// A detection result for `id` from an `(exists, met)` pair, mapped to the outcome
/// enum: absent / drifted (generic `File` current) / converged. `held` covers the
/// `Undetermined` arm.
fn det(id: &str, exists: bool, met: bool) -> (ResourceId, Detection) {
    let detection = match (exists, met) {
        (false, _) => Detection::Absent,
        (true, false) => Detection::Drifted {
            current: CurrentState::File {
                drift: FileDrift::Content,
            },
        },
        (true, true) => Detection::Converged,
    };
    (ResourceId(id.to_owned()), detection)
}

/// An `Undetermined` detection for `id` — the planner must hold (no change), not
/// create.
fn held(id: &str, reason: &str) -> (ResourceId, Detection) {
    (
        ResourceId(id.to_owned()),
        Detection::Undetermined {
            reason: reason.to_owned(),
        },
    )
}

/// A drifted detection carrying a typed current state (for the service-stop test).
fn drifted(id: &str, current: CurrentState) -> (ResourceId, Detection) {
    (ResourceId(id.to_owned()), Detection::Drifted { current })
}

/// Collect detections into the `resource_id`-keyed map `diff` consumes.
fn detected(states: Vec<(ResourceId, Detection)>) -> BTreeMap<ResourceId, Detection> {
    states.into_iter().collect()
}

/// A target with the given package/service managers (local).
fn target(pm: Option<&str>, sm: Option<&str>) -> Target {
    fn parse<T: serde::de::DeserializeOwned>(name: &str) -> T {
        serde_json::from_value(serde_json::Value::String(name.to_owned())).expect("valid manager")
    }
    Target {
        package_manager: pm.map(parse),
        service_manager: sm.map(parse),
        ..Target::local()
    }
}

/// Find an emitted change by resource id.
fn find<'a>(changes: &'a [Change], id: &str) -> Option<&'a Change> {
    changes.iter().find(|c| c.resource_id.0 == id)
}

/// The emitted resource ids, in plan order.
fn ids(changes: &[Change]) -> Vec<String> {
    changes.iter().map(|c| c.resource_id.0.clone()).collect()
}

#[test]
fn create_directory_has_no_commands() {
    let resources = vec![res(serde_json::json!({
        "id": "data", "type": "directory", "path": "/opt/data", "mode": "755"
    }))];
    let det = detected(vec![det("data", false, false)]);
    let result = diff(DiffInputs {
        resources: &resources,
        detected: &det,
        target: &target(None, None),
        machine: &local_machine(),
        lock: None,
        pending: &BTreeMap::new(),
        var: &zap_types::last_run::ReportVar::unset,
    });

    assert_eq!(result.warnings, Vec::<String>::new());
    assert_eq!(result.plan.changes.len(), 1);
    let change = &result.plan.changes[0];
    assert_eq!(change.action, ChangeAction::Create);
    // directory is native std::fs IO — no pre-baked command.
    assert!(change.steps.is_empty());
}

#[test]
fn converged_resource_is_absent_from_the_fact() {
    let resources = vec![res(serde_json::json!({
        "id": "data", "type": "directory", "path": "/opt/data"
    }))];
    let det = detected(vec![det("data", true, true)]);
    let result = diff(DiffInputs {
        resources: &resources,
        detected: &det,
        target: &target(None, None),
        machine: &local_machine(),
        lock: None,
        pending: &BTreeMap::new(),
        var: &zap_types::last_run::ReportVar::unset,
    });
    assert!(
        result.plan.changes.is_empty(),
        "converged → skipped → dropped"
    );
}

#[test]
fn diverged_resource_becomes_update() {
    let resources = vec![res(serde_json::json!({
        "id": "data", "type": "directory", "path": "/opt/data", "mode": "755"
    }))];
    let det = detected(vec![det("data", true, false)]);
    let result = diff(DiffInputs {
        resources: &resources,
        detected: &det,
        target: &target(None, None),
        machine: &local_machine(),
        lock: None,
        pending: &BTreeMap::new(),
        var: &zap_types::last_run::ReportVar::unset,
    });
    assert_eq!(result.plan.changes.len(), 1);
    assert_eq!(result.plan.changes[0].action, ChangeAction::Update);
}

#[test]
fn single_package_install_is_fronted_by_a_cache_update() {
    let resources = vec![res(serde_json::json!({
        "id": "curl", "type": "package", "from": {"apt": "curl"}
    }))];
    let det = detected(vec![det("curl", false, false)]);
    let result = diff(DiffInputs {
        resources: &resources,
        detected: &det,
        target: &target(Some("apt"), None),
        machine: &local_machine(),
        lock: None,
        pending: &BTreeMap::new(),
        var: &zap_types::last_run::ReportVar::unset,
    });

    assert_eq!(ids(&result.plan.changes), vec!["cache-update-apt", "curl"]);
    let cache = find(&result.plan.changes, "cache-update-apt").unwrap();
    assert_eq!(cache.steps, vec![PlanStep::run("sudo apt-get update")]);
    let curl = find(&result.plan.changes, "curl").unwrap();
    assert_eq!(
        curl.depends_on,
        vec![ResourceId("cache-update-apt".to_owned())]
    );
    assert_eq!(
        curl.steps,
        vec![PlanStep::run(
            "sudo DEBIAN_FRONTEND=noninteractive apt-get install -y curl"
        )]
    );
}

#[test]
fn multiple_package_installs_are_batched() {
    let resources = vec![
        res(serde_json::json!({"id": "curl", "type": "package", "from": {"apt": "curl"}})),
        res(serde_json::json!({"id": "git", "type": "package", "from": {"apt": "git"}})),
    ];
    let det = detected(vec![det("curl", false, false), det("git", false, false)]);
    let result = diff(DiffInputs {
        resources: &resources,
        detected: &det,
        target: &target(Some("apt"), None),
        machine: &local_machine(),
        lock: None,
        pending: &BTreeMap::new(),
        var: &zap_types::last_run::ReportVar::unset,
    });

    // Individual packages are gone; cache-update + a single batch remain, in order.
    assert_eq!(
        ids(&result.plan.changes),
        vec!["cache-update-apt", "batch-install-apt"]
    );
    let batch = find(&result.plan.changes, "batch-install-apt").unwrap();
    assert_eq!(batch.action, ChangeAction::Create);
    assert_eq!(
        batch.steps,
        vec![PlanStep::run(
            "sudo DEBIAN_FRONTEND=noninteractive apt-get install -y curl git"
        )]
    );
    assert_eq!(
        batch.depends_on,
        vec![ResourceId("cache-update-apt".to_owned())]
    );
}

#[test]
fn apk_package_install_is_fronted_by_a_cache_update() {
    use zap_types::package_managers::{install, update_cache};
    use zap_types::schema::PackageManager;

    let resources = vec![
        res(serde_json::json!({"id": "curl", "type": "package", "from": {"apk": "curl"}})),
        res(serde_json::json!({"id": "git", "type": "package", "from": {"apk": "git"}})),
    ];
    let det = detected(vec![det("curl", false, false), det("git", false, false)]);
    let result = diff(DiffInputs {
        resources: &resources,
        detected: &det,
        target: &target(Some("apk"), None),
        machine: &local_machine(),
        lock: None,
        pending: &BTreeMap::new(),
        var: &zap_types::last_run::ReportVar::unset,
    });

    // The apk batch fronts `apk update`, then a single `apk add <pkgs>` — same
    // cache-update → batch-install shape as apt, derived from the apk templates.
    assert_eq!(
        ids(&result.plan.changes),
        vec!["cache-update-apk", "batch-install-apk"]
    );
    let cache = find(&result.plan.changes, "cache-update-apk").unwrap();
    let update_cmd = update_cache(PackageManager::Apk).unwrap();
    assert_eq!(
        cache.steps,
        vec![PlanStep::run(format!("sudo {update_cmd}"))]
    );

    let batch = find(&result.plan.changes, "batch-install-apk").unwrap();
    assert_eq!(batch.action, ChangeAction::Create);
    let install_cmd = install(PackageManager::Apk, "curl git").unwrap();
    assert_eq!(
        batch.steps,
        vec![PlanStep::run(format!("sudo {install_cmd}"))]
    );
    assert_eq!(
        batch.depends_on,
        vec![ResourceId("cache-update-apk".to_owned())]
    );
}

#[test]
fn already_installed_packages_are_not_batched() {
    // Converged packages skip; with nothing to install there's no cache-update.
    let resources = vec![
        res(serde_json::json!({"id": "curl", "type": "package", "from": {"apt": "curl"}})),
        res(serde_json::json!({"id": "git", "type": "package", "from": {"apt": "git"}})),
    ];
    let det = detected(vec![det("curl", true, true), det("git", true, true)]);
    let result = diff(DiffInputs {
        resources: &resources,
        detected: &det,
        target: &target(Some("apt"), None),
        machine: &local_machine(),
        lock: None,
        pending: &BTreeMap::new(),
        var: &zap_types::last_run::ReportVar::unset,
    });
    assert!(result.plan.changes.is_empty());
}

#[test]
fn batching_remaps_and_dedups_dependents_and_inherits_external_deps() {
    // A downstream resource depending on *both* batched packages collapses to a single
    // dep on the batch (remap + dedup); the cache-update inherits the packages' external
    // deps (here `base`) but never an intra-batch edge: remap, dedup, and "union minus
    // self-references".
    let resources = vec![
        res(serde_json::json!({"id": "base", "type": "directory", "path": "/opt/app"})),
        res(
            serde_json::json!({"id": "curl", "type": "package", "from": {"apt": "curl"}, "depends_on": ["base"]}),
        ),
        res(serde_json::json!({"id": "git", "type": "package", "from": {"apt": "git"}})),
        res(
            serde_json::json!({"id": "conf", "type": "file", "path": "/etc/app.conf", "content": {"type": "inline", "content": "x"}, "depends_on": ["curl", "git"]}),
        ),
    ];
    let det = detected(vec![
        det("base", false, false),
        det("curl", false, false),
        det("git", false, false),
        det("conf", false, false),
    ]);
    let result = diff(DiffInputs {
        resources: &resources,
        detected: &det,
        target: &target(Some("apt"), None),
        machine: &local_machine(),
        lock: None,
        pending: &BTreeMap::new(),
        var: &zap_types::last_run::ReportVar::unset,
    });

    // Dependent remapped from [curl, git] onto the single batch, deduped to one entry.
    let conf = find(&result.plan.changes, "conf").unwrap();
    assert_eq!(
        conf.depends_on,
        vec![ResourceId("batch-install-apt".to_owned())],
        "dependents on batched packages collapse to one batch dep"
    );
    // Cache-update inherits the batch's external dep (`base`), not the sibling package.
    let cache = find(&result.plan.changes, "cache-update-apt").unwrap();
    assert_eq!(cache.depends_on, vec![ResourceId("base".to_owned())]);
    // The individual package changes are gone.
    assert!(find(&result.plan.changes, "curl").is_none());
    assert!(find(&result.plan.changes, "git").is_none());
}

#[test]
fn a_package_behind_a_change_behind_another_package_batches_in_a_later_layer() {
    // `site` waits on `curl`/`git` and `nginx`/`jq` wait on `site`: one batch of all four
    // would wait on itself. Each layer batches on its own, the second after `site`.
    let pkg = |id: &str, deps: &[&str]| {
        res(serde_json::json!({
            "id": id, "type": "package", "from": {"apt": id}, "depends_on": deps,
        }))
    };
    let resources = vec![
        pkg("curl", &[]),
        pkg("git", &[]),
        dir("site", &["curl", "git"]),
        pkg("jq", &["site"]),
        pkg("nginx", &["site", "curl"]),
    ];
    let det = detected(
        ["curl", "git", "site", "jq", "nginx"]
            .into_iter()
            .map(|id| det(id, false, false))
            .collect(),
    );
    let result = diff(DiffInputs {
        resources: &resources,
        detected: &det,
        target: &target(Some("apt"), None),
        machine: &local_machine(),
        lock: None,
        pending: &BTreeMap::new(),
        var: &zap_types::last_run::ReportVar::unset,
    });
    assert_eq!(
        ids(&result.plan.changes),
        vec![
            "cache-update-apt",
            "batch-install-apt",
            "site",
            "batch-install-apt-2"
        ]
    );
    let later = find(&result.plan.changes, "batch-install-apt-2").unwrap();
    assert_eq!(
        later.steps,
        vec![PlanStep::run(
            "sudo DEBIAN_FRONTEND=noninteractive apt-get install -y jq nginx"
        )]
    );
    assert_eq!(
        later.depends_on,
        ["batch-install-apt", "cache-update-apt", "site"].map(|id| ResourceId(id.to_owned()))
    );
}

/// A package behind a resource that changes nothing — a converged directory, a held one
/// is no different, a service no trigger fired — behind another package still batches
/// later: the dropped resource is replaced by what it waits on, so one batch would wait
/// on itself.
#[test]
fn a_package_behind_an_unchanged_resource_behind_another_package_batches_later() {
    let pkg = |id: &str, deps: &[&str]| {
        res(serde_json::json!({
            "id": id, "type": "package", "from": {"apt": id}, "depends_on": deps,
        }))
    };
    let plan = |resources: &[Resource], det: BTreeMap<ResourceId, Detection>| {
        diff(DiffInputs {
            resources,
            detected: &det,
            target: &target(Some("apt"), Some("systemd")),
            machine: &local_machine(),
            lock: None,
            pending: &BTreeMap::new(),
            var: &zap_types::last_run::ReportVar::unset,
        })
        .plan
    };
    // p0 ← conf (converged) ← p1: one layer each, `p1` after `p0`.
    let resources = [pkg("p0", &[]), dir("conf", &["p0"]), pkg("p1", &["conf"])];
    let changes = plan(
        &resources,
        detected(vec![
            det("p0", false, false),
            det("conf", true, true),
            det("p1", false, false),
        ]),
    )
    .changes;
    assert_eq!(ids(&changes), ["cache-update-apt", "p0", "p1"]);
    assert_eq!(
        find(&changes, "p1").unwrap().depends_on,
        ["cache-update-apt", "p0"].map(|id| ResourceId(id.to_owned()))
    );
    // Two packages each side, so each layer is a batch.
    let resources = [
        pkg("a0", &[]),
        pkg("b0", &[]),
        dir("conf", &["a0", "b0"]),
        pkg("a1", &["conf"]),
        pkg("b1", &["conf", "a0"]),
    ];
    let mut states = vec![det("conf", true, true)];
    states.extend(["a0", "b0", "a1", "b1"].map(|id| det(id, false, false)));
    let changes = plan(&resources, detected(states)).changes;
    assert_eq!(
        ids(&changes),
        [
            "cache-update-apt",
            "batch-install-apt",
            "batch-install-apt-2"
        ]
    );
    // An unfired service between them.
    let resources = [
        pkg("p0", &[]),
        service("svc", &serde_json::json!({"depends_on": ["p0"]})),
        pkg("p1", &["svc"]),
    ];
    let changes = plan(
        &resources,
        detected(vec![
            det("p0", false, false),
            det("svc", true, true),
            det("p1", false, false),
        ]),
    )
    .changes;
    assert_eq!(ids(&changes), ["cache-update-apt", "p0", "p1"]);
}

/// Over many small random configs — apt and apk packages, directories, files that
/// trigger services, services that `restart_on` / `reload_on` — in every detected state,
/// the plan is computed without an internal error, every change comes after each change
/// it depends on, and every ordering the config states between two planned resources
/// survives: transitively, through resources the plan drops, a dependency is planned
/// earlier or installed in the same batch.
#[test]
fn random_small_configs_plan_in_a_dependency_order() {
    let mut seed: u64 = 0x2545_f491_4f6c_dd1d;
    let mut next = |bound: u64| {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed % bound
    };
    for round in 0..3000 {
        let pm = if round % 2 == 0 { "apt" } else { "apk" };
        let count = 2 + usize::try_from(next(6)).unwrap();
        let kinds: Vec<u64> = (0..count).map(|_| next(4)).collect();
        // Ids sort against declaration order, so the plan's tie-break by id never puts a
        // dependency first by itself: only the edges can.
        let id = |index: usize| format!("r{}", count - index);
        // Each resource's ordering edges, every one to an earlier resource.
        let mut edges: Vec<Vec<usize>> = vec![Vec::new(); count];
        let mut resources = Vec::new();
        let mut states = Vec::new();
        for index in 0..count {
            let deps: Vec<usize> = (0..index).filter(|_| next(3) == 0).collect();
            edges[index].extend(&deps);
            let dep_ids: Vec<String> = deps.iter().map(|&dep| id(dep)).collect();
            let resource = match kinds[index] {
                0 => serde_json::json!({
                    "id": id(index), "type": "package", "depends_on": dep_ids,
                    "from": {"apt": id(index), "apk": id(index)},
                }),
                1 => serde_json::json!({
                    "id": id(index), "type": "directory", "path": format!("/opt/{}", id(index)),
                    "depends_on": dep_ids,
                }),
                2 => {
                    // A file triggers a later service, which then runs after it.
                    let services: Vec<usize> = (index + 1..count)
                        .filter(|&s| kinds[s] == 3 && next(2) == 0)
                        .collect();
                    for &service in &services {
                        edges[service].push(index);
                    }
                    serde_json::json!({
                        "id": id(index), "type": "file", "path": format!("/etc/{}", id(index)),
                        "content": {"type": "inline", "content": "x"}, "depends_on": dep_ids,
                        "triggers": services.iter().map(|&s| id(s)).collect::<Vec<_>>(),
                    })
                }
                _ => {
                    let restart: Vec<usize> = (0..index).filter(|_| next(4) == 0).collect();
                    let reload: Vec<usize> = (0..index).filter(|_| next(4) == 0).collect();
                    edges[index].extend(restart.iter().chain(&reload));
                    serde_json::json!({
                        "id": id(index), "type": "service", "service": id(index),
                        "depends_on": dep_ids,
                        "restart_on": restart.iter().map(|&r| id(r)).collect::<Vec<_>>(),
                        "reload_on": reload.iter().map(|&r| id(r)).collect::<Vec<_>>(),
                    })
                }
            };
            resources.push(res(resource));
            states.push(match next(4) {
                0 => det(&id(index), false, false),
                1 => det(&id(index), true, false),
                2 => det(&id(index), true, true),
                _ => held(&id(index), "unreadable"),
            });
        }
        let result = diff(DiffInputs {
            resources: &resources,
            detected: &detected(states),
            target: &target(Some(pm), Some("systemd")),
            machine: &local_machine(),
            lock: None,
            pending: &BTreeMap::new(),
            var: &zap_types::last_run::ReportVar::unset,
        });
        let changes = &result.plan.changes;
        let position = |id: &str| changes.iter().position(|c| c.resource_id.0 == id);
        for (index, change) in changes.iter().enumerate() {
            for dep in &change.depends_on {
                assert!(
                    position(&dep.0).is_some_and(|at| at < index),
                    "{} depends on {} out of order: {resources:#?}",
                    change.resource_id.0,
                    dep.0
                );
            }
        }
        // Where each resource is planned: its own change, or the batch that installs it.
        let planned = |index: usize| {
            position(&id(index)).or_else(|| {
                changes.iter().position(|change| {
                    change.resource_id.0.starts_with("batch-install-")
                        && runs(&change.steps)
                            .iter()
                            .any(|run| run.split_whitespace().any(|word| word == id(index)))
                })
            })
        };
        // Every stated ordering, transitively, between two planned resources.
        let mut reach: Vec<Vec<bool>> = vec![vec![false; count]; count];
        for index in 0..count {
            for &dep in &edges[index] {
                reach[index][dep] = true;
                let below = reach[dep].clone();
                for (deeper, reached) in below.into_iter().enumerate() {
                    reach[index][deeper] |= reached;
                }
            }
        }
        for (later, reached) in reach.iter().enumerate() {
            for (earlier, &ordered) in reached.iter().enumerate() {
                if !ordered {
                    continue;
                }
                if let (Some(after), Some(before)) = (planned(later), planned(earlier)) {
                    assert!(
                        before <= after,
                        "{} is ordered after {} but planned before it: {changes:#?}\n{resources:#?}",
                        id(later),
                        id(earlier)
                    );
                }
            }
        }
    }
}

#[test]
fn a_dependency_through_a_converged_resource_keeps_its_order() {
    // `a-app` waits on `m-mid` (converged, dropped), which waits on `z-base` (planned):
    // the fact keeps `z-base` before `a-app` through the dropped edge.
    let resources = vec![
        dir("a-app", &["m-mid"]),
        dir("m-mid", &["z-base"]),
        dir("z-base", &[]),
    ];
    let det = detected(vec![
        det("a-app", false, false),
        det("m-mid", true, true),
        det("z-base", false, false),
    ]);
    let result = diff(DiffInputs {
        resources: &resources,
        detected: &det,
        target: &target(None, None),
        machine: &local_machine(),
        lock: None,
        pending: &BTreeMap::new(),
        var: &zap_types::last_run::ReportVar::unset,
    });
    assert_eq!(ids(&result.plan.changes), vec!["z-base", "a-app"]);
    assert_eq!(
        find(&result.plan.changes, "a-app").unwrap().depends_on,
        vec![ResourceId("z-base".to_owned())]
    );
}

#[test]
fn installer_emits_a_typed_fetch_and_pipe() {
    let resources = vec![res(serde_json::json!({
        "id": "deno", "type": "installer",
        "url": "https://deno.land/install.sh", "check": "~/.deno", "shell": "sh"
    }))];
    let det = detected(vec![det("deno", false, false)]);
    let result = diff(DiffInputs {
        resources: &resources,
        detected: &det,
        target: &target(None, None),
        machine: &local_machine(),
        lock: None,
        pending: &BTreeMap::new(),
        var: &zap_types::last_run::ReportVar::unset,
    });
    let steps = &result.plan.changes[0].steps;
    assert_eq!(
        steps,
        &[PlanStep::Installer(zap_types::plan::InstallerStep {
            url: "https://deno.land/install.sh".to_owned(),
            shell: "sh".to_owned(),
        })]
    );
    assert_eq!(
        runs(steps),
        [
            "zap_s=$(curl --proto '=https' --proto-redir '=https' -fsSL -- \
             'https://deno.land/install.sh') || exit; \
             [ -n \"$zap_s\" ] || { echo 'zap: the installer script is empty' >&2; exit 1; }; \
             printf '%s\\n' \"$zap_s\" | sh"
        ]
    );
}

#[test]
fn service_enable_commands_and_dependency_order() {
    // A package the service depends on, plus the service itself (both to create).
    let resources = vec![
        res(serde_json::json!({
            "id": "nginx-svc", "type": "service", "service": "nginx",
            "enabled": true, "running": true, "depends_on": ["nginx-pkg"]
        })),
        res(serde_json::json!({
            "id": "nginx-pkg", "type": "package", "from": {"apt": "nginx"}
        })),
    ];
    let det = detected(vec![
        det("nginx-svc", false, false),
        det("nginx-pkg", false, false),
    ]);
    let result = diff(DiffInputs {
        resources: &resources,
        detected: &det,
        target: &target(Some("apt"), Some("systemd")),
        machine: &local_machine(),
        lock: None,
        pending: &BTreeMap::new(),
        var: &zap_types::last_run::ReportVar::unset,
    });

    // The package install (fronted by cache-update) precedes the service.
    let order = ids(&result.plan.changes);
    let svc_pos = order.iter().position(|id| id == "nginx-svc").unwrap();
    let pkg_pos = order.iter().position(|id| id == "nginx-pkg").unwrap();
    assert!(
        pkg_pos < svc_pos,
        "dependency precedes dependent: {order:?}"
    );

    let svc = find(&result.plan.changes, "nginx-svc").unwrap();
    assert_eq!(
        svc.steps,
        vec![
            // daemon-reload first so a changed unit file takes effect before enable/start.
            PlanStep::run("sudo systemctl daemon-reload"),
            PlanStep::run("sudo systemctl enable nginx"),
            PlanStep::run("sudo systemctl start nginx")
        ]
    );
}

#[test]
fn file_trigger_promotes_converged_service_to_restart() {
    // The config file is new (create); it triggers a restart of an otherwise
    // converged service, which must be promoted from skip to update.
    let resources = vec![
        res(serde_json::json!({
            "id": "nginx-conf", "type": "file",
            "path": "/etc/nginx/nginx.conf",
            "content": {"type": "inline", "content": "worker_processes auto;"},
            "triggers": ["nginx-svc"]
        })),
        res(serde_json::json!({
            "id": "nginx-svc", "type": "service", "service": "nginx", "enabled": true
        })),
    ];
    // file absent → create; service fully converged → would skip without the trigger.
    let det = detected(vec![
        det("nginx-conf", false, false),
        det("nginx-svc", true, true),
    ]);
    let result = diff(DiffInputs {
        resources: &resources,
        detected: &det,
        target: &target(None, Some("systemd")),
        machine: &local_machine(),
        lock: None,
        pending: &BTreeMap::new(),
        var: &zap_types::last_run::ReportVar::unset,
    });

    let svc = find(&result.plan.changes, "nginx-svc").expect("service promoted into the plan");
    assert_eq!(svc.action, ChangeAction::Update);
    assert_eq!(
        svc.trigger,
        Some(Trigger {
            kind: TriggerKind::Restart,
            sources: vec![ResourceId("nginx-conf".to_owned())],
            pending: false,
        })
    );
    // A converged service runs its trigger alone — no enable or start, which would
    // start a service the config left unmanaged — after daemon-reload, so the restart
    // acts on the freshly-written unit rather than the stale in-memory one. The restart
    // acts only on a running service.
    assert_eq!(
        svc.steps,
        [
            PlanStep::run("sudo systemctl daemon-reload"),
            PlanStep::run("sudo systemctl try-restart nginx"),
        ]
    );
    // Implicit edge: the service waits for the file.
    assert!(
        svc.depends_on
            .contains(&ResourceId("nginx-conf".to_owned()))
    );
}

#[test]
fn dependency_cycle_yields_empty_plan_and_a_warning() {
    let resources = vec![
        res(serde_json::json!({"id": "a", "type": "directory", "path": "/a", "depends_on": ["b"]})),
        res(serde_json::json!({"id": "b", "type": "directory", "path": "/b", "depends_on": ["a"]})),
    ];
    let det = detected(vec![det("a", false, false), det("b", false, false)]);
    let result = diff(DiffInputs {
        resources: &resources,
        detected: &det,
        target: &target(None, None),
        machine: &local_machine(),
        lock: None,
        pending: &BTreeMap::new(),
        var: &zap_types::last_run::ReportVar::unset,
    });
    assert!(result.plan.changes.is_empty());
    assert_eq!(result.warnings.len(), 1);
    assert!(
        result.warnings[0].contains("cycle"),
        "{:?}",
        result.warnings
    );
}

#[test]
fn duplicate_resource_ids_yield_empty_plan_and_a_warning() {
    // Two resources sharing an id is unsound (collapsed edges/detections) — fatal,
    // like a cycle: empty plan + warning rather than a silently-wrong plan.
    let resources = vec![
        res(serde_json::json!({"id": "dup", "type": "directory", "path": "/a"})),
        res(serde_json::json!({"id": "dup", "type": "directory", "path": "/b"})),
    ];
    let det = detected(vec![det("dup", false, false)]);
    let result = diff(DiffInputs {
        resources: &resources,
        detected: &det,
        target: &target(None, None),
        machine: &local_machine(),
        lock: None,
        pending: &BTreeMap::new(),
        var: &zap_types::last_run::ReportVar::unset,
    });
    assert!(result.plan.changes.is_empty());
    assert_eq!(result.warnings.len(), 1);
    assert!(
        result.warnings[0].contains("duplicate"),
        "{:?}",
        result.warnings
    );
}

#[test]
fn plan_hash_is_deterministic_and_declaration_order_independent() {
    let a = res(serde_json::json!({"id": "a", "type": "directory", "path": "/a"}));
    let b = res(serde_json::json!({"id": "b", "type": "directory", "path": "/b"}));
    let det = detected(vec![det("a", false, false), det("b", false, false)]);
    let tgt = target(None, None);

    let forward = diff(DiffInputs {
        resources: &[a.clone(), b.clone()],
        detected: &det,
        target: &tgt,
        machine: &local_machine(),
        lock: None,
        pending: &BTreeMap::new(),
        var: &zap_types::last_run::ReportVar::unset,
    });
    let reversed = diff(DiffInputs {
        resources: &[b, a],
        detected: &det,
        target: &tgt,
        machine: &local_machine(),
        lock: None,
        pending: &BTreeMap::new(),
        var: &zap_types::last_run::ReportVar::unset,
    });

    // Same canonical order (ids), so the same fact and the same hash regardless of
    // how the two independent resources were declared.
    assert_eq!(ids(&forward.plan.changes), vec!["a", "b"]);
    assert_eq!(ids(&reversed.plan.changes), vec!["a", "b"]);
    assert_eq!(
        plan_hash(&forward.plan).unwrap(),
        plan_hash(&reversed.plan).unwrap()
    );
}

#[test]
fn file_trigger_to_non_service_warns() {
    let resources = vec![
        res(serde_json::json!({
            "id": "conf", "type": "file", "path": "/etc/x.conf",
            "content": {"type": "inline", "content": "x"}, "triggers": ["other-dir"]
        })),
        res(serde_json::json!({"id": "other-dir", "type": "directory", "path": "/srv"})),
    ];
    let det = detected(vec![
        det("conf", false, false),
        det("other-dir", false, false),
    ]);
    let result = diff(DiffInputs {
        resources: &resources,
        detected: &det,
        target: &target(None, None),
        machine: &local_machine(),
        lock: None,
        pending: &BTreeMap::new(),
        var: &zap_types::last_run::ReportVar::unset,
    });
    assert_eq!(result.warnings.len(), 1);
    assert!(
        result.warnings[0].contains("non-service"),
        "{:?}",
        result.warnings
    );
}

#[test]
fn undetermined_detection_is_held_not_created() {
    // The footgun fix: a probe that couldn't determine the state (here a service
    // with no service_manager) must NOT become a create — it's held with a warning.
    let resources = vec![res(serde_json::json!({
        "id": "nginx-svc", "type": "service", "service": "nginx", "enabled": true
    }))];
    let det = detected(vec![held(
        "nginx-svc",
        "service_manager not set in target (required for service resources)",
    )]);
    let result = diff(DiffInputs {
        resources: &resources,
        detected: &det,
        target: &target(None, None),
        machine: &local_machine(),
        lock: None,
        pending: &BTreeMap::new(),
        var: &zap_types::last_run::ReportVar::unset,
    });

    assert!(
        result.plan.changes.is_empty(),
        "undetermined → held, not created: {:?}",
        result.plan.changes
    );
    // The hold is a *verdict*, not narrative: it rides `held`, so a caller can see the
    // plan is partial rather than having to scan a warning list for it. A held resource
    // that only warned meant `zap plan` on an unprobeable target printed an empty
    // changeset, a trailing `warning:` line, and exit 0 — "converged".
    assert!(
        result.warnings.is_empty(),
        "a hold is not a warning: {:?}",
        result.warnings
    );
    assert_eq!(result.held.len(), 1);
    assert_eq!(result.held[0].resource_id.0, "nginx-svc");
    assert!(
        result.held[0]
            .describe()
            .contains("service_manager not set"),
        "{:?}",
        result.held
    );
}

/// A resource that detection gave no answer for plans nothing: no detection is no
/// evidence it is absent, so it is held rather than created.
#[test]
fn a_resource_with_no_detection_is_held_not_created() {
    let resources = vec![res(serde_json::json!({
        "id": "data", "type": "directory", "path": "/srv/data"
    }))];
    let result = diff(DiffInputs {
        resources: &resources,
        detected: &BTreeMap::new(),
        target: &target(None, None),
        machine: &local_machine(),
        lock: None,
        pending: &BTreeMap::new(),
        var: &zap_types::last_run::ReportVar::unset,
    });
    assert!(result.plan.changes.is_empty(), "{:?}", result.plan.changes);
    assert_eq!(result.held.len(), 1, "{:?}", result.held);
    assert_eq!(result.held[0].resource_id.0, "data");
}

#[test]
fn running_service_configured_stopped_warns() {
    // A service currently running but configured `running: false` will be STOPPED —
    // the planner surfaces a loud warning (using the typed Drifted current state).
    let resources = vec![res(serde_json::json!({
        "id": "old-svc", "type": "service", "service": "old", "enabled": false, "running": false
    }))];
    let det = detected(vec![drifted(
        "old-svc",
        CurrentState::Service {
            is_running: true,
            is_enabled: false,
        },
    )]);
    let result = diff(DiffInputs {
        resources: &resources,
        detected: &det,
        target: &target(None, Some("systemd")),
        machine: &local_machine(),
        lock: None,
        pending: &BTreeMap::new(),
        var: &zap_types::last_run::ReportVar::unset,
    });

    // It's still an update (stop the service), with the heads-up warning.
    let svc = find(&result.plan.changes, "old-svc").expect("service updated");
    assert_eq!(svc.action, ChangeAction::Update);
    assert!(
        result.warnings.iter().any(|w| w.contains("will STOP it")),
        "{:?}",
        result.warnings
    );
}

#[test]
fn unported_kind_uses_first_seen_resource_type() {
    // Sanity: a swap resource emits its fallocate sequence.
    let resources = vec![res(serde_json::json!({
        "id": "swap", "type": "swap", "size": "2G", "path": "/swapfile"
    }))];
    let det = detected(vec![det("swap", false, false)]);
    let result = diff(DiffInputs {
        resources: &resources,
        detected: &det,
        target: &target(None, None),
        machine: &local_machine(),
        lock: None,
        pending: &BTreeMap::new(),
        var: &zap_types::last_run::ReportVar::unset,
    });
    assert_eq!(result.plan.changes[0].desired.kind(), ResourceType::Swap);
    assert!(
        result.plan.changes[0]
            .steps
            .contains(&PlanStep::run("sudo fallocate -l '2G' -- '/swapfile'"))
    );
}

/// A `swap` create persists to `/etc/fstab` with a real, idempotent command (not a
/// preview `Note`).
#[test]
fn swap_persists_to_fstab_with_a_real_command() {
    let resources = vec![res(serde_json::json!({
        "id": "swap", "type": "swap", "size": "2G", "path": "/swapfile"
    }))];
    let det = detected(vec![det("swap", false, false)]);
    let steps = &diff(DiffInputs {
        resources: &resources,
        detected: &det,
        target: &target(None, None),
        machine: &local_machine(),
        lock: None,
        pending: &BTreeMap::new(),
        var: &zap_types::last_run::ReportVar::unset,
    })
    .plan
    .changes[0]
        .steps;
    let runs = runs(steps);
    assert!(
        runs.iter().any(|c| c.contains("awk '{ print }' /etc/fstab")
            && c.contains("printf '%s\\n' '/swapfile none swap sw 0 0'")
            && c.contains("zap_m=$(stat -L -c %a '/etc/fstab')")
            && c.contains("else zap_m='644'; fi; ")
            && c.ends_with(" sh '/etc/fstab' \"$zap_m\" '' '' ''; }")),
        "swap emits a real fstab rewrite: {steps:?}"
    );
    assert!(
        !runs.iter().any(|c| c.contains("tee ")),
        "nothing appends to the table in place: {steps:?}"
    );
    assert!(
        !steps.iter().any(|s| matches!(s, PlanStep::Note(_))),
        "no preview Notes remain for a sized swap: {steps:?}"
    );
}

#[test]
fn an_active_swap_file_missing_from_fstab_is_only_listed() {
    // Allocating an active swap file again fails (`fallocate`: text file busy), so the
    // repair is the fstab entry alone.
    let resources = vec![res(serde_json::json!({
        "id": "swap", "type": "swap", "size": "2G", "path": "/swapfile"
    }))];
    let det = detected(vec![drifted(
        "swap",
        CurrentState::Swap {
            is_active: true,
            in_fstab: false,
        },
    )]);
    let result = diff(DiffInputs {
        resources: &resources,
        detected: &det,
        target: &target(None, None),
        machine: &local_machine(),
        lock: None,
        pending: &BTreeMap::new(),
        var: &zap_types::last_run::ReportVar::unset,
    });
    let steps = &result.plan.changes[0].steps;
    assert!(matches!(
        steps.as_slice(),
        [PlanStep::SwapCheck(_), PlanStep::Put(_)]
    ));
}

/// A `database` create emits guarded (idempotent) role/db creation, a GRANT, and a
/// per-host `pg_hba` rule — all runnable commands, no preview `Note`s. Each declared
/// auth host gets a rule.
#[test]
fn database_steps_are_guarded_and_runnable() {
    let resources = vec![res(serde_json::json!({
        "id": "db", "type": "database", "engine": "postgresql",
        "database_name": "app", "username": "app",
        "auth": {"hosts": ["127.0.0.1/32", "::1/128"]}
    }))];
    let det = detected(vec![det("db", false, false)]);
    let steps = &diff(DiffInputs {
        resources: &resources,
        detected: &det,
        target: &target(None, Some("systemd")),
        machine: &local_machine(),
        lock: None,
        pending: &BTreeMap::new(),
        var: &zap_types::last_run::ReportVar::unset,
    })
    .plan
    .changes[0]
        .steps;
    let runs = runs(steps);
    let runs: Vec<&str> = runs.iter().map(String::as_str).collect();
    assert!(
        !steps.iter().any(|s| matches!(s, PlanStep::Note(_))),
        "database firmed — no preview Notes: {steps:?}"
    );
    assert!(
        runs.iter().any(
            |c| c.contains("pg_roles") && c.contains("|| sudo -u postgres createuser -- 'app'")
        ),
        "guarded role create: {runs:?}"
    );
    assert!(
        runs.iter()
            .any(|c| c.contains("GRANT ALL PRIVILEGES ON DATABASE \"app\" TO \"app\"")),
        "grant step: {runs:?}"
    );
    assert_eq!(
        runs.iter()
            .filter(|c| c.contains("SHOW hba_file") && c.contains("sudo -u postgres sh -c"))
            .count(),
        2,
        "one pg_hba rule per declared host: {runs:?}"
    );
}

/// A `user` create emits idempotent, runnable steps (no preview `Note`s): a
/// guarded `useradd`, a home `chmod`, a `.ssh` set to its owner and mode through a
/// descriptor, an explicit-keys `authorized_keys` put as the account, and a `0440`
/// sudoers file put behind the `visudo` check.
#[test]
fn user_steps_are_idempotent_and_runnable() {
    let resources = vec![res(serde_json::json!({
        "id": "u", "type": "user", "username": "deploy",
        "shell": "/bin/bash", "home_mode": "711",
        "ssh_keys": {"keys": ["ssh-ed25519 AAAA deploy@host"]},
        "sudo": "nopasswd"
    }))];
    let det = detected(vec![det("u", false, false)]);
    let steps = &diff(DiffInputs {
        resources: &resources,
        detected: &det,
        target: &target(None, None),
        machine: &local_machine(),
        lock: None,
        pending: &BTreeMap::new(),
        var: &zap_types::last_run::ReportVar::unset,
    })
    .plan
    .changes[0]
        .steps;
    let runs = runs(steps);
    let runs: Vec<&str> = runs.iter().map(String::as_str).collect();
    assert!(
        !steps.iter().any(|s| matches!(s, PlanStep::Note(_))),
        "user firmed — no preview Notes: {steps:?}"
    );
    assert!(
        runs.contains(
            &"id -u -- 'deploy' >/dev/null 2>&1 || sudo useradd -m -d '/home/deploy' -s '/bin/bash' -- 'deploy'"
        ),
        "guarded useradd: {runs:?}"
    );
    assert!(
        runs.contains(&"sudo chmod 711 -- '/home/deploy'"),
        "home mode: {runs:?}"
    );
    // A text put runs the put script with its text on stdin: the text is what a
    // `printf '%s\n' '<line>'` prints.
    let text_put = |path: &str, mode: &str, run_as: RunAs<'_>, check: PutCheck| {
        let command = file_put_command(run_as, path, FileAttrs::mode(mode), check);
        steps.iter().find_map(|step| match step.execution() {
            Some(StepExecution::Put {
                command: put,
                content,
            }) if put == command => Some(content.to_owned()),
            _ => None,
        })
    };
    assert_eq!(
        text_put(
            "/home/deploy/.ssh/authorized_keys",
            "600",
            RunAs::User("deploy"),
            PutCheck::None
        )
        .as_deref(),
        Some("ssh-ed25519 AAAA deploy@host\n"),
        "authorized_keys put as the account: {steps:?}"
    );
    assert!(
        runs.iter().any(|c| c
            .starts_with("sudo mkdir -p -- '/home/deploy/.ssh' && sudo timeout 300 sh -c '")
            && c.ends_with("sh '/home/deploy/.ssh' '700' 'deploy:deploy'")),
        ".ssh owner and mode through a descriptor: {runs:?}"
    );
    assert_eq!(
        text_put(
            "/etc/sudoers.d/deploy",
            "440",
            RunAs::Root,
            PutCheck::Sudoers
        )
        .as_deref(),
        Some("deploy ALL=(ALL) NOPASSWD: ALL\n"),
        "sudoers put at 0440 behind the visudo check: {steps:?}"
    );
}

/// A `user` with `sudo: false` removes the sudoers file instead of writing one.
#[test]
fn user_sudo_false_removes_sudoers() {
    let resources = vec![res(serde_json::json!({
        "id": "u", "type": "user", "username": "limited", "sudo": false
    }))];
    let det = detected(vec![det("u", false, false)]);
    let steps = &diff(DiffInputs {
        resources: &resources,
        detected: &det,
        target: &target(None, None),
        machine: &local_machine(),
        lock: None,
        pending: &BTreeMap::new(),
        var: &zap_types::last_run::ReportVar::unset,
    })
    .plan
    .changes[0]
        .steps;
    let runs = runs(steps);
    let runs: Vec<&str> = runs.iter().map(String::as_str).collect();
    assert!(
        runs.contains(&"sudo rm -f -- '/etc/sudoers.d/limited'"),
        "removes sudoers: {runs:?}"
    );
    assert!(
        !runs
            .iter()
            .any(|c| c.contains("'/etc/sudoers.d/limited' '440'")),
        "no sudoers write: {runs:?}"
    );
}

/// An `apt_repo` create writes the sources list with `signed-by` injected and
/// `/etc/os-release` sourced (so distro-codename vars resolve at apply time) — a
/// real command, not a preview `Note`.
#[test]
fn apt_repo_writes_the_sources_list() {
    let resources = vec![res(serde_json::json!({
        "id": "pgdg", "type": "apt_repo",
        "key_url": "https://example.com/key.asc",
        "source": "deb https://example.com/apt stable main"
    }))];
    let det = detected(vec![det("pgdg", false, false)]);
    let steps = &diff(DiffInputs {
        resources: &resources,
        detected: &det,
        target: &target(None, None),
        machine: &local_machine(),
        lock: None,
        pending: &BTreeMap::new(),
        var: &zap_types::last_run::ReportVar::unset,
    })
    .plan
    .changes[0]
        .steps;
    assert!(
        runs(steps).iter().any(|c| c.contains(". /etc/os-release")
            && c.contains("signed-by=/usr/share/keyrings/pgdg.asc")
            && c.ends_with(" sh '/etc/apt/sources.list.d/pgdg.list' '644' '' '' ''")),
        "apt_repo writes the signed-by source line: {steps:?}"
    );
    assert!(
        !steps.iter().any(|s| matches!(s, PlanStep::Note(_))),
        "no preview Notes remain: {steps:?}"
    );
}

/// The shell text each step runs: a command's whole text, a text put's put command.
fn runs(steps: &[PlanStep]) -> Vec<String> {
    steps
        .iter()
        .filter_map(PlanStep::execution)
        .map(|execution| execution.text().to_owned())
        .collect()
}

/// The desired content pin of a `file`'s emitted change, or `None`.
fn change_file_pin<'a>(changes: &'a [Change], id: &str) -> Option<&'a str> {
    let zap_types::schema::ResourceKind::File(file) = &find(changes, id)?.desired.kind else {
        return None;
    };
    let zap_types::schema::FileContent::Remote(remote) = &file.content else {
        return None;
    };
    remote.blake3.as_deref()
}

#[test]
fn tracked_remote_file_pin_is_folded_into_the_fact() {
    use zap_types::lock::{LOCK_VERSION, LockEntry, ZapLock};

    // A tracked remote file (no in-config `blake3`), drifted on its pin → emitted.
    let resources = vec![res(serde_json::json!({
        "id": "zig", "type": "file", "path": "/opt/zig",
        "content": {"type": "remote", "url": "https://h/zig.tar.xz", "extract": {"type": "tar.xz"}}
    }))];
    let det = detected(vec![drifted(
        "zig",
        CurrentState::File {
            drift: FileDrift::Pin {
                observed: "a".repeat(64),
            },
        },
    )]);
    let pin = "b".repeat(64);
    let mut entries = BTreeMap::new();
    entries.insert(
        ResourceId("zig".to_owned()),
        LockEntry::RemoteFile {
            config_hash: "ignored".to_owned(),
            blake3: ContentHash::new(pin.clone()).unwrap(),
        },
    );
    let lock = ZapLock {
        version: LOCK_VERSION,
        toolchain: None,
        entries,
    };

    // With the lock, the desired pin is folded in (config ⊕ lock); without it, the
    // tracked file's desired pin stays `None` (the symbolic, pre-resolution form).
    let folded = diff(DiffInputs {
        resources: &resources,
        detected: &det,
        target: &target(None, None),
        machine: &local_machine(),
        lock: Some(&lock),
        pending: &BTreeMap::new(),
        var: &zap_types::last_run::ReportVar::unset,
    });
    assert_eq!(
        change_file_pin(&folded.plan.changes, "zig"),
        Some(pin.as_str())
    );
    let unfolded = diff(DiffInputs {
        resources: &resources,
        detected: &det,
        target: &target(None, None),
        machine: &local_machine(),
        lock: None,
        pending: &BTreeMap::new(),
        var: &zap_types::last_run::ReportVar::unset,
    });
    assert_eq!(change_file_pin(&unfolded.plan.changes, "zig"), None);
}

#[test]
fn vendored_pin_is_left_untouched_by_the_fold() {
    use zap_types::lock::{LOCK_VERSION, ZapLock};

    // A vendored file (declared `blake3`) self-pins — an empty lock changes nothing.
    let declared = "c".repeat(64);
    let resources = vec![res(serde_json::json!({
        "id": "v", "type": "file", "path": "/opt/v",
        "content": {"type": "remote", "url": "https://h/v", "blake3": declared}
    }))];
    let det = detected(vec![drifted(
        "v",
        CurrentState::File {
            drift: FileDrift::Pin {
                observed: "a".repeat(64),
            },
        },
    )]);
    let empty = ZapLock {
        version: LOCK_VERSION,
        toolchain: None,
        entries: BTreeMap::new(),
    };
    let result = diff(DiffInputs {
        resources: &resources,
        detected: &det,
        target: &target(None, None),
        machine: &local_machine(),
        lock: Some(&empty),
        pending: &BTreeMap::new(),
        var: &zap_types::last_run::ReportVar::unset,
    });
    assert_eq!(
        change_file_pin(&result.plan.changes, "v"),
        Some(declared.as_str())
    );
}

/// The desired source pin of a `build`'s emitted change, or `None`.
fn change_build_pin<'a>(changes: &'a [Change], id: &str) -> Option<&'a str> {
    let zap_types::schema::ResourceKind::Build(build) = &find(changes, id)?.desired.kind else {
        return None;
    };
    let zap_types::schema::BuildSource::Remote(remote) = &build.source;
    remote.blake3.as_deref()
}

#[test]
fn tracked_build_source_pin_is_folded_into_the_fact() {
    use zap_types::lock::{LOCK_VERSION, LockEntry, ZapLock};

    // A tracked build (no in-config `blake3`), drifted on its source pin → emitted.
    let resources = vec![res(serde_json::json!({
        "id": "ghostty", "type": "build",
        "source": {"type": "remote", "url": "https://h/ghostty.tar.xz", "extract": {"type": "tar.xz"}},
        "run": "zig build -p $HOME/.local",
        "output": "/opt/ghostty/bin/ghostty"
    }))];
    let det = detected(vec![drifted(
        "ghostty",
        CurrentState::Build {
            observed: "a".repeat(64),
        },
    )]);
    let pin = "b".repeat(64);
    let mut entries = BTreeMap::new();
    entries.insert(
        ResourceId("ghostty".to_owned()),
        LockEntry::Build {
            config_hash: "ignored".to_owned(),
            blake3: ContentHash::new(pin.clone()).unwrap(),
        },
    );
    let lock = ZapLock {
        version: LOCK_VERSION,
        toolchain: None,
        entries,
    };

    // With the lock, the build's desired source pin is folded in (config ⊕ lock); without
    // it, the tracked source's pin stays `None` (the symbolic, pre-resolution form).
    let folded = diff(DiffInputs {
        resources: &resources,
        detected: &det,
        target: &target(None, None),
        machine: &local_machine(),
        lock: Some(&lock),
        pending: &BTreeMap::new(),
        var: &zap_types::last_run::ReportVar::unset,
    });
    assert_eq!(
        change_build_pin(&folded.plan.changes, "ghostty"),
        Some(pin.as_str())
    );
    let unfolded = diff(DiffInputs {
        resources: &resources,
        detected: &det,
        target: &target(None, None),
        machine: &local_machine(),
        lock: None,
        pending: &BTreeMap::new(),
        var: &zap_types::last_run::ReportVar::unset,
    });
    assert_eq!(change_build_pin(&unfolded.plan.changes, "ghostty"), None);
}

/// A tracked `apt_repo` key's lock pin is folded into the fact's `key_blake3`, which is
/// what the executor installs by; a vendored one is left as declared.
#[test]
fn tracked_apt_key_pin_is_folded_into_the_fact() {
    use zap_types::lock::{LOCK_VERSION, LockEntry, ZapLock};
    use zap_types::schema::ResourceKind;

    let repo = |key_blake3: Option<&str>| {
        let mut json = serde_json::json!({
            "id": "pgdg", "type": "apt_repo", "key_url": "https://h/key.asc",
            "source": "deb https://h/apt stable main",
        });
        if let Some(pin) = key_blake3 {
            json["key_blake3"] = serde_json::json!(pin);
        }
        vec![res(json)]
    };
    let det = detected(vec![(ResourceId("pgdg".to_owned()), Detection::Absent)]);
    let pin = "c".repeat(64);
    let vendored = "d".repeat(64);
    let mut entries = BTreeMap::new();
    entries.insert(
        ResourceId("pgdg".to_owned()),
        LockEntry::AptKey {
            config_hash: "ignored".to_owned(),
            blake3: ContentHash::new(pin.clone()).unwrap(),
        },
    );
    let lock = ZapLock {
        version: LOCK_VERSION,
        toolchain: None,
        entries,
    };
    let key_pin = |resources: &[Resource], lock: Option<&ZapLock>| {
        let result = diff(DiffInputs {
            resources,
            detected: &det,
            target: &target(None, None),
            machine: &local_machine(),
            lock,
            pending: &BTreeMap::new(),
            var: &zap_types::last_run::ReportVar::unset,
        });
        let ResourceKind::AptRepo(repo) = &result.plan.changes[0].desired.kind else {
            panic!("an apt_repo change");
        };
        repo.key_blake3.as_ref().map(|pin| pin.as_str().to_owned())
    };
    assert_eq!(key_pin(&repo(None), Some(&lock)), Some(pin));
    assert_eq!(key_pin(&repo(None), None), None);
    assert_eq!(
        key_pin(&repo(Some(&vendored)), Some(&lock)),
        Some(vendored.clone())
    );
}

#[test]
fn plan_hash_changes_when_the_folded_pin_advances() {
    use zap_types::lock::{LOCK_VERSION, LockEntry, ZapLock};

    // The fold makes the pin part of the content-addressed fact, so advancing it (a
    // `zap update`) must change `plan_hash` — otherwise CI / diffing couldn't see a
    // moving tracked pin.
    let resources = vec![res(serde_json::json!({
        "id": "zig", "type": "file", "path": "/opt/zig",
        "content": {"type": "remote", "url": "https://h/zig.tar.xz", "extract": {"type": "tar.xz"}}
    }))];
    let det = detected(vec![drifted(
        "zig",
        CurrentState::File {
            drift: FileDrift::Pin {
                observed: "a".repeat(64),
            },
        },
    )]);
    let lock_with = |pin: &str| {
        let mut entries = BTreeMap::new();
        entries.insert(
            ResourceId("zig".to_owned()),
            LockEntry::RemoteFile {
                config_hash: "ignored".to_owned(),
                blake3: ContentHash::new(pin).unwrap(),
            },
        );
        ZapLock {
            version: LOCK_VERSION,
            toolchain: None,
            entries,
        }
    };

    let plan_a = diff(DiffInputs {
        resources: &resources,
        detected: &det,
        target: &target(None, None),
        machine: &local_machine(),
        lock: Some(&lock_with(&"b".repeat(64))),
        pending: &BTreeMap::new(),
        var: &zap_types::last_run::ReportVar::unset,
    })
    .plan;
    let plan_b = diff(DiffInputs {
        resources: &resources,
        detected: &det,
        target: &target(None, None),
        machine: &local_machine(),
        lock: Some(&lock_with(&"c".repeat(64))),
        pending: &BTreeMap::new(),
        var: &zap_types::last_run::ReportVar::unset,
    })
    .plan;
    assert_ne!(
        plan_hash(&plan_a).unwrap(),
        plan_hash(&plan_b).unwrap(),
        "advancing the folded pin must change plan_hash"
    );
}

/// Every condition `diff` warns about must also be a hard error at the structural gate.
///
/// `diff`'s warnings for these are unreachable from the binary — `zap_core` runs the gate
/// before any detection — but that is an *invariant*, not a coincidence, and two of them
/// (duplicate ids, cycle) degrade to an empty plan, which reads as "converged". If a new
/// structural warning were added here without a matching validator, that degradation would
/// become the binary's only signal for it: exit 0 on a config zap can't actually plan.
///
/// So each case asserts both halves — `diff` warns, *and* the pure validators the gate is
/// built from reject. The gate itself lives in `zap_core` (it aggregates these); pinning
/// the pairing at the pure layer is what keeps the two from drifting.
#[test]
fn every_diff_warning_is_also_a_structural_gate_error() {
    use zap_types::plan::dependency_cycle;
    use zap_types::validate::{duplicate_resource_ids, unresolved_references};

    let dir = |id: &str| serde_json::json!({"id": id, "type": "directory", "path": "/srv"});

    // 1. Duplicate ids — `diff` returns an empty plan; the gate rejects.
    let dupes = vec![res(dir("a")), res(dir("a"))];
    let result = diff(DiffInputs {
        resources: &dupes,
        detected: &detected(vec![]),
        target: &target(None, None),
        machine: &local_machine(),
        lock: None,
        pending: &BTreeMap::new(),
        var: &zap_types::last_run::ReportVar::unset,
    });
    assert!(!result.warnings.is_empty(), "diff warns on duplicate ids");
    assert!(result.plan.changes.is_empty(), "and cannot plan");
    assert!(!duplicate_resource_ids(&dupes).is_empty(), "gate rejects");

    // 2. Dependency cycle — same degradation, same gate coverage.
    let cycle = vec![
        res(serde_json::json!({"id": "a", "type": "directory", "path": "/a", "depends_on": ["b"]})),
        res(serde_json::json!({"id": "b", "type": "directory", "path": "/b", "depends_on": ["a"]})),
    ];
    let result = diff(DiffInputs {
        resources: &cycle,
        detected: &detected(vec![]),
        target: &target(None, None),
        machine: &local_machine(),
        lock: None,
        pending: &BTreeMap::new(),
        var: &zap_types::last_run::ReportVar::unset,
    });
    assert!(!result.warnings.is_empty(), "diff warns on a cycle");
    assert!(result.plan.changes.is_empty(), "and cannot plan");
    assert!(dependency_cycle(&cycle).is_some(), "gate rejects");

    // 3. A file triggering an unknown resource.
    let unknown_trigger = vec![res(serde_json::json!({
        "id": "f", "type": "file", "path": "/etc/x",
        "content": {"type": "inline", "content": ""}, "triggers": ["ghost"],
    }))];
    let result = diff(DiffInputs {
        resources: &unknown_trigger,
        detected: &detected(vec![det("f", false, false)]),
        target: &target(None, None),
        machine: &local_machine(),
        lock: None,
        pending: &BTreeMap::new(),
        var: &zap_types::last_run::ReportVar::unset,
    });
    assert!(
        !result.warnings.is_empty(),
        "diff warns on an unknown trigger"
    );
    assert!(
        !unresolved_references(&unknown_trigger).is_empty(),
        "gate rejects"
    );

    // 4. A file triggering a non-service resource.
    let non_service = vec![
        res(serde_json::json!({
            "id": "f", "type": "file", "path": "/etc/x",
            "content": {"type": "inline", "content": ""}, "triggers": ["d"],
        })),
        res(dir("d")),
    ];
    let result = diff(DiffInputs {
        resources: &non_service,
        detected: &detected(vec![det("f", false, false), det("d", false, false)]),
        target: &target(None, None),
        machine: &local_machine(),
        lock: None,
        pending: &BTreeMap::new(),
        var: &zap_types::last_run::ReportVar::unset,
    });
    assert!(
        !result.warnings.is_empty(),
        "diff warns on a non-service trigger"
    );
    assert!(
        !unresolved_references(&non_service).is_empty(),
        "gate rejects"
    );

    // 5. A service whose `restart_on` names an unknown resource.
    let unknown_restart_on = vec![res(serde_json::json!({
        "id": "svc", "type": "service", "service": "nginx", "enabled": true,
        "restart_on": ["ghost"],
    }))];
    let result = diff(DiffInputs {
        resources: &unknown_restart_on,
        detected: &detected(vec![det("svc", false, false)]),
        target: &target(None, Some("systemd")),
        machine: &local_machine(),
        lock: None,
        pending: &BTreeMap::new(),
        var: &zap_types::last_run::ReportVar::unset,
    });
    assert!(
        !result.warnings.is_empty(),
        "diff warns on an unknown restart_on"
    );
    assert!(
        !unresolved_references(&unknown_restart_on).is_empty(),
        "gate rejects"
    );
}

// --- collect_residual (the post-apply Observe verdict) ---

#[test]
fn residual_collects_non_converged_post_detections() {
    use zap_types::event::ChangeOutcome;
    use zap_types::plan::{ResidualState, collect_residual};

    // Three resources after a wetrun: one re-detects converged (not residual), one
    // still absent though its change completed (the `script`-whose-`check`-still-fails
    // case), one the re-probe couldn't read — unestablished, which disqualifies the
    // wetrun's "converged" claim exactly as observed drift does.
    let resources = vec![
        res(serde_json::json!({"id": "fine", "type": "directory", "path": "/opt/fine"})),
        res(serde_json::json!({
            "id": "still-absent", "type": "script", "check": "false", "run": "true",
        })),
        res(serde_json::json!({"id": "unreadable", "type": "directory", "path": "/opt/u"})),
    ];
    let detections = vec![
        Detection::Converged,
        Detection::Absent,
        Detection::Undetermined {
            reason: "probe blip".to_owned(),
        },
    ];
    let outcomes = vec![ChangeOutcome::Completed {
        resource_id: ResourceId("still-absent".to_owned()),
        output: String::new(),
    }];
    let residual = collect_residual(&resources, &detections, &outcomes, &[]);
    assert_eq!(residual.len(), 2, "{residual:?}");
    assert_eq!(residual[0].resource_id.0, "still-absent");
    assert_eq!(residual[0].state, ResidualState::Absent);
    assert_eq!(residual[1].resource_id.0, "unreadable");
    assert!(
        matches!(&residual[1].state, ResidualState::Undetermined { reason } if reason == "probe blip"),
        "{residual:?}"
    );
    // A no-change resource that drifted during the run (e.g. broken by another
    // resource's execution) is residual too — the post-pass checks every resource.
    let drifted_mid_run = vec![
        Detection::Drifted {
            current: CurrentState::Directory {
                mode: "700".to_owned(),
                owner: "root".to_owned(),
                group: "root".to_owned(),
            },
        },
        Detection::Converged,
        Detection::Converged,
    ];
    let residual = collect_residual(&resources, &drifted_mid_run, &[], &[]);
    assert_eq!(residual.len(), 1, "{residual:?}");
    assert_eq!(residual[0].resource_id.0, "fine");
    assert!(matches!(residual[0].state, ResidualState::Drifted { .. }));
}

#[test]
fn residual_exempts_pipeline_failed_skipped_and_held() {
    use zap_types::error_code::ErrorCode;
    use zap_types::event::ChangeOutcome;
    use zap_types::plan::{HeldResource, HoldCause, collect_residual};

    // Four non-converged post-detections, none residual: a `pipeline` detects absent
    // by construction (imperative — it always runs); a failed change and its
    // stop-on-first-failure skip are already the run's loud exit-1 (non-convergence
    // implied); a held resource is already the `undetermined` verdict (nothing was
    // applied for it).
    let resources = vec![
        res(serde_json::json!({
            "id": "pipe", "type": "pipeline",
            "steps": [{"id": "s1", "run": "true"}],
        })),
        res(serde_json::json!({
            "id": "boomed", "type": "script", "check": "false", "run": "boom",
        })),
        res(serde_json::json!({
            "id": "never-ran", "type": "script", "check": "false", "run": "true",
        })),
        res(serde_json::json!({"id": "was-held", "type": "directory", "path": "~/x"})),
    ];
    let detections = vec![
        Detection::Absent,
        Detection::Absent,
        Detection::Absent,
        Detection::Undetermined {
            reason: "no declared home".to_owned(),
        },
    ];
    let outcomes = vec![
        ChangeOutcome::Failed {
            resource_id: ResourceId("boomed".to_owned()),
            error: "boom".to_owned(),
            code: ErrorCode::ExecutionFailed,
        },
        ChangeOutcome::Skipped {
            resource_id: ResourceId("never-ran".to_owned()),
            reason: "previous change failed".to_owned(),
        },
    ];
    let held = vec![HeldResource {
        resource_id: ResourceId("was-held".to_owned()),
        trigger: None,
        cause: HoldCause::Undetermined {
            reason: "no declared home".to_owned(),
        },
    }];
    let residual = collect_residual(&resources, &detections, &outcomes, &held);
    assert!(residual.is_empty(), "{residual:?}");
}

/// A service with a reload trigger and a restart trigger feeding one nginx service —
/// the fixture for the pending-marker tests. Both sources converged by default.
fn pending_fixture() -> Vec<Resource> {
    vec![
        res(serde_json::json!({
            "id": "site", "type": "file", "path": "/etc/nginx/site",
            "content": {"type": "inline", "content": "server {}"},
        })),
        res(serde_json::json!({
            "id": "nginx-svc", "type": "service", "service": "nginx", "enabled": true,
            "reload_on": ["site"],
        })),
    ]
}

#[test]
fn a_pending_marker_alone_promotes_a_converged_service() {
    // Nothing changed this run, but an earlier apply never completed the reload: the
    // marker re-fires it, with no sources and `pending` set.
    let resources = pending_fixture();
    let det = detected(vec![det("site", true, true), det("nginx-svc", true, true)]);
    let pending = BTreeMap::from([("nginx".to_owned(), TriggerKind::Reload)]);
    let result = diff(DiffInputs {
        resources: &resources,
        detected: &det,
        target: &target(None, Some("systemd")),
        machine: &local_machine(),
        lock: None,
        pending: &pending,
        var: &zap_types::last_run::ReportVar::unset,
    });
    let svc = find(&result.plan.changes, "nginx-svc").expect("pending re-fires the reload");
    assert_eq!(svc.action, ChangeAction::Update);
    assert_eq!(
        svc.trigger,
        Some(Trigger {
            kind: TriggerKind::Reload,
            sources: Vec::new(),
            pending: true,
        })
    );
    assert!(
        svc.steps
            .contains(&PlanStep::run("sudo systemctl try-reload-or-restart nginx")),
        "{:?}",
        svc.steps
    );
}

#[test]
fn a_pending_restart_outranks_a_fired_reload() {
    // The source fires a reload this run; the marker asks for a restart. The restart
    // subsumes the reload, and the trigger records both origins.
    let resources = pending_fixture();
    let det = detected(vec![
        det("site", false, false),
        det("nginx-svc", true, true),
    ]);
    let pending = BTreeMap::from([("nginx".to_owned(), TriggerKind::Restart)]);
    let result = diff(DiffInputs {
        resources: &resources,
        detected: &det,
        target: &target(None, Some("systemd")),
        machine: &local_machine(),
        lock: None,
        pending: &pending,
        var: &zap_types::last_run::ReportVar::unset,
    });
    let svc = find(&result.plan.changes, "nginx-svc").expect("service in the plan");
    assert_eq!(
        svc.trigger,
        Some(Trigger {
            kind: TriggerKind::Restart,
            sources: vec![ResourceId("site".to_owned())],
            pending: true,
        })
    );
    assert!(
        svc.steps
            .contains(&PlanStep::run("sudo systemctl try-restart nginx"))
    );
    assert!(
        !svc.steps
            .contains(&PlanStep::run("sudo systemctl try-reload-or-restart nginx")),
        "one lifecycle action, not both: {:?}",
        svc.steps
    );
}

#[test]
fn a_pending_marker_for_another_service_changes_nothing() {
    let resources = pending_fixture();
    let det = detected(vec![det("site", true, true), det("nginx-svc", true, true)]);
    let pending = BTreeMap::from([("postgresql".to_owned(), TriggerKind::Restart)]);
    let result = diff(DiffInputs {
        resources: &resources,
        detected: &det,
        target: &target(None, Some("systemd")),
        machine: &local_machine(),
        lock: None,
        pending: &pending,
        var: &zap_types::last_run::ReportVar::unset,
    });
    assert!(result.plan.changes.is_empty(), "{:?}", result.plan.changes);
}

/// A remote target declaring `host` and both users, references and all.
fn remote_target(host: &Text) -> Target {
    serde_json::from_value(serde_json::json!({
        "host": host, "user": Text::reference("T_USER"), "bootstrap_user": "root",
        "package_manager": "apt", "service_manager": "systemd",
    }))
    .expect("valid target json")
}

/// A report resolver: `*_TOKEN` names are secrets, `T_DSN` carries one, `env` supplies
/// the rest (unset resolves empty).
fn var(env: &[(&str, &str)]) -> impl Fn(&str) -> zap_types::last_run::ReportVar {
    use zap_types::last_run::ReportVar;
    let env: Vec<(String, String)> = env
        .iter()
        .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
        .collect();
    move |name| {
        if name.ends_with("_TOKEN") {
            ReportVar::Secret(zap_types::secrecy::SecretReason::Name)
        } else if name == "T_DSN" {
            ReportVar::Masked("db-[MASKED:T_PW_TOKEN]".to_owned())
        } else {
            ReportVar::Value(
                env.iter()
                    .find(|(known, _)| known == name)
                    .map(|(_, value)| value.clone())
                    .unwrap_or_default(),
            )
        }
    }
}

/// A machine is the target's host and connecting user as the environment resolves
/// them: a local target is `local` as the account zap runs as, a secret reference is its token
/// (never its value), an empty host is no machine, and an empty user is none.
#[test]
fn a_machine_is_the_target_as_the_environment_resolves_it() {
    let env = [("T_HOST", "a.example.com"), ("T_USER", "deploy")];
    let remote = remote_target(&Text::reference("T_HOST"));
    assert_eq!(
        Machine::resolve(
            &Target::local(),
            Some(&Text::literal("ignored")),
            local_account,
            var(&env)
        ),
        Some(local_machine())
    );
    assert_eq!(local_machine().host(), "local");
    assert_eq!(local_machine().user(), Some("op"));

    let machine = Machine::resolve(&remote, remote.user(), no_local, var(&env)).unwrap();
    assert_eq!(
        machine,
        Machine::Remote {
            host: "a.example.com".to_owned(),
            user: Some("deploy".to_owned()),
        }
    );
    assert_eq!(machine.host(), "a.example.com");
    assert_eq!(machine.user(), Some("deploy"));
    // The run's selected user, not always the primary one.
    assert_eq!(
        Machine::resolve(&remote, remote.bootstrap_user(), no_local, var(&env))
            .unwrap()
            .user(),
        Some("root")
    );
    // No user declared, or one that resolves empty: the connection names the host alone.
    assert_eq!(
        Machine::resolve(&remote, None, no_local, var(&env))
            .unwrap()
            .user(),
        None
    );
    assert_eq!(
        Machine::resolve(
            &remote,
            remote.user(),
            no_local,
            var(&[("T_HOST", "a.example.com")])
        )
        .unwrap()
        .user(),
        None
    );
    // A host that resolves to nothing names no machine.
    assert_eq!(
        Machine::resolve(&remote, remote.user(), no_local, var(&[])),
        None
    );
    // A secret reference is its token; a value carrying a secret arrives masked.
    assert_eq!(
        Machine::resolve(
            &remote_target(&Text::of_pieces([Ref("T_HOST_TOKEN"), Lit(".example")])),
            Some(&Text::reference("T_DSN")),
            no_local,
            var(&env)
        ),
        Some(Machine::Remote {
            host: "[MASKED:T_HOST_TOKEN].example".to_owned(),
            user: Some("db-[MASKED:T_PW_TOKEN]".to_owned()),
        })
    );
}

/// A local plan names the account zap runs as: one declaration run as another user, or
/// with another home for its paths' `~`, is another plan — a preview under one doesn't
/// bind a wetrun under the other, `sudo`'s root included. The same account is the same
/// plan.
#[test]
fn a_local_plan_hash_names_its_user_and_home() {
    let resources = vec![res(
        serde_json::json!({"id": "x", "type": "file", "path": "~/x", "content": {"type": "inline", "content": "hi\n"}}),
    )];
    let det = detected(vec![det("x", false, false)]);
    let plan_for = |machine: &Machine| {
        diff(DiffInputs {
            resources: &resources,
            detected: &det,
            target: &Target::local(),
            machine,
            lock: None,
            pending: &BTreeMap::new(),
            var: &zap_types::last_run::ReportVar::unset,
        })
        .plan
    };
    let hash_for = |machine: &Machine| plan_hash(&plan_for(machine)).unwrap();
    let as_ = |user: &str, home: Option<&str>| {
        Machine::Local(zap_types::plan::LocalAccount {
            user: user.to_owned(),
            home: home.map(str::to_owned),
        })
    };

    let a = as_("op", Some("/home/op"));
    assert_eq!(plan_for(&a).machine, a, "the fact carries the account");
    assert_eq!(hash_for(&a), hash_for(&as_("op", Some("/home/op"))));
    for (other, what) in [
        (as_("op", Some("/home/other")), "another home"),
        (as_("op", None), "no home"),
        (
            as_("root", Some("/home/op")),
            "another user, as under `sudo -E`",
        ),
        (as_("root", Some("/root")), "root, as under `sudo`"),
    ] {
        assert_eq!(
            serde_json::to_value(&plan_for(&a).changes).unwrap(),
            serde_json::to_value(&plan_for(&other).changes).unwrap(),
            "only the account differs"
        );
        assert_ne!(hash_for(&a), hash_for(&other), "{what}");
    }
}

/// One declaration under two environments is two plans: the changeset and the declared
/// target are the same text, and the hash differs with the host or the connecting user
/// the references resolve to. The same environment is the same plan.
#[test]
fn a_plan_hash_names_the_machine_the_target_resolved_to() {
    let resources = vec![res(
        serde_json::json!({"id": "data", "type": "directory", "path": "/srv/data"}),
    )];
    let det = detected(vec![det("data", false, false)]);
    let remote = remote_target(&Text::reference("T_HOST"));
    let plan_for = |machine: &Machine| {
        diff(DiffInputs {
            resources: &resources,
            detected: &det,
            target: &remote,
            machine,
            lock: None,
            pending: &BTreeMap::new(),
            var: &zap_types::last_run::ReportVar::unset,
        })
        .plan
    };
    let hash_for = |machine: &Machine| plan_hash(&plan_for(machine)).unwrap();
    let on = |host: &str, user: Option<&str>| Machine::Remote {
        host: host.to_owned(),
        user: user.map(str::to_owned),
    };

    let a = on("a.example.com", Some("deploy"));
    assert_eq!(plan_for(&a).machine, a, "the fact carries the machine");
    assert_eq!(hash_for(&a), hash_for(&on("a.example.com", Some("deploy"))));
    // Everything but the machine is identical between the two plans.
    let b = on("b.example.com", Some("deploy"));
    assert_eq!(
        serde_json::to_value(&plan_for(&a).changes).unwrap(),
        serde_json::to_value(&plan_for(&b).changes).unwrap()
    );
    assert_eq!(plan_for(&a).target, plan_for(&b).target);
    for (other, what) in [
        (b, "another host"),
        (on("a.example.com", Some("root")), "another connecting user"),
        (on("a.example.com", None), "no connecting user"),
        (local_machine(), "the local machine"),
    ] {
        assert_ne!(hash_for(&a), hash_for(&other), "{what}");
    }
    // The degraded plans carry it too.
    let twice = vec![resources[0].clone(), resources[0].clone()];
    let degraded = diff(DiffInputs {
        resources: &twice,
        detected: &det,
        target: &remote,
        machine: &a,
        lock: None,
        pending: &BTreeMap::new(),
        var: &zap_types::last_run::ReportVar::unset,
    });
    assert!(degraded.plan.changes.is_empty());
    assert_eq!(degraded.plan.machine, a);
    let cyclic = vec![
        res(serde_json::json!({"id": "x", "type": "directory", "path": "/x", "depends_on": ["y"]})),
        res(serde_json::json!({"id": "y", "type": "directory", "path": "/y", "depends_on": ["x"]})),
    ];
    let degraded = diff(DiffInputs {
        resources: &cyclic,
        detected: &det,
        target: &remote,
        machine: &a,
        lock: None,
        pending: &BTreeMap::new(),
        var: &zap_types::last_run::ReportVar::unset,
    });
    assert!(degraded.plan.changes.is_empty());
    assert_eq!(degraded.plan.machine, a);
}

/// A plan records what each reference its changes use resolves to — a secret as a
/// secret, an unset one as unset — and nothing of a reference no change uses: a
/// converged resource's, a held one's, the target's own. A fetch credential's reference
/// is recorded with the rest, and a reference that reaches only a step's text is found
/// there.
#[test]
fn a_plan_records_the_references_its_changes_use_and_no_others() {
    use zap_types::last_run::ReportVar;
    use zap_types::plan::ReferenceValue;
    use zap_types::secrecy::SecretReason;

    let resources = vec![
        res(serde_json::json!({
            "id": "data", "type": "directory",
            "path": Text::of_pieces([Lit("/srv/"), Ref("APP_DIR")]),
        })),
        res(serde_json::json!({
            "id": "db", "type": "database", "engine": "postgresql",
            "database_name": "app", "username": Text::reference("DB_ROLE"),
        })),
        res(serde_json::json!({
            "id": "blob", "type": "file", "path": "/opt/blob",
            "content": {
                "type": "remote", "url": Text::of_pieces([Lit("https://e.x/"), Ref("BLOB")]),
                "blake3": "ab".repeat(32),
                "auth": {"scheme": "bearer", "token": Text::reference("FETCH_TOKEN")},
            },
        })),
        res(serde_json::json!({
            "id": "go", "type": "script", "check": Text::reference("STAGE"),
            "run": "true", "env": {"A": Text::reference("NOT_SET")},
        })),
        res(serde_json::json!({
            "id": "converged", "type": "directory",
            "path": Text::of_pieces([Lit("/srv/"), Ref("CONVERGED_ONLY")]),
        })),
        res(serde_json::json!({
            "id": "unread", "type": "directory",
            "path": Text::of_pieces([Lit("/srv/"), Ref("HELD_ONLY")]),
        })),
    ];
    let states = detected(vec![
        det("data", false, false),
        det("db", false, false),
        det("blob", false, false),
        det("go", false, false),
        det("converged", true, true),
        held("unread", "probe failed"),
    ]);
    let remote: Target = serde_json::from_value(serde_json::json!({
        "host": Text::reference("HOST"), "user": Text::reference("DEPLOY_USER"),
        "service_manager": "systemd",
    }))
    .unwrap();
    let var = |name: &str| match name {
        "FETCH_TOKEN" => ReportVar::Secret(SecretReason::Credential),
        "NOT_SET" => ReportVar::Value(String::new()),
        "BLOB" => ReportVar::Masked("blob-[MASKED:PW]".to_owned()),
        other => ReportVar::Value(format!("value of {other}")),
    };
    let plan = diff(DiffInputs {
        resources: &resources,
        detected: &states,
        target: &remote,
        machine: &Machine::Remote {
            host: "a.example.com".to_owned(),
            user: Some("deploy".to_owned()),
        },
        lock: None,
        pending: &BTreeMap::new(),
        var: &var,
    })
    .plan;
    let value = |text: &str| ReferenceValue::Value(text.to_owned());
    assert_eq!(
        plan.references
            .iter()
            .map(|(name, value)| (name.as_str(), value.clone()))
            .collect::<Vec<_>>(),
        [
            ("APP_DIR", value("value of APP_DIR")),
            ("BLOB", value("blob-[MASKED:PW]")),
            ("DB_ROLE", value("value of DB_ROLE")),
            ("FETCH_TOKEN", ReferenceValue::Secret),
            ("NOT_SET", ReferenceValue::Unset),
            ("STAGE", value("value of STAGE")),
        ]
    );
    // The wire form: a value under `value`, the other two states as words.
    assert_eq!(
        serde_json::to_value(&plan.references).unwrap(),
        serde_json::json!({
            "APP_DIR": {"value": "value of APP_DIR"},
            "BLOB": {"value": "blob-[MASKED:PW]"},
            "DB_ROLE": {"value": "value of DB_ROLE"},
            "FETCH_TOKEN": "secret",
            "NOT_SET": "unset",
            "STAGE": {"value": "value of STAGE"},
        })
    );

    // The changes are the same under any value; the hash is not. A secret's value is
    // the exception: it is in neither.
    let under = |var: &dyn Fn(&str) -> ReportVar| {
        diff(DiffInputs {
            resources: &resources,
            detected: &states,
            target: &remote,
            machine: &local_machine(),
            lock: None,
            pending: &BTreeMap::new(),
            var,
        })
        .plan
    };
    let base = under(&var);
    let moved = under(&|name| match name {
        "APP_DIR" => ReportVar::Value("/etc".to_owned()),
        other => var(other),
    });
    assert_eq!(moved.changes, base.changes);
    assert_ne!(plan_hash(&moved).unwrap(), plan_hash(&base).unwrap());
    let other_secret = under(&|name| match name {
        "FETCH_TOKEN" => ReportVar::Secret(SecretReason::Declared),
        other => var(other),
    });
    assert_eq!(plan_hash(&other_secret).unwrap(), plan_hash(&base).unwrap());
    // A reference only a converged resource uses moves nothing.
    let unused = under(&|name| match name {
        "CONVERGED_ONLY" | "HELD_ONLY" | "HOST" | "DEPLOY_USER" => {
            ReportVar::Value("elsewhere".to_owned())
        }
        other => var(other),
    });
    assert_eq!(plan_hash(&unused).unwrap(), plan_hash(&base).unwrap());

    // A plan with no reference records none.
    let plain = diff(DiffInputs {
        resources: &[res(
            serde_json::json!({"id": "d", "type": "directory", "path": "/opt/d"}),
        )],
        detected: &detected(vec![det("d", false, false)]),
        target: &target(None, None),
        machine: &local_machine(),
        lock: None,
        pending: &BTreeMap::new(),
        var: &ReportVar::unset,
    })
    .plan;
    assert!(plan.references.len() > plain.references.len());
    assert!(plain.references.is_empty());
    assert_eq!(
        serde_json::to_value(&plain).unwrap()["references"],
        serde_json::json!({})
    );
}

/// A reference that only a step's text holds is recorded: a change whose `desired`
/// holds none and whose command and note each hold one.
#[test]
fn a_reference_only_a_steps_text_holds_is_recorded() {
    use zap_types::last_run::ReportVar;
    use zap_types::plan::{ReferenceValue, references};
    use zap_types::var_ref::marker;

    let desired = res(serde_json::json!({"id": "d", "type": "directory", "path": "/opt/d"}));
    let change = Change {
        resource_id: desired.id.clone(),
        action: ChangeAction::Create,
        steps: vec![
            PlanStep::run(format!("install -d {}", marker("STEP_ONLY_RUN"))),
            PlanStep::Note(format!("see {}", marker("STEP_ONLY_NOTE"))),
            PlanStep::Installer(zap_types::plan::InstallerStep {
                url: format!("https://{}/i.sh", marker("STEP_ONLY_URL")),
                shell: format!("sh -s -- {}", marker("STEP_ONLY_SHELL")),
            }),
            serde_json::from_value(serde_json::json!({"put": {
                "path": "/etc/apt/sources.list.d/x.list", "run_as": "root", "check": "none",
                "source": {"command": {
                    "mode": {"set": "644"},
                    "producer": {"apt_source_line": {
                        "line": format!("deb https://{}/apt stable main", marker("STEP_ONLY_LINE")),
                    }},
                }},
            }}))
            .unwrap(),
        ],
        desired,
        depends_on: Vec::new(),
        trigger: None,
    };
    let recorded = references(&[change], &|name| {
        ReportVar::Value(format!("value of {name}"))
    });
    assert_eq!(
        recorded
            .iter()
            .map(|(name, value)| (name.as_str(), value.clone()))
            .collect::<Vec<_>>(),
        [
            "STEP_ONLY_LINE",
            "STEP_ONLY_NOTE",
            "STEP_ONLY_RUN",
            "STEP_ONLY_SHELL",
            "STEP_ONLY_URL",
        ]
        .map(|name| (name, ReferenceValue::Value(format!("value of {name}"))))
    );
}

/// A plan reads back from its own JSON as itself — every kind's change, a typed step, a
/// trigger, a remote machine, each state of a reference, and a batched install, whose
/// stand-in declares no package name of its own.
#[test]
fn a_plan_round_trips_through_its_json() {
    use zap_types::last_run::ReportVar;
    use zap_types::plan::Plan;
    use zap_types::secrecy::SecretReason;

    let resources = vec![
        res(serde_json::json!({"id": "curl", "type": "package", "from": {"apt": "curl"}})),
        res(serde_json::json!({"id": "gpp", "type": "package", "from": {"apt": "g++"}})),
        res(serde_json::json!({
            "id": "conf", "type": "file", "path": Text::of_pieces([Lit("/etc/"), Ref("NAME")]),
            "content": {"type": "inline", "content": "x"}, "triggers": ["api"],
        })),
        res(serde_json::json!({"id": "api", "type": "service", "service": "api"})),
        res(serde_json::json!({
            "id": "db", "type": "database", "engine": "postgresql",
            "database_name": "app", "username": Text::reference("DB_ROLE"),
        })),
        res(serde_json::json!({
            "id": "deploy", "type": "user", "username": "deploy",
            "ssh_keys": {"copy_from": "root"}, "sudo": "nopasswd",
        })),
        res(serde_json::json!({
            "id": "go", "type": "script", "check": "false",
            "run": Text::reference("TOKEN"), "env": {"A": Text::reference("NOT_SET")},
        })),
    ];
    let states = detected(
        resources
            .iter()
            .map(|r| det(&r.id.0, false, false))
            .collect(),
    );
    let remote: Target = serde_json::from_value(serde_json::json!({
        "host": Text::reference("HOST"), "user": "deploy",
        "package_manager": "apt", "service_manager": "systemd",
    }))
    .unwrap();
    let plan = diff(DiffInputs {
        resources: &resources,
        detected: &states,
        target: &remote,
        machine: &Machine::Remote {
            host: "a.example.com".to_owned(),
            user: Some("deploy".to_owned()),
        },
        lock: None,
        pending: &BTreeMap::new(),
        var: &|name| match name {
            "TOKEN" => ReportVar::Secret(SecretReason::Declared),
            "NOT_SET" => ReportVar::Value(String::new()),
            other => ReportVar::Value(format!("value of {other}")),
        },
    })
    .plan;
    let batch = find(&plan.changes, "batch-install-apt").expect("a batched install");
    assert_eq!(
        batch.steps,
        [PlanStep::run(
            "sudo DEBIAN_FRONTEND=noninteractive apt-get install -y curl g++"
        )]
    );
    assert_eq!(
        serde_json::to_value(&batch.desired).unwrap(),
        serde_json::json!({"id": "batch-install-apt", "type": "package", "from": {}})
    );
    assert!(plan.changes.iter().any(|change| change.trigger.is_some()));
    assert_eq!(plan.references.len(), 4);

    let json = serde_json::to_string(&plan).unwrap();
    let read: Plan = serde_json::from_str(&json).unwrap();
    assert_eq!(read, plan);
    assert_eq!(plan_hash(&read).unwrap(), plan_hash(&plan).unwrap());
}

/// The local account of a remote target, which no resolution reads.
fn no_local() -> zap_types::plan::LocalAccount {
    panic!("a remote target is resolved without the local account")
}

// --- holds spread: forward along `depends_on`, in reverse along trigger edges ----------

/// Plan `resources` over `states` on a local apt + systemd target.
fn plan_held(
    resources: &[Resource],
    states: Vec<(ResourceId, Detection)>,
) -> zap_types::plan::PlanResult {
    let det = detected(states);
    diff(DiffInputs {
        resources,
        detected: &det,
        target: &target(Some("apt"), Some("systemd")),
        machine: &local_machine(),
        lock: None,
        pending: &BTreeMap::new(),
        var: &zap_types::last_run::ReportVar::unset,
    })
}

/// The held entries as `(id, cause)`, in report order.
fn holds(result: &zap_types::plan::PlanResult) -> Vec<(String, zap_types::plan::HoldCause)> {
    result
        .held
        .iter()
        .map(|held| (held.resource_id.0.clone(), held.cause.clone()))
        .collect()
}

fn rid(id: &str) -> ResourceId {
    ResourceId(id.to_owned())
}

fn waits(on: &[&str]) -> zap_types::plan::HoldCause {
    zap_types::plan::HoldCause::Waits {
        on: on.iter().map(|id| rid(id)).collect(),
    }
}

fn triggers(service: &str, kind: TriggerKind) -> zap_types::plan::HoldCause {
    zap_types::plan::HoldCause::Triggers {
        service: rid(service),
        kind,
    }
}

fn undetermined(reason: &str) -> zap_types::plan::HoldCause {
    zap_types::plan::HoldCause::Undetermined {
        reason: reason.to_owned(),
    }
}

fn dir(id: &str, depends_on: &[&str]) -> Resource {
    res(serde_json::json!({
        "id": id, "type": "directory", "path": format!("/opt/{id}"), "depends_on": depends_on,
    }))
}

fn service(id: &str, extra: &serde_json::Value) -> Resource {
    let mut json = serde_json::json!({
        "id": id, "type": "service", "service": id, "enabled": true,
    });
    json.as_object_mut()
        .unwrap()
        .extend(extra.as_object().unwrap().clone());
    res(json)
}

fn conf(id: &str, triggers: &[&str]) -> Resource {
    res(serde_json::json!({
        "id": id, "type": "file", "path": format!("/etc/{id}"),
        "content": {"type": "inline", "content": "x"}, "triggers": triggers,
    }))
}

#[test]
fn a_held_resource_holds_its_dependents() {
    // `app` waits on `data`, which detection couldn't read: running it first could act
    // on a directory that isn't there, so it is held behind `data` — reported, out of
    // the plan. `other` waits on nothing held and is planned.
    let resources = vec![dir("data", &[]), dir("app", &["data"]), dir("other", &[])];
    let result = plan_held(
        &resources,
        vec![
            held("data", "the read exited 1"),
            det("app", false, false),
            det("other", false, false),
        ],
    );
    assert_eq!(ids(&result.plan.changes), ["other"]);
    assert_eq!(
        holds(&result),
        [
            ("data".to_owned(), undetermined("the read exited 1")),
            ("app".to_owned(), waits(&["data"])),
        ]
    );
    assert_eq!(result.held[1].describe(), "waits on `data`, which is held");
    assert!(result.held[0].is_undetermined());
    assert!(!result.held[1].is_undetermined());
}

#[test]
fn a_hold_passes_through_a_converged_resource_unreported() {
    // `mid` is converged — it changes nothing, so it isn't reported — but `leaf` still
    // waits on `root` through it, and names `root`. `fan` waits on two holds.
    let resources = vec![
        dir("root", &[]),
        dir("other-root", &[]),
        dir("mid", &["root"]),
        dir("leaf", &["mid"]),
        dir("fan", &["mid", "other-root"]),
    ];
    let result = plan_held(
        &resources,
        vec![
            held("root", "unread"),
            held("other-root", "unread"),
            det("mid", true, true),
            det("leaf", true, false),
            det("fan", false, false),
        ],
    );
    assert!(result.plan.changes.is_empty(), "{:?}", result.plan.changes);
    let holds = holds(&result);
    assert!(
        holds.contains(&("leaf".to_owned(), waits(&["root"]))),
        "{holds:?}"
    );
    assert!(
        holds.contains(&("fan".to_owned(), waits(&["other-root", "root"]))),
        "{holds:?}"
    );
    assert!(!holds.iter().any(|(id, _)| id == "mid"), "{holds:?}");
    let fan = result
        .held
        .iter()
        .find(|held| held.resource_id.0 == "fan")
        .unwrap();
    assert_eq!(
        fan.describe(),
        "waits on `other-root`, `root`, which are held"
    );
}

#[test]
fn a_package_held_behind_another_is_not_batched() {
    // `tools` waits on the held `repo`; the batch installs the other two alone.
    let resources = vec![
        dir("repo", &[]),
        res(serde_json::json!({
            "id": "tools", "type": "package", "from": {"apt": "tools"}, "depends_on": ["repo"],
        })),
        res(serde_json::json!({"id": "curl", "type": "package", "from": {"apt": "curl"}})),
        res(serde_json::json!({"id": "git", "type": "package", "from": {"apt": "git"}})),
    ];
    let result = plan_held(
        &resources,
        vec![
            held("repo", "unread"),
            det("tools", false, false),
            det("curl", false, false),
            det("git", false, false),
        ],
    );
    assert_eq!(
        ids(&result.plan.changes),
        ["cache-update-apt", "batch-install-apt"]
    );
    let batch = find(&result.plan.changes, "batch-install-apt").unwrap();
    assert_eq!(
        batch.steps,
        [PlanStep::run(
            "sudo DEBIAN_FRONTEND=noninteractive apt-get install -y curl git"
        )]
    );
    assert_eq!(
        holds(&result),
        [
            ("repo".to_owned(), undetermined("unread")),
            ("tools".to_owned(), waits(&["repo"])),
        ]
    );
}

#[test]
fn a_held_service_holds_the_sources_that_would_trigger_it() {
    // Each source's change would owe `web` a restart or a reload; with `web` held,
    // nothing would run it and no pending marker would remember it, so each source is
    // held. A converged source changes nothing and isn't reported.
    let resources = vec![
        conf("pushed", &["web"]),
        res(serde_json::json!({
            "id": "pulled", "type": "script", "check": "false", "run": "true",
        })),
        conf("reloads", &[]),
        conf("quiet", &[]),
        service(
            "web",
            &serde_json::json!({
                "restart_on": ["pulled", "quiet"], "reload_on": ["reloads"],
            }),
        ),
    ];
    let result = plan_held(
        &resources,
        vec![
            det("pushed", false, false),
            det("pulled", false, false),
            det("reloads", true, false),
            det("quiet", true, true),
            held("web", "the unit read exited 1"),
        ],
    );
    assert!(result.plan.changes.is_empty(), "{:?}", result.plan.changes);
    let mut holds = holds(&result);
    holds.sort_by(|a, b| a.0.cmp(&b.0));
    assert_eq!(
        holds,
        [
            ("pulled".to_owned(), triggers("web", TriggerKind::Restart)),
            ("pushed".to_owned(), triggers("web", TriggerKind::Restart)),
            ("reloads".to_owned(), triggers("web", TriggerKind::Reload)),
            ("web".to_owned(), undetermined("the unit read exited 1")),
        ]
    );
    let reloads = result
        .held
        .iter()
        .find(|held| held.resource_id.0 == "reloads")
        .unwrap();
    assert_eq!(reloads.describe(), "would reload `web`, which is held");
}

#[test]
fn a_held_plain_dependency_holds_nothing_upstream() {
    // `web` depends on `unit` but isn't triggered by it: what a held resource depends
    // on still runs.
    let resources = vec![
        conf("unit", &[]),
        service("web", &serde_json::json!({"depends_on": ["unit"]})),
    ];
    let result = plan_held(
        &resources,
        vec![det("unit", false, false), held("web", "unread")],
    );
    assert_eq!(ids(&result.plan.changes), ["unit"]);
    assert_eq!(holds(&result), [("web".to_owned(), undetermined("unread"))]);
}

#[test]
fn a_shared_source_held_for_one_service_holds_the_other() {
    // `shared` would restart both; `db` is held, so `shared` is held, and `web` —
    // promoted only to take the restart — waits on it.
    let resources = vec![
        conf("shared", &["db", "web"]),
        service("db", &serde_json::json!({})),
        service("web", &serde_json::json!({})),
    ];
    let result = plan_held(
        &resources,
        vec![
            det("shared", true, false),
            held("db", "unread"),
            det("web", true, true),
        ],
    );
    assert!(result.plan.changes.is_empty(), "{:?}", result.plan.changes);
    let mut holds = holds(&result);
    holds.sort_by(|a, b| a.0.cmp(&b.0));
    assert_eq!(
        holds,
        [
            ("db".to_owned(), undetermined("unread")),
            ("shared".to_owned(), triggers("db", TriggerKind::Restart)),
            ("web".to_owned(), waits(&["shared"])),
        ]
    );
}

#[test]
fn trigger_holds_cascade() {
    // `front` restarts on `back`, a drifted service that reloads on `conf`: `front`
    // held holds `back`, which holds `conf`, which holds `after`, its dependent.
    let resources = vec![
        conf("conf", &[]),
        dir("after", &["conf"]),
        service("back", &serde_json::json!({"reload_on": ["conf"]})),
        service("front", &serde_json::json!({"restart_on": ["back"]})),
    ];
    let result = plan_held(
        &resources,
        vec![
            det("conf", false, false),
            det("after", false, false),
            drifted(
                "back",
                CurrentState::Service {
                    is_enabled: false,
                    is_running: true,
                },
            ),
            held("front", "unread"),
        ],
    );
    assert!(result.plan.changes.is_empty(), "{:?}", result.plan.changes);
    let mut holds = holds(&result);
    holds.sort_by(|a, b| a.0.cmp(&b.0));
    assert_eq!(
        holds,
        [
            ("after".to_owned(), waits(&["conf"])),
            ("back".to_owned(), triggers("front", TriggerKind::Restart)),
            ("conf".to_owned(), triggers("back", TriggerKind::Reload)),
            ("front".to_owned(), undetermined("unread")),
        ]
    );
}

/// `back` is converged and promoted only by `conf`'s change; `front` restarts on
/// `back`. Run with `front` sorting after `back` and before every resource, so the
/// promotion is seen whichever side of it `front`'s id falls.
fn promoted_cascade(front: &str) -> Vec<Resource> {
    vec![
        conf("conf", &[]),
        service("back", &serde_json::json!({"restart_on": ["conf"]})),
        service(front, &serde_json::json!({"restart_on": ["back"]})),
    ]
}

#[test]
fn a_promoted_service_fires_its_own_trigger_whatever_the_ids() {
    for front in ["z-front", "a-front"] {
        let result = plan_held(
            &promoted_cascade(front),
            vec![
                det("conf", true, false),
                det("back", true, true),
                det(front, true, true),
            ],
        );
        assert!(result.held.is_empty(), "{front}: {:?}", result.held);
        assert_eq!(
            ids(&result.plan.changes),
            ["conf", "back", front],
            "{front}"
        );
        let trigger = find(&result.plan.changes, front)
            .and_then(|change| change.trigger.as_ref())
            .unwrap();
        assert_eq!(trigger.kind, TriggerKind::Restart, "{front}");
        assert_eq!(trigger.sources, [rid("back")], "{front}");
    }
}

#[test]
fn trigger_holds_cascade_through_a_promoted_service() {
    // `front` held holds `back`, whose change exists only to take `conf`'s restart,
    // and `back` held holds `conf`: nothing runs, and `front`'s restart stays owed to
    // the next plan that can read it, whichever side of `back` its id sorts.
    for front in ["z-front", "a-front"] {
        let result = plan_held(
            &promoted_cascade(front),
            vec![
                det("conf", true, false),
                det("back", true, true),
                held(front, "unread"),
            ],
        );
        assert!(
            result.plan.changes.is_empty(),
            "{front}: {:?}",
            result.plan.changes
        );
        let mut holds = holds(&result);
        holds.sort_by(|a, b| a.0.cmp(&b.0));
        let mut expected = vec![
            ("back".to_owned(), triggers(front, TriggerKind::Restart)),
            ("conf".to_owned(), triggers("back", TriggerKind::Restart)),
            (front.to_owned(), undetermined("unread")),
        ];
        expected.sort_by(|a, b| a.0.cmp(&b.0));
        assert_eq!(holds, expected, "{front}");
    }
}

/// Plan `resources` over `states` with `pending` markers left on the target.
fn plan_pending(
    resources: &[Resource],
    states: Vec<(ResourceId, Detection)>,
    pending: &BTreeMap<String, TriggerKind>,
) -> zap_types::plan::PlanResult {
    let det = detected(states);
    diff(DiffInputs {
        resources,
        detected: &det,
        target: &target(Some("apt"), Some("systemd")),
        machine: &local_machine(),
        lock: None,
        pending,
        var: &zap_types::last_run::ReportVar::unset,
    })
}

#[test]
fn an_owed_restart_runs_past_an_unreadable_trigger_source() {
    // `web` is converged and owes a restart from an earlier apply. Its source `unit`
    // can't be read, so it fires nothing: the owed restart is all `web` would run, and
    // `unit` holds only itself — whether `web` restarts on it or `unit` pushes it.
    let pending = BTreeMap::from([("web".to_owned(), TriggerKind::Restart)]);
    for resources in [
        vec![
            conf("unit", &[]),
            service("web", &serde_json::json!({"restart_on": ["unit"]})),
        ],
        vec![
            conf("unit", &["web"]),
            service("web", &serde_json::json!({})),
        ],
    ] {
        let result = plan_pending(
            &resources,
            vec![held("unit", "unread"), det("web", true, true)],
            &pending,
        );
        assert_eq!(
            holds(&result),
            [("unit".to_owned(), undetermined("unread"))]
        );
        assert_eq!(ids(&result.plan.changes), ["web"]);
        let web = find(&result.plan.changes, "web").unwrap();
        assert_eq!(
            web.trigger,
            Some(Trigger {
                kind: TriggerKind::Restart,
                sources: Vec::new(),
                pending: true,
            })
        );
        assert_eq!(
            web.steps.last(),
            Some(&PlanStep::run("sudo systemctl try-restart web"))
        );
        assert!(web.depends_on.is_empty(), "{:?}", web.depends_on);
    }
}

#[test]
fn an_owed_restart_still_waits_on_a_declared_held_dependency() {
    // `web` declares it depends on `unit` as well as restarting on it, and on the held
    // package `tools`: a declared edge still holds it.
    let pending = BTreeMap::from([("web".to_owned(), TriggerKind::Restart)]);
    for (declared, on) in [("unit", "unit"), ("tools", "tools")] {
        let resources = vec![
            conf("unit", &[]),
            res(serde_json::json!({"id": "tools", "type": "package", "from": {"apt": "tools"}})),
            service(
                "web",
                &serde_json::json!({"restart_on": ["unit"], "depends_on": [declared]}),
            ),
        ];
        let result = plan_pending(
            &resources,
            vec![
                held("unit", "unread"),
                held("tools", "unread"),
                det("web", true, true),
            ],
            &pending,
        );
        assert!(
            result.plan.changes.is_empty(),
            "{declared}: {:?}",
            result.plan.changes
        );
        assert!(
            holds(&result).contains(&("web".to_owned(), waits(&[on]))),
            "{declared}: {:?}",
            holds(&result)
        );
    }
}

#[test]
fn a_fired_source_held_behind_another_still_holds_an_owed_restart() {
    // `unit` changed, so it fires `web`, but it waits on the held `data`: `web`'s
    // trigger names `unit`, and `web` waits on it whatever restart it also owes.
    let pending = BTreeMap::from([("web".to_owned(), TriggerKind::Restart)]);
    let mut unit = conf("unit", &[]);
    unit.depends_on = vec![rid("data")];
    let resources = vec![
        dir("data", &[]),
        unit,
        service("web", &serde_json::json!({"restart_on": ["unit"]})),
    ];
    let result = plan_pending(
        &resources,
        vec![
            held("data", "unread"),
            det("unit", true, false),
            det("web", true, true),
        ],
        &pending,
    );
    assert!(result.plan.changes.is_empty(), "{:?}", result.plan.changes);
    let mut holds = holds(&result);
    holds.sort_by(|a, b| a.0.cmp(&b.0));
    assert_eq!(
        holds,
        [
            ("data".to_owned(), undetermined("unread")),
            ("unit".to_owned(), waits(&["data"])),
            ("web".to_owned(), waits(&["unit"])),
        ]
    );
}

#[test]
fn a_cycle_through_trigger_edges_is_rejected() {
    use zap_types::plan::dependency_cycle;
    // Two services restarting on each other.
    let mutual = vec![
        service("a", &serde_json::json!({"restart_on": ["b"]})),
        service("b", &serde_json::json!({"reload_on": ["a"]})),
    ];
    assert!(dependency_cycle(&mutual).is_some());
    let result = plan_held(&mutual, vec![det("a", true, false), det("b", true, false)]);
    assert!(result.plan.changes.is_empty(), "{:?}", result.plan.changes);
    assert!(
        result
            .warnings
            .iter()
            .any(|w| w.contains("dependency cycle")),
        "{:?}",
        result.warnings
    );
    // A file that triggers the service it depends on.
    let mut pushed = conf("unit", &["web"]);
    pushed.depends_on = vec![rid("web")];
    let pushed = vec![pushed, service("web", &serde_json::json!({}))];
    assert_eq!(
        dependency_cycle(&pushed),
        Some(vec![rid("unit"), rid("web")])
    );
    // A trigger that runs with the edges, not against them, is no cycle.
    let chain = promoted_cascade("front");
    assert_eq!(dependency_cycle(&chain), None);
}

#[test]
fn a_resource_held_behind_another_is_not_residual() {
    // After a wetrun the dependent still reads absent — nothing ran for it — and it is
    // already reported held, so it is not residual.
    use zap_types::plan::collect_residual;
    let resources = vec![dir("data", &[]), dir("app", &["data"])];
    let result = plan_held(
        &resources,
        vec![held("data", "unread"), det("app", false, false)],
    );
    let residual = collect_residual(
        &resources,
        &[
            Detection::Undetermined {
                reason: "unread".to_owned(),
            },
            Detection::Absent,
        ],
        &[],
        &result.held,
    );
    assert!(residual.is_empty(), "{residual:?}");
}
