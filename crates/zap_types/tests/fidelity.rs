//! Full-config round-trip fidelity guard.
//!
//! Nothing the config-eval sidecar emits should be lost on round-trip through the
//! typed schema: not top-level config (`mask_vars` / `unmask_vars` / `deploy`), not a
//! per-kind field (`pipeline.max_concurrency`, …).
//!
//! A kitchen-sink config
//! exercising every kind and every field is parsed into [`ZapConfig`] and
//! reserialized, and we assert **every key present in the input survives in the
//! output** (a subset check — the schema *adds* materialized defaults, which is
//! fine; it must never *drop* a field). A stray field hard-fails at parse via
//! `deny_unknown_fields` on the plain/leaf structs, the tagged enums and the wire
//! structs the hand-read ones go through, so this guard stands behind that rejection:
//! it would catch a type added without one.

#![expect(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test helpers outside `#[test]` fns panic on a failed setup or check"
)]

mod common;

use std::collections::{BTreeMap, BTreeSet};

use common::local_machine;
use serde_json::{Value, json};
use zap_types::detected::Detection;
use zap_types::plan::{DiffInputs, PlanStep, StepExecution, diff};
use zap_types::schema::{ResourceType, TextRole, WireError, ZapConfig};
use zap_types::text::Text;
use zap_types::var_ref::Segment::{Ref, Text as Lit};
use zap_types::var_ref::{map_refs, marker};

/// Assert every key/element present in `input` also appears in `output`, with equal
/// scalar leaves. Default-materialized keys present only in `output` are allowed
/// (the schema may add them); a key present only in `input` is a dropped field.
fn assert_no_drops(input: &Value, output: &Value, path: &str) {
    match (input, output) {
        (Value::Object(input_map), Value::Object(output_map)) => {
            for (key, input_value) in input_map {
                let output_value = output_map
                    .get(key)
                    .unwrap_or_else(|| panic!("dropped field at {path}.{key}"));
                assert_no_drops(input_value, output_value, &format!("{path}.{key}"));
            }
        }
        (Value::Array(input_items), Value::Array(output_items)) => {
            assert_eq!(
                input_items.len(),
                output_items.len(),
                "array length changed at {path}"
            );
            for (index, (input_value, output_value)) in
                input_items.iter().zip(output_items).enumerate()
            {
                assert_no_drops(input_value, output_value, &format!("{path}[{index}]"));
            }
        }
        (input_leaf, output_leaf) => {
            assert_eq!(input_leaf, output_leaf, "value changed at {path}");
        }
    }
}

/// A config exercising every resource kind with every field set, plus every
/// top-level field. The shape the config-eval sidecar emits (raw `{type, ...}`
/// spread — no defaults materialized).
fn kitchen_sink() -> Value {
    json!({
        "target": {
            "local": false,
            "host": Text::reference("DEPLOY_HOST"),
            "user": "deploy",
            "bootstrap_user": "root",
            "port": 2222,
            "key_path": "/home/deploy/.ssh/id_ed25519",
            "package_manager": "apt",
            "service_manager": "systemd",
            "home": "/home/deploy"
        },
        "resources": [
            // Both `check` forms: a path, and a command.
            {"id": "curl", "name": "curl", "type": "package",
             "from": {"apt": "curl"}, "check": "/usr/bin/curl"},
            {"id": "jq", "name": "jq", "type": "package",
             "from": {"apt": "jq", "apk": "jq"}, "check": "command -v jq"},
            {"id": "pgdg", "name": "PostgreSQL apt repo", "type": "apt_repo",
             "key_url": "https://example.com/key.asc",
             "key_path": "/usr/share/keyrings/pgdg.asc",
             "source": "deb https://apt.example.com/pub stable main",
             "list_file": "/etc/apt/sources.list.d/pgdg.list"},
            {"id": "fish-setup", "name": "fish setup", "type": "script",
             "check": "test -f ~/.config/fish/config.fish",
             "run": "curl -fsSL https://example.com/fish | fish",
             "cwd": "/home/deploy", "env": {"TERM": "xterm"}},
            {"id": "deno", "name": "Deno", "type": "installer",
             "url": "https://deno.land/install.sh", "check": "~/.deno", "shell": "bash"},
            {"id": "appdir", "name": "App dir", "type": "directory",
             "path": "/srv/app", "mode": "755", "owner": "deploy", "group": "deploy",
             "depends_on": ["curl"]},
            {"id": "nginx-conf", "name": "nginx config", "type": "file",
             "path": "/etc/nginx/nginx.conf",
             "content": {"type": "template", "template": "server {{name}};",
                         "vars": {"name": "app", "count": 3,
                                  "upstream": {"host": "app.internal", "ports": [8080]}}},
             "mode": "644", "owner": "root", "group": "root",
             "triggers": ["nginx-svc"], "validate": "nginx -t"},
            // Every `FileContent` variant — each carries distinct fields, so the
            // oracle must round-trip all four or a drop in (e.g.) `remote.extract` or the
            // `remote.auth` credential would slip past it.
            {"id": "motd", "name": "motd", "type": "file", "path": "/etc/motd",
             "content": {"type": "inline", "content": "welcome\n"}},
            {"id": "bashrc", "name": "bashrc", "type": "file", "path": "/home/deploy/.bashrc",
             "content": {"type": "source", "path": "./files/bashrc"}},
            {"id": "zig", "name": "zig toolchain", "type": "file", "path": "/opt/zig",
             "content": {"type": "remote",
                         "url": Text::of_pieces([
                             Ref("ZAP_BASE_URL"),
                             Lit("/artifacts/zig-x86_64-linux-0.15.2.tar.xz"),
                         ]),
                         "blake3": "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262",
                         "extract": {"type": "tar.xz", "strip_components": 1},
                         "auth": {"scheme": "bearer", "token": Text::reference("ZAP_TOKEN")}}},
            // `user` — the richest optional surface and the most security-sensitive:
            // both `ssh_keys` forms and all three `sudo` forms across the three entries.
            {"id": "deploy-user", "name": "deploy user", "type": "user",
             "username": "deploy", "shell": "/bin/bash", "home_mode": "711",
             "ssh_keys": {"keys": ["ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA deploy@host"]},
             "sudo": {"mode": "password", "commands": ["/usr/bin/systemctl restart app"]},
             "groups": ["docker", "postgres"]},
            {"id": "ops-user", "name": "ops user", "type": "user",
             "username": "ops", "ssh_keys": {"copy_from": "root"}, "sudo": "nopasswd"},
            {"id": "guest-user", "name": "guest user", "type": "user",
             "username": "guest", "sudo": false},
            {"id": "current", "name": "current symlink", "type": "link",
             "path": "/srv/app/current", "target": "/srv/app/releases/1"},
            {"id": "nginx-svc", "name": "nginx", "type": "service",
             "service": "nginx", "enabled": true, "running": true,
             "restart_on": ["nginx-conf"], "reload_on": ["appdir"]},
            {"id": "app-db", "name": "app db", "type": "database",
             "engine": "postgresql", "database_name": "app", "username": "app",
             "auth": {"method": "md5", "hosts": ["10.0.0.0/8"]}},
            {"id": "swapfile", "name": "swap", "type": "swap",
             "size": "2G", "path": "/swapfile"},
            {"id": "ufw", "name": "firewall", "type": "firewall",
             "backend": "ufw", "default_incoming": "deny", "default_outgoing": "allow",
             "allow": ["OpenSSH", {"port": 443, "proto": "tcp"}]},
            {"id": "verify-ssh", "name": "verify", "type": "verify",
             "assertions": [
                {"type": "path_exists", "path": "/home/deploy/.ssh/authorized_keys",
                 "file_type": "file", "mode": "600", "owner": "deploy", "not_empty": true},
                {"type": "command", "run": "sudo whoami", "expect": "root"}
             ]},
            {"id": "ci", "name": "CI", "type": "pipeline",
             "env": {"CI": "true"}, "max_concurrency": 2,
             "steps": [
                {"id": "test", "name": "Test", "run": "npm test",
                 "cwd": "/srv/app", "env": {"NODE_ENV": "test"}, "depends_on": ["build"]},
                {"id": "build", "run": "npm run build"}
             ]},
            // `build` with the full `source` shape — the oracle must round-trip the
            // source `url` / `extract` / `strip_components` / `verify` block and the
            // never-hashed `auth` credential, or a drop would slip past it.
            {"id": "ghostty", "name": "ghostty from source", "type": "build",
             "source": {"type": "remote",
                        "url": "https://release.files.ghostty.org/1.2.3/ghostty-1.2.3.tar.gz",
                        "extract": {"type": "tar.gz", "strip_components": 1},
                        "auth": {"scheme": "bearer", "token": Text::reference("ZAP_TOKEN")},
                        "verify": {"scheme": "minisign",
                                   "public_key": "RWQlAjJC23149WL2sEpT/l0QKy7hMIFhYdQOFy0Z7z7PbneUgvlsnYcV",
                                   "signature_url": "https://release.files.ghostty.org/1.2.3/ghostty-1.2.3.tar.gz.minisig"},
                        "blake3": "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"},
             "run": "zig build -p $HOME/.local -Doptimize=ReleaseFast",
             "output": "/home/deploy/.local/bin/ghostty",
             "cwd": "/tmp/ghostty-src", "env": {"ZIG_GLOBAL_CACHE_DIR": "/tmp/zcache"},
             "depends_on": ["zig"]}
        ],
        "deploy": {"build": "npm run build", "artifacts": ["dist"], "path": "/srv/app",
                   "releases": 5, "service": "nginx",
                   "shared": [".env.production"],
                   "prepare": ["deno cache src/lib/server/server.ts"],
                   "health": {"domain": Text::reference("DEPLOY_DOMAIN"), "path": "/health",
                              "attempts": 15, "interval_ms": 2000}},
        "mask_vars": ["SMTP_PASSWORD_FOR_SES"],
        "unmask_vars": ["PUBLIC_KEY_DESCRIPTION"]
    })
}

#[test]
fn full_config_round_trips_without_dropping_fields() {
    let input = kitchen_sink();
    let config: ZapConfig =
        serde_json::from_value(input.clone()).expect("kitchen-sink config must parse");
    let output = serde_json::to_value(&config).expect("config must reserialize");
    assert_no_drops(&input, &output, "$");
}

#[test]
fn kitchen_sink_covers_every_resource_kind() {
    // A new kind must be added here too, or the round-trip guard silently stops
    // covering it.
    let input = kitchen_sink();
    let kinds: BTreeSet<&str> = input["resources"]
        .as_array()
        .unwrap()
        .iter()
        .map(|resource| resource["type"].as_str().unwrap())
        .collect();
    assert_eq!(
        kinds.len(),
        ResourceType::ALL.len(),
        "kitchen sink must exercise every kind: {kinds:?}"
    );
}

#[test]
fn unknown_resource_kind_hard_fails() {
    // A typo'd / unmodeled `type` is rejected,
    // rather than silently parsing into a catch-all.
    let bogus = json!({
        "target": {"local": true, "package_manager": "apt"},
        "resources": [{"id": "x", "name": "x", "type": "wormhole", "path": "/x"}]
    });
    let parsed: Result<ZapConfig, _> = serde_json::from_value(bogus);
    assert!(
        parsed.is_err(),
        "an unknown resource kind must hard-fail parse"
    );
}

#[test]
fn unknown_package_manager_hard_fails() {
    // Managers are a closed enum; an unknown value is rejected.
    let bogus = json!({
        "target": {"local": true, "package_manager": "nixpkgs"},
        "resources": []
    });
    let parsed: Result<ZapConfig, _> = serde_json::from_value(bogus);
    assert!(
        parsed.is_err(),
        "an unknown package manager must hard-fail parse"
    );
}

/// Whether `value` is how a config declares one text: a string, or what a [`Text`] that
/// holds a reference is declared as.
fn declares_a_text(value: &Value) -> bool {
    value.is_string() || serde_json::from_value::<Text>(value.clone()).is_ok()
}

/// Every text `value` declares, as `(path, pointer)`: the path a reader sees (a resource
/// by its id) and the JSON pointer that addresses it.
fn string_leaves(value: &Value, path: &str, pointer: &str, leaves: &mut Vec<(String, String)>) {
    if declares_a_text(value) {
        leaves.push((path.to_owned(), pointer.to_owned()));
        return;
    }
    match value {
        Value::Array(items) => {
            for (index, item) in items.iter().enumerate() {
                let named = match (path, item.get("id").and_then(Value::as_str)) {
                    ("resources", Some(id)) => format!("resources.{id}"),
                    _ => format!("{path}[{index}]"),
                };
                string_leaves(item, &named, &format!("{pointer}/{index}"), leaves);
            }
        }
        Value::Object(map) => {
            for (key, item) in map {
                let named = if path.is_empty() {
                    key.clone()
                } else {
                    format!("{path}.{key}")
                };
                string_leaves(item, &named, &format!("{pointer}/{key}"), leaves);
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
    }
}

/// The fields that take a reference, each with the role its text has to the
/// config's scanners. Every other string in a config is used as written.
const REFERENCE_TAKING: &[(&str, TextRole)] = &[
    ("target.host", TextRole::TargetIdentity),
    ("target.user", TextRole::TargetIdentity),
    ("target.bootstrap_user", TextRole::TargetIdentity),
    // A `package` check in its path form; a command check (`jq`'s) takes none.
    ("resources.curl.check", TextRole::Resource),
    ("resources.pgdg.key_url", TextRole::Resource),
    ("resources.fish-setup.check", TextRole::Resource),
    ("resources.fish-setup.run", TextRole::Resource),
    ("resources.fish-setup.env.TERM", TextRole::Resource),
    ("resources.deno.url", TextRole::Resource),
    ("resources.deno.check", TextRole::Resource),
    ("resources.deno.shell", TextRole::Resource),
    ("resources.appdir.path", TextRole::Resource),
    ("resources.nginx-conf.path", TextRole::Resource),
    ("resources.nginx-conf.content.vars.name", TextRole::Resource),
    ("resources.nginx-conf.validate", TextRole::Resource),
    ("resources.motd.path", TextRole::Resource),
    ("resources.bashrc.path", TextRole::Resource),
    ("resources.bashrc.content.path", TextRole::Resource),
    ("resources.zig.path", TextRole::Resource),
    ("resources.zig.content.url", TextRole::Resource),
    (
        "resources.zig.content.auth.token",
        TextRole::FetchCredential,
    ),
    ("resources.current.path", TextRole::Resource),
    ("resources.current.target", TextRole::Resource),
    ("resources.app-db.database_name", TextRole::Resource),
    ("resources.app-db.username", TextRole::Resource),
    ("resources.app-db.auth.hosts[0]", TextRole::Resource),
    ("resources.swapfile.size", TextRole::Resource),
    ("resources.ci.steps[0].run", TextRole::Resource),
    ("resources.ci.steps[1].run", TextRole::Resource),
    ("resources.ghostty.source.url", TextRole::Resource),
    (
        "resources.ghostty.source.auth.token",
        TextRole::FetchCredential,
    ),
    (
        "resources.ghostty.source.verify.signature_url",
        TextRole::Resource,
    ),
    ("resources.ghostty.run", TextRole::Resource),
    ("resources.ghostty.output", TextRole::Resource),
    (
        "resources.ghostty.env.ZIG_GLOBAL_CACHE_DIR",
        TextRole::Resource,
    ),
    ("deploy.health.domain", TextRole::Deploy),
];

/// Which fields take a reference is the schema's to say, and this is the list.
///
/// A reference is put at each string of the kitchen sink in turn. Where the list says a
/// field takes one, the config parses, its walk visits the reference once with the role
/// the list gives, and the field is a `Text` by its type — read off the config's `Debug`
/// form, so the walk can't visit a `String` or skip a `Text`. Everywhere else the parse
/// fails with exactly one finding, naming exactly that field.
#[test]
fn a_reference_is_accepted_exactly_where_a_field_takes_one() {
    const PROBE: &str = "ZAP_PARTITION_PROBE";
    let base = kitchen_sink();
    let mut leaves = Vec::new();
    string_leaves(&base, "", "", &mut leaves);
    assert!(leaves.len() > REFERENCE_TAKING.len());

    let mut visited = BTreeSet::new();
    let mut typed = BTreeSet::new();
    for (path, pointer) in &leaves {
        let mut probed = base.clone();
        let leaf = probed.pointer_mut(pointer).unwrap();
        let declared: Text = serde_json::from_value(leaf.clone()).unwrap();
        let injected = Text::of_pieces(declared.pieces().chain([Ref(PROBE)]));
        *leaf = json!(injected);
        let config = match ZapConfig::from_wire_value(&probed) {
            Ok(config) => config,
            Err(WireError::Misplaced(findings)) => {
                let named = format!("{}takes no reference: ", finding_subject(&base, path));
                assert_eq!(findings.len(), 1, "{path}: {findings:#?}");
                assert!(
                    findings[0].starts_with(&named),
                    "{path}: {}\n  does not start: {named}",
                    findings[0]
                );
                continue;
            }
            Err(other) => panic!("{path}: a reference there is not named: {other}"),
        };
        let mut roles = Vec::new();
        config.for_each_text(|role, text| {
            if text.ref_names().any(|name| name == PROBE) {
                roles.push(role);
            }
        });
        assert_eq!(roles.len(), 1, "{path} is accepted and visited {roles:?}");
        visited.insert((path.as_str(), format!("{:?}", roles[0])));
        if format!("{config:?}").contains(&format!("{injected:?}")) {
            typed.insert(path.as_str());
        }
    }

    let expected: BTreeSet<(&str, String)> = REFERENCE_TAKING
        .iter()
        .map(|(path, role)| (*path, format!("{role:?}")))
        .collect();
    assert_eq!(visited, expected);
    assert_eq!(
        typed,
        REFERENCE_TAKING
            .iter()
            .map(|(path, _)| *path)
            .collect::<BTreeSet<_>>(),
        "the fields that are a `Text` by type"
    );
}

/// How a finding names the field at `path` (spelled as [`string_leaves`] spells one):
/// the resource by its id — by its position when the field is the id itself — then the
/// field, or the whole path outside a resource.
fn finding_subject(config: &Value, path: &str) -> String {
    let Some((id, field)) = path
        .strip_prefix("resources.")
        .and_then(|rest| rest.split_once('.'))
    else {
        return format!("`{path}` ");
    };
    if field == "id" {
        let position = config["resources"]
            .as_array()
            .unwrap()
            .iter()
            .position(|resource| resource["id"] == id)
            .unwrap();
        return format!("resource {}: `id` ", position + 1);
    }
    format!("resource `{id}`: `{field}` ")
}

/// No reference reaches a command through a field that takes none.
///
/// A step's text is resolved whole when it runs, so a marker in a field written into
/// one would be substituted there whatever the field's type says. A marker can't get
/// there: at every string of the config — the fields a step is built from among them —
/// a string holding one is refused as the config is read, naming the string.
#[test]
fn a_marker_cannot_be_declared_as_text() {
    const WORD: &str = "zapstepprobe";
    let mut base = kitchen_sink();
    // An `apt_repo` whose key and list paths are built from its id.
    base["resources"].as_array_mut().unwrap().push(json!({
        "id": "extra", "type": "apt_repo", "key_url": "https://example.com/extra.asc",
        "source": "deb https://apt.example.com/extra stable main",
    }));
    let taking: BTreeSet<&str> = REFERENCE_TAKING
        .iter()
        .map(|(path, _)| *path)
        .chain(["resources.extra.key_url"])
        .collect();
    let mut leaves = Vec::new();
    string_leaves(&base, "", "", &mut leaves);

    let mut reached = BTreeSet::new();
    for (path, pointer) in &leaves {
        let literal = |config: &Value| -> String {
            let declared: Text = serde_json::from_value(config.pointer(pointer).unwrap().clone())
                .unwrap_or_else(|error| panic!("{path}: {error}"));
            declared.literals().collect()
        };

        let mut marked = base.clone();
        *marked.pointer_mut(pointer).unwrap() =
            Value::String(format!("{}{}", literal(&base), marker("ZAP_STEP_PROBE")));
        match ZapConfig::from_wire_value(&marked) {
            Err(WireError::Delimiter(at)) => {
                let wire_path = pointer_as_path(pointer);
                assert_eq!(at, wire_path, "{path}");
            }
            other => panic!("{path}: a marker in a string was not refused: {other:?}"),
        }

        if taking.contains(path.as_str()) {
            continue;
        }
        // Which of the fields that take no reference a step is built from: a plain word
        // there shows up in a step's text.
        for (package_manager, service_manager) in MANAGER_STACKS {
            let mut probed = base.clone();
            probed["target"]["package_manager"] = json!(package_manager);
            probed["target"]["service_manager"] = json!(service_manager);
            *probed.pointer_mut(pointer).unwrap() =
                Value::String(format!("{}{WORD}", literal(&base)));
            let Ok(config) = ZapConfig::from_wire_value(&probed) else {
                continue;
            };
            let in_a_step = lowered(&config)
                .iter()
                .any(|(_, texts)| texts.iter().any(|text| text.contains(WORD)));
            if in_a_step {
                reached.insert(path.as_str());
            }
        }
    }
    // The fields a step is built from that take no reference.
    assert_eq!(
        reached.into_iter().collect::<Vec<_>>(),
        [
            "resources.curl.from.apt",
            "resources.deploy-user.groups[0]",
            "resources.deploy-user.groups[1]",
            "resources.deploy-user.shell",
            "resources.deploy-user.ssh_keys.keys[0]",
            "resources.deploy-user.sudo.commands[0]",
            "resources.deploy-user.username",
            "resources.extra.id",
            "resources.extra.source",
            "resources.guest-user.username",
            "resources.jq.from.apk",
            "resources.jq.from.apt",
            "resources.nginx-svc.service",
            "resources.ops-user.ssh_keys.copy_from",
            "resources.ops-user.username",
            "resources.pgdg.key_path",
            "resources.pgdg.list_file",
            "resources.pgdg.source",
            "resources.swapfile.path",
            "resources.ufw.allow[0]",
        ]
    );
}

/// A JSON pointer as the path a wire error names: `/resources/3/env/TERM` is
/// `resources[3].env.TERM`.
fn pointer_as_path(pointer: &str) -> String {
    let mut path = String::new();
    for token in pointer.split('/').skip(1) {
        if token.bytes().all(|byte| byte.is_ascii_digit()) {
            path.extend(["[", token, "]"]);
        } else {
            if !path.is_empty() {
                path.push('.');
            }
            path.push_str(token);
        }
    }
    path
}

/// The JSON pointer of the field `path` names in `config`, where `path` is spelled the
/// way [`REFERENCE_TAKING`] spells one.
fn pointer_of(config: &Value, path: &str) -> String {
    let resource = path.strip_prefix("resources.").map(|rest| {
        let (id, fields) = rest.split_once('.').unwrap();
        let index = config["resources"]
            .as_array()
            .unwrap()
            .iter()
            .position(|resource| resource["id"] == id)
            .unwrap_or_else(|| panic!("no resource `{id}`"));
        (index, fields)
    });
    let (mut tokens, fields) = resource.map_or_else(
        || (Vec::new(), path),
        |(index, fields)| (vec!["resources".to_owned(), index.to_string()], fields),
    );
    for field in fields.split('.') {
        match field.split_once('[') {
            Some((key, index)) => {
                tokens.extend([key.to_owned(), index.trim_end_matches(']').to_owned()]);
            }
            None => tokens.push(field.to_owned()),
        }
    }
    format!("/{}", tokens.join("/"))
}

/// The paths of the resource fields that take a reference, in a fixed order.
fn resource_text_paths() -> Vec<&'static str> {
    REFERENCE_TAKING
        .iter()
        .map(|(path, _)| *path)
        .filter(|path| path.starts_with("resources."))
        .collect()
}

/// The name the parity tests reference from the field at `index` of
/// [`resource_text_paths`].
fn parity_name(index: usize) -> String {
    format!("ZAP_PARITY_{index}")
}

/// The kitchen sink under the given managers, each resource field that takes a reference
/// rewritten to `rewrite(index, path, literal)` — `literal` being the text the field
/// declares outside any reference.
fn with_resource_texts(
    (package_manager, service_manager): (&str, &str),
    rewrite: impl Fn(usize, &str, &str) -> Value,
) -> ZapConfig {
    let mut config = kitchen_sink();
    config["target"]["package_manager"] = json!(package_manager);
    config["target"]["service_manager"] = json!(service_manager);
    for (index, path) in resource_text_paths().into_iter().enumerate() {
        let pointer = pointer_of(&config, path);
        let field = config
            .pointer_mut(&pointer)
            .unwrap_or_else(|| panic!("{path} is not in the kitchen sink"));
        let declared: Text = serde_json::from_value(field.clone())
            .unwrap_or_else(|error| panic!("{path} is not a text: {error}"));
        let literal: String = declared
            .pieces()
            .filter_map(|piece| match piece {
                Lit(text) => Some(text),
                Ref(_) => None,
            })
            .collect();
        *field = rewrite(index, path, &literal);
    }
    serde_json::from_value(config).expect("the rewritten kitchen sink parses")
}

/// `literal` followed by a reference to `name`, as a config declares it.
fn referencing(literal: &str, name: &str) -> Value {
    let literal = (!literal.is_empty()).then_some(Lit(literal));
    json!(Text::of_pieces(literal.into_iter().chain([Ref(name)])))
}

/// The text every step of `config`'s plan executes, per resource, when nothing it
/// declares is on the machine yet: a command's text, and a put's command and content.
fn lowered(config: &ZapConfig) -> Vec<(String, Vec<String>)> {
    let detected: BTreeMap<_, _> = config
        .resources
        .iter()
        .map(|resource| (resource.id.clone(), Detection::Absent))
        .collect();
    diff(DiffInputs {
        resources: &config.resources,
        detected: &detected,
        target: &config.target,
        machine: &local_machine(),
        lock: None,
        pending: &BTreeMap::new(),
        var: &zap_types::last_run::ReportVar::unset,
    })
    .plan
    .changes
    .iter()
    .map(|change| {
        let texts = change
            .steps
            .iter()
            .filter_map(PlanStep::execution)
            .flat_map(|execution| match execution {
                StepExecution::Command(text) => vec![text],
                StepExecution::Put { command, content } => vec![command, content.to_owned()],
            })
            .collect();
        (change.resource_id.0.clone(), texts)
    })
    .collect()
}

/// `lowered` with every text mapped through `map`.
fn map_lowered(
    lowered: Vec<(String, Vec<String>)>,
    map: impl Fn(String) -> String,
) -> Vec<(String, Vec<String>)> {
    lowered
        .into_iter()
        .map(|(id, texts)| (id, texts.into_iter().map(&map).collect()))
        .collect()
}

const MANAGER_STACKS: [(&str, &str); 2] = [("apt", "systemd"), ("apk", "openrc")];

/// A reference is opaque to planning.
///
/// Every resource field that takes a reference is given one, after the text it already
/// declares. The text the plan's steps execute, with each reference's marker swapped for
/// a plain word, is the text of the plan whose fields declare that word outright: no
/// step builder reads, escapes, splits or drops a marker — it rides through as a word
/// does.
#[test]
fn a_reference_rides_through_planning_as_a_plain_word_does() {
    let word = |index: usize| format!("zapparity{index}x");
    for managers in MANAGER_STACKS {
        let referenced = lowered(&with_resource_texts(managers, |index, _, literal| {
            referencing(literal, &parity_name(index))
        }));
        let plain = lowered(&with_resource_texts(managers, |index, _, literal| {
            json!(format!("{literal}{}", word(index)))
        }));
        let count = resource_text_paths().len();
        let swapped = map_lowered(referenced.clone(), |text| {
            (0..count).fold(text, |text, index| {
                text.replace(&marker(&parity_name(index)), &word(index))
            })
        });
        assert_eq!(swapped, plain, "{managers:?}");

        // The fields whose reference a step carries: the comparison above is over these.
        let carried: Vec<&str> = resource_text_paths()
            .into_iter()
            .enumerate()
            .filter(|(index, _)| {
                let marker = marker(&parity_name(*index));
                referenced
                    .iter()
                    .any(|(_, texts)| texts.iter().any(|text| text.contains(&marker)))
            })
            .map(|(_, path)| path)
            .collect();
        assert_eq!(carried, STEP_CARRIED, "{managers:?}");
    }
}

/// The resource fields whose text a planned step carries, of those that take a
/// reference. The rest reach the machine another way: a path a file is put at, content,
/// a fetch, a check detection runs.
const STEP_CARRIED: &[&str] = &[
    "resources.fish-setup.run",
    "resources.deno.url",
    "resources.deno.shell",
    "resources.app-db.database_name",
    "resources.app-db.username",
    "resources.app-db.auth.hosts[0]",
    "resources.swapfile.size",
    "resources.ci.steps[0].run",
    "resources.ci.steps[1].run",
    "resources.ghostty.run",
];

/// Resolving a plan is planning the resolved config.
///
/// The text the steps of a reference-bearing plan execute, resolved the way the executor
/// resolves a step — each reference replaced by its value, found by the one scanner — is
/// the text of the plan whose fields declare those values outright. The values hold
/// what a shell would act on unquoted, and no `'`, `"` or NUL (which resolution
/// refuses). A `database`'s names take a plain word: they are matched as a pattern, where
/// a resolved value is used as it is and a declared one is escaped.
#[test]
fn resolving_a_plans_steps_is_planning_the_resolved_config() {
    let value = |index: usize, path: &str| {
        if path.starts_with("resources.app-db.") {
            format!("v{index}")
        } else {
            format!("v{index} $HOME;\\ `id` * | &\n# {{}}")
        }
    };
    let paths = resource_text_paths();
    let value_of = |name: &str| {
        let index = paths
            .iter()
            .enumerate()
            .position(|(index, _)| parity_name(index) == name)
            .unwrap_or_else(|| panic!("an unexpected reference to `{name}`"));
        value(index, paths[index])
    };
    for managers in MANAGER_STACKS {
        let referenced = lowered(&with_resource_texts(managers, |index, _, literal| {
            referencing(literal, &parity_name(index))
        }));
        let resolved = map_lowered(referenced, |text| map_refs(&text, value_of));
        let planned = lowered(&with_resource_texts(managers, |index, path, literal| {
            json!(format!("{literal}{}", value(index, path)))
        }));
        assert_eq!(resolved, planned, "{managers:?}");
    }
}

/// The pointer of every node under `value` — objects, arrays, and leaves of any type.
fn every_pointer(value: &Value, pointer: &str, out: &mut Vec<String>) {
    out.push(pointer.to_owned());
    match value {
        Value::Array(items) => {
            for (index, item) in items.iter().enumerate() {
                every_pointer(item, &format!("{pointer}/{index}"), out);
            }
        }
        Value::Object(map) => {
            for (key, child) in map {
                let key = key.replace('~', "~0").replace('/', "~1");
                every_pointer(child, &format!("{pointer}/{key}"), out);
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
    }
}

/// A reference at any node of a config — where a map, a list, a number, or a flag goes
/// as much as where a string does — parses only where the node is a [`Text`]: the
/// parsed config holds it as that text's reference, and writes it back where it was.
#[test]
fn a_reference_at_any_node_parses_only_as_a_text() {
    let sink = kitchen_sink();
    let mut pointers = Vec::new();
    every_pointer(&sink, "", &mut pointers);
    let mut accepted = 0;
    for pointer in &pointers {
        for node in [
            json!(Text::reference("ZAP_T_ANYWHERE")),
            referencing("/a", "ZAP_T_ANYWHERE"),
        ] {
            let mut config = sink.clone();
            *config.pointer_mut(pointer).unwrap() = node.clone();
            let Ok(parsed) = ZapConfig::from_wire_value(&config) else {
                continue;
            };
            accepted += 1;
            let mut visited = false;
            parsed.for_each_text(|_, text| {
                visited |= text.ref_names().any(|name| name == "ZAP_T_ANYWHERE");
            });
            assert!(visited, "{pointer}: accepted {node}, and no text holds it");
            assert_eq!(
                serde_json::to_value(&parsed).unwrap().pointer(pointer),
                Some(&node),
                "{pointer}"
            );
        }
    }
    // Each field that takes a reference took both forms, a path-only `check` aside.
    assert!(accepted >= REFERENCE_TAKING.len(), "{accepted}");
}
