//! The resource schema — the contract shared by config eval, the lock, and
//! hashing.
//!
//! `Resource` is a **payload-carrying, internally-tagged enum**: the common
//! identity (`id` / `name` / `depends_on`) is flat, and `kind` is a
//! `#[serde(tag = "type")]` enum whose variants hold the typed per-kind fields.
//! One enum, not a tag beside an untyped `#[serde(flatten)]` map: `detect` / `steps` /
//! `effects` / `execute` all match the *same* type, so a new kind is a compile error
//! in every stage at once, and there is no fallible "ask for the matching kind"
//! accessor — the variant is already the right type.
//!
//! **Full fidelity:** every field each kind carries in `src/lib/schema.ts` is modeled,
//! so nothing the config-eval sidecar emits is silently dropped on round-trip. Unknown
//! *kinds* hard-fail; unknown *fields* hard-fail too, via
//! `#[serde(deny_unknown_fields)]` on every plain struct — the leaf `*Resource`
//! payloads (which work *despite* being newtype variants of the flattened,
//! internally-tagged `ResourceKind`: serde routes the identity fields and the `type`
//! tag away before the leaf sees them) plus `Target` / `ZapConfig` / `DatabaseAuth` /
//! `PipelineStep` / the `Deploy*` blocks. So a misspelled field (`ownr`, `blake33`) or
//! one placed at the wrong level fails at config-eval with a precise `unknown field`
//! error instead of being silently dropped. The enums reject one too: an
//! internally-tagged enum with a struct variant carries `deny_unknown_fields` itself
//! (`FileContent`, `RemoteAuth`), a variant with **optional** fields wraps a
//! `deny`-bearing struct (`BuildSource`, `VerifyAssertion`, …), and an enum with no
//! tag — or one with a variant that has no fields, on which the derive can refuse
//! nothing — reads its object form through a private `deny`-bearing wire struct
//! (`SshKeys`, `UserSudo`, `FirewallAllowRule`, `ExtractMode`). A value is also read
//! only in the shape its field has: an array where an object goes, or an object where
//! a name goes, fails the parse ([`ZapConfig::from_wire`]). A field that takes a
//! reference is a [`Text`](crate::text::Text), held inert — its *resolution* is
//! apply-time IO in `zap_core` — and [`ZapConfig::for_each_text`] is the walk over
//! them.
//!
//! The schema is split into submodules, re-exported flat here so every
//! `schema::X` path resolves regardless of which submodule defines `X`:
//! `target` (the `Target` wire-bridge), `template_kind` (what a `template`
//! variable may be declared to hold), `helpers` (the probe/mutation-shared
//! command and path helpers), and `resources` (the per-kind payloads + closed-set
//! enums). The spine — `ResourceId`, `Resource`, `ResourceKind`, `ZapConfig` — stays
//! here.

mod helpers;
mod resolved;
mod resources;
mod target;
mod template_kind;
mod texts;
mod wire;

pub use helpers::*;
pub use resolved::{MissingResolvedField, ResolvedField, ResolvedFields};
pub use resources::*;
pub use target::*;
pub use template_kind::TemplateKind;
pub use texts::TextRole;
pub use wire::WireError;
pub(crate) use wire::path_matches;

use serde::{Deserialize, Serialize};

use crate::scalar::EnvVarName;

/// A resource's stable identifier within a config (the operator-written `id`).
/// Identity across the plan, lock, cache, and events all key on this.
///
/// A config's ids are names ([`is_name`](Self::is_name)), which the structural gate
/// holds every one to ([`crate::validate::unusable_resource_ids`]) before anything reads
/// the config. The rule is the gate's and not the parse's because an id is also read
/// back from what zap wrote — a lock's keys, a last-run report's, an event on its way
/// through the masker — where a value that no longer parses would lose the whole record.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ResourceId(pub String);

impl ResourceId {
    /// Whether the id is a name: a letter, a digit or `_`, then letters, digits and
    /// `_ . + : @ -`.
    ///
    /// An id is more than a label: an `apt_repo`'s is the default name of its key and
    /// list files ([`apt_keyring_path`], [`apt_sources_list_path`]), and the key's path
    /// sits inside the double quotes of a root shell's `echo`
    /// ([`apt_source_command`]), which detection runs. So none of `"` `$` a
    /// backtick `\` (read inside those quotes), whitespace or a control character (a
    /// second word, a second line), `/` (another directory), nor a leading `-` or `.`
    /// (an option, a hidden file, `..`) is part of one; every other character a shell
    /// acts on is left out with them, and an id is ASCII, so it reads the same wherever
    /// it is printed.
    #[must_use]
    pub fn is_name(&self) -> bool {
        let mut bytes = self.0.bytes();
        bytes
            .next()
            .is_some_and(|first| first.is_ascii_alphanumeric() || first == b'_')
            && bytes.all(|b| b.is_ascii_alphanumeric() || b"_.+:@-".contains(&b))
    }
}

/// A declared resource: its identity, optional display name, dependency edges, and
/// the typed per-kind payload.
///
/// The per-kind fields live in [`kind`](Self::kind), an internally-tagged
/// (`#[serde(tag = "type")]`) enum flattened into the wire shape, so a resource
/// serializes flat (`{id, name?, depends_on?, type, ...kind fields}`) exactly as
/// the config-eval sidecar emits it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Resource {
    /// Stable identity within the config.
    pub id: ResourceId,
    /// A label for whoever reads the config, optional, so synthetic resources omit it.
    /// Detection and planning never read it, but a [`Change`](crate::plan::Change)'s
    /// `desired` carries it, so it is part of the `plan_hash`, and a plan prints it under
    /// the change's header for that; everything else (apply's progress, events) names a
    /// resource by `id`. The resource and last-run hashes leave it out.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Resource ids this depends on (the resource-graph edges).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub depends_on: Vec<ResourceId>,
    /// The typed per-kind payload (carries the `type` discriminant).
    #[serde(flatten)]
    pub kind: ResourceKind,
}

impl Resource {
    /// The lightweight `Copy` kind tag for this resource.
    #[must_use]
    pub const fn kind(&self) -> ResourceType {
        self.kind.kind()
    }
}

/// The typed per-kind payload of a [`Resource`], internally tagged on `type`.
///
/// Exhaustive matching here is the compile-time forcing function: adding a variant
/// breaks `detect` / `resource_steps` / `compute_config_hash` until each handles it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ResourceKind {
    /// System package via a package manager.
    Package(PackageResource),
    /// Apt repository (GPG key + sources list).
    AptRepo(AptRepoResource),
    /// Idempotent command (check / run).
    Script(ScriptResource),
    /// Curl-piped installer script.
    Installer(InstallerResource),
    /// Unix user (shell, home mode, SSH keys, sudoers).
    User(UserResource),
    /// Directory with managed permissions.
    Directory(DirectoryResource),
    /// File with managed content.
    File(FileResource),
    /// Symbolic link.
    Link(LinkResource),
    /// Service lifecycle (enable/run).
    Service(ServiceResource),
    /// `PostgreSQL` database + role.
    Database(DatabaseResource),
    /// Swap file.
    Swap(SwapResource),
    /// Firewall (ufw or nftables) rules.
    Firewall(FirewallResource),
    /// Assertions checked at detection and again at its place in dependency order on a
    /// wetrun; one still failing there fails the run.
    Verify(VerifyResource),
    /// Imperative multi-step pipeline.
    Pipeline(PipelineResource),
    /// Build a verified source and install it to a path (provenance-pinned).
    Build(BuildResource),
}

impl ResourceKind {
    /// The lightweight `Copy` kind tag.
    #[must_use]
    pub const fn kind(&self) -> ResourceType {
        match self {
            Self::Package(_) => ResourceType::Package,
            Self::AptRepo(_) => ResourceType::AptRepo,
            Self::Script(_) => ResourceType::Script,
            Self::Installer(_) => ResourceType::Installer,
            Self::User(_) => ResourceType::User,
            Self::Directory(_) => ResourceType::Directory,
            Self::File(_) => ResourceType::File,
            Self::Link(_) => ResourceType::Link,
            Self::Service(_) => ResourceType::Service,
            Self::Database(_) => ResourceType::Database,
            Self::Swap(_) => ResourceType::Swap,
            Self::Firewall(_) => ResourceType::Firewall,
            Self::Verify(_) => ResourceType::Verify,
            Self::Pipeline(_) => ResourceType::Pipeline,
            Self::Build(_) => ResourceType::Build,
        }
    }

    /// The runtime-resolved fields of this kind — each [`ResolvedField`] with its
    /// value, references / `$HOME` / `~` already expanded by the injected `resolve`.
    /// Mostly paths, plus `database`'s identifiers (an operator-env `zap.env('USER')`
    /// username is the "role matching the OS user" config).
    ///
    /// **The one shared seam for the `resolved-fields ⟺ expand_runtime_path`
    /// invariant.** All three path-resolution consumers read it instead of
    /// re-resolving independently: `compute_config_hash` (so a lock pin can't survive
    /// an env-resolution change), the detectors in
    /// `zap_core::resource::detect` (which probe the resolved path), and the
    /// executors in `zap_core::resource::execute` (which write/mkdir/symlink at it).
    /// One source means there is nothing to keep in sync — the residual that the
    /// old field-*name* list (`resolved_path_fields`) couldn't close, since each
    /// detector still resolved on its own.
    ///
    /// `package` resolves nothing here — its `check` is resolved only as a path
    /// ([`DeclaredPackageCheck::Path`]) by `zap_core`'s `Observed::for_resource` and the
    /// `package` hash arm, so it can't be a flat unconditional field. Kinds with no
    /// operator-env field (`swap`'s `path` and `apt_repo`'s paths are used as declared
    /// and take no reference; `firewall` / `service` have none;
    /// `script` / `verify` / `pipeline` resolve their commands elsewhere) return an
    /// empty map.
    ///
    /// Every variant is listed (no `_` arm) on purpose — adding a kind is a compile
    /// error here until its author declares which path fields its detector/executor
    /// resolve.
    #[must_use]
    pub fn resolved_fields(&self, resolve: impl Fn(&str) -> String) -> ResolvedFields {
        match self {
            Self::Directory(dir) => [(ResolvedField::Path, resolve(&dir.path))].into(),
            Self::File(file) => [(ResolvedField::Path, resolve(&file.path))].into(),
            Self::Link(link) => [
                (ResolvedField::Path, resolve(&link.path)),
                (ResolvedField::Target, resolve(&link.target)),
            ]
            .into(),
            Self::Installer(installer) => {
                [(ResolvedField::Check, resolve(&installer.check))].into()
            }
            Self::Build(build) => [(ResolvedField::Output, resolve(&build.output))].into(),
            // Not paths, but the same invariant: the hash, the detector's probes, and
            // the mutations the probes guard must all see one resolved identifier, or
            // a `zap.env('USER')` config detects against the unresolved reference and never
            // converges.
            Self::Database(database) => [
                (ResolvedField::Username, resolve(&database.username)),
                (ResolvedField::DatabaseName, resolve(&database.database_name)),
            ]
            .into(),
            Self::Package(_)
            | Self::AptRepo(_)
            | Self::Script(_)
            | Self::Service(_)
            | Self::Swap(_)
            | Self::Firewall(_)
            | Self::Verify(_)
            | Self::Pipeline(_)
            // `user`'s paths are all derived from `username` (`/home/<user>`,
            // `/etc/sudoers.d/<user>`) — absolute, no operator-env field to resolve.
            | Self::User(_) => ResolvedFields::default(),
        }
    }
}

/// The whole evaluated config: the target descriptor plus declared resources.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ZapConfig {
    /// The machine this config targets.
    pub target: Target,
    /// The declared resources.
    pub resources: Vec<Resource>,
    /// The `deploy()` release-management block (consumed by `zap deploy`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deploy: Option<DeploySpec>,
    /// Env-var names the operator declares secret (ones neither their name nor their
    /// value's form gives away). Captured so the builder's `mask(...)` survives into the
    /// schema; [`SecretRule`](crate::secrecy::SecretRule) consumes it. Typed
    /// as [`EnvVarName`] so a malformed name fails at config-eval rather than sitting
    /// inert (it could never match a real env var).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mask_vars: Option<Vec<EnvVarName>>,
    /// Env-var names the operator declares not secret (ones that only read as secrets,
    /// by name or by value). Captured for the same reason as `mask_vars`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unmask_vars: Option<Vec<EnvVarName>>,
}

#[cfg(test)]
mod tests {
    use super::{FileContent, RemoteAuth, TemplateVar};
    use crate::text::Text;
    use crate::var_ref::Segment::{Ref, Text as Lit};
    use crate::var_ref::marker;

    /// An env-only resolver (the `resolve_env_vars` category): substitutes a reference
    /// but leaves `~` / `$HOME` literal — what every `TemplateContent::render` call site passes.
    fn env_only(input: &str) -> String {
        input.replace(&marker("DIR"), "/srv/app")
    }

    #[test]
    fn a_template_resolves_vars_but_leaves_home_literal() {
        // A `~` / `$HOME` in a template value is content text, not a path: it must
        // survive rendering verbatim so the hashed `rendered_content` stays
        // machine-independent and matches the bytes written at apply time.
        let content = super::TemplateContent {
            template: "root={{base}}\nhome={{cfg}}\n".to_owned(),
            vars: [
                (
                    "base".to_owned(),
                    TemplateVar::Text(Text::of_pieces([Ref("DIR"), Lit("/data")])),
                ),
                (
                    "cfg".to_owned(),
                    TemplateVar::Text(Text::of_pieces([Lit("~/.config/"), Ref("DIR")])),
                ),
            ]
            .into_iter()
            .collect(),
            kinds: std::collections::BTreeMap::new(),
        };
        let rendered = content.render(env_only);
        // The reference resolved; `~` / `$HOME` left literal.
        assert_eq!(rendered, "root=/srv/app/data\nhome=~/.config//srv/app\n");
    }

    /// A template is read once: each placeholder is replaced by its variable's value,
    /// and a value is never read for placeholders — so one that holds another variable's
    /// placeholder is written as it is, whatever the variables' order.
    #[test]
    fn a_template_is_substituted_in_one_pass() {
        let render = |template: &str, vars: serde_json::Value| {
            serde_json::from_value::<super::TemplateContent>(serde_json::json!({
                "template": template, "vars": vars,
            }))
            .unwrap()
            .render(env_only)
        };
        for (template, vars, rendered) in [
            (
                "{{a}}-{{b}}-{{a}}",
                serde_json::json!({"a": "1", "b": "2"}),
                "1-2-1",
            ),
            (
                "{{a}} {{z}}",
                serde_json::json!({"a": "{{z}}", "z": "{{a}}"}),
                "{{z}} {{a}}",
            ),
            (
                "{{a}}",
                serde_json::json!({"a": "{{a}}{{a}}"}),
                "{{a}}{{a}}",
            ),
            (
                "{{a}}",
                serde_json::json!({"a": {"k": "{{b}}"}, "b": "x"}),
                r#"{"k":"{{b}}"}"#,
            ),
            (
                "{{{a}}} {{a}}} {{ a }} {{b}} }} {{",
                serde_json::json!({"a": "1"}),
                "{1} 1} {{ a }} {{b}} }} {{",
            ),
            (
                "{{a.b}}|{{}}",
                serde_json::json!({"a.b": "dotted", "": "empty"}),
                "dotted|empty",
            ),
            ("", serde_json::json!({}), ""),
        ] {
            assert_eq!(
                render(template, vars.clone()),
                rendered,
                "{template} {vars}"
            );
        }
    }

    /// A string variable is substituted as text, its references resolved; any other
    /// value as its compact JSON text. Either kind is its own JSON on the wire.
    #[test]
    fn a_template_variable_renders_as_text_or_as_json_text() {
        let json = serde_json::json!({
            "type": "template", "template": "{{name}}:{{port}} {{upstream}}",
            "vars": {"name": Text::of_pieces([Ref("DIR"), Lit("/data")]), "port": 8080,
                     "upstream": {"root": "/srv/$$DIR$$", "on": true}},
        });
        let content: FileContent = serde_json::from_value(json.clone()).unwrap();
        let FileContent::Template(template) = &content else {
            panic!("a template");
        };
        assert!(matches!(template.vars["name"], TemplateVar::Text(_)));
        assert!(matches!(template.vars["port"], TemplateVar::Json(_)));
        assert_eq!(
            template.vars["upstream"].render(env_only),
            r#"{"on":true,"root":"/srv/$$DIR$$"}"#
        );
        assert_eq!(
            template.render(env_only),
            r#"/srv/app/data:8080 {"on":true,"root":"/srv/$$DIR$$"}"#
        );
        assert_eq!(serde_json::to_value(&content).unwrap(), json);

        let scalars: super::TemplateContent = serde_json::from_value(serde_json::json!({
            "template": "{{nil}}|{{off}}|{{ratio}}|{{list}}",
            "vars": {"nil": null, "off": false, "ratio": 1.5, "list": [1, "two", null]},
        }))
        .unwrap();
        assert_eq!(scalars.render(env_only), r#"null|false|1.5|[1,"two",null]"#);
    }

    /// A non-string variable takes no reference at any depth: a reference nested in one
    /// — or the keys only a reference has, or a raw delimiter — is rejected, and a
    /// malformed reference where a string variable goes is too.
    #[test]
    fn a_reference_inside_a_non_string_template_variable_is_rejected() {
        let parse = |var: serde_json::Value| {
            serde_json::from_value::<FileContent>(serde_json::json!({
                "type": "template", "template": "{{v}}", "vars": {"v": var},
            }))
        };
        for nested in [
            serde_json::json!({"root": Text::reference("DIR")}),
            serde_json::json!([1, Text::reference("DIR")]),
            serde_json::json!({"a": [{"b": Text::of_pieces([Lit("x"), Ref("DIR")])}]}),
            serde_json::json!({"a": {"$env": 5}}),
            serde_json::json!({"a": {"$text": "x", "other": 1}}),
            serde_json::json!({"a": marker("DIR")}),
            serde_json::json!({marker("DIR"): 1}),
        ] {
            let error = parse(nested.clone()).unwrap_err().to_string();
            assert!(
                error.contains("a reference inside a non-string var is not supported"),
                "{nested}: {error}"
            );
        }
        for malformed in [
            serde_json::json!({"$env": 5}),
            serde_json::json!({"$env": "DIR", "other": 1}),
            serde_json::json!({"$text": ["only"]}),
            serde_json::json!(marker("DIR")),
        ] {
            assert!(parse(malformed.clone()).is_err(), "{malformed}");
        }
        assert!(parse(serde_json::json!({"env": "DIR", "text": ["a"]})).is_ok());
    }

    /// A `package` check is a path or a command by how its text begins, and the same
    /// value on the wire either way. Only a path takes a reference: one in a check that
    /// doesn't begin as a path is rejected.
    #[test]
    fn a_package_check_is_a_path_or_a_command_by_its_first_characters() {
        use super::DeclaredPackageCheck;
        let parse = |check: serde_json::Value| {
            serde_json::from_value::<DeclaredPackageCheck>(check).unwrap()
        };
        let tool = Text::of_pieces([Lit("$HOME/bin/"), Ref("TOOL")]);
        for path in [
            Text::literal("/usr/bin/curl"),
            Text::literal("~/.local/bin/x"),
            tool.clone(),
            Text::of_pieces([Lit("/"), Ref("TOOL")]),
        ] {
            assert_eq!(
                parse(serde_json::json!(path)),
                DeclaredPackageCheck::Path(path)
            );
        }
        for command in ["command -v curl", "$$BIN$$/tool", "dpkg -s curl", ""] {
            assert_eq!(
                parse(serde_json::json!(command)),
                DeclaredPackageCheck::Command(command.to_owned())
            );
        }
        for referencing in [
            Text::reference("BIN"),
            Text::of_pieces([Ref("BIN"), Lit("/tool")]),
            Text::of_pieces([Lit("command -v "), Ref("TOOL")]),
        ] {
            let error =
                serde_json::from_value::<DeclaredPackageCheck>(serde_json::json!(referencing))
                    .unwrap_err()
                    .to_string();
            assert_eq!(error, "a command check takes no reference");
        }
        assert_eq!(
            serde_json::to_value(parse(serde_json::json!(tool))).unwrap(),
            serde_json::json!(tool)
        );
        assert_eq!(
            serde_json::to_value(parse(serde_json::json!("which jq"))).unwrap(),
            serde_json::json!("which jq")
        );
        assert_eq!(
            parse(serde_json::json!("which jq")).as_declared(),
            "which jq"
        );
    }

    #[test]
    fn local_target_with_remote_fields_is_rejected() {
        // The contradictory `local: true` + a remote-only field is unrepresentable in
        // the enum and rejected at the wire→enum boundary.
        let err = serde_json::from_value::<super::Target>(serde_json::json!({
            "local": true, "host": "example.com",
        }))
        .unwrap_err()
        .to_string();
        assert!(err.contains("cannot also set"), "got: {err}");
    }

    /// A target's keys are a closed set: one it doesn't have fails the parse by name.
    #[test]
    fn a_key_the_target_does_not_have_is_rejected() {
        for key in ["container_engine", "hostname", "sudo"] {
            let mut target = serde_json::json!({"host": "h.example"});
            target[key] = serde_json::json!("docker");
            let error = serde_json::from_value::<super::Target>(target)
                .unwrap_err()
                .to_string();
            assert!(
                error.starts_with(&format!("unknown field `{key}`, expected one of")),
                "{error}"
            );
        }
    }

    /// A count that zero can't be is refused at the parse: a port, a health gate's
    /// attempts, a pipeline's concurrency.
    #[test]
    fn a_zero_port_attempt_count_or_concurrency_is_rejected() {
        use super::{DeploySpec, Resource, Target};
        let zero = |error: serde_json::Error| {
            let error = error.to_string();
            assert!(
                error.starts_with("invalid value: integer `0`, expected a nonzero"),
                "{error}"
            );
        };
        zero(
            serde_json::from_value::<Target>(serde_json::json!({"host": "h.example", "port": 0}))
                .unwrap_err(),
        );
        zero(
            serde_json::from_value::<Resource>(serde_json::json!({
                "id": "fw", "type": "firewall", "backend": "ufw", "allow": [{"port": 0}],
            }))
            .unwrap_err(),
        );
        zero(
            serde_json::from_value::<Resource>(serde_json::json!({
                "id": "p", "type": "pipeline", "steps": [], "max_concurrency": 0,
            }))
            .unwrap_err(),
        );
        zero(
            serde_json::from_value::<DeploySpec>(serde_json::json!({
                "artifacts": ["build/"], "path": "/srv/app",
                "health": {"domain": "a.example", "path": "/health", "attempts": 0},
            }))
            .unwrap_err(),
        );
        serde_json::from_value::<Target>(serde_json::json!({"host": "h.example", "port": 65535}))
            .unwrap();
    }

    #[test]
    fn local_target_with_bootstrap_user_is_rejected() {
        // `bootstrap_user` is a remote-only connecting identity — on a `local: true`
        // target it has no meaning, so it's rejected by the same wire→enum guard as the
        // other remote-only fields.
        let err = serde_json::from_value::<super::Target>(serde_json::json!({
            "local": true, "bootstrap_user": "root",
        }))
        .unwrap_err()
        .to_string();
        assert!(err.contains("cannot also set"), "got: {err}");
    }

    /// An apt name `dpkg-query` would never find installed is refused when the config is
    /// parsed, by what it is, through the whole wire parse an evaluated config takes;
    /// the apt forms the query reads, and apk names, parse.
    #[test]
    fn an_apt_name_the_query_never_finds_is_refused_at_parse() {
        let config = |from: serde_json::Value| {
            super::ZapConfig::from_wire_value(&serde_json::json!({
                "target": {"local": true, "package_manager": "apt"},
                "resources": [{"id": "p", "type": "package", "from": from}],
            }))
        };
        for (name, problem) in [
            ("nginx=", "has an empty version after `=`"),
            ("nginx:", "has an empty architecture after `:`"),
            ("python3:any", "names `:any`, an architecture apt resolves"),
            (
                "libc6:native",
                "names `:native`, an architecture apt resolves",
            ),
            ("libc6:AMD64", "names `:AMD64`, which is no architecture"),
            (
                "tzdata:all",
                "names `:all`, which apt reads as the native architecture",
            ),
        ] {
            let Err(error) = config(serde_json::json!({"apt": name})) else {
                panic!("{name} parsed");
            };
            let error = error.to_string();
            assert!(
                error.contains(&format!("apt package `{name}` {problem}"))
                    && error.contains("`dpkg-query` would never find it installed"),
                "{name}: {error}"
            );
        }
        for from in [
            serde_json::json!({"apt": "libc6:amd64=2.36-9", "apk": "musl"}),
            serde_json::json!({"apt": "memtest86+"}),
            serde_json::json!({"apk": "cmd:git"}),
        ] {
            assert!(config(from.clone()).is_ok(), "{from}");
        }
    }

    /// An apk name `apk info -e` would read installed whether or not it is (an operator
    /// with no version after it) is refused when the config is parsed, through the whole
    /// wire parse; the apk forms the query reads, and the same names under apt, parse.
    #[test]
    fn an_apk_name_the_query_always_finds_is_refused_at_parse() {
        let config = |from: serde_json::Value| {
            super::ZapConfig::from_wire_value(&serde_json::json!({
                "target": {"local": true, "package_manager": "apk"},
                "resources": [{"id": "p", "type": "package", "from": from}],
            }))
        };
        for (name, operator) in [
            ("nginx=", "="),
            ("nginx~", "~"),
            ("nginx==", "=="),
            ("nginx=~", "=~"),
            ("nginx~=", "~="),
            ("nginx~~", "~~"),
            ("nginx@edge=", "="),
            ("nginx@=", "="),
            ("cmd:git=", "="),
        ] {
            let Err(error) = config(serde_json::json!({"apk": name})) else {
                panic!("{name} parsed");
            };
            let error = error.to_string();
            assert!(
                error.contains(&format!(
                    "apk package `{name}` has an empty version after `{operator}`"
                )) && error.contains("`apk info -e` would read it installed whether or not it is"),
                "{name}: {error}"
            );
        }
        for from in [
            serde_json::json!({"apk": "nginx"}),
            serde_json::json!({"apk": "busybox=1.37.0-r31"}),
            serde_json::json!({"apk": "busybox~1"}),
            serde_json::json!({"apk": "nginx@edge"}),
            serde_json::json!({"apk": "cmd:git"}),
            serde_json::json!({"apk": "so:libc.musl-x86_64.so.1"}),
            serde_json::json!({"apk": "musl", "apt": "nginx~"}),
        ] {
            assert!(config(from.clone()).is_ok(), "{from}");
        }
    }

    #[test]
    fn user_sudo_true_is_rejected_and_false_round_trips() {
        use super::UserSudo;
        // `true` is not a grant: a bool arm would read it as Disabled and *remove* the
        // sudoers file an untyped config meant to write.
        let err = serde_json::from_value::<UserSudo>(serde_json::json!(true))
            .unwrap_err()
            .to_string();
        assert!(err.contains("`sudo: true` grants nothing"), "got: {err}");
        // The three wire forms parse, and Disabled serializes back to `false`.
        let disabled = serde_json::from_value::<UserSudo>(serde_json::json!(false)).unwrap();
        assert_eq!(disabled, UserSudo::Disabled);
        assert_eq!(
            serde_json::to_value(&disabled).unwrap(),
            serde_json::json!(false)
        );
        assert!(matches!(
            serde_json::from_value::<UserSudo>(serde_json::json!("nopasswd")).unwrap(),
            UserSudo::Mode(_)
        ));
        let restricted = serde_json::from_value::<UserSudo>(
            serde_json::json!({"mode": "password", "commands": ["/usr/bin/systemctl"]}),
        )
        .unwrap();
        assert!(matches!(restricted, UserSudo::Restricted { .. }));
        assert_eq!(
            serde_json::to_value(&restricted).unwrap(),
            serde_json::json!({"mode": "password", "commands": ["/usr/bin/systemctl"]})
        );
    }

    #[test]
    fn target_round_trips_through_the_flat_wire() {
        use super::{Target, TargetLocation};
        // Local: `local: true` round-trips; no remote fields.
        let local: Target = serde_json::from_value(serde_json::json!({
            "local": true, "package_manager": "apt",
        }))
        .unwrap();
        assert!(local.is_local());
        assert_eq!(
            serde_json::to_value(&local).unwrap(),
            serde_json::json!({"local": true, "package_manager": "apt"})
        );
        // Remote: an explicit `local: false` survives, connection fields route into the
        // variant, and `home` / `bootstrap_user` are remote-only.
        let remote: Target = serde_json::from_value(serde_json::json!({
            "local": false, "host": Text::reference("H"), "user": "deploy",
            "bootstrap_user": "root",
            "port": 2222, "home": "/home/deploy",
        }))
        .unwrap();
        assert!(matches!(remote.location, TargetLocation::Remote { .. }));
        assert_eq!(
            remote.host().map(Text::as_inert),
            Some(marker("H").as_str())
        );
        assert_eq!(remote.user().map(Text::as_inert), Some("deploy"));
        assert_eq!(remote.bootstrap_user().map(Text::as_inert), Some("root"));
        assert_eq!(remote.home(), Some("/home/deploy"));
        assert_eq!(
            serde_json::to_value(&remote).unwrap(),
            serde_json::json!({
                "local": false, "host": Text::reference("H"), "user": "deploy",
            "bootstrap_user": "root",
                "port": 2222, "home": "/home/deploy",
            })
        );
    }

    #[test]
    fn unknown_field_on_a_leaf_resource_is_rejected() {
        // deny_unknown_fields on the leaf payload works through the flatten + internal
        // tag: a misspelled field fails at parse instead of being silently dropped.
        let err = serde_json::from_value::<super::Resource>(serde_json::json!({
            "id": "curl", "type": "package", "fromm": {"apt": "curl"},
        }))
        .unwrap_err()
        .to_string();
        assert!(err.contains("unknown field `fromm`"), "got: {err}");
    }

    #[test]
    fn sizeless_swap_is_rejected_at_parse() {
        // `size` is required — a sizeless swap can't emit a `fallocate`, so it must
        // fail at config-eval, not converge-as-success doing nothing (a sizeless swap
        // emitted only a skipped `Note` and reported `Completed` every run).
        let err = serde_json::from_value::<super::Resource>(serde_json::json!({
            "id": "s", "type": "swap", "path": "/swapfile",
        }))
        .unwrap_err()
        .to_string();
        assert!(err.contains("missing field `size`"), "got: {err}");
    }

    #[test]
    fn ufw_target_is_the_shared_rule_identity() {
        use super::{FirewallAllowRule, Protocol};
        // The one identity the `firewall` detector's status-needle and the step builder's
        // `ufw allow` argument both consume — pinned here so the probe and the mutation
        // can't drift. A typed rule renders `<port>/<proto>`, an any-proto rule the bare
        // port (ufw omits the suffix), a named profile its verbatim name.
        assert_eq!(
            FirewallAllowRule::PortProto {
                port: std::num::NonZeroU16::new(22).unwrap(),
                proto: Protocol::Tcp
            }
            .ufw_target(),
            "22/tcp"
        );
        assert_eq!(
            FirewallAllowRule::PortProto {
                port: std::num::NonZeroU16::new(53).unwrap(),
                proto: Protocol::Udp
            }
            .ufw_target(),
            "53/udp"
        );
        assert_eq!(
            FirewallAllowRule::PortProto {
                port: std::num::NonZeroU16::new(8080).unwrap(),
                proto: Protocol::Any
            }
            .ufw_target(),
            "8080"
        );
        assert_eq!(
            FirewallAllowRule::Named("Nginx Full".to_owned()).ufw_target(),
            "Nginx Full"
        );
    }

    /// A port rule and a restricted grant are objects with their own keys: one that is
    /// misspelled is an error, not a rule or a grant with the default in its place.
    #[test]
    fn unknown_field_in_a_port_rule_or_a_restricted_grant_is_rejected() {
        let rule = serde_json::from_value::<super::Resource>(serde_json::json!({
            "id": "fw", "type": "firewall", "backend": "ufw",
            "allow": [{"port": 53, "protocol": "udp"}]
        }))
        .unwrap_err()
        .to_string();
        assert!(rule.contains("unknown field `protocol`"), "got: {rule}");
        let grant = serde_json::from_value::<super::Resource>(serde_json::json!({
            "id": "u", "type": "user", "username": "deploy",
            "sudo": {"mode": "nopasswd", "commands": ["/usr/bin/true"], "command": "x"}
        }))
        .unwrap_err()
        .to_string();
        assert!(grant.contains("unknown field `command`"), "got: {grant}");
        // the spelled-out forms still parse
        for ok in [
            serde_json::json!({"id": "fw", "type": "firewall", "backend": "ufw",
                "allow": [{"port": 53, "proto": "udp"}, {"port": 22}]}),
            serde_json::json!({"id": "u", "type": "user", "username": "deploy",
                "sudo": {"mode": "nopasswd", "commands": ["/usr/bin/true"]}}),
        ] {
            serde_json::from_value::<super::Resource>(ok).unwrap();
        }
    }

    /// A restricted grant lists at least one command, each a spec of its own on one
    /// line: an empty list is not the unrestricted grant, and says how that is written.
    #[test]
    fn a_restricted_grant_lists_the_commands_it_covers() {
        use super::{SudoCommands, SudoMode, SudoScope, UserSudo, build_sudoers_content};
        let grant = |mode: &str, commands: &[&str]| {
            serde_json::from_value::<super::Resource>(serde_json::json!({
                "id": "u", "type": "user", "username": "deploy",
                "sudo": {"mode": mode, "commands": commands},
            }))
            .map_err(|error| error.to_string())
        };
        for (mode, commands, expected) in [
            (
                "nopasswd",
                &[][..],
                "`sudo.commands` is empty: a grant limited to no command grants nothing, and \
                 zap does not read an empty list as every command; for a grant of every \
                 command write the mode alone (`sudo: 'nopasswd'`), or list the commands the \
                 grant covers",
            ),
            ("password", &[], "(`sudo: 'password'`)"),
            ("nopasswd", &[""], "`sudo.commands[0]` is blank;"),
            ("nopasswd", &["   "], "`sudo.commands[0]` is blank;"),
            (
                "nopasswd",
                &["/bin/a\u{7f}"],
                "`sudo.commands[0]` holds a control",
            ),
            (
                "nopasswd",
                &["/bin/ls", " \t"],
                "`sudo.commands[1]` is blank;",
            ),
            (
                "nopasswd",
                &["/bin/a\nroot ALL=(ALL) NOPASSWD: ALL"],
                "`sudo.commands[0]` holds a control character (a tab and a line break \
                 are each one); a command spec is one stretch of one line of the sudoers \
                 file — separate its words with spaces",
            ),
            (
                "nopasswd",
                &["/usr/bin/systemctl\trestart app"],
                "`sudo.commands[0]` holds a control character (a tab and",
            ),
            (
                "nopasswd",
                &["/bin/ls", "/bin/a\rb"],
                "`sudo.commands[1]` holds a control character (",
            ),
            (
                "nopasswd",
                &["/bin/a\u{0}"],
                "`sudo.commands[0]` holds a control",
            ),
            (
                "nopasswd",
                &["/bin/a\u{85}"],
                "`sudo.commands[0]` holds a control",
            ),
        ] {
            let error = grant(mode, commands).unwrap_err();
            assert!(error.contains(expected), "{commands:?}: {error}");
        }
        assert_eq!(
            SudoCommands::new(Vec::new()),
            Err(super::InvalidSudoCommands::Empty)
        );

        // What parses, and the sudoers line each grant is.
        let sudo = |sudo: serde_json::Value| serde_json::from_value::<UserSudo>(sudo).unwrap();
        let line = |sudo: &UserSudo| {
            let (mode, scope) = sudo.grant().unwrap();
            build_sudoers_content("deploy", mode, scope)
        };
        for (wire, text) in [
            (
                serde_json::json!("nopasswd"),
                "deploy ALL=(ALL) NOPASSWD: ALL\n",
            ),
            (serde_json::json!("password"), "deploy ALL=(ALL) ALL\n"),
            (
                serde_json::json!({"mode": "nopasswd", "commands": ["/bin/ls"]}),
                "deploy ALL=(ALL) NOPASSWD: /bin/ls\n",
            ),
            (
                serde_json::json!({"mode": "password",
                    "commands": ["/usr/bin/systemctl restart app", "/bin/ls -l /srv/*"]}),
                "deploy ALL=(ALL) /usr/bin/systemctl restart app, /bin/ls -l /srv/*\n",
            ),
        ] {
            let parsed = sudo(wire.clone());
            assert_eq!(line(&parsed), text);
            assert_eq!(serde_json::to_value(&parsed).unwrap(), wire);
        }
        assert_eq!(
            sudo(serde_json::json!("nopasswd")).grant(),
            Some((SudoMode::Nopasswd, SudoScope::All))
        );
        assert_eq!(sudo(serde_json::json!(false)).grant(), None);
    }

    /// `type: 'none'` extracts nothing and takes no other key: a `strip_components`
    /// beside it is an error that says where the key belongs, not a key dropped. Only
    /// the object form is read, and a valid mode is the same value on the wire.
    #[test]
    fn a_key_beside_an_extract_of_none_is_rejected() {
        use super::ExtractMode;
        let extract = |extract: serde_json::Value| {
            serde_json::from_value::<super::Resource>(serde_json::json!({
                "id": "f", "type": "file", "path": "/opt/f",
                "content": {"type": "remote", "url": "https://x/a", "extract": extract},
            }))
            .map_err(|error| error.to_string())
        };
        for (wire, expected) in [
            (
                serde_json::json!({"type": "none", "strip_components": 1}),
                "`strip_components` belongs to a tar archive (`type: 'tar.xz'` or `'tar.gz'`); \
                 `type: 'none'` writes the fetched bytes as they are and takes no other key",
            ),
            (
                serde_json::json!({"type": "none", "strip_components": 0}),
                "`strip_components` belongs to a tar archive",
            ),
            (
                serde_json::json!({"type": "none", "strip": 1}),
                "unknown field `strip`, expected `type` or `strip_components`",
            ),
            (
                serde_json::json!({"type": "tar.gz", "strip_component": 1}),
                "unknown field `strip_component`",
            ),
            (
                serde_json::json!({"type": "zip"}),
                "unknown variant `zip`, expected one of `none`, `tar.xz`, `tar.gz`",
            ),
            (
                serde_json::json!({"strip_components": 1}),
                "missing field `type`",
            ),
            (serde_json::json!({}), "missing field `type`"),
            (
                serde_json::json!({"type": {"none": null}}),
                "invalid type: map, expected a string",
            ),
            (
                serde_json::json!({"type": 0}),
                "invalid type: integer `0`, expected a string",
            ),
            (
                serde_json::json!(["none"]),
                "expected `extract` as an object with a `type` of `none`, `tar.xz`, or `tar.gz`",
            ),
            (
                serde_json::json!(["tar.gz", 1]),
                "expected `extract` as an object with a `type`",
            ),
            (
                serde_json::json!("tar.gz"),
                "expected `extract` as an object with a `type`",
            ),
        ] {
            let error = extract(wire.clone()).unwrap_err();
            assert!(error.contains(expected), "{wire}: {error}");
        }
        for (wire, mode, serialized) in [
            (
                serde_json::json!({"type": "none"}),
                ExtractMode::None,
                serde_json::json!({"type": "none"}),
            ),
            (
                serde_json::json!({"type": "tar.xz"}),
                ExtractMode::TarXz {
                    strip_components: 0,
                },
                serde_json::json!({"type": "tar.xz"}),
            ),
            (
                serde_json::json!({"type": "tar.xz", "strip_components": 0}),
                ExtractMode::TarXz {
                    strip_components: 0,
                },
                serde_json::json!({"type": "tar.xz"}),
            ),
            (
                serde_json::json!({"type": "tar.gz", "strip_components": 2}),
                ExtractMode::TarGz {
                    strip_components: 2,
                },
                serde_json::json!({"type": "tar.gz", "strip_components": 2}),
            ),
        ] {
            let parsed: ExtractMode = serde_json::from_value(wire.clone()).unwrap();
            assert_eq!(parsed, mode, "{wire}");
            assert_eq!(serde_json::to_value(parsed).unwrap(), serialized, "{wire}");
            extract(wire).unwrap();
        }
    }

    /// A tagged enum's own variants, and a user's `ssh_keys`, reject a key they don't
    /// name: a misspelled `strip_components` is not an archive extracted unstripped,
    /// and `keys` beside `copy_from` is not a copy with the keys dropped.
    #[test]
    fn unknown_field_in_an_enum_variant_is_rejected() {
        let file = |content: serde_json::Value| {
            serde_json::from_value::<super::Resource>(serde_json::json!({
                "id": "f", "type": "file", "path": "/opt/f", "content": content,
            }))
            .map(|_| ())
            .map_err(|error| error.to_string())
        };
        for (content, unknown) in [
            (
                serde_json::json!({"type": "remote", "url": "https://x/a.tar.xz",
                    "extract": {"type": "tar.xz", "strip_component": 1}}),
                "strip_component",
            ),
            (
                serde_json::json!({"type": "inline", "content": "x", "vars": {"a": "b"}}),
                "vars",
            ),
            (
                serde_json::json!({"type": "source", "path": "/y", "mode": "644"}),
                "mode",
            ),
            (
                serde_json::json!({"type": "remote", "url": "https://x/a",
                    "auth": {"scheme": "bearer", "token": "t", "header": "x"}}),
                "header",
            ),
        ] {
            let error = file(content).unwrap_err();
            assert!(
                error.contains(&format!("unknown field `{unknown}`")),
                "got: {error}"
            );
        }
        file(
            serde_json::json!({"type": "remote", "url": "https://x/a.tar.xz",
            "extract": {"type": "tar.xz", "strip_components": 1}}),
        )
        .unwrap();

        let keys = |ssh_keys: serde_json::Value| {
            serde_json::from_value::<super::Resource>(serde_json::json!({
                "id": "u", "type": "user", "username": "deploy", "ssh_keys": ssh_keys,
            }))
            .map(|_| ())
            .map_err(|error| error.to_string())
        };
        for (ssh_keys, expected) in [
            (
                serde_json::json!({"copy_from": "root", "keys": ["ssh-ed25519 AAAA a"]}),
                "not both",
            ),
            (
                serde_json::json!({"keys": ["ssh-ed25519 AAAA a"], "copy_form": "root"}),
                "unknown field `copy_form`",
            ),
            (serde_json::json!({}), "takes `copy_from` or `keys`"),
            // only the object form is read: an array is not its keys by position
            (
                serde_json::json!(["root"]),
                "expected an object with `copy_from` or `keys`",
            ),
            (
                serde_json::json!([null, ["ssh-ed25519 AAAA a"]]),
                "expected an object with `copy_from` or `keys`",
            ),
            (
                serde_json::json!("root"),
                "expected an object with `copy_from` or `keys`",
            ),
        ] {
            let error = keys(ssh_keys).unwrap_err();
            assert!(error.contains(expected), "got: {error}");
        }
        keys(serde_json::json!({"copy_from": "root"})).unwrap();
        keys(serde_json::json!({"keys": ["ssh-ed25519 AAAA a"]})).unwrap();
    }

    #[test]
    fn unknown_field_in_a_wrapped_enum_variant_is_rejected() {
        // A typo'd optional field inside the nested tagged enums (newtype-wrapped
        // variants) is caught — e.g. `blake33` would otherwise silently flip a vendored
        // file to tracked, and a dropped `verify` would silently disable signature check.
        let remote_file = serde_json::from_value::<super::Resource>(serde_json::json!({
            "id": "zig", "type": "file", "path": "/opt/zig",
            "content": {"type": "remote", "url": "https://x/zig", "blake33": "aa"},
        }));
        assert!(
            remote_file
                .unwrap_err()
                .to_string()
                .contains("unknown field `blake33`"),
            "remote file typo must be rejected"
        );
        let build = serde_json::from_value::<super::Resource>(serde_json::json!({
            "id": "b", "type": "build", "run": "make", "output": "/opt/b",
            "source": {"type": "remote", "url": "https://x/s.tgz", "verifyy": {}},
        }));
        assert!(
            build
                .unwrap_err()
                .to_string()
                .contains("unknown field `verifyy`"),
            "build source typo must be rejected"
        );
        let verify = serde_json::from_value::<super::Resource>(serde_json::json!({
            "id": "v", "type": "verify",
            "assertions": [{"type": "command", "run": "true", "expct": "ok"}],
        }));
        assert!(
            verify
                .unwrap_err()
                .to_string()
                .contains("unknown field `expct`"),
            "verify assertion typo must be rejected"
        );
    }

    #[test]
    fn numeric_owner_is_rejected_at_parse() {
        let parse = |owner: &str| {
            serde_json::from_value::<super::Resource>(serde_json::json!({
                "id": "f", "type": "file", "path": "/etc/x",
                "content": {"type": "inline", "content": "hi"}, "owner": owner,
            }))
        };
        // A purely-numeric uid never converges against the name from `stat -c %U` — reject.
        let err = parse("1000").unwrap_err().to_string();
        assert!(err.contains("numeric owner/group"), "got: {err}");
        // A name (even with digits) is fine.
        assert!(parse("deploy").is_ok());
        assert!(parse("user1").is_ok());
    }

    #[test]
    fn numeric_group_and_verify_owner_are_rejected() {
        let dir = serde_json::from_value::<super::Resource>(serde_json::json!({
            "id": "d", "type": "directory", "path": "/srv", "group": "42",
        }));
        assert!(dir.unwrap_err().to_string().contains("numeric owner/group"));
        let verify = serde_json::from_value::<super::Resource>(serde_json::json!({
            "id": "v", "type": "verify",
            "assertions": [{"type": "path_exists", "path": "/srv", "owner": "0"}],
        }));
        assert!(
            verify
                .unwrap_err()
                .to_string()
                .contains("numeric owner/group")
        );
    }

    #[test]
    fn bearer_auth_resolves_and_formats_the_header() {
        let auth = RemoteAuth::Bearer {
            token: Text::reference("TOK"),
        };
        let (name, value) = auth.to_header(|_| "abc123".to_owned()).unwrap();
        assert_eq!(name, "Authorization");
        assert_eq!(value, "Bearer abc123");
    }

    #[test]
    fn bearer_auth_with_empty_credential_is_none() {
        let auth = RemoteAuth::Bearer {
            token: Text::reference("UNSET"),
        };
        // An unset token resolves empty → no header (the caller errors clearly rather
        // than send a bogus `Bearer `).
        assert!(auth.to_header(|_| String::new()).is_none());
    }
}
