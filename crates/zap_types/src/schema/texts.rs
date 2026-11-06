//! The walk over every [`Text`] a config holds — the one statement of which fields take
//! a reference.
//!
//! Every struct is destructured in full, with no `..`: a field added to the schema does
//! not compile until it is placed here, as a `Text` that is visited or a field that
//! holds none. A field whose type changes still compiles; the partition test in
//! `tests/fidelity.rs` is what fails then.

use std::collections::BTreeMap;

use super::{
    AptRepoResource, BuildResource, BuildSource, CommandAssertion, DatabaseAuth, DatabaseResource,
    DeclaredPackageCheck, DeployHealth, DeploySpec, DirectoryResource, FileContent, FileResource,
    FirewallAllowRule, FirewallResource, InstallerResource, LinkResource, MinisignVerify,
    PackageResource, PathExistsAssertion, PipelineResource, PipelineStep, RemoteAuth,
    RemoteContent, RemoteSource, Resource, ResourceKind, ScriptResource, ServiceResource,
    SourceVerify, SshKeys, SwapResource, Target, TargetLocation, TemplateContent, TemplateVar,
    UserResource, UserSudo, VerifyAssertion, VerifyResource, ZapConfig,
};
use crate::scalar::EnvVarName;
use crate::text::Text;

/// What a [`Text`] is to the consumers that scan a config for references.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TextRole {
    /// The target's `host`, `user`, or `bootstrap_user` — which machine a run reads and
    /// who it reads it as.
    TargetIdentity,
    /// A resource field detection, execution, or the resource's hashes resolve.
    Resource,
    /// A fetch credential — a `remote` file's or a `build` source's [`RemoteAuth`]. It
    /// resolves for the request alone and is no part of any hash or comparison.
    FetchCredential,
    /// A field of the `deploy` block, which only `zap deploy` reads.
    Deploy,
}

impl ZapConfig {
    /// Call `f` with every [`Text`] in the config and its [`TextRole`]: the target's,
    /// each resource's in declared order, then the `deploy` block's.
    pub fn for_each_text(&self, mut f: impl FnMut(TextRole, &Text)) {
        let Self {
            target,
            resources,
            deploy,
            mask_vars: _,
            unmask_vars: _,
        } = self;
        target.for_each_text(&mut f);
        for resource in resources {
            resource.for_each_text(&mut f);
        }
        if let Some(deploy) = deploy {
            deploy_texts(deploy, &mut f);
        }
    }
}

impl Target {
    /// Call `f` with every [`Text`] the target holds — its `host`, `user`, and
    /// `bootstrap_user`, each a [`TextRole::TargetIdentity`].
    pub fn for_each_text(&self, mut f: impl FnMut(TextRole, &Text)) {
        let Self {
            location,
            package_manager: _,
            service_manager: _,
        } = self;
        match location {
            TargetLocation::Local => {}
            TargetLocation::Remote {
                host,
                user,
                bootstrap_user,
                port: _,
                key_path: _,
                home: _,
            } => {
                for text in [host, user, bootstrap_user].into_iter().flatten() {
                    f(TextRole::TargetIdentity, text);
                }
            }
        }
    }
}

impl Resource {
    /// Call `f` with every [`Text`] the resource holds: each a [`TextRole::Resource`]
    /// but a fetch credential's, a [`TextRole::FetchCredential`].
    pub fn for_each_text(&self, mut f: impl FnMut(TextRole, &Text)) {
        let Self {
            id: _,
            name: _,
            depends_on: _,
            kind,
        } = self;
        let f = &mut f;
        match kind {
            ResourceKind::Package(PackageResource { from: _, check }) => match check {
                Some(DeclaredPackageCheck::Path(path)) => f(TextRole::Resource, path),
                Some(DeclaredPackageCheck::Command(_)) | None => {}
            },
            ResourceKind::AptRepo(AptRepoResource {
                key_url,
                key_blake3: _,
                key_path: _,
                source: _,
                list_file: _,
            }) => f(TextRole::Resource, key_url),
            ResourceKind::Script(ScriptResource {
                check,
                run,
                cwd: _,
                env,
            }) => {
                f(TextRole::Resource, check);
                f(TextRole::Resource, run);
                env_texts(env.as_ref(), f);
            }
            ResourceKind::Installer(InstallerResource { url, check, shell }) => {
                f(TextRole::Resource, url);
                f(TextRole::Resource, check);
                f(TextRole::Resource, shell);
            }
            ResourceKind::Directory(DirectoryResource {
                path,
                mode: _,
                owner: _,
                group: _,
            }) => f(TextRole::Resource, path),
            ResourceKind::File(file) => file_texts(file, f),
            ResourceKind::Link(LinkResource { path, target }) => {
                f(TextRole::Resource, path);
                f(TextRole::Resource, target);
            }
            ResourceKind::Database(DatabaseResource {
                engine: _,
                database_name,
                username,
                auth,
            }) => {
                f(TextRole::Resource, database_name);
                f(TextRole::Resource, username);
                if let Some(DatabaseAuth { method: _, hosts }) = auth {
                    for host in hosts {
                        f(TextRole::Resource, host);
                    }
                }
            }
            ResourceKind::Swap(SwapResource { size, path: _ }) => f(TextRole::Resource, size),
            ResourceKind::Pipeline(PipelineResource {
                env: _,
                steps,
                max_concurrency: _,
            }) => {
                for PipelineStep {
                    id: _,
                    name: _,
                    run,
                    cwd: _,
                    env: _,
                    depends_on: _,
                } in steps
                {
                    f(TextRole::Resource, run);
                }
            }
            ResourceKind::Build(build) => build_texts(build, f),
            // Every field of these kinds is used as declared: account names, modes, and
            // closed sets, and text a reference is rejected in or never resolved in.
            ResourceKind::User(UserResource {
                username: _,
                shell: _,
                home_mode: _,
                ssh_keys,
                sudo,
                groups: _,
            }) => {
                match ssh_keys {
                    Some(SshKeys::CopyFrom { copy_from: _ } | SshKeys::Keys { keys: _ }) | None => {
                    }
                }
                match sudo {
                    Some(
                        UserSudo::Disabled
                        | UserSudo::Mode(_)
                        | UserSudo::Restricted {
                            mode: _,
                            commands: _,
                        },
                    )
                    | None => {}
                }
            }
            ResourceKind::Service(ServiceResource {
                service: _,
                enabled: _,
                running: _,
                restart_on: _,
                reload_on: _,
            }) => {}
            ResourceKind::Firewall(FirewallResource {
                backend: _,
                default_incoming: _,
                default_outgoing: _,
                allow,
            }) => {
                for rule in allow {
                    match rule {
                        FirewallAllowRule::Named(_)
                        | FirewallAllowRule::PortProto { port: _, proto: _ } => {}
                    }
                }
            }
            ResourceKind::Verify(VerifyResource { assertions }) => {
                for assertion in assertions {
                    match assertion {
                        VerifyAssertion::PathExists(PathExistsAssertion {
                            path: _,
                            file_type: _,
                            mode: _,
                            owner: _,
                            not_empty: _,
                        })
                        | VerifyAssertion::Command(CommandAssertion { run: _, expect: _ }) => {}
                    }
                }
            }
        }
    }
}

/// A `file`'s texts: its path, its `validate` command, and what its content resolves.
fn file_texts(file: &FileResource, f: &mut impl FnMut(TextRole, &Text)) {
    let FileResource {
        path,
        content,
        mode: _,
        owner: _,
        group: _,
        triggers: _,
        validate,
    } = file;
    f(TextRole::Resource, path);
    match content {
        FileContent::Inline { content: _ } => {}
        FileContent::Template(TemplateContent {
            template: _,
            vars,
            kinds: _,
        }) => {
            for var in vars.values() {
                match var {
                    TemplateVar::Text(text) => f(TextRole::Resource, text),
                    TemplateVar::Json(_) => {}
                }
            }
        }
        FileContent::Source { path } => f(TextRole::Resource, path),
        FileContent::Remote(RemoteContent {
            url,
            blake3: _,
            extract: _,
            auth,
        }) => {
            f(TextRole::Resource, url);
            auth_texts(auth.as_ref(), f);
        }
    }
    if let Some(validate) = validate {
        f(TextRole::Resource, validate);
    }
}

/// A `build`'s texts: its command, output path, `env` values, and its source's.
fn build_texts(build: &BuildResource, f: &mut impl FnMut(TextRole, &Text)) {
    let BuildResource {
        source,
        run,
        output,
        cwd: _,
        env,
    } = build;
    let BuildSource::Remote(RemoteSource {
        url,
        extract: _,
        auth,
        verify,
        blake3: _,
    }) = source;
    f(TextRole::Resource, url);
    auth_texts(auth.as_ref(), f);
    match verify {
        Some(SourceVerify::Minisign(MinisignVerify {
            public_key: _,
            signature_url: Some(signature_url),
        })) => f(TextRole::Resource, signature_url),
        Some(SourceVerify::Minisign(MinisignVerify {
            public_key: _,
            signature_url: None,
        }))
        | None => {}
    }
    f(TextRole::Resource, run);
    f(TextRole::Resource, output);
    env_texts(env.as_ref(), f);
}

/// A fetch credential's text — the one place a [`TextRole::FetchCredential`] is named.
fn auth_texts(auth: Option<&RemoteAuth>, f: &mut impl FnMut(TextRole, &Text)) {
    match auth {
        Some(RemoteAuth::Bearer { token }) => f(TextRole::FetchCredential, token),
        None => {}
    }
}

/// An `env` map's values.
fn env_texts(env: Option<&BTreeMap<EnvVarName, Text>>, f: &mut impl FnMut(TextRole, &Text)) {
    for value in env.into_iter().flat_map(BTreeMap::values) {
        f(TextRole::Resource, value);
    }
}

impl DeploySpec {
    /// Call `f` with every [`Text`] the `deploy` block holds, each a
    /// [`TextRole::Deploy`].
    pub fn for_each_text(&self, mut f: impl FnMut(TextRole, &Text)) {
        deploy_texts(self, &mut f);
    }
}

/// The `deploy` block's one text: the health check's domain.
fn deploy_texts(deploy: &DeploySpec, f: &mut impl FnMut(TextRole, &Text)) {
    let DeploySpec {
        build: _,
        artifacts: _,
        path: _,
        releases: _,
        service: _,
        shared: _,
        prepare: _,
        health,
    } = deploy;
    if let Some(DeployHealth {
        domain,
        path: _,
        attempts: _,
        interval_ms: _,
    }) = health
    {
        f(TextRole::Deploy, domain);
    }
}
