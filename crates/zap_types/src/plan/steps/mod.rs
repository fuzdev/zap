//! Per-resource-kind step builders for the plan fact.
//!
//! [`resource_steps`] dispatches on `ResourceKind` to one pure builder per kind, one
//! file per kind. Each `*_steps` fn is deterministic and IO-free — it templates the
//! shell / SQL / fstab commands a change runs (or returns preview
//! [`Note`](crate::plan::PlanStep::Note)s for the genuinely unrunnable). `file` /
//! `directory` / `link` carry no steps (native `std::fs` IO at execution).

mod apt_repo;
mod build;
mod database;
mod firewall;
mod installer;
mod package;
mod pipeline;
mod script;
mod service;
mod swap;
mod user;
mod verify;

use crate::detected::{CurrentState, Detection};
use crate::plan::PlanStep;
use crate::schema::{Resource, ResourceKind, Target};

/// Generate the steps a change runs, for the dry-run preview and the plan fact.
///
/// Pure dispatcher: each kind's builder lives in its own submodule. `file` /
/// `directory` / `link` return **empty** — they're native `std::fs` IO at execution,
/// with no pre-baked command. A malformed config
/// yields no steps.
///
/// Each step is a [`PlanStep::Run`] (verbatim-runnable shell), a typed operation
/// ([`PlanStep::Put`], [`PlanStep::Dir`], [`PlanStep::PgHbaRule`],
/// [`PlanStep::SwapCheck`] — what one of zap's
/// constant scripts does, without the script), or a [`PlanStep::Note`] (a preview the
/// executor can't run as it stands — an unsupported-manager marker, a `verify`
/// description). The executor runs every step but a `Note`.
///
/// `detected` narrows a kind whose drift is read part by part to the missing parts: a
/// drifted `swap` repairs only what isn't there ([`swap::swap_steps`]), and an absent
/// `user` adds its home's owner change to the creation ([`user::user_steps`]).
#[must_use]
pub(super) fn resource_steps(
    resource: &Resource,
    target: &Target,
    detected: Option<&Detection>,
) -> Vec<PlanStep> {
    match &resource.kind {
        ResourceKind::File(_) | ResourceKind::Directory(_) | ResourceKind::Link(_) => Vec::new(),
        ResourceKind::Package(package) => package::package_steps(package, target),
        ResourceKind::Script(script) => script::script_steps(script),
        ResourceKind::Installer(installer) => installer::installer_steps(installer),
        ResourceKind::User(user) => user::user_steps(user, detected),
        ResourceKind::Service(service) => service::service_steps(service, target),
        ResourceKind::Swap(swap) => match detected {
            Some(Detection::Drifted {
                current:
                    CurrentState::Swap {
                        is_active,
                        in_fstab,
                    },
            }) => swap::swap_steps(
                swap,
                swap::SwapParts {
                    is_active: *is_active,
                    in_fstab: *in_fstab,
                },
            ),
            _ => swap::swap_steps(swap, swap::SwapParts::NONE),
        },
        ResourceKind::Firewall(firewall) => firewall::firewall_steps(firewall),
        ResourceKind::Verify(verify) => verify::verify_steps(verify),
        ResourceKind::Database(database) => database::database_steps(database),
        ResourceKind::AptRepo(repo) => apt_repo::apt_repo_steps(repo, &resource.id),
        ResourceKind::Pipeline(pipeline) => pipeline::pipeline_steps(pipeline),
        ResourceKind::Build(build) => build::build_steps(build),
    }
}
