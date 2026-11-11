//! Command cores — the engine entry points behind each CLI verb.
//!
//! The `zap` binary parses args and renders; these `run_*` functions are the
//! reusable cores, so one command can call another without going through the CLI.
//!
//! Two tiers: `plan` / `apply` / `status` are the convergence *roles*; `detect`
//! (and, later, `preflight`) are *stage inspectors* one level down. `run_detect`
//! renders raw detected state; `run_plan` runs the same detection and diffs it into
//! the plan fact; `status` reads the last-run report every detection pass writes,
//! without probing.
//!
//! Every core reads its config through one of two seams — `eval_target` (binds a
//! `Connection`) or `eval_untargeted` (doesn't) — and both run the same private
//! `config_gates`. That is deliberate structure, not convenience: a core cannot obtain
//! a `ZapConfig` ungated, so "which commands validate the config" has one answer instead
//! of nine, and both seams eval through the L0 cache, so no eval escapes its
//! shadow-mismatch observation.

use std::path::Path;

use crate::error::Result;
use crate::home::zap_home_default;

pub mod apply;
mod checks;
pub mod deploy;
pub mod detect;
mod detect_pass;
pub mod lock;
pub mod plan;
pub mod preview;
pub mod prompt;
mod render;
pub mod status;
mod target;
#[cfg(test)]
mod test_support;
pub mod update;

pub use apply::{ApplyOptions, render_apply, run_apply};
pub use deploy::{DeployOptions, DeployOutcome, DeployReport, render_deploy, run_deploy};
pub use detect::{render_detect, run_detect};
pub(crate) use detect_pass::PassContext;
pub use lock::{
    LockCheckReport, LockReport, render_lock, render_lock_check, run_lock, run_lock_check,
};
pub use plan::{render_plan, render_plan_diff, run_plan};
pub use preview::{RecordedPreview, Withdrawal};
pub use prompt::{Confirmation, Prompt};
pub use render::REFERENCE_VALUE_SHOWN;
pub use status::{render_status, run_status};
pub use update::{UpdateReport, render_update, run_update};

/// A command's report as the binary delivers it.
///
/// Its exit code, and whether its run changed something besides answering, which decides
/// the exit code of a run whose report couldn't be written: a run that changed the machine
/// or the lock keeps its own code, which describes them; one whose report was its answer
/// fails where it would have succeeded, since the answer never arrived. And the preview
/// the run recorded, which the binary withdraws when the report that shows it can't be
/// written ([`RecordedPreview::withdraw`]).
///
/// Each report says so beside its own type, where its fixtures can hold it to it, so the
/// binary holds no per-report rule of its own.
pub trait Delivered {
    /// The report's own exit code.
    fn exit_code(&self) -> u8;
    /// Whether the run changed the machine or the lock.
    fn changed(&self) -> bool;
    /// The preview the run recorded, if it recorded one. No default, so a report that
    /// records one can't leave it bound by leaving this out.
    fn preview(&self) -> Option<&RecordedPreview>;
}

// The helpers the command modules share, each reached from them as `super::<name>`.
use checks::{
    APPLY_REFUSAL, LOCK_WITHHELD_FROM_COMPARISON, RefusalText, empty_changeset_line,
    mask_diagnostics, render_lock_standing, render_refused, render_undetermined,
    render_unverifiable, render_warnings, unresolved_env_message, unrunnable_changes,
    unrunnable_message, unverifiable_refs, validate_config_structure, warn_unrunnable,
};
use detect_pass::{
    Diffed, detect_and_diff, detect_pass, diff_unrecorded, prepare_lock, record_pass, spend_review,
};
use render::{
    NO_USER, check_references, render_address, render_change, render_change_header,
    render_declared, render_machine, render_native_puts, render_plan_subject, render_references,
    render_steps, render_target, render_trigger, render_unrecorded, target_location,
};
use target::{
    NAMES_NO_ONE_MACHINE, PinFrom, ResolvedMachine, connecting_user, eval_target, eval_untargeted,
    masked_label_refs, masking_errors, resolve_machine, unidentified_host_message,
};
#[cfg(test)]
use test_support::{refused_target, scratch_tempdir, scratch_write_config, test_fgro};

/// A plan's content address, or why it has none.
///
/// A hash is a handle on a plan for one machine: it is printed, recorded as a preview,
/// and bound to by a wetrun, all or none. A plan whose machine is a masking token has
/// none of the three.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlanAddress {
    /// The plan names one machine: its `plan_hash`.
    Hash(String),
    /// The plan names no one machine, so nothing addresses it. Carries why.
    Unbindable(String),
}

impl PlanAddress {
    /// The `plan_hash`, when the plan has one.
    #[must_use]
    pub fn hash(&self) -> Option<&str> {
        match self {
            Self::Hash(hash) => Some(hash),
            Self::Unbindable(_) => None,
        }
    }
}

/// `zap config validate` core — eval the config and run the machine-free gates (secret
/// well-formedness + structural integrity), returning the resource count for display.
///
/// No detection and no target: a pure config check, so it's the fast pre-flight an
/// operator (or CI) runs before a real `plan`/`apply`. It is not, however, cache-free —
/// it evals through the same L0 cache every other command does (see `eval_untargeted`),
/// which is what keeps it inside the shadow-mismatch observation rather than a private
/// path of its own. The only network it can touch is the eval sandbox's, which is denied.
///
/// It runs *the same seam* as every convergence role rather than its own copy of the
/// gates, so "passes `config validate`" and "clears the gates in `apply`" are the same
/// claim by construction — a well-formedness bug can't surprise `apply` later.
///
/// Deliberately **not** the env gate (`unresolved_env_message`): this check is meant
/// to run anywhere, including a CI job that holds no secrets, so requiring every
/// a reference to resolve would break its whole point. A config can pass here and still be
/// rejected by a wetrun for unset references — that gate belongs to the commands that
/// actually resolve them.
///
/// # Errors
/// Propagates config-eval ([`Error::ConfigEval`] / [`Error::ConfigParse`]), secret
/// validation (a hardcoded literal secret), and structural validation
/// ([`Error::Config`]).
///
/// [`Error::ConfigEval`]: crate::error::Error::ConfigEval
/// [`Error::ConfigParse`]: crate::error::Error::ConfigParse
/// [`Error::Config`]: crate::error::Error::Config
pub async fn run_config_validate(config_path: &Path, fgro: Option<&Path>) -> Result<usize> {
    run_config_validate_in(zap_home_default()?.as_deref(), fgro, config_path).await
}

/// `run_config_validate` with the `~/.zap` root injected — the L0 eval cache's root
/// (the hermetic test seam; `None` disables the cache for this run).
///
/// # Errors
/// Same as [`run_config_validate`].
pub async fn run_config_validate_in(
    zap_home: Option<&Path>,
    fgro: Option<&Path>,
    config_path: &Path,
) -> Result<usize> {
    // The whole command *is* the shared gates — `eval_untargeted` runs exactly the pair
    // every other core runs, so this can't check less (or more) than they do.
    let (config, _) = eval_untargeted(zap_home, fgro, config_path, PinFrom::Lock).await?;
    Ok(config.resources.len())
}

#[cfg(test)]
mod tests;
