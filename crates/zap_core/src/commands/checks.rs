//! The checks over a config and a plan — the structural gate, the env gate, the
//! unrunnable and unverifiable findings — and the verdict, refusal, and warning
//! banners the commands render from them.

use std::fmt::Write as _;

use zap_types::last_run::{PassLabel, PlanUnreviewed};
use zap_types::plan::{HeldResource, HoldCause, Plan};
use zap_types::schema::{ResourceId, ZapConfig};

use crate::error::{Error, Result};
use crate::escape::{escape_join, escape_line, render_block};
use crate::lock::LockStanding;
use crate::resolve::env_var;
use crate::secret::SecretMasker;

use super::Confirmation;

/// Reject a structurally-invalid config before any detection runs — the pure
/// pre-flight gate symmetric with the secret gate
/// ([`build_validated_masker`](crate::secret::build_validated_masker)); `config_gates`
/// is where the pair is run as one.
///
/// Catches duplicate resource ids, dangling `depends_on` / service `restart_on` /
/// `reload_on` / file-`triggers` references, a trigger on a service kept stopped, a
/// resource at or under zap's own state directory, dependency cycles, `pipeline` features
/// the sequential executor would silently drop, and a NUL byte in any resource, `target`,
/// or `deploy` string a shell, a path, or an argv would see (a shell drops it, running a
/// different command). Each is a
/// config bug that would
/// otherwise drop a dependency edge or a restart and **converge to a wrong state with
/// no error** — or, for a cycle/duplicate, emit an empty plan that reports "converged"
/// (exit 0). Pure (no IO), so every command runs it up front, before touching the
/// connection.
///
/// # Errors
/// [`Error::Config`] listing every structural problem found.
pub(super) fn validate_config_structure(config: &ZapConfig) -> Result<()> {
    let join = |ids: &[ResourceId]| {
        ids.iter()
            .map(|id| id.0.as_str())
            .collect::<Vec<_>>()
            .join(", ")
    };

    let mut errors = Vec::new();
    let duplicates = zap_types::validate::duplicate_resource_ids(&config.resources);
    if !duplicates.is_empty() {
        errors.push(format!("duplicate resource ids: {}", join(&duplicates)));
    }
    errors.extend(zap_types::validate::unusable_resource_ids(
        &config.resources,
    ));
    errors.extend(zap_types::validate::unresolved_references(
        &config.resources,
    ));
    errors.extend(zap_types::validate::triggers_on_stopped_services(
        &config.resources,
    ));
    errors.extend(zap_types::claim::conflicting_claims(&config.resources));
    errors.extend(zap_types::claim::zap_state_claims(
        &config.resources,
        config.deploy.as_ref().map(|deploy| deploy.path.as_str()),
    ));
    errors.extend(zap_types::validate::unsupported_pipeline_features(
        &config.resources,
    ));
    errors.extend(zap_types::validate::duplicate_pipeline_step_ids(
        &config.resources,
    ));
    errors.extend(zap_types::validate::unsupported_firewall_rules(
        &config.resources,
    ));
    errors.extend(zap_types::validate::empty_ssh_keys(&config.resources));
    errors.extend(zap_types::validate::managed_root_user(&config.resources));
    errors.extend(zap_types::validate::unsupported_file_validate(
        &config.resources,
    ));
    errors.extend(zap_types::validate::unmatched_template_vars(
        &config.resources,
    ));
    errors.extend(zap_types::validate::unfit_template_values(
        &config.resources,
    ));
    errors.extend(zap_types::validate::missing_firewall_persistence(
        &config.resources,
    ));
    errors.extend(zap_types::validate::missing_target_host(&config.target));
    errors.extend(zap_types::validate::nul_bytes(&config.resources));
    errors.extend(zap_types::validate::unusable_strings(config));
    errors.extend(zap_types::validate::unusable_pg_hba_fields(
        &config.resources,
    ));
    errors.extend(zap_types::validate::unusable_deploy_releases(
        config.deploy.as_ref(),
    ));
    errors.extend(zap_types::validate::config_nul_bytes(
        &config.target,
        config.deploy.as_ref(),
    ));
    errors.extend(zap_types::validate::unusable_deploy_path(
        config.deploy.as_ref(),
    ));
    errors.extend(zap_types::validate::unusable_deploy_shared(
        config.deploy.as_ref(),
    ));
    errors.extend(zap_types::validate::unusable_deploy_artifacts(
        config.deploy.as_ref(),
    ));
    errors.extend(zap_types::validate::reserved_env_names(&config.resources));
    errors.extend(zap_types::validate::unusable_working_directories(
        &config.resources,
    ));
    errors.extend(zap_types::validate::blank_health_domain(
        config.deploy.as_ref(),
    ));
    errors.extend(zap_types::validate::missing_service_manager(
        &config.resources,
        config.deploy.as_ref(),
        config.target.service_manager,
    ));
    if let Some(cycle) = zap_types::plan::dependency_cycle(&config.resources) {
        errors.push(format!(
            "dependency cycle: {} (the edges are `depends_on`, and a service runs after \
             each resource it `restart_on` / `reload_on` and each file that `triggers` it)",
            join(&cycle)
        ));
    }

    if errors.is_empty() {
        return Ok(());
    }
    Err(Error::Config(format!(
        "config has {} structural error(s):\n  - {}",
        errors.len(),
        escape_join(&errors, "\n  - ")
    )))
}

/// The unresolved-reference finding for a config, as an operator-facing message —
/// `None` when every referenced var resolves to a non-empty value.
///
/// The shared half of the fail-fast env gate, run by every command that *executes*
/// against a target (`apply` and `deploy`). Both consume the whole config with the
/// operator's env authority, so an unset reference is equally load-bearing for
/// either: `apply` bakes the empty string into a command / a written file / a `.env`
/// line, and `deploy` detects every apply-managed resource in its drift preflight
/// against the same empty-resolved desired state — manufacturing or masking drift.
///
/// The caller decides the severity, which is the whole point of returning a message
/// rather than a `Result`: a **wetrun** turns it into a hard error before any side effect.
///
/// On a **dry run** the right severity depends on whether the command *compares*
/// anything. `deploy`'s dry run doesn't (its drift preflight is wetrun-only), so its
/// output is sound and this is a true warning — a heads-up that a wetrun would be
/// rejected. `apply`'s dry run does compare, and there a warning would understate: the
/// changeset itself is unsound, so it reports the narrower [`unverifiable_refs`] verdict
/// instead.
pub(super) fn unresolved_env_message(config: &ZapConfig) -> Option<String> {
    let unresolved = crate::resolve::unresolved_env_vars(config, env_var);
    if unresolved.is_empty() {
        return None;
    }
    Some(format!(
        "{} environment variable(s) referenced by the config are unset or empty: {}\n  \
         provide them via --env-file or the environment before a wetrun \
         (an unset reference resolves to an empty string otherwise)",
        unresolved.len(),
        escape_join(&unresolved, ", ")
    ))
}

/// The wetrun preflight over a computed plan: every change whose command text a wetrun
/// would refuse to run ([`refused_changes`](crate::resource::refused_changes)) — a
/// reference resolving to a value its command can't take. Empty when the plan can run.
///
/// A **wetrun** turns a non-empty finding into a hard error before the lock write and
/// any change ([`unrunnable_message`]). A **preview** (`zap plan`, a dry `zap apply`)
/// appends it to its warnings ([`warn_unrunnable`]): the comparison and the plan are
/// sound — the reference is inert in both — so this is the narrative kind of finding, a
/// heads-up that the wetrun of this plan will be refused, not a verdict on the plan.
pub(super) fn unrunnable_changes(plan: &Plan) -> Vec<String> {
    crate::resource::refused_changes(plan)
}

/// The error a wetrun stops with when its plan holds [`unrunnable_changes`].
pub(super) fn unrunnable_message(unrunnable: &[String]) -> String {
    format!(
        "{} change(s) can't be run, so nothing was changed:\n  {}",
        unrunnable.len(),
        escape_join(unrunnable, "\n  ")
    )
}

/// Append a preview's [`unrunnable_changes`] to its warnings.
pub(super) fn warn_unrunnable(warnings: &mut Vec<String>, unrunnable: Vec<String>) {
    warnings.extend(
        unrunnable
            .into_iter()
            .map(|finding| format!("a wetrun of this plan will be refused — {finding}")),
    );
}

/// The refs blocking a faithful comparison for this config — the `unverifiable` verdict's
/// finding, empty when the diff can be trusted.
///
/// Every command that **compares** declared state against a live target (`detect`,
/// `plan`, and `apply`'s dry run) computes this and reports it, because they share the
/// one detection path that resolves references into the desired side. A wetrun never sees
/// it non-empty: [`unresolved_env_message`]'s blanket gate is a superset and rejects
/// first.
pub(super) fn unverifiable_refs(config: &ZapConfig) -> Vec<String> {
    crate::resolve::unverifiable_env_vars(config, env_var)
}

/// Render the `unverifiable` verdict — the banner that tells an operator the changeset
/// below it is not evidence. No-op when `refs` is empty.
///
/// Deliberately **not** a `warning:` line at the foot of the report: a warning frames the
/// output as sound with an aside, and here the output is the thing in doubt. It leads.
pub(super) fn render_unverifiable(out: &mut String, refs: &[String]) {
    if refs.is_empty() {
        return;
    }
    let _ = writeln!(
        out,
        "  UNVERIFIABLE — {} referenced variable(s) are unset or empty, so this comparison \
         cannot be trusted:\n      {}\n  \
         an unset reference resolves to an empty string, which can both hide real drift and \
         invent drift that isn't there.\n  \
         provide them (--env-file or the environment) and re-run.",
        refs.len(),
        escape_join(refs, ", ")
    );
}

/// A command's wording for the two refusals that read its own record.
pub(super) struct RefusalText {
    /// The sentence for a host with nothing recorded.
    pub no_preview: &'static str,
    /// What the plan is computed from — what moved when it differs from the preview.
    pub moved: &'static str,
}

/// `apply`'s refusal wording.
pub(super) const APPLY_REFUSAL: RefusalText = RefusalText {
    no_preview: "no plan has been previewed on this host.",
    moved: "the config, the target, or the user the run connects as",
};

/// Render a wetrun's refusal — the banner under the plan it rendered instead of running,
/// set apart from the plan by a blank line, and the reason the plan has no review, in
/// the command's wording (`text`).
///
/// The banner says what follows for this run, and nothing about a review the reason
/// may say never happened: refused with no question asked, asked at the prompt, or
/// declined there (`confirmation`). The reason line under it says why, so each banner
/// reads true over each reason. The caller follows a refusal with its own command's way
/// to bind the next wetrun, and a question with the question.
pub(super) fn render_refused<P: PassLabel, N: PassLabel>(
    out: &mut String,
    reason: &PlanUnreviewed<P, N>,
    text: &RefusalText,
    confirmation: Option<Confirmation>,
) {
    let banner = match confirmation {
        None | Some(Confirmation::Accepted) => "REFUSED — nothing ran: this plan was not reviewed.",
        Some(Confirmation::Asking) => {
            "UNREVIEWED — nothing has run: this plan runs only once it is confirmed below."
        }
        Some(Confirmation::Declined) => "DECLINED — nothing ran: this plan was not confirmed.",
    };
    let _ = writeln!(out, "\n  {banner}");
    match reason {
        PlanUnreviewed::Expected { expected } => {
            let _ = writeln!(
                out,
                "    --expect-plan {} is not this plan's hash.",
                escape_line(expected)
            );
        }
        PlanUnreviewed::NoPreview { prior: None } => {
            let _ = writeln!(out, "    {}", text.no_preview);
        }
        PlanUnreviewed::NoPreview {
            prior: Some(command),
        } => {
            let _ = writeln!(
                out,
                "    the last run on this host ({}) previewed no plan.",
                command.label()
            );
        }
        PlanUnreviewed::Changed {
            reviewed,
            command,
            ran_at,
        } => {
            let _ = writeln!(
                out,
                "    the last preview ({} at {}) planned {}; {} changed since.",
                command.label(),
                escape_line(ran_at),
                escape_line(reviewed),
                text.moved
            );
        }
    }
}

/// The `warning:` lines at the foot of a report.
pub(super) fn render_warnings(out: &mut String, warnings: &[String]) {
    for warning in warnings {
        render_block(out, "warning: ", warning);
    }
}

/// What a comparing command's `LOCK` banner says follows from a pin the ledger doesn't
/// answer for: its resource is left out of the comparison rendered under the banner.
pub(super) const LOCK_WITHHELD_FROM_COMPARISON: &str =
    "so they are withheld from the comparison below";

/// Render the `lock` standing — the banner that tells an operator the ledger doesn't
/// answer for part of this config, so those resources were **withheld** from the
/// comparison below. No-op when every eligible pin is current (orphans alone stay
/// silent here; `zap lock --check` is where they're reported). `so` is the clause that
/// says what follows from that for the command at hand
/// ([`LOCK_WITHHELD_FROM_COMPARISON`] for the ones that compare).
///
/// It leads for the same reason [`render_unverifiable`] and [`render_undetermined`] do,
/// and it leads *them*: a withheld pin is the **cause** of the undetermined resource
/// they describe, and it's the one an operator can act on (`zap update <id>`).
pub(super) fn render_lock_standing(out: &mut String, standing: &LockStanding, so: &str) {
    if !standing.has_errors() {
        return;
    }
    let _ = writeln!(
        out,
        "  LOCK — the pin ledger does not answer for {} resource(s), {so}:",
        standing.error_count()
    );
    for id in &standing.missing {
        let id = escape_line(id);
        let _ = writeln!(out, "      {id} — no pin yet; run `zap update {id}`");
    }
    for id in &standing.stale {
        let id = escape_line(id);
        let _ = writeln!(
            out,
            "      {id} — stale: the config changed since the pin was minted; run \
             `zap update {id}`"
        );
    }
    for entry in &standing.unverifiable {
        let _ = writeln!(
            out,
            "      {} — cannot be verified: unset {}, which its url/path address depends on; \
             set it (the env the pin was minted with) and re-run",
            escape_line(&entry.id),
            escape_join(&entry.vars, ", ")
        );
    }
}

/// Mask a report's operator-facing **narrative** — the `warnings` lines and each
/// undetermined resource's `reason`.
///
/// Both are engine-authored prose, but they interpolate values the engine resolved or
/// read back: a detector's `Undetermined` reason carries the seam-resolved path or
/// identifier the probe failed on, and a deploy warning carries a failed remote command's
/// stderr. Execution surfaces are already covered ([`mask_outcomes`] for the batch report,
/// the event [`mask_handler`] for the stream); the narrative ones were the last strings
/// leaving the engine unmasked. Same posture as those: mask at the consumption boundary,
/// so the producers stay masking-unaware. A hold behind another names only resource
/// ids, which the config declares, so it has nothing to mask.
///
/// [`mask_outcomes`]: crate::secret::mask_outcomes
/// [`mask_handler`]: crate::event::mask_handler
pub(super) fn mask_diagnostics(
    masker: &SecretMasker,
    warnings: &mut [String],
    held: &mut [HeldResource],
) {
    for warning in warnings.iter_mut() {
        *warning = masker.mask(warning);
    }
    for entry in held.iter_mut() {
        if let HoldCause::Undetermined { reason } = &mut entry.cause {
            *reason = masker.mask(reason);
        }
    }
}

/// The empty-changeset line, which must not say "converged" when part of the target
/// couldn't be read — that claim is exactly what the [`render_undetermined`] banner above
/// it is retracting.
pub(super) const fn empty_changeset_line(held: &[HeldResource]) -> &'static str {
    if held.is_empty() {
        "  (no changes — converged)"
    } else {
        "  (no changes among the resources that could be probed — see UNDETERMINED above)"
    }
}

/// Render the `undetermined` verdict — the banner that tells an operator the changeset
/// below it is **partial**. No-op when `held` is empty.
///
/// The observed-side sibling of [`render_unverifiable`], and it leads for the same
/// reason: a held resource contributes no change, so an unprobeable target renders an
/// empty changeset that reads exactly like a converged one. The verdict has to outrank
/// the changeset, not trail it as a `warning:` line, where it would be
/// indistinguishable from "you have uncommitted changes".
///
/// The resources detection couldn't read come first, each with why; those held behind
/// them follow under their own line, each with what it waits on or would trigger.
pub(super) fn render_undetermined(out: &mut String, held: &[HeldResource]) {
    if held.is_empty() {
        return;
    }
    let (roots, behind): (Vec<&HeldResource>, Vec<&HeldResource>) =
        held.iter().partition(|entry| entry.is_undetermined());
    let _ = writeln!(
        out,
        "  UNDETERMINED — {} resource(s) could not be probed, so no change is planned for \
         them and this changeset is partial:",
        roots.len()
    );
    let render_entries = |out: &mut String, entries: &[&HeldResource]| {
        for entry in entries {
            let lead = format!("      {} — ", escape_line(&entry.resource_id.0));
            render_block(out, &lead, &entry.describe());
        }
    };
    render_entries(out, &roots);
    let _ = writeln!(
        out,
        "  their live state is unknown: neither converged nor drifted. resolve the probe \
         failure and re-run."
    );
    if !behind.is_empty() {
        let _ = writeln!(
            out,
            "  held behind them — {} resource(s) can't change until they do:",
            behind.len()
        );
        render_entries(out, &behind);
    }
}
