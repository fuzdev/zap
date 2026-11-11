//! `zap plan` — the plan fact (diff desired against detected).
//!
//! The convergence *role* one tier above the `detect` stage inspector: where
//! `detect` renders raw detected state, `plan` runs the same detection then diffs
//! it against the config to emit the content-addressed changeset (the plan fact)
//! plus its `plan_hash`. Runs against a local or SSH target. Like `detect`, its pass
//! writes the last-run report. `apply` (dry-run/converge) reuses this same load →
//! detect → diff pipeline.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::Path;

use zap_types::detected::Detection;
use zap_types::diff_view::{DiffChange, DiffLine, diff_view};
use zap_types::last_run::RunCommand;
use zap_types::plan::{Change, ChangeAction, HeldResource, Plan};
use zap_types::schema::{ResourceId, ZapConfig};

use super::preview::RecordedPreview;
use super::{
    Diffed, PassContext, PlanAddress, detect_and_diff, eval_target, render_trigger,
    resolve_machine, target_location,
};
use crate::connection::Connection;
use crate::error::Result;
use crate::escape::escape_line;
use crate::home::zap_home_default;
use crate::lock::{LockStanding, inspect_lock};
use crate::resolve::env_var;

/// The plan fact and the context needed to render it. Returned by `run_plan`; the
/// binary renders it via [`render_plan`].
#[derive(Debug, Clone)]
pub struct PlanReport {
    /// Target location label (`local`, or a host).
    pub target: String,
    /// The ordered, mutation-only changeset, with the machine it is for.
    pub plan: Plan,
    /// Content address of the whole plan (blake3 over its canonical JSON) — or, for a
    /// config whose target names no one machine, why it has none.
    pub plan_hash: PlanAddress,
    /// Why the pass left no last-run report, when it left none: the target's host is a
    /// masking token (`unidentified_host_message`).
    pub unrecorded: Option<String>,
    /// Non-fatal diagnostics (cycle fallbacks, dangling trigger references).
    pub warnings: Vec<String>,
    /// The observed `before` state per resource — the `--diff` join's left side,
    /// joined against each `Change.desired` at render time — with every registered
    /// secret masked out of its text. In-memory only: never serialized, hashed, or
    /// persisted (the plan fact stays observed-free).
    pub detected: BTreeMap<ResourceId, Detection>,
    /// Referenced vars the comparison needed but couldn't resolve. Non-empty means the
    /// `plan` above is **not** evidence — it may hide drift or invent it.
    pub unverifiable: Vec<String>,
    /// Resources whose live state couldn't be probed, so no change was planned for them.
    /// Non-empty means the `plan` above is **partial** — the observed-side counterpart of
    /// [`unverifiable`](Self::unverifiable).
    pub held: Vec<HeldResource>,
    /// How the config's tracked pins stand against `zap.lock`. A non-current pin is
    /// withheld from detection, so an entry here is normally *why* its resource is
    /// [`held`](Self::held) — and it's the standing an operator can act on.
    pub lock_standing: LockStanding,
    /// The preview this pass was recorded as, when it was: what the binary withdraws
    /// when the report never arrives ([`RecordedPreview::withdraw`]).
    pub preview: Option<RecordedPreview>,
}

/// A plan only answers.
impl super::Delivered for PlanReport {
    fn exit_code(&self) -> u8 {
        Self::exit_code(self)
    }
    fn changed(&self) -> bool {
        false
    }
    fn preview(&self) -> Option<&RecordedPreview> {
        self.preview.as_ref()
    }
}

impl PlanReport {
    /// Process exit code: `1` when the comparison was **unverifiable**, any resource was
    /// **held** (unprobeable), or the **lock standing** has errors; else `0`.
    ///
    /// `plan` doesn't use the drift code (it reports the changeset; deciding is the
    /// caller's job), but it must not exit `0` on a diff it couldn't compute faithfully —
    /// that reads as "here is the answer." Both verdicts break that faithfulness from
    /// opposite sides: `unverifiable` is a desired side that couldn't be built, `held` a
    /// live side that couldn't be read. Mirrors `lock --check`'s unverifiable → `1`.
    ///
    /// The lock check is belt and braces: withholding a non-current pin already leaves
    /// its resource `held`, so the standing has no code of its own to contribute — but
    /// the exit code is the one thing a script reads, and it must not depend on a
    /// detector's choice to hold. `apply`'s `Error::LockStale` / `LockUnverifiable` stay
    /// exit 2 (an error, not a verdict); a read-only command exits 1, with the rest of
    /// the not-established family.
    #[must_use]
    pub fn exit_code(&self) -> u8 {
        u8::from(
            !self.unverifiable.is_empty()
                || !self.held.is_empty()
                || self.lock_standing.has_errors(),
        )
    }
}

/// Plan role — eval the config, detect live state, and diff to the plan fact.
///
/// Uses the default `~/.zap`. `no_cache` (`--no-cache`) forces a fresh config eval,
/// bypassing the L0 eval cache.
///
/// `bootstrap` connects as the target's `bootstrap_user` (the `--bootstrap` switch) — the
/// initial provisioning run before SSH hardening creates the primary user.
///
/// # Errors
/// Propagates config-eval, secret-validation (a literal secret in the config), and
/// detection failures (including SSH connectivity for a remote target), or a
/// plan-hashing failure.
pub async fn run_plan(
    config_path: &Path,
    fgro: Option<&Path>,
    no_cache: bool,
    bootstrap: bool,
) -> Result<PlanReport> {
    run_plan_in(
        zap_home_default()?.as_deref(),
        fgro,
        config_path,
        no_cache,
        bootstrap,
    )
    .await
}

/// `run_plan` with the `~/.zap` root injected (the hermetic test seam).
///
/// `None` turns off the eval cache, the content cache, and the last-run report.
/// `bootstrap` selects the target's `bootstrap_user` as the connecting identity.
///
/// # Errors
/// Same as [`run_plan`].
pub async fn run_plan_in(
    zap_home: Option<&Path>,
    fgro: Option<&Path>,
    config_path: &Path,
    no_cache: bool,
    bootstrap: bool,
) -> Result<PlanReport> {
    // The plan fact is a shareable artifact (CI / `--diff` / content address), so the
    // seam's secret gate matters here: a hardcoded literal secret is rejected before it
    // can be rendered into a `PlanStep`. The masker it builds is kept — the fact itself
    // needs none (every desired value stays inert), but a held resource's `reason` is
    // detector prose carrying the seam-resolved value the probe failed on.
    let (config, conn, masker) =
        eval_target(config_path, zap_home, fgro, no_cache, bootstrap).await?;
    let ctx = PassContext {
        zap_home,
        config_path,
        masker: &masker,
        bootstrap,
    };
    plan_over(&conn, &config, ctx).await
}

/// Plan an evaluated, gated `config` over `conn`: [`run_plan_in`] past the config eval
/// and the connection bind — the seam the mock-driven tests enter.
///
/// # Errors
/// Same as [`run_plan`], less the config eval's — each masked by the run's masker.
pub(crate) async fn plan_over(
    conn: &Connection,
    config: &ZapConfig,
    ctx: PassContext<'_>,
) -> Result<PlanReport> {
    super::masking_errors(ctx.masker, plan_unmasked(conn, config, ctx)).await
}

/// [`plan_over`], its errors as they were raised.
async fn plan_unmasked(
    conn: &Connection,
    config: &ZapConfig,
    ctx: PassContext<'_>,
) -> Result<PlanReport> {
    let PassContext {
        config_path,
        masker,
        bootstrap,
        ..
    } = ctx;

    // Source the lock **on-disk only** (no cold-start mint), like `detect` — `plan` is a
    // read-only role and must stay offline-faithful: it never does network IO, so a
    // cold-start tracked `remote_file` with no on-disk pin reads `Undetermined` (held in
    // the diff) rather than silently fetching. Minting belongs to `apply` / `zap lock`.
    // What it *does* do is validate: a stale or unverifiable pin is withheld, so it
    // behaves like a missing one instead of silently comparing against a pin the ledger
    // can't vouch for (a stale pin still matches the target's old bytes, so `plan`
    // would print "converged" while `apply` refused to run).
    let (lock, lock_standing) = inspect_lock(config, config_path, env_var)?;

    // The diff below resolves references into its desired side, so an unset reference
    // makes the result untrustworthy rather than merely incomplete — reported as a
    // verdict, not a footnote.
    let unverifiable = super::unverifiable_refs(config);

    let machine = resolve_machine(config, masker, bootstrap)?;
    let Diffed {
        result,
        detected,
        plan_hash: hash,
        recorded: preview,
        ..
    } = detect_and_diff(conn, config, ctx, &machine, lock.as_ref(), RunCommand::Plan).await?;
    let unrecorded = machine.unidentified_host;
    let (mut warnings, mut held) = (result.warnings, result.held);
    super::mask_diagnostics(masker, &mut warnings, &mut held);
    // The observed side is what the target holds, which can be a secret's resolved
    // value (a link pointing into a path named for one): masked as `detect` masks it.
    let detected = detected
        .into_iter()
        .map(|(id, detection)| (id, detection.map_text(|text| masker.mask(text))))
        .collect();
    super::warn_unrunnable(&mut warnings, super::unrunnable_changes(&result.plan));

    Ok(PlanReport {
        target: target_location(&config.target),
        unverifiable,
        held,
        lock_standing,
        plan: result.plan,
        plan_hash: hash,
        unrecorded,
        warnings,
        detected,
        preview,
    })
}

/// Render a [`PlanReport`] to the text shown by `zap plan`.
#[must_use]
pub fn render_plan(report: &PlanReport) -> String {
    let mut out = String::new();
    super::render_lock_standing(
        &mut out,
        &report.lock_standing,
        super::LOCK_WITHHELD_FROM_COMPARISON,
    );
    super::render_unverifiable(&mut out, &report.unverifiable);
    super::render_undetermined(&mut out, &report.held);
    let changes = &report.plan.changes;

    let creates = changes
        .iter()
        .filter(|c| c.action == ChangeAction::Create)
        .count();
    let updates = changes
        .iter()
        .filter(|c| c.action == ChangeAction::Update)
        .count();
    let _ = writeln!(
        out,
        "plan — target {} ({} change(s): +{creates} ~{updates})",
        escape_line(&report.target),
        changes.len()
    );
    super::render_plan_subject(&mut out, &report.target, &report.plan);

    for change in changes {
        super::render_change(&mut out, change);
    }
    if changes.is_empty() {
        let _ = writeln!(out, "{}", super::empty_changeset_line(&report.held));
    }

    super::render_warnings(&mut out, &report.warnings);
    super::render_unrecorded(&mut out, report.unrecorded.as_deref());
    super::render_address(&mut out, &report.plan_hash);
    out
}

/// Render a [`PlanReport`] as the `zap plan --diff` view: the `zap plan` view with
/// each drifted update's `current → desired` attribute lines above its steps.
///
/// The join is the observed [`Detection`] (`report.detected`, already masked by the
/// run's masker) against each `Change.desired` via the pure [`diff_view`]. It resolves
/// no reference — every desired value is shown inert, exactly as the dry-run preview
/// shows refs verbatim — so a secret can surface only on the observed side, and that
/// side is masked where the report is built. Every change renders its steps; an update
/// with observed drift renders the attribute diff above them, and a create or an
/// update with no drift (a converged service promoted by a fired trigger) has none
/// (`render_change_diff`).
#[must_use]
pub fn render_plan_diff(report: &PlanReport) -> String {
    let mut out = String::new();
    super::render_lock_standing(
        &mut out,
        &report.lock_standing,
        super::LOCK_WITHHELD_FROM_COMPARISON,
    );
    super::render_unverifiable(&mut out, &report.unverifiable);
    super::render_undetermined(&mut out, &report.held);
    let changes = &report.plan.changes;

    let creates = changes
        .iter()
        .filter(|c| c.action == ChangeAction::Create)
        .count();
    let updates = changes
        .iter()
        .filter(|c| c.action == ChangeAction::Update)
        .count();
    let _ = writeln!(
        out,
        "plan diff — target {} ({} change(s): +{creates} ~{updates})",
        escape_line(&report.target),
        changes.len()
    );
    super::render_plan_subject(&mut out, &report.target, &report.plan);

    for change in changes {
        render_change_diff(&mut out, change, report.detected.get(&change.resource_id));
    }
    if changes.is_empty() {
        let _ = writeln!(out, "{}", super::empty_changeset_line(&report.held));
    }

    super::render_warnings(&mut out, &report.warnings);
    super::render_unrecorded(&mut out, report.unrecorded.as_deref());
    super::render_address(&mut out, &report.plan_hash);
    out
}

/// Render one change's diff: the shared `[+/~] id (kind)` header, its trigger line,
/// what it declares (`render_declared`), the attribute diff of a drifted update, then
/// the file zap installs ahead of its steps and the steps — every change's, as `zap
/// plan` prints them.
///
/// The steps follow the diff rather than standing in for it: the diff names only what
/// drifted, and a field that hasn't — a user's groups or keys, a firewall's rules — is
/// on screen only in the steps that apply it. The plan's hash covers both, so the view
/// that prints the hash prints both.
fn render_change_diff(out: &mut String, change: &Change, detection: Option<&Detection>) {
    super::render_change_header(out, change);
    if let Some(trigger) = &change.trigger {
        render_trigger(out, trigger);
    }
    super::render_declared(out, &change.desired);
    if let Some(Detection::Drifted { current }) = detection {
        for line in diff_view(current, &change.desired.kind) {
            write_diff_line(out, &line);
        }
    }
    super::render_native_puts(out, change);
    super::render_steps(out, change);
}

/// Render one [`DiffLine`] as an indented `~`/`+`/`-` attribute line. An attribute is
/// one line: its label and its observed and desired values are each escaped, a newline
/// in one included.
fn write_diff_line(out: &mut String, line: &DiffLine) {
    let label = escape_line(&line.label);
    let _ = match &line.change {
        DiffChange::Update { from, to } => writeln!(
            out,
            "      ~ {label}: {} → {}",
            escape_line(from),
            escape_line(to)
        ),
        DiffChange::Replace { to } => {
            writeln!(out, "      ~ {label}: differs → {}", escape_line(to))
        }
        DiffChange::Add { to } => writeln!(out, "      + {label} {}", escape_line(to)),
        DiffChange::Remove { detail } => {
            writeln!(out, "      - {label} ({})", escape_line(detail))
        }
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    use zap_types::detected::{CurrentState, UserDrift};
    use zap_types::plan::{PlanStep, Trigger, TriggerKind};
    use zap_types::schema::Resource;

    use crate::test_support::local_machine;

    fn resource(json: serde_json::Value) -> Resource {
        serde_json::from_value(json).unwrap()
    }

    fn report(changes: Vec<Change>, detected: BTreeMap<ResourceId, Detection>) -> PlanReport {
        PlanReport {
            preview: None,
            target: "local".to_owned(),
            plan: Plan {
                references: BTreeMap::new(),
                changes,
                target: serde_json::from_value(serde_json::json!({"local": true})).unwrap(),
                machine: local_machine(),
            },
            plan_hash: PlanAddress::Hash("deadbeef".to_owned()),
            unrecorded: None,
            warnings: Vec::new(),
            detected,
            unverifiable: Vec::new(),
            held: Vec::new(),
            lock_standing: LockStanding::default(),
        }
    }

    #[test]
    fn diff_render_branches_on_create_drift_and_trigger() {
        // Every change renders its steps; a drifted update renders attribute lines above
        // them; an update with no observed drift (a trigger-promoted converged service)
        // has no attribute diff, so it shows its trigger line + steps — the same shape
        // the non-diff plan view shows.
        let create = Change {
            resource_id: ResourceId("pkg".to_owned()),
            action: ChangeAction::Create,
            steps: vec![PlanStep::run("sudo apt-get install -y git")],
            desired: resource(
                serde_json::json!({"id": "pkg", "type": "package", "from": {"apt": "git"}}),
            ),
            depends_on: Vec::new(),
            trigger: None,
        };
        let drifted = Change {
            resource_id: ResourceId("u".to_owned()),
            action: ChangeAction::Update,
            steps: Vec::new(),
            desired: resource(
                serde_json::json!({"id": "u", "type": "user", "username": "u", "shell": "/bin/bash"}),
            ),
            depends_on: Vec::new(),
            trigger: None,
        };
        let promoted = Change {
            resource_id: ResourceId("svc".to_owned()),
            action: ChangeAction::Update,
            steps: vec![PlanStep::run("sudo systemctl restart svc")],
            desired: resource(
                serde_json::json!({"id": "svc", "type": "service", "service": "svc", "enabled": true}),
            ),
            depends_on: Vec::new(),
            trigger: Some(Trigger {
                kind: TriggerKind::Restart,
                sources: vec![ResourceId("unit".to_owned())],
                pending: false,
            }),
        };

        let mut detected = BTreeMap::new();
        detected.insert(
            ResourceId("u".to_owned()),
            Detection::Drifted {
                current: CurrentState::User {
                    drift: UserDrift {
                        shell: Some("/bin/sh".to_owned()),
                        ..UserDrift::default()
                    },
                },
            },
        );
        // The promoted service was converged — its update came from a fired trigger.
        detected.insert(ResourceId("svc".to_owned()), Detection::Converged);

        let out = render_plan_diff(&report(vec![create, drifted, promoted], detected));
        assert!(out.contains("plan diff — target local (3 change(s): +1 ~2)"));
        // create → steps
        assert!(out.contains("  [+] pkg  (package)"));
        assert!(out.contains("      > sudo apt-get install -y git"));
        // drifted update → attribute diff
        assert!(out.contains("  [~] u  (user)"));
        assert!(out.contains("      ~ shell: /bin/sh → /bin/bash"));
        // trigger-promoted update → trigger line + steps, but no `~`/`+`/`-` attribute
        // diff (there was no observed drift to join).
        assert!(out.contains("  [~] svc  (service)"));
        assert!(out.contains("      (triggered restart)"));
        assert!(out.contains("      > sudo systemctl restart svc"));
        assert!(!out.contains("~ enabled"));
    }

    /// An absent user with an attribute under its home: the plan and `--diff` both
    /// print the owner change its creation runs, built by the planner itself.
    #[test]
    fn a_created_users_home_owner_change_renders() {
        let user = resource(
            serde_json::json!({"id": "u", "type": "user", "username": "deploy", "home_mode": "750"}),
        );
        let mut detected = BTreeMap::new();
        detected.insert(ResourceId("u".to_owned()), Detection::Absent);
        let planned = zap_types::plan::diff(zap_types::plan::DiffInputs {
            resources: std::slice::from_ref(&user),
            detected: &detected,
            target: &serde_json::from_value(serde_json::json!({"local": true})).unwrap(),
            machine: &local_machine(),
            lock: None,
            pending: &BTreeMap::new(),
            var: &zap_types::last_run::ReportVar::unset,
        });
        let report = report(planned.plan.changes, detected);
        let chown = "> sudo chown -h -- 'deploy:' '/home/deploy'\n";
        let plan = render_plan(&report);
        assert!(plan.contains(chown), "{plan}");
        let diff = render_plan_diff(&report);
        assert!(diff.contains(chown), "{diff}");
    }

    /// `--diff` prints a change's `name` and a pipeline's steps as the plan does: under
    /// the header, above the attribute diff of a drifted update and every change's
    /// steps. A drifted update's steps follow its diff, so what didn't drift — the
    /// user's group — is on screen too.
    #[test]
    fn diff_render_shows_the_name_and_a_pipelines_steps() {
        let drifted = Change {
            resource_id: ResourceId("u".to_owned()),
            action: ChangeAction::Update,
            steps: vec![
                PlanStep::run("sudo usermod -s '/bin/bash' -- 'u'"),
                PlanStep::run("sudo usermod -aG 'docker' -- 'u'"),
            ],
            desired: resource(serde_json::json!({
                "id": "u", "name": "The app user", "type": "user", "username": "u",
                "shell": "/bin/bash", "groups": ["docker"],
            })),
            depends_on: Vec::new(),
            trigger: None,
        };
        let pipeline = Change {
            resource_id: ResourceId("release".to_owned()),
            action: ChangeAction::Create,
            steps: vec![PlanStep::run("./migrate up"), PlanStep::run("make")],
            desired: resource(serde_json::json!({
                "id": "release", "type": "pipeline",
                "steps": [
                    {"id": "migrate", "name": "Run migrations", "run": "./migrate up"},
                    {"id": "build", "run": "make"},
                ],
            })),
            depends_on: Vec::new(),
            trigger: None,
        };
        let mut detected = BTreeMap::new();
        detected.insert(
            ResourceId("u".to_owned()),
            Detection::Drifted {
                current: CurrentState::User {
                    drift: UserDrift {
                        shell: Some("/bin/sh".to_owned()),
                        ..UserDrift::default()
                    },
                },
            },
        );
        let out = render_plan_diff(&report(vec![drifted, pipeline], detected));
        assert!(
            out.contains(
                "  [~] u  (user)\n      name: The app user\n      ~ shell: /bin/sh → \
                 /bin/bash\n      > sudo usermod -s '/bin/bash' -- 'u'\n      > sudo usermod \
                 -aG 'docker' -- 'u'\n  [+] release"
            ),
            "{out}"
        );
        assert!(
            out.contains(
                "  [+] release  (pipeline)\n      step: migrate\n      step name: Run \
                 migrations\n      step: build\n      > ./migrate up\n      > make\n"
            ),
            "{out}"
        );
    }

    /// A key that isn't its pin's bytes renders as the key line the apply replaces,
    /// with the pin it installs, then the install of the key under it, as `zap plan`
    /// prints it.
    #[test]
    fn a_drifted_apt_key_renders_the_pin_it_installs() {
        let pin = "ab".repeat(32);
        let change = Change {
            resource_id: ResourceId("pgdg".to_owned()),
            action: ChangeAction::Update,
            steps: Vec::new(),
            desired: resource(serde_json::json!({
                "id": "pgdg", "type": "apt_repo", "key_url": "https://e.x/key.asc",
                "key_blake3": pin, "source": "deb https://e.x/apt stable main",
            })),
            depends_on: Vec::new(),
            trigger: None,
        };
        let mut detected = BTreeMap::new();
        detected.insert(
            ResourceId("pgdg".to_owned()),
            Detection::Drifted {
                current: CurrentState::AptRepo {
                    drift: zap_types::detected::AptRepoDrift::KeyDiffers,
                },
            },
        );
        let out = render_plan_diff(&report(vec![change], detected));
        assert!(out.contains("  [~] pgdg  (apt_repo)\n"), "{out}");
        assert!(out.contains(&format!("      pin: blake3 {pin}\n")), "{out}");
        assert!(
            out.contains(&format!(
                "      ~ signing key: differs → blake3 {pin}\n      = put \
                 /usr/share/keyrings/pgdg.asc  (mode 644, owner root:root, as root)\n"
            )),
            "{out}"
        );
    }
}
