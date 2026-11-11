//! `zap status` — the last run, offline.
//!
//! Evals the config to enumerate the declared resources, reads the last-run report the
//! most recent detection pass wrote for the target's host (`crate::last_run`), and joins
//! the two: each declared resource's verdict as of that run, flagged when its config has
//! changed since, plus the declared resources the run didn't read and the ones it read
//! that are no longer declared. Offline: no SSH, no probing. It loads the **on-disk**
//! lock (no network resolve) so a tracked `remote_file`'s folded pin recomputes its
//! hash, and classifies it while it's there — a stale pin is a lock problem, and saying
//! "config changed since" about it would point the operator at the wrong fix.
//! `run_status` returns a [`StatusReport`]; the binary renders it via [`render_status`]
//! and owns stdout.
//!
//! Everything it reports is as of the last run, which every render says, with when and
//! by which command it was taken: `status` never claims what the target is now.

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::path::Path;

use zap_types::last_run::{
    LastRun, ReportVar, RunCommand, Verdict, desired_hash, host_label, target_hash,
};
use zap_types::lock::ZapLock;
use zap_types::schema::{ResourceId, ResourceType, ZapConfig};

use super::{PinFrom, eval_untargeted, target_location, unidentified_host_message};
use crate::error::Result;
use crate::escape::{escape_join, escape_line, render_block};
use crate::home::zap_home_default;
use crate::last_run::{read_last_run, report_var};
use crate::lock::{LockStanding, inspect_lock};
use crate::resolve::env_var;
use crate::secret::SecretMasker;

/// Where one resource stands as of the last run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Standing {
    /// Read in the last run, with the config it has now.
    Read(Verdict),
    /// Read in the last run, but its config has changed since (the resource was edited,
    /// a variable it references resolves differently, its lock pin moved, or the
    /// target it was read against changed) — the verdict predates the change, so it says
    /// nothing about the resource as declared.
    ChangedSince(Verdict),
    /// Declared, but not in the last run — added since, or there is no last run.
    NotInLastRun,
    /// In the last run, but no longer declared.
    Orphaned(Verdict),
}

/// One resource's line.
#[derive(Debug, Clone)]
pub struct ResourceStatus {
    /// The resource id.
    pub id: ResourceId,
    /// The declared kind, when still in the config; orphans have none.
    pub kind: Option<ResourceType>,
    /// Where it stands as of the last run.
    pub standing: Standing,
    /// Whether the run recorded it as referencing a secret: its recorded hash takes the
    /// secret as a token, so a changed secret value since the run isn't visible here.
    pub references_secret: bool,
}

/// When, how, and where the last run was taken.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LastRunInfo {
    /// When the pass finished, RFC 3339 UTC.
    pub ran_at: String,
    /// The command pass that took it.
    pub command: RunCommand,
    /// The plan the pass computed, when it planned — the reviewed plan a wetrun binds
    /// to when the pass previewed it ([`RunCommand::previews_plan`]).
    pub plan_hash: Option<String>,
    /// The references the run's comparison couldn't resolve — non-empty means its
    /// verdicts aren't evidence.
    pub unverifiable: Vec<String>,
}

/// The offline status report. Returned by `run_status`; rendered by the binary.
#[derive(Debug, Clone)]
pub struct StatusReport {
    /// Target location label (`local`, a host, or an unresolved reference).
    pub target: String,
    /// Declared package manager, for the header.
    pub package_manager: Option<String>,
    /// Declared service manager, for the header.
    pub service_manager: Option<String>,
    /// The host the last run is looked up by ([`host_label`]) — `local`, or the remote
    /// host with its references resolved and a secret one as its token. `None`
    /// when the target's host doesn't resolve (an unset reference), so no report can be
    /// found.
    pub host: Option<String>,
    /// Why no last run is kept for this target, when none is: its host resolves through
    /// a masked reference, so [`host`](Self::host) is a token every machine behind the
    /// reference shares and a report under it would be any of theirs. No report is
    /// written for such a host and none is read.
    pub unidentified: Option<String>,
    /// The last run on [`host`](Self::host), or `None` when there is none.
    pub last_run: Option<LastRunInfo>,
    /// The references the config's comparison needs that don't resolve here and now —
    /// each resource's hash is recomputed with them empty, so "unchanged since" can't be
    /// established for what they feed.
    pub unverifiable: Vec<String>,
    /// Whether the target (`zap.target(...)`) differs from the one the last run read — a
    /// changed manager, home, user, or anything else it declares. Every verdict then
    /// predates it, so every declared resource the run read is
    /// [`ChangedSince`](Standing::ChangedSince).
    pub target_changed: bool,
    /// The declared resources in config order, then the orphans.
    pub resources: Vec<ResourceStatus>,
    /// How the config's tracked pins stand against `zap.lock` — offline, no minting.
    pub lock_standing: LockStanding,
}

/// The last run, read offline, only answers.
impl super::Delivered for StatusReport {
    fn exit_code(&self) -> u8 {
        Self::exit_code(self)
    }
    fn changed(&self) -> bool {
        false
    }
    fn preview(&self) -> Option<&super::RecordedPreview> {
        None
    }
}

impl StatusReport {
    /// Process exit code: `1` when anything is unestablished — the lock standing has
    /// errors, the last run or this one has **unverifiable** references, or a declared
    /// resource is [`ChangedSince`](Standing::ChangedSince),
    /// [`NotInLastRun`](Standing::NotInLastRun), or read
    /// [`Undetermined`](Verdict::Undetermined); else `2` when any was read
    /// [`Drifted`](Verdict::Drifted) or [`Absent`](Verdict::Absent); else `0`.
    ///
    /// The convergence drift-code convention (0 converged / 2 drifted / 1 not
    /// established), scoped to what this command reports: the codes are claims about the
    /// **last run**, not the live target, and every render says so. `2` means "the last
    /// run read drift", which is established. `1` means the last run doesn't answer for
    /// some resource at all — it wasn't read, it couldn't be, it has been edited since, or
    /// the run (or this recompute) compared against a desired side with unset references
    /// in it — so neither "converged" nor "drifted" can be said. It outranks `2` for the
    /// same reason it does on [`ApplyReport`](super::apply::ApplyReport): an unestablished
    /// state outranks an established one. Orphans are warn-only (`0`), matching
    /// `lock --check`.
    ///
    /// The **lock** check isn't redundant with the hash comparison: withholding a
    /// non-current pin moves most tracked resources' hashes anyway, but the standing
    /// names the cause, and the code mustn't ride on it.
    ///
    /// With no last run, every declared resource is `NotInLastRun`, so the code is `1`
    /// unless nothing is declared — which is what makes `status` usable in a script. The
    /// live signal remains `plan` / a bare `apply` (dry-run by default).
    #[must_use]
    pub fn exit_code(&self) -> u8 {
        let run_unverifiable = self
            .last_run
            .as_ref()
            .is_some_and(|run| !run.unverifiable.is_empty());
        if self.lock_standing.has_errors() || !self.unverifiable.is_empty() || run_unverifiable {
            return 1;
        }
        let mut drifted = false;
        for resource in &self.resources {
            match resource.standing {
                Standing::ChangedSince(_)
                | Standing::NotInLastRun
                | Standing::Read(Verdict::Undetermined) => return 1,
                Standing::Read(Verdict::Drifted | Verdict::Absent) => drifted = true,
                Standing::Read(Verdict::Converged) | Standing::Orphaned(_) => {}
            }
        }
        u8::from(drifted) * 2
    }
}

/// Join the declared resources against a last-run report into a [`StatusReport`].
///
/// Pure given `var` — how a reference resolves (the command core passes
/// [`report_var`], the resolver the report was taken with), so the bulk of coverage stays
/// env-independent. The host a report is looked up by is [`host_label`] through `var`. A
/// declared resource the report holds is [`Read`](Standing::Read) when its
/// [`desired_hash`] through `var` matches the recorded one, else
/// [`ChangedSince`](Standing::ChangedSince) — a hash that couldn't be computed on either
/// side reads as changed, and so does every one when the target's [`target_hash`] differs
/// from the recorded one. `lock` is the on-disk lock, whose pins fold into the recompute
/// as they did into the run's; `unverifiable` is this env's unresolved references.
///
/// A target whose host resolves through a masked reference has no last run, whatever
/// `last_run` holds: its label names no one machine, so a report under it isn't this
/// machine's to show ([`StatusReport::unidentified`]).
#[must_use]
pub fn build_status_report(
    config: &ZapConfig,
    last_run: Option<&LastRun>,
    lock: Option<&ZapLock>,
    lock_standing: LockStanding,
    unverifiable: Vec<String>,
    var: impl Fn(&str) -> ReportVar,
) -> StatusReport {
    let host = host_label(&config.target, &var);
    let unidentified = unidentified_host_message(&config.target, &var);
    let last_run = last_run
        .filter(|_| unidentified.is_none())
        .filter(|run| Some(run.host.as_str()) == host.as_deref());
    let target_now = target_hash(&config.target, &var).ok();
    let target_changed = last_run.is_some_and(
        |run| !matches!((&run.target_hash, &target_now), (Some(then), Some(now)) if then == now),
    );
    let mut resources: Vec<ResourceStatus> = config
        .resources
        .iter()
        .map(|resource| {
            let record = last_run.and_then(|run| run.resources.get(&resource.id));
            let standing = record.map_or(Standing::NotInLastRun, |record| {
                let lock_entry = lock.and_then(|l| l.entries.get(&resource.id));
                let now = desired_hash(resource, &var, lock_entry).ok();
                match (&record.desired_hash, now) {
                    (Some(then), Some(now)) if !target_changed && *then == now.hash => {
                        Standing::Read(record.verdict)
                    }
                    _ => Standing::ChangedSince(record.verdict),
                }
            });
            ResourceStatus {
                id: resource.id.clone(),
                kind: Some(resource.kind()),
                standing,
                references_secret: record.is_some_and(|record| record.references_secret),
            }
        })
        .collect();
    let declared: BTreeSet<&ResourceId> = config.resources.iter().map(|r| &r.id).collect();
    if let Some(run) = last_run {
        for (id, record) in &run.resources {
            if !declared.contains(id) {
                resources.push(ResourceStatus {
                    id: id.clone(),
                    kind: None,
                    standing: Standing::Orphaned(record.verdict),
                    references_secret: false,
                });
            }
        }
    }

    StatusReport {
        target: target_location(&config.target),
        package_manager: config.target.package_manager.map(|m| m.as_str().to_owned()),
        service_manager: config.target.service_manager.map(|m| m.as_str().to_owned()),
        host,
        unidentified,
        last_run: last_run.map(|run| LastRunInfo {
            ran_at: run.ran_at.clone(),
            command: run.command,
            plan_hash: run.plan_hash.clone(),
            unverifiable: run.unverifiable.clone(),
        }),
        unverifiable,
        target_changed,
        resources,
        lock_standing,
    }
}

/// One resource's label and trailing note.
fn describe(resource: &ResourceStatus) -> (&'static str, String) {
    let (label, mut note) = match resource.standing {
        Standing::Read(verdict) => (verdict.as_str(), String::new()),
        Standing::ChangedSince(verdict) => (
            verdict.as_str(),
            "  — config changed since; this verdict predates it".to_owned(),
        ),
        Standing::NotInLastRun => ("not read", "  — not in the last run".to_owned()),
        Standing::Orphaned(verdict) => (
            "orphaned",
            format!("  — read {}, no longer declared", verdict.as_str()),
        ),
    };
    if resource.references_secret {
        note.push_str("  — depends on a secret; a changed value isn't visible offline");
    }
    (label, note)
}

/// Render the last run's own unverifiable references — the banner that says its verdicts
/// were compared against a desired side with empty strings in it. No-op when empty.
fn render_run_unverifiable(out: &mut String, refs: &[String]) {
    if refs.is_empty() {
        return;
    }
    let _ = writeln!(
        out,
        "  UNVERIFIABLE — the last run couldn't resolve {} referenced variable(s), so its \
         verdicts aren't evidence:\n      {}\n  \
         provide them (--env-file or the environment) and re-run `zap plan`.",
        refs.len(),
        escape_join(refs, ", ")
    );
}

/// Render a [`StatusReport`] to the text shown by `zap status`.
///
/// Every render says the state is the last run's — when, and by which command — and
/// states what a `0` exit claims, which is what scopes [`StatusReport::exit_code`] to
/// the last run rather than the target.
#[must_use]
pub fn render_status(report: &StatusReport) -> String {
    let mut out = String::new();
    super::render_lock_standing(
        &mut out,
        &report.lock_standing,
        super::LOCK_WITHHELD_FROM_COMPARISON,
    );
    super::render_unverifiable(&mut out, &report.unverifiable);
    if let Some(run) = &report.last_run {
        render_run_unverifiable(&mut out, &run.unverifiable);
    }
    let pkg = escape_line(report.package_manager.as_deref().unwrap_or("none"));
    let svc = escape_line(report.service_manager.as_deref().unwrap_or("none"));
    let _ = writeln!(
        out,
        "target {} (pkg: {pkg}, service: {svc})",
        escape_line(&report.target)
    );

    match (&report.host, &report.last_run) {
        _ if report.unidentified.is_some() => {
            render_block(
                &mut out,
                "no last run is kept for this target: ",
                report.unidentified.as_deref().unwrap_or_default(),
            );
        }
        (None, _) => {
            let _ = writeln!(
                out,
                "no last run found: the target names no host here (`target.host` is undeclared, \
                 empty, or references a variable that is unset or empty — see --env-file), so \
                 there is no report to look up"
            );
        }
        (Some(host), None) => {
            let _ = writeln!(
                out,
                "no last run on {} — `zap plan` (or `detect` / `apply`) reads the target \
                 and records one",
                escape_line(host)
            );
        }
        (Some(host), Some(run)) => {
            let _ = writeln!(
                out,
                "last run on {}: {}, at {} — offline; `zap plan` reads the target live",
                escape_line(host),
                run.command.label(),
                escape_line(&run.ran_at),
            );
            // Read back from the report file, like the time above.
            if let Some(plan_hash) = run.plan_hash.as_deref().map(escape_line) {
                if run.command.previews_plan() {
                    let _ = writeln!(
                        out,
                        "  previewed plan_hash: {plan_hash} — the plan `zap apply --wetrun` binds to"
                    );
                } else {
                    let _ = writeln!(out, "  plan_hash: {plan_hash}");
                }
            }
        }
    }
    if report.target_changed {
        let _ = writeln!(
            out,
            "  the target (`zap.target`) changed since the last run — every verdict below \
             predates it"
        );
    }
    let secret_caveat = if report.resources.iter().any(|r| r.references_secret) {
        " (a changed secret value excepted)"
    } else {
        ""
    };
    let _ = writeln!(
        out,
        "  a 0 exit means every declared resource read converged in the last run and its \
         config is unchanged since{secret_caveat} — not that the target still is"
    );
    for resource in &report.resources {
        let (label, note) = describe(resource);
        let id = escape_line(&resource.id.0);
        let kind = resource
            .kind
            .map_or_else(String::new, |kind| format!("  {}", kind.as_str()));
        let _ = writeln!(out, "  {label:<12} {id}{kind}{note}");
    }
    out
}

/// Build the offline status report for `config_path`, reading the last run under the
/// default `~/.zap`.
///
/// # Errors
/// Propagates config-eval failures — no `fgro` or toolchain pin, a throwing config, or
/// JSON that doesn't match the schema — secret-validation (a literal secret in the
/// config), and a lock that can't be read. A missing or unreadable last-run report is
/// no error: it reads as no last run.
pub async fn run_status(config_path: &Path, fgro: Option<&Path>) -> Result<StatusReport> {
    run_status_in(zap_home_default()?.as_deref(), fgro, config_path).await
}

/// `run_status` with the `~/.zap` root injected.
///
/// The seam tests use to point `~/.zap` at a tempdir without mutating process env
/// (`set_var` is `unsafe`, which the workspace forbids). `None` reads no last run and no
/// eval cache.
///
/// # Errors
/// Same as `run_status`.
pub async fn run_status_in(
    zap_home: Option<&Path>,
    fgro: Option<&Path>,
    config_path: &Path,
) -> Result<StatusReport> {
    let (config, masker) = eval_untargeted(zap_home, fgro, config_path, PinFrom::Lock).await?;
    status_over(zap_home, config_path, &config, &masker)
}

/// The status of an evaluated, gated `config`: [`run_status_in`] past the config eval —
/// the seam the tests that build a config directly enter.
///
/// # Errors
/// Same as [`run_status`], less the config eval's — each masked by `masker`.
pub(crate) fn status_over(
    zap_home: Option<&Path>,
    config_path: &Path,
    config: &ZapConfig,
    masker: &SecretMasker,
) -> Result<StatusReport> {
    status_unmasked(zap_home, config_path, config, masker).map_err(|error| error.masked(masker))
}

/// [`status_over`], its errors as they were raised.
fn status_unmasked(
    zap_home: Option<&Path>,
    config_path: &Path,
    config: &ZapConfig,
    masker: &SecretMasker,
) -> Result<StatusReport> {
    // The report is filed under its host label and holds token-resolved, masked hashes,
    // so both sides of the join go through the same resolver — with this env's masker,
    // which needs the writing run's secrets to mask a value exactly as it did.
    let var = report_var(config, masker);
    // A file at a host label that names no one machine is not this machine's report:
    // `build_status_report` drops it.
    let last_run = zap_home
        .zip(host_label(&config.target, &var))
        .and_then(|(home, host)| read_last_run(home, config_path, &host));
    // Load the on-disk lock (offline — no network resolve) so a tracked `remote_file`'s
    // hash recomputes with its folded pin, and classify it: a pin the ledger can't vouch
    // for is withheld here too, so `status` names the lock problem instead of reporting
    // its downstream "config changed since".
    let (lock, lock_standing) = inspect_lock(config, config_path, env_var)?;
    let unverifiable = super::unverifiable_refs(config);
    Ok(build_status_report(
        config,
        last_run.as_ref(),
        lock.as_ref(),
        lock_standing,
        unverifiable,
        var,
    ))
}

#[cfg(test)]
mod tests {
    use zap_types::last_run::host_label;
    use zap_types::schema::{Target, ZapConfig};

    use crate::commands::target::build_ssh;
    use crate::commands::tests::{fgro, fgro_available};
    use crate::connection::Connection;
    use crate::last_run::report_var_with;

    /// End to end with the real resolver: a pass over a config one of whose resources
    /// resolves through a secret (`CARGO_PKG_NAME`, which cargo sets for every test
    /// run, opted in with `mask`) records no trace of its value — and `status` finds the
    /// report, reads the resource as unchanged, and notes the secret. fgro-gated (config
    /// eval).
    #[tokio::test]
    async fn a_secret_resource_round_trips_through_status_without_its_value() {
        use crate::commands::{PassContext, PinFrom, detect_pass, eval_untargeted};
        use crate::connection::MockConnection;
        use crate::home::last_run_dir_for;
        use crate::resource::Markers;
        use zap_types::last_run::RunCommand;

        use super::{Standing, render_status, run_status_in};

        if !fgro_available() {
            eprintln!("skipping a_secret_resource_round_trips: ZAP_FGRO not set");
            return;
        }
        let secret = env!("CARGO_PKG_NAME");
        let proj = crate::commands::scratch_tempdir().unwrap();
        let config_path = proj.path().join("zap.ts");
        crate::commands::scratch_write_config(
            &config_path,
            r"
export default (zap) => {
    zap.target({host: 'forge.example', user: 'deploy'});
    zap.mask('CARGO_PKG_NAME');
    zap.directory({id: 'srv', path: `/srv/${zap.env('CARGO_PKG_NAME')}`});
    zap.directory({id: 'plain', path: '/srv/plain'});
};
",
        )
        .unwrap();
        let home = crate::commands::scratch_tempdir().unwrap();
        let (config, masker) =
            eval_untargeted(Some(home.path()), fgro(), &config_path, PinFrom::Lock)
                .await
                .unwrap();
        detect_pass(
            &Connection::Mock(MockConnection::new("forge.example")),
            &config,
            PassContext {
                zap_home: Some(home.path()),
                config_path: &config_path,
                masker: &masker,
                bootstrap: false,
            },
            &crate::commands::resolve_machine(&config, &masker, false).unwrap(),
            None,
            Markers::Skip,
            RunCommand::Detect,
        )
        .await
        .unwrap();

        // One report, under the host, holding none of the secret.
        let files: Vec<_> = std::fs::read_dir(last_run_dir_for(home.path(), &config_path))
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .collect();
        assert_eq!(files.len(), 1, "{files:?}");
        assert_eq!(files[0].file_name().unwrap(), "forge.example.json");
        let bytes = std::fs::read_to_string(&files[0]).unwrap();
        assert!(!bytes.contains(secret), "{bytes}");

        let report = run_status_in(Some(home.path()), fgro(), &config_path)
            .await
            .unwrap();
        assert_eq!(report.host.as_deref(), Some("forge.example"));
        assert_eq!(report.unidentified, None);
        let line = |id: &str| report.resources.iter().find(|r| r.id.0 == id).unwrap();
        assert!(matches!(line("srv").standing, Standing::Read(_)));
        assert!(line("srv").references_secret);
        assert!(!line("plain").references_secret);
        let rendered = render_status(&report);
        assert!(
            rendered.contains("depends on a secret; a changed value isn't visible offline"),
            "{rendered}"
        );
        assert!(!rendered.contains(secret), "{rendered}");
    }

    /// End to end with the real resolver: a target whose host resolves through a secret
    /// name (`CARGO_PKG_NAME`, opted in with `mask`) is labelled by a token every
    /// machine behind the reference shares, so a pass over it files no report — under
    /// the token or anything else — and `status` reads none, says why, and exits 1
    /// without the secret's value. fgro-gated (config eval).
    #[tokio::test]
    async fn a_secret_host_keeps_no_last_run() {
        use crate::commands::{PassContext, PinFrom, detect_pass, eval_untargeted};
        use crate::connection::MockConnection;
        use crate::home::last_run_dir_for;
        use crate::resource::Markers;
        use zap_types::last_run::RunCommand;

        use super::{Standing, render_status, run_status_in};

        if !fgro_available() {
            eprintln!("skipping a_secret_host_keeps_no_last_run: ZAP_FGRO not set");
            return;
        }
        let secret = env!("CARGO_PKG_NAME");
        let proj = crate::commands::scratch_tempdir().unwrap();
        let config_path = proj.path().join("zap.ts");
        crate::commands::scratch_write_config(
            &config_path,
            r"
export default (zap) => {
    zap.target({host: `${zap.env('CARGO_PKG_NAME')}.example`, user: 'deploy'});
    zap.mask('CARGO_PKG_NAME');
    zap.directory({id: 'plain', path: '/srv/plain'});
};
",
        )
        .unwrap();
        let home = crate::commands::scratch_tempdir().unwrap();
        let (config, masker) =
            eval_untargeted(Some(home.path()), fgro(), &config_path, PinFrom::Lock)
                .await
                .unwrap();
        detect_pass(
            &Connection::Mock(MockConnection::new(format!("{secret}.example"))),
            &config,
            PassContext {
                zap_home: Some(home.path()),
                config_path: &config_path,
                masker: &masker,
                bootstrap: false,
            },
            &crate::commands::resolve_machine(&config, &masker, false).unwrap(),
            None,
            Markers::Skip,
            RunCommand::Detect,
        )
        .await
        .unwrap();
        assert!(
            !last_run_dir_for(home.path(), &config_path).exists(),
            "no report is filed for a host that names no one machine"
        );

        let report = run_status_in(Some(home.path()), fgro(), &config_path)
            .await
            .unwrap();
        assert_eq!(
            report.host.as_deref(),
            Some("[MASKED:CARGO_PKG_NAME].example")
        );
        assert_eq!(report.last_run, None);
        assert!(matches!(
            report.resources[0].standing,
            Standing::NotInLastRun
        ));
        assert_eq!(report.exit_code(), 1);
        let rendered = render_status(&report);
        assert!(
            rendered.contains(&format!(
                "no last run is kept for this target: the target host \
                 `{name}.example` references `{name}`, which the config declares a secret \
                 (drop its `zap.mask('CARGO_PKG_NAME')` if it is not one, or declare the \
                 value literally); a report filed under a masking token would stand for \
                 every machine the reference names\n",
                name = zap_types::var_ref::shown("CARGO_PKG_NAME")
            )),
            "{rendered}"
        );
        assert!(!rendered.contains(secret), "{rendered}");
    }

    /// `status` looks a report up by the host the run's connection read — `local`, or the
    /// resolved remote host.
    #[test]
    fn the_host_label_is_the_connections_host() {
        let config = ZapConfig::default();
        let masker = crate::secret::SecretRegistry::new().freeze().unwrap();
        let var = report_var_with(&config, &masker, |_| None);
        assert_eq!(
            host_label(&Target::local(), &var),
            Some(Connection::Local.host().to_owned())
        );
        let remote: Target = serde_json::from_value(serde_json::json!({
            "host": "forge.example.com", "user": "deploy",
        }))
        .unwrap();
        assert_eq!(
            host_label(&remote, &var),
            Some(build_ssh(&remote, false).unwrap().host)
        );
        // An unresolved reference resolves empty: no host, no report to find.
        let unresolved: Target = serde_json::from_value(serde_json::json!({
            "host": zap_types::text::Text::reference("ZAP_TEST_UNSET_HOST"), "user": "deploy",
        }))
        .unwrap();
        assert_eq!(host_label(&unresolved, &var), None);
    }

    /// An error `status` returns names a registered secret by its token: here a lock
    /// that doesn't parse, whose text holds the value where the parse quotes it.
    #[test]
    fn a_status_error_names_a_secret_by_token() {
        use super::status_over;
        use crate::error::Error;

        const SECRET: &str = "hunter2-status-value";
        let mut registry = crate::secret::SecretRegistry::new();
        registry.register("ZAP_T_STATUS_SECRET", SECRET);
        let masker = registry.freeze().unwrap();
        let proj = crate::commands::scratch_tempdir().unwrap();
        let config_path = proj.path().join("zap.ts");
        std::fs::write(
            proj.path().join("zap.lock"),
            format!(r#"{{"version": "{SECRET}", "entries": {{}}}}"#),
        )
        .unwrap();
        let home = crate::commands::scratch_tempdir().unwrap();

        let error = status_over(
            Some(home.path()),
            &config_path,
            &ZapConfig::default(),
            &masker,
        )
        .unwrap_err();
        assert!(matches!(error, Error::LockParse { .. }), "{error:?}");
        let rendered = error.render();
        assert!(
            rendered.contains("[MASKED:ZAP_T_STATUS_SECRET]"),
            "{rendered}"
        );
        assert!(!rendered.contains(SECRET), "{rendered}");
    }
}
