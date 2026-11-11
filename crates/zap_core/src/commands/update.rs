//! `zap update [resource_id...]` — advance lock pins from upstream.
//!
//! Re-fetches each target's content (fetch-and-hash) and, when the resolved pin
//! differs from the lock, advances the entry; when the bytes are the same but the
//! entry's `config_hash` is stale (the resource was edited around an unchanged source
//! — a `build`'s `run`, a `strip_components`), it refreshes the entry in place, so the
//! `zap update <id>` the stale-lock error prescribes always clears it.
//! Writes are **per-resource incremental**
//! (each advance rewrites `zap.lock` under its own `flock`), so a mid-run failure
//! keeps the advances that already succeeded — Cargo's model. With ids, advances only
//! those; bareword (no ids) advances every eligible entry (tracked `remote_file` +
//! tracked `build` source). Exit non-zero if any target failed: `1` when any failure is
//! operational, else `2`, the code each failure's error has elsewhere
//! ([`UpdateReport::exit_code`]).

use std::fmt::Write as _;
use std::path::Path;

use zap_types::lock::{LockEntry, ZapLock};
use zap_types::scalar::ContentHash;
use zap_types::schema::{Resource, ResourceId, ZapConfig};

use super::{PinFrom, eval_untargeted, masking_errors};
use crate::error::{Error, Result};
use crate::escape::{escape_join, escape_line};
use crate::home::zap_home_default;
use crate::lock::{
    LockAddressing, NameOnlyRefs, is_lock_eligible, lock_path_for, name_only_refs, read_zap_lock,
    render_name_only_refs, update_zap_lock,
};
use crate::resolve::env_var;
use crate::resource::short_pin;
use crate::secret::SecretMasker;

/// One target's outcome.
#[derive(Debug, Clone)]
pub enum UpdateOutcome {
    /// Advanced from `from` (a short pin, or `none`) to `to`.
    Advanced {
        /// The resource id.
        id: String,
        /// The previous pin (short), or `None` if there was no entry.
        from: Option<String>,
        /// The new pin (short).
        to: String,
    },
    /// Re-resolved to the same pin, and the entry's `config_hash` was stale — the entry
    /// was rewritten for the edited resource, pin unchanged.
    Refreshed {
        /// The resource id.
        id: String,
        /// The pin (short), unchanged.
        pin: String,
    },
    /// Re-resolved to the same pin with a current `config_hash` — no change.
    Unchanged {
        /// The resource id.
        id: String,
    },
    /// Resolution failed; the entry was left untouched.
    Failed {
        /// The resource id.
        id: String,
        /// The failure reason.
        error: String,
        /// What the failure's error is, by [`Error::exit_code`].
        class: FailureClass,
    },
}

/// What a failed entry's error is, by its [`Error::exit_code`]: the two codes an error
/// exits with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailureClass {
    /// Re-running unchanged fails the same way: an unset reference in the URL or the
    /// credential, a signature that doesn't verify (exit `2`).
    NeedsAction,
    /// A retry may clear it: a fetch, a write, the network (exit `1`).
    Operational,
}

impl FailureClass {
    /// The class of `error`.
    #[must_use]
    pub const fn of(error: &Error) -> Self {
        if error.exit_code() == 2 {
            Self::NeedsAction
        } else {
            Self::Operational
        }
    }

    /// The exit code an error of this class has.
    #[must_use]
    pub const fn exit_code(self) -> u8 {
        match self {
            Self::NeedsAction => 2,
            Self::Operational => 1,
        }
    }
}

/// Result of a `zap update` run.
#[derive(Debug, Clone)]
pub struct UpdateReport {
    /// Per-target outcomes, in the order processed.
    pub outcomes: Vec<UpdateOutcome>,
    /// The targets whose address names a reference by name only, whatever their outcome.
    pub name_only: Vec<NameOnlyRefs>,
}

/// An update changed the lock when an entry advanced or was refreshed; one whose entries
/// were all unchanged or failed wrote nothing (`update_over` writes only those two), and
/// only answered.
impl super::Delivered for UpdateReport {
    fn exit_code(&self) -> u8 {
        Self::exit_code(self)
    }
    fn changed(&self) -> bool {
        self.outcomes.iter().any(|outcome| {
            matches!(
                outcome,
                UpdateOutcome::Advanced { .. } | UpdateOutcome::Refreshed { .. }
            )
        })
    }
}

impl UpdateReport {
    /// `0` if no target failed; `1` if any failure is operational, which leaves that
    /// entry's answer unestablished (as an unestablished answer outranks an established
    /// one across zap's exit codes); else `2`, every failure needing action.
    #[must_use]
    pub fn exit_code(&self) -> u8 {
        let mut code = 0;
        for outcome in &self.outcomes {
            match outcome {
                UpdateOutcome::Failed {
                    class: FailureClass::Operational,
                    ..
                } => return 1,
                UpdateOutcome::Failed {
                    class: FailureClass::NeedsAction,
                    ..
                } => code = 2,
                _ => {}
            }
        }
        code
    }
}

/// Select the resources to advance: the named ids (validated as eligible), or every
/// eligible resource when `ids` is empty.
fn targets<'a>(
    config: &'a ZapConfig,
    ids: &[String],
) -> std::result::Result<Vec<&'a Resource>, String> {
    if ids.is_empty() {
        return Ok(config
            .resources
            .iter()
            .filter(|r| is_lock_eligible(r))
            .collect());
    }
    let mut out = Vec::with_capacity(ids.len());
    for id in ids {
        let resource = config
            .resources
            .iter()
            .find(|r| &r.id.0 == id)
            .ok_or_else(|| format!("no resource `{id}` in config"))?;
        if !is_lock_eligible(resource) {
            return Err(format!(
                "resource `{id}` is not lock-eligible \
                 (no tracked remote file, build source, or apt_repo key to update)"
            ));
        }
        out.push(resource);
    }
    Ok(out)
}

/// Advance lock pins. Uses the default `~/.zap` content cache.
///
/// # Errors
/// Propagates config-eval / secret-validation failures, an unknown/ineligible id, or
/// a missing `zap_home`. Per-target resolve failures are recorded in the report (not
/// returned), so successes still persist.
pub async fn run_update(
    config_path: &Path,
    fgro: Option<&Path>,
    ids: &[String],
) -> Result<UpdateReport> {
    run_update_in(zap_home_default()?.as_deref(), fgro, config_path, ids).await
}

/// `run_update` with the `~/.zap` root injected (the hermetic test seam) — the
/// resolver's content-cache root, and the L0 eval cache's.
///
/// # Errors
/// Same as [`run_update`].
pub async fn run_update_in(
    zap_home: Option<&Path>,
    fgro: Option<&Path>,
    config_path: &Path,
    ids: &[String],
) -> Result<UpdateReport> {
    // Advances the ledger from this eval — same standing as `run_lock_in`'s: a cached
    // config is one whose whole manifest re-validated on lookup.
    // The toolchain pin is the lock's: `update` advances content pins, never the
    // toolchain's, so a binary off its pin refuses here and `zap lock` re-pins it.
    let (config, masker) = eval_untargeted(zap_home, fgro, config_path, PinFrom::Lock).await?;
    masking_errors(
        &masker,
        update_over(zap_home, config_path, &config, &masker, ids),
    )
    .await
}

/// Set `id`'s entry in the lock at `path`, merged into what the lock holds now (another
/// writer's entries since this run read it are kept), and return the lock as written.
fn advance(path: &Path, id: &ResourceId, entry: LockEntry) -> Result<ZapLock> {
    update_zap_lock(path, |current| {
        current.entries.insert(id.clone(), entry);
    })
}

/// Advance the pins of an evaluated, gated `config`: [`run_update_in`] past the config
/// eval, its errors as they were raised. A failure it records in the report instead is
/// masked by `masker` where it is recorded.
async fn update_over(
    zap_home: Option<&Path>,
    config_path: &Path,
    config: &ZapConfig,
    masker: &SecretMasker,
    ids: &[String],
) -> Result<UpdateReport> {
    let home = zap_home.ok_or(Error::ZapHomeUnset)?;
    let targets = targets(config, ids).map_err(Error::Config)?;

    let path = lock_path_for(config_path);
    let mut lock: ZapLock = read_zap_lock(&path)?.unwrap_or_default();
    let mut outcomes = Vec::with_capacity(targets.len());
    let addressing = LockAddressing::of(config);
    let name_only = name_only_refs(config, targets.iter().copied(), env_var);

    for resource in targets {
        let id = resource.id.0.clone();
        match addressing.resolve_entry(resource, home).await {
            Ok(entry) => {
                let new_pin = entry
                    .pin()
                    .map(ContentHash::as_str)
                    .unwrap_or_default()
                    .to_owned();
                let old_pin = lock
                    .entries
                    .get(&resource.id)
                    .and_then(LockEntry::pin)
                    .map(ContentHash::as_str);
                if lock.entries.get(&resource.id) == Some(&entry) {
                    outcomes.push(UpdateOutcome::Unchanged { id });
                } else if old_pin == Some(new_pin.as_str()) {
                    lock = advance(&path, &resource.id, entry)?;
                    outcomes.push(UpdateOutcome::Refreshed {
                        id,
                        pin: short_pin(&new_pin).to_owned(),
                    });
                } else {
                    let from = old_pin.map(|pin| short_pin(pin).to_owned());
                    // Incremental: persist each advance immediately under its own flock.
                    lock = advance(&path, &resource.id, entry)?;
                    outcomes.push(UpdateOutcome::Advanced {
                        id,
                        from,
                        to: short_pin(&new_pin).to_owned(),
                    });
                }
            }
            Err(error) => outcomes.push(UpdateOutcome::Failed {
                id,
                class: FailureClass::of(&error),
                error: error.masked(masker).to_string(),
            }),
        }
    }

    Ok(UpdateReport {
        outcomes,
        name_only,
    })
}

/// Render an [`UpdateReport`] (the `Advanced:` / `Failed:` per-entry summary).
#[must_use]
pub fn render_update(report: &UpdateReport) -> String {
    let mut out = String::new();
    let mut advanced = Vec::new();
    let mut refreshed = Vec::new();
    let mut failed = Vec::new();
    let mut unchanged = 0u32;
    for outcome in &report.outcomes {
        match outcome {
            UpdateOutcome::Advanced { id, from, to } => {
                let from = from.as_deref().unwrap_or("none");
                advanced.push(format!(
                    "{} ({} → {})",
                    escape_line(id),
                    escape_line(from),
                    escape_line(to)
                ));
            }
            UpdateOutcome::Refreshed { id, pin } => {
                refreshed.push(format!("{} ({})", escape_line(id), escape_line(pin)));
            }
            UpdateOutcome::Unchanged { .. } => unchanged += 1,
            // One entry of a one-line list: a failure that runs to several lines is
            // shown on this one.
            UpdateOutcome::Failed { id, error, .. } => {
                failed.push(format!("{} ({})", escape_line(id), escape_line(error)));
            }
        }
    }
    if advanced.is_empty() && refreshed.is_empty() && failed.is_empty() {
        let _ = writeln!(out, "all {unchanged} pin(s) already up to date");
        render_name_only_refs(&mut out, &report.name_only);
        return out;
    }
    if !advanced.is_empty() {
        let _ = writeln!(out, "Advanced: {}", advanced.join(", "));
    }
    if !refreshed.is_empty() {
        let _ = writeln!(
            out,
            "Refreshed (same pin, entry rewritten for the edited resource): {}",
            refreshed.join(", ")
        );
    }
    if unchanged > 0 {
        let _ = writeln!(out, "Unchanged: {unchanged}");
    }
    if !failed.is_empty() {
        let _ = writeln!(out, "Failed (lock unchanged): {}", failed.join(", "));
        let ids: Vec<&str> = report
            .outcomes
            .iter()
            .filter_map(|o| match o {
                UpdateOutcome::Failed { id, .. } => Some(id.as_str()),
                _ => None,
            })
            .collect();
        let _ = writeln!(
            out,
            "Re-run `zap update {}` after addressing.",
            escape_join(ids, " ")
        );
    }
    render_name_only_refs(&mut out, &report.name_only);
    out
}

#[cfg(test)]
mod tests {
    use zap_types::schema::ZapConfig;

    use super::{
        FailureClass, UpdateOutcome, UpdateReport, render_update, run_update_in, update_over,
    };
    use crate::commands::tests::{fgro, fgro_available};
    use crate::error::Error;

    /// An update changed the lock only when an entry advanced or was refreshed.
    #[test]
    fn an_update_changed_the_lock_only_when_an_entry_moved() {
        use crate::commands::Delivered;

        let id = || "zig".to_owned();
        let changed = |outcomes: Vec<UpdateOutcome>| {
            Delivered::changed(&UpdateReport {
                outcomes,
                name_only: Vec::new(),
            })
        };
        let unchanged = || UpdateOutcome::Unchanged { id: id() };
        let failed = || UpdateOutcome::Failed {
            id: id(),
            error: "unreachable".to_owned(),
            class: FailureClass::Operational,
        };
        assert!(!changed(vec![]));
        assert!(!changed(vec![unchanged(), failed()]));
        let advanced = UpdateOutcome::Advanced {
            id: id(),
            from: None,
            to: "abc".to_owned(),
        };
        assert!(changed(vec![unchanged(), advanced]));
        let refreshed = UpdateOutcome::Refreshed {
            id: id(),
            pin: "abc".to_owned(),
        };
        assert!(changed(vec![failed(), refreshed]));
    }

    const SECRET: &str = "hunter2-update-value";
    const TOKEN: &str = "[MASKED:ZAP_T_UPDATE_SECRET]";

    /// A failure `update` records against one id names a registered secret by its
    /// token — here the content cache's path, under a directory named by the value,
    /// with a file where the cache's directory goes, so nothing is fetched.
    #[tokio::test]
    async fn a_recorded_failure_names_a_secret_by_token() {
        let mut registry = crate::secret::SecretRegistry::new();
        registry.register("ZAP_T_UPDATE_SECRET", SECRET);
        let masker = registry.freeze().unwrap();
        let config: ZapConfig = serde_json::from_value(serde_json::json!({
            "target": {"local": true},
            "resources": [{
                "id": "f", "type": "file", "path": "/opt/f",
                "content": {"type": "remote", "url": "http://127.0.0.1:1/f.bin"},
            }],
        }))
        .unwrap();
        let root = crate::commands::scratch_tempdir().unwrap();
        let home = root.path().join(SECRET).join("home");
        std::fs::create_dir_all(home.join("cache")).unwrap();
        std::fs::write(home.join("cache").join("files"), "").unwrap();
        let config_path = root.path().join("zap.ts");

        let report = update_over(Some(&home), &config_path, &config, &masker, &[])
            .await
            .unwrap();
        let [UpdateOutcome::Failed { id, error, class }] = report.outcomes.as_slice() else {
            panic!("expected one failure: {:?}", report.outcomes);
        };
        assert_eq!(id, "f");
        // the content cache couldn't be written: a retry may clear it
        assert_eq!(*class, FailureClass::Operational);
        assert_eq!(report.exit_code(), 1);
        assert!(error.contains(TOKEN), "{error}");
        assert!(!error.contains(SECRET), "{error}");
        let rendered = render_update(&report);
        assert!(rendered.contains(TOKEN), "{rendered}");
        assert!(!rendered.contains(SECRET), "{rendered}");
    }

    /// A tracked URL with an unset reference fails its entry needs-action, exit 2, as it
    /// does `zap lock`; a failure a retry may clear outranks it, exit 1, whatever the
    /// order.
    #[tokio::test]
    async fn a_failed_entry_keeps_its_errors_exit_code() {
        use zap_types::text::Text;
        use zap_types::var_ref::Segment::{Ref, Text as Lit};
        let _env = crate::resolve::test_env::set(&[("ZAP_T_UPDATE_UNSET", "")]);
        let masker = crate::secret::SecretRegistry::new().freeze().unwrap();
        let url = Text::of_pieces([Lit("http://127.0.0.1:1/"), Ref("ZAP_T_UPDATE_UNSET")]);
        let config: ZapConfig = serde_json::from_value(serde_json::json!({
            "target": {"local": true},
            "resources": [{
                "id": "f", "type": "file", "path": "/opt/f",
                "content": {"type": "remote", "url": url},
            }],
        }))
        .unwrap();
        let root = crate::commands::scratch_tempdir().unwrap();
        let config_path = root.path().join("zap.ts");

        let report = update_over(Some(root.path()), &config_path, &config, &masker, &[])
            .await
            .unwrap();
        let [UpdateOutcome::Failed { id, class, .. }] = report.outcomes.as_slice() else {
            panic!("expected one failure: {:?}", report.outcomes);
        };
        assert_eq!(id, "f");
        assert_eq!(*class, FailureClass::NeedsAction);
        assert_eq!(report.exit_code(), 2);

        let failed = |id: &str, class| UpdateOutcome::Failed {
            id: id.to_owned(),
            error: "x".to_owned(),
            class,
        };
        let unchanged = UpdateOutcome::Unchanged { id: "u".to_owned() };
        for (outcomes, code) in [
            (vec![unchanged.clone()], 0),
            (
                vec![unchanged.clone(), failed("a", FailureClass::NeedsAction)],
                2,
            ),
            (
                vec![
                    failed("a", FailureClass::NeedsAction),
                    failed("b", FailureClass::Operational),
                ],
                1,
            ),
            (
                vec![
                    failed("b", FailureClass::Operational),
                    failed("a", FailureClass::NeedsAction),
                    unchanged,
                ],
                1,
            ),
        ] {
            let report = UpdateReport {
                outcomes,
                name_only: Vec::new(),
            };
            assert_eq!(report.exit_code(), code, "{:?}", report.outcomes);
        }
    }

    /// A lock that doesn't parse, whose text holds a secret's value where a parse would
    /// quote it, is reported by position: it is read for its toolchain pin before the
    /// config is evaluated, so before the masker knows the secret. fgro-gated (config
    /// eval).
    #[tokio::test]
    async fn an_update_error_names_a_secret_by_token() {
        if !fgro_available() {
            eprintln!("skipping an_update_error_names_a_secret_by_token: ZAP_FGRO not set");
            return;
        }
        let _env = crate::resolve::test_env::set(&[("ZAP_T_UPDATE_SECRET", SECRET)]);
        let proj = crate::commands::scratch_tempdir().unwrap();
        let config_path = proj.path().join("zap.ts");
        crate::commands::scratch_write_config(
            &config_path,
            r"
export default (zap) => {
    zap.target({local: true});
    zap.script({id: 's', check: 'false', run: 'true', env: {TOKEN: zap.env('ZAP_T_UPDATE_SECRET')}});
};
",
        )
        .unwrap();
        std::fs::write(
            proj.path().join("zap.lock"),
            format!(r#"{{"version": "{SECRET}", "entries": {{}}}}"#),
        )
        .unwrap();
        let home = crate::commands::scratch_tempdir().unwrap();

        let error = run_update_in(Some(home.path()), fgro(), &config_path, &[])
            .await
            .unwrap_err();
        assert!(matches!(error, Error::LockParse { .. }), "{error:?}");
        let rendered = error.render();
        assert!(rendered.contains("line 1 column"), "{rendered}");
        assert!(!rendered.contains(SECRET), "{rendered}");
    }
}
