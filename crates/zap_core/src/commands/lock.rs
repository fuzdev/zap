//! `zap lock` (re-baseline) and `zap lock --check` (pure config↔lock consistency).
//!
//! `zap lock` pins the toolchain — the blake3 of the `fgro` binary it evaluates the
//! config with — then re-resolves every eligible resource from upstream and rewrites
//! `zap.lock` from scratch — the explicit re-baseline / post-edit reset. It is the one
//! command that evaluates with a binary the lock doesn't already pin: it re-pins
//! whatever the lock held, missing or stale, since a re-baseline records what is
//! current. For both
//! eligible kinds (tracked `remote_file` + tracked `build` source) resolution is
//! fetch-and-hash, operator-side (the `build` source archive is fetched + minisign-
//! verified locally), so it needs **no target connection**. No partial writes: all
//! pins resolve before anything is written.
//!
//! `zap lock --check` is the CI gate — **no network, no detection**. It first holds the
//! `fgro` binary to the lock's toolchain pin: a lock with no pin refuses
//! ([`Error::ToolchainUnpinned`]), and a binary that doesn't hash to the pin is
//! reported as a stale pin (exit 1) without evaluating the config, whose entries then
//! go unchecked. Otherwise it evals the config and loads the lock, then renders the
//! four standings of the shared
//! [`classify_lock`] predicate (the whole-config lift of
//! the one apply enforces and the read-only commands carry, so gate, banner, and
//! enforcement can't drift): **missing** entries and **stale** entries (config changed
//! since the pin → would fail `apply` with `LockStale`) both exit 1; **unverifiable**
//! entries (a hash-relevant, non-secret reference is unset, so the hash can't be
//! recomputed — fail closed) exit 1; **orphans** warn (exit 0). No check needs a
//! credential: a reference that is secret by its role, the config's `mask`, or its
//! name is addressed by its name, never its value, so an entry verifies with it unset.
//! Verifying a url that carries any other reference needs that var (literal urls verify
//! anywhere).

use std::fmt::Write as _;
use std::path::Path;

use zap_types::lock::{Toolchain, ZapLock};
use zap_types::scalar::ContentHash;
use zap_types::schema::{Resource, ZapConfig};

use super::{PinFrom, eval_untargeted, masking_errors};
use crate::config::fgro::{current_pin, locked_pin, pin_cache_dir, require_fgro};
use crate::error::{Error, Result};
use crate::escape::{escape_join, escape_line};
use crate::home::zap_home_default;
use crate::lock::{
    LockAddressing, LockStanding, NameOnlyRefs, classify_lock, is_lock_eligible, lock_path_for,
    name_only_refs, read_zap_lock, render_name_only_refs, write_zap_lock,
};
use crate::resolve::env_var;

/// Eligible (lock-tracked) resources in config order — tracked `remote_file`s and
/// tracked `build` sources.
fn eligible(config: &ZapConfig) -> impl Iterator<Item = &Resource> {
    config.resources.iter().filter(|r| is_lock_eligible(r))
}

/// `zap lock` exits 0 once it has written the lock, which it always writes.
impl super::Delivered for LockReport {
    fn exit_code(&self) -> u8 {
        0
    }
    fn changed(&self) -> bool {
        true
    }
}

/// Result of a `zap lock` re-baseline.
#[derive(Debug, Clone)]
pub struct LockReport {
    /// The lock path written.
    pub path: String,
    /// The `fgro` build pinned: the blake3 of the binary the config was evaluated with.
    pub toolchain: ContentHash,
    /// The pin the lock held before, when it held another: the evaluator moved.
    pub previous_toolchain: Option<ContentHash>,
    /// Resource ids pinned (in config order).
    pub locked: Vec<String>,
    /// The pinned resources whose address names a reference by name only.
    pub name_only: Vec<NameOnlyRefs>,
}

/// Re-baseline the lock: resolve every eligible resource from upstream and rewrite
/// `zap.lock` from scratch. Uses the default `~/.zap` content cache.
///
/// # Errors
/// Propagates config-eval / secret-validation / resolve / write failures. Resolution
/// is all-or-nothing — a single failure aborts before any write (no partial lock).
pub async fn run_lock(config_path: &Path, fgro: Option<&Path>) -> Result<LockReport> {
    run_lock_in(zap_home_default()?.as_deref(), fgro, config_path).await
}

/// `run_lock` with the `~/.zap` root injected (the hermetic test seam) — the
/// resolver's content-cache root, and the L0 eval cache's.
///
/// # Errors
/// Same as [`run_lock`]; also errors if no `zap_home` is available (the resolver's
/// content cache root).
pub async fn run_lock_in(
    zap_home: Option<&Path>,
    fgro: Option<&Path>,
    config_path: &Path,
) -> Result<LockReport> {
    // The pin is whatever the operator's binary hashes to now: `zap lock` is the
    // re-baseline, so a missing or stale pin is re-pinned, and the config is evaluated
    // with the binary it records.
    crate::lock::refuse_lock_named_config(config_path)?;
    let pin = current_pin(require_fgro(fgro)?, pin_cache_dir(zap_home).as_deref()).await?;
    // what the lock pinned before, to report a move. A lock that doesn't read is
    // rewritten whole, so it has no pin to report, except one from a newer zap:
    // rewriting that would downgrade it, so it refuses as every command does.
    let previous = match read_zap_lock(&lock_path_for(config_path)) {
        Err(error @ Error::LockVersion { .. }) => return Err(error),
        read => read.ok().flatten(),
    }
    .and_then(|lock| lock.toolchain)
    .map(|toolchain| toolchain.fgro_blake3)
    .filter(|previous| *previous != pin);
    // The ledger is written from this eval, so it's worth being explicit that a cached
    // config is trusted here as much as anywhere: a hit re-validates the whole manifest
    // (module bytes, resolution files, driver, fgro build) on lookup, so it is the
    // same config a fresh eval would produce — the argument `apply` already stakes a
    // wetrun on. The default `Shadow` posture re-evals regardless; only an operator who
    // set `ZAP_EVAL_CACHE=skip` takes the manifest at its word.
    let (config, masker) =
        eval_untargeted(zap_home, fgro, config_path, PinFrom::Given(&pin)).await?;
    let mut report =
        masking_errors(&masker, lock_over(zap_home, config_path, &config, pin)).await?;
    report.previous_toolchain = previous;
    Ok(report)
}

/// Re-baseline the lock of an evaluated, gated `config`: [`run_lock_in`] past the config
/// eval, its errors as they were raised.
async fn lock_over(
    zap_home: Option<&Path>,
    config_path: &Path,
    config: &ZapConfig,
    toolchain: ContentHash,
) -> Result<LockReport> {
    let home = zap_home.ok_or(Error::ZapHomeUnset)?;

    // Resolve all eligible pins first (no partial writes), then rewrite from scratch —
    // dropping any orphan entries for resources no longer in the config.
    let addressing = LockAddressing::of(config);
    let mut lock = ZapLock {
        toolchain: Some(Toolchain {
            fgro_blake3: toolchain.clone(),
        }),
        ..ZapLock::default()
    };
    let mut locked = Vec::new();
    for resource in eligible(config) {
        let entry = addressing.resolve_entry(resource, home).await?;
        lock.entries.insert(resource.id.clone(), entry);
        locked.push(resource.id.0.clone());
    }

    let path = lock_path_for(config_path);
    // Write even an empty lock here: `zap lock` is an explicit re-baseline, so a
    // config with no eligible resources means "the lock should be empty."
    write_zap_lock(&path, &lock)?;
    Ok(LockReport {
        path: path.display().to_string(),
        toolchain,
        previous_toolchain: None,
        locked,
        name_only: name_only_refs(config, eligible(config), env_var),
    })
}

/// Render a [`LockReport`].
#[must_use]
pub fn render_lock(report: &LockReport) -> String {
    let mut out = String::new();
    let path = escape_line(&report.path);
    match &report.previous_toolchain {
        Some(previous) => {
            let _ = writeln!(
                out,
                "pinned fgro {} (was {})",
                report.toolchain.as_str(),
                previous.as_str()
            );
        }
        None => {
            let _ = writeln!(out, "pinned fgro {}", report.toolchain.as_str());
        }
    }
    if report.locked.is_empty() {
        let _ = writeln!(out, "wrote {path} (no eligible resources)");
    } else {
        let _ = writeln!(
            out,
            "wrote {path} — pinned {} resource(s): {}",
            report.locked.len(),
            escape_join(&report.locked, ", ")
        );
    }
    render_name_only_refs(&mut out, &report.name_only);
    out
}

/// `zap lock --check`: pure config↔lock consistency — **no network, no detection**.
///
/// Eval + the machine-free gates + [`classify_lock`]; the classification itself is the
/// report, so the CI gate and the standing the read-only commands render are one
/// predicate evaluated once.
///
/// # Errors
/// Propagates config-eval / secret-validation / lock-read / hashing failures only.
pub async fn run_lock_check(config_path: &Path, fgro: Option<&Path>) -> Result<LockCheckReport> {
    run_lock_check_in(zap_home_default()?.as_deref(), fgro, config_path).await
}

/// `run_lock_check` with the `~/.zap` root injected — the L0 eval cache's root (the
/// hermetic test seam; `None` disables the cache for this run). The gate itself stays
/// network- and machine-free.
///
/// # Errors
/// Same as [`run_lock_check`].
pub async fn run_lock_check_in(
    zap_home: Option<&Path>,
    fgro: Option<&Path>,
    config_path: &Path,
) -> Result<LockCheckReport> {
    crate::lock::refuse_lock_named_config(config_path)?;
    super::target::require_config(config_path)?;
    let fgro_path = require_fgro(fgro)?;
    let pinned = locked_pin(config_path)?;
    let current = current_pin(fgro_path, pin_cache_dir(zap_home).as_deref()).await?;
    if current != pinned {
        // Not evaluated: only `zap lock` runs a config through a binary the lock
        // doesn't pin.
        return Ok(LockCheckReport {
            stale_toolchain: Some(StaleToolchain {
                fgro: fgro_path.display().to_string(),
                pinned,
                current,
            }),
            ..LockCheckReport::default()
        });
    }
    let (config, masker) =
        eval_untargeted(zap_home, fgro, config_path, PinFrom::Given(&pinned)).await?;
    let check = || {
        let lock = read_zap_lock(&lock_path_for(config_path))?.unwrap_or_default();
        Ok(LockCheckReport {
            stale_toolchain: None,
            standing: classify_lock(&config, &lock, env_var)?,
            name_only: name_only_refs(&config, eligible(&config), env_var),
        })
    };
    check().map_err(|error: Error| error.masked(&masker))
}

/// The `fgro` binary `lock --check` was given, when it doesn't hash to the lock's
/// toolchain pin.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StaleToolchain {
    /// The binary's path, as the operator named it.
    pub fgro: String,
    /// The lock's pin.
    pub pinned: ContentHash,
    /// What the binary hashes to.
    pub current: ContentHash,
}

/// Result of a `zap lock --check`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LockCheckReport {
    /// The `fgro` binary, when it isn't the lock's toolchain pin: then the config was
    /// not evaluated, and [`standing`](Self::standing) is empty.
    pub stale_toolchain: Option<StaleToolchain>,
    /// The config's standing against its lock — the verdict.
    pub standing: LockStanding,
    /// The eligible resources whose address names a reference by name only — a note,
    /// never part of the verdict.
    pub name_only: Vec<NameOnlyRefs>,
}

/// The lock's check only answers.
impl super::Delivered for LockCheckReport {
    fn exit_code(&self) -> u8 {
        Self::exit_code(self)
    }
    fn changed(&self) -> bool {
        false
    }
}

impl LockCheckReport {
    /// `1` if the toolchain pin is stale, or any eligible resource is missing, stale,
    /// or unverifiable.
    #[must_use]
    pub fn exit_code(&self) -> u8 {
        if self.stale_toolchain.is_some() {
            1
        } else {
            self.standing.exit_code()
        }
    }
}

/// Render a [`LockCheckReport`] as the `zap lock --check` gate report.
///
/// The gate view: every standing listed, orphans included, and a clean bill of health
/// when there's nothing to say. The read-only commands render the same data as a
/// leading banner instead (`commands::render_lock_standing`), which is silent about
/// orphans — they don't withhold anything.
#[must_use]
pub fn render_lock_check(check: &LockCheckReport) -> String {
    let report = &check.standing;
    let mut out = String::new();
    if let Some(stale) = &check.stale_toolchain {
        let _ = writeln!(
            out,
            "error: the toolchain pin is stale — fgro {} hashes to {}, the lock pins {}; \
             run `zap lock` to pin it, or point --fgro at the pinned build (the config was \
             not evaluated, so its entries were not checked)",
            escape_line(&stale.fgro),
            stale.current.as_str(),
            stale.pinned.as_str()
        );
        return out;
    }
    for id in &report.orphans {
        let id = escape_line(id);
        let _ = writeln!(
            out,
            "warning: lock entry `{id}` is not in config (run `zap lock` to rebuild and prune)"
        );
    }
    for id in &report.missing {
        let id = escape_line(id);
        let _ = writeln!(
            out,
            "error: `{id}` is lock-eligible but has no entry — run `zap update {id}`"
        );
    }
    for id in &report.stale {
        let id = escape_line(id);
        let _ = writeln!(
            out,
            "error: `{id}` is stale — config changed since lock; run `zap update {id}`"
        );
    }
    for entry in &report.unverifiable {
        let _ = writeln!(
            out,
            "error: `{}` cannot be verified — unset {}, which its url/path address depends \
             on; set it (the env the lock was minted with) and re-run",
            escape_line(&entry.id),
            escape_join(&entry.vars, ", ")
        );
    }
    if !report.has_errors() && report.orphans.is_empty() {
        let _ = writeln!(out, "lock is consistent with config");
    }
    render_name_only_refs(&mut out, &check.name_only);
    out
}

#[cfg(test)]
mod tests {
    use super::{run_lock_check_in, run_lock_in};
    use crate::commands::tests::{fgro, fgro_available};
    use crate::error::Error;

    const SECRET: &str = "hunter2-lock-value";
    const TOKEN: &str = "[MASKED:ZAP_T_LOCK_SECRET]";

    /// A config that isn't there is said to be missing before the lock is asked for a
    /// toolchain pin it can't hold — by the eval every command but `zap lock` shares,
    /// and by `zap lock --check` — and only a config that is there is told to pin one.
    /// No `fgro` runs: the named one doesn't exist.
    #[tokio::test]
    async fn a_missing_config_is_refused_before_the_pin_is_read() {
        use crate::commands::target::{PinFrom, eval_untargeted};

        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("zap.ts");
        let fgro = std::path::Path::new("/nonexistent/fgro");
        let errors = async || {
            [
                eval_untargeted(None, Some(fgro), &config, PinFrom::Lock)
                    .await
                    .map(drop)
                    .unwrap_err(),
                run_lock_check_in(None, Some(fgro), &config)
                    .await
                    .map(drop)
                    .unwrap_err(),
            ]
        };
        for error in errors().await {
            assert!(
                matches!(&error, Error::ConfigNotFound { path, .. } if *path == config.display().to_string()),
                "{error:?}"
            );
        }
        std::fs::write(&config, "export default () => {};\n").unwrap();
        for error in errors().await {
            assert!(
                matches!(error, Error::ToolchainUnpinned { .. }),
                "{error:?}"
            );
        }
    }

    /// A config that tracks one remote file and references the secret, so the command's
    /// own gates register it.
    const CONFIG: &str = r"
export default (zap) => {
    zap.target({local: true});
    zap.file({id: 'f', path: '/opt/f', content: {type: 'remote', url: 'http://127.0.0.1:1/f.bin'}});
    zap.script({id: 's', check: 'false', run: 'true', env: {TOKEN: zap.env('ZAP_T_LOCK_SECRET')}});
};
";

    /// An error `lock` returns names a registered secret by its token — here the content
    /// cache's path, under a directory named by the value, with a file where the cache's
    /// directory goes, so nothing is fetched. fgro-gated (config eval).
    #[tokio::test]
    async fn a_lock_error_names_a_secret_by_token() {
        if !fgro_available() {
            eprintln!("skipping a_lock_error_names_a_secret_by_token: ZAP_FGRO not set");
            return;
        }
        let _env = crate::resolve::test_env::set(&[("ZAP_T_LOCK_SECRET", SECRET)]);
        let proj = crate::commands::scratch_tempdir().unwrap();
        let config_path = proj.path().join("zap.ts");
        crate::commands::scratch_write_config(&config_path, CONFIG).unwrap();
        let root = crate::commands::scratch_tempdir().unwrap();
        let home = root.path().join(SECRET).join("home");
        std::fs::create_dir_all(home.join("cache")).unwrap();
        std::fs::write(home.join("cache").join("files"), "").unwrap();
        let written = std::fs::read(proj.path().join("zap.lock")).ok();

        let error = run_lock_in(Some(&home), fgro(), &config_path)
            .await
            .unwrap_err();
        assert!(matches!(error, Error::CacheWrite { .. }), "{error:?}");
        let rendered = error.render();
        assert!(rendered.contains(TOKEN), "{rendered}");
        assert!(!rendered.contains(SECRET), "{rendered}");
        // Nothing resolved, so the lock is the one the test wrote.
        assert_eq!(std::fs::read(proj.path().join("zap.lock")).ok(), written);
    }

    /// `zap lock` refuses a lock from a newer zap instead of rewriting it at this
    /// zap's version, and leaves it as it was. fgro-gated (the pin is hashed first).
    #[tokio::test]
    async fn lock_refuses_a_newer_lock_and_leaves_it() {
        if !fgro_available() {
            eprintln!("skipping lock_refuses_a_newer_lock_and_leaves_it: ZAP_FGRO not set");
            return;
        }
        let proj = crate::commands::scratch_tempdir().unwrap();
        let config_path = proj.path().join("zap.ts");
        crate::commands::scratch_write_config(
            &config_path,
            "export default (zap) => { zap.target({local: true}); };",
        )
        .unwrap();
        let lock_path = proj.path().join("zap.lock");
        let newer = format!(
            r#"{{"version": {}, "entries": []}}"#,
            zap_types::lock::LOCK_VERSION + 1
        );
        std::fs::write(&lock_path, &newer).unwrap();
        let home = crate::commands::scratch_tempdir().unwrap();

        let error = run_lock_in(Some(home.path()), fgro(), &config_path)
            .await
            .unwrap_err();
        assert!(matches!(error, Error::LockVersion { .. }), "{error:?}");
        assert_eq!(std::fs::read_to_string(&lock_path).unwrap(), newer);
    }

    /// A lock that doesn't parse, whose text holds a secret's value where a parse would
    /// quote it, is reported by position: it is read for its toolchain pin before the
    /// config is evaluated, so before the masker knows the secret.
    /// fgro-gated (config eval).
    #[tokio::test]
    async fn a_lock_check_error_names_a_secret_by_token() {
        if !fgro_available() {
            eprintln!("skipping a_lock_check_error_names_a_secret_by_token: ZAP_FGRO not set");
            return;
        }
        let _env = crate::resolve::test_env::set(&[("ZAP_T_LOCK_SECRET", SECRET)]);
        let proj = crate::commands::scratch_tempdir().unwrap();
        let config_path = proj.path().join("zap.ts");
        crate::commands::scratch_write_config(&config_path, CONFIG).unwrap();
        std::fs::write(
            proj.path().join("zap.lock"),
            format!(r#"{{"version": "{SECRET}", "entries": {{}}}}"#),
        )
        .unwrap();
        let home = crate::commands::scratch_tempdir().unwrap();

        let error = run_lock_check_in(Some(home.path()), fgro(), &config_path)
            .await
            .unwrap_err();
        assert!(matches!(error, Error::LockParse { .. }), "{error:?}");
        let rendered = error.render();
        assert!(rendered.contains("line 1 column"), "{rendered}");
        assert!(!rendered.contains(SECRET), "{rendered}");
    }
}
