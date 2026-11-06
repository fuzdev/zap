//! L0 eval-cache — skip the config eval on a re-validated manifest hit.
//!
//! `eval_config` runs `fgro` on every command that reads a config — the target-binding
//! `plan`/`apply`/`detect`/`deploy` (via `commands::target::eval_target`) and the
//! target-free `status` / `lock` / `lock --check` / `update` / `config validate` (via
//! `commands::target::eval_untargeted`). This module skips that run: it **persists** the
//! value beside a re-validatable **manifest** (the files the run read, with their
//! blake3s, the paths it found nothing at, and the blake3 of the value itself), and on a
//! later run, if the manifest still holds and the value is the one it names, serves the
//! cached `ZapConfig` without evaluating.
//!
//! [`eval_cached`] is the entry point; [`EvalCacheMode`] picks the posture:
//! - **[`Skip`](EvalCacheMode::Skip)** — serve cached on a validated hit (the win).
//! - **[`Shadow`](EvalCacheMode::Shadow)** (the conservative default) — still eval
//!   every run, but compare fresh-vs-cached and flag a [`ShadowMismatch`] when the
//!   manifest under-captures: "observe, never skip", the tool to run on real
//!   configs before trusting `Skip`.
//!
//! Everything here is **advisory**: any failure (an unreadable cache file, a write
//! that fails) degrades to a [`Miss`](EvalCacheObservation::Miss) / no-skip or is
//! swallowed — it must never fail a convergence run. The manifest is captured from
//! the module graph `fgro` reported for the run ([`fuz_eval::GraphDump`]), so it reads
//! nothing of its own; only a successful eval is cached. A hit in
//! [`Skip`](EvalCacheMode::Skip) mode runs no eval: the value it serves came from a run
//! of the same `fgro` build over the same recorded files, which is not the same run —
//! a symbolic link retargeted moves no recorded file (`EvalInputs` lists what the key
//! leaves out).
//!
//! [`ShadowMismatch`]: EvalCacheObservation::ShadowMismatch
//!
//! The key is a **re-validated manifest**, not a forward hash: you cannot hash the
//! transitive import graph without loading the modules (the run we're skipping), so on
//! a miss we record the graph and on the next run re-check it, cargo/ninja-shaped.
//!
//! The typed cache key — [`EvalInputs`] — and its pure re-validation policy live in
//! [`zap_types::eval_inputs`] (the on-disk contract + pure-policy home, beside
//! `ConfigHashInputs`); this module is the IO half: the capture from the graph, the
//! [`DRIVER_JS`] coupling, the `fgro` hash a lookup checks, and the read/write/classify
//! orchestration. [`EvalInputs::validate`] is called here with injected `hash_file` and
//! `is_absent` closures.

use std::path::Path;

use fuz_eval::{DumpRole, GraphDump};
use zap_types::eval_inputs::{
    AbsentEntry, EVAL_CACHE_VERSION, EvalInputs, EvalKey, InputEntry, InputRole,
};
use zap_types::schema::ZapConfig;

use crate::config::DRIVER_JS;
use crate::config::eval::{EvaluatedConfig, PinnedFgro, eval_config_raw};
use crate::config::fgro::current_pin;
use crate::escape::escape_line;
use crate::home::{eval_cache_dir_for, write_atomic};

/// The persisted `ZapConfig` JSON (the eval's value) — the cache *value*.
///
/// Both files live in the config's `<config-slug>/eval/` subdir
/// (`crate::home::eval_cache_dir_for`), a sibling of its `last_run/` reports.
const CONFIG_FILE: &str = "value.json";
/// The persisted [`EvalInputs`] manifest — the re-validated cache *key*.
const MANIFEST_FILE: &str = "manifest.json";

/// Whether zap's evals run with V8's JIT: never (`fuz_eval` passes no `--jit`).
const JIT: bool = false;

/// What the L0 cache *would* have done this run — reported, not acted on.
///
/// Returned so the orchestration is testable; the loud
/// [`ShadowMismatch`](Self::ShadowMismatch) also prints unconditionally.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EvalCacheObservation {
    /// No `~/.zap` home — L0 disabled for this run (nothing persisted).
    Disabled,
    /// No prior manifest, or it failed re-validation — eval would have re-run. The
    /// fresh output + a new manifest were persisted.
    Miss(String),
    /// The manifest re-validated **and** the cached `ZapConfig` equals a fresh eval —
    /// a real, safe would-hit.
    Hit,
    /// The manifest re-validated as a would-hit, but a fresh eval produced a
    /// *different* `ZapConfig` — manifest under-capture (an uncaptured input slipped
    /// the key). The signal `Shadow` exists to surface; the cache was refreshed to the
    /// fresh truth.
    ShadowMismatch,
}

/// How a run uses the L0 eval-cache.
///
/// The two modes are the two halves of the design's determinism posture:
///
/// - [`Shadow`](Self::Shadow) — **always eval**, then persist + compare fresh-vs-cached
///   ([`observe_and_persist`]). Pays the eval every run; its only benefit is the loud
///   [`ShadowMismatch`](EvalCacheObservation::ShadowMismatch) when the manifest
///   under-captures. This is the **conservative default**: caching reliance is not
///   increased until an operator opts in, and the shadow signal runs continuously.
/// - [`Skip`](Self::Skip) — on a validated manifest hit, **serve the cached `ZapConfig`
///   without evaluating** (the actual win). A miss falls through to a fresh eval +
///   persist. Opt-in (`ZAP_EVAL_CACHE=skip`) because it's the step where a manifest
///   under-capture silently serves a stale config — a `node_modules` link or a link to
///   a module in the project pointed at other files moves no recorded hash — and
///   where what a fresh run would refuse — a directory turned world-writable on the
///   way to the project — is not seen. Nothing carries a mismatch `Shadow` saw over
///   to a later run: `Skip` trusts every manifest hit.
///
/// Selected by [`mode_from_env`]; the `--no-cache` CLI `bust` force-refreshes over this
/// posture — see [`eval_cached`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum EvalCacheMode {
    /// Always eval; persist + shadow-compare + log. The conservative default.
    #[default]
    Shadow,
    /// Serve a validated cached config on a hit (skip the eval); eval on a miss.
    Skip,
}

/// Resolve the L0 mode from `ZAP_EVAL_CACHE`.
///
/// `skip` opts into the real eval skip; anything else (incl. unset) is the
/// conservative [`Shadow`](EvalCacheMode::Shadow) default. This sets the *posture*; the
/// `--no-cache` bust composes over it (forcing a fresh eval for one
/// run regardless — see [`eval_cached`]'s `bust`). Enabling `Skip` stays env-only by
/// design (it's the transitional bake-in opt-in; a persistent CLI/config enable waits
/// until shadow verification graduates `Skip` toward default-eligible).
#[must_use]
pub fn mode_from_env() -> EvalCacheMode {
    match std::env::var("ZAP_EVAL_CACHE").as_deref() {
        Ok("skip") => EvalCacheMode::Skip,
        _ => EvalCacheMode::Shadow,
    }
}

/// Evaluate a config through the L0 cache, with the pinned `fgro`.
///
/// The eval entry point **every** command core uses (via `commands::target::eval_target`
/// or `commands::target::eval_untargeted`), so no eval escapes the shadow-mismatch observation
/// that justifies the `Shadow` default.
///
/// [`Skip`](EvalCacheMode::Skip) mode tries a validated hit first (`lookup_hit`), which
/// runs nothing: it hashes the `fgro` binary through the pin cache, and a binary that
/// isn't the pin is no hit (the fresh eval then refuses it). Otherwise (a miss, or
/// [`Shadow`](EvalCacheMode::Shadow) mode) it evals fresh and runs
/// [`observe_and_persist`] to record the value + manifest. Advisory throughout: the
/// cache only ever *skips* an eval or *persists*; it never fails the eval, and a `None`
/// `zap_home` just means no caching.
///
/// `bust` is the per-run CLI force-fresh override (`--no-cache`). It composes *over*
/// `mode`: when set it suppresses the [`Skip`](EvalCacheMode::Skip) lookup, so the run
/// always evals fresh and re-persists — the bust **wins** over a `Skip` posture (the
/// cached value is ignored, then overwritten, leaving the cache warm).
/// In [`Shadow`](EvalCacheMode::Shadow) mode `bust` is nearly a no-op (Shadow already
/// evals every run); it still re-persists, and `observe_and_persist` may still emit a
/// shadow signal — informative here (the cache *was* stale), not a problem.
///
/// # Errors
/// Propagates eval failures from [`eval_config_raw`] (a throwing/invalid config, an
/// `fgro` that can't run or isn't the pin, a schema-parse failure).
pub async fn eval_cached(
    zap_home: Option<&Path>,
    config_path: &Path,
    fgro: PinnedFgro<'_>,
    mode: EvalCacheMode,
    bust: bool,
) -> crate::error::Result<ZapConfig> {
    if !bust
        && mode == EvalCacheMode::Skip
        && let Some(cached) = lookup_hit(zap_home, config_path, fgro).await
    {
        if std::env::var_os("ZAP_EVAL_CACHE_LOG").is_some() {
            eprintln!("{}", skipped_line(config_path));
        }
        return Ok(cached);
    }
    // Shadow mode (always), a Skip miss, or a bust: eval fresh, then persist + (shadow)
    // compare. On a Skip miss this re-validates the manifest a second time inside
    // `observe_and_persist`'s classify — negligible (a few file re-hashes) next to the
    // eval we just paid, and it keeps one persistence path.
    let fresh = eval_config_raw(config_path, fgro).await?;
    observe_and_persist(zap_home, config_path, &fresh);
    Ok(fresh.config)
}

/// Skip-mode hit lookup: a validated cached `ZapConfig`, or `None` (a miss — the
/// caller evals fresh). **Runs nothing**: it hashes the `fgro` binary (through the pin
/// cache, so an unchanged binary is a `stat`) and re-checks the manifest's files.
///
/// The binary must hash to the pin: a hit then serves only what that build computed,
/// and a binary that moved off its pin is a miss, whose fresh eval refuses it.
async fn lookup_hit(
    zap_home: Option<&Path>,
    config_path: &Path,
    fgro: PinnedFgro<'_>,
) -> Option<ZapConfig> {
    let dir = eval_cache_dir_for(zap_home?, config_path);
    let canonical = std::fs::canonicalize(config_path).ok()?;
    let now_fgro = current_pin(fgro.path, fgro.pin_cache).await.ok()?;
    if now_fgro != *fgro.pin {
        return None;
    }
    cached_hit(
        &dir,
        &EvalKey {
            config_path: &canonical.to_string_lossy(),
            driver_blake3: &driver_blake3(),
            fgro_blake3: now_fgro.as_str(),
            jit: JIT,
        },
    )
}

/// The pure core of `lookup_hit`: a validated cached config, or `None`. Re-hashes the
/// manifest's files and checks its absent paths (IO) but runs nothing.
fn cached_hit(dir: &Path, now: &EvalKey<'_>) -> Option<ZapConfig> {
    let manifest = read_manifest(dir)?;
    manifest.validate(now, hash_file, is_absent).ok()?;
    read_cached_config(dir, &manifest).ok()
}

/// blake3 hex of the embedded [`DRIVER_JS`] driver — the hash `fgro`'s envelope names.
#[must_use]
pub fn driver_blake3() -> String {
    blake3::hash(DRIVER_JS.as_bytes()).to_hex().to_string()
}

/// Persist the fresh eval output and report what the L0 cache would have done.
///
/// The `Shadow` orchestration (see the module docs). `config_path` is the path as
/// given, which names the cache directory; `fresh` is the eval that just ran: its
/// parsed config, its value (persisted as the cache value), the canonical path it
/// evaluated, the graph the manifest captures, and the `fgro` build it ran on.
/// Advisory — every failure degrades to a `Miss` or is swallowed; this never returns
/// an error.
pub fn observe_and_persist(
    zap_home: Option<&Path>,
    config_path: &Path,
    fresh: &EvaluatedConfig,
) -> EvalCacheObservation {
    let Some(zap_home) = zap_home else {
        return EvalCacheObservation::Disabled;
    };
    let dir = eval_cache_dir_for(zap_home, config_path);

    let observation = classify(&dir, fresh);
    // A `Hit` means the persisted value is still current; every other verdict
    // (re)captures the manifest + value (a miss has none/stale, a shadow-mismatch
    // refreshes to the fresh truth).
    if observation != EvalCacheObservation::Hit {
        persist(zap_home, &dir, fresh);
    }

    log_observation(config_path, &observation);
    observation
}

/// The key terms of `fresh`'s run.
fn fresh_key<'a>(fresh: &'a EvaluatedConfig, config_path: &'a str, driver: &'a str) -> EvalKey<'a> {
    EvalKey {
        config_path,
        driver_blake3: driver,
        fgro_blake3: fresh.fgro_blake3.as_str(),
        jit: JIT,
    }
}

/// Classify the would-be cache outcome without acting on it — pure but for the file
/// re-hashing in [`EvalInputs::validate`]. The persistence decision lives in the caller.
fn classify(dir: &Path, fresh: &EvaluatedConfig) -> EvalCacheObservation {
    let Some(prior) = read_manifest(dir) else {
        return EvalCacheObservation::Miss("no prior manifest".to_owned());
    };
    let config_path = fresh.config_path.to_string_lossy();
    let driver = driver_blake3();
    if let Err(reason) = prior.validate(
        &fresh_key(fresh, &config_path, &driver),
        hash_file,
        is_absent,
    ) {
        return EvalCacheObservation::Miss(reason);
    }
    // Manifest re-validated. A fresh eval matching the cached value is a safe hit; a
    // *present but differing* value is manifest under-capture (an uncaptured input
    // slipped the key) — the loud signal. A missing/unreadable value is just a miss
    // (e.g. the value file was deleted): don't cry under-capture when there's nothing
    // to compare against.
    match read_cached_config(dir, &prior) {
        Ok(cached) if cached == fresh.config => EvalCacheObservation::Hit,
        Ok(_) => EvalCacheObservation::ShadowMismatch,
        Err(CachedValue::Unreadable) => {
            EvalCacheObservation::Miss("cached value unreadable".to_owned())
        }
        Err(CachedValue::Unvouched) => {
            EvalCacheObservation::Miss("cached value doesn't match its manifest".to_owned())
        }
    }
}

/// Capture a fresh manifest and write it + the fresh value. Advisory: a capture that
/// can't place every id, or a write failure, leaves the cache as-is (the next run
/// re-captures).
fn persist(zap_home: &Path, dir: &Path, fresh: &EvaluatedConfig) {
    let Some(manifest) = capture(fresh, blake3::hash(fresh.value_json.as_bytes())) else {
        return;
    };
    let Ok(manifest_json) = serde_json::to_vec_pretty(&manifest) else {
        return;
    };
    // Write the value first, then the manifest: a manifest is only ever trusted
    // against a value that's already on disk.
    let _ = write_atomic(zap_home, dir, CONFIG_FILE, fresh.value_json.as_bytes());
    let _ = write_atomic(zap_home, dir, MANIFEST_FILE, &manifest_json);
}

/// The manifest of `fresh`'s run, vouching for the value whose bytes hash to `value`,
/// or `None` when the graph names an id it gives no path for (a graph this capture
/// can't vouch for is not cached).
fn capture(fresh: &EvaluatedConfig, value: blake3::Hash) -> Option<EvalInputs> {
    let (entries, absent) = capture_graph(&fresh.graph)?;
    Some(EvalInputs {
        eval_cache_version: EVAL_CACHE_VERSION,
        config_path: fresh.config_path.to_string_lossy().into_owned(),
        driver_blake3: driver_blake3(),
        fgro_blake3: fresh.fgro_blake3.as_str().to_owned(),
        jit: JIT,
        entries,
        absent,
        value_blake3: value.to_hex().to_string(),
    })
}

/// The inputs `graph` records: each module (by the blake3 of the bytes `fgro` read for
/// it), each consulted `package.json` with its role, and each absent path — every id's
/// path taken from `local.paths`, a module's under its id cut at the first `?` or `#`.
/// `None` when an id has no path there, or a module has no blake3 (which only a failed
/// run leaves, and a failed run is never cached).
fn capture_graph(graph: &GraphDump) -> Option<(Vec<InputEntry>, Vec<AbsentEntry>)> {
    let path_of = |id: &str| graph.local.paths.get(id).cloned();
    let mut entries = Vec::with_capacity(graph.modules.len() + graph.consulted.len());
    for module in &graph.modules {
        let file_id = module
            .id
            .split(['?', '#'])
            .next()
            .unwrap_or(module.id.as_str());
        entries.push(InputEntry {
            id: module.id.clone(),
            path: path_of(file_id)?,
            role: InputRole::Module,
            blake3: module.blake3.clone()?,
        });
    }
    for consulted in &graph.consulted {
        entries.push(InputEntry {
            id: consulted.id.clone(),
            path: path_of(&consulted.id)?,
            role: match consulted.role {
                DumpRole::Exports => InputRole::Exports,
                DumpRole::PackageScope => InputRole::PackageScope,
                DumpRole::SearchBound => InputRole::SearchBound,
                DumpRole::Version => InputRole::Version,
            },
            blake3: consulted.blake3.clone(),
        });
    }
    let absent = graph
        .absent
        .iter()
        .map(|id| {
            Some(AbsentEntry {
                id: id.clone(),
                path: path_of(id)?,
            })
        })
        .collect::<Option<Vec<_>>>()?;
    Some((entries, absent))
}

/// blake3 hex of a file's bytes, or `None` if it can't be read.
fn hash_file(path: &Path) -> Option<String> {
    let bytes = std::fs::read(path).ok()?;
    Some(blake3::hash(&bytes).to_hex().to_string())
}

/// Whether nothing stands at `path` — not even a dangling link. Anything there, or a
/// path that can't be checked, is not absent.
fn is_absent(path: &Path) -> bool {
    matches!(
        std::fs::symlink_metadata(path),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound
    )
}

/// Read + parse the persisted manifest, or `None` (advisory — absent/unreadable/stale
/// shape all read as "no prior manifest").
fn read_manifest(dir: &Path) -> Option<EvalInputs> {
    let bytes = std::fs::read(dir.join(MANIFEST_FILE)).ok()?;
    serde_json::from_slice(&bytes).ok()
}

/// Why no cached value is served beside a manifest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CachedValue {
    /// None is there, or it can't be read or parsed.
    Unreadable,
    /// Its bytes don't hash to the manifest's
    /// [`value_blake3`](EvalInputs::value_blake3): edited, swapped, or another run's.
    Unvouched,
}

/// Read + parse the persisted `ZapConfig` value `manifest` vouches for — a value whose
/// bytes don't hash to the manifest's [`value_blake3`](EvalInputs::value_blake3) is
/// [`Unvouched`](CachedValue::Unvouched), and one that does is parsed through
/// [`ZapConfig::from_wire`], the one way a config's JSON is read, so a cached value is
/// held to what a fresh eval's is.
fn read_cached_config(dir: &Path, manifest: &EvalInputs) -> Result<ZapConfig, CachedValue> {
    let json =
        std::fs::read_to_string(dir.join(CONFIG_FILE)).map_err(|_| CachedValue::Unreadable)?;
    if blake3::hash(json.as_bytes()).to_hex().as_str() != manifest.value_blake3 {
        return Err(CachedValue::Unvouched);
    }
    ZapConfig::from_wire(&json).map_err(|_| CachedValue::Unreadable)
}

/// The eval-cache log line for an eval a valid hit skipped.
fn skipped_line(config_path: &Path) -> String {
    format!(
        "zap: L0 eval-cache HIT (skipped eval) for {}",
        shown_path(config_path)
    )
}

/// A config path as a line of the eval-cache log shows it: the command line's text,
/// escaped.
fn shown_path(path: &Path) -> String {
    escape_line(&path.display().to_string()).into_owned()
}

/// Emit the shadow line ([`observation_line`]), when the observation has one.
fn log_observation(config_path: &Path, observation: &EvalCacheObservation) {
    let log = std::env::var_os("ZAP_EVAL_CACHE_LOG").is_some();
    if let Some(line) = observation_line(config_path, observation, log) {
        eprintln!("{line}");
    }
}

/// The eval-cache log line for `observation`. A
/// [`ShadowMismatch`](EvalCacheObservation::ShadowMismatch) is a correctness signal and
/// always has one; `Hit` / `Miss` / `Disabled` have one only with `log`
/// (`ZAP_EVAL_CACHE_LOG` — bake-in measurement, off by default to avoid noise). The
/// config path and a miss's reason are shown escaped.
fn observation_line(
    config_path: &Path,
    observation: &EvalCacheObservation,
    log: bool,
) -> Option<String> {
    let config = shown_path(config_path);
    let verdict = match observation {
        EvalCacheObservation::ShadowMismatch => {
            return Some(format!(
                "zap: L0 eval-cache SHADOW MISMATCH for {config} — a fresh eval differs \
                 from the cached output the manifest validated; an input is uncaptured. \
                 This run used the fresh eval and cached it; under ZAP_EVAL_CACHE=skip a \
                 later change to that input is served stale."
            ));
        }
        _ if !log => return None,
        EvalCacheObservation::Hit => "would HIT".to_owned(),
        EvalCacheObservation::Miss(reason) => {
            format!("would MISS ({})", escape_line(reason))
        }
        EvalCacheObservation::Disabled => "disabled".to_owned(),
    };
    Some(format!("zap: L0 eval-cache {verdict} for {config}"))
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use fuz_eval::{DumpConsulted, DumpFormat, DumpLocal, DumpModule, DumpOrigin};
    use zap_types::scalar::ContentHash;

    use super::*;

    // `EvalInputs::validate` re-validation logic is unit-tested in `zap_types::eval_inputs`
    // (pure, with injected IO). These tests cover the IO-side orchestration that lives
    // here: capture (`capture_graph`) and `classify` / `cached_hit`.
    /// The config every seeded manifest is for.
    const CONFIG: &str = "/test/zap.ts";

    /// The `fgro` build every seeded manifest is for.
    fn fgro_pin() -> ContentHash {
        ContentHash::new("f".repeat(64)).unwrap()
    }

    fn now<'a>(config: &'a str, fgro: &'a str, driver: &'a str) -> EvalKey<'a> {
        EvalKey {
            config_path: config,
            driver_blake3: driver,
            fgro_blake3: fgro,
            jit: false,
        }
    }

    /// An empty graph of a project at `/test`.
    fn graph() -> GraphDump {
        GraphDump {
            graph_version: 1,
            roots: vec!["project:zap.ts".to_owned()],
            modules: Vec::new(),
            consulted: Vec::new(),
            absent: Vec::new(),
            local: DumpLocal {
                project: "/test".to_owned(),
                box_roots: vec!["/test".to_owned()],
                paths: std::collections::BTreeMap::new(),
            },
        }
    }

    /// A fresh eval of [`CONFIG`] producing `config`, as `classify` is handed one.
    fn fresh(config: &ZapConfig) -> EvaluatedConfig {
        EvaluatedConfig {
            config: config.clone(),
            value_json: String::new(),
            config_path: PathBuf::from(CONFIG),
            graph: graph(),
            fgro_blake3: fgro_pin(),
        }
    }

    fn module(id: &str, blake3: Option<&str>) -> DumpModule {
        DumpModule {
            id: id.to_owned(),
            blake3: blake3.map(str::to_owned),
            origin: DumpOrigin::Project,
            format: Some(DumpFormat::Typescript),
            imports: Vec::new(),
        }
    }

    /// Each module, each consulted `package.json` with its role, and each absent path
    /// are captured by their `local.paths` path; a module's path is under its id cut at
    /// `?` or `#`.
    #[test]
    fn the_capture_is_the_graph_by_its_local_paths() {
        let mut graph = graph();
        graph.modules = vec![
            module("project:zap.ts", Some("aa")),
            module("project:dep.ts?x=1#y", Some("bb")),
        ];
        graph.consulted = vec![DumpConsulted {
            id: "project:package.json".to_owned(),
            blake3: "cc".to_owned(),
            role: DumpRole::PackageScope,
        }];
        graph.absent = vec!["project:sub/package.json".to_owned()];
        for (id, path) in [
            ("project:zap.ts", "/test/zap.ts"),
            ("project:dep.ts", "/test/dep.ts"),
            ("project:package.json", "/test/package.json"),
            ("project:sub/package.json", "/test/sub/package.json"),
        ] {
            graph.local.paths.insert(id.to_owned(), path.to_owned());
        }
        let (entries, absent) = capture_graph(&graph).unwrap();
        assert_eq!(
            entries,
            vec![
                InputEntry {
                    id: "project:zap.ts".to_owned(),
                    path: "/test/zap.ts".to_owned(),
                    role: InputRole::Module,
                    blake3: "aa".to_owned(),
                },
                InputEntry {
                    id: "project:dep.ts?x=1#y".to_owned(),
                    path: "/test/dep.ts".to_owned(),
                    role: InputRole::Module,
                    blake3: "bb".to_owned(),
                },
                InputEntry {
                    id: "project:package.json".to_owned(),
                    path: "/test/package.json".to_owned(),
                    role: InputRole::PackageScope,
                    blake3: "cc".to_owned(),
                },
            ]
        );
        assert_eq!(
            absent,
            vec![AbsentEntry {
                id: "project:sub/package.json".to_owned(),
                path: "/test/sub/package.json".to_owned(),
            }]
        );

        // An id with no path, and a module with no blake3, aren't captured at all.
        let mut unplaced = graph.clone();
        unplaced.local.paths.remove("project:sub/package.json");
        assert!(capture_graph(&unplaced).is_none());
        let mut unloaded = graph;
        unloaded.modules[1].blake3 = None;
        assert!(capture_graph(&unloaded).is_none());
    }

    /// Write a valid manifest (covering `module_file`) + a cached value into `dir`,
    /// so `classify` sees a re-validatable would-hit.
    fn seed_cache(dir: &Path, module_file: &Path, cached: &ZapConfig) {
        seed_value(dir, module_file, &serde_json::to_vec(cached).unwrap());
    }

    /// [`seed_cache`] with the value's bytes as given, the manifest vouching for them.
    fn seed_value(dir: &Path, module_file: &Path, value: &[u8]) {
        seed_manifest(dir, module_file, &driver_blake3(), value);
        std::fs::write(dir.join(CONFIG_FILE), value).unwrap();
    }

    fn seed_manifest(dir: &Path, module_file: &Path, driver: &str, value: &[u8]) {
        let manifest = EvalInputs {
            eval_cache_version: EVAL_CACHE_VERSION,
            config_path: CONFIG.to_owned(),
            driver_blake3: driver.to_owned(),
            fgro_blake3: fgro_pin().as_str().to_owned(),
            jit: false,
            entries: vec![InputEntry {
                id: "project:zap.ts".to_owned(),
                path: module_file.to_string_lossy().into_owned(),
                role: InputRole::Module,
                blake3: hash_file(module_file).unwrap(),
            }],
            absent: vec![AbsentEntry {
                id: "project:absent.ts".to_owned(),
                path: dir.join("absent.ts").to_string_lossy().into_owned(),
            }],
            value_blake3: blake3::hash(value).to_hex().to_string(),
        };
        std::fs::write(
            dir.join(MANIFEST_FILE),
            serde_json::to_vec(&manifest).unwrap(),
        )
        .unwrap();
    }

    fn config_with_resource(id: &str) -> ZapConfig {
        serde_json::from_value(serde_json::json!({
            "target": {"local": true},
            "resources": [{"id": id, "type": "directory", "path": "/tmp/x"}],
        }))
        .unwrap()
    }

    fn hit(dir: &Path, config: &str) -> Option<ZapConfig> {
        let fgro = fgro_pin();
        cached_hit(dir, &now(config, fgro.as_str(), &driver_blake3()))
    }

    /// A value another build cached is never served: its manifest names that build's
    /// driver, so it doesn't validate — whatever the value holds. And a cached value is
    /// read the way a fresh one is, so one this build can't parse — a marker written as
    /// a plain string — is no hit either.
    #[test]
    fn a_value_cached_by_another_build_is_never_served() {
        let dir = tempfile::tempdir().unwrap();
        let module = dir.path().join("zap.ts");
        std::fs::write(&module, b"export default () => {};").unwrap();
        let cached = config_with_resource("d");
        seed_cache(dir.path(), &module, &cached);
        assert_eq!(hit(dir.path(), CONFIG), Some(cached));

        // The same files under a manifest written by a build with another driver.
        let other: &[u8] = br#"{"target":{"local":true},"resources":[{"id":"d","type":"directory","path":"/srv/$$APP$$"}]}"#;
        seed_manifest(
            dir.path(),
            &module,
            &blake3::hash(b"another driver").to_hex(),
            other,
        );
        std::fs::write(dir.path().join(CONFIG_FILE), other).unwrap();
        assert_eq!(hit(dir.path(), CONFIG), None);
        assert_eq!(
            classify(dir.path(), &fresh(&ZapConfig::default())),
            EvalCacheObservation::Miss("the driver changed".to_owned())
        );

        // Under a manifest that does validate, a value holding a marker as a plain
        // string is unreadable, not a config — in a field that takes a reference, and
        // in one that takes none, where only the wire reading refuses it.
        for resource in [
            serde_json::json!({"id": "d", "type": "directory",
                               "path": zap_types::var_ref::marker("APP")}),
            serde_json::json!({"id": "s", "type": "service",
                               "service": zap_types::var_ref::marker("APP")}),
        ] {
            seed_value(
                dir.path(),
                &module,
                &serde_json::to_vec(&serde_json::json!({
                    "target": {"local": true}, "resources": [resource],
                }))
                .unwrap(),
            );
            assert_eq!(hit(dir.path(), CONFIG), None);
        }
    }

    /// A value another fgro build computed is never served.
    #[test]
    fn a_value_another_fgro_computed_is_never_served() {
        let dir = tempfile::tempdir().unwrap();
        let module = dir.path().join("zap.ts");
        std::fs::write(&module, b"export default () => {};").unwrap();
        seed_cache(dir.path(), &module, &config_with_resource("d"));
        let other = "e".repeat(64);
        assert_eq!(
            cached_hit(dir.path(), &now(CONFIG, &other, &driver_blake3())),
            None
        );
    }

    #[test]
    fn classify_misses_without_a_manifest() {
        let dir = tempfile::tempdir().unwrap();
        let observation = classify(dir.path(), &fresh(&ZapConfig::default()));
        assert_eq!(
            observation,
            EvalCacheObservation::Miss("no prior manifest".to_owned())
        );
    }

    #[test]
    fn classify_hits_when_manifest_valid_and_value_matches() {
        let dir = tempfile::tempdir().unwrap();
        let module = dir.path().join("zap.ts");
        std::fs::write(&module, b"export default () => {};").unwrap();
        let cached = config_with_resource("d");
        seed_cache(dir.path(), &module, &cached);

        // Fresh eval equals the cached value → safe would-hit.
        let observation = classify(dir.path(), &fresh(&cached));
        assert_eq!(observation, EvalCacheObservation::Hit);
    }

    #[test]
    fn classify_flags_shadow_mismatch_when_value_differs() {
        let dir = tempfile::tempdir().unwrap();
        let module = dir.path().join("zap.ts");
        std::fs::write(&module, b"export default () => {};").unwrap();
        seed_cache(dir.path(), &module, &config_with_resource("old"));

        // Manifest still validates, but a fresh eval produced a *different* config →
        // manifest under-capture, not a hit.
        let observation = classify(dir.path(), &fresh(&config_with_resource("new")));
        assert_eq!(observation, EvalCacheObservation::ShadowMismatch);
    }

    #[test]
    fn classify_misses_not_mismatches_when_value_is_gone() {
        let dir = tempfile::tempdir().unwrap();
        let module = dir.path().join("zap.ts");
        std::fs::write(&module, b"export default () => {};").unwrap();
        seed_cache(dir.path(), &module, &config_with_resource("d"));
        // Delete only the value: a valid manifest with nothing to compare against is a
        // miss, never a (loud) shadow mismatch.
        std::fs::remove_file(dir.path().join(CONFIG_FILE)).unwrap();

        let observation = classify(dir.path(), &fresh(&ZapConfig::default()));
        assert_eq!(
            observation,
            EvalCacheObservation::Miss("cached value unreadable".to_owned())
        );
    }

    #[test]
    fn cached_hit_returns_the_value_on_a_valid_manifest() {
        let dir = tempfile::tempdir().unwrap();
        let module = dir.path().join("zap.ts");
        std::fs::write(&module, b"export default () => {};").unwrap();
        let cached = config_with_resource("d");
        seed_cache(dir.path(), &module, &cached);

        // The skip path: a valid manifest serves the cached value verbatim.
        assert_eq!(hit(dir.path(), CONFIG), Some(cached));
    }

    /// A value is served only as the manifest vouches for it: one edited or swapped
    /// beside a manifest that still validates — a parseable config, another run's — is
    /// no hit, and no shadow comparison is made against it.
    #[test]
    fn a_value_the_manifest_does_not_vouch_for_is_never_served() {
        let dir = tempfile::tempdir().unwrap();
        let module = dir.path().join("zap.ts");
        std::fs::write(&module, b"export default () => {};").unwrap();
        let cached = config_with_resource("d");
        seed_cache(dir.path(), &module, &cached);
        assert_eq!(hit(dir.path(), CONFIG), Some(cached));

        let swapped = config_with_resource("swapped");
        std::fs::write(
            dir.path().join(CONFIG_FILE),
            serde_json::to_vec(&swapped).unwrap(),
        )
        .unwrap();
        assert_eq!(hit(dir.path(), CONFIG), None);
        assert_eq!(
            classify(dir.path(), &fresh(&swapped)),
            EvalCacheObservation::Miss("cached value doesn't match its manifest".to_owned())
        );
    }

    /// Two configs whose paths share a cache directory never serve each other's value.
    #[test]
    fn cached_hit_is_none_for_another_config() {
        let dir = tempfile::tempdir().unwrap();
        let module = dir.path().join("zap.ts");
        std::fs::write(&module, b"export default () => {};").unwrap();
        seed_cache(dir.path(), &module, &config_with_resource("d"));
        assert_eq!(hit(dir.path(), "/elsewhere/zap.ts"), None);
    }

    #[test]
    fn cached_hit_is_none_when_a_module_changed() {
        let dir = tempfile::tempdir().unwrap();
        let module = dir.path().join("zap.ts");
        std::fs::write(&module, b"export default () => {};").unwrap();
        seed_cache(dir.path(), &module, &config_with_resource("d"));
        // Edit the captured module → manifest no longer validates → miss (no skip).
        std::fs::write(&module, b"export default () => { /* changed */ };").unwrap();

        assert_eq!(hit(dir.path(), CONFIG), None);
    }

    /// Something appearing where a resolution found nothing — a file, or a dangling
    /// link — is a miss.
    #[test]
    fn cached_hit_is_none_when_an_absent_path_appears() {
        let dir = tempfile::tempdir().unwrap();
        let module = dir.path().join("zap.ts");
        std::fs::write(&module, b"export default () => {};").unwrap();
        let cached = config_with_resource("d");
        seed_cache(dir.path(), &module, &cached);
        assert_eq!(hit(dir.path(), CONFIG), Some(cached));
        std::os::unix::fs::symlink("/nowhere", dir.path().join("absent.ts")).unwrap();
        assert_eq!(hit(dir.path(), CONFIG), None);
    }

    #[tokio::test]
    async fn disabled_without_a_home() {
        let fresh = fresh(&ZapConfig::default());
        let observation = observe_and_persist(None, Path::new("/tmp/zap.ts"), &fresh);
        assert_eq!(observation, EvalCacheObservation::Disabled);
    }

    /// A config path reaches the eval-cache log escaped: it can't add a line to stderr
    /// or act on the terminal.
    #[test]
    fn the_log_shows_a_config_path_escaped() {
        assert_eq!(
            shown_path(Path::new("a\n\u{1b}[2Kzap: forged\u{200b}.ts")),
            "a<U+000A><U+001B>[2Kzap: forged<U+200B>.ts"
        );
        assert_eq!(shown_path(Path::new("site/zap.ts")), "site/zap.ts");
    }

    /// Each log line, word for word, with the config path and a miss's reason escaped
    /// — one line whatever they hold — and only the mismatch without the log switch.
    #[test]
    fn each_log_line_is_one_line() {
        const SHOWN: &str = "site<U+000A>zap: forged/zap.ts";
        let path = Path::new("site\nzap: forged/zap.ts");
        let miss = EvalCacheObservation::Miss("changed: a\r\u{1b}[2K\nzap: L0 forged".to_owned());
        assert_eq!(
            observation_line(path, &miss, true).unwrap(),
            format!(
                "zap: L0 eval-cache would MISS (changed: a<U+000D><U+001B>[2K<U+000A>zap: L0 \
                 forged) for {SHOWN}"
            )
        );
        assert_eq!(
            observation_line(path, &EvalCacheObservation::Hit, true).unwrap(),
            format!("zap: L0 eval-cache would HIT for {SHOWN}")
        );
        assert_eq!(
            observation_line(path, &EvalCacheObservation::Disabled, true).unwrap(),
            format!("zap: L0 eval-cache disabled for {SHOWN}")
        );
        let mismatch =
            observation_line(path, &EvalCacheObservation::ShadowMismatch, false).unwrap();
        assert!(
            mismatch.starts_with(&format!(
                "zap: L0 eval-cache SHADOW MISMATCH for {SHOWN} — "
            )),
            "{mismatch}"
        );
        assert!(!mismatch.contains('\n'));
        for quiet in [
            miss,
            EvalCacheObservation::Hit,
            EvalCacheObservation::Disabled,
        ] {
            assert_eq!(observation_line(path, &quiet, false), None);
        }
        assert_eq!(
            skipped_line(path),
            format!("zap: L0 eval-cache HIT (skipped eval) for {SHOWN}")
        );
    }
}
