//! L0 eval-cache inputs **and the pure re-validation policy** — the per-layer
//! analogue of [`config_hash::ConfigHashInputs`](crate::config_hash::ConfigHashInputs).
//!
//! [`EvalInputs`] names every input captured into the L0 cache key: the config it
//! evaluated, the driver's blake3 (the embedded eval driver in `zap_core::config`),
//! the pinned `fgro` binary's blake3, whether the JIT ran, the files the run read
//! (each module and each `package.json` a resolution consulted, as an
//! [`InputEntry`] with its blake3), the paths a resolution went past finding nothing
//! ([`AbsentEntry`]), and the [`EVAL_CACHE_VERSION`] domain separator. Everything
//! **not** represented here is, by construction, outside the cache key — see the type
//! docs for the deliberate non-captures (the cache leak surface).
//!
//! Unlike `ConfigHashInputs` (which forward-*hashes* its captured fields), `EvalInputs`
//! is **re-validated**: you cannot hash the transitive import graph without loading the
//! modules — the eval the cache exists to skip — so on a miss the graph `fgro`
//! reported is recorded and on the next run re-checked, cargo/ninja-shaped.
//! [`EvalInputs::validate`] is that re-validation; it serves a hit iff every key term
//! still matches.
//!
//! **Pure** like the rest of `zap_types`: the file re-hashing and the absence check are
//! *injected* as closures (mirroring `ConfigHashInputs`'s injected `resolve`), so the
//! filesystem IO lives in `zap_core` while the validity policy is testable here as data.
//! Capture — reading `fgro`'s module graph — is the IO half, in
//! `zap_core::config::eval_cache`. The persisted shape (`eval/manifest.json`) is an
//! on-disk contract, the same role [`LastRun`](crate::last_run::LastRun) plays for the
//! last-run report, which is why this typed value lives in `zap_types`.

use std::path::Path;

use serde::{Deserialize, Serialize};

/// Bump to invalidate every persisted L0 manifest.
///
/// It moves on a change to the emitted-JSON shape, the
/// [`ZapConfig`](crate::schema::ZapConfig) schema that parses it, the manifest's layout
/// or what it captures, or **how a config is evaluated**.
///
/// The L0 analogue of [`RESOURCE_HASH_VERSION`](crate::config_hash::RESOURCE_HASH_VERSION):
/// the manifest validates that the *input files* are unchanged, but the cached value is
/// already-emitted JSON parsed by the **current** binary's schema, so a schema move
/// underneath an old entry needs a domain separator (the driver's hash misses a pure
/// Rust-side schema change). A bump invalidates every L0 entry uniformly — the same
/// cheap escape a resource-hash bump gives the lock.
///
/// It also stands for everything about the evaluation the key has no term of its own
/// for: the arguments `fuz_eval` runs `fgro` with (the timeout among them), and which of
/// the graph's records the manifest takes as inputs. An entry written under one
/// invocation re-validates as a hit under another, so a change to either moves this
/// number with it.
pub const EVAL_CACHE_VERSION: u32 = 9;

/// Why a file is among the inputs: a module the run loaded, or a `package.json` a
/// resolution read, by what it was read for (`fgro`'s graph roles).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InputRole {
    /// A module the run loaded.
    Module,
    /// A package's `package.json`, for its `"exports"`.
    Exports,
    /// The nearest `package.json` above a module, for its `"type"`, or above an
    /// importer, for a self-reference.
    PackageScope,
    /// A `package.json` on the walk up for the project root.
    SearchBound,
    /// The `package.json` of the package an entry inside `node_modules` is in.
    Version,
}

/// One input file the run read, and the blake3 of the bytes it read. Re-hashed on the
/// next run; a changed hash (or a vanished file) is a miss.
///
/// `path` is **absolute**: it is `fgro`'s own record of where the id lives, so a
/// re-validation re-hashes the same file regardless of the run's working directory.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InputEntry {
    /// The graph's location-independent id (`project:<path>`, `linked:<path>`).
    pub id: String,
    /// Absolute path of the file.
    pub path: String,
    /// What the file was read as.
    pub role: InputRole,
    /// blake3 hex of the bytes the run read.
    pub blake3: String,
}

/// A path a resolution went past finding nothing there.
///
/// A `package.json` on a walk up, or a package directory in a `node_modules` the search
/// passed. A file or directory appearing there would change the resolution, so its
/// absence is an input.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AbsentEntry {
    /// The graph's id.
    pub id: String,
    /// Absolute path that was missing.
    pub path: String,
}

/// The complete set of inputs captured into the L0 eval-cache key — the inspectable,
/// re-validatable value the cache bets on.
///
/// Everything **not** represented here is, by construction, outside the key (the cache
/// leak surface). `fgro` gives the evaluated code no file read but its imports, no
/// environment, no clock and no randomness, and records every file a resolution read
/// and every path it found empty. What is left outside the key:
/// - **a symbolic link retargeted** — an entry is recorded at the real path its id
///   resolved to, so a `node_modules` link, or a link to a module inside the project,
///   pointed at other files leaves every recorded file as it was: a hit serves the
///   value the old target produced;
/// - **what `import.meta.resolve` resolved to** — its file is a module of the graph
///   only if it's also imported, and when it fails and the code catches it, the
///   `package.json` files it read are not recorded;
/// - **a directory's mode** — one a walk passed turning world-writable makes a fresh
///   run refuse, which a hit doesn't see;
/// - **the box's roots** — a link added to `node_modules` that changes the closure can
///   make a fresh run fail, which a hit doesn't see.
///
/// Where the project lives is captured: [`config_path`](Self::config_path), the
/// config's canonical path, is a term. References' values and the operator's
/// environment never reach the evaluation, so neither is an input.
///
/// The key is not complete, so `Skip` stays opt-in: **shadow** (a fresh eval compared
/// to the temporally-distant cached output) is what catches what it misses.
///
/// `ctx` is *not* a separate field: it is the constant `{}` baked into the driver, so
/// [`driver_blake3`](Self::driver_blake3) already captures it. When `--profile`
/// threads a non-empty `ctx` from Rust, add it here (and the store keys `slug × ctx`).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvalInputs {
    /// Domain separator — see [`EVAL_CACHE_VERSION`].
    pub eval_cache_version: u32,
    /// The canonical (absolute) path of the config this entry evaluated, the envelope's
    /// `entry.id`. The cache directory is named by a short digest of the path, so two
    /// configs can share one; an entry is only ever served for its own config.
    pub config_path: String,
    /// blake3 hex of the driver `fgro` ran the config through — invalidates on any
    /// driver change (incl. `ctx`, which lives in the driver).
    pub driver_blake3: String,
    /// blake3 hex of the `fgro` binary that evaluated, the project's toolchain pin.
    pub fgro_blake3: String,
    /// Whether the run had V8's JIT. zap evaluates jitless, so always `false`; a
    /// term so an entry can't outlive a change to it.
    pub jit: bool,
    /// The files the run read: each module, then each consulted `package.json` by
    /// role, as the graph lists them. Re-hashed to validate. Never empty for a usable
    /// entry: the config itself is one.
    pub entries: Vec<InputEntry>,
    /// The paths a resolution found nothing at. Each must still be missing.
    pub absent: Vec<AbsentEntry>,
    /// blake3 hex of the cached value's bytes (`eval/value.json`), the value this
    /// manifest vouches for. A value whose bytes hash otherwise is not served: a
    /// manifest re-validates its inputs, and this binds it to the one output they
    /// produced, so a value edited, swapped, or written by another run beside it is a
    /// miss.
    pub value_blake3: String,
}

/// The key terms a lookup checks an [`EvalInputs`] against, besides the files.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EvalKey<'a> {
    /// The canonical path of the config being evaluated.
    pub config_path: &'a str,
    /// blake3 hex of the driver this build runs.
    pub driver_blake3: &'a str,
    /// blake3 hex of the `fgro` binary this run would evaluate with.
    pub fgro_blake3: &'a str,
    /// Whether this run would have V8's JIT.
    pub jit: bool,
}

impl EvalInputs {
    /// Re-validate this manifest against the current key terms and on-disk state.
    ///
    /// Returns `Ok(())` for a would-hit, or `Err(reason)` naming the first mismatch.
    /// `hash_file` and `is_absent` are injected (the filesystem IO lives in
    /// `zap_core`), so this is the pure validity policy. `hash_file` returns the file's
    /// blake3 hex, or `None` for an unreadable/removed file (→ a miss); `is_absent`
    /// answers whether nothing stands at a path (anything there, or a path that can't
    /// be checked, is no longer absent → a miss).
    ///
    /// # Errors
    /// Returns the first mismatch reason: a version change, an entry for another config,
    /// a driver, `fgro` or JIT change, a manifest with no captured file (a capture that
    /// read nothing vouches for nothing), a changed/removed captured file, or something
    /// now standing where a resolution found nothing.
    pub fn validate(
        &self,
        now: &EvalKey<'_>,
        hash_file: impl Fn(&Path) -> Option<String>,
        is_absent: impl Fn(&Path) -> bool,
    ) -> Result<(), String> {
        if self.eval_cache_version != EVAL_CACHE_VERSION {
            return Err(format!(
                "eval_cache_version {} != {EVAL_CACHE_VERSION}",
                self.eval_cache_version
            ));
        }
        if self.config_path != now.config_path {
            return Err(format!("an entry for another config: {}", self.config_path));
        }
        if self.driver_blake3 != now.driver_blake3 {
            return Err("the driver changed".to_owned());
        }
        if self.fgro_blake3 != now.fgro_blake3 {
            return Err("the fgro binary changed".to_owned());
        }
        if self.jit != now.jit {
            return Err("the JIT setting changed".to_owned());
        }
        if self.entries.is_empty() {
            return Err("no captured modules".to_owned());
        }
        for entry in &self.entries {
            match hash_file(Path::new(&entry.path)) {
                Some(hash) if hash == entry.blake3 => {}
                Some(_) => return Err(format!("changed: {}", entry.path)),
                None => return Err(format!("unreadable/removed: {}", entry.path)),
            }
        }
        for entry in &self.absent {
            if !is_absent(Path::new(&entry.path)) {
                return Err(format!("now present: {}", entry.path));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A `hash_file` backed by an in-memory map — keeps `validate` tests pure (no IO).
    fn map_hasher(entries: &[(&str, &str)]) -> impl Fn(&Path) -> Option<String> {
        let owned: Vec<(String, String)> = entries
            .iter()
            .map(|(p, h)| ((*p).to_owned(), (*h).to_owned()))
            .collect();
        move |path: &Path| {
            let key = path.to_string_lossy();
            owned
                .iter()
                .find(|(p, _)| *p == key)
                .map(|(_, h)| h.clone())
        }
    }

    /// An `is_absent` over a set of paths that are present.
    fn present(paths: &[&str]) -> impl Fn(&Path) -> bool {
        let owned: Vec<String> = paths.iter().map(|p| (*p).to_owned()).collect();
        move |path: &Path| !owned.iter().any(|p| *p == path.to_string_lossy())
    }

    const CONFIG: &str = "/p/zap.ts";

    const NOW: EvalKey<'static> = EvalKey {
        config_path: CONFIG,
        driver_blake3: "driver-hash",
        fgro_blake3: "fgro-hash",
        jit: false,
    };

    fn module(path: &str, blake3: &str) -> InputEntry {
        InputEntry {
            id: format!("project:{path}"),
            path: path.to_owned(),
            role: InputRole::Module,
            blake3: blake3.to_owned(),
        }
    }

    fn inputs_with(entries: Vec<InputEntry>) -> EvalInputs {
        EvalInputs {
            eval_cache_version: EVAL_CACHE_VERSION,
            config_path: CONFIG.to_owned(),
            driver_blake3: "driver-hash".to_owned(),
            fgro_blake3: "fgro-hash".to_owned(),
            jit: false,
            entries,
            absent: Vec::new(),
            value_blake3: String::new(),
        }
    }

    #[test]
    fn validate_accepts_an_unchanged_manifest() {
        let inputs = inputs_with(vec![module("/p/dep.ts", "aaaa")]);
        let hasher = map_hasher(&[("/p/dep.ts", "aaaa")]);
        assert!(inputs.validate(&NOW, hasher, present(&[])).is_ok());
    }

    #[test]
    fn validate_rejects_a_changed_file() {
        let inputs = inputs_with(vec![module("/p/dep.ts", "aaaa")]);
        let hasher = map_hasher(&[("/p/dep.ts", "bbbb")]);
        let err = inputs.validate(&NOW, hasher, present(&[])).unwrap_err();
        assert!(err.starts_with("changed:"), "{err}");
    }

    #[test]
    fn validate_rejects_a_removed_file() {
        let inputs = inputs_with(vec![module("/gone.ts", "aa")]);
        let err = inputs
            .validate(&NOW, map_hasher(&[]), present(&[]))
            .unwrap_err();
        assert!(err.starts_with("unreadable/removed:"), "{err}");
    }

    /// A path a resolution found nothing at must still be missing: a `package.json` or
    /// a package directory appearing there changes what resolves.
    #[test]
    fn validate_rejects_an_absent_path_that_appeared() {
        let mut inputs = inputs_with(vec![module(CONFIG, "aaaa")]);
        inputs.absent.push(AbsentEntry {
            id: "project:package.json".to_owned(),
            path: "/p/sub/package.json".to_owned(),
        });
        let hasher = map_hasher(&[(CONFIG, "aaaa")]);
        assert!(inputs.validate(&NOW, &hasher, present(&[])).is_ok());
        assert_eq!(
            inputs
                .validate(&NOW, &hasher, present(&["/p/sub/package.json"]))
                .unwrap_err(),
            "now present: /p/sub/package.json"
        );
    }

    #[test]
    fn validate_rejects_a_driver_fgro_or_jit_change_and_a_version_bump() {
        let inputs = inputs_with(vec![]);
        for (now, reason) in [
            (
                EvalKey {
                    driver_blake3: "new-driver",
                    ..NOW
                },
                "the driver changed",
            ),
            (
                EvalKey {
                    fgro_blake3: "new-fgro",
                    ..NOW
                },
                "the fgro binary changed",
            ),
            (EvalKey { jit: true, ..NOW }, "the JIT setting changed"),
        ] {
            assert_eq!(
                inputs
                    .validate(&now, map_hasher(&[]), present(&[]))
                    .unwrap_err(),
                reason
            );
        }

        let mut stale = inputs_with(vec![]);
        stale.eval_cache_version = EVAL_CACHE_VERSION + 1;
        assert!(
            stale
                .validate(&NOW, map_hasher(&[]), present(&[]))
                .unwrap_err()
                .contains("eval_cache_version")
        );
    }

    /// An entry is served only for the config it evaluated, and only when it captured
    /// something: an entry for another config sharing the directory, and one whose
    /// capture read no file, are misses.
    #[test]
    fn validate_rejects_another_config_and_an_empty_capture() {
        let inputs = inputs_with(vec![module(CONFIG, "aaaa")]);
        let hasher = map_hasher(&[(CONFIG, "aaaa")]);
        assert!(
            inputs
                .validate(
                    &EvalKey {
                        config_path: "/q/zap.ts",
                        ..NOW
                    },
                    &hasher,
                    present(&[])
                )
                .unwrap_err()
                .starts_with("an entry for another config")
        );
        assert_eq!(
            inputs_with(vec![])
                .validate(&NOW, &hasher, present(&[]))
                .unwrap_err(),
            "no captured modules"
        );
    }

    /// The leak-surface contract, assertable: the captured key is **exactly** these
    /// fields, so adding an input is a deliberate, reviewed schema change (and a
    /// reference's value / env read — outside this set — can never be a captured input).
    #[test]
    fn captured_surface_is_exactly_the_named_inputs() {
        let inputs = inputs_with(vec![module(CONFIG, "aaaa")]);
        let value = serde_json::to_value(&inputs).unwrap();
        let mut keys: Vec<&str> = value
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            [
                "absent",
                "config_path",
                "driver_blake3",
                "entries",
                "eval_cache_version",
                "fgro_blake3",
                "jit",
                "value_blake3",
            ],
            "the captured surface changed — anything not here is the leak surface \
             shadow must certify; adding a field is a deliberate version bump"
        );
    }

    /// A manifest an older build wrote (another layout) doesn't parse as this one, so
    /// it reads as no manifest rather than as a partial key.
    #[test]
    fn an_older_layout_does_not_parse() {
        let old = serde_json::json!({
            "eval_cache_version": 7,
            "config_path": CONFIG,
            "builder_js_hash": "b",
            "deno_version": "2.8.0",
            "modules": [{"path": CONFIG, "blake3": "aaaa"}],
        });
        assert!(serde_json::from_value::<EvalInputs>(old).is_err());
    }
}
