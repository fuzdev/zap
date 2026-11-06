//! Which `fgro` evaluates a config, and the blake3 it must hash to.
//!
//! **The binary** is the operator's setting: `--fgro <path>` on the command line, else
//! `ZAP_FGRO` in the environment ([`fgro_setting`]). Either must be an absolute path;
//! nothing is looked up on `PATH`, so the binary that runs is the one named. `sudo`
//! resets the environment, so under `sudo` only the flag reaches zap.
//!
//! **The pin** is the project's: `zap.lock`'s [`Toolchain`] records the blake3 of the
//! binary `zap lock` evaluated with ([`locked_pin`]), and every other command evaluates
//! only through a binary that hashes to it. A lock with no pin refuses the eval
//! ([`Error::ToolchainUnpinned`]); a binary that doesn't hash to it is
//! [`Error::FgroPinMismatch`]. `zap lock` computes the pin ([`current_pin`]) and
//! records it.
//!
//! **The pin cache.** Hashing the binary on every eval reads all of it, so
//! `fuz_eval` keeps a stat-keyed hash cache in a directory of its caller's choosing:
//! here `~/.zap/cache/fgro_pins/` ([`pin_cache_dir`]). `fuz_eval` requires it to be
//! the effective uid's own, which `~/.zap` already is by its own rule
//! (`crate::home::claim_state_dirs`): under `sudo` zap's home is root's (`sudo` sets
//! `HOME`), and a user's `~/.zap` reached as root is refused before any eval, so the
//! cache is per effective uid by construction and needs no branch of its own. With no
//! `~/.zap`, the binary is hashed on every eval.
//!
//! [`Toolchain`]: zap_types::lock::Toolchain

use std::path::{Path, PathBuf};

use zap_types::scalar::ContentHash;

use crate::config::eval::map_eval_error;
use crate::error::{Error, Result};
use crate::home::ensure_state_dir;
use crate::lock::{lock_path_for, read_zap_lock};

/// The environment variable that names the `fgro` binary when `--fgro` doesn't.
pub const FGRO_VAR: &str = "ZAP_FGRO";

/// The flag that names the `fgro` binary, over [`FGRO_VAR`].
pub const FGRO_FLAG: &str = "--fgro";

/// The pin cache's directory under `~/.zap/cache/`. A config slug always ends in
/// `-<8 hex>`, so none is this name.
pub const PIN_CACHE_DIR: &str = "fgro_pins";

/// The `fgro` binary the operator named: `flag` (`--fgro`) when given, else
/// `ZAP_FGRO`. `None` when neither names one, which an eval refuses
/// ([`Error::FgroUnset`]); a command that evaluates nothing never asks.
///
/// # Errors
/// [`Error::FgroNotAbsolute`] when the one that decides is empty or relative: a
/// relative path would be resolved against wherever zap happens to run, which is
/// not a statement of which binary to trust.
pub fn fgro_setting(flag: Option<&str>) -> Result<Option<PathBuf>> {
    if let Some(flag) = flag {
        return absolute(FGRO_FLAG, flag.into()).map(Some);
    }
    std::env::var_os(FGRO_VAR).map_or(Ok(None), |value| absolute(FGRO_VAR, value.into()).map(Some))
}

/// `path`, when it is absolute.
fn absolute(from: &'static str, path: PathBuf) -> Result<PathBuf> {
    if path.is_absolute() {
        Ok(path)
    } else {
        Err(Error::FgroNotAbsolute { from })
    }
}

/// The `fgro` an eval runs: the operator's setting, or [`Error::FgroUnset`].
///
/// # Errors
/// [`Error::FgroUnset`] when `fgro` is `None`.
pub fn require_fgro(fgro: Option<&Path>) -> Result<&Path> {
    fgro.ok_or(Error::FgroUnset)
}

/// The toolchain pin `config_path`'s lock records.
///
/// Read before the config is evaluated, so before any secret it references is known to
/// the masker: a lock that doesn't parse is reported by where it fails, never by the
/// text there, which a later, masked read of the same lock would quote.
///
/// # Errors
/// [`Error::ToolchainUnpinned`] when there is no lock or it pins no toolchain; the
/// lock's own read errors ([`read_zap_lock`]), a parse error by position only.
pub fn locked_pin(config_path: &Path) -> Result<ContentHash> {
    let path = lock_path_for(config_path);
    read_zap_lock(&path)
        .map_err(|error| match error {
            Error::LockParse { path, source } => Error::LockParse {
                path,
                source: <serde_json::Error as serde::de::Error>::custom(format!(
                    "not a lock zap reads ({:?} error at line {} column {})",
                    source.classify(),
                    source.line(),
                    source.column()
                )),
            },
            other => other,
        })?
        .and_then(|lock| lock.toolchain)
        .map(|toolchain| toolchain.fgro_blake3)
        .ok_or_else(|| Error::ToolchainUnpinned {
            lock: path.display().to_string(),
        })
}

/// The blake3 of the `fgro` binary at `fgro`, as `fuz_eval` checks a pin — the pin
/// `zap lock` records, and what `zap lock --check` compares the lock's to. Through the
/// pin cache when there is one.
///
/// # Errors
/// The binary can't be opened, isn't one `fuz_eval` will run, or the cache directory
/// breaks its rule — mapped as an eval's would be.
pub async fn current_pin(fgro: &Path, pin_cache: Option<&Path>) -> Result<ContentHash> {
    let (fgro, pin_cache) = (fgro.to_path_buf(), pin_cache.map(Path::to_path_buf));
    let hash =
        tokio::task::spawn_blocking(move || fuz_eval::fgro_blake3(&fgro, pin_cache.as_deref()))
            .await
            .map_err(|error| Error::ConfigIo(std::io::Error::other(error)))?
            .map_err(map_eval_error)?;
    ContentHash::new(hash).map_err(|error| {
        Error::ConfigIo(std::io::Error::other(format!(
            "fgro's blake3 is not 64 lowercase hex: {error}"
        )))
    })
}

/// `~/.zap/cache/fgro_pins/`, the pin cache `fuz_eval` keys the binary's hash in.
///
/// Made zap's own like every directory of the home. `None` with no home, or when the
/// directory can't be made: the cache is advisory, and without it the binary is hashed
/// on every eval. A directory that is there and isn't zap's own is refused earlier, by
/// `crate::home::claim_state_dirs`, with the rest of the home.
#[must_use]
pub fn pin_cache_dir(zap_home: Option<&Path>) -> Option<PathBuf> {
    let home = zap_home?;
    let dir = home.join("cache").join(PIN_CACHE_DIR);
    ensure_state_dir(home, &dir).ok().map(|()| dir)
}

#[cfg(test)]
mod tests {
    use super::*;
    use zap_types::lock::LOCK_VERSION;

    #[test]
    fn a_relative_or_empty_flag_is_refused() {
        for flag in ["fgro", "./fgro", ""] {
            assert!(
                matches!(
                    fgro_setting(Some(flag)),
                    Err(Error::FgroNotAbsolute { from: FGRO_FLAG })
                ),
                "{flag:?}"
            );
        }
        assert_eq!(
            fgro_setting(Some("/opt/fgro")).unwrap(),
            Some(PathBuf::from("/opt/fgro"))
        );
    }

    #[test]
    fn an_eval_with_no_fgro_is_refused() {
        assert!(matches!(require_fgro(None), Err(Error::FgroUnset)));
    }

    /// No lock, and a lock with no toolchain (a version 1 lock), both refuse naming the
    /// lock.
    #[test]
    fn a_missing_pin_refuses_naming_the_lock() {
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("zap.ts");
        let lock = dir.path().join("zap.lock");
        let unpinned = |error: Error| match error {
            Error::ToolchainUnpinned { lock: named } => {
                assert_eq!(named, lock.display().to_string());
            }
            other => panic!("expected an unpinned toolchain, got {other:?}"),
        };
        unpinned(locked_pin(&config).unwrap_err());
        std::fs::write(&lock, r#"{"version": 1, "entries": {}}"#).unwrap();
        unpinned(locked_pin(&config).unwrap_err());
        let pin = "a".repeat(64);
        std::fs::write(
            &lock,
            format!(
                r#"{{"version": {LOCK_VERSION}, "toolchain": {{"fgro_blake3": "{pin}"}}, "entries": {{}}}}"#
            ),
        )
        .unwrap();
        assert_eq!(locked_pin(&config).unwrap().as_str(), pin);
    }

    /// A lock that doesn't parse is named by position, never by the text it holds: it
    /// is read before the masker knows any secret.
    #[test]
    fn an_unparsable_lock_is_named_without_its_text() {
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("zap.ts");
        std::fs::write(
            dir.path().join("zap.lock"),
            r#"{"version": "hunter2", "entries": {}}"#,
        )
        .unwrap();
        let error = locked_pin(&config).unwrap_err();
        assert!(matches!(error, Error::LockParse { .. }), "{error:?}");
        let rendered = error.render();
        assert!(!rendered.contains("hunter2"), "{rendered}");
        assert!(rendered.contains("line 1 column"), "{rendered}");
    }
}
