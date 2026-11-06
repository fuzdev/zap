//! `zap.lock` schema — the operator intent ledger (committed to git).
//!
//! Load/save IO is `zap_core`; this is the format contract only. The lock pins the
//! toolchain that evaluates the config ([`Toolchain`]: the `fgro` binary's blake3)
//! beside its per-resource entries, keyed by `resource_id`. The entry is a
//! `kind`-discriminated union: *pins* carry causal authority (the operator committed to an exact content identity) and *witnesses*
//! diagnostic authority (what the last apply observed). The `remote_file`, `build`,
//! and `apt_key` pins are built — `installed_version` witnesses slot in as a variant
//! when a config gains an `installs.version` field to exercise them.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::scalar::ContentHash;
use crate::schema::ResourceId;

/// Lock format version. Any schema change bumps it (strict-schema discipline — no
/// additive forward-compat; an older reader refuses a newer lock).
///
/// Version 2 added [`ZapLock::toolchain`]; version 3 the [`LockEntry::AptKey`] kind. A
/// version 1 lock still reads, with no toolchain pin, so it refuses every eval until
/// `zap lock` pins one; a version 2 lock reads as it is, and is written as version 3.
pub const LOCK_VERSION: u32 = 3;

/// The toolchain a project's configs are evaluated with: the `fgro` binary, by its
/// blake3.
///
/// Written by `zap lock` from the binary it evaluated with; every other command
/// evaluates only through a binary that hashes to it. A build of `fgro` is not
/// reproducible across machines, so the pin names one build: a new build, or the
/// same build on another machine that doesn't share its bytes, is a stale pin until
/// `zap lock` records it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Toolchain {
    /// The `fgro` binary's blake3, 64 lowercase hex.
    pub fgro_blake3: ContentHash,
}

/// A single lock entry, discriminated by `kind`.
///
/// Each variant carries its own per-resource `config_hash` (the fixed point — the
/// *output* of [`compute_config_hash`] with the entry's pinned state folded in, not
/// a hash input itself — so `lock --check` can detect a config that outgrew its
/// entry). Pin entries (`remote_file`, `build`, `apt_key`) record the exact identity the next
/// apply compares against; an `installed_version` witness kind would be a further
/// variant.
///
/// [`compute_config_hash`]: crate::config_hash::compute_config_hash
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum LockEntry {
    /// A pin for a *tracked* `zap.file remote` (no `blake3` declared in config): the
    /// resolved content hash the next apply compares the target file/sentinel
    /// against. `zap update` re-fetches and advances it. A *vendored* file (a
    /// declared `blake3`) self-pins in-config and writes **no** lock entry.
    RemoteFile {
        /// The per-resource config hash that produced this entry (the fixed point).
        config_hash: String,
        /// The resolved content pin (blake3 hex). Folded into `config_hash` so
        /// advancing the pin moves it like any other desired-state change. The content
        /// cache is
        /// content-addressed by this value, so it doubles as the integrity check —
        /// `size` is deliberately omitted (decorative beside blake3).
        blake3: ContentHash,
    },
    /// A pin for a *tracked* `build` source (no `blake3` declared in config): the
    /// resolved blake3 of the source archive the build is produced from — the build's
    /// provenance. `zap update` re-fetches the source and advances it; the executor
    /// records a digest over it and the build in the output's sidecar
    /// ([`build_provenance`](crate::config_hash::build_provenance)) so detection can
    /// compare.
    /// A *vendored* source (a declared `blake3`) self-pins in-config and writes **no**
    /// lock entry.
    Build {
        /// The per-resource config hash that produced this entry (the fixed point).
        config_hash: String,
        /// The resolved source content pin (blake3 hex), folded into `config_hash`.
        blake3: ContentHash,
    },
    /// A pin for a *tracked* `apt_repo` signing key (no `key_blake3` declared in
    /// config): the blake3 of the key's bytes. The executor installs only bytes that
    /// hash to it, and detection compares the installed key against it. `zap update`
    /// re-fetches and advances it. A *vendored* key self-pins in-config and writes
    /// **no** lock entry.
    AptKey {
        /// The per-resource config hash that produced this entry (the fixed point).
        config_hash: String,
        /// The resolved key pin (blake3 hex), folded into `config_hash`.
        blake3: ContentHash,
    },
}

impl LockEntry {
    /// The per-resource `config_hash` recorded on this entry.
    #[must_use]
    pub fn config_hash(&self) -> &str {
        match self {
            Self::RemoteFile { config_hash, .. }
            | Self::Build { config_hash, .. }
            | Self::AptKey { config_hash, .. } => config_hash,
        }
    }

    /// The pinned identity to fold into [`compute_config_hash`] (the value, *not* the
    /// entry's own `config_hash` field). Every pin kind folds its content blake3.
    ///
    // TODO: when `InstalledVersion` (version) witnesses land, each returns its folded
    // identity here — the triad folds pins *and* witnesses. Keep this the single
    // fold-source so the cache invalidates uniformly across kinds. `Build`
    // (tarball-source) already folds its source blake3 (a git-source build would fold a
    // commit instead).
    ///
    /// [`compute_config_hash`]: crate::config_hash::compute_config_hash
    #[must_use]
    pub const fn pin(&self) -> Option<&ContentHash> {
        match self {
            Self::RemoteFile { blake3, .. }
            | Self::Build { blake3, .. }
            | Self::AptKey { blake3, .. } => Some(blake3),
        }
    }
}

/// The lock file: the toolchain pin and the per-resource entries keyed by
/// `resource_id`. `BTreeMap` for stable, diff-friendly ordering.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ZapLock {
    /// Lock format version (any schema change bumps it).
    pub version: u32,
    /// The toolchain the config is evaluated with. `None` in a lock no `zap lock`
    /// has pinned one in (a version 1 lock), which refuses every eval; not written
    /// when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub toolchain: Option<Toolchain>,
    /// Entries keyed by resource id.
    pub entries: BTreeMap<ResourceId, LockEntry>,
}

impl Default for ZapLock {
    fn default() -> Self {
        Self {
            version: LOCK_VERSION,
            toolchain: None,
            entries: BTreeMap::new(),
        }
    }
}
