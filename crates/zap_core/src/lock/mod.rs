//! `zap.lock` IO — load/save, the classification of a config's entries, and the
//! cold-start resolve pass that mints missing tracked pins.
//!
//! A write holds an advisory `flock` on the lock file, confirmed to still be the file at
//! its path, and replaces it as deterministic JSON ([`update_zap_lock`],
//! [`write_zap_lock`]).
//!
//! The lock is the operator's intent ledger (committed to git): for a *tracked*
//! `zap.file remote` (no `blake3` in config) it pins the resolved content blake3, for a
//! *tracked* `build` source (no `blake3` in config) the resolved source blake3 — the
//! build's provenance — and for a *tracked* `apt_repo` key (no `key_blake3`) the key's
//! blake3. Detection compares the target against the pin and
//! `config_hash` folds it. A *vendored* file/source (a declared `blake3`) self-pins
//! in-config and writes **no** entry.
//!
//! The lock is committed, so an entry's `config_hash` is public. [`LockAddressing`] is
//! one config's addressing — the value every path here mints and verifies through — and
//! its address function resolves a secret reference ([`SecretRule::classify`], the rule
//! the masker registers by) to its fixed [`masked_token`] instead of its value, and
//! folds a plain value as the masker prints it, so a secret held inside one stands as
//! its token too: an address can't be used to test guesses at a secret. Two limits: a
//! secret shorter than `secret::ADDRESS_MIN_CHARS` inside a plain value is folded as it
//! is, and an entry whose address takes a plain value is not minted while a secret the
//! config references is unset, since the value could hold it unmasked; checked then, a
//! matching address reads current and a changed one unverifiable.
//!
//! Resolution is **fetch-and-hash** (the [`resolver`]): GET the url,
//! compute blake3. The resolve pass runs during planning (the one network IO a
//! dry-run does); only a `--wetrun` persists the result (the operator-side ledger
//! write — not a target mutation). `zap update` re-fetches and advances pins;
//! `zap lock` re-baselines; `zap lock --check` is a pure (no-network) config↔lock
//! consistency gate.
//!
//! [`classify_lock`] is the whole-config predicate behind both that gate and the
//! read-only commands: one [`LockStanding`] per config, so `lock --check`'s verdict
//! and the standing `plan` / `detect` / `status` / deploy-preflight report can't drift
//! apart.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use zap_types::config_hash::compute_config_hash;
use zap_types::lock::{LOCK_VERSION, LockEntry, ZapLock};
use zap_types::observe::apt_repo::KEY_READ_MAX;
use zap_types::scalar::ContentHash;
use zap_types::schema::{
    AptRepoResource, BuildSource, FileContent, RemoteAuth, RemoteContent, RemoteSource, Resource,
    ResourceId, ResourceKind, SourceVerify, ZapConfig,
};
use zap_types::secrecy::{Secrecy, SecretReason, SecretRule};
use zap_types::text::Text;
use zap_types::var_ref::{self, masked_token};

use crate::error::{Error, Result};
use crate::escape::escape_line;
use crate::resolve::env_var;
use crate::resolver;

/// Derive the lock path adjacent to the config — its filename with the extension
/// swapped to `.lock`: `zap.ts` → `zap.lock`, `configs/local.zap.ts` →
/// `configs/local.zap.lock`.
#[must_use]
pub fn lock_path_for(config_path: &Path) -> PathBuf {
    let mut path = config_path.to_path_buf();
    path.set_extension("lock");
    path
}

/// Refuse a config whose own name is its lock's: a file named `*.lock` maps to itself
/// ([`lock_path_for`]), so writing its lock would write over the config.
///
/// # Errors
/// [`Error::ConfigNamedLikeLock`] naming the config.
pub fn refuse_lock_named_config(config_path: &Path) -> Result<()> {
    if lock_path_for(config_path) == config_path {
        return Err(Error::ConfigNamedLikeLock {
            path: config_path.display().to_string(),
        });
    }
    Ok(())
}

/// Why a symbolic link where the lock goes is refused, by a read and a write alike.
const LOCK_LINK_REFUSAL: &str = "it is a symbolic link, and zap replaces the lock file rather \
                                 than writing through a link — put the lock itself beside the \
                                 config";

/// The bytes of the regular file at `path`, opened with no link at its name followed:
/// a symbolic link is [`LOCK_LINK_REFUSAL`], anything else that isn't a regular file
/// (a directory, a FIFO a read would block on) is refused too.
fn read_regular(path: &Path) -> std::io::Result<Vec<u8>> {
    use std::io::Read as _;
    use std::os::unix::fs::OpenOptionsExt as _;

    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
        .open(path)
        .map_err(|error| {
            if std::fs::symlink_metadata(path).is_ok_and(|found| found.file_type().is_symlink()) {
                std::io::Error::new(std::io::ErrorKind::InvalidInput, LOCK_LINK_REFUSAL)
            } else {
                error
            }
        })?;
    if !file.metadata()?.is_file() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "it is not a regular file",
        ));
    }
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    Ok(bytes)
}

/// Read the lock at `path`, or `Ok(None)` when it's absent (no lock yet).
///
/// The lock is a regular file read with no link at its name followed: a symbolic link
/// there is refused, as the write refuses it (`LockGuard`).
///
/// An empty file is no lock too: a writer's guard creates the file empty before the
/// lock's first write renames the real one over it, so a first write that was killed
/// in between leaves an empty `zap.lock`, which holds nothing.
///
/// Errors on an unreadable file or one that isn't a regular file, malformed JSON, or a
/// future format version this zap can't read (strict-schema discipline — never a
/// partial parse).
///
/// # Errors
/// [`Error::LockIo`] on a read failure, [`Error::LockParse`] on malformed JSON,
/// [`Error::LockVersion`] on a newer-than-supported format.
pub fn read_zap_lock(path: &Path) -> Result<Option<ZapLock>> {
    #[derive(serde::Deserialize)]
    struct VersionOnly {
        version: u32,
    }
    let bytes = match read_regular(path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(source) => {
            return Err(Error::LockIo {
                path: path.display().to_string(),
                source,
            });
        }
    };
    if bytes.is_empty() {
        return Ok(None);
    }
    // the version first, so a newer format refuses as one even when its shape no
    // longer parses as this zap's
    if let Ok(VersionOnly { version }) = serde_json::from_slice(&bytes)
        && version > LOCK_VERSION
    {
        return Err(Error::LockVersion {
            path: path.display().to_string(),
            found: version,
            supported: LOCK_VERSION,
        });
    }
    let lock: ZapLock = serde_json::from_slice(&bytes).map_err(|source| Error::LockParse {
        path: path.display().to_string(),
        source,
    })?;
    Ok(Some(lock))
}

/// Write `lock` to `path` atomically (temp+rename) under the lock's guard
/// (`LockGuard`), without reading what is there.
///
/// A whole-file replacement, for a writer whose lock is the whole intent (`zap lock`'s
/// re-baseline) — which is why it never parses the old file: a lock that doesn't parse
/// (merge-conflict markers) is what a re-baseline rebuilds. A writer that changes some
/// entries goes through [`update_zap_lock`], which reads what is there under the same
/// guard.
///
/// # Errors
/// As [`update_zap_lock`], but nothing is read.
pub fn write_zap_lock(path: &Path, lock: &ZapLock) -> Result<()> {
    let guard = LockGuard::take(path)?;
    let mut lock = lock.clone();
    guard.write(&mut lock)
}

/// Read the lock at `path`, let `update` change it, and write it back, under one guard.
///
/// The lock read is empty when there is none; the write is atomic (temp+rename), and the
/// guard (`LockGuard`) serializes writers, so neither loses the other's entries.
/// Returns what was written.
///
/// # Errors
/// As `LockGuard::take` and `LockGuard::write`; the errors of [`read_zap_lock`] for
/// what is there.
pub fn update_zap_lock(path: &Path, update: impl FnOnce(&mut ZapLock)) -> Result<ZapLock> {
    let guard = LockGuard::take(path)?;
    let mut lock = match read_zap_lock(path) {
        Ok(lock) => lock.unwrap_or_default(),
        Err(error) => return Err(guard.abandon(error)),
    };
    update(&mut lock);
    guard.write(&mut lock)?;
    Ok(lock)
}

/// The advisory exclusive `flock` every lock writer holds: on the lock file itself,
/// opened read-write (created empty when there is none, which an exclusive `flock` on a
/// network filesystem needs), and confirmed, once held, to still be the file at the
/// path — same device and inode, its descriptor's against the name's.
///
/// A writer replaces the file by renaming a new one over it while it holds the lock on
/// the old one, and that rename is the last thing its critical section changes. A writer
/// that was waiting then holds a lock on a file no longer at the path, finds the
/// identities differ, and takes the lock again on the file that is. So whoever holds a
/// confirmed guard holds the one lock on what the path names, and no file is left
/// beside the lock. It is **advisory** (the lock holds operator-side authority, not the
/// engine).
struct LockGuard<'a> {
    path: &'a Path,
    held: nix::fcntl::Flock<std::fs::File>,
}

impl<'a> LockGuard<'a> {
    /// Take the guard on the lock at `path`, creating its directory.
    ///
    /// Nothing is opened through a link: a symlink at `path` is refused, since the
    /// write's rename would replace the link with a file, which is not what a linked
    /// lock was set up for.
    ///
    /// # Errors
    /// [`Error::LockIo`] on a directory-create, open, `flock`, or `stat` failure, or a
    /// link at `path`.
    fn take(path: &'a Path) -> Result<Self> {
        use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};

        use nix::fcntl::{Flock, FlockArg};

        let io = |source: std::io::Error| Error::LockIo {
            path: path.display().to_string(),
            source,
        };
        std::fs::create_dir_all(lock_dir(path)).map_err(io)?;
        loop {
            let file = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(false)
                .custom_flags(nix::libc::O_NOFOLLOW)
                .open(path)
                .map_err(|error| {
                    io(
                        if std::fs::symlink_metadata(path)
                            .is_ok_and(|found| found.file_type().is_symlink())
                        {
                            std::io::Error::new(std::io::ErrorKind::InvalidInput, LOCK_LINK_REFUSAL)
                        } else if error.kind() == std::io::ErrorKind::PermissionDenied {
                            // The guard opens the lock read-write, which an exclusive
                            // `flock` on a network filesystem needs, and creates it when
                            // it isn't there.
                            let message = if std::fs::symlink_metadata(path).is_ok() {
                                format!(
                                    "{} is not writable: {error}; zap rewrites it, so give it \
                                     write permission",
                                    path.file_name().map_or_else(
                                        || path.display(),
                                        |name| Path::new(name).display()
                                    )
                                )
                            } else {
                                format!(
                                    "its directory {} is not writable: {error}; zap creates the \
                                     lock there, so give it write permission",
                                    lock_dir(path).display()
                                )
                            };
                            std::io::Error::new(error.kind(), message)
                        } else {
                            error
                        },
                    )
                })?;
            let held =
                Flock::lock(file, FlockArg::LockExclusive).map_err(|(_, errno)| Error::LockIo {
                    path: path.display().to_string(),
                    source: std::io::Error::from(errno),
                })?;
            let opened = held.metadata().map_err(io)?;
            match std::fs::symlink_metadata(path) {
                Ok(named) if named.dev() == opened.dev() && named.ino() == opened.ino() => {
                    return Ok(Self { path, held });
                }
                // Renamed over (or removed) while this waited: lock what is there now.
                Ok(_) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(io(error)),
            }
        }
    }

    /// Give up the guard after `error`, first removing the file it holds when that is
    /// still empty and still the file at the path — one the guard created, which no write
    /// replaced — so a first write that fails leaves no empty `zap.lock` behind. Returns
    /// `error`.
    fn abandon(self, error: Error) -> Error {
        use std::os::unix::fs::MetadataExt as _;

        if let Ok(held) = self.held.metadata()
            && held.len() == 0
            && std::fs::symlink_metadata(self.path)
                .is_ok_and(|named| named.dev() == held.dev() && named.ino() == held.ino())
        {
            let _ = std::fs::remove_file(self.path);
        }
        error
        // `self.held` drops here → flock released, after the removal.
    }

    /// Write `lock` over the guarded file atomically (temp+rename), then release; a write
    /// that fails is [`abandon`](Self::abandon)ed.
    ///
    /// JSON is `serde_json` pretty over the `BTreeMap`-keyed entries + fixed struct/enum
    /// field order — deterministic *and* diff-friendly for git.
    ///
    /// The written `version` is always the current [`LOCK_VERSION`], never the one that
    /// was parsed: [`read_zap_lock`] accepts any version `<= LOCK_VERSION`, so echoing
    /// the parsed value back would strand an older file at its old version forever — the
    /// first bump would leave files nothing ever rewrites. Every writer comes here, so
    /// the stamp is the single upgrade-in-place point.
    ///
    /// The temp file is created new — whatever stands at its name is removed first — and
    /// is removed again if the write or the rename fails.
    ///
    /// # Errors
    /// [`Error::LockIo`] on a serialize, temp-write, rename, or directory-sync failure.
    fn write(self, lock: &mut ZapLock) -> Result<()> {
        match self.replace(lock) {
            Ok(()) => Ok(()),
            Err(error) => Err(self.abandon(error)),
        }
        // `self.held` drops here → flock released.
    }

    /// [`write`](Self::write)'s replacement, the guard still held.
    fn replace(&self, lock: &mut ZapLock) -> Result<()> {
        let path = self.path;
        let io = |source: std::io::Error| Error::LockIo {
            path: path.display().to_string(),
            source,
        };
        lock.version = LOCK_VERSION;
        // Pretty JSON + trailing newline: deterministic (BTreeMap entries iterate sorted;
        // struct/tagged-enum fields serialize in a fixed order) and reads/diffs cleanly.
        let mut json = serde_json::to_string_pretty(&*lock).map_err(|source| Error::LockParse {
            path: path.display().to_string(),
            source,
        })?;
        json.push('\n');

        let dir = lock_dir(path);
        let name = path.file_name().map_or_else(
            || std::ffi::OsString::from("zap.lock"),
            std::ffi::OsStr::to_owned,
        );
        let tmp = dir.join(format!(
            ".{}.tmp.{}",
            name.to_string_lossy(),
            std::process::id()
        ));
        // Write + fsync the temp, rename, then fsync the parent dir. The lock is the
        // operator's authoritative, version-controlled intent ledger (not regenerable), so
        // a crash between the rename and the directory-entry flush must not leave it
        // pointing at unflushed bytes.
        replace_through(&tmp, path, json.as_bytes()).map_err(io)?;
        std::fs::File::open(dir)
            .and_then(|d| d.sync_all())
            .map_err(io)
    }
}

/// Put `bytes` at `path` by writing them to `tmp` ([`write_new`]) and renaming it over
/// `path`; a failure of either leaves no file at `tmp`.
fn replace_through(tmp: &Path, path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let replaced = write_new(tmp, bytes).and_then(|()| std::fs::rename(tmp, path));
    if replaced.is_err() {
        let _ = std::fs::remove_file(tmp);
    }
    replaced
}

/// Write `bytes` to a file created new at `path` and flush it to disk. Whatever stands
/// at the name — a temp file an earlier run with this pid left, a link — is removed
/// first and never written through.
fn write_new(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write as _;
    match std::fs::remove_file(path) {
        Err(error) if error.kind() != std::io::ErrorKind::NotFound => return Err(error),
        _ => {}
    }
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()
}

/// The directory a lock at `path` lives in — where its temp file is staged and what is
/// fsynced after the rename.
///
/// A bare file name (`zap.lock`, beside the default `zap.ts`) has the empty path as its
/// parent, which names no directory: it is the current one, `.`.
fn lock_dir(path: &Path) -> &Path {
    match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    }
}

// TODO: `installed_version` witnesses are the lock's remaining kind. When they land,
// `TrackedSource` gains a kind and `LockAddressing::resolve_entry` its minting.
// Witnesses also need the bareword-`zap update` pin-only scoping.
/// Which [`LockEntry`] variant a tracked source's pin is recorded as.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TrackedKind {
    /// A tracked `zap.file remote`.
    RemoteFile,
    /// A tracked `build` source.
    Build,
    /// A tracked `apt_repo` signing key.
    AptKey,
}

/// A lock-eligible resource's fetch: a `zap.file remote` or a `build` source with **no**
/// `blake3` declared in config, or an `apt_repo` key with no `key_blake3`, so its pin
/// lives in the lock. A vendored one (a declared pin) self-pins in-config and is not
/// tracked.
struct TrackedSource<'a> {
    kind: TrackedKind,
    /// The fetch url, as declared.
    url: &'a Text,
    /// The resource's path field the address resolves (`file.path` / `build.output`);
    /// `None` for an `apt_repo`, whose key path takes no reference.
    path: Option<&'a Text>,
    auth: Option<&'a RemoteAuth>,
    verify: Option<&'a SourceVerify>,
    /// The most bytes the fetch may take, when the kind bounds them (an `apt_repo` key:
    /// what detection can read back, `KEY_READ_MAX`); `None` is the content cap.
    max: Option<u64>,
}

impl<'a> TrackedSource<'a> {
    /// `resource`'s tracked source, or `None` for a vendored or non-eligible resource.
    const fn of(resource: &'a Resource) -> Option<Self> {
        match &resource.kind {
            ResourceKind::File(file) => match &file.content {
                FileContent::Remote(RemoteContent {
                    url,
                    auth,
                    blake3: None,
                    ..
                }) => Some(Self {
                    kind: TrackedKind::RemoteFile,
                    url,
                    path: Some(&file.path),
                    auth: auth.as_ref(),
                    // a `remote` file has no upstream-signature verification.
                    verify: None,
                    max: None,
                }),
                _ => None,
            },
            ResourceKind::Build(build) => match &build.source {
                BuildSource::Remote(RemoteSource {
                    url,
                    auth,
                    verify,
                    blake3: None,
                    ..
                }) => Some(Self {
                    kind: TrackedKind::Build,
                    url,
                    path: Some(&build.output),
                    auth: auth.as_ref(),
                    verify: verify.as_ref(),
                    max: None,
                }),
                // a vendored source self-pins in-config — no lock entry.
                BuildSource::Remote(_) => None,
            },
            ResourceKind::AptRepo(AptRepoResource {
                key_url,
                key_blake3: None,
                ..
            }) => Some(Self {
                kind: TrackedKind::AptKey,
                url: key_url,
                path: None,
                // the key is checked against its pin, not a signature: what it signs is
                // what apt checks.
                auth: None,
                verify: None,
                max: Some(KEY_READ_MAX as u64),
            }),
            _ => None,
        }
    }

    /// The entry recording `blake3` as this source's pin, addressed by `config_hash`.
    const fn entry(&self, config_hash: String, blake3: ContentHash) -> LockEntry {
        match self.kind {
            TrackedKind::RemoteFile => LockEntry::RemoteFile {
                config_hash,
                blake3,
            },
            TrackedKind::Build => LockEntry::Build {
                config_hash,
                blake3,
            },
            TrackedKind::AptKey => LockEntry::AptKey {
                config_hash,
                blake3,
            },
        }
    }

    /// The variable names in the fields an entry's address **resolves**: the url and
    /// the path. `auth` is outside the content address, and a `build`'s `run` / `cwd` /
    /// `env` are addressed as written, so neither is scanned.
    fn address_refs(&self) -> BTreeSet<String> {
        self.url
            .ref_names()
            .chain(self.path.into_iter().flat_map(Text::ref_names))
            .map(str::to_owned)
            .collect()
    }
}

/// Whether a resource's pin lives in the lock — a tracked `remote_file`, a tracked
/// `build` source (no in-config `blake3`), or a tracked `apt_repo` key (no in-config
/// `key_blake3`).
///
/// The single eligibility predicate the lock commands (`zap lock` / `zap update`) and
/// the cold-start [`resolve_lock`] all share.
#[must_use]
pub const fn is_lock_eligible(resource: &Resource) -> bool {
    TrackedSource::of(resource).is_some()
}

/// A tracked lock entry's standing against the current config.
///
/// The single predicate shared by apply's [`resolve_lock`] (enforcement) and `lock
/// --check` (the gate), so the gate and the enforcement can't drift.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EntryStatus {
    /// The recomputed `config_hash` matches the entry — the pin is current.
    Current,
    /// The recomputed `config_hash` differs — the config (or a non-secret reference it
    /// resolves) changed since the pin was minted. Run `zap update <id>`.
    Stale,
    /// A hash-relevant reference is unset in the current env, so `config_hash` can't be
    /// recomputed faithfully. **Fail closed** — never `Current`: an unset var resolves
    /// to empty, which would both mask real drift *and* manufacture a misleading
    /// `Stale`, so the only safe answer is "can't tell — provide the env." A variable
    /// that is secret whether or not it is set never blocks: the address holds its
    /// fixed token either way.
    Unverifiable {
        /// The unset variables' names blocking verification (sorted).
        unresolved: Vec<String>,
    },
}

/// How one config's lock entries are addressed: the config's rule for which
/// references are secret, bound to the operations that depend on it.
///
/// Minting ([`resolve_entry`](Self::resolve_entry)) and verification
/// ([`classify_entry`](Self::classify_entry)) are methods of one value built from one
/// [`ZapConfig`] ([`of`](Self::of), the only constructor), and both go through
/// [`entry_config_hash`](Self::entry_config_hash) — so an entry can't be minted under
/// one rule and verified under another, or under none.
#[derive(Debug, Clone)]
pub struct LockAddressing {
    secrets: SecretRule,
    /// Every variable the config references, in any field — the names whose secret
    /// values the masker registers ([`crate::secret::build_registry`]).
    names: BTreeSet<String>,
}

impl LockAddressing {
    /// The addressing `config` declares: its [`SecretRule`], over the variables it
    /// references.
    #[must_use]
    pub fn of(config: &ZapConfig) -> Self {
        Self {
            secrets: SecretRule::of(config),
            names: crate::secret::scan_env_var_names(config),
        }
    }

    /// How the address takes a reference to `name` in the environment `env_get` reads.
    fn secrecy(&self, name: &str, env_get: &impl Fn(&str) -> Option<String>) -> Secrecy {
        self.secrets.classify(name, env_get(name).as_deref())
    }

    /// A lock entry's `config_hash` for `resource` with `pin_entry`'s pin folded — the
    /// one address function minting and verification share.
    ///
    /// Each reference in a hashed field resolves through `env_get`, except a
    /// secret one, which resolves to its fixed [`masked_token`]. So the address moves
    /// when a non-secret value changes (the staleness signal) and never with a secret's
    /// value: a committed `config_hash` gives nothing to test a guess at the secret
    /// against. A variable that is secret only by the form of its value — a url holding
    /// a password — is addressed by its token while it has that form, and by value
    /// again once it doesn't, so losing or gaining the form reads stale and a changed
    /// password doesn't. Only the address is masked; a fetch still resolves the url's
    /// real value.
    ///
    /// A non-secret value is folded as the masker would print it: a secret value the
    /// config registers anywhere ([`crate::secret::build_registry`]) that occurs inside
    /// it — a signed url carrying another variable's token — stands as that variable's
    /// token, so a plain value carries no set secret of at least
    /// `secret::ADDRESS_MIN_CHARS` characters into the address. A secret that is unset
    /// can't be found in a value: minting refuses the entry then, and verification
    /// reads a mismatch as unverifiable ([`classify_entry`](Self::classify_entry)).
    ///
    /// # Errors
    /// [`Error::ConfigHash`] if the resource can't be hashed; [`Error::Secret`] if a
    /// registered value holds a masking token.
    pub fn entry_config_hash(
        &self,
        resource: &Resource,
        pin_entry: &LockEntry,
        env_get: impl Fn(&str) -> Option<String>,
    ) -> Result<String> {
        let masker = crate::secret::masker_of(
            &self.names,
            &self.secrets,
            &env_get,
            crate::secret::ADDRESS_MIN_CHARS,
        )?;
        let resolve = |input: &str| {
            var_ref::map_refs(input, |name| {
                let value = env_get(name);
                if self.secrets.classify(name, value.as_deref()).is_secret() {
                    masked_token(name)
                } else {
                    masker.mask(&value.unwrap_or_default())
                }
            })
        };
        compute_config_hash(resource, resolve, Some(pin_entry)).map_err(Error::ConfigHash)
    }

    /// The references in `resource`'s address that are addressed **by name only** because
    /// they read as secrets — by their name, or by the form of the value `env_get`
    /// resolves (sorted by name). Empty for a resource that isn't lock-eligible.
    ///
    /// A change to such a variable's value never reads stale, which is the point for a
    /// secret and a lost signal for a variable that only looks like one; the lock
    /// commands list these so the operator can `unmask` it. A name the config lists in
    /// `mask`, or uses as a fetch credential, is addressed by name too, but by the
    /// config's own statement, so it isn't listed.
    #[must_use]
    pub fn name_only_refs(
        &self,
        resource: &Resource,
        env_get: impl Fn(&str) -> Option<String>,
    ) -> Vec<NameOnlyRef> {
        TrackedSource::of(resource)
            .map(|source| source.address_refs())
            .unwrap_or_default()
            .into_iter()
            .filter_map(|name| match self.secrecy(&name, &env_get) {
                Secrecy::Secret(reason) if reason.by_shape() => Some(NameOnlyRef { name, reason }),
                Secrecy::Secret(_) | Secrecy::Plain => None,
            })
            .collect()
    }

    /// The unset variables' names `resource`'s address depends on (sorted): the
    /// references in its resolved hashed fields that are no secret while unset.
    ///
    /// A reference that is secret by its role, the config's `mask`, or its name is not
    /// counted for itself: its token is folded, never its value, so the address is the
    /// same with it unset. One that would be secret only by its value's form is
    /// counted: unset, it has none.
    fn unresolved_hash_vars(
        &self,
        resource: &Resource,
        env_get: &impl Fn(&str) -> Option<String>,
    ) -> Vec<String> {
        self.plain_refs(resource, env_get)
            .into_iter()
            .filter(|name| is_unset(name, env_get))
            .collect()
    }

    /// The references of `resource`'s address that are no secret.
    fn plain_refs(
        &self,
        resource: &Resource,
        env_get: &impl Fn(&str) -> Option<String>,
    ) -> Vec<String> {
        TrackedSource::of(resource)
            .map(|source| source.address_refs())
            .unwrap_or_default()
            .into_iter()
            .filter(|name| !self.secrecy(name, env_get).is_secret())
            .collect()
    }

    /// When `resource`'s address takes a plain value, every variable the config
    /// references that is a secret while unset (by its role, `mask`, or name) and is
    /// unset (sorted). A plain value is folded with each set secret inside it masked
    /// ([`entry_config_hash`](Self::entry_config_hash)); an unset one can't be found
    /// there, so the value would be folded with the secret in it.
    fn unset_hidden_secrets(
        &self,
        resource: &Resource,
        env_get: &impl Fn(&str) -> Option<String>,
    ) -> Vec<String> {
        if self.plain_refs(resource, env_get).is_empty() {
            return Vec::new();
        }
        self.names
            .iter()
            .filter(|name| self.secrets.classify(name, None).is_secret())
            .filter(|name| is_unset(name, env_get))
            .cloned()
            .collect()
    }

    /// Classify a lock-eligible resource's lock entry against the current config — pure
    /// modulo the injected `env_get` (no network, no detection).
    ///
    /// Kind-agnostic: it folds the entry's own pin (`LockEntry::pin`) regardless of
    /// variant, so it serves tracked `remote_file`, `build`, and `apt_key` entries alike.
    ///
    /// Fail-safe by construction: an unset hash-relevant, non-secret reference yields
    /// [`EntryStatus::Unverifiable`], never [`EntryStatus::Current`], so neither the
    /// gate nor apply silently passes an entry it couldn't actually check. The match
    /// itself recomputes the address with the entry folded as its own pin (the fixed
    /// point — [`entry_config_hash`](Self::entry_config_hash), the call
    /// [`resolve_entry`](Self::resolve_entry) mints with) and compares to the stored
    /// `config_hash`.
    ///
    /// A secret the config references that is unset can't be masked in a plain value
    /// (`unset_hidden_secrets`), but only a mismatch can be its doing: a match shows the
    /// bytes folded are the ones minted, and gives away nothing the committed address
    /// doesn't. So a match reads current, and a mismatch with such a secret unset reads
    /// unverifiable, naming it, rather than stale — the value may hold the secret,
    /// unmasked.
    ///
    /// # Errors
    /// [`Error::ConfigHash`] if the resource can't be hashed. Callers pass only
    /// lock-eligible resources.
    pub fn classify_entry(
        &self,
        resource: &Resource,
        entry: &LockEntry,
        env_get: impl Fn(&str) -> Option<String>,
    ) -> Result<EntryStatus> {
        let unresolved = self.unresolved_hash_vars(resource, &env_get);
        if !unresolved.is_empty() {
            return Ok(EntryStatus::Unverifiable { unresolved });
        }
        let recomputed = self.entry_config_hash(resource, entry, &env_get)?;
        if recomputed == entry.config_hash() {
            return Ok(EntryStatus::Current);
        }
        let hidden = self.unset_hidden_secrets(resource, &env_get);
        Ok(if hidden.is_empty() {
            EntryStatus::Stale
        } else {
            EntryStatus::Unverifiable { unresolved: hidden }
        })
    }

    /// Resolve a lock-eligible resource from upstream (fetch, verify, hash) and mint its
    /// lock entry — the single minting site, for a tracked `remote_file`, `build` source,
    /// and `apt_repo` key alike.
    ///
    /// An `apt_repo` key's fetch stops past `KEY_READ_MAX` and fails: no pin is minted
    /// for a key detection couldn't read back to compare.
    ///
    /// The pin is the fetched bytes' blake3 — for a `build`, the source archive's, which
    /// the provenance `execute_build` records in the `<output>.zap-build` sidecar is a
    /// digest over. A declared
    /// `verify` runs in the resolver before the pin exists, so a tampered source never
    /// becomes an entry. The entry's `config_hash` is
    /// [`entry_config_hash`](Self::entry_config_hash) with the fresh pin folded (the
    /// fixed point; the entry's own `config_hash` field is never an input), read from
    /// the operator env the fetch resolved its url from.
    ///
    /// # Errors
    /// [`Error::EntryNotResolvable`] for a resource that isn't lock-eligible; a
    /// content-resolution error (`Error::{FetchVarUnset,Fetch,AuthUnset,
    /// SignatureVerification,CacheWrite}`) on a fetch/verify failure — a url reference
    /// that is unset or empty refuses the fetch, so no pin is minted from another url's
    /// bytes; [`Error::ConfigHash`] if the resource can't be hashed.
    pub async fn resolve_entry(&self, resource: &Resource, zap_home: &Path) -> Result<LockEntry> {
        let Some(source) = TrackedSource::of(resource) else {
            return Err(Error::EntryNotResolvable {
                id: resource.id.0.clone(),
                expected: "lock-eligible",
            });
        };
        // Nor is one minted while a secret its plain value could hold is unset: the
        // address would fold the secret unmasked. (An unset url reference refuses the
        // fetch below.)
        let unresolved = self.unset_hidden_secrets(resource, &env_var);
        if !unresolved.is_empty() {
            return Err(Error::LockUnverifiable {
                id: resource.id.0.clone(),
                vars: unresolved.join(", "),
            });
        }
        let resolved = resolver::resolve_content_within(
            zap_home,
            source.url,
            None,
            source.auth,
            source.verify,
            source.max,
        )
        .await?;
        let pin = resolved.blake3;
        let probe = source.entry(String::new(), pin.clone());
        let config_hash = self.entry_config_hash(resource, &probe, env_var)?;
        Ok(source.entry(config_hash, pin))
    }
}

/// Whether `name` is unset *or empty* — an exported-but-blank var would fold `""` into
/// the hash and read as a confident `Current`/`Stale`, the fail-open
/// [`EntryStatus::Unverifiable`] exists to prevent. Matches the `unresolved_env_vars` /
/// `unverifiable_env_vars` predicate.
fn is_unset(name: &str, env_get: &impl Fn(&str) -> Option<String>) -> bool {
    env_get(name).is_none_or(|value| value.is_empty())
}

/// An eligible resource whose lock entry can't be verified — a hash-relevant reference
/// is unset in the current env.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnverifiableEntry {
    /// The resource id.
    pub id: String,
    /// The unset variables' names blocking verification (sorted).
    pub vars: Vec<String>,
}

/// A reference a lock entry addresses by name only because it reads as a secret.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NameOnlyRef {
    /// The variable.
    pub name: String,
    /// What makes it read as one: its name, or the form of its value.
    pub reason: SecretReason,
}

/// An eligible resource and the references its lock entry addresses by name
/// only because they read as secrets ([`LockAddressing::name_only_refs`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NameOnlyRefs {
    /// The resource id.
    pub id: String,
    /// The references (sorted by name), never empty.
    pub vars: Vec<NameOnlyRef>,
}

/// Each of `resources` whose address names a reference by name only, in the order given.
///
/// What `zap lock` and `zap lock --check` report for a config's eligible resources, and
/// `zap update` for its targets. Derived from `config`, the resources, and the
/// environment `env_get` reads, whatever became of their entries.
#[must_use]
pub fn name_only_refs<'a>(
    config: &ZapConfig,
    resources: impl IntoIterator<Item = &'a Resource>,
    env_get: impl Fn(&str) -> Option<String>,
) -> Vec<NameOnlyRefs> {
    let addressing = LockAddressing::of(config);
    resources
        .into_iter()
        .filter_map(|resource| {
            let vars = addressing.name_only_refs(resource, &env_get);
            (!vars.is_empty()).then(|| NameOnlyRefs {
                id: resource.id.0.clone(),
                vars,
            })
        })
        .collect()
}

/// Append one line per [`NameOnlyRefs`] to `out`: which references read as secrets and
/// by what, what that does to the address, and how to make one count by value.
pub fn render_name_only_refs(out: &mut String, name_only: &[NameOnlyRefs]) {
    use std::fmt::Write as _;
    for entry in name_only {
        let refs: Vec<String> = entry
            .vars
            .iter()
            .map(|var| {
                let shown = var_ref::shown(&escape_line(&var.name));
                match var.reason {
                    SecretReason::Value(shape) => {
                        format!("{shown} (its value is {})", shape.describe())
                    }
                    SecretReason::Name | SecretReason::Declared | SecretReason::Credential => {
                        format!("{shown} (named like a secret)")
                    }
                }
            })
            .collect();
        let _ = writeln!(
            out,
            "note: `{}`: {} — addressed by name only (the value is not part of the lock \
             address, and a change to it never reads stale); `unmask` any that is not a \
             secret",
            escape_line(&entry.id),
            refs.join(", ")
        );
    }
}

/// A whole config's standing against its lock — every eligible resource classified,
/// plus the entries no eligible resource claims.
///
/// The one verdict `zap lock --check` renders as its gate and the read-only commands
/// (`plan` / `detect` / `status` / deploy-preflight) carry as a leading banner, so a
/// standing the gate calls an error can't read as fine anywhere else. The three error
/// standings share a meaning: **the ledger does not answer for this resource**, which
/// is why the read-only commands withhold those pins from detection rather than
/// comparing against one they can't vouch for.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LockStanding {
    /// Eligible resources declared in config but missing a lock entry.
    pub missing: Vec<String>,
    /// Eligible resources whose lock entry no longer matches the config — config (or a
    /// non-secret reference it resolves) changed since the pin was minted. Run `zap
    /// update <id>`.
    pub stale: Vec<String>,
    /// Eligible resources whose lock entry can't be recomputed — a hash-relevant,
    /// non-secret reference is unset (fail closed rather than fold an empty value).
    pub unverifiable: Vec<UnverifiableEntry>,
    /// Lock entries no longer matching an eligible declared resource (warn-only — only
    /// `zap lock` prunes them).
    pub orphans: Vec<String>,
}

impl LockStanding {
    /// Whether any eligible resource's pin is missing, stale, or unverifiable — the
    /// standings that mean the ledger doesn't answer for this config.
    ///
    /// Orphans are excluded: an orphan is an entry for a resource the config no longer
    /// declares, so it can't make any *declared* resource unresolved.
    #[must_use]
    pub const fn has_errors(&self) -> bool {
        !self.missing.is_empty() || !self.stale.is_empty() || !self.unverifiable.is_empty()
    }

    /// The number of eligible resources the ledger doesn't answer for.
    #[must_use]
    pub const fn error_count(&self) -> usize {
        self.missing.len() + self.stale.len() + self.unverifiable.len()
    }

    /// `1` if any eligible resource is missing, stale, or unverifiable; orphans alone
    /// stay `0`.
    #[must_use]
    pub fn exit_code(&self) -> u8 {
        u8::from(self.has_errors())
    }
}

/// Classify every lock-eligible resource's entry against the current config — pure
/// modulo the injected `env_get` (no network, no detection).
///
/// The whole-config lift of [`LockAddressing::classify_entry`], under `config`'s own
/// addressing: `zap lock --check` renders the result as its gate verdict, and the
/// read-only commands use it to decide which pins are trustworthy enough to detect
/// against. One predicate, so the CI gate and the per-command banner are the same claim.
///
/// # Errors
/// [`Error::ConfigHash`] if a resource can't be hashed.
pub fn classify_lock(
    config: &ZapConfig,
    lock: &ZapLock,
    env_get: impl Fn(&str) -> Option<String>,
) -> Result<LockStanding> {
    let addressing = LockAddressing::of(config);
    let mut standing = LockStanding::default();
    let mut eligible_ids = BTreeSet::new();
    for resource in config.resources.iter().filter(|r| is_lock_eligible(r)) {
        eligible_ids.insert(&resource.id);
        let Some(entry) = lock.entries.get(&resource.id) else {
            standing.missing.push(resource.id.0.clone());
            continue;
        };
        match addressing.classify_entry(resource, entry, &env_get)? {
            EntryStatus::Current => {}
            EntryStatus::Stale => standing.stale.push(resource.id.0.clone()),
            EntryStatus::Unverifiable { unresolved } => {
                standing.unverifiable.push(UnverifiableEntry {
                    id: resource.id.0.clone(),
                    vars: unresolved,
                });
            }
        }
    }
    standing.orphans = lock
        .entries
        .keys()
        .filter(|id| !eligible_ids.contains(id))
        .map(|id| id.0.clone())
        .collect();
    Ok(standing)
}

/// The lock a read-only command should detect against, and the [`LockStanding`] that
/// produced it: the on-disk entries **retained to the `Current` ones**.
///
/// Withholding is the whole mechanism behind "read-only commands validate": a stale or
/// unverifiable pin is dropped, so the resource behaves exactly like one whose pin was
/// never minted — its detector holds `Undetermined`, the planner holds it out of the
/// changeset, and the existing verdict plumbing turns that into exit 1 (deploy's
/// preflight into `PreflightUndetermined`). Nothing compares against a pin the ledger
/// can't vouch for, and no new verdict variant was needed to say so.
///
/// Orphan entries are kept: they belong to no eligible resource, so they feed nothing
/// this run, and pruning the ledger is `zap lock`'s job alone.
///
/// # Errors
/// Propagates read/parse/version failures from [`read_zap_lock`] and hashing failures
/// from [`classify_lock`].
pub fn inspect_lock(
    config: &ZapConfig,
    config_path: &Path,
    env_get: impl Fn(&str) -> Option<String>,
) -> Result<(Option<ZapLock>, LockStanding)> {
    let Some(mut lock) = read_zap_lock(&lock_path_for(config_path))? else {
        // No lock file at all: every eligible resource reads `missing` (a cold start is
        // a standing, not an absence of one), and detection gets no lock.
        let standing = classify_lock(config, &ZapLock::default(), env_get)?;
        return Ok((None, standing));
    };
    let standing = classify_lock(config, &lock, env_get)?;
    let withheld: BTreeSet<&str> = standing
        .stale
        .iter()
        .map(String::as_str)
        .chain(standing.unverifiable.iter().map(|entry| entry.id.as_str()))
        .collect();
    lock.entries
        .retain(|id, _| !withheld.contains(id.0.as_str()));
    Ok((Some(lock), standing))
}

/// The in-memory lock for a run — existing on-disk entries plus any freshly resolved
/// tracked pins — and the ids newly resolved this pass (for the dry-run "would lock"
/// render).
#[derive(Debug, Clone, Default)]
pub struct ResolvedLock {
    /// The resolved lock (thread into hashing / detection / execution).
    pub lock: ZapLock,
    /// Lock-eligible resources that had no entry and were resolved this pass.
    pub newly_resolved: Vec<ResourceId>,
    /// Lock-eligible resources a [`ColdStart::Preview`] left without a pin, because
    /// their fetch url references an unset variable.
    pub unmintable: Vec<Unmintable>,
}

/// A resource a preview couldn't mint a pin for: its fetch url references `vars`, which
/// are unset or empty here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unmintable {
    /// The resource id.
    pub id: ResourceId,
    /// The unset variables' names (comma-joined for display).
    pub vars: String,
}

/// What a cold start does about a pin it can't mint because the fetch url references an
/// unset variable ([`Error::FetchVarUnset`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ColdStart {
    /// The pin is required: the error is returned.
    Mint,
    /// A preview: the resource is left without a pin and recorded in
    /// [`ResolvedLock::unmintable`], so detection holds it and the run still renders.
    Preview,
}

/// Load the on-disk lock and resolve any missing tracked pins (`remote_file`, `build`,
/// `apt_key`).
///
/// This is the cold-start auto-lock. Existing entries are validated against the
/// current config (a `config_hash` mismatch is [`Error::LockStale`] — zap never
/// auto-reconciles).
///
/// Network IO happens here (the one resolve a dry-run does); the caller persists the
/// result only on a `--wetrun`. `--no_lock` skips this entirely (the caller passes
/// `None` downstream). `cold_start` says what a pin that can't be minted for an unset
/// url reference does: fail the run, or leave a preview's resource unpinned.
///
/// # Errors
/// [`Error::LockStale`] if an entry's `config_hash` no longer matches its resource;
/// plus the read / resolve / hash errors of the helpers.
pub async fn resolve_lock(
    config: &ZapConfig,
    config_path: &Path,
    zap_home: &Path,
    cold_start: ColdStart,
) -> Result<ResolvedLock> {
    let path = lock_path_for(config_path);
    let mut lock = read_zap_lock(&path)?.unwrap_or_default();
    let mut newly_resolved = Vec::new();
    let mut unmintable = Vec::new();
    let addressing = LockAddressing::of(config);

    for resource in &config.resources {
        if !is_lock_eligible(resource) {
            continue;
        }
        if let Some(entry) = lock.entries.get(&resource.id) {
            // Validate the existing pin against the current config via the shared
            // predicate (so apply's enforcement and `lock --check`'s gate can't drift).
            match addressing.classify_entry(resource, entry, env_var)? {
                EntryStatus::Current => {}
                EntryStatus::Stale => {
                    return Err(Error::LockStale {
                        id: resource.id.0.clone(),
                    });
                }
                EntryStatus::Unverifiable { unresolved } => {
                    return Err(Error::LockUnverifiable {
                        id: resource.id.0.clone(),
                        vars: unresolved.join(", "),
                    });
                }
            }
        } else {
            // Cold start: resolve upstream and pin.
            match addressing.resolve_entry(resource, zap_home).await {
                Ok(entry) => {
                    lock.entries.insert(resource.id.clone(), entry);
                    newly_resolved.push(resource.id.clone());
                }
                Err(Error::FetchVarUnset { vars, .. } | Error::LockUnverifiable { vars, .. })
                    if cold_start == ColdStart::Preview =>
                {
                    unmintable.push(Unmintable {
                        id: resource.id.clone(),
                        vars,
                    });
                }
                Err(error) => return Err(error),
            }
        }
    }

    Ok(ResolvedLock {
        lock,
        newly_resolved,
        unmintable,
    })
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use zap_types::lock::{LOCK_VERSION, LockEntry, ZapLock};
    use zap_types::scalar::ContentHash;
    use zap_types::schema::ResourceId;

    use super::{lock_dir, lock_path_for, read_zap_lock, update_zap_lock, write_zap_lock};

    #[test]
    fn lock_path_swaps_extension() {
        assert_eq!(
            lock_path_for(std::path::Path::new("zap.ts")).to_str(),
            Some("zap.lock")
        );
        assert_eq!(
            lock_path_for(std::path::Path::new("configs/local.zap.ts")).to_str(),
            Some("configs/local.zap.lock")
        );
    }

    fn sample() -> ZapLock {
        let mut entries = BTreeMap::new();
        entries.insert(
            ResourceId("zig".to_owned()),
            LockEntry::RemoteFile {
                config_hash: "abc123".to_owned(),
                blake3: ContentHash::of_bytes(b"def456"),
            },
        );
        ZapLock {
            version: LOCK_VERSION,
            toolchain: Some(zap_types::lock::Toolchain {
                fgro_blake3: ContentHash::of_bytes(b"fgro"),
            }),
            entries,
        }
    }

    /// An empty `zap.lock` — what a first write killed before its rename leaves — is no
    /// lock; and a first write that fails removes the empty file its guard created.
    #[test]
    fn an_empty_lock_is_none_and_a_failed_first_write_leaves_none() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("zap.lock");
        std::fs::write(&path, "").unwrap();
        assert_eq!(read_zap_lock(&path).unwrap(), None);
        std::fs::remove_file(&path).unwrap();
        // A directory at the temp name fails the write before its rename.
        let tmp = dir
            .path()
            .join(format!(".zap.lock.tmp.{}", std::process::id()));
        std::fs::create_dir(&tmp).unwrap();
        assert!(write_zap_lock(&path, &sample()).is_err());
        assert!(!path.exists(), "the empty lock the guard made is removed");
        // An existing lock is never removed by a failed write.
        std::fs::remove_dir(&tmp).unwrap();
        write_zap_lock(&path, &sample()).unwrap();
        std::fs::create_dir(&tmp).unwrap();
        assert!(update_zap_lock(&path, |_| {}).is_err());
        assert_eq!(read_zap_lock(&path).unwrap(), Some(sample()));
    }

    /// A read-only lock can't be rewritten (the guard opens it read-write), and the
    /// refusal says so.
    #[test]
    fn a_read_only_lock_is_refused_as_not_writable() {
        use std::os::unix::fs::PermissionsExt as _;

        if nix::unistd::geteuid().is_root() {
            return; // root opens it anyway
        }
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("zap.lock");
        write_zap_lock(&path, &sample()).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o444)).unwrap();
        let error = write_zap_lock(&path, &sample()).unwrap_err().to_string();
        assert!(error.contains("zap.lock is not writable: "), "{error}");
    }

    /// A lock that can't be created, its directory not writable, says that of the
    /// directory, not of a lock that isn't there.
    #[test]
    fn an_unwritable_lock_directory_is_named_as_the_directory() {
        use std::os::unix::fs::PermissionsExt as _;

        if nix::unistd::geteuid().is_root() {
            return; // root writes it anyway
        }
        let dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o555)).unwrap();
        let error = write_zap_lock(&dir.path().join("zap.lock"), &sample())
            .unwrap_err()
            .to_string();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(
            error.contains(&format!(
                "its directory {} is not writable: ",
                dir.path().display()
            )),
            "{error}"
        );
        assert!(!error.contains("zap.lock is not writable"), "{error}");
    }

    /// A writer waiting on the guard while another renames a new lock over the path
    /// takes the guard again on the file now there: it waits for whoever holds that one,
    /// and merges into what is there when it gets it — never running beside a writer
    /// because it held a lock on the inode renamed away.
    #[test]
    fn a_writer_waiting_while_the_lock_is_renamed_over_waits_for_the_new_one() {
        use nix::fcntl::{Flock, FlockArg};

        let entry = |name: &str| {
            (
                ResourceId(name.to_owned()),
                LockEntry::RemoteFile {
                    config_hash: name.to_owned(),
                    blake3: ContentHash::of_bytes(name.as_bytes()),
                },
            )
        };
        let lock_of = |path: &std::path::Path| {
            Flock::lock(
                std::fs::OpenOptions::new()
                    .read(true)
                    .write(true)
                    .open(path)
                    .unwrap(),
                FlockArg::LockExclusive,
            )
            .unwrap()
        };
        let ino = |path: &std::path::Path| {
            std::os::unix::fs::MetadataExt::ino(&std::fs::metadata(path).unwrap())
        };
        // The test reads blocked `flock`s from `/proc/locks`; without it there is nothing
        // to wait on, so it doesn't run.
        if std::fs::read_to_string("/proc/locks").map_or(true, |locks| locks.trim().is_empty()) {
            return;
        }
        // Whether a `flock` waits on the inode, as `/proc/locks` lists it (`->`): as soon
        // as it does, or not within about 30 seconds.
        let waits_on = |ino: u64| {
            (0..3000).any(|_| {
                let waiting = std::fs::read_to_string("/proc/locks").is_ok_and(|locks| {
                    locks
                        .lines()
                        .any(|line| line.contains("-> FLOCK") && line.contains(&format!(":{ino} ")))
                });
                if !waiting {
                    std::thread::sleep(std::time::Duration::from_millis(10));
                }
                waiting
            })
        };
        let rename_in = |dir: &std::path::Path, path: &std::path::Path, lock: &ZapLock| {
            let staged = dir.join("staged");
            std::fs::write(&staged, serde_json::to_string(lock).unwrap()).unwrap();
            std::fs::rename(&staged, path).unwrap();
        };

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("zap.lock");
        write_zap_lock(&path, &sample()).unwrap();
        let old = lock_of(&path);
        let old_ino = ino(&path);
        let waiter = {
            let path = path.clone();
            std::thread::spawn(move || {
                update_zap_lock(&path, |lock| {
                    lock.entries.extend([entry("waiter")]);
                })
                .unwrap()
            })
        };
        assert!(
            waits_on(old_ino),
            "the waiter never blocked on the old lock"
        );
        // Another writer renames a new lock over the path and holds it.
        let mut renamed = sample();
        renamed.entries.extend([entry("renamed-in")]);
        rename_in(dir.path(), &path, &renamed);
        let new = lock_of(&path);
        let new_ino = ino(&path);
        drop(old);
        assert!(
            waits_on(new_ino),
            "the waiter went on under the old file's lock, beside the new one's holder"
        );
        // That writer's own rename lands before the waiter gets the guard.
        renamed.entries.extend([entry("late")]);
        rename_in(dir.path(), &path, &renamed);
        drop(new);
        let written = waiter.join().unwrap();
        let ids: Vec<&str> = written.entries.keys().map(|id| id.0.as_str()).collect();
        assert_eq!(ids, ["late", "renamed-in", "waiter", "zig"]);
        assert_eq!(read_zap_lock(&path).unwrap(), Some(written));
    }

    /// A whole-lock write never reads the old file, so it rebuilds one that doesn't
    /// parse (merge-conflict markers); a writer that merges into it refuses it instead.
    #[test]
    fn a_whole_write_rebuilds_a_lock_that_does_not_parse() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("zap.lock");
        let conflicted = "<<<<<<< HEAD\n{\"version\": 2}\n=======\n{}\n>>>>>>> other\n";
        std::fs::write(&path, conflicted).unwrap();
        assert!(matches!(
            update_zap_lock(&path, |_| {}),
            Err(crate::error::Error::LockParse { .. })
        ));
        assert_eq!(std::fs::read_to_string(&path).unwrap(), conflicted);
        write_zap_lock(&path, &sample()).unwrap();
        assert_eq!(read_zap_lock(&path).unwrap(), Some(sample()));
    }

    /// With no lock there, a merging write starts from an empty one, and only the lock
    /// is left in the directory.
    #[test]
    fn a_merging_write_with_no_lock_starts_empty() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("zap.lock");
        let written = update_zap_lock(&path, |lock| lock.clone_from(&sample())).unwrap();
        assert_eq!(written, sample());
        let names: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        assert_eq!(names, ["zap.lock"]);
    }

    /// Writers that each read, change, and write the lock serialize on the one guard: no
    /// entry one adds is lost to another's rename, however they interleave.
    #[test]
    fn concurrent_updates_lose_no_entry() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("zap.lock");
        write_zap_lock(&path, &sample()).unwrap();
        let writers: Vec<_> = (0..8)
            .map(|writer| {
                let path = path.clone();
                std::thread::spawn(move || {
                    for update in 0..12 {
                        update_zap_lock(&path, |lock| {
                            lock.entries.insert(
                                ResourceId(format!("w{writer}-{update}")),
                                LockEntry::RemoteFile {
                                    config_hash: "h".to_owned(),
                                    blake3: ContentHash::of_bytes(b"x"),
                                },
                            );
                        })
                        .unwrap();
                    }
                })
            })
            .collect();
        for writer in writers {
            writer.join().unwrap();
        }
        let lock = read_zap_lock(&path).unwrap().unwrap();
        assert_eq!(lock.entries.len(), 1 + 8 * 12);
        assert_eq!(lock.toolchain, sample().toolchain);
    }

    #[test]
    fn write_then_read_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("zap.lock");
        let lock = sample();
        write_zap_lock(&path, &lock).unwrap();
        let read = read_zap_lock(&path).unwrap().unwrap();
        assert_eq!(read, lock);
    }

    /// A config named `*.lock` is its own lock path, and is refused before a lock could
    /// be written over it; any other name is taken.
    #[test]
    fn a_config_named_like_its_lock_is_refused() {
        use std::path::Path;

        use super::refuse_lock_named_config;
        use crate::error::Error;

        for config in ["zap.lock", "configs/prod.lock", "/abs/x.zap.lock"] {
            let error = refuse_lock_named_config(Path::new(config)).unwrap_err();
            assert!(
                matches!(error, Error::ConfigNamedLikeLock { .. }),
                "{error:?}"
            );
            assert_eq!(error.exit_code(), 2);
            assert!(
                error
                    .to_string()
                    .contains(&format!("the config `{config}` has the name its own lock")),
                "{error}"
            );
        }
        for config in ["zap.ts", "zap", "lock", "configs/zap.lock.ts", ".lock"] {
            refuse_lock_named_config(Path::new(config)).unwrap();
        }
    }

    /// A write that fails leaves no temp file beside the lock, and a temp name that is
    /// taken — by a stale file, or by a link — is replaced, never written through.
    #[cfg(unix)]
    #[test]
    fn a_lock_write_writes_through_no_link_and_leaves_no_temp() {
        let dir = tempfile::tempdir().unwrap();
        let names = |dir: &std::path::Path| {
            let mut names: Vec<String> = std::fs::read_dir(dir)
                .unwrap()
                .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
                .collect();
            names.sort();
            names
        };
        let victim = dir.path().join("victim");
        std::fs::write(&victim, b"untouched").unwrap();

        // A rename that fails — a directory stands at the lock's path — leaves no temp.
        let blocked = dir.path().join("blocked");
        let occupied = blocked.join("zap.lock");
        std::fs::create_dir_all(occupied.join("inner")).unwrap();
        super::replace_through(&blocked.join(".zap.lock.tmp.1"), &occupied, b"{}").unwrap_err();
        write_zap_lock(&occupied, &sample()).unwrap_err();
        assert_eq!(names(&blocked), ["zap.lock"]);

        // A link at the temp's name is replaced, and its target left alone.
        let work = dir.path().join("work");
        std::fs::create_dir(&work).unwrap();
        let path = work.join("zap.lock");
        let temp = work.join(format!(".zap.lock.tmp.{}", std::process::id()));
        std::os::unix::fs::symlink(&victim, &temp).unwrap();
        write_zap_lock(&path, &sample()).unwrap();
        assert_eq!(read_zap_lock(&path).unwrap().unwrap(), sample());
        assert_eq!(names(&work), ["zap.lock"]);

        // A link at the lock's own path is refused: nothing is written, the link stays,
        // and a dangling one's target is not created.
        for target in [victim.clone(), dir.path().join("dangling")] {
            std::fs::remove_file(&path).unwrap();
            std::os::unix::fs::symlink(&target, &path).unwrap();
            let error = write_zap_lock(&path, &sample()).unwrap_err().to_string();
            assert!(error.contains("it is a symbolic link"), "{error}");
            assert!(
                std::fs::symlink_metadata(&path)
                    .unwrap()
                    .file_type()
                    .is_symlink()
            );
            assert_eq!(names(&work), ["zap.lock"]);
        }
        assert_eq!(std::fs::read(&victim).unwrap(), b"untouched");
        assert!(!dir.path().join("dangling").exists());
    }

    /// A read refuses what a write refuses: a link where the lock goes, to a lock or to
    /// nothing, is an error, never the linked file's lock or no lock; and what isn't a
    /// regular file (a directory, a FIFO) is an error too, never a blocked read.
    #[test]
    fn a_read_refuses_a_link_or_a_file_that_isnt_regular() {
        let dir = crate::test_scratch::tempdir();
        let real = dir.path().join("real.lock");
        write_zap_lock(&real, &sample()).unwrap();
        let path = dir.path().join("zap.lock");
        for target in [real, dir.path().join("dangling")] {
            std::os::unix::fs::symlink(&target, &path).unwrap();
            let error = read_zap_lock(&path).unwrap_err().to_string();
            assert!(error.contains("it is a symbolic link"), "{error}");
            std::fs::remove_file(&path).unwrap();
        }
        std::fs::create_dir(&path).unwrap();
        let error = read_zap_lock(&path).unwrap_err().to_string();
        assert!(error.contains("not a regular file"), "{error}");
        std::fs::remove_dir(&path).unwrap();
        nix::unistd::mkfifo(&path, nix::sys::stat::Mode::S_IRWXU).unwrap();
        let error = read_zap_lock(&path).unwrap_err().to_string();
        assert!(error.contains("not a regular file"), "{error}");
    }

    #[test]
    fn a_bare_file_name_lives_in_the_current_directory() {
        use std::path::Path;
        // `Path::parent` of a bare name is the empty path, which opens as nothing.
        assert_eq!(lock_dir(Path::new("zap.lock")), Path::new("."));
        assert_eq!(lock_dir(Path::new("./zap.lock")), Path::new("."));
        assert_eq!(
            lock_dir(Path::new("configs/local.zap.lock")),
            Path::new("configs")
        );
        assert_eq!(lock_dir(Path::new("/etc/zap.lock")), Path::new("/etc"));
    }

    #[test]
    fn missing_lock_reads_as_none() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("absent.lock");
        assert!(read_zap_lock(&path).unwrap().is_none());
    }

    #[test]
    fn a_version_1_lock_reads_with_no_toolchain_and_is_written_as_the_current_one() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("zap.lock");
        std::fs::write(&path, r#"{"version": 1, "entries": {}}"#).unwrap();
        let read = read_zap_lock(&path).unwrap().unwrap();
        assert_eq!(read.version, 1);
        assert_eq!(read.toolchain, None);
        write_zap_lock(&path, &read).unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        assert_eq!(
            text,
            format!("{{\n  \"version\": {LOCK_VERSION},\n  \"entries\": {{}}\n}}\n")
        );
    }

    /// A version 2 lock — a toolchain pin, entries of the kinds it had — reads as it is
    /// and is written back as the current version, its pin and entries kept.
    #[test]
    fn a_version_2_lock_reads_as_it_is_and_is_written_as_the_current_one() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("zap.lock");
        let (fgro, pin, config_hash) = ("f".repeat(64), "a".repeat(64), "c".repeat(64));
        std::fs::write(
            &path,
            format!(
                r#"{{"version": 2, "toolchain": {{"fgro_blake3": "{fgro}"}},
                "entries": {{"zig": {{"kind": "remote_file", "config_hash": "{config_hash}",
                "blake3": "{pin}"}}}}}}"#
            ),
        )
        .unwrap();
        let read = read_zap_lock(&path).unwrap().unwrap();
        assert_eq!(read.version, 2);
        assert_eq!(read.toolchain.as_ref().unwrap().fgro_blake3.as_str(), fgro);
        assert_eq!(
            read.entries[&ResourceId("zig".to_owned())],
            LockEntry::RemoteFile {
                config_hash,
                blake3: ContentHash::new(pin).unwrap(),
            }
        );
        write_zap_lock(&path, &read).unwrap();
        let written = read_zap_lock(&path).unwrap().unwrap();
        assert_eq!(written.version, LOCK_VERSION);
        assert_eq!(LOCK_VERSION, 3);
        assert_eq!(written.toolchain, read.toolchain);
        assert_eq!(written.entries, read.entries);
    }

    #[test]
    fn future_version_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("zap.lock");
        std::fs::write(
            &path,
            serde_json::to_string(&serde_json::json!({
                "version": LOCK_VERSION + 1, "entries": {}
            }))
            .unwrap(),
        )
        .unwrap();
        assert!(matches!(
            read_zap_lock(&path),
            Err(crate::error::Error::LockVersion { .. })
        ));
    }

    #[test]
    fn a_future_version_with_an_unknown_shape_is_refused_as_a_version() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("zap.lock");
        std::fs::write(
            &path,
            serde_json::to_string(&serde_json::json!({
                "version": LOCK_VERSION + 1, "entries": []
            }))
            .unwrap(),
        )
        .unwrap();
        assert!(matches!(
            read_zap_lock(&path),
            Err(crate::error::Error::LockVersion { .. })
        ));
    }

    #[test]
    fn malformed_lock_errors() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("zap.lock");
        std::fs::write(&path, "{not json").unwrap();
        assert!(matches!(
            read_zap_lock(&path),
            Err(crate::error::Error::LockParse { .. })
        ));
    }

    #[test]
    fn write_is_pretty_and_deterministic() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("zap.lock");
        write_zap_lock(&path, &sample()).unwrap();
        let a = std::fs::read_to_string(&path).unwrap();
        write_zap_lock(&path, &sample()).unwrap();
        let b = std::fs::read_to_string(&path).unwrap();
        assert_eq!(a, b, "serialization is deterministic");
        assert!(a.contains('\n'), "pretty (multi-line)");
        assert!(a.ends_with('\n'), "trailing newline");
    }
}
