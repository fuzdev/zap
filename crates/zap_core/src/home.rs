//! `~/.zap` — zap's owner-only local state on the operator machine, and where each
//! piece of it lives.
//!
//! Everything here is advisory: nothing under `~/.zap` is authority over a target (the
//! lock, beside the config, is the operator's ledger). The layout:
//!
//! - `cache/<config-slug>/eval/` — the L0 eval cache (`crate::config::eval_cache`);
//! - `cache/<config-slug>/last_run/<host>.json` — the last-run report per host
//!   (`crate::last_run`);
//! - `cache/<config-slug>/deploy_preview/<host>.json` — the deploy preview per host
//!   (`crate::deploy_preview`);
//! - `cache/files/<blake3>/<name>` — the content cache (`crate::resolver`);
//! - `cache/fgro_pins/` — the `fgro` binary's stat-keyed hash cache
//!   (`crate::config::fgro`), whose entries `fuz_eval` writes;
//! - `ssh/` — the `ControlMaster` sockets.
//!
//! A config's entries share one directory, named by [`config_slug`]; a slug always ends
//! in `-<8 hex>`, so none is `files` or `fgro_pins`. A host becomes a file name only through
//! `host_file_stem`, so a resolved value can't escape its directory.
//!
//! Every directory of the tree comes to be through `ensure_state_dir`, from the root
//! down: created `0700`, or found a real directory of this user's — never a symlink —
//! and held to `0700`. Every file is written `0600`.

use std::ffi::OsString;
use std::path::{Path, PathBuf};

use crate::error::{Error, Result};

/// A home directory as an environment variable gives it — the one reading of `HOME`
/// and `ZAP_HOME`, wherever either is needed.
///
/// Unset and empty are the same: no home (`None`), which the caller answers for. A
/// relative path is refused: joined onto, it names a directory under wherever zap
/// happens to be run, and zap's state — or a file a config manages — would land there.
/// Nothing is guessed in a home's place: no `/root`, no password-database lookup.
///
/// # Errors
/// [`Error::HomeNotAbsolute`] naming `var` when its value is a relative path.
pub(crate) fn home_from(var: &'static str, value: Option<OsString>) -> Result<Option<PathBuf>> {
    let Some(value) = value.filter(|value| !value.is_empty()) else {
        return Ok(None);
    };
    let home = PathBuf::from(value);
    if home.is_absolute() {
        Ok(Some(home))
    } else {
        Err(Error::HomeNotAbsolute { var })
    }
}

/// `~/.zap` — `ZAP_HOME` if set, else `$HOME/.zap`, each read by [`home_from`]. `None`
/// when neither is set (the eval cache, the content cache, the last-run report and the
/// deploy preview are then off for the run). Read from the process environment, never an
/// `--env-file`: where zap keeps its state is the operator's setting, not a config's
/// input. Reading env is safe; only `set_var` is not, so tests inject the root via the
/// `run_*_in` cores rather than setting `ZAP_HOME`.
///
/// # Errors
/// [`Error::HomeNotAbsolute`] when the variable that decides it holds a relative path.
pub(crate) fn zap_home_default() -> Result<Option<PathBuf>> {
    if let Some(dir) = home_from("ZAP_HOME", std::env::var_os("ZAP_HOME"))? {
        return Ok(Some(dir));
    }
    Ok(home_from("HOME", std::env::var_os("HOME"))?.map(|home| home.join(".zap")))
}

/// A stable, human-readable namespace for an **absolute** config path.
///
/// The file stem plus a short blake3 of the path (8 hex, 32 bits), so
/// identically-named configs in different directories land apart with overwhelming
/// probability, not certainty. What is filed under a slug says which config it is for
/// where a mix-up would matter: the eval cache's manifest records its config's path. Pure — pass an absolute path (see
/// [`config_dir_for`], which canonicalizes); a relative path still yields a slug but
/// won't match the canonicalized one.
#[must_use]
pub fn config_slug(absolute_config_path: &Path) -> String {
    let hex = blake3::hash(absolute_config_path.to_string_lossy().as_bytes())
        .to_hex()
        .to_string();
    let short = &hex[..8];
    match absolute_config_path
        .file_stem()
        .and_then(|stem| stem.to_str())
    {
        Some(stem) if !stem.is_empty() => format!("{stem}-{short}"),
        _ => format!("config-{short}"),
    }
}

/// Resolve a config path to an absolute one for addressing, falling back to the path
/// as-given when it can't be canonicalized (e.g. it doesn't exist yet).
fn canonical_config_path(config_path: &Path) -> PathBuf {
    std::fs::canonicalize(config_path).unwrap_or_else(|_| config_path.to_path_buf())
}

/// A config's own directory: `<zap_home>/cache/<config-slug>`.
///
/// The one place the config path is canonicalized (the only IO here), so every reader
/// and writer derives the same slug from any path spelling.
#[must_use]
pub fn config_dir_for(zap_home: &Path, config_path: &Path) -> PathBuf {
    zap_home
        .join("cache")
        .join(config_slug(&canonical_config_path(config_path)))
}

/// The L0 eval-cache directory for a config: `<zap_home>/cache/<config-slug>/eval`.
#[must_use]
pub fn eval_cache_dir_for(zap_home: &Path, config_path: &Path) -> PathBuf {
    config_dir_for(zap_home, config_path).join("eval")
}

/// The last-run report directory for a config:
/// `<zap_home>/cache/<config-slug>/last_run`.
#[must_use]
pub fn last_run_dir_for(zap_home: &Path, config_path: &Path) -> PathBuf {
    config_dir_for(zap_home, config_path).join("last_run")
}

/// The last-run report path for a config and host — the one place a host becomes a
/// path component, so the writer and `zap status` can't disagree about the mapping.
///
/// `host` is a host label (`zap_types::last_run::host_label`), whose secret
/// references are tokens, so a host that resolves through a secret never lands in a
/// file name — and no report is filed under a label holding a token at all (the
/// commands' `record_pass`).
#[must_use]
pub fn last_run_path_for(zap_home: &Path, config_path: &Path, host: &str) -> PathBuf {
    last_run_dir_for(zap_home, config_path).join(last_run_file_name(host))
}

/// The last-run report's file name for `host` within [`last_run_dir_for`].
#[must_use]
pub fn last_run_file_name(host: &str) -> String {
    format!("{}.json", host_file_stem(host))
}

/// The deploy-preview directory for a config:
/// `<zap_home>/cache/<config-slug>/deploy_preview`.
///
/// A subtree of its own, so a host's deploy preview and its last-run report are two
/// files and neither write replaces the other.
#[must_use]
pub fn deploy_preview_dir_for(zap_home: &Path, config_path: &Path) -> PathBuf {
    config_dir_for(zap_home, config_path).join("deploy_preview")
}

/// The deploy preview's file name for `host` within [`deploy_preview_dir_for`] — the
/// stem the last-run report files the same host under.
#[must_use]
pub fn deploy_preview_file_name(host: &str) -> String {
    format!("{}.json", host_file_stem(host))
}

/// The deploy-preview path for a config and host.
#[must_use]
pub fn deploy_preview_path_for(zap_home: &Path, config_path: &Path, host: &str) -> PathBuf {
    deploy_preview_dir_for(zap_home, config_path).join(deploy_preview_file_name(host))
}

/// The file-name stem for a host — a safe path component by construction.
///
/// A host is a reference-resolved *value* interpolated into a file name, so it can't
/// be trusted as a path component: a `/` or a `..` would read and write outside the
/// config's directory. A host that is already a safe file name is used verbatim, so the
/// ordinary case keeps the readable `<host>.json`; anything else — a path separator, a
/// leading `.`, an empty resolution, a masking token — falls back to
/// `host-<short blake3 of the raw host>` (8 hex, 32 bits), which keeps distinct hosts
/// apart with overwhelming probability (the [`config_slug`] technique) at the cost of
/// readability for a pathological one.
fn host_file_stem(host: &str) -> String {
    let safe = !host.is_empty()
        && !host.starts_with('.')
        && host
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'));
    if safe {
        return host.to_owned();
    }
    let hex = blake3::hash(host.as_bytes()).to_hex().to_string();
    format!("host-{}", &hex[..8])
}

/// Write `bytes` to `dir/filename` — a directory of `zap_home` — via temp-write + atomic
/// rename, owner-only.
///
/// The shared local-state write primitive: establishes the directory
/// ([`ensure_state_dir`]), writes a pid-suffixed temp file created new at `0600` (so
/// its bytes are never readable by anyone else, even before the rename, and nothing
/// already at that name is written through), then renames; a failed write or rename
/// removes the temp file. Used by the L0 eval cache, the last-run report, and the deploy
/// preview.
///
/// # Errors
/// Returns the underlying [`std::io::Error`] if the directory can't be established or
/// the write/rename fails. Callers treat a write failure here as non-fatal.
pub(crate) fn write_atomic(
    zap_home: &Path,
    dir: &Path,
    filename: &str,
    bytes: &[u8],
) -> std::io::Result<()> {
    ensure_state_dir(zap_home, dir)?;
    let final_path = dir.join(filename);
    let tmp_path = dir.join(format!("{filename}.tmp.{}", std::process::id()));
    let written =
        write_owner_only(&tmp_path, bytes).and_then(|()| std::fs::rename(&tmp_path, &final_path));
    if written.is_err() {
        let _ = std::fs::remove_file(&tmp_path);
    }
    written
}

/// Write `bytes` to a new file at `path`, created owner-only (`0600` on unix). A file
/// left at the name by an earlier run with this pid is removed first, never written
/// through: the file written is one this call created.
fn write_owner_only(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write as _;
    match std::fs::remove_file(path) {
        Err(error) if error.kind() != std::io::ErrorKind::NotFound => return Err(error),
        _ => {}
    }
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    options.open(path)?.write_all(bytes)
}

/// A record file taken from its name by [`take_record`]: held under a name of this
/// call's own until it is put back ([`restore`](Self::restore)) or dropped, which
/// removes it.
#[derive(Debug)]
pub(crate) struct TakenRecord {
    /// The name the record stood at.
    path: PathBuf,
    /// The name it is held under.
    held: PathBuf,
}

impl TakenRecord {
    /// Where the taken record can be read.
    pub(crate) fn held(&self) -> &Path {
        &self.held
    }

    /// Put the record back at its name, unless a newer one stands there now. Best
    /// effort: a record that can't be put back is gone, which costs a preview.
    pub(crate) fn restore(self) {
        let _ = std::fs::hard_link(&self.held, &self.path);
    }
}

impl Drop for TakenRecord {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.held);
    }
}

/// Take the record file at `path` away from its name, so that no other run can read or
/// take it: `None` when nothing stands there.
///
/// One `rename` to a name no other call uses, so of the runs that try to take one file
/// exactly one gets it, and a run that takes a file holds the very bytes it reads
/// after — never a record written there in between, as a run that read the name and
/// then removed it could. A review that binds one wetrun is spent this way: the run
/// that takes the record it bound to executes under it, and every other run finds the
/// name empty or holding a later record.
///
/// # Errors
/// The underlying [`std::io::Error`] when something stands at `path` and can't be
/// taken, a directory or any other file that isn't a regular one included.
pub(crate) fn take_record(path: &Path) -> std::io::Result<Option<TakenRecord>> {
    use std::sync::atomic::{AtomicU64, Ordering};
    static TAKEN: AtomicU64 = AtomicU64::new(0);

    match std::fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
        Ok(metadata) if !metadata.is_file() => {
            return Err(std::io::Error::other("it is not a regular file"));
        }
        Ok(_) => {}
    }
    let name = path
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default();
    let held = path.with_file_name(format!(
        ".{name}.taken.{}.{}",
        std::process::id(),
        TAKEN.fetch_add(1, Ordering::Relaxed)
    ));
    match std::fs::rename(path, &held) {
        Ok(()) => Ok(Some(TakenRecord {
            path: path.to_owned(),
            held,
        })),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

/// What stands where a directory of zap's goes, when it isn't one zap can take as its
/// own.
#[derive(Debug)]
enum Found {
    /// A symbolic link.
    Symlink,
    /// Something that is no directory, named for what it is.
    NotDirectory(&'static str),
    /// A directory of another user's.
    OtherOwner,
    /// A directory of this user's that can't be opened, so that nothing could be
    /// checked of it through a handle.
    Unopenable(std::io::Error),
    /// A directory whose name, or whose open handle, can't be read for what it is.
    Unreadable(std::io::Error),
    /// A directory of this user's, open to others, whose mode can't be tightened.
    Unrestrictable(std::io::Error),
}

impl Found {
    /// What stands there, as a clause after the path.
    fn clause(&self) -> String {
        match self {
            Self::Symlink => "is a symbolic link".to_owned(),
            Self::NotDirectory(kind) => format!("is {kind}, not a directory"),
            Self::OtherOwner => "belongs to another user".to_owned(),
            Self::Unopenable(error) => format!("can't be opened ({error})"),
            Self::Unreadable(error) => format!("can't be read ({error})"),
            Self::Unrestrictable(error) => {
                format!("can't be restricted to its owner ({error})")
            }
        }
    }

    /// The clause, and what to do about it: the way out is the finding's own.
    fn clause_and_remedy(&self) -> String {
        let remedy = match self {
            Self::Symlink => {
                "zap doesn't follow a link there: replace the link with a directory, or — \
                 when the link is zap's home itself — set `ZAP_HOME` to the directory it \
                 points to"
            }
            Self::NotDirectory(_) => "remove it, or set `ZAP_HOME` to another directory",
            Self::OtherOwner => {
                "run zap as that user, or set `ZAP_HOME` to a directory of your own"
            }
            Self::Unopenable(_) | Self::Unreadable(_) => {
                "restore your access to it (`chmod 700`), or set `ZAP_HOME` to another \
                 directory"
            }
            Self::Unrestrictable(_) => {
                "restrict it yourself (`chmod 700`), or set `ZAP_HOME` to another directory"
            }
        };
        format!("{} — {remedy}", self.clause())
    }
}

/// Why a directory can't be one of zap's.
#[derive(Debug)]
enum DirProblem {
    /// Something zap can't take as its own stands at the path: it is used for nothing.
    Refused {
        /// The path.
        path: PathBuf,
        /// What stands there.
        found: Found,
    },
    /// The directory couldn't be created.
    Io(std::io::Error),
}

impl From<std::io::Error> for DirProblem {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<DirProblem> for std::io::Error {
    fn from(problem: DirProblem) -> Self {
        match problem {
            DirProblem::Refused { path, found } => Self::new(
                std::io::ErrorKind::InvalidInput,
                format!("{} {}", path.display(), found.clause()),
            ),
            DirProblem::Io(error) => error,
        }
    }
}

/// Make `dir` a directory zap owns: created `0700` if it isn't there (its parent must
/// be), and otherwise required to be a real directory — no symlink — that belongs to
/// the user zap runs as, its mode tightened to `0700` when anyone else can reach it.
///
/// What stands at the path is judged before it is opened, from the name itself: a
/// directory of another user's is refused whether or not this user may open it — one
/// its owner left searchable but unreadable would otherwise fail to open, read as a
/// directory zap merely couldn't prepare, and have its records read by path all the
/// same. It is then opened without following a link and judged again and restricted
/// through that one handle, so what is checked is what is restricted.
#[cfg(unix)]
fn establish_dir(dir: &Path) -> std::result::Result<(), DirProblem> {
    use std::os::unix::fs::OpenOptionsExt as _;
    use std::os::unix::fs::PermissionsExt as _;
    use std::os::unix::fs::{DirBuilderExt as _, FileTypeExt as _, MetadataExt as _};

    use nix::fcntl::OFlag;

    match std::fs::DirBuilder::new().mode(0o700).create(dir) {
        Ok(()) => return Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error.into()),
    }
    let refused = |found| DirProblem::Refused {
        path: dir.to_path_buf(),
        found,
    };
    let user = nix::unistd::geteuid().as_raw();
    let named = std::fs::symlink_metadata(dir)?;
    let kind = named.file_type();
    if kind.is_symlink() {
        return Err(refused(Found::Symlink));
    }
    if !kind.is_dir() {
        return Err(refused(Found::NotDirectory(if kind.is_file() {
            "a file"
        } else if kind.is_socket() {
            "a socket"
        } else if kind.is_fifo() {
            "a fifo"
        } else {
            "a device"
        })));
    }
    if named.uid() != user {
        return Err(refused(Found::OtherOwner));
    }
    let held = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags((OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW).bits())
        .open(dir)
        .map_err(|error| match error.raw_os_error() {
            // What stood there was replaced, or removed, since it was looked at.
            Some(code) if code == nix::libc::ELOOP => refused(Found::Symlink),
            Some(code) if code == nix::libc::ENOTDIR => {
                refused(Found::NotDirectory("something else"))
            }
            Some(code) if code == nix::libc::ENOENT => DirProblem::Io(error),
            _ => refused(Found::Unopenable(error)),
        })?;
    let metadata = held
        .metadata()
        .map_err(|error| refused(Found::Unreadable(error)))?;
    if metadata.uid() != user {
        return Err(refused(Found::OtherOwner));
    }
    if metadata.mode() & 0o077 != 0 {
        held.set_permissions(std::fs::Permissions::from_mode(0o700))
            .map_err(|error| refused(Found::Unrestrictable(error)))?;
    }
    Ok(())
}

#[cfg(not(unix))]
fn establish_dir(dir: &Path) -> std::result::Result<(), DirProblem> {
    match std::fs::create_dir(dir) {
        Err(error) if error.kind() != std::io::ErrorKind::AlreadyExists => Err(error.into()),
        _ => Ok(()),
    }
}

/// [`ensure_state_dir`], its refusals told apart from its IO failures.
fn establish_under(zap_home: &Path, dir: &Path) -> std::result::Result<(), DirProblem> {
    let below = dir.strip_prefix(zap_home).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("{} is not under {}", dir.display(), zap_home.display()),
        )
    })?;
    // Every component is a plain name, or nothing is made: a `..` is refused before
    // any directory comes to be.
    let names = below
        .components()
        .map(|component| match component {
            std::path::Component::Normal(name) => Ok(name),
            _ => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("{} is not a plain path under zap's home", dir.display()),
            )),
        })
        .collect::<std::io::Result<Vec<_>>>()?;
    // What is above the root is the operator's, as it is.
    if let Some(above) = zap_home.parent() {
        std::fs::create_dir_all(above)?;
    }
    establish_dir(zap_home)?;
    let mut at = zap_home.to_path_buf();
    for name in names {
        at.push(name);
        establish_dir(&at)?;
    }
    Ok(())
}

/// Establish `dir`, a directory under `zap_home`, as zap's own — `zap_home` first, then
/// each directory down to `dir`, by one rule (`establish_dir`): created `0700`, or
/// found a real directory of this user's and held to `0700`.
///
/// The one way a directory of the `~/.zap` tree comes to be, so the tree is owner-only
/// at every level — the root, `cache/`, a config's directory and its subtrees, the
/// content cache, the SSH socket directory — and nothing of it is a link to somewhere
/// else.
///
/// # Errors
/// The underlying [`std::io::Error`], or one of kind
/// [`InvalidInput`](std::io::ErrorKind::InvalidInput) naming the path that is a
/// symlink, is no directory, belongs to another user, or can't be opened.
pub(crate) fn ensure_state_dir(zap_home: &Path, dir: &Path) -> std::io::Result<()> {
    establish_under(zap_home, dir).map_err(Into::into)
}

/// The directory of zap's home the SSH `ControlMaster` sockets live in.
pub(crate) const SSH_DIR: &str = "ssh";

/// Hold what there is of `config_path`'s state under `zap_home` to being zap's own,
/// before anything is read from it: the root, `cache/`, the SSH socket directory, the
/// `fgro` pin cache, the
/// config's directory, and each of its subtrees — whichever exist — are checked and
/// tightened by the rule every directory of the tree is made by
/// ([`ensure_state_dir`]). Nothing is created here: a directory comes to be when
/// something is first written into it.
///
/// The records kept there decide things — a recorded preview is what a wetrun binds
/// to, a cached evaluation is a config, a control socket is a connection — so a
/// directory that isn't zap's own is an error, not a cache miss. That includes one
/// that exists and can't be opened: nothing could be checked of it, and its records
/// would still be read by path. Only a directory that isn't there is nothing to hold.
///
/// # Errors
/// [`Error::StateDir`] naming the path that is a symlink, is no directory, belongs to
/// another user, or can't be opened or restricted.
pub(crate) fn claim_state_dirs(zap_home: &Path, config_path: &Path) -> Result<()> {
    let dirs = [
        zap_home.to_path_buf(),
        zap_home.join("cache"),
        zap_home.join(SSH_DIR),
        zap_home
            .join("cache")
            .join(crate::config::fgro::PIN_CACHE_DIR),
        config_dir_for(zap_home, config_path),
        eval_cache_dir_for(zap_home, config_path),
        last_run_dir_for(zap_home, config_path),
        deploy_preview_dir_for(zap_home, config_path),
    ];
    for dir in dirs
        .iter()
        .filter(|dir| std::fs::symlink_metadata(dir).is_ok())
    {
        let (path, found) = match establish_under(zap_home, dir) {
            Ok(()) => continue,
            // It was there a moment ago and is gone: nothing to hold.
            Err(DirProblem::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {
                continue;
            }
            Err(DirProblem::Io(error)) => (dir.clone(), Found::Unreadable(error)),
            Err(DirProblem::Refused { path, found }) => (path, found),
        };
        return Err(Error::StateDir {
            path: path.display().to_string(),
            found: found.clause_and_remedy(),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::{config_dir_for, host_file_stem, last_run_dir_for, last_run_path_for, take_record};

    /// A record is taken by one run: the name is empty after, and the bytes held are
    /// the ones that stood there. A later take finds nothing; a record put back
    /// returns to its name unless a newer one stands there; whatever is let go leaves
    /// no file behind.
    #[test]
    fn a_record_is_taken_once_and_put_back_only_over_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("h.json");
        let names = || {
            let mut names: Vec<String> = std::fs::read_dir(dir.path())
                .unwrap()
                .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
                .collect();
            names.sort();
            names
        };
        assert!(take_record(&path).unwrap().is_none());

        std::fs::write(&path, b"one").unwrap();
        let taken = take_record(&path).unwrap().unwrap();
        assert!(!path.exists());
        assert_eq!(std::fs::read(taken.held()).unwrap(), b"one");
        assert!(take_record(&path).unwrap().is_none());
        taken.restore();
        assert_eq!(std::fs::read(&path).unwrap(), b"one");
        assert_eq!(names(), ["h.json"]);

        let taken = take_record(&path).unwrap().unwrap();
        std::fs::write(&path, b"two").unwrap();
        taken.restore();
        assert_eq!(std::fs::read(&path).unwrap(), b"two");
        assert_eq!(names(), ["h.json"]);

        drop(take_record(&path).unwrap());
        assert_eq!(names(), [""; 0]);
    }

    /// What stands at a record's name and is no regular file can't be taken: here a
    /// directory, which stays where it is.
    #[test]
    fn a_record_that_is_no_file_cannot_be_taken() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("h.json");
        std::fs::create_dir_all(path.join("occupied")).unwrap();
        take_record(&path).unwrap_err();
        assert!(path.join("occupied").is_dir());
    }

    #[test]
    fn a_traversal_shaped_host_stays_in_the_last_run_dir() {
        let home = Path::new("/zap-home");
        let config = Path::new("/tmp/example/zap.ts");
        let dir = last_run_dir_for(home, config);
        let unresolved = zap_types::var_ref::marker("UNRESOLVED");
        for host in [
            "../../escape",
            "..",
            ".",
            "a/b",
            "",
            unresolved.as_str(),
            "[MASKED:SECRET_HOST]",
        ] {
            let path = last_run_path_for(home, config, host);
            assert_eq!(path.parent(), Some(dir.as_path()), "{host:?}");
            let stem = host_file_stem(host);
            assert!(stem.starts_with("host-"), "{host:?} -> {stem:?}");
        }
        // An ordinary host keeps its readable name.
        assert_eq!(
            last_run_path_for(home, config, "forge.example.com"),
            dir.join("forge.example.com.json")
        );
        assert_eq!(
            last_run_path_for(home, config, "local"),
            dir.join("local.json")
        );
    }

    #[test]
    fn distinct_unsafe_hosts_get_distinct_files() {
        // The fallback is a hash of the *raw* host, so two hosts that would sanitize
        // alike don't share one file.
        assert_ne!(host_file_stem("a/b"), host_file_stem("a_b"));
        assert_ne!(host_file_stem("../x"), host_file_stem("./x"));
    }

    /// A host's deploy preview is filed under the stem its last-run report has, in a
    /// subtree of its own: the two never share a path, and a host that is no safe file
    /// name stays inside it.
    #[test]
    fn a_deploy_preview_is_filed_beside_the_last_run_report() {
        use super::{deploy_preview_dir_for, deploy_preview_path_for};

        let home = Path::new("/zap-home");
        let config = Path::new("/tmp/example/zap.ts");
        let dir = deploy_preview_dir_for(home, config);
        assert_eq!(dir, config_dir_for(home, config).join("deploy_preview"));
        for host in ["forge.example.com", "../../escape", "last_run", ""] {
            let preview = deploy_preview_path_for(home, config, host);
            let report = last_run_path_for(home, config, host);
            assert_eq!(preview.parent(), Some(dir.as_path()), "{host:?}");
            assert_eq!(preview.file_name(), report.file_name(), "{host:?}");
            assert_ne!(preview, report, "{host:?}");
        }
    }

    /// The report lives in its own subtree, so no host — `eval` included — can collide
    /// with the eval cache's.
    #[test]
    fn a_host_named_eval_does_not_collide_with_the_eval_cache() {
        let home = Path::new("/zap-home");
        let config = Path::new("/tmp/example/zap.ts");
        let report = last_run_path_for(home, config, "eval");
        assert_eq!(
            report,
            config_dir_for(home, config).join("last_run/eval.json")
        );
    }
}

#[cfg(test)]
#[cfg(unix)]
mod unix_tests {
    use std::os::unix::fs::PermissionsExt;
    use std::path::Path;

    use super::{claim_state_dirs, config_dir_for, ensure_state_dir, home_from, write_atomic};
    use crate::error::Error;

    fn mode(path: &Path) -> u32 {
        std::fs::symlink_metadata(path)
            .unwrap()
            .permissions()
            .mode()
            & 0o777
    }

    fn chmod(path: &Path, mode: u32) {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
    }

    /// Unset and empty are no home; a relative path is refused by the variable's name;
    /// an absolute one is the home.
    #[test]
    fn a_home_is_absolute_or_it_is_none() {
        assert_eq!(home_from("ZAP_HOME", None).unwrap(), None);
        assert_eq!(home_from("ZAP_HOME", Some("".into())).unwrap(), None);
        assert_eq!(
            home_from("HOME", Some("/home/op".into())).unwrap(),
            Some("/home/op".into())
        );
        for relative in ["rel", "./rel", "../rel", ".", "~", "~/x"] {
            for var in ["ZAP_HOME", "HOME"] {
                let Err(Error::HomeNotAbsolute { var: named }) =
                    home_from(var, Some(relative.into()))
                else {
                    panic!("{var}={relative} was taken for a home");
                };
                assert_eq!(named, var);
            }
        }
    }

    #[test]
    fn a_written_file_and_every_dir_above_it_are_owner_only() {
        let scratch = tempfile::tempdir().unwrap();
        // The root's own parent is the operator's: created as needed, left as it is.
        let home = scratch.path().join("above/zap-home");
        let dir = home.join("cache/slug/last_run");
        write_atomic(&home, &dir, "local.json", b"{}").unwrap();
        // Low 12 bits — the rename preserves the temp file's 0600.
        assert_eq!(mode(&dir.join("local.json")), 0o600);
        for owned in [
            home.clone(),
            home.join("cache"),
            home.join("cache/slug"),
            dir.clone(),
        ] {
            assert_eq!(mode(&owned), 0o700, "{}", owned.display());
        }
        assert_ne!(mode(&scratch.path().join("above")) & 0o700, 0);

        // A tree that was left open is tightened at every level, the root included.
        for open in [home.clone(), home.join("cache"), home.join("cache/slug")] {
            chmod(&open, 0o775);
        }
        write_atomic(&home, &dir, "local.json", b"{}").unwrap();
        for owned in [home.clone(), home.join("cache"), home.join("cache/slug")] {
            assert_eq!(mode(&owned), 0o700, "{}", owned.display());
        }
        // Whoever else it is open to: its group alone is as much someone else.
        for open in [0o770, 0o750, 0o710, 0o701] {
            chmod(&home.join("cache"), open);
            ensure_state_dir(&home, &home.join("cache")).unwrap();
            assert_eq!(mode(&home.join("cache")), 0o700, "{open:o}");
        }
        // One the owner restricted further is left alone.
        chmod(&home.join("cache"), 0o500);
        ensure_state_dir(&home, &home.join("cache")).unwrap();
        assert_eq!(mode(&home.join("cache")), 0o500);
        chmod(&home.join("cache"), 0o700);
    }

    /// A directory of zap's is named by plain components under its home: a `..` among
    /// them is refused before anything past it is made, and so is a path outside it.
    #[test]
    fn a_state_dir_is_a_plain_path_under_the_home() {
        let scratch = tempfile::tempdir().unwrap();
        let home = scratch.path().join("zap-home");
        for dir in [
            home.join("cache/../escaped"),
            scratch.path().join("outside"),
        ] {
            let error = ensure_state_dir(&home, &dir).unwrap_err();
            assert_eq!(
                error.kind(),
                std::io::ErrorKind::InvalidInput,
                "{}",
                dir.display()
            );
        }
        assert!(!home.join("escaped").exists());
        assert!(!scratch.path().join("outside").exists());
    }

    /// A symlink where a directory of zap's goes is refused by its path — at the root,
    /// in the middle, at the leaf — and what it points at is neither written into nor
    /// re-moded. So is a file there.
    #[test]
    fn a_symlink_in_the_tree_is_refused_and_not_followed() {
        let scratch = tempfile::tempdir().unwrap();
        let elsewhere = scratch.path().join("elsewhere");
        std::fs::create_dir(&elsewhere).unwrap();
        chmod(&elsewhere, 0o755);

        for linked in ["", "cache", "cache/slug", "cache/slug/last_run"] {
            let home = scratch
                .path()
                .join(format!("home-{}", linked.replace('/', "-")));
            let dir = home.join("cache/slug/last_run");
            let at = if linked.is_empty() {
                home.clone()
            } else {
                home.join(linked)
            };
            std::fs::create_dir_all(at.parent().unwrap()).unwrap();
            std::os::unix::fs::symlink(&elsewhere, &at).unwrap();

            let error = write_atomic(&home, &dir, "local.json", b"{}").unwrap_err();
            assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput, "{linked}");
            assert_eq!(
                error.to_string(),
                format!("{} is a symbolic link", at.display()),
                "{linked}"
            );
            assert_eq!(
                mode(&elsewhere),
                0o755,
                "{linked}: the link's target was re-moded"
            );
            assert_eq!(
                std::fs::read_dir(&elsewhere).unwrap().count(),
                0,
                "{linked}: written through the link"
            );
        }

        let home = scratch.path().join("home-file");
        std::fs::create_dir(&home).unwrap();
        std::fs::write(home.join("cache"), b"").unwrap();
        let error = ensure_state_dir(&home, &home.join("cache/slug")).unwrap_err();
        assert_eq!(
            error.to_string(),
            format!(
                "{} is a file, not a directory",
                home.join("cache").display()
            )
        );
        // A directory that isn't under the home is no directory of the tree.
        ensure_state_dir(&home, &scratch.path().join("other")).unwrap_err();
        ensure_state_dir(&home, &home.join("cache/../../other")).unwrap_err();
        assert!(!scratch.path().join("other").exists());

        // A path that leaves its plain names is refused before anything is made: not
        // the home, not a directory before the `..`.
        let fresh = scratch.path().join("fresh-home");
        let error = ensure_state_dir(&fresh, &fresh.join("a/b/../c")).unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput, "{error}");
        assert!(!fresh.exists(), "nothing of the home is made");
    }

    /// A command holds its config's directory to being zap's own before reading from
    /// it: a symlinked one — or a symlinked subtree a record would be read from — is an
    /// error naming the path, and a tree that is zap's own, or not there yet, passes.
    #[test]
    fn a_command_refuses_a_config_dir_that_is_not_its_own() {
        let scratch = tempfile::tempdir().unwrap();
        let config = scratch.path().join("zap.ts");
        std::fs::write(&config, "").unwrap();
        let elsewhere = scratch.path().join("elsewhere");
        std::fs::create_dir(&elsewhere).unwrap();

        // Nothing is made by taking it: a directory comes to be when it is written to.
        let home = scratch.path().join("home");
        claim_state_dirs(&home, &config).unwrap();
        assert!(!home.exists());
        let config_dir = config_dir_for(&home, &config);
        ensure_state_dir(&home, &config_dir).unwrap();
        // A tree left open is tightened from the root down.
        for open in [home.clone(), home.join("cache"), config_dir.clone()] {
            chmod(&open, 0o775);
        }
        claim_state_dirs(&home, &config).unwrap();
        for owned in [home.clone(), home.join("cache"), config_dir.clone()] {
            assert_eq!(mode(&owned), 0o700, "{}", owned.display());
        }

        for subtree in ["eval", "last_run", "deploy_preview"] {
            let at = config_dir.join(subtree);
            std::os::unix::fs::symlink(&elsewhere, &at).unwrap();
            let Err(Error::StateDir { path, found }) = claim_state_dirs(&home, &config) else {
                panic!("a symlinked {subtree} was taken");
            };
            assert_eq!(path, at.display().to_string());
            assert!(
                found.starts_with("is a symbolic link — zap doesn't follow"),
                "{found}"
            );
            std::fs::remove_file(&at).unwrap();
            // A real one, left open, is tightened.
            std::fs::create_dir(&at).unwrap();
            chmod(&at, 0o777);
            claim_state_dirs(&home, &config).unwrap();
            assert_eq!(mode(&at), 0o700);
        }

        std::fs::remove_dir_all(&config_dir).unwrap();
        std::os::unix::fs::symlink(&elsewhere, &config_dir).unwrap();
        let error = claim_state_dirs(&home, &config).unwrap_err();
        assert_eq!(
            error.to_string(),
            format!(
                "zap keeps its state in directories of its own, and {} is a symbolic link \
                 — zap doesn't follow a link there: replace the link with a directory, or \
                 — when the link is zap's home itself — set `ZAP_HOME` to the directory it \
                 points to",
                config_dir.display()
            )
        );
        assert_eq!(std::fs::read_dir(&elsewhere).unwrap().count(), 0);
    }

    /// A directory that belongs to another user is refused by its path and left as it
    /// is, though this user can open it: `/` is root's on every unix.
    #[test]
    fn a_directory_of_another_users_is_refused() {
        if nix::unistd::geteuid().is_root() {
            return;
        }
        let root = Path::new("/");
        let before = mode(root);
        let error = ensure_state_dir(root, root).unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
        assert_eq!(error.to_string(), "/ belongs to another user");
        assert_eq!(mode(root), before);

        // One this user can't open is refused the same way — by whose it is, read
        // from its name, not by the failure to open it. `/root` is such a directory
        // wherever root keeps its home closed.
        let closed = Path::new("/root");
        if closed.is_dir() && std::fs::read_dir(closed).is_err() {
            let error = ensure_state_dir(closed, closed).unwrap_err();
            assert_eq!(error.to_string(), "/root belongs to another user");
            let config = Path::new("/nonexistent/zap.ts");
            let Err(Error::StateDir { path, found }) = claim_state_dirs(closed, config) else {
                panic!("another user's closed directory was taken");
            };
            assert_eq!(path, "/root");
            assert_eq!(
                found,
                "belongs to another user — run zap as that user, or set `ZAP_HOME` to a \
                 directory of your own"
            );
        }
    }

    /// A directory of this user's that can't be opened is not one zap can hold to its
    /// rule: a command refuses it by its path, with how to open it again, and a write
    /// fails naming it. What isn't there at all is nothing to refuse.
    #[test]
    fn a_directory_that_cannot_be_opened_is_refused() {
        if nix::unistd::geteuid().is_root() {
            return;
        }
        let scratch = tempfile::tempdir().unwrap();
        let config = scratch.path().join("zap.ts");
        std::fs::write(&config, "").unwrap();
        let home = scratch.path().join("home");
        let config_dir = config_dir_for(&home, &config);
        ensure_state_dir(&home, &config_dir.join("last_run")).unwrap();
        ensure_state_dir(&home, &home.join("ssh")).unwrap();

        for closed in [config_dir, home.join("ssh"), home.join("cache")] {
            for mode in [0o311, 0o000] {
                chmod(&closed, mode);
                let Err(Error::StateDir { path, found }) = claim_state_dirs(&home, &config) else {
                    panic!("{} at {mode:o} was taken", closed.display());
                };
                assert_eq!(path, closed.display().to_string());
                assert!(
                    found.starts_with("can't be opened (")
                        && found.ends_with(
                            ") — restore your access to it (`chmod 700`), or set `ZAP_HOME` \
                             to another directory"
                        ),
                    "{found}"
                );
                let error = ensure_state_dir(&home, &closed).unwrap_err();
                assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
                assert!(
                    error
                        .to_string()
                        .starts_with(&format!("{} can't be opened (", closed.display())),
                    "{error}"
                );
            }
            chmod(&closed, 0o700);
            claim_state_dirs(&home, &config).unwrap();
        }
        // A symlinked socket directory is refused like the rest of the tree.
        std::fs::remove_dir(home.join("ssh")).unwrap();
        std::os::unix::fs::symlink(scratch.path(), home.join("ssh")).unwrap();
        let Err(Error::StateDir { path, .. }) = claim_state_dirs(&home, &config) else {
            panic!("a symlinked ssh/ was taken");
        };
        assert_eq!(path, home.join("ssh").display().to_string());
    }

    /// A rename that fails (the destination is a directory) leaves no temp file behind.
    #[test]
    fn a_failed_write_leaves_no_temp_file() {
        let home = tempfile::tempdir().unwrap();
        let dir = home.path().join("last_run");
        std::fs::create_dir_all(dir.join("local.json/occupied")).unwrap();
        write_atomic(home.path(), &dir, "local.json", b"{}").unwrap_err();
        let mut names: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        names.sort();
        assert_eq!(names, ["local.json"]);
    }

    /// The temp file is created new: a link left at its name is replaced, never written
    /// through.
    #[test]
    fn a_link_at_the_temp_name_is_not_written_through() {
        let home = tempfile::tempdir().unwrap();
        let dir = home.path().join("last_run");
        std::fs::create_dir(&dir).unwrap();
        let victim = home.path().join("victim");
        std::fs::write(&victim, b"untouched").unwrap();
        let temp = dir.join(format!("local.json.tmp.{}", std::process::id()));
        std::os::unix::fs::symlink(&victim, &temp).unwrap();
        write_atomic(home.path(), &dir, "local.json", b"{}").unwrap();
        assert_eq!(std::fs::read(&victim).unwrap(), b"untouched");
        assert_eq!(std::fs::read(dir.join("local.json")).unwrap(), b"{}");
        assert!(std::fs::symlink_metadata(&temp).is_err());
    }
}
