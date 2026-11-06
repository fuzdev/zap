//! The `Local` connection's native file install: the operator's own write, with the
//! properties the privileged put script (`zap_types::put::FILE_PUT`) gives a root one.
//!
//! The content is staged in a new file in the destination's own directory — an
//! exclusive create under a name nobody could have planted, `0600` until its mode is
//! set — given its owner and mode through the open handle, flushed to disk, and renamed
//! over the destination. So the destination never exists with the wrong mode or owner,
//! a symbolic link there is replaced rather than followed, a directory there is
//! refused, and a crash leaves the old file or the new one.
//!
//! What the install's [`FileAttrs`] leave out is a plain create's, or with
//! [`Unset::Keep`] what the path has: an existing regular file's owner, group, and mode
//! (less any set-id or sticky bit), or for a new file its directory's owner and group —
//! the privileged script's rule, read here by name as the operator, a hard-linked file
//! and anywhere below a directory anyone may write (`/tmp`) giving nothing, and a mode
//! to keep from a file with a POSIX access list refused.
//!
//! A directory's mode and owner are set the same way ([`set_dir_attrs`]): through a
//! handle on the directory itself, never by a name a symbolic link could stand at.
//!
//! An operation the operator isn't allowed (an unwritable directory, an owner only root
//! may set, a kept owner of another account's) fails with [`PermissionDenied`](std::io::ErrorKind::PermissionDenied), and
//! that alone ([`Native::Denied`]) is the caller's cue for the privileged script. Anything
//! else — a link where the directory should be, a directory where the file should go, a
//! full disk — is the answer, and `sudo` is never asked to repeat it. The staged file is
//! removed on every failure.

use std::io::Write as _;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};

use tempfile::NamedTempFile;
use zap_types::extract::NOT_A_DIRECTORY_REFUSAL;
use zap_types::put::{
    ACCESS_LIST_KEEP_REFUSAL, FileAttrs, MISSING_COMPONENT_REFUSAL, NO_FILE_NAME_REFUSAL,
    NO_PROC_REFUSAL, NOT_A_DIRECTORY_NAME_REFUSAL, NOT_ABSOLUTE_REFUSAL, NOTHING_MADE_REFUSAL,
    Unset,
};

/// Where an installed file's bytes come from.
pub(super) enum LocalSource {
    /// Bytes in memory.
    Bytes(Vec<u8>),
    /// A file on this machine, streamed rather than read whole.
    File(PathBuf),
}

impl std::fmt::Debug for LocalSource {
    /// The bytes' length, never the bytes: a file's content may be a secret, and this
    /// is the form a log line or a panic message would print.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Bytes(bytes) => write!(f, "Bytes({} bytes)", bytes.len()),
            Self::File(path) => f.debug_tuple("File").field(path).finish(),
        }
    }
}

/// Whether a native operation's failure is the cue to do it with `sudo` instead: only
/// when the operator was **not permitted** (`EACCES`, `EPERM`). Every other failure —
/// nothing there, a directory or a link in the way, a read-only filesystem, a full
/// disk, a bad value — would fail the same way as root or says something root shouldn't
/// paper over, so it is reported as it is.
fn escalates(error: &std::io::Error) -> bool {
    error.kind() == std::io::ErrorKind::PermissionDenied
}

/// What a native attempt came to, for the caller deciding whether `sudo` is next.
#[derive(Debug)]
pub(super) enum Native {
    /// It was done.
    Done,
    /// The operator was not permitted: the privileged script is next.
    Denied,
    /// It failed for a reason more privilege wouldn't change. This is the result.
    Failed(std::io::Error),
}

impl Native {
    /// Read a native attempt's result — the one place the escalation rule is applied
    /// ([`escalates`]), for a write, a place, and a directory change alike.
    pub(super) fn of(result: std::io::Result<()>) -> Self {
        match result {
            Ok(()) => Self::Done,
            Err(error) if escalates(&error) => Self::Denied,
            Err(error) => Self::Failed(error),
        }
    }
}

/// The mode and ids an install applies, resolved from a [`FileAttrs`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Resolved {
    mode: Option<u32>,
    uid: Option<u32>,
    gid: Option<u32>,
    /// Whether what is left out is taken from what the path holds ([`Unset::Keep`]).
    keep: bool,
}

/// What an install that keeps what it leaves unset ([`Unset::Keep`]) finds at its path,
/// looked up by name with no link followed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Found {
    /// A regular file: its mode (permission bits only) and ids.
    File { mode: u32, uid: u32, gid: u32 },
    /// Nothing: the ids of the directory the file goes in.
    Nothing { uid: u32, gid: u32 },
    /// Something else — a symbolic link, a directory, a file with a second name — or
    /// anything below a directory anyone may put an entry in: it gives nothing.
    Other,
}

impl Resolved {
    /// These attributes with what they leave out filled from `found`: a regular file's
    /// owner, group, and mode less any set-id or sticky bit; with nothing there, the
    /// directory's owner and group. A declared value always stands.
    const fn filled(self, found: Found) -> Self {
        let (mode, uid, gid) = match found {
            Found::File { mode, uid, gid } => (Some(mode & 0o777), Some(uid), Some(gid)),
            Found::Nothing { uid, gid } => (None, Some(uid), Some(gid)),
            Found::Other => (None, None, None),
        };
        Self {
            mode: match self.mode {
                Some(mode) => Some(mode),
                None => mode,
            },
            uid: match self.uid {
                Some(uid) => Some(uid),
                None => uid,
            },
            gid: match self.gid {
                Some(gid) => Some(gid),
                None => gid,
            },
            keep: self.keep,
        }
    }
}

/// Whether a directory's mode lets anyone put an entry in it — its sticky bit set
/// (`/tmp`), or writable by every account — so that nothing in it, nor the name of
/// one missing, says what its own owner meant.
const fn open_to_anyone(dir_mode: u32) -> bool {
    dir_mode & 0o1002 != 0
}

/// Whether the directory held at `dir`, or any directory above it, lets anyone put an
/// entry in it ([`open_to_anyone`]). The walk goes up by `..` from the handle (the
/// kernel's parent, never a name), one `fstat` each, and stops at the root, whose `..`
/// is itself. Below such a directory anyone could have made or renamed in what is
/// there, so nothing in it says what its owner meant.
fn crossed_open_dir(dir: &impl std::os::fd::AsFd) -> std::io::Result<bool> {
    use nix::fcntl::{OFlag, openat};
    use nix::sys::stat::{Mode, fstat};

    let mut held = fstat(dir)?;
    let mut parent = openat(
        dir,
        "..",
        OFlag::O_PATH | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC,
        Mode::empty(),
    )?;
    loop {
        if open_to_anyone(held.st_mode) {
            return Ok(true);
        }
        let above = fstat(&parent)?;
        if (above.st_dev, above.st_ino) == (held.st_dev, held.st_ino) {
            return Ok(false);
        }
        held = above;
        parent = openat(
            &parent,
            "..",
            OFlag::O_PATH | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC,
            Mode::empty(),
        )?;
    }
}

/// Whether `dir` as declared, or any prefix of it, leads to a directory anyone may put
/// an entry in ([`open_to_anyone`]), each read following links. The walk up by `..`
/// ([`crossed_open_dir`]) passes only through where the links resolve, so a link
/// planted in a shared directory — an attacker's `/tmp/cache` pointing at a directory
/// of theirs — is seen here, where it sits. A link met on the way that leads through a
/// second link sitting in a shared directory off both chains is seen by neither.
fn declared_open_dir(dir: &Path) -> std::io::Result<bool> {
    use std::os::unix::fs::MetadataExt as _;

    for prefix in dir
        .ancestors()
        .filter(|prefix| !prefix.as_os_str().is_empty())
    {
        if open_to_anyone(std::fs::metadata(prefix)?.mode()) {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Whether the file at `path` carries an extended POSIX access list: its
/// `system.posix_acl_access` attribute, read with no link followed. None there
/// (`ENODATA`), or a filesystem without them (`EOPNOTSUPP`), is no list.
fn has_access_list(path: &Path) -> std::io::Result<bool> {
    match rustix::fs::lgetxattr(path, "system.posix_acl_access", &mut [0_u8; 0][..]) {
        Ok(_) => Ok(true),
        Err(rustix::io::Errno::NODATA | rustix::io::Errno::NOTSUP) => Ok(false),
        Err(errno) => Err(errno.into()),
    }
}

/// The refusal of a mode to keep from a file with an access list ([`has_access_list`]):
/// its mode bits show the list's mask, not its group's, and the new file carries no
/// list. Not a denial, so `sudo` is never asked to repeat it.
fn access_list_refused() -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidInput, ACCESS_LIST_KEEP_REFUSAL)
}

/// What is at `path`, for an install into `dir` that keeps what it leaves unset. The
/// name is looked up with no link followed; `dir` is followed, as the install's own
/// create in it is. Anywhere below a directory anyone may put an entry in, on the chain
/// `dir` resolves to ([`crossed_open_dir`]) or on its path as declared
/// ([`declared_open_dir`]), gives nothing, and so does a regular file with another name
/// (a hard link).
fn found_at(path: &Path, dir: &Path) -> std::io::Result<Found> {
    use std::os::unix::fs::MetadataExt as _;

    use nix::fcntl::OFlag;
    use nix::sys::stat::{Mode, fstat};

    let held = nix::fcntl::open(
        dir,
        OFlag::O_PATH | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC,
        Mode::empty(),
    )?;
    if declared_open_dir(dir)? || crossed_open_dir(&held)? {
        return Ok(Found::Other);
    }
    let dir = fstat(&held)?;
    match std::fs::symlink_metadata(path) {
        Ok(meta) if meta.is_file() && meta.nlink() == 1 => Ok(Found::File {
            mode: meta.mode() & 0o7777,
            uid: meta.uid(),
            gid: meta.gid(),
        }),
        Ok(_) => Ok(Found::Other),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Found::Nothing {
            uid: dir.st_uid,
            gid: dir.st_gid,
        }),
        Err(error) => Err(error),
    }
}

impl Resolved {
    /// Parse the octal mode and resolve the owner and group as `chown` does: a name is
    /// looked up, and one with no entry that is all digits is the id itself (what a
    /// snapshot of an existing file records).
    fn of(attrs: FileAttrs<'_>) -> std::io::Result<Self> {
        let invalid =
            |message: String| std::io::Error::new(std::io::ErrorKind::InvalidInput, message);
        let numeric = |name: &str| {
            name.bytes()
                .all(|byte| byte.is_ascii_digit())
                .then(|| name.parse::<u32>().ok())
                .flatten()
        };
        let mode = attrs
            .mode
            .map(|mode| {
                u32::from_str_radix(mode, 8)
                    .map_err(|_| invalid(format!("not an octal mode: {mode}")))
            })
            .transpose()?;
        let uid = attrs
            .owner
            .map(|name| match nix::unistd::User::from_name(name) {
                Ok(Some(user)) => Ok(user.uid.as_raw()),
                Ok(None) => numeric(name).ok_or_else(|| invalid(format!("no such user: {name}"))),
                Err(errno) => Err(std::io::Error::from(errno)),
            })
            .transpose()?;
        let gid = attrs
            .group
            .map(|name| match nix::unistd::Group::from_name(name) {
                Ok(Some(group)) => Ok(group.gid.as_raw()),
                Ok(None) => numeric(name).ok_or_else(|| invalid(format!("no such group: {name}"))),
                Err(errno) => Err(std::io::Error::from(errno)),
            })
            .transpose()?;
        Ok(Self {
            mode,
            uid,
            gid,
            keep: attrs.unset == Unset::Keep,
        })
    }
}

/// Refuse a `path` that isn't absolute ([`NOT_ABSOLUTE_REFUSAL`]), as the put scripts
/// do: a relative one would resolve against this process's working directory.
fn refuse_relative(path: &str) -> std::io::Result<()> {
    if path.starts_with('/') {
        Ok(())
    } else {
        Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            NOT_ABSOLUTE_REFUSAL,
        ))
    }
}

/// Install `source` at `path` with `attrs`, off the async runtime's threads.
///
/// # Errors
/// The failing operation's error; `InvalidInput` for a `path` that isn't absolute;
/// `PermissionDenied` for one the operator isn't allowed.
pub(super) async fn put(
    path: &str,
    source: LocalSource,
    attrs: FileAttrs<'_>,
) -> std::io::Result<()> {
    refuse_relative(path)?;
    let resolved = Resolved::of(attrs)?;
    let path = PathBuf::from(path);
    tokio::task::spawn_blocking(move || {
        let staged = stage(&path, &source, resolved)?;
        staged
            .persist(&path)
            .map(|_| ())
            .map_err(|error| error.error)
    })
    .await
    .map_err(std::io::Error::other)?
}

/// Make the directory `path` and its missing parents, off the async runtime's threads:
/// the native form of the privileged `zap_types::put::MAKE_DIRS`, with its rule — each
/// directory made gets the owner and group of the one it was made in, which down the
/// chain is the nearest one that was there, except below a directory anyone may write.
///
/// # Errors
/// `PermissionDenied` for what the operator isn't allowed — making a directory where it
/// may not, or giving one an owner or group it can't (another account's, or a group it
/// isn't in), which is known before anything is made; any other failure as it came.
pub(super) async fn make_dirs(path: &str) -> std::io::Result<()> {
    let path = path.to_owned();
    tokio::task::spawn_blocking(move || dirs(&path))
        .await
        .map_err(std::io::Error::other)?
}

/// Whether the operator may give what it makes the owner `uid` and group `gid`: root
/// may give any; anyone else only their own uid and a group they are in.
fn may_give(uid: u32, gid: u32) -> bool {
    let euid = nix::unistd::geteuid();
    if euid.is_root() {
        return true;
    }
    let gid = nix::unistd::Gid::from_raw(gid);
    uid == euid.as_raw()
        && (gid == nix::unistd::getegid()
            || nix::unistd::getgroups().is_ok_and(|groups| groups.contains(&gid)))
}

/// [`make_dirs`]' work. The path is walked up by name (a symbolic link counts as there)
/// to the nearest entry that is, which must lead to a directory, and is opened (a link
/// to one followed, as `mkdir -p` follows it). From there everything goes by handle:
/// each missing component is made in the directory held open before it (`mkdirat`),
/// opened there with no link at its name followed, and — when this run made it — given
/// that directory's owner and group through the handle, read from the handle each time.
/// So a component renamed or replaced by a link underneath the walk can't send the next
/// create, or an owner change, anywhere else.
///
/// A directory made is given its owner only while the handle holds an empty directory
/// the operator owns: as root, the owner of the directory it was made in could rename
/// a directory of theirs over it before the open, and would otherwise be handed that
/// one; a listing that fails gives it nothing either, and says so. Anywhere below a
/// directory anyone may write, resolved ([`crossed_open_dir`]) or as declared
/// ([`declared_open_dir`]), what is made stays the operator's.
fn dirs(path: &str) -> std::io::Result<()> {
    use std::os::fd::OwnedFd;

    use nix::errno::Errno;
    use nix::fcntl::OFlag;
    use nix::sys::stat::{Mode, fstat};

    let invalid = |message: &str| std::io::Error::new(std::io::ErrorKind::InvalidInput, message);
    refuse_relative(path)?;
    let trimmed = path.trim_end_matches('/');
    let mut at = if trimmed.is_empty() { "/" } else { trimmed };
    let mut missing = Vec::new();
    loop {
        match std::fs::symlink_metadata(at) {
            Ok(_) => break,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        let (parent, name) = at.rsplit_once('/').unwrap_or(("", at));
        if matches!(name, "" | "." | "..") {
            return Err(invalid(MISSING_COMPONENT_REFUSAL));
        }
        missing.push(name);
        at = if parent.is_empty() { "/" } else { parent };
    }
    let not_a_dir = || std::io::Error::new(std::io::ErrorKind::NotADirectory, NOTHING_MADE_REFUSAL);
    let parent: OwnedFd = match nix::fcntl::open(
        at,
        OFlag::O_PATH | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC,
        Mode::empty(),
    ) {
        Ok(fd) => fd,
        Err(Errno::ENOTDIR | Errno::ENOENT) => return Err(not_a_dir()),
        Err(errno) => return Err(errno.into()),
    };
    if missing.is_empty() {
        return Ok(());
    }
    let base = fstat(&parent)?;
    let crossed = declared_open_dir(Path::new(at))? || crossed_open_dir(&parent)?;
    if !crossed && !may_give(base.st_uid, base.st_gid) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "the directories it makes take an owner or group the operator can't give",
        ));
    }
    missing.reverse();
    make_below(parent, &missing, crossed, &|_| {})
}

/// Make `names` in turn, each in the one before it, the first in `parent` — the
/// by-handle half of [`dirs`]. With `crossed` (`parent` is below a directory anyone may
/// write), or once the walk meets one, nothing made from there on is given an owner.
/// `after_make` runs after each create this run made, with its name: nothing in a run,
/// the tests' way to move something underneath the walk.
fn make_below(
    mut parent: std::os::fd::OwnedFd,
    names: &[&str],
    mut crossed: bool,
    after_make: &dyn Fn(&str),
) -> std::io::Result<()> {
    use std::os::fd::AsRawFd as _;
    use std::os::unix::fs::MetadataExt as _;

    use nix::errno::Errno;
    use nix::fcntl::{OFlag, openat};
    use nix::sys::stat::{Mode, fstat, mkdirat};

    let me = nix::unistd::geteuid().as_raw();
    for &name in names {
        let held = fstat(&parent)?;
        crossed |= open_to_anyone(held.st_mode);
        let give = (!crossed).then_some((held.st_uid, held.st_gid));
        let made = match mkdirat(&parent, name, Mode::from_bits_truncate(0o777)) {
            Ok(()) => true,
            Err(Errno::EEXIST) => false,
            Err(errno) => return Err(errno.into()),
        };
        if made {
            after_make(name);
        }
        let child = openat(
            &parent,
            name,
            OFlag::O_PATH | OFlag::O_NOFOLLOW | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC,
            Mode::empty(),
        )
        .map_err(|errno| match errno {
            Errno::ENOTDIR | Errno::ELOOP => std::io::Error::new(
                std::io::ErrorKind::NotADirectory,
                format!("{name} is not a directory of its own (a symbolic link is not followed)"),
            ),
            errno => errno.into(),
        })?;
        if let (true, Some((uid, gid))) = (made, give) {
            let proc = format!("/proc/self/fd/{}", child.as_raw_fd());
            let has = std::fs::metadata(&proc).map_err(needs_proc)?;
            let unlisted = |error: std::io::Error| {
                std::io::Error::new(
                    error.kind(),
                    format!("{name} could not be listed, so it is given no owner: {error}"),
                )
            };
            let mut listing = std::fs::read_dir(&proc).map_err(|error| {
                if error.kind() == std::io::ErrorKind::NotFound {
                    needs_proc(error)
                } else {
                    unlisted(error)
                }
            })?;
            let empty = match listing.next() {
                None => true,
                Some(Ok(_)) => false,
                Some(Err(error)) => return Err(unlisted(error)),
            };
            if has.uid() != me || !empty {
                return Err(std::io::Error::other(format!(
                    "{name} is not the empty directory just made, so it is given no owner"
                )));
            }
            let uid = Some(uid).filter(|uid| *uid != has.uid());
            let gid = Some(gid).filter(|gid| *gid != has.gid());
            if uid.is_some() || gid.is_some() {
                std::os::unix::fs::chown(&proc, uid, gid).map_err(needs_proc)?;
            }
        }
        parent = child;
    }
    Ok(())
}

/// Set the directory at `path` to `attrs`' mode, owner, and group, off the async
/// runtime's threads.
///
/// # Errors
/// The failing operation's error; `InvalidInput` for a `path` that isn't absolute;
/// `PermissionDenied` for one the operator isn't allowed.
pub(super) async fn set_dir_attrs(path: &str, attrs: FileAttrs<'_>) -> std::io::Result<()> {
    refuse_relative(path)?;
    let resolved = Resolved::of(attrs)?;
    let path = path.to_owned();
    tokio::task::spawn_blocking(move || dir_attrs(&path, resolved))
        .await
        .map_err(std::io::Error::other)?
}

/// Set a directory's owner, then its mode, through a handle on the directory itself.
///
/// The path is opened `O_PATH | O_NOFOLLOW | O_DIRECTORY`: a symbolic link at its last
/// component is not followed (the open fails — the path is then not a directory), and
/// no read or search permission on the directory is needed, so a directory the operator
/// owns but can't list is still theirs to change. Trailing slashes are dropped first and
/// a last component of `.` or `..` is refused — either would name what a link points
/// at. The changes go through `/proc/self/fd/<n>`, which names the open directory
/// whatever its path has become.
fn dir_attrs(path: &str, attrs: Resolved) -> std::io::Result<()> {
    use std::os::fd::AsRawFd as _;
    use std::os::unix::fs::OpenOptionsExt as _;

    use nix::fcntl::OFlag;

    let trimmed = path.trim_end_matches('/');
    let path = if trimmed.is_empty() { "/" } else { trimmed };
    if path.ends_with("/.") || path.ends_with("/..") || path == "." || path == ".." {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            NOT_A_DIRECTORY_NAME_REFUSAL,
        ));
    }
    let flags = OFlag::O_PATH | OFlag::O_NOFOLLOW | OFlag::O_DIRECTORY;
    let dir = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(flags.bits())
        .open(path)
        .map_err(|error| match error.kind() {
            std::io::ErrorKind::NotADirectory => {
                std::io::Error::new(error.kind(), NOT_A_DIRECTORY_REFUSAL)
            }
            _ => error,
        })?;
    let held = format!("/proc/self/fd/{}", dir.as_raw_fd());
    // The owner first: changing it clears the set-id bits a mode may carry.
    if attrs.uid.is_some() || attrs.gid.is_some() {
        std::os::unix::fs::chown(&held, attrs.uid, attrs.gid).map_err(needs_proc)?;
    }
    if let Some(mode) = attrs.mode {
        std::fs::set_permissions(&held, std::fs::Permissions::from_mode(mode))
            .map_err(needs_proc)?;
    }
    Ok(())
}

/// The error of a change made through `/proc/self/fd/<n>`, with a `NotFound` said as
/// what it is. The directory is open — it exists — so the only name that can be missing
/// is the `/proc` one: a machine without `/proc` mounted. Left as it came, the error
/// would read as the directory itself not being there.
fn needs_proc(error: std::io::Error) -> std::io::Error {
    if error.kind() == std::io::ErrorKind::NotFound {
        std::io::Error::new(error.kind(), NO_PROC_REFUSAL)
    } else {
        error
    }
}

/// Stage `source` beside `path`, as the file a rename then installs: its content
/// written, its owner and mode set, and all of it flushed to disk. Dropping the result
/// removes it.
///
/// With `keep`, what `attrs` leave out is taken from what `path` holds ([`found_at`],
/// [`Resolved::filled`]), so an owner or group the operator may not give — a file another
/// account owns, a directory root owns — is `PermissionDenied`, the cue for the
/// privileged put, which keeps them. An owner or group the staged file already has is not
/// set again.
fn stage(path: &Path, source: &LocalSource, attrs: Resolved) -> std::io::Result<NamedTempFile> {
    use std::os::unix::fs::MetadataExt as _;

    if path.file_name().is_none() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            NO_FILE_NAME_REFUSAL,
        ));
    }
    let dir = match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    };
    let attrs = if attrs.keep {
        let found = found_at(path, dir)?;
        if attrs.mode.is_none() && matches!(found, Found::File { .. }) && has_access_list(path)? {
            return Err(access_list_refused());
        }
        attrs.filled(found)
    } else {
        attrs
    };
    let mut builder = tempfile::Builder::new();
    builder.prefix(".zap.");
    if attrs.mode.is_none() {
        // No mode declared: the one a plain create gives, `0666` less the umask, which
        // the kernel applies at the create. A declared mode is set below, on a file
        // that is `0600` until then.
        builder.permissions(std::fs::Permissions::from_mode(0o666));
    }
    let mut staged = builder.tempfile_in(dir)?;
    // The owner before the content, so one the operator may not give costs no copy, and
    // before the mode: changing it clears the set-id bits a mode may carry.
    let has = staged.as_file().metadata()?;
    let uid = attrs.uid.filter(|uid| *uid != has.uid());
    let gid = attrs.gid.filter(|gid| *gid != has.gid());
    if uid.is_some() || gid.is_some() {
        std::os::unix::fs::fchown(staged.as_file(), uid, gid)?;
    }
    match source {
        LocalSource::Bytes(bytes) => staged.as_file_mut().write_all(bytes)?,
        LocalSource::File(from) => {
            std::io::copy(&mut std::fs::File::open(from)?, staged.as_file_mut())?;
        }
    }
    if let Some(mode) = attrs.mode {
        staged
            .as_file()
            .set_permissions(std::fs::Permissions::from_mode(mode))?;
    }
    staged.as_file().sync_all()?;
    Ok(staged)
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _, symlink};

    use zap_types::put::{FileAttrs, NOT_ABSOLUTE_REFUSAL};

    use super::{
        Found, LocalSource, Native, Resolved, escalates, make_below, make_dirs, may_give,
        needs_proc, put, set_dir_attrs, stage,
    };

    fn bytes(content: &[u8]) -> LocalSource {
        LocalSource::Bytes(content.to_vec())
    }

    fn mode_of(path: &std::path::Path) -> u32 {
        std::fs::symlink_metadata(path).unwrap().mode() & 0o7777
    }

    /// The names in `dir`, sorted.
    fn entries(dir: &std::path::Path) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(dir)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        names
    }

    /// The staged file carries its declared mode before the rename, so the destination
    /// never exists with another; with no mode declared it has the umask's.
    #[test]
    fn the_staged_file_has_its_final_mode_before_it_is_renamed() {
        let dir = crate::test_scratch::tempdir();
        let path = dir.path().join("secret.env");
        let declared = Resolved::of(FileAttrs::mode("640")).unwrap();
        let staged = stage(&path, &bytes(b"TOKEN=1\n"), declared).unwrap();
        assert!(!path.exists(), "nothing is at the destination yet");
        assert_eq!(mode_of(staged.path()), 0o640);
        assert_eq!(staged.path().parent(), Some(dir.path()));
        assert_eq!(std::fs::read(staged.path()).unwrap(), b"TOKEN=1\n");
        let staged_path = staged.path().to_path_buf();
        drop(staged);
        assert!(!staged_path.exists(), "an abandoned stage is removed");

        let undeclared = Resolved::of(FileAttrs::NONE).unwrap();
        let staged = stage(&path, &bytes(b"x"), undeclared).unwrap();
        let plain = dir.path().join("plain");
        std::fs::write(&plain, "").unwrap();
        assert_eq!(
            mode_of(staged.path()),
            mode_of(&plain),
            "no declared mode: what a plain create gives under this umask"
        );
    }

    /// A set-id mode survives the owner being set: the owner goes first. The owner and
    /// group are given as ids, as a snapshot records them.
    #[test]
    fn the_owner_is_set_before_a_set_id_mode() {
        let dir = crate::test_scratch::tempdir();
        let path = dir.path().join("tool");
        let own = std::fs::metadata(dir.path()).unwrap();
        let (uid, gid) = (own.uid().to_string(), own.gid().to_string());
        let attrs = Resolved::of(FileAttrs {
            mode: Some("2750"),
            owner: Some(&uid),
            group: Some(&gid),
            ..FileAttrs::NONE
        })
        .unwrap();
        assert_eq!((attrs.uid, attrs.gid), (Some(own.uid()), Some(own.gid())));
        let staged = stage(&path, &bytes(b"#!/bin/sh\n"), attrs).unwrap();
        assert_eq!(mode_of(staged.path()), 0o2750);
    }

    /// A symbolic link or a world-writable file waiting at the fixed sibling name a
    /// predictable stage would use is neither followed nor reused, and a link at the
    /// destination is replaced, its target untouched.
    #[tokio::test]
    async fn planted_names_are_neither_followed_nor_reused() {
        let dir = crate::test_scratch::tempdir();
        let at = |name: &str| dir.path().join(name);
        std::fs::write(at("victim"), "ORIGINAL").unwrap();
        std::fs::set_permissions(at("victim"), std::fs::Permissions::from_mode(0o600)).unwrap();

        symlink(at("victim"), at("a.conf.zap-tmp")).unwrap();
        std::fs::write(at("b.conf.zap-tmp"), "").unwrap();
        std::fs::set_permissions(at("b.conf.zap-tmp"), std::fs::Permissions::from_mode(0o666))
            .unwrap();
        symlink(at("victim"), at("c.conf")).unwrap();

        for name in ["a.conf", "b.conf", "c.conf"] {
            let path = at(name);
            put(
                &path.to_string_lossy(),
                bytes(b"NEW"),
                FileAttrs::mode("600"),
            )
            .await
            .unwrap();
            let installed = std::fs::symlink_metadata(&path).unwrap();
            assert!(installed.is_file(), "{name}: a regular file, not a link");
            assert_eq!(installed.mode() & 0o7777, 0o600, "{name}");
            assert_eq!(std::fs::read(&path).unwrap(), b"NEW", "{name}");
        }
        assert_eq!(std::fs::read(at("victim")).unwrap(), b"ORIGINAL");
        assert_eq!(mode_of(&at("victim")), 0o600);
        assert!(
            std::fs::symlink_metadata(at("a.conf.zap-tmp"))
                .unwrap()
                .is_symlink()
        );
        assert_eq!(std::fs::read(at("b.conf.zap-tmp")).unwrap(), b"");
        assert_eq!(
            entries(dir.path()),
            [
                "a.conf",
                "a.conf.zap-tmp",
                "b.conf",
                "b.conf.zap-tmp",
                "c.conf",
                "victim"
            ],
            "no stage is left behind"
        );
    }

    /// A directory at the destination is refused — the file is not dropped inside it —
    /// and a file is streamed from disk byte for byte.
    #[tokio::test]
    async fn a_directory_at_the_destination_is_refused_and_a_file_source_is_streamed() {
        let dir = crate::test_scratch::tempdir();
        let taken = dir.path().join("taken");
        std::fs::create_dir(&taken).unwrap();
        let error = put(&taken.to_string_lossy(), bytes(b"x"), FileAttrs::NONE)
            .await
            .unwrap_err();
        assert_ne!(error.kind(), std::io::ErrorKind::PermissionDenied);
        assert!(entries(&taken).is_empty());
        assert_eq!(entries(dir.path()), ["taken"]);

        let source = dir.path().join("source.bin");
        std::fs::write(&source, b"\x7fELF\0\0binary").unwrap();
        let dest = dir.path().join("dest.bin");
        put(
            &dest.to_string_lossy(),
            LocalSource::File(source),
            FileAttrs::mode("755"),
        )
        .await
        .unwrap();
        assert_eq!(std::fs::read(&dest).unwrap(), b"\x7fELF\0\0binary");
        assert_eq!(mode_of(&dest), 0o755);
    }

    /// A path that isn't absolute is refused, as the put scripts refuse it, never
    /// resolved against the working directory — and the refusal doesn't escalate.
    #[tokio::test]
    async fn a_relative_path_is_refused_natively() {
        let name = format!("zap-relative-put-{}", std::process::id());
        let error = put(&name, bytes(b"x"), FileAttrs::NONE).await.unwrap_err();
        let made = std::path::Path::new(&name).exists();
        if made {
            std::fs::remove_file(&name).unwrap();
        }
        assert!(!made, "a relative put wrote into the working directory");
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
        assert_eq!(error.to_string(), NOT_ABSOLUTE_REFUSAL);
        assert!(!escalates(&error));

        // `src` is a directory in the working directory a test runs in.
        assert!(std::path::Path::new("src").is_dir());
        let error = set_dir_attrs("src", FileAttrs::NONE).await.unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
        assert_eq!(error.to_string(), NOT_ABSOLUTE_REFUSAL);
        assert!(!escalates(&error));
    }

    /// What the operator may not do is `PermissionDenied` — the caller's cue to escalate
    /// — and a name that resolves to nothing is an error of its own, never a guess.
    #[tokio::test]
    async fn a_refused_operation_is_permission_denied_and_an_unknown_name_is_not() {
        let dir = crate::test_scratch::tempdir();
        let path = dir.path().join("f");
        let unknown = FileAttrs {
            mode: None,
            owner: Some("zap-no-such-user"),
            group: None,
            ..FileAttrs::NONE
        };
        let error = put(&path.to_string_lossy(), bytes(b"x"), unknown)
            .await
            .unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
        let error = put(&path.to_string_lossy(), bytes(b"x"), FileAttrs::mode("9"))
            .await
            .unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);

        // Root may do all of this, so only an unprivileged run can see the refusals.
        if nix::unistd::geteuid().is_root() {
            return;
        }
        let root_owned = FileAttrs {
            mode: None,
            owner: Some("root"),
            group: None,
            ..FileAttrs::NONE
        };
        let error = put(&path.to_string_lossy(), bytes(b"x"), root_owned)
            .await
            .unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
        assert!(entries(dir.path()).is_empty(), "the stage is removed");

        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o555)).unwrap();
        let error = put(&path.to_string_lossy(), bytes(b"x"), FileAttrs::NONE)
            .await
            .unwrap_err();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
    }

    /// Only "not permitted" sends an operation to `sudo`. What a script or the kernel
    /// refuses for any other reason is the answer.
    #[test]
    fn only_a_denied_operation_escalates() {
        use nix::errno::Errno;

        let os = |errno: Errno| std::io::Error::from_raw_os_error(errno as i32);
        for denied in [Errno::EACCES, Errno::EPERM] {
            assert!(escalates(&os(denied)), "{denied}");
        }
        for final_answer in [
            Errno::ENOENT,
            Errno::EISDIR,
            Errno::ENOTDIR,
            Errno::ELOOP,
            Errno::EROFS,
            Errno::ENOSPC,
            Errno::EEXIST,
            Errno::ENAMETOOLONG,
            Errno::EIO,
            Errno::EXDEV,
        ] {
            assert!(!escalates(&os(final_answer)), "{final_answer}");
        }
        for kind in [
            std::io::ErrorKind::InvalidInput,
            std::io::ErrorKind::Other,
            std::io::ErrorKind::WriteZero,
        ] {
            assert!(!escalates(&std::io::Error::new(kind, "x")), "{kind:?}");
        }

        // What a caller acts on: done, `sudo` next, or the failure as the result.
        assert!(matches!(Native::of(Ok(())), Native::Done));
        assert!(matches!(Native::of(Err(os(Errno::EPERM))), Native::Denied));
        assert!(matches!(Native::of(Err(os(Errno::EACCES))), Native::Denied));
        for final_answer in [Errno::ENOTDIR, Errno::EISDIR, Errno::ENOENT, Errno::EROFS] {
            assert!(
                matches!(
                    Native::of(Err(os(final_answer))),
                    Native::Failed(error) if error.raw_os_error() == Some(final_answer as i32)
                ),
                "{final_answer}"
            );
        }
    }

    /// A change through `/proc/self/fd/<n>` that finds no such name says `/proc` is
    /// what's missing — the directory is open, so it isn't the directory. Any other
    /// failure passes as it came, so "not permitted" still escalates.
    #[test]
    fn a_missing_proc_is_said_as_that() {
        use nix::errno::Errno;

        let os = |errno: Errno| std::io::Error::from_raw_os_error(errno as i32);
        let mapped = needs_proc(os(Errno::ENOENT));
        assert_eq!(mapped.kind(), std::io::ErrorKind::NotFound);
        assert_eq!(mapped.to_string(), zap_types::put::NO_PROC_REFUSAL);
        assert!(!escalates(&mapped));
        for other in [Errno::EPERM, Errno::EACCES, Errno::EROFS] {
            let passed = needs_proc(os(other));
            assert_eq!(passed.raw_os_error(), Some(other as i32), "{other}");
        }
        assert!(escalates(&needs_proc(os(Errno::EPERM))));
    }

    /// A source's bytes never reach its debug form.
    #[test]
    fn a_source_debugs_as_its_length() {
        let shown = format!("{:?}", bytes(b"TOKEN=hunter2"));
        assert_eq!(shown, "Bytes(13 bytes)");
        let shown = format!("{:?}", LocalSource::File("/srv/a".into()));
        assert_eq!(shown, "File(\"/srv/a\")");
    }

    /// A directory's mode and group are set on the directory itself — one the operator
    /// owns but can't read included — and a link to a directory, with or without a
    /// trailing slash or a `/.`, a file, and nothing at all are each an error that
    /// doesn't escalate, with what the link names untouched.
    #[tokio::test]
    async fn dir_attrs_change_the_directory_and_follow_no_link() {
        let dir = crate::test_scratch::tempdir();
        // born under the process umask (0777 at umask 000); pinned, so the refused
        // `victim/..` attempt at 777 would be a visible change
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let at = |name: &str| dir.path().join(name).to_string_lossy().into_owned();
        let own = std::fs::metadata(dir.path()).unwrap();
        let gid = own.gid().to_string();
        let attrs = FileAttrs {
            mode: Some("2750"),
            owner: None,
            group: Some(&gid),
            ..FileAttrs::NONE
        };

        std::fs::create_dir(at("d")).unwrap();
        set_dir_attrs(&at("d"), attrs).await.unwrap();
        assert_eq!(mode_of(at("d").as_ref()), 0o2750);
        set_dir_attrs(&format!("{}//", at("d")), FileAttrs::mode("700"))
            .await
            .unwrap();
        assert_eq!(mode_of(at("d").as_ref()) & 0o777, 0o700);

        // Write and search only: no read permission is needed to hold it.
        std::fs::set_permissions(at("d"), std::fs::Permissions::from_mode(0o300)).unwrap();
        set_dir_attrs(&at("d"), FileAttrs::mode("755"))
            .await
            .unwrap();
        assert_eq!(mode_of(at("d").as_ref()) & 0o777, 0o755);

        std::fs::create_dir(at("victim")).unwrap();
        std::fs::set_permissions(at("victim"), std::fs::Permissions::from_mode(0o700)).unwrap();
        symlink(at("victim"), at("link")).unwrap();
        std::fs::write(at("file"), "").unwrap();
        for refused in [
            at("link"),
            format!("{}/", at("link")),
            format!("{}/.", at("link")),
            format!("{}/..", at("victim")),
            at("file"),
            at("absent"),
        ] {
            let error = set_dir_attrs(&refused, FileAttrs::mode("777"))
                .await
                .unwrap_err();
            assert!(!escalates(&error), "{refused}: {error}");
        }
        let error = set_dir_attrs(&at("link"), FileAttrs::mode("777"))
            .await
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("a symbolic link is not followed")
        );
        assert_eq!(mode_of(at("victim").as_ref()), 0o700);
        assert_eq!(mode_of(dir.path()), own.mode() & 0o7777);

        // Root may give a directory away, so only an unprivileged run sees the denial.
        if !nix::unistd::geteuid().is_root() {
            let root = FileAttrs {
                mode: None,
                owner: Some("root"),
                group: None,
                ..FileAttrs::NONE
            };
            let error = set_dir_attrs(&at("d"), root).await.unwrap_err();
            assert!(escalates(&error), "{error}");
        }
    }

    /// What a kept install fills: only what is left out — from a regular file its ids
    /// and its mode less any set-id or sticky bit, from an empty name the directory's ids
    /// alone, from anything else nothing.
    #[test]
    fn a_kept_install_fills_only_what_is_left_out() {
        let declared = |mode, uid, gid| Resolved {
            mode,
            uid,
            gid,
            keep: true,
        };
        let file = Found::File {
            mode: 0o4750,
            uid: 7,
            gid: 8,
        };
        let nothing = Found::Nothing { uid: 3, gid: 4 };
        let cases = [
            (
                declared(None, None, None),
                file,
                (Some(0o750), Some(7), Some(8)),
            ),
            (
                declared(Some(0o600), None, Some(1)),
                file,
                (Some(0o600), Some(7), Some(1)),
            ),
            (
                declared(None, Some(1), None),
                Found::File {
                    mode: 0o1644,
                    uid: 7,
                    gid: 8,
                },
                (Some(0o644), Some(1), Some(8)),
            ),
            (
                declared(None, None, None),
                nothing,
                (None, Some(3), Some(4)),
            ),
            (
                declared(Some(0o640), Some(1), None),
                nothing,
                (Some(0o640), Some(1), Some(4)),
            ),
            (declared(None, None, None), Found::Other, (None, None, None)),
            (
                declared(Some(0o600), Some(1), Some(2)),
                file,
                (Some(0o600), Some(1), Some(2)),
            ),
        ];
        for (attrs, found, (mode, uid, gid)) in cases {
            let filled = attrs.filled(found);
            assert_eq!(
                (filled.mode, filled.uid, filled.gid),
                (mode, uid, gid),
                "{attrs:?} {found:?}"
            );
            assert!(filled.keep);
        }
        assert!(!Resolved::of(FileAttrs::NONE).unwrap().keep);
        assert!(Resolved::of(FileAttrs::NONE.keeping()).unwrap().keep);
    }

    /// Natively, a kept install keeps a file's group and mode (less a set-id bit), gives
    /// a new file its directory's group, and replaces a link at the path, or a file with
    /// a second name, with a fresh file, what the other name names untouched; anywhere
    /// below a directory anyone may put an entry in, it keeps nothing. A fresh install
    /// of the same file gives a plain create's mode and the operator's group.
    #[tokio::test]
    async fn a_kept_install_keeps_what_the_path_has() {
        let primary = nix::unistd::getegid().as_raw();
        let gid = nix::unistd::getgroups()
            .unwrap_or_default()
            .into_iter()
            .map(nix::unistd::Gid::as_raw)
            .find(|gid| *gid != primary)
            .unwrap_or(primary);
        let me = nix::unistd::geteuid().as_raw();
        let dir = crate::test_scratch::tempdir();
        let at = |name: &str| dir.path().join(name);
        let of = |path: &std::path::Path| {
            let meta = std::fs::symlink_metadata(path).unwrap();
            (meta.mode() & 0o7777, meta.uid(), meta.gid())
        };
        let existing = |name: &str, mode: u32| {
            std::fs::write(at(name), "OLD").unwrap();
            std::os::unix::fs::chown(at(name), None, Some(gid)).unwrap();
            std::fs::set_permissions(at(name), std::fs::Permissions::from_mode(mode)).unwrap();
        };
        let install = |name: &str, attrs: FileAttrs<'static>| {
            let path = at(name).to_string_lossy().into_owned();
            async move { put(&path, bytes(b"NEW"), attrs).await }
        };
        std::fs::write(at("plain"), "").unwrap();
        let plain = mode_of(&at("plain"));

        existing("kept", 0o2750);
        install("kept", FileAttrs::NONE.keeping()).await.unwrap();
        assert_eq!(of(&at("kept")), (0o750, me, gid));
        assert_eq!(std::fs::read(at("kept")).unwrap(), b"NEW");
        install("kept", FileAttrs::mode("600").keeping())
            .await
            .unwrap();
        assert_eq!(of(&at("kept")), (0o600, me, gid));

        existing("fresh", 0o640);
        install("fresh", FileAttrs::NONE).await.unwrap();
        assert_eq!(of(&at("fresh")), (plain, me, primary));

        std::fs::create_dir(at("theirs")).unwrap();
        std::os::unix::fs::chown(at("theirs"), None, Some(gid)).unwrap();
        install("theirs/new", FileAttrs::NONE.keeping())
            .await
            .unwrap();
        assert_eq!(of(&at("theirs/new")), (plain, me, gid));

        existing("victim", 0o600);
        symlink(at("victim"), at("linked")).unwrap();
        install("linked", FileAttrs::NONE.keeping()).await.unwrap();
        assert_eq!(of(&at("linked")), (plain, me, primary));
        assert_eq!(of(&at("victim")), (0o600, me, gid));
        assert_eq!(std::fs::read(at("victim")).unwrap(), b"OLD");

        // A file with a second name keeps nothing, the other name's untouched.
        existing("first", 0o640);
        std::fs::hard_link(at("first"), at("second")).unwrap();
        install("second", FileAttrs::NONE.keeping()).await.unwrap();
        assert_eq!(of(&at("second")), (plain, me, primary));
        assert_eq!(of(&at("first")), (0o640, me, gid));

        // A directory anyone may put an entry in gives nothing, file or new name.
        for (shared, mode) in [("sticky", 0o1777), ("open", 0o777)] {
            std::fs::create_dir(at(shared)).unwrap();
            std::os::unix::fs::chown(at(shared), None, Some(gid)).unwrap();
            std::fs::set_permissions(at(shared), std::fs::Permissions::from_mode(mode)).unwrap();
            existing(&format!("{shared}/planted"), 0o640);
            // So does a directory of another's inside it, open to no one itself.
            let cache = format!("{shared}/cache");
            std::fs::create_dir(at(&cache)).unwrap();
            std::os::unix::fs::chown(at(&cache), None, Some(gid)).unwrap();
            std::fs::set_permissions(at(&cache), std::fs::Permissions::from_mode(0o755)).unwrap();
            existing(&format!("{cache}/planted"), 0o640);
            for name in ["planted", "new", "cache/planted", "cache/new"] {
                let name = format!("{shared}/{name}");
                install(&name, FileAttrs::NONE.keeping()).await.unwrap();
                assert_eq!(of(&at(&name)), (plain, me, primary), "{name}");
            }
        }
    }

    /// Natively, a link planted in a shared directory passes on nothing: through
    /// `cache`, a link in a directory with its sticky bit set or one anyone may write
    /// to a directory open to no one, a kept install keeps neither the mode nor the
    /// group of the file there, and the directories made are the operator's own. The
    /// same link in a directory of the operator's own passes both on.
    #[tokio::test]
    async fn a_link_planted_in_a_shared_directory_passes_on_nothing() {
        let primary = nix::unistd::getegid().as_raw();
        let gid = nix::unistd::getgroups()
            .unwrap_or_default()
            .into_iter()
            .map(nix::unistd::Gid::as_raw)
            .find(|gid| *gid != primary)
            .unwrap_or(primary);
        let me = nix::unistd::geteuid().as_raw();
        let dir = crate::test_scratch::tempdir();
        let of = |path: &std::path::Path| {
            let meta = std::fs::symlink_metadata(path).unwrap();
            (meta.mode() & 0o7777, meta.uid(), meta.gid())
        };
        let probe = dir.path().join("probe");
        std::fs::write(&probe, "").unwrap();
        let plain = mode_of(&probe);
        let theirs = dir.path().join("theirs");
        std::fs::create_dir(&theirs).unwrap();
        std::os::unix::fs::chown(&theirs, None, Some(gid)).unwrap();
        std::fs::set_permissions(&theirs, std::fs::Permissions::from_mode(0o755)).unwrap();
        for (holder, mode, passes) in [
            ("sticky", 0o1777, false),
            ("open", 0o777, false),
            ("own", 0o755, true),
        ] {
            let at = dir.path().join(holder);
            std::fs::create_dir(&at).unwrap();
            std::fs::set_permissions(&at, std::fs::Permissions::from_mode(mode)).unwrap();
            symlink(&theirs, at.join("cache")).unwrap();
            let planted = theirs.join("planted");
            std::fs::write(&planted, "OLD").unwrap();
            std::os::unix::fs::chown(&planted, None, Some(gid)).unwrap();
            std::fs::set_permissions(&planted, std::fs::Permissions::from_mode(0o640)).unwrap();

            let through = at.join("cache/planted").to_string_lossy().into_owned();
            put(&through, bytes(b"NEW"), FileAttrs::NONE.keeping())
                .await
                .unwrap();
            assert_eq!(std::fs::read(&planted).unwrap(), b"NEW", "{holder}");
            let kept = if passes {
                (0o640, me, gid)
            } else {
                (plain, me, primary)
            };
            assert_eq!(of(&planted), kept, "{holder}");

            let made = at.join("cache").join(holder).join("b");
            make_dirs(&made.to_string_lossy()).await.unwrap();
            let group = if passes { gid } else { primary };
            for made in [theirs.join(holder), theirs.join(holder).join("b")] {
                let meta = std::fs::metadata(&made).unwrap();
                assert_eq!((meta.uid(), meta.gid()), (me, group), "{holder}: {made:?}");
            }
        }
    }

    /// A mode to keep from a file with an extended POSIX access list is refused — not a
    /// denial, so `sudo` isn't asked — with the file as it was and nothing staged; a
    /// declared mode installs, the new file with no list, and a file without one keeps
    /// its mode.
    #[tokio::test]
    async fn a_kept_mode_from_a_file_with_an_access_list_is_refused() {
        let dir = crate::test_scratch::tempdir();
        let at = |name: &str| dir.path().join(name);
        std::fs::write(at("listed"), "OLD").unwrap();
        std::fs::set_permissions(at("listed"), std::fs::Permissions::from_mode(0o640)).unwrap();
        assert!(!super::has_access_list(&at("listed")).unwrap());
        // No `setfacl` checks nothing here, and `tests/required_programs.rs` fails
        // unless that is allowed; one that fails is a failure.
        match std::process::Command::new("setfacl")
            .args(["-m", "u:nobody:rw", "--"])
            .arg(at("listed"))
            .output()
        {
            Ok(output) => assert!(output.status.success(), "setfacl: {output:?}"),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                eprintln!("a kept mode under an access list not checked: no setfacl");
                return;
            }
            Err(error) => panic!("setfacl: {error}"),
        }
        assert!(super::has_access_list(&at("listed")).unwrap());
        let path = at("listed").to_string_lossy().into_owned();
        let error = put(&path, bytes(b"NEW"), FileAttrs::NONE.keeping())
            .await
            .unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput, "{error}");
        assert!(!escalates(&error));
        assert!(
            error.to_string().contains("has an access list (ACL)"),
            "{error}"
        );
        assert_eq!(std::fs::read(at("listed")).unwrap(), b"OLD");
        assert_eq!(entries(dir.path()), ["listed"], "nothing staged");

        put(&path, bytes(b"NEW"), FileAttrs::mode("640").keeping())
            .await
            .unwrap();
        assert_eq!(std::fs::read(at("listed")).unwrap(), b"NEW");
        assert_eq!(mode_of(&at("listed")), 0o640);
        assert!(!super::has_access_list(&at("listed")).unwrap());
        put(&path, bytes(b"AGAIN"), FileAttrs::NONE.keeping())
            .await
            .unwrap();
        assert_eq!(mode_of(&at("listed")), 0o640, "no list: the mode is kept");
    }

    /// An owner the operator may not give is refused before the content is copied: a
    /// source that isn't there is never opened.
    #[test]
    fn an_owner_not_the_operators_to_give_costs_no_copy() {
        if nix::unistd::geteuid().is_root() {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let attrs = Resolved {
            mode: None,
            uid: Some(0),
            gid: None,
            keep: false,
        };
        let error = stage(
            &dir.path().join("f"),
            &LocalSource::File(dir.path().join("no-such-source")),
            attrs,
        )
        .unwrap_err();
        assert_eq!(
            error.kind(),
            std::io::ErrorKind::PermissionDenied,
            "{error}"
        );
        assert!(entries(dir.path()).is_empty(), "the stage is removed");
    }

    /// In a directory anyone may put an entry in — `/tmp`, whose owner is root — a kept
    /// install keeps nothing: a new name there is the operator's own, not root's, so an
    /// operator without `sudo` still writes there natively. A directory root owns that
    /// isn't open to all would give root's owner, which only the privileged put may
    /// give; that is the declared root owner's `PermissionDenied`
    /// (`a_refused_operation_is_permission_denied_and_an_unknown_name_is_not`).
    #[tokio::test]
    async fn a_kept_install_in_tmp_is_the_operators_own() {
        let tmp = std::path::Path::new("/tmp");
        let usable = std::fs::metadata(tmp).is_ok_and(|meta| super::open_to_anyone(meta.mode()))
            && nix::unistd::access(tmp, nix::unistd::AccessFlags::W_OK).is_ok();
        if !usable {
            eprintln!("a kept install in /tmp not checked: no shared /tmp to write");
            return;
        }
        let name = format!("/tmp/zap-kept-owner-{}", std::process::id());
        let path = std::path::Path::new(&name);
        put(&name, bytes(b"x"), FileAttrs::NONE.keeping())
            .await
            .unwrap();
        let meta = std::fs::metadata(path).unwrap();
        assert_eq!(
            (meta.uid(), meta.gid()),
            (
                nix::unistd::geteuid().as_raw(),
                nix::unistd::getegid().as_raw()
            )
        );
        std::fs::remove_file(path).unwrap();
    }

    /// The directories made natively take the nearest existing one's group; what isn't a
    /// directory, a link at the name, and a missing `..` are answers, not denials; and
    /// an owner the operator can't give — a directory root owns that the operator may
    /// write (`/tmp`, where it is one) — is denied before anything is made.
    #[tokio::test]
    async fn the_directories_made_natively_take_their_ancestors_ids() {
        let primary = nix::unistd::getegid().as_raw();
        let gid = nix::unistd::getgroups()
            .unwrap_or_default()
            .into_iter()
            .map(nix::unistd::Gid::as_raw)
            .find(|gid| *gid != primary)
            .unwrap_or(primary);
        let me = nix::unistd::geteuid().as_raw();
        let dir = crate::test_scratch::tempdir();
        let at = |name: &str| dir.path().join(name);
        let text = |name: &str| at(name).to_string_lossy().into_owned();
        std::fs::create_dir(at("base")).unwrap();
        std::os::unix::fs::chown(at("base"), None, Some(gid)).unwrap();
        make_dirs(&text("base/a/b/")).await.unwrap();
        for made in ["base/a", "base/a/b"] {
            let meta = std::fs::metadata(at(made)).unwrap();
            assert_eq!((meta.uid(), meta.gid()), (me, gid), "{made}");
        }
        make_dirs(&text("base")).await.unwrap();

        std::fs::write(at("file"), "").unwrap();
        symlink(at("nowhere"), at("dangling")).unwrap();
        for refused in ["file", "file/x", "dangling", "gone/../x", "gone//x"] {
            let error = make_dirs(&text(refused)).await.unwrap_err();
            assert!(!escalates(&error), "{refused}: {error}");
        }
        assert!(!escalates(&make_dirs("relative/x").await.unwrap_err()));
        assert!(!at("nowhere").exists() && !at("gone").exists());

        // Anywhere below a directory anyone may write — inside a directory of another's
        // there too — what is made is the operator's own.
        for (shared, mode) in [("sticky", 0o1777), ("open", 0o777)] {
            std::fs::create_dir(at(shared)).unwrap();
            std::os::unix::fs::chown(at(shared), None, Some(gid)).unwrap();
            std::fs::set_permissions(at(shared), std::fs::Permissions::from_mode(mode)).unwrap();
            let cache = at(shared).join("cache");
            std::fs::create_dir(&cache).unwrap();
            std::os::unix::fs::chown(&cache, None, Some(gid)).unwrap();
            std::fs::set_permissions(&cache, std::fs::Permissions::from_mode(0o755)).unwrap();
            make_dirs(&text(&format!("{shared}/a/b"))).await.unwrap();
            make_dirs(&text(&format!("{shared}/cache/a/b")))
                .await
                .unwrap();
            for made in ["a", "a/b", "cache/a", "cache/a/b"] {
                let meta = std::fs::metadata(at(shared).join(made)).unwrap();
                assert_eq!((meta.uid(), meta.gid()), (me, primary), "{shared}/{made}");
            }
        }

        assert!(may_give(me, primary) && may_give(me, gid));
        if nix::unistd::geteuid().is_root() {
            return;
        }
        assert!(!may_give(0, primary));
        // `/tmp` is root's, but anyone's to write: nothing is denied, the operator's own.
        let tmp = std::path::Path::new("/tmp");
        let usable = std::fs::metadata(tmp).is_ok_and(|meta| super::open_to_anyone(meta.mode()))
            && nix::unistd::access(tmp, nix::unistd::AccessFlags::W_OK).is_ok();
        if usable {
            let top = format!("/tmp/zap-made-{}", std::process::id());
            make_dirs(&format!("{top}/sub")).await.unwrap();
            let meta = std::fs::metadata(&top).unwrap();
            assert_eq!((meta.uid(), meta.gid()), (me, primary));
            std::fs::remove_dir(format!("{top}/sub")).unwrap();
            std::fs::remove_dir(&top).unwrap();
        }
    }

    /// The by-handle walk, with something moved underneath it: a link where a
    /// component is to be made sends nothing through it, and a directory of another's
    /// renamed over the one just made — what an owner of the directory it was made in
    /// can do before the open — is refused, given no owner, and gets nothing made in it.
    #[test]
    fn a_component_moved_underneath_the_walk_redirects_nothing() {
        let dir = crate::test_scratch::tempdir();
        let at = |name: &str| dir.path().join(name);
        let open = |name: &str| {
            nix::fcntl::open(
                &at(name),
                nix::fcntl::OFlag::O_PATH | nix::fcntl::OFlag::O_DIRECTORY,
                nix::sys::stat::Mode::empty(),
            )
            .unwrap()
        };
        std::fs::create_dir(at("elsewhere")).unwrap();
        std::fs::set_permissions(at("elsewhere"), std::fs::Permissions::from_mode(0o700)).unwrap();

        std::fs::create_dir(at("linked")).unwrap();
        symlink(at("elsewhere"), at("linked/a")).unwrap();
        let error = make_below(open("linked"), &["a", "b"], false, &|_| {}).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("a is not a directory of its own"),
            "{error}"
        );
        assert!(!escalates(&error));
        assert!(
            entries(&at("elsewhere")).is_empty(),
            "nothing through the link"
        );

        std::fs::create_dir(at("renamed")).unwrap();
        std::fs::write(at("elsewhere/theirs"), "x").unwrap();
        let victim = at("elsewhere");
        let made = at("renamed/a");
        let error = make_below(open("renamed"), &["a", "b"], false, &|name| {
            if name == "a" {
                std::fs::rename(&victim, &made).unwrap();
            }
        })
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("a is not the empty directory just made"),
            "{error}"
        );
        assert!(!escalates(&error));
        assert_eq!(entries(&at("renamed/a")), ["theirs"], "nothing made in it");
        assert_eq!(mode_of(&at("renamed/a")), 0o700);

        // One that can't be listed is given nothing either, and the error says why.
        std::fs::create_dir(at("unlistable")).unwrap();
        let made = at("unlistable/a");
        let error = make_below(open("unlistable"), &["a", "b"], false, &|_| {
            std::fs::set_permissions(&made, std::fs::Permissions::from_mode(0o300)).unwrap();
        })
        .unwrap_err();
        std::fs::set_permissions(&made, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(
            error
                .to_string()
                .contains("a could not be listed, so it is given no owner"),
            "{error}"
        );
        // Denied, so a local run retries it under `sudo`, as any denied listing.
        assert!(escalates(&error));
        assert!(entries(&made).is_empty(), "nothing made in it");

        // Unmoved, the same walk makes both.
        std::fs::create_dir(at("plain")).unwrap();
        make_below(open("plain"), &["a", "b"], false, &|_| {}).unwrap();
        assert!(at("plain/a/b").is_dir());
    }
}
