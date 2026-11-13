//! `user` — existence, then each managed attribute: shell, home mode, SSH keys, the
//! `/etc/shadow` password field, supplementary groups, sudoers.
//!
//! Each read runs at the least privilege that answers it:
//!
//! - as the connecting user ([`Query::login_command`]): `id -u`, the `/etc/passwd`
//!   shell and home, what is at `/home/<name>` and its owner ([`home_entry_snippet`]),
//!   the home directory's `stat -c '%a'`, and `id -nG`;
//! - as root ([`Query::root_command`]): the `/etc/shadow` password field and the
//!   sudoers file's `test -f`;
//! - [`Elevated`](Privilege::Elevated) (zap's reads of the files it manages): the
//!   sudoers contents, a bounded [`Read`](PathFacet::Read);
//! - as the managed user, through the root lane: its `authorized_keys`
//!   ([`authorized_keys_snippet`]), a file the user owns and the step writes as the
//!   user, so a link the user plants there is never read through as root.
//!
//! **The home is `/home/<name>`.** `home_mode` and `ssh_keys` act on paths under it,
//! derived from the name at plan time, so a user that declares either has its
//! `/etc/passwd` home read too: an existing account whose home is anything else (or
//! that has none there) is held, naming the home it has, before any attribute is
//! compared. The planner's `useradd -m -d /home/<name>` creates an account with that
//! home, whatever the distro default.
//!
//! **The home directory is the user's or root's.** For the same users, what is at
//! `/home/<name>` is read without following a link ([`home_entry_snippet`]), whether
//! the account exists or not, since `useradd` leaves a directory already there as it
//! was (root's, typically) and skips the skeleton files. Nothing there, a directory the
//! user owns, or a directory root owns reads on (its group is left alone). For an
//! account that exists, a root-owned home is left as it is (an sshd `ChrootDirectory`
//! home must stay root's); for one that doesn't, the verdict stays `Absent` and the
//! planner's creation gives the directory to the user and its primary group. A
//! directory any other uid owns (a live account's, or an orphaned uid's), a symbolic
//! link, or anything but a directory holds the user, naming what is there: zap acts on
//! no home it can't confirm is a directory, and through no link it didn't make.
//!
//! A `copy_from` user's desired `authorized_keys` is another user's file, found through
//! that user's `/etc/passwd` home — a read that depends on another read's answer, so the
//! two compose in the target shell, in one command of the root lane
//! ([`copy_source_snippet`]). The file itself is read **as the source account**
//! ([`copy_source_keys`], the read the step that copies it makes), so the desired
//! content is one apply can produce: read as root, a source that links its key file to
//! one only root may read would give detection keys the step can never install. The
//! root lane, because becoming the source account takes `sudo`, and a `copy_from` user
//! always has `ssh_keys`, whose shadow read runs there anyway. The `/etc/passwd` lookup
//! rides along — the file is world-readable, so root reads what the login user would.
//!
//! **SSH keys are content-compared**: the desired `authorized_keys` (the explicit keys,
//! or the `copy_from` source's file) against the target's, surrounding whitespace
//! trimmed — so a rotated, added, or removed key drifts. For an `ssh_keys` user the
//! `/etc/shadow` password field is managed authoritatively: it must be the disabled
//! sentinel `*` (no password, *not* locked), and ANY other value drifts — a `!`-lock
//! (`useradd` leaves a passwordless account locked, which Alpine's sshd refuses pubkey
//! login to), an empty field (passwordless login — a security hole), or a real password
//! hash.
//!
//! An attribute is read only when the config manages it, and a managed attribute whose
//! probe exits nonzero (a `stat` of a missing home, say) holds the user, naming what
//! couldn't be read: an attribute nobody read is neither converged nor drifted. The
//! content reads are the exception — there a file that can't be read is itself the
//! drift ([`SshKeysDrift`], [`SudoDrift`]). A probe with no answer at all (timed out,
//! its batch failed) holds the user too.

use super::batch::{NOT_REGULAR_EXIT, contents};
use super::{
    CommandObservation, PathFacet, PathObservation, Privilege, Query, QueryResult, command_answer,
    drifted_or_converged, layout_mismatch, path_answer, unexpected_answer,
};
use crate::detected::{
    CurrentState, Detection, ShadowPasswordDrift, SshKeysDrift, SudoDrift, UserDrift,
};
use crate::schema::{
    PasswdField, SshKeys, UserResource, authorized_keys_path, build_sudoers_content,
    copy_source_home, copy_source_keys, normalize_mode, passwd_field, render_authorized_keys,
    shadow_password_field, sudoers_path, user_home_dir,
};
use crate::shell::single_quote;

/// The most bytes of an `authorized_keys` file detection reads: 1 MiB.
///
/// Over a thousand 4096-bit RSA keys. It bounds the target's file and a `copy_from`
/// source's alike: a target file past it drifts, and a source past it reads as
/// unreadable.
pub const AUTHORIZED_KEYS_READ_MAX: u32 = 1024 * 1024;

/// The most bytes of a user's sudoers drop-in detection reads. zap writes one line; a
/// file past this bound drifts.
pub const SUDOERS_READ_MAX: u32 = 64 * 1024;

/// Index of the existence probe in [`queries`] — always first.
const ID: usize = 0;

/// The shell snippet that prints a `copy_from` source user's `authorized_keys`.
///
/// It reads the user's home from `/etc/passwd` ([`copy_source_home`], the read the step
/// that copies the file runs first), then, as the source account ([`copy_source_keys`], the
/// step's own read), at most [`AUTHORIZED_KEYS_READ_MAX`] + 1 bytes of
/// `<home>/.ssh/authorized_keys`.
///
/// It exits 0 with the bytes, 3 when the user has no `/etc/passwd` entry (or an empty
/// home), and with `head`'s or `sudo`'s own failure status when the source account
/// can't read the file or `sudo` can't become the account. The verdict reads any
/// failure the same way: the source is unreadable.
#[must_use]
pub fn copy_source_snippet(source: &str) -> String {
    format!(
        "{} || exit 3; exec {}",
        copy_source_home(source),
        copy_source_keys(
            source,
            &format!("head -c {}", u64::from(AUTHORIZED_KEYS_READ_MAX) + 1)
        ),
    )
}

/// The shell snippet that prints a managed user's own `authorized_keys`, read **as that
/// user** (`sudo -u`).
///
/// At most [`AUTHORIZED_KEYS_READ_MAX`] + 1 bytes of it, as the account that owns the
/// file and that the step installing it writes as.
///
/// The user can put anything at the name, so nothing is opened when it is a symbolic
/// link or anything but a regular file: the snippet exits [`NOT_REGULAR_EXIT`] before
/// the read (the tests are root's, and open nothing). Absent or unreadable, `head` (or
/// `sudo`) fails. The verdict reads every failure the same way: the file is missing,
/// which the step's write replaces.
#[must_use]
pub fn authorized_keys_snippet(username: &str) -> String {
    let path = single_quote(&authorized_keys_path(username));
    format!(
        "[ ! -L {path} ] || exit {NOT_REGULAR_EXIT}; \
         [ ! -e {path} ] || [ -f {path} ] || exit {NOT_REGULAR_EXIT}; \
         exec sudo -u {} head -c {} -- {path}",
        single_quote(username),
        u64::from(AUTHORIZED_KEYS_READ_MAX) + 1,
    )
}

/// The exit status of [`home_entry_snippet`] when `/home` is missing or not a directory
/// the connecting user can search, so nothing under it can be seen.
pub const HOME_UNSEARCHABLE_EXIT: i32 = 94;

/// The shell snippet that prints what is at a managed user's home, `/home/<name>`.
///
/// When the name exists (as anything, a dangling link included), it `exec`s one
/// `stat -c '%f %u %g'`, which doesn't follow a link: the raw mode in hex, then the
/// owner's uid and gid. When it doesn't, and `/home` is a directory the connecting
/// user can search, it prints `absent`; otherwise it exits
/// [`HOME_UNSEARCHABLE_EXIT`], so a name the probe couldn't see is never read as
/// missing.
#[must_use]
pub fn home_entry_snippet(username: &str) -> String {
    let path = single_quote(&user_home_dir(username));
    format!(
        "if [ -e {path} ] || [ -L {path} ]; then exec stat -c '%f %u %g' -- {path}; \
         elif [ -d /home ] && [ -x /home ]; then echo absent; \
         else exit {HOME_UNSEARCHABLE_EXIT}; fi"
    )
}

/// What [`home_entry_snippet`] found at `/home/<name>`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HomeEntry {
    /// Nothing is there.
    Absent,
    /// A directory, and its owner's uid.
    Directory { owner: u32 },
    /// A symbolic link.
    Link,
    /// Something other than a directory or a link.
    Other,
}

/// The file-type bits of a raw mode (`S_IFMT`), and the two types told apart.
const S_IFMT: u32 = 0o170_000;
const S_IFDIR: u32 = 0o040_000;
const S_IFLNK: u32 = 0o120_000;

impl HomeEntry {
    /// Parse the snippet's answer, `None` for anything it doesn't print.
    fn parse(text: &str) -> Option<Self> {
        if text == "absent" {
            return Some(Self::Absent);
        }
        let mut fields = text.split(' ');
        let mode = u32::from_str_radix(fields.next()?, 16).ok()?;
        let owner = fields.next()?.parse::<u32>().ok()?;
        let _group = fields.next()?.parse::<u32>().ok()?;
        if fields.next().is_some() {
            return None;
        }
        Some(match mode & S_IFMT {
            S_IFDIR => Self::Directory { owner },
            S_IFLNK => Self::Link,
            _ => Self::Other,
        })
    }
}

/// A user's reads and where each sits — built once, by [`Reads::of`], for both
/// [`queries`] and the verdict.
#[derive(Debug, Clone)]
struct Reads {
    /// The reads, in order; the existence probe is [`ID`].
    queries: Vec<Query>,
    /// The `/etc/passwd` login shell.
    shell: Option<usize>,
    /// The `/etc/passwd` home, read when a managed attribute lives under it.
    home: Option<usize>,
    /// What is at `/home/<name>` ([`home_entry_snippet`]), read beside `home`.
    home_entry: Option<usize>,
    /// The home directory's mode.
    home_mode: Option<usize>,
    /// The reads managed `ssh_keys` add.
    ssh_keys: Option<SshKeyReads>,
    /// The supplementary groups.
    groups: Option<usize>,
    /// The reads a managed `sudo` adds.
    sudo: Option<SudoReads>,
}

/// Where the reads of a user with `ssh_keys` sit.
#[derive(Debug, Clone, Copy)]
struct SshKeyReads {
    /// A `copy_from` source's `authorized_keys` ([`copy_source_snippet`]).
    copy_source: Option<usize>,
    /// The target's `authorized_keys` contents.
    authorized_keys: usize,
    /// The `/etc/shadow` password field.
    shadow: usize,
}

/// Where the reads of a user with a managed `sudo` sit.
#[derive(Debug, Clone, Copy)]
struct SudoReads {
    /// Whether the sudoers drop-in is a regular file.
    present: usize,
    /// The drop-in's contents, when sudo is granted.
    content: Option<usize>,
}

impl Reads {
    fn of(user: &UserResource) -> Self {
        let username = user.username.as_str();
        let mut queries = vec![Query::login_command(format!(
            "id -u -- {}",
            single_quote(username)
        ))];
        let mut push = |query: Query| {
            queries.push(query);
            queries.len() - 1
        };
        let shell = user.shell.as_ref().map(|_| {
            push(Query::login_command(passwd_field(
                username,
                PasswdField::Shell,
            )))
        });
        // `home_mode` and `ssh_keys` act on paths under `/home/<name>`, so the account's
        // real home is read beside them, to hold the user when they would miss it.
        let manages_home = user.home_mode.is_some() || user.ssh_keys.is_some();
        let home = manages_home.then(|| {
            push(Query::login_command(passwd_field(
                username,
                PasswdField::Home,
            )))
        });
        let home_entry =
            manages_home.then(|| push(Query::login_command(home_entry_snippet(username))));
        let home_mode = user.home_mode.as_ref().map(|_| {
            push(Query::login_command(format!(
                "stat -c '%a' -- {}",
                single_quote(&user_home_dir(username))
            )))
        });
        let ssh_keys = user.ssh_keys.as_ref().map(|ssh_keys| SshKeyReads {
            copy_source: match ssh_keys {
                SshKeys::CopyFrom { copy_from } => Some(push(Query::root_command(
                    copy_source_snippet(copy_from.as_str()),
                ))),
                SshKeys::Keys { .. } => None,
            },
            authorized_keys: push(Query::root_command(authorized_keys_snippet(username))),
            // `exec`'d, so the probe's `timeout` signals `awk` itself.
            shadow: push(Query::root_command(format!(
                "exec {}",
                shadow_password_field(username)
            ))),
        });
        let groups = (!user.groups.is_empty()).then(|| {
            push(Query::login_command(format!(
                "id -nG -- {}",
                single_quote(username)
            )))
        });
        let sudo = user.sudo.as_ref().map(|sudo| {
            let path = sudoers_path(username);
            SudoReads {
                present: push(Query::root_command(format!(
                    "test -f {}",
                    single_quote(&path)
                ))),
                content: sudo.grant().map(|_| {
                    push(Query::path(
                        path,
                        PathFacet::Read {
                            max: SUDOERS_READ_MAX,
                        },
                        Privilege::Elevated,
                    ))
                }),
            }
        });
        Self {
            queries,
            shell,
            home,
            home_entry,
            home_mode,
            ssh_keys,
            groups,
            sudo,
        }
    }
}

/// A user's reads (see the module docs): `id -u`, then one or two per managed attribute.
#[must_use]
pub fn queries(user: &UserResource) -> Vec<Query> {
    Reads::of(user).queries
}

/// The verdict for a user from the answers to [`queries`]: `Absent` when `id -u` fails
/// (the other answers unread but what is at the home, which can hold it), else
/// converged or drifted on every managed attribute.
#[must_use]
pub fn interpret(user: &UserResource, results: &[QueryResult]) -> Detection {
    verdict(user, &Reads::of(user), results).unwrap_or_else(|held| held)
}

fn verdict(
    user: &UserResource,
    reads: &Reads,
    results: &[QueryResult],
) -> Result<Detection, Detection> {
    let id = command_answer(results, ID)?;
    // A probe's stdout as lossy text, trimmed.
    let text = |observation: &CommandObservation| {
        String::from_utf8_lossy(&observation.stdout)
            .trim()
            .to_owned()
    };
    // A managed attribute's answer. A probe that exited nonzero read nothing, so the
    // user is held, by what couldn't be read: the attribute is neither as declared nor
    // drifted.
    let read = |index: usize, what: &str| -> Result<&CommandObservation, Detection> {
        let observation = command_answer(results, index)?;
        if observation.succeeded() {
            Ok(observation)
        } else {
            Err(Detection::Undetermined {
                reason: format!(
                    "detection failed: couldn't read {what} (the probe exited {})",
                    observation.code
                ),
            })
        }
    };
    let username = user.username.as_str();

    if !id.succeeded() {
        // `useradd` leaves a directory already at the home as it was: one the creation
        // can't make the user's holds the account before it is created.
        if let Some(index) = reads.home_entry {
            home_entry_hold(username, None, home_entry(results, index, username)?)?;
        }
        return Ok(Detection::Absent);
    }

    // zap manages a user's home as `/home/<name>`: an existing account whose home is
    // elsewhere would have its `home_mode` and `ssh_keys` applied to a directory it
    // doesn't use, so the user is held, naming the home it has.
    if let Some(index) = reads.home {
        let current = text(read(index, &format!("{username}'s home from /etc/passwd"))?);
        let managed = user_home_dir(username);
        if current != managed {
            return Err(Detection::Undetermined {
                reason: foreign_home_reason(username, &current, &managed),
            });
        }
    }

    let mut drift = UserDrift::default();

    if let Some(index) = reads.home_entry {
        let entry = home_entry(results, index, username)?;
        let uid = text(id)
            .parse::<u32>()
            .map_err(|_| Detection::Undetermined {
                reason: format!(
                    "detection failed: couldn't read {username}'s uid (`id -u` printed {:?})",
                    text(id)
                ),
            })?;
        home_entry_hold(username, Some(uid), entry)?;
    }

    if let (Some(want), Some(index)) = (&user.shell, reads.shell) {
        let current = text(read(
            index,
            &format!("{username}'s login shell from /etc/passwd"),
        )?);
        if current != *want {
            drift.shell = Some(current);
        }
    }

    if let (Some(want), Some(index)) = (&user.home_mode, reads.home_mode) {
        let current = text(read(
            index,
            &format!("the mode of {}", user_home_dir(username)),
        )?);
        if normalize_mode(&current) != normalize_mode(want) {
            drift.home_mode = Some(current);
        }
    }

    if let (Some(ssh_keys), Some(key_reads)) = (&user.ssh_keys, reads.ssh_keys) {
        drift.ssh_keys = ssh_keys_drift(ssh_keys, key_reads, results)?;
        let shadow = read(
            key_reads.shadow,
            &format!("{username}'s password field from /etc/shadow"),
        )?;
        if text(shadow) != "*" {
            drift.shadow_password = Some(ShadowPasswordDrift::NotDisabled);
        }
    }

    // Additive: a desired group not listed drifts; a group the config omits is never
    // stripped.
    if let Some(index) = reads.groups {
        let current = read(index, &format!("{username}'s groups"))?;
        let listed = String::from_utf8_lossy(&current.stdout);
        for group in &user.groups {
            let name = group.as_str();
            if !listed.split_whitespace().any(|present| present == name) {
                drift.groups.push(name.to_owned());
            }
        }
    }

    if let (Some(sudo), Some(sudo_reads)) = (&user.sudo, reads.sudo) {
        let present = command_answer(results, sudo_reads.present)?.succeeded();
        drift.sudo = match (sudo.grant(), present) {
            // `Disabled` — a present sudoers file should be removed.
            (None, true) => Some(SudoDrift::ShouldBeAbsent),
            (None, false) => None,
            (Some(_), false) => Some(SudoDrift::Missing),
            // Granted (bare mode or command-restricted) — compare the sudoers content.
            (Some((mode, scope)), true) => {
                let index = sudo_reads.content.ok_or_else(layout_mismatch)?;
                let expected = build_sudoers_content(&user.username, mode, scope);
                match file_contents(results, index)? {
                    None => Some(SudoDrift::Unreadable),
                    Some((current, truncated)) => (truncated || current.trim() != expected.trim())
                        .then_some(SudoDrift::ContentDiffers),
                }
            }
        };
    }

    Ok(drifted_or_converged(CurrentState::User { drift }))
}

/// What the home entry read reads, for a hold.
fn home_entry_what(username: &str) -> String {
    format!("what is at {}", user_home_dir(username))
}

/// The home entry read's answer, or a hold: naming `/home` when the probe couldn't see
/// under it, or saying the read failed or printed something [`home_entry_snippet`]
/// doesn't.
fn home_entry(
    results: &[QueryResult],
    index: usize,
    username: &str,
) -> Result<HomeEntry, Detection> {
    let observation = command_answer(results, index)?;
    let what = home_entry_what(username);
    if observation.code == HOME_UNSEARCHABLE_EXIT {
        return Err(Detection::Undetermined {
            reason: format!(
                "detection failed: couldn't read {what}: /home is missing, or not a directory \
                 the connecting user can search"
            ),
        });
    }
    if !observation.succeeded() {
        return Err(Detection::Undetermined {
            reason: format!(
                "detection failed: couldn't read {what} (the probe exited {})",
                observation.code
            ),
        });
    }
    let printed = String::from_utf8_lossy(&observation.stdout);
    HomeEntry::parse(printed.trim()).ok_or_else(|| Detection::Undetermined {
        reason: format!(
            "detection failed: couldn't read {what} (unexpected answer {:?})",
            printed.trim()
        ),
    })
}

/// The hold for the home `entry` of `username`, whose uid is `uid` (`None` for an
/// account that doesn't exist yet), naming what is there.
///
/// Nothing there, a directory the user owns, or a directory root owns reads on: an
/// existing account's root-owned home is left as it is, and the creation gives an absent
/// account's to the user. A directory any other uid owns, a link, or anything but a
/// directory holds.
fn home_entry_hold(username: &str, uid: Option<u32>, entry: HomeEntry) -> Result<(), Detection> {
    let home = user_home_dir(username);
    let held = |found: String| {
        Err(Detection::Undetermined {
            reason: format!(
                "{found}: zap manages a user's home as the directory {home}, the user's own or \
                 root's"
            ),
        })
    };
    match entry {
        HomeEntry::Absent | HomeEntry::Directory { owner: 0 } => Ok(()),
        HomeEntry::Directory { owner } if Some(owner) == uid => Ok(()),
        HomeEntry::Directory { owner } => {
            let whose = uid.map_or_else(
                || format!("{username} doesn't exist yet"),
                |uid| format!("{username}'s uid is {uid}"),
            );
            held(format!(
                "{home} is owned by uid {owner} ({whose}); chown it to {username}, or remove it"
            ))
        }
        HomeEntry::Link => held(format!(
            "{home} is a symbolic link, which zap doesn't follow; replace it with a directory, \
             or declare neither home_mode nor ssh_keys"
        )),
        HomeEntry::Other => held(format!(
            "{home} is not a directory; move it aside, or remove it"
        )),
    }
}

/// Why a user whose account exists with a home other than `/home/<name>` is held.
fn foreign_home_reason(username: &str, current: &str, managed: &str) -> String {
    let found = if current.is_empty() {
        format!("{username} has no home in /etc/passwd")
    } else {
        format!("{username}'s home in /etc/passwd is {current}")
    };
    format!(
        "{found}, not {managed}: zap manages a user's home as /home/<name>, so its \
         `home_mode` and `ssh_keys` would miss the account's own"
    )
}

/// Compare the target's `authorized_keys` against the desired content, returning the
/// drift state (`None` = converged). An unreadable `copy_from` source is drift
/// ([`SshKeysDrift::Unreadable`]) before the target is compared; a target file that
/// can't be read, or is empty, is [`SshKeysDrift::MissingOrEmpty`].
fn ssh_keys_drift(
    ssh_keys: &SshKeys,
    reads: SshKeyReads,
    results: &[QueryResult],
) -> Result<Option<SshKeysDrift>, Detection> {
    let desired = match (ssh_keys, reads.copy_source) {
        (SshKeys::Keys { keys }, _) => render_authorized_keys(keys),
        (SshKeys::CopyFrom { .. }, None) => return Err(layout_mismatch()),
        (SshKeys::CopyFrom { .. }, Some(index)) => {
            let source = command_answer(results, index)?;
            if !source.succeeded() {
                return Ok(Some(SshKeysDrift::Unreadable));
            }
            // A source past the bound can't be compared whole.
            match contents(source.stdout.clone(), AUTHORIZED_KEYS_READ_MAX) {
                PathObservation::Contents {
                    bytes,
                    truncated: false,
                } => String::from_utf8_lossy(&bytes).into_owned(),
                _ => return Ok(Some(SshKeysDrift::Unreadable)),
            }
        }
    };
    let current = command_answer(results, reads.authorized_keys)?;
    let current = current.succeeded().then(|| {
        let max = usize::try_from(AUTHORIZED_KEYS_READ_MAX).unwrap_or(usize::MAX);
        let bytes = current.stdout.get(..max).unwrap_or(&current.stdout);
        (
            String::from_utf8_lossy(bytes).into_owned(),
            current.stdout.len() > max,
        )
    });
    Ok(match current {
        // Absent, unreadable, or not a regular file → re-apply.
        None => Some(SshKeysDrift::MissingOrEmpty),
        Some((current, false)) if current.trim().is_empty() => Some(SshKeysDrift::MissingOrEmpty),
        Some((current, truncated)) if truncated || current.trim() != desired.trim() => {
            Some(SshKeysDrift::ContentDiffers)
        }
        Some(_) => None,
    })
}

/// A bounded [`Read`](PathFacet::Read)'s answer as lossy text and whether it was cut
/// short, or `None` when the file couldn't be read (absent, unopenable at the read's
/// privilege, or not a regular file of its own).
fn file_contents(
    results: &[QueryResult],
    index: usize,
) -> Result<Option<(String, bool)>, Detection> {
    match path_answer(results, index)? {
        PathObservation::Contents { bytes, truncated } => Ok(Some((
            String::from_utf8_lossy(bytes).into_owned(),
            *truncated,
        ))),
        PathObservation::Failed | PathObservation::NotRegular => Ok(None),
        PathObservation::Kind(_)
        | PathObservation::Metadata(_)
        | PathObservation::LinkTarget(_)
        | PathObservation::Digest(_)
        | PathObservation::Empty(_) => Err(unexpected_answer(index)),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        AUTHORIZED_KEYS_READ_MAX, HOME_UNSEARCHABLE_EXIT, NOT_REGULAR_EXIT,
        authorized_keys_snippet, copy_source_snippet, home_entry_snippet, interpret, queries,
    };
    use crate::detected::{
        CurrentState, Detection, ShadowPasswordDrift, SshKeysDrift, SudoDrift, UserDrift,
    };
    use crate::observe::testing::{exited, failed};
    use crate::observe::{
        COMMAND_TIMEOUT, Observation, PathFacet, PathObservation, Privilege, Query, QueryError,
        QueryResult,
    };
    use crate::schema::{UserResource, copy_source_keys};

    fn user(json: serde_json::Value) -> UserResource {
        serde_json::from_value(json).unwrap()
    }

    #[expect(
        clippy::unnecessary_wraps,
        reason = "builds the answer type `interpret` reads, which is always a `Result`"
    )]
    fn read(bytes: &[u8], truncated: bool) -> QueryResult {
        Ok(Observation::Path(PathObservation::Contents {
            bytes: bytes.to_vec(),
            truncated,
        }))
    }

    /// The home entry read's answer for `/home/deploy` as a directory uid 1001 owns.
    fn own_home() -> QueryResult {
        exited(0, "41ed 1001 1001\n")
    }

    fn drifted(drift: UserDrift) -> Detection {
        Detection::Drifted {
            current: CurrentState::User { drift },
        }
    }

    #[test]
    fn every_read_keeps_the_privilege_of_its_old_probe() {
        let everything = user(serde_json::json!({
            "username": "deploy",
            "shell": "/bin/sh",
            "home_mode": "750",
            "ssh_keys": {"copy_from": "ops"},
            "groups": ["users"],
            "sudo": {"mode": "password", "commands": ["/usr/bin/true"]},
        }));
        let login = |snippet: &str| Query::login_command(snippet);
        let root = |snippet: &str| Query::root_command(snippet);
        let read =
            |path: &str, max| Query::path(path, PathFacet::Read { max }, Privilege::Elevated);
        assert_eq!(
            queries(&everything),
            [
                login("id -u -- 'deploy'"),
                login("awk -F: -v u='deploy' '$1\"\"==u{print $7}' /etc/passwd"),
                login("awk -F: -v u='deploy' '$1\"\"==u{print $6}' /etc/passwd"),
                login(&home_entry_snippet("deploy")),
                login("stat -c '%a' -- '/home/deploy'"),
                root(&copy_source_snippet("ops")),
                root(&authorized_keys_snippet("deploy")),
                root("exec awk -F: -v u='deploy' '$1\"\"==u{print $2}' /etc/shadow"),
                login("id -nG -- 'deploy'"),
                root("test -f '/etc/sudoers.d/deploy'"),
                read("/etc/sudoers.d/deploy", 64 * 1024),
            ]
        );
        // `sudo: false` reads only whether the file is there; unmanaged attributes
        // read nothing.
        let disabled = user(serde_json::json!({"username": "deploy", "sudo": false}));
        assert_eq!(
            queries(&disabled),
            [
                login("id -u -- 'deploy'"),
                root("test -f '/etc/sudoers.d/deploy'"),
            ]
        );
        assert!(queries(&everything).iter().all(|query| match query {
            Query::Command { timeout_secs, .. } => *timeout_secs == COMMAND_TIMEOUT,
            Query::Path { .. } => true,
        }));
    }

    #[test]
    fn the_copy_source_is_read_through_its_passwd_home_in_one_snippet() {
        assert_eq!(
            copy_source_snippet("ops"),
            "SRC_HOME=$(awk -F: -v u='ops' '$1\"\"==u{print $6}' /etc/passwd) && \
             [ -n \"$SRC_HOME\" ] || exit 3; \
             exec sudo -u 'ops' head -c 1048577 -- \"$SRC_HOME/.ssh/authorized_keys\""
        );
        // The file is read by the read the step that copies it makes: as the source
        // account, never as root.
        assert!(copy_source_snippet("ops").ends_with(&format!(
            "exec {}",
            copy_source_keys("ops", "head -c 1048577")
        )));
        assert_eq!(
            copy_source_keys("ops", "cat"),
            "sudo -u 'ops' cat -- \"$SRC_HOME/.ssh/authorized_keys\""
        );
    }

    #[test]
    fn an_absent_user_reads_nothing_else() {
        let resource = user(serde_json::json!({
            "username": "deploy", "shell": "/bin/sh", "sudo": "nopasswd",
        }));
        let unanswered = Err(QueryError::Unrecorded);
        assert_eq!(
            interpret(
                &resource,
                &[
                    exited(1, ""),
                    unanswered.clone(),
                    unanswered.clone(),
                    unanswered
                ]
            ),
            Detection::Absent
        );
    }

    /// A managed attribute whose probe exits nonzero was not read: the user is held, by
    /// what couldn't be read, and never reads converged or drifted on the rest.
    #[test]
    fn a_managed_attribute_that_could_not_be_read_holds_the_user() {
        let resource = user(serde_json::json!({
            "username": "deploy",
            "shell": "/bin/sh",
            "home_mode": "750",
            "ssh_keys": {"keys": ["k1"]},
            "groups": ["users"],
        }));
        // id, shell awk, home awk, home entry, home stat, authorized_keys, shadow awk,
        // `id -nG` — all as declared.
        let converged = [
            exited(0, "1001\n"),
            exited(0, "/bin/sh\n"),
            exited(0, "/home/deploy\n"),
            own_home(),
            exited(0, "750\n"),
            exited(0, "k1\n"),
            exited(0, "*\n"),
            exited(0, "deploy users\n"),
        ];
        assert_eq!(interpret(&resource, &converged), Detection::Converged);
        for (index, code, what) in [
            (1, 2, "deploy's login shell from /etc/passwd"),
            (2, 2, "deploy's home from /etc/passwd"),
            (3, 1, "what is at /home/deploy"),
            (4, 1, "the mode of /home/deploy"),
            (6, 1, "deploy's password field from /etc/shadow"),
            (7, 1, "deploy's groups"),
        ] {
            let mut results = converged.clone();
            results[index] = exited(code, "");
            assert_eq!(
                interpret(&resource, &results),
                Detection::Undetermined {
                    reason: format!(
                        "detection failed: couldn't read {what} (the probe exited {code})"
                    ),
                },
                "{what}"
            );
            // Drift elsewhere doesn't outrank it: the user is not read whole.
            results[1] = if index == 1 {
                exited(code, "")
            } else {
                exited(0, "/bin/bash\n")
            };
            assert!(
                matches!(
                    interpret(&resource, &results),
                    Detection::Undetermined { .. }
                ),
                "{what}"
            );
        }
        // Every probe failing at once holds too.
        let results = [
            exited(0, "1001\n"),
            exited(2, ""),
            exited(2, ""),
            exited(1, ""),
            exited(1, ""),
            exited(0, "k1\n"),
            exited(1, ""),
            exited(1, ""),
        ];
        assert!(matches!(
            interpret(&resource, &results),
            Detection::Undetermined { .. }
        ));
    }

    /// An attribute the config doesn't declare is not read, so nothing about it can
    /// hold the user.
    #[test]
    fn an_attribute_the_config_does_not_manage_is_not_read() {
        let resource = user(serde_json::json!({"username": "deploy"}));
        assert_eq!(queries(&resource).len(), 1);
        assert_eq!(
            interpret(&resource, &[exited(0, "1001\n")]),
            Detection::Converged
        );
        let shell_only = user(serde_json::json!({"username": "deploy", "shell": "/bin/sh"}));
        assert_eq!(queries(&shell_only).len(), 2);
        assert_eq!(
            interpret(&shell_only, &[exited(0, "1001\n"), exited(0, "/bin/sh\n")]),
            Detection::Converged
        );
    }

    #[test]
    fn each_attribute_drifts_on_its_own_observation() {
        let resource = user(serde_json::json!({
            "username": "deploy",
            "shell": "/bin/sh",
            "home_mode": "750",
            "ssh_keys": {"keys": ["k1"]},
            "groups": ["users", "video"],
            "sudo": "nopasswd",
        }));
        let results = [
            exited(0, "1001\n"),
            exited(0, "/sbin/nologin\n"),
            exited(0, "/home/deploy\n"),
            own_home(),
            exited(0, "755\n"),
            exited(0, "k1\nk2\n"),
            exited(0, "!\n"),
            exited(0, "deploy users\n"),
            exited(0, ""),
            read(b"deploy ALL=(ALL) ALL\n", false),
        ];
        assert_eq!(
            interpret(&resource, &results),
            drifted(UserDrift {
                shell: Some("/sbin/nologin".to_owned()),
                home_mode: Some("755".to_owned()),
                ssh_keys: Some(SshKeysDrift::ContentDiffers),
                sudo: Some(SudoDrift::ContentDiffers),
                shadow_password: Some(ShadowPasswordDrift::NotDisabled),
                groups: vec!["video".to_owned()],
            })
        );
    }

    /// zap manages a user's home as `/home/<name>`: an existing account whose
    /// `/etc/passwd` home is anything else, or that has none there, is held when the
    /// user declares an attribute under it, ahead of any drift.
    #[test]
    fn a_home_other_than_home_name_holds_the_user() {
        for declared in [
            serde_json::json!({"username": "deploy", "home_mode": "750"}),
            serde_json::json!({"username": "deploy", "ssh_keys": {"keys": ["k1"]}}),
        ] {
            let resource = user(declared);
            // Every read after the home awk, as declared.
            let rest = if resource.home_mode.is_some() {
                vec![exited(0, "750\n")]
            } else {
                vec![exited(0, "k1\n"), exited(0, "*\n")]
            };
            let with_home = |home: &str| {
                let mut results = vec![exited(0, "1001\n"), exited(0, home), own_home()];
                results.extend(rest.iter().cloned());
                interpret(&resource, &results)
            };
            assert_eq!(with_home("/home/deploy\n"), Detection::Converged);
            for (home, reason) in [
                (
                    "/srv/deploy\n",
                    "deploy's home in /etc/passwd is /srv/deploy, not /home/deploy: zap \
                     manages a user's home as /home/<name>, so its `home_mode` and `ssh_keys` \
                     would miss the account's own",
                ),
                (
                    "/home/deploy/\n",
                    "deploy's home in /etc/passwd is /home/deploy/, not /home/deploy: zap \
                     manages a user's home as /home/<name>, so its `home_mode` and `ssh_keys` \
                     would miss the account's own",
                ),
                // An account `id` knows that /etc/passwd doesn't list (NSS), or an empty
                // home field.
                (
                    "",
                    "deploy has no home in /etc/passwd, not /home/deploy: zap manages a \
                     user's home as /home/<name>, so its `home_mode` and `ssh_keys` would \
                     miss the account's own",
                ),
            ] {
                assert_eq!(
                    with_home(home),
                    Detection::Undetermined {
                        reason: reason.to_owned()
                    },
                    "{home:?}"
                );
            }
        }
        // Drift on another attribute doesn't outrank the hold.
        let resource = user(serde_json::json!({
            "username": "deploy", "shell": "/bin/sh", "home_mode": "750",
        }));
        assert!(matches!(
            interpret(
                &resource,
                &[
                    exited(0, "1001\n"),
                    exited(0, "/bin/bash\n"),
                    exited(0, "/srv/deploy\n"),
                    own_home(),
                    exited(0, "755\n"),
                ]
            ),
            Detection::Undetermined { .. }
        ));
        // An account that doesn't exist yet has no passwd home to hold it: only what is
        // at its home is read.
        let unanswered = Err(QueryError::Unrecorded);
        assert_eq!(
            interpret(
                &resource,
                &[
                    exited(1, ""),
                    unanswered.clone(),
                    unanswered.clone(),
                    exited(0, "absent\n"),
                    unanswered
                ]
            ),
            Detection::Absent
        );
        // Shell, groups and sudo act on no path under the home: it isn't read.
        let elsewhere = user(serde_json::json!({
            "username": "deploy", "shell": "/bin/sh", "groups": ["users"], "sudo": false,
        }));
        assert!(!queries(&elsewhere).iter().any(|query| query
            == &Query::login_command("awk -F: -v u='deploy' '$1\"\"==u{print $6}' /etc/passwd")));
    }

    #[test]
    fn a_missing_answer_holds_the_user() {
        let resource = user(serde_json::json!({"username": "deploy", "shell": "/bin/sh"}));
        let timed_out = Err(QueryError::TimedOut {
            secs: COMMAND_TIMEOUT,
        });
        assert!(matches!(
            interpret(&resource, &[exited(0, "1001\n"), timed_out.clone()]),
            Detection::Undetermined { .. }
        ));
        assert!(matches!(
            interpret(&resource, &[timed_out, exited(0, "/bin/sh\n")]),
            Detection::Undetermined { .. }
        ));
    }

    #[test]
    fn authorized_keys_compare_trimmed_and_bounded() {
        let resource =
            user(serde_json::json!({"username": "deploy", "ssh_keys": {"keys": ["k1"]}}));
        let keys = |target: QueryResult| {
            interpret(
                &resource,
                &[
                    exited(0, "1001\n"),
                    exited(0, "/home/deploy\n"),
                    own_home(),
                    target,
                    exited(0, "*\n"),
                ],
            )
        };
        let ssh_keys = |drift| {
            drifted(UserDrift {
                ssh_keys: Some(drift),
                ..UserDrift::default()
            })
        };
        assert_eq!(keys(exited(0, "k1\n\n  ")), Detection::Converged);
        // Absent or unreadable (`head`'s 1), or no regular file of its own: re-applied.
        for code in [1, NOT_REGULAR_EXIT] {
            assert_eq!(
                keys(exited(code, "")),
                ssh_keys(SshKeysDrift::MissingOrEmpty),
                "{code}"
            );
        }
        assert_eq!(
            keys(exited(0, " \n")),
            ssh_keys(SshKeysDrift::MissingOrEmpty)
        );
        assert_eq!(
            keys(exited(0, "k2\n")),
            ssh_keys(SshKeysDrift::ContentDiffers)
        );
        // Past the bound, the file can't be compared whole: it drifts.
        let whole = format!(
            "k1\n{}",
            " ".repeat(usize::try_from(AUTHORIZED_KEYS_READ_MAX).unwrap() - 3)
        );
        assert_eq!(keys(exited(0, &whole)), Detection::Converged);
        assert_eq!(
            keys(exited(0, &format!("{whole} "))),
            ssh_keys(SshKeysDrift::ContentDiffers)
        );
        assert!(matches!(
            keys(Err(QueryError::Unrecorded)),
            Detection::Undetermined { .. }
        ));
    }

    #[test]
    fn a_copy_source_answers_by_exit_status_and_bound() {
        let resource =
            user(serde_json::json!({"username": "deploy", "ssh_keys": {"copy_from": "ops"}}));
        let keys = |source: QueryResult, target: QueryResult| {
            interpret(
                &resource,
                &[
                    exited(0, "1001\n"),
                    exited(0, "/home/deploy\n"),
                    own_home(),
                    source,
                    target,
                    exited(0, "*\n"),
                ],
            )
        };
        let unreadable = drifted(UserDrift {
            ssh_keys: Some(SshKeysDrift::Unreadable),
            ..UserDrift::default()
        });
        // No passwd entry or home (3), no source file (4), a source `head` can't read (1):
        // the desired content is unknown, before the target is consulted.
        for code in [3, 4, 1] {
            assert_eq!(
                keys(exited(code, ""), Err(QueryError::Unrecorded)),
                unreadable,
                "{code}"
            );
        }
        assert_eq!(
            keys(exited(0, "k1\n"), exited(0, "k1")),
            Detection::Converged
        );
        // An empty source leaves nothing to match but an empty target — missing.
        assert_eq!(
            keys(exited(0, ""), exited(0, "")),
            drifted(UserDrift {
                ssh_keys: Some(SshKeysDrift::MissingOrEmpty),
                ..UserDrift::default()
            })
        );
        // A source past the bound can't be compared whole.
        let over = "k".repeat(usize::try_from(AUTHORIZED_KEYS_READ_MAX).unwrap() + 1);
        assert_eq!(keys(exited(0, &over), exited(0, &over)), unreadable);
        assert!(matches!(
            keys(
                Err(QueryError::TimedOut {
                    secs: COMMAND_TIMEOUT
                }),
                exited(0, "k1")
            ),
            Detection::Undetermined { .. }
        ));
    }

    #[test]
    fn sudoers_presence_then_content() {
        let granted = user(serde_json::json!({"username": "deploy", "sudo": "nopasswd"}));
        let sudo = |present: QueryResult, content: QueryResult| {
            interpret(&granted, &[exited(0, "1001\n"), present, content])
        };
        let drift = |drift| {
            drifted(UserDrift {
                sudo: Some(drift),
                ..UserDrift::default()
            })
        };
        let line = b"deploy ALL=(ALL) NOPASSWD: ALL\n";
        assert_eq!(sudo(exited(0, ""), read(line, false)), Detection::Converged);
        assert_eq!(
            sudo(
                exited(0, ""),
                read(b"deploy ALL=(ALL) NOPASSWD: ALL\n\n", false)
            ),
            Detection::Converged
        );
        assert_eq!(sudo(exited(0, ""), failed()), drift(SudoDrift::Unreadable));
        assert_eq!(
            sudo(exited(0, ""), read(line, true)),
            drift(SudoDrift::ContentDiffers)
        );
        // Absent: the content read's answer isn't consulted.
        assert_eq!(
            sudo(exited(1, ""), Err(QueryError::Unrecorded)),
            drift(SudoDrift::Missing)
        );

        let disabled = user(serde_json::json!({"username": "deploy", "sudo": false}));
        assert_eq!(
            interpret(&disabled, &[exited(0, "1001\n"), exited(0, "")]),
            drift(SudoDrift::ShouldBeAbsent)
        );
        assert_eq!(
            interpret(&disabled, &[exited(0, "1001\n"), exited(1, "")]),
            Detection::Converged
        );
    }

    /// What is at `/home/<name>`, for an account that exists (uid 1001) and one that
    /// doesn't yet: the user's directory, root's, or nothing reads on (an absent
    /// account stays a create), and anything else holds, naming it.
    #[test]
    fn the_home_entry_holds_any_home_but_the_users_or_roots() {
        let resource = user(serde_json::json!({"username": "deploy", "home_mode": "750"}));
        let existing = |entry: QueryResult| {
            interpret(
                &resource,
                &[
                    exited(0, "1001\n"),
                    exited(0, "/home/deploy\n"),
                    entry,
                    exited(0, "750\n"),
                ],
            )
        };
        let unanswered = || Err(QueryError::Unrecorded);
        let absent = |entry: QueryResult| {
            interpret(
                &resource,
                &[exited(1, ""), unanswered(), entry, unanswered()],
            )
        };
        let reason = |found: &str| Detection::Undetermined {
            reason: format!(
                "{found}: zap manages a user's home as the directory /home/deploy, the user's \
                 own or root's"
            ),
        };
        // The user's own directory, whatever its group; root's, left as it is (a chroot
        // home) or given to the user by the creation; nothing there.
        for answer in ["41ed 1001 0\n", "41ed 0 0\n", "absent\n"] {
            assert_eq!(
                existing(exited(0, answer)),
                Detection::Converged,
                "{answer}"
            );
        }
        for answer in ["41c0 0 0\n", "absent\n"] {
            assert_eq!(absent(exited(0, answer)), Detection::Absent, "{answer}");
        }
        // Another uid's, a live account's or an orphan's.
        assert_eq!(
            existing(exited(0, "41ed 1002 1002\n")),
            reason(
                "/home/deploy is owned by uid 1002 (deploy's uid is 1001); chown it to deploy, \
                 or remove it"
            )
        );
        assert_eq!(
            absent(exited(0, "41ed 1001 1001\n")),
            reason(
                "/home/deploy is owned by uid 1001 (deploy doesn't exist yet); chown it to \
                 deploy, or remove it"
            )
        );
        // A link, wherever it points and whoever owns it, and anything but a directory.
        for answer in ["a1ff 0 0\n", "a1ff 1001 1001\n"] {
            let held = reason(
                "/home/deploy is a symbolic link, which zap doesn't follow; replace it with a \
                 directory, or declare neither home_mode nor ssh_keys",
            );
            assert_eq!(existing(exited(0, answer)), held, "{answer}");
            assert_eq!(absent(exited(0, answer)), held, "{answer}");
        }
        for answer in ["81a4 1001 1001\n", "11a4 0 0\n"] {
            let held = reason("/home/deploy is not a directory; move it aside, or remove it");
            assert_eq!(existing(exited(0, answer)), held, "{answer}");
            assert_eq!(absent(exited(0, answer)), held, "{answer}");
        }
        // An answer the snippet doesn't print, or a failed probe, holds.
        for answer in [
            "",
            "41ed 1001\n",
            "41ed x 1001\n",
            "41ed 1001 1001 7\n",
            "dir\n",
        ] {
            assert!(
                matches!(
                    existing(exited(0, answer)),
                    Detection::Undetermined { reason }
                        if reason.starts_with("detection failed: couldn't read what is at \
                                               /home/deploy (unexpected answer")
                ),
                "{answer:?}"
            );
        }
        assert_eq!(
            absent(exited(1, "")),
            Detection::Undetermined {
                reason: "detection failed: couldn't read what is at /home/deploy (the probe \
                         exited 1)"
                    .to_owned()
            }
        );
        // `/home` itself unseen: named, and held whether the account exists or not.
        let unsearchable = Detection::Undetermined {
            reason: "detection failed: couldn't read what is at /home/deploy: /home is \
                     missing, or not a directory the connecting user can search"
                .to_owned(),
        };
        assert_eq!(existing(exited(HOME_UNSEARCHABLE_EXIT, "")), unsearchable);
        assert_eq!(absent(exited(HOME_UNSEARCHABLE_EXIT, "")), unsearchable);
        // An account whose `id -u` isn't a number can't be compared with the owner.
        assert!(matches!(
            interpret(
                &resource,
                &[
                    exited(0, "deploy\n"),
                    exited(0, "/home/deploy\n"),
                    own_home(),
                    exited(0, "750\n"),
                ],
            ),
            Detection::Undetermined { reason } if reason.contains("couldn't read deploy's uid")
        ));
    }

    #[test]
    fn the_home_entry_snippet_reads_without_following_a_link() {
        assert_eq!(
            home_entry_snippet("deploy"),
            "if [ -e '/home/deploy' ] || [ -L '/home/deploy' ]; then exec stat -c '%f %u %g' \
             -- '/home/deploy'; elif [ -d /home ] && [ -x /home ]; then echo absent; else exit \
             94; fi"
        );
    }
}
