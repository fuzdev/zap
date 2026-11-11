//! The operator-side reads of the checkout a deploy ships: whether the working tree is
//! dirty, the release version (the short commit hash, `-dirty-<id>` under `--force`),
//! and the id of an uncommitted tree. Each is read through `git` with the checkout
//! settings that would narrow what it compares forced off.

use crate::connection::{CommandOutput, Connection, RunOptions};
use crate::error::{Error, Result};
use crate::escape::escape_line;
use crate::secret::SecretMasker;

/// Whether the working tree has uncommitted changes or untracked files git doesn't
/// ignore, read through [`DIRTY_TREE_STATUS`].
///
/// # Errors
/// [`Error::Git`] when the tree can't be read: "clean" is a fact of the plan, never a
/// default for a read that failed.
pub(super) async fn git_uncommitted(local: &Connection, masker: &SecretMasker) -> Result<bool> {
    let out = local.run(DIRTY_TREE_STATUS, &RunOptions::default()).await?;
    if !out.success {
        return Err(git_error(
            "the working tree",
            DIRTY_TREE_STATUS,
            &out,
            masker,
        ));
    }
    Ok(!out.stdout.trim().is_empty())
}

/// A failed git read as an [`Error::Git`]: what couldn't be read, the command, and the
/// first line git said — masked, then escaped — so a checkout git refuses to trust and
/// a directory that is no checkout read differently. With nothing said, the usual cause.
fn git_error(what: &str, command: &str, out: &CommandOutput, masker: &SecretMasker) -> Error {
    let said = out
        .stderr
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty());
    Error::Git(said.map_or_else(
        || format!("could not read {what} (`{command}`) — run from the app's checkout"),
        |line| {
            format!(
                "could not read {what} (`{command}`): {}",
                escape_line(&masker.mask(line))
            )
        },
    ))
}

/// The short git commit hash, with `-dirty-` and the tree's [`dirty_id`] when `dirty`
/// is set.
pub(super) async fn git_version(
    local: &Connection,
    dirty: bool,
    masker: &SecretMasker,
) -> Result<String> {
    const COMMAND: &str = "git rev-parse --short=12 HEAD";
    let out = local.run(COMMAND, &RunOptions::default()).await?;
    if !out.success {
        return Err(git_error("the commit hash", COMMAND, &out, masker));
    }
    let hash = out.stdout.trim();
    Ok(if dirty {
        format!("{hash}-dirty-{}", dirty_id(local, masker).await?)
    } else {
        hash.to_owned()
    })
}

/// The `git` every read of the working tree runs, with the checkout settings that would
/// narrow what it compares forced: `core.fsmonitor=false`, `core.untrackedCache=false`,
/// `core.ignoreStat=false`, `core.fileMode=true` (a mode change counts),
/// `core.autocrlf=false` (no line-ending conversion), and `core.splitIndex=false` (the
/// copy of the index writes no shared index into the checkout's `.git`). A checkout on
/// a filesystem without executable bits, or one checked out with `core.autocrlf=true`,
/// therefore reads dirty.
macro_rules! dirty_git {
    () => {
        "git -c core.fsmonitor=false -c core.untrackedCache=false -c core.ignoreStat=false \
         -c core.fileMode=true -c core.autocrlf=false -c core.splitIndex=false"
    };
}

/// The prefix every read of the working tree runs under: an index of the checkout's
/// own entries — each path, mode, blob id, and stage, read with `git ls-files -s` — and
/// nothing else, in a directory of its own that is removed when the read ends, or is
/// stopped by a signal.
///
/// The checkout's index also caches what each file's `stat` looked like when git last
/// read it and which directories held no new files, and git believes a file unchanged
/// when its `stat` still matches. A `core.fsmonitor` that reports nothing changed lets
/// those caches go stale: a later `git status` writes them back trusted, after which a
/// file rewritten to its old size within the second it was read, or a file added to a
/// directory in that second, reads unchanged to git with the monitor off as well; a
/// file whose size and mtime were set back reads unchanged under `core.trustctime=false`
/// with no monitor at all. The copy holds no `stat` data and none of the index's flags
/// (`assume-unchanged`, `skip-worktree`, the monitor's and the untracked cache's), so
/// git compares every file's contents. `core.ignoreStat`, which would mark every entry
/// of the copy unchanged, is off while it is built and read ([`dirty_git!`]).
macro_rules! entries_index {
    () => {
        concat!(
            "zap_x=$(mktemp -d) && trap 'rm -rf -- \"$zap_x\"' EXIT && trap 'exit 1' HUP INT TERM && ",
            dirty_git!(),
            " ls-files -s -z --full-name -- ':/' > \"$zap_x/entries\" && ",
            "GIT_INDEX_FILE=$zap_x/index && export GIT_INDEX_FILE && ",
            dirty_git!(),
            " update-index -z --index-info < \"$zap_x/entries\" && ",
        )
    };
}

/// The dirty check: any change to a tracked or staged file and any untracked file git
/// doesn't ignore, read against [`entries_index!`]'s copy of the index with the
/// settings [`dirty_git!`] forces, and a submodule whose checkout moved or holds
/// changes its own index shows (`--ignore-submodules=none`, past
/// `submodule.<name>.ignore` and `diff.ignoreSubmodules`; `--untracked-files=normal`,
/// past `status.showUntrackedFiles`). What the checkout's attributes say still decides
/// what a change is: a clean filter (`filter=…`, `.git/info/attributes` included) or an
/// `eol` or `text` attribute can make a worktree that differs from `HEAD` read clean,
/// and a flag can't turn either off. A submodule's own index is read as it is, so an
/// `assume-unchanged` edit or a stale `stat` inside one can read clean. A sparse
/// checkout's files outside its cone read as deleted, so its tree reads dirty.
pub(super) const DIRTY_TREE_STATUS: &str = concat!(
    entries_index!(),
    dirty_git!(),
    " status --porcelain --untracked-files=normal --ignore-submodules=none",
);

/// The git commands [`dirty_id`] reads the working tree through, in order: the changes
/// to tracked files, the untracked files git doesn't ignore, and (with any) the blob ids
/// of their contents, each against [`entries_index!`]'s copy of the index with the
/// settings [`dirty_git!`] forces. Each covers the whole work tree whatever directory
/// zap runs from (as the dirty check, `git status`, does), with names relative to its
/// top; none applies a configured external diff or `textconv` (the checkout's
/// attributes still apply: see [`DIRTY_TREE_STATUS`]), and none writes to the
/// repository. The blob ids come through `xargs`, so no list of names is ever one
/// command line. An untracked nested repository is listed as one `name/` entry and
/// never hashed: it counts by its name alone. An untracked symlink counts by its target
/// path, as git records one (dangling or naming a directory alike), on an `l <id>` line.
/// Every counted name gets its line in name order, so which name is the symlink names
/// the tree; the regular files between two symlinks are hashed in one call. Names reach
/// every command as arguments, never as shell text.
pub(super) const DIRTY_TREE_DIFF: &str = concat!(
    entries_index!(),
    dirty_git!(),
    " diff HEAD --binary --no-ext-diff --no-textconv --no-color --no-relative \
     --ignore-submodules=none",
);
pub(super) const DIRTY_TREE_UNTRACKED: &str = concat!(
    entries_index!(),
    dirty_git!(),
    " ls-files -o --exclude-standard -z --full-name -- ':/'",
);
pub(super) const DIRTY_TREE_BLOBS: &str = concat!(
    entries_index!(),
    "zap_top=$(",
    dirty_git!(),
    " rev-parse --show-toplevel) && cd -- \"$zap_top\" && ",
    dirty_git!(),
    " ls-files -o --exclude-standard -z --full-name -- ':/' | ",
    "xargs -0 sh -c 'zap_n=$#; for f do [ \"$zap_n\" -eq 0 ] || { zap_n=0; set --; }; ",
    "case $f in */) ;; *) if [ -L \"$f\" ]; then ",
    "[ $# -eq 0 ] || ",
    dirty_git!(),
    " hash-object --no-filters -- \"$@\" || exit 1; set --; ",
    "zap_t=$(readlink -- \"$f\" && echo x) || exit 1; ",
    "zap_id=$(printf %s \"${zap_t%?x}\" | ",
    dirty_git!(),
    " hash-object --stdin) || exit 1; ",
    "printf \"l %s\\n\" \"$zap_id\"; ",
    "else set -- \"$@\" \"$f\"; fi;; esac; done; ",
    "[ $# -eq 0 ] || ",
    dirty_git!(),
    " hash-object --no-filters -- \"$@\"' zap",
);

/// The id of an uncommitted tree: 8 lowercase hex of the blake3 over what the tree adds
/// to `HEAD` — its tracked changes, and its untracked files' names and contents (a
/// symlink's target path) — read as the bytes git prints, never a decoded text.
///
/// A function of the tree alone (no clock, no stash commit), so a dry run and the
/// wetrun bound to it name the same release, and two different dirty trees on one
/// commit are two releases rather than one extracted over the other.
///
/// # Errors
/// [`Error::Git`] when a read fails, or when the blob ids don't answer the untracked
/// names one for one (a file that went away between the reads).
pub(super) async fn dirty_id(local: &Connection, masker: &SecretMasker) -> Result<String> {
    let read = |command: &'static str| async move {
        local
            .run_stdout_bytes(command)
            .await?
            .map_err(|out| git_error("the uncommitted tree", command, &out, masker))
    };
    let diff = read(DIRTY_TREE_DIFF).await?;
    let untracked = read(DIRTY_TREE_UNTRACKED).await?;
    // a `name/` entry is an untracked nested repository, which gets no blob id
    let names = untracked
        .split(|&b| b == 0)
        .filter(|n| !n.is_empty() && !n.ends_with(b"/"))
        .count();
    let blobs = if names == 0 {
        Vec::new()
    } else {
        read(DIRTY_TREE_BLOBS).await?
    };
    let lines: Vec<&[u8]> = blobs
        .split(|&b| b == b'\n')
        .filter(|id| !id.is_empty())
        .collect();
    if lines.len() != names {
        return Err(Error::Git(format!(
            "could not read the uncommitted tree (`{DIRTY_TREE_BLOBS}`): {} blob id(s) for \
             {names} untracked file(s) — the tree changed while it was read",
            lines.len()
        )));
    }
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"zap-dirty-tree\0");
    for part in [&diff, &untracked, &blobs] {
        hasher.update(&(part.len() as u64).to_le_bytes());
        hasher.update(part);
    }
    let hex = hasher.finalize().to_hex();
    Ok(hex[..8].to_owned())
}
