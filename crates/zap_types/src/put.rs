//! The constant shell scripts every privileged file write, directory creation,
//! directory mode/owner change, and validated write's snapshot runs, and the commands
//! that call them.
//!
//! A path zap writes can sit in a directory someone other than root may write: an
//! application's `shared/` owned by its service account, a managed user's `~/.ssh`. A
//! write that names a file there twice (stage, then rename), or changes a mode or owner
//! by name after the write, acts on whatever that name holds at each instant — a
//! symbolic link planted between two steps sends root's write, `chmod`, or `chown`
//! somewhere else. Each script holds what it acts on **open** and acts through the
//! descriptor (`/proc/self/fd/3`), so the name can change underneath it without
//! moving the effect.
//!
//! Each is one constant text, passed as one single-quoted word to `sh -c`; everything
//! that varies arrives as a positional argument or on stdin, so nothing config-derived
//! is parsed by a shell. None holds a `'` (it would end the word), a reference delimiter (a plan
//! step's text is scanned for references), or a newline.
//!
//! One definition, shared by the planner (the steps that install a file: a `user`'s
//! keys and sudoers, an `apt_repo`'s list, the nftables ruleset, a `swap`'s fstab
//! entry) and `zap_core`'s connection (every content write and directory change, and
//! deploy's archive upload), so a plan step and an executor write install a file the
//! same way.

use serde::{Deserialize, Serialize};

use crate::shell::single_quote;

/// The exit status of a refusal a script here makes itself, as opposed to a failure of
/// a tool it runs.
///
/// A refusal is the script's own verdict on what it was asked or on what it found — a
/// path it won't write, content that isn't what was sent, a symbolic link where a
/// directory should be, a tool or `/proc` the target lacks — and running it again with
/// more privilege gives the same answer. A step that fails because the operation was
/// not permitted, or because the disk is full, exits with the failing tool's own status
/// (1 for `chown`, `chmod`, `cat`, `sync`, `mv`, and the scripts' own `exit 1`; 2 for a
/// shell redirection error; 126 / 127 for a command that can't be run).
///
/// 93 is none of those, nor a status zap reads elsewhere: the command wrapper's 98 for
/// a stream that isn't a frame, the detection batch's 95–97, `timeout`'s 124 / 125, a
/// signal's 128 and up, or the `sysexits` range 64–78.
pub const REFUSED_EXIT: i32 = refused_exit!();

/// [`REFUSED_EXIT`] as a literal, for a script's `concat!`.
macro_rules! refused_exit {
    () => {
        93
    };
}
pub(crate) use refused_exit;

/// [`HARD_LINK_REFUSAL`] as a literal, for a script's `concat!`.
macro_rules! hard_link_refusal_text {
    () => {
        "it has more than one hard link, so it is not read: replace it with a copy of its \
         own (a single link)"
    };
}

/// Why a root read refuses a regular file with more than one hard link — the scripts'
/// refusal and the native reads' error alike.
///
/// A hard link is the same file under another name, which an account can make in a
/// directory it writes — to a file it doesn't own, where `fs.protected_hardlinks` is
/// off. A root read of the declared path would then read, compare, or copy that file,
/// whoever owns it. A file of one link is the declared path's own; no owner is exempt.
pub const HARD_LINK_REFUSAL: &str = hard_link_refusal_text!();

/// The fragment that refuses (`refusal!`'s `no`) the file held open when `$count`, its
/// link count read from the descriptor, isn't 1 ([`HARD_LINK_REFUSAL`]).
macro_rules! hard_link_refusal {
    ($count:literal) => {
        concat!(
            r#"[ ""#,
            $count,
            r#"" = 1 ] || no ""#,
            hard_link_refusal_text!(),
            r#""; "#
        )
    };
}

/// The fragment that defines a script's `no`, the refusal: it prints `zap: <path>: ` (the
/// path from `$p`), its argument, and `$outcome`, which says what was left as it was —
/// it begins with `; `, or is empty — and exits [`REFUSED_EXIT`].
macro_rules! refusal {
    ($outcome:literal) => {
        concat!(
            r#"no() { echo "zap: $p: $1"#,
            $outcome,
            r#"" >&2; exit "#,
            $crate::put::refused_exit!(),
            "; }; ",
        )
    };
}
pub(crate) use refusal;

/// [`NOT_ABSOLUTE_REFUSAL`] as a literal, for a script's `concat!`.
macro_rules! not_absolute_refusal {
    () => {
        "not an absolute path"
    };
}
pub(crate) use not_absolute_refusal;

/// The fragment that refuses a `$p` that isn't an absolute path
/// ([`NOT_ABSOLUTE_REFUSAL`]).
macro_rules! absolute_path {
    () => {
        concat!(
            r#"case $p in /*) ;; *) no ""#,
            $crate::put::not_absolute_refusal!(),
            r#"";; esac; "#,
        )
    };
}
pub(crate) use absolute_path;

/// The fragment that drops the trailing slashes of `$p`, `/` itself kept: a path ending
/// in one names what a link at it points to.
macro_rules! strip_trailing_slashes {
    () => {
        r#"while :; do case $p in ?*/) p=${p%/};; *) break;; esac; done; "#
    };
}
pub(crate) use strip_trailing_slashes;

/// The fragment that refuses, naming the first one missing, unless every tool in
/// `$tools` (a space-separated list) is on `PATH`.
macro_rules! need_tools {
    ($tools:literal) => {
        concat!(
            "for t in ",
            $tools,
            r#"; do command -v $t >/dev/null || no "no $t on this machine"; done; "#,
        )
    };
}
pub(crate) use need_tools;

/// The refusal of a machine without `/proc`, as a literal for a script's `concat!`:
/// [`NO_PROC_REFUSAL`], or with what the script would `$hold` through it said instead.
macro_rules! no_proc_refusal {
    () => {
        $crate::put::no_proc_refusal!("hold it open through")
    };
    ($hold:literal) => {
        concat!("no /proc on this machine to ", $hold)
    };
}
pub(crate) use no_proc_refusal;

/// The fragment that refuses unless the directory of `$fd` (`/proc/self/fd`) is there
/// (`no_proc_refusal!`, with any `$hold` it is given).
macro_rules! need_proc {
    ($($hold:literal)?) => {
        concat!(
            r#"[ -d ${fd%/*} ] || no ""#,
            $crate::put::no_proc_refusal!($($hold)?),
            r#""; "#,
        )
    };
}
pub(crate) use need_proc;

/// Why a script here, or `zap_core`'s native write beside it, refuses a path that isn't
/// absolute.
pub const NOT_ABSOLUTE_REFUSAL: &str = not_absolute_refusal!();

/// Why [`FILE_PUT`], or the native write, refuses a path with no file name (`/`, or a
/// last component of `.` or `..`).
pub const NO_FILE_NAME_REFUSAL: &str = "no file name in the path";

/// Why [`DIR_ATTRS`], [`EXTRACT_ARCHIVE`](crate::extract::EXTRACT_ARCHIVE), or the
/// native directory change, refuses a path whose last component is `.` or `..`: it
/// names what a link points at, not a directory of its own.
pub const NOT_A_DIRECTORY_NAME_REFUSAL: &str = "it does not name a directory itself";

/// Why [`MAKE_DIRS`], or the native directory creation, refuses a missing component
/// that is `.`, `..`, or empty.
pub const MISSING_COMPONENT_REFUSAL: &str = "a missing component is not a name to make";

/// Why [`MAKE_DIRS`], or the native directory creation, refuses a nearest existing
/// entry that doesn't lead to a directory.
pub const NOTHING_MADE_REFUSAL: &str = "not a directory, nothing made";

/// Why [`FILE_PUT`], or the native write, refuses to keep the mode of a file with an
/// extended POSIX access list.
pub const ACCESS_LIST_KEEP_REFUSAL: &str =
    "it has an access list (ACL), which keeping its mode would drop; declare its mode";

/// Why a script here that holds what it acts on open through `/proc/self/fd`, or the
/// native directory change, can't on a machine without `/proc`. [`FILE_PUT`] says it
/// of its staged copy instead.
pub const NO_PROC_REFUSAL: &str = no_proc_refusal!();

/// The fragment [`FILE_PUT`], [`MAKE_DIRS`], and
/// [`EXTRACT_ARCHIVE`](crate::extract::EXTRACT_ARCHIVE) run after `cd -P` into the
/// directory they act in: it sets `w` to `open` when a directory on either chain to it
/// has its sticky bit set or is writable by every account, else to nothing. Its
/// argument names the shell variable holding the directory's absolute path as declared.
///
/// Two chains, in a subshell:
///
/// - The resolved one: up from the shell's own working directory, `cd -P ..` at a time
///   (the kernel's `..`, never a name), reading each directory's mode and identity from
///   `.` in one `stat`, to the root, whose `..` is itself (the same device and inode
///   twice).
/// - The declared one: every prefix of the declared path, the path itself first and `/`
///   last, each read with `stat -L`, so a component that is a symbolic link is read as
///   what it leads to — and a link planted in a shared directory (an attacker's
///   `/tmp/cache` pointing at a directory of theirs) is seen there, where the resolved
///   chain, which only passes through the link's target, can't see it. Each step drops
///   a component, so the walk ends whatever the path holds.
///
/// A `stat` or a `cd` that fails fails the script with nothing made. Below a directory
/// anyone may put an entry in, anyone could have made or renamed in what is under it,
/// so nothing there says what its owner meant. Neither chain sees a link met on the way
/// that leads through a second link sitting in a shared directory off both chains.
macro_rules! crossed_walk {
    ($declared:literal) => {
        concat!(
            r#"w=$(c=; while s=$(stat -c %f:%d:%i .) && [ -n "$s" ] || exit 1; [ "${s#*:}" != "$c" ]; do "#,
            r#"[ $((0x${s%%:*} & 01002)) -eq 0 ] || { echo open; exit 0; }; c=${s#*:}; cd -P .. || exit 1; done; "#,
            r#"x=$"#,
            $declared,
            r#"; while :; do s=$(stat -L -c %f -- "${x:-/}") && [ -n "$s" ] || exit 1; "#,
            r#"[ $((0x$s & 01002)) -eq 0 ] || { echo open; exit 0; }; case $x in */*) x=${x%/*};; *) exit 0;; esac; done) || exit 1; "#,
        )
    };
}
pub(crate) use crossed_walk;

/// The fragment that reads whether `$operand` carries an extended POSIX access list
/// (ACL) into the shell variable named `$var`: empty when it has none.
///
/// `getfacl` reads it when the target has it (`-c`: no header; `-s`: nothing for a file
/// with only the base entries), else GNU `ls -l` shows it as the `+` after the mode;
/// `BusyBox` `ls` prints none, so a target with neither shows no list. A read that fails
/// fails the script. `$getfacl` and `$ls` are the flags: `-p` where the operand is an
/// absolute path (`getfacl` otherwise says on stderr that it drops the leading `/`), and
/// `-L` where it may be a symbolic link, read as what it leads to.
///
/// The `format:` form is the same text with its braces doubled, for a `format!` string
/// whose operand is one of its arguments.
macro_rules! acl_read {
    ($var:literal, $getfacl:literal, $ls:literal, $operand:literal) => {
        $crate::put::acl_read!(@ $var, $getfacl, $ls, $operand, "{", "}")
    };
    (format: $var:literal, $getfacl:literal, $ls:literal, $operand:literal) => {
        $crate::put::acl_read!(@ $var, $getfacl, $ls, $operand, "{{", "}}")
    };
    (@ $var:literal, $getfacl:literal, $ls:literal, $operand:literal, $open:literal, $close:literal) => {
        concat!(
            "if command -v getfacl >/dev/null; then ",
            $var, "=$(getfacl ", $getfacl, " -- ", $operand, ") || exit 1; ",
            "else ", $var, "=$(ls ", $ls, " -- ", $operand, ") || exit 1; ",
            "case $", $open, $var, "%% *", $close, " in *+) ;; *) ", $var, "=;; esac; fi; ",
        )
    };
}
pub(crate) use acl_read;

/// The fragment that stages a copy beside the file it will replace, in the shell's
/// working directory, and holds it open on descriptor 3 (`$fd`, `/proc/self/fd/3`),
/// followed by `$refuse` when what it holds isn't a new file of its own.
///
/// `mktemp` makes the name under `umask 077`: created exclusively, mode `0600` whatever
/// a default ACL on the directory would give, owned by the caller. It is opened for
/// reading, which creates nothing, so a name swapped for a link can't make a file
/// where it points; writes go through `$fd`. The script goes on only when what it holds
/// open is a regular file of the caller's (`id -u`, into `n`), empty, with one name, and
/// the staged name itself (not followed) is that file (same device and inode). Only
/// then does the `EXIT` trap remove the staged name: a name the script didn't make is
/// not its to remove. Sets `tmp`, `i`, and `n`; the umask stays `077`.
macro_rules! staged_copy {
    ($refuse:literal) => {
        concat!(
            r#"umask 077 && tmp=$(mktemp ./.zap.XXXXXX) || exit 1; "#,
            r#"exec 3<"$tmp" || exit 1; "#,
            r#"i=$(stat -L -c %d:%i:%u:%s:%h $fd) && [ -n "$i" ] && [ -f $fd ] && n=$(id -u) && "#,
            r#"[ "${i#*:*:}" = "$n:0:1" ] && [ "$(stat -c %d:%i "$tmp")" = "${i%:*:*:*}" ] || "#,
            $refuse,
            r#"; clean() { rm -f "$tmp"; }; trap clean EXIT; trap "exit 1" HUP INT TERM; "#,
        )
    };
}
pub(crate) use staged_copy;

/// The script that installs a file: stage, verify, set owner and mode, rename — in one
/// run, so no part of it can be skipped by a stream that ends early.
///
/// Positional parameters: the absolute path (`$1`), the octal mode or empty (`$2`), the
/// `chown` owner spec or empty (`$3`), a check to run on the staged file or empty
/// (`$4`; `sudoers` is the only one), and what an attribute left out takes (`$5`: empty
/// for a fresh file's, `keep` for what the path has; [`Unset`]). Its stdin is the
/// content's SHA-512 as one line of lowercase hex, then the content's bytes to the end
/// of the stream. The digest travels
/// on stdin, never an argv: a process list would show it, and a digest confirms a guess
/// at a short secret.
///
/// In order, with the path left as it was whenever a step can't be done. A step the
/// script refuses itself (`no`) says why and exits [`REFUSED_EXIT`]; a tool that fails
/// exits with its own status.
///
/// Before anything is created:
///
/// - The path must be absolute and end in a file name (not `/`, `.`, or `..`), and the
///   check and the attribute rule must be ones the script knows.
/// - Every tool the script runs must be on `PATH` — and, for the `sudoers` check,
///   `visudo` (from `PATH`, else `/usr/sbin/visudo`) — and `/proc/self/fd` must be
///   there. A target missing one is told which, rather than failing partway with
///   another step's message.
/// - The digest line is read with the shell's own `read` — a byte at a time on a pipe,
///   so nothing past its newline is consumed — and must be 128 characters. A stream cut
///   inside it is refused here.
///
/// Then:
///
/// - `cd -P` into the path's directory, once: the stage, the rename, and the cleanup
///   all name entries of that one directory (`./…`), so a path component replaced
///   afterwards redirects none of them. The directory must exist; a component that is a
///   symbolic link when the `cd` runs is followed.
/// - With `keep`, what the attributes left out take is read now. Below a directory with
///   its sticky bit set or that anyone may write (`/tmp`) — that directory or any above
///   it, on the chain the `cd` resolved or on the path as declared, a link read as what
///   it leads to (`crossed_walk!`) — it gives nothing, as without `keep`: anyone could
///   have put what is there, or made or renamed in a directory on the way.
///   Otherwise it is read from that directory's entry by its name with no link followed
///   (one `stat`): a regular file there with one name (a link count of 1) gives its
///   owner, its group, and its mode less any set-id or sticky bit; nothing there gives
///   the directory's own owner and group (the mode stays a plain create's); anything
///   else there — a symbolic link, a directory, a file with another name elsewhere —
///   gives nothing, as without `keep`. An entry that is there but can't be read fails
///   the script with nothing created. Only what was left out is filled: a declared
///   owner, group, or mode stands.
/// - A mode to keep from a file with an extended POSIX access list (ACL) is refused:
///   its mode bits show the list's mask, not its group's, and the new file would carry
///   no list, so keeping them would widen what its group may do. The config is asked to
///   declare the mode. The list is read with `getfacl` when the target has it, else
///   from the `+` GNU `ls -l` prints after the mode; `BusyBox` `ls` prints none, so a
///   target with neither can't show one, and the mode is kept.
/// - The staged file is made by `mktemp` in the same directory (so the rename never
///   crosses a filesystem): created exclusively, mode `0600` whatever the umask or a
///   default ACL on the directory would give, owned by the caller. It is opened for
///   reading — which creates nothing, so a name swapped for a link can't make a file
///   where it points — and the script goes on only when what it holds open is a regular
///   file of the caller's, empty, with one name, and the staged name itself (not
///   followed) is that file (same device and inode); else it refuses with nothing
///   written. Only from here is the staged name the script's to remove. A name swapped
///   for a link to a fifo there holds the open waiting for a writer.
/// - The content is written through `/proc/self/fd/3` (the file held open, whatever
///   its name has become), and its SHA-512 — read back from the file —
///   must be the digest sent. A stream cut anywhere in the content, or altered, is
///   refused here.
/// - The owner, then the mode, are set through the descriptor: on the file created, not
///   on a name. Each value follows `--`, so it is never read as an option. The owner
///   goes first, since `chown` clears the set-id bits a mode may carry. With no mode
///   given or kept, the file gets the one a plain create would: `0666` less the caller's
///   umask.
/// - The `sudoers` check runs `visudo -cf` on the staged file; one it rejects is refused.
/// - The file is flushed to disk (`sync`), and the staged name must still be the file
///   held open (same device and inode, the name itself not followed), else the script
///   refuses to install something it didn't write.
/// - `mv -fT` renames it over the path, so a reader sees the old content or the new.
///   Nothing at the path is followed or entered: a symbolic link to a file is replaced
///   by the file; a directory fails the `mv`; a symbolic link to a directory is replaced
///   under coreutils and fails the `mv` — left in place — under `BusyBox`.
///
/// A failure after the stage exists removes it. An error names the path, never the
/// content or the digest.
pub const FILE_PUT: &str = concat!(
    r#"p=$1; mode=$2; own=$3; chk=$4; keep=$5; fd=/proc/self/fd/3; "#,
    refusal!("; left unchanged"),
    absolute_path!(),
    r#"d=${p%/*}; b=${p##*/}; [ -n "$d" ] || d=/; "#,
    r#"case $b in ""|.|..) no "no file name in the path";; esac; "#,
    r#"case $chk in ""|sudoers) ;; *) no "unknown check $chk";; esac; "#,
    r#"case $keep in ""|keep) ;; *) no "unknown attribute rule $keep";; esac; "#,
    need_tools!("mktemp cat sha512sum chown chmod sync stat mv rm id ls"),
    r#"[ -z "$chk" ] || { v=$(command -v visudo) || v=/usr/sbin/visudo; "#,
    r#"[ -x "$v" ] || no "no visudo on this machine to check it with"; }; "#,
    need_proc!("hold its staged copy through"),
    r#"IFS= read -r want && [ ${#want} -eq 128 ] || no "its content did not arrive"; "#,
    r#"CDPATH= cd -P -- "$d" || exit 1; "#,
    r#"km=; ko=; if [ -n "$keep" ]; then q=$(stat -c %f:%u:%g .) && [ -n "$q" ] || exit 1; "#,
    crossed_walk!("d"),
    r#"[ -z "$w" ] || keep=; fi; "#,
    r#"if [ -z "$keep" ]; then :; elif [ -e "./$b" ] || [ -L "./$b" ]; then "#,
    r#"s=$(stat -c %f:%h:%u:%g -- "./$b") && [ -n "$s" ] || exit 1; f=${s%%:*}; s=${s#*:}; "#,
    r#"if [ $((0x$f & 0170000)) -eq 32768 ] && [ "${s%%:*}" = 1 ]; then km=$(printf %o $((0x$f & 0777))) && ko=${s#*:} || exit 1; fi; "#,
    r#"else ko=${q#*:}; fi; "#,
    r#"[ -z "$ko" ] || case $own in "") own=$ko;; :*) own=${ko%:*}$own;; *:*) ;; *) own=$own:${ko#*:};; esac; "#,
    r#"if [ -z "$mode" ] && [ -n "$km" ]; then "#,
    acl_read!("a", "-cs", "-ld", r#""./$b""#),
    r#"[ -z "$a" ] || no "it has an access list (ACL), which keeping its mode would drop; declare its mode"; fi; "#,
    r#"[ -n "$mode" ] || mode=$km; "#,
    r#"u=$(umask) && "#,
    staged_copy!(r#"no "no new file to stage it in""#),
    r#"cat >$fd || exit 1; "#,
    r#"got=$(sha512sum <$fd) || exit 1; "#,
    r#"[ "${got%% *}" = "$want" ] || no "the bytes received are not the bytes sent"; "#,
    r#"[ -z "$own" ] || chown -- "$own" $fd || exit 1; "#,
    r#"[ -n "$mode" ] || mode=$(printf %o "$((0666 & ~0$u))") || exit 1; "#,
    r#"chmod -- "$mode" $fd || exit 1; "#,
    r#"[ -z "$chk" ] || "$v" -cf $fd >/dev/null || no "visudo did not accept the new content"; "#,
    r#"sync $fd || exit 1; "#,
    r#"i=$(stat -L -c %d:%i $fd) && [ -n "$i" ] && [ "$(stat -c %d:%i "$tmp")" = "$i" ] || "#,
    r#"no "its staged copy was replaced before it could be installed"; "#,
    r#"mv -fT "$tmp" "./$b" || exit 1; trap - EXIT"#,
);

/// The script a `link` is made with: the link is made under a fresh name beside the
/// path and renamed over it, except that a real directory at the path fails the step.
///
/// Run as `sh -c LINK_PUT sh <path> <target>`, under `sudo` over SSH and on this machine
/// when a native link is refused. A link at the path, even to a directory, is replaced.
///
/// - The new link is made inside a fresh directory (`mktemp -d`, `.zap-link.XXXXXX`) in
///   the path's parent, so no name an earlier run left, and nothing another account
///   placed, is reused; the directory is removed on every exit.
/// - It is renamed over the path (`mv -fT`): what stands at the path is replaced in one
///   step, so it never reads as missing. A rename refuses a directory there, so one put
///   at the path after the check is never linked into, as `ln -sfn` would link into it
///   and exit 0, leaving the resource residual on every run.
/// - `BusyBox` `mv -T` refuses to replace a link to a directory with a link to anything
///   else. Then, with a link still at the path, the link there is removed and the rename
///   made again: the path is missing between the two, and a directory put there in
///   between is still refused.
pub const LINK_PUT: &str = concat!(
    r#"if [ -d "$1" ] && [ ! -L "$1" ]; then echo "is a directory, not a link" >&2; exit 1; fi; "#,
    r#"t=$(mktemp -d "${1%/*}/.zap-link.XXXXXX") && [ -n "$t" ] || exit 1; "#,
    r#"cl() { rm -f -- "$t/l"; rmdir -- "$t"; }; trap cl EXIT; trap "exit 1" HUP INT TERM; "#,
    r#"ln -s -- "$2" "$t/l" || exit 1; "#,
    r#"e=$(mv -fT -- "$t/l" "$1" 2>&1) && exit 0; "#,
    r#"[ -L "$1" ] && rm -f -- "$1" && e=$(mv -fT -- "$t/l" "$1" 2>&1) && exit 0; "#,
    r#"if [ -d "$1" ] && [ ! -L "$1" ]; then echo "is a directory, not a link" >&2; else printf "%s\n" "$e" >&2; fi; exit 1"#,
);

/// The command [`LINK_PUT`] runs in, for `path` and `target`.
#[must_use]
pub fn link_put_command(sudo: &str, path: &str, target: &str) -> String {
    format!(
        "{sudo}sh -c {} sh {} {}",
        single_quote(LINK_PUT),
        single_quote(path),
        single_quote(target)
    )
}

/// The script that sets a directory's owner and mode without following a symbolic link
/// at its name.
///
/// Positional parameters: the absolute path (`$1`), the octal mode or empty (`$2`), and
/// the `chown` owner spec or empty (`$3`). Trailing slashes are dropped first (a path
/// ending in one names what a link points to), and a last component of `.` or `..` is
/// refused for the same reason. Its tools (`stat`, `chown`, `chmod`) and `/proc/self/fd`
/// must be there, and a target missing one is told which.
///
/// The path must lead to a directory (so the open that follows can't wait on a fifo). It
/// is then opened, and the script goes on only when the name itself — not followed — is
/// the directory held open: same device and inode, in one `stat` of the name. A
/// directory has one name, so at that instant the path named this directory directly,
/// and nothing between the first test and the open can have aimed the descriptor
/// elsewhere unnoticed. The owner, then the mode — each after `--`, so never read as an
/// option — are set through the descriptor, so a link swapped in afterwards changes
/// nothing they touch. A symbolic link at the path is refused with the link's target
/// untouched. A name swapped to a link to a fifo between the test and the open would
/// hold the open waiting for a writer; the `timeout` the script runs under
/// ([`dir_attrs_command`]) ends it.
///
/// Its own refusals exit [`REFUSED_EXIT`]; a tool that fails, or a directory the caller
/// may not open, exits with that failure's status.
pub const DIR_ATTRS: &str = concat!(
    r#"p=$1; mode=$2; own=$3; fd=/proc/self/fd/3; "#,
    refusal!("; left unchanged"),
    absolute_path!(),
    strip_trailing_slashes!(),
    r#"case ${p##*/} in .|..) no "it does not name a directory itself";; esac; "#,
    need_tools!("stat chown chmod"),
    need_proc!(),
    r#"[ -d "$p" ] || no "not a directory"; "#,
    r#"exec 3<"$p" || exit 1; "#,
    r#"i=$(stat -L -c %d:%i $fd) && [ -n "$i" ] && [ -d $fd ] && [ "$(stat -c %d:%i "$p")" = "$i" ] || "#,
    r#"no "not a directory of its own (a symbolic link is not followed)"; "#,
    r#"[ -z "$own" ] || chown -- "$own" $fd || exit 1; "#,
    r#"[ -z "$mode" ] || chmod -- "$mode" $fd"#,
);

/// The script that makes a directory and its missing parents, each made one given the
/// owner and group of the nearest directory that was already there.
///
/// Positional parameter: the absolute path (`$1`). Trailing slashes are dropped first.
/// Its tools (`stat`, `mkdir`, `chown`, `ls`, `id`) and `/proc/self/fd` must be there,
/// and a target missing one is told which.
///
/// In order, as `mkdir -p` would, but by descriptor:
///
/// - The path is walked up by name to the nearest entry that is there (a symbolic link
///   counts, dangling or not), collecting the missing components. A missing component of
///   `.` or `..`, or an empty one (`//`), is refused with nothing made.
/// - That entry must lead to a directory (a symbolic link to one is followed, as
///   `mkdir -p` follows it), else the script refuses. With nothing missing, that is all:
///   an existing directory's owner is never changed.
/// - `cd -P` into it. Then each missing component in turn: the mode, owner, and group of
///   the directory the script is in are read from `.` (one `stat`, so a name changed
///   since redirects none of them), and `mkdir` names the component there (`./…`; one
///   that appeared meanwhile is used if it is a directory, and not made). It is opened,
///   and the script goes on only when the name itself — not followed — is the directory
///   held open: same device and inode, in one `stat` of the name. A link swapped in is
///   refused, nothing made through it.
/// - One the script made is given the owner and group just read through the descriptor
///   (after `--`) — only when what the descriptor holds is still an empty directory the
///   caller owns (`ls -A`, `stat -L` against `id -u`). The owner of the directory it was
///   made in can rename a directory of theirs over the new one before the open, and
///   the checks above pass for it; root would then hand them that directory. So
///   anything else is refused, nothing given — a listing that fails too, said as such.
///   Once the walk is below a directory with its sticky bit set or that every account
///   may write (`/tmp`) — the nearest existing directory or any above it, on the chain
///   the `cd` resolved or on the path to it as declared (`crossed_walk!`), or one met on
///   the way down — nothing made from there on is given an owner, and it stays the
///   caller's: anyone could have made or renamed in what is below it.
/// - Then it is entered through the descriptor, so the next is made inside it whatever
///   its name has become.
///
/// So each directory made belongs to the owner of the directory it was made in, who
/// could have made it: the nearest existing directory's owner and group, down the
/// whole chain, when nothing moves underneath the script; anywhere below a directory
/// anyone may write, the caller's.
///
/// The mode of each directory made is `mkdir`'s: `0777` less the caller's umask. A name
/// swapped to a link to a fifo between the test and the open would hold the open
/// waiting for a writer; the `timeout` the script runs under ([`make_dirs_command`])
/// ends it. Its own refusals exit [`REFUSED_EXIT`]; a tool that fails exits with that
/// failure's status.
pub const MAKE_DIRS: &str = concat!(
    r#"p=$1; fd=/proc/self/fd/3; "#,
    refusal!(""),
    absolute_path!(),
    strip_trailing_slashes!(),
    need_tools!("stat mkdir chown ls id"),
    need_proc!(),
    r#"a=$p; t=; while [ ! -e "$a" ] && [ ! -L "$a" ]; do c=${a##*/}; "#,
    r#"case $c in ""|.|..) no "a missing component is not a name to make";; esac; "#,
    r#"t=$c${t:+/$t}; a=${a%/*}; [ -n "$a" ] || a=/; done; "#,
    r#"[ -d "$a" ] || no "not a directory, nothing made"; "#,
    r#"if [ -n "$t" ]; then CDPATH= cd -P -- "$a" || exit 1; "#,
    crossed_walk!("a"),
    r#"set -f; IFS=/; set -- $t; unset IFS; "#,
    r#"for c do q=$(stat -c %f:%u:%g .) && [ -n "$q" ] || exit 1; o=${q#*:}; "#,
    r#"[ -z "$w" ] && [ $((0x${q%%:*} & 01002)) -eq 0 ] || { w=1; o=; }; "#,
    r#"n=; [ -d "./$c" ] || { mkdir -- "./$c" || exit 1; n=1; }; "#,
    r#"exec 3<"./$c" || exit 1; "#,
    r#"i=$(stat -L -c %d:%i $fd) && [ -n "$i" ] && [ -d $fd ] && [ "$(stat -c %d:%i "./$c")" = "$i" ] || "#,
    r#"no "$c is not a directory of its own (a symbolic link is not followed)"; "#,
    r#"if [ -n "$n" ] && [ -n "$o" ]; then "#,
    r#"e=$(ls -A $fd/) || no "$c could not be listed, so it is given no owner"; "#,
    r#"[ -z "$e" ] && u=$(id -u) && [ "$(stat -L -c %u $fd)" = "$u" ] || "#,
    r#"no "$c is not the empty directory just made, so it is given no owner"; "#,
    r#"chown -- "$o" $fd || exit 1; fi; "#,
    r#"CDPATH= cd -P -- $fd || exit 1; done; fi"#,
);

/// The script that reads what a validated write is about to replace — the bytes and the
/// mode, owner, and group of the file at a path — through one descriptor, never
/// through a symbolic link at its name.
///
/// Positional parameters: the absolute path (`$1`) and the most bytes the snapshot may
/// hold (`$2`). Its tools (`stat`, `head`) and `/proc/self/fd` must be there, and a
/// target missing one is told which.
///
/// A symbolic link at the path is refused, dangling or not: what a rollback puts back
/// is a regular file, and the bytes behind a link are some other file's. Nothing at the
/// path answers `absent` on a line of its own — only when the path's directory is one
/// the caller can enter (a `cd` the kernel checks, so access lists and security modules
/// count, which a shell's `test -x` reading the mode bits can miss): a name that can't
/// be looked up is no absence (a rollback would remove what is there), so that fails,
/// as a failure and not a refusal, which a caller without the permission may retry with
/// it. Anything else that isn't a regular file
/// — a directory, a fifo, a device — is refused before it is opened, so a fifo can't
/// hold the open waiting for a writer. The file is then opened, and the script goes on
/// only when the descriptor is a regular file and the name itself — not followed — is
/// the file held open: same device and inode. Its mode, owner, group, and size come from
/// one `stat` of the descriptor, and its bytes from the descriptor itself, so the name
/// changing underneath it moves neither.
///
/// Its output is one line, `file <mode> <uid> <gid> <size>` (the mode in octal, the ids
/// in decimal), then exactly `size` bytes: `head -c` reads no more, and a file whose
/// size moved while it was read is refused after it. A file larger than `$2` is
/// refused before a byte is read.
///
/// What it can't close is the instant between the tests and the open: a name swapped
/// to a link there is opened through (and then refused, not read), and a link to a fifo
/// holds the open until the `timeout` it runs under ([`file_snapshot_command`]) ends it.
/// Its own refusals exit [`REFUSED_EXIT`]; a tool that fails exits with that failure's
/// status.
pub const FILE_SNAPSHOT: &str = concat!(
    r#"p=$1; max=$2; fd=/proc/self/fd/3; "#,
    refusal!("; left unchanged"),
    absolute_path!(),
    r#"case $max in ""|*[!0-9]*) no "no byte limit to hold it to";; esac; "#,
    need_tools!("stat head"),
    need_proc!(),
    r#"[ ! -L "$p" ] || no "a symbolic link is not read through"; "#,
    r#"if [ ! -e "$p" ]; then d=${p%/*}; [ -n "$d" ] || d=/; "#,
    r#"( CDPATH= cd -P -- "$d" ) 2>/dev/null || { echo "zap: $p: its directory cannot be searched" >&2; exit 1; }; "#,
    r#"echo absent; else "#,
    r#"[ -f "$p" ] || no "not a regular file"; "#,
    r#"exec 3<"$p" || exit 1; "#,
    r#"m=$(stat -L -c "%d:%i %a %u %g %s %h" $fd) && [ -f $fd ] && [ "$(stat -c %d:%i "$p")" = "${m%% *}" ] || "#,
    r#"no "not a regular file of its own (a symbolic link is not followed)"; "#,
    r#"set -- $m; "#,
    hard_link_refusal!("$6"),
    r#"[ "$5" -le "$max" ] || no "larger than the $max bytes a snapshot holds"; "#,
    r#"echo "file $2 $3 $4 $5"; "#,
    r#"head -c "$5" <&3 || exit 1; "#,
    r#"[ "$(stat -L -c %s $fd)" = "$5" ] || no "it changed while it was read"; fi"#,
);

/// The script that prints the bytes of the regular file at a path (`$1`), for a read
/// that compares them whole (an uncached `remote` file's detection).
///
/// A symbolic link at the path, dangling or not, is refused, and so is anything there
/// that isn't a regular file — a directory, a device, a fifo — before it is opened: run
/// as root, opening a device can act on the machine, and reading one whole may never
/// end. The file is then opened, and its bytes are printed from that descriptor only
/// when it is a regular file and the name itself — not followed — is the file held
/// open: same device and inode, as [`FILE_SNAPSHOT`] holds it. Its tools (`stat`,
/// `cat`) and `/proc/self/fd` must be there, and a target missing one is told which.
/// Nothing there fails the open. Its refusals exit [`REFUSED_EXIT`], naming the path.
///
/// As with [`FILE_SNAPSHOT`], what it can't close is the instant between the tests and
/// the open: a name swapped to a link there is opened through, then refused, not read;
/// a link to a fifo holds the open until the `timeout` it runs under
/// ([`file_bytes_command`]) ends it.
pub const FILE_BYTES: &str = concat!(
    r#"p=$1; fd=/proc/self/fd/3; "#,
    refusal!(""),
    need_tools!("stat cat"),
    need_proc!(),
    r#"[ ! -L "$p" ] || no "a symbolic link is not read through"; "#,
    r#"[ ! -e "$p" ] || [ -f "$p" ] || no "not a regular file"; "#,
    r#"exec 3<"$p" || exit 1; "#,
    r#"m=$(stat -L -c %d:%i:%h $fd) && [ -f $fd ] && [ "$(stat -c %d:%i -- "$p")" = "${m%:*}" ] || "#,
    r#"no "not a regular file of its own (a symbolic link is not followed)"; "#,
    hard_link_refusal!("${m##*:}"),
    r#"exec cat <&3"#,
);

/// The command that runs [`FILE_BYTES`] for `path`, after `prefix` (`sudo ` to read as
/// root, nothing to read as the caller), under `timeout` to [`SCRIPT_TIMEOUT_SECS`].
#[must_use]
pub fn file_bytes_command(prefix: &str, path: &str) -> String {
    format!(
        "{prefix}timeout {SCRIPT_TIMEOUT_SECS} sh -c {} sh {}",
        single_quote(FILE_BYTES),
        single_quote(path)
    )
}

/// The most bytes a validated write's snapshot holds ([`FILE_SNAPSHOT`]'s `$2`): the
/// snapshot is held in memory for the length of the write and its check, and a larger
/// file is refused before the write.
pub const SNAPSHOT_MAX_BYTES: u64 = 16 * 1024 * 1024;

/// How long [`FILE_SNAPSHOT`], [`FILE_BYTES`], [`DIR_ATTRS`], and [`MAKE_DIRS`] may run,
/// in seconds.
///
/// Each runs under `timeout`, so a name swapped to a link to a fifo in the instant
/// before the open — which would hold the open waiting for a writer — fails the step
/// instead of stalling it. Generous, so a whole [`SNAPSHOT_MAX_BYTES`] snapshot over a
/// slow link fits.
///
/// [`FILE_PUT`] runs unbounded: it opens only the staged file it creates itself, so no
/// swapped name can stall it, its run is the content's transfer, which a slow link and
/// a large file make as long as they make it, and a `SIGTERM` would skip the shell's
/// `EXIT` trap that removes the staged file.
pub const SCRIPT_TIMEOUT_SECS: u32 = 300;

/// Whether `code` is a `timeout` expiry: GNU `timeout` exits 124, `BusyBox`'s 143 (its
/// `SIGTERM`), the reading detection's probes use too.
#[must_use]
pub const fn script_timed_out(code: i32) -> bool {
    matches!(code, 124 | 143)
}

/// The command that runs [`FILE_SNAPSHOT`] for `path`, held to [`SNAPSHOT_MAX_BYTES`] and,
/// under `timeout`, to [`SCRIPT_TIMEOUT_SECS`].
#[must_use]
pub fn file_snapshot_command(run_as: RunAs<'_>, path: &str) -> String {
    format!(
        "{}timeout {SCRIPT_TIMEOUT_SECS} sh -c {} sh {} {SNAPSHOT_MAX_BYTES}",
        run_as.prefix(),
        single_quote(FILE_SNAPSHOT),
        single_quote(path),
    )
}

/// What [`FILE_SNAPSHOT`] found at a path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Snapshot {
    /// Nothing was there.
    Absent,
    /// A regular file: its bytes, and the mode, owner, and group of the file they were
    /// read from.
    File {
        /// The mode, set-id and sticky bits included, as `stat` reported it.
        mode: u32,
        /// The owner's uid.
        uid: u32,
        /// The group's gid.
        gid: u32,
        /// The content.
        bytes: Vec<u8>,
    },
}

/// Read [`FILE_SNAPSHOT`]'s output, or `None` when it isn't one.
///
/// One is an `absent` line alone, or a `file` line whose mode is octal, whose ids are
/// decimal, and whose size is at most [`SNAPSHOT_MAX_BYTES`] and exactly the length of
/// the bytes that follow it.
#[must_use]
pub fn parse_snapshot(output: &[u8]) -> Option<Snapshot> {
    let newline = output.iter().position(|&byte| byte == b'\n')?;
    let (line, rest) = (
        std::str::from_utf8(&output[..newline]).ok()?,
        &output[newline + 1..],
    );
    if line == "absent" {
        return rest.is_empty().then_some(Snapshot::Absent);
    }
    let digits = |field: &str| !field.is_empty() && field.bytes().all(|b| b.is_ascii_digit());
    let [kind, mode, uid, gid, size] = line.split(' ').collect::<Vec<_>>()[..] else {
        return None;
    };
    if kind != "file" || ![mode, uid, gid, size].into_iter().all(digits) {
        return None;
    }
    let mode = u32::from_str_radix(mode, 8)
        .ok()
        .filter(|mode| *mode <= 0o7777)?;
    let size: u64 = size.parse().ok()?;
    if size > SNAPSHOT_MAX_BYTES || u64::try_from(rest.len()).ok() != Some(size) {
        return None;
    }
    Some(Snapshot::File {
        mode,
        uid: uid.parse().ok()?,
        gid: gid.parse().ok()?,
        bytes: rest.to_vec(),
    })
}

/// What a file write gives the mode, owner, and group its [`FileAttrs`] leave out.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Unset {
    /// What a plain create by the writer gives: the writer's owner and group, and `0666`
    /// less its umask. zap's own files and the files a plan's steps install (a user's
    /// keys and sudoers, an apt list, the nftables ruleset, `/etc/fstab`) take this:
    /// their owner is the writer's whatever someone left at the path.
    #[default]
    Fresh,
    /// What the path already has: a regular file there keeps its owner, group, and mode
    /// (less any set-id or sticky bit); with nothing there, the new file takes its
    /// directory's owner and group and a plain create's mode; anything else there (a
    /// symbolic link, which the write replaces, or a file with a second name — a hard
    /// link) gives nothing, as [`Fresh`](Self::Fresh). So does anywhere below a directory
    /// with its sticky bit set or that anyone may write (`/tmp`), on the path as written
    /// or as its links resolve, whatever is there: anyone could have put it there. A
    /// mode to keep from a file with an extended POSIX access list is refused, the mode
    /// left to be declared. A `file` resource's write takes this, so what it leaves
    /// unset is left as it is.
    Keep,
}

impl Unset {
    /// [`FILE_PUT`]'s `$5`.
    const fn word(self) -> &'static str {
        match self {
            Self::Fresh => "",
            Self::Keep => "keep",
        }
    }
}

/// The mode and ownership a write gives the file it installs, or a directory is set to.
/// Each is applied only when given; what a file write gives the rest is `unset`'s.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FileAttrs<'a> {
    /// The octal mode (`"600"`).
    pub mode: Option<&'a str>,
    /// The owning user's name.
    pub owner: Option<&'a str>,
    /// The owning group's name.
    pub group: Option<&'a str>,
    /// What a file write gives what is left out. A directory change sets only what is
    /// given, whatever this says.
    pub unset: Unset,
}

impl<'a> FileAttrs<'a> {
    /// No mode, owner, or group.
    pub const NONE: Self = Self {
        mode: None,
        owner: None,
        group: None,
        unset: Unset::Fresh,
    };

    /// A mode alone.
    #[must_use]
    pub const fn mode(mode: &'a str) -> Self {
        Self {
            mode: Some(mode),
            ..Self::NONE
        }
    }

    /// These attributes, with what they leave out kept from what the path holds
    /// ([`Unset::Keep`]).
    #[must_use]
    pub const fn keeping(self) -> Self {
        Self {
            unset: Unset::Keep,
            ..self
        }
    }

    /// Whether nothing is given.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.mode.is_none() && self.owner.is_none() && self.group.is_none()
    }

    /// The `chown` spec for the owner and group — `owner:group`, `owner`, `:group` — or
    /// `None` with neither.
    #[must_use]
    pub fn owner_spec(&self) -> Option<String> {
        match (self.owner, self.group) {
            (Some(owner), Some(group)) => Some(format!("{owner}:{group}")),
            (Some(owner), None) => Some(owner.to_owned()),
            (None, Some(group)) => Some(format!(":{group}")),
            (None, None) => None,
        }
    }
}

/// Who a script runs as.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunAs<'a> {
    /// The shell's own user — no `sudo`.
    Caller,
    /// Root (`sudo`).
    Root,
    /// A named account (`sudo -u`): a write into a directory that account owns is made
    /// with its privileges, so nothing it plants there can aim the write at a file it
    /// couldn't have written itself.
    User(&'a str),
}

impl RunAs<'_> {
    /// The command prefix.
    pub(crate) fn prefix(self) -> String {
        match self {
            Self::Caller => String::new(),
            Self::Root => "sudo ".to_owned(),
            Self::User(name) => format!("sudo -u {} ", single_quote(name)),
        }
    }
}

/// A check [`FILE_PUT`] runs on the staged file before installing it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PutCheck {
    /// None.
    None,
    /// `visudo -cf`: a sudoers file that doesn't parse is never installed.
    Sudoers,
}

impl PutCheck {
    /// The script's `$4`.
    const fn word(self) -> &'static str {
        match self {
            Self::None => "",
            Self::Sudoers => "sudoers",
        }
    }
}

/// The command that runs [`FILE_PUT`] for `path`.
///
/// Its stdin must be the digest line and the content ([`FILE_PUT`]'s contract); the text
/// itself is the same for any content. It runs under no `timeout`
/// ([`SCRIPT_TIMEOUT_SECS`] says why).
#[must_use]
pub fn file_put_command(
    run_as: RunAs<'_>,
    path: &str,
    attrs: FileAttrs<'_>,
    check: PutCheck,
) -> String {
    put_command(
        run_as,
        path,
        &single_quote(attrs.mode.unwrap_or_default()),
        attrs,
        check,
    )
}

/// [`file_put_command`] with the mode given as `mode_word`: a shell word, already
/// quoted, in place of `attrs`' own mode.
fn put_command(
    run_as: RunAs<'_>,
    path: &str,
    mode_word: &str,
    attrs: FileAttrs<'_>,
    check: PutCheck,
) -> String {
    format!(
        "{}sh -c {} sh {} {mode_word} {} {} {}",
        run_as.prefix(),
        single_quote(FILE_PUT),
        single_quote(path),
        single_quote(&attrs.owner_spec().unwrap_or_default()),
        single_quote(check.word()),
        single_quote(attrs.unset.word()),
    )
}

/// The command that runs [`DIR_ATTRS`] for `path`, under `timeout`
/// ([`SCRIPT_TIMEOUT_SECS`]).
#[must_use]
pub fn dir_attrs_command(run_as: RunAs<'_>, path: &str, attrs: FileAttrs<'_>) -> String {
    format!(
        "{}timeout {SCRIPT_TIMEOUT_SECS} sh -c {} sh {} {} {}",
        run_as.prefix(),
        single_quote(DIR_ATTRS),
        single_quote(path),
        single_quote(attrs.mode.unwrap_or_default()),
        single_quote(&attrs.owner_spec().unwrap_or_default()),
    )
}

/// The command that runs [`MAKE_DIRS`] for `path`, under `timeout`
/// ([`SCRIPT_TIMEOUT_SECS`]).
#[must_use]
pub fn make_dirs_command(run_as: RunAs<'_>, path: &str) -> String {
    format!(
        "{}timeout {SCRIPT_TIMEOUT_SECS} sh -c {} sh {}",
        run_as.prefix(),
        single_quote(MAKE_DIRS),
        single_quote(path),
    )
}

/// A plan step that installs, through [`FILE_PUT`], the text a shell command prints.
///
/// `producer` is that command — the caller's own constant shape, with any
/// config-derived text already single-quoted in it. The step captures its output once
/// (a producer that fails fails the step, with nothing written), digests the capture
/// with the target's `sha512sum`, and pipes the digest line and the capture to the put.
/// So the bytes installed are the bytes the producer printed, whole: a producer that
/// stops partway can't leave a short file in place.
///
/// The capture is held in a shell variable and written by the shell's own `printf`, a
/// builtin in `dash`, `BusyBox` `ash`, and `bash` — it is on no argv there. It is text:
/// a NUL in the producer's output is dropped.
#[must_use]
pub fn put_text_step(
    producer: &str,
    run_as: RunAs<'_>,
    path: &str,
    attrs: FileAttrs<'_>,
    check: PutCheck,
) -> String {
    feed_put(producer, &file_put_command(run_as, path, attrs, check))
}

/// The feeder of [`put_text_step`]: capture `producer`'s output, digest it, and pipe the
/// digest line and the capture to `put`.
fn feed_put(producer: &str, put: &str) -> String {
    format!(
        "zap_c=$({producer} && echo .) || exit 1; zap_c=${{zap_c%.}}; \
         zap_h=$(printf %s \"$zap_c\" | sha512sum) || exit 1; \
         {{ printf \"%s\\n\" \"${{zap_h%% *}}\"; printf %s \"$zap_c\"; }} | {put}"
    )
}

/// [`put_text_step`] for a file that keeps the mode it has.
///
/// The step reads the mode of what `path` leads to (`stat -L`, so a link's target's, not
/// the link's own) and hands it to the put, so the rewrite changes content only. A file
/// that isn't there is installed at `attrs`' mode. A mode that can't be read fails the
/// step with nothing written.
///
/// A file with an extended POSIX access list (ACL) is refused, exiting
/// [`REFUSED_EXIT`] with nothing written: its mode bits show the list's mask, not its
/// group's, and the rewrite would carry no list. The list is read as [`FILE_PUT`] reads
/// it (`acl_read!`) — `getfacl` when the target has it, else GNU `ls`'s `+` — so
/// `BusyBox` alone can't show one.
///
/// The mode is read as the step's own user, before the producer runs; `attrs` must give
/// a mode.
#[must_use]
pub fn put_text_step_keeping_mode(
    producer: &str,
    run_as: RunAs<'_>,
    path: &str,
    attrs: FileAttrs<'_>,
    check: PutCheck,
) -> String {
    let quoted = single_quote(path);
    format!(
        concat!(
            "if [ -e {quoted} ]; then zap_m=$(stat -L -c %a {quoted}) && [ -n \"$zap_m\" ] || exit 1; ",
            acl_read!(format: "zap_a", "-cps", "-dlL", "{quoted}"),
            "[ -z \"$zap_a\" ] || {{ printf 'zap: %s: it has an access list (ACL), which keeping its mode \
             would drop; remove it (setfacl -b) to have it rewritten; left unchanged\\n' {quoted} >&2; \
             exit {refused}; }}; \
             else zap_m={mode}; fi; {put}",
        ),
        quoted = quoted,
        refused = REFUSED_EXIT,
        mode = single_quote(attrs.mode.unwrap_or_default()),
        put = feed_put(
            producer,
            &put_command(run_as, path, "\"$zap_m\"", attrs, check)
        ),
    )
}

#[cfg(test)]
mod tests {
    use super::{
        DIR_ATTRS, FILE_PUT, FILE_SNAPSHOT, FileAttrs, LINK_PUT, MAKE_DIRS, PutCheck, REFUSED_EXIT,
        RunAs, SCRIPT_TIMEOUT_SECS, SNAPSHOT_MAX_BYTES, Snapshot, Unset, dir_attrs_command,
        file_put_command, file_snapshot_command, link_put_command, make_dirs_command,
        parse_snapshot, put_text_step, put_text_step_keeping_mode, script_timed_out,
    };

    /// A refusal the native operations share with a script is the script's own text, so
    /// the two say one thing.
    #[test]
    fn the_shared_refusals_are_the_scripts_own() {
        use super::{
            ACCESS_LIST_KEEP_REFUSAL, MISSING_COMPONENT_REFUSAL, NO_FILE_NAME_REFUSAL,
            NO_PROC_REFUSAL, NOT_A_DIRECTORY_NAME_REFUSAL, NOT_ABSOLUTE_REFUSAL,
            NOTHING_MADE_REFUSAL,
        };
        use crate::extract::{EXTRACT_ARCHIVE, NOT_A_DIRECTORY_REFUSAL};
        for (name, script, refusals) in [
            (
                "FILE_PUT",
                FILE_PUT,
                &[
                    NOT_ABSOLUTE_REFUSAL,
                    NO_FILE_NAME_REFUSAL,
                    ACCESS_LIST_KEEP_REFUSAL,
                ][..],
            ),
            (
                "DIR_ATTRS",
                DIR_ATTRS,
                &[
                    NOT_ABSOLUTE_REFUSAL,
                    NOT_A_DIRECTORY_NAME_REFUSAL,
                    NO_PROC_REFUSAL,
                    NOT_A_DIRECTORY_REFUSAL,
                ][..],
            ),
            (
                "MAKE_DIRS",
                MAKE_DIRS,
                &[
                    NOT_ABSOLUTE_REFUSAL,
                    NO_PROC_REFUSAL,
                    MISSING_COMPONENT_REFUSAL,
                    NOTHING_MADE_REFUSAL,
                ][..],
            ),
            (
                "FILE_SNAPSHOT",
                FILE_SNAPSHOT,
                &[NOT_ABSOLUTE_REFUSAL, NO_PROC_REFUSAL][..],
            ),
            (
                "EXTRACT_ARCHIVE",
                EXTRACT_ARCHIVE,
                &[
                    NOT_ABSOLUTE_REFUSAL,
                    NOT_A_DIRECTORY_NAME_REFUSAL,
                    NO_PROC_REFUSAL,
                    NOT_A_DIRECTORY_REFUSAL,
                ][..],
            ),
        ] {
            for refusal in refusals {
                assert!(
                    script.contains(&format!(" no \"{refusal}\"")),
                    "{name}: {refusal}"
                );
            }
        }
    }

    #[test]
    fn the_snapshot_command_passes_the_path_and_the_limit_as_words() {
        assert_eq!(
            file_snapshot_command(RunAs::Root, "/etc/it's"),
            format!(
                "sudo timeout {SCRIPT_TIMEOUT_SECS} sh -c '{FILE_SNAPSHOT}' sh '/etc/it'\\''s' \
                 {SNAPSHOT_MAX_BYTES}"
            )
        );
        assert_eq!(
            file_snapshot_command(RunAs::Caller, "/etc/x"),
            format!(
                "timeout {SCRIPT_TIMEOUT_SECS} sh -c '{FILE_SNAPSHOT}' sh '/etc/x' \
                 {SNAPSHOT_MAX_BYTES}"
            )
        );
    }

    /// A snapshot's answer is an `absent` line alone, or a `file` line and exactly the
    /// bytes it counts, every field in its form, the size within the limit; anything
    /// else is no answer.
    #[test]
    fn a_snapshot_parses_only_in_its_one_form() {
        assert_eq!(parse_snapshot(b"absent\n"), Some(Snapshot::Absent));
        assert_eq!(
            parse_snapshot(b"file 4755 0 1000 4\na\nb\n"),
            Some(Snapshot::File {
                mode: 0o4755,
                uid: 0,
                gid: 1000,
                bytes: b"a\nb\n".to_vec(),
            })
        );
        assert_eq!(
            parse_snapshot(b"file 600 1 2 0\n"),
            Some(Snapshot::File {
                mode: 0o600,
                uid: 1,
                gid: 2,
                bytes: Vec::new(),
            })
        );
        let over = format!("file 644 0 0 {}\n", SNAPSHOT_MAX_BYTES + 1);
        for garbled in [
            &b""[..],
            b"absent",
            b"absent\nx",
            b"file 644 0 0 3\nab",
            b"file 644 0 0 3\nabcd",
            b"file 648 0 0 1\na",
            b"file 17777 0 0 1\na",
            b"file 644 -1 0 1\na",
            b"file 644 0 0 1 x\na",
            b"file 644 0 0\n",
            b"file  644 0 0 1\na",
            b"dir 755 0 0 0\n",
            over.as_bytes(),
        ] {
            assert_eq!(
                parse_snapshot(garbled),
                None,
                "{}",
                String::from_utf8_lossy(garbled)
            );
        }
    }

    #[test]
    fn the_scripts_are_one_inert_quoted_word() {
        // Each is passed single-quoted, so a `'` would end the word; a step's whole text
        // is scanned for references, so neither holds a delimiter of one; and a newline
        // would make it more than the one line the callers compose it into.
        for script in [FILE_PUT, DIR_ATTRS, FILE_SNAPSHOT, MAKE_DIRS] {
            assert!(!script.contains('\''));
            assert!(!crate::var_ref::holds_delimiter(script));
            assert!(!script.contains('\n'));
            // Every refusal goes through `no`, which exits the documented status; no
            // other exit of the script's own is that one.
            assert_eq!(
                script.matches("exit ").count()
                    - script.matches("exit 1").count()
                    - script.matches("exit 0").count(),
                1
            );
            assert!(script.contains(&format!(">&2; exit {REFUSED_EXIT}; }}; ")));
        }
    }

    #[test]
    fn the_owner_spec_names_what_is_given() {
        let attrs = |owner, group| FileAttrs {
            owner,
            group,
            ..FileAttrs::NONE
        };
        assert_eq!(
            attrs(Some("app"), Some("www")).owner_spec().as_deref(),
            Some("app:www")
        );
        assert_eq!(
            attrs(Some("app"), None).owner_spec().as_deref(),
            Some("app")
        );
        assert_eq!(
            attrs(None, Some("www")).owner_spec().as_deref(),
            Some(":www")
        );
        assert_eq!(attrs(None, None).owner_spec(), None);
        assert!(FileAttrs::NONE.is_empty());
        assert!(!FileAttrs::mode("600").is_empty());
    }

    #[test]
    fn the_put_command_passes_every_value_as_its_own_word() {
        let attrs = FileAttrs {
            mode: Some("640"),
            owner: Some("app"),
            group: Some("www"),
            ..FileAttrs::NONE
        };
        assert_eq!(
            file_put_command(RunAs::Root, "/srv/it's/.env", attrs, PutCheck::None),
            format!("sudo sh -c '{FILE_PUT}' sh '/srv/it'\\''s/.env' '640' 'app:www' '' ''")
        );
        assert_eq!(
            file_put_command(
                RunAs::Caller,
                "/etc/sudoers.d/app",
                FileAttrs::mode("440"),
                PutCheck::Sudoers
            ),
            format!("sh -c '{FILE_PUT}' sh '/etc/sudoers.d/app' '440' '' 'sudoers' ''")
        );
        assert_eq!(
            file_put_command(
                RunAs::User("app"),
                "/home/app/x",
                FileAttrs::NONE,
                PutCheck::None
            ),
            format!("sudo -u 'app' sh -c '{FILE_PUT}' sh '/home/app/x' '' '' '' ''")
        );
        // Keeping what is left out is the last word; what is given is passed as before.
        assert_eq!(
            file_put_command(
                RunAs::Root,
                "/srv/app/.env",
                FileAttrs::mode("600").keeping(),
                PutCheck::None
            ),
            format!("sudo sh -c '{FILE_PUT}' sh '/srv/app/.env' '600' '' '' 'keep'")
        );
        assert_eq!(FileAttrs::NONE.keeping().unset, Unset::Keep);
        assert_eq!(FileAttrs::default(), FileAttrs::NONE);
    }

    #[test]
    fn the_dir_attrs_command_passes_every_value_as_its_own_word() {
        assert_eq!(
            dir_attrs_command(
                RunAs::Root,
                "/srv/app",
                FileAttrs {
                    mode: Some("750"),
                    group: Some("www"),
                    ..FileAttrs::NONE
                }
            ),
            format!(
                "sudo timeout {SCRIPT_TIMEOUT_SECS} sh -c '{DIR_ATTRS}' sh '/srv/app' '750' ':www'"
            )
        );
    }

    #[test]
    fn the_make_dirs_command_passes_the_path_as_its_word() {
        assert_eq!(
            make_dirs_command(RunAs::Root, "/srv/it's/a"),
            format!("sudo timeout {SCRIPT_TIMEOUT_SECS} sh -c '{MAKE_DIRS}' sh '/srv/it'\\''s/a'")
        );
        assert_eq!(
            make_dirs_command(RunAs::Caller, "/srv"),
            format!("timeout {SCRIPT_TIMEOUT_SECS} sh -c '{MAKE_DIRS}' sh '/srv'")
        );
    }

    #[test]
    fn the_link_put_command_passes_the_path_then_the_target_as_its_words() {
        assert_eq!(
            link_put_command("sudo ", "/srv/it's/current", "/srv/releases/a b"),
            format!("sudo sh -c '{LINK_PUT}' sh '/srv/it'\\''s/current' '/srv/releases/a b'")
        );
        assert_eq!(
            link_put_command("", "/l", "/t"),
            format!("sh -c '{LINK_PUT}' sh '/l' '/t'")
        );
    }

    #[test]
    fn a_timeout_expiry_is_either_timeout_s_status() {
        assert!(script_timed_out(124) && script_timed_out(143));
        for code in [0, 1, 2, REFUSED_EXIT, 125, 126, 127, 137, -1] {
            assert!(!script_timed_out(code), "{code}");
        }
    }

    #[test]
    fn a_text_step_captures_once_and_pipes_the_digest_ahead_of_the_text() {
        let step = put_text_step(
            "printf '%s\\n' 'a line'",
            RunAs::Root,
            "/etc/x",
            FileAttrs::mode("600"),
            PutCheck::None,
        );
        assert_eq!(
            step,
            format!(
                "zap_c=$(printf '%s\\n' 'a line' && echo .) || exit 1; zap_c=${{zap_c%.}}; \
                 zap_h=$(printf %s \"$zap_c\" | sha512sum) || exit 1; \
                 {{ printf \"%s\\n\" \"${{zap_h%% *}}\"; printf %s \"$zap_c\"; }} | \
                 sudo sh -c '{FILE_PUT}' sh '/etc/x' '600' '' '' ''"
            )
        );
        // Nothing the step adds pairs into a reference.
        assert!(!crate::var_ref::holds_delimiter(&step));

        // Keeping the file's mode: read first, then the same feeder with the mode as a
        // variable in the put's mode position.
        let keeping = put_text_step_keeping_mode(
            "printf '%s\\n' 'a line'",
            RunAs::Root,
            "/etc/it's",
            FileAttrs::mode("644"),
            PutCheck::None,
        );
        assert_eq!(
            keeping,
            format!(
                "if [ -e '/etc/it'\\''s' ]; then zap_m=$(stat -L -c %a '/etc/it'\\''s') && \
                 [ -n \"$zap_m\" ] || exit 1; if command -v getfacl >/dev/null; then \
                 zap_a=$(getfacl -cps -- '/etc/it'\\''s') || exit 1; else \
                 zap_a=$(ls -dlL -- '/etc/it'\\''s') || exit 1; case ${{zap_a%% *}} in *+) ;; \
                 *) zap_a=;; esac; fi; [ -z \"$zap_a\" ] || {{ printf 'zap: %s: it has an access \
                 list (ACL), which keeping its mode would drop; remove it (setfacl -b) to have \
                 it rewritten; left unchanged\\n' '/etc/it'\\''s' >&2; exit {REFUSED_EXIT}; }}; \
                 else zap_m='644'; fi; \
                 zap_c=$(printf '%s\\n' 'a line' && echo .) || exit 1; zap_c=${{zap_c%.}}; \
                 zap_h=$(printf %s \"$zap_c\" | sha512sum) || exit 1; \
                 {{ printf \"%s\\n\" \"${{zap_h%% *}}\"; printf %s \"$zap_c\"; }} | \
                 sudo sh -c '{FILE_PUT}' sh '/etc/it'\\''s' \"$zap_m\" '' '' ''"
            )
        );
        assert!(!crate::var_ref::holds_delimiter(&keeping));
    }
}
