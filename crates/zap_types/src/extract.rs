//! The constant shell script every archive extraction runs, and the command that calls
//! it.
//!
//! A `remote` file's archive is extracted as root into the resource's declared path, and
//! a `build` source's into a scratch directory. Run by name, `mkdir -p <path> && tar -C
//! <path>` extracts into whatever the path's last component is at each instant — a
//! symbolic link there sends the whole tree somewhere else — and `tar` as root gives each
//! file the user and group ids the archive recorded, which on the target belong to
//! whoever happens to hold them. The script extracts into a fresh directory of its own
//! inside a private staging directory beside the destination, both held **open** and
//! reached through their descriptors, with the archive's ownership and its set-id and
//! group/other-write bits dropped, gives the new tree the destination's owner and mode
//! (nothing kept below a directory anyone may write), and only then swaps it into place.
//!
//! Like the [`put`](crate::put) scripts it is one constant text passed as one
//! single-quoted word to `sh -c`, with everything that varies as a positional argument:
//! it holds no `'`, no reference delimiter, and no newline.

use crate::put::RunAs;
use crate::schema::ExtractMode;
use crate::shell::single_quote;

/// Why [`EXTRACT_ARCHIVE`] refuses a symbolic link at the destination — and why
/// detection holds a tree there.
pub const LINK_REFUSAL: &str = "a symbolic link is not extracted through";

/// Why [`EXTRACT_ARCHIVE`] refuses a destination that isn't a directory — and why
/// detection holds a tree there.
///
/// [`DIR_ATTRS`](crate::put::DIR_ATTRS), and the native directory change beside it,
/// refuse a path that isn't a directory of its own with it too.
pub const NOT_A_DIRECTORY_REFUSAL: &str =
    "not a directory of its own (a symbolic link is not followed)";

/// Why [`EXTRACT_ARCHIVE`] refuses a destination that holds anything and no extract
/// sentinel — and why detection holds a tree there.
pub const UNMARKED_REFUSAL: &str = "it holds files and no extract sentinel, so zap did not \
                                    extract it; move it aside or remove it";

/// The script that extracts a `tar` archive into a directory, never through a link.
///
/// It follows no symbolic link at the directory's name, restores none of the archive's
/// owners, and runs `tar` nowhere another account can reach.
///
/// Positional parameters: the archive's absolute path (`$1`), the destination's absolute
/// path (`$2`), the `tar` decompression letter (`$3`: `z` or `J`), the count of leading
/// path components to strip (`$4`), the provenance the destination's sentinel is to
/// record, or empty (`$5`), and the archive's SHA-512 as lowercase hex (`$6`).
///
/// In order. A step the script refuses itself (`no`) says why and exits
/// [`REFUSED_EXIT`](crate::put::REFUSED_EXIT); a tool that fails exits 1.
///
/// Before anything is created, moved, or removed:
///
/// - Both paths must be absolute. Trailing slashes are dropped from the destination (a
///   path ending in one names what a link points to), and a last component of `.` or
///   `..` is refused for the same reason — as is `/`, which has no last component and
///   is never a tree to extract over or replace. The letter and the count must be ones
///   the script knows, so neither is ever read as another option, and the digest must
///   be one.
/// - Its tools (`tar`, `mkdir`, `mktemp`, `mv`, `stat`, `ls`, `rm`, `rmdir`, `chown`,
///   `chmod`, `id`, `cat`, `sha512sum`, `find`, `sort`, `uniq`) and `/proc/self/fd` must
///   be there, and a target missing one is told which.
/// - The archive is opened once, by name, and held. It must be a regular file at that
///   name, not a link, and what is held must belong to the account that uploaded it —
///   the one running the script, or the one `sudo` was run by (`SUDO_UID`) — with one
///   link and writable by no other account. The archive is uploaded as the connecting
///   user into a private staging directory of its own (`/tmp/zap-remote-XXXXXX`, or
///   the build's) and extracted as root, so these mean no other account placed it, and
///   the digest below, of a copy no one else can reach, means its owner didn't change
///   it either.
/// - A symbolic link at the destination is refused.
/// - A destination already there must be a directory of its own (its type read from its
///   name, no link followed, in one `stat`, with its owner, group, and mode), and is
///   replaced only when zap may replace it: with a provenance given, when it holds an
///   extract sentinel (a regular file, not a link; named literally, `.zap_remote_hash`,
///   the name detection reads: `observe::file::REMOTE_HASH_SENTINEL`), which only zap's
///   extraction leaves; else only when it is empty. Any other destination — one zap
///   didn't extract that holds anything — is refused: it is never extracted into, merged
///   with, or removed. A caller other than root replaces only a destination it owns whose
///   group is one of its own (`id -G`), else it fails (exit 1, so a local run's retry
///   under `sudo` does it), since it couldn't give the new one that owner and group; so
///   does a destination it can't list.
///
/// Then the tree is built aside and swapped in:
///
/// - `umask 022`, whatever the caller's: the directories made and the files extracted
///   are never group- or world-writable.
/// - `mkdir -p` makes the destination's parent (a component that is a symbolic link is
///   followed). An account that can write the parent can rename what is in it: the
///   destination's own name is only as trustworthy as the parent, which is why the
///   staging directory below is checked and then never reached through its name.
/// - `mktemp -d` makes a staging directory beside the destination, `.<name>.zap-XXXXXX`
///   in the same parent (a fresh name, mode `0700`, the caller's), and the script opens
///   it and goes on only when what it holds open is the directory at that name (same
///   device, inode, owner, and mode in two `stat`s, the name's not followed), owned by
///   the caller, mode `0700`, and empty. From there on everything inside it is reached
///   through the descriptor (`/proc/self/fd/4/new`, `/proc/self/fd/4/old`), so a name
///   swapped for a link, or for another directory, after the check steers nothing.
/// - From inside the staging directory, held, the parent is checked as
///   [`FILE_PUT`](crate::put::FILE_PUT) checks the directory it installs in (the
///   `crossed_walk!` fragment): when a directory on the chain the parent resolves to,
///   or on its path as declared (a link read as what it leads to), has its sticky bit
///   set or is writable by every account, nothing of the destination is kept — the new
///   tree keeps the caller's owner and group and the mode `mkdir` gives it — since
///   anyone could have made, or renamed in, what is there. Where the replaced tree's
///   mode is kept (always, short of a shared parent; a declared `mode` is set after),
///   a destination with an extended POSIX access list (ACL) is refused: its mode bits
///   show the list's mask, not its group's, and the tree replacing it would carry no
///   list. The list is read with `getfacl` when the target has it, else from GNU `ls`'s
///   `+`; `BusyBox` `ls` shows none.
/// - The new tree's directory is made inside it and opened, and the script goes on only
///   when what it reaches by the descriptor's path is the directory held open.
/// - On every exit the staging directory's `new` and `old` are removed through the
///   descriptor — with whatever a failed extraction left there — and then the staging
///   directory by name (`rmdir`, which removes no link and no directory holding
///   anything), so a failure before the swap leaves the destination as it was, and a
///   retry starts clean. A staging directory that failed the check is only `rmdir`ed.
/// - The held archive is copied into the staging directory (`$sf/a`, reached through the
///   descriptor, so only the caller can reach it), and its SHA-512 must be `$6`; else
///   nothing is extracted. Everything after reads that copy: a file swapped in at the
///   uploaded name, or written over in place, after the open or during the copy is
///   never extracted. The copy is removed with the staging directory.
/// - `cd -P` through the descriptor; `tar -x` of the copy with `--no-same-owner
///   --no-same-permissions`: every file and directory belongs to the user running the
///   script (root, when it runs under `sudo`), not to the ids the archive recorded; file
///   modes are the archive's less the umask, with no set-user-id or set-group-id bit (run
///   as root, `BusyBox` `tar` keeps a directory's set-group-id bit; the group it then
///   passes on is root's own). Both `tar`s accept both options. Nothing here is
///   reachable by another account while `tar` writes: the staging directory admits only
///   its owner. Neither `tar` writes through a symbolic link the archive carries (each
///   makes the links last, or refuses one that leaves the tree), and GNU `tar` makes a
///   hard link only to a member of the archive.
/// - `BusyBox` `tar` makes a hard link to any file its target names, `../` and `/`
///   included, so the new tree is checked: an entry of it other than a directory (a
///   file, a link, a fifo — each read without following it) with more links than the
///   tree holds to it is linked from outside the archive, and the extraction is
///   refused, the new tree removed. Hard links among the archive's own files pass.
/// - With a provenance, the sentinel is written into the new tree last, after removing
///   whatever the archive put at its name, so a destination is never in place without
///   it.
/// - Then, through the descriptor and still inside the staging directory, the new tree
///   is given its owner and mode: the owner and group of the destination it replaces
///   (when they differ from its own, and not below a shared directory), and the mode it
///   is to keep. An archive's `./` member sets the directory's mode as GNU `tar`
///   extracts it (`BusyBox` `tar` leaves it), so the mode is the one rule: a tree that
///   replaces a destination keeps the replaced one's mode, less any set-id or sticky
///   bit; one made fresh, or below a shared directory, keeps what `mkdir` gave it. So
///   an extraction changes the tree, not who owns its top or who may enter it. Root
///   writes nothing into the tree after this, and its owner can't reach it until the
///   swap; a failure here leaves the destination as it was.
/// - The swap: a destination being replaced that holds a sentinel is renamed into the
///   staging directory (`mv -T`), the new tree renamed to its name, and the old one
///   removed with the staging directory. The name is empty only between the two
///   renames, and a failure of the second puts the old tree back. An empty destination is
///   replaced by the one rename, which the kernel refuses should it no longer be empty,
///   and an absent one is the one rename too. Should putting an old tree back fail, it
///   is left in the staging directory, and the script says where.
/// - The archive is removed. A failed extraction leaves it.
pub const EXTRACT_ARCHIVE: &str = concat!(
    r#"a=$1; p=$2; z=$3; strip=$4; pin=$5; want=$6; fd=/proc/self/fd/3; sf=/proc/self/fd/4; af=/proc/self/fd/5; st=; h=; old=; o=; "#,
    crate::put::refusal!("; nothing was extracted"),
    r#"case $a in /*) ;; *) no "the archive is not at an absolute path";; esac; "#,
    crate::put::absolute_path!(),
    crate::put::strip_trailing_slashes!(),
    r#"case ${p##*/} in ""|.|..) no "it does not name a directory itself";; esac; "#,
    r#"case $z in z|J) ;; *) no "unknown archive format";; esac; "#,
    r#"case $strip in ""|*[!0-9]*) no "not a count of path components to strip";; esac; "#,
    r#"case $want in *[!0-9a-f]*) want=;; esac; [ ${#want} -eq 128 ] || no "not a SHA-512 digest for the archive"; "#,
    crate::put::need_tools!(
        "tar mkdir mktemp mv stat ls rm rmdir chown chmod id cat sha512sum find sort uniq"
    ),
    crate::put::need_proc!(),
    r#"[ -f "$a" ] && [ ! -L "$a" ] || no "the archive is not a regular file"; command exec 5<"$a" || exit 1; "#,
    r#"q=$(stat -L -c %u:%h:%a $af) && [ -n "$q" ] && [ -f $af ] || exit 1; "#,
    // The uploader is the account running the script (a caller's extract, or root's
    // own), or the one `sudo` was run by. Either is safe to accept: root under `sudo`
    // has `SUDO_UID` from `sudo` itself, and a caller's inherited `SUDO_UID` can only
    // name an account whose file the caller then extracts with its own privileges; in
    // both cases the bytes extracted are a copy whose digest is checked below.
    r#"[ "${q%%:*}" = "$(id -u)" ] || [ "${q%%:*}" = "${SUDO_UID-}" ] || no "the archive is not a file the uploading account owns"; "#,
    r#"q=${q#*:}; [ "${q%:*}" = 1 ] || no "the archive has another hard link"; "#,
    r#"case ${q#*:} in *[2367]|*[2367]?) no "the archive can be written by other accounts";; esac; "#,
    r#"[ ! -L "$p" ] || no "a symbolic link is not extracted through"; "#,
    r#"d=${p%/*}; b=${p##*/}; s=.zap_remote_hash; "#,
    r#"if [ -e "$p" ]; then o=$(stat -c %f:%u:%g -- "$p") && [ -n "$o" ] || exit 1; "#,
    r#"[ $((0x${o%%:*} & 0170000)) -eq 16384 ] || no "not a directory of its own (a symbolic link is not followed)"; "#,
    r#"[ -r "$p" ] && [ -x "$p" ] || exit 1; "#,
    r#"if [ -n "$pin" ] && [ -f "$p/$s" ] && [ ! -L "$p/$s" ]; then old=1; "#,
    r#"else e=$(ls -A -- "$p") || exit 1; "#,
    r#"[ -z "$e" ] || no "it holds files and no extract sentinel, so zap did not extract it; move it aside or remove it"; fi; "#,
    r#"k=${o#*:}; me=$(id -u) && gs=$(id -G) || exit 1; "#,
    r#"[ "$me" = 0 ] || { [ "$me" = "${k%:*}" ] && case " $gs " in *" ${k#*:} "*) ;; *) false;; esac; } || "#,
    r#"{ echo "zap: $p: its owner or group is not one this account can give; nothing was extracted" >&2; exit 1; }; fi; "#,
    r#"umask 022; mkdir -p -- "${d:-/}" || exit 1; "#,
    r#"cl() { [ -n "$h" ] || { rmdir -- "$st"; return; }; "#,
    r#"if [ -d $sf/old ] && [ ! -e "$p" ] && [ ! -L "$p" ] && ! mv -T -- $sf/old "$p"; then "#,
    r#"echo "zap: $p: the tree it held is left at $st/old" >&2; else rm -rf -- $sf/new $sf/old $sf/a; rmdir -- "$st"; fi; }; "#,
    r#"trap "exit 1" HUP INT TERM; "#,
    r#"st=$(mktemp -d "$d/.$b.zap-XXXXXX") && [ -n "$st" ] || { st=; exit 1; }; trap cl EXIT; "#,
    r#"command exec 4<"$st" || exit 1; me=$(id -u) && w=$(stat -c %d:%i:%u:%f -- "$st") && [ -n "$w" ] && "#,
    r#"[ "$(stat -L -c %d:%i:%u:%f $sf)" = "$w" ] && [ "${w%:*}" = "${w%:*:*}:$me" ] && "#,
    r#"[ $((0x${w##*:} & 0170777)) -eq 16832 ] && e=$(ls -A $sf) && [ -z "$e" ] || exit 1; h=1; "#,
    r#"CDPATH= cd -P -- $sf || exit 1; "#,
    r#"cat <&5 >$sf/a && command exec 5<&- && g=$(sha512sum <$sf/a) && [ -n "$g" ] || exit 1; "#,
    r#"[ "${g%% *}" = "$want" ] || no "the archive is not the pinned one (its SHA-512 differs)"; "#,
    crate::put::crossed_walk!("d"),
    r#"[ -z "$w" ] || o=; "#,
    r#"if [ -n "$o" ]; then "#,
    crate::put::acl_read!("e", "-cps", "-ld", r#""$p""#),
    r#"[ -z "$e" ] || no "it has an access list (ACL), which the tree replacing it would not carry; remove it (setfacl -b)"; fi; "#,
    r#"mkdir -- $sf/new && command exec 3<$sf/new || exit 1; "#,
    r#"i=$(stat -L -c %d:%i $fd) && [ -n "$i" ] && [ -d $fd ] && [ "$(stat -c %d:%i $sf/new)" = "$i" ] || exit 1; "#,
    r#"CDPATH= cd -P -- $fd || exit 1; "#,
    r#"m=$(stat -L -c %f $fd) && [ -n "$m" ] || exit 1; m=$((0x$m & 07777)); "#,
    r#"[ -z "$o" ] || m=$((0x${o%%:*} & 0777)); "#,
    r#"tar -x${z}f - --strip-components=$strip --no-same-owner --no-same-permissions <$sf/a || exit 1; "#,
    r#"l=$(find . ! -type d -links +1 -exec stat -c %d:%i:%h {} +) || exit 1; "#,
    r#"if [ -n "$l" ]; then x=$(printf "%s\n" "$l" | sort | uniq -c | while read -r n k; do [ "$n" = "${k##*:}" ] || echo x; done) || exit 1; "#,
    r#"[ -z "$x" ] || no "the archive links a file outside itself (a hard link)"; fi; "#,
    r#"[ -z "$pin" ] || { rm -rf -- "$s" && printf %s "$pin" >"$s"; } || exit 1; "#,
    r#"[ -z "$o" ] || [ "$(stat -L -c %u:%g $fd)" = "$k" ] || chown -- "$k" $fd || exit 1; "#,
    r#"c=$(stat -L -c %f $fd) && [ -n "$c" ] || exit 1; "#,
    r#"[ $((0x$c & 07777)) -eq $m ] || chmod -- "$(printf %05o $m)" $fd || exit 1; "#,
    r#"[ -z "$old" ] || mv -T -- "$p" $sf/old || exit 1; "#,
    r#"mv -T -- $sf/new "$p" || exit 1; "#,
    r#"rm -f -- "$a""#,
);

/// The `tar` decompression letter for an archive [`ExtractMode`]. Empty for
/// [`ExtractMode::None`], which is no archive: the script refuses it.
const fn tar_letter(extract: ExtractMode) -> &'static str {
    match extract {
        ExtractMode::TarGz { .. } => "z",
        ExtractMode::TarXz { .. } => "J",
        ExtractMode::None => "",
    }
}

/// The command that runs [`EXTRACT_ARCHIVE`]: extract `archive`, whose SHA-512 is
/// `sha512` (lowercase hex), into `dest` as `extract` says, then remove the archive.
///
/// `replaces` is the provenance of the content being extracted
/// ([`extract_provenance`](crate::config_hash::extract_provenance)), for a destination
/// that records it in an extract sentinel: the script writes it into the new tree, and a
/// destination holding a sentinel is replaced. `None` writes no sentinel and replaces
/// only an empty destination.
#[must_use]
pub fn extract_archive_command(
    run_as: RunAs<'_>,
    archive: &str,
    dest: &str,
    extract: ExtractMode,
    replaces: Option<&str>,
    sha512: &str,
) -> String {
    format!(
        "{}sh -c {} sh {} {} {} {} {} {}",
        run_as.prefix(),
        single_quote(EXTRACT_ARCHIVE),
        single_quote(archive),
        single_quote(dest),
        single_quote(tar_letter(extract)),
        single_quote(&extract.strip_components().to_string()),
        single_quote(replaces.unwrap_or_default()),
        single_quote(sha512),
    )
}

#[cfg(test)]
mod tests {
    use super::{
        EXTRACT_ARCHIVE, LINK_REFUSAL, NOT_A_DIRECTORY_REFUSAL, UNMARKED_REFUSAL,
        extract_archive_command,
    };
    use crate::observe::file::REMOTE_HASH_SENTINEL;
    use crate::put::{REFUSED_EXIT, RunAs};
    use crate::schema::ExtractMode;

    #[test]
    fn the_script_is_one_inert_quoted_word() {
        assert!(!EXTRACT_ARCHIVE.contains('\''));
        assert!(!crate::var_ref::holds_delimiter(EXTRACT_ARCHIVE));
        assert!(!EXTRACT_ARCHIVE.contains('\n'));
        // Every refusal goes through `no`; no other exit of the script's own is that one.
        assert_eq!(
            EXTRACT_ARCHIVE.matches("exit ").count()
                - EXTRACT_ARCHIVE.matches("exit 1").count()
                - EXTRACT_ARCHIVE.matches("exit 0").count(),
            1
        );
        assert!(EXTRACT_ARCHIVE.contains(&format!(">&2; exit {REFUSED_EXIT}; }}; ")));
        // The sentinel the replacement guard reads, and the script writes, is the one
        // detection reads, and so are the refusals detection holds with.
        assert!(EXTRACT_ARCHIVE.contains(&format!(" s={REMOTE_HASH_SENTINEL}; ")));
        for refusal in [LINK_REFUSAL, NOT_A_DIRECTORY_REFUSAL, UNMARKED_REFUSAL] {
            assert!(
                EXTRACT_ARCHIVE.contains(&format!(" no \"{refusal}\"; ")),
                "{refusal}"
            );
        }
        // The guard's sentinel is a regular file, not a link — what detection's `Lstat`
        // of it reads — and its emptiness is `ls -A`'s, the `Empty` facet's.
        assert!(EXTRACT_ARCHIVE.contains(r#"[ -f "$p/$s" ] && [ ! -L "$p/$s" ]"#));
        assert!(EXTRACT_ARCHIVE.contains(r#"e=$(ls -A -- "$p")"#));
    }

    #[test]
    fn the_archive_is_extracted_as_the_extracting_user() {
        assert!(EXTRACT_ARCHIVE.contains(" --no-same-owner --no-same-permissions "));
        assert!(EXTRACT_ARCHIVE.contains("umask 022; "));
    }

    #[test]
    fn the_command_passes_every_value_as_its_own_word() {
        assert_eq!(
            extract_archive_command(
                RunAs::Root,
                "/tmp/zap-remote-Ab12/archive.tar.xz",
                "/opt/it's",
                ExtractMode::TarXz {
                    strip_components: 1
                },
                Some("PIN"),
                "SHA",
            ),
            format!(
                "sudo sh -c '{EXTRACT_ARCHIVE}' sh '/tmp/zap-remote-Ab12/archive.tar.xz' \
                 '/opt/it'\\''s' 'J' '1' 'PIN' 'SHA'"
            )
        );
        assert_eq!(
            extract_archive_command(
                RunAs::Caller,
                "/tmp/b/archive.tar.gz",
                "/tmp/b",
                ExtractMode::TarGz {
                    strip_components: 0
                },
                None,
                "SHA",
            ),
            format!(
                "sh -c '{EXTRACT_ARCHIVE}' sh '/tmp/b/archive.tar.gz' '/tmp/b' 'z' '0' '' 'SHA'"
            )
        );
        // No archive format is no letter, which the script refuses.
        assert!(
            extract_archive_command(RunAs::Caller, "/a", "/d", ExtractMode::None, None, "")
                .ends_with(" '/a' '/d' '' '0' '' ''")
        );
    }
}
