//! Pure command/path helpers the detector and planner share — one definition each
//! (sudoers, passwd/shadow reads, apt source-line + keyring paths, mode normalization)
//! so the probe and the mutation it guards can't diverge.

use super::{SudoMode, SudoScope};
use crate::shell::single_quote;

/// Build the `/etc/sudoers.d/<user>` line for a granted `user` resource.
///
/// Pure; the single definition the planner emits from and the detector compares
/// against, so the two can't diverge. The
/// `password` mode omits the `NOPASSWD:` tag; the scope is `ALL` for the unrestricted
/// [`UserSudo::Mode`](super::UserSudo::Mode) grant and the listed specs for a
/// restricted one. Returns a single newline-terminated line.
#[must_use]
pub fn build_sudoers_content(username: &str, mode: SudoMode, scope: SudoScope<'_>) -> String {
    let tag = match mode {
        SudoMode::Nopasswd => "NOPASSWD: ",
        SudoMode::Password => "",
    };
    format!("{username} ALL=(ALL) {tag}{}\n", scope.sudoers_spec())
}

/// The `authorized_keys` content for a `user`'s explicit keys: each key on its own line,
/// the last one ended too.
///
/// Pure; the single definition the planner installs and the detector compares against,
/// so the two can't diverge.
#[must_use]
pub fn render_authorized_keys(keys: &[String]) -> String {
    let mut out = String::new();
    for key in keys {
        out.push_str(key);
        out.push('\n');
    }
    out
}

/// Directory holding per-user sudoers drop-in files.
pub const SUDOERS_DIR: &str = "/etc/sudoers.d";

/// The sudoers drop-in path for a managed `user` (`/etc/sudoers.d/<user>`). Shared
/// by the planner (writes/removes it) and the detector (compares it).
#[must_use]
pub fn sudoers_path(username: &str) -> String {
    format!("{SUDOERS_DIR}/{username}")
}

/// A managed `user`'s home directory (`/home/<user>`). The one place the `/home/`
/// prefix is spelled, shared by the detector (home-mode probe) and the planner.
///
/// Derived from the name, never read from the target, so the plan doesn't depend on
/// detection. What keeps it true: the structural gate refuses a `user` named `root`
/// ([`managed_root_user`](crate::validate::managed_root_user)), and detection holds an
/// existing account whose `/etc/passwd` home is anything else, when the user declares
/// `home_mode` or `ssh_keys` — and, for those users, anything at this path but nothing,
/// the user's own directory, or a directory root owns (which the creation of an absent
/// account gives to the user, and an existing account keeps).
#[must_use]
pub fn user_home_dir(username: &str) -> String {
    format!("/home/{username}")
}

/// A managed `user`'s `.ssh` directory (`/home/<user>/.ssh`).
#[must_use]
pub fn user_ssh_dir(username: &str) -> String {
    format!("{}/.ssh", user_home_dir(username))
}

/// A managed `user`'s `authorized_keys` path (`/home/<user>/.ssh/authorized_keys`).
/// Shared by the planner (writes it) and the detector (checks it).
#[must_use]
pub fn authorized_keys_path(username: &str) -> String {
    format!("{}/authorized_keys", user_ssh_dir(username))
}

/// The ruleset file an nftables `firewall` writes whole.
///
/// It is the canonical path the Alpine nftables `OpenRC` service loads at boot
/// (`nftables_file` in `/etc/conf.d/nftables`). Writing the ruleset here, plus enabling
/// the nftables service, makes it boot-persistent; the `nft -f` step applies it now.
pub const NFTABLES_RULESET_PATH: &str = "/etc/nftables.nft";

/// A colon-separated `/etc/passwd` field the `user` stage reads back.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PasswdField {
    /// Home directory — field 6.
    Home,
    /// Login shell — field 7.
    Shell,
}

impl PasswdField {
    /// The 1-based field index in a `passwd(5)` line.
    const fn index(self) -> u8 {
        match self {
            Self::Home => 6,
            Self::Shell => 7,
        }
    }
}

/// Command that prints `field` of `name`'s `/etc/passwd` entry, read from the file
/// itself with `awk`.
///
/// The file, not `getent passwd` (which both families have): it is what `useradd`
/// writes and what zap manages, read the same way on Debian and Alpine, with no NSS
/// source in between. The two agree for zap's **local** users and diverge only for
/// NSS-backed ones (LDAP and friends), which zap doesn't create. Shared by the `user`
/// planner (the `copy_from` home read) and detector (shell drift,
/// the managed user's home check, and the `copy_from` home read) so the probe and the
/// mutation it guards read the same bytes.
///
/// `name` is [`single_quote`]d into an `awk -v` assignment; `AccountName`'s charset
/// excludes the backslash, so `awk`'s `-v` escape processing is a no-op and the value
/// lands verbatim. The compare is forced to strings (`$1""==u`): a `-v` value and a
/// field that look numeric compare as numbers, which on some `awk`s matches `inf` to
/// an `infinity` line or matches `nan` to nothing, and those are valid account names.
#[must_use]
pub fn passwd_field(name: &str, field: PasswdField) -> String {
    format!(
        "awk -F: -v u={} '$1\"\"==u{{print ${}}}' /etc/passwd",
        single_quote(name),
        field.index()
    )
}

/// The shell variable [`copy_source_keys`] reads the source account's home from, set by
/// [`copy_source_home`].
const COPY_SOURCE_HOME: &str = "SRC_HOME";

/// Shell text that reads a `copy_from` source account's home into a shell variable.
///
/// The home is read from `/etc/passwd` ([`passwd_field`]) into the variable
/// [`copy_source_keys`] names the key file by, and the text succeeds only when the
/// account has one. It ends in the test, with no failure branch: the caller follows it with `||` and
/// what a missing home means there — the step fails saying so, the detector's read
/// exits with a status of its own.
///
/// Shared by the `user` planner (ahead of the producer of the key file it installs) and
/// detector (ahead of its read of the same file), so both look the home up one way.
#[must_use]
pub fn copy_source_home(source: &str) -> String {
    format!(
        "{COPY_SOURCE_HOME}=$({}) && [ -n \"${COPY_SOURCE_HOME}\" ]",
        passwd_field(source, PasswdField::Home)
    )
}

/// Command that prints a `copy_from` source account's `authorized_keys`, read **as that
/// account**.
///
/// The file is `<home>/.ssh/authorized_keys`, the home taken from the shell variable
/// [`copy_source_home`] sets, which the caller runs first. It is read by a
/// tool the account itself runs (`sudo -u`), so a link the account plants at its key
/// file leads to nothing the account couldn't read, and the name follows `--`, so a
/// home that begins with `-` is no option. `reader` is that tool: `cat` to copy the
/// file, `head -c <n>` to read a bounded part of it. A file the account can't read
/// fails the command.
///
/// Shared by the `user` planner (the producer of the key file it installs) and detector
/// (the desired content it compares against), so what detection expects is what apply
/// can produce.
#[must_use]
pub fn copy_source_keys(source: &str, reader: &str) -> String {
    format!(
        "sudo -u {} {reader} -- \"${COPY_SOURCE_HOME}/.ssh/authorized_keys\"",
        single_quote(source),
    )
}

/// Command that exits 0 when `table` has a line whose first field is exactly `path`.
///
/// `table` is a whitespace-columned file like `/proc/swaps` or `/etc/fstab`. It exits
/// nonzero otherwise: 1 for no such line; a GNU or `mawk` `awk` that can't read the table
/// exits 2 — `BusyBox`'s exits 1, so there an unreadable table reads as not listing the
/// path.
///
/// Shared by the `swap` detector (active and persisted) and the planner's `/etc/fstab`
/// append guard, so the probe and the mutation it guards agree on what "listed" means:
/// the whole first field, so a declared `/swap` isn't listed by a `/swapfile` line, and
/// a commented-out `#/swap` line lists nothing. The path reaches `awk` through the
/// environment (`ENVIRON`), never `-v`, whose escape processing would rewrite a
/// backslash in it.
#[must_use]
pub fn table_lists_path(table: &str, path: &str) -> String {
    format!(
        "P={} awk '$1 == ENVIRON[\"P\"] {{ found = 1 }} END {{ exit !found }}' {table}",
        single_quote(path)
    )
}

/// The `/etc/fstab` line that persists a swap file at `path`.
#[must_use]
pub fn fstab_swap_entry(path: &str) -> String {
    format!("{path} none swap sw 0 0")
}

/// Command that prints `table` with the swap entry for `path` ([`fstab_swap_entry`])
/// added at the end.
///
/// `awk` prints each line of the table with its newline — one it adds to a last line
/// that had none — and exits nonzero when it can't read the file. A table that doesn't
/// exist prints as nothing.
///
/// The `swap` planner installs what this prints, guarded by the [`table_lists_path`]
/// read the detector makes of the same table, so the entry it adds is one that read
/// then finds.
#[must_use]
pub fn fstab_with_entry(table: &str, path: &str) -> String {
    format!(
        "{{ [ ! -e {table} ] || awk '{{ print }}' {table}; }} && printf '%s\\n' {}",
        single_quote(&fstab_swap_entry(path))
    )
}

/// Command that prints `name`'s `/etc/shadow` password field (field 2) — the
/// shadow-lock read, the `/etc/shadow` analog of [`passwd_field`].
///
/// `useradd` leaves a passwordless account `!`-locked in this field, which Alpine's
/// sshd treats as "account is locked" and refuses pubkey login; the detector reads it
/// and drifts on **any** value other than the disabled sentinel `*` — a `!`-lock, an
/// empty field (a passwordless-login hole), or a real password hash all re-converge to
/// `*` (no password, not locked), authoritatively matching the resource's key-only
/// `ssh_keys` posture. Unlike world-readable `/etc/passwd`, `/etc/shadow` is root-only, so
/// the command carries **no** `sudo` (per the "commands carry no sudo; the caller
/// adds it" contract — the detector runs it as root, in the root batch).
///
/// `name` reaches `awk` and is compared as [`passwd_field`] says.
#[must_use]
pub fn shadow_password_field(name: &str) -> String {
    format!(
        "awk -F: -v u={} '$1\"\"==u{{print $2}}' /etc/shadow",
        single_quote(name)
    )
}

/// Inject `signed-by=<key_path>` into a deb source line.
///
/// Pure, with no regex dep. No-op if
/// `signed-by` is already present or the line isn't a recognizable `deb` /
/// `deb-src` entry. Shared by the `apt_repo` detector (compares the live list
/// against this) and the planner (emits the write command from this) — one source
/// line, one definition.
#[must_use]
pub fn inject_signed_by(source: &str, key_path: &str) -> String {
    if source.contains("signed-by=") {
        return source.to_owned();
    }
    // Match a `deb` or `deb-src` prefix followed by whitespace.
    let rest = source
        .strip_prefix("deb-src")
        .map(|rest| ("deb-src", rest))
        .or_else(|| source.strip_prefix("deb").map(|rest| ("deb", rest)));
    let Some((prefix, after_prefix)) = rest else {
        return source.to_owned();
    };
    let after_prefix = after_prefix.trim_start();
    // The prefix must be a whole token (followed by whitespace before the rest).
    if after_prefix.len() == source.len() - prefix.len() {
        return source.to_owned();
    }

    if let Some(stripped) = after_prefix.strip_prefix('[') {
        // Existing bracketed options — merge `signed-by` in.
        if let Some(close) = stripped.find(']') {
            let options = &stripped[..close];
            let tail = stripped[close + 1..].trim_start();
            return format!("{prefix} [{options} signed-by={key_path}] {tail}");
        }
        return source.to_owned();
    }
    // No brackets — add them.
    format!("{prefix} [signed-by={key_path}] {after_prefix}")
}

/// The shared `apt_repo` source-resolution command — one definition for probe and mutation.
///
/// Builds `. /etc/os-release && printf '%s\n' "<line>"`, which resolves a
/// distro-codename-templated apt source line (`$VERSION_CODENAME` from
/// `/etc/os-release`) on the target. `line` is the source line as the list holds it —
/// the declared source with `signed-by=<key_path>` injected ([`inject_signed_by`]).
/// Shared by the `apt_repo` step builder (the producer of the list it installs) and
/// detector (the expected-line probe) so the resolved source line can't drift between
/// probe and mutation. The line stays inside the double quotes UNQUOTED by design — the
/// codename must expand. It is printed by `printf`, which writes its argument as it is:
/// `echo` reads a backslash escape in one under `dash` and not under `BusyBox` `ash`,
/// so one source would make two lists.
#[must_use]
pub fn apt_source_command(line: &str) -> String {
    format!(". /etc/os-release && printf '%s\\n' \"{line}\"")
}

/// Directory holding `apt_repo` GPG signing keys.
pub const APT_KEYRING_DIR: &str = "/usr/share/keyrings";
/// Directory holding `apt_repo` `.list` source files.
pub const APT_SOURCES_LIST_DIR: &str = "/etc/apt/sources.list.d";

/// Default GPG key path for an `apt_repo` (`/usr/share/keyrings/<id>.asc`).
///
/// The one definition the detector and the step builder both fall back to when
/// `key_path` is unset, so they agree on where the key lives.
#[must_use]
pub fn apt_keyring_path(id: &str) -> String {
    format!("{APT_KEYRING_DIR}/{id}.asc")
}

/// The mode, owner, and group an `apt_repo`'s signing key is installed with: `644`,
/// `root:root`, whatever the path held before — apt reads it as an unprivileged user,
/// and only root may replace it.
pub const APT_KEY_ATTRS: crate::put::FileAttrs<'static> = crate::put::FileAttrs {
    mode: Some("644"),
    owner: Some("root"),
    group: Some("root"),
    unset: crate::put::Unset::Fresh,
};

/// Default `.list` path for an `apt_repo` (`/etc/apt/sources.list.d/<id>.list`).
/// Shared fallback for `list_file`, so the detector and step builder agree.
#[must_use]
pub fn apt_sources_list_path(id: &str) -> String {
    format!("{APT_SOURCES_LIST_DIR}/{id}.list")
}

/// Normalize an octal file mode for comparison: strip leading zeros so `"0755"`
/// and `"755"` are the same value; an all-zero mode collapses to `"0"`.
///
/// The one definition the detector's drift decision (`metadata_mismatch`) and the
/// `--diff` join ([`diff_view`](crate::diff_view)) both use, so a leading-zero
/// difference can't read as drift in one place and converged in the other. Pure
/// (a string trim), so it lives here with the other probe/mutation-shared helpers.
#[must_use]
pub fn normalize_mode(mode: &str) -> &str {
    let trimmed = mode.trim_start_matches('0');
    if trimmed.is_empty() { "0" } else { trimmed }
}

#[cfg(test)]
mod tests {
    use super::{
        PasswdField, apt_source_command, copy_source_home, fstab_swap_entry, fstab_with_entry,
        inject_signed_by, passwd_field, shadow_password_field,
    };

    const KEY: &str = "/usr/share/keyrings/pgdg.asc";

    #[test]
    fn passwd_field_parses_etc_passwd_portably() {
        // An `awk` read of `/etc/passwd` itself, with the name `single_quote`d into the
        // `-v` assignment. Home = field 6, shell = field 7.
        assert_eq!(
            passwd_field("root", PasswdField::Home),
            "awk -F: -v u='root' '$1\"\"==u{print $6}' /etc/passwd"
        );
        assert_eq!(
            passwd_field("deploy", PasswdField::Shell),
            "awk -F: -v u='deploy' '$1\"\"==u{print $7}' /etc/passwd"
        );
        // A name with a single quote is escaped into the assignment (injection-safe).
        assert_eq!(
            passwd_field("o'brien", PasswdField::Home),
            r#"awk -F: -v u='o'\''brien' '$1""==u{print $6}' /etc/passwd"#
        );
    }

    #[test]
    fn shadow_password_field_reads_etc_shadow_field_two() {
        // The shadow-lock read: field 2 of `/etc/shadow`, the same `awk` shape as
        // `passwd_field` but no `sudo` (the detector adds it at the call site).
        assert_eq!(
            shadow_password_field("deploy"),
            "awk -F: -v u='deploy' '$1\"\"==u{print $2}' /etc/shadow"
        );
    }

    #[test]
    fn the_copy_source_home_read_ends_in_its_test() {
        assert_eq!(
            copy_source_home("ops"),
            "SRC_HOME=$(awk -F: -v u='ops' '$1\"\"==u{print $6}' /etc/passwd) && [ -n \"$SRC_HOME\" ]"
        );
    }

    #[test]
    fn the_fstab_rewrite_prints_the_table_then_the_entry() {
        assert_eq!(fstab_swap_entry("/swapfile"), "/swapfile none swap sw 0 0");
        assert_eq!(
            fstab_with_entry("/etc/fstab", "/swapfile"),
            "{ [ ! -e /etc/fstab ] || awk '{ print }' /etc/fstab; } && \
             printf '%s\\n' '/swapfile none swap sw 0 0'"
        );
    }

    #[test]
    fn the_apt_source_command_prints_the_line_after_reading_os_release() {
        // The line is left unquoted inside the double quotes so the codename expands on
        // the target.
        assert_eq!(
            apt_source_command(&inject_signed_by(
                "deb https://example.com/apt stable main",
                KEY
            )),
            ". /etc/os-release && printf '%s\\n' \"deb [signed-by=/usr/share/keyrings/pgdg.asc] https://example.com/apt stable main\"",
        );
    }

    #[test]
    fn adds_brackets_when_absent() {
        assert_eq!(
            inject_signed_by("deb https://example.com/apt stable main", KEY),
            "deb [signed-by=/usr/share/keyrings/pgdg.asc] https://example.com/apt stable main"
        );
    }

    #[test]
    fn merges_into_existing_brackets() {
        assert_eq!(
            inject_signed_by("deb [arch=amd64] https://example.com/apt stable main", KEY),
            "deb [arch=amd64 signed-by=/usr/share/keyrings/pgdg.asc] https://example.com/apt stable main"
        );
    }

    #[test]
    fn handles_deb_src_prefix() {
        assert_eq!(
            inject_signed_by("deb-src https://example.com/apt stable main", KEY),
            "deb-src [signed-by=/usr/share/keyrings/pgdg.asc] https://example.com/apt stable main"
        );
    }

    #[test]
    fn is_a_noop_when_already_signed() {
        let already = "deb [signed-by=/etc/keys/other.asc] https://example.com/apt stable main";
        assert_eq!(inject_signed_by(already, KEY), already);
    }

    #[test]
    fn leaves_unrecognized_lines_untouched() {
        // Not a deb/deb-src entry, or `deb` not a whole token.
        assert_eq!(inject_signed_by("# a comment", KEY), "# a comment");
        assert_eq!(inject_signed_by("debug-tool run", KEY), "debug-tool run");
    }
}
