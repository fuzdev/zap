//! `PostgreSQL` command primitives shared by the `database` detector (probes) and
//! the `database` step builder (mutations).
//!
//! Pure string transforms. The detector and the planner both interpolate
//! operator-controlled identifiers (role / database names, `pg_hba` CIDR hosts)
//! into `psql` SQL and `grep -E` patterns; escaping lives here so the probe and
//! the mutation it guards build byte-identical commands and can't silently
//! disagree about whether a rule is present.

use crate::shell::single_quote;
use crate::text::Text;
use crate::var_ref::Segment;

/// Wrap a SQL statement as a non-interactive `psql` query run as `postgres`, for a
/// caller that reads its output.
///
/// `psql -X -tAc`: tuples-only, unaligned, single command, and `-X` so the `postgres`
/// role's `~/.psqlrc` isn't read — a setting there (`\timing`, say) would print lines
/// the reader can't tell from the answer. The SQL is single-quoted for the shell layer,
/// so an identifier carrying an exotic character (already SQL-escaped via [`sql_lit`])
/// can't break out of the argument. The detector's catalog query and the step builder's
/// guards and `hba_file` read all route through this, so probe and mutation quote alike.
#[must_use]
pub fn psql_query(sql: &str) -> String {
    format!("sudo -u postgres psql -X -tAc {}", single_quote(sql))
}

/// Escape a value for embedding in a single-quoted SQL string literal.
///
/// The standard `'` → `''` doubling. The result is still wrapped by [`single_quote`]
/// (usually via [`psql_query`]) for the shell layer; this only closes the SQL-literal
/// layer.
#[must_use]
pub fn sql_lit(value: &str) -> String {
    value.replace('\'', "''")
}

/// Quote a value as a SQL *identifier* (`"name"`, embedded `"` doubled).
///
/// For the spots where a role/database name is an identifier rather than a string
/// literal (`GRANT … ON DATABASE "db" TO "user"`). Always-quoted so the name is
/// taken exactly as written — matching `createuser`/`createdb`, which pass their
/// argument verbatim — instead of being case-folded by the SQL parser (unquoted
/// `Foo` would target `foo` while `createuser Foo` had created `Foo`).
#[must_use]
pub fn sql_ident(name: &str) -> String {
    format!("\"{}\"", name.replace('"', "\"\""))
}

/// Escape a value for literal embedding in a `grep -E` (POSIX ERE) pattern.
///
/// Backslash-escapes every ERE metacharacter so a CIDR host's `.` matches a literal
/// dot rather than any character.
#[must_use]
pub fn ere_escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        if matches!(
            ch,
            '.' | '^' | '$' | '*' | '+' | '?' | '(' | ')' | '[' | ']' | '{' | '}' | '|' | '\\'
        ) {
            out.push('\\');
        }
        out.push(ch);
    }
    out
}

/// The `grep -E` pattern matching a `pg_hba.conf` `host` line for a tuple.
///
/// For the given database / role / host / auth-method: every field is
/// [`ere_escape`]d so a CIDR host's metacharacters match literally; the trailing
/// `(\s|$)` anchors the method as a whole field, and the leading `^\s*` admits an
/// indented line, which `PostgreSQL` reads as the same rule. The single shared pattern the
/// detector greps for and the step builder's idempotency guard both consume.
///
/// A reference rides through unescaped: the step builder interpolates fields still
/// carrying inert references, and [`ere_escape`] touches only ERE metacharacters, which
/// a marker holds none of, so the reference resolves when the step runs. Its *resolved*
/// value enters the pattern as it is — a value carrying ERE metacharacters is read as a
/// pattern, which is accepted for the role, database and CIDR names this guards. The
/// detector passes already-resolved fields, escaped whole.
#[must_use]
pub fn pg_hba_pattern(db: &str, user: &str, host: &str, method: &str) -> String {
    format!(
        "^\\s*host\\s+{}\\s+{}\\s+{}\\s+{}(\\s|$)",
        ere_escape(db),
        ere_escape(user),
        ere_escape(host),
        ere_escape(method)
    )
}

/// `script` as a command run by the `postgres` account's shell: one single-quoted word
/// to `sh -c`, its positional parameters following.
fn as_postgres(script: &str) -> String {
    format!("sudo -u postgres sh -c {} sh", single_quote(script))
}

/// The shell script [`pg_hba_find_rules`] runs: whether a `pg_hba.conf` holds a line
/// matching each of some patterns.
///
/// Its positional parameters are the file (`$1`) and one `grep -E` pattern per rule. It
/// prints each `grep`'s exit status, in order, each preceded by a space: 0 for a line
/// found, 1 for none, anything else for a file that couldn't be read.
///
/// It holds no single quote (it is passed single-quoted) and no reference delimiter.
pub const PG_HBA_FIND_RULES: &str =
    r#"f=$1; shift; for p in "$@"; do grep -qE -e "$p" -- "$f"; printf " %s" "$?"; done"#;

/// The command that reads which of `patterns` ([`pg_hba_pattern`]s) the `pg_hba.conf`
/// named by the shell variable `hba` holds: [`PG_HBA_FIND_RULES`], run as the `postgres`
/// account.
///
/// The file is read as the account that owns it, as [`pg_hba_rule_step`] rewrites it:
/// the path is the server's answer, so the read reaches no file `postgres` couldn't read
/// itself, whatever is at that name. A `sudo` that fails prints fewer statuses than
/// there are patterns.
#[must_use]
pub fn pg_hba_find_rules(patterns: &[String]) -> String {
    let mut command = format!("{} \"$hba\"", as_postgres(PG_HBA_FIND_RULES));
    for pattern in patterns {
        command.push(' ');
        command.push_str(&single_quote(pattern));
    }
    command
}

/// The shell script [`pg_hba_rule_step`] runs as the `postgres` account: add one line to
/// a `pg_hba.conf` unless a line matching a pattern is already there.
///
/// Its positional parameters are the file (`$1`), the `grep -E` guard pattern (`$2`),
/// and the line (`$3`); the text itself is constant, so nothing config-derived is ever
/// parsed as shell, `sed`, or `awk`.
///
/// The path is the server's answer and the file's directory belongs to the `postgres`
/// account, so whoever holds that account decides what is at the name — a link to any
/// file on the machine included. The script therefore runs as that account and never as
/// root: it reads, stages, and renames with the account's own privileges, and a name
/// aimed at a file `postgres` couldn't rewrite itself fails. The account can also rename
/// anything in the directory while the script works there, so the script names the file
/// and its staged copy once each, to open them, and after that reads, writes, and sets
/// attributes only through the two descriptors (`/proc/self/fd/4` the file,
/// `/proc/self/fd/3` the copy) — the discipline of [`FILE_PUT`](crate::put::FILE_PUT).
/// In order:
///
/// - Its tools and `/proc/self/fd` must be there; a target missing one is told which.
/// - The file is resolved through any symlink and must be a regular file, else the
///   script fails. It enters the file's directory once (`cd -P`) and names only `./…`
///   after.
/// - The file is opened. Whatever is at its name by then is what the rest reads: the
///   contents copied and the group and mode given to the copy all come from that one
///   open file, so a file swapped in at the name can't have its contents installed
///   under another file's permissions.
/// - `grep -qE` decides: a match exits 0 with the file untouched, no match goes on,
///   and any other status fails the script.
/// - The file must belong to the account the script runs as. The copy can only be that
///   account's, so a file owned by anyone else — root included — is left as it is, and
///   the refusal names the file and the account. So is a file whose directory the
///   account can't write, where the copy would be staged: the refusal names both, with
///   the script's one failure status, before a shell's own redirection error could.
/// - The copy is staged as the put stages its own (`staged_copy!`): a new file made by
///   `mktemp` in the same directory, mode `0600` from the start, held open, and checked
///   to be a regular file of the account's, empty, with one name, still at its staged
///   name; else the script refuses with nothing written.
/// - The new contents are written to it. The line goes immediately before the first
///   `host*` record (`pg_hba` is first-match-wins, and `local` lines stay above), or at
///   the end of a file with none. A record is found as `PostgreSQL` finds it, past
///   leading spaces and tabs, so the line never lands below an indented rule that would
///   shadow it. Every other line is copied as read, by the shell's own `read` and
///   `printf`, which `dash` and `BusyBox` `ash` share.
/// - Each `printf` is checked itself (a loop's status is its last command's), so a
///   write that fails — a full disk — fails the script at once. The finished copy must
///   then hold exactly one line more than the file (`grep -c ""`, which counts a last
///   line with no newline), and exactly the file's bytes plus the line's (`wc -c`; one
///   more when the file's last line had no newline): a read that ended early is not
///   installed, nor is a copy of a file holding a NUL, which the shell's `read` drops,
///   and the refusal says so.
/// - The copy is given the file's group, then its mode, through its descriptor, and
///   flushed to disk. Its name must still be the file held open (same device and inode,
///   the name itself not followed), else nothing is installed.
/// - `mv -fT` renames the copy over the file, so a reader sees the old contents or the
///   new, never part of either, and an interrupted run leaves the file as it was. A
///   failed script removes the copy and exits nonzero.
/// - Once the copy is in place the script prints `added`, its only output, so its
///   caller can tell a rule it added from one that was there.
///
/// It doesn't follow an `include`, `include_if_exists`, or `include_dir` directive: a
/// rule in an included file is neither seen by the guard nor counted as a `host` line.
///
/// It holds no single quote (it is passed single-quoted), and no reference delimiter:
/// the engine resolves references across a whole step's text.
pub const PG_HBA_ADD_RULE: &str = concat!(
    r#"fd=/proc/self/fd/3; src=/proc/self/fd/4; "#,
    r#"die() { echo "zap: $1" >&2; exit 1; }; "#,
    r#"for t in readlink grep mktemp stat id wc tail chown chmod sync mv rm; do "#,
    r#"command -v $t >/dev/null || die "no $t on this machine"; done; "#,
    r#"[ -d ${fd%/*} ] || die "no /proc on this machine to hold the pg_hba file open through"; "#,
    r#"f=$(readlink -f -- "$1") && [ -f "$f" ] || die "pg_hba file not found: $1"; "#,
    r#"d=${f%/*}; b=${f##*/}; [ -n "$d" ] || d=/; "#,
    r#"CDPATH= cd -P -- "$d" || exit 1; "#,
    r#"exec 4<"./$b" || exit 1; [ -f $src ] || die "pg_hba file not found: $1"; "#,
    r#"grep -qE -e "$2" $src; s=$?; [ "$s" -ne 0 ] || exit 0; [ "$s" -eq 1 ] || exit 1; "#,
    r#"nl=$(grep -c "" $src); [ $? -le 1 ] || exit 1; "#,
    r#"at=$(stat -L -c "%u:%g %a" $src) && [ -n "$at" ] || exit 1; "#,
    r#"me=$(id -u) && [ -n "$me" ] || exit 1; [ "${at%%:*}" = "$me" ] || "#,
    r#"die "$f does not belong to $(id -un), the account its rewrite runs as; left unchanged"; "#,
    r#"[ -w . ] || die "$(id -un) can not write $d, where the rewrite of $f is staged; left unchanged"; "#,
    r#"c=$(wc -c <$src) && e=$(tail -c 1 <$src | wc -l) && r=$(printf "%s\n" "$3" | wc -c) || exit 1; "#,
    crate::put::staged_copy!(r#"die "no new file to stage the rewrite of $f in; left unchanged""#),
    r#"put=; tab=$(printf "\t"); "#,
    r#"{ while IFS= read -r line || [ -n "$line" ]; do "#,
    r#"case ${line#"${line%%[! $tab]*}"} in host*) "#,
    r#"[ -n "$put" ] || { printf "%s\n" "$3" || exit 1; put=1; };; esac; "#,
    r#"printf "%s\n" "$line" || exit 1; done; "#,
    r#"[ -n "$put" ] || printf "%s\n" "$3"; } <$src >$fd || exit 1; "#,
    r#"[ "$(grep -c "" $fd)" -eq "$((nl + 1))" ] || "#,
    r#"die "the rewrite of $f is not its $nl lines plus the rule; left unchanged"; "#,
    r#"[ "$(wc -c <$fd)" -eq "$((c + r + (c > 0 && e == 0)))" ] || "#,
    r#"die "the rewrite of $f is not its $c bytes plus the rule (a NUL byte is not copied); left unchanged"; "#,
    r#"chown -- "${at% *}" $fd || die "the rewrite of $f could not be given the group of the file; left unchanged"; "#,
    r#"chmod -- "${at#* }" $fd || exit 1; "#,
    r#"sync $fd || exit 1; "#,
    r#"i=$(stat -L -c %d:%i $fd) && [ -n "$i" ] && [ "$(stat -c %d:%i -- "$tmp")" = "$i" ] || "#,
    r#"die "the staged rewrite of $f was replaced before it could be installed; left unchanged"; "#,
    r#"mv -fT -- "$tmp" "./$b" || exit 1; trap - EXIT; echo added"#,
);

/// The step that adds a `database`'s `pg_hba.conf` rule for one host, unless it is
/// already there.
///
/// It reads the file's path from the server ([`psql_query`]; a failed or empty answer
/// fails the step) and hands it, the [`pg_hba_pattern`] guard, and the rule line to
/// [`PG_HBA_ADD_RULE`], run as the `postgres` account (`sudo -u postgres`) — the account
/// the file belongs to, and never root. The guard is the pattern the detector greps for
/// ([`pg_hba_find_rules`], as the same account), so the step is idempotent and agrees
/// with detection about whether the rule is present. The pattern and the line are each one single-quoted word carrying the same
/// inert references, so apply-time resolution gives both the same values.
///
/// A rule the script added (it prints `added`) is put in force with `pg_reload_conf()`,
/// as `postgres`: `pg_hba.conf` is read again on a reload, so no restart, and no service
/// manager, is needed. A rule that was already there reloads nothing, and any other
/// output from the script fails the step. For an added rule, in order:
///
/// - The step reads [`PG_HBA_FILE_PARSES`] (`PostgreSQL` 10 or later; on an older
///   server the query fails, and so does the step, saying so) and goes on only on `t`.
///   On `f` it fails saying the server can't parse the file, so nothing was reloaded
///   and the old rules stay in force; any other answer fails as unexpected. The view
///   parses the file on disk each time it is read, so it judges what the reload would.
/// - It reads [`PG_CONF_LOAD_TIME`], then asks for the reload, which must answer `t`.
/// - A `t` says only that the signal was sent; the server reloads on its own time. So
///   the step reads the load time again, once a second, each from a new connection,
///   until it moves, for up to [`PG_RELOAD_WAIT_SECS`] seconds. A connection that reads
///   the new time was started after the server handled the reload, `pg_hba.conf`
///   included, so the rule is in force for it and for every connection a dependent
///   opens after.
///   A time that never moves fails the step: a `postgresql.conf` the server can't parse
///   keeps it where it was even though `pg_hba.conf` is read again, and the message
///   says so.
/// - Once it moves, the step reads [`PG_HBA_FILE_PARSES`] again: a file changed after
///   the first check (another writer's edit) and that the server can't parse leaves the
///   old rules in force, so `f` fails the step saying so.
///
/// A failing rewrite or `pg_hba_file_rules` read makes its status the step's; every
/// other failure exits 1.
#[must_use]
pub fn pg_hba_rule_step(db: &str, user: &str, host: &str, method: &str) -> String {
    let load_time = psql_query(PG_CONF_LOAD_TIME);
    let parses = psql_query(PG_HBA_FILE_PARSES);
    format!(
        "hba=$({}) && [ -n \"$hba\" ] || \
         {{ echo 'zap: PostgreSQL reported no hba_file' >&2; exit 1; }}; \
         out=$({} \"$hba\" {} {}) || exit; \
         case $out in added) \
         ok=$({parses}) || {{ s=$?; \
         echo 'zap: could not read pg_hba_file_rules (PostgreSQL 10 or later)' >&2; exit $s; }}; \
         case $ok in t) ;; f) echo 'zap: PostgreSQL can not parse its pg_hba.conf, so it was \
         not reloaded and the old rules stay in force (see the error column of \
         pg_hba_file_rules)' >&2; exit 1;; \
         *) echo 'zap: unexpected output from the pg_hba_file_rules check' >&2; exit 1;; esac; \
         t0=$({load_time}) && [ -n \"$t0\" ] || \
         {{ echo 'zap: could not read when PostgreSQL last loaded its configuration' >&2; exit 1; }}; \
         {} | grep -qx t || \
         {{ echo 'zap: PostgreSQL did not reload its configuration' >&2; exit 1; }}; \
         w=0; while t=$({load_time}) && [ -n \"$t\" ] || \
         {{ echo 'zap: could not read when PostgreSQL last loaded its configuration' >&2; exit 1; }}; \
         [ \"$t\" = \"$t0\" ]; do [ $w -lt {PG_RELOAD_WAIT_SECS} ] || \
         {{ echo 'zap: PostgreSQL did not load its configuration within {PG_RELOAD_WAIT_SECS} seconds of \
         the reload, so the rule may not be in force; a postgresql.conf it can not parse keeps \
         the load time from moving (see the server log)' >&2; exit 1; }}; \
         w=$((w + 1)); sleep 1; done; \
         ok=$({parses}) || {{ s=$?; \
         echo 'zap: could not read pg_hba_file_rules (PostgreSQL 10 or later)' >&2; exit $s; }}; \
         [ \"$ok\" = t ] || {{ echo 'zap: PostgreSQL can not parse its pg_hba.conf, \
         which changed after it was checked, so the rule may not be in force (see the error \
         column of pg_hba_file_rules)' >&2; exit 1; }};; \
         '') ;; \
         *) echo 'zap: unexpected output from the pg_hba rewrite' >&2; exit 1;; esac",
        psql_query("SHOW hba_file"),
        as_postgres(PG_HBA_ADD_RULE),
        single_quote(&pg_hba_pattern(db, user, host, method)),
        single_quote(&pg_hba_rule_line(db, user, host, method)),
        psql_query("SELECT pg_reload_conf()"),
    )
}

/// The query [`pg_hba_rule_step`] checks the file with before it reloads: `t` when the
/// server can parse every line of the `pg_hba.conf` on disk.
///
/// `pg_hba_file_rules` is `PostgreSQL` 10 or later and readable by a superuser, as
/// `postgres` is.
pub const PG_HBA_FILE_PARSES: &str =
    "SELECT NOT EXISTS (SELECT FROM pg_hba_file_rules WHERE error IS NOT NULL)";

/// The query [`pg_hba_rule_step`] reads, before and after a reload, for when the server
/// last loaded its configuration.
pub const PG_CONF_LOAD_TIME: &str = "SELECT pg_conf_load_time()";

/// How long, in seconds, [`pg_hba_rule_step`] waits for the server's load time to move
/// after a reload.
pub const PG_RELOAD_WAIT_SECS: u32 = 30;

/// The `pg_hba.conf` line [`pg_hba_rule_step`] adds for one host.
///
/// The fields are written as they are, separated by blanks, so each must be one a rule
/// line reads as itself: [`pg_hba_field_problem`] says when one isn't, and a config's fields are held to them as written and again as resolved.
#[must_use]
pub fn pg_hba_rule_line(db: &str, user: &str, host: &str, method: &str) -> String {
    format!("host    {db}    {user}    {host}    {method}")
}

/// Which field of a `pg_hba.conf` rule line a text is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PgHbaField {
    /// The database column: a database's name.
    Database,
    /// The user column: a role's name.
    Role,
    /// The address.
    Host,
}

const PG_HBA_EMPTY: &str = "is empty, and a `pg_hba.conf` rule line would read the next \
     field in its place";
const PG_HBA_CHARACTER: &str = "holds a character that changes what a `pg_hba.conf` rule \
     line means (whitespace, `#`, `\"`, `,`, or a control character)";
const PG_HBA_DATABASE_KEYWORD: &str = "is a word `pg_hba.conf` reads as a keyword in its \
     database column, not a database's name (`all`, `sameuser`, `samerole`, `samegroup`, \
     `replication`)";
const PG_HBA_ROLE_KEYWORD: &str = "is `all`, which `pg_hba.conf` reads as a keyword in its \
     user column — every role — not a role's name";
const PG_HBA_FORM: &str = "begins with `+`, `@` or `/`, which `pg_hba.conf` reads as a \
     group, a file of names, or a pattern rather than a name";
const PG_HBA_OPTION: &str = "begins with `-`, which `createuser` and `createdb` would read \
     as an option";
const PG_HBA_CIDR: &str = "is not an IP address with a prefix length (`127.0.0.1/32`, \
     `::1/128`): `pg_hba.conf` reads a keyword there (`all`, `samehost`, `samenet`) as a \
     set of addresses, and a host name as whatever it resolves to";

/// Whether `text` is an IP address and a prefix length no longer than the address,
/// the one address form a rule zap writes takes.
fn is_cidr(text: &str) -> bool {
    let Some((address, length)) = text.split_once('/') else {
        return false;
    };
    let Ok(address) = address.parse::<std::net::IpAddr>() else {
        return false;
    };
    let max = if address.is_ipv4() { 32 } else { 128 };
    !length.is_empty()
        && length.bytes().all(|b| b.is_ascii_digit())
        && length.len() <= 3
        && length.parse::<u32>().is_ok_and(|length| length <= max)
}

/// Whether `text` holds a character a rule line doesn't read as part of a field: a
/// blank or a control character ends the field, `#` begins a comment, `"` begins a
/// quoted field, and `,` separates the names of a list.
fn breaks_pg_hba_field(text: &str) -> bool {
    text.chars()
        .any(|c| c.is_whitespace() || c.is_control() || matches!(c, '#' | '"' | ','))
}

/// Whether a name begins as something other than a name: `+group`, `@file`, a
/// `/pattern`, or an option of the commands that create it.
fn pg_hba_name_prefix_problem(text: &str) -> Option<&'static str> {
    match text.chars().next() {
        Some('+' | '@' | '/') => Some(PG_HBA_FORM),
        Some('-') => Some(PG_HBA_OPTION),
        _ => None,
    }
}

/// What is wrong with `value` as `field` of a `pg_hba.conf` rule line — said as the
/// rest of a sentence about it — or `None` when the line reads it as itself.
///
/// Each column has its own keywords: the database column reads `all`, `sameuser`,
/// `samerole`, `samegroup` and `replication` as rules about more than one database, and
/// the user column only `all` — a role named `replication` is a role. The address is
/// an IP address with a prefix length: a keyword (`all`, `samehost`, `samenet`) or a
/// host name there is refused.
#[must_use]
pub fn pg_hba_field_problem(value: &str, field: PgHbaField) -> Option<&'static str> {
    if value.is_empty() {
        return Some(PG_HBA_EMPTY);
    }
    if breaks_pg_hba_field(value) {
        return Some(PG_HBA_CHARACTER);
    }
    match field {
        PgHbaField::Database
            if matches!(
                value,
                "all" | "sameuser" | "samerole" | "samegroup" | "replication"
            ) =>
        {
            Some(PG_HBA_DATABASE_KEYWORD)
        }
        PgHbaField::Role if value == "all" => Some(PG_HBA_ROLE_KEYWORD),
        PgHbaField::Database | PgHbaField::Role => pg_hba_name_prefix_problem(value),
        PgHbaField::Host => (!is_cidr(value)).then_some(PG_HBA_CIDR),
    }
}

/// What is wrong with a rule-line field as a config wrote it, or `None`.
///
/// The rule its resolved value is held to ([`pg_hba_field_problem`]), applied to what
/// is known before a reference resolves: a text with no reference is its value, and
/// around a reference the written text can already hold a character no field can, or
/// begin as no name does.
#[must_use]
pub fn pg_hba_written_problem(text: &Text, field: PgHbaField) -> Option<&'static str> {
    if let Some(literal) = text.as_literal() {
        return pg_hba_field_problem(literal, field);
    }
    if text.literals().any(breaks_pg_hba_field) {
        return Some(PG_HBA_CHARACTER);
    }
    match (field, text.pieces().next()) {
        (PgHbaField::Database | PgHbaField::Role, Some(Segment::Text(leading))) => {
            pg_hba_name_prefix_problem(leading)
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::{
        PG_HBA_ADD_RULE, PG_HBA_FIND_RULES, ere_escape, pg_hba_find_rules, pg_hba_pattern,
        pg_hba_rule_step, psql_query, sql_ident, sql_lit,
    };

    #[test]
    fn sql_lit_doubles_quotes() {
        assert_eq!(sql_lit("o'brien"), "o''brien");
        assert_eq!(sql_lit("plain"), "plain");
    }

    #[test]
    fn sql_ident_quotes_and_doubles_double_quotes() {
        assert_eq!(sql_ident("app"), "\"app\"");
        assert_eq!(sql_ident("we\"ird"), "\"we\"\"ird\"");
    }

    #[test]
    fn ere_escape_escapes_cidr_dots() {
        assert_eq!(ere_escape("127.0.0.1/32"), r"127\.0\.0\.1/32");
        assert_eq!(ere_escape("trust"), "trust");
    }

    #[test]
    fn psql_query_skips_the_psqlrc_and_shell_quotes_the_sql() {
        assert_eq!(
            psql_query(&format!(
                "SELECT 1 FROM pg_roles WHERE rolname='{}'",
                sql_lit("app")
            )),
            "sudo -u postgres psql -X -tAc 'SELECT 1 FROM pg_roles WHERE rolname='\\''app'\\'''"
        );
    }

    #[test]
    fn the_pg_hba_script_is_inert_inside_a_step() {
        // Passed single-quoted, so a `'` would end the word; and a step's whole text is
        // scanned for references, so the script holds no delimiter of one.
        assert!(!PG_HBA_ADD_RULE.contains('\''));
        assert!(!crate::var_ref::holds_delimiter(PG_HBA_ADD_RULE));
        assert!(!PG_HBA_ADD_RULE.contains('\n'));
        // Past the two opens, neither the file nor its staged copy is read, written, or
        // given an owner or a mode by name: no `cp`, the file named once (to open it), and
        // the copy staged as the put stages its own, then written through its descriptor.
        assert!(!PG_HBA_ADD_RULE.contains("cp "));
        assert_eq!(PG_HBA_ADD_RULE.matches("\"./$b\"").count(), 2);
        assert!(PG_HBA_ADD_RULE.contains("exec 4<\"./$b\" "));
        assert!(
            PG_HBA_ADD_RULE
                .ends_with("mv -fT -- \"$tmp\" \"./$b\" || exit 1; trap - EXIT; echo added")
        );
        for script in [PG_HBA_ADD_RULE, PG_HBA_FIND_RULES] {
            assert!(!script.contains('\''));
            assert!(!crate::var_ref::holds_delimiter(script));
            assert!(!script.contains('\n'));
        }
        assert!(!PG_HBA_ADD_RULE.contains(">\"$tmp\""));
        assert!(!PG_HBA_ADD_RULE.contains("mktemp -u"));
        assert!(PG_HBA_ADD_RULE.contains(crate::put::staged_copy!(
            r#"die "no new file to stage the rewrite of $f in; left unchanged""#
        )));
        assert!(PG_HBA_ADD_RULE.contains("} <$src >$fd || exit 1; "));
    }

    #[test]
    fn the_pg_hba_step_passes_the_guard_and_the_line_as_words() {
        assert_eq!(
            pg_hba_rule_step("app", "o'brien", "127.0.0.1/32", "trust"),
            format!(
                "hba=$(sudo -u postgres psql -X -tAc 'SHOW hba_file') && [ -n \"$hba\" ] || \
                 {{ echo 'zap: PostgreSQL reported no hba_file' >&2; exit 1; }}; \
                 out=$(sudo -u postgres sh -c '{PG_HBA_ADD_RULE}' sh \"$hba\" \
                 '^\\s*host\\s+app\\s+o'\\''brien\\s+127\\.0\\.0\\.1/32\\s+trust(\\s|$)' \
                 'host    app    o'\\''brien    127.0.0.1/32    trust') || exit; \
                 case $out in added) \
                 ok=$(sudo -u postgres psql -X -tAc \
                 'SELECT NOT EXISTS (SELECT FROM pg_hba_file_rules WHERE error IS NOT NULL)') || {{ s=$?; \
                 echo 'zap: could not read pg_hba_file_rules (PostgreSQL 10 or later)' >&2; exit $s; }}; \
                 case $ok in t) ;; f) echo 'zap: PostgreSQL can not parse its pg_hba.conf, so it was \
                 not reloaded and the old rules stay in force (see the error column of \
                 pg_hba_file_rules)' >&2; exit 1;; \
                 *) echo 'zap: unexpected output from the pg_hba_file_rules check' >&2; exit 1;; esac; \
                 t0=$(sudo -u postgres psql -X -tAc 'SELECT pg_conf_load_time()') && [ -n \"$t0\" ] || \
                 {{ echo 'zap: could not read when PostgreSQL last loaded its configuration' >&2; exit 1; }}; \
                 sudo -u postgres psql -X -tAc 'SELECT pg_reload_conf()' | grep -qx t || \
                 {{ echo 'zap: PostgreSQL did not reload its configuration' >&2; exit 1; }}; \
                 w=0; while t=$(sudo -u postgres psql -X -tAc 'SELECT pg_conf_load_time()') && [ -n \"$t\" ] || \
                 {{ echo 'zap: could not read when PostgreSQL last loaded its configuration' >&2; exit 1; }}; \
                 [ \"$t\" = \"$t0\" ]; do [ $w -lt 30 ] || \
                 {{ echo 'zap: PostgreSQL did not load its configuration within 30 seconds of \
                 the reload, so the rule may not be in force; a postgresql.conf it can not parse keeps \
                 the load time from moving (see the server log)' >&2; exit 1; }}; \
                 w=$((w + 1)); sleep 1; done; \
                 ok=$(sudo -u postgres psql -X -tAc \
                 'SELECT NOT EXISTS (SELECT FROM pg_hba_file_rules WHERE error IS NOT NULL)') || {{ s=$?; \
                 echo 'zap: could not read pg_hba_file_rules (PostgreSQL 10 or later)' >&2; exit $s; }}; \
                 [ \"$ok\" = t ] || {{ echo 'zap: PostgreSQL can not parse its pg_hba.conf, \
                 which changed after it was checked, so the rule may not be in force (see the error \
                 column of pg_hba_file_rules)' >&2; exit 1; }};; \
                 '') ;; \
                 *) echo 'zap: unexpected output from the pg_hba rewrite' >&2; exit 1;; esac"
            )
        );
    }

    /// The rewrite and the read of the file both run as the account that owns it, and
    /// neither under a bare `sudo`: root never opens the path the server names.
    #[test]
    fn the_pg_hba_file_is_read_and_rewritten_as_postgres_never_root() {
        let step = pg_hba_rule_step("app", "app", "127.0.0.1/32", "trust");
        let read = pg_hba_find_rules(&["a'b".to_owned(), "c".to_owned()]);
        assert_eq!(
            read,
            format!("sudo -u postgres sh -c '{PG_HBA_FIND_RULES}' sh \"$hba\" 'a'\\''b' 'c'")
        );
        for command in [step.as_str(), read.as_str()] {
            assert_eq!(
                command.matches("sudo ").count(),
                command.matches("sudo -u postgres ").count(),
                "{command}"
            );
        }
        // The rewrite refuses a file that isn't the account's own before it stages
        // anything, and compares bytes as well as lines before it installs.
        let owner = PG_HBA_ADD_RULE.find("does not belong to").unwrap();
        let stage = PG_HBA_ADD_RULE.find("tmp=$(mktemp ").unwrap();
        assert!(owner < stage);
        assert!(PG_HBA_ADD_RULE.contains("[ \"$(wc -c <$fd)\" -eq "));
    }

    #[test]
    fn pg_hba_pattern_escapes_every_field() {
        assert_eq!(
            pg_hba_pattern("app", "app", "127.0.0.1/32", "trust"),
            r"^\s*host\s+app\s+app\s+127\.0\.0\.1/32\s+trust(\s|$)"
        );
    }

    #[test]
    fn pg_hba_pattern_leaves_env_refs_resolvable() {
        // A reference whose marker the escaping changed would no longer resolve when
        // the step runs — the guard would never match the line its step inserts. The
        // marker survives verbatim; everything around it still escapes.
        let user = crate::var_ref::marker("USER");
        assert_eq!(
            pg_hba_pattern("app", &format!("{user}.x"), "127.0.0.1/32", "trust"),
            format!(r"^\s*host\s+app\s+{user}\.x\s+127\.0\.0\.1/32\s+trust(\s|$)")
        );
        // A `$` is a metachar to escape, wherever it stands.
        assert_eq!(
            pg_hba_pattern("app", "lap$", "127.0.0.1/32", "trust"),
            r"^\s*host\s+app\s+lap\$\s+127\.0\.0\.1/32\s+trust(\s|$)"
        );
    }
}
