//! One step of a change: a command, a note, or an operation one of zap's constant
//! scripts carries out.
//!
//! A typed step ([`PutStep`], [`DirStep`], [`PgHbaRuleStep`], [`InstallerStep`],
//! [`SwapCheckStep`]) holds
//! what the operation is — the path, the mode, who it runs as, the content or which of
//! zap's commands produces it, the URL and the shell — and never the shell text that
//! performs it. [`PlanStep::execution`] is the one place a typed step becomes what
//! runs, and [`PlanStep::summary`] the one place it is named, for a preview line and a
//! failure alike.

use serde::{Deserialize, Serialize};

use crate::fetch_url::TARGET_CURL;
use crate::observe::swap::FSTAB_PATH;
use crate::postgres::{pg_hba_rule_line, pg_hba_rule_step};
use crate::put::{
    FileAttrs, PutCheck, RunAs, dir_attrs_command, file_put_command, put_text_step,
    put_text_step_keeping_mode,
};
use crate::scalar::{AccountName, Mode};
use crate::schema::{
    PgAuthMethod, apt_source_command, copy_source_home, copy_source_keys, fstab_swap_entry,
    fstab_with_entry, table_lists_path,
};
use crate::shell::single_quote;

/// One step of a change's plan: a verbatim-runnable shell command, a human-readable
/// preview note that is **not** safe to execute as-is, or a typed operation.
///
/// A `Note` marks a step whose real command isn't pre-bakeable at plan time (needs
/// native IO, or a manager zap has no backend for) — the executor never tries to
/// `sh -c` a preview like `"[package not defined for apt]"`. A typed step is an
/// operation zap performs through shell text of its own — a constant script
/// ([`FILE_PUT`](crate::put::FILE_PUT), [`DIR_ATTRS`](crate::put::DIR_ATTRS),
/// [`PG_HBA_ADD_RULE`](crate::postgres::PG_HBA_ADD_RULE)) or the fetch an installer's
/// script arrives by: the step says what is done, and that text is no part of it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PlanStep {
    /// A complete shell command to run verbatim, in order.
    Run(String),
    /// A preview/description shown in the dry-run but not executed as-is (the
    /// executor must firm it into real commands).
    Note(String),
    /// Install a file.
    Put(PutStep),
    /// Make a directory and set its mode and owner.
    Dir(DirStep),
    /// Add a rule to the `PostgreSQL` server's `pg_hba.conf`.
    PgHbaRule(PgHbaRuleStep),
    /// Fetch an installer script and run it.
    Installer(InstallerStep),
    /// Check a swap file's path before it is allocated.
    SwapCheck(SwapCheckStep),
}

impl PlanStep {
    /// Convenience for an executable command step.
    pub fn run(cmd: impl Into<String>) -> Self {
        Self::Run(cmd.into())
    }

    /// Convenience for a non-executable preview step.
    pub fn note(text: impl Into<String>) -> Self {
        Self::Note(text.into())
    }

    /// How the executor carries the step out; `None` for a [`Note`](Self::Note), which
    /// it doesn't.
    #[must_use]
    pub fn execution(&self) -> Option<StepExecution<'_>> {
        match self {
            Self::Run(cmd) => Some(StepExecution::Command(cmd.clone())),
            Self::Note(_) => None,
            Self::Put(put) => Some(put.execution()),
            Self::Dir(dir) => Some(StepExecution::Command(dir.command())),
            Self::PgHbaRule(rule) => Some(StepExecution::Command(rule.command())),
            Self::Installer(installer) => Some(StepExecution::Command(installer.command())),
            Self::SwapCheck(check) => Some(StepExecution::Command(check.command())),
        }
    }

    /// Call `f` with every text of the step a reference can stand in: a command, a
    /// note, a put's path and content, the source line or the swap path its producer
    /// is built from, a directory's path, a rule's database, role and address, an
    /// installer's URL and shell. The closed-set fields — modes, accounts, checks, an
    /// authentication method — hold none.
    pub fn for_each_text<'a>(&'a self, mut f: impl FnMut(&'a str)) {
        match self {
            Self::Run(text) | Self::Note(text) => f(text),
            Self::Put(PutStep {
                path,
                run_as: _,
                check: _,
                source,
            }) => {
                f(path);
                match source {
                    PutSource::Text(PutText { mode: _, content }) => f(content),
                    PutSource::Command(PutCommand { mode: _, producer }) => match producer {
                        PutProducer::AptSourceLine { line } => f(line),
                        PutProducer::FstabSwapEntry { path } => f(path),
                        PutProducer::AuthorizedKeysOf { account: _ } => {}
                    },
                }
            }
            Self::Dir(DirStep {
                path,
                mode: _,
                owner: _,
                group: _,
            })
            | Self::SwapCheck(SwapCheckStep { path }) => f(path),
            Self::PgHbaRule(PgHbaRuleStep {
                database,
                user,
                host,
                method: _,
            }) => {
                f(database);
                f(user);
                f(host);
            }
            Self::Installer(InstallerStep { url, shell }) => {
                f(url);
                f(shell);
            }
        }
    }

    /// What a typed step is, in words; `None` for a [`Run`](Self::Run) or a
    /// [`Note`](Self::Note), which are their own text.
    #[must_use]
    pub fn summary(&self) -> Option<StepSummary> {
        match self {
            Self::Run(_) | Self::Note(_) => None,
            Self::Put(put) => Some(put.summary()),
            Self::Dir(dir) => Some(dir.summary()),
            Self::PgHbaRule(rule) => Some(rule.summary()),
            Self::Installer(installer) => Some(installer.summary()),
            Self::SwapCheck(check) => Some(check.summary()),
        }
    }
}

/// How a step is carried out on the target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StepExecution<'a> {
    /// Run this shell text. Its references are resolved first.
    Command(String),
    /// Run `command` — [`file_put_command`]'s, the same text for any content — with
    /// `content` on its stdin behind the content's SHA-512 line
    /// ([`FILE_PUT`](crate::put::FILE_PUT)'s contract). Neither holds a reference.
    Put {
        /// The command that runs the put script.
        command: String,
        /// The bytes it installs.
        content: &'a str,
    },
}

impl StepExecution<'_> {
    /// The shell text the step runs — the whole of it for a
    /// [`Command`](Self::Command), the put's command for a [`Put`](Self::Put).
    #[must_use]
    pub fn text(&self) -> &str {
        match self {
            Self::Command(text) | Self::Put { command: text, .. } => text,
        }
    }
}

/// What a typed step is, in words: the one description a preview line and a failure
/// message are both built from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StepSummary {
    /// The operation and what it acts on (`put /etc/sudoers.d/deploy`).
    pub what: String,
    /// How: the mode, the owner, who it runs as, a check (`mode 440, as root, checked
    /// by visudo`).
    pub details: String,
}

impl StepSummary {
    /// The step as one phrase, as a failure names it: `<what> (<details>)`.
    #[must_use]
    pub fn label(&self) -> String {
        format!("{} ({})", self.what, self.details)
    }
}

/// Who a typed step's script runs as. Never the connecting user: a plan step that
/// writes a file says whose privileges the write is made with.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PutAs {
    /// Root (`sudo`).
    Root,
    /// A named account (`sudo -u`): a write into a directory that account owns is made
    /// with its privileges.
    User(AccountName),
}

impl PutAs {
    /// The [`RunAs`] the put script's command is built for.
    #[must_use]
    pub fn run_as(&self) -> RunAs<'_> {
        match self {
            Self::Root => RunAs::Root,
            Self::User(name) => RunAs::User(name.as_str()),
        }
    }

    /// `root`, or the account's name.
    fn name(&self) -> &str {
        match self {
            Self::Root => "root",
            Self::User(name) => name.as_str(),
        }
    }
}

/// Install a file through [`FILE_PUT`](crate::put::FILE_PUT): staged beside the path,
/// verified against its SHA-512, given its mode, optionally checked, and renamed into
/// place.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PutStep {
    /// The absolute path installed.
    pub path: String,
    /// Who the put runs as.
    pub run_as: PutAs,
    /// A check the staged file must pass before it is installed.
    pub check: PutCheck,
    /// Where the content comes from, and the mode it is installed at.
    pub source: PutSource,
}

/// Where a [`PutStep`]'s content comes from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PutSource {
    /// Text the plan holds.
    Text(PutText),
    /// What a command prints on the target.
    Command(PutCommand),
}

/// Content the plan holds: the exact bytes installed. zap computes their SHA-512 and
/// sends it, with the bytes, on the put script's stdin.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PutText {
    /// The mode the file is installed at.
    pub mode: Mode,
    /// The bytes installed, as text. Holds no reference: nothing resolves
    /// one here.
    pub content: String,
}

/// Content a command prints on the target: the step captures it there, digests the
/// capture with the target's `sha512sum`, and pipes both to the put script
/// ([`put_text_step`]).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PutCommand {
    /// The mode the file is installed at.
    pub mode: PutMode,
    /// Which of zap's commands prints the content.
    pub producer: PutProducer,
}

/// Which of zap's own commands prints a [`PutCommand`]'s content, and what it is given.
///
/// A closed set: a step names its producer and holds what the config said — a source
/// line, a path, an account — never shell text. The command, what runs ahead of it and
/// the guard that skips the step are derived here, from the helpers the detector's
/// reads are built from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum PutProducer {
    /// An `apt` source line, printed on the target after `/etc/os-release` is read
    /// ([`apt_source_command`]).
    AptSourceLine {
        /// The line as the list holds it, `signed-by` included. The target's shell
        /// reads it inside double quotes, which is how a `$VERSION_CODENAME` in it
        /// resolves — and a command substitution in it runs, when the step does and
        /// whenever the detector reads the line.
        line: String,
    },
    /// `/etc/fstab` as it reads, then the entry for a swap file ([`fstab_with_entry`]);
    /// the step does nothing when the table already lists the file
    /// ([`table_lists_path`], the detector's read).
    FstabSwapEntry {
        /// The swap file's path.
        path: String,
    },
    /// An account's `authorized_keys`, read as that account ([`copy_source_keys`]) from
    /// the home `/etc/passwd` gives it ([`copy_source_home`]).
    AuthorizedKeysOf {
        /// The account whose keys are copied.
        account: AccountName,
    },
}

impl PutProducer {
    /// The shell text whose output is installed. One that fails fails the step with
    /// nothing written.
    fn command(&self) -> String {
        match self {
            Self::AptSourceLine { line } => apt_source_command(line),
            Self::FstabSwapEntry { path } => fstab_with_entry(FSTAB_PATH, path),
            Self::AuthorizedKeysOf { account } => copy_source_keys(account, "cat"),
        }
    }

    /// Shell text run ahead of the command, in the step's own shell, whose variable the
    /// command reads. The put follows it whatever its status, so it exits the step
    /// itself when there is nothing to go on: an account with no home.
    fn setup(&self) -> Option<String> {
        match self {
            Self::AptSourceLine { .. } | Self::FstabSwapEntry { .. } => None,
            Self::AuthorizedKeysOf { account } => Some(format!(
                "{} || {{ echo {} >&2; exit 1; }}",
                copy_source_home(account),
                single_quote(&format!("zap: no home directory for {}", account.as_str())),
            )),
        }
    }

    /// Shell text that, when it succeeds, means the file already holds what the step
    /// would add: the step then does nothing.
    fn guard(&self) -> Option<String> {
        match self {
            Self::AptSourceLine { .. } | Self::AuthorizedKeysOf { .. } => None,
            Self::FstabSwapEntry { path } => Some(table_lists_path(FSTAB_PATH, path)),
        }
    }

    /// Where the content comes from, in words, and the text of the config's it is
    /// made of.
    #[must_use]
    pub fn summary(&self) -> ProducerSummary {
        match self {
            Self::AptSourceLine { line } => ProducerSummary {
                from: "the line below, as the target's shell reads it inside double quotes \
                       after reading /etc/os-release: a variable in it expands and a $(…) \
                       in it runs, at every plan too"
                    .to_owned(),
                line: Some(line.clone()),
            },
            Self::FstabSwapEntry { path } => ProducerSummary {
                from: format!(
                    "{FSTAB_PATH} as it reads, then the line below; skipped when it lists {path}"
                ),
                line: Some(fstab_swap_entry(path)),
            },
            Self::AuthorizedKeysOf { account } => ProducerSummary {
                from: format!(
                    "the authorized_keys of {account}, read as {account}",
                    account = account.as_str()
                ),
                line: None,
            },
        }
    }
}

/// A [`PutProducer`] in words: what a preview prints under a put of a command's output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProducerSummary {
    /// Where the content comes from.
    pub from: String,
    /// The line the content is, or ends with, as the step's shell is given it — before
    /// the target expands anything in it.
    pub line: Option<String>,
}

/// The mode a [`PutCommand`] installs its file at.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum PutMode {
    /// This mode.
    Set(Mode),
    /// The mode the file has, so the rewrite changes content only
    /// ([`put_text_step_keeping_mode`]).
    Keep {
        /// The mode of a file that isn't there yet.
        if_new: Mode,
    },
}

impl PutStep {
    fn execution(&self) -> StepExecution<'_> {
        let run_as = self.run_as.run_as();
        match &self.source {
            PutSource::Text(text) => StepExecution::Put {
                command: file_put_command(
                    run_as,
                    &self.path,
                    FileAttrs::mode(text.mode.as_str()),
                    self.check,
                ),
                content: &text.content,
            },
            PutSource::Command(command) => {
                let producer = command.producer.command();
                let put = match &command.mode {
                    PutMode::Set(mode) => put_text_step(
                        &producer,
                        run_as,
                        &self.path,
                        FileAttrs::mode(mode.as_str()),
                        self.check,
                    ),
                    PutMode::Keep { if_new } => put_text_step_keeping_mode(
                        &producer,
                        run_as,
                        &self.path,
                        FileAttrs::mode(if_new.as_str()),
                        self.check,
                    ),
                };
                let put = match command.producer.setup() {
                    Some(setup) => format!("{setup}; {put}"),
                    None => put,
                };
                StepExecution::Command(match command.producer.guard() {
                    Some(guard) => format!("{guard} || {{ {put}; }}"),
                    None => put,
                })
            }
        }
    }

    fn summary(&self) -> StepSummary {
        let mode = match &self.source {
            PutSource::Text(PutText { mode, .. })
            | PutSource::Command(PutCommand {
                mode: PutMode::Set(mode),
                ..
            }) => format!("mode {}, ", mode.as_str()),
            PutSource::Command(PutCommand {
                mode: PutMode::Keep { if_new },
                ..
            }) => format!("keeps its mode, {} if new; ", if_new.as_str()),
        };
        let check = match self.check {
            PutCheck::None => "",
            PutCheck::Sudoers => ", checked by visudo",
        };
        StepSummary {
            what: format!("put {}", self.path),
            details: format!("{mode}as {}{check}", self.run_as.name()),
        }
    }
}

/// Make a directory when it is missing (`mkdir -p`), then set its mode and owner
/// through [`DIR_ATTRS`](crate::put::DIR_ATTRS), which refuses a symbolic link at the
/// path. Both run as root.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirStep {
    /// The absolute path of the directory.
    pub path: String,
    /// The mode it is set to.
    pub mode: Mode,
    /// The user it is given to.
    pub owner: AccountName,
    /// The group it is given to.
    pub group: AccountName,
}

impl DirStep {
    fn command(&self) -> String {
        format!(
            "sudo mkdir -p -- {} && {}",
            single_quote(&self.path),
            dir_attrs_command(
                RunAs::Root,
                &self.path,
                FileAttrs {
                    mode: Some(self.mode.as_str()),
                    owner: Some(self.owner.as_str()),
                    group: Some(self.group.as_str()),
                    ..FileAttrs::NONE
                },
            )
        )
    }

    fn summary(&self) -> StepSummary {
        StepSummary {
            what: format!("dir {}", self.path),
            details: format!(
                "mode {}, owner {}:{}, as root, created if missing",
                self.mode.as_str(),
                self.owner.as_str(),
                self.group.as_str()
            ),
        }
    }
}

/// The check a swap file's creation runs first, as root, before anything is written.
///
/// `mkswap` overwrites whatever is at the path, so the path must be absolute, every
/// directory on the way to it must be root's and writable by no group or other account
/// (so no one but root can put a link at the path between this check and the steps
/// after it, or re-point a directory above it), and the path must not be a symbolic
/// link (one would send the allocation, the mode, and the format to another file). The
/// directories are walked twice up to `/`: the path's own, as declared, each read where
/// it resolves (`stat -L`), and the one it resolves to (`readlink -f`), each as itself,
/// so a link on the declared path is judged by the directory holding it and by where
/// it leads. A refusal names the path, the directory, and why, and exits
/// [`REFUSED_EXIT`](crate::put::REFUSED_EXIT).
///
/// Positional parameter: the swap file's path (`$1`). One constant text, holding no `'`
/// or newline, passed as one single-quoted word to `sh -c`.
pub const SWAP_PATH_CHECK: &str = concat!(
    r#"p=$1; "#,
    crate::put::refusal!("; no swap file was made"),
    crate::put::absolute_path!(),
    r#"ok() { o=$(stat $2 -c %u:%a -- "$1") && case $o in 0:*[2367]|0:*[2367]?) false;; 0:?*) ;; *) false;; esac || "#,
    r#"no "the directory $1 on its path can not be read, is not owned by root, or can be written by other accounts"; }; "#,
    r#"up() { d=$1; while :; do d=${d%/*}; d=${d:-/}; ok "$d" $2; [ "$d" != / ] || break; done; }; "#,
    r#"up "$p" -L; r=$(readlink -f -- "${p%/*}/") && [ -n "$r" ] || no "its directory can not be resolved"; "#,
    r#"up "${r%/}/x"; "#,
    r#"[ ! -L "$p" ] || no "a symbolic link is not made into swap""#,
);

/// Check a swap file's path before the steps that allocate, format, and enable it.
///
/// Through [`SWAP_PATH_CHECK`], as root: every directory on the way to it must be root's
/// and writable by no one else, and the path no symbolic link.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SwapCheckStep {
    /// The swap file's path, as declared (absolute).
    pub path: String,
}

impl SwapCheckStep {
    fn command(&self) -> String {
        format!(
            "sudo sh -c {} sh {}",
            single_quote(SWAP_PATH_CHECK),
            single_quote(&self.path)
        )
    }

    fn summary(&self) -> StepSummary {
        StepSummary {
            what: format!("check {}", self.path),
            details: "not a link, below directories only root writes, as root".to_owned(),
        }
    }
}

/// Add one `host` rule to the server's `pg_hba.conf` unless a matching rule is there
/// ([`pg_hba_rule_step`]).
///
/// The file is the one the server reports, it is rewritten as the `postgres` account,
/// and the rule goes above its first `host` record. A rule added is put in force by
/// reloading the server's configuration (`pg_reload_conf()`) and waiting for the
/// server to load it, and the step fails if the server can't parse the file
/// (`pg_hba_file_rules` lists an error, checked before the reload) or doesn't load it
/// in time; one already there reloads nothing.
///
/// The database and user are as declared: a reference in one resolves when
/// the step runs, as it does for the detector's read.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PgHbaRuleStep {
    /// The rule's database.
    pub database: String,
    /// The rule's role.
    pub user: String,
    /// The rule's address, in CIDR notation.
    pub host: String,
    /// The rule's authentication method.
    pub method: PgAuthMethod,
}

impl PgHbaRuleStep {
    fn command(&self) -> String {
        pg_hba_rule_step(&self.database, &self.user, &self.host, self.method.as_str())
    }

    fn summary(&self) -> StepSummary {
        StepSummary {
            what: format!(
                "pg_hba rule: {}",
                pg_hba_rule_line(&self.database, &self.user, &self.host, self.method.as_str())
            ),
            details: "as postgres, in the server's hba_file, above its first host record, \
                      unless it is already there; an added rule reloads the server's \
                      configuration"
                .to_owned(),
        }
    }
}

/// What a step prints when an installer's fetch succeeded and the script is empty.
const EMPTY_INSTALLER_SCRIPT: &str = "zap: the installer script is empty";

/// Fetch an installer script and hand it to a shell on its stdin.
///
/// The script is fetched whole into a shell variable, and the shell is started only
/// with a script to run. A plain `curl … | <shell>` has the shell's status, and a shell
/// given nothing exits 0: a fetch that failed, or one that answered with no script,
/// would read as an install that ran. Here a failed fetch is the step's own failure,
/// with `curl`'s status, and a script that is empty or only newlines fails the step
/// with a message on its stderr. The script is text — the capture drops a NUL and its
/// trailing newlines, and one newline is written back — and it is written by the
/// shell's own `printf`, a builtin, so it is on no argv.
///
/// The URL and the shell are as declared: a reference in either resolves when the step
/// runs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstallerStep {
    /// Where the script is fetched from: [`TARGET_CURL`]'s fetch — https only, the
    /// redirects it follows included.
    pub url: String,
    /// The command the script is piped to. Command text, run as written: it may carry
    /// arguments (`sh -s -- --yes`).
    pub shell: String,
}

impl InstallerStep {
    /// The URL follows `--`, single-quoted; the shell is left bare, since it is a
    /// command position and not one word.
    fn command(&self) -> String {
        format!(
            "zap_s=$({TARGET_CURL} -- {}) || exit; \
             [ -n \"$zap_s\" ] || {{ echo '{EMPTY_INSTALLER_SCRIPT}' >&2; exit 1; }}; \
             printf '%s\\n' \"$zap_s\" | {}",
            single_quote(&self.url),
            self.shell
        )
    }

    fn summary(&self) -> StepSummary {
        StepSummary {
            what: format!("run the script fetched from {}", self.url),
            details: format!("piped to {}", self.shell),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        DirStep, InstallerStep, PgHbaRuleStep, PlanStep, ProducerSummary, PutAs, PutCommand,
        PutMode, PutProducer, PutSource, PutStep, PutText, StepExecution,
    };
    use crate::postgres::{PG_HBA_ADD_RULE, pg_hba_rule_step};
    use crate::put::{
        DIR_ATTRS, FILE_PUT, FileAttrs, PutCheck, RunAs, dir_attrs_command, file_put_command,
    };
    use crate::scalar::{AccountName, Mode};
    use crate::schema::PgAuthMethod;
    use crate::var_ref::marker;

    fn mode(mode: &str) -> Mode {
        Mode::new(mode).unwrap()
    }

    fn account(name: &str) -> AccountName {
        AccountName::new(name).unwrap()
    }

    fn text_put() -> PutStep {
        PutStep {
            path: "/etc/sudoers.d/deploy".to_owned(),
            run_as: PutAs::Root,
            check: PutCheck::Sudoers,
            source: PutSource::Text(PutText {
                mode: mode("440"),
                content: "deploy ALL=(ALL) NOPASSWD: ALL\n".to_owned(),
            }),
        }
    }

    /// The put of an `apt_repo`'s list, as its builder makes it.
    fn apt_put() -> PutStep {
        PutStep {
            path: "/etc/apt/sources.list.d/pgdg.list".to_owned(),
            run_as: PutAs::Root,
            check: PutCheck::None,
            source: PutSource::Command(PutCommand {
                mode: PutMode::Set(mode("644")),
                producer: PutProducer::AptSourceLine {
                    line: "deb [signed-by=/usr/share/keyrings/pgdg.asc] \
                           https://example.com/apt $VERSION_CODENAME-pgdg main"
                        .to_owned(),
                },
            }),
        }
    }

    /// The put of a `swap`'s fstab entry, as its builder makes it.
    fn fstab_put() -> PutStep {
        PutStep {
            path: "/etc/fstab".to_owned(),
            run_as: PutAs::Root,
            check: PutCheck::None,
            source: PutSource::Command(PutCommand {
                mode: PutMode::Keep {
                    if_new: mode("644"),
                },
                producer: PutProducer::FstabSwapEntry {
                    path: "/sw'ap file".to_owned(),
                },
            }),
        }
    }

    /// The put of a `copy_from` user's key file, as its builder makes it.
    fn keys_put() -> PutStep {
        PutStep {
            path: "/home/deploy/.ssh/authorized_keys".to_owned(),
            run_as: PutAs::User(account("deploy")),
            check: PutCheck::None,
            source: PutSource::Command(PutCommand {
                mode: PutMode::Set(mode("600")),
                producer: PutProducer::AuthorizedKeysOf {
                    account: account("ops"),
                },
            }),
        }
    }

    fn installer() -> InstallerStep {
        InstallerStep {
            url: format!("https://{}/i.sh", marker("MIRROR")),
            shell: "sh -s -- --yes".to_owned(),
        }
    }

    fn dir() -> DirStep {
        DirStep {
            path: "/home/deploy/.ssh".to_owned(),
            mode: mode("700"),
            owner: account("deploy"),
            group: account("www"),
        }
    }

    fn rule() -> PgHbaRuleStep {
        PgHbaRuleStep {
            database: "app".to_owned(),
            user: marker("ROLE"),
            host: "::1/128".to_owned(),
            method: PgAuthMethod::ScramSha256,
        }
    }

    #[test]
    fn a_text_put_runs_the_put_command_with_its_content_on_stdin() {
        let put = text_put();
        assert_eq!(
            PlanStep::Put(put).execution(),
            Some(StepExecution::Put {
                command: file_put_command(
                    RunAs::Root,
                    "/etc/sudoers.d/deploy",
                    FileAttrs::mode("440"),
                    PutCheck::Sudoers,
                ),
                content: "deploy ALL=(ALL) NOPASSWD: ALL\n",
            })
        );
    }

    /// What each producer's put runs, the put script's own text aside: the command, the
    /// setup ahead of it, the guard around it, and the feeder that captures and digests
    /// the command's output, each byte of it.
    #[test]
    fn a_command_put_lowers_to_the_text_its_producer_derives() {
        let text = |step: PutStep| match PlanStep::Put(step).execution() {
            Some(StepExecution::Command(text)) => text.replace(FILE_PUT, "<FILE_PUT>"),
            other => panic!("expected a command, got {other:?}"),
        };
        assert_eq!(
            text(apt_put()),
            "zap_c=$(. /etc/os-release && printf '%s\\n' \"deb [signed-by=/usr/share/keyrings/pgdg.asc] https://example.com/apt $VERSION_CODENAME-pgdg main\" && echo .) || exit 1; zap_c=${zap_c%.}; zap_h=$(printf %s \"$zap_c\" | sha512sum) || exit 1; { printf \"%s\\n\" \"${zap_h%% *}\"; printf %s \"$zap_c\"; } | sudo sh -c '<FILE_PUT>' sh '/etc/apt/sources.list.d/pgdg.list' '644' '' '' ''"
        );
        // The guard skips the whole of it, the mode read included.
        assert_eq!(
            text(fstab_put()),
            "P='/sw'\\''ap file' awk '$1 == ENVIRON[\"P\"] { found = 1 } END { exit !found }' /etc/fstab || { if [ -e '/etc/fstab' ]; then zap_m=$(stat -L -c %a '/etc/fstab') && [ -n \"$zap_m\" ] || exit 1; if command -v getfacl >/dev/null; then zap_a=$(getfacl -cps -- '/etc/fstab') || exit 1; else zap_a=$(ls -dlL -- '/etc/fstab') || exit 1; case ${zap_a%% *} in *+) ;; *) zap_a=;; esac; fi; [ -z \"$zap_a\" ] || { printf 'zap: %s: it has an access list (ACL), which keeping its mode would drop; remove it (setfacl -b) to have it rewritten; left unchanged\\n' '/etc/fstab' >&2; exit 93; }; else zap_m='644'; fi; zap_c=$({ [ ! -e /etc/fstab ] || awk '{ print }' /etc/fstab; } && printf '%s\\n' '/sw'\\''ap file none swap sw 0 0' && echo .) || exit 1; zap_c=${zap_c%.}; zap_h=$(printf %s \"$zap_c\" | sha512sum) || exit 1; { printf \"%s\\n\" \"${zap_h%% *}\"; printf %s \"$zap_c\"; } | sudo sh -c '<FILE_PUT>' sh '/etc/fstab' \"$zap_m\" '' '' ''; }"
        );
        // The setup runs ahead of the put, in the same shell.
        assert_eq!(
            text(keys_put()),
            "SRC_HOME=$(awk -F: -v u='ops' '$1\"\"==u{print $6}' /etc/passwd) && [ -n \"$SRC_HOME\" ] || { echo 'zap: no home directory for ops' >&2; exit 1; }; zap_c=$(sudo -u 'ops' cat -- \"$SRC_HOME/.ssh/authorized_keys\" && echo .) || exit 1; zap_c=${zap_c%.}; zap_h=$(printf %s \"$zap_c\" | sha512sum) || exit 1; { printf \"%s\\n\" \"${zap_h%% *}\"; printf %s \"$zap_c\"; } | sudo -u 'deploy' sh -c '<FILE_PUT>' sh '/home/deploy/.ssh/authorized_keys' '600' '' '' ''"
        );
    }

    #[test]
    fn an_installer_lowers_to_the_guarded_fetch_and_pipe() {
        assert_eq!(
            PlanStep::Installer(installer()).execution(),
            Some(StepExecution::Command(format!(
                "zap_s=$(curl --proto '=https' --proto-redir '=https' -fsSL -- \
                 'https://{}/i.sh') || exit; \
                 [ -n \"$zap_s\" ] || {{ echo 'zap: the installer script is empty' >&2; exit 1; }}; \
                 printf '%s\\n' \"$zap_s\" | sh -s -- --yes",
                marker("MIRROR")
            )))
        );
    }

    /// The texts a reference can stand in are the config's own: a producer's line or
    /// path, an installer's URL and shell — and nothing derived from them.
    #[test]
    fn a_steps_texts_are_what_the_config_wrote() {
        let texts = |step: PlanStep| {
            let mut texts = Vec::new();
            step.for_each_text(|text| texts.push(text.to_owned()));
            texts
        };
        assert_eq!(
            texts(PlanStep::Put(apt_put())),
            [
                "/etc/apt/sources.list.d/pgdg.list",
                "deb [signed-by=/usr/share/keyrings/pgdg.asc] https://example.com/apt \
                 $VERSION_CODENAME-pgdg main",
            ]
        );
        assert_eq!(
            texts(PlanStep::Put(fstab_put())),
            ["/etc/fstab", "/sw'ap file"]
        );
        assert_eq!(
            texts(PlanStep::Put(keys_put())),
            ["/home/deploy/.ssh/authorized_keys"]
        );
        assert_eq!(
            texts(PlanStep::Installer(installer())),
            [
                format!("https://{}/i.sh", marker("MIRROR")),
                "sh -s -- --yes".to_owned()
            ]
        );
    }

    #[test]
    fn a_producer_is_summarized_in_words_with_the_configs_line() {
        let summary = |step: PutStep| match step.source {
            PutSource::Command(command) => command.producer.summary(),
            PutSource::Text(_) => panic!("a command put"),
        };
        assert_eq!(
            summary(apt_put()),
            ProducerSummary {
                from: "the line below, as the target's shell reads it inside double quotes \
                       after reading /etc/os-release: a variable in it expands and a $(…) \
                       in it runs, at every plan too"
                    .to_owned(),
                line: Some(
                    "deb [signed-by=/usr/share/keyrings/pgdg.asc] https://example.com/apt \
                     $VERSION_CODENAME-pgdg main"
                        .to_owned()
                ),
            }
        );
        assert_eq!(
            summary(fstab_put()),
            ProducerSummary {
                from: "/etc/fstab as it reads, then the line below; skipped when it lists \
                       /sw'ap file"
                    .to_owned(),
                line: Some("/sw'ap file none swap sw 0 0".to_owned()),
            }
        );
        assert_eq!(
            summary(keys_put()),
            ProducerSummary {
                from: "the authorized_keys of ops, read as ops".to_owned(),
                line: None,
            }
        );
    }

    #[test]
    fn a_dir_and_a_pg_hba_rule_lower_to_their_commands() {
        assert_eq!(
            PlanStep::Dir(dir()).execution(),
            Some(StepExecution::Command(format!(
                "sudo mkdir -p -- '/home/deploy/.ssh' && {}",
                dir_attrs_command(
                    RunAs::Root,
                    "/home/deploy/.ssh",
                    FileAttrs {
                        mode: Some("700"),
                        owner: Some("deploy"),
                        group: Some("www"),
                        ..FileAttrs::NONE
                    },
                )
            )))
        );
        assert_eq!(
            PlanStep::PgHbaRule(rule()).execution(),
            Some(StepExecution::Command(pg_hba_rule_step(
                "app",
                &marker("ROLE"),
                "::1/128",
                "scram-sha-256"
            )))
        );
        assert_eq!(
            PlanStep::run("true").execution(),
            Some(StepExecution::Command("true".to_owned()))
        );
        assert_eq!(PlanStep::note("a note").execution(), None);
    }

    /// What each typed step runs holds its constant script, so a change to a script is
    /// a change to the text `plan_hash` folds.
    #[test]
    fn each_typed_step_runs_its_constant_script() {
        let text = |step: PlanStep| step.execution().unwrap().text().to_owned();
        assert!(text(PlanStep::Put(text_put())).contains(FILE_PUT));
        for put in [apt_put(), fstab_put(), keys_put()] {
            assert!(text(PlanStep::Put(put)).contains(FILE_PUT));
        }
        assert!(text(PlanStep::Dir(dir())).contains(DIR_ATTRS));
        assert!(text(PlanStep::PgHbaRule(rule())).contains(PG_HBA_ADD_RULE));
    }

    #[test]
    fn a_summary_names_the_operation_and_holds_no_script() {
        let label = |step: PlanStep| step.summary().unwrap().label();
        let labels = [
            (
                PlanStep::Put(text_put()),
                "put /etc/sudoers.d/deploy (mode 440, as root, checked by visudo)",
            ),
            (
                PlanStep::Put(apt_put()),
                "put /etc/apt/sources.list.d/pgdg.list (mode 644, as root)",
            ),
            (
                PlanStep::Put(fstab_put()),
                "put /etc/fstab (keeps its mode, 644 if new; as root)",
            ),
            (
                PlanStep::Put(keys_put()),
                "put /home/deploy/.ssh/authorized_keys (mode 600, as deploy)",
            ),
            (
                PlanStep::Installer(installer()),
                &format!(
                    "run the script fetched from https://{}/i.sh (piped to sh -s -- --yes)",
                    marker("MIRROR")
                ),
            ),
            (
                PlanStep::Dir(dir()),
                "dir /home/deploy/.ssh (mode 700, owner deploy:www, as root, created if missing)",
            ),
            (
                PlanStep::PgHbaRule(rule()),
                &format!(
                    "pg_hba rule: host    app    {}    ::1/128    scram-sha-256 (as postgres, \
                     in the server's hba_file, above its first host record, unless it is \
                     already there; an added rule reloads the server's configuration)",
                    marker("ROLE")
                ),
            ),
        ];
        for (step, expected) in labels {
            assert_eq!(label(step), expected);
        }
        assert_eq!(PlanStep::run("true").summary(), None);
        assert_eq!(PlanStep::note("a note").summary(), None);
    }

    #[test]
    fn each_step_round_trips_and_an_unknown_field_is_rejected() {
        let steps = [
            (PlanStep::run("true"), serde_json::json!({"run": "true"})),
            (
                PlanStep::note("a note"),
                serde_json::json!({"note": "a note"}),
            ),
            (
                PlanStep::Put(text_put()),
                serde_json::json!({"put": {
                    "path": "/etc/sudoers.d/deploy", "run_as": "root", "check": "sudoers",
                    "source": {"text": {
                        "mode": "440", "content": "deploy ALL=(ALL) NOPASSWD: ALL\n",
                    }},
                }}),
            ),
            (
                PlanStep::Put(apt_put()),
                serde_json::json!({"put": {
                    "path": "/etc/apt/sources.list.d/pgdg.list", "run_as": "root",
                    "check": "none",
                    "source": {"command": {
                        "mode": {"set": "644"},
                        "producer": {"apt_source_line": {
                            "line": "deb [signed-by=/usr/share/keyrings/pgdg.asc] \
                                     https://example.com/apt $VERSION_CODENAME-pgdg main",
                        }},
                    }},
                }}),
            ),
            (
                PlanStep::Put(fstab_put()),
                serde_json::json!({"put": {
                    "path": "/etc/fstab", "run_as": "root", "check": "none",
                    "source": {"command": {
                        "mode": {"keep": {"if_new": "644"}},
                        "producer": {"fstab_swap_entry": {"path": "/sw'ap file"}},
                    }},
                }}),
            ),
            (
                PlanStep::Dir(dir()),
                serde_json::json!({"dir": {
                    "path": "/home/deploy/.ssh", "mode": "700", "owner": "deploy",
                    "group": "www",
                }}),
            ),
            (
                PlanStep::PgHbaRule(rule()),
                serde_json::json!({"pg_hba_rule": {
                    "database": "app", "user": marker("ROLE"), "host": "::1/128",
                    "method": "scram-sha-256",
                }}),
            ),
            (
                PlanStep::Put(keys_put()),
                serde_json::json!({"put": {
                    "path": "/home/deploy/.ssh/authorized_keys", "run_as": {"user": "deploy"},
                    "check": "none",
                    "source": {"command": {
                        "mode": {"set": "600"},
                        "producer": {"authorized_keys_of": {"account": "ops"}},
                    }},
                }}),
            ),
            (
                PlanStep::Installer(installer()),
                serde_json::json!({"installer": {
                    "url": format!("https://{}/i.sh", marker("MIRROR")),
                    "shell": "sh -s -- --yes",
                }}),
            ),
        ];
        for (step, json) in &steps {
            assert_eq!(&serde_json::to_value(step).unwrap(), json);
            assert_eq!(
                &serde_json::from_value::<PlanStep>(json.clone()).unwrap(),
                step
            );
        }

        // A field no step has is an error wherever it is put.
        let stray = |pointer: &str, json: &serde_json::Value| {
            let mut json = json.clone();
            json.pointer_mut(pointer)
                .and_then(serde_json::Value::as_object_mut)
                .unwrap_or_else(|| panic!("no object at {pointer}"))
                .insert("stray".to_owned(), serde_json::json!(1));
            json
        };
        for (pointer, json) in [
            ("/put", &steps[2].1),
            ("/put/source/text", &steps[2].1),
            ("/put/source/command", &steps[3].1),
            ("/put/source/command/mode/keep", &steps[4].1),
            ("/put/source/command/producer/apt_source_line", &steps[3].1),
            ("/put/source/command/producer/fstab_swap_entry", &steps[4].1),
            ("/dir", &steps[5].1),
            ("/pg_hba_rule", &steps[6].1),
            (
                "/put/source/command/producer/authorized_keys_of",
                &steps[7].1,
            ),
            ("/installer", &steps[8].1),
        ] {
            let error = serde_json::from_value::<PlanStep>(stray(pointer, json))
                .expect_err("a stray field is rejected");
            assert!(error.to_string().contains("unknown field"), "{error}");
        }
        // A producer is one of the closed set, never shell text; a setup or a guard is
        // no field of a put, and a second producer beside the first is none either.
        let command = |edit: &dyn Fn(&mut serde_json::Map<String, serde_json::Value>)| {
            let mut json = steps[4].1.clone();
            edit(
                json.pointer_mut("/put/source/command")
                    .and_then(serde_json::Value::as_object_mut)
                    .unwrap(),
            );
            serde_json::from_value::<PlanStep>(json)
                .expect_err("not a command put")
                .to_string()
        };
        let shell = "{ [ ! -e /etc/fstab ] || awk '{ print }' /etc/fstab; } && echo x";
        let error = command(&|put| {
            put.insert("producer".to_owned(), serde_json::json!(shell));
        });
        assert!(error.contains("unknown variant"), "{error}");
        for stray in ["unless", "setup"] {
            let error = command(&|put| {
                put.insert(stray.to_owned(), serde_json::json!("true"));
            });
            assert!(
                error.contains(&format!("unknown field `{stray}`")),
                "{error}"
            );
        }
        for (producer, expected) in [
            (
                serde_json::json!({"cat": {"path": "/a"}}),
                "unknown variant `cat`",
            ),
            (
                serde_json::json!({"authorized_keys_of": {"account": "0"}}),
                "numeric owner/group `0`",
            ),
            (
                serde_json::json!({"authorized_keys_of": {"account": "o'ps"}}),
                "",
            ),
            (
                serde_json::json!({
                    "fstab_swap_entry": {"path": "/a"}, "apt_source_line": {"line": "deb x"},
                }),
                "",
            ),
        ] {
            let error = command(&|put| {
                put.insert("producer".to_owned(), producer.clone());
            });
            assert!(error.contains(expected), "{producer}: {error}");
        }

        // A value outside a closed set, a non-octal mode, and a numeric account are too.
        for (pointer, value) in [
            ("/put/check", serde_json::json!("lint")),
            ("/put/run_as", serde_json::json!("caller")),
            ("/put/source/text/mode", serde_json::json!("rw")),
            ("/put/run_as", serde_json::json!({"user": "0"})),
        ] {
            let mut json = steps[2].1.clone();
            *json.pointer_mut(pointer).unwrap() = value;
            assert!(
                serde_json::from_value::<PlanStep>(json).is_err(),
                "{pointer}"
            );
        }
    }
}
