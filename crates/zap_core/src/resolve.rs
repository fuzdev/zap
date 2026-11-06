//! Runtime string resolution — references, `$HOME`, and leading `~`.
//!
//! Two resolutions with **different sources of truth** live here, deliberately
//! kept apart (target-categorized):
//!
//! - **A reference** ([`resolve_env_vars`]) — *operator-machine* env, the same
//!   whether the target is local or remote (secrets/config resolved in the parent,
//!   where that authority lives). A content address resolves only these: built from
//!   declared desired state, leaving `~`/`$HOME` literal so it is deterministic,
//!   offline-reproducible, and identical across operators/CI. The `zap.lock` entry
//!   address (`crate::lock::entry_config_hash`) resolves them through its own resolver,
//!   which gives a secret reference its fixed token instead of its value.
//! - **`~` / `$HOME`** — the *target's* home directory. [`expand_runtime_path`]
//!   resolves it against the **local** operator's `$HOME` (correct: for a local
//!   target the operator *is* the target). For a remote target the home is the
//!   remote's, so it is resolved at the IO boundary by the `Connection` (using the
//!   declared `target.home`); see `Connection::apply_home`. The hash never bakes
//!   it in.
//!
//! References that aren't set resolve to empty — a missing env var is not an error
//! *at resolution*. Before a wetrun
//! `apply` or `deploy` executes, though, the [`unresolved_env_vars`] preflight
//! rejects a config whose referenced vars are unset/empty, so a missing value fails
//! loudly up front instead of silently writing an empty string into a command, file,
//! or `.env`. A dry run executes nothing, so it must still render without the values (the
//! one fetch it makes, a cold-start pin, is skipped for a url it can't resolve, and that
//! resource holds) — but a command that **compares** declared state against a
//! target ([`unverifiable_env_vars`]) still can't trust the diff it just computed, and
//! says so rather than reporting a confident "converged" / "drifted".

use std::collections::{BTreeSet, HashMap};
use std::path::Path;
use std::sync::OnceLock;

use zap_types::schema::TemplateContent;
use zap_types::secrecy::Secrecy;
use zap_types::var_ref;

use crate::error::{Error, Result};

/// Process-wide operator-env overlay, populated once at startup from `--env-file`.
///
/// Every operator-env read funnels through [`env_var`], which consults this overlay
/// **before** falling through to `std::env` — so a reference and the secret
/// reader both see the file's values without mutating the process environment
/// (`std::env::set_var` is `unsafe`, forbidden workspace-wide). Set once via
/// [`set_env_overlay`] in the binary's startup; unset in library/test contexts, so
/// reads fall through to `std::env` exactly as before (test hermeticity preserved).
static ENV_OVERLAY: OnceLock<HashMap<String, String>> = OnceLock::new();

/// Install the operator-env overlay (the `--env-file` contents).
///
/// Call once, at startup, before any resolution. Returns `false` if an overlay was
/// already set (the overlay is set-once; a second call is a no-op). The default-hasher
/// `HashMap` is deliberate — the overlay is built once from [`parse_env_file`], not a
/// hot path.
#[allow(clippy::implicit_hasher)]
pub fn set_env_overlay(vars: HashMap<String, String>) -> bool {
    ENV_OVERLAY.set(vars).is_ok()
}

/// Read an operator env var: the `--env-file` overlay first, then `std::env`.
///
/// The single funnel for every config/secret env read in the engine, so `--env-file`
/// reaches the direct reference path and the injected secret reader alike.
#[must_use]
pub fn env_var(name: &str) -> Option<String> {
    #[cfg(test)]
    if let Some(value) = test_env::get(name) {
        return Some(value);
    }
    if let Some(value) = ENV_OVERLAY.get().and_then(|overlay| overlay.get(name)) {
        return Some(value.clone());
    }
    std::env::var(name).ok()
}

/// Why an env file isn't one zap reads: its first line zap isn't sure of.
///
/// It names the line and — when the line has one — the variable, and never any part of
/// a value.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("line {line}: {}", .problem.describe(.name.as_deref()))]
pub struct EnvFileProblem {
    /// The line's number, from 1.
    pub line: usize,
    /// The variable the line assigns, when its name is a variable's name.
    pub name: Option<String>,
    /// What is wrong with the line.
    pub problem: EnvLineProblem,
}

/// What is wrong with one line of an env file ([`EnvFileProblem`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnvLineProblem {
    /// The line has no `=`.
    NoAssignment,
    /// What stands before the `=` is not an environment variable's name.
    Name,
    /// The variable is assigned on an earlier line too.
    Duplicate {
        /// That earlier line's number.
        first: usize,
    },
    /// An unquoted value holds a `#` a reader may take for a comment: at its start, or
    /// after whitespace.
    Comment,
    /// A quoted value has no closing quote on its line.
    Unterminated,
    /// Text that is not a comment follows a value's closing quote.
    AfterQuote,
    /// An unquoted value holds a control character other than a tab, or a Unicode
    /// line or paragraph separator: something a reader may take for the end of the
    /// line.
    Control,
    /// An unquoted value ends in a backslash, which a shell reads as joining the next
    /// line to this one.
    Continuation,
    /// The value holds a NUL byte.
    Nul,
}

impl EnvLineProblem {
    /// The problem in words, naming the variable `name` when the line has one.
    fn describe(&self, name: Option<&str>) -> String {
        let var = name.map_or_else(|| "the value".to_owned(), |name| format!("`{name}`"));
        match self {
            Self::NoAssignment => "not a blank line, a `#` comment, or a `NAME=VALUE` \
                                   assignment (a value is one line: a quoted value that \
                                   continues on the next line isn't read)"
                .to_owned(),
            Self::Name => "what stands before the `=` is not a variable's name \
                           (`[A-Za-z_][A-Za-z0-9_]*`)"
                .to_owned(),
            Self::Duplicate { first } => {
                format!("{var} is already assigned on line {first}; assign it once")
            }
            Self::Comment => format!(
                "{var} has an unquoted value holding a `#` that reads as a comment to some \
                 tools and as part of the value to others — quote the value if the `#` \
                 belongs to it, or move the comment to a line of its own"
            ),
            Self::Unterminated => format!(
                "{var} has a quoted value with no closing quote on its line (a value is one \
                 line: write a line break in a double-quoted value as `\\n`)"
            ),
            Self::AfterQuote => {
                format!("{var} has text after its value's closing quote that is not a `#` comment")
            }
            Self::Control => format!(
                "{var} has an unquoted value holding a control character or a line \
                 separator, which some tools read as the end of the line — quote the \
                 value, or remove the character"
            ),
            Self::Continuation => format!(
                "{var} has an unquoted value ending in a backslash, which a shell reads \
                 as joining the next line to it — quote the value"
            ),
            Self::Nul => format!("{var} holds a NUL byte"),
        }
    }
}

/// Parse an env file's content into a map: the strict subset of dotenv zap reads.
///
/// Lines end at a line feed, a carriage return before it dropped. A line is blank, a
/// comment (`#` first), or `[export ]NAME=VALUE`, with whitespace around the name and
/// the value trimmed; `export` is the keyword only before a space. `NAME` is an
/// environment variable's name
/// ([`is_env_var_name`](zap_types::scalar::is_env_var_name)). `VALUE` is one of:
///
/// - **bare** — the rest of the line, as it is. One holding a `#` at its start or after
///   whitespace is refused: dotenv loaders cut the value there and others keep it, so
///   the line doesn't say which value is meant. So is one holding a control character
///   other than a tab or a Unicode line separator (a lone carriage return among them),
///   and one ending in a backslash: each reads as one line to some tools and two to
///   others;
/// - **single-quoted** — literal, to the next `'`;
/// - **double-quoted** — to the next unescaped `"`, with `\\`, `\"`, `\n` and `\r`
///   decoded and any other backslash kept;
///
/// and after a quoted value's closing quote only whitespace or a `#` comment may
/// follow. Nothing is interpolated: a `$` is a `$`. A leading byte-order mark is
/// skipped.
///
/// Everything else is an error rather than a guess — a line with no `=`, a name that
/// is no variable's, a variable assigned twice, a quote left open (so a multi-line
/// value, whose later lines would otherwise be read as names), a NUL: a value read
/// wrong is a secret registered wrong, and then printed unmasked.
///
/// # Errors
/// [`EnvFileProblem`] for the first such line.
pub fn parse_env_file(
    contents: &str,
) -> std::result::Result<HashMap<String, String>, EnvFileProblem> {
    let mut vars = HashMap::new();
    let mut assigned: HashMap<String, usize> = HashMap::new();
    let contents = contents.strip_prefix('\u{feff}').unwrap_or(contents);
    for (index, line) in contents.lines().enumerate() {
        let number = index + 1;
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let assignment = line.strip_prefix("export ").map_or(line, str::trim_start);
        let problem = |name: Option<&str>, problem| EnvFileProblem {
            line: number,
            name: name.map(str::to_owned),
            problem,
        };
        let Some((name, value)) = assignment.split_once('=') else {
            return Err(problem(None, EnvLineProblem::NoAssignment));
        };
        let name = name.trim();
        if !zap_types::scalar::is_env_var_name(name) {
            return Err(problem(None, EnvLineProblem::Name));
        }
        if let Some(first) = assigned.insert(name.to_owned(), number) {
            return Err(problem(Some(name), EnvLineProblem::Duplicate { first }));
        }
        let value = env_value(value.trim()).map_err(|found| problem(Some(name), found))?;
        vars.insert(name.to_owned(), value);
    }
    Ok(vars)
}

/// The value an assignment's right-hand side (trimmed) spells, by
/// [`parse_env_file`]'s rules.
fn env_value(written: &str) -> std::result::Result<String, EnvLineProblem> {
    if written.contains('\0') {
        return Err(EnvLineProblem::Nul);
    }
    let after_quote = |rest: &str| {
        let rest = rest.trim_start();
        (rest.is_empty() || rest.starts_with('#'))
            .then_some(())
            .ok_or(EnvLineProblem::AfterQuote)
    };
    if let Some(quoted) = written.strip_prefix('\'') {
        let (value, rest) = quoted
            .split_once('\'')
            .ok_or(EnvLineProblem::Unterminated)?;
        after_quote(rest)?;
        return Ok(value.to_owned());
    }
    if let Some(quoted) = written.strip_prefix('"') {
        let mut value = String::with_capacity(quoted.len());
        let mut chars = quoted.char_indices();
        while let Some((at, c)) = chars.next() {
            match c {
                '"' => {
                    after_quote(&quoted[at + 1..])?;
                    return Ok(value);
                }
                '\\' => match chars.clone().next() {
                    Some((_, escaped @ ('\\' | '"'))) => {
                        value.push(escaped);
                        chars.next();
                    }
                    Some((_, 'n')) => {
                        value.push('\n');
                        chars.next();
                    }
                    Some((_, 'r')) => {
                        value.push('\r');
                        chars.next();
                    }
                    _ => value.push('\\'),
                },
                other => value.push(other),
            }
        }
        return Err(EnvLineProblem::Unterminated);
    }
    if written
        .chars()
        .any(|c| (c.is_control() && c != '\t') || matches!(c, '\u{2028}' | '\u{2029}'))
    {
        return Err(EnvLineProblem::Control);
    }
    let comment = written.starts_with('#')
        || written
            .char_indices()
            .any(|(at, c)| c == '#' && written[..at].ends_with(char::is_whitespace));
    if comment {
        return Err(EnvLineProblem::Comment);
    }
    if written.ends_with('\\') {
        return Err(EnvLineProblem::Continuation);
    }
    Ok(written.to_owned())
}

/// What [`install_env_file`] loaded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvFileLoaded {
    /// How many variables the file assigns.
    pub vars: usize,
    /// A warning for the operator, when the file's mode lets other users write it, or
    /// read the secrets it holds: one line, naming the file and the `chmod` that closes
    /// it.
    pub warning: Option<String>,
}

/// Read a `--env-file` and install its pairs as the operator-env overlay (read by
/// [`env_var`] before `std::env`). Call once at startup, before any resolution.
///
/// The file is read by [`parse_env_file`]'s rules, and a line outside them is an error
/// naming the file, the line, and the variable — never a value.
///
/// # Errors
/// Returns [`Error::EnvFile`] if the file can't be read, or holds a line zap doesn't
/// read ([`EnvFileProblem`]).
pub fn install_env_file(path: &Path) -> Result<EnvFileLoaded> {
    let failed = |message: String| Error::EnvFile {
        path: path.display().to_string(),
        message,
    };
    let contents = std::fs::read_to_string(path).map_err(|error| failed(error.to_string()))?;
    let vars = parse_env_file(&contents).map_err(|problem| failed(problem.to_string()))?;
    let loaded = EnvFileLoaded {
        vars: vars.len(),
        warning: open_file_warning(path, &vars),
    };
    set_env_overlay(vars);
    Ok(loaded)
}

/// The warning for an env file other users can reach, saying who — its group, or
/// everyone — and how: one its group or everyone can
/// **write** — whoever can rewrite it chooses every value zap resolves, the host it
/// connects to among them — and one they can **read** that holds a secret: a variable
/// that is one by its name or its value's form ([`Secrecy::by_shape`], the rule a
/// config's references are classified by before the config says more), with a value.
/// `None` when neither holds, or the platform has no such mode to read.
#[cfg(unix)]
fn open_file_warning(path: &Path, vars: &HashMap<String, String>) -> Option<String> {
    use std::os::unix::fs::PermissionsExt as _;

    let mode = std::fs::metadata(path).ok()?.permissions().mode() & 0o777;
    // Who a pair of mode bits lets in: the file's group alone, or everyone.
    let who = |group: u32, others: u32| {
        if mode & others != 0 {
            Some("everyone")
        } else {
            (mode & group != 0).then_some("its group")
        }
    };
    let holds_secrets = vars
        .iter()
        .any(|(name, value)| !value.is_empty() && Secrecy::by_shape(name, Some(value)).is_secret());
    let readers = who(0o040, 0o004).filter(|_| holds_secrets);
    let found = match (readers, who(0o020, 0o002)) {
        (Some(readers), Some(writers)) if readers == writers => {
            format!("holds secrets and is readable and writable by {readers}")
        }
        (Some(readers), Some(writers)) => {
            format!("holds secrets and is readable by {readers} and writable by {writers}")
        }
        (Some(readers), None) => format!("holds secrets and is readable by {readers}"),
        (None, Some(writers)) => format!("is writable by {writers}"),
        (None, None) => return None,
    };
    Some(format!(
        "warning: env file {} {found} (mode {mode:03o}) — run `chmod 600` on it",
        path.display()
    ))
}

#[cfg(not(unix))]
fn open_file_warning(_path: &Path, _vars: &HashMap<String, String>) -> Option<String> {
    None
}

/// The names of every variable `config` references
/// ([`crate::secret::scan_env_var_names`]) that resolves to an unset or empty value via
/// `env_get` (sorted, deduplicated).
///
/// The fail-fast preflight's finding. A referenced var with no value would otherwise
/// resolve to the empty string silently ([`resolve_env_vars`]) and be baked into a
/// command, a written file, or a `.env` line — an insecure or broken apply with no
/// error (an empty `SECRET_COOKIE_KEYS` written to `.env.production` is the canonical
/// trap). Every command that *executes* against a target — `apply` and `deploy` alike —
/// turns a non-empty result into a hard error before a wetrun runs, and into a warning on
/// a dry run (which keeps the refs inert, so it must still succeed without them). Empty
/// means every referenced var is satisfied. The shared message is
/// `commands::checks::unresolved_env_message`.
pub fn unresolved_env_vars<F>(config: &zap_types::schema::ZapConfig, env_get: F) -> Vec<String>
where
    F: Fn(&str) -> Option<String>,
{
    crate::secret::scan_env_var_names(config)
        .into_iter()
        .filter(|name| env_get(name).is_none_or(|value| value.is_empty()))
        .collect()
}

/// The referenced vars that block a **faithful comparison** — unset names among those a
/// detection/diff actually resolves (sorted, deduplicated).
///
/// The finding behind the `unverifiable` verdict. Where [`unresolved_env_vars`] answers
/// "would a wetrun bake in an empty string?", this answers the narrower question a *dry
/// run* turns on: **can the diff it just computed be trusted?** It can't, if a resolved
/// field came back empty — `resolve_env_vars` collapses an unset reference to `""`, and
/// the desired-vs-live comparison then both **masks real drift** (live already holds the
/// empty value) and **manufactures false drift** (live holds the real value). The lock
/// layer already rules on exactly this hazard and fails closed
/// (`crate::lock::EntryStatus::Unverifiable`); this extends the same verdict to the
/// changeset itself.
///
/// A non-empty result must not be presented as a warning under an otherwise
/// confident-looking plan — the plan is the thing in doubt. Empty means the comparison
/// resolved everything it needed.
pub fn unverifiable_env_vars<F>(config: &zap_types::schema::ZapConfig, env_get: F) -> Vec<String>
where
    F: Fn(&str) -> Option<String>,
{
    crate::secret::scan_comparison_var_names(config)
        .into_iter()
        .filter(|name| env_get(name).is_none_or(|value| value.is_empty()))
        .collect()
}

/// Whether an (env-resolved) string references the target home — a `$HOME` token
/// or a leading `~`.
///
/// The `$HOME` match is at a variable boundary (not followed by an identifier
/// char), so `$HOMEBREW_PREFIX` is left alone. A remote path that references the
/// home but has no `target.home` declared can't be resolved (the `Connection`
/// surfaces a clear error).
#[must_use]
pub fn references_home(resolved: &str) -> bool {
    contains_home_var(resolved) || resolved == "~" || resolved.starts_with("~/")
}

/// Whether `s` contains a `$HOME` *token* — `$HOME` not immediately followed by an
/// identifier char (so `$HOMEBREW` doesn't count).
fn contains_home_var(s: &str) -> bool {
    let mut rest = s;
    while let Some(idx) = rest.find("$HOME") {
        let after = &rest[idx + "$HOME".len()..];
        if !after
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_alphanumeric() || c == '_')
        {
            return true;
        }
        rest = after;
    }
    false
}

/// Replace every `$HOME` *token* (boundary-checked as in `contains_home_var`) with
/// `home`, leaving `$HOMEBREW_PREFIX` and friends intact.
fn replace_home_var(s: &str, home: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(idx) = rest.find("$HOME") {
        out.push_str(&rest[..idx]);
        let after = &rest[idx + "$HOME".len()..];
        let boundary = !after
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_alphanumeric() || c == '_');
        out.push_str(if boundary { home } else { "$HOME" });
        rest = after;
    }
    out.push_str(rest);
    out
}

/// Substitute a given `home` for `$HOME` and a leading `~` in an already
/// reference-resolved string.
fn substitute_home(resolved: &str, home: &str) -> String {
    let resolved = replace_home_var(resolved, home);
    if resolved == "~" {
        home.to_owned()
    } else if let Some(rest) = resolved.strip_prefix("~/") {
        format!("{home}/{rest}")
    } else {
        resolved
    }
}

/// Resolve references ([`resolve_field`]), then substitute an explicit target `home` for
/// `$HOME` / a leading `~`.
///
/// The remote half of path resolution — the `Connection` passes the declared
/// `target.home`; the local half is [`expand_runtime_path`].
///
/// # Errors
/// [`UnsafeValue`] naming the first reference whose value no path can hold.
pub fn expand_with_home(path: &str, home: &str) -> std::result::Result<String, UnsafeValue> {
    Ok(substitute_home(&resolve_field(path)?, home))
}

/// Resolve references against the environment (unset → empty).
///
/// Env-var-only — does **not** expand `~` / `$HOME` (that's `expand_runtime_path`).
/// Unchecked: for a value that reaches no shell and no path of the target's — file
/// content, a url, the host and user a connection is built from (checked where it is
/// built). A path, or a name on its way into a probe, goes through [`resolve_field`];
/// command text — quoted before its references resolve — through [`resolve_command`].
pub fn resolve_env_vars(input: &str) -> String {
    var_ref::map_refs(input, |name| env_var(name).unwrap_or_default())
}

/// A reference whose resolved value can't be put where it was asked for.
///
/// Names the variable, never its value, and says what is wrong with the value — what to
/// do about it depends on the place, which the caller knows.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum UnsafeValue {
    /// The value holds a single quote and was bound for command text.
    #[error(
        "`{}` resolves to a value containing a single quote, which zap won't substitute \
         into a command: the value would end the quoting around it and the rest would run \
         as shell",
        var_ref::shown(.name)
    )]
    SingleQuote {
        /// The reference's name.
        name: String,
    },
    /// The value holds a double quote and was bound for a SQL identifier.
    #[error(
        "`{}` resolves to a value containing a double quote, which zap won't use in a \
         database identifier: the value would end the identifier's quoting and the rest \
         would run as SQL",
        var_ref::shown(.name)
    )]
    DoubleQuote {
        /// The reference's name.
        name: String,
    },
    /// The value holds a NUL byte, which no command line or environment can carry.
    #[error(
        "`{}` resolves to a value containing a NUL byte, which a shell would silently drop",
        var_ref::shown(.name)
    )]
    Nul {
        /// The reference's name.
        name: String,
    },
    /// The value holds a reference delimiter. Resolution is one pass and never reads a
    /// value for references, so the value could resolve nothing — and text that reaches
    /// a shell holding a delimiter is refused there, so it is named here instead.
    #[error(
        "`{}` resolves to a value containing a reference delimiter (U+FDD0 or U+FDD1), \
         which zap won't substitute into a command",
        var_ref::shown(.name)
    )]
    Delimiter {
        /// The reference's name.
        name: String,
    },
    /// The value holds a NUL byte and was bound for a path or a name zap reads the
    /// target by.
    #[error(
        "`{}` resolves to a value containing a NUL byte, which no path or name on the \
         target can hold",
        var_ref::shown(.name)
    )]
    FieldNul {
        /// The reference's name.
        name: String,
    },
    /// The value holds a reference delimiter and was bound for a path or a name zap
    /// reads the target by. Every read and write refuses text holding a delimiter — it
    /// is what an unresolved reference looks like — so the value is named here, for the
    /// one resource that takes it.
    #[error(
        "`{}` resolves to a value containing a reference delimiter (U+FDD0 or U+FDD1), \
         which zap won't use as a path or a name on the target",
        var_ref::shown(.name)
    )]
    FieldDelimiter {
        /// The reference's name.
        name: String,
    },
    /// The value holds a line break and was bound for a `template` variable, whose text
    /// lands in the file as it is: in a line-oriented file (an `EnvironmentFile`, an
    /// nginx site), a line break there would add a line of the value's choosing.
    #[error(
        "`{}` resolves to a value containing a line break (CR or LF), which a template \
         value can't hold: it would add a line to the file",
        var_ref::shown(.name)
    )]
    LineBreak {
        /// The reference's name.
        name: String,
    },
    /// The text itself holds a delimiter that is no part of a reference — nothing a
    /// config can declare, so the text is not what any config meant.
    #[error(
        "the text holds a reference delimiter (U+FDD0 or U+FDD1) outside a reference, \
         which zap won't run"
    )]
    StrayDelimiter,
    /// A field's references resolved to a value the field can't be: a path that isn't
    /// absolute, a name a `pg_hba.conf` rule line reads as something else. Names the
    /// field and says what is wrong, in zap's own words; the value is in neither.
    #[error("`{field}` resolves to a value that {problem}")]
    Field {
        /// The field, as a config names it.
        field: String,
        /// What is wrong with the value, as the rest of a sentence about it.
        problem: &'static str,
    },
    /// A `template` variable rendered to a value that isn't the kind it declares. Names
    /// the variable and the kind, never the value.
    #[error(
        "`content.vars.{var}` resolves to a value that {problem}, which its kind `{kind}` refuses"
    )]
    TemplateKind {
        /// The variable, as `content.vars` names it.
        var: String,
        /// The kind it declares.
        kind: &'static str,
        /// What is wrong with the value, as the rest of a sentence about it.
        problem: &'static str,
    },
}

impl UnsafeValue {
    /// `value` when it has no `problem`, else the refusal for `field`.
    ///
    /// # Errors
    /// [`UnsafeValue::Field`] naming `field` when `problem` finds one.
    pub fn held_to(
        field: &str,
        value: String,
        problem: impl FnOnce(&str) -> Option<&'static str>,
    ) -> std::result::Result<String, Self> {
        if let Some(problem) = problem(&value) {
            return Err(Self::Field {
                field: field.to_owned(),
                problem,
            });
        }
        Ok(value)
    }
}

/// Resolve the references in **command text** — a plan step, a `script`'s
/// `check`, a `build`'s `run`, a `file`'s `validate` — refusing a value that could change
/// what the text means to a shell.
///
/// Substitution into a command is textual: the text was composed, and quoted, with the
/// reference still inert, so the value lands inside whatever quoting surrounds it. zap
/// quotes every value it composes into a command with single quotes
/// (`zap_types::shell::single_quote`), inside which a shell reads every byte literally
/// except a single quote — so a value without one can't leave zap's quoting, whatever
/// else it holds (`$`, backticks, `"`, `;`, spaces, newlines), and a value with one is
/// refused rather than escaped: the escape that is right inside single quotes corrupts
/// the value anywhere else, and the text doesn't say which it is. A NUL is refused too
/// (a shell drops it, running a different command).
///
/// An operator's own command text gets the same substitution and the same refusal;
/// where the operator puts a reference outside single quotes — bare, or inside double
/// quotes — the shell reads the value as it reads the text around it. (The fields zap
/// itself composes unquoted take no reference at all: none is a
/// [`Text`](zap_types::text::Text).)
///
/// # Errors
/// [`UnsafeValue`] naming the first reference whose value holds a single quote or a NUL.
pub fn resolve_command(input: &str) -> std::result::Result<String, UnsafeValue> {
    resolve_checked(input, Bound::Command)
}

/// Resolve the references in a value zap quotes *after* resolving it — an
/// `env` map's value — which can therefore hold anything a process environment can:
/// every byte but NUL.
///
/// # Errors
/// [`UnsafeValue::Nul`] naming the first reference whose value holds a NUL.
pub fn resolve_env_value(input: &str) -> std::result::Result<String, UnsafeValue> {
    resolve_checked(input, Bound::EnvValue)
}

/// Resolve the references in a **field zap reads or writes the target by**, refusing a
/// value that field can't hold: a NUL, or a reference delimiter.
///
/// Such a field is a path, a `database`'s role or name on its way into a probe, or a
/// `pg_hba` host. Its value is quoted after it resolves, so it can hold anything else.
/// A delimiter is refused here, by the variable's name, because it is refused later
/// anyway and less usefully: a path or a probe that holds one is not read
/// (`Connection::observe` fails the whole pass, a path primitive the one operation),
/// since that is what a reference nobody resolved looks like. Refused here, the one
/// resource that takes the value holds, and every other resource is still read.
///
/// # Errors
/// [`UnsafeValue::FieldNul`] or [`UnsafeValue::FieldDelimiter`] naming the first
/// reference whose value holds one.
pub fn resolve_field(input: &str) -> std::result::Result<String, UnsafeValue> {
    resolve_checked(input, Bound::Field)
}

/// Render a `file`'s `template` content, refusing a value that would add a line, or
/// one that isn't the kind its variable declares.
///
/// Its variables' references resolve, and a value that could add to the file more than
/// the one value it stands for is refused: a NUL, a reference delimiter, or a line
/// break (CR or LF).
///
/// A template's text is written into the file as it is, and the files templates make
/// are read a line at a time — a systemd `EnvironmentFile`, an nginx site, a sudoers
/// drop-in — so a line break in a value is a line of the value's own: a variable of its
/// choosing in an `EnvironmentFile`, a directive in a config. What a line holds is the
/// file's grammar, which zap doesn't know: a value that must not hold a `;` or a `}` in
/// its place (an nginx `server_name`) is kept out by the kind its variable declares
/// ([`TemplateKind`](zap_types::schema::TemplateKind)), checked on the whole rendered
/// value. Detection holds the file on a refusal, and the wetrun preflight and the
/// executor refuse to write it, all through this one function.
///
/// # Errors
/// [`UnsafeValue`] naming the first reference whose value holds one, or
/// [`UnsafeValue::TemplateKind`] naming the first variable whose value isn't its kind.
pub fn resolve_template(template: &TemplateContent) -> std::result::Result<String, UnsafeValue> {
    template.try_render(
        |text| resolve_checked(text, Bound::TemplateValue),
        |var, kind, problem| UnsafeValue::TemplateKind {
            var: var.to_owned(),
            kind: kind.as_str(),
            problem,
        },
    )
}

/// Resolve the references in a `database` identifier (a role or database
/// name) the way its `GRANT` takes it.
///
/// That is inside SQL double quotes (`zap_types::postgres::sql_ident`), composed with the
/// reference still inert — so a value holding a double quote would end the identifier.
///
/// # Errors
/// [`UnsafeValue`] naming the first reference whose value holds a double quote or a NUL.
pub fn resolve_sql_identifier(input: &str) -> std::result::Result<String, UnsafeValue> {
    resolve_checked(input, Bound::SqlIdentifier)
}

/// What a checked resolve's text is bound for — which decides what its values can hold,
/// and how a refusal is worded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Bound {
    /// Command text, its values inside single quotes.
    Command,
    /// An `env` value, quoted after it resolves.
    EnvValue,
    /// A SQL identifier, its values inside double quotes.
    SqlIdentifier,
    /// A path or a name zap reads or writes the target by, quoted after it resolves.
    Field,
    /// A `template` variable's value, written into the file as it is.
    TemplateValue,
}

/// [`resolve_env_vars`], refusing a value with a NUL or a reference delimiter — or with
/// the character that would end the quoting a value `bound` for a command or an
/// identifier lands in — and text that holds a delimiter outside a reference. What it
/// returns holds no delimiter.
///
/// One pass: each reference is replaced by its value and the value is never read for
/// references of its own.
fn resolve_checked(input: &str, bound: Bound) -> std::result::Result<String, UnsafeValue> {
    let mut out = String::with_capacity(input.len());
    for segment in var_ref::segments(input) {
        match segment {
            var_ref::Segment::Text(text) => {
                if var_ref::holds_delimiter(text) {
                    return Err(UnsafeValue::StrayDelimiter);
                }
                out.push_str(text);
            }
            var_ref::Segment::Ref(name) => {
                let value = env_var(name).unwrap_or_default();
                let name = name.to_owned();
                let field = bound == Bound::Field;
                if value.contains('\0') {
                    return Err(if field {
                        UnsafeValue::FieldNul { name }
                    } else {
                        UnsafeValue::Nul { name }
                    });
                }
                if var_ref::holds_delimiter(&value) {
                    return Err(if field {
                        UnsafeValue::FieldDelimiter { name }
                    } else {
                        UnsafeValue::Delimiter { name }
                    });
                }
                match bound {
                    Bound::Command if value.contains('\'') => {
                        return Err(UnsafeValue::SingleQuote { name });
                    }
                    Bound::SqlIdentifier if value.contains('"') => {
                        return Err(UnsafeValue::DoubleQuote { name });
                    }
                    Bound::TemplateValue if value.contains(['\n', '\r']) => {
                        return Err(UnsafeValue::LineBreak { name });
                    }
                    Bound::Command
                    | Bound::EnvValue
                    | Bound::SqlIdentifier
                    | Bound::Field
                    | Bound::TemplateValue => {}
                }
                out.push_str(&value);
            }
        }
    }
    Ok(out)
}

/// Expand references, then `$HOME` / a leading `~` against the **local** operator
/// home — the full path expansion for a *local* target.
///
/// The home is `HOME` as the operator env gives it ([`env_var`], an `--env-file`
/// included), read by the one rule for a home directory (`crate::home::home_from`) and
/// only for a path that references it: a path with no `~` / `$HOME` resolves whatever
/// `HOME` holds.
///
/// Remote targets resolve the home via `Connection::apply_home` ([`expand_with_home`]
/// with the declared `target.home`); a content address resolves references alone (home
/// left literal).
///
/// # Errors
/// [`Error::UnusableValue`] naming the first reference whose value no path can hold;
/// [`Error::LocalHomeUnset`] when the path references the home and `HOME` is unset or
/// empty, [`Error::HomeNotAbsolute`] when it is a relative path.
pub fn expand_runtime_path(path: &str) -> Result<String> {
    let resolved = resolve_field(path).map_err(Error::UnusableValue)?;
    if !references_home(&resolved) {
        return Ok(resolved);
    }
    let home =
        crate::home::home_from("HOME", env_var("HOME").map(Into::into))?.ok_or_else(|| {
            Error::LocalHomeUnset {
                path: path.to_owned(),
            }
        })?;
    Ok(substitute_home(&resolved, &home.to_string_lossy()))
}

/// Collect the distinct reference names in `input` into `names`, through the same
/// scanner as [`resolve_env_vars`].
///
/// The fail-safe seam for `lock --check`: knowing *which* vars a hash-relevant field
/// references lets the caller distinguish "unset → can't verify" from "config changed"
/// — `resolve_env_vars` itself collapses an unset var to empty and loses that signal.
pub fn var_names_in(input: &str, names: &mut BTreeSet<String>) {
    names.extend(var_ref::ref_names(input).map(str::to_owned));
}

/// Operator-env values a test supplies — read by [`env_var`] ahead of everything else,
/// on the test's own thread only.
#[cfg(test)]
pub(crate) mod test_env {
    use std::cell::RefCell;
    use std::collections::HashMap;

    thread_local! {
        static VARS: RefCell<HashMap<String, String>> = RefCell::new(HashMap::new());
    }

    /// The test value of `name` on this thread, if one is set.
    pub(super) fn get(name: &str) -> Option<String> {
        VARS.with_borrow(|vars| vars.get(name).cloned())
    }

    /// Holds a set of test values; dropping it puts back what each name held before
    /// (an outer guard's value, or nothing).
    pub struct TestEnv(Vec<(String, Option<String>)>);

    /// Set `vars` for this thread until the returned guard drops.
    pub fn set(vars: &[(&str, &str)]) -> TestEnv {
        VARS.with_borrow_mut(|map| {
            TestEnv(
                vars.iter()
                    .map(|(name, value)| {
                        let before = map.insert((*name).to_owned(), (*value).to_owned());
                        ((*name).to_owned(), before)
                    })
                    .collect(),
            )
        })
    }

    impl Drop for TestEnv {
        fn drop(&mut self) {
            VARS.with_borrow_mut(|map| {
                // Last set, first restored: a name given twice ends at its first `before`.
                for (name, before) in self.0.drain(..).rev() {
                    match before {
                        Some(value) => map.insert(name, value),
                        None => map.remove(&name),
                    };
                }
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        Error, UnsafeValue, env_var, expand_runtime_path, expand_with_home, install_env_file,
        parse_env_file, references_home, resolve_command, resolve_env_value, resolve_env_vars,
        resolve_field, resolve_sql_identifier, resolve_template, test_env, unresolved_env_vars,
        unverifiable_env_vars,
    };
    use zap_types::text::Text;
    use zap_types::var_ref::Segment::{Ref, Text as Lit};
    use zap_types::var_ref::{marker, shown};

    /// [`expand_runtime_path`] of a path every value of which a path can hold.
    fn expand_local(path: &str) -> String {
        expand_runtime_path(path).unwrap()
    }

    /// [`expand_with_home`] of a path every value of which a path can hold.
    fn expand_home(path: &str, home: &str) -> String {
        expand_with_home(path, home).unwrap()
    }

    /// A test value shadows an outer one only while its guard lives.
    #[test]
    fn a_test_value_restores_the_one_it_shadowed() {
        let _outer = test_env::set(&[("ZAP_T_NESTED", "outer")]);
        {
            let _inner = test_env::set(&[("ZAP_T_NESTED", "inner"), ("ZAP_T_INNER", "x")]);
            assert_eq!(env_var("ZAP_T_NESTED").as_deref(), Some("inner"));
        }
        assert_eq!(env_var("ZAP_T_NESTED").as_deref(), Some("outer"));
        assert_eq!(env_var("ZAP_T_INNER"), None);
    }

    /// An env file whose value holds a NUL is refused at load, naming the file, the
    /// line and the variable and not the value — before it could reach the overlay.
    #[test]
    fn an_env_file_value_holding_a_nul_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("zap.env");
        std::fs::write(&path, "ZAP_T_FINE=ok\nZAP_T_BAD=secret\0tail\n").unwrap();
        let error = install_env_file(&path).unwrap_err().to_string();
        assert_eq!(
            error,
            format!(
                "failed to read env file {}: line 2: `ZAP_T_BAD` holds a NUL byte",
                path.display()
            )
        );
        assert_eq!(env_var("ZAP_T_FINE"), None);
    }

    /// A template value takes anything a line of the file can hold — a `;`, a `}`, a
    /// quote, the text of another placeholder — and refuses a line break (LF or CR), a
    /// NUL, and a reference delimiter, naming the variable and never the value. Only a
    /// variable a placeholder names is resolved, and a non-string value is never read.
    #[test]
    fn a_template_value_refuses_a_line_break_by_name() {
        let template = |vars: serde_json::Value| -> zap_types::schema::TemplateContent {
            serde_json::from_value(serde_json::json!({
                "template": "server_name {{domain}};\nport {{port}}\n",
                "vars": vars,
            }))
            .unwrap()
        };
        let _env = test_env::set(&[
            ("ZAP_T_DOMAIN", "a.example b.example; } {{port}} 'x\" \t"),
            ("ZAP_T_LF", "a.example\nEXTRA=1"),
            ("ZAP_T_CR", "a.example\rEXTRA=1"),
            ("ZAP_T_NUL", "a\0b"),
            ("ZAP_T_DELIM", "a\u{FDD0}b"),
        ]);
        let with =
            |name: &str| template(serde_json::json!({"domain": {"$env": name}, "port": 8080}));
        assert_eq!(
            resolve_template(&with("ZAP_T_DOMAIN")).unwrap(),
            "server_name a.example b.example; } {{port}} 'x\" \t;\nport 8080\n"
        );
        for (name, refused) in [
            (
                "ZAP_T_LF",
                UnsafeValue::LineBreak {
                    name: "ZAP_T_LF".to_owned(),
                },
            ),
            (
                "ZAP_T_CR",
                UnsafeValue::LineBreak {
                    name: "ZAP_T_CR".to_owned(),
                },
            ),
            (
                "ZAP_T_NUL",
                UnsafeValue::Nul {
                    name: "ZAP_T_NUL".to_owned(),
                },
            ),
            (
                "ZAP_T_DELIM",
                UnsafeValue::Delimiter {
                    name: "ZAP_T_DELIM".to_owned(),
                },
            ),
        ] {
            let error = resolve_template(&with(name)).unwrap_err();
            assert_eq!(error, refused, "{name}");
            assert!(!error.to_string().contains("EXTRA"), "{error}");
        }
        assert!(
            UnsafeValue::LineBreak {
                name: "ZAP_T_LF".to_owned()
            }
            .to_string()
            .contains("line break")
        );
    }

    /// A variable that declares a kind is held to it on its whole rendered value — the
    /// `;` and `}` a `text` value may hold are refused in a `hostname` — naming the
    /// variable and its kind, never the value; one with no kind keeps the `text` rule,
    /// and a non-string value is checked as the JSON text it renders to.
    #[test]
    fn a_template_value_is_held_to_its_declared_kind() {
        let template = |vars: serde_json::Value, kinds: serde_json::Value| {
            serde_json::from_value::<zap_types::schema::TemplateContent>(serde_json::json!({
                "template": "server_name {{domain}};\nlisten {{port}};\n# {{note}}\n",
                "vars": vars,
                "kinds": kinds,
            }))
            .unwrap()
        };
        let _env = test_env::set(&[
            ("ZAP_T_GOOD_DOMAIN", "app.example.com"),
            ("ZAP_T_BAD_DOMAIN", "app.example.com; } server { listen 9"),
        ]);
        let kinds = serde_json::json!({"domain": "hostname", "port": "port"});
        let vars = |domain: &str, port: serde_json::Value| serde_json::json!({"domain": {"$env": domain}, "port": port, "note": "a; {b}"});
        assert_eq!(
            resolve_template(&template(
                vars("ZAP_T_GOOD_DOMAIN", serde_json::json!(8080)),
                kinds.clone()
            ))
            .unwrap(),
            "server_name app.example.com;\nlisten 8080;\n# a; {b}\n"
        );
        let error = resolve_template(&template(
            vars("ZAP_T_BAD_DOMAIN", serde_json::json!(8080)),
            kinds.clone(),
        ))
        .unwrap_err();
        assert_eq!(
            error,
            UnsafeValue::TemplateKind {
                var: "domain".to_owned(),
                kind: "hostname",
                problem: zap_types::schema::TemplateKind::Hostname
                    .problem("x;")
                    .unwrap(),
            }
        );
        let message = error.to_string();
        assert!(
            message
                .starts_with("`content.vars.domain` resolves to a value that is not a host name"),
            "{message}"
        );
        assert!(message.contains("its kind `hostname`"), "{message}");
        assert!(!message.contains("listen 9"), "{message}");
        for port in [
            serde_json::json!(0),
            serde_json::json!("80;"),
            serde_json::json!(65536),
        ] {
            assert!(
                matches!(
                    resolve_template(&template(vars("ZAP_T_GOOD_DOMAIN", port.clone()), kinds.clone())),
                    Err(UnsafeValue::TemplateKind { ref var, kind: "port", .. }) if var == "port"
                ),
                "{port}"
            );
        }
        // without a kind, the same value is text, and only a line break is refused
        assert!(
            resolve_template(&template(
                vars("ZAP_T_BAD_DOMAIN", serde_json::json!(8080)),
                serde_json::json!({})
            ))
            .is_ok()
        );
    }

    /// A database identifier takes a single quote (its shell quoting is checked as
    /// command text) but not a double quote, which would end the SQL identifier.
    #[test]
    fn a_sql_identifier_refuses_a_double_quote_by_name() {
        let _env = test_env::set(&[
            ("ZAP_T_ROLE", "app\"; DROP ROLE x; --"),
            ("ZAP_T_OK", "a$b"),
        ]);
        assert_eq!(
            resolve_sql_identifier(&format!("x_{}", marker("ZAP_T_OK"))).unwrap(),
            "x_a$b"
        );
        let refused =
            resolve_sql_identifier(&format!("{}_{}", marker("ZAP_T_OK"), marker("ZAP_T_ROLE")))
                .unwrap_err();
        assert_eq!(
            refused,
            UnsafeValue::DoubleQuote {
                name: "ZAP_T_ROLE".to_owned()
            }
        );
        assert!(!refused.to_string().contains("DROP"));
        // Command text takes a double quote: inside single quotes it is literal.
        assert!(resolve_command(&format!("'{}'", marker("ZAP_T_ROLE"))).is_ok());
    }

    /// Command text takes any value but one holding a single quote or a NUL, and the
    /// refusal names the variable, never the value.
    #[test]
    fn command_text_refuses_a_single_quote_and_a_nul_by_name() {
        let _env = test_env::set(&[
            ("ZAP_T_PLAIN", "a $HOME `id` \"q\" ; | & * \\ \n b"),
            ("ZAP_T_QUOTE", "pass'; touch pwned; '"),
            ("ZAP_T_NUL", "a\0b"),
        ]);
        assert_eq!(
            resolve_command(&format!("x '{}' y", marker("ZAP_T_PLAIN"))).unwrap(),
            "x 'a $HOME `id` \"q\" ; | & * \\ \n b' y"
        );
        let refused = resolve_command(&format!(
            "psql -c '{} {}'",
            marker("ZAP_T_PLAIN"),
            marker("ZAP_T_QUOTE")
        ))
        .unwrap_err();
        assert_eq!(
            refused,
            UnsafeValue::SingleQuote {
                name: "ZAP_T_QUOTE".to_owned()
            }
        );
        let message = refused.to_string();
        assert!(
            message.contains(&format!("`{}`", shown("ZAP_T_QUOTE"))),
            "{message}"
        );
        assert!(!message.contains("pwned"), "{message}");
        let refused = resolve_command(&format!("echo {}", marker("ZAP_T_NUL"))).unwrap_err();
        assert_eq!(
            refused,
            UnsafeValue::Nul {
                name: "ZAP_T_NUL".to_owned()
            }
        );
        assert!(!refused.to_string().contains("a\0b"));
        // Text with no reference passes through; an unset reference resolves to nothing.
        assert_eq!(resolve_command("echo 'it''s'").unwrap(), "echo 'it''s'");
        assert_eq!(
            resolve_command(&format!("a{}b", marker("ZAP_T_UNSET"))).unwrap(),
            "ab"
        );
    }

    /// An `env` value is quoted after it resolves, so it takes a single quote — and
    /// everything else but a NUL.
    #[test]
    fn an_env_value_takes_a_single_quote_but_not_a_nul() {
        let _env = test_env::set(&[("ZAP_T_QUOTE", "it's"), ("ZAP_T_NUL", "a\0b")]);
        assert_eq!(
            resolve_env_value(&format!("<{}>", marker("ZAP_T_QUOTE"))).unwrap(),
            "<it's>"
        );
        assert_eq!(
            resolve_env_value(&marker("ZAP_T_NUL")).unwrap_err(),
            UnsafeValue::Nul {
                name: "ZAP_T_NUL".to_owned()
            }
        );
    }

    #[test]
    fn plain_path_is_unchanged() {
        assert_eq!(expand_local("/etc/hosts"), "/etc/hosts");
    }

    #[test]
    fn env_resolution_leaves_home_literal() {
        // `resolve_env_vars` resolves references only: `~` / `$HOME` stay literal, as
        // they do in a content address (home-independent, offline-reproducible).
        assert_eq!(resolve_env_vars("~/app"), "~/app");
        assert_eq!(resolve_env_vars("$HOME/app"), "$HOME/app");
    }

    #[test]
    fn references_home_detects_home_tokens() {
        assert!(references_home("~/app"));
        assert!(references_home("~"));
        assert!(references_home("/opt/$HOME/x"));
        assert!(!references_home("/etc/app"));
    }

    #[test]
    fn unresolved_env_vars_flags_unset_and_empty_but_not_satisfied() {
        let config: zap_types::schema::ZapConfig = serde_json::from_value(serde_json::json!({
            "target": {"local": true},
            "resources": [
                {"id": "f1", "type": "file", "path": "/etc/x",
                 "content": {"type": "template", "template": "{{a}}",
                             "vars": {"a": Text::of_pieces([Ref("FOO"), Lit(" and "), Ref("BAR")])}}},
                {"id": "f2", "type": "file", "path": "/etc/y",
                 "content": {"type": "template", "template": "{{b}}",
                             "vars": {"b": Text::reference("BAZ")}}}
            ]
        }))
        .expect("valid config");
        // FOO is satisfied; BAR resolves empty; BAZ is unset — both BAR and BAZ are flagged.
        let env = |name: &str| match name {
            "FOO" => Some("value".to_owned()),
            "BAR" => Some(String::new()),
            _ => None,
        };
        assert_eq!(
            unresolved_env_vars(&config, env),
            vec!["BAR".to_owned(), "BAZ".to_owned()]
        );
        // All satisfied → empty.
        assert!(unresolved_env_vars(&config, |_| Some("x".to_owned())).is_empty());
    }

    /// The comparison scan is narrower than the blanket one, in exactly two places: the
    /// `deploy` block (convergence never reads it) and `auth` credentials (excluded from
    /// the content address). Everything else counts — an unset ref anywhere a detector
    /// resolves makes the diff untrustworthy.
    #[test]
    fn unverifiable_scan_excludes_deploy_and_auth_but_nothing_else() {
        let config: zap_types::schema::ZapConfig = serde_json::from_value(serde_json::json!({
            "target": {"local": true},
            "resources": [
                // A template variable and `path` both feed the file comparison.
                {"id": "f1", "type": "file",
                 "path": Text::of_pieces([Lit("/etc/"), Ref("PATH_VAR")]),
                 "content": {"type": "template", "template": "{{v}}",
                             "vars": {"v": Text::reference("CONTENT_VAR")}}},
                // `auth` is a credential — unset doesn't make the hash unverifiable.
                {"id": "f2", "type": "file", "path": "/opt/bin",
                 "content": {"type": "remote", "url": "https://example.com/x",
                             "blake3": "ab".repeat(32),
                             "auth": {"scheme": "bearer", "token": Text::reference("AUTH_VAR")},
                             "extract": {"type": "none"}}},
            ],
            "deploy": {"artifacts": ["build/"], "path": "/srv/app",
                       "health": {"domain": Text::reference("DEPLOY_VAR"), "path": "/ready"}},
        }))
        .expect("valid config");

        let none = |_: &str| None;
        assert_eq!(
            unverifiable_env_vars(&config, none),
            vec!["CONTENT_VAR".to_owned(), "PATH_VAR".to_owned()],
            "only the refs a comparison resolves"
        );
        // The blanket wetrun gate is a strict superset — it must still catch all four, so
        // an executing run can never bake in an empty string.
        assert_eq!(
            unresolved_env_vars(&config, none),
            vec![
                "AUTH_VAR".to_owned(),
                "CONTENT_VAR".to_owned(),
                "DEPLOY_VAR".to_owned(),
                "PATH_VAR".to_owned()
            ]
        );
        // All satisfied → verifiable.
        assert!(unverifiable_env_vars(&config, |_| Some("x".to_owned())).is_empty());
    }

    /// Only a fetch credential is left out of the comparison scan — not whatever is
    /// named `auth`: a `database`'s `auth.hosts`, which detection resolves, and a
    /// template variable called `auth` are counted, so a pass with one unset is
    /// unverifiable.
    #[test]
    fn unverifiable_scan_counts_an_auth_that_is_not_a_fetch_credential() {
        let config: zap_types::schema::ZapConfig = serde_json::from_value(serde_json::json!({
            "target": {"local": true, "service_manager": "systemd"},
            "resources": [
                {"id": "db", "type": "database", "engine": "postgresql",
                 "database_name": "app", "username": "app",
                 "auth": {"method": "scram-sha-256", "hosts": [Text::of_pieces([Ref("DB_HOST"), Lit("/32")])]}},
                {"id": "t", "type": "file", "path": "/etc/t",
                 "content": {"type": "template", "template": "{{auth}}",
                             "vars": {"auth": Text::reference("TEMPLATE_VAR")}}},
                {"id": "f", "type": "file", "path": "/opt/bin",
                 "content": {"type": "remote", "url": "https://example.com/x",
                             "blake3": "ab".repeat(32),
                             "auth": {"scheme": "bearer", "token": Text::reference("FILE_TOKEN")},
                             "extract": {"type": "none"}}},
                {"id": "b", "type": "build", "run": "make", "output": "/opt/b",
                 "source": {"type": "remote", "url": "https://example.com/src.tar.gz",
                            "blake3": "cd".repeat(32),
                            "extract": {"type": "tar.gz", "strip_components": 1},
                            "auth": {"scheme": "bearer", "token": Text::reference("BUILD_TOKEN")}}},
            ],
        }))
        .expect("valid config");
        assert_eq!(
            unverifiable_env_vars(&config, |_| None),
            vec!["DB_HOST".to_owned(), "TEMPLATE_VAR".to_owned()]
        );
    }

    #[test]
    fn parse_env_file_reads_pairs_comments_quotes_and_export() {
        // Note: the overlay install (`set_env_overlay`) is process-global set-once, so
        // it's exercised by the binary, not here — only the pure parse is unit-tested.
        let vars = parse_env_file(
            "\u{feff}# a comment\n\
             \n\
             \t  # an indented comment\n\
             DEPLOY_HOST=forge.example.com\r\n\
             export DEPLOY_USER=fuz_forge\n\
             export   SPACED_EXPORT=1\n\
             TABS=a\tb\n\
             export=a variable of that name\n\
             SECRET_TOKEN=\"quoted value\"\n\
             SINGLE='single quoted'\n\
             SPACED   =   trimmed  \n\
             WITH_EQ=a=b=c\n\
             EMPTY=\n\
             EMPTY_QUOTED=\"\"\n\
             INNER_SPACES=two words\n\
             FRAGMENT=https://x.example/#frag\n\
             HASH_IN_QUOTES=\"a # b\"  # then a comment\n\
             HASH_IN_SINGLE='a # b'# then a comment\n\
             DOLLAR=\"$HOME ${X}\"\n\
             INNER_QUOTE=it's \"fine\"\n\
             ESCAPES=\"a\\\"b\\\\c\\nd\\re\\tf\"\n\
             SINGLE_LITERAL='a\\nb \"c\"'\n\
             PADDED=\"  kept  \"",
        )
        .unwrap();
        let expected = [
            ("DEPLOY_HOST", "forge.example.com"),
            ("DEPLOY_USER", "fuz_forge"), // `export ` stripped
            ("SPACED_EXPORT", "1"),
            ("TABS", "a\tb"), // a tab is the one control character a bare value holds
            ("export", "a variable of that name"),
            ("SECRET_TOKEN", "quoted value"), // double quotes stripped
            ("SINGLE", "single quoted"),      // single quotes stripped
            ("SPACED", "trimmed"),            // name + value trimmed
            ("WITH_EQ", "a=b=c"),             // only the first `=` splits
            ("EMPTY", ""),
            ("EMPTY_QUOTED", ""),
            ("INNER_SPACES", "two words"),
            ("FRAGMENT", "https://x.example/#frag"), // a `#` after no whitespace
            ("HASH_IN_QUOTES", "a # b"),
            ("HASH_IN_SINGLE", "a # b"),
            ("DOLLAR", "$HOME ${X}"), // nothing is interpolated
            ("INNER_QUOTE", "it's \"fine\""),
            ("ESCAPES", "a\"b\\c\nd\re\\tf"), // the four escapes; any other backslash kept
            ("SINGLE_LITERAL", "a\\nb \"c\""),
            ("PADDED", "  kept  "),
        ];
        for (name, value) in expected {
            assert_eq!(vars.get(name).map(String::as_str), Some(value), "{name}");
        }
        assert_eq!(vars.len(), expected.len());
    }

    /// A line zap isn't sure of is an error, never a guess: it names the line and the
    /// variable when the line has one, and holds no part of a value.
    #[test]
    fn parse_env_file_refuses_what_it_does_not_understand() {
        use super::{EnvFileProblem, EnvLineProblem};

        let cases: [(&str, usize, Option<&str>, EnvLineProblem, &str); 22] = [
            (
                "A=1\nnoequalsline\n",
                2,
                None,
                EnvLineProblem::NoAssignment,
                "line 2: not a blank line, a `#` comment, or a `NAME=VALUE` assignment",
            ),
            (
                "TOKEN=abc123 # prod\n",
                1,
                Some("TOKEN"),
                EnvLineProblem::Comment,
                "line 1: `TOKEN` has an unquoted value holding a `#`",
            ),
            (
                "TOKEN=abc123\t#prod\n",
                1,
                Some("TOKEN"),
                EnvLineProblem::Comment,
                "line 1: `TOKEN` has an unquoted value holding a `#`",
            ),
            (
                "A=1\n\nTOKEN= # nothing yet\n",
                3,
                Some("TOKEN"),
                EnvLineProblem::Comment,
                "line 3: `TOKEN` has an unquoted value holding a `#`",
            ),
            (
                "TOKEN=#abc123\n",
                1,
                Some("TOKEN"),
                EnvLineProblem::Comment,
                "line 1: `TOKEN` has",
            ),
            (
                "KEY=\"-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASC=\n\"\n",
                1,
                Some("KEY"),
                EnvLineProblem::Unterminated,
                "line 1: `KEY` has a quoted value with no closing quote on its line",
            ),
            (
                "KEY='abc123\n",
                1,
                Some("KEY"),
                EnvLineProblem::Unterminated,
                "line 1: `KEY` has a quoted value with no closing quote",
            ),
            (
                "KEY=\"abc123\\\"\n",
                1,
                Some("KEY"),
                EnvLineProblem::Unterminated,
                "line 1: `KEY` has a quoted value with no closing quote",
            ),
            (
                "KEY=\"abc\"123\n",
                1,
                Some("KEY"),
                EnvLineProblem::AfterQuote,
                "line 1: `KEY` has text after its value's closing quote that is not a `#` \
                 comment",
            ),
            (
                "KEY='abc' 123 # c\n",
                1,
                Some("KEY"),
                EnvLineProblem::AfterQuote,
                "line 1: `KEY` has text after",
            ),
            (
                "A=1\nB=2\nexport A=abc123\n",
                3,
                Some("A"),
                EnvLineProblem::Duplicate { first: 1 },
                "line 3: `A` is already assigned on line 1; assign it once",
            ),
            (
                "MIIEvQIBADANBgkqhkiG9w0BAQEFAASC+abc123=\n",
                1,
                None,
                EnvLineProblem::Name,
                "line 1: what stands before the `=` is not a variable's name",
            ),
            (
                "my-key=abc123\n",
                1,
                None,
                EnvLineProblem::Name,
                "line 1: what stands before the `=`",
            ),
            (
                "=abc123\n",
                1,
                None,
                EnvLineProblem::Name,
                "line 1: what stands before the `=`",
            ),
            // `export` is the keyword before a space only; after a tab it is part of a
            // name, and no variable's.
            (
                "export\tA=abc123\n",
                1,
                None,
                EnvLineProblem::Name,
                "line 1: what stands before the `=`",
            ),
            // A lone carriage return is not a line end here: the line is refused, not
            // read as one long value.
            (
                "A=abc123\rB=prod\n",
                1,
                Some("A"),
                EnvLineProblem::Control,
                "line 1: `A` has an unquoted value holding a control character or a line \
                 separator",
            ),
            (
                "A=1\nB=abc123\u{c}prod\n",
                2,
                Some("B"),
                EnvLineProblem::Control,
                "line 2: `B` has an unquoted value holding a control character",
            ),
            (
                "B=abc123\u{2028}prod\n",
                1,
                Some("B"),
                EnvLineProblem::Control,
                "line 1: `B` has",
            ),
            (
                "B=abc123\u{2029}prod\n",
                1,
                Some("B"),
                EnvLineProblem::Control,
                "line 1: `B` has",
            ),
            (
                "B=abc123\u{1b}[0m\n",
                1,
                Some("B"),
                EnvLineProblem::Control,
                "line 1: `B` has",
            ),
            (
                "A=abc123\\\nB=prod\n",
                1,
                Some("A"),
                EnvLineProblem::Continuation,
                "line 1: `A` has an unquoted value ending in a backslash, which a shell \
                 reads as joining the next line to it — quote the value",
            ),
            (
                "A=\\\n",
                1,
                Some("A"),
                EnvLineProblem::Continuation,
                "line 1: `A` has an unquoted value ending in a backslash",
            ),
        ];
        for (contents, line, name, problem, message) in cases {
            let found = parse_env_file(contents).unwrap_err();
            assert_eq!(
                found,
                EnvFileProblem {
                    line,
                    name: name.map(str::to_owned),
                    problem
                },
                "{contents:?}"
            );
            let shown = found.to_string();
            assert!(shown.starts_with(message), "{shown}");
            for value in ["abc123", "prod", "MIIE", "nothing yet", "my-key"] {
                assert!(!shown.contains(value), "{shown}");
            }
        }
    }

    /// An env file other users can write is warned about whatever it holds, and one
    /// they can read when it holds a secret: one line, with the file and the `chmod`.
    /// An owner-only one, and a readable one that holds no secret, is not.
    #[cfg(unix)]
    #[test]
    fn an_env_file_other_users_can_reach_is_warned_about() {
        use std::os::unix::fs::PermissionsExt as _;

        use super::{open_file_warning, parse_env_file};

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("zap.env");
        let warning = |contents: &str, mode: u32| {
            std::fs::write(&path, contents).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
            open_file_warning(&path, &parse_env_file(contents).unwrap())
        };
        let by_name = "DEPLOY_HOST=h.example\nAPI_TOKEN=tok-12345678\n";
        let by_value = "DATABASE_URL=postgres://app:hunter2@db/app\n";
        let plain = "DEPLOY_HOST=h.example\n";
        for (contents, mode, found) in [
            (
                by_name,
                0o644,
                Some(("644", "holds secrets and is readable by everyone")),
            ),
            (
                by_name,
                0o640,
                Some(("640", "holds secrets and is readable by its group")),
            ),
            (
                by_name,
                0o604,
                Some(("604", "holds secrets and is readable by everyone")),
            ),
            (
                by_value,
                0o664,
                Some((
                    "664",
                    "holds secrets and is readable by everyone and writable by its group",
                )),
            ),
            (
                by_name,
                0o666,
                Some((
                    "666",
                    "holds secrets and is readable and writable by everyone",
                )),
            ),
            (
                by_name,
                0o660,
                Some((
                    "660",
                    "holds secrets and is readable and writable by its group",
                )),
            ),
            (
                by_name,
                0o642,
                Some((
                    "642",
                    "holds secrets and is readable by its group and writable by everyone",
                )),
            ),
            (by_name, 0o620, Some(("620", "is writable by its group"))),
            (plain, 0o664, Some(("664", "is writable by its group"))),
            (plain, 0o602, Some(("602", "is writable by everyone"))),
            ("", 0o666, Some(("666", "is writable by everyone"))),
            (by_name, 0o600, None),
            (by_name, 0o700, None),
            (by_name, 0o611, None),
            (plain, 0o644, None),
            ("API_TOKEN=\n", 0o644, None),
            // A switch under a secret's name is a setting.
            ("ENABLE_AUTH=true\n", 0o644, None),
        ] {
            assert_eq!(
                warning(contents, mode),
                found.map(|(mode, found)| format!(
                    "warning: env file {} {found} (mode {mode}) — run `chmod 600` on it",
                    path.display()
                )),
                "{contents:?} at {mode:o}"
            );
        }
    }

    #[test]
    fn expand_with_home_substitutes_an_explicit_home() {
        assert_eq!(expand_home("~/app", "/home/deploy"), "/home/deploy/app");
        assert_eq!(expand_home("$HOME/x", "/home/deploy"), "/home/deploy/x");
        // a non-home path is untouched by the home substitution
        assert_eq!(expand_home("/etc/app", "/home/deploy"), "/etc/app");
    }

    #[test]
    fn resolves_multiple_vars_with_literal_text() {
        // Robust regardless of whether PATH is set: an unset var resolves to
        // empty, and we compare against the same lookup the resolver does.
        let path = std::env::var("PATH").unwrap_or_default();
        assert_eq!(
            expand_local(&format!("x:{}:y", marker("PATH"))),
            format!("x:{path}:y")
        );
    }

    #[test]
    fn unset_var_resolves_to_empty() {
        assert_eq!(
            expand_local(&format!("a{}b", marker("ZAP_DEFINITELY_UNSET_VAR_123"))),
            "ab"
        );
    }

    /// Only a marker is a reference: text that spells one — `{env:NAME}`, as one is
    /// shown, or `$$NAME$$` — is left as it is, whatever the variable holds.
    #[test]
    fn text_that_spells_a_reference_is_left_verbatim() {
        let _env = test_env::set(&[("ZAP_T_SPELLED", "resolved")]);
        for text in [
            "$$NOCLOSE",
            "$$ZAP_T_SPELLED$$",
            "{env:ZAP_T_SPELLED}",
            "a $$ b $$$$ c",
        ] {
            assert_eq!(expand_local(text), text);
            assert_eq!(resolve_command(text).as_deref(), Ok(text));
        }
        assert_eq!(
            resolve_command(&marker("ZAP_T_SPELLED")).as_deref(),
            Ok("resolved")
        );
    }

    /// A path, or a name the target is read by, takes any value but one holding a NUL
    /// or a reference delimiter — a quote, a space, a `$` are a path's to hold — and the
    /// refusal names the variable, says what the value was for, and holds no value.
    #[test]
    fn a_field_value_is_refused_by_name_for_a_nul_or_a_delimiter_only() {
        use zap_types::var_ref::{CLOSE, OPEN};
        let _env = test_env::set(&[
            ("ZAP_T_FIELD_OK", "/srv/it's \"a\" $dir"),
            ("ZAP_T_FIELD_REF", &format!("/srv/{OPEN}X{CLOSE}/d")),
            ("ZAP_T_FIELD_HALF", &format!("/srv/{CLOSE}")),
            ("ZAP_T_FIELD_NUL", "/srv/a\0b"),
        ]);
        let path = |name: &str| format!("{}/x", marker(name));
        assert_eq!(
            resolve_field(&path("ZAP_T_FIELD_OK")).as_deref(),
            Ok("/srv/it's \"a\" $dir/x")
        );
        assert_eq!(
            expand_runtime_path(&path("ZAP_T_FIELD_OK")).ok().as_deref(),
            Some("/srv/it's \"a\" $dir/x")
        );
        for name in ["ZAP_T_FIELD_REF", "ZAP_T_FIELD_HALF"] {
            let refused = UnsafeValue::FieldDelimiter {
                name: name.to_owned(),
            };
            assert_eq!(resolve_field(&path(name)), Err(refused.clone()));
            let Err(Error::UnusableValue(found)) = expand_runtime_path(&path(name)) else {
                panic!("{name} resolved into a path");
            };
            assert_eq!(found, refused);
            assert_eq!(expand_with_home(&path(name), "/home/d"), Err(refused));
        }
        let refused = UnsafeValue::FieldNul {
            name: "ZAP_T_FIELD_NUL".to_owned(),
        };
        assert_eq!(
            resolve_field(&path("ZAP_T_FIELD_NUL")),
            Err(refused.clone())
        );
        assert_eq!(
            refused.to_string(),
            "`{env:ZAP_T_FIELD_NUL}` resolves to a value containing a NUL byte, which no path \
             or name on the target can hold"
        );
        assert_eq!(
            UnsafeValue::FieldDelimiter {
                name: "ZP".to_owned()
            }
            .to_string(),
            "`{env:ZP}` resolves to a value containing a reference delimiter (U+FDD0 or \
             U+FDD1), which zap won't use as a path or a name on the target"
        );
    }

    /// A value is substituted once and never read for references of its own: one that
    /// holds a marker is refused by name where it would reach a command, and so is text
    /// holding a delimiter outside a reference — what a checked resolver returns holds
    /// no delimiter.
    #[test]
    fn a_value_cannot_smuggle_a_reference() {
        use zap_types::var_ref::{CLOSE, OPEN};
        let _env = test_env::set(&[
            ("ZAP_T_OUTER", &marker("ZAP_T_INNER")),
            ("ZAP_T_INNER", "inner value"),
            ("ZAP_T_HALF", &format!("half{OPEN}")),
        ]);
        let outer = format!("echo '{}'", marker("ZAP_T_OUTER"));
        // The unchecked resolver substitutes once: the value's marker is left as text.
        assert_eq!(
            resolve_env_vars(&outer),
            format!("echo '{}'", marker("ZAP_T_INNER"))
        );
        for resolve in [resolve_command, resolve_env_value, resolve_sql_identifier] {
            assert_eq!(
                resolve(&outer),
                Err(UnsafeValue::Delimiter {
                    name: "ZAP_T_OUTER".to_owned()
                })
            );
            assert_eq!(
                resolve(&marker("ZAP_T_HALF")),
                Err(UnsafeValue::Delimiter {
                    name: "ZAP_T_HALF".to_owned()
                })
            );
            for stray in [
                format!("echo {OPEN}"),
                format!("echo {CLOSE}"),
                format!("echo {OPEN}not a name{CLOSE}"),
                format!("{OPEN}{}", marker("ZAP_T_INNER")),
            ] {
                assert_eq!(
                    resolve(&stray),
                    Err(UnsafeValue::StrayDelimiter),
                    "{stray:?}"
                );
            }
        }
        let message = UnsafeValue::Delimiter {
            name: "ZAP_T_OUTER".to_owned(),
        }
        .to_string();
        assert!(
            message.starts_with("`{env:ZAP_T_OUTER}` resolves to a value containing a reference"),
            "{message}"
        );
        assert!(!message.contains("inner"), "{message}");
    }

    #[test]
    fn expands_leading_tilde_to_home() {
        let _env = test_env::set(&[("HOME", "/home/zap-test")]);
        assert_eq!(expand_local("~/bin"), "/home/zap-test/bin");
        assert_eq!(expand_local("~"), "/home/zap-test");
        assert_eq!(expand_local("$HOME/.local"), "/home/zap-test/.local");
        // a non-leading tilde is not special
        assert_eq!(expand_local("/a/~/b"), "/a/~/b");
    }

    /// A local path that references the home needs one: an empty `HOME` is no home, a
    /// relative one is refused by name, and neither is guessed around. A path that
    /// references no home resolves whatever `HOME` holds.
    #[test]
    fn a_local_home_path_needs_an_absolute_home() {
        for (home, relative) in [("", false), ("rel/home", true), (".", true)] {
            let _env = test_env::set(&[("HOME", home)]);
            for path in ["~/bin", "~", "$HOME/.local"] {
                let error = expand_runtime_path(path).unwrap_err();
                // Either way it is the operator's to fix, as a remote target's is.
                assert_eq!(error.exit_code(), 2, "{home:?}: {error}");
                if relative {
                    assert!(
                        matches!(error, Error::HomeNotAbsolute { var: "HOME" }),
                        "{home:?}: {error}"
                    );
                } else {
                    assert_eq!(
                        error.to_string(),
                        format!(
                            "local path `{path}` references the home directory, but `HOME` \
                             is unset or empty (set it, or use an absolute path)"
                        )
                    );
                }
            }
            for path in ["/etc/motd", "/a/~/b", "/opt/$HOMEBREW_PREFIX"] {
                assert_eq!(expand_local(path), path, "{home:?}");
            }
        }
    }
}
