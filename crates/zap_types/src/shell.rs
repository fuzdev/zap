//! Shell-quoting primitives shared by the planner (step generation) and the IO
//! engine (detection probes).
//!
//! Pure string transforms — they belong here so the plan fact and the detector
//! quote identically (a probe and the mutation it guards must build byte-identical
//! commands, or detection and execution silently disagree).

/// Single-quote a value for safe interpolation into a `sh -c` command (a literal
/// `'` becomes `'\''`).
///
/// The canonical shell-escape both crates use: the planner wraps user-supplied
/// SSH-key / sudoers text fed into a `tee` pipe, and the detector wraps `psql`
/// arguments and `grep` patterns. One definition so quoting can't drift between
/// the probe and the mutation it guards.
#[must_use]
pub fn single_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', r"'\''"))
}

/// What becomes of the message a failed `cd` prints, in [`run_context`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CdMessage {
    /// Left on stderr — a command's failure says which directory it couldn't enter.
    Kept,
    /// Discarded with anything else the `cd` prints — a probe read by its exit status.
    Discarded,
}

/// The line that puts a command in its working directory with its environment, for the
/// command to follow on the next — or nothing, with neither a `cwd` nor `env`:
///
/// ```text
/// CDPATH= cd -P -- '<cwd>' [>/dev/null 2>&1 ]|| exit; export K='v' …
/// ```
///
/// - The `cd` consults no `CDPATH`, is physical, and takes the path after `--`: the
///   `chdir` a process spawned in the directory makes. When it fails the shell exits
///   with its (nonzero) status, so nothing after it runs anywhere else.
/// - The `env` is exported after the `cd` (so no value steers it) and for everything
///   that follows — every command of a compound sees it. Each value, and the `cwd`, is
///   single-quoted here, so it can hold any text.
/// - It ends with a newline: a shell reads a whole line before it runs any of it, so
///   text that follows and doesn't parse can't keep the `cd` from running first.
///
/// One definition, so a `script`'s check and its `run` enter the same directory with the
/// same environment, on every connection.
#[must_use]
pub fn run_context<'a>(
    cwd: Option<&str>,
    env: impl IntoIterator<Item = (&'a str, &'a str)>,
    cd_message: CdMessage,
) -> String {
    let mut parts = Vec::new();
    if let Some(cwd) = cwd {
        let discard = match cd_message {
            CdMessage::Kept => "",
            CdMessage::Discarded => ">/dev/null 2>&1 ",
        };
        parts.push(format!(
            "CDPATH= cd -P -- {} {discard}|| exit",
            single_quote(cwd)
        ));
    }
    let assignments: Vec<String> = env
        .into_iter()
        .map(|(key, value)| format!("{key}={}", single_quote(value)))
        .collect();
    if !assignments.is_empty() {
        parts.push(format!("export {}", assignments.join(" ")));
    }
    if parts.is_empty() {
        return String::new();
    }
    format!("{}\n", parts.join("; "))
}

#[cfg(test)]
mod tests {
    use super::{CdMessage, run_context, single_quote};

    #[test]
    fn the_run_context_is_one_line_ahead_of_the_command() {
        let env = [("TOKEN", "a b"), ("MODE", "it's")];
        assert_eq!(
            run_context(Some("/srv/my app"), env, CdMessage::Kept),
            "CDPATH= cd -P -- '/srv/my app' || exit; export TOKEN='a b' MODE='it'\\''s'\n"
        );
        assert_eq!(
            run_context(Some("/srv/my app"), env, CdMessage::Discarded),
            "CDPATH= cd -P -- '/srv/my app' >/dev/null 2>&1 || exit; export TOKEN='a b' \
             MODE='it'\\''s'\n"
        );
        assert_eq!(
            run_context(Some("/srv/app"), [], CdMessage::Kept),
            "CDPATH= cd -P -- '/srv/app' || exit\n"
        );
        assert_eq!(
            run_context(None, [("TOKEN", "a b")], CdMessage::Kept),
            "export TOKEN='a b'\n"
        );
        assert_eq!(run_context(None, [], CdMessage::Discarded), "");
    }

    #[test]
    fn wraps_in_single_quotes() {
        assert_eq!(single_quote("plain"), "'plain'");
    }

    #[test]
    fn escapes_embedded_single_quotes() {
        assert_eq!(single_quote("a'b"), r"'a'\''b'");
    }
}
