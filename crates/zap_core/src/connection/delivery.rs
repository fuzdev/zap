//! How a command's text reaches the shell that runs it: on that shell's **stdin**, to a
//! constant wrapper — never on an argv.
//!
//! Every command [`Connection::run`](super::Connection::run) and its siblings execute is
//! a [`Delivery`]: the constant shell program the child is started with
//! ([`COMMAND_SHELL`]), and the bytes written to its stdin. So no command text, `env`
//! value, or `cwd` is on the argv of the local `sh`, the local `ssh`, the target's login
//! shell, or the target's `sh`. Each program a command starts has an argv of its own
//! (`curl -H "Authorization: …"` shows its header while it runs); that is the command's
//! doing, outside the delivery.
//!
//! The stdin is a **frame**: a decimal line count, that many lines of script, then —
//! when the command reads data — the payload's bytes to the end of the stream. The
//! wrapper takes the count and the script with the shell's `read`, which a POSIX shell
//! performs one byte at a time on a pipe, so it consumes the script's last newline and
//! nothing after it, and then `eval`s the script:
//!
//! - **With a payload**, the command inherits the stdin positioned at the payload's first
//!   byte. The shell never reads a payload byte, so a payload can hold anything (NULs, no
//!   trailing newline, text that looks like a script or a count) and be any size, and the
//!   command can read nothing but the payload.
//! - **With none**, the script's first act is to detach its stdin (`/dev/null`), so the
//!   command reads nothing.
//!
//! A frame is all or nothing: a stream that ends before the script does, or doesn't start
//! with a count the wrapper accepts (one to nine digits and nothing else, no leading
//! zero), exits
//! 98 with nothing run — a command is never run in part. A payload has no
//! length of its own; one cut short reaches its command short, as a file piped to it
//! would. A command that must not act on a short payload checks it itself: the put
//! script (`zap_types::put::FILE_PUT`) reads a digest line ahead of the content and
//! installs nothing unless the bytes it received match.
//!
//! A script can't hold a NUL (a shell would drop it and run different text), so
//! [`Delivery::of`] refuses one; a payload can. It refuses a script holding a reference
//! delimiter too ([`refuse_delimiter`]): every reference in command text is resolved
//! before the text gets here, so one that is still there was missed, and the text is
//! not the command anyone reviewed.
//!
//! The wrapper is one line and holds no single quote, backslash, or `!`, so
//! [`ssh_remote_arg`]'s one quoted word reads the same to a login shell that treats `\'`
//! inside single quotes as an escape (`fish`) as to a POSIX one. It uses shell builtins
//! only. Reading a byte at a time costs: tens of milliseconds for a 64 KiB script, about
//! half a second for a 1 MiB one of few lines, and seconds for a 1 MiB one of many short
//! lines (each line is appended to the text read so far).
//!
//! A detection batch is delivered by its own wrapper (`zap_types::observe::batch`), not
//! this one.

use std::ffi::OsStr;
use std::process::Stdio;

use tokio::process::Command;
use zap_types::shell::single_quote;

use super::{RunOptions, pipe_stdin_and_wait};

/// The shell program every command runs under: read the frame's line count, then that
/// many lines as the script, then `eval` it with the stdin left where the script ended.
///
/// The count line must be one to nine ASCII digits and nothing else, the first not `0`
/// (so no sign, blank, carriage return, or leading zero, which a shell's arithmetic
/// would read as octal) — anything else, and a stream that ends before the count's
/// newline or before the script's last one, exits 98 with nothing run. `IFS= read -r`
/// takes each line raw; the newline that ends it is put back from `__zap_nl`, made
/// without a literal one.
pub(super) const COMMAND_SHELL: &str = concat!(
    "IFS= read -r __zap_n || exit 98; ",
    "case $__zap_n in ??????????*|0*) exit 98;; esac; ",
    "__zap_l=$__zap_n; ",
    "while :; do case $__zap_l in [0-9]*) __zap_l=${__zap_l#?};; *) break;; esac; done; ",
    "[ -z \"$__zap_l\" ] || exit 98; ",
    "[ \"$__zap_n\" -gt 0 ] 2>/dev/null || exit 98; ",
    "__zap_nl=$(echo; echo .); __zap_nl=${__zap_nl%.}; ",
    "[ ${#__zap_nl} -eq 1 ] || exit 98; ",
    "__zap_script=; ",
    "while [ \"$__zap_n\" -gt 0 ]; do ",
    "IFS= read -r __zap_l || exit 98; ",
    "__zap_script=$__zap_script$__zap_l$__zap_nl; ",
    "__zap_n=$((__zap_n - 1)); ",
    "done; ",
    "eval \"$__zap_script\"",
);

/// What every delivered script starts with: the wrapper's own variables unset, so the
/// script's text is in no environment the command passes on (a login environment that
/// exports one of these names would otherwise carry it to every child).
const UNSET: &str = "unset __zap_script __zap_n __zap_l __zap_nl; ";

/// What a script with no payload does next: detach its stdin, so its commands read
/// nothing.
const DETACH: &str = "exec </dev/null; ";

/// Refuse command text that holds a reference delimiter, resolved or not.
///
/// A reference is resolved before its text is delivered, and resolution leaves no
/// delimiter behind. Text that still holds one would reach the shell as bytes it doesn't
/// read as anything — the command would run with a hole where a value belonged.
///
/// # Errors
/// [`std::io::ErrorKind::InvalidInput`] when `script` holds either delimiter.
pub(super) fn refuse_delimiter(script: &str) -> std::io::Result<()> {
    refuse_delimiter_as(script, COMMAND_HOLDS_DELIMITER)
}

/// [`refuse_delimiter`] for a path a detection query reads: the same refusal, said of
/// a path.
///
/// # Errors
/// [`std::io::ErrorKind::InvalidInput`] when `path` holds either delimiter.
pub(super) fn refuse_delimiter_in_path(path: &str) -> std::io::Result<()> {
    refuse_delimiter_as(path, PATH_HOLDS_DELIMITER)
}

fn refuse_delimiter_as(text: &str, message: &'static str) -> std::io::Result<()> {
    if zap_types::var_ref::holds_delimiter(text) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            message,
        ));
    }
    Ok(())
}

/// What a refused command is told. It says what is known: the text holds a delimiter.
/// Which of the two ways it got there — a reference nobody resolved, or a value that
/// holds one — the text doesn't say.
const COMMAND_HOLDS_DELIMITER: &str = "the command holds a reference delimiter (U+FDD0 or \
    U+FDD1) — an unresolved reference, or a value containing one — which no shell can read; \
    it was not run";

/// What a refused path is told ([`COMMAND_HOLDS_DELIMITER`]'s counterpart).
pub(super) const PATH_HOLDS_DELIMITER: &str = "the path holds a reference delimiter (U+FDD0 \
    or U+FDD1) — an unresolved reference, or a value containing one; nothing was read or \
    written";

/// One command, as it is handed to a shell: the constant program the shell is started
/// with, and what is written to its stdin.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Delivery {
    /// The shell program — [`COMMAND_SHELL`], never command text.
    pub(super) wrapper: &'static str,
    /// The bytes for the shell's stdin: the frame's count and script, and after them
    /// the payload.
    pub(super) stdin: Vec<u8>,
}

impl Delivery {
    /// Deliver `script`, with `payload` as the stdin the script's commands read (`None`:
    /// they read nothing).
    ///
    /// # Errors
    /// [`std::io::ErrorKind::InvalidInput`] when `script` holds a NUL byte — a shell
    /// would drop it and run a different command — or a reference delimiter
    /// ([`refuse_delimiter`]).
    pub(super) fn of(script: &str, payload: Option<&[u8]>) -> std::io::Result<Self> {
        if script.contains('\0') {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "the command holds a NUL byte, which a shell would drop; it was not run",
            ));
        }
        refuse_delimiter(script)?;
        let detach = if payload.is_some() { "" } else { DETACH };
        let script = format!("{UNSET}{detach}{script}\n");
        let lines = script.bytes().filter(|&byte| byte == b'\n').count();
        let mut stdin = format!("{lines}\n{script}").into_bytes();
        stdin.extend_from_slice(payload.unwrap_or_default());
        Ok(Self {
            wrapper: COMMAND_SHELL,
            stdin,
        })
    }

    /// The `shell` command that runs this delivery on this machine, with `options`' `cwd`
    /// and `env` set on the process itself (its working directory and environment, not
    /// its argv).
    pub(super) fn local_command(&self, shell: impl AsRef<OsStr>, options: &RunOptions) -> Command {
        let mut command = Command::new(shell);
        command.arg("-c").arg(self.wrapper);
        if let Some(cwd) = &options.cwd {
            command.current_dir(cwd);
        }
        for (key, value) in &options.env {
            command.env(key, value);
        }
        command
    }

    /// Start `command` with its stdio piped, write the stdin, and collect its output.
    ///
    /// The child stays in the caller's process group and session, so a `sudo` in the
    /// script can still prompt on the terminal zap runs in.
    pub(super) async fn run(self, mut command: Command) -> std::io::Result<std::process::Output> {
        let child = command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        pipe_stdin_and_wait(child, self.stdin).await
    }
}

/// The argument the `ssh` client passes as the remote command, for a remote `command`:
/// `sh -c` over it, so the target's login shell only has to parse one quoted word.
pub(super) fn ssh_remote_arg(command: &str) -> String {
    format!("sh -c {}", single_quote(command))
}

#[cfg(test)]
mod tests;
