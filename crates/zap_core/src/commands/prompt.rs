//! The review a wetrun asks for when nothing was reviewed before it.
//!
//! A wetrun executes only a reviewed plan. On an interactive terminal, a wetrun whose
//! plan has no review — no preview recorded on this host, or one of another plan — shows
//! the plan it computed, with its `plan_hash`, and asks the operator to type the first
//! [`CONFIRM_CHARS`] characters of that hash: the operator reviews it there. The answer
//! comes from the plan, and what was typed before the question appears is discarded
//! ([`discard_typeahead`]), so neither a `y` nor the confirmation of an earlier run
//! typed ahead while detection runs answers it. The right characters execute exactly the plan
//! shown, under the same steps as a wetrun bound to a recorded preview; anything else is
//! the refusal a wetrun with no review gets everywhere else.
//!
//! It is never asked when the operator named a plan (`--expect-plan`) — a mismatch is
//! refused, never swapped for the plan computed — nor under `--json`, nor when there is
//! no terminal to ask on. The terminal is the caller's ([`Prompt`]); this crate prints
//! nothing on its own: [`ask_on`] writes only to the writer its caller passes.

use std::fmt::Debug;
use std::os::fd::AsFd;

use zap_types::last_run::{PassLabel, PlanUnreviewed};

/// Where a wetrun asks its operator to confirm a plan: the binary's terminal, or a
/// test's script.
pub trait Prompt: Debug + Send + Sync {
    /// Whether an operator is there to answer — the standard input and the standard
    /// error are both terminals.
    fn interactive(&self) -> bool;

    /// Show `text` (the plan, then the question, with no newline after it), discard any
    /// input typed before it ([`discard_typeahead`]), and read one line of answer
    /// ([`ask_on`]). `None` at the end of the input or on a read error.
    fn ask(&self, text: &str) -> Option<String>;
}

/// How a wetrun's review at the prompt went, on the report it ends with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Confirmation {
    /// The plan is shown and the question is open — the render the prompt is asked
    /// under, never a report a command returns.
    Asking,
    /// The operator typed the plan's confirmation: it ran as a reviewed one.
    Accepted,
    /// The operator answered anything else, or nothing: the wetrun refused, as one with
    /// no review does without a prompt.
    Declined,
}

/// How many leading characters of the `plan_hash` confirm a plan: 32 bits, so the
/// confirmation of one plan, retyped from memory, confirms another only by a collision
/// no operator meets.
pub const CONFIRM_CHARS: usize = 8;

/// Discard the input a terminal holds unread (`tcflush(TCIFLUSH)`): what was typed
/// before the question appeared can't answer it.
///
/// # Errors
///
/// The flush's error, when `terminal` is not a terminal.
pub fn discard_typeahead(terminal: impl AsFd) -> std::io::Result<()> {
    rustix::termios::tcflush(terminal, rustix::termios::QueueSelector::IFlush)?;
    Ok(())
}

/// `apply`'s question, before the characters it asks for.
pub(crate) const APPLY_QUESTION: &str = "Apply this plan?";

/// `deploy`'s question, before the characters it asks for.
pub(crate) const DEPLOY_QUESTION: &str = "Deploy this plan?";

/// The question as asked: `question`, then what to type to confirm `plan_hash` — its
/// first [`CONFIRM_CHARS`] characters.
pub(crate) fn asked(question: &str, plan_hash: &str) -> String {
    format!(
        "{question} Type {}, the start of its plan_hash, to confirm: ",
        confirmation_of(plan_hash)
    )
}

/// The characters that confirm `plan_hash`: its first [`CONFIRM_CHARS`].
fn confirmation_of(plan_hash: &str) -> &str {
    plan_hash.get(..CONFIRM_CHARS).unwrap_or(plan_hash)
}

/// Ask a wetrun's operator to confirm the plan it would refuse for `reason`, when it may
/// ask: `None` when it didn't ask, else the answer.
///
/// It asks only when the plan has no review at all — no preview, or a preview of
/// another plan. A plan `--expect-plan` named and this one isn't
/// ([`PlanUnreviewed::Expected`]) is refused unasked: the operator named a plan, and
/// another one is not offered in its place. Never under `--json` (`emit_json`), and
/// never without a `prompt` that is [`interactive`](Prompt::interactive). `show` is the
/// plan as the operator reviews it, rendered only when the question is asked; the
/// `question` follows it, asking for the start of `plan_hash` ([`asked`]).
pub(crate) fn confirm<P: PassLabel, N: PassLabel>(
    prompt: Option<&dyn Prompt>,
    emit_json: bool,
    reason: &PlanUnreviewed<P, N>,
    plan_hash: &str,
    show: impl FnOnce() -> String,
    question: &str,
) -> Option<Confirmation> {
    if emit_json || matches!(reason, PlanUnreviewed::Expected { .. }) {
        return None;
    }
    let prompt = prompt.filter(|prompt| prompt.interactive())?;
    let answer = prompt.ask(&format!("{}{}", show(), asked(question, plan_hash)));
    Some(if confirms(answer.as_deref(), plan_hash) {
        Confirmation::Accepted
    } else {
        Confirmation::Declined
    })
}

/// Whether `answer` confirms `plan_hash`: exactly its first [`CONFIRM_CHARS`]
/// characters, in any case, blanks around them aside. Nothing else does — not a `y`,
/// not more of the hash, and no answer at all.
fn confirms(answer: Option<&str>, plan_hash: &str) -> bool {
    let expected = confirmation_of(plan_hash);
    expected.len() == CONFIRM_CHARS
        && answer.is_some_and(|answer| answer.trim().eq_ignore_ascii_case(expected))
}

/// A terminal a question is answered on: what was typed before the question can be
/// discarded, and a line read after it.
pub trait TerminalInput {
    /// Discard the input typed but not yet read ([`discard_typeahead`] on a terminal).
    ///
    /// # Errors
    /// The discard's error: the input is no terminal it can discard on.
    fn discard_typeahead(&mut self) -> std::io::Result<()>;

    /// Read one line of answer into `line`, as [`std::io::BufRead::read_line`] does.
    ///
    /// # Errors
    /// The read's error.
    fn read_line(&mut self, line: &mut String) -> std::io::Result<usize>;
}

/// This process's standard input, as the terminal a question is answered on.
#[derive(Debug, Clone, Copy)]
pub struct StdinTerminal;

impl TerminalInput for StdinTerminal {
    fn discard_typeahead(&mut self) -> std::io::Result<()> {
        discard_typeahead(std::io::stdin())
    }

    fn read_line(&mut self, line: &mut String) -> std::io::Result<usize> {
        std::io::stdin().read_line(line)
    }
}

/// Ask `text` on a terminal: write it to `out`, discard what was typed before it
/// appeared, and read one line from `input`.
///
/// `None` when the discard fails (asked only on a terminal, that is a read error), at
/// the end of the input, or on a read error; then a line break ends the question's line
/// before what follows.
pub fn ask_on(
    out: &mut impl std::io::Write,
    input: &mut impl TerminalInput,
    text: &str,
) -> Option<String> {
    let _ = write!(out, "{text}");
    let _ = out.flush();
    let mut answer = String::new();
    match input
        .discard_typeahead()
        .and_then(|()| input.read_line(&mut answer))
    {
        Ok(0) | Err(_) => {
            let _ = writeln!(out);
            None
        }
        Ok(_) => Some(answer),
    }
}

/// What a [`ScriptedPrompt`] answers.
#[cfg(test)]
#[derive(Debug, Clone)]
pub(crate) enum Scripted {
    /// This line, or the end of the input (`None`).
    Line(Option<String>),
    /// What the question it was shown asks to be typed, read off that text as an
    /// operator reads it off the screen.
    TheConfirmation,
}

/// A [`Prompt`] a test scripts: whether it is interactive, what it answers, and every
/// text it was shown.
#[cfg(test)]
#[derive(Debug)]
pub(crate) struct ScriptedPrompt {
    /// What [`Prompt::interactive`] says.
    pub terminal: bool,
    /// What [`Prompt::ask`] reads.
    pub answer: Scripted,
    /// Each text [`Prompt::ask`] was shown, in order.
    pub shown: std::sync::Mutex<Vec<String>>,
}

#[cfg(test)]
impl ScriptedPrompt {
    fn of(terminal: bool, answer: Scripted) -> std::sync::Arc<Self> {
        std::sync::Arc::new(Self {
            terminal,
            answer,
            shown: std::sync::Mutex::new(Vec::new()),
        })
    }

    /// An interactive prompt answering `answer`.
    pub(crate) fn answering(answer: Option<&str>) -> std::sync::Arc<Self> {
        Self::of(true, Scripted::Line(answer.map(str::to_owned)))
    }

    /// An interactive prompt that types what the question asks for.
    pub(crate) fn confirming() -> std::sync::Arc<Self> {
        Self::of(true, Scripted::TheConfirmation)
    }

    /// A prompt with no terminal, which would confirm if it were ever asked.
    pub(crate) fn no_terminal() -> std::sync::Arc<Self> {
        Self::of(false, Scripted::TheConfirmation)
    }

    /// Every text the prompt was shown.
    pub(crate) fn shown(&self) -> Vec<String> {
        self.shown.lock().unwrap().clone()
    }
}

#[cfg(test)]
impl Prompt for ScriptedPrompt {
    fn interactive(&self) -> bool {
        self.terminal
    }

    fn ask(&self, text: &str) -> Option<String> {
        self.shown.lock().unwrap().push(text.to_owned());
        match &self.answer {
            Scripted::Line(line) => line.clone(),
            Scripted::TheConfirmation => text
                .rsplit_once(" Type ")
                .and_then(|(_, rest)| rest.split_once(','))
                .map(|(characters, _)| format!("{characters}\n")),
        }
    }
}

#[cfg(test)]
mod tests {
    use zap_types::last_run::{PlanUnreviewed, RunCommand};

    use super::{
        CONFIRM_CHARS, Confirmation, Prompt, ScriptedPrompt, asked, confirm, confirms,
        discard_typeahead,
    };

    const HASH: &str = "afdcd1b9e92f4272cc1593f271ffcd88c725c2f2969885154684348fd33c63e9";

    /// The start of the plan's hash confirms it, in any case and with blanks around it;
    /// nothing else does — not a `y`, not a prefix of another length, not the whole
    /// hash, not another hash's start, and no answer at all.
    #[test]
    fn only_the_start_of_the_plan_hash_confirms_it() {
        assert_eq!(CONFIRM_CHARS, 8);
        for answer in [
            "afdcd1b9",
            "AFDCD1B9",
            "AfDcD1b9",
            "afdcd1b9\n",
            "  afdcd1b9 \r\n",
            "\tAFDCD1B9\n",
        ] {
            assert!(confirms(Some(answer), HASH), "{answer:?}");
        }
        for answer in [
            None,
            Some(""),
            Some("\n"),
            Some("y"),
            Some("Y\n"),
            Some("yes"),
            Some("afdc"),
            Some("afdcd1b"),
            Some("afdcd1b9e"),
            Some(HASH),
            Some("abcdd1b9"),
            Some("afdc d1b9"),
            Some("y\nafdcd1b9"),
            Some("ａｆｄｃｄ１ｂ９"),
        ] {
            assert!(!confirms(answer, HASH), "{answer:?}");
        }
        // A hash too short to have the characters is confirmed by nothing.
        assert!(!confirms(Some("afdcd1b"), "afdcd1b"));
    }

    #[test]
    fn the_question_names_the_characters_to_type() {
        assert_eq!(
            asked("Apply this plan?", HASH),
            "Apply this plan? Type afdcd1b9, the start of its plan_hash, to confirm: "
        );
    }

    /// Input typed into a terminal before the question is asked is discarded: the line
    /// read after it is the one typed after it.
    #[test]
    fn typeahead_is_discarded_before_the_answer_is_read() {
        use std::io::{BufRead, BufReader, Write};

        use rustix::pty::{OpenptFlags, grantpt, openpt, ptsname, unlockpt};

        let controller = openpt(OpenptFlags::RDWR | OpenptFlags::NOCTTY).unwrap();
        grantpt(&controller).unwrap();
        unlockpt(&controller).unwrap();
        let name = ptsname(&controller, Vec::new()).unwrap();
        let terminal = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(name.to_str().unwrap())
            .unwrap();
        let mut keyboard = std::fs::File::from(controller);

        keyboard.write_all(b"afdcd1b9\n").unwrap();
        discard_typeahead(&terminal).unwrap();
        keyboard.write_all(b"typed after\n").unwrap();
        let mut answer = String::new();
        BufReader::new(&terminal).read_line(&mut answer).unwrap();
        assert_eq!(answer, "typed after\n");

        // Not a terminal: an error, never a silent pass.
        assert!(discard_typeahead(tempfile::tempfile().unwrap()).is_err());
    }

    /// A terminal whose input holds `typed` until it is discarded, then `answer`.
    /// What the fake terminal and its writer did, in order.
    type Log = std::rc::Rc<std::cell::RefCell<Vec<&'static str>>>;

    struct FakeTerminal {
        typed: Option<&'static str>,
        answer: &'static str,
        discard_fails: bool,
        log: Log,
    }

    impl super::TerminalInput for FakeTerminal {
        fn discard_typeahead(&mut self) -> std::io::Result<()> {
            self.log.borrow_mut().push("discard");
            if self.discard_fails {
                return Err(std::io::Error::other("not a terminal"));
            }
            self.typed = None;
            Ok(())
        }

        fn read_line(&mut self, line: &mut String) -> std::io::Result<usize> {
            self.log.borrow_mut().push("read");
            let next = self.typed.take().unwrap_or(self.answer);
            line.push_str(next);
            Ok(next.len())
        }
    }

    /// The writer the question goes to, logging each write beside the terminal's acts.
    struct LoggedWriter {
        bytes: Vec<u8>,
        log: Log,
    }

    impl std::io::Write for LoggedWriter {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            if !buf.is_empty() {
                self.log.borrow_mut().push("write");
            }
            self.bytes.extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    fn fake(
        typed: Option<&'static str>,
        answer: &'static str,
        discard_fails: bool,
    ) -> (LoggedWriter, FakeTerminal) {
        let log = Log::default();
        let out = LoggedWriter {
            bytes: Vec::new(),
            log: std::rc::Rc::clone(&log),
        };
        let terminal = FakeTerminal {
            typed,
            answer,
            discard_fails,
            log,
        };
        (out, terminal)
    }

    /// A question is answered by what is typed after it is shown: the line typed ahead
    /// is discarded first, after the question is written; a discard that fails is no
    /// answer.
    #[test]
    fn the_terminal_answer_is_read_after_the_typeahead_is_discarded() {
        let (mut out, mut terminal) = fake(Some("afdcd1b9\n"), "typed after\n", false);
        let answer = super::ask_on(&mut out, &mut terminal, "Go? ");
        assert_eq!(answer.as_deref(), Some("typed after\n"));
        assert_eq!(out.bytes, b"Go? ");
        assert_eq!(*terminal.log.borrow(), ["write", "discard", "read"]);

        // No answer ends the question's line.
        let (mut out, mut terminal) = fake(None, "", false);
        assert_eq!(super::ask_on(&mut out, &mut terminal, "Go? "), None);
        assert_eq!(out.bytes, b"Go? \n");

        // A discard that fails reads nothing typed ahead: there is no answer.
        let (mut out, mut terminal) = fake(Some("afdcd1b9\n"), "typed after\n", true);
        assert_eq!(super::ask_on(&mut out, &mut terminal, "Go? "), None);
        assert_eq!(out.bytes, b"Go? \n");
        assert_eq!(*terminal.log.borrow(), ["write", "discard", "write"]);
    }

    type Reason = PlanUnreviewed<RunCommand, RunCommand>;

    /// It asks only an interactive prompt, never under `--json`, and never about a plan
    /// `--expect-plan` named.
    #[test]
    fn it_asks_only_an_interactive_operator_who_named_no_plan() {
        let no_preview: Reason = PlanUnreviewed::NoPreview { prior: None };
        let expected: Reason = PlanUnreviewed::Expected {
            expected: "abc".to_owned(),
        };
        let shown = || "the plan\n".to_owned();

        let typed = ScriptedPrompt::answering(Some("AFDCD1B9\n"));
        assert_eq!(
            confirm(Some(&*typed), false, &no_preview, HASH, shown, "Go?"),
            Some(Confirmation::Accepted)
        );
        // An operator reading the question types what confirms it.
        let reading = ScriptedPrompt::confirming();
        assert_eq!(
            confirm(Some(&*reading), false, &no_preview, HASH, shown, "Go?"),
            Some(Confirmation::Accepted)
        );
        assert_eq!(
            typed.shown(),
            ["the plan\nGo? Type afdcd1b9, the start of its plan_hash, to confirm: "]
        );
        for answer in [Some("y"), Some("yes"), Some(""), None] {
            let prompt = ScriptedPrompt::answering(answer);
            assert_eq!(
                confirm(Some(&*prompt), false, &no_preview, HASH, shown, "Go?"),
                Some(Confirmation::Declined),
                "{answer:?}"
            );
        }

        let never = |prompt: Option<&dyn Prompt>, emit_json: bool, reason: &Reason| {
            confirm(
                prompt,
                emit_json,
                reason,
                HASH,
                || panic!("the plan is rendered only to be asked about"),
                "Go?",
            )
        };
        let typed = ScriptedPrompt::confirming();
        assert_eq!(never(Some(&*typed), false, &expected), None);
        assert_eq!(never(Some(&*typed), true, &no_preview), None);
        assert_eq!(never(None, false, &no_preview), None);
        let no_terminal = ScriptedPrompt::no_terminal();
        assert_eq!(never(Some(&*no_terminal), false, &no_preview), None);
        assert!(typed.shown().is_empty() && no_terminal.shown().is_empty());
    }
}
