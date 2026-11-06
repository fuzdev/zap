//! Intended divergences — the behavior changes a candidate makes on purpose.
//!
//! The differential compares the two binaries verbatim, so a candidate that changes
//! behavior deliberately (fixes a defect, rewords a reason it can no longer reproduce)
//! diverges. Each such change is recorded here, in a small reviewed table: one entry per
//! `(distro, suite, scenario, cold/warm, command, stream)` and output line, naming the
//! exact line the oracle prints and the exact line the candidate prints in its place, with
//! the reason. Nothing looser: whole lines, matched exactly.
//!
//! A run then treats a divergence as follows:
//!
//! - every oracle-only and candidate-only line of a command (under the same alignment
//!   the rendered diff uses) that an entry names is **accepted**, and reported as
//!   `INTENDED`;
//! - anything left — a line no entry names, an exit code no entry covers — is still a
//!   divergence;
//! - an entry for a run that executed whose oracle or candidate line doesn't appear as a
//!   changed line is an **error**: the allowlist is stale, and a stale entry would
//!   otherwise wave through whatever later lands on its line.
//!
//! A side is `None` when the change adds or removes a line outright (a verdict banner
//! that appears or disappears). An exit-code change is an entry on [`Stream::Exit`],
//! whose lines are the two codes.
//!
//! At [`Level::Semantic`] the same rules apply to the projected text, and each entry is
//! read through the projection first ([`semantic_line`]): a line the projection leaves
//! out of its side counts as no line, a line it rewrites is matched as rewritten, and an
//! entry left with nothing to say — both sides gone, or both the same — is skipped
//! rather than stale, since the projection already took the change it records out of
//! the comparison.

use super::compare::{self, Level, Observed};
use super::scenarios::Suite;
use super::vm::Distro;

/// The content-cache variant of a run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Variant {
    Cold,
    Warm,
}

impl Variant {
    pub const fn name(self) -> &'static str {
        match self {
            Self::Cold => "cold",
            Self::Warm => "warm",
        }
    }
}

/// Which part of a command's result an entry is about.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stream {
    Stdout,
    Stderr,
    /// The exit code, as its decimal text.
    Exit,
}

/// One accepted change of one output line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Intended {
    pub distro: Distro,
    pub suite: Suite,
    pub scenario: &'static str,
    pub variant: Variant,
    /// `detect`, `plan-diff`, or `plan` (see `runner::COMMANDS`).
    pub command: &'static str,
    /// The resource the line is about (a label: a banner line may cover several).
    pub resource: &'static str,
    pub stream: Stream,
    /// The exact oracle line, or `None` when the candidate adds a line outright.
    pub oracle: Option<&'static str>,
    /// The exact candidate line, or `None` when the candidate drops the line.
    pub candidate: Option<&'static str>,
    /// Why the change is intended.
    pub why: &'static str,
}

/// One command's run: what an entry must name to apply to it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RunKey<'a> {
    pub distro: Distro,
    pub suite: Suite,
    pub scenario: &'a str,
    pub variant: Variant,
    pub command: &'a str,
}

impl Intended {
    fn applies_to(&self, key: &RunKey<'_>) -> bool {
        self.distro == key.distro
            && self.suite == key.suite
            && self.scenario == key.scenario
            && self.variant == key.variant
            && self.command == key.command
    }
}

/// The judgment of one command's oracle-vs-candidate comparison.
#[derive(Debug, Default)]
pub struct Judged {
    /// The entries whose lines were found and accepted.
    pub accepted: Vec<Intended>,
    /// Stale entries: a named line that isn't a changed line of this run.
    pub stale: Vec<String>,
    /// Whether any difference is left that no entry accepts.
    pub unaccepted: bool,
}

/// Judge one command's comparison against `table`, at `level`. `oracle` and
/// `candidate` are the normalized observations; the projection is applied here.
pub fn judge(
    table: &[Intended],
    key: &RunKey<'_>,
    level: Level,
    oracle: &Observed,
    candidate: &Observed,
) -> Judged {
    let mut judged = Judged::default();
    let entries: Vec<&Intended> = table.iter().filter(|e| e.applies_to(key)).collect();
    let code = |code: Option<i32>| code.map_or_else(|| "none".to_owned(), |c| c.to_string());
    let (oracle_code, candidate_code) = (code(oracle.code), code(candidate.code));
    let compared = [oracle, candidate].map(|side| compare::at_level(level, key.command, side));
    let [compared_oracle, compared_candidate] = &compared;
    for (stream, old, new, raw) in [
        (
            Stream::Stdout,
            compared_oracle.stdout.as_str(),
            compared_candidate.stdout.as_str(),
            [oracle.stdout.as_str(), candidate.stdout.as_str()],
        ),
        (
            Stream::Stderr,
            compared_oracle.stderr.as_str(),
            compared_candidate.stderr.as_str(),
            [oracle.stderr.as_str(), candidate.stderr.as_str()],
        ),
        (
            Stream::Exit,
            oracle_code.as_str(),
            candidate_code.as_str(),
            ["", ""],
        ),
    ] {
        // Exit codes are one value, compared as one "line" each.
        let (mut removed, mut added) = if stream == Stream::Exit {
            if old == new {
                (Vec::new(), Vec::new())
            } else {
                (vec![(0, old)], vec![(0, new)])
            }
        } else {
            compare::changed_lines(old, new)
        };
        let mut accepted_old = Vec::new();
        let mut accepted_new = Vec::new();
        for entry in entries.iter().filter(|e| e.stream == stream) {
            let [entry_oracle, entry_candidate] = match (level, stream) {
                (Level::Exact, _) | (_, Stream::Exit) => {
                    [entry.oracle, entry.candidate].map(|line| line.map(str::to_owned))
                }
                (Level::Semantic, _) => {
                    let sides =
                        [(entry.oracle, raw[0]), (entry.candidate, raw[1])].map(|(line, raw)| {
                            line.and_then(|line| semantic_line(key.command, stream, raw, line))
                        });
                    // The projection took this entry's change out of the comparison.
                    if sides[0] == sides[1] {
                        continue;
                    }
                    sides
                }
            };
            let mut found = true;
            for (line, pool, taken, side) in [
                (entry_oracle, &mut removed, &mut accepted_old, "oracle"),
                (entry_candidate, &mut added, &mut accepted_new, "candidate"),
            ] {
                let Some(line) = line.as_deref() else {
                    continue;
                };
                if let Some(at) = pool.iter().position(|(_, l)| *l == line) {
                    taken.push(pool.remove(at).0);
                } else {
                    found = false;
                    judged.stale.push(format!(
                        "stale intended divergence ({} {:?}, {}): its {side} line isn't a \
                         changed line of this run: {line:?}",
                        entry.command, entry.stream, entry.resource
                    ));
                }
            }
            if found {
                judged.accepted.push(**entry);
            }
        }
        judged.unaccepted |= !removed.is_empty() || !added.is_empty();
        // The backstop, on exact bytes rather than the alignment: with the accepted lines
        // taken out of each side, what's left must be byte-identical.
        judged.unaccepted |=
            stream != Stream::Exit && without(old, &accepted_old) != without(new, &accepted_new);
    }
    judged
}

/// What an entry's `line` is at the semantic level, on the side whose normalized
/// output for `stream` is `raw`: `None` when the projection leaves it out.
///
/// The projection reads a line by where it stands, so the entry's line is looked up
/// in `raw`: it becomes what the projection makes of it there — nothing, when every
/// place it stands is left out. A line that isn't in `raw` at all is matched as
/// written (as its `plan_hash: <HASH>` form, for a hash line), so an entry that no
/// longer describes its run is still stale.
fn semantic_line(command: &str, stream: Stream, raw: &str, line: &str) -> Option<String> {
    let projected = match stream {
        Stream::Stdout => compare::project_lines(command, raw),
        Stream::Stderr => compare::project_stderr_lines(raw),
        Stream::Exit => return Some(line.to_owned()),
    };
    let mut places = compare::split_lines(raw)
        .into_iter()
        .zip(projected)
        .filter(|(raw_line, _)| *raw_line == line)
        .map(|(_, projected)| projected)
        .peekable();
    if places.peek().is_none() {
        let as_written = match stream {
            Stream::Stdout if command != "detect" => compare::hash_line_projection(line),
            _ => None,
        };
        return Some(as_written.unwrap_or(line).to_owned());
    }
    places.flatten().next().map(std::borrow::Cow::into_owned)
}

/// `text` with the [`compare::split_lines`] elements at `indices` removed, rejoined.
fn without(text: &str, indices: &[usize]) -> String {
    compare::split_lines(text)
        .into_iter()
        .enumerate()
        .filter(|(index, _)| !indices.contains(index))
        .map(|(_, line)| line)
        .collect::<Vec<_>>()
        .join("\n")
}

/// Render one accepted entry for the run output.
pub fn render(tag: &str, entry: &Intended) -> String {
    use std::fmt::Write as _;
    let mut out = format!(
        "  INTENDED [{tag}] {} {:?} {}: {}\n",
        entry.command, entry.stream, entry.resource, entry.why
    );
    if let Some(line) = entry.oracle {
        let _ = writeln!(out, "    - {line}");
    }
    if let Some(line) = entry.candidate {
        let _ = writeln!(out, "    + {line}");
    }
    out
}

/// Every intended divergence. Review each entry: it must name exactly what the candidate
/// changes and why, and nothing else. A line that quotes a tool the binary ran differs by
/// distro (`BusyBox` and GNU `cat` word their errors differently), so it is an entry per
/// distro.
///
/// Empty: against a build of the engine the candidate grows from, what the candidate
/// changes on purpose is text a semantic run leaves out: a plan's `references:` block,
/// the commands its steps run, and the `plan_hash` of a plan whose steps' scripts
/// changed. An exact run against that engine diverges there by design, and those lines
/// can't be entries: a plan's hash binds its references, which name the harness's
/// per-run content port. Compare the two at the semantic level; the exact level passes
/// again once the oracle is a build that carries the change.
pub const fn table() -> Vec<Intended> {
    Vec::new()
}

#[cfg(test)]
mod tests {
    use super::{Intended, Judged, RunKey, Stream, Variant};
    use crate::differential::compare::{Level, Observed};
    use crate::differential::scenarios::Suite;
    use crate::differential::vm::Distro;

    fn observed(code: i32, stdout: &str) -> Observed {
        Observed {
            code: Some(code),
            stdout: stdout.to_owned(),
            stderr: String::new(),
        }
    }

    /// [`super::judge`] at the exact level.
    fn judge(
        table: &[Intended],
        key: &RunKey<'_>,
        oracle: &Observed,
        candidate: &Observed,
    ) -> Judged {
        super::judge(table, key, Level::Exact, oracle, candidate)
    }

    const KEY: RunKey<'static> = RunKey {
        distro: Distro::Alpine,
        suite: Suite::Ssh,
        scenario: "s",
        variant: Variant::Cold,
        command: "detect",
    };

    const fn entry(
        stream: Stream,
        oracle: Option<&'static str>,
        candidate: Option<&'static str>,
    ) -> Intended {
        Intended {
            distro: Distro::Alpine,
            suite: Suite::Ssh,
            scenario: "s",
            variant: Variant::Cold,
            command: "detect",
            resource: "r",
            stream,
            oracle,
            candidate,
            why: "because",
        }
    }

    #[test]
    fn a_named_change_is_accepted_and_anything_else_still_diverges() {
        let oracle = observed(1, "a\n  ? r — old reason\nb\n");
        let candidate = observed(1, "a\n  ? r — new reason\nb\n");
        let table = [entry(
            Stream::Stdout,
            Some("  ? r — old reason"),
            Some("  ? r — new reason"),
        )];
        let judged = judge(&table, &KEY, &oracle, &candidate);
        assert_eq!(judged.accepted.len(), 1);
        assert!(judged.stale.is_empty());
        assert!(!judged.unaccepted);

        // A second, unnamed change is still a divergence.
        let candidate = observed(1, "a\n  ? r — new reason\nB\n");
        let judged = judge(&table, &KEY, &oracle, &candidate);
        assert!(judged.unaccepted);
        assert_eq!(judged.accepted.len(), 1);
    }

    #[test]
    fn a_line_added_or_dropped_outright_and_an_exit_code() {
        let oracle = observed(1, "BANNER\n  ok x\n");
        let candidate = observed(0, "  ok x\n");
        let dropped = entry(Stream::Stdout, Some("BANNER"), None);
        assert!(judge(&[dropped], &KEY, &oracle, &candidate).unaccepted);
        let table = [dropped, entry(Stream::Exit, Some("1"), Some("0"))];
        let judged = judge(&table, &KEY, &oracle, &candidate);
        assert!(!judged.unaccepted);
        assert!(judged.stale.is_empty());
        assert_eq!(judged.accepted.len(), 2);
    }

    #[test]
    fn an_entry_whose_lines_do_not_both_appear_is_stale() {
        let same = observed(0, "a\n");
        let table = [entry(Stream::Stdout, Some("a"), Some("b"))];
        let judged = judge(&table, &KEY, &same, &same);
        assert_eq!(judged.stale.len(), 2);
        assert!(judged.accepted.is_empty());
        assert!(!judged.unaccepted);

        // Half-present is stale too, and the other half stays a divergence.
        let candidate = observed(0, "c\n");
        let judged = judge(&table, &KEY, &same, &candidate);
        assert_eq!(judged.stale.len(), 1);
        assert!(judged.unaccepted);

        // An exit entry where the codes didn't change is stale.
        let judged = judge(
            &[entry(Stream::Exit, Some("1"), Some("0"))],
            &KEY,
            &same,
            &same,
        );
        assert_eq!(judged.stale.len(), 2);
    }

    /// A trailing-newline or line-ending change is a byte difference: never waved through
    /// with the rest of an accepted run.
    #[test]
    fn line_endings_are_never_laundered() {
        let table = [entry(Stream::Stdout, Some("old"), Some("new"))];
        for (oracle, candidate) in [
            ("a\nold\nb\n", "a\nnew\nb"),
            ("a\nold\nb\n", "a\r\nnew\nb\n"),
            ("a\nb\n", "a\nb"),
            ("a\r\n", "a\n"),
        ] {
            let judged = judge(&table, &KEY, &observed(0, oracle), &observed(0, candidate));
            assert!(judged.unaccepted, "{oracle:?} vs {candidate:?}");
        }
        // The exact change alone is accepted.
        let judged = judge(
            &table,
            &KEY,
            &observed(0, "a\nold\nb\n"),
            &observed(0, "a\nnew\nb\n"),
        );
        assert!(!judged.unaccepted && judged.stale.is_empty());
    }

    #[test]
    fn an_entry_applies_only_to_its_own_run() {
        let oracle = observed(0, "a\n");
        let candidate = observed(0, "b\n");
        let table = [entry(Stream::Stdout, Some("a"), Some("b"))];
        for key in [
            RunKey {
                variant: Variant::Warm,
                ..KEY
            },
            RunKey {
                command: "plan",
                ..KEY
            },
            RunKey {
                distro: Distro::Debian,
                ..KEY
            },
        ] {
            let judged = judge(&table, &key, &oracle, &candidate);
            assert!(judged.unaccepted);
            assert!(judged.accepted.is_empty() && judged.stale.is_empty());
        }
    }

    const PLAN_KEY: RunKey<'static> = RunKey {
        command: "plan",
        ..KEY
    };

    const fn plan_entry(oracle: Option<&'static str>, candidate: Option<&'static str>) -> Intended {
        Intended {
            command: "plan",
            ..entry(Stream::Stdout, oracle, candidate)
        }
    }

    const OLD_HASH: &str =
        "plan_hash: f2f8aed3eec7941617af09b646c0e9b9f0c42f8e51f2ac1a4c050129a0da5f25";
    const STALE_HASH: &str =
        "plan_hash: 8340de655b23e9ffa55bfe423ef755e2c778356462679f7f8d005e809145d9ee";

    /// An oracle plan with a create the candidate holds instead, as two generations of
    /// zap render it.
    fn semantic_pair() -> (Observed, Observed) {
        let oracle = format!(
            "plan — target h (2 change(s): +2 ~0)\n  [+] database  (database)\n      \
             > createuser zapdiff\n      > createdb zapdiff\n  [+] pipeline  (pipeline)\n      \
             > true\n{OLD_HASH}\n"
        );
        let candidate = format!(
            "  UNDETERMINED — 1 resource(s) could not be probed:\n      database — held\n\
             plan — target h (1 change(s): +1 ~0)\n  host: 10.0.0.1\n  user: ops\n  \
             target: {{\"local\":false}}\n  [+] pipeline  (pipeline)\n      > true\n\
             plan_hash: {}\n",
            "0".repeat(64)
        );
        (observed(0, &oracle), observed(0, &candidate))
    }

    /// The entries that record [`semantic_pair`]'s change line by line, as an exact run
    /// needs them — the candidate's hash one stale.
    fn semantic_table() -> Vec<Intended> {
        vec![
            plan_entry(
                Some("plan — target h (2 change(s): +2 ~0)"),
                Some("plan — target h (1 change(s): +1 ~0)"),
            ),
            plan_entry(
                None,
                Some("  UNDETERMINED — 1 resource(s) could not be probed:"),
            ),
            plan_entry(None, Some("      database — held")),
            plan_entry(Some("  [+] database  (database)"), None),
            plan_entry(Some("      > createuser zapdiff"), None),
            plan_entry(Some("      > createdb zapdiff"), None),
            plan_entry(Some(OLD_HASH), Some(STALE_HASH)),
        ]
    }

    #[test]
    fn a_semantic_run_skips_what_the_projection_took_out() {
        let (oracle, candidate) = semantic_pair();
        let table = semantic_table();
        let judged = super::judge(&table, &PLAN_KEY, Level::Semantic, &oracle, &candidate);
        assert_eq!(judged.stale, Vec::<String>::new());
        assert!(!judged.unaccepted);
        // the header, the two banner lines, and the dropped change line; the two step
        // entries and the hash entry say nothing at this level
        assert_eq!(judged.accepted, table[..4]);

        // at the exact level the same table is stale on its candidate hash, and the
        // rendering differences are divergences
        let judged = super::judge(&table, &PLAN_KEY, Level::Exact, &oracle, &candidate);
        assert_eq!(judged.stale.len(), 1, "{:?}", judged.stale);
        assert!(judged.stale[0].contains(STALE_HASH));
        assert!(judged.unaccepted);
    }

    #[test]
    fn a_semantic_run_still_judges_what_the_projection_keeps() {
        let (oracle, candidate) = semantic_pair();
        // without the entry for the dropped change line, that line is a divergence
        let mut table = semantic_table();
        table.remove(3);
        let judged = super::judge(&table, &PLAN_KEY, Level::Semantic, &oracle, &candidate);
        assert!(judged.unaccepted);
        assert!(judged.stale.is_empty());

        // an entry naming a kept line that isn't in the run is stale, as at any level
        let table = [plan_entry(Some("  [+] nope  (file)"), None)];
        let judged = super::judge(&table, &PLAN_KEY, Level::Semantic, &oracle, &candidate);
        assert_eq!(judged.stale.len(), 1);

        // a step line the run doesn't have at all is matched as written: stale
        let table = [plan_entry(Some("      > never printed"), None)];
        let judged = super::judge(&table, &PLAN_KEY, Level::Semantic, &oracle, &candidate);
        assert_eq!(judged.stale.len(), 1);

        // a missing hash is not what a hash entry records
        let hashless = observed(0, &candidate.stdout.replace("plan_hash: ", "plan_hush: "));
        let table = semantic_table();
        let judged = super::judge(&table, &PLAN_KEY, Level::Semantic, &oracle, &hashless);
        assert!(judged.unaccepted);
    }

    /// An exit-code entry is the same at both levels.
    #[test]
    fn a_semantic_run_judges_exit_codes_as_they_are() {
        let table = [entry(Stream::Exit, Some("1"), Some("0"))];
        let judged = super::judge(
            &table,
            &KEY,
            Level::Semantic,
            &observed(1, "a\n"),
            &observed(0, "a\n"),
        );
        assert_eq!(judged.accepted.len(), 1);
        assert!(!judged.unaccepted);
        let same = observed(0, "a\n");
        let judged = super::judge(&table, &KEY, Level::Semantic, &same, &same);
        assert_eq!(judged.stale.len(), 2);
    }

    /// A hash entry doesn't abort a semantic run: an entry whose two lines are both
    /// `plan_hash:` lines says nothing at that level.
    #[test]
    fn a_hash_entry_says_nothing_at_the_semantic_level() {
        let entry = plan_entry(Some(OLD_HASH), Some(STALE_HASH));
        let run = observed(
            0,
            &format!("plan — target h\nplan_hash: {}\n", "1".repeat(64)),
        );
        let judged = super::judge(&[entry], &PLAN_KEY, Level::Semantic, &run, &run);
        assert!(judged.stale.is_empty(), "{:?}", judged.stale);
        assert!(judged.accepted.is_empty() && !judged.unaccepted);
        // and at the exact level it is stale, as any entry its run doesn't show
        let judged = super::judge(&[entry], &PLAN_KEY, Level::Exact, &run, &run);
        assert_eq!(judged.stale.len(), 2);
    }

    #[test]
    fn every_entry_is_complete_and_names_a_scenario_it_can_run_in() {
        for entry in super::table() {
            let scenario = crate::differential::scenarios::scenarios(entry.distro)
                .into_iter()
                .filter(|s| s.suite == entry.suite)
                .find(|s| s.name == entry.scenario);
            let Some(scenario) = scenario else {
                panic!("no such scenario: {entry:?}");
            };
            assert!(
                entry.variant == Variant::Cold || scenario.remote,
                "a warm entry for a scenario that runs cold only: {entry:?}"
            );
            assert!(
                entry.oracle.is_some() || entry.candidate.is_some(),
                "{entry:?}"
            );
            assert!(!entry.why.is_empty(), "{entry:?}");
            assert!(
                matches!(entry.command, "detect" | "plan-diff" | "plan"),
                "{entry:?}"
            );
        }
    }
}
