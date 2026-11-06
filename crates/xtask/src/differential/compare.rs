//! Oracle-vs-candidate comparison: normalize the only legitimately
//! nondeterministic text, then diff what's left line by line.
//!
//! Two [`Level`]s. `Exact` diffs the normalized text as it is. `Semantic` first
//! [`project`]s both sides down to what each command decided, for an oracle that
//! renders the same decisions differently by design.

use std::borrow::Cow;
use std::fmt::Write as _;

use super::process::Captured;

/// One command's captured result, normalized and ready to compare.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Observed {
    pub code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
}

/// Normalize a capture for comparison.
///
/// Exactly three substitutions, all for values that differ between the oracle and
/// candidate runs *by construction* rather than by behavior:
///
/// - each run's private `ZAP_HOME` (a fresh temp dir per binary per command, so
///   neither sees the other's cache) → `<ZAP_HOME>`;
/// - the binary's own path (`argv[0]`, printed in usage text) → `<ZAP>`;
/// - the binary's own staged fixture tree (`stage`, where its config and `zap.lock`
///   live; empty when both binaries share one) → `<STAGE>`.
///
/// Nothing else is rewritten — verdict text, resource order, `plan_hash`, exit
/// codes and stderr are compared verbatim, so any drift in them is a divergence.
pub fn normalize(captured: &Captured, zap_home: &str, binary: &str, stage: &str) -> Observed {
    let rewrite = |text: &str| {
        let mut text = text.to_owned();
        for (from, to) in [
            (zap_home, "<ZAP_HOME>"),
            (binary, "<ZAP>"),
            (stage, "<STAGE>"),
        ] {
            if !from.is_empty() {
                text = text.replace(from, to);
            }
        }
        text
    };
    Observed {
        code: if captured.timed_out {
            None
        } else {
            captured.code
        },
        stdout: rewrite(&captured.stdout),
        stderr: rewrite(&captured.stderr),
    }
}

/// Compare two observations; `None` when identical, else a readable report of
/// every differing stream.
pub fn compare(oracle: &Observed, candidate: &Observed) -> Option<String> {
    let mut report = String::new();
    if oracle.code != candidate.code {
        let _ = writeln!(
            report,
            "exit code: oracle {} vs candidate {}",
            format_code(oracle.code),
            format_code(candidate.code)
        );
    }
    for (stream, a, b) in [
        ("stdout", &oracle.stdout, &candidate.stdout),
        ("stderr", &oracle.stderr, &candidate.stderr),
    ] {
        if a != b {
            let _ = writeln!(report, "{stream}:");
            report.push_str(&unified_diff(a, b, 2));
        }
    }
    (!report.is_empty()).then_some(report)
}

/// How closely two observations are compared.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Level {
    /// Byte for byte, after [`normalize`].
    Exact,
    /// After [`project`]: what each command decided, without how it is rendered.
    Semantic,
}

impl Level {
    pub const fn name(self) -> &'static str {
        match self {
            Self::Exact => "exact",
            Self::Semantic => "semantic",
        }
    }

    pub fn parse(name: &str) -> Option<Self> {
        [Self::Exact, Self::Semantic]
            .into_iter()
            .find(|level| level.name() == name)
    }
}

/// `observed` as `level` compares it: itself, or its semantic projection for
/// `command` (`detect`, `plan-diff`, or `plan`).
pub fn at_level(level: Level, command: &str, observed: &Observed) -> Observed {
    match level {
        Level::Exact => observed.clone(),
        Level::Semantic => Observed {
            code: observed.code,
            stdout: project(command, &observed.stdout),
            stderr: project_stderr(&observed.stderr),
        },
    }
}

/// One line's fate under a projection, per [`split_lines`] element: `None` when the
/// line is left out, else the line as compared.
pub type Projected<'a> = Vec<Option<Cow<'a, str>>>;

/// The semantic projection of `command`'s stdout: [`project_lines`], rejoined.
pub fn project(command: &str, text: &str) -> String {
    rejoin(&project_lines(command, text))
}

/// The semantic projection of a stderr: [`project_stderr_lines`], rejoined.
pub fn project_stderr(text: &str) -> String {
    rejoin(&project_stderr_lines(text))
}

fn rejoin(lines: &Projected<'_>) -> String {
    lines
        .iter()
        .flatten()
        .map(Cow::as_ref)
        .collect::<Vec<_>>()
        .join("\n")
}

/// The semantic projection of `command`'s stdout, line by line.
///
/// Lines are classified by how they start, never by how they end, and a line that is
/// kept is kept byte for byte — so a `\r` or a missing final newline on a kept line
/// still differs. The last [`split_lines`] element (the text after the final newline:
/// empty for a terminated output) is always kept as it is.
///
/// **A plan** (`plan`, `plan-diff`) is read top to bottom in four places:
///
/// - *Before the header* (`plan — target …` / `plan diff — target …` at column 0):
///   everything is kept — the verdict banners and their lines.
/// - *Directly under the header*: `  host: …`, `  user: …`, `  home: …`, `  target: …`
///   are left out — each at most once, in that order, and only while they are the next lines —
///   and so is a `  references:` line that follows them, with the lines under it that
///   stand exactly four spaces in (one a reference: its name, then its value or its
///   state). The same text anywhere else is not the block. What a plan's references
///   resolve to is what the plan is for, as its machine is: a zap that prints it and
///   one that doesn't have decided the same thing.
/// - *Under a change* (after a `  [+] …` or `  [~] …` line, which is kept): a line is
///   kept when it is another change line, the change's trigger line (`      (triggered
///   …` or `      (pending …`, only as the line directly under the change line), or —
///   for `plan-diff` — an attribute line (`      ~ …`, `      + …`, `      - …`,
///   exactly six spaces). A line that ends the changes is kept and leaves this place:
///   `plan_hash: …` or `warning: …` at column 0, or a line indented exactly two
///   spaces that opens with `(` (a footer) or with capitals and ` — ` (a banner).
///   Every other line there is left out: what the change declares, its steps, and
///   the continuation lines of either, at whatever column they stand.
/// - *After the changes*, and in a plan with none: everything is kept.
///
/// Wherever it is kept, a line that is exactly `plan_hash: ` and 64 lowercase hex
/// digits becomes `plan_hash: <HASH>`: that a plan has a hash is compared, its value
/// is not. Any other spelling of that line is kept as it is.
///
/// **A `detect`** is kept up to and including its `N resource(s):` line. After it, a
/// line indented exactly two spaces — a resource row, a banner — is kept as it is.
/// Any other line is a continuation of the message above it and is compared without
/// its leading spaces (written back under six), since where a continuation line
/// stands is rendering.
pub fn project_lines<'a>(command: &str, text: &'a str) -> Projected<'a> {
    let lines = split_lines(text);
    let mut projected = match command {
        "detect" => project_detect(&lines),
        _ => project_plan(&lines, command == "plan-diff"),
    };
    if let (Some(last), Some(line)) = (projected.last_mut(), lines.last()) {
        *last = Some(Cow::Borrowed(line));
    }
    projected
}

/// The semantic projection of a stderr, line by line: kept as it is up to and
/// including the first line that starts `error: `; every line after that is compared
/// without its leading spaces, since an error's later lines are indented under it by
/// some renders and not by others.
pub fn project_stderr_lines(text: &str) -> Projected<'_> {
    let mut in_error = false;
    split_lines(text)
        .into_iter()
        .map(|line| {
            let kept = if in_error {
                line.trim_start_matches(' ')
            } else {
                line
            };
            in_error |= line.starts_with("error: ");
            Some(Cow::Borrowed(kept))
        })
        .collect()
}

/// The lines directly under a plan's header that name its machine, in the order zap
/// prints them: `  host:` and `  user:` over SSH, `  user:` and `  home:` locally, then
/// `  target:`.
const MACHINE_BLOCK: [&str; 4] = ["  host: ", "  user: ", "  home: ", "  target: "];

/// The line that opens a plan's references under its machine block.
const REFERENCES_LINE: &str = "  references:";

/// Whether `line` is one reference of a plan's `references:` block: indented exactly
/// four spaces.
fn is_reference_line(line: &str) -> bool {
    line.strip_prefix("    ")
        .is_some_and(|rest| !rest.is_empty() && !rest.starts_with(' '))
}

/// Where [`project_plan`] is in a plan.
#[derive(Clone, Copy, PartialEq, Eq)]
enum PlanPlace {
    /// Before the header.
    Preamble,
    /// Directly under the header; the index of the next [`MACHINE_BLOCK`] line allowed.
    Machine(usize),
    /// Under the [`REFERENCES_LINE`] that closed the machine block.
    References,
    /// After the machine block, outside any change.
    Body,
    /// Under a change line; `first` while the next line is the one directly under it.
    Change { first: bool },
}

fn project_plan<'a>(lines: &[&'a str], diff: bool) -> Projected<'a> {
    let header = if diff {
        "plan diff — target "
    } else {
        "plan — target "
    };
    let mut place = PlanPlace::Preamble;
    lines
        .iter()
        .map(|&line| {
            if let PlanPlace::Machine(next) = place {
                let at = MACHINE_BLOCK
                    .iter()
                    .position(|key| line.starts_with(key))
                    .filter(|&at| at >= next);
                if let Some(at) = at {
                    place = PlanPlace::Machine(at + 1);
                    return None;
                }
                if line == REFERENCES_LINE {
                    place = PlanPlace::References;
                    return None;
                }
                place = PlanPlace::Body;
            }
            if place == PlanPlace::References {
                if is_reference_line(line) {
                    return None;
                }
                place = PlanPlace::Body;
            }
            let first = matches!(place, PlanPlace::Change { first: true });
            let under_change = matches!(place, PlanPlace::Change { .. });
            if place == PlanPlace::Preamble {
                if line.starts_with(header) {
                    place = PlanPlace::Machine(0);
                }
            } else if is_change_line(line) {
                place = PlanPlace::Change { first: true };
            } else if under_change {
                if ends_changes(line) {
                    place = PlanPlace::Body;
                } else {
                    place = PlanPlace::Change { first: false };
                    let kept =
                        (first && is_trigger_line(line)) || (diff && is_attribute_line(line));
                    return kept.then_some(Cow::Borrowed(line));
                }
            }
            Some(hash_line_projection(line).map_or(Cow::Borrowed(line), Cow::Borrowed))
        })
        .collect()
}

fn project_detect<'a>(lines: &[&'a str]) -> Projected<'a> {
    let mut counted = false;
    lines
        .iter()
        .map(|&line| {
            if !counted {
                counted = is_count_line(line);
                return Some(Cow::Borrowed(line));
            }
            Some(if has_two_space_indent(line) {
                Cow::Borrowed(line)
            } else {
                Cow::Owned(format!("      {}", line.trim_start_matches(' ')))
            })
        })
        .collect()
}

/// `plan_hash: <HASH>` when `line` is exactly a `plan_hash:` line with a 64-digit
/// lowercase hex value — what such a line is compared as at the semantic level.
pub fn hash_line_projection(line: &str) -> Option<&'static str> {
    let hash = line.strip_prefix("plan_hash: ")?;
    (hash.len() == 64 && hash.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')))
        .then_some("plan_hash: <HASH>")
}

/// A changeset line: `  [+] <id>  (<kind>)` or `  [~] …`, by its first six bytes.
pub fn is_change_line(line: &str) -> bool {
    line.starts_with("  [+] ") || line.starts_with("  [~] ")
}

/// A change's trigger line: `      (triggered …` or `      (pending …`.
fn is_trigger_line(line: &str) -> bool {
    line.starts_with("      (triggered ") || line.starts_with("      (pending ")
}

/// A `plan --diff` attribute line: exactly six spaces, then `~ `, `+ `, or `- `.
fn is_attribute_line(line: &str) -> bool {
    ["      ~ ", "      + ", "      - "]
        .iter()
        .any(|mark| line.starts_with(mark))
}

/// A line that can only follow a plan's changes: `plan_hash: …` or `warning: …` at
/// column 0, a footer (`  (…`), or a banner (`  NAME — …`).
fn ends_changes(line: &str) -> bool {
    line.starts_with("plan_hash: ")
        || line.starts_with("warning: ")
        || (has_two_space_indent(line)
            && (line[2..].starts_with('(') || banner_name(line).is_some()))
}

/// The name of the verdict banner `line` opens — `  NAME — …`, the name in ASCII
/// capitals — if it opens one.
pub fn banner_name(line: &str) -> Option<&str> {
    let rest = line.strip_prefix("  ")?;
    let (name, _) = rest.split_once(" — ")?;
    (!name.is_empty() && name.bytes().all(|b| b.is_ascii_uppercase())).then_some(name)
}

/// Whether `line` is indented exactly two spaces: zap's own column for a resource
/// row, a change line, a banner, a footer. A continuation line of a multi-line value
/// stands further in.
pub fn has_two_space_indent(line: &str) -> bool {
    line.strip_prefix("  ")
        .is_some_and(|rest| !rest.is_empty() && !rest.starts_with(' '))
}

/// `42 resource(s):` — the line `detect`'s resource rows follow.
pub fn is_count_line(line: &str) -> bool {
    line.strip_suffix(" resource(s):")
        .is_some_and(|count| !count.is_empty() && count.bytes().all(|b| b.is_ascii_digit()))
}

fn format_code(code: Option<i32>) -> String {
    code.map_or_else(
        || "none (killed or timed out)".to_owned(),
        |c| c.to_string(),
    )
}

/// A line edit in an LCS alignment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Edit<'a> {
    Same(&'a str),
    Removed(&'a str),
    Added(&'a str),
}

/// Line-level LCS alignment of `old` → `new` (outputs are at most a few hundred
/// lines, so the quadratic table is fine).
fn align<'a>(old: &[&'a str], new: &[&'a str]) -> Vec<Edit<'a>> {
    let mut lcs = vec![vec![0_usize; new.len() + 1]; old.len() + 1];
    for row in (0..old.len()).rev() {
        for col in (0..new.len()).rev() {
            lcs[row][col] = if old[row] == new[col] {
                lcs[row + 1][col + 1] + 1
            } else {
                lcs[row + 1][col].max(lcs[row][col + 1])
            };
        }
    }
    let (mut row, mut col) = (0, 0);
    let mut edits = Vec::with_capacity(old.len().max(new.len()));
    while row < old.len() && col < new.len() {
        if old[row] == new[col] {
            edits.push(Edit::Same(old[row]));
            row += 1;
            col += 1;
        } else if lcs[row + 1][col] >= lcs[row][col + 1] {
            edits.push(Edit::Removed(old[row]));
            row += 1;
        } else {
            edits.push(Edit::Added(new[col]));
            col += 1;
        }
    }
    edits.extend(old[row..].iter().map(|line| Edit::Removed(line)));
    edits.extend(new[col..].iter().map(|line| Edit::Added(line)));
    edits
}

/// `text` split on `\n` alone, keeping every byte: a `\r` stays on its line, and a
/// trailing newline leaves a final empty element — so joining the parts with `\n`
/// gives back `text` exactly, and any byte difference between two texts is a
/// difference between their lines. (`str::lines` drops both, and would let `a\r\n`
/// and `a\n`, or `a\n` and `a`, compare equal.)
pub fn split_lines(text: &str) -> Vec<&str> {
    text.split('\n').collect()
}

/// One line and its index in its text's [`split_lines`].
pub type IndexedLine<'a> = (usize, &'a str);

/// The lines only `old` has and the lines only `new` has, each with its index, under the
/// same LCS alignment (over [`split_lines`]) the rendered diff uses.
pub fn changed_lines<'a>(
    old: &'a str,
    new: &'a str,
) -> (Vec<IndexedLine<'a>>, Vec<IndexedLine<'a>>) {
    let old = split_lines(old);
    let new = split_lines(new);
    let (mut at_old, mut at_new) = (0, 0);
    let mut removed = Vec::new();
    let mut added = Vec::new();
    for edit in align(&old, &new) {
        match edit {
            Edit::Same(_) => {
                at_old += 1;
                at_new += 1;
            }
            Edit::Removed(line) => {
                removed.push((at_old, line));
                at_old += 1;
            }
            Edit::Added(line) => {
                added.push((at_new, line));
                at_new += 1;
            }
        }
    }
    (removed, added)
}

/// A unified-style diff (`-` oracle, `+` candidate) with `context` unchanged lines
/// around each change; runs of hidden unchanged lines collapse to `  …`.
pub fn unified_diff(oracle: &str, candidate: &str, context: usize) -> String {
    labeled_diff(("oracle", oracle), ("candidate", candidate), context)
}

/// [`unified_diff`] with caller-chosen `---` / `+++` labels.
pub fn labeled_diff(old: (&str, &str), new: (&str, &str), context: usize) -> String {
    let ((old_label, oracle), (new_label, candidate)) = (old, new);
    let old = split_lines(oracle);
    let new = split_lines(candidate);
    let edits = align(&old, &new);
    let changed: Vec<usize> = edits
        .iter()
        .enumerate()
        .filter(|(_, edit)| !matches!(edit, Edit::Same(_)))
        .map(|(index, _)| index)
        .collect();
    let visible = |index: usize| {
        changed
            .iter()
            .any(|&c| index + context >= c && index <= c + context)
    };
    let mut out = format!("    --- {old_label}\n    +++ {new_label}\n");
    let mut hidden = false;
    for (index, edit) in edits.iter().enumerate() {
        if !visible(index) {
            hidden = true;
            continue;
        }
        if hidden {
            out.push_str("      …\n");
            hidden = false;
        }
        let (mark, line) = match edit {
            Edit::Same(line) => (' ', line),
            Edit::Removed(line) => ('-', line),
            Edit::Added(line) => ('+', line),
        };
        // a `\r` is shown, not printed; a removed or added empty last line is a
        // trailing newline one side lacks
        let _ = writeln!(out, "    {mark} {}", line.replace('\r', "\\r"));
    }
    if hidden {
        out.push_str("      …\n");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::{
        Level, Observed, at_level, banner_name, changed_lines, compare, has_two_space_indent,
        hash_line_projection, normalize, project, project_stderr, split_lines, unified_diff,
    };
    use crate::differential::process::Captured;

    fn captured(code: i32, stdout: &str, stderr: &str) -> Captured {
        Captured {
            code: Some(code),
            stdout: stdout.to_owned(),
            stderr: stderr.to_owned(),
            timed_out: false,
        }
    }

    #[test]
    fn normalize_rewrites_only_the_run_specific_paths() {
        let raw = captured(
            1,
            "cache at /tmp/zd-1/home/cache\nconverged\n",
            "usage: /opt/oracle/zap detect\n",
        );
        let observed = normalize(&raw, "/tmp/zd-1/home", "/opt/oracle/zap", "");
        assert_eq!(observed.stdout, "cache at <ZAP_HOME>/cache\nconverged\n");
        assert_eq!(observed.stderr, "usage: <ZAP> detect\n");
        assert_eq!(observed.code, Some(1));
    }

    #[test]
    fn normalize_rewrites_the_binarys_own_staged_tree() {
        let raw = captured(
            2,
            "",
            "error: /tmp/zd-1/stage/oracle/crates/x/zap.ts: boom\n",
        );
        let observed = normalize(&raw, "/tmp/zd-1/home", "/o/zap", "/tmp/zd-1/stage/oracle");
        assert_eq!(observed.stderr, "error: <STAGE>/crates/x/zap.ts: boom\n");
    }

    #[test]
    fn a_timeout_has_no_exit_code() {
        let mut raw = captured(0, "", "");
        raw.timed_out = true;
        raw.code = None;
        assert_eq!(normalize(&raw, "h", "b", "s").code, None);
    }

    #[test]
    fn identical_observations_compare_equal() {
        let a = Observed {
            code: Some(0),
            stdout: "x\n".to_owned(),
            stderr: String::new(),
        };
        assert_eq!(compare(&a, &a.clone()), None);
    }

    #[test]
    fn a_verdict_change_is_reported_with_both_sides() {
        let oracle = Observed {
            code: Some(0),
            stdout: "a\n  ok     inline  file  — converged\nb\n".to_owned(),
            stderr: String::new(),
        };
        let candidate = Observed {
            code: Some(1),
            stdout: "a\n  drift  inline  file  — drifted (content differs)\nb\n".to_owned(),
            stderr: String::new(),
        };
        let report = compare(&oracle, &candidate).expect("diverged");
        assert!(report.contains("exit code: oracle 0 vs candidate 1"));
        assert!(report.contains("    -   ok     inline  file  — converged\n"));
        assert!(report.contains("    +   drift  inline  file  — drifted (content differs)\n"));
        assert!(!report.contains("stderr:"));
    }

    #[test]
    fn unified_diff_elides_distant_context() {
        let a = "1\n2\n3\n4\n5\n6\n7\n8\n9\n";
        let b = "1\n2\n3\n4\nFIVE\n6\n7\n8\n9\n";
        let diff = unified_diff(a, b, 1);
        assert_eq!(
            diff,
            "    --- oracle\n    +++ candidate\n      …\n      4\n    - 5\n    + FIVE\n      6\n      …\n"
        );
    }

    #[test]
    fn unified_diff_handles_insertions_at_the_end() {
        let diff = unified_diff("a\n", "a\nb\n", 2);
        assert!(diff.ends_with("      a\n    + b\n      \n"), "{diff:?}");
    }

    #[test]
    fn a_trailing_newline_difference_is_a_line_difference() {
        assert!(compare(&observed("a\nb\n"), &observed("a\nb")).is_some());
        let diff = unified_diff("a\n", "a", 2);
        assert!(diff.contains("    - \n"), "{diff:?}");
        assert_eq!(changed_lines("a\nb\n", "a\nb"), (vec![(2, "")], vec![]));
    }

    #[test]
    fn a_line_ending_difference_is_a_line_difference() {
        assert_eq!(
            changed_lines("a\r\nb\n", "a\nb\n"),
            (vec![(0, "a\r")], vec![(0, "a")])
        );
        let diff = unified_diff("a\r\n", "a\n", 2);
        assert!(diff.contains("    - a\\r\n"), "{diff:?}");
        assert!(diff.contains("    + a\n"), "{diff:?}");
    }

    #[test]
    fn split_lines_keeps_every_byte() {
        for text in ["", "a", "a\n", "a\r\n\nb", "\n\n"] {
            assert_eq!(split_lines(text).join("\n"), text);
        }
    }

    fn observed(stdout: &str) -> Observed {
        Observed {
            code: Some(0),
            stdout: stdout.to_owned(),
            stderr: String::new(),
        }
    }

    fn hash(digit: char) -> String {
        format!("plan_hash: {}", digit.to_string().repeat(64))
    }

    /// A plan as a zap that prints the plan's subject and what each change declares
    /// renders it.
    fn full_plan() -> String {
        format!(
            "  LOCK — the pin ledger does not answer for 1 resource(s):\n      \
             blob — no pin yet; run `zap update blob`\n\
             plan — target {{env:H}} (3 change(s): +1 ~2)\n  host: 10.0.0.1\n  user: ops\n  \
             target: {{\"local\":false,\"host\":{{\"$env\":\"H\"}}}}\n  \
             [~] sleeper  (service)\n      (triggered reload)\n      reload_on: conf\n      \
             > sudo rc-service sleeper reload\n  \
             [+] inline  (file)\n      path: /etc/x\n      mode: 644\n      \
             content: inline (3 bytes, sha512 0123456789abcdef…)\n      # write /etc/x\n  \
             [~] fw  (firewall)\n      > printf '%s\\n' '#!/usr/sbin/nft -f\n        \
             table inet filter' | sudo sh\n\
             warning: a wetrun of this plan will be refused — x\n{}\n",
            hash('a')
        )
    }

    /// The same plan as a zap that prints neither, with a multi-line step written raw.
    fn bare_plan() -> String {
        format!(
            "  LOCK — the pin ledger does not answer for 1 resource(s):\n      \
             blob — no pin yet; run `zap update blob`\n\
             plan — target 10.0.0.1 (3 change(s): +1 ~2)\n  \
             [~] sleeper  (service)\n      (triggered reload)\n      \
             > sudo rc-service sleeper reload\n  \
             [+] inline  (file)\n      # write /etc/x (other words)\n  \
             [~] fw  (firewall)\n      > printf '%s\\n' '#!/usr/sbin/nft -f\n\n\
             table inet filter\n\tchain input {{\n}}' | sudo tee /etc/nftables.nft\n\
             warning: a wetrun of this plan will be refused — x\n{}\n",
            hash('b')
        )
    }

    const PROJECTED_PLAN: &str = "  LOCK — the pin ledger does not answer for 1 resource(s):\n      \
         blob — no pin yet; run `zap update blob`\n\
         plan — target {env:H} (3 change(s): +1 ~2)\n  \
         [~] sleeper  (service)\n      (triggered reload)\n  \
         [+] inline  (file)\n  \
         [~] fw  (firewall)\n\
         warning: a wetrun of this plan will be refused — x\nplan_hash: <HASH>\n";

    #[test]
    fn a_plan_projects_to_its_banners_changes_triggers_warnings_and_that_it_has_a_hash() {
        assert_eq!(project("plan", &full_plan()), PROJECTED_PLAN);
        // the header is kept as printed, and the two name the target in it differently
        assert_eq!(
            project("plan", &bare_plan()),
            PROJECTED_PLAN.replace("{env:H}", "10.0.0.1")
        );
    }

    #[test]
    fn the_machine_block_is_only_the_lines_directly_under_the_header() {
        // a lookalike in a banner, before the header, is the banner's own line
        let banner = "  UNDETERMINED — 1 resource(s):\n  host: not a machine\n\
                      plan — target h (0 change(s): +0 ~0)\n  user: ops\n  target: {}\n  \
                      (no changes — converged)\n  host: after the footer\n  target: nor this\n";
        assert_eq!(
            project("plan", banner),
            "  UNDETERMINED — 1 resource(s):\n  host: not a machine\n\
             plan — target h (0 change(s): +0 ~0)\n  \
             (no changes — converged)\n  host: after the footer\n  target: nor this\n"
        );
        // each line once, in order: a second `user:` or a `host:` after `user:` stays
        let repeated = "plan — target h (0 change(s): +0 ~0)\n  user: a\n  user: b\n  host: c\n";
        assert_eq!(
            project("plan", repeated),
            "plan — target h (0 change(s): +0 ~0)\n  user: b\n  host: c\n"
        );
        // the other command's header opens no machine block
        let other = "plan diff — target h (0 change(s): +0 ~0)\n  host: x\n";
        assert_eq!(project("plan", other), other);
        assert_eq!(
            project("plan-diff", other),
            "plan diff — target h (0 change(s): +0 ~0)\n"
        );
        // indented otherwise, it isn't the block
        let deeper = "plan — target h (0 change(s): +0 ~0)\n   host: x\n";
        assert_eq!(project("plan", deeper), deeper);
    }

    /// What a plan's references resolve to is printed under its machine block, and is
    /// left out with it: the `references:` line and each reference's line under it. A
    /// zap that prints the block and one that doesn't then compare as the same plan.
    #[test]
    fn the_references_block_is_left_out_with_the_machine_block() {
        let with = "plan — target h (1 change(s): +1 ~0)\n  host: 10.0.0.1\n  user: ops\n  \
                    target: {}\n  references:\n    A_DIR = /srv/a\n    \
                    B_TOKEN is a secret: its value is not shown, and no part of it is in the \
                    plan or its hash\n    C is unset or empty: a wetrun stops before any \
                    change until it is set\n  [+] go  (script)\n      check: true\n\
                    plan_hash: 00\n";
        let without = "plan — target h (1 change(s): +1 ~0)\n  [+] go  (script)\n\
                       plan_hash: 00\n";
        assert_eq!(project("plan", with), without);
        // a local plan's machine lines are its user and home, and a plan may have no change
        let local = "plan — target local (0 change(s): +0 ~0)\n  user: ops\n  home: /home/ops\n  \
                     target: {\"local\":true}\n  references:\n    A = b\n  \
                     (no changes — converged)\n";
        assert_eq!(
            project("plan", local),
            "plan — target local (0 change(s): +0 ~0)\n  (no changes — converged)\n"
        );
        // a value can't end the block early or pass for a line that is kept: it stands
        // four spaces in, behind its name
        let hostile = "plan — target h (1 change(s): +1 ~0)\n  references:\n    \
                       A =   [+] forged  (script)\n    B = plan_hash: 00\n  [+] go  (script)\n";
        assert_eq!(
            project("plan", hostile),
            "plan — target h (1 change(s): +1 ~0)\n  [+] go  (script)\n"
        );
        // only directly under the header's block: after a change it is a line under the
        // change, and after the footer it is kept
        let later = "plan — target h (0 change(s): +0 ~0)\n  (no changes — converged)\n  \
                     references:\n    A = b\n";
        assert_eq!(project("plan", later), later);
        // a line further in, or not four in, ends the block and is kept
        let ended = "plan — target h (0 change(s): +0 ~0)\n  references:\n    A = b\n     \
                     five in\n    C = d\n";
        assert_eq!(
            project("plan", ended),
            "plan — target h (0 change(s): +0 ~0)\n     five in\n    C = d\n"
        );
        // and a `references:` line once more is not the block's
        let twice = "plan — target h (0 change(s): +0 ~0)\n  references:\n  references:\n";
        assert_eq!(
            project("plan", twice),
            "plan — target h (0 change(s): +0 ~0)\n  references:\n"
        );
    }

    #[test]
    fn a_change_line_is_kept_whatever_its_id() {
        let plan = "plan — target h (3 change(s): +3 ~0)\n  \
                    [+] plan_hash: 00  (script)\n      check: true\n  \
                    [+] it's (odd) — id  (file)\n      path: /x\n  \
                    [+]   (script)\n      > true\n";
        assert_eq!(
            project("plan", plan),
            "plan — target h (3 change(s): +3 ~0)\n  [+] plan_hash: 00  (script)\n  \
             [+] it's (odd) — id  (file)\n  [+]   (script)\n"
        );
    }

    #[test]
    fn a_trigger_line_is_kept_only_directly_under_its_change() {
        let plan = "plan — target h (2 change(s): +0 ~2)\n  \
                    [~] a  (service)\n      (pending restart from an earlier apply)\n      \
                    (triggered reload)\n  \
                    [~] b  (service)\n      restart_on: x\n      \
                    (triggered restart, also pending from an earlier apply)\n";
        assert_eq!(
            project("plan", plan),
            "plan — target h (2 change(s): +0 ~2)\n  [~] a  (service)\n      \
             (pending restart from an earlier apply)\n  [~] b  (service)\n"
        );
    }

    #[test]
    fn attribute_lines_are_kept_for_plan_diff_alone() {
        let diff = "plan diff — target h (2 change(s): +1 ~1)\n  target: {}\n  \
                    [~] f  (file)\n      path: /x\n      ~ mode: 600 → 644\n      \
                    + line a\n      - line (b)\n        ~ deeper: not an attribute\n  \
                    [+] g  (script)\n      check: true\n      > run\n";
        assert_eq!(
            project("plan-diff", diff),
            "plan diff — target h (2 change(s): +1 ~1)\n  \
             [~] f  (file)\n      ~ mode: 600 → 644\n      + line a\n      - line (b)\n  \
             [+] g  (script)\n"
        );
        let plan = diff.replace("plan diff — ", "plan — ");
        assert_eq!(
            project("plan", &plan),
            "plan — target h (2 change(s): +1 ~1)\n  [~] f  (file)\n  [+] g  (script)\n"
        );
    }

    /// A typed step's lines are steps like any other: a plan that words where a put's
    /// content comes from, and one that prints the command that produces it, project
    /// to one text, in either view.
    #[test]
    fn a_typed_steps_lines_are_left_out_however_they_are_worded() {
        let worded = "plan — target h (2 change(s): +2 ~0)\n  target: {}\n  \
                      [+] swap  (swap)\n      > sudo swapon -- '/swapfile'\n      \
                      = put /etc/fstab  (keeps its mode, 644 if new; as root)\n          \
                      from: /etc/fstab as it reads, then the line below; skipped when it \
                      lists /swapfile\n          line: /swapfile none swap sw 0 0\n  \
                      [+] tool  (installer)\n      check: /opt/tool\n      \
                      = run the script fetched from https://e.x/i.sh  (piped to sh)\n\
                      plan_hash: 0000000000000000000000000000000000000000000000000000000000000000\n";
        let scripted = "plan — target h (2 change(s): +2 ~0)\n  target: {}\n  \
                        [+] swap  (swap)\n      > sudo swapon -- '/swapfile'\n      \
                        = put /etc/fstab  (keeps its mode, 644 if new; as root)\n          \
                        unless: P='/swapfile' awk '$1 == ENVIRON[\"P\"]' /etc/fstab\n          \
                        from: { awk '{ print }' /etc/fstab; } && printf '%s\\n' '/swapfile'\n  \
                        [+] tool  (installer)\n      check: /opt/tool\n      \
                        > zap_s=$(curl -- 'https://e.x/i.sh') && printf '%s\\n' \"$zap_s\" | sh\n\
                        plan_hash: 1111111111111111111111111111111111111111111111111111111111111111\n";
        let projected = "plan — target h (2 change(s): +2 ~0)\n  [+] swap  (swap)\n  \
                         [+] tool  (installer)\nplan_hash: <HASH>\n";
        for text in [worded, scripted] {
            assert_eq!(project("plan", text), projected);
            assert_eq!(
                project("plan-diff", &text.replace("plan — ", "plan diff — ")),
                projected.replace("plan — ", "plan diff — ")
            );
        }
    }

    #[test]
    fn footers_and_banners_end_the_changes_and_are_kept_with_their_lines() {
        let plan = "plan — target h (1 change(s): +1 ~0)\n  [+] go  (script)\n      > run\n  \
                    UNRECORDED — no last run is kept: why\n                 more why\n  \
                    (a wetrun of this config is refused)\n  UNBINDABLE — reason\n";
        assert_eq!(
            project("plan", plan),
            "plan — target h (1 change(s): +1 ~0)\n  [+] go  (script)\n  \
             UNRECORDED — no last run is kept: why\n                 more why\n  \
             (a wetrun of this config is refused)\n  UNBINDABLE — reason\n"
        );
        // not a banner: lowercase, no dash, or further in
        let plan = "plan — target h (1 change(s): +1 ~0)\n  [+] go  (script)\n  note — x\n  \
                    NOTE x\n    NOTE — x\nplan_hash: 00\n";
        assert_eq!(
            project("plan", plan),
            "plan — target h (1 change(s): +1 ~0)\n  [+] go  (script)\nplan_hash: 00\n"
        );
    }

    #[test]
    fn a_hash_is_compared_as_present_not_by_value() {
        let plan = |foot: &str| {
            format!("plan — target h (0 change(s): +0 ~0)\n  (no changes — converged)\n{foot}")
        };
        let with = |digit| project("plan", &plan(&format!("{}\n", hash(digit))));
        assert_eq!(with('a'), with('b'));
        assert!(with('a').ends_with("plan_hash: <HASH>\n"));
        // a missing hash still differs
        assert_ne!(project("plan", &plan("")), with('a'));
        // only a well-formed hash line is rewritten: short, uppercase, trailing text,
        // indented, or a carriage return on it are all kept as they are
        for foot in [
            "plan_hash: abc\n".to_owned(),
            format!("plan_hash: {}\n", "A".repeat(64)),
            format!("{} trailing\n", hash('a')),
            format!("  {}\n", hash('a')),
            format!("{}\r\n", hash('a')),
        ] {
            assert_eq!(project("plan", &plan(&foot)), plan(&foot), "{foot:?}");
        }
        assert_eq!(hash_line_projection(&hash('0')), Some("plan_hash: <HASH>"));
        assert_eq!(hash_line_projection("plan_hash: "), None);
    }

    /// A kept line is kept byte for byte, so a line ending is still compared.
    #[test]
    fn the_projection_launders_no_line_ending() {
        let unix = full_plan();
        let dos = unix.replace('\n', "\r\n");
        assert_ne!(project("plan", &unix), project("plan", &dos));
        // a kept line keeps its `\r`
        let one = unix.replace("  [+] inline  (file)\n", "  [+] inline  (file)\r\n");
        assert!(project("plan", &one).contains("  [+] inline  (file)\r\n"));
        // a missing final newline differs, with the hash present or not
        let unterminated = unix.trim_end_matches('\n');
        assert_ne!(project("plan", unterminated), project("plan", &unix));
        let cut = "plan — target h (1 change(s): +1 ~0)\n  [+] go  (script)\n      > run";
        assert_ne!(project("plan", cut), project("plan", &format!("{cut}\n")));
        assert!(project("plan", cut).ends_with("  [+] go  (script)\n      > run"));
        for (text, command) in [("a\r\nb", "detect"), ("x\n\n", "plan"), ("", "plan-diff")] {
            assert_eq!(project(command, text), text);
        }
        assert_ne!(
            project("detect", "1 resource(s):\n  ok a  b  — c\r\n"),
            project("detect", "1 resource(s):\n  ok a  b  — c\n")
        );
    }

    #[test]
    fn output_with_no_plan_header_is_kept_whole() {
        let text = "  [+] go  (script)\n      > run\n  host: x\nerror text\n";
        assert_eq!(project("plan", text), text);
    }

    #[test]
    fn a_detect_keeps_its_rows_and_compares_continuation_lines_without_their_indent() {
        let rows = "  LOCK — the pin ledger:\n      blob — missing\n\
                    detected live state — target x (pkg: apk, service: openrc)\n3 resource(s):\n  \
                    ok     curl  package  — converged\n  \
                    ?      verify  verify  — undetermined: command said:\n";
        let indented = format!(
            "{rows}                               first — line\n                               \
             second\n  drift  inline  file  — drifted (content differs)\n"
        );
        let raw = format!(
            "{rows}first — line\n   second\n  drift  inline  file  — drifted (content differs)\n"
        );
        let projected = format!(
            "{rows}      first — line\n      second\n  drift  inline  file  — drifted (content differs)\n"
        );
        assert_eq!(project("detect", &indented), projected);
        assert_eq!(project("detect", &raw), projected);
        // a row's own text is compared as it is
        let other = indented.replace("content differs", "mode differs");
        assert_ne!(project("detect", &other), projected);
        // before the count line nothing is touched
        assert!(projected.starts_with("  LOCK — the pin ledger:\n      blob — missing\n"));
    }

    #[test]
    fn a_stderr_compares_an_errors_later_lines_without_their_indent() {
        let indented = "Warning:   kept\nerror: boom\n       second line\n       third\nhint: x\n";
        let raw = "Warning:   kept\nerror: boom\nsecond line\nthird\nhint: x\n";
        assert_eq!(project_stderr(indented), raw);
        assert_eq!(project_stderr(raw), raw);
        assert_eq!(project_stderr("  no error here\n"), "  no error here\n");
        assert_ne!(project_stderr("error: a\r\n"), project_stderr("error: a\n"));
    }

    #[test]
    fn the_exact_level_compares_what_was_observed() {
        let observed = Observed {
            code: Some(2),
            stdout: full_plan(),
            stderr: "error: a\n  b\n".to_owned(),
        };
        assert_eq!(at_level(Level::Exact, "plan", &observed), observed);
        let semantic = at_level(Level::Semantic, "plan", &observed);
        assert_eq!(semantic.code, Some(2));
        assert_eq!(semantic.stdout, PROJECTED_PLAN);
        assert_eq!(semantic.stderr, "error: a\nb\n");
        assert_eq!(Level::parse("semantic"), Some(Level::Semantic));
        assert_eq!(Level::parse("exact"), Some(Level::Exact));
        assert_eq!(Level::parse("Exact"), None);
    }

    #[test]
    fn banners_and_two_space_lines_are_read_by_their_columns() {
        assert_eq!(banner_name("  LOCK — x"), Some("LOCK"));
        assert_eq!(
            banner_name("  UNDETERMINED — 1 resource(s)"),
            Some("UNDETERMINED")
        );
        for line in [
            "LOCK — x",
            "   LOCK — x",
            "  Lock — x",
            "  LOCK - x",
            "   — x",
            "  FAIL  a  — b",
        ] {
            assert_eq!(banner_name(line), None, "{line:?}");
        }
        assert!(has_two_space_indent("  ok     a  b  — c"));
        for line in ["", "  ", " a", "   a", "a", "\t a"] {
            assert!(!has_two_space_indent(line), "{line:?}");
        }
    }
}
