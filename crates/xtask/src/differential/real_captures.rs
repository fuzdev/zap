//! The semantic projection and the output readers, against output captured from two
//! generations of zap: `old` prints a plan's changes bare and a multi-line step raw
//! (its later lines at whatever column the text has); `new` prints the plan's subject
//! under the header, what each change declares, and every block indented under its
//! lead. Each case under `testdata/real/` is one `local: true` config planned by both,
//! as `op` with its home at `/home/op`, against the same directory state:
//!
//! - `absent`: a directory, file, link, and a script with a multi-line `run` (a heredoc
//!   holding an nftables ruleset: tabs, a blank line, a column-0 `- item`), nothing there;
//! - `drifted`: the same config with the directory, file, and link each drifted;
//! - `held`: an unset reference in a path and a tracked `remote` with no pin —
//!   `LOCK`, `UNVERIFIABLE`, and `UNDETERMINED` banners, exit 1. The one case of two
//!   configs: each generation writes the reference in its own notation, which the other
//!   doesn't read;
//! - `converged`: one converged directory;
//! - `hostile`: `drifted` with a `run` whose later lines spell a footer, a change line,
//!   a `plan_hash:`, a banner, and a `warning:`;
//! - `lookalike`: a `run` whose later lines spell `--diff` attribute lines and a
//!   trigger line, at six spaces;
//! - `invalid`: the stderr of a config with two structural errors;
//! - `tracked.*.zap.lock`: the lock each generation's `zap lock` minted for one config
//!   with a tracked `remote` file and a tracked `build` source, from the same bytes.
//!
//! `testdata/real/recapture.sh` remakes every `new` capture but
//! `tracked.new.zap.lock`; rerun it when the renderer's output changes. The `old`
//! captures are frozen: their zap evaluated configs with Deno, and the script drives
//! only a zap that evaluates through `fgro`.

use super::audit::compare_locks;
use super::compare::{Level, Observed, compare, project, project_stderr};
use super::intended::{self, RunKey, Variant};
use super::process::Captured;
use super::reviewed::only_imperative_changes;
use super::runner::{Pair, Run, candidate_problems, detect_movers, well_formed};
use super::scenarios::Suite;
use super::vm::Distro;

macro_rules! capture {
    ($case:literal, $command:literal, $generation:literal) => {
        include_str!(concat!(
            "testdata/real/",
            $case,
            ".",
            $command,
            ".",
            $generation,
            ".out"
        ))
    };
}

/// `(case, command, old, new)` for every capture pair of a plan or a detect.
const PAIRS: [(&str, &str, &str, &str); 18] = {
    macro_rules! pair {
        ($case:literal, $command:literal) => {
            (
                $case,
                $command,
                capture!($case, $command, "old"),
                capture!($case, $command, "new"),
            )
        };
    }
    [
        pair!("absent", "plan"),
        pair!("absent", "plan-diff"),
        pair!("absent", "detect"),
        pair!("drifted", "plan"),
        pair!("drifted", "plan-diff"),
        pair!("drifted", "detect"),
        pair!("held", "plan"),
        pair!("held", "plan-diff"),
        pair!("held", "detect"),
        pair!("converged", "plan"),
        pair!("converged", "plan-diff"),
        pair!("converged", "detect"),
        pair!("hostile", "plan"),
        pair!("hostile", "plan-diff"),
        pair!("hostile", "detect"),
        pair!("lookalike", "plan"),
        pair!("lookalike", "plan-diff"),
        pair!("lookalike", "detect"),
    ]
};

/// The cases whose two generations decided the same thing and whose step text spells
/// nothing the projection reads.
const SAME: [&str; 4] = ["absent", "drifted", "held", "converged"];

fn pair_of(case: &str, command: &str) -> (&'static str, &'static str) {
    PAIRS
        .iter()
        .find(|(c, k, _, _)| *c == case && *k == command)
        .map(|(_, _, old, new)| (*old, *new))
        .expect("a capture pair")
}

#[test]
fn two_generations_of_the_same_decision_project_equal() {
    for (case, command, old, new) in PAIRS {
        if !SAME.contains(&case) {
            continue;
        }
        assert_eq!(
            project(command, old),
            project(command, new),
            "{case} {command}"
        );
        if command != "detect" {
            // and they are not equal as printed: the projection is what makes them so
            assert_ne!(old, new, "{case} {command}");
        }
    }
}

/// The projection of a real `plan --diff`, spelled out: the header, each change line,
/// its attribute lines, and that there is a hash.
#[test]
fn a_drifted_plan_diff_projects_to_its_changes_and_attributes() {
    let expected = "plan diff — target local (4 change(s): +1 ~3)\n  \
                    [~] home-dir  (directory)\n      ~ mode: 700 → 755\n  \
                    [~] home-file  (file)\n      ~ content: differs → inline (18 bytes)\n  \
                    [~] home-link  (link)\n      ~ target: /nonexistent → ~/zr/file.txt\n  \
                    [+] script  (script)\nplan_hash: <HASH>\n";
    let (old, new) = pair_of("drifted", "plan-diff");
    assert_eq!(project("plan-diff", old), expected);
    assert_eq!(project("plan-diff", new), expected);
    // the same plans as `plan` renders them carry no attribute line
    let plan = "plan — target local (4 change(s): +1 ~3)\n  [~] home-dir  (directory)\n  \
                [~] home-file  (file)\n  [~] home-link  (link)\n  [+] script  (script)\n\
                plan_hash: <HASH>\n";
    let (old, new) = pair_of("drifted", "plan");
    assert_eq!(project("plan", old), plan);
    assert_eq!(project("plan", new), plan);
}

/// Banners lead the header and are compared whole, with the lines under them.
#[test]
fn a_held_plan_keeps_every_banner_line() {
    let (old, new) = pair_of("held", "plan");
    let projected = project("plan", new);
    assert_eq!(projected, project("plan", old));
    let header = new.find("plan — target ").expect("a header");
    assert!(projected.starts_with(&new[..header]), "{projected}");
    for banner in ["  LOCK — ", "  UNVERIFIABLE — ", "  UNDETERMINED — "] {
        assert!(projected.contains(banner), "{banner}");
    }
    assert!(projected.ends_with(
        "  [+] home-dir  (directory)\n  [+] s  (script)\n  [+] tmpl  (file)\nplan_hash: <HASH>\n"
    ));
}

/// Every decision the projection keeps still differs when one side changes it. Each
/// edit is made to the newer generation's real output and compared with the older's.
#[test]
fn a_changed_decision_still_differs_from_the_other_generation() {
    let edits: [(&str, &str, &str, &str, &str); 12] = [
        // (case, command, what, from, to)
        (
            "drifted",
            "plan",
            "an action flipped",
            "  [~] home-link  (link)",
            "  [+] home-link  (link)",
        ),
        (
            "drifted",
            "plan",
            "a change re-kinded",
            "  [~] home-link  (link)",
            "  [~] home-link  (file)",
        ),
        (
            "drifted",
            "plan",
            "a change renamed",
            "  [~] home-link  (link)",
            "  [~] other-link  (link)",
        ),
        (
            "drifted",
            "plan",
            "a change removed",
            "  [~] home-link  (link)\n      path: ~/zr/link\n      to: ~/zr/file.txt\n",
            "",
        ),
        (
            "drifted",
            "plan",
            "a change added",
            "  [+] script  (script)\n",
            "  [+] extra  (file)\n      path: /x\n  [+] script  (script)\n",
        ),
        (
            "drifted",
            "plan",
            "the count in the header",
            "(4 change(s): +1 ~3)",
            "(4 change(s): +2 ~2)",
        ),
        (
            "drifted",
            "plan-diff",
            "an attribute's observed value",
            "      ~ mode: 700 → 755",
            "      ~ mode: 750 → 755",
        ),
        (
            "drifted",
            "plan-diff",
            "an attribute removed",
            "      ~ target: /nonexistent → ~/zr/file.txt\n",
            "",
        ),
        (
            "drifted",
            "plan",
            "no hash",
            "plan_hash: ",
            "  (a wetrun of this config is refused)\n  UNBINDABLE — ",
        ),
        (
            "drifted",
            "plan",
            "a warning",
            "plan_hash: ",
            "warning: a wetrun of this plan will be refused — x\nplan_hash: ",
        ),
        (
            "converged",
            "plan",
            "a banner where there was none",
            "plan — target ",
            "  UNDETERMINED — 1 resource(s) could not be probed:\n      x — held\nplan — target ",
        ),
        ("held", "plan", "a banner gone", "      ZR_UNSET\n", ""),
    ];
    for (case, command, what, from, to) in edits {
        let (old, new) = pair_of(case, command);
        assert!(new.contains(from), "{what}: the capture has no {from:?}");
        let edited = new.replacen(from, to, 1);
        assert_ne!(
            project(command, old),
            project(command, &edited),
            "{case} {command}: {what}"
        );
    }
    // a trigger line directly under a change line is a decision too
    let (old, new) = pair_of("drifted", "plan");
    let triggered = new.replacen(
        "  [~] home-dir  (directory)\n",
        "  [~] home-dir  (directory)\n      (triggered restart)\n",
        1,
    );
    assert_ne!(project("plan", old), project("plan", &triggered));
    let row = "  drift  home-link  link  — drifted (points to /nonexistent)";
    let (old, new) = pair_of("drifted", "detect");
    for to in [
        "  ok     home-link  link  — converged",
        "  drift  home-link  link  — drifted (points to /elsewhere)",
    ] {
        assert!(new.contains(row));
        assert_ne!(
            project("detect", old),
            project("detect", &new.replacen(row, to, 1))
        );
    }
}

/// What a semantic pass does not establish: the lines under a change that say what it
/// declares and how it gets there, the plan's subject, and the hash's value.
#[test]
fn what_the_projection_leaves_out_is_not_compared() {
    let (old, new) = pair_of("drifted", "plan");
    for (from, to) in [
        ("      mode: 755\n", "      mode: 700\n"),
        ("      to: ~/zr/file.txt\n", "      to: /etc/shadow\n"),
        (
            "        touch ~/zr/script.marker\n",
            "        rm -rf ~/zr\n",
        ),
        ("\"package_manager\":\"apt\"", "\"package_manager\":\"apk\""),
    ] {
        assert!(new.contains(from), "the capture has no {from:?}");
        assert_eq!(
            project("plan", old),
            project("plan", &new.replacen(from, to, 1))
        );
    }
}

/// An older zap prints a multi-line step raw, so a later line of one can spell a line
/// the projection reads. That shows as a difference — the comparison fails, it does
/// not pass — and every extra line is one of the step's own.
#[test]
fn a_raw_step_line_that_spells_a_kept_line_diverges() {
    for command in ["plan", "plan-diff"] {
        let (old, new) = pair_of("hostile", command);
        let (older, newer) = (project(command, old), project(command, new));
        assert_ne!(older, newer, "{command}");
        let extra: Vec<&str> = older
            .lines()
            .filter(|line| !newer.lines().any(|kept| kept == *line))
            .collect();
        assert_eq!(
            extra,
            [
                "  (paren line) \\",
                "  [+] fake  (file)",
                "plan_hash: nothere",
                "  NAME — banner like",
                "warning: fake",
                "  touch ~/zr/script.marker",
            ],
            "{command}"
        );
    }
    // at six spaces a later line can spell an attribute line, which `plan --diff` reads
    // and `plan` does not; a trigger line is read only directly under its change line
    let (old, new) = pair_of("lookalike", "plan");
    assert_eq!(project("plan", old), project("plan", new));
    let (old, new) = pair_of("lookalike", "plan-diff");
    let older = project("plan-diff", old);
    assert_ne!(older, project("plan-diff", new));
    assert!(older.contains("      - six spaces dash\n      ~ six spaces tilde\n"));
    assert!(!older.contains("(triggered reload)"));
}

/// An error's later lines are indented by one generation and not the other.
#[test]
fn an_errors_later_lines_compare_without_their_indent() {
    let old = include_str!("testdata/real/invalid.plan.old.err");
    let new = include_str!("testdata/real/invalid.plan.new.err");
    assert_ne!(old, new);
    assert_eq!(project_stderr(old), project_stderr(new));
    assert_eq!(
        project_stderr(new),
        "error: invalid config: config has 2 structural error(s):\n\
         - duplicate resource ids: dup\n- resource `dup` depends_on unknown resource `nope`\n"
    );
}

fn run_of(code: i32, stdout: &str) -> Run {
    let captured = Captured {
        code: Some(code),
        stdout: stdout.to_owned(),
        stderr: String::new(),
        timed_out: false,
    };
    let observed = Observed {
        code: Some(code),
        stdout: stdout.to_owned(),
        stderr: String::new(),
    };
    Run { captured, observed }
}

/// One case's three commands as the runner pairs them, `old` as the oracle.
fn pairs_of(case: &str, code: i32) -> Vec<Pair> {
    ["detect", "plan-diff", "plan"]
        .into_iter()
        .map(|command| {
            let (old, new) = pair_of(case, command);
            Pair {
                command,
                oracle: run_of(code, old),
                candidate: run_of(code, new),
            }
        })
        .collect()
}

#[test]
fn real_pairs_pass_the_semantic_judgment_and_fail_the_exact_one() {
    for (case, code) in [("absent", 0), ("drifted", 0), ("held", 1), ("converged", 0)] {
        for pair in pairs_of(case, code) {
            let key = RunKey {
                distro: Distro::Debian,
                suite: Suite::Local,
                scenario: "real",
                variant: Variant::Cold,
                command: pair.command,
            };
            let judge = |level| {
                intended::judge(
                    &[],
                    &key,
                    level,
                    &pair.oracle.observed,
                    &pair.candidate.observed,
                )
            };
            assert!(
                !judge(Level::Semantic).unaccepted,
                "{case} {}",
                pair.command
            );
            assert_eq!(
                judge(Level::Exact).unaccepted,
                pair.command != "detect",
                "{case} {}",
                pair.command
            );
        }
    }
}

/// The readers of one binary's own output, on what each generation really prints.
#[test]
fn the_output_readers_read_real_output() {
    let resources = [("absent", 4), ("drifted", 4), ("held", 4), ("converged", 1)];
    for (case, count) in resources {
        let code = i32::from(case == "held");
        let pairs = pairs_of(case, code);
        for pair in &pairs {
            for run in [&pair.oracle, &pair.candidate] {
                assert_eq!(
                    well_formed(pair.command, &run.captured, count),
                    Ok(()),
                    "{case} {}",
                    pair.command
                );
            }
        }
        // the newer generation names its machine and target under every plan header,
        // and its two plans of one state carry one hash
        assert_eq!(candidate_problems(&pairs, None), Vec::<String>::new());
        // the older one names neither: as a candidate it would be an ERROR
        let swapped: Vec<Pair> = pairs
            .into_iter()
            .map(|pair| Pair {
                command: pair.command,
                oracle: pair.candidate,
                candidate: pair.oracle,
            })
            .collect();
        let problems = candidate_problems(&swapped, None);
        let unnamed = problems
            .iter()
            .filter(|problem| problem.contains("doesn't name its machine"))
            .count();
        assert_eq!(unnamed, 2, "{case}: {problems:?}");
        // and it prints a step's TAB raw, where the newer one writes spaces
        let raw_tab = problems
            .iter()
            .filter(|problem| problem.contains("holds a raw U+0009"))
            .count();
        let tabbed = if matches!(case, "absent" | "drifted") {
            2
        } else {
            0
        };
        assert_eq!(raw_tab, tabbed, "{case}: {problems:?}");
        assert_eq!(problems.len(), unnamed + raw_tab, "{case}: {problems:?}");
    }
    let movers = |case| {
        let (old, new) = pair_of(case, "detect");
        assert_eq!(detect_movers(old), detect_movers(new), "{case}");
        detect_movers(new)
    };
    let mark = |id: &str, mark: &str| (id.to_owned(), mark.to_owned());
    assert_eq!(
        movers("drifted"),
        [
            mark("home-dir", "drift"),
            mark("home-file", "drift"),
            mark("home-link", "drift"),
            mark("script", "absent"),
        ]
    );
    assert_eq!(
        movers("held"),
        [
            mark("blob-tracked", "?"),
            mark("home-dir", "absent"),
            mark("s", "absent"),
            mark("tmpl", "absent"),
        ]
    );
    assert_eq!(movers("converged"), []);
}

/// The second-apply check, on the dry `apply` each generation really prints.
#[test]
fn the_idempotence_check_reads_real_dry_applies() {
    for generation in [
        capture!("converged", "apply", "old"),
        capture!("converged", "apply", "new"),
    ] {
        assert_eq!(only_imperative_changes(generation), Ok(()));
    }
    for generation in [
        capture!("absent", "apply", "old"),
        capture!("absent", "apply", "new"),
    ] {
        assert_eq!(
            only_imperative_changes(generation),
            Err(
                "still planned: [+] home-dir  (directory); [+] home-file  (file); \
                 [+] home-link  (link); [+] script  (script)"
                    .to_owned()
            )
        );
        assert!(generation.contains("\nplan_hash: "));
    }
}

/// `compare` on two projections renders the difference of what was kept.
#[test]
fn a_semantic_divergence_is_rendered_from_the_projections() {
    let (old, new) = pair_of("drifted", "plan");
    let edited = new.replacen("  [~] home-link  (link)", "  [+] home-link  (link)", 1);
    let side = |stdout: &str| Observed {
        code: Some(0),
        stdout: project("plan", stdout),
        stderr: String::new(),
    };
    let report = compare(&side(old), &side(&edited)).expect("diverged");
    assert!(
        report.contains("    -   [~] home-link  (link)\n"),
        "{report}"
    );
    assert!(
        report.contains("    +   [+] home-link  (link)\n"),
        "{report}"
    );
    assert!(!report.contains("path:"), "{report}");
}

/// A plan that names no one machine ends in a footer and a banner where its hash would
/// be. The footer is the line directly under the last change's steps: it ends the
/// changes and is kept.
// `{env:NAME}` is the notation a reference is shown in, written out here as text.
#[allow(clippy::literal_string_with_formatting_args)]
#[test]
fn a_footer_directly_under_the_last_change_is_kept() {
    let foot = "  (a wetrun of this config is refused, so this plan has no plan_hash and is not \
                recorded as a preview)\n  UNBINDABLE — the connecting user references `{env:U}`\n";
    for generation in [
        capture!("absent", "plan", "old"),
        capture!("absent", "plan", "new"),
    ] {
        let hash = generation.rfind("plan_hash: ").expect("a hash line");
        let unbindable = format!("{}{foot}", &generation[..hash]);
        let projected = project("plan", &unbindable);
        assert!(
            projected.ends_with(&format!("  [+] script  (script)\n{foot}")),
            "{projected}"
        );
    }
}

/// Two generations pin the same bytes under the same ids and address the declaring
/// config differently: no pin difference, an address difference per entry.
#[test]
fn two_generations_locks_pin_the_same_and_address_differently() {
    let old = include_bytes!("testdata/real/tracked.old.zap.lock");
    let new = include_bytes!("testdata/real/tracked.new.zap.lock");
    let comparison = compare_locks(old, new).expect("well-formed locks");
    assert_eq!(comparison.pins, Vec::<String>::new());
    assert_eq!(comparison.addresses.len(), 2, "{comparison:?}");
    assert!(comparison.addresses[0].starts_with("`blob-tracked` config_hash: oracle "));
    assert!(comparison.addresses[1].starts_with("`build-tracked` config_hash: oracle "));
    // one binary's two locks are the same lock
    assert_eq!(
        compare_locks(new, new),
        Ok(super::audit::LockComparison::default())
    );
}
