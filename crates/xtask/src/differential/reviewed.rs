//! The checks on a reviewed apply's output — a dry `apply` (the preview a wetrun binds
//! to), the `apply --wetrun` bound to it, and the further preview that must plan nothing
//! but `pipeline` — shared by the base build (`base`), a scenario's reconverge phase
//! (`reconverge`), and the bootstrap-replace scenario (`bootstrap`). Each reads zap's
//! own columns: a banner and a change line stand two spaces in, and nothing under a
//! change is read as one.

use super::compare;
use super::process::Captured;

/// A dry `apply`: the preview a wetrun binds to. `--no-cache`, like every apply the
/// harness runs, so no call reads what an earlier one cached about the config or the
/// target: a wetrun runs the plan it computes itself.
pub const PREVIEW: &[&str] = &["apply", "--no-cache"];

/// The `apply --wetrun` bound to the [`PREVIEW`] recorded in the same `ZAP_HOME`.
pub const WETRUN: &[&str] = &["apply", "--wetrun", "--no-cache"];

/// A preview a wetrun can bind to: a dry `apply` that exited 0 (nothing to do) or 2
/// (changes planned) and printed a `plan_hash:` line. Exit 1 is a preview with a held
/// or unverifiable resource; no hash is a plan that names no one machine.
pub fn check_preview(apply: &Captured) -> Result<(), String> {
    if !matches!(apply.code, Some(0 | 2)) {
        // The whole report: a banner that says why leads it, far from the tail.
        return Err(format!(
            "failed: {}\n{}",
            apply.describe_failure(),
            apply.stdout
        ));
    }
    if prints_plan_hash(&apply.stdout) {
        Ok(())
    } else {
        Err(format!("printed no plan_hash:\n{}", apply.stdout))
    }
}

/// The value of every `plan_hash: ` line at column 0: the plan's own (one inside a
/// step stands further in).
pub fn plan_hashes(stdout: &str) -> Vec<&str> {
    stdout
        .lines()
        .filter_map(|line| line.strip_prefix("plan_hash: "))
        .collect()
}

/// The plan's `plan_hash`, when the report prints exactly one ([`plan_hashes`]).
pub fn one_plan_hash(stdout: &str) -> Option<&str> {
    match plan_hashes(stdout)[..] {
        [hash] => Some(hash),
        _ => None,
    }
}

/// Whether a report carries the plan's own `plan_hash:` line ([`plan_hashes`]).
pub fn prints_plan_hash(stdout: &str) -> bool {
    !plan_hashes(stdout).is_empty()
}

/// The id and kind of a change line (`  [+] <id>  (<kind>)`).
pub fn change_of(line: &str) -> Option<(&str, &str)> {
    let (id, kind) = line.get(6..)?.trim_end().rsplit_once("  (")?;
    Some((id, kind.strip_suffix(')')?))
}

/// A preview that plans exactly `ids`: a dry `apply` that exited 2 with no verdict
/// banner, printed a `plan_hash:`, and has a change line (a create or an update) for
/// each of `ids` and for nothing else but `pipeline` resources, which plan on every run
/// by design. `what` says how `ids` came to be planned (`held`, `drifted`), for the
/// message.
pub fn plans_exactly(apply: &Captured, ids: &[&str], what: &str) -> Result<(), String> {
    if apply.code != Some(2) {
        return Err(format!(
            "failed: expected exit 2 (a plan of {}), got {}",
            ids.join(", "),
            apply.describe_failure()
        ));
    }
    if let Some(banner) = apply.stdout.lines().find_map(compare::banner_name) {
        return Err(format!("reports {banner}"));
    }
    if !prints_plan_hash(&apply.stdout) {
        return Err("printed no plan_hash:".to_owned());
    }
    let mut planned = Vec::new();
    let mut stray = Vec::new();
    for line in apply
        .stdout
        .lines()
        .filter(|line| compare::is_change_line(line))
    {
        match change_of(line) {
            Some((_, "pipeline")) => {}
            Some((id, _)) if ids.contains(&id) => planned.push(id),
            _ => stray.push(line.trim()),
        }
    }
    if !stray.is_empty() {
        return Err(format!(
            "plans more than the resources that were {what}: {}",
            stray.join("; ")
        ));
    }
    let missing: Vec<&str> = ids
        .iter()
        .copied()
        .filter(|id| !planned.contains(id))
        .collect();
    if missing.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "does not plan a resource that was {what}: {}",
            missing.join(", ")
        ))
    }
}

/// `problem`, then what the run wrote to stderr — where a zap that stopped on an
/// error says why, with nothing on stdout — and its whole report.
pub fn with_report(problem: &str, apply: &Captured) -> String {
    let stderr = apply.stderr.trim();
    if stderr.is_empty() {
        format!("{problem}\n{}", apply.stdout)
    } else {
        format!("{problem}\nstderr: {stderr}\n{}", apply.stdout)
    }
}

/// A wetrun that completed every change it ran: no `  FAIL  <id>` or `  skip  <id>`
/// outcome line, and one `applied: <n> ok, <n> failed, <n> skipped (of <n>)` summary
/// at column 0 with nothing failed or skipped.
pub fn summary_problem(stdout: &str) -> Result<(), String> {
    let incomplete: Vec<&str> = stdout
        .lines()
        .filter(|line| line.starts_with("  FAIL  ") || line.starts_with("  skip  "))
        .map(str::trim)
        .collect();
    if !incomplete.is_empty() {
        return Err(format!(
            "did not complete every change: {}",
            incomplete.join("; ")
        ));
    }
    let summaries: Vec<&str> = stdout
        .lines()
        .filter(|line| line.starts_with("applied: "))
        .collect();
    let [summary] = summaries[..] else {
        return Err("did not print one `applied:` summary line".to_owned());
    };
    match incomplete_counts(summary) {
        Some((0, 0)) => Ok(()),
        Some(_) => Err(format!("did not complete every change: {summary}")),
        None => Err(format!("printed a summary that can't be read: {summary}")),
    }
}

/// The failed and skipped counts of a wetrun's
/// `applied: <n> ok, <n> failed, <n> skipped (of <n>)` line.
fn incomplete_counts(summary: &str) -> Option<(u32, u32)> {
    let rest = summary.strip_prefix("applied: ")?;
    let (ok, rest) = rest.split_once(" ok, ")?;
    let (failed, rest) = rest.split_once(" failed, ")?;
    let (skipped, rest) = rest.split_once(" skipped (of ")?;
    let total = rest.strip_suffix(')')?;
    ok.parse::<u32>().ok()?;
    total.parse::<u32>().ok()?;
    Some((failed.parse().ok()?, skipped.parse().ok()?))
}

/// The wetrun bound to a preview whose plan hashed to `reviewed`: it exited 0, with no
/// verdict banner, every change completed ([`summary_problem`]), and the same
/// `plan_hash`.
pub fn wetrun_problem(apply: &Captured, reviewed: &str) -> Result<(), String> {
    if apply.code != Some(0) {
        return Err(format!("failed: {}", apply.describe_failure()));
    }
    if let Some(banner) = apply.stdout.lines().find_map(compare::banner_name) {
        return Err(format!("reports {banner}"));
    }
    summary_problem(&apply.stdout)?;
    match one_plan_hash(&apply.stdout) {
        Some(hash) if hash == reviewed => Ok(()),
        found => Err(format!(
            "ran plan_hash {}, not the reviewed {reviewed}",
            found.unwrap_or("none")
        )),
    }
}

/// A second (dry-run) apply must plan nothing but imperative `pipeline`
/// resources, which plan on every run by design.
pub fn check_idempotent(apply: &Captured) -> Result<(), String> {
    if !matches!(apply.code, Some(0 | 2)) {
        return Err(apply.describe_failure());
    }
    only_imperative_changes(&apply.stdout)
}

/// See [`check_idempotent`]: the stdout half. Any verdict banner (`  NAME — …`:
/// `UNDETERMINED`, `UNVERIFIABLE`, `RESIDUAL`, `LOCK`, `UNBINDABLE`, `UNRECORDED`,
/// `REFUSED`, or one this list doesn't know) fails it.
///
/// Read by zap's own columns: a banner and a change line (`  [+] <id>  (<kind>)`) are
/// indented exactly two spaces. The lines under the header that name the machine and
/// the target, and the lines under a change — what it declares, its steps, their
/// continuation lines — are none of those, whatever text they carry.
pub fn only_imperative_changes(stdout: &str) -> Result<(), String> {
    if let Some(banner) = stdout.lines().find_map(compare::banner_name) {
        return Err(format!("the plan reports {banner}\n{stdout}"));
    }
    if stdout
        .lines()
        .any(|line| line == "  (no changes — converged)")
    {
        return Ok(());
    }
    let changes: Vec<&str> = stdout
        .lines()
        .filter(|line| compare::is_change_line(line))
        .collect();
    if changes.is_empty() {
        return Err(format!(
            "no converged marker and no change lines:\n{stdout}"
        ));
    }
    let stray: Vec<&str> = changes
        .into_iter()
        .filter(|line| !line.trim_end().ends_with("(pipeline)"))
        .map(str::trim)
        .collect();
    if stray.is_empty() {
        Ok(())
    } else {
        Err(format!("still planned: {}", stray.join("; ")))
    }
}

#[cfg(test)]
pub mod tests {
    use super::{
        change_of, check_preview, incomplete_counts, one_plan_hash, only_imperative_changes,
        plan_hashes, plans_exactly, prints_plan_hash, wetrun_problem,
    };
    use crate::differential::compare::is_change_line;
    use crate::differential::process::Captured;

    /// A second apply as a zap without the plan's subject and declared lines prints it.
    pub const PIPELINE_ONLY: &str = "apply — target {env:ZAPDIFF_HOST} (dry-run)\n  \
        [+] pipeline  (pipeline)\n      > true\n  (dry-run — re-run with --wetrun to apply)\n\
        plan_hash: 1de19df0\n";

    /// A second apply with the machine, the target and the references under the header.
    pub const PIPELINE_ONLY_WITH_SUBJECT: &str = "apply — target {env:ZAPDIFF_HOST} (dry-run)\n  \
        host: 192.168.122.10\n  user: ops\n  \
        target: {\"local\":false,\"host\":{\"$env\":\"ZAPDIFF_HOST\"},\"user\":{\"$env\":\"ZAPDIFF_USER\"}}\n  \
        references:\n    ZAPDIFF_CONTENT = http://127.0.0.1:8080\n    \
        ZAPDIFF_EXPECT is unset or empty: a wetrun stops before any change until it is set\n  \
        [+] pipeline  (pipeline)\n      > true\n  (dry-run — re-run with --wetrun to apply)\n\
        plan_hash: 1de19df0\n";

    pub fn captured(code: i32, stdout: &str) -> Captured {
        Captured {
            code: Some(code),
            stdout: stdout.to_owned(),
            stderr: String::new(),
            timed_out: false,
        }
    }

    #[test]
    fn change_lines_are_recognized() {
        assert!(is_change_line("  [+] pipeline  (pipeline)"));
        assert!(is_change_line("  [~] nginx-service  (service)"));
        assert!(!is_change_line("      > true"));
        assert!(!is_change_line(
            "  (dry-run — re-run with --wetrun to apply)"
        ));
        // a step's continuation line that spells a change line stands further in
        assert!(!is_change_line("        [+] inline  (file)"));
        assert!(!is_change_line("[+] inline  (file)"));
    }

    #[test]
    fn a_converged_or_pipeline_only_plan_is_idempotent() {
        assert_eq!(only_imperative_changes(PIPELINE_ONLY), Ok(()));
        assert_eq!(only_imperative_changes(PIPELINE_ONLY_WITH_SUBJECT), Ok(()));
        assert_eq!(
            only_imperative_changes("apply — target local (dry-run)\n  (no changes — converged)\n"),
            Ok(())
        );
        assert_eq!(
            only_imperative_changes(
                "apply — target local (dry-run)\n  target: {\"local\":true}\n  \
                 (no changes — converged)\nplan_hash: ab\n"
            ),
            Ok(())
        );
    }

    // `{env:NAME}` is the notation a reference is shown in, written out here as text.
    #[allow(clippy::literal_string_with_formatting_args)]
    #[test]
    fn any_other_change_or_verdict_is_not() {
        for plan in [PIPELINE_ONLY, PIPELINE_ONLY_WITH_SUBJECT] {
            let drift = plan.replace(
                "  [+] pipeline  (pipeline)\n",
                "  [+] pipeline  (pipeline)\n  [~] inline  (file)\n      path: /etc/x\n      \
                 content: inline (3 bytes, sha512 0123456789abcdef…)\n",
            );
            let error = only_imperative_changes(&drift).expect_err("drift");
            assert_eq!(error, "still planned: [~] inline  (file)");
        }
        for banner in [
            "  UNDETERMINED — 1 resource(s) could not be probed",
            "  UNVERIFIABLE — 1 referenced variable(s) are unset",
            "  LOCK — the pin ledger does not answer for 1 resource(s)",
            "  RESIDUAL — 1 resource(s) do not read converged",
            "  UNBINDABLE — the target host `{env:H}` references `{env:H}`, a secret name",
            "  UNRECORDED — no last run is kept for this target",
            "  REFUSED — nothing ran: this plan was not reviewed.",
        ] {
            let text = format!("{banner}\n  (no changes — converged)\n");
            assert!(only_imperative_changes(&text).is_err(), "{banner}");
        }
        assert!(only_imperative_changes("").is_err());
        // the converged marker is a line of its own, not text inside another
        assert!(
            only_imperative_changes(
                "apply — target local (dry-run)\n  [~] x  (script)\n      \
                 check: echo '  (no changes — converged)'\n"
            )
            .is_err()
        );
    }

    /// What a change declares and what its steps say are not change lines or banners,
    /// even when they spell one.
    #[test]
    fn lines_under_a_change_are_not_read_as_changes_or_banners() {
        let plan = PIPELINE_ONLY_WITH_SUBJECT.replace(
            "      > true\n",
            "      > printf 'a\n        [~] inline  (file)\n        UNDETERMINED — not a banner\n        \
             (no changes — converged)'\n",
        );
        assert_eq!(only_imperative_changes(&plan), Ok(()));
    }

    #[test]
    fn a_preview_must_exit_0_or_2_and_print_a_hash() {
        assert_eq!(
            check_preview(&captured(2, PIPELINE_ONLY_WITH_SUBJECT)),
            Ok(())
        );
        assert_eq!(check_preview(&captured(0, PIPELINE_ONLY)), Ok(()));
        // held or unverifiable
        let held = check_preview(&captured(1, PIPELINE_ONLY)).expect_err("exit 1");
        assert!(held.starts_with("failed: exit 1"), "{held}");
        // unbindable: a changeset and no hash
        let unbound = PIPELINE_ONLY.replace("plan_hash: 1de19df0\n", "");
        let error = check_preview(&captured(2, &unbound)).expect_err("no hash");
        assert!(error.starts_with("printed no plan_hash:"), "{error}");
        // a hash-shaped line inside a step is not the plan's
        let inside = unbound.replace("      > true\n", "      > echo\n        plan_hash: 00\n");
        assert!(check_preview(&captured(2, &inside)).is_err());
        let mut timed_out = captured(2, PIPELINE_ONLY);
        timed_out.code = None;
        assert!(check_preview(&timed_out).is_err());
    }

    /// A preview of a drifted state plans exactly the drifted resources, whichever
    /// order zap lists them in, and says so in the reconverge's words.
    #[test]
    fn a_plan_of_exactly_the_drifted_resources() {
        let plan = PIPELINE_ONLY_WITH_SUBJECT.replace(
            "  [+] pipeline  (pipeline)\n",
            "  [~] user-keys  (user)\n  [~] user-copy  (user)\n  [+] pipeline  (pipeline)\n",
        );
        let drifted = ["user-copy", "user-keys"];
        assert_eq!(
            plans_exactly(&captured(2, &plan), &drifted, "drifted"),
            Ok(())
        );
        assert_eq!(
            plans_exactly(&captured(2, &plan), &["user-copy"], "drifted"),
            Err(
                "plans more than the resources that were drifted: [~] user-keys  (user)".to_owned()
            )
        );
        assert_eq!(
            plans_exactly(&captured(2, PIPELINE_ONLY), &drifted, "drifted"),
            Err("does not plan a resource that was drifted: user-copy, user-keys".to_owned())
        );
        let error =
            plans_exactly(&captured(0, PIPELINE_ONLY), &drifted, "drifted").expect_err("exit 0");
        assert!(
            error.starts_with(
                "failed: expected exit 2 (a plan of user-copy, user-keys), got exit 0"
            ),
            "{error}"
        );
    }

    /// The plan's own hash is the one at column 0; one in a step's text is not.
    #[test]
    fn a_plan_hash_is_read_at_column_0() {
        let inside = "plan — x\n      > echo\n        plan_hash: zz\nplan_hash: ab\n";
        assert_eq!(plan_hashes(inside), ["ab"]);
        assert_eq!(one_plan_hash(inside), Some("ab"));
        assert!(prints_plan_hash(inside));
        let twice = "plan_hash: ab\nplan_hash: ab\n";
        assert_eq!(plan_hashes(twice), ["ab", "ab"]);
        assert_eq!(one_plan_hash(twice), None);
        assert_eq!(one_plan_hash("plan — x\n"), None);
        assert!(!prints_plan_hash("  plan_hash: ab\n"));
    }

    #[test]
    fn a_change_line_names_its_id_and_kind() {
        assert_eq!(
            change_of("  [+] pipeline  (pipeline)"),
            Some(("pipeline", "pipeline"))
        );
        assert_eq!(
            change_of("  [~] nginx-service  (service)"),
            Some(("nginx-service", "service"))
        );
        // an id may hold what ends a change line
        assert_eq!(change_of("  [+] a  (b)  (file)"), Some(("a  (b)", "file")));
        assert_eq!(change_of("  [+] bare"), None);
    }

    #[test]
    fn a_summary_gives_its_failed_and_skipped_counts() {
        assert_eq!(
            incomplete_counts("applied: 41 ok, 0 failed, 0 skipped (of 41)"),
            Some((0, 0))
        );
        assert_eq!(
            incomplete_counts("applied: 3 ok, 1 failed, 37 skipped (of 41)"),
            Some((1, 37))
        );
        for line in [
            "applied: 3 ok, 1 failed",
            "applied: 3 ok, x failed, 0 skipped (of 3)",
            "applied: 3 ok, 0 failed, 0 skipped (of 3) and more",
            "  applied: 3 ok, 0 failed, 0 skipped (of 3)",
        ] {
            assert_eq!(incomplete_counts(line), None, "{line}");
        }
    }

    const WETRUN_REPORT: &str = "apply — target {env:ZAPDIFF_HOST} (wetrun)\n  host: 192.168.122.11\n  \
        user: ops\n  ok    firewall\n  ok    pipeline\n\
        applied: 2 ok, 0 failed, 0 skipped (of 2)\nplan_hash: 9f0e\n";

    #[test]
    fn the_wetrun_runs_the_reviewed_plan_to_completion() {
        assert_eq!(wetrun_problem(&captured(0, WETRUN_REPORT), "9f0e"), Ok(()));
        assert_eq!(
            wetrun_problem(&captured(0, WETRUN_REPORT), "1234"),
            Err("ran plan_hash 9f0e, not the reviewed 1234".to_owned())
        );
        let refused = "  REFUSED — nothing ran: this plan was not reviewed.\n";
        assert!(
            wetrun_problem(&captured(1, refused), "9f0e")
                .expect_err("refused")
                .starts_with("failed: exit 1")
        );
        let residual = WETRUN_REPORT.replace(
            "applied: ",
            "  RESIDUAL — 1 resource(s) do not read converged after this apply:\napplied: ",
        );
        assert_eq!(
            wetrun_problem(&captured(0, &residual), "9f0e"),
            Err("reports RESIDUAL".to_owned())
        );
        let failed = WETRUN_REPORT.replace("2 ok, 0 failed", "1 ok, 1 failed");
        assert_eq!(
            wetrun_problem(&captured(0, &failed), "9f0e"),
            Err(
                "did not complete every change: applied: 1 ok, 1 failed, 0 skipped (of 2)"
                    .to_owned()
            )
        );
        let unsummed = WETRUN_REPORT.replace("applied: ", "  applied: ");
        assert_eq!(
            wetrun_problem(&captured(0, &unsummed), "9f0e"),
            Err("did not print one `applied:` summary line".to_owned())
        );
        let unhashed = WETRUN_REPORT.replace("plan_hash: 9f0e\n", "");
        assert_eq!(
            wetrun_problem(&captured(0, &unhashed), "9f0e"),
            Err("ran plan_hash none, not the reviewed 9f0e".to_owned())
        );
        // an outcome line that failed or was skipped fails it, whatever the summary says
        let skipped = WETRUN_REPORT.replace(
            "  ok    pipeline\n",
            "  skip  pipeline  — an earlier change failed\n",
        );
        assert_eq!(
            wetrun_problem(&captured(0, &skipped), "9f0e"),
            Err(
                "did not complete every change: skip  pipeline  — an earlier change failed"
                    .to_owned()
            )
        );
    }
}
