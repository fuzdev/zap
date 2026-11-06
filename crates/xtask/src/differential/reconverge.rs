//! The reconverge phase of a scenario that carries a probe (`Scenario::reconverge`):
//! once the read-only phase has compared and audited the drifted state, the
//! **candidate alone** applies it back the way an operator does, and the machine must
//! read as it did on the base.
//!
//! Under `--compare exact` the read-only phase has already proven the candidate's plan
//! of the drifted state byte-identical to the oracle's, `plan_hash` (which covers every
//! step) included; what is left is whether executing it restores the machine, which is
//! the candidate's own property. With the candidate's staged tree, environment, and a
//! `ZAP_HOME` of the phase's own:
//!
//! 1. a dry `apply` plans exactly the scenario's expected resources and nothing else
//!    but `pipeline` (`reviewed::plans_exactly`);
//! 2. the `apply --wetrun` bound to it exits 0 with every change completed
//!    (`reviewed::wetrun_problem`) and the preview's `plan_hash`;
//! 3. a further dry `apply` plans nothing but `pipeline` (`reviewed::check_idempotent`);
//! 4. `detect` reads every resource but the `pipeline` `ok` (a `pipeline` reads
//!    `absent` by design);
//! 5. the scenario's probe reads what it read on the base.
//!
//! The first four are zap checking itself. The probe is the check that isn't circular:
//! a root shell snippet that never goes through zap, read on the base before the
//! mutation, right after it (where it must differ, or the drift didn't take), and after
//! the apply. A detector that misreads wrong state as converged passes the first four
//! and fails the probe.
//!
//! The phase fetches nothing (the scenarios that reconverge are offline) and leaves the
//! candidate's `zap.lock` as `zap lock` minted it; a lock it rewrote is put back and
//! reported. Its write set isn't audited: what an
//! apply touches (ufw and postgres each write several files) is the apply's business,
//! and the probe judges the result.

use std::time::Duration;

use super::compare;
use super::process::Captured;
use super::reviewed::{
    PREVIEW, WETRUN, check_idempotent, one_plan_hash, plans_exactly, wetrun_problem, with_report,
};
use super::runner::{self, Side, ZAP_TIMEOUT};
use super::scenarios::Scenario;
use super::vm;
use super::{Context, DistroSetup, fetch_count};

/// Where a probe's output starts: `@@zapdiff probe <label>`.
const PROBE_MARK: &str = "@@zapdiff probe ";
/// Where it ends, with the probe's exit status: `@@zapdiff probe-status <n>`.
const PROBE_STATUS: &str = "@@zapdiff probe-status ";
/// The heredoc delimiter a probe is carried in, which no probe line may be.
const PROBE_EOF: &str = "@@ZAPDIFF_PROBE_EOF";

/// The probe's reading of the base, before the mutation.
pub const ON_BASE: &str = "base";
/// Its reading right after the mutation.
pub const DRIFTED: &str = "drifted";
/// Its reading after the candidate's apply.
const RECONVERGED: &str = "reconverged";

/// How long the probe's own root shell may take.
const PROBE_TIMEOUT: Duration = Duration::from_secs(120);

/// The root shell lines that run `probe` in a shell of its own (`sh -eu -o pipefail`,
/// so a failure anywhere in a pipeline fails it; stdin closed, stderr folded into its
/// output) and print what it printed between a `label` mark and its exit status. The
/// script that carries them goes on whatever the probe does: a failed probe is a
/// reading, judged by [`probe_reading`].
pub fn probe_script(label: &str, probe: &str) -> String {
    format!(
        "zapdiff_probe=$(cat <<'{PROBE_EOF}'\n{probe}\n{PROBE_EOF}\n)\n\
         echo '{PROBE_MARK}{label}'\n\
         zapdiff_status=0\n\
         sh -eu -o pipefail -c \"$zapdiff_probe\" </dev/null 2>&1 || zapdiff_status=$?\n\
         echo \"{PROBE_STATUS}$zapdiff_status\""
    )
}

/// What the probe printed under `label` in `stdout` (the output of a
/// [`probe_script`]), when it ran once and exited 0.
pub fn probe_reading(stdout: &str, label: &str) -> Result<String, String> {
    let mark = format!("{PROBE_MARK}{label}");
    let mut starts = stdout.lines().enumerate().filter(|(_, line)| *line == mark);
    let (Some((at, _)), None) = (starts.next(), starts.next()) else {
        return Err(format!("the output doesn't hold one `{mark}` reading"));
    };
    let mut reading = String::new();
    for line in stdout.lines().skip(at + 1) {
        if let Some(status) = line.strip_prefix(PROBE_STATUS) {
            return if status == "0" {
                Ok(reading)
            } else {
                Err(format!("it exited {status}:\n{reading}"))
            };
        }
        reading.push_str(line);
        reading.push('\n');
    }
    Err(format!("its `{mark}` reading never ended:\n{reading}"))
}

/// The probe must see the mutation: a `drifted` reading equal to the `base` one means
/// the drift didn't take, or the probe doesn't read what the scenario drifts.
pub fn drift_problem(base: &str, drifted: &str) -> Option<String> {
    // any difference: a probe of a several-part mutation must print each part, which
    // only its own lines show
    (base == drifted).then(|| {
        format!(
            "the probe reads the same after the mutation as on the base, so the drift didn't \
             take or the probe doesn't see it:\n{}",
            indent(base)
        )
    })
}

/// The probe must read the base again after the apply.
pub fn restored_problem(base: &str, after: &str) -> Option<String> {
    (base != after).then(|| {
        format!(
            "the probe doesn't read the base after the apply:\n{}",
            indent(&compare::labeled_diff(
                ("on the base", base),
                ("after the apply", after),
                1
            ))
        )
    })
}

/// `text` four spaces in, an empty line left empty.
fn indent(text: &str) -> String {
    text.lines()
        .map(|line| {
            if line.is_empty() {
                String::new()
            } else {
                format!("    {line}")
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// A `detect` of the reconverged machine: a well-formed report of all `resources`,
/// exit 0, every resource but the `pipeline` `ok` (a `pipeline` reads `absent` by
/// design, and `runner::detect_movers` leaves it out).
pub fn detect_problem(detect: &Captured, resources: usize) -> Result<(), String> {
    runner::well_formed("detect", detect, resources)?;
    let moved = runner::detect_movers(&detect.stdout);
    if !moved.is_empty() {
        let moved: Vec<String> = moved
            .iter()
            .map(|(id, mark)| format!("{id}({mark})"))
            .collect();
        return Err(format!("reads {} not ok", moved.join(" ")));
    }
    if detect.code == Some(0) {
        Ok(())
    } else {
        Err(format!("failed: {}", detect.describe_failure()))
    }
}

/// The candidate's staged `zap.lock` as `zap lock` minted it: the scenarios after this
/// one read it.
struct MintedLock {
    path: std::path::PathBuf,
    minted: Vec<u8>,
}

impl MintedLock {
    fn take(path: std::path::PathBuf) -> Result<Self, String> {
        let minted = std::fs::read(&path)
            .map_err(|error| format!("reading {} failed: {error}", path.display()))?;
        Ok(Self { path, minted })
    }

    /// Put the minted lock back if the phase changed it: `Ok(true)` when it had to.
    fn restore(&self) -> Result<bool, String> {
        if std::fs::read(&self.path).is_ok_and(|now| now == self.minted) {
            return Ok(false);
        }
        std::fs::write(&self.path, &self.minted)
            .map(|()| true)
            .map_err(|error| format!("restoring {} failed: {error}", self.path.display()))
    }
}

/// The phase's `outcome` with what became of the lock (`MintedLock::restore`): a
/// rewrite is a failure of its own, reported beside any other, so a failed wetrun that
/// also rewrote the lock doesn't hide the rewrite.
fn with_lock(outcome: Result<(), String>, restored: Result<bool, String>) -> Result<(), String> {
    let lock = match restored {
        Ok(false) => None,
        Ok(true) => Some(
            "the apply rewrote the candidate's zap.lock (put back as `zap lock` minted it)"
                .to_owned(),
        ),
        Err(error) => Some(format!(
            "the apply rewrote the candidate's zap.lock: {error}"
        )),
    };
    match (outcome, lock) {
        (outcome, None) => outcome,
        (Ok(()), Some(lock)) => Err(lock),
        (Err(problem), Some(lock)) => Err(format!("{problem}\nand {lock}")),
    }
}

/// Run the phase for `scenario`, whose mutation script printed `mutated` (the `base`
/// and `drifted` probe readings among it); `Err` is the first check that failed, and a
/// rewritten `zap.lock` beside it.
pub fn run(
    context: &Context,
    setup: &DistroSetup<'_>,
    scenario: &Scenario,
    probe: &str,
    mutated: &str,
) -> Result<(), String> {
    let base = probe_reading(mutated, ON_BASE)
        .map_err(|error| format!("the probe failed on the base: {error}"))?;
    let drifted = probe_reading(mutated, DRIFTED)
        .map_err(|error| format!("the probe failed after the mutation: {error}"))?;
    if let Some(problem) = drift_problem(&base, &drifted) {
        return Err(problem);
    }
    let run = setup.runs[Side::Candidate.index()];
    let lock = MintedLock::take(run.config.with_file_name("zap.lock"))?;
    let outcome = apply_back(context, setup, scenario, probe, &base);
    with_lock(outcome, lock.restore())
}

/// The candidate's apply of the drifted state, its own checks of the result, and the
/// probe's reading of it against `base`.
fn apply_back(
    context: &Context,
    setup: &DistroSetup<'_>,
    scenario: &Scenario,
    probe: &str,
    base: &str,
) -> Result<(), String> {
    let distro = setup.distro;
    let run = setup.runs[Side::Candidate.index()];
    let candidate = context.binary(Side::Candidate);
    let home = context.homes.home(&format!(
        "{}/{}/{}/reconverge",
        distro.name(),
        scenario.suite.name(),
        scenario.name
    ));
    let zap = |args: &[&str]| runner::run_host_zap(run, candidate, &home, args, ZAP_TIMEOUT);
    let fetched_before = fetch_count(context);

    let expected: Vec<&str> = scenario.expect.iter().map(|(id, _)| *id).collect();
    let preview = zap(PREVIEW)?;
    plans_exactly(&preview, &expected, "drifted").map_err(|problem| {
        format!(
            "the preview apply {}",
            with_report(&problem, &preview).trim_end()
        )
    })?;
    let reviewed = one_plan_hash(&preview.stdout)
        .ok_or("the preview apply printed no one plan_hash")?
        .to_owned();
    let applied = zap(WETRUN)?;
    wetrun_problem(&applied, &reviewed).map_err(|problem| {
        format!(
            "the apply --wetrun {}",
            with_report(&problem, &applied).trim_end()
        )
    })?;
    let again = zap(PREVIEW)?;
    check_idempotent(&again)
        .map_err(|problem| format!("a further preview apply plans more: {problem}"))?;
    let detect = zap(&["detect", "--no-cache"])?;
    detect_problem(&detect, setup.ssh_resources).map_err(|problem| {
        format!(
            "the detect after the apply {}",
            with_report(&problem, &detect).trim_end()
        )
    })?;

    let fetched = fetch_count(context) - fetched_before;
    if fetched > 0 {
        return Err(format!(
            "the apply fetched remote content {fetched} time(s); a reconverging scenario is \
             offline"
        ));
    }

    let probed = vm::root_shell(distro, &probe_script(RECONVERGED, probe), PROBE_TIMEOUT)?;
    if !probed.success() {
        return Err(format!(
            "the probe's shell failed after the apply: {}",
            probed.describe_failure()
        ));
    }
    let after = probe_reading(&probed.stdout, RECONVERGED)
        .map_err(|error| format!("the probe failed after the apply: {error}"))?;
    restored_problem(base, &after).map_or(Ok(()), Err)
}

#[cfg(test)]
mod tests {
    use std::process::Command;
    use std::time::Duration;

    use super::{
        DRIFTED, ON_BASE, detect_problem, drift_problem, indent, probe_reading, probe_script,
        restored_problem, with_lock,
    };
    use crate::differential::process;
    use crate::differential::reviewed::tests::captured;
    use crate::differential::scenarios::scenarios;
    use crate::differential::vm::Distro;

    /// Run `script` the way `vm::root_shell` delivers one: whole on stdin, under
    /// `set -eu`, evaluated by `sh` from `/`.
    fn root_shell(script: &str) -> process::Captured {
        let mut command = Command::new("sh");
        command.args(["-c", "script=$(cat) && exec </dev/null && eval \"$script\""]);
        let script = format!("set -eu\ncd /\n{script}\n");
        process::run(command, Some(script.as_bytes()), Duration::from_secs(30))
            .expect("the shell runs")
    }

    /// A probe runs in a shell of its own: what it prints is its reading, its failure
    /// is reported with what it printed, and the script that carries it goes on.
    #[test]
    fn a_probe_reads_what_it_prints_and_a_failure_is_its_own() {
        let script = format!(
            "{}\necho mutated\n{}\necho after",
            probe_script(ON_BASE, "echo one\nprintf 'two\\n' >&2"),
            probe_script(DRIFTED, "echo partial\nfalse\necho never")
        );
        let ran = root_shell(&script);
        assert!(ran.success(), "{ran:?}");
        assert_eq!(
            probe_reading(&ran.stdout, ON_BASE),
            Ok("one\ntwo\n".to_owned())
        );
        assert_eq!(
            probe_reading(&ran.stdout, DRIFTED),
            Err("it exited 1:\npartial\n".to_owned())
        );
        assert!(
            ran.stdout.ends_with(
                "mutated\n@@zapdiff probe drifted\npartial\n@@zapdiff probe-status 1\nafter\n"
            ),
            "{}",
            ran.stdout
        );
        // a failure inside a pipeline fails the probe
        let piped = probe_script(ON_BASE, "false | sort\necho never");
        assert_eq!(
            probe_reading(&root_shell(&piped).stdout, ON_BASE),
            Err("it exited 1:\n".to_owned())
        );
        // a probe can't read the harness's stdin, nor end its heredoc early
        let quoted = probe_script(ON_BASE, "cat\necho \"$0 'q' $HOME\" | wc -l");
        assert_eq!(
            probe_reading(&root_shell(&quoted).stdout, ON_BASE),
            Ok("1\n".to_owned())
        );
    }

    #[test]
    fn a_reading_is_one_marked_block_with_its_status() {
        let block = "@@zapdiff probe base\nx\n@@zapdiff probe-status 0\n";
        assert_eq!(probe_reading(block, ON_BASE), Ok("x\n".to_owned()));
        assert_eq!(
            probe_reading(&format!("{block}{block}"), ON_BASE),
            Err("the output doesn't hold one `@@zapdiff probe base` reading".to_owned())
        );
        assert!(probe_reading(block, DRIFTED).is_err());
        assert_eq!(
            probe_reading("@@zapdiff probe base\nx\n", ON_BASE),
            Err("its `@@zapdiff probe base` reading never ended:\nx\n".to_owned())
        );
        // an empty reading is a reading
        let empty = "@@zapdiff probe base\n@@zapdiff probe-status 0\n";
        assert_eq!(probe_reading(empty, ON_BASE), Ok(String::new()));
    }

    #[test]
    fn the_drift_must_show_and_the_apply_must_undo_it() {
        assert_eq!(drift_problem("a\n", "b\n"), None);
        let same = drift_problem("Default: deny (incoming)\n", "Default: deny (incoming)\n")
            .expect("a problem");
        assert!(
            same.starts_with("the probe reads the same after the mutation"),
            "{same}"
        );
        assert!(same.ends_with("\n    Default: deny (incoming)"), "{same}");

        assert_eq!(restored_problem("a\nb\n", "a\nb\n"), None);
        let left = restored_problem("a\nb\n", "a\nc\n").expect("a problem");
        assert!(
            left.starts_with("the probe doesn't read the base after the apply:\n"),
            "{left}"
        );
        for line in ["--- on the base", "+++ after the apply", "- b", "+ c"] {
            assert!(left.lines().any(|l| l.trim() == line), "{line}: {left}");
        }
    }

    /// A rewritten lock is reported beside the phase's own failure, not in its place.
    #[test]
    fn a_rewritten_lock_is_reported_whatever_else_failed() {
        assert_eq!(with_lock(Ok(()), Ok(false)), Ok(()));
        let failed = Err("the apply --wetrun failed: exit 1".to_owned());
        assert_eq!(with_lock(failed.clone(), Ok(false)), failed);
        let rewrote =
            "the apply rewrote the candidate's zap.lock (put back as `zap lock` minted it)";
        assert_eq!(with_lock(Ok(()), Ok(true)), Err(rewrote.to_owned()));
        assert_eq!(
            with_lock(failed, Ok(true)),
            Err(format!("the apply --wetrun failed: exit 1\nand {rewrote}"))
        );
        assert_eq!(
            with_lock(
                Ok(()),
                Err("restoring /s/zap.lock failed: denied".to_owned())
            ),
            Err(
                "the apply rewrote the candidate's zap.lock: restoring /s/zap.lock failed: denied"
                    .to_owned()
            )
        );
    }

    #[test]
    fn an_indented_empty_line_stays_empty() {
        assert_eq!(indent("a\n\nb\n"), "    a\n\n    b");
    }

    const DETECT: &str = "detected live state — target x (pkg: apt, service: systemd)\n\
        2 resource(s):\n  ok     firewall  firewall  — converged\n  \
        absent pipeline  pipeline  — absent\n";

    #[test]
    fn the_detect_after_reads_every_resource_ok() {
        assert_eq!(detect_problem(&captured(0, DETECT), 2), Ok(()));
        assert!(detect_problem(&captured(0, DETECT), 3).is_err());
        let drift = DETECT.replace(
            "ok     firewall  firewall  — converged",
            "drift  firewall  firewall  — drifted",
        );
        assert_eq!(
            detect_problem(&captured(0, &drift), 2),
            Err("reads firewall(drift) not ok".to_owned())
        );
        assert!(detect_problem(&captured(1, DETECT), 2).is_err());
    }

    /// Each probe is a script `sh` parses, and none carries the line that would end
    /// its heredoc.
    #[test]
    fn every_probe_parses_as_sh() {
        for distro in Distro::ALL {
            for scenario in scenarios(distro) {
                let Some(probe) = scenario.reconverge else {
                    continue;
                };
                assert!(!probe.lines().any(|line| line == super::PROBE_EOF));
                let checked = Command::new("sh")
                    .args(["-n", "-c", &probe])
                    .output()
                    .expect("sh runs");
                assert!(
                    checked.status.success(),
                    "{distro}/{}: {}",
                    scenario.name,
                    String::from_utf8_lossy(&checked.stderr)
                );
            }
        }
    }
}
