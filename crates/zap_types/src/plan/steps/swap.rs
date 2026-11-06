//! `swap` step builder — allocate, format, enable, and persist a swap file.

use crate::observe::swap::FSTAB_PATH;
use crate::plan::{
    PlanStep, PutAs, PutCommand, PutMode, PutProducer, PutSource, PutStep, SwapCheckStep,
};
use crate::put::PutCheck;
use crate::scalar::Mode;
use crate::schema::SwapResource;
use crate::shell::single_quote;

/// The parts of a swap file detection found in place.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct SwapParts {
    /// It is active (`/proc/swaps`).
    pub is_active: bool,
    /// It is listed in `/etc/fstab`.
    pub in_fstab: bool,
}

impl SwapParts {
    /// Nothing in place: an absent swap file, or one planned without a drift reading.
    pub const NONE: Self = Self {
        is_active: false,
        in_fstab: false,
    };
}

/// Steps to create and persist a `swap` file, or the parts of one `have` lacks. `size` is
/// required by the schema, so the `fallocate` is always well-formed (a sizeless swap fails
/// at config-eval).
///
/// Only what is missing runs: an active swap file isn't allocated, chmodded, formatted,
/// or enabled again (`fallocate` on an active swap file fails, so a swap left out of
/// `/etc/fstab` would fail every run), and one already in `/etc/fstab` isn't listed
/// again. One that isn't active is allocated again whether or not a file is there, so a
/// short file an earlier run left (a full disk) is made whole before it is formatted.
///
/// The first step is the path's check ([`SwapCheckStep`]), so nothing is allocated, chmodded,
/// formatted, enabled, or persisted through a link or in a directory another account can
/// write.
///
/// `path` and `size` are `single_quote`d in every step — the same quoting the `swap`
/// detector's probes use — so a path with a space or quote converges instead of
/// breaking, and the fstab guard is the detector's own
/// [`table_lists_path`](crate::schema::table_lists_path) read.
///
/// The fstab entry is added by rewriting the file, not appending to it: the step prints
/// the table as it stands, each line ended (so the entry never joins a last line that
/// had no newline), then the entry, and installs that through a [`PutStep`],
/// `root`-owned, at the mode the table has (`644` for one that isn't there). A run cut
/// short or a full disk leaves the old table, never a truncated one. A table that can't be read fails
/// the step with nothing written; one that isn't there is created with the entry. An
/// edit made to the table between the step's read and its rename is lost.
pub(super) fn swap_steps(swap: &SwapResource, have: SwapParts) -> Vec<PlanStep> {
    let path = single_quote(&swap.path);
    let size = single_quote(&swap.size);
    let mut steps = vec![PlanStep::SwapCheck(SwapCheckStep {
        path: swap.path.clone(),
    })];
    if !have.is_active {
        steps.extend([
            PlanStep::run(format!("sudo fallocate -l {size} -- {path}")),
            PlanStep::run(format!("sudo chmod 600 -- {path}")),
            PlanStep::run(format!("sudo mkswap -- {path}")),
            PlanStep::run(format!("sudo swapon -- {path}")),
        ]);
    }
    if !have.in_fstab {
        // Persist across reboots: add the fstab entry only if absent (idempotent guard).
        steps.push(PlanStep::Put(PutStep {
            path: FSTAB_PATH.to_owned(),
            run_as: PutAs::Root,
            check: PutCheck::None,
            source: PutSource::Command(PutCommand {
                mode: PutMode::Keep {
                    if_new: Mode::fixed("644"),
                },
                producer: PutProducer::FstabSwapEntry {
                    path: swap.path.clone(),
                },
            }),
        }));
    }
    steps
}

#[cfg(test)]
mod tests {
    use super::{SwapParts, swap_steps};
    use crate::observe::Query;
    use crate::plan::{
        PlanStep, PutAs, PutCommand, PutMode, PutProducer, PutSource, PutStep, StepExecution,
    };
    use crate::put::{FileAttrs, PutCheck, RunAs, put_text_step_keeping_mode};
    use crate::scalar::Mode;
    use crate::schema::{SwapResource, fstab_with_entry, table_lists_path};

    fn swap(json: serde_json::Value) -> SwapResource {
        serde_json::from_value(json).expect("valid swap json")
    }

    /// The steps before the fstab entry, in full: the path's check, then the
    /// allocation, the mode, the format, and the enable, each on the quoted path.
    #[test]
    fn the_swap_file_is_checked_before_it_is_allocated() {
        use crate::plan::{SWAP_PATH_CHECK, SwapCheckStep};

        let path = "/var/sw'ap";
        let steps = swap_steps(
            &swap(serde_json::json!({"size": "2G", "path": path})),
            SwapParts::NONE,
        );
        let quoted = r"'/var/sw'\''ap'";
        assert_eq!(
            steps[..5],
            [
                PlanStep::SwapCheck(SwapCheckStep {
                    path: path.to_owned()
                }),
                PlanStep::run(format!("sudo fallocate -l '2G' -- {quoted}")),
                PlanStep::run(format!("sudo chmod 600 -- {quoted}")),
                PlanStep::run(format!("sudo mkswap -- {quoted}")),
                PlanStep::run(format!("sudo swapon -- {quoted}")),
            ]
        );
        assert_eq!(
            steps[0].execution().unwrap().text(),
            format!("sudo sh -c '{SWAP_PATH_CHECK}' sh {quoted}")
        );
        let summary = steps[0].summary().unwrap();
        assert_eq!(
            summary.label(),
            "check /var/sw'ap (not a link, below directories only root writes, as root)"
        );
    }

    /// A drifted swap file repairs only its missing parts: an active one left out of
    /// `/etc/fstab` is only listed (allocating it again would fail on the live file).
    #[test]
    fn a_drifted_swap_file_repairs_only_what_is_missing() {
        let swap = swap(serde_json::json!({"size": "2G", "path": "/swapfile"}));
        let runs = |have| {
            swap_steps(&swap, have)
                .iter()
                .map(|step| match step {
                    PlanStep::SwapCheck(_) => "check",
                    PlanStep::Put(_) => "fstab",
                    PlanStep::Run(run) if run.starts_with("sudo fallocate") => "fallocate",
                    PlanStep::Run(run) if run.starts_with("sudo chmod") => "chmod",
                    PlanStep::Run(run) if run.starts_with("sudo mkswap") => "mkswap",
                    PlanStep::Run(run) if run.starts_with("sudo swapon") => "swapon",
                    other => panic!("unexpected step {other:?}"),
                })
                .collect::<Vec<_>>()
        };
        let have = |is_active, in_fstab| SwapParts {
            is_active,
            in_fstab,
        };
        assert_eq!(runs(have(true, false)), ["check", "fstab"]);
        // An inactive file is allocated again, so a short one left by a full disk is
        // made whole before it is formatted.
        assert_eq!(
            runs(have(false, true)),
            ["check", "fallocate", "chmod", "mkswap", "swapon"]
        );
        assert_eq!(
            runs(have(false, false)),
            ["check", "fallocate", "chmod", "mkswap", "swapon", "fstab"]
        );
        assert_eq!(
            runs(SwapParts::NONE),
            ["check", "fallocate", "chmod", "mkswap", "swapon", "fstab"]
        );
    }

    #[test]
    fn sized_swap_allocates_and_persists_to_fstab() {
        let steps = swap_steps(
            &swap(serde_json::json!({"size": "2G", "path": "/swapfile"})),
            SwapParts::NONE,
        );
        assert!(steps.contains(&PlanStep::run("sudo fallocate -l '2G' -- '/swapfile'")));
        assert!(steps.contains(&PlanStep::run("sudo swapon -- '/swapfile'")));
        // Idempotent guarded fstab append — not a raw, duplicating append. The guard is
        // the detector's own exact-first-field read, so `/swapfile` isn't taken as listed
        // by a `/swapfile2` line.
        assert_eq!(
            fstab_with_entry("/etc/fstab", "/swapfile"),
            "{ [ ! -e /etc/fstab ] || awk '{ print }' /etc/fstab; } && \
             printf '%s\\n' '/swapfile none swap sw 0 0'"
        );
        let guard =
            "P='/swapfile' awk '$1 == ENVIRON[\"P\"] { found = 1 } END { exit !found }' /etc/fstab";
        let put = PlanStep::Put(PutStep {
            path: "/etc/fstab".to_owned(),
            run_as: PutAs::Root,
            check: PutCheck::None,
            source: PutSource::Command(PutCommand {
                mode: PutMode::Keep {
                    if_new: Mode::new("644").unwrap(),
                },
                producer: PutProducer::FstabSwapEntry {
                    path: "/swapfile".to_owned(),
                },
            }),
        });
        assert_eq!(steps.last(), Some(&put));
        assert_eq!(
            put.execution(),
            Some(StepExecution::Command(format!(
                "{guard} || {{ {}; }}",
                put_text_step_keeping_mode(
                    &fstab_with_entry("/etc/fstab", "/swapfile"),
                    RunAs::Root,
                    "/etc/fstab",
                    FileAttrs::mode("644"),
                    PutCheck::None,
                )
            )))
        );
        // Nothing appends to the table in place.
        assert!(
            !steps
                .iter()
                .filter_map(PlanStep::execution)
                .any(|execution| execution.text().contains("tee "))
        );
        assert!(!steps.iter().any(|s| matches!(s, PlanStep::Note(_))));
    }

    /// The fstab step's guard is the read the detector makes of the same table, and
    /// what it installs past the guard is the table with the entry that read then finds.
    #[test]
    fn the_fstab_step_is_guarded_by_the_detectors_read_of_the_table() {
        let path = "/sw'ap file";
        let guard = table_lists_path("/etc/fstab", path);
        let detector: Vec<String> = crate::observe::swap::queries(path)
            .into_iter()
            .filter_map(|query| match query {
                Query::Command { snippet, .. } => Some(snippet),
                Query::Path { .. } => None,
            })
            .collect();
        assert_eq!(
            detector.last(),
            Some(&format!("test -e /etc/fstab || exit 1; {guard}"))
        );
        let steps = swap_steps(
            &swap(serde_json::json!({"size": "1G", "path": path})),
            SwapParts::NONE,
        );
        let text = steps.last().unwrap().execution().unwrap().text().to_owned();
        assert!(text.starts_with(&format!("{guard} || {{ ")), "{text}");
        assert!(
            text.contains(&format!(
                "zap_c=$({} && echo .) || exit 1; ",
                fstab_with_entry("/etc/fstab", path)
            )),
            "{text}"
        );
    }

    #[test]
    fn fstab_guard_shell_escapes_a_quoting_path() {
        // A path with an embedded single quote must be `single_quote`-escaped on the
        // mutation side just as the detector's probe escapes it — otherwise the guard's
        // needle would break out of its quotes and the guard would misfire. The escaped
        // form of `/sw'ap` is `'/sw'\''ap'`, not the broken raw `'/sw'ap'`.
        let steps = swap_steps(
            &swap(serde_json::json!({"size": "1G", "path": "/sw'ap"})),
            SwapParts::NONE,
        );
        let fstab = steps
            .iter()
            .filter_map(PlanStep::execution)
            .map(|execution| execution.text().to_owned())
            .find(|c| c.contains("/etc/fstab"))
            .expect("a fstab guard step");
        // The `single_quote`-escaped needle, byte-identical to the detector's probe.
        assert!(
            fstab.contains(r"P='/sw'\''ap' awk "),
            "fstab guard needle is single_quote-escaped: {fstab}"
        );
        // The broken raw form (a bare `'/sw'ap'`) must not appear.
        assert!(
            !fstab.contains("P='/sw'ap'"),
            "fstab guard needle is not the broken raw interpolation: {fstab}"
        );
        // The added fstab line is escaped the same way.
        assert!(
            fstab.contains(r"printf '%s\n' '/sw'\''ap none swap sw 0 0'"),
            "fstab added line is single_quote-escaped: {fstab}"
        );
    }
}
