//! The preview a run recorded, and its withdrawal when the report that showed it never
//! arrived.
//!
//! A preview (`zap plan`, a dry `zap apply` or `zap deploy`, a refused wetrun) is
//! recorded by the engine as it renders the plan, before the binary writes the report.
//! When that write fails — a full device, a reader gone before the report reached it —
//! the binary withdraws the record, so the next wetrun without `--expect-plan` refuses
//! and asks for a preview instead of binding to a plan whose report never arrived. A
//! report that was written but not read (sent to `/dev/null`, cut short by `head` once
//! it was whole in the pipe) is no failed write, so its preview stands.
//!
//! The withdrawal is a compare-and-delete, never a blind delete: the record is taken
//! from its name (`crate::home::take_record`, one `rename`), and deleted only when it is
//! still the one this run wrote — the same command or pass, plan hash, and time to the
//! second. Anything else there (a later preview, a deploy preflight's report, a
//! wetrun's) is put back (`TakenRecord::restore`, a hard link that never overwrites a
//! newer file). What can go wrong fails closed, costing a new preview, never an
//! execution:
//!
//! - two runs that wrote the same record within one second can't be told apart, so one's
//!   withdrawal can take the other's;
//! - a wetrun that tries to claim the record while the withdrawal holds it finds the name
//!   empty and stops with nothing run (`Error::PreviewSpent`);
//! - a crash between the take and the delete or the put-back leaves the record under its
//!   taken name (`.<name>.taken.<pid>.<n>`), which no read looks at and nothing sweeps:
//!   the name stays empty, and the next wetrun refuses.
//!
//! One window stays open: a wetrun started while the report was still being written can
//! claim the record before the write fails, and runs as any wetrun bound to it would;
//! the withdrawal then finds the record spent, and leaves whatever stands there. And a
//! run stopped between its record and the end of its write (a signal; nothing here
//! catches one) withdraws nothing, so its record binds as one whose report arrived.
//!
//! The record is deleted rather than kept with its plan hash cleared: a cleared one
//! would make the next refusal say the last run previewed no plan, when it did. The cost
//! is that `zap status` has no report for that host until the next pass.

use std::path::{Path, PathBuf};

use zap_types::deploy_preview::DeployPreviewPass;
use zap_types::last_run::RunCommand;

use crate::deploy_preview::read_deploy_preview_file;
use crate::home::take_record;
use crate::last_run::read_last_run_file;

/// A preview a run recorded: where its record is, and what identifies it as this run's.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordedPreview {
    /// The record's file.
    path: PathBuf,
    /// What the record holds that identifies it.
    record: Record,
}

/// What identifies a recorded preview as one run's.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Record {
    /// A last-run report that previewed a plan.
    LastRun {
        /// The pass that wrote it.
        command: RunCommand,
        /// The plan it previewed.
        plan_hash: String,
        /// When, to the second.
        ran_at: String,
    },
    /// A deploy preview.
    Deploy {
        /// The pass that wrote it.
        pass: DeployPreviewPass,
        /// The host it is for, which its read checks.
        host: String,
        /// The plan it previewed.
        plan_hash: String,
        /// When, to the second.
        ran_at: String,
    },
}

/// What [`RecordedPreview::withdraw`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Withdrawal {
    /// The record was this run's, and is gone.
    Withdrawn,
    /// Another record stands at its name now, and was left there.
    Superseded,
    /// Nothing stands at its name.
    Gone,
}

impl RecordedPreview {
    /// The last-run report at `path`, written by `command` at `ran_at` with `plan_hash`.
    pub(crate) const fn last_run(
        path: PathBuf,
        command: RunCommand,
        plan_hash: String,
        ran_at: String,
    ) -> Self {
        Self {
            path,
            record: Record::LastRun {
                command,
                plan_hash,
                ran_at,
            },
        }
    }

    /// The deploy preview at `path`, written by `pass` for `host` at `ran_at` with
    /// `plan_hash`.
    pub(crate) const fn deploy(
        path: PathBuf,
        pass: DeployPreviewPass,
        host: String,
        plan_hash: String,
        ran_at: String,
    ) -> Self {
        Self {
            path,
            record: Record::Deploy {
                pass,
                host,
                plan_hash,
                ran_at,
            },
        }
    }

    /// Withdraw the record, when it is still this run's (module docs).
    ///
    /// # Errors
    /// The underlying [`std::io::Error`] when something stands at the record's name and
    /// can't be taken.
    pub fn withdraw(&self) -> std::io::Result<Withdrawal> {
        let Some(taken) = take_record(&self.path)? else {
            return Ok(Withdrawal::Gone);
        };
        if self.is_held_at(taken.held()) {
            drop(taken);
            Ok(Withdrawal::Withdrawn)
        } else {
            taken.restore();
            Ok(Withdrawal::Superseded)
        }
    }

    /// Whether the record in the file at `held` is this one.
    fn is_held_at(&self, held: &Path) -> bool {
        match &self.record {
            Record::LastRun {
                command,
                plan_hash,
                ran_at,
            } => read_last_run_file(held).is_some_and(|report| {
                report.command == *command
                    && report.plan_hash.as_ref() == Some(plan_hash)
                    && report.ran_at == *ran_at
            }),
            Record::Deploy {
                pass,
                host,
                plan_hash,
                ran_at,
            } => read_deploy_preview_file(held, host).is_some_and(|preview| {
                preview.pass == *pass
                    && preview.plan_hash == *plan_hash
                    && preview.ran_at == *ran_at
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::path::Path;

    use zap_types::deploy_preview::DeployPreviewPass;
    use zap_types::last_run::{LAST_RUN_VERSION, LastRun, RunCommand};

    use super::{RecordedPreview, Withdrawal};
    use crate::deploy_preview::{new_deploy_preview, write_deploy_preview};
    use crate::home::{deploy_preview_path_for, last_run_path_for};
    use crate::last_run::write_last_run;

    const HOST: &str = "box.example";
    const RAN_AT: &str = "2026-01-02T03:04:05Z";

    fn report(command: RunCommand, plan_hash: Option<&str>, ran_at: &str) -> LastRun {
        LastRun {
            version: LAST_RUN_VERSION,
            ran_at: ran_at.to_owned(),
            command,
            host: HOST.to_owned(),
            target_hash: None,
            unverifiable: Vec::new(),
            plan_hash: plan_hash.map(str::to_owned),
            resources: BTreeMap::new(),
            batches: Vec::new(),
        }
    }

    /// What a directory holds, by name: the withdrawal leaves no taken copy behind.
    fn names(dir: &Path) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(dir)
            .map(|entries| {
                entries
                    .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
                    .collect()
            })
            .unwrap_or_default();
        names.sort();
        names
    }

    /// A last-run preview is withdrawn only while it is still the record this run
    /// wrote: the same command, plan hash, and time. Any other record at its name — a
    /// later preview of the same plan, another plan, another pass, one that previewed
    /// nothing — is put back as it was, and nothing at all is nothing to withdraw.
    #[test]
    fn a_last_run_preview_is_withdrawn_only_while_it_is_this_runs() {
        let home = tempfile::tempdir().unwrap();
        let config = home.path().join("zap.ts");
        let path = last_run_path_for(home.path(), &config, HOST);
        let ours = RecordedPreview::last_run(
            path.clone(),
            RunCommand::Apply,
            "aaaa".to_owned(),
            RAN_AT.to_owned(),
        );
        assert_eq!(ours.withdraw().unwrap(), Withdrawal::Gone);

        write_last_run(
            home.path(),
            &config,
            &report(RunCommand::Apply, Some("aaaa"), RAN_AT),
        )
        .unwrap();
        let dir = path.parent().unwrap().to_owned();
        let before = names(&dir);
        assert_eq!(ours.withdraw().unwrap(), Withdrawal::Withdrawn);
        assert!(!path.exists());
        assert_eq!(
            names(&dir),
            before
                .iter()
                .filter(|name| **name != path.file_name().unwrap().to_string_lossy())
                .cloned()
                .collect::<Vec<_>>()
        );

        for theirs in [
            report(RunCommand::Apply, Some("aaaa"), "2026-01-02T03:04:06Z"),
            report(RunCommand::Apply, Some("bbbb"), RAN_AT),
            report(RunCommand::Plan, Some("aaaa"), RAN_AT),
            report(RunCommand::ApplyRefused, Some("aaaa"), RAN_AT),
            report(RunCommand::Apply, None, RAN_AT),
            report(RunCommand::ApplyAfterChanges, Some("aaaa"), RAN_AT),
        ] {
            write_last_run(home.path(), &config, &theirs).unwrap();
            let bytes = std::fs::read(&path).unwrap();
            let before = names(&dir);
            assert_eq!(
                ours.withdraw().unwrap(),
                Withdrawal::Superseded,
                "{theirs:?}"
            );
            assert_eq!(std::fs::read(&path).unwrap(), bytes, "{theirs:?}");
            assert_eq!(names(&dir), before, "{theirs:?}");
        }
    }

    /// A deploy preview is withdrawn the same way: only while it is the pass, plan, and
    /// time this run recorded.
    #[test]
    fn a_deploy_preview_is_withdrawn_only_while_it_is_this_runs() {
        let home = tempfile::tempdir().unwrap();
        let config = home.path().join("zap.ts");
        let path = deploy_preview_path_for(home.path(), &config, HOST);
        let written = |pass, plan_hash: &str, ran_at: &str| {
            let mut preview = new_deploy_preview(pass, HOST, plan_hash);
            ran_at.clone_into(&mut preview.ran_at);
            write_deploy_preview(home.path(), &config, &preview).unwrap();
        };
        let ours = RecordedPreview::deploy(
            path.clone(),
            DeployPreviewPass::DryRun,
            HOST.to_owned(),
            "aaaa".to_owned(),
            RAN_AT.to_owned(),
        );
        for (pass, plan_hash, ran_at) in [
            (DeployPreviewPass::RefusedWetrun, "aaaa", RAN_AT),
            (DeployPreviewPass::DryRun, "bbbb", RAN_AT),
            (DeployPreviewPass::DryRun, "aaaa", "2026-01-02T03:04:06Z"),
        ] {
            written(pass, plan_hash, ran_at);
            let bytes = std::fs::read(&path).unwrap();
            assert_eq!(ours.withdraw().unwrap(), Withdrawal::Superseded);
            assert_eq!(std::fs::read(&path).unwrap(), bytes);
        }
        written(DeployPreviewPass::DryRun, "aaaa", RAN_AT);
        assert_eq!(ours.withdraw().unwrap(), Withdrawal::Withdrawn);
        assert!(!path.exists());
        assert_eq!(names(path.parent().unwrap()), Vec::<String>::new());
        assert_eq!(ours.withdraw().unwrap(), Withdrawal::Gone);
    }
}
