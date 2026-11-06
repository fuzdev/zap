//! The deploy preview — the record of the deploy plan last shown for review, per config
//! and host: its on-disk shape, its version gate, and the rule a deploy wetrun binds
//! under.
//!
//! A deploy pass that renders a plan and executes none of it — a dry run, a refused
//! wetrun — writes one, latest-only. A deploy wetrun without `--expect-plan` executes
//! only when the plan it computes is the recorded one ([`review_deploy_plan`]). It is a
//! record of its own, apart from the last-run report: that one is what a detection pass
//! read and what `apply` binds to, and neither command's preview replaces the other's.
//! The IO (the path under `~/.zap`, the atomic write, the clock, the removal before a
//! deploy executes) is `zap_core`'s; this module is the contract.
//!
//! It holds the plan's hash, never the plan: nothing a config resolves to is persisted.

use std::convert::Infallible;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::last_run::{PassLabel, PlanUnreviewed, Recorded, review_against};

/// The record format's version. A file whose `version` isn't this one is read as **no
/// preview**, never interpreted.
///
/// Bump on any change to [`DeployPreview`]'s shape or to what a field means.
pub const DEPLOY_PREVIEW_VERSION: u32 = 1;

/// The deploy pass that wrote a preview — each rendered the whole plan and ran none of
/// it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeployPreviewPass {
    /// A dry-run `zap deploy`.
    DryRun,
    /// `zap deploy --wetrun` that refused to execute because its plan wasn't the
    /// reviewed one.
    RefusedWetrun,
}

impl DeployPreviewPass {
    /// How the pass renders in a refusal.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::DryRun => "zap deploy (dry run)",
            Self::RefusedWetrun => {
                "zap deploy --wetrun, refused (its plan was not the reviewed one)"
            }
        }
    }
}

impl PassLabel for DeployPreviewPass {
    fn label(self) -> &'static str {
        Self::label(self)
    }
}

/// The deploy preview for one config and host — the file's whole contents.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeployPreview {
    /// Always [`DEPLOY_PREVIEW_VERSION`] for a record this zap writes.
    pub version: u32,
    /// When the pass rendered the plan, RFC 3339 UTC (the operator machine's clock).
    pub ran_at: String,
    /// The pass that rendered it.
    pub pass: DeployPreviewPass,
    /// The host the plan is for, as the plan names it
    /// ([`DeployPlan::host`](crate::deploy::DeployPlan::host)) — the label the record is
    /// filed under.
    pub host: String,
    /// The content address of the plan that was rendered
    /// ([`deploy_plan_hash`](crate::config_hash::deploy_plan_hash)).
    pub plan_hash: String,
}

impl DeployPreview {
    /// Parse a record file's bytes: `None` for anything that isn't a current-version
    /// record — unparseable bytes, a missing or different `version`, or a shape this
    /// version doesn't read.
    ///
    /// The version is checked before the shape, so a file from another format is never
    /// misread as a preview even where its fields happen to fit.
    #[must_use]
    pub fn parse(bytes: &[u8]) -> Option<Self> {
        let value: Value = serde_json::from_slice(bytes).ok()?;
        let version = value.get("version")?.as_u64()?;
        if version != u64::from(DEPLOY_PREVIEW_VERSION) {
            return None;
        }
        serde_json::from_value(value).ok()
    }
}

/// Why a deploy wetrun refused to execute.
///
/// Only previews write a [`DeployPreview`], so there is no recorded pass that previewed
/// nothing: a [`NoPreview`](PlanUnreviewed::NoPreview) always means nothing is recorded.
pub type DeployUnreviewed = PlanUnreviewed<DeployPreviewPass, Infallible>;

/// Whether a deploy wetrun's `fresh` plan is the reviewed one — the review it requires
/// before the drift preflight and any step.
///
/// An explicit `expected` hash (`--expect-plan`) binds alone: it must equal `fresh`, and
/// `recorded` isn't consulted. Otherwise `recorded` — the host's preview, when there is
/// one — must hold `fresh`. Pure: the caller reads the record and computes the hash.
///
/// # Errors
/// The [`DeployUnreviewed`] reason, which the caller renders beside the fresh plan.
pub fn review_deploy_plan(
    fresh: &str,
    expected: Option<&str>,
    recorded: Option<&DeployPreview>,
) -> Result<(), DeployUnreviewed> {
    review_against(
        fresh,
        expected,
        recorded.map_or(Recorded::Nothing, |preview| Recorded::Preview {
            plan_hash: &preview.plan_hash,
            command: preview.pass,
            ran_at: &preview.ran_at,
        }),
    )
}

#[cfg(test)]
mod tests {
    use super::{
        DEPLOY_PREVIEW_VERSION, DeployPreview, DeployPreviewPass, DeployUnreviewed,
        review_deploy_plan,
    };

    fn preview() -> DeployPreview {
        DeployPreview {
            version: DEPLOY_PREVIEW_VERSION,
            ran_at: "2026-09-28T12:00:00Z".to_owned(),
            pass: DeployPreviewPass::DryRun,
            host: "app.example.com".to_owned(),
            plan_hash: "p".to_owned(),
        }
    }

    /// With no `--expect-plan` the wetrun binds to the recorded preview: the same hash
    /// executes, no record is no review, and another hash says which pass rendered it
    /// and when.
    #[test]
    fn a_deploy_binds_to_the_recorded_preview() {
        assert_eq!(review_deploy_plan("p", None, Some(&preview())), Ok(()));
        assert_eq!(
            review_deploy_plan("p", None, None),
            Err(DeployUnreviewed::NoPreview { prior: None })
        );
        for pass in [DeployPreviewPass::DryRun, DeployPreviewPass::RefusedWetrun] {
            let recorded = DeployPreview { pass, ..preview() };
            assert_eq!(review_deploy_plan("p", None, Some(&recorded)), Ok(()));
            assert_eq!(
                review_deploy_plan("q", None, Some(&recorded)),
                Err(DeployUnreviewed::Changed {
                    reviewed: "p".to_owned(),
                    command: pass,
                    ran_at: "2026-09-28T12:00:00Z".to_owned(),
                })
            );
        }
    }

    /// `--expect-plan` decides by itself: a recorded preview of the fresh plan doesn't
    /// rescue a wrong hash, and a recorded preview of another plan doesn't refuse the
    /// right one.
    #[test]
    fn an_explicit_hash_binds_alone() {
        assert_eq!(review_deploy_plan("p", Some("p"), None), Ok(()));
        let other = DeployPreview {
            plan_hash: "other".to_owned(),
            ..preview()
        };
        assert_eq!(review_deploy_plan("p", Some("p"), Some(&other)), Ok(()));
        assert_eq!(
            review_deploy_plan("p", Some("q"), Some(&preview())),
            Err(DeployUnreviewed::Expected {
                expected: "q".to_owned()
            })
        );
    }

    #[test]
    fn a_preview_round_trips() {
        let bytes = serde_json::to_vec(&preview()).unwrap();
        assert_eq!(DeployPreview::parse(&bytes), Some(preview()));
        assert_eq!(
            serde_json::to_value(preview()).unwrap(),
            serde_json::json!({
                "version": 1, "ran_at": "2026-09-28T12:00:00Z", "pass": "dry_run",
                "host": "app.example.com", "plan_hash": "p",
            })
        );
    }

    /// Anything but a current-version record is no preview: another version, no
    /// version, a pass this version doesn't name, a field it doesn't hold, a last-run
    /// report, and bytes that aren't JSON.
    #[test]
    fn anything_but_a_current_record_is_no_preview() {
        let parse =
            |value: &serde_json::Value| DeployPreview::parse(&serde_json::to_vec(value).unwrap());
        let current = serde_json::to_value(preview()).unwrap();
        assert_eq!(parse(&current), Some(preview()));

        let mut other_version = current.clone();
        other_version["version"] = serde_json::json!(DEPLOY_PREVIEW_VERSION + 1);
        assert_eq!(parse(&other_version), None);
        let mut unversioned = current.clone();
        unversioned.as_object_mut().unwrap().remove("version");
        assert_eq!(parse(&unversioned), None);
        let mut other_pass = current.clone();
        other_pass["pass"] = serde_json::json!("deployed");
        assert_eq!(parse(&other_pass), None);
        let mut extra = current.clone();
        extra["resources"] = serde_json::json!({});
        assert_eq!(parse(&extra), None);
        let mut no_hash = current;
        no_hash.as_object_mut().unwrap().remove("plan_hash");
        assert_eq!(parse(&no_hash), None);

        let last_run = serde_json::json!({
            "version": 1, "ran_at": "2026-09-28T12:00:00Z", "command": "plan",
            "host": "app.example.com", "target_hash": null, "unverifiable": [],
            "plan_hash": "p", "resources": {}, "batches": [],
        });
        assert_eq!(parse(&last_run), None);
        assert_eq!(DeployPreview::parse(b"not json"), None);
        assert_eq!(DeployPreview::parse(b""), None);
    }
}
