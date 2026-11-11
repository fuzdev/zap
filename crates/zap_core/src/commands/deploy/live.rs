//! The reads of what the target serves: the live release `current` names, and whether
//! that release is on the host.

use zap_types::shell::single_quote;

use crate::connection::{Connection, RunOptions};
use crate::error::Result;

/// `server_version`'s exit for "nothing at `current`".
const NOT_DEPLOYED_EXIT: i32 = 3;
/// `server_version`'s exit for a `current` that exists but isn't a symlink.
const NOT_A_LINK_EXIT: i32 = 4;

/// The read `server_version` runs: `readlink` of `current` when it is a link, else exit
/// [`NOT_A_LINK_EXIT`] when something else is there, or [`NOT_DEPLOYED_EXIT`] when
/// nothing is.
pub(super) fn server_version_command(app_path: &str) -> String {
    let current = single_quote(&format!("{app_path}/current"));
    format!(
        "if [ -L {current} ]; then readlink -- {current}; elif [ -e {current} ]; then exit {NOT_A_LINK_EXIT}; else exit {NOT_DEPLOYED_EXIT}; fi"
    )
}

/// Why [`server_version`] read no live release.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum LiveReadError {
    /// The read itself failed: the command didn't run, or `readlink` failed.
    Unreadable(String),
    /// Something that isn't a symbolic link is at `current`.
    NotALink(String),
    /// `current` is a link, and what it names is no release's name.
    NoRelease(String),
}

impl std::fmt::Display for LiveReadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unreadable(message) | Self::NotALink(message) | Self::NoRelease(message) => {
                f.write_str(message)
            }
        }
    }
}

/// The version currently serving on the target, derived from the live `current`
/// symlink (`{app_path}/current` → `releases/<version>`; the release dir is named
/// by version, so the basename *is* the live version). Trailing slashes are dropped,
/// and a basename that is no release's name (`zap_types::deploy::release_of_link`) is
/// [`LiveReadError::NoRelease`]: a `.` segment or a path below a release would name a
/// release by a word that isn't its, which the rollback and the prune would then not
/// know.
///
/// `Ok(None)` means the symlink isn't there — a host that has never been deployed to.
/// [`LiveReadError::Unreadable`] means the read itself failed, and
/// [`LiveReadError::NotALink`] that something else is at `current`; neither is the same
/// thing and must not be silently folded into it: this value is the auto-rollback's only
/// target, so a swallowed error would disarm the post-swap safety net (and mislabel the
/// failure as "no previous release is known") on a host that in fact has one. The caller
/// surfaces it before shipping, while the operator can still act.
///
/// The symlink is authoritative — it reflects an out-of-band rollback (a manual
/// `ln -sfn` of `current`), which `deploy_info.json` cannot: that file is stamped
/// at swap time and a later rollback never rewrites it, so it drifts from reality.
/// Reading the swap target keeps "previous" honest about what's actually serving.
pub(super) async fn server_version(
    target: &Connection,
    app_path: &str,
) -> std::result::Result<Option<String>, LiveReadError> {
    let cmd = server_version_command(app_path);
    let out = target
        .run(&cmd, &RunOptions::default())
        .await
        .map_err(|error| LiveReadError::Unreadable(error.to_string()))?;
    // Exit 3 is the command *working* and finding nothing at `current` — not deployed
    // yet. Anything else that isn't success (a `current` that isn't a link, a `readlink`
    // that failed, ssh's 255) is a failed read; an `app_path` the user can't search reads
    // as nothing there.
    if out.code == NOT_DEPLOYED_EXIT {
        return Ok(None);
    }
    if !out.success {
        let stderr = out.stderr.trim();
        return Err(if out.code == NOT_A_LINK_EXIT {
            LiveReadError::NotALink(format!("{app_path}/current exists but is not a symlink"))
        } else {
            LiveReadError::Unreadable(format!(
                "couldn't read {app_path}/current (exit {}): {stderr}",
                out.code
            ))
        });
    }
    let link = out.stdout.strip_suffix('\n').unwrap_or(&out.stdout);
    zap_types::deploy::release_of_link(link)
        .map(|version| Some(version.to_owned()))
        .ok_or_else(|| {
            LiveReadError::NoRelease(format!(
                "{app_path}/current names {link}, which is no release (releases/<version>)"
            ))
        })
}

/// Whether `current` resolves to a release directory on the target: `false` for a link
/// whose release is missing.
pub(super) async fn live_release_present(target: &Connection, app_path: &str) -> Result<bool> {
    let cmd = format!("test -d {}", single_quote(&format!("{app_path}/current")));
    Ok(target.run(&cmd, &RunOptions::default()).await?.success)
}
