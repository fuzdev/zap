//! The deploy preview's IO. The shape and the rule are [`zap_types::deploy_preview`].
//!
//! Record the plan a deploy pass rendered, and read it back for the next wetrun's
//! review. A deploy that is about to execute takes it away first
//! (`crate::commands::detect_pass::spend_review`).
//!
//! Latest-only, one file per config and host (`crate::home::deploy_preview_path_for`),
//! beside the last-run report and apart from it: a detection pass never writes here, and
//! a deploy preview never writes there, so `zap plan` and `zap deploy` each keep the
//! review their own wetrun binds to. Written owner-only through
//! `crate::home::write_atomic`.
//!
//! A file here is read as untrusted text: anything but a current-version record for the
//! host asked about is no preview, and a wetrun that finds none refuses.

use std::io::Read as _;
use std::path::Path;

use zap_types::deploy_preview::{DEPLOY_PREVIEW_VERSION, DeployPreview, DeployPreviewPass};

use crate::home::{
    deploy_preview_dir_for, deploy_preview_file_name, deploy_preview_path_for, write_atomic,
};
use crate::last_run::now_rfc3339;

/// The most a record file is read. A record is a few short fields; a larger file is not
/// one.
const MAX_RECORD_BYTES: u64 = 16 * 1024;

/// The record of `pass` having rendered the plan `plan_hash` for `host`, taken now.
#[must_use]
pub fn new_deploy_preview(pass: DeployPreviewPass, host: &str, plan_hash: &str) -> DeployPreview {
    DeployPreview {
        version: DEPLOY_PREVIEW_VERSION,
        ran_at: now_rfc3339(),
        pass,
        host: host.to_owned(),
        plan_hash: plan_hash.to_owned(),
    }
}

/// Write `preview` as the config's deploy preview on its host, replacing any earlier one.
///
/// # Errors
/// The underlying [`std::io::Error`] if the record can't be serialized or written. A
/// preview that isn't recorded binds no wetrun, so the caller says so.
pub fn write_deploy_preview(
    zap_home: &Path,
    config_path: &Path,
    preview: &DeployPreview,
) -> std::io::Result<()> {
    let json = serde_json::to_vec_pretty(preview).map_err(std::io::Error::other)?;
    write_atomic(
        zap_home,
        &deploy_preview_dir_for(zap_home, config_path),
        &deploy_preview_file_name(&preview.host),
        &json,
    )
}

/// The config's deploy preview on `host` (the plan's host label), when there is one.
///
/// `None` for no file, an unreadable or oversized one, one that isn't a current-version
/// record ([`DeployPreview::parse`]), or one that names another host.
#[must_use]
pub fn read_deploy_preview(
    zap_home: &Path,
    config_path: &Path,
    host: &str,
) -> Option<DeployPreview> {
    read_deploy_preview_file(&deploy_preview_path_for(zap_home, config_path, host), host)
}

/// The deploy preview on `host` in the file at `path`, read as [`read_deploy_preview`]
/// reads one.
#[must_use]
pub(crate) fn read_deploy_preview_file(path: &Path, host: &str) -> Option<DeployPreview> {
    let file = std::fs::File::open(path).ok()?;
    let mut bytes = Vec::new();
    file.take(MAX_RECORD_BYTES + 1)
        .read_to_end(&mut bytes)
        .ok()?;
    if bytes.len() as u64 > MAX_RECORD_BYTES {
        return None;
    }
    DeployPreview::parse(&bytes).filter(|preview| preview.host == host)
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use zap_types::deploy_preview::{DEPLOY_PREVIEW_VERSION, DeployPreviewPass};

    use super::{MAX_RECORD_BYTES, new_deploy_preview, read_deploy_preview, write_deploy_preview};
    use crate::home::deploy_preview_path_for;

    const HOST: &str = "app.example.com";

    #[test]
    fn a_written_preview_reads_back_until_a_later_one_replaces_it() {
        let home = tempfile::tempdir().unwrap();
        let config_path = Path::new("/tmp/proj/zap.ts");
        assert_eq!(read_deploy_preview(home.path(), config_path, HOST), None);

        let preview = new_deploy_preview(DeployPreviewPass::DryRun, HOST, "abc");
        assert_eq!(preview.version, DEPLOY_PREVIEW_VERSION);
        assert_eq!(preview.ran_at.len(), "2026-09-28T12:00:00Z".len());
        write_deploy_preview(home.path(), config_path, &preview).unwrap();
        assert_eq!(
            read_deploy_preview(home.path(), config_path, HOST),
            Some(preview)
        );
        // Per host, and per config.
        assert_eq!(
            read_deploy_preview(home.path(), config_path, "other.example.com"),
            None
        );
        assert_eq!(
            read_deploy_preview(home.path(), Path::new("/tmp/other/zap.ts"), HOST),
            None
        );

        // A later preview replaces it.
        let later = new_deploy_preview(DeployPreviewPass::RefusedWetrun, HOST, "def");
        write_deploy_preview(home.path(), config_path, &later).unwrap();
        assert_eq!(
            read_deploy_preview(home.path(), config_path, HOST),
            Some(later)
        );
    }

    /// A file that isn't a current-version record for this host is no preview: corrupt
    /// bytes, another version, a record naming another host, and one past the size a
    /// record has.
    #[test]
    fn a_file_that_is_not_this_hosts_current_record_is_no_preview() {
        let home = tempfile::tempdir().unwrap();
        let config_path = Path::new("/tmp/proj/zap.ts");
        let path = deploy_preview_path_for(home.path(), config_path, HOST);
        let preview = new_deploy_preview(DeployPreviewPass::DryRun, HOST, "abc");
        write_deploy_preview(home.path(), config_path, &preview).unwrap();
        let good = std::fs::read(&path).unwrap();
        let read = || read_deploy_preview(home.path(), config_path, HOST);
        assert_eq!(read(), Some(preview.clone()));

        std::fs::write(&path, b"{\"version\": 1, \"plan_hash\": \"abc\"").unwrap();
        assert_eq!(read(), None, "truncated");

        let mut value: serde_json::Value = serde_json::from_slice(&good).unwrap();
        value["version"] = serde_json::json!(DEPLOY_PREVIEW_VERSION + 1);
        std::fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
        assert_eq!(read(), None, "another version");

        let mut value: serde_json::Value = serde_json::from_slice(&good).unwrap();
        value["host"] = serde_json::json!("other.example.com");
        std::fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
        assert_eq!(read(), None, "another host's record");

        // Valid JSON for this host, padded past the bound with whitespace.
        let mut padded = good.clone();
        padded.resize(usize::try_from(MAX_RECORD_BYTES).unwrap() + 1, b' ');
        std::fs::write(&path, &padded).unwrap();
        assert_eq!(read(), None, "oversized");

        std::fs::write(&path, &good).unwrap();
        assert_eq!(read(), Some(preview));
    }

    #[cfg(unix)]
    #[test]
    fn a_preview_and_its_directories_are_owner_only() {
        use std::os::unix::fs::PermissionsExt as _;

        let home = tempfile::tempdir().unwrap();
        let config_path = Path::new("/tmp/proj/zap.ts");
        let preview = new_deploy_preview(DeployPreviewPass::DryRun, HOST, "abc");
        write_deploy_preview(home.path(), config_path, &preview).unwrap();
        let path = deploy_preview_path_for(home.path(), config_path, HOST);
        let mode = |path: &Path| std::fs::metadata(path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&path), 0o600);
        let dir = path.parent().unwrap();
        assert_eq!(mode(dir), 0o700);
        // The config's own directory above it, which the write hardens too.
        assert_eq!(mode(dir.parent().unwrap()), 0o700);
    }
}
