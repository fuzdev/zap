//! A scratch project a config can be evaluated from, a config written there, and the
//! `fgro` the tests evaluate with.

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

/// `tempfile::tempdir()`, its directory pinned to `0755` and made a project. zap
/// refuses to evaluate a config in a directory every user can write, which a bare temp
/// directory is under `umask 000`, and one with no project `package.json` above it.
pub fn tempdir() -> std::io::Result<tempfile::TempDir> {
    let dir = tempfile::tempdir()?;
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o755))?;
    write_file(
        dir.path().join("package.json"),
        r#"{"name": "zap-scratch", "private": true}"#,
    )?;
    Ok(dir)
}

/// `std::fs::write` of a config, the file pinned to `0644` (zap refuses a config file
/// every user can write, which a written file is under `umask 000`), and, when there is
/// a test `fgro` and the config has no lock yet, a lock pinning it ([`pin_lock`]).
pub fn write_config(path: impl AsRef<Path>, contents: impl AsRef<[u8]>) -> std::io::Result<()> {
    write_file(&path, contents)?;
    pin_lock(path.as_ref())
}

/// `std::fs::write`, the file pinned to `0644`.
fn write_file(path: impl AsRef<Path>, contents: impl AsRef<[u8]>) -> std::io::Result<()> {
    std::fs::write(&path, contents)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o644))
}

/// The `fgro` the tests evaluate with: `ZAP_FGRO`, when it names a file by an absolute
/// path. A test that evaluates a config checks nothing without it; the crate's
/// `tests/required_programs.rs` is the test that fails there.
pub fn fgro() -> Option<&'static Path> {
    static PATH: OnceLock<Option<PathBuf>> = OnceLock::new();
    PATH.get_or_init(|| {
        std::env::var_os("ZAP_FGRO")
            .map(PathBuf::from)
            .filter(|path| path.is_absolute() && path.is_file())
    })
    .as_deref()
}

/// The test `fgro`'s blake3, hashed once per test binary (on a thread of its own, so a
/// caller inside a runtime can ask). Panics without a test `fgro`.
#[expect(
    clippy::expect_used,
    reason = "test helpers outside `#[test]` fns panic on a failed setup or check"
)]
pub fn fgro_pin() -> &'static str {
    static PIN: OnceLock<String> = OnceLock::new();
    PIN.get_or_init(|| {
        let fgro = fgro().expect("ZAP_FGRO names an fgro build");
        std::thread::spawn(move || {
            tokio::runtime::Builder::new_current_thread()
                .build()
                .expect("a runtime")
                .block_on(zap_core::config::fgro::current_pin(fgro, None))
                .expect("hash the test fgro")
                .as_str()
                .to_owned()
        })
        .join()
        .expect("the hashing thread")
    })
}

/// Write a lock beside `config_path` that pins the test `fgro` and holds no entry, when
/// there is a test `fgro` and no lock stands there yet.
pub fn pin_lock(config_path: &Path) -> std::io::Result<()> {
    if fgro().is_none() {
        return Ok(());
    }
    let lock = zap_core::lock::lock_path_for(config_path);
    if std::fs::symlink_metadata(&lock).is_ok() {
        return Ok(());
    }
    write_file(
        lock,
        format!(
            "{{\"version\": 2, \"toolchain\": {{\"fgro_blake3\": \"{}\"}}, \"entries\": {{}}}}\n",
            fgro_pin()
        ),
    )
}
