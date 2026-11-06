//! A scratch directory for the tests that read what a write keeps or a directory made
//! inherits.
//!
//! Below a directory anyone may put an entry in (`/tmp`, a temp directory's usual
//! home), a write keeps nothing and a directory made takes no owner, so a test of what
//! is kept can't run under one. [`tempdir`] makes its directories in the build's target
//! directory, whatever `TMPDIR` says.

use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

/// `tempfile::tempdir()`, under `<target>/zap-test-scratch` (made `0755`, its own mode
/// pinned so the process umask can't open it). The target directory is found from the
/// test binary's own path, `<target>/<profile>/deps/`, so a `CARGO_TARGET_DIR` elsewhere
/// is followed and the source tree is never written. Panics when a directory above it
/// has its sticky bit set or is writable by every account: a target directory in one
/// can't run these tests.
pub fn tempdir() -> tempfile::TempDir {
    tempfile::tempdir_in(base()).unwrap()
}

fn base() -> &'static Path {
    static BASE: OnceLock<PathBuf> = OnceLock::new();
    BASE.get_or_init(|| {
        let exe = std::env::current_exe().unwrap();
        let deps = exe
            .parent()
            .filter(|deps| deps.file_name() == Some("deps".as_ref()))
            .unwrap_or_else(|| {
                panic!(
                    "{} is not in a `deps` directory, so no target directory to make \
                     scratch in was found",
                    exe.display()
                )
            });
        let base = deps
            .ancestors()
            .nth(2)
            .unwrap_or_else(|| panic!("{} has no target directory above it", deps.display()))
            .join("zap-test-scratch");
        std::fs::create_dir_all(&base).unwrap();
        std::fs::set_permissions(&base, std::fs::Permissions::from_mode(0o755)).unwrap();
        let base = base.canonicalize().unwrap();
        for dir in base.ancestors() {
            let mode = std::fs::metadata(dir).unwrap().mode();
            assert!(
                mode & 0o1002 == 0,
                "{} has its sticky bit set or is writable by every account, so nothing \
                 below it is kept; build with a target directory elsewhere",
                dir.display()
            );
        }
        base
    })
}
