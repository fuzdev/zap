//! What the command cores' tests share: a refused target, scratch directories and
//! configs, and the test `fgro`.

use std::path::Path;

/// A target no connection reaches, whose host and connecting user are secrets: what the
/// tests of each command's error masking run against.
pub(super) mod refused_target {
    use std::path::PathBuf;

    use zap_types::schema::ZapConfig;

    use crate::commands::PassContext;
    use crate::commands::target::bind_target;
    use crate::connection::Connection;
    use crate::connection::ssh::test_client::{self, Remote, TestClient};
    use crate::error::Error;
    use crate::resolve::test_env::{self, TestEnv};
    use crate::secret::SecretMasker;

    /// The host the target's reference resolves to.
    pub const HOST: &str = "10.9.8.7";
    /// The user the target's reference resolves to.
    pub const USER: &str = "opsuser";

    /// A config evaluated, gated and bound as [`eval_target`](crate::commands::eval_target) binds
    /// one, on a thread whose `ssh` refuses every connection and says who it was for.
    pub struct RefusedTarget {
        pub config: ZapConfig,
        pub conn: Connection,
        pub masker: SecretMasker,
        pub home: tempfile::TempDir,
        pub config_path: PathBuf,
        _env: TestEnv,
        _client: TestClient,
    }

    impl RefusedTarget {
        /// A target declaring `host` and `user` as secret references, managing
        /// `resources` and deploying, bound over a stand-in `ssh` that exits 255.
        pub fn new(resources: &serde_json::Value) -> Self {
            let env = test_env::set(&[
                ("ZAP_T_REFUSED_HOST_SECRET", HOST),
                ("ZAP_T_REFUSED_LOGIN_TOKEN", USER),
            ]);
            let config: ZapConfig = serde_json::from_value(serde_json::json!({
                "target": {
                    "host": {"$env": "ZAP_T_REFUSED_HOST_SECRET"},
                    "user": {"$env": "ZAP_T_REFUSED_LOGIN_TOKEN"},
                    "port": 1,
                },
                "resources": resources,
                "deploy": {"build": "make", "artifacts": ["build/"], "path": "/srv/app"},
            }))
            .unwrap();
            let home = tempfile::tempdir().unwrap();
            let client = test_client::set(home.path(), Remote::Refuse);
            let (conn, masker) = bind_target(&config, false).unwrap();
            Self {
                config_path: home.path().join("zap.ts"),
                config,
                conn,
                masker,
                home,
                _env: env,
                _client: client,
            }
        }

        /// The pass context of a command run over this target.
        pub fn ctx(&self) -> PassContext<'_> {
            PassContext {
                zap_home: Some(self.home.path()),
                config_path: &self.config_path,
                masker: &self.masker,
                bootstrap: false,
            }
        }
    }

    /// `error` is the connection failure, exit 1, and what it prints names the host and
    /// the user by their tokens — in zap's label and in what `ssh` said — never by value.
    pub fn assert_masked(command: &str, error: &Error) {
        assert!(
            matches!(error, Error::Connectivity { .. }),
            "{command}: {error:?}"
        );
        assert_eq!(error.exit_code(), 1, "{command}");
        let rendered = error.render();
        assert!(
            rendered.starts_with(
                "error: cannot connect to ssh://[MASKED:ZAP_T_REFUSED_LOGIN_TOKEN]@\
                 [MASKED:ZAP_T_REFUSED_HOST_SECRET]: ssh: connect to host failed ("
            ),
            "{command}: {rendered}"
        );
        assert!(
            rendered.contains(
                " [MASKED:ZAP_T_REFUSED_LOGIN_TOKEN]@[MASKED:ZAP_T_REFUSED_HOST_SECRET] "
            ),
            "{command}: {rendered}"
        );
        for secret in [HOST, USER] {
            assert!(!rendered.contains(secret), "{command}: {rendered}");
            assert!(
                !format!("{error:?}").contains(secret),
                "{command}: {error:?}"
            );
        }
    }
}

/// `tempfile::tempdir()`, its directory pinned to `0755` and made a project: the tests
/// evaluate configs from it, and zap refuses one in a directory every user can write,
/// which a bare temp directory is under `umask 000`, and one with no project
/// `package.json` above it.
pub(super) fn scratch_tempdir() -> std::io::Result<tempfile::TempDir> {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir()?;
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o755))?;
    write_scratch_file(
        dir.path().join("package.json"),
        r#"{"name": "zap-scratch", "private": true}"#,
    )?;
    Ok(dir)
}

/// `std::fs::write` of a config the tests evaluate, the file pinned to `0644`: zap
/// refuses a config file every user can write, which a written file is under
/// `umask 000`. Its lock is given the test `fgro`'s toolchain pin
/// ([`test_fgro::pin_lock`]), when there is a test `fgro`.
pub(super) fn scratch_write_config(
    path: impl AsRef<Path>,
    contents: impl AsRef<[u8]>,
) -> std::io::Result<()> {
    write_scratch_file(&path, contents)?;
    test_fgro::pin_lock(path.as_ref());
    Ok(())
}

/// `std::fs::write`, the file pinned to `0644`.
fn write_scratch_file(path: impl AsRef<Path>, contents: impl AsRef<[u8]>) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::write(&path, contents)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o644))
}

/// The `fgro` the tests that evaluate a config run: `ZAP_FGRO`, an absolute path to a
/// build. A test that needs it checks nothing without it; the crate's
/// `tests/required_programs.rs` is the test that fails there.
pub(super) mod test_fgro {
    use std::path::{Path, PathBuf};
    use std::sync::OnceLock;

    use zap_types::lock::{Toolchain, ZapLock};
    use zap_types::scalar::ContentHash;

    use crate::lock::{lock_path_for, read_zap_lock, write_zap_lock};

    /// `ZAP_FGRO`, when it names a file by an absolute path.
    pub fn path() -> Option<&'static Path> {
        static PATH: OnceLock<Option<PathBuf>> = OnceLock::new();
        PATH.get_or_init(|| {
            std::env::var_os("ZAP_FGRO")
                .map(PathBuf::from)
                .filter(|path| path.is_absolute() && path.is_file())
        })
        .as_deref()
    }

    /// Whether there is a test `fgro`.
    pub fn available() -> bool {
        path().is_some()
    }

    /// The test `fgro`, as a core takes it. `None` without one, which an eval refuses:
    /// pass it only past an [`available`] gate.
    pub fn fgro() -> Option<&'static Path> {
        path()
    }

    /// The test `fgro`. Panics without one.
    fn required() -> &'static Path {
        path().expect("ZAP_FGRO names an fgro build")
    }

    /// The test `fgro`'s blake3, hashed once per test binary.
    pub fn pin() -> &'static ContentHash {
        static PIN: OnceLock<ContentHash> = OnceLock::new();
        PIN.get_or_init(|| {
            ContentHash::new(fuz_eval::fgro_blake3(required(), None).expect("hash the test fgro"))
                .expect("a blake3")
        })
    }

    /// The toolchain pin of the test `fgro`, or `None` without one.
    pub fn toolchain() -> Option<Toolchain> {
        available().then(|| Toolchain {
            fgro_blake3: pin().clone(),
        })
    }

    /// Give `config_path`'s lock the test `fgro`'s toolchain pin, keeping whatever else
    /// it holds (a lock that doesn't read is left as it is). Nothing without a test
    /// `fgro`.
    pub fn pin_lock(config_path: &Path) {
        if !available() {
            return;
        }
        let path = lock_path_for(config_path);
        let Ok(lock) = read_zap_lock(&path) else {
            return;
        };
        let lock = ZapLock {
            toolchain: toolchain(),
            ..lock.unwrap_or_default()
        };
        write_zap_lock(&path, &lock).expect("write the test lock");
    }
}
