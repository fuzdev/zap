//! The oracle a run compares against when `--oracle <path>` names none: a release build
//! of a committed revision — `origin/main` unless `--oracle-rev` names another — kept as
//! `~/.zap/oracle/zap-<short-rev>` and built only when that file isn't there.
//!
//! `origin/main` rather than HEAD's upstream: the oracle is what landed, and `main` is
//! where work lands, whatever branch the working tree has checked out — a feature
//! branch's upstream is the branch itself, which hasn't. The ref is read as it stands
//! locally; nothing is fetched.
//!
//! A build is the one an operator would make by hand: the revision's tree from
//! `git archive` in a temporary directory under the harness's cache dir, beside a link
//! to each sibling checkout its manifest names by path (`../fuz`), then
//! `cargo build --release -p zap` there and the executable copied into place.
//! `CARGO_BUILD_JOBS` is cargo's own to read; the target directory is the tree's own,
//! so nothing lands in the working tree's; and the toolchain is the revision's own
//! `rust-toolchain.toml`, not the one `cargo xtask` runs under. A sibling is linked as
//! it stands, uncommitted changes and all, not at the revision: the oracle is the
//! revision's zap over today's siblings. Deleting the kept file forces a rebuild.
//!
//! The temporary directory, named for the harness's pid, goes when the build ends,
//! whether it succeeded or not; one an interrupted build left is swept by the next
//! build once its process is gone.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

/// The revision the oracle is built from when neither `--oracle` nor `--oracle-rev` is
/// given.
pub const DEFAULT_REV: &str = "origin/main";

/// What an oracle build's temporary directory is named for, before the harness's pid.
const BUILD_DIR_PREFIX: &str = "oracle-build-";

/// Where a run's oracle comes from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OracleSource {
    /// A binary the operator named (`--oracle <path>`).
    Binary(PathBuf),
    /// A release build of a revision (`--oracle-rev <rev>`, by default [`DEFAULT_REV`]).
    Rev(String),
}

/// What [`ensure`] found or made.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevOracle {
    /// The revision as asked for (`origin/main`).
    pub rev: String,
    /// The commit it named, abbreviated as the file name carries it.
    pub short: String,
    /// The binary.
    pub path: PathBuf,
    /// Whether this call built it (else it was already there).
    pub built: bool,
}

impl RevOracle {
    /// The line the run prints for it.
    pub fn describe(&self) -> String {
        format!(
            "oracle rev {} = {} ({} {})",
            self.rev,
            self.short,
            if self.built { "built" } else { "reused" },
            self.path.display()
        )
    }
}

/// The directory rev-built oracles are kept in: `<home>/.zap/oracle`.
pub fn oracle_dir(home: &Path) -> PathBuf {
    home.join(".zap").join("oracle")
}

/// The file name of the oracle built from the commit abbreviated `short`.
pub fn oracle_file_name(short: &str) -> String {
    format!("zap-{short}")
}

/// The oracle for `rev` in `repo`: `<home>/.zap/oracle/zap-<short>` when it is there,
/// else built from the commit `rev` names in a temporary directory under `cache`.
///
/// # Errors
/// `rev` doesn't name one commit, or the build fails.
pub fn ensure(repo: &Path, rev: &str, home: &Path, cache: &Path) -> Result<RevOracle, String> {
    let (sha, short) = resolve_rev(repo, rev)?;
    let path = oracle_dir(home).join(oracle_file_name(&short));
    let built = if path.is_file() {
        false
    } else {
        build(repo, &sha, &path, cache)?;
        true
    };
    Ok(RevOracle {
        rev: rev.to_owned(),
        short,
        path,
        built,
    })
}

/// The commit `rev` names in `repo`, in full and abbreviated (at least seven
/// characters, more where seven would be ambiguous). A revision that names none, or
/// is ambiguous, fails with git's own words.
fn resolve_rev(repo: &Path, rev: &str) -> Result<(String, String), String> {
    if rev.starts_with('-') {
        return Err(format!("oracle revision `{rev}` is not a revision"));
    }
    let sha = git(
        repo,
        &["rev-parse", "--verify", &format!("{rev}^{{commit}}")],
    )
    .map_err(|error| format!("oracle revision `{rev}` doesn't name one commit: {error}"))?;
    let short = git(repo, &["rev-parse", "--short=7", &sha])?;
    Ok((sha, short))
}

/// Run `git` in `repo` and return its stdout, trimmed.
fn git(repo: &Path, args: &[&str]) -> Result<String, String> {
    let output = Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(args)
        .stdin(Stdio::null())
        .output()
        .map_err(|error| format!("failed to run git: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "git {} failed ({}): {}",
            args.join(" "),
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

/// The sibling checkouts a workspace manifest names by relative path: the first
/// component of every `path = "../<name>/…"` in it.
fn sibling_dirs(manifest: &str) -> BTreeSet<String> {
    manifest
        .lines()
        .flat_map(|line| {
            line.match_indices("path").filter_map(|(at, key)| {
                let rest = line[at + key.len()..].trim_start().strip_prefix('=')?;
                let rest = rest.trim_start().strip_prefix("\"../")?;
                let name = rest.split(['/', '"']).next()?;
                (!name.is_empty() && name != "." && name != "..").then(|| name.to_owned())
            })
        })
        .collect()
}

/// Build commit `sha` of `repo` in a temporary directory under `cache` and install
/// its `zap` at `dest`.
fn build(repo: &Path, sha: &str, dest: &Path, cache: &Path) -> Result<(), String> {
    std::fs::create_dir_all(cache)
        .map_err(|error| format!("creating {} failed: {error}", cache.display()))?;
    super::fixture::sweep_dead_dirs(cache, BUILD_DIR_PREFIX);
    let work = tempfile::Builder::new()
        .prefix(&format!("{BUILD_DIR_PREFIX}{}-", std::process::id()))
        .tempdir_in(cache)
        .map_err(|error| format!("creating a build directory failed: {error}"))?;
    let name = repo
        .file_name()
        .ok_or_else(|| format!("{} has no directory name", repo.display()))?;
    let tree = work.path().join(name);
    std::fs::create_dir(&tree)
        .map_err(|error| format!("creating {} failed: {error}", tree.display()))?;
    println!(
        "building the oracle from {} in {} …",
        &sha[..sha.len().min(12)],
        tree.display()
    );
    extract_rev(repo, sha, &tree)?;
    let manifest = std::fs::read_to_string(tree.join("Cargo.toml"))
        .map_err(|error| format!("reading the revision's Cargo.toml failed: {error}"))?;
    let parent = repo
        .parent()
        .ok_or_else(|| format!("{} has no parent directory", repo.display()))?;
    for sibling in sibling_dirs(&manifest) {
        let target = parent.join(&sibling);
        std::os::unix::fs::symlink(&target, work.path().join(&sibling))
            .map_err(|error| format!("linking the sibling {} failed: {error}", target.display()))?;
    }
    let output = Command::new("cargo")
        .args([
            "build",
            "--release",
            "--package",
            "zap",
            "--message-format=json-render-diagnostics",
        ])
        .env("CARGO_TARGET_DIR", tree.join("target"))
        // the revision's `rust-toolchain.toml`, not the toolchain `cargo xtask` runs under
        .env_remove("RUSTUP_TOOLCHAIN")
        .env_remove("RUSTUP_TOOLCHAIN_SOURCE")
        .current_dir(&tree)
        .stdin(Stdio::null())
        .stderr(Stdio::inherit())
        .output()
        .map_err(|error| format!("failed to run cargo: {error}"))?;
    if !output.status.success() {
        return Err(format!("the oracle build failed ({})", output.status));
    }
    let built = super::built_executable(&String::from_utf8_lossy(&output.stdout), "zap")
        .ok_or("cargo reported no `zap` executable for the oracle")?;
    install(&built, dest)?;
    work.close()
        .map_err(|error| format!("removing the oracle's build directory failed: {error}"))
}

/// Write commit `sha`'s tree of `repo` into `tree` (`git archive | tar -x`).
fn extract_rev(repo: &Path, sha: &str, tree: &Path) -> Result<(), String> {
    let mut archive = Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(["archive", "--format=tar", sha])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .spawn()
        .map_err(|error| format!("failed to run git archive: {error}"))?;
    let stdout = archive.stdout.take().ok_or("git archive gave no stdout")?;
    let untar = Command::new("tar")
        .arg("-x")
        .arg("-C")
        .arg(tree)
        .stdin(stdout)
        .status()
        .map_err(|error| format!("failed to run tar: {error}"))?;
    let archived = archive
        .wait()
        .map_err(|error| format!("waiting for git archive failed: {error}"))?;
    if !archived.success() || !untar.success() {
        return Err(format!(
            "extracting {sha} failed (git archive {archived}, tar {untar})"
        ));
    }
    Ok(())
}

/// Copy `built` to `dest`, by way of a temporary name beside it, so `dest` is the whole
/// binary or nothing.
fn install(built: &Path, dest: &Path) -> Result<(), String> {
    let dir = dest
        .parent()
        .ok_or_else(|| format!("{} has no parent directory", dest.display()))?;
    std::fs::create_dir_all(dir)
        .map_err(|error| format!("creating {} failed: {error}", dir.display()))?;
    let staging = tempfile::Builder::new()
        .prefix(".zap-oracle-")
        .tempfile_in(dir)
        .map_err(|error| format!("staging in {} failed: {error}", dir.display()))?;
    std::fs::copy(built, staging.path())
        .map_err(|error| format!("copying the oracle into {} failed: {error}", dir.display()))?;
    staging
        .persist(dest)
        .map_err(|error| format!("installing {} failed: {}", dest.display(), error.error))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::path::Path;
    use std::process::Command;

    use super::{BUILD_DIR_PREFIX, ensure, oracle_dir, oracle_file_name, sibling_dirs};

    #[test]
    fn an_oracle_is_named_for_its_commit_under_the_zap_home() {
        assert_eq!(oracle_file_name("6cab2de"), "zap-6cab2de");
        assert_eq!(
            oracle_dir(Path::new("/home/u")).join(oracle_file_name("6cab2de")),
            Path::new("/home/u/.zap/oracle/zap-6cab2de")
        );
    }

    #[test]
    fn the_siblings_are_the_manifests_relative_paths_out_of_the_tree() {
        let manifest = r#"
[workspace.dependencies]
zap_types = { path = "crates/zap_types" }
fuz_audit = { path = "../fuz/crates/fuz_audit" }
fuz_eval = { path="../fuz/crates/fuz_eval" }
other = { version = "1", path = "../other" }
xpath = { path = "../xpath-sibling" }
# path = "../.."
"#;
        assert_eq!(
            sibling_dirs(manifest).into_iter().collect::<Vec<_>>(),
            ["fuz", "other", "xpath-sibling"]
        );
    }

    /// A git repository in a temporary directory with one commit; `None` without `git`.
    fn repo_with_a_commit() -> Option<(tempfile::TempDir, String)> {
        let dir = tempfile::tempdir().unwrap();
        let git = |args: &[&str]| {
            Command::new("git")
                .arg("-C")
                .arg(dir.path())
                .args([
                    "-c",
                    "user.name=t",
                    "-c",
                    "user.email=t@example.invalid",
                    "-c",
                    "commit.gpgsign=false",
                ])
                .args(args)
                .output()
        };
        let Ok(init) = git(&["init", "-q", "-b", "main"]) else {
            eprintln!("skipping: no git");
            return None;
        };
        assert!(init.status.success(), "{init:?}");
        std::fs::write(dir.path().join("Cargo.toml"), "").unwrap();
        for args in [&["add", "Cargo.toml"][..], &["commit", "-q", "-m", "one"]] {
            let output = git(args).unwrap();
            assert!(output.status.success(), "{output:?}");
        }
        let head = git(&["rev-parse", "HEAD"]).unwrap();
        Some((
            dir,
            String::from_utf8(head.stdout).unwrap().trim().to_owned(),
        ))
    }

    /// A revision resolves to its commit, and an oracle already kept for that commit is
    /// the one used — nothing is built.
    #[test]
    fn a_kept_oracle_for_the_revision_is_reused() {
        let Some((repo, head)) = repo_with_a_commit() else {
            return;
        };
        let home = tempfile::tempdir().unwrap();
        let short = &head[..7];
        let kept = oracle_dir(home.path()).join(oracle_file_name(short));
        std::fs::create_dir_all(kept.parent().unwrap()).unwrap();
        std::fs::write(&kept, b"kept").unwrap();
        // a cache dir that can't be made: a build would fail, so a pass is a reuse
        let cache = home.path().join("kept-oracle-file").join("cache");
        std::fs::write(home.path().join("kept-oracle-file"), b"").unwrap();
        for rev in ["main", "HEAD", head.as_str()] {
            let oracle = ensure(repo.path(), rev, home.path(), &cache).unwrap();
            assert_eq!(oracle.short, short, "{rev}");
            assert_eq!(oracle.path, kept, "{rev}");
            assert!(!oracle.built, "{rev}");
            assert_eq!(
                oracle.describe(),
                format!("oracle rev {rev} = {short} (reused {})", kept.display())
            );
        }
        assert_eq!(std::fs::read(&kept).unwrap(), b"kept");
    }

    /// A build directory an interrupted build left is swept once its process is gone;
    /// a live process's, and anything else in the cache dir, is left.
    #[test]
    fn a_dead_builds_directory_is_swept() {
        let cache = tempfile::tempdir().unwrap();
        let mut gone = Command::new("true").spawn().unwrap();
        let dead = gone.id();
        gone.wait().unwrap();
        let names = [
            format!("{BUILD_DIR_PREFIX}{dead}-abc"),
            format!("{BUILD_DIR_PREFIX}{}-def", std::process::id()),
            format!("{dead}-run"),
            "pki".to_owned(),
        ];
        for name in &names {
            std::fs::create_dir(cache.path().join(name)).unwrap();
        }
        crate::differential::fixture::sweep_dead_dirs(cache.path(), BUILD_DIR_PREFIX);
        for (name, kept) in names.iter().zip([false, true, true, true]) {
            assert_eq!(cache.path().join(name).exists(), kept, "{name}");
        }
    }

    /// A revision that names no commit, or that reads as an option, is refused before
    /// anything is built.
    #[test]
    fn a_revision_that_names_no_commit_is_refused() {
        let Some((repo, _)) = repo_with_a_commit() else {
            return;
        };
        let home = tempfile::tempdir().unwrap();
        for rev in ["origin/main", "no-such-branch", "--all"] {
            let error =
                ensure(repo.path(), rev, home.path(), &home.path().join("cache")).expect_err(rev);
            assert!(error.contains(&format!("`{rev}`")), "{error}");
        }
        assert!(!home.path().join("cache").exists(), "nothing was built");
    }
}
