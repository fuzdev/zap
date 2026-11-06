//! The extract script (`zap_types::extract`) and the deploy extract-and-swap script
//! (`zap_types::deploy`), run for real: under the system `sh`, and under `BusyBox` with
//! only its applets on `PATH` (when installed), with a stand-in `sudo` that runs its
//! command as the test's own user. The archives are built by the host's `tar`.
//!
//! What only root can show — files landing owned by the extracting user rather than by
//! the ids an archive recorded, and without the set-id bits an unprivileged `tar` drops
//! anyway — is shown under `fakeroot` where it is installed (a faked uid 0, which both
//! `tar`s act on), and not otherwise. The deploy script refusing an archive another
//! user owns is shown nowhere here.

use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _, symlink};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use zap_types::deploy::{DeployAction, DeployContext, DriftPreflight, plan_deploy};
use zap_types::extract::extract_archive_command;
use zap_types::put::{REFUSED_EXIT, RunAs};
use zap_types::schema::{DeploySpec, ExtractMode, Target};

use super::put::{
    Leg, entries, executable, feed, led_by, mode_of, on_path, only_tools, stand_in_bin, stderr,
};
use super::support::test_shells;
use crate::connection::delivery::Delivery;
use crate::digest::sha512_hex;

/// The applets the extract script and the deploy script run, beyond the batch's.
const APPLETS: &[&str] = &[
    "tar", "mkdir", "rm", "mktemp", "chown", "chmod", "sync", "mv", "ln", "date", "basename", "ls",
    "grep", "tail", "xargs", "id", "rmdir", "sort", "find", "uniq",
];

const GZ: ExtractMode = ExtractMode::TarGz {
    strip_components: 1,
};

/// A source tree under `dir` and its archives, as the host's `tar` writes them: a
/// payload, a set-user-id tool, a world-writable file, and a world-writable directory,
/// all under `top/`. The `.tar.xz` is `None` on a host whose `tar` can't write one.
struct Fixture {
    gz: PathBuf,
    xz: Option<PathBuf>,
    /// `top/` holding a `.zap_remote_hash` that is a link to `../victim`.
    linked: PathBuf,
}

fn host_tar(args: &[&str], out: &Path, from: &Path, member: &str) -> bool {
    Command::new("tar")
        .args(args)
        .arg(out)
        .arg("-C")
        .arg(from)
        .arg(member)
        .output()
        .is_ok_and(|output| output.status.success())
}

fn fixture(dir: &Path) -> Fixture {
    let src = dir.join("src");
    let top = src.join("top");
    std::fs::create_dir_all(top.join("wide")).unwrap();
    std::fs::write(top.join("f.txt"), "payload").unwrap();
    std::fs::write(top.join("wide").join("inner"), "in").unwrap();
    let set_mode = |name: &str, mode: u32| {
        std::fs::write(top.join(name), "#!/bin/sh\n").unwrap();
        std::fs::set_permissions(top.join(name), std::fs::Permissions::from_mode(mode)).unwrap();
    };
    set_mode("tool", 0o4755);
    set_mode("open", 0o666);
    std::fs::set_permissions(top.join("wide"), std::fs::Permissions::from_mode(0o777)).unwrap();
    let gz = dir.join("fixture.tar.gz");
    assert!(host_tar(&["-czf"], &gz, &src, "top"), "a host tar");
    let xz = dir.join("fixture.tar.xz");
    let xz = host_tar(&["-cJf"], &xz, &src, "top").then_some(xz);

    let linked_src = dir.join("linked-src");
    std::fs::create_dir_all(linked_src.join("top")).unwrap();
    std::fs::write(linked_src.join("top").join("f.txt"), "payload").unwrap();
    symlink("../victim", linked_src.join("top").join(".zap_remote_hash")).unwrap();
    let linked = dir.join("linked.tar.gz");
    assert!(host_tar(&["-czf"], &linked, &linked_src, "top"));
    Fixture { gz, xz, linked }
}

/// A copy of `fixture` for one extraction to consume, in a directory of its own, with
/// the mode a content-cache entry has (`0600`), which the upload keeps.
fn staged(case: &Path, fixture: &Path) -> PathBuf {
    let stage = tempfile::tempdir_in(case).unwrap().keep();
    let name = fixture.file_name().unwrap();
    let staged = stage.join(name);
    std::fs::copy(fixture, &staged).unwrap();
    std::fs::set_permissions(&staged, std::fs::Permissions::from_mode(0o600)).unwrap();
    staged
}

/// [`extract_archive_command`] with the digest of what is at `archive` now, or of
/// nothing when nothing is.
fn extract_command(
    run_as: RunAs<'_>,
    archive: &str,
    dest: &str,
    mode: ExtractMode,
    pin: Option<&str>,
) -> String {
    let digest = sha512_hex(&std::fs::read(archive).unwrap_or_default());
    extract_archive_command(run_as, archive, dest, mode, pin, &digest)
}

/// Run `step` under the leg's shell.
fn run(leg: &Leg, step: &str) -> Output {
    let (_, shell, env_path) = leg;
    let mut command = Command::new(shell);
    if let Some(path) = env_path {
        command.env("PATH", path);
    }
    command.args(["-c", step]).output().unwrap()
}

/// Extract `archive` into `dest` as root would (the stand-in `sudo`).
fn extract(leg: &Leg, archive: &Path, dest: &str, mode: ExtractMode, pin: Option<&str>) -> Output {
    run(
        leg,
        &extract_command(RunAs::Root, &archive.to_string_lossy(), dest, mode, pin),
    )
}

/// The staging directories the extract script left in `parent`: hidden names carrying
/// `.zap-`, which every exit of the script removes.
fn staging_left(parent: &Path) -> Vec<String> {
    entries(parent)
        .into_iter()
        .filter(|name| name.starts_with('.') && name.contains(".zap-"))
        .collect()
}

/// An archive lands in its destination with the archive's set-id and group/other-write
/// bits gone — whatever umask the caller had — in a destination the script made, named
/// however a shell could misread; the staged archive is removed; no sentinel is
/// written without a pin. (An unprivileged `tar` drops the set-id bits by itself; the
/// umask is the script's.) With a pin, a destination holding a sentinel, or empty, is
/// replaced and the new tree carries the pin's sentinel; one holding other files is
/// refused.
#[test]
fn an_archive_is_extracted_without_its_modes_of_privilege_under_both_shells() {
    let dir = crate::test_scratch::tempdir();
    let bin = stand_in_bin(dir.path());
    let fixture = fixture(dir.path());
    let mut checked = Vec::new();
    for leg in test_shells(dir.path(), APPLETS, Some(&bin)) {
        let label = leg.0;
        let case = tempfile::tempdir_in(dir.path()).unwrap();
        let at = |name: &str| case.path().join(name);
        let mut formats = vec![("gz", fixture.gz.clone(), GZ)];
        if let Some(xz) = &fixture.xz {
            formats.push((
                "xz",
                xz.clone(),
                ExtractMode::TarXz {
                    strip_components: 1,
                },
            ));
        }
        for (format, archive, mode) in formats {
            // A caller's open umask is not the extraction's.
            let dest = at(&format!("it's a {format} dest")).join("-rf $HOME");
            let archive = staged(case.path(), &archive);
            let step = extract_command(
                RunAs::Root,
                &archive.to_string_lossy(),
                &dest.to_string_lossy(),
                mode,
                None,
            );
            let output = run(&leg, &format!("umask 000; {step}"));
            assert!(output.status.success(), "{label}: {format}: {output:?}");
            assert_eq!(
                std::fs::read(dest.join("f.txt")).unwrap(),
                b"payload",
                "{label}: {format}"
            );
            assert!(
                !archive.exists(),
                "{label}: {format}: the archive is removed"
            );
            assert_eq!(
                mode_of(&dest.join("tool")),
                0o755,
                "{label}: {format}: no set-id bit"
            );
            assert_eq!(mode_of(&dest.join("open")), 0o644, "{label}: {format}");
            assert_eq!(mode_of(&dest.join("wide")), 0o755, "{label}: {format}");
            assert_eq!(mode_of(&dest), 0o755, "{label}: {format}: made under 022");
            assert_eq!(
                entries(&dest),
                ["f.txt", "open", "tool", "wide"],
                "{label}: {format}: no sentinel is the script's to write"
            );
        }

        // No components stripped: the archive's own top directory.
        let archive = staged(case.path(), &fixture.gz);
        let whole = at("whole");
        let unstripped = ExtractMode::TarGz {
            strip_components: 0,
        };
        let output = extract(&leg, &archive, &whole.to_string_lossy(), unstripped, None);
        assert!(output.status.success(), "{label}: {output:?}");
        assert_eq!(entries(&whole), ["top"], "{label}");

        // The replacement guard: with a pin, a destination holding a sentinel (whichever
        // pin it records) is replaced whole and the new one carries this pin; an empty
        // one is replaced too; one that holds anything else is refused, untouched.
        for (what, recorded, replaced) in [
            ("another pin", Some("OLD"), true),
            ("this pin", Some("NEW"), true),
            ("no sentinel", None, false),
        ] {
            let dest = tempfile::tempdir_in(case.path()).unwrap().keep();
            std::fs::write(dest.join("theirs"), "KEEP").unwrap();
            if let Some(recorded) = recorded {
                std::fs::write(dest.join(".zap_remote_hash"), recorded).unwrap();
            }
            let archive = staged(case.path(), &fixture.gz);
            let output = extract(&leg, &archive, &dest.to_string_lossy(), GZ, Some("NEW"));
            assert_eq!(dest.join("theirs").exists(), !replaced, "{label}: {what}");
            assert_eq!(dest.join("f.txt").exists(), replaced, "{label}: {what}");
            if replaced {
                assert!(output.status.success(), "{label}: {what}: {output:?}");
                assert_eq!(
                    std::fs::read_to_string(dest.join(".zap_remote_hash")).unwrap(),
                    "NEW",
                    "{label}: {what}: the script writes the sentinel"
                );
            } else {
                assert_eq!(
                    output.status.code(),
                    Some(REFUSED_EXIT),
                    "{label}: {what}: {output:?}"
                );
                assert!(
                    stderr(&output).contains("no extract sentinel, so zap did not extract it"),
                    "{label}: {what}: {output:?}"
                );
                assert_eq!(entries(&dest), ["theirs"], "{label}: {what}");
                assert!(archive.exists(), "{label}: {what}: the archive is left");
            }
        }
        let empty = tempfile::tempdir_in(case.path()).unwrap().keep();
        let archive = staged(case.path(), &fixture.gz);
        let output = extract(&leg, &archive, &empty.to_string_lossy(), GZ, Some("NEW"));
        assert!(output.status.success(), "{label}: empty: {output:?}");
        assert_eq!(
            entries(&empty),
            [".zap_remote_hash", "f.txt", "open", "tool", "wide"],
            "{label}: an empty destination is replaced"
        );

        // With no pin, a sentinel authorizes nothing: a destination holding files is
        // refused whatever its sentinel says.
        let dest = tempfile::tempdir_in(case.path()).unwrap().keep();
        std::fs::write(dest.join("theirs"), "KEEP").unwrap();
        std::fs::write(dest.join(".zap_remote_hash"), "OLD").unwrap();
        let archive = staged(case.path(), &fixture.gz);
        let output = extract(&leg, &archive, &dest.to_string_lossy(), GZ, None);
        assert_eq!(
            output.status.code(),
            Some(REFUSED_EXIT),
            "{label}: {output:?}"
        );
        assert_eq!(entries(&dest), [".zap_remote_hash", "theirs"], "{label}");
        assert_eq!(staging_left(case.path()), Vec::<String>::new(), "{label}");
        checked.push(label);
    }
    eprintln!("extract checked under: {checked:?}");
}

/// A symbolic link at the destination is refused, with nothing extracted and nothing
/// removed where it points — as it stands, with a trailing slash or `/.`, dangling, and
/// planted after the script's first look; so is one swapped in at the new tree's name. So is a destination or an archive that
/// isn't absolute, a format the script doesn't know, and a target missing a tool. A
/// link in a directory *component* is followed.
/// Root extracts only the archive it was told of: bytes whose SHA-512 is the pinned
/// one's, held open from the uploaded name and read from a copy no other account can
/// reach, in a regular file the uploading account owns (the one running the script, or
/// the one `sudo` was run by), with one link, writable by no
/// one else. Anything else — an archive swapped at its name, a link there, a second
/// hard link, a file another account owns or may write — is refused, and nothing is
/// extracted.
#[test]
fn only_the_pinned_archive_is_extracted_under_both_shells() {
    let dir = crate::test_scratch::tempdir();
    let bin = stand_in_bin(dir.path());
    let fixture = fixture(dir.path());
    let me = nix::unistd::geteuid().as_raw();
    let pinned = sha512_hex(&std::fs::read(&fixture.gz).unwrap());
    let mut checked = Vec::new();
    for leg in test_shells(dir.path(), APPLETS, Some(&bin)) {
        let label = leg.0;
        let case = tempfile::tempdir_in(dir.path()).unwrap();
        let refused = |what: &str, archive: &Path, prefix: &str, digest: &str, why: &str| {
            let dest = case.path().join(format!("{what} dest"));
            let step = extract_archive_command(
                RunAs::Root,
                &archive.to_string_lossy(),
                &dest.to_string_lossy(),
                GZ,
                Some("NEW"),
                digest,
            );
            let output = run(&leg, &format!("{prefix}{step}"));
            assert_eq!(
                output.status.code(),
                Some(REFUSED_EXIT),
                "{label} {what}: {output:?}"
            );
            assert!(
                stderr(&output).contains(&format!("{why}; nothing was extracted")),
                "{label} {what}: {output:?}"
            );
            assert!(!dest.exists(), "{label} {what}: nothing is extracted");
            assert_eq!(staging_left(case.path()), [""; 0], "{label} {what}");
        };

        // the pinned bytes are extracted
        let archive = staged(case.path(), &fixture.gz);
        let dest = case.path().join("pinned");
        let step = extract_archive_command(
            RunAs::Root,
            &archive.to_string_lossy(),
            &dest.to_string_lossy(),
            GZ,
            Some("NEW"),
            &pinned,
        );
        let output = run(&leg, &step);
        assert!(output.status.success(), "{label}: {output:?}");
        assert_eq!(std::fs::read(dest.join("f.txt")).unwrap(), b"payload");

        // other bytes at the uploaded name: another archive, or the pinned one altered
        let swapped = staged(case.path(), &fixture.linked);
        refused(
            "swapped",
            &swapped,
            "",
            &pinned,
            "the archive is not the pinned one (its SHA-512 differs)",
        );
        assert!(swapped.exists(), "{label}: a refused archive is left");
        let archive = staged(case.path(), &fixture.gz);
        refused(
            "no digest",
            &archive,
            "",
            "",
            "not a SHA-512 digest for the archive",
        );
        refused(
            "an uppercase digest",
            &archive,
            "",
            &pinned.to_uppercase(),
            "not a SHA-512 digest for the archive",
        );

        // a link at the name, even to the pinned archive
        let link = archive.with_file_name("link.tar.gz");
        symlink(&archive, &link).unwrap();
        refused(
            "a link",
            &link,
            "",
            &pinned,
            "the archive is not a regular file",
        );

        // a second hard link to it
        let other = case.path().join("hard.tar.gz");
        std::fs::hard_link(&archive, &other).unwrap();
        refused(
            "a hard link",
            &archive,
            "",
            &pinned,
            "the archive has another hard link",
        );
        std::fs::remove_file(&other).unwrap();

        // writable by its group, or by anyone
        for mode in [0o620, 0o602] {
            std::fs::set_permissions(&archive, std::fs::Permissions::from_mode(mode)).unwrap();
            refused(
                &format!("mode {mode:o}"),
                &archive,
                "",
                &pinned,
                "the archive can be written by other accounts",
            );
        }
        std::fs::set_permissions(&archive, std::fs::Permissions::from_mode(0o600)).unwrap();

        // a caller's inherited `SUDO_UID` naming another account: the caller's own file
        // is still the caller's upload, and is extracted
        let dest = case.path().join("inherited dest");
        let step = format!(
            "SUDO_UID={} {}",
            me + 1,
            extract_archive_command(
                RunAs::Caller,
                &archive.to_string_lossy(),
                &dest.to_string_lossy(),
                GZ,
                Some("NEW"),
                &pinned,
            )
        );
        let output = run(&leg, &step);
        assert!(output.status.success(), "{label}: {output:?}");
        assert_eq!(std::fs::read(dest.join("f.txt")).unwrap(), b"payload");

        // owned by neither the account running the script (a stand-in `id` answers
        // another) nor the one `sudo` was run by
        let archive = staged(case.path(), &fixture.gz);
        let lead = tempfile::tempdir_in(dir.path()).unwrap();
        executable(&lead.path().join("id"), &format!("echo {}", me + 1));
        let led = (
            label,
            leg.1.clone(),
            Some(led_by(lead.path(), leg.2.as_ref())),
        );
        let dest = case.path().join("another uploader dest");
        let step = format!(
            "SUDO_UID={} {}",
            me + 2,
            extract_archive_command(
                RunAs::Root,
                &archive.to_string_lossy(),
                &dest.to_string_lossy(),
                GZ,
                Some("NEW"),
                &pinned,
            )
        );
        let output = run(&led, &step);
        assert_eq!(
            output.status.code(),
            Some(REFUSED_EXIT),
            "{label}: {output:?}"
        );
        assert!(
            stderr(&output).contains(
                "the archive is not a file the uploading account owns; nothing was extracted"
            ),
            "{label}: {output:?}"
        );
        assert!(!dest.exists(), "{label}");
        checked.push(label);
    }
    eprintln!("only the pinned archive extracted under: {checked:?}");
}

#[test]
fn an_extraction_follows_no_link_at_its_destination_under_both_shells() {
    let dir = crate::test_scratch::tempdir();
    let bin = stand_in_bin(dir.path());
    let fixture = fixture(dir.path());
    let mut checked = Vec::new();
    for leg in test_shells(dir.path(), APPLETS, Some(&bin)) {
        let (label, shell, env_path) = &leg;
        let case = tempfile::tempdir_in(dir.path()).unwrap();
        let at = |name: &str| case.path().join(name);
        let real = at("real");
        std::fs::create_dir(&real).unwrap();
        std::fs::write(real.join("theirs"), "KEEP").unwrap();
        std::fs::write(real.join(".zap_remote_hash"), "OLD").unwrap();
        symlink(&real, at("alias")).unwrap();
        symlink(at("nowhere"), at("dangling")).unwrap();
        let untouched = |what: &str| {
            assert_eq!(
                entries(&real),
                [".zap_remote_hash", "theirs"],
                "{label}: {what}: nothing lands in, or leaves, what the link names"
            );
            assert!(!at("nowhere").exists(), "{label}: {what}");
        };
        let refused = |what: &str, dest: &str, mode: ExtractMode, says: &str| {
            let archive = staged(case.path(), &fixture.gz);
            let output = extract(&leg, &archive, dest, mode, Some("NEW"));
            assert_eq!(
                output.status.code(),
                Some(REFUSED_EXIT),
                "{label}: {what}: {output:?}"
            );
            assert!(
                stderr(&output).contains(says),
                "{label}: {what}: {output:?}"
            );
            assert!(archive.exists(), "{label}: {what}: the archive is left");
            untouched(what);
        };
        let alias = at("alias").to_string_lossy().into_owned();
        refused("a link to a directory", &alias, GZ, "symbolic link");
        refused("…with a trailing slash", &format!("{alias}/"), GZ, "link");
        refused(
            "…with a `/.`",
            &format!("{alias}/."),
            GZ,
            "does not name a directory itself",
        );
        refused(
            "a dangling link",
            &at("dangling").to_string_lossy(),
            GZ,
            "symbolic link",
        );
        refused("a relative path", "real", GZ, "not an absolute path");
        refused(
            "no archive format",
            &at("fresh").to_string_lossy(),
            ExtractMode::None,
            "unknown archive format",
        );
        assert!(!at("fresh").exists(), "{label}: refused before the mkdir");

        // `/` is no destination: refused before anything could be removed or made. The
        // archive named isn't there and no pin is given, so nothing past the refusal
        // could act either.
        for root in ["/", "//"] {
            let output = run(
                &leg,
                &extract_command(
                    RunAs::Caller,
                    &at("no-such-archive.tar.gz").to_string_lossy(),
                    root,
                    GZ,
                    None,
                ),
            );
            assert_eq!(
                output.status.code(),
                Some(REFUSED_EXIT),
                "{label}: {root}: {output:?}"
            );
            assert!(
                stderr(&output).contains("does not name a directory itself"),
                "{label}: {root}: {output:?}"
            );
        }

        // A relative archive would be looked for inside the destination.
        let output = run(
            &leg,
            &extract_command(
                RunAs::Root,
                "archive.tar.gz",
                &at("fresh").to_string_lossy(),
                GZ,
                None,
            ),
        );
        assert_eq!(output.status.code(), Some(REFUSED_EXIT), "{label}");
        assert!(!at("fresh").exists(), "{label}");

        // A link swapped in at the new tree's name after it was made: a `mkdir`
        // stand-in replaces the directory it just made inside the staging directory
        // with one. The descriptor check stops there, before `tar`, and nothing lands
        // where the link leads.
        let lead = tempfile::tempdir_in(dir.path()).unwrap();
        let swapped = at("swapped");
        executable(
            &lead.path().join("mkdir"),
            &format!(
                "{mkdir} \"$@\" || exit 1\n\
                 for a; do case $a in */new) rmdir \"$a\" && ln -s {real} \"$a\" || exit 1;; esac; done",
                mkdir = zap_types::shell::single_quote(
                    &on_path(env_path.as_ref(), "mkdir").to_string_lossy()
                ),
                real = zap_types::shell::single_quote(&real.to_string_lossy()),
            ),
        );
        let archive = staged(case.path(), &fixture.gz);
        let output = Command::new(shell)
            .env("PATH", led_by(lead.path(), env_path.as_ref()))
            .args([
                "-c",
                &extract_command(
                    RunAs::Root,
                    &archive.to_string_lossy(),
                    &swapped.to_string_lossy(),
                    GZ,
                    None,
                ),
            ])
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(1), "{label}: {output:?}");
        assert!(!swapped.exists(), "{label}: nothing is swapped in");
        assert_eq!(staging_left(case.path()), Vec::<String>::new(), "{label}");
        untouched("a link swapped in at the new tree's name");

        // A link swapped in at the destination's name after the first look: a `tar`
        // stand-in plants one as it extracts. The rename onto the name replaces no link
        // and goes through none; nothing is extracted where it leads.
        let lead = tempfile::tempdir_in(dir.path()).unwrap();
        let planted = at("planted");
        executable(
            &lead.path().join("tar"),
            &format!(
                "ln -s {real} {dest} || exit 1\nexec {tar} \"$@\"",
                tar = zap_types::shell::single_quote(
                    &on_path(env_path.as_ref(), "tar").to_string_lossy()
                ),
                dest = zap_types::shell::single_quote(&planted.to_string_lossy()),
                real = zap_types::shell::single_quote(&real.to_string_lossy()),
            ),
        );
        let archive = staged(case.path(), &fixture.gz);
        let output = Command::new(shell)
            .env("PATH", led_by(lead.path(), env_path.as_ref()))
            .args([
                "-c",
                &extract_command(
                    RunAs::Root,
                    &archive.to_string_lossy(),
                    &planted.to_string_lossy(),
                    GZ,
                    None,
                ),
            ])
            .output()
            .unwrap();
        assert!(!output.status.success(), "{label}: {output:?}");
        assert!(
            std::fs::symlink_metadata(&planted).unwrap().is_symlink(),
            "{label}: the planted link stays"
        );
        assert_eq!(staging_left(case.path()), Vec::<String>::new(), "{label}");
        untouched("a link planted at the destination during the extraction");

        // A file at the destination is refused, and left as it is.
        std::fs::write(at("a file"), "x").unwrap();
        let archive = staged(case.path(), &fixture.gz);
        let output = extract(&leg, &archive, &at("a file").to_string_lossy(), GZ, None);
        assert_eq!(
            output.status.code(),
            Some(REFUSED_EXIT),
            "{label}: {output:?}"
        );
        assert!(
            stderr(&output).contains("not a directory of its own"),
            "{label}: {output:?}"
        );
        assert_eq!(std::fs::read(at("a file")).unwrap(), b"x", "{label}");

        // A target without `tar` is told so, before anything is made.
        let only = only_tools(
            dir.path(),
            env_path.as_ref(),
            &["mkdir", "stat", "cat", "rm"],
        );
        let archive = staged(case.path(), &fixture.gz);
        let output = Command::new(shell)
            .env("PATH", &only)
            .args([
                "-c",
                &extract_command(
                    RunAs::Caller,
                    &archive.to_string_lossy(),
                    &at("toolless").to_string_lossy(),
                    GZ,
                    None,
                ),
            ])
            .output()
            .unwrap();
        assert_eq!(
            output.status.code(),
            Some(REFUSED_EXIT),
            "{label}: {output:?}"
        );
        assert!(
            stderr(&output).contains("no tar on this machine"),
            "{label}: {output:?}"
        );
        assert!(!at("toolless").exists(), "{label}");

        // A directory component that is a link is followed: the tree lands under what
        // it names.
        let archive = staged(case.path(), &fixture.gz);
        let through = at("alias").join("sub");
        let output = extract(&leg, &archive, &through.to_string_lossy(), GZ, None);
        assert!(output.status.success(), "{label}: {output:?}");
        assert!(real.join("sub").join("f.txt").exists(), "{label}");
        checked.push(*label);
    }
    eprintln!("extract links checked under: {checked:?}");
}

/// The extraction happens in the directory that was checked, whatever its name has
/// become since: a `stat` stand-in moves the new tree's directory aside and leaves a
/// link to another directory at its name once the script has compared the two. The tree
/// lands in the directory the script holds open — the one moved aside — and nothing
/// lands where the link leads.
#[test]
fn an_extraction_lands_in_the_directory_it_checked_under_both_shells() {
    let dir = crate::test_scratch::tempdir();
    let bin = stand_in_bin(dir.path());
    let fixture = fixture(dir.path());
    let mut checked = Vec::new();
    for leg in test_shells(dir.path(), APPLETS, Some(&bin)) {
        let (label, shell, env_path) = &leg;
        let case = tempfile::tempdir_in(dir.path()).unwrap();
        let at = |name: &str| case.path().join(name);
        let quoted = |path: &Path| zap_types::shell::single_quote(&path.to_string_lossy());
        std::fs::create_dir(at("theirs")).unwrap();
        // The by-name `stat` is the one without `-L`: the script's last look at the name.
        let lead = tempfile::tempdir_in(dir.path()).unwrap();
        executable(
            &lead.path().join("stat"),
            &format!(
                "{stat} \"$@\"\nstatus=$?\n\
                 if [ \"$1\" = -c ]; then case $3 in */new) \
                 mv \"$3\" {aside} && ln -s {theirs} \"$3\" || exit 1;; esac; fi\n\
                 exit $status",
                stat = quoted(&on_path(env_path.as_ref(), "stat")),
                aside = quoted(&at("aside")),
                theirs = quoted(&at("theirs")),
            ),
        );
        let archive = staged(case.path(), &fixture.gz);
        let output = Command::new(shell)
            .env("PATH", led_by(lead.path(), env_path.as_ref()))
            .args([
                "-c",
                &extract_command(
                    RunAs::Root,
                    &archive.to_string_lossy(),
                    &at("dest").to_string_lossy(),
                    GZ,
                    None,
                ),
            ])
            .output()
            .unwrap();
        assert!(output.status.success(), "{label}: {output:?}");
        assert!(
            at("aside").is_dir() && std::fs::symlink_metadata(at("dest")).unwrap().is_symlink(),
            "{label}: the swap happened"
        );
        assert!(
            at("aside").join("f.txt").exists(),
            "{label}: the tree is in the directory that was checked"
        );
        assert_eq!(
            entries(&at("theirs")),
            Vec::<String>::new(),
            "{label}: nothing lands where the link leads"
        );
        checked.push(*label);
    }
    eprintln!("extract after a swap checked under: {checked:?}");
}

/// An archive that carries a link at the sentinel's own name can't aim the pin
/// anywhere: the script removes the link and writes the sentinel in its place.
#[test]
fn the_sentinel_replaces_a_link_the_archive_carried_under_both_shells() {
    let dir = crate::test_scratch::tempdir();
    let bin = stand_in_bin(dir.path());
    let fixture = fixture(dir.path());
    let mut checked = Vec::new();
    for leg in test_shells(dir.path(), APPLETS, Some(&bin)) {
        let label = leg.0;
        let case = tempfile::tempdir_in(dir.path()).unwrap();
        let victim = case.path().join("victim");
        std::fs::write(&victim, "ORIGINAL").unwrap();
        let dest = case.path().join("tree");
        let sentinel = dest.join(".zap_remote_hash");
        let archive = staged(case.path(), &fixture.linked);
        let output = extract(&leg, &archive, &dest.to_string_lossy(), GZ, Some("PIN"));
        assert!(output.status.success(), "{label}: {output:?}");
        assert!(
            std::fs::symlink_metadata(&sentinel).unwrap().is_file(),
            "{label}"
        );
        assert_eq!(std::fs::read(&sentinel).unwrap(), b"PIN", "{label}");
        assert_eq!(std::fs::read(&victim).unwrap(), b"ORIGINAL", "{label}");
        checked.push(label);
    }
    eprintln!("sentinel over a link checked under: {checked:?}");
}

/// A `.tar.gz` at `out` of `members` — each a name, a ustar type flag, a link target,
/// and the bytes — written as raw ustar headers and gzipped by the host's `gzip`: an
/// archive no `tar` writes from a tree, a hard link whose target leaves the archive.
fn raw_tar_gz(out: &Path, members: &[(&str, u8, &str, &[u8])]) {
    let field = |header: &mut [u8; 512], at: usize, text: &str| {
        header[at..at + text.len()].copy_from_slice(text.as_bytes());
    };
    let mut tar = Vec::new();
    for (name, kind, link, data) in members {
        let mut header = [0u8; 512];
        field(&mut header, 0, name);
        let mode = if *kind == b'5' { "0000755" } else { "0000644" };
        field(&mut header, 100, mode);
        field(&mut header, 108, "0000000");
        field(&mut header, 116, "0000000");
        field(&mut header, 124, &format!("{:011o}", data.len()));
        field(&mut header, 136, "00000000000");
        field(&mut header, 148, "        ");
        header[156] = *kind;
        field(&mut header, 157, link);
        field(&mut header, 257, "ustar\u{0}00");
        let sum: u32 = header.iter().map(|byte| u32::from(*byte)).sum();
        field(&mut header, 148, &format!("{sum:06o}\u{0} "));
        tar.extend_from_slice(&header);
        tar.extend_from_slice(data);
        tar.resize(tar.len().next_multiple_of(512), 0);
    }
    tar.resize(tar.len() + 1024, 0);
    let mut gzip = Command::new("gzip")
        .args(["-n", "-c"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .expect("a host gzip");
    std::io::Write::write_all(&mut gzip.stdin.take().unwrap(), &tar).unwrap();
    let output = gzip.wait_with_output().unwrap();
    assert!(output.status.success());
    std::fs::write(out, output.stdout).unwrap();
}

/// An archive can't reach a file outside itself through a hard link: `BusyBox` `tar`
/// links a member to any path its target names, so the script refuses a tree holding
/// an entry linked from outside it — a regular file or a fifo — and the destination is
/// never made. GNU `tar` refuses the link itself. Hard links among the archive's own
/// members extract.
#[test]
fn an_extraction_links_no_file_outside_the_archive_under_both_shells() {
    let dir = crate::test_scratch::tempdir();
    let bin = stand_in_bin(dir.path());
    let inside = dir.path().join("inside.tar.gz");
    raw_tar_gz(
        &inside,
        &[
            ("top/", b'5', "", b""),
            ("top/f.txt", b'0', "", b"payload"),
            ("top/same", b'1', "top/f.txt", b""),
        ],
    );
    // Stripped of `top/`, a target `top/../../x` is `../../x`: from the new tree, past
    // the staging directory, to the destination's parent.
    let outside = |name: &str, target: &str| {
        let archive = dir.path().join(name);
        raw_tar_gz(
            &archive,
            &[
                ("top/", b'5', "", b""),
                ("top/f.txt", b'0', "", b"payload"),
                ("top/hl", b'1', target, b""),
            ],
        );
        archive
    };
    let to_file = outside("outside.tar.gz", "top/../../victim");
    let to_fifo = outside("outside-fifo.tar.gz", "top/../../victim.fifo");
    let mut checked = Vec::new();
    for leg in test_shells(dir.path(), APPLETS, Some(&bin)) {
        let label = leg.0;
        let case = tempfile::tempdir_in(dir.path()).unwrap();
        let victim = case.path().join("victim");
        std::fs::write(&victim, "ORIGINAL").unwrap();
        let fifo = case.path().join("victim.fifo");
        assert!(
            Command::new("mkfifo")
                .arg(&fifo)
                .status()
                .unwrap()
                .success()
        );

        let dest = case.path().join("tree");
        for (archive, linked) in [(&to_file, &victim), (&to_fifo, &fifo)] {
            let archive = staged(case.path(), archive);
            let output = extract(&leg, &archive, &dest.to_string_lossy(), GZ, Some("PIN"));
            assert!(!output.status.success(), "{label}: {output:?}");
            if label == "busybox" {
                assert_eq!(
                    output.status.code(),
                    Some(REFUSED_EXIT),
                    "{label}: {output:?}"
                );
                assert!(
                    stderr(&output).contains("links a file outside itself"),
                    "{label}: {output:?}"
                );
            }
            assert_eq!(
                std::fs::symlink_metadata(linked).unwrap().nlink(),
                1,
                "{label}: {linked:?}"
            );
            assert!(!dest.exists(), "{label}: no destination is made");
            assert!(staging_left(case.path()).is_empty(), "{label}");
        }

        let archive = staged(case.path(), &inside);
        let output = extract(&leg, &archive, &dest.to_string_lossy(), GZ, Some("PIN"));
        assert!(output.status.success(), "{label}: {output:?}");
        assert_eq!(
            std::fs::read(dest.join("same")).unwrap(),
            b"payload",
            "{label}"
        );
        assert_eq!(
            std::fs::metadata(dest.join("same")).unwrap().nlink(),
            2,
            "{label}"
        );
        checked.push(label);
    }
    eprintln!("hard links checked under: {checked:?}");
}

/// The hidden staging and moved-aside entries the deploy script left in `releases/`.
fn leftovers(app: &Path) -> Vec<String> {
    entries(&app.join("releases"))
        .into_iter()
        .filter(|name| name.starts_with(".zap-"))
        .collect()
}

/// Whether the installed `busybox` carries `applet`.
fn busybox_has(applet: &str) -> bool {
    Command::new("busybox")
        .arg("--list")
        .output()
        .is_ok_and(|output| {
            String::from_utf8_lossy(&output.stdout)
                .lines()
                .any(|line| line == applet)
        })
}

/// The shells the deploy script runs under: [`test_shells`] with [`APPLETS`], and a
/// `flock` on each leg's `PATH`. The `BusyBox` leg takes `BusyBox`'s own applet when the
/// installed one carries it (Alpine's does; Debian's is built without it, `flock` being
/// util-linux's there) and the host's `flock` after its applets otherwise.
fn deploy_shells(dir: &Path, bin: &Path) -> Vec<Leg> {
    let own = busybox_has("flock");
    let mut applets = APPLETS.to_vec();
    if own {
        applets.push("flock");
    }
    let host_flock = on_path(std::env::var_os("PATH").as_ref(), "flock");
    test_shells(dir, &applets, Some(bin))
        .into_iter()
        .map(|(label, shell, path)| {
            if label != "busybox" || own {
                return (label, shell, path);
            }
            let extra = tempfile::tempdir_in(dir).unwrap().keep();
            symlink(&host_flock, extra.join("flock")).unwrap();
            let path = std::env::join_paths(
                path.iter()
                    .flat_map(std::env::split_paths)
                    .chain(std::iter::once(extra)),
            )
            .unwrap();
            eprintln!("busybox carries no flock applet: its leg runs the host's");
            (label, shell, Some(path))
        })
        .collect()
}

/// The deploy lock of the app at `app`, held by another process until this is dropped.
struct HeldLock(std::process::Child);

impl HeldLock {
    /// Take the lock on `lock` with the host's `flock`, returning once it is held.
    fn take(lock: &Path) -> Self {
        use std::io::BufRead as _;

        let mut child = Command::new("flock")
            .arg(lock)
            .args(["sh", "-c", "echo held; exec cat"])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        let mut line = String::new();
        std::io::BufReader::new(child.stdout.take().unwrap())
            .read_line(&mut line)
            .unwrap();
        assert_eq!(line, "held\n");
        Self(child)
    }
}

impl Drop for HeldLock {
    fn drop(&mut self) {
        drop(self.0.stdin.take());
        let _ = self.0.wait();
    }
}

/// The lines the script marked as warnings on its stdout, without the mark.
fn marked(output: &Output) -> Vec<String> {
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(|line| line.strip_prefix(zap_types::deploy::SCRIPT_WARNING_PREFIX))
        .map(str::to_owned)
        .collect()
}

/// An operator's name and a version read off the target that a shell, `printf` and JSON
/// would each read as more than text.
const DEPLOYED_BY: &str = "o'p \"q\" $(id) `id` \\n %s@box";
const PREVIOUS_VERSION: &str = "v0 \"x\" \\ \t$HOME";

/// A shared file's name that a shell would read as more than a name.
const ODD_SHARED: &str = "o'dd \"q\" $HOME `id` \\n *.env";

/// What the planner reads as the live release of the app under `app`: the last segment
/// of what `current` names, none when there is no link or it names nothing.
fn live_version(app: &Path) -> Option<String> {
    let target = std::fs::read_link(app.join("current")).ok()?;
    let text = target.to_string_lossy();
    let version = text.trim().rsplit('/').next().unwrap_or("").trim();
    (!version.is_empty()).then(|| version.to_owned())
}

/// The extract-and-swap script the planner emits for an app under `app`, planned against
/// what its `current` names now, and where it expects the archive.
fn deploy_script(app: &Path, version: &str, prepare: &[&str]) -> (String, PathBuf) {
    deploy_script_against(app, version, prepare, live_version(app).as_deref())
}

/// [`deploy_script`] planned when the live release was `previous`.
fn deploy_script_against(
    app: &Path,
    version: &str,
    prepare: &[&str],
    previous: Option<&str>,
) -> (String, PathBuf) {
    let spec = DeploySpec {
        build: None,
        artifacts: vec!["build/".to_owned()],
        path: app.to_string_lossy().into_owned(),
        releases: 5,
        service: None,
        shared: vec![".env".to_owned(), ODD_SHARED.to_owned()],
        prepare: prepare.iter().map(|&command| command.to_owned()).collect(),
        health: None,
    };
    let ctx = DeployContext {
        references: std::collections::BTreeMap::new(),
        version: version.to_owned(),
        target_user: "deploy".to_owned(),
        deployed_by: DEPLOYED_BY.to_owned(),
        previous_version: previous.map(str::to_owned),
        target_host: "host.example".to_owned(),
        health_domain: String::new(),
        dirty: false,
        skip_build: false,
        preflight: DriftPreflight::Skipped,
    };
    let plan = plan_deploy(&spec, &Target::default(), &ctx);
    let mut script = None;
    let mut remote = None;
    for step in plan.steps {
        match step.action {
            DeployAction::ExtractSwap { script: text } => script = Some(text),
            DeployAction::Upload { remote: path } => remote = Some(PathBuf::from(path)),
            _ => {}
        }
    }
    (script.unwrap(), remote.unwrap())
}

/// The deploy script extracts the archive it finds only when it is the one whose digest
/// arrives on its stdin — a regular file of the caller's that nobody else can write —
/// and removes it whichever way it ends. A release is extracted without its set-id
/// bits, the shared file is linked in, `current` is swapped, `deploy_info.json` is valid
/// JSON holding each value as it was, and a `prepare` command reads nothing from the
/// script's stdin. A wrong digest, a digest that never arrives,
/// an archive others can write, no archive, a missing shared file, and a release that
/// ships a directory at a shared name each stop it with `current` where it was, no
/// release directory made, and no staging left. A deploy of a
/// version whose directory exists — not live, or live — replaces it whole, and one that
/// fails after the extraction leaves what was there.
#[test]
fn the_deploy_script_extracts_only_the_archive_it_was_told_of_under_both_shells() {
    let dir = crate::test_scratch::tempdir();
    let bin = stand_in_bin(dir.path());
    let src = dir.path().join("release-src");
    std::fs::create_dir(&src).unwrap();
    std::fs::write(src.join("f.txt"), "release").unwrap();
    std::fs::write(src.join("server"), "#!/bin/sh\n").unwrap();
    std::fs::set_permissions(src.join("server"), std::fs::Permissions::from_mode(0o4755)).unwrap();
    let archive = dir.path().join("release.tar.gz");
    assert!(host_tar(&["-czf"], &archive, &src, "."), "a host tar");
    let bytes = std::fs::read(&archive).unwrap();
    let digest = sha512_hex(&bytes);
    // A release that ships a directory where a shared file is linked.
    std::fs::create_dir(src.join(".env")).unwrap();
    std::fs::write(src.join(".env").join("inside"), "shipped").unwrap();
    let shadowing_archive = dir.path().join("shadowing.tar.gz");
    assert!(
        host_tar(&["-czf"], &shadowing_archive, &src, "."),
        "a host tar"
    );
    let shadowing = std::fs::read(&shadowing_archive).unwrap();
    let shadowing_line = format!("{}\n", sha512_hex(&shadowing));

    let mut checked = Vec::new();
    for leg in deploy_shells(dir.path(), &bin) {
        let (label, shell, env_path) = &leg;
        let case = tempfile::tempdir_in(dir.path()).unwrap();
        let app = case.path().join("it's an app");
        std::fs::create_dir_all(app.join("shared")).unwrap();
        std::fs::write(app.join("shared").join(".env"), "A=1\n").unwrap();
        std::fs::write(app.join("shared").join(ODD_SHARED), "B=2\n").unwrap();
        let upload = |remote: &Path, mode: u32| {
            std::fs::write(remote, &bytes).unwrap();
            std::fs::set_permissions(remote, std::fs::Permissions::from_mode(mode)).unwrap();
        };
        let deliver = |script: &str, stdin: &[u8]| {
            let stdin = Delivery::of(script, Some(stdin)).unwrap().stdin;
            feed(shell, env_path.as_ref(), &stdin)
        };
        let line = format!("{digest}\n");
        // A live release under a name that a shell, `printf` and JSON would each read as
        // more than text, which the plan reads and the script checks again.
        std::fs::create_dir(app.join("releases")).unwrap();
        symlink(
            app.join("releases").join(PREVIOUS_VERSION),
            app.join("current"),
        )
        .unwrap();

        // The release it was told of.
        let (script, remote) = deploy_script(&app, "v1", &["cat > stdin-seen"]);
        assert_eq!(remote, app.join(".zap-deploy-deploy-v1.tar.gz"), "{label}");
        upload(&remote, 0o600);
        let output = deliver(&script, line.as_bytes());
        assert!(output.status.success(), "{label}: {output:?}");
        let release = app.join("releases").join("v1");
        assert_eq!(
            std::fs::read_link(app.join("current")).unwrap(),
            release,
            "{label}"
        );
        assert_eq!(std::fs::read(release.join("f.txt")).unwrap(), b"release");
        assert_eq!(
            mode_of(&release.join("server")),
            0o755,
            "{label}: no set-id bit"
        );
        assert_eq!(
            std::fs::read_link(release.join(".env")).unwrap(),
            app.join("shared").join(".env"),
            "{label}"
        );
        // A shared file is linked under its own name, whatever the name holds.
        assert_eq!(
            std::fs::read_link(release.join(ODD_SHARED)).unwrap(),
            app.join("shared").join(ODD_SHARED),
            "{label}"
        );
        assert_eq!(std::fs::read(release.join(ODD_SHARED)).unwrap(), b"B=2\n");
        assert_eq!(
            entries(&app.join("shared")),
            [".env", ODD_SHARED],
            "{label}: nothing else was made of the name"
        );
        assert_eq!(
            std::fs::read(release.join("stdin-seen")).unwrap(),
            b"",
            "{label}: a prepare command reads nothing"
        );
        // The record is JSON whatever its values hold, each arriving as written.
        let info: serde_json::Value =
            serde_json::from_slice(&std::fs::read(app.join("deploy_info.json")).unwrap())
                .unwrap_or_else(|error| panic!("{label}: deploy_info.json: {error}"));
        assert_eq!(info["version"], "v1", "{label}");
        assert_eq!(info["deployed_by"], DEPLOYED_BY, "{label}");
        assert_eq!(info["previous_version"], PREVIOUS_VERSION, "{label}");
        assert_eq!(
            info["deployed_at"].as_str().map(str::len),
            Some("2000-01-01T00:00:00Z".len()),
            "{label}"
        );
        assert!(!remote.exists(), "{label}: the archive is removed");

        // An archive name the trap can't remove at exit (a `prepare` command leaves a
        // directory there) doesn't turn a completed deploy into a failed one.
        let blocker = format!(
            "mkdir -- {}",
            zap_types::shell::single_quote(
                &app.join(".zap-deploy-deploy-v1b.tar.gz").to_string_lossy()
            )
        );
        let (script, remote) = deploy_script(&app, "v1b", &[&blocker]);
        upload(&remote, 0o600);
        let output = deliver(&script, line.as_bytes());
        assert!(output.status.success(), "{label}: {output:?}");
        assert!(
            String::from_utf8_lossy(&output.stdout).contains("Deployed version v1b"),
            "{label}: {output:?}"
        );
        assert!(
            remote.is_dir(),
            "{label}: the trap's `rm` had a directory to fail on"
        );
        std::fs::remove_dir(&remote).unwrap();
        let release = app.join("releases").join("v1b");

        // Everything that stops it: `current` stays, no release is made, and the
        // archive is gone all the same.
        let stopped = |what: &str, version: &str, mode: Option<u32>, stdin: &[u8], says: &str| {
            let (script, remote) = deploy_script(&app, version, &[]);
            if let Some(mode) = mode {
                upload(&remote, mode);
            }
            let output = deliver(&script, stdin);
            assert!(!output.status.success(), "{label}: {what}: {output:?}");
            assert!(
                stderr(&output).contains(says),
                "{label}: {what}: {output:?}"
            );
            assert_eq!(
                std::fs::read_link(app.join("current")).unwrap(),
                release,
                "{label}: {what}"
            );
            assert!(
                !app.join("releases").join(version).exists(),
                "{label}: {what}: nothing was extracted"
            );
            assert!(!remote.exists(), "{label}: {what}: the archive is removed");
            assert!(
                leftovers(&app).is_empty(),
                "{label}: {what}: no staging is left"
            );
        };
        let other = format!("{}\n", sha512_hex(b"another archive"));
        stopped(
            "another archive's digest",
            "v2",
            Some(0o600),
            other.as_bytes(),
            "is not the archive this deploy built",
        );
        stopped(
            "no digest",
            "v3",
            Some(0o600),
            b"",
            "the digest of the release archive did not arrive",
        );
        stopped(
            "a digest cut short",
            "v4",
            Some(0o600),
            &line.as_bytes()[..64],
            "did not arrive",
        );
        for (mode, what) in [(0o620, "group-writable"), (0o602, "world-writable")] {
            stopped(
                what,
                "v5",
                Some(mode),
                line.as_bytes(),
                "can be written by other users",
            );
        }
        stopped(
            "no archive",
            "v6",
            None,
            line.as_bytes(),
            "no release archive at",
        );
        // A `stat` or an `id` that prints nothing answers neither check: an owner that
        // wasn't read is not the caller's, and a mode that wasn't read is not a safe one.
        let real_stat =
            zap_types::shell::single_quote(&on_path(env_path.as_ref(), "stat").to_string_lossy());
        for (what, id, stat, says) in [
            (
                "no owner and no uid",
                Some("exit 0"),
                format!("[ \"$3\" = %u ] || exec {real_stat} \"$@\""),
                "is not a file this user uploaded",
            ),
            (
                "no mode",
                None,
                format!("[ \"$3\" = %a ] || exec {real_stat} \"$@\""),
                "can be written by other users",
            ),
        ] {
            let lead = tempfile::tempdir_in(dir.path()).unwrap();
            if let Some(id) = id {
                executable(&lead.path().join("id"), id);
            }
            executable(&lead.path().join("stat"), &stat);
            let (script, remote) = deploy_script(&app, "v8", &[]);
            upload(&remote, 0o600);
            let stdin = Delivery::of(&script, Some(line.as_bytes())).unwrap().stdin;
            let output = feed(shell, Some(&led_by(lead.path(), env_path.as_ref())), &stdin);
            assert!(!output.status.success(), "{label}: {what}: {output:?}");
            assert!(
                stderr(&output).contains(says),
                "{label}: {what}: {output:?}"
            );
            assert!(!app.join("releases").join("v8").exists(), "{label}: {what}");
            assert!(!remote.exists(), "{label}: {what}");
        }

        std::fs::remove_file(app.join("shared").join(".env")).unwrap();
        stopped(
            "a missing shared file",
            "v7",
            Some(0o600),
            line.as_bytes(),
            "not found under shared/",
        );
        std::fs::write(app.join("shared").join(".env"), "A=1\n").unwrap();

        // A release that ships a directory at a shared name: `ln -sfn` would link inside
        // it and the release would run on the shipped directory, so the deploy stops,
        // with `current` where it was, no release made, and nothing left.
        let (script, remote) = deploy_script(&app, "v13", &[]);
        std::fs::write(&remote, &shadowing).unwrap();
        std::fs::set_permissions(&remote, std::fs::Permissions::from_mode(0o600)).unwrap();
        let output = deliver(&script, shadowing_line.as_bytes());
        assert!(
            !output.status.success(),
            "{label}: a shipped .env/: {output:?}"
        );
        assert!(
            stderr(&output)
                .contains("the release ships a directory at .env, where a shared file is linked"),
            "{label}: {output:?}"
        );
        assert_eq!(std::fs::read_link(app.join("current")).unwrap(), release);
        assert!(!app.join("releases").join("v13").exists(), "{label}");
        assert!(!remote.exists(), "{label}: the archive is removed");
        assert!(leftovers(&app).is_empty(), "{label}: no staging is left");
        assert_eq!(
            std::fs::read(app.join("shared").join(".env")).unwrap(),
            b"A=1\n",
            "{label}: the shared file is untouched"
        );

        // A release is one whole extraction: a deploy of a version whose directory is
        // left from before — not live, then live under `--force` — replaces it, so a
        // file the new archive doesn't hold is gone, and `current` names the new tree.
        let deployed = |version: &str, prepare: &[&str]| {
            let (script, remote) = deploy_script(&app, version, prepare);
            upload(&remote, 0o600);
            deliver(&script, line.as_bytes())
        };
        let v1 = app.join("releases").join("v1");
        for what in ["a release that isn't live", "the live release"] {
            std::fs::write(v1.join("stale"), "old").unwrap();
            let output = deployed("v1", &[]);
            assert!(output.status.success(), "{label}: {what}: {output:?}");
            assert_eq!(std::fs::read_link(app.join("current")).unwrap(), v1);
            assert!(!v1.join("stale").exists(), "{label}: {what}");
            assert_eq!(std::fs::read(v1.join("f.txt")).unwrap(), b"release");
            assert!(leftovers(&app).is_empty(), "{label}: {what}");
        }

        // A deploy that fails after the extraction — a `prepare` command — leaves no
        // staging, `current` where it was, and a directory already holding the version's
        // name as it was.
        for (version, existing) in [("v9", false), ("v10", true)] {
            let release = app.join("releases").join(version);
            if existing {
                std::fs::create_dir(&release).unwrap();
                std::fs::write(release.join("kept"), "x").unwrap();
            }
            let output = deployed(version, &["false"]);
            assert!(!output.status.success(), "{label}: {version}: {output:?}");
            assert_eq!(std::fs::read_link(app.join("current")).unwrap(), v1);
            assert_eq!(release.join("kept").exists(), existing, "{label}");
            assert!(!release.join("f.txt").exists(), "{label}");
            assert!(leftovers(&app).is_empty(), "{label}: {version}");
        }

        // A directory moved aside comes back when the release never takes its name: the
        // rename into place fails, or a hangup lands just as the move aside completes
        // (the shell runs the signal's trap before its next command).
        let real_mv =
            zap_types::shell::single_quote(&on_path(env_path.as_ref(), "mv").to_string_lossy());
        for (what, version, mv) in [
            (
                "the rename into place fails",
                "v11",
                format!("case $3 in */.zap-stage) exit 1;; esac\nexec {real_mv} \"$@\""),
            ),
            (
                "a hangup during the move aside",
                "v12",
                format!(
                    "case $4 in */.zap-old-*) {real_mv} \"$@\"; zap_s=$?; kill -HUP $PPID; exit $zap_s;; esac\nexec {real_mv} \"$@\""
                ),
            ),
        ] {
            let release = app.join("releases").join(version);
            std::fs::create_dir(&release).unwrap();
            std::fs::write(release.join("kept"), "x").unwrap();
            let lead = tempfile::tempdir_in(dir.path()).unwrap();
            executable(&lead.path().join("mv"), &mv);
            let (script, remote) = deploy_script(&app, version, &[]);
            upload(&remote, 0o600);
            let stdin = Delivery::of(&script, Some(line.as_bytes())).unwrap().stdin;
            let output = feed(shell, Some(&led_by(lead.path(), env_path.as_ref())), &stdin);
            assert!(!output.status.success(), "{label}: {what}: {output:?}");
            assert_eq!(
                std::fs::read_link(app.join("current")).unwrap(),
                v1,
                "{label}: {what}"
            );
            assert!(release.join("kept").exists(), "{label}: {what}: {output:?}");
            assert!(!release.join("f.txt").exists(), "{label}: {what}");
            assert!(leftovers(&app).is_empty(), "{label}: {what}");
            assert!(!remote.exists(), "{label}: {what}");
        }
        checked.push(*label);
    }
    eprintln!("deploy script checked under: {checked:?}");
}

/// One deploy of an app at a time. The script takes the app's lock, made with no
/// permission for other users, and a deploy that finds it held stops at once — saying
/// so, with its archive removed — and touches nothing in `releases/`, not even what a
/// deploy that died there left. `prepare` runs with the lock held and its descriptor
/// closed, so a process it leaves running doesn't hold the lock past the script.
#[test]
fn the_deploy_script_holds_the_app_lock_under_both_shells() {
    let dir = crate::test_scratch::tempdir();
    let bin = stand_in_bin(dir.path());
    let src = dir.path().join("release-src");
    std::fs::create_dir(&src).unwrap();
    std::fs::write(src.join("f.txt"), "release").unwrap();
    let archive = dir.path().join("release.tar.gz");
    assert!(host_tar(&["-czf"], &archive, &src, "."), "a host tar");
    let bytes = std::fs::read(&archive).unwrap();
    let line = format!("{}\n", sha512_hex(&bytes));

    let mut checked = Vec::new();
    for leg in deploy_shells(dir.path(), &bin) {
        let (label, shell, env_path) = &leg;
        let case = tempfile::tempdir_in(dir.path()).unwrap();
        let app = case.path().join("it's an app");
        std::fs::create_dir_all(app.join("shared")).unwrap();
        std::fs::write(app.join("shared").join(".env"), "A=1\n").unwrap();
        std::fs::write(app.join("shared").join(ODD_SHARED), "B=2\n").unwrap();
        let lock = app.join(".zap-deploy.lock");
        // Each deploy under an open umask: the lock's mode is the script's doing.
        let deployed = |version: &str, prepare: &[&str]| {
            let (script, remote) = deploy_script(&app, version, prepare);
            std::fs::write(&remote, &bytes).unwrap();
            std::fs::set_permissions(&remote, std::fs::Permissions::from_mode(0o600)).unwrap();
            let script = format!("umask 000\n{script}");
            let stdin = Delivery::of(&script, Some(line.as_bytes())).unwrap().stdin;
            (feed(shell, env_path.as_ref(), &stdin), remote)
        };

        // The first deploy makes the lock with nothing for others;
        // `prepare` finds it held and its own descriptor closed, and a process it leaves
        // running doesn't keep it.
        let (output, _) = deployed(
            "v1",
            &[
                "if flock -n ../../.zap-deploy.lock true; then echo unlocked >&2; exit 1; fi",
                "if sh -c '[ -e /proc/self/fd/9 ]'; then echo inherited >&2; exit 1; fi",
                "sleep 30 >/dev/null 2>&1 </dev/null & echo $! > ../../sleeper",
            ],
        );
        assert!(output.status.success(), "{label}: {output:?}");
        assert!(lock.is_file(), "{label}");
        assert_eq!(mode_of(&lock) & 0o007, 0, "{label}: nothing for others");
        let sleeper = std::fs::read_to_string(app.join("sleeper")).unwrap();
        let (output, _) = deployed("v2", &[]);
        let _ = Command::new("kill").arg(sleeper.trim()).status();
        assert!(
            output.status.success(),
            "{label}: the lock went with the script: {output:?}"
        );
        assert!(marked(&output).is_empty(), "{label}: {output:?}");
        let v2 = app.join("releases").join("v2");
        assert_eq!(std::fs::read_link(app.join("current")).unwrap(), v2);

        // Another deploy holds it: this one stops at once, and what lies in `releases/`
        // — the other's staging and its release moved aside — is left as it is.
        let releases = app.join("releases");
        std::fs::create_dir(releases.join(".zap-stage")).unwrap();
        std::fs::create_dir(releases.join(".zap-old-v2")).unwrap();
        let held = HeldLock::take(&lock);
        let (output, remote) = deployed("v2", &[]);
        drop(held);
        assert!(!output.status.success(), "{label}: {output:?}");
        assert!(
            stderr(&output).contains("ERROR: another deploy is running for this app"),
            "{label}: {output:?}"
        );
        // The script's own reason is marked on its stdout too, where no `prepare`
        // command's output goes.
        assert_eq!(
            String::from_utf8_lossy(&output.stdout),
            format!(
                "{}another deploy is running for this app\n",
                zap_types::deploy::SCRIPT_ERROR_PREFIX
            ),
            "{label}"
        );
        assert!(!remote.exists(), "{label}: the archive is removed");
        assert_eq!(
            leftovers(&app),
            [".zap-old-v2", ".zap-stage"],
            "{label}: nothing of the other deploy's is touched"
        );
        assert!(v2.join("f.txt").exists(), "{label}");
        assert_eq!(std::fs::read_link(app.join("current")).unwrap(), v2);
        assert!(marked(&output).is_empty(), "{label}: {output:?}");
        std::fs::remove_dir(releases.join(".zap-stage")).unwrap();
        std::fs::remove_dir(releases.join(".zap-old-v2")).unwrap();

        // The lock is opened read-only: a lock file this user may only read (as a
        // group member the umask gave read alone would find it) still holds. Skipped
        // where the write bits bind no one (root).
        std::fs::set_permissions(&lock, std::fs::Permissions::from_mode(0o440)).unwrap();
        if std::fs::OpenOptions::new()
            .append(true)
            .open(&lock)
            .is_err()
        {
            let (output, _) = deployed("v4", &[]);
            assert!(
                output.status.success(),
                "{label}: a read-only lock: {output:?}"
            );
            assert_eq!(
                std::fs::read_link(app.join("current")).unwrap(),
                releases.join("v4")
            );
        }
        std::fs::set_permissions(&lock, std::fs::Permissions::from_mode(0o640)).unwrap();

        // A target with no `flock` is told so, before anything in `releases/`.
        let only = only_tools(
            dir.path(),
            env_path.as_ref(),
            &["cat", "rm", "mkdir", "id", "stat", "sha512sum", "tar"],
        );
        let (script, remote) = deploy_script(&app, "v3", &[]);
        std::fs::write(&remote, &bytes).unwrap();
        std::fs::set_permissions(&remote, std::fs::Permissions::from_mode(0o600)).unwrap();
        let stdin = Delivery::of(&script, Some(line.as_bytes())).unwrap().stdin;
        let output = feed(shell, Some(&only.into_os_string()), &stdin);
        assert!(!output.status.success(), "{label}: {output:?}");
        assert!(
            stderr(&output).contains("no flock on this machine"),
            "{label}: {output:?}"
        );
        assert!(!releases.join("v3").exists(), "{label}");
        checked.push(*label);
    }
    eprintln!("deploy lock checked under: {checked:?}");
}

/// Under the lock, before anything else in `releases/`, the script puts right what a
/// deploy that did not finish left, and says what it did: the staging directory is
/// removed; a release moved aside under its version comes back when its name is empty —
/// so a `current` left naming nothing resolves again, even when this deploy then fails —
/// and is removed when the name is filled. An entry under a name the script doesn't
/// give is left alone, unmentioned.
#[test]
fn the_deploy_script_recovers_what_a_dead_deploy_left_under_both_shells() {
    let dir = crate::test_scratch::tempdir();
    let bin = stand_in_bin(dir.path());
    let src = dir.path().join("release-src");
    std::fs::create_dir(&src).unwrap();
    std::fs::write(src.join("f.txt"), "release").unwrap();
    let archive = dir.path().join("release.tar.gz");
    assert!(host_tar(&["-czf"], &archive, &src, "."), "a host tar");
    let bytes = std::fs::read(&archive).unwrap();
    let line = format!("{}\n", sha512_hex(&bytes));

    let mut checked = Vec::new();
    for leg in deploy_shells(dir.path(), &bin) {
        let (label, shell, env_path) = &leg;
        let case = tempfile::tempdir_in(dir.path()).unwrap();
        let app = case.path().join("it's an app");
        std::fs::create_dir_all(app.join("shared")).unwrap();
        std::fs::write(app.join("shared").join(".env"), "A=1\n").unwrap();
        std::fs::write(app.join("shared").join(ODD_SHARED), "B=2\n").unwrap();
        let releases = app.join("releases");
        let deployed = |version: &str, stdin_line: &str| {
            let (script, remote) = deploy_script(&app, version, &[]);
            std::fs::write(&remote, &bytes).unwrap();
            std::fs::set_permissions(&remote, std::fs::Permissions::from_mode(0o600)).unwrap();
            let stdin = Delivery::of(&script, Some(stdin_line.as_bytes()))
                .unwrap()
                .stdin;
            feed(shell, env_path.as_ref(), &stdin)
        };
        let planted = |name: &str, content: &str| {
            std::fs::create_dir(releases.join(name)).unwrap();
            std::fs::write(releases.join(name).join("kept"), content).unwrap();
        };
        let output = deployed("v1", &line);
        assert!(output.status.success(), "{label}: {output:?}");

        // A killed `--force` of the live release: moved aside, its name empty, `current`
        // naming nothing. The next deploy puts it back before it checks its archive,
        // so even one that then fails leaves `current` resolving.
        let v1 = releases.join("v1");
        std::fs::rename(&v1, releases.join(".zap-old-v1")).unwrap();
        let other = format!("{}\n", sha512_hex(b"another archive"));
        let output = deployed("v2", &other);
        assert!(!output.status.success(), "{label}: {output:?}");
        assert!(
            stderr(&output).contains("is not the archive this deploy built"),
            "{label}: {output:?}"
        );
        assert_eq!(
            marked(&output),
            ["restored releases/v1, which a deploy that did not finish had moved aside"],
            "{label}"
        );
        assert_eq!(std::fs::read_link(app.join("current")).unwrap(), v1);
        assert_eq!(std::fs::read(v1.join("f.txt")).unwrap(), b"release");
        assert!(leftovers(&app).is_empty(), "{label}");

        // The staging directory; a release moved aside whose name was filled again; and
        // look-alikes under names the script doesn't give, which it leaves alone.
        planted(".zap-stage", "half");
        planted(".zap-old-v1", "old");
        let strangers = [".zap-old.4242", ".zap-stage.4242", ".zap-stagex"];
        for name in strangers {
            planted(name, name);
        }
        let output = deployed("v3", &line);
        assert!(output.status.success(), "{label}: {output:?}");
        assert_eq!(
            marked(&output),
            [
                "removed releases/.zap-stage, the staging directory of a deploy that did not finish",
                "removed releases/.zap-old-v1, the release a deploy that did not finish had replaced",
            ],
            "{label}"
        );
        assert_eq!(leftovers(&app), strangers, "{label}");
        for name in strangers {
            assert_eq!(
                std::fs::read(releases.join(name).join("kept")).unwrap(),
                name.as_bytes(),
                "{label}"
            );
        }
        assert_eq!(std::fs::read(v1.join("f.txt")).unwrap(), b"release");
        assert!(
            !v1.join("kept").exists(),
            "{label}: the live name kept its own"
        );
        assert_eq!(
            std::fs::read_link(app.join("current")).unwrap(),
            releases.join("v3")
        );
        checked.push(*label);
    }
    eprintln!("deploy recovery checked under: {checked:?}");
}

/// Under the lock, after the recovery, the script checks that `current` still names the
/// release its plan read as live, by the link's last segment: a deploy planned before
/// another one swapped stops, saying what `current` names now, with its archive removed
/// and nothing of its own made — so the release it would roll back to is the one live
/// just before its swap. A plan that read no live release stops on a `current` that
/// names one, and goes on with none; a plan whose read still holds goes on.
#[test]
fn the_deploy_script_stops_when_current_moved_since_its_plan_under_both_shells() {
    let dir = crate::test_scratch::tempdir();
    let bin = stand_in_bin(dir.path());
    let src = dir.path().join("release-src");
    std::fs::create_dir(&src).unwrap();
    std::fs::write(src.join("f.txt"), "release").unwrap();
    let archive = dir.path().join("release.tar.gz");
    assert!(host_tar(&["-czf"], &archive, &src, "."), "a host tar");
    let bytes = std::fs::read(&archive).unwrap();
    let line = format!("{}\n", sha512_hex(&bytes));

    let mut checked = Vec::new();
    for leg in deploy_shells(dir.path(), &bin) {
        let (label, shell, env_path) = &leg;
        let case = tempfile::tempdir_in(dir.path()).unwrap();
        let app = case.path().join("it's an app");
        std::fs::create_dir_all(app.join("shared")).unwrap();
        std::fs::write(app.join("shared").join(".env"), "A=1\n").unwrap();
        std::fs::write(app.join("shared").join(ODD_SHARED), "B=2\n").unwrap();
        let releases = app.join("releases");
        let run = |(script, remote): (String, PathBuf)| {
            std::fs::write(&remote, &bytes).unwrap();
            std::fs::set_permissions(&remote, std::fs::Permissions::from_mode(0o600)).unwrap();
            let stdin = Delivery::of(&script, Some(line.as_bytes())).unwrap().stdin;
            (feed(shell, env_path.as_ref(), &stdin), remote)
        };

        // A first deploy: no live release read, none there.
        let (output, _) = run(deploy_script_against(&app, "v1", &[], None));
        assert!(output.status.success(), "{label}: {output:?}");
        let v1 = releases.join("v1");
        assert_eq!(std::fs::read_link(app.join("current")).unwrap(), v1);

        // Planned while v1 was live; v2 swapped in before it ran. It stops after the
        // recovery, touching nothing of its own.
        let stale = deploy_script_against(&app, "v3", &[], Some("v1"));
        let (output, _) = run(deploy_script(&app, "v2", &[]));
        assert!(output.status.success(), "{label}: {output:?}");
        let v2 = releases.join("v2");
        std::fs::create_dir(releases.join(".zap-stage")).unwrap();
        let (output, remote) = run(stale);
        assert!(!output.status.success(), "{label}: {output:?}");
        assert!(
            stderr(&output).contains(&format!(
                "ERROR: `current` changed since this deploy was planned: it names {} now \
                 (another deploy ran, or something else is there now); run zap deploy again",
                v2.display()
            )),
            "{label}: {output:?}"
        );
        assert_eq!(
            marked(&output),
            ["removed releases/.zap-stage, the staging directory of a deploy that did not finish"],
            "{label}: the recovery ran first"
        );
        assert_eq!(std::fs::read_link(app.join("current")).unwrap(), v2);
        assert!(!releases.join("v3").exists(), "{label}");
        assert!(leftovers(&app).is_empty(), "{label}");
        assert!(!remote.exists(), "{label}: the archive is removed");

        // A plan that read no live release (its read failed) stops on one that is there.
        let (output, _) = run(deploy_script_against(&app, "v4", &[], None));
        assert!(!output.status.success(), "{label}: {output:?}");
        assert!(
            stderr(&output).contains("changed since this deploy was planned: it names"),
            "{label}: {output:?}"
        );
        assert!(!releases.join("v4").exists(), "{label}");

        // A plan whose read still holds goes on, `current` compared by its last segment.
        std::fs::remove_file(app.join("current")).unwrap();
        symlink("releases/v2", app.join("current")).unwrap();
        let (output, _) = run(deploy_script_against(&app, "v5", &[], Some("v2")));
        assert!(output.status.success(), "{label}: {output:?}");
        assert_eq!(
            std::fs::read_link(app.join("current")).unwrap(),
            releases.join("v5")
        );
        checked.push(*label);
    }
    eprintln!("deploy plan staleness checked under: {checked:?}");
}

/// The deploy script prints `SWAPPED_LINE` once `current` names the new release, and
/// nothing on its stdout but its own lines: a `prepare` command's output goes to
/// stderr — so a marked line it prints is no warning — and one that exits or `exec`s
/// ends only itself. What fails after the swap — here a prune
/// that can't remove an old release — is a marked warning, and the script still exits
/// 0; a `prepare` command that fails stops it before the swap, with no such line. A
/// `current` read with a trailing slash is the release it names, and a plan that read
/// no live release stops on one.
#[test]
fn the_deploy_script_marks_its_swap_and_only_warns_after_it_under_both_shells() {
    use std::time::{Duration, SystemTime};
    use zap_types::deploy::SWAPPED_LINE;

    let dir = crate::test_scratch::tempdir();
    let bin = stand_in_bin(dir.path());
    let src = dir.path().join("release-src");
    std::fs::create_dir(&src).unwrap();
    std::fs::write(src.join("f.txt"), "release").unwrap();
    let archive = dir.path().join("release.tar.gz");
    assert!(host_tar(&["-czf"], &archive, &src, "."), "a host tar");
    let bytes = std::fs::read(&archive).unwrap();
    let line = format!("{}\n", sha512_hex(&bytes));
    // The script's stdout less its marked warnings (`marked`).
    let stdout_lines = |output: &Output| -> Vec<String> {
        String::from_utf8_lossy(&output.stdout)
            .lines()
            .filter(|line| !line.starts_with(zap_types::deploy::SCRIPT_WARNING_PREFIX))
            .map(str::to_owned)
            .collect()
    };

    let mut checked = Vec::new();
    for leg in deploy_shells(dir.path(), &bin) {
        let (label, shell, env_path) = &leg;
        let case = tempfile::tempdir_in(dir.path()).unwrap();
        let app = case.path().join("it's an app");
        std::fs::create_dir_all(app.join("shared")).unwrap();
        std::fs::write(app.join("shared").join(".env"), "A=1\n").unwrap();
        std::fs::write(app.join("shared").join(ODD_SHARED), "B=2\n").unwrap();
        let releases = app.join("releases");
        // Six old releases, the oldest holding what its owner can't remove.
        for (i, name) in [
            "aaaa001", "aaaa002", "aaaa003", "aaaa004", "aaaa005", "aaaa006",
        ]
        .into_iter()
        .enumerate()
        {
            let release = releases.join(name);
            std::fs::create_dir_all(&release).unwrap();
            if i == 0 {
                std::fs::create_dir(release.join("held")).unwrap();
                std::fs::write(release.join("held").join("f"), "x").unwrap();
                std::fs::set_permissions(
                    release.join("held"),
                    std::fs::Permissions::from_mode(0o555),
                )
                .unwrap();
            }
            let at = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000 + i as u64);
            std::fs::File::open(&release)
                .unwrap()
                .set_modified(at)
                .unwrap();
        }
        symlink(releases.join("aaaa006"), app.join("current")).unwrap();
        let run = |(script, remote): (String, PathBuf)| {
            std::fs::write(&remote, &bytes).unwrap();
            std::fs::set_permissions(&remote, std::fs::Permissions::from_mode(0o600)).unwrap();
            let stdin = Delivery::of(&script, Some(line.as_bytes())).unwrap().stdin;
            (feed(shell, env_path.as_ref(), &stdin), remote)
        };

        // `prepare` commands that exit, `exec`, and print: the swap goes on, and the
        // prune that fails after it is a warning.
        let (output, _) = run(deploy_script(
            &app,
            "bbbb001",
            &[
                "exit 0",
                "exec sh -c :",
                "echo prepared",
                "echo also >&2",
                "echo 'zap warning: printed by a prepare command'",
            ],
        ));
        assert!(output.status.success(), "{label}: {output:?}");
        assert_eq!(
            stdout_lines(&output),
            [SWAPPED_LINE, "Deployed version bbbb001"],
            "{label}: {output:?}"
        );
        assert!(
            stderr(&output).contains("prepared\n"),
            "{label}: {output:?}"
        );
        assert_eq!(
            std::fs::read_link(app.join("current")).unwrap(),
            releases.join("bbbb001"),
            "{label}"
        );
        let warned = marked(&output);
        assert!(
            !warned
                .iter()
                .any(|warning| warning.contains("prepare command")),
            "{label}: {output:?}"
        );
        assert_eq!(
            warned.first().map(String::as_str),
            Some("after the swap, the old releases were not pruned"),
            "{label}: {output:?}"
        );
        assert!(
            warned.len() > 1,
            "{label}: rm's own words follow: {output:?}"
        );
        assert!(releases.join("aaaa001").exists(), "{label}");
        assert!(app.join("deploy_info.json").is_file(), "{label}");

        // A `prepare` command that fails stops the script before the swap.
        let (output, remote) = run(deploy_script(&app, "cccc001", &["exit 3"]));
        assert!(!output.status.success(), "{label}: {output:?}");
        assert!(
            !stdout_lines(&output)
                .iter()
                .any(|line| line == SWAPPED_LINE),
            "{label}: {output:?}"
        );
        assert_eq!(
            std::fs::read_link(app.join("current")).unwrap(),
            releases.join("bbbb001"),
            "{label}"
        );
        assert!(!releases.join("cccc001").exists(), "{label}");
        assert!(!remote.exists(), "{label}");

        // A `current` with a trailing slash names its release; a plan that read none
        // stops on it.
        std::fs::remove_file(app.join("current")).unwrap();
        symlink("releases/bbbb001/", app.join("current")).unwrap();
        let (output, _) = run(deploy_script_against(&app, "cccc002", &[], None));
        assert!(!output.status.success(), "{label}: {output:?}");
        assert!(
            stderr(&output).contains("changed since this deploy was planned"),
            "{label}: {output:?}"
        );
        let (output, _) = run(deploy_script_against(&app, "cccc002", &[], Some("bbbb001")));
        assert!(output.status.success(), "{label}: {output:?}");
        assert_eq!(
            std::fs::read_link(app.join("current")).unwrap(),
            releases.join("cccc002"),
            "{label}"
        );
        assert!(
            releases.join("bbbb001").is_dir(),
            "{label}: kept as the previous release"
        );

        std::fs::set_permissions(
            releases.join("aaaa001").join("held"),
            std::fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        checked.push(*label);
    }
    eprintln!("swap line checked under: {checked:?}");
}

/// The auto-rollback's swap (`zap_types::deploy::rollback_swap_command`) re-points
/// `current` at the previous release only while it names the failed one, and only with
/// the app's lock: a `current` a newer deploy replaced, or that names nothing, is left
/// as it is, and so is one while another deploy holds the lock.
#[test]
fn the_rollback_re_points_only_its_own_release_under_both_shells() {
    use zap_types::deploy::{RollbackSwap, rollback_swap_command};

    let dir = crate::test_scratch::tempdir();
    let bin = stand_in_bin(dir.path());
    let mut checked = Vec::new();
    for leg in deploy_shells(dir.path(), &bin) {
        let label = leg.0;
        let case = tempfile::tempdir_in(dir.path()).unwrap();
        let app = case.path().join("it's an app");
        let releases = app.join("releases");
        for name in ["v1", "v2", "v3"] {
            std::fs::create_dir_all(releases.join(name)).unwrap();
        }
        let current = app.join("current");
        let point = |name: Option<&str>| {
            let _ = std::fs::remove_file(&current);
            if let Some(name) = name {
                symlink(releases.join(name), &current).unwrap();
            }
        };
        let command = rollback_swap_command(&app.to_string_lossy(), "v2", "v1");
        let rolled = || {
            let output = run(&leg, &command);
            assert!(output.status.success(), "{label}: {output:?}");
            RollbackSwap::parse(&String::from_utf8_lossy(&output.stdout)).unwrap()
        };

        // Another deploy holds the lock: nothing moves.
        point(Some("v2"));
        let held = HeldLock::take(&app.join(".zap-deploy.lock"));
        assert_eq!(rolled(), RollbackSwap::Busy, "{label}");
        drop(held);
        assert_eq!(std::fs::read_link(&current).unwrap(), releases.join("v2"));

        // A newer deploy replaced the release, and a `current` naming nothing: left.
        point(Some("v3"));
        assert_eq!(rolled(), RollbackSwap::Replaced, "{label}");
        assert_eq!(std::fs::read_link(&current).unwrap(), releases.join("v3"));
        point(None);
        assert_eq!(rolled(), RollbackSwap::Absent, "{label}");
        assert!(std::fs::symlink_metadata(&current).is_err(), "{label}");

        // The previous release is gone: `current` stays rather than naming nothing.
        point(Some("v2"));
        std::fs::rename(releases.join("v1"), case.path().join("v1")).unwrap();
        assert_eq!(rolled(), RollbackSwap::Gone, "{label}");
        assert_eq!(std::fs::read_link(&current).unwrap(), releases.join("v2"));
        std::fs::rename(case.path().join("v1"), releases.join("v1")).unwrap();

        // No `flock`: no token and a failed exit, never `busy`; nothing moves.
        point(Some("v2"));
        let only = only_tools(dir.path(), leg.2.as_ref(), &["readlink", "ln", "mv"]);
        let output = run(
            &(leg.0, leg.1.clone(), Some(only.into_os_string())),
            &command,
        );
        assert!(!output.status.success(), "{label}: {output:?}");
        assert!(
            RollbackSwap::parse(&String::from_utf8_lossy(&output.stdout)).is_err(),
            "{label}: {output:?}"
        );
        assert_eq!(std::fs::read_link(&current).unwrap(), releases.join("v2"));

        // Still this deploy's release: rolled back, and through a lock file this user
        // may only read (the lock is opened read-only).
        std::fs::set_permissions(
            app.join(".zap-deploy.lock"),
            std::fs::Permissions::from_mode(0o440),
        )
        .unwrap();
        point(Some("v2"));
        assert_eq!(rolled(), RollbackSwap::RolledBack, "{label}");
        assert_eq!(std::fs::read_link(&current).unwrap(), releases.join("v1"));
        assert!(!app.join("current.new").exists(), "{label}");
        checked.push(label);
    }
    eprintln!("rollback swap checked under: {checked:?}");
}

/// The release prune (`zap_types::deploy::PRUNE_RELEASES`) under both shells, in a
/// releases directory of its own: it keeps the newest `keep` releases, the live one and
/// the one just deployed among them whatever their age, and removes only directories
/// named as zap names a release. A directory whose name holds a space and the live
/// release's name, one named like an option, a file, a link named like a release and a
/// directory under any other name are all left where they are — and so is the live
/// release. Two releases of the same second are ordered by name, the same way under
/// both shells.
#[test]
fn the_release_prune_removes_only_old_releases_under_both_shells() {
    use std::time::{Duration, SystemTime};

    use zap_types::deploy::{PRUNE_RELEASES, prune_releases_call};

    let dir = crate::test_scratch::tempdir();
    let aged = |path: &Path, age_secs: u64| {
        let at = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000 - age_secs);
        std::fs::File::open(path).unwrap().set_modified(at).unwrap();
    };
    let mut checked = Vec::new();
    for (label, shell, env_path) in test_shells(dir.path(), &["sort", "rm"], None) {
        // An app with `releases` (name, age in seconds), `current` aimed at `live`.
        let app_with = |releases: &[(&str, u64)], live: Option<&str>| {
            let case = tempfile::tempdir_in(dir.path()).unwrap();
            let app = case.path().join("it's an app");
            std::fs::create_dir_all(app.join("releases")).unwrap();
            for (name, age) in releases {
                let release = app.join("releases").join(name);
                std::fs::create_dir(&release).unwrap();
                std::fs::write(release.join("f"), "x").unwrap();
                aged(&release, *age);
            }
            if let Some(live) = live {
                symlink(app.join("releases").join(live), app.join("current")).unwrap();
            }
            (case, app)
        };
        let prune = |app: &Path, keep: u32, version: &str, previous: Option<&str>| {
            let script = format!(
                "set -e\n{PRUNE_RELEASES}{}\necho pruned",
                prune_releases_call(&app.to_string_lossy(), keep, version, previous)
            );
            let mut command = Command::new(&shell);
            if let Some(path) = &env_path {
                command.env("PATH", path);
            }
            let output = command.args(["-c", &script]).output().unwrap();
            assert!(output.status.success(), "{label}: {output:?}");
            assert_eq!(output.stdout, b"pruned\n", "{label}");
            entries(&app.join("releases"))
        };

        // What isn't a release is left alone, whatever its name and age; the live
        // release, the oldest of them, is not a candidate.
        let (_case, app) = app_with(
            &[
                ("aaaa001", 900),
                ("aaaa002", 800),
                ("bbbb001", 700),
                ("cccc001", 0),
                ("zzz bbbb001", 9000),
                ("-rf", 9000),
                ("v1", 9000),
                ("abc", 9000),
                ("ABCD123", 9000),
                ("abcd123-dirty-x", 9000),
                ("abcd123-dirty", 9000),
                ("abcd123-dirty-0123abc", 9000),
                ("abcd123-dirty-0123abcde", 9000),
                ("abcd123-dirty-0123ABCD", 9000),
                ("abcd123-dirty-0123abcd-dirty-0123abcd", 9000),
                (".zap-stage.123", 9000),
                (".zap-old.123", 9000),
            ],
            Some("bbbb001"),
        );
        let releases = app.join("releases");
        std::fs::write(releases.join("dddd001"), "a file").unwrap();
        let elsewhere = app.join("elsewhere");
        std::fs::create_dir(&elsewhere).unwrap();
        std::fs::write(elsewhere.join("kept"), "x").unwrap();
        symlink(&elsewhere, releases.join("eeee001")).unwrap();
        assert_eq!(
            prune(&app, 2, "cccc001", None),
            [
                "-rf",
                ".zap-old.123",
                ".zap-stage.123",
                "ABCD123",
                "abc",
                "abcd123-dirty",
                "abcd123-dirty-0123ABCD",
                "abcd123-dirty-0123abc",
                "abcd123-dirty-0123abcd-dirty-0123abcd",
                "abcd123-dirty-0123abcde",
                "abcd123-dirty-x",
                "bbbb001",
                "cccc001",
                "dddd001",
                "eeee001",
                "v1",
                "zzz bbbb001",
            ],
            "{label}"
        );
        assert!(elsewhere.join("kept").exists(), "{label}");
        assert!(releases.join("bbbb001/f").exists(), "{label}");

        // The count: the release just deployed and the newest others, `keep` in all —
        // one below it, at it, and above it. A dirty tree's release is a release.
        let five = [
            ("1111aaa", 500),
            ("2222aaa-dirty-0123abcd", 400),
            ("3333aaa", 300),
            ("4444aaa", 200),
            ("5555aaa", 0),
        ];
        for (keep, left) in [
            (2, &["4444aaa", "5555aaa"][..]),
            (3, &["3333aaa", "4444aaa", "5555aaa"][..]),
            (
                4,
                &["2222aaa-dirty-0123abcd", "3333aaa", "4444aaa", "5555aaa"][..],
            ),
            (
                5,
                &[
                    "1111aaa",
                    "2222aaa-dirty-0123abcd",
                    "3333aaa",
                    "4444aaa",
                    "5555aaa",
                ][..],
            ),
            (
                6,
                &[
                    "1111aaa",
                    "2222aaa-dirty-0123abcd",
                    "3333aaa",
                    "4444aaa",
                    "5555aaa",
                ][..],
            ),
        ] {
            let (_case, app) = app_with(&five, Some("5555aaa"));
            assert_eq!(
                prune(&app, keep, "5555aaa", None),
                left,
                "{label}: keep {keep}"
            );
        }

        // `current` at an older release (something re-pointed it): that one and the one
        // just deployed are kept, and the newest others fill what is left of the count.
        let (_case, app) = app_with(&five, Some("1111aaa"));
        assert_eq!(
            prune(&app, 3, "5555aaa", None),
            ["1111aaa", "4444aaa", "5555aaa"],
            "{label}"
        );
        let (_case, app) = app_with(&five, Some("1111aaa"));
        assert_eq!(
            prune(&app, 2, "5555aaa", None),
            ["1111aaa", "5555aaa"],
            "{label}"
        );

        // The release just deployed is kept whatever its age, wherever `current` points:
        // a redeploy of the oldest release, `current` re-pointed at another.
        let (_case, app) = app_with(&five, Some("3333aaa"));
        assert_eq!(
            prune(&app, 2, "1111aaa", None),
            ["1111aaa", "3333aaa"],
            "{label}"
        );

        // The release that was live before the deploy is the one a failed deploy is
        // rolled back to, so it is kept however old it is. `current` had been left at the
        // oldest release by an earlier rollback; the deploy swaps to the newest, and the
        // oldest still stands, with the newest other filling the count.
        let (_case, app) = app_with(&five, Some("5555aaa"));
        assert_eq!(
            prune(&app, 3, "5555aaa", Some("1111aaa")),
            ["1111aaa", "4444aaa", "5555aaa"],
            "{label}"
        );
        // At the least count there is: a deploy that failed and was rolled back leaves
        // its release newer than the live one, and the next deploy keeps the live one —
        // its own way back — over it.
        let (_case, app) = app_with(
            &[("cccc001", 200), ("dddd001", 100), ("eeee001", 0)],
            Some("eeee001"),
        );
        assert_eq!(
            prune(&app, 2, "eeee001", Some("cccc001")),
            ["cccc001", "eeee001"],
            "{label}"
        );
        // A previous release that is the newest other changes nothing, and one that is
        // no release here (already gone, or no name zap gives one) protects nothing.
        let (_case, app) = app_with(&five, Some("5555aaa"));
        assert_eq!(
            prune(&app, 2, "5555aaa", Some("4444aaa")),
            ["4444aaa", "5555aaa"],
            "{label}"
        );
        for gone in ["9999aaa", "", "*", "1111aaa 2222aaa-dirty-0123abcd"] {
            let (_case, app) = app_with(&five, Some("5555aaa"));
            assert_eq!(
                prune(&app, 2, "5555aaa", Some(gone)),
                ["4444aaa", "5555aaa"],
                "{label}: {gone:?}"
            );
        }

        // A `current` that leads nowhere, and none at all: the one just deployed is
        // kept, and the count holds.
        for live in [Some("9999aaa"), None] {
            let (_case, app) = app_with(&five, live);
            assert_eq!(
                prune(&app, 2, "5555aaa", None),
                ["4444aaa", "5555aaa"],
                "{label}: {live:?}"
            );
        }

        // A `current` with trailing slashes names its release, which is kept; one
        // whose last segment names no release (`.`, `..`, a path below a release, the
        // root) stops the prune before it removes anything.
        for link in ["releases/1111aaa/", "releases/1111aaa//"] {
            let (_case, app) = app_with(&five, None);
            symlink(link, app.join("current")).unwrap();
            assert_eq!(
                prune(&app, 2, "5555aaa", None),
                ["1111aaa", "5555aaa"],
                "{label}: {link}"
            );
        }
        for link in [
            "releases/1111aaa/.",
            "releases/1111aaa/..",
            "releases/1111aaa/sub",
            "/",
        ] {
            let (_case, app) = app_with(&five, None);
            symlink(link, app.join("current")).unwrap();
            let script = format!(
                "{PRUNE_RELEASES}{}",
                prune_releases_call(&app.to_string_lossy(), 2, "5555aaa", None)
            );
            let mut command = Command::new(&shell);
            if let Some(path) = &env_path {
                command.env("PATH", path);
            }
            let output = command.args(["-c", &script]).output().unwrap();
            assert!(!output.status.success(), "{label}: {link}: {output:?}");
            assert_eq!(
                String::from_utf8_lossy(&output.stderr),
                format!("current names {link}, which is no release, so no release was pruned\n"),
                "{label}"
            );
            assert_eq!(entries(&app.join("releases")).len(), 5, "{label}: {link}");
        }

        // Two releases of the same second: the name decides, under either shell.
        let (_case, app) = app_with(
            &[("bbbb222", 100), ("aaaa111", 100), ("cccc333", 0)],
            Some("cccc333"),
        );
        assert_eq!(
            prune(&app, 2, "cccc333", None),
            ["aaaa111", "cccc333"],
            "{label}"
        );

        // An empty releases directory is nothing to prune.
        let (_case, app) = app_with(&[], None);
        assert_eq!(
            prune(&app, 2, "cccc333", None),
            Vec::<String>::new(),
            "{label}"
        );
        checked.push(label);
    }
    eprintln!("release prune checked under: {checked:?}");
}

/// A target with no `sort` can't order its releases, so the prune removes nothing and
/// fails, saying so — which the deploy script reports as a warning after its swap —
/// rather than keeping every release without a word.
#[test]
fn the_release_prune_without_sort_removes_nothing_and_says_so_under_both_shells() {
    use zap_types::deploy::{PRUNE_RELEASES, prune_releases_call};

    let dir = crate::test_scratch::tempdir();
    let mut checked = Vec::new();
    for (label, shell, env_path) in test_shells(dir.path(), &["rm"], None) {
        let case = tempfile::tempdir_in(dir.path()).unwrap();
        let app = case.path().join("app");
        let releases = app.join("releases");
        for name in ["aaaa001", "aaaa002", "aaaa003", "bbbb001"] {
            std::fs::create_dir_all(releases.join(name)).unwrap();
        }
        symlink(releases.join("bbbb001"), app.join("current")).unwrap();
        let only = only_tools(dir.path(), env_path.as_ref(), &["readlink", "stat", "rm"]);
        let script = format!(
            "{PRUNE_RELEASES}{}",
            prune_releases_call(&app.to_string_lossy(), 2, "bbbb001", None)
        );
        let output = Command::new(&shell)
            .env("PATH", &only)
            .args(["-c", &script])
            .output()
            .unwrap();
        assert!(!output.status.success(), "{label}: {output:?}");
        assert!(
            stderr(&output).contains("no sort on this machine, so no release was pruned"),
            "{label}: {output:?}"
        );
        assert_eq!(
            entries(&releases),
            ["aaaa001", "aaaa002", "aaaa003", "bbbb001"],
            "{label}"
        );
        checked.push(label);
    }
    eprintln!("prune without sort checked under: {checked:?}");
}

/// `fakeroot` on the host's `PATH`, when it works here: a session in which `id -u`
/// answers 0 and ownership changes are recorded rather than refused.
pub(super) fn fakeroot() -> Option<PathBuf> {
    let fakeroot = std::env::var_os("PATH").and_then(|path| {
        std::env::split_paths(&path)
            .map(|dir| dir.join("fakeroot"))
            .find(|candidate| candidate.is_file())
    })?;
    let probe = Command::new(&fakeroot)
        .args(["--", "id", "-u"])
        .output()
        .ok()?;
    (probe.status.success() && probe.stdout == b"0\n").then_some(fakeroot)
}

/// Run `step` under the leg's shell inside one `fakeroot` session.
pub(super) fn run_as_fake_root(fakeroot: &Path, leg: &Leg, step: &str) -> Output {
    let (_, shell, env_path) = leg;
    let mut command = Command::new(fakeroot);
    command.arg("--").arg("env");
    if let Some(path) = env_path {
        let mut assignment = std::ffi::OsString::from("PATH=");
        assignment.push(path);
        command.arg(assignment);
    }
    command.arg(shell).args(["-c", step]).output().unwrap()
}

/// As root, an archive whose members record another user, a set-user-id bit, and
/// write permission for everyone lands owned by root, with neither — under both `tar`s.
/// Root is `fakeroot`'s: without the script's `--no-same-owner --no-same-permissions`
/// the same session restores the recorded owner and the set-id bit, which the last
/// assertion shows, so the first ones are the options' doing.
#[test]
fn as_root_an_archive_lands_owned_by_root_without_its_set_id_bits_under_both_shells() {
    let Some(fakeroot) = fakeroot() else {
        eprintln!("root's extraction not checked: no working fakeroot");
        return;
    };
    let dir = crate::test_scratch::tempdir();
    let bin = stand_in_bin(dir.path());
    // The fixture's tree again, its members recorded as another user's.
    fixture(dir.path());
    let foreign = dir.path().join("foreign.tar.gz");
    let recorded = Command::new("tar")
        .args(["--owner=1234", "--group=5678", "--numeric-owner", "-czf"])
        .arg(&foreign)
        .arg("-C")
        .arg(dir.path().join("src"))
        .arg("top")
        .output()
        .unwrap();
    if !recorded.status.success() {
        eprintln!("root's extraction not checked: the host tar records no owner");
        return;
    }
    let seen = "stat -c '%n %u:%g %a' tool open wide";
    let mut checked = Vec::new();
    for leg in deploy_shells(dir.path(), &bin) {
        let label = leg.0;
        let case = tempfile::tempdir_in(dir.path()).unwrap();
        let dest = case.path().join("tree");
        let archive = staged(case.path(), &foreign);
        let step = extract_command(
            RunAs::Root,
            &archive.to_string_lossy(),
            &dest.to_string_lossy(),
            GZ,
            None,
        );
        let quoted = zap_types::shell::single_quote(&dest.to_string_lossy());
        let output = run_as_fake_root(
            &fakeroot,
            &leg,
            &format!("umask 000; {step} && cd {quoted} && {seen}"),
        );
        assert!(output.status.success(), "{label}: {output:?}");
        assert_eq!(
            String::from_utf8_lossy(&output.stdout),
            "tool 0:0 755\nopen 0:0 644\nwide 0:0 755\n",
            "{label}"
        );

        // The same root, a plain `tar -x`: the archive's owner and its set-id bit.
        let plain = case.path().join("plain");
        std::fs::create_dir(&plain).unwrap();
        let archive = staged(case.path(), &foreign);
        let output = run_as_fake_root(
            &fakeroot,
            &leg,
            &format!(
                "cd {} && tar -xzf {} --strip-components=1 && {seen}",
                zap_types::shell::single_quote(&plain.to_string_lossy()),
                zap_types::shell::single_quote(&archive.to_string_lossy()),
            ),
        );
        assert!(output.status.success(), "{label}: {output:?}");
        assert!(
            String::from_utf8_lossy(&output.stdout).starts_with("tool 1234:5678 4755\n"),
            "{label}: {output:?}"
        );

        // The deploy script, connecting as root: the release is root's too.
        let app = case.path().join("app");
        std::fs::create_dir_all(app.join("shared")).unwrap();
        std::fs::write(app.join("shared").join(".env"), "A=1\n").unwrap();
        std::fs::write(app.join("shared").join(ODD_SHARED), "B=2\n").unwrap();
        let (script, remote) = deploy_script(
            &app,
            "v1",
            &["stat -c '%n %u:%g %a' top/tool > owners-seen"],
        );
        let bytes = std::fs::read(&foreign).unwrap();
        std::fs::write(&remote, &bytes).unwrap();
        std::fs::set_permissions(&remote, std::fs::Permissions::from_mode(0o600)).unwrap();
        let stdin = Delivery::of(
            &script,
            Some(format!("{}\n", sha512_hex(&bytes)).as_bytes()),
        )
        .unwrap()
        .stdin;
        let mut command = Command::new(&fakeroot);
        command.arg("--").arg("env");
        if let Some(path) = &leg.2 {
            let mut assignment = std::ffi::OsString::from("PATH=");
            assignment.push(path);
            command.arg(assignment);
        }
        let mut child = command
            .arg(&leg.1)
            .args(["-c", crate::connection::delivery::COMMAND_SHELL])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        std::io::Write::write_all(&mut child.stdin.take().unwrap(), &stdin).unwrap();
        let output = child.wait_with_output().unwrap();
        assert!(output.status.success(), "{label}: {output:?}");
        assert_eq!(
            std::fs::read_to_string(app.join("releases").join("v1").join("owners-seen")).unwrap(),
            "top/tool 0:0 755\n",
            "{label}"
        );
        checked.push(label);
    }
    eprintln!("root's extraction checked under: {checked:?}");
}

/// Below a directory with its sticky bit set or that every account may write — directly,
/// or through a link planted in it to a directory open to no one — a re-extract keeps
/// nothing of the destination it replaces: the new tree is the caller's, at the mode
/// `mkdir` gives it. The walk up from where the link leads never passes the shared
/// directory; the path as declared does. In a directory of the caller's own, through the
/// same link too, the owner and mode are kept. Where the mode is kept, a destination
/// with an extended access list is refused with nothing replaced and no staging left —
/// seen through `getfacl`, else GNU `ls`'s `+`, so not with `BusyBox`'s applets alone.
#[test]
fn a_re_extract_below_a_shared_directory_keeps_nothing_under_both_shells() {
    let (_, gid) = super::put::a_gid_of_mine();
    let me = (
        nix::unistd::geteuid().as_raw(),
        nix::unistd::getegid().as_raw(),
    );
    let dir = crate::test_scratch::tempdir();
    let bin = stand_in_bin(dir.path());
    let fixture = fixture(dir.path());
    let mut checked = Vec::new();
    for leg in test_shells(dir.path(), APPLETS, Some(&bin)) {
        let label = leg.0;
        let case = tempfile::tempdir_in(dir.path()).unwrap();
        let replaced = |dest: &Path| {
            std::fs::create_dir(dest).unwrap();
            std::fs::write(dest.join("theirs"), "OLD").unwrap();
            std::fs::write(dest.join(".zap_remote_hash"), "OLD").unwrap();
            std::os::unix::fs::chown(dest, None, Some(gid)).unwrap();
            std::fs::set_permissions(dest, std::fs::Permissions::from_mode(0o750)).unwrap();
        };
        let attrs = |dest: &Path| {
            let meta = std::fs::metadata(dest).unwrap();
            (meta.mode() & 0o7777, meta.uid(), meta.gid())
        };
        let theirs = case.path().join("theirs");
        std::fs::create_dir(&theirs).unwrap();
        std::os::unix::fs::chown(&theirs, None, Some(gid)).unwrap();
        std::fs::set_permissions(&theirs, std::fs::Permissions::from_mode(0o755)).unwrap();
        for (holder, mode, kept) in [
            ("sticky", 0o1777, false),
            ("open", 0o777, false),
            ("own", 0o755, true),
        ] {
            let at = case.path().join(holder);
            std::fs::create_dir(&at).unwrap();
            std::fs::set_permissions(&at, std::fs::Permissions::from_mode(mode)).unwrap();
            symlink(&theirs, at.join("cache")).unwrap();
            for dest in [at.join("tree"), at.join("cache").join(holder)] {
                replaced(&dest);
                let archive = staged(case.path(), &fixture.gz);
                let output = extract(&leg, &archive, &dest.to_string_lossy(), GZ, Some("NEW"));
                assert!(output.status.success(), "{label} {dest:?}: {output:?}");
                assert!(!dest.join("theirs").exists(), "{label} {dest:?}");
                let want = if kept {
                    (0o750, me.0, gid)
                } else {
                    (0o755, me.0, me.1)
                };
                assert_eq!(attrs(&dest), want, "{label} {dest:?}");
            }
        }

        // A kept mode from a destination with an access list.
        let listed = case.path().join("own/listed");
        replaced(&listed);
        if !super::put::run_setfacl(&["-m", "u:nobody:rwx"], &listed) {
            eprintln!("{label}: a kept mode under an access list not checked: no setfacl");
            checked.push(label);
            continue;
        }
        let refused = |output: &Output, how: &str| {
            assert_eq!(
                output.status.code(),
                Some(REFUSED_EXIT),
                "{label} {how}: {output:?}"
            );
            assert!(
                stderr(output).contains("has an access list (ACL)"),
                "{label} {how}: {output:?}"
            );
            assert!(listed.join("theirs").exists(), "{label} {how}");
            assert_eq!(
                staging_left(&case.path().join("own")),
                Vec::<String>::new(),
                "{label} {how}"
            );
        };
        let archive = staged(case.path(), &fixture.gz);
        let output = extract(&leg, &archive, &listed.to_string_lossy(), GZ, Some("NEW"));
        if label == "busybox" {
            assert!(output.status.success(), "{label}: unseen: {output:?}");
        } else {
            refused(&output, "by getfacl");
            // Without `getfacl`, GNU `ls` shows it.
            let gnu = only_tools(
                dir.path(),
                leg.2.as_ref(),
                &[
                    "tar",
                    "gzip",
                    "mkdir",
                    "mktemp",
                    "mv",
                    "stat",
                    "ls",
                    "rm",
                    "rmdir",
                    "chown",
                    "chmod",
                    "id",
                    "cat",
                    "sha512sum",
                    "find",
                    "sort",
                    "uniq",
                ],
            );
            let output = Command::new(gnu.join("sh"))
                .env("PATH", &gnu)
                .arg("-c")
                .arg(extract_command(
                    RunAs::Caller,
                    &archive.to_string_lossy(),
                    &listed.to_string_lossy(),
                    GZ,
                    Some("NEW"),
                ))
                .output()
                .unwrap();
            refused(&output, "by ls");
        }
        checked.push(label);
    }
    eprintln!("a re-extract below a shared directory checked under: {checked:?}");
}

/// A destination replaced because it holds a sentinel is given, once the new tree is in
/// place, the owner, group, and mode the replaced one had, less a set-id or sticky bit:
/// as the caller here, and as root (`fakeroot`'s) for an owner and group of another
/// account's. The mode holds against an archive whose `./` member carries one of its
/// own, which `tar` gives the directory it extracts into. A caller other than root
/// replaces nothing it couldn't give the new destination — another account's, or a group
/// it isn't in — and fails (not a refusal), so a local run's `sudo` retry does it.
#[test]
fn a_re_extract_keeps_the_destinations_owner_and_mode_under_both_shells() {
    let (_, gid) = super::put::a_gid_of_mine();
    let me = nix::unistd::geteuid().as_raw();
    let dir = crate::test_scratch::tempdir();
    let bin = stand_in_bin(dir.path());
    let fixture = fixture(dir.path());
    // An archive of a tree's `.`, as `tar -C src .` makes one: its first member is
    // `./`, mode 0755, extracted with no components stripped.
    let dotted_src = dir.path().join("dotted-src");
    std::fs::create_dir(&dotted_src).unwrap();
    std::fs::write(dotted_src.join("f.txt"), "payload").unwrap();
    std::fs::set_permissions(&dotted_src, std::fs::Permissions::from_mode(0o755)).unwrap();
    let dotted = dir.path().join("dotted.tar.gz");
    assert!(host_tar(&["-czf"], &dotted, &dotted_src, "."), "a host tar");
    let unstripped = ExtractMode::TarGz {
        strip_components: 0,
    };
    let fakeroot = fakeroot();
    let mut checked = Vec::new();
    for leg in test_shells(dir.path(), APPLETS, Some(&bin)) {
        let label = leg.0;
        let case = tempfile::tempdir_in(dir.path()).unwrap();
        let replaced = |name: &str| {
            let dest = case.path().join(name);
            std::fs::create_dir(&dest).unwrap();
            std::fs::write(dest.join("theirs"), "OLD").unwrap();
            std::fs::write(dest.join(".zap_remote_hash"), "OLD").unwrap();
            std::os::unix::fs::chown(&dest, None, Some(gid)).unwrap();
            std::fs::set_permissions(&dest, std::fs::Permissions::from_mode(0o2750)).unwrap();
            dest
        };

        // In a set-group-id parent, the remade destination inherits the bit from
        // `mkdir`; giving back the removed one's mode clears it.
        let set_gid = case.path().join("set-gid");
        std::fs::create_dir(&set_gid).unwrap();
        std::fs::set_permissions(&set_gid, std::fs::Permissions::from_mode(0o2775)).unwrap();
        for (name, archive, mode) in [
            ("kept", &fixture.gz, GZ),
            ("dotted", &dotted, unstripped),
            ("set-gid/kept", &fixture.gz, GZ),
            ("set-gid/dotted", &dotted, unstripped),
        ] {
            let dest = replaced(name);
            let archive = staged(case.path(), archive);
            let output = extract(&leg, &archive, &dest.to_string_lossy(), mode, Some("NEW"));
            assert!(output.status.success(), "{label} {name}: {output:?}");
            assert!(
                !dest.join("theirs").exists(),
                "{label} {name}: replaced whole"
            );
            assert!(dest.join("f.txt").exists(), "{label} {name}");
            let meta = std::fs::metadata(&dest).unwrap();
            assert_eq!(
                (meta.mode() & 0o7777, meta.uid(), meta.gid()),
                (0o750, me, gid),
                "{label} {name}: the removed destination's owner and mode, no set-id bit"
            );
        }

        // A destination this caller (not root) couldn't give its owner and group: an
        // `id` stand-in that answers another uid, then one that answers this uid with
        // groups that don't hold the destination's. Nothing is removed either time.
        let other_gid = if gid == 4242 { 4243 } else { 4242 };
        for (name, answer) in [
            ("not mine", "echo 4242".to_owned()),
            (
                "not my group",
                format!("case $1 in -u) echo {me};; *) echo {other_gid};; esac"),
            ),
        ] {
            let dest = replaced(name);
            let lead = tempfile::tempdir_in(dir.path()).unwrap();
            executable(&lead.path().join("id"), &answer);
            let archive = staged(case.path(), &fixture.gz);
            // the archive's own check reads the uploader from `sudo`'s `SUDO_UID` first,
            // so the stand-in `id` is left to the destination's
            let step = format!(
                "SUDO_UID={me} {}",
                extract_command(
                    RunAs::Caller,
                    &archive.to_string_lossy(),
                    &dest.to_string_lossy(),
                    GZ,
                    Some("NEW"),
                )
            );
            let led = (
                label,
                leg.1.clone(),
                Some(led_by(lead.path(), leg.2.as_ref())),
            );
            let output = run(&led, &step);
            assert_eq!(output.status.code(), Some(1), "{label} {name}: {output:?}");
            assert!(
                stderr(&output).contains(
                    "its owner or group is not one this account can give; nothing was extracted"
                ),
                "{label} {name}: {output:?}"
            );
            assert_eq!(
                entries(&dest),
                [".zap_remote_hash", "theirs"],
                "{label} {name}: nothing removed"
            );
            assert!(archive.exists(), "{label} {name}: nothing extracted");
        }

        for (name, archive, mode) in [
            ("theirs", &fixture.gz, GZ),
            ("theirs dotted", &dotted, unstripped),
        ] {
            let Some(fakeroot) = &fakeroot else { break };
            let dest = case.path().join(name);
            let archive = staged(case.path(), archive);
            let step = extract_command(
                RunAs::Root,
                &archive.to_string_lossy(),
                &dest.to_string_lossy(),
                mode,
                Some("NEW"),
            );
            let quoted = zap_types::shell::single_quote(&dest.to_string_lossy());
            let output = run_as_fake_root(
                fakeroot,
                &leg,
                &format!(
                    "mkdir {quoted} && echo OLD > {quoted}/.zap_remote_hash && \
                     chown 1234:5678 {quoted} && chmod 3750 {quoted} && {step} && \
                     stat -c '%u:%g %a' {quoted}"
                ),
            );
            assert!(output.status.success(), "{label} {name}: {output:?}");
            assert_eq!(
                String::from_utf8_lossy(&output.stdout),
                "1234:5678 750\n",
                "{label} {name}: as root, another account's owner and group kept"
            );
        }
        checked.push(label);
    }
    eprintln!("re-extract ownership checked under: {checked:?}");
}

/// An extraction never changes its destination's own mode, though an archive of a
/// tree's `.` carries a `./` member with a mode of its own, which GNU `tar` gives the
/// directory it extracts into (`BusyBox` `tar` leaves it): one made fresh keeps what
/// `mkdir` gave it, and one replaced — an empty one zap didn't extract too — keeps the
/// replaced one's, less a set-id bit. A re-extract that fails leaves the old tree as it
/// was, sentinel, owner, and mode, and no staging directory; its retry replaces it — as
/// the caller here, and as root (`fakeroot`'s) for another account's owner and group.
#[test]
fn a_failed_re_extract_leaves_the_old_tree_and_its_retry_replaces_it_under_both_shells() {
    let (_, gid) = super::put::a_gid_of_mine();
    let me = nix::unistd::geteuid().as_raw();
    let dir = crate::test_scratch::tempdir();
    let bin = stand_in_bin(dir.path());
    // `tar -C src .`, with a `./` member whose mode no destination here has.
    let dotted_src = dir.path().join("dotted-src");
    std::fs::create_dir(&dotted_src).unwrap();
    std::fs::write(dotted_src.join("f.txt"), "payload").unwrap();
    std::fs::set_permissions(&dotted_src, std::fs::Permissions::from_mode(0o701)).unwrap();
    let dotted = dir.path().join("dotted.tar.gz");
    assert!(host_tar(&["-czf"], &dotted, &dotted_src, "."), "a host tar");
    // The same archive cut off inside its gzip stream: `tar` fails on it.
    let broken = dir.path().join("broken.tar.gz");
    let bytes = std::fs::read(&dotted).unwrap();
    std::fs::write(&broken, &bytes[..bytes.len() / 2]).unwrap();
    let unstripped = ExtractMode::TarGz {
        strip_components: 0,
    };
    let fakeroot = fakeroot();
    let mut checked = Vec::new();
    for leg in test_shells(dir.path(), APPLETS, Some(&bin)) {
        let label = leg.0;
        let case = tempfile::tempdir_in(dir.path()).unwrap();

        // Made fresh, and an empty one replaced: neither takes the `./` mode.
        let fresh = case.path().join("fresh");
        let archive = staged(case.path(), &dotted);
        let output = extract(&leg, &archive, &fresh.to_string_lossy(), unstripped, None);
        assert!(output.status.success(), "{label} fresh: {output:?}");
        assert!(fresh.join("f.txt").exists(), "{label} fresh");
        assert_eq!(mode_of(&fresh), 0o755, "{label} fresh: mkdir's mode");
        let placed = case.path().join("placed");
        std::fs::create_dir(&placed).unwrap();
        std::os::unix::fs::chown(&placed, None, Some(gid)).unwrap();
        std::fs::set_permissions(&placed, std::fs::Permissions::from_mode(0o2750)).unwrap();
        let archive = staged(case.path(), &dotted);
        let output = extract(
            &leg,
            &archive,
            &placed.to_string_lossy(),
            unstripped,
            Some("NEW"),
        );
        assert!(output.status.success(), "{label} placed: {output:?}");
        assert!(placed.join("f.txt").exists(), "{label} placed");
        let meta = std::fs::metadata(&placed).unwrap();
        assert_eq!(
            (meta.mode() & 0o7777, meta.uid(), meta.gid()),
            (0o750, me, gid),
            "{label} placed: the empty one's owner and mode, no set-id bit"
        );

        // A re-extract that fails, then its retry.
        let dest = case.path().join("retried");
        std::fs::create_dir(&dest).unwrap();
        std::fs::write(dest.join("theirs"), "OLD").unwrap();
        std::fs::write(dest.join(".zap_remote_hash"), "OLD").unwrap();
        std::os::unix::fs::chown(&dest, None, Some(gid)).unwrap();
        std::fs::set_permissions(&dest, std::fs::Permissions::from_mode(0o2750)).unwrap();
        let archive = staged(case.path(), &broken);
        let output = extract(
            &leg,
            &archive,
            &dest.to_string_lossy(),
            unstripped,
            Some("NEW"),
        );
        assert_eq!(output.status.code(), Some(1), "{label} failed: {output:?}");
        assert_eq!(
            entries(&dest),
            [".zap_remote_hash", "theirs"],
            "{label} failed: the old tree is left whole"
        );
        assert_eq!(
            std::fs::read(dest.join(".zap_remote_hash")).unwrap(),
            b"OLD",
            "{label} failed"
        );
        let meta = std::fs::metadata(&dest).unwrap();
        assert_eq!(
            (meta.mode() & 0o7777, meta.uid(), meta.gid()),
            (0o2750, me, gid),
            "{label} failed: the old tree's owner and mode, untouched"
        );
        assert_eq!(
            staging_left(case.path()),
            Vec::<String>::new(),
            "{label} failed: no staging directory is left"
        );
        let archive = staged(case.path(), &dotted);
        let output = extract(
            &leg,
            &archive,
            &dest.to_string_lossy(),
            unstripped,
            Some("NEW"),
        );
        assert!(output.status.success(), "{label} retried: {output:?}");
        assert_eq!(
            entries(&dest),
            [".zap_remote_hash", "f.txt"],
            "{label} retried: replaced whole"
        );
        let meta = std::fs::metadata(&dest).unwrap();
        assert_eq!(
            (meta.mode() & 0o7777, meta.uid(), meta.gid()),
            (0o750, me, gid),
            "{label} retried: the old tree's owner and mode, no set-id bit"
        );
        assert_eq!(staging_left(case.path()), Vec::<String>::new(), "{label}");

        if let Some(fakeroot) = &fakeroot {
            let dest = case.path().join("theirs retried");
            let quoted = zap_types::shell::single_quote(&dest.to_string_lossy());
            let step = |archive: &Path| {
                extract_command(
                    RunAs::Root,
                    &archive.to_string_lossy(),
                    &dest.to_string_lossy(),
                    unstripped,
                    Some("NEW"),
                )
            };
            let (failing, retry) = (
                step(&staged(case.path(), &broken)),
                step(&staged(case.path(), &dotted)),
            );
            let output = run_as_fake_root(
                fakeroot,
                &leg,
                &format!(
                    "mkdir {quoted} && echo OLD > {quoted}/.zap_remote_hash && \
                     chown 1234:5678 {quoted} && chmod 3750 {quoted} && \
                     {{ ! {failing}; }} && stat -c '%u:%g %a' {quoted} && \
                     {retry} && stat -c '%u:%g %a' {quoted}"
                ),
            );
            assert!(output.status.success(), "{label} as root: {output:?}");
            assert_eq!(
                String::from_utf8_lossy(&output.stdout),
                "1234:5678 3750\n1234:5678 750\n",
                "{label} as root: untouched by the failure, kept by the retry"
            );
        }
        checked.push(label);
    }
    eprintln!("failed re-extract and retry checked under: {checked:?}");
}

/// `tar` runs in a directory only the extracting user can reach — never in the
/// destination, though another account owns it: a `tar` stand-in records where it
/// runs (the directory's inode and owner, and its parent's owner and mode) before the
/// real one extracts. As the caller here, and as root (`fakeroot`'s) replacing a
/// destination another account owns.
#[test]
fn tar_runs_in_a_staging_directory_of_the_extracting_users_under_both_shells() {
    let dir = crate::test_scratch::tempdir();
    let bin = stand_in_bin(dir.path());
    let fixture = fixture(dir.path());
    let fakeroot = fakeroot();
    let me = nix::unistd::geteuid().as_raw();
    let mut checked = Vec::new();
    for leg in test_shells(dir.path(), APPLETS, Some(&bin)) {
        let (label, shell, env_path) = &leg;
        let case = tempfile::tempdir_in(dir.path()).unwrap();
        let seen = case.path().join("seen");
        let lead = tempfile::tempdir_in(dir.path()).unwrap();
        executable(
            &lead.path().join("tar"),
            &format!(
                "{stat} -c '%i %u %a' . .. > {seen} || exit 1\nexec {tar} \"$@\"",
                stat = zap_types::shell::single_quote(
                    &on_path(env_path.as_ref(), "stat").to_string_lossy()
                ),
                tar = zap_types::shell::single_quote(
                    &on_path(env_path.as_ref(), "tar").to_string_lossy()
                ),
                seen = zap_types::shell::single_quote(&seen.to_string_lossy()),
            ),
        );
        let path = led_by(lead.path(), env_path.as_ref());
        let led = (*label, shell.clone(), Some(path));

        let dest = case.path().join("tree");
        std::fs::create_dir(&dest).unwrap();
        std::fs::write(dest.join(".zap_remote_hash"), "OLD").unwrap();
        let inode = std::fs::metadata(&dest).unwrap().ino();
        let archive = staged(case.path(), &fixture.gz);
        let output = extract(&led, &archive, &dest.to_string_lossy(), GZ, Some("NEW"));
        assert!(output.status.success(), "{label}: {output:?}");
        let ran = std::fs::read_to_string(&seen).unwrap();
        let ran: Vec<Vec<&str>> = ran.lines().map(|l| l.split(' ').collect()).collect();
        assert_ne!(
            ran[0][0],
            inode.to_string(),
            "{label}: not in the destination"
        );
        assert_eq!(ran[0][1], me.to_string(), "{label}");
        assert_eq!(
            (ran[1][1], ran[1][2]),
            (me.to_string().as_str(), "700"),
            "{label}: inside a directory only its owner enters"
        );

        if let Some(fakeroot) = &fakeroot {
            let dest = case.path().join("theirs");
            let quoted = zap_types::shell::single_quote(&dest.to_string_lossy());
            let archive = staged(case.path(), &fixture.gz);
            let step = extract_command(
                RunAs::Root,
                &archive.to_string_lossy(),
                &dest.to_string_lossy(),
                GZ,
                Some("NEW"),
            );
            let output = run_as_fake_root(
                fakeroot,
                &led,
                &format!(
                    "mkdir {quoted} && echo OLD > {quoted}/.zap_remote_hash && \
                     chown 1234:5678 {quoted} && {step} && stat -c '%u:%g' {quoted}"
                ),
            );
            assert!(output.status.success(), "{label} as root: {output:?}");
            assert_eq!(
                String::from_utf8_lossy(&output.stdout),
                "1234:5678\n",
                "{label} as root: the old owner is given to the new tree"
            );
            let ran = std::fs::read_to_string(&seen).unwrap();
            let ran: Vec<Vec<&str>> = ran.lines().map(|l| l.split(' ').collect()).collect();
            assert_eq!(
                (ran[0][1], ran[1][1], ran[1][2]),
                ("0", "0", "700"),
                "{label} as root: root's, inside root's private directory"
            );
        }
        checked.push(*label);
    }
    eprintln!("where tar runs checked under: {checked:?}");
}

/// The swap puts the old tree back when the new one can't take its name, and when
/// putting it back fails too, leaves it where it is and says so: an `mv` stand-in
/// refuses the second rename, then the first one back as well.
#[test]
fn a_failed_swap_puts_the_old_tree_back_under_both_shells() {
    let dir = crate::test_scratch::tempdir();
    let bin = stand_in_bin(dir.path());
    let fixture = fixture(dir.path());
    let mut checked = Vec::new();
    for leg in test_shells(dir.path(), APPLETS, Some(&bin)) {
        let (label, shell, env_path) = &leg;
        let case = tempfile::tempdir_in(dir.path()).unwrap();
        for (what, refused) in [("put back", "*/new"), ("left aside", "*/new|*/old")] {
            let lead = tempfile::tempdir_in(dir.path()).unwrap();
            executable(
                &lead.path().join("mv"),
                &format!(
                    "case $3 in {refused}) exit 1;; esac\nexec {mv} \"$@\"",
                    mv = zap_types::shell::single_quote(
                        &on_path(env_path.as_ref(), "mv").to_string_lossy()
                    ),
                ),
            );
            let led = (
                *label,
                shell.clone(),
                Some(led_by(lead.path(), env_path.as_ref())),
            );
            let dest = case.path().join(what);
            std::fs::create_dir(&dest).unwrap();
            std::fs::write(dest.join("theirs"), "OLD").unwrap();
            std::fs::write(dest.join(".zap_remote_hash"), "OLD").unwrap();
            let archive = staged(case.path(), &fixture.gz);
            let output = extract(&led, &archive, &dest.to_string_lossy(), GZ, Some("NEW"));
            assert_eq!(output.status.code(), Some(1), "{label} {what}: {output:?}");
            if what == "put back" {
                assert_eq!(
                    entries(&dest),
                    [".zap_remote_hash", "theirs"],
                    "{label} {what}"
                );
                assert_eq!(staging_left(case.path()), Vec::<String>::new(), "{label}");
            } else {
                assert!(!dest.exists(), "{label} {what}");
                let left = staging_left(case.path());
                assert_eq!(left.len(), 1, "{label} {what}: {left:?}");
                let old = case.path().join(&left[0]).join("old");
                assert_eq!(entries(&old), [".zap_remote_hash", "theirs"], "{label}");
                assert!(
                    stderr(&output)
                        .contains(&format!("the tree it held is left at {}", old.display())),
                    "{label} {what}: {output:?}"
                );
                std::fs::remove_dir_all(case.path().join(&left[0])).unwrap();
            }
        }
        checked.push(*label);
    }
    eprintln!("a failed swap checked under: {checked:?}");
}

/// An account that can write the destination's parent can rename what is in it — the
/// staging directory too. Swapped for a link, or for a directory that isn't the fresh
/// private one, between `mktemp` and the script's opening it (a `mktemp` stand-in does
/// it as it returns), the staging directory is refused and nothing is made, extracted,
/// moved, or removed anywhere: the destination and the planted directories are as they
/// were. Swapped once the script holds it open (a `mkdir` stand-in does it as the new
/// tree's directory is made), it steers nothing: everything still happens in the
/// directory held open, and the tree takes the destination's name. As root
/// (`fakeroot`'s), a planted `0700` directory of another account's is refused too.
#[test]
fn the_staging_directory_is_held_open_under_both_shells() {
    let dir = crate::test_scratch::tempdir();
    let bin = stand_in_bin(dir.path());
    let fixture = fixture(dir.path());
    let fakeroot = fakeroot();
    let mut checked = Vec::new();
    for leg in test_shells(dir.path(), APPLETS, Some(&bin)) {
        let (label, shell, env_path) = &leg;
        let quoted = |path: &Path| zap_types::shell::single_quote(&path.to_string_lossy());
        // A marked destination to replace, in a case of its own.
        let case_with = |planted: Option<(&str, u32, bool)>| {
            let case = tempfile::tempdir_in(dir.path()).unwrap();
            let dest = case.path().join("dest");
            std::fs::create_dir(&dest).unwrap();
            std::fs::write(dest.join("theirs"), "OLD").unwrap();
            std::fs::write(dest.join(".zap_remote_hash"), "OLD").unwrap();
            std::fs::create_dir(case.path().join("aside")).unwrap();
            // Where a planted link leads: private, empty, and this account's, as the
            // staging directory is, so only the name check tells them apart.
            std::fs::create_dir(case.path().join("elsewhere")).unwrap();
            std::fs::set_permissions(
                case.path().join("elsewhere"),
                std::fs::Permissions::from_mode(0o700),
            )
            .unwrap();
            if let Some((name, mode, keep)) = planted {
                let planted = case.path().join(name);
                std::fs::create_dir(&planted).unwrap();
                if keep {
                    std::fs::write(planted.join("keep"), "MINE").unwrap();
                }
                std::fs::set_permissions(&planted, std::fs::Permissions::from_mode(mode)).unwrap();
            }
            case
        };
        let led = |stand_in: &str, body: &str| {
            let lead = tempfile::tempdir_in(dir.path()).unwrap().keep();
            executable(&lead.join(stand_in), body);
            (
                *label,
                shell.clone(),
                Some(led_by(&lead, env_path.as_ref())),
            )
        };
        let untouched = |case: &Path, what: &str, output: &Output| {
            assert_eq!(output.status.code(), Some(1), "{label} {what}: {output:?}");
            let dest = case.join("dest");
            assert_eq!(
                entries(&dest),
                [".zap_remote_hash", "theirs"],
                "{label} {what}: the destination is as it was"
            );
            assert_eq!(std::fs::read(dest.join("theirs")).unwrap(), b"OLD");
            // Our own staging directory, moved aside, is left as `mktemp` made it.
            for name in ["aside/ours", "elsewhere"] {
                assert_eq!(
                    entries(&case.join(name)),
                    Vec::<String>::new(),
                    "{label} {what}: nothing lands in {name}"
                );
            }
        };

        // Before it is opened: a link, then directories that aren't the fresh one.
        let mktemp = on_path(env_path.as_ref(), "mktemp");
        for (what, planted, plant) in [
            ("a link", None, "ln -s elsewhere \"$st\""),
            (
                "an open directory",
                Some(("planted", 0o755, false)),
                "mv planted \"$st\"",
            ),
            (
                "a directory holding a file",
                Some(("planted", 0o700, true)),
                "mv planted \"$st\"",
            ),
        ] {
            let case = case_with(planted);
            let leg = led(
                "mktemp",
                &format!(
                    "st=$({mktemp} \"$@\") || exit 1\ncd {case} && mv \"$st\" aside/ours && {plant} || exit 1\necho \"$st\"",
                    mktemp = quoted(&mktemp),
                    case = quoted(case.path()),
                ),
            );
            let archive = staged(case.path(), &fixture.gz);
            let dest = case.path().join("dest");
            let output = extract(&leg, &archive, &dest.to_string_lossy(), GZ, Some("NEW"));
            untouched(case.path(), what, &output);
            let left = staging_left(case.path());
            if planted.is_some_and(|(_, _, keep)| keep) {
                assert_eq!(left.len(), 1, "{label} {what}: {left:?}");
                assert_eq!(
                    entries(&case.path().join(&left[0])),
                    ["keep"],
                    "{label} {what}"
                );
            }
            assert!(archive.exists(), "{label} {what}: nothing extracted");
        }

        // A link while it is opened, our own directory again once it is looked at by
        // name: a `stat` stand-in puts it back just before the by-name `stat`. The
        // descriptor holds where the link led, and that is refused.
        {
            let case = case_with(None);
            let lead = tempfile::tempdir_in(dir.path()).unwrap().keep();
            executable(
                &lead.join("mktemp"),
                &format!(
                    "st=$({mktemp} \"$@\") || exit 1\ncd {case} && mv \"$st\" aside/ours && ln -s elsewhere \"$st\" || exit 1\necho \"$st\"",
                    mktemp = quoted(&mktemp),
                    case = quoted(case.path()),
                ),
            );
            executable(
                &lead.join("stat"),
                &format!(
                    "if [ \"$1\" = -c ] && [ -L \"$4\" ]; then case $4 in */.dest.zap-*) rm \"$4\" && mv {ours} \"$4\" || exit 1;; esac; fi\nexec {stat} \"$@\"",
                    ours = quoted(&case.path().join("aside").join("ours")),
                    stat = quoted(&on_path(env_path.as_ref(), "stat")),
                ),
            );
            let leg = (
                *label,
                shell.clone(),
                Some(led_by(&lead, env_path.as_ref())),
            );
            let archive = staged(case.path(), &fixture.gz);
            let dest = case.path().join("dest");
            let output = extract(&leg, &archive, &dest.to_string_lossy(), GZ, Some("NEW"));
            // Ours, put back at its name, is the empty one `rmdir` removed.
            assert_eq!(staging_left(case.path()), Vec::<String>::new(), "{label}");
            std::fs::create_dir(case.path().join("aside").join("ours")).unwrap();
            untouched(case.path(), "a link put back", &output);
            assert!(
                archive.exists(),
                "{label} a link put back: nothing extracted"
            );
        }

        // As root: a planted private directory of another account's.
        if let Some(fakeroot) = &fakeroot {
            let case = case_with(Some(("planted", 0o700, false)));
            let leg = led(
                "mktemp",
                &format!(
                    "st=$({mktemp} \"$@\") || exit 1\ncd {case} && mv \"$st\" aside/ours && mv planted \"$st\" || exit 1\necho \"$st\"",
                    mktemp = quoted(&mktemp),
                    case = quoted(case.path()),
                ),
            );
            let archive = staged(case.path(), &fixture.gz);
            let dest = case.path().join("dest");
            // `fakeroot` shows every file as root's until the session gives it another
            // owner.
            let output = run_as_fake_root(
                fakeroot,
                &leg,
                &format!(
                    "chown 1234:5678 {planted} && {step}",
                    planted = quoted(&case.path().join("planted")),
                    step = extract_command(
                        RunAs::Root,
                        &archive.to_string_lossy(),
                        &dest.to_string_lossy(),
                        GZ,
                        Some("NEW"),
                    ),
                ),
            );
            untouched(case.path(), "another account's", &output);
        }

        // After it is opened: the name swapped for a link steers nothing.
        let case = case_with(None);
        let leg = led(
            "mkdir",
            &format!(
                "case $2 in */new) for st in {case}/.dest.zap-*; do mv \"$st\" {case}/aside/ours && ln -s elsewhere \"$st\" || exit 1; done;; esac\nexec {mkdir} \"$@\"",
                mkdir = quoted(&on_path(env_path.as_ref(), "mkdir")),
                case = quoted(case.path()),
            ),
        );
        let archive = staged(case.path(), &fixture.gz);
        let dest = case.path().join("dest");
        let output = extract(&leg, &archive, &dest.to_string_lossy(), GZ, Some("NEW"));
        assert!(output.status.success(), "{label} after: {output:?}");
        assert!(
            dest.join("f.txt").exists(),
            "{label} after: the tree is in place"
        );
        assert!(
            !dest.join("theirs").exists(),
            "{label} after: replaced whole"
        );
        assert_eq!(
            entries(&case.path().join("elsewhere")),
            Vec::<String>::new(),
            "{label} after: nothing lands where the link leads"
        );
        assert_eq!(
            entries(&case.path().join("aside").join("ours")),
            Vec::<String>::new(),
            "{label} after: the old tree is removed from the directory held open"
        );
        checked.push(*label);
    }
    eprintln!("staging directory held open checked under: {checked:?}");
}

/// The new tree takes the destination's owner and mode before it takes its name, so
/// when that fails the destination is left whole: a `chmod` stand-in fails, and a
/// `chown` one under `fakeroot`.
#[test]
fn a_failed_owner_or_mode_leaves_the_old_tree_under_both_shells() {
    let (_, gid) = super::put::a_gid_of_mine();
    let dir = crate::test_scratch::tempdir();
    let bin = stand_in_bin(dir.path());
    let fixture = fixture(dir.path());
    let fakeroot = fakeroot();
    let mut checked = Vec::new();
    for leg in test_shells(dir.path(), APPLETS, Some(&bin)) {
        let (label, shell, env_path) = &leg;
        let case = tempfile::tempdir_in(dir.path()).unwrap();
        let failing = |tool: &str| {
            let lead = tempfile::tempdir_in(dir.path()).unwrap().keep();
            executable(&lead.join(tool), "exit 1");
            (
                *label,
                shell.clone(),
                Some(led_by(&lead, env_path.as_ref())),
            )
        };
        let dest = case.path().join("tree");
        std::fs::create_dir(&dest).unwrap();
        std::fs::write(dest.join("theirs"), "OLD").unwrap();
        std::fs::write(dest.join(".zap_remote_hash"), "OLD").unwrap();
        std::os::unix::fs::chown(&dest, None, Some(gid)).unwrap();
        std::fs::set_permissions(&dest, std::fs::Permissions::from_mode(0o750)).unwrap();
        let archive = staged(case.path(), &fixture.gz);
        let output = extract(
            &failing("chmod"),
            &archive,
            &dest.to_string_lossy(),
            GZ,
            Some("NEW"),
        );
        assert_eq!(output.status.code(), Some(1), "{label}: {output:?}");
        assert_eq!(
            entries(&dest),
            [".zap_remote_hash", "theirs"],
            "{label}: the old tree is left whole"
        );
        assert_eq!(mode_of(&dest), 0o750, "{label}");
        assert_eq!(staging_left(case.path()), Vec::<String>::new(), "{label}");

        if let Some(fakeroot) = &fakeroot {
            let dest = case.path().join("theirs");
            let quoted = zap_types::shell::single_quote(&dest.to_string_lossy());
            let archive = staged(case.path(), &fixture.gz);
            let step = extract_command(
                RunAs::Root,
                &archive.to_string_lossy(),
                &dest.to_string_lossy(),
                GZ,
                Some("NEW"),
            );
            let output = run_as_fake_root(
                fakeroot,
                &failing("chown"),
                &format!(
                    "mkdir {quoted} && echo OLD > {quoted}/.zap_remote_hash && \\
                     /bin/chown 1234:5678 {quoted} && {{ {step}; [ $? -eq 1 ]; }} && ls -A {quoted}"
                ),
            );
            assert!(output.status.success(), "{label} as root: {output:?}");
            assert_eq!(
                String::from_utf8_lossy(&output.stdout),
                ".zap_remote_hash\n",
                "{label} as root: the old tree is left whole"
            );
        }
        checked.push(*label);
    }
    eprintln!("a failed owner or mode checked under: {checked:?}");
}
