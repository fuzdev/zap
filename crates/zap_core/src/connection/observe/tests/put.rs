//! The put, directory-attrs, and snapshot scripts (`zap_types::put`) and the `user` steps
//! built on them, run for real: under the system `sh`, and under `BusyBox` with only its applets
//! on `PATH` (when installed), with a stand-in `sudo` that runs its command as the
//! test's own user. A put goes through the real command wrapper, as a delivery's stdin —
//! a plan's put of text it holds among them, with the plan's text as that stdin.
//!
//! What only root can show is not shown here: an owner other than the test's own (but
//! a kept one, under `fakeroot` where it is installed), a write into a directory the
//! test can't write, and `sudo`'s own handling of the descriptor and the stdin.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::io::Write as _;
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _, symlink};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use zap_types::detected::Detection;
use zap_types::plan::{DiffInputs, PlanStep, StepExecution, diff};
use zap_types::put::{
    DIR_ATTRS, FILE_PUT, FILE_SNAPSHOT, FileAttrs, MAKE_DIRS, PutCheck, REFUSED_EXIT, RunAs,
    SNAPSHOT_MAX_BYTES, Snapshot, dir_attrs_command, file_put_command, file_snapshot_command,
    make_dirs_command, parse_snapshot,
};
use zap_types::schema::{Resource, Target};
use zap_types::shell::single_quote;

use super::support::test_shells;
use crate::connection::delivery::{COMMAND_SHELL, Delivery};
use crate::connection::put_payload;
use crate::digest::sha512_hex;
use crate::test_support::local_machine;

/// The applets a put, a directory change, and the `user` steps run, beyond the batch's.
const APPLETS: &[&str] = &[
    "mktemp", "rm", "chown", "chmod", "sync", "mv", "mkdir", "awk", "ln", "grep", "ls", "id",
];

/// One shell leg: its label, the shell, and its `PATH`.
pub(super) type Leg = (&'static str, PathBuf, Option<OsString>);

pub(super) fn executable(path: &Path, body: &str) {
    std::fs::write(path, format!("#!/bin/sh\n{body}\n")).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
}

/// A `bin` directory holding a `sudo` that drops `-u <name>` (logging the name and the
/// command's first word to `<bin>/sudo.log`) and runs the rest as the test's user.
pub(super) fn stand_in_bin(dir: &Path) -> PathBuf {
    let bin = dir.join("bin");
    std::fs::create_dir(&bin).unwrap();
    executable(
        &bin.join("sudo"),
        &format!(
            "if [ \"$1\" = -u ]; then echo \"$2 $3\" >> {}; shift 2; fi\nexec \"$@\"",
            single_quote(&bin.join("sudo.log").to_string_lossy())
        ),
    );
    bin
}

/// The names in `dir`, sorted.
pub(super) fn entries(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

pub(super) fn mode_of(path: &Path) -> u32 {
    std::fs::symlink_metadata(path).unwrap().mode() & 0o7777
}

pub(super) fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

/// `tool` as the leg's `PATH` finds it.
pub(super) fn on_path(path: Option<&OsString>, tool: &str) -> PathBuf {
    path.map(std::env::split_paths)
        .into_iter()
        .flatten()
        .map(|dir| dir.join(tool))
        .find(|candidate| candidate.is_file())
        .unwrap_or_else(|| panic!("a {tool} on the leg's PATH"))
}

/// The leg's `PATH` with `lead` ahead of it.
pub(super) fn led_by(lead: &Path, path: Option<&OsString>) -> OsString {
    std::env::join_paths(
        std::iter::once(lead.to_path_buf())
            .chain(path.map(std::env::split_paths).into_iter().flatten()),
    )
    .unwrap()
}

/// Run `stdin` through the command wrapper under `shell`.
pub(super) fn feed(shell: &Path, path: Option<&OsString>, stdin: &[u8]) -> Output {
    let mut command = Command::new(shell);
    if let Some(path) = path {
        command.env("PATH", path);
    }
    let mut child = command
        .args(["-c", COMMAND_SHELL])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    // A script that stops early closes its end: the rest of the write then fails.
    let _ = child.stdin.take().unwrap().write_all(stdin);
    child.wait_with_output().unwrap()
}

/// The stdin of a delivered put: `script` framed, then the digest line and `content`.
fn framed(script: &str, digest: &str, content: &[u8]) -> (Vec<u8>, usize) {
    let mut payload = format!("{digest}\n").into_bytes();
    payload.extend_from_slice(content);
    let stdin = Delivery::of(script, Some(&payload)).unwrap().stdin;
    let frame = stdin.len() - payload.len();
    (stdin, frame)
}

/// Put `content` at `path` as the connection does: the script under `sudo`, the digest
/// and the bytes behind the frame.
pub(super) fn put(leg: &Leg, path: &Path, attrs: FileAttrs<'_>, content: &[u8]) -> Output {
    let (_, shell, env_path) = leg;
    let script = file_put_command(RunAs::Root, &path.to_string_lossy(), attrs, PutCheck::None);
    let (stdin, _) = framed(&script, &sha512_hex(content), content);
    feed(shell, env_path.as_ref(), &stdin)
}

/// A group of the test's user to hand a file to, by name — any but its primary one when
/// it has another, so the change shows.
pub(super) fn a_group_of_mine() -> String {
    let primary = nix::unistd::getegid();
    let gid = nix::unistd::getgroups()
        .unwrap_or_default()
        .into_iter()
        .find(|gid| *gid != primary)
        .unwrap_or(primary);
    nix::unistd::Group::from_gid(gid).unwrap().unwrap().name
}

/// A binary payload: every byte value, NULs first, no final newline.
fn binary() -> Vec<u8> {
    let mut bytes = b"\0\0".to_vec();
    bytes.extend((0..70_000_u32).map(|n| n.to_le_bytes()[0] ^ n.to_le_bytes()[1]));
    bytes.extend_from_slice(b"tail without a newline");
    bytes
}

/// A put installs what it was sent, byte for byte, with the mode and group it was given
/// — set on the staged file, so a set-id mode survives the owner change — or, with no
/// mode, the one a plain create gives under the caller's umask. It replaces a symbolic
/// link at the path instead of following it, names files a shell could misread, and
/// leaves nothing else in the directory.
#[test]
fn a_put_installs_the_bytes_with_their_mode_and_owner_under_both_shells() {
    let dir = crate::test_scratch::tempdir();
    let bin = stand_in_bin(dir.path());
    let content = binary();
    let group = a_group_of_mine();
    let mut checked = Vec::new();
    for leg in test_shells(dir.path(), APPLETS, Some(&bin)) {
        let label = leg.0;
        let case = tempfile::tempdir_in(dir.path()).unwrap();
        let at = |name: &str| case.path().join(name);

        let output = put(&leg, &at("a.env"), FileAttrs::mode("640"), &content);
        assert!(output.status.success(), "{label}: {output:?}");
        assert!(std::fs::read(at("a.env")).unwrap() == content, "{label}");
        assert_eq!(mode_of(&at("a.env")), 0o640, "{label}");
        assert_eq!(entries(case.path()), ["a.env"], "{label}: no stage is left");

        // No mode: a plain create's, under each umask. The umask is the delivered
        // script's own, as a login shell's would be.
        for (umask, mode) in [("022", 0o644), ("027", 0o640), ("077", 0o600)] {
            let path = at(&format!("umask-{umask}"));
            let script = format!(
                "umask {umask}; {}",
                file_put_command(
                    RunAs::Root,
                    &path.to_string_lossy(),
                    FileAttrs::NONE,
                    PutCheck::None
                )
            );
            let (stdin, _) = framed(&script, &sha512_hex(b"x\n"), b"x\n");
            let output = feed(&leg.1, leg.2.as_ref(), &stdin);
            assert!(output.status.success(), "{label}: {output:?}");
            assert_eq!(mode_of(&path), mode, "{label}: umask {umask}");
        }

        // An empty file is a file.
        let output = put(&leg, &at("empty"), FileAttrs::mode("600"), b"");
        assert!(output.status.success(), "{label}: {output:?}");
        assert_eq!(std::fs::read(at("empty")).unwrap(), b"", "{label}");

        // The group through the descriptor, then a set-gid mode: set the other way
        // round, the group change would clear the bit.
        let attrs = FileAttrs {
            mode: Some("2750"),
            owner: None,
            group: Some(&group),
            ..FileAttrs::NONE
        };
        let output = put(&leg, &at("tool"), attrs, b"#!/bin/sh\n");
        assert!(output.status.success(), "{label}: {output:?}");
        let installed = std::fs::metadata(at("tool")).unwrap();
        assert_eq!(installed.mode() & 0o7777, 0o2750, "{label}");
        assert_eq!(
            nix::unistd::Group::from_gid(nix::unistd::Gid::from_raw(installed.gid()))
                .unwrap()
                .unwrap()
                .name,
            group,
            "{label}"
        );

        // A link at the path is replaced; what it pointed at is untouched.
        std::fs::write(at("victim"), "ORIGINAL").unwrap();
        std::fs::set_permissions(at("victim"), std::fs::Permissions::from_mode(0o600)).unwrap();
        symlink(at("victim"), at("linked.conf")).unwrap();
        let output = put(&leg, &at("linked.conf"), FileAttrs::mode("644"), b"NEW");
        assert!(output.status.success(), "{label}: {output:?}");
        assert!(
            std::fs::symlink_metadata(at("linked.conf"))
                .unwrap()
                .is_file(),
            "{label}"
        );
        assert_eq!(std::fs::read(at("linked.conf")).unwrap(), b"NEW", "{label}");
        assert_eq!(std::fs::read(at("victim")).unwrap(), b"ORIGINAL", "{label}");
        assert_eq!(mode_of(&at("victim")), 0o600, "{label}");

        // A quote, spaces, and a leading `-` in the names.
        std::fs::create_dir(at("it's a dir")).unwrap();
        let odd = at("it's a dir").join("-rf name $HOME");
        let output = put(&leg, &odd, FileAttrs::mode("600"), b"odd");
        assert!(output.status.success(), "{label}: {output:?}");
        assert_eq!(std::fs::read(&odd).unwrap(), b"odd", "{label}");
        assert_eq!(entries(&at("it's a dir")), ["-rf name $HOME"], "{label}");

        // Through a directory that is itself a link: the link is followed once, and
        // the file lands in the directory it names.
        std::fs::create_dir(at("real")).unwrap();
        symlink(at("real"), at("alias")).unwrap();
        let output = put(&leg, &at("alias").join("f"), FileAttrs::mode("600"), b"in");
        assert!(output.status.success(), "{label}: {output:?}");
        assert_eq!(
            std::fs::read(at("real").join("f")).unwrap(),
            b"in",
            "{label}"
        );

        // A link to a directory at the path is never followed: nothing lands in the
        // directory. Coreutils `mv -T` replaces the link with the file; BusyBox refuses
        // and leaves the link.
        std::fs::create_dir(at("a dir")).unwrap();
        symlink(at("a dir"), at("dirlink")).unwrap();
        let output = put(&leg, &at("dirlink"), FileAttrs::mode("600"), b"f");
        assert!(entries(&at("a dir")).is_empty(), "{label}: {output:?}");
        let there = std::fs::symlink_metadata(at("dirlink")).unwrap();
        if label == "busybox" {
            assert!(!output.status.success(), "{label}: {output:?}");
            assert_ne!(
                output.status.code(),
                Some(REFUSED_EXIT),
                "{label}: `mv`'s own"
            );
            assert!(there.is_symlink(), "{label}");
        } else if output.status.success() {
            assert!(there.is_file(), "{label}");
        } else {
            assert!(there.is_symlink(), "{label}");
        }
        assert!(
            !entries(case.path())
                .iter()
                .any(|name| name.starts_with(".zap.")),
            "{label}"
        );

        // A mode or owner that reads as an option is a value all the same: after `--`
        // it is refused as a bad mode or name, never obeyed. (Without the `--`,
        // coreutils would copy the reference file's mode and group.)
        std::fs::write(at("reference"), "").unwrap();
        std::fs::set_permissions(at("reference"), std::fs::Permissions::from_mode(0o666)).unwrap();
        let option = format!("--reference={}", at("reference").display());
        for attrs in [
            FileAttrs::mode(&option),
            FileAttrs {
                mode: Some("600"),
                owner: Some(&option),
                group: None,
                ..FileAttrs::NONE
            },
        ] {
            let output = put(&leg, &at("optioned"), attrs, b"x");
            assert!(!output.status.success(), "{label}: {attrs:?}: {output:?}");
            assert!(!at("optioned").exists(), "{label}: {attrs:?}");
        }
        checked.push(label);
    }
    eprintln!("put checked under: {checked:?}");
}

/// A put that can't be completed exits nonzero, leaves what was at the path as it was,
/// and leaves no staged file behind: a stream cut in the content, inside the digest
/// line, or ahead of it; a digest that isn't the content's; a directory at the path; a
/// directory that isn't there; a path that isn't absolute or names no file.
#[test]
fn a_put_that_fails_leaves_the_old_file_and_no_stage_under_both_shells() {
    let dir = crate::test_scratch::tempdir();
    let bin = stand_in_bin(dir.path());
    let content = binary();
    let digest = sha512_hex(&content);
    let mut checked = Vec::new();
    for leg in test_shells(dir.path(), APPLETS, Some(&bin)) {
        let (label, shell, env_path) = &leg;
        let case = tempfile::tempdir_in(dir.path()).unwrap();
        let conf = case.path().join("app.conf");
        std::fs::write(&conf, "OLD").unwrap();
        std::fs::set_permissions(&conf, std::fs::Permissions::from_mode(0o640)).unwrap();
        let script = file_put_command(
            RunAs::Root,
            &conf.to_string_lossy(),
            FileAttrs::mode("600"),
            PutCheck::None,
        );
        let refused = |what: &str, stdin: &[u8], says: &str| {
            let output = feed(shell, env_path.as_ref(), stdin);
            assert!(!output.status.success(), "{label}: {what}: {output:?}");
            assert_eq!(
                output.status.code(),
                Some(REFUSED_EXIT),
                "{label}: {what}: the put's own refusal"
            );
            assert!(
                stderr(&output).contains(says),
                "{label}: {what}: {output:?}"
            );
            assert_eq!(std::fs::read(&conf).unwrap(), b"OLD", "{label}: {what}");
            assert_eq!(mode_of(&conf), 0o640, "{label}: {what}");
            assert_eq!(entries(case.path()), ["app.conf"], "{label}: {what}");
            let said = stderr(&output);
            assert!(
                !said.contains(&digest),
                "{label}: {what}: the digest: {said}"
            );
        };

        let (whole, frame) = framed(&script, &digest, &content);
        for (what, cut, says) in [
            (
                "cut in the content",
                frame + 129 + 30_000,
                "not the bytes sent",
            ),
            (
                "cut at the content's last byte",
                whole.len() - 1,
                "not the bytes sent",
            ),
            (
                "cut after the digest line",
                frame + 129,
                "not the bytes sent",
            ),
            ("cut at the digest's newline", frame + 128, "did not arrive"),
            ("cut inside the digest", frame + 60, "did not arrive"),
            ("cut ahead of the digest", frame, "did not arrive"),
        ] {
            refused(what, &whole[..cut], says);
        }
        let (wrong, _) = framed(&script, &sha512_hex(b"other"), &content);
        refused("another content's digest", &wrong, "not the bytes sent");
        let (short, _) = framed(&script, &digest[..127], &content);
        refused("a short digest", &short, "did not arrive");

        // The whole of it does install — the refusals above are the cut's doing.
        let output = feed(shell, env_path.as_ref(), &whole);
        assert!(output.status.success(), "{label}: {output:?}");
        assert!(std::fs::read(&conf).unwrap() == content, "{label}");
        assert_eq!(mode_of(&conf), 0o600, "{label}");
        assert_eq!(entries(case.path()), ["app.conf"], "{label}");

        // A directory at the path is refused, and nothing is put inside it.
        let taken = case.path().join("taken");
        std::fs::create_dir(&taken).unwrap();
        let output = put(&leg, &taken, FileAttrs::mode("600"), b"x");
        assert!(!output.status.success(), "{label}: {output:?}");
        assert!(entries(&taken).is_empty(), "{label}");
        assert_eq!(entries(case.path()), ["app.conf", "taken"], "{label}");

        // A directory that isn't there: the put creates none.
        let output = put(
            &leg,
            &case.path().join("absent").join("f"),
            FileAttrs::NONE,
            b"x",
        );
        assert!(!output.status.success(), "{label}: {output:?}");
        assert_eq!(entries(case.path()), ["app.conf", "taken"], "{label}");

        // Not a path the script will write.
        for (bad, says) in [
            ("relative/f".to_owned(), "not an absolute path"),
            (format!("{}/", case.path().display()), "no file name"),
            (format!("{}/..", case.path().display()), "no file name"),
            (format!("{}/.", case.path().display()), "no file name"),
        ] {
            let output = put(&leg, Path::new(&bad), FileAttrs::NONE, b"x");
            assert!(!output.status.success(), "{label}: {bad}: {output:?}");
            assert!(stderr(&output).contains(says), "{label}: {bad}: {output:?}");
        }
        assert_eq!(entries(case.path()), ["app.conf", "taken"], "{label}");
        checked.push(*label);
    }
    eprintln!("put refusals checked under: {checked:?}");
}

/// Names planted for a put to trip on are neither followed nor reused: a link and a
/// world-writable file at the fixed sibling name a predictable stage would use; and —
/// with a `mktemp` stand-in handing the script a name that is already taken — a link
/// to a device (which the open follows, then refuses), a dangling link (the open makes
/// nothing where it points), a regular file with content, and an empty one with a
/// second name. A name swapped between the open and its check is refused; the content
/// sits in a file only the caller may read until its mode is set, whatever the umask
/// would give. A staged name swapped for a link once the file is open is refused, and
/// the mode and owner have landed on the staged file, not on what the link names.
#[test]
fn a_put_follows_and_reuses_no_planted_name_under_both_shells() {
    let dir = crate::test_scratch::tempdir();
    let bin = stand_in_bin(dir.path());
    let mut checked = Vec::new();
    for leg in test_shells(dir.path(), APPLETS, Some(&bin)) {
        let (label, shell, env_path) = &leg;
        let case = tempfile::tempdir_in(dir.path()).unwrap();
        let at = |name: &str| case.path().join(name);
        std::fs::write(at("victim"), "ORIGINAL").unwrap();
        std::fs::set_permissions(at("victim"), std::fs::Permissions::from_mode(0o640)).unwrap();
        let victim_untouched = |what: &str| {
            assert_eq!(
                std::fs::read(at("victim")).unwrap(),
                b"ORIGINAL",
                "{label}: {what}"
            );
            assert_eq!(mode_of(&at("victim")), 0o640, "{label}: {what}");
        };

        // The fixed sibling name: a link to the victim, and a file anyone may write.
        symlink(at("victim"), at("a.conf.zap-tmp")).unwrap();
        std::fs::write(at("b.env.zap-tmp"), "").unwrap();
        std::fs::set_permissions(at("b.env.zap-tmp"), std::fs::Permissions::from_mode(0o666))
            .unwrap();
        let planted = std::fs::metadata(at("b.env.zap-tmp")).unwrap().ino();
        for name in ["a.conf", "b.env"] {
            let output = put(&leg, &at(name), FileAttrs::mode("600"), b"SECRET=1\n");
            assert!(output.status.success(), "{label}: {name}: {output:?}");
            let installed = std::fs::symlink_metadata(at(name)).unwrap();
            assert!(installed.is_file(), "{label}: {name}");
            assert_eq!(installed.mode() & 0o7777, 0o600, "{label}: {name}");
            assert_ne!(
                installed.ino(),
                planted,
                "{label}: {name}: a file of its own"
            );
        }
        victim_untouched("a link at the fixed sibling name");
        assert_eq!(std::fs::read(at("b.env.zap-tmp")).unwrap(), b"", "{label}");
        assert_eq!(mode_of(&at("b.env.zap-tmp")), 0o666, "{label}");
        for name in ["a.conf", "a.conf.zap-tmp", "b.env", "b.env.zap-tmp"] {
            std::fs::remove_file(at(name)).unwrap();
        }

        // The stage's own name, already taken: a `mktemp` that answers a fixed name.
        let lead = dir.path().join(format!("lead-mktemp-{label}"));
        std::fs::create_dir(&lead).unwrap();
        executable(&lead.join("mktemp"), "echo ./.zap.taken");
        let taken_path = led_by(&lead, env_path.as_ref());
        std::fs::write(at("c.conf"), "OLD").unwrap();
        let script = file_put_command(
            RunAs::Root,
            &at("c.conf").to_string_lossy(),
            FileAttrs::mode("644"),
            PutCheck::None,
        );
        let (stdin, _) = framed(&script, &sha512_hex(b"NEW"), b"NEW");
        let plant: [(&str, &dyn Fn()); 4] = [
            ("a link to a device", &|| {
                symlink("/dev/null", at(".zap.taken")).unwrap();
            }),
            ("a dangling link", &|| {
                symlink(at("nowhere"), at(".zap.taken")).unwrap();
            }),
            ("a regular file", &|| {
                std::fs::write(at(".zap.taken"), "THEIRS").unwrap();
            }),
            ("an empty file with a second name", &|| {
                std::fs::write(at(".zap.taken"), "").unwrap();
                std::fs::hard_link(at(".zap.taken"), at("second")).unwrap();
            }),
        ];
        for (what, plant) in plant {
            plant();
            let before = std::fs::symlink_metadata(at(".zap.taken")).unwrap().ino();
            let output = feed(shell, Some(&taken_path), &stdin);
            assert!(!output.status.success(), "{label}: {what}: {output:?}");
            assert_eq!(
                std::fs::read(at("c.conf")).unwrap(),
                b"OLD",
                "{label}: {what}"
            );
            assert_eq!(
                std::fs::symlink_metadata(at(".zap.taken")).unwrap().ino(),
                before,
                "{label}: {what}: a name the put didn't create is not its to remove"
            );
            assert!(!at("nowhere").exists(), "{label}: {what}");
            assert_eq!(
                std::fs::read(at("c.conf")).unwrap(),
                b"OLD",
                "{label}: {what}"
            );
            std::fs::remove_file(at(".zap.taken")).unwrap();
            let _ = std::fs::remove_file(at("second"));
        }
        // The device link is opened and then refused, before a byte is written; so is
        // a file with a second name.
        symlink("/dev/null", at(".zap.taken")).unwrap();
        let output = feed(shell, Some(&taken_path), &stdin);
        assert_eq!(
            output.status.code(),
            Some(REFUSED_EXIT),
            "{label}: {output:?}"
        );
        assert!(
            stderr(&output).contains("no new file to stage it in"),
            "{label}: {output:?}"
        );
        std::fs::remove_file(at(".zap.taken")).unwrap();
        std::fs::write(at(".zap.taken"), "").unwrap();
        std::fs::hard_link(at(".zap.taken"), at("second")).unwrap();
        let output = feed(shell, Some(&taken_path), &stdin);
        assert_eq!(
            output.status.code(),
            Some(REFUSED_EXIT),
            "{label}: {output:?}"
        );
        assert_eq!(std::fs::read(at("second")).unwrap(), b"", "{label}");
        std::fs::remove_file(at(".zap.taken")).unwrap();
        std::fs::remove_file(at("second")).unwrap();
        victim_untouched("a taken stage name");

        // The staged name swapped between the open and its check (an `id` stand-in,
        // which the check runs, moves the file aside and leaves an empty one of the
        // caller's in its place): refused, nothing written to either, and the name not
        // the put's to remove.
        let real_id = on_path(env_path.as_ref(), "id");
        let lead = tempfile::tempdir_in(dir.path()).unwrap();
        executable(
            &lead.path().join("id"),
            &format!(
                "for f in ./.zap.*; do mv \"$f\" ./moved && : > \"$f\"; done\nexec {} \"$@\"",
                single_quote(&real_id.to_string_lossy())
            ),
        );
        let output = feed(shell, Some(&led_by(lead.path(), env_path.as_ref())), &stdin);
        assert_eq!(
            output.status.code(),
            Some(REFUSED_EXIT),
            "{label}: {output:?}"
        );
        assert!(
            stderr(&output).contains("no new file to stage it in"),
            "{label}: {output:?}"
        );
        assert_eq!(std::fs::read(at("c.conf")).unwrap(), b"OLD", "{label}");
        assert_eq!(std::fs::read(at("moved")).unwrap(), b"", "{label}");
        let left: Vec<String> = entries(case.path());
        assert_eq!(left.len(), 4, "{label}: {left:?}");
        for name in &left {
            if name.starts_with(".zap.") {
                assert_eq!(std::fs::read(at(name)).unwrap(), b"", "{label}");
                std::fs::remove_file(at(name)).unwrap();
            }
        }
        std::fs::remove_file(at("moved")).unwrap();
        assert_eq!(entries(case.path()), ["c.conf", "victim"], "{label}");

        // While the content is in the staged file and its mode isn't set yet, it is the
        // caller's alone — whatever the umask and the declared mode. A `sha512sum`
        // stand-in reads the mode at that point.
        let real = on_path(env_path.as_ref(), "sha512sum");
        let lead = tempfile::tempdir_in(dir.path()).unwrap();
        let seen = lead.path().join("staged-mode");
        executable(
            &lead.path().join("sha512sum"),
            &format!(
                "stat -c %a ./.zap.* > {}\nexec {} \"$@\"",
                single_quote(&seen.to_string_lossy()),
                single_quote(&real.to_string_lossy())
            ),
        );
        let (open_umask, _) = framed(&format!("umask 000; {script}"), &sha512_hex(b"NEW"), b"NEW");
        let output = feed(
            shell,
            Some(&led_by(lead.path(), env_path.as_ref())),
            &open_umask,
        );
        assert!(output.status.success(), "{label}: {output:?}");
        assert_eq!(std::fs::read_to_string(&seen).unwrap(), "600\n", "{label}");
        assert_eq!(mode_of(&at("c.conf")), 0o644, "{label}");
        std::fs::write(at("c.conf"), "OLD").unwrap();

        // The staged name swapped once the file is open: a `sha512sum` stand-in moves
        // the staged file aside and leaves a link in its place — to the victim, then to
        // the staged file itself, which a followed comparison would accept.
        for (target, what) in [
            (at("victim"), "a link to the victim"),
            (at("moved"), "a link to the staged file"),
        ] {
            let lead = tempfile::tempdir_in(dir.path()).unwrap();
            executable(
                &lead.path().join("sha512sum"),
                &format!(
                    "for f in ./.zap.*; do mv \"$f\" ./moved && ln -s {} \"$f\"; done\nexec {} \"$@\"",
                    single_quote(&target.to_string_lossy()),
                    single_quote(&real.to_string_lossy())
                ),
            );
            let output = feed(shell, Some(&led_by(lead.path(), env_path.as_ref())), &stdin);
            assert!(!output.status.success(), "{label}: {what}: {output:?}");
            assert!(
                stderr(&output).contains("staged copy was replaced"),
                "{label}: {what}: {output:?}"
            );
            assert_eq!(
                std::fs::read(at("c.conf")).unwrap(),
                b"OLD",
                "{label}: {what}"
            );
            victim_untouched(what);
            // The mode went to the file the put created, whatever its name became.
            assert_eq!(mode_of(&at("moved")), 0o644, "{label}: {what}");
            assert_eq!(
                std::fs::read(at("moved")).unwrap(),
                b"NEW",
                "{label}: {what}"
            );
            assert_eq!(
                entries(case.path()),
                ["c.conf", "moved", "victim"],
                "{label}: {what}: the planted link is removed with the stage's name"
            );
            std::fs::remove_file(at("moved")).unwrap();
        }
        checked.push(*label);
    }
    eprintln!("put planted names checked under: {checked:?}");
}

/// A default access list on the directory overrides the umask a shell's own create
/// would apply; the staged file is still the caller's alone (`0600`) while the content
/// is in it, and the installed file has its declared mode.
#[test]
fn the_staged_copy_is_the_callers_alone_under_a_default_access_list_under_both_shells() {
    let dir = crate::test_scratch::tempdir();
    let bin = stand_in_bin(dir.path());
    let mut checked = Vec::new();
    for leg in test_shells(dir.path(), APPLETS, Some(&bin)) {
        let (label, shell, env_path) = &leg;
        let listed = tempfile::tempdir_in(dir.path()).unwrap();
        if !run_setfacl(&["-d", "-m", "u::rw,g::rw,o::rw"], listed.path()) {
            eprintln!("a default access list not checked: no setfacl");
            return;
        }
        let dest = listed.path().join("d.conf");
        let script = file_put_command(
            RunAs::Root,
            &dest.to_string_lossy(),
            FileAttrs::mode("644"),
            PutCheck::None,
        );
        let (stdin, _) = framed(&script, &sha512_hex(b"NEW"), b"NEW");
        let real = on_path(env_path.as_ref(), "sha512sum");
        let lead = tempfile::tempdir_in(dir.path()).unwrap();
        let seen = lead.path().join("staged-mode");
        executable(
            &lead.path().join("sha512sum"),
            &format!(
                "stat -c %a ./.zap.* > {}\nexec {} \"$@\"",
                single_quote(&seen.to_string_lossy()),
                single_quote(&real.to_string_lossy())
            ),
        );
        let output = feed(shell, Some(&led_by(lead.path(), env_path.as_ref())), &stdin);
        assert!(output.status.success(), "{label}: {output:?}");
        assert_eq!(std::fs::read_to_string(&seen).unwrap(), "600\n", "{label}");
        assert_eq!(mode_of(&dest), 0o644, "{label}");
        assert_eq!(std::fs::read(&dest).unwrap(), b"NEW", "{label}");
        checked.push(*label);
    }
    eprintln!("staging under a default access list checked under: {checked:?}");
}

/// The `sudoers` check: a file `visudo` rejects is never installed — the old one stays,
/// the put fails, and the stage is gone — one it accepts is, and an unknown check
/// installs nothing.
#[test]
fn a_put_installs_only_what_its_check_accepts_under_both_shells() {
    let dir = crate::test_scratch::tempdir();
    let bin = stand_in_bin(dir.path());
    // A `visudo` that reads the file it is given and rejects one holding `BAD`.
    executable(
        &bin.join("visudo"),
        "[ \"$1\" = -cf ] || exit 64\nif grep -q BAD \"$2\"; then echo \"syntax error\" >&2; exit 1; fi\necho \"$2: parsed OK\"",
    );
    let mut checked = Vec::new();
    for leg in test_shells(dir.path(), APPLETS, Some(&bin)) {
        let (label, shell, env_path) = &leg;
        let case = tempfile::tempdir_in(dir.path()).unwrap();
        let drop_in = case.path().join("deploy");
        std::fs::write(&drop_in, "OLD\n").unwrap();
        let check = |content: &[u8], check: &str| {
            let script = file_put_command(
                RunAs::Root,
                &drop_in.to_string_lossy(),
                FileAttrs::mode("440"),
                PutCheck::Sudoers,
            )
            .replace(" 'sudoers'", &format!(" '{check}'"));
            let (stdin, _) = framed(&script, &sha512_hex(content), content);
            feed(shell, env_path.as_ref(), &stdin)
        };

        let output = check(b"deploy ALL=(ALL BAD\n", "sudoers");
        assert!(!output.status.success(), "{label}: {output:?}");
        assert!(
            stderr(&output).contains("visudo did not accept"),
            "{label}: {output:?}"
        );
        assert_eq!(std::fs::read(&drop_in).unwrap(), b"OLD\n", "{label}");
        assert_eq!(entries(case.path()), ["deploy"], "{label}");

        let output = check(b"deploy ALL=(ALL) ALL\n", "nosuchcheck");
        assert!(!output.status.success(), "{label}: {output:?}");
        assert_eq!(std::fs::read(&drop_in).unwrap(), b"OLD\n", "{label}");
        assert_eq!(entries(case.path()), ["deploy"], "{label}");

        let output = check(b"deploy ALL=(ALL) ALL\n", "sudoers");
        assert!(output.status.success(), "{label}: {output:?}");
        assert!(output.stdout.is_empty(), "{label}: {output:?}");
        assert_eq!(
            std::fs::read(&drop_in).unwrap(),
            b"deploy ALL=(ALL) ALL\n",
            "{label}"
        );
        assert_eq!(mode_of(&drop_in), 0o440, "{label}");
        checked.push(*label);
    }
    eprintln!("put check checked under: {checked:?}");
}

/// The directory script sets a directory's mode and group through a descriptor, drops a
/// trailing slash, and refuses anything that isn't the directory itself — a symbolic
/// link to one (with or without a trailing slash, or a `/.`), a file, nothing — leaving
/// what a link names untouched.
#[test]
fn dir_attrs_change_the_directory_and_follow_no_link_under_both_shells() {
    let dir = crate::test_scratch::tempdir();
    let bin = stand_in_bin(dir.path());
    let group = a_group_of_mine();
    let mut checked = Vec::new();
    for (label, shell, env_path) in test_shells(dir.path(), APPLETS, Some(&bin)) {
        let case = tempfile::tempdir_in(dir.path()).unwrap();
        let at = |name: &str| case.path().join(name).to_string_lossy().into_owned();
        let run = |path: &str, attrs: FileAttrs<'_>| {
            let mut command = Command::new(&shell);
            if let Some(path) = &env_path {
                command.env("PATH", path);
            }
            command
                .args(["-c", &dir_attrs_command(RunAs::Root, path, attrs)])
                .output()
                .unwrap()
        };
        let group_of = |path: &str| {
            let gid = std::fs::metadata(path).unwrap().gid();
            nix::unistd::Group::from_gid(nix::unistd::Gid::from_raw(gid))
                .unwrap()
                .unwrap()
                .name
        };
        let set = FileAttrs {
            mode: Some("750"),
            owner: None,
            group: Some(&group),
            ..FileAttrs::NONE
        };

        std::fs::create_dir(at("it's a dir")).unwrap();
        let output = run(&at("it's a dir"), set);
        assert!(output.status.success(), "{label}: {output:?}");
        assert_eq!(mode_of(Path::new(&at("it's a dir"))), 0o750, "{label}");
        assert_eq!(group_of(&at("it's a dir")), group, "{label}");
        let output = run(&format!("{}//", at("it's a dir")), FileAttrs::mode("700"));
        assert!(output.status.success(), "{label}: {output:?}");
        assert_eq!(mode_of(Path::new(&at("it's a dir"))), 0o700, "{label}");

        // the case directory is born under the process umask (0777 at umask 000);
        // pinned, so the refused `victim/..` attempt at 777 would be a visible change
        std::fs::set_permissions(case.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let case_mode = mode_of(case.path());
        assert_ne!(case_mode, 0o777);
        std::fs::create_dir(at("victim")).unwrap();
        std::fs::set_permissions(at("victim"), std::fs::Permissions::from_mode(0o700)).unwrap();
        let victim_group = group_of(&at("victim"));
        symlink(at("victim"), at("link")).unwrap();
        std::fs::write(at("file"), "").unwrap();
        std::fs::set_permissions(at("file"), std::fs::Permissions::from_mode(0o600)).unwrap();
        let open = FileAttrs {
            mode: Some("777"),
            owner: None,
            group: Some(&group),
            ..FileAttrs::NONE
        };
        for refused in [
            at("link"),
            format!("{}/", at("link")),
            format!("{}/.", at("link")),
            format!("{}/..", at("victim")),
            at("file"),
            at("absent"),
            "relative".to_owned(),
        ] {
            let output = run(&refused, open);
            assert_eq!(
                output.status.code(),
                Some(REFUSED_EXIT),
                "{label}: {refused}: {output:?}"
            );
            if refused.ends_with("link") || refused.ends_with("link/") {
                assert!(
                    stderr(&output).contains("a symbolic link is not followed"),
                    "{label}: {refused}: {output:?}"
                );
            }
            assert!(
                stderr(&output).starts_with("zap: "),
                "{label}: {refused}: {output:?}"
            );
        }
        assert_eq!(mode_of(Path::new(&at("victim"))), 0o700, "{label}");
        assert_eq!(group_of(&at("victim")), victim_group, "{label}");

        // A value that reads as an option is refused as a value, after `--`.
        let option = format!("--reference={}", at("victim"));
        for attrs in [
            FileAttrs::mode(&option),
            FileAttrs {
                mode: None,
                owner: Some(&option),
                group: None,
                ..FileAttrs::NONE
            },
        ] {
            let before = mode_of(Path::new(&at("it's a dir")));
            let output = run(&at("it's a dir"), attrs);
            assert!(!output.status.success(), "{label}: {attrs:?}: {output:?}");
            assert_eq!(mode_of(Path::new(&at("it's a dir"))), before, "{label}");
        }
        assert_eq!(mode_of(Path::new(&at("file"))), 0o600, "{label}");
        assert_eq!(
            mode_of(case.path()),
            case_mode,
            "{label}: `..` was not followed"
        );
        checked.push(label);
    }
    eprintln!("dir attrs checked under: {checked:?}");
}

/// Run `command` under `shell` with `env_path`, killing it — its whole process group, so
/// a child left waiting can't hold its pipes open — if it hasn't finished within a
/// minute, far past what any of these takes on a loaded machine: `None` then, so a hang
/// fails the test instead of holding it.
fn run_bounded(shell: &Path, env_path: Option<&OsString>, command: &str) -> Option<Output> {
    use std::os::unix::process::CommandExt as _;

    let mut child = Command::new(shell);
    if let Some(path) = env_path {
        child.env("PATH", path);
    }
    let child = child
        .process_group(0)
        .args(["-c", command])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let pid = nix::unistd::Pid::from_raw(i32::try_from(child.id()).unwrap());
    let (sender, receiver) = std::sync::mpsc::channel();
    // drained on its own thread, so a large answer can't fill the pipe and stall it
    std::thread::spawn(move || sender.send(child.wait_with_output().unwrap()));
    if let Ok(output) = receiver.recv_timeout(std::time::Duration::from_secs(60)) {
        return Some(output);
    }
    let _ = nix::sys::signal::killpg(pid, nix::sys::signal::Signal::SIGKILL);
    let _ = receiver.recv();
    None
}

/// The snapshot script reads a regular file's bytes, mode (set-id bits included), owner,
/// and group through one descriptor, and says `absent` for nothing. It refuses, with
/// nothing read, a symbolic link at the name (to a file, or dangling), a fifo — without
/// waiting on it for a writer — a directory, a file past the byte limit, and a relative
/// path; and names a tool the target lacks.
#[test]
fn the_snapshot_reads_one_regular_file_and_nothing_else_under_both_shells() {
    let dir = crate::test_scratch::tempdir();
    let bin = stand_in_bin(dir.path());
    let (uid, gid) = (
        nix::unistd::geteuid().as_raw(),
        nix::unistd::getegid().as_raw(),
    );
    let mut checked = Vec::new();
    for (label, shell, env_path) in test_shells(dir.path(), APPLETS, Some(&bin)) {
        let case = tempfile::tempdir_in(dir.path()).unwrap();
        let at = |name: &str| case.path().join(name).to_string_lossy().into_owned();
        let snapshot = |path: &str| {
            run_bounded(
                &shell,
                env_path.as_ref(),
                &file_snapshot_command(RunAs::Root, path),
            )
            .unwrap_or_else(|| panic!("{label}: {path}: the snapshot hung"))
        };

        let content = binary();
        std::fs::write(at("it's a file"), &content).unwrap();
        std::fs::set_permissions(at("it's a file"), std::fs::Permissions::from_mode(0o4750))
            .unwrap();
        let output = snapshot(&at("it's a file"));
        assert!(output.status.success(), "{label}: {output:?}");
        assert_eq!(
            parse_snapshot(&output.stdout),
            Some(Snapshot::File {
                mode: 0o4750,
                uid,
                gid,
                bytes: content.clone(),
            }),
            "{label}"
        );
        std::fs::write(at("empty"), b"").unwrap();
        std::fs::set_permissions(at("empty"), std::fs::Permissions::from_mode(0o600)).unwrap();
        let output = snapshot(&at("empty"));
        assert_eq!(
            parse_snapshot(&output.stdout),
            Some(Snapshot::File {
                mode: 0o600,
                uid,
                gid,
                bytes: Vec::new(),
            }),
            "{label}: {output:?}"
        );
        let output = snapshot(&at("absent"));
        assert_eq!(
            parse_snapshot(&output.stdout),
            Some(Snapshot::Absent),
            "{label}: {output:?}"
        );

        symlink(at("it's a file"), at("link")).unwrap();
        symlink(at("absent"), at("dangling")).unwrap();
        let fifo = Command::new("mkfifo").arg(at("fifo")).status().unwrap();
        assert!(fifo.success());
        std::fs::create_dir(at("dir")).unwrap();
        for (refused, says) in [
            (at("link"), "a symbolic link is not read through"),
            (at("dangling"), "a symbolic link is not read through"),
            (at("fifo"), "not a regular file"),
            (at("dir"), "not a regular file"),
            ("relative".to_owned(), "not an absolute path"),
        ] {
            let output = snapshot(&refused);
            assert_eq!(
                output.status.code(),
                Some(REFUSED_EXIT),
                "{label}: {refused}: {output:?}"
            );
            assert!(output.stdout.is_empty(), "{label}: {refused}: {output:?}");
            assert!(
                stderr(&output).starts_with(&format!("zap: {refused}: {says}")),
                "{label}: {refused}: {output:?}"
            );
        }
        // A name in a directory the caller can't search is no absence: it fails, and not
        // as a refusal, so a local snapshot retries it with `sudo`. (Root searches any
        // directory, so this shows only for another user.)
        if !nix::unistd::geteuid().is_root() {
            std::fs::create_dir(at("shut")).unwrap();
            std::fs::write(at("shut/x"), b"old").unwrap();
            std::fs::set_permissions(at("shut"), std::fs::Permissions::from_mode(0o600)).unwrap();
            let output = snapshot(&at("shut/x"));
            std::fs::set_permissions(at("shut"), std::fs::Permissions::from_mode(0o700)).unwrap();
            assert_eq!(output.status.code(), Some(1), "{label}: {output:?}");
            assert!(output.stdout.is_empty(), "{label}: {output:?}");
            assert!(
                stderr(&output).contains("its directory cannot be searched"),
                "{label}: {output:?}"
            );
        }
        // Past the limit the command composes: refused before a byte is read. Sparse, so
        // the size is the limit's and the disk holds nothing.
        let big = std::fs::File::create(at("big")).unwrap();
        big.set_len(SNAPSHOT_MAX_BYTES + 1).unwrap();
        let output = snapshot(&at("big"));
        assert_eq!(
            output.status.code(),
            Some(REFUSED_EXIT),
            "{label}: {output:?}"
        );
        assert!(output.stdout.is_empty(), "{label}: {output:?}");
        assert!(
            stderr(&output).contains(&format!(
                "larger than the {SNAPSHOT_MAX_BYTES} bytes a snapshot holds"
            )),
            "{label}: {output:?}"
        );
        // A file that changes while it is read: a `head` that copies, then appends a byte.
        std::fs::write(at("growing"), b"old").unwrap();
        let grows = case.path().join("grows");
        std::fs::create_dir(&grows).unwrap();
        executable(
            &grows.join("head"),
            &format!(
                "{} \"$@\" && printf x >> {}",
                single_quote(&on_path(env_path.as_ref(), "head").to_string_lossy()),
                single_quote(&at("growing"))
            ),
        );
        let output = run_bounded(
            &shell,
            Some(&led_by(&grows, env_path.as_ref())),
            &file_snapshot_command(RunAs::Root, &at("growing")),
        )
        .unwrap();
        assert_eq!(
            output.status.code(),
            Some(REFUSED_EXIT),
            "{label}: {output:?}"
        );
        assert!(
            stderr(&output).contains("it changed while it was read"),
            "{label}: {output:?}"
        );
        assert_eq!(std::fs::read(at("growing")).unwrap(), b"oldx", "{label}");
        // Each tool it runs, missing from the `PATH`.
        for missing in ["stat", "head"] {
            let tools: Vec<&str> = ["stat", "head"]
                .into_iter()
                .filter(|tool| tool != &missing)
                .collect();
            let path = only_tools(dir.path(), env_path.as_ref(), &tools);
            let output = run_text(
                &path.join("sh"),
                &path,
                FILE_SNAPSHOT,
                &[&at("it's a file"), "100"],
                b"",
            );
            assert_eq!(
                output.status.code(),
                Some(REFUSED_EXIT),
                "{label}: {output:?}"
            );
            assert!(
                stderr(&output).contains(&format!("no {missing} on this machine")),
                "{label}: {output:?}"
            );
        }
        checked.push(label);
    }
    eprintln!("snapshot checked under: {checked:?}");
}

/// The local snapshot end to end (`snapshot_local`): the real script under each shell,
/// the operator's own lookup of the path, and a stand-in `sudo` that logs and runs its
/// command as the test's user. A file the operator reads, and a name in a directory it
/// can enter and finds missing, take no `sudo`; a name in a directory it can't enter is
/// neither `absent` nor a refusal, so it goes to `sudo` once — whose answer, here the
/// same user's, is the failure, never `absent`.
#[tokio::test]
async fn the_local_snapshot_escalates_only_what_the_operator_cannot_read_under_both_shells() {
    if nix::unistd::geteuid().is_root() {
        eprintln!("skipping: root enters every directory");
        return;
    }
    let dir = crate::test_scratch::tempdir();
    let bin = dir.path().join("logbin");
    std::fs::create_dir(&bin).unwrap();
    let log = bin.join("sudo.log");
    executable(
        &bin.join("sudo"),
        &format!(
            "echo \"$1\" >> {}\nexec \"$@\"",
            single_quote(&log.to_string_lossy())
        ),
    );
    let mut checked = Vec::new();
    for (label, shell, env_path) in test_shells(dir.path(), APPLETS, Some(&bin)) {
        let case = tempfile::tempdir_in(dir.path()).unwrap();
        let at = |name: &str| case.path().join(name).to_string_lossy().into_owned();
        let snapshot = |path: String| {
            let (shell, env_path) = (shell.clone(), env_path.clone());
            async move {
                crate::connection::snapshot_local(
                    &path,
                    |run_as| {
                        let (shell, env_path) = (shell.clone(), env_path.clone());
                        let command = file_snapshot_command(run_as, &path);
                        async move {
                            Ok(run_bounded(&shell, env_path.as_ref(), &command)
                                .expect("the snapshot hung")
                                .into())
                        }
                    },
                    |path| std::fs::symlink_metadata(path).map(|_| ()),
                )
                .await
                .unwrap()
            }
        };
        let sudo_calls = || {
            std::fs::read_to_string(&log)
                .unwrap_or_default()
                .lines()
                .count()
        };
        let _ = std::fs::remove_file(&log);

        std::fs::write(at("mine"), b"old").unwrap();
        let read = snapshot(at("mine")).await;
        assert!(read.success, "{label}: {:?}", read.stderr);
        assert!(read.stdout.starts_with(b"file "), "{label}");
        let absent = snapshot(at("absent")).await;
        assert_eq!(absent.stdout, b"absent\n", "{label}: {:?}", absent.stderr);
        assert_eq!(
            sudo_calls(),
            0,
            "{label}: no sudo for what the operator reads"
        );

        std::fs::create_dir(at("shut")).unwrap();
        std::fs::write(at("shut/x"), b"old").unwrap();
        std::fs::set_permissions(at("shut"), std::fs::Permissions::from_mode(0o600)).unwrap();
        let shut = snapshot(at("shut/x")).await;
        std::fs::set_permissions(at("shut"), std::fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(
            sudo_calls(),
            1,
            "{label}: the name it can't look up goes to sudo"
        );
        assert!(!shut.success, "{label}: {shut:?}", shut = shut.stdout);
        assert_eq!(shut.code, 1, "{label}: {:?}", shut.stderr);
        assert!(
            shut.stderr.contains("its directory cannot be searched"),
            "{label}: {:?}",
            shut.stderr
        );
        checked.push(label);
    }
    eprintln!("local snapshot checked under: {checked:?}");
}

/// What one planned step runs, as the executor runs it: shell text, and for a put of
/// text the plan holds, the digest line and the text on its stdin.
#[derive(Debug, Clone)]
pub(super) struct Ran {
    /// The shell text.
    pub(super) text: String,
    /// The put script's stdin, for a put of held text.
    pub(super) stdin: Option<Vec<u8>>,
}

impl Ran {
    fn of(step: &PlanStep) -> Option<Self> {
        Some(match step.execution()? {
            StepExecution::Command(text) => Self { text, stdin: None },
            StepExecution::Put { command, content } => Self {
                text: command,
                stdin: Some(put_payload(content.as_bytes())),
            },
        })
    }

    /// The text a put installs, without its digest line.
    pub(super) fn content(&self) -> Option<&[u8]> {
        let stdin = self.stdin.as_deref()?;
        let line = stdin.iter().position(|byte| *byte == b'\n')?;
        Some(&stdin[line + 1..])
    }

    /// This step with its text rewritten.
    pub(super) fn with_text(&self, rewrite: impl FnOnce(&str) -> String) -> Self {
        Self {
            text: rewrite(&self.text),
            stdin: self.stdin.clone(),
        }
    }

    /// Run it under `shell`: a command as `sh -c`'s text, a put through the command
    /// wrapper, its payload behind the frame — as a connection delivers each.
    pub(super) fn run(&self, shell: &Path, path: Option<&OsString>) -> Output {
        let Some(payload) = &self.stdin else {
            let mut command = Command::new(shell);
            if let Some(path) = path {
                command.env("PATH", path);
            }
            return command.args(["-c", &self.text]).output().unwrap();
        };
        feed(
            shell,
            path,
            &Delivery::of(&self.text, Some(payload)).unwrap().stdin,
        )
    }
}

/// What `printf '%s\n' <lines>` prints under `shell`: the bytes a step that fed the put
/// from such a command installed.
pub(super) fn printf_lines(shell: &Path, path: Option<&OsString>, lines: &[&str]) -> Vec<u8> {
    let args: Vec<String> = lines.iter().map(|line| single_quote(line)).collect();
    let mut command = Command::new(shell);
    if let Some(path) = path {
        command.env("PATH", path);
    }
    let output = command
        .args(["-c", &format!("printf '%s\\n' {}", args.join(" "))])
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    output.stdout
}

/// The steps the planner emits for a resource that isn't there yet, as they run.
pub(super) fn absent_run_steps(resource: serde_json::Value) -> Vec<Ran> {
    let resource: Resource = serde_json::from_value(resource).unwrap();
    let detected = BTreeMap::from([(resource.id.clone(), Detection::Absent)]);
    let result = diff(DiffInputs {
        resources: &[resource],
        detected: &detected,
        target: &Target::local(),
        machine: &local_machine(),
        lock: None,
        pending: &BTreeMap::new(),
        var: &zap_types::last_run::ReportVar::unset,
    });
    result.plan.changes[0]
        .steps
        .iter()
        .filter_map(Ran::of)
        .collect()
}

/// The test's own account, when it can stand in for a managed user: a name the schema
/// accepts, with a group of the same name it belongs to (the steps `chown` to
/// `<user>:<user>`).
fn own_account() -> Option<String> {
    let name = nix::unistd::User::from_uid(nix::unistd::geteuid())
        .ok()??
        .name;
    let group = nix::unistd::Group::from_name(&name).ok()??;
    let mine =
        nix::unistd::getegid() == group.gid || nix::unistd::getgroups().ok()?.contains(&group.gid);
    let valid = serde_json::from_value::<zap_types::scalar::AccountName>(name.clone().into());
    (mine && valid.is_ok()).then_some(name)
}

/// The `user` steps for `authorized_keys`, run for real with the account's home moved
/// into the test's directory: the keys land in a `0700` `.ssh` as a `0600` regular
/// file, written as the account; a link planted at `authorized_keys` is replaced, its
/// target untouched; a link planted at `.ssh` fails the step that sets the directory up,
/// with what it names untouched; and `copy_from` reads the source as the source account,
/// failing — the existing keys left in place — when it can't.
#[test]
fn the_authorized_keys_steps_follow_no_planted_link_under_both_shells() {
    let Some(account) = own_account() else {
        eprintln!("authorized_keys steps not checked: no account to stand in for a user");
        return;
    };
    let dir = crate::test_scratch::tempdir();
    let bin = stand_in_bin(dir.path());
    let keys = "ssh-ed25519 AAAA it's one\nssh-rsa BBBB two\n";
    let mut checked = Vec::new();
    for (label, shell, env_path) in test_shells(dir.path(), APPLETS, Some(&bin)) {
        let case = tempfile::tempdir_in(dir.path()).unwrap();
        let home = case.path().join("home");
        std::fs::create_dir(&home).unwrap();
        let ssh = home.join(".ssh");
        let authorized = ssh.join("authorized_keys");
        // The steps name `/home/<user>` and `/etc/passwd`; here they name the test's.
        let passwd = case.path().join("passwd");
        let moved = |step: &str| {
            assert!(step.contains(&format!("/home/{account}/.ssh")), "{step}");
            step.replace(&format!("/home/{account}"), &home.to_string_lossy())
                .replace(
                    " /etc/passwd)",
                    &format!(" {})", single_quote(&passwd.to_string_lossy())),
                )
        };
        let ssh_steps = |ssh_keys: serde_json::Value| -> Vec<Ran> {
            absent_run_steps(serde_json::json!({
                "id": "u", "type": "user", "username": account, "ssh_keys": ssh_keys,
            }))
            .iter()
            .filter(|step| step.text.contains("/.ssh"))
            .map(|step| step.with_text(moved))
            .collect()
        };
        let run = |step: &Ran| step.run(&shell, env_path.as_ref());
        let sudo_log = || std::fs::read_to_string(bin.join("sudo.log")).unwrap_or_default();
        let explicit = ssh_steps(serde_json::json!({
            "keys": ["ssh-ed25519 AAAA it's one", "ssh-rsa BBBB two"]
        }));
        let [prepare, write] = explicit.as_slice() else {
            panic!("the directory step, then the key file's: {explicit:?}");
        };
        // The key file's text is the plan's own, sent with its digest — the bytes a
        // `printf` of the keys prints.
        assert_eq!(write.content(), Some(keys.as_bytes()), "{label}");
        assert_eq!(
            printf_lines(
                &shell,
                env_path.as_ref(),
                &["ssh-ed25519 AAAA it's one", "ssh-rsa BBBB two"]
            ),
            keys.as_bytes(),
            "{label}"
        );

        // A fresh home.
        let _ = std::fs::remove_file(bin.join("sudo.log"));
        for step in [prepare, write] {
            let output = run(step);
            assert!(output.status.success(), "{label}: {step:?}: {output:?}");
        }
        assert_eq!(mode_of(&ssh), 0o700, "{label}");
        assert_eq!(
            std::fs::read_to_string(&authorized).unwrap(),
            keys,
            "{label}"
        );
        assert_eq!(mode_of(&authorized), 0o600, "{label}");
        assert_eq!(entries(&ssh), ["authorized_keys"], "{label}");
        assert_eq!(
            sudo_log(),
            format!("{account} sh\n"),
            "{label}: the key file is written as the account, and only it"
        );

        // A link planted at the key file: replaced, its target untouched.
        let victim = case.path().join("root-keys");
        std::fs::write(&victim, "ssh-ed25519 ROOT\n").unwrap();
        std::fs::set_permissions(&victim, std::fs::Permissions::from_mode(0o640)).unwrap();
        std::fs::remove_file(&authorized).unwrap();
        symlink(&victim, &authorized).unwrap();
        for step in [prepare, write] {
            let output = run(step);
            assert!(output.status.success(), "{label}: {step:?}: {output:?}");
        }
        assert!(
            std::fs::symlink_metadata(&authorized).unwrap().is_file(),
            "{label}"
        );
        assert_eq!(
            std::fs::read_to_string(&authorized).unwrap(),
            keys,
            "{label}"
        );
        assert_eq!(
            std::fs::read_to_string(&victim).unwrap(),
            "ssh-ed25519 ROOT\n",
            "{label}"
        );
        assert_eq!(mode_of(&victim), 0o640, "{label}");

        // `copy_from`: the source's keys, read as the source account.
        let source_home = case.path().join("source home");
        std::fs::create_dir_all(source_home.join(".ssh")).unwrap();
        std::fs::write(
            source_home.join(".ssh/authorized_keys"),
            "ssh-ed25519 SOURCE\n\n",
        )
        .unwrap();
        std::fs::write(
            &passwd,
            format!(
                "source:x:1:1::{}:/bin/sh\nhomeless:x:2:2:::/bin/sh\n",
                source_home.display()
            ),
        )
        .unwrap();
        let copied = ssh_steps(serde_json::json!({"copy_from": "source"}));
        let _ = std::fs::remove_file(bin.join("sudo.log"));
        let output = run(&copied[1]);
        assert!(output.status.success(), "{label}: {output:?}");
        assert_eq!(
            std::fs::read_to_string(&authorized).unwrap(),
            "ssh-ed25519 SOURCE\n\n",
            "{label}: byte for byte, trailing newlines too"
        );
        assert_eq!(
            sudo_log(),
            format!("source cat\n{account} sh\n"),
            "{label}: read as the source, written as the account"
        );
        // A source that can't be read, or has no home: the step fails and the keys stay.
        std::fs::remove_file(source_home.join(".ssh/authorized_keys")).unwrap();
        let output = run(&copied[1]);
        assert!(!output.status.success(), "{label}: {output:?}");
        let homeless = ssh_steps(serde_json::json!({"copy_from": "homeless"}));
        let output = run(&homeless[1]);
        assert!(!output.status.success(), "{label}: {output:?}");
        assert!(
            stderr(&output).contains("no home directory for homeless"),
            "{label}: {output:?}"
        );
        assert_eq!(
            std::fs::read_to_string(&authorized).unwrap(),
            "ssh-ed25519 SOURCE\n\n",
            "{label}"
        );
        assert_eq!(entries(&ssh), ["authorized_keys"], "{label}");

        // A link planted at `.ssh`: the directory step fails, and what the link names
        // keeps its mode and gains nothing.
        let elsewhere = case.path().join("root-ssh");
        std::fs::create_dir(&elsewhere).unwrap();
        std::fs::set_permissions(&elsewhere, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::remove_dir_all(&ssh).unwrap();
        symlink(&elsewhere, &ssh).unwrap();
        let output = run(prepare);
        assert!(!output.status.success(), "{label}: {output:?}");
        assert!(
            stderr(&output).contains("a symbolic link is not followed"),
            "{label}: {output:?}"
        );
        assert_eq!(mode_of(&elsewhere), 0o755, "{label}");
        assert!(entries(&elsewhere).is_empty(), "{label}");
        checked.push(label);
    }
    eprintln!("authorized_keys steps checked under: {checked:?}");
}

/// The `user` sudoers step, run for real against a directory of the test's own: the
/// line lands at `0440` once `visudo` accepts it, and a file `visudo` rejects leaves the
/// old one in place, fails the step, and leaves no stage behind.
#[test]
fn the_sudoers_step_installs_only_what_visudo_accepts_under_both_shells() {
    let dir = crate::test_scratch::tempdir();
    let bin = stand_in_bin(dir.path());
    let verdict = dir.path().join("visudo-verdict");
    executable(
        &bin.join("visudo"),
        &format!(
            "[ \"$1\" = -cf ] && [ -s \"$2\" ] || exit 64\n. {}",
            single_quote(&verdict.to_string_lossy())
        ),
    );
    let mut checked = Vec::new();
    for (label, shell, env_path) in test_shells(dir.path(), APPLETS, Some(&bin)) {
        let case = tempfile::tempdir_in(dir.path()).unwrap();
        let steps = absent_run_steps(serde_json::json!({
            "id": "u", "type": "user", "username": "deploy",
            "sudo": {"mode": "nopasswd", "commands": ["/usr/bin/systemctl restart it's"]},
        }));
        let step = steps.last().unwrap();
        assert!(
            step.text.contains("'/etc/sudoers.d/deploy'") && step.text.ends_with(" 'sudoers' ''"),
            "{step:?}"
        );
        let step =
            step.with_text(|text| text.replace("/etc/sudoers.d", &case.path().to_string_lossy()));
        let drop_in = case.path().join("deploy");
        let run = || step.run(&shell, env_path.as_ref());
        let line = "deploy ALL=(ALL) NOPASSWD: /usr/bin/systemctl restart it's\n";
        // The text is the plan's own, sent with its digest — the bytes a `printf` of the
        // line prints.
        assert_eq!(step.content(), Some(line.as_bytes()), "{label}");
        assert_eq!(
            printf_lines(&shell, env_path.as_ref(), &[line.trim_end()]),
            line.as_bytes(),
            "{label}"
        );

        std::fs::write(&verdict, "exit 0").unwrap();
        let output = run();
        assert!(output.status.success(), "{label}: {output:?}");
        assert_eq!(std::fs::read_to_string(&drop_in).unwrap(), line, "{label}");
        assert_eq!(mode_of(&drop_in), 0o440, "{label}");
        assert_eq!(entries(case.path()), ["deploy"], "{label}");

        std::fs::remove_file(&drop_in).unwrap();
        std::fs::write(&drop_in, "OLD\n").unwrap();
        std::fs::write(&verdict, "echo 'syntax error near line 1' >&2; exit 1").unwrap();
        let output = run();
        assert!(!output.status.success(), "{label}: {output:?}");
        assert!(
            stderr(&output).contains("syntax error"),
            "{label}: {output:?}"
        );
        assert!(
            stderr(&output).contains("visudo did not accept"),
            "{label}: {output:?}"
        );
        assert_eq!(
            std::fs::read_to_string(&drop_in).unwrap(),
            "OLD\n",
            "{label}"
        );
        assert_eq!(entries(case.path()), ["deploy"], "{label}");
        checked.push(label);
    }
    eprintln!("sudoers step checked under: {checked:?}");
}

/// The owner change lands on the file the put holds open, whatever its name has become:
/// with the staged name swapped for a link to a victim, the victim keeps its group and
/// the put refuses. A `chown` by name would have followed the link.
#[test]
fn a_swapped_stage_name_takes_no_owner_change_to_its_target_under_both_shells() {
    let primary = nix::unistd::getegid();
    let Some(other) = nix::unistd::getgroups()
        .unwrap_or_default()
        .into_iter()
        .find(|gid| *gid != primary)
    else {
        eprintln!("owner change through a swapped name not checked: one group only");
        return;
    };
    let group = nix::unistd::Group::from_gid(other).unwrap().unwrap().name;
    let dir = crate::test_scratch::tempdir();
    let bin = stand_in_bin(dir.path());
    let mut checked = Vec::new();
    for (label, shell, env_path) in test_shells(dir.path(), APPLETS, Some(&bin)) {
        let case = tempfile::tempdir_in(dir.path()).unwrap();
        let at = |name: &str| case.path().join(name);
        std::fs::write(at("victim"), "ORIGINAL").unwrap();
        let victim_gid = std::fs::metadata(at("victim")).unwrap().gid();
        assert_ne!(victim_gid, other.as_raw(), "{label}");
        std::fs::write(at("c.conf"), "OLD").unwrap();
        let script = file_put_command(
            RunAs::Root,
            &at("c.conf").to_string_lossy(),
            FileAttrs {
                mode: Some("644"),
                owner: None,
                group: Some(&group),
                ..FileAttrs::NONE
            },
            PutCheck::None,
        );
        let (stdin, _) = framed(&script, &sha512_hex(b"NEW"), b"NEW");
        let real = on_path(env_path.as_ref(), "sha512sum");
        let lead = tempfile::tempdir_in(dir.path()).unwrap();
        executable(
            &lead.path().join("sha512sum"),
            &format!(
                "for f in ./.zap.*; do mv \"$f\" ./moved && ln -s {} \"$f\"; done\nexec {} \"$@\"",
                single_quote(&at("victim").to_string_lossy()),
                single_quote(&real.to_string_lossy())
            ),
        );
        let output = feed(
            &shell,
            Some(&led_by(lead.path(), env_path.as_ref())),
            &stdin,
        );
        assert!(!output.status.success(), "{label}: {output:?}");
        assert!(
            stderr(&output).contains("staged copy was replaced"),
            "{label}: {output:?}"
        );
        assert_eq!(
            std::fs::metadata(at("victim")).unwrap().gid(),
            victim_gid,
            "{label}: the group went through the planted link"
        );
        assert_eq!(
            std::fs::metadata(at("moved")).unwrap().gid(),
            other.as_raw(),
            "{label}: the group went to the file the put created"
        );
        assert_eq!(std::fs::read(at("c.conf")).unwrap(), b"OLD", "{label}");
        checked.push(label);
    }
    eprintln!("owner through a swapped name checked under: {checked:?}");
}

/// A directory holding links to `tools` as the leg's `PATH` finds them, and `sh` — a
/// whole `PATH` with exactly those on it.
pub(super) fn only_tools(dir: &Path, leg_path: Option<&OsString>, tools: &[&str]) -> PathBuf {
    let only = tempfile::tempdir_in(dir).unwrap().keep();
    for tool in tools.iter().chain(&["sh"]) {
        symlink(on_path(leg_path, tool), only.join(tool)).unwrap();
    }
    only
}

/// Run a script's text itself — `sh -c <text> sh <args>` — with `stdin`.
fn run_text(shell: &Path, path: &Path, text: &str, args: &[&str], stdin: &[u8]) -> Output {
    let mut child = Command::new(shell)
        .env("PATH", path)
        .args(["-c", text, "sh"])
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let _ = child.stdin.take().unwrap().write_all(stdin);
    child.wait_with_output().unwrap()
}

/// What a target lacks is said plainly, as the script's own refusal, before anything is
/// created: a tool the script runs, `visudo` for the `sudoers` check, and `/proc` (the
/// script's descriptor root pointed somewhere that isn't there). With all of them, the
/// same call installs.
#[test]
fn a_script_names_what_the_target_lacks_and_creates_nothing_under_both_shells() {
    const PUT_TOOLS: &[&str] = &[
        "mktemp",
        "cat",
        "sha512sum",
        "chown",
        "chmod",
        "sync",
        "stat",
        "mv",
        "rm",
        "id",
        "ls",
    ];
    const DIR_TOOLS: &[&str] = &["stat", "chown", "chmod"];
    const MAKE_TOOLS: &[&str] = &["stat", "mkdir", "chown", "ls", "id"];
    let dir = crate::test_scratch::tempdir();
    let mut stdin = format!("{}\n", sha512_hex(b"NEW")).into_bytes();
    stdin.extend_from_slice(b"NEW");
    let mut checked = Vec::new();
    for (label, _, env_path) in test_shells(dir.path(), APPLETS, None) {
        let case = tempfile::tempdir_in(dir.path()).unwrap();
        let conf = case.path().join("app.conf");
        std::fs::write(&conf, "OLD").unwrap();
        let conf_arg = conf.to_string_lossy().into_owned();
        let sub = case.path().join("sub");
        std::fs::create_dir(&sub).unwrap();
        std::fs::set_permissions(&sub, std::fs::Permissions::from_mode(0o700)).unwrap();
        let sub_arg = sub.to_string_lossy().into_owned();
        let refused = |what: &str, output: &Output, says: &str| {
            assert_eq!(
                output.status.code(),
                Some(REFUSED_EXIT),
                "{label}: {what}: {output:?}"
            );
            assert!(stderr(output).contains(says), "{label}: {what}: {output:?}");
            assert_eq!(std::fs::read(&conf).unwrap(), b"OLD", "{label}: {what}");
            assert_eq!(entries(case.path()), ["app.conf", "sub"], "{label}: {what}");
            assert_eq!(mode_of(&sub), 0o700, "{label}: {what}");
        };

        // Each tool in turn missing from the `PATH`.
        for missing in PUT_TOOLS {
            let tools: Vec<&str> = PUT_TOOLS.iter().copied().filter(|t| t != missing).collect();
            let path = only_tools(dir.path(), env_path.as_ref(), &tools);
            let output = run_text(
                &path.join("sh"),
                &path,
                FILE_PUT,
                &[&conf_arg, "600", "", ""],
                &stdin,
            );
            refused(missing, &output, &format!("no {missing} on this machine"));
        }
        for missing in DIR_TOOLS {
            let tools: Vec<&str> = DIR_TOOLS.iter().copied().filter(|t| t != missing).collect();
            let path = only_tools(dir.path(), env_path.as_ref(), &tools);
            let output = run_text(
                &path.join("sh"),
                &path,
                DIR_ATTRS,
                &[&sub_arg, "755", ""],
                b"",
            );
            refused(missing, &output, &format!("no {missing} on this machine"));
        }
        let made = sub.join("made");
        let made_arg = made.to_string_lossy().into_owned();
        for missing in MAKE_TOOLS {
            let tools: Vec<&str> = MAKE_TOOLS
                .iter()
                .copied()
                .filter(|t| t != missing)
                .collect();
            let path = only_tools(dir.path(), env_path.as_ref(), &tools);
            let output = run_text(&path.join("sh"), &path, MAKE_DIRS, &[&made_arg], b"");
            refused(missing, &output, &format!("no {missing} on this machine"));
            assert!(!made.exists(), "{label}: {missing}");
        }

        let all = only_tools(dir.path(), env_path.as_ref(), PUT_TOOLS);
        let sh = all.join("sh");

        // No `visudo` — on the `PATH` or at the fallback — for the `sudoers` check.
        assert_eq!(FILE_PUT.matches("/usr/sbin/visudo").count(), 1);
        let no_visudo = FILE_PUT.replace("/usr/sbin/visudo", "/nonexistent/visudo");
        let output = run_text(
            &sh,
            &all,
            &no_visudo,
            &[&conf_arg, "440", "", "sudoers"],
            &stdin,
        );
        refused("visudo", &output, "no visudo on this machine");

        // No `/proc`: each script's one mention of it, pointed at nothing.
        for script in [FILE_PUT, DIR_ATTRS, MAKE_DIRS] {
            assert_eq!(script.matches("/proc/self/fd").count(), 1);
        }
        let no_proc = FILE_PUT.replace("/proc/self/fd", "/nonexistent/fd");
        let output = run_text(&sh, &all, &no_proc, &[&conf_arg, "600", "", ""], &stdin);
        refused("/proc, for a put", &output, "no /proc on this machine");
        let no_proc = DIR_ATTRS.replace("/proc/self/fd", "/nonexistent/fd");
        let output = run_text(&sh, &all, &no_proc, &[&sub_arg, "755", ""], b"");
        refused(
            "/proc, for a directory",
            &output,
            "no /proc on this machine",
        );
        let make = only_tools(dir.path(), env_path.as_ref(), MAKE_TOOLS);
        let no_proc = MAKE_DIRS.replace("/proc/self/fd", "/nonexistent/fd");
        let output = run_text(&make.join("sh"), &make, &no_proc, &[&made_arg], b"");
        refused("/proc, to make one", &output, "no /proc on this machine");
        assert!(!made.exists(), "{label}");
        let output = run_text(&make.join("sh"), &make, MAKE_DIRS, &[&made_arg], b"");
        assert!(output.status.success(), "{label}: {output:?}");
        assert!(made.is_dir(), "{label}");
        std::fs::remove_dir(&made).unwrap();

        // With everything there, the same calls do their work.
        let output = run_text(&sh, &all, DIR_ATTRS, &[&sub_arg, "755", ""], b"");
        assert!(output.status.success(), "{label}: {output:?}");
        assert_eq!(mode_of(&sub) & 0o777, 0o755, "{label}");
        let output = run_text(&sh, &all, FILE_PUT, &[&conf_arg, "600", "", ""], &stdin);
        assert!(output.status.success(), "{label}: {output:?}");
        assert_eq!(std::fs::read(&conf).unwrap(), b"NEW", "{label}");
        checked.push(label);
    }
    eprintln!("missing tools checked under: {checked:?}");
}

/// The gid of a group of the test's user: [`a_group_of_mine`]'s.
pub(super) fn a_gid_of_mine() -> (String, u32) {
    let name = a_group_of_mine();
    let gid = nix::unistd::Group::from_name(&name)
        .unwrap()
        .unwrap()
        .gid
        .as_raw();
    (name, gid)
}

/// A `bin` holding [`stand_in_bin`]'s `sudo` and a `chown` that logs its arguments to
/// `<bin>/chown.log`, a line per call, then runs the leg's own `chown`: the next on a
/// `PATH` this `bin` leads.
pub(super) fn recording_bin(dir: &Path) -> PathBuf {
    let bin = stand_in_bin(dir);
    executable(
        &bin.join("chown"),
        &format!(
            "echo \"$*\" >> {}\nPATH=${{PATH#*:}} exec chown \"$@\"",
            single_quote(&bin.join("chown.log").to_string_lossy()),
        ),
    );
    bin
}

/// The `chown` calls a [`recording_bin`] logged, and the log cleared.
pub(super) fn chown_calls(bin: &Path) -> Vec<String> {
    let log = bin.join("chown.log");
    let calls = std::fs::read_to_string(&log)
        .unwrap_or_default()
        .lines()
        .map(str::to_owned)
        .collect();
    let _ = std::fs::remove_file(&log);
    calls
}

/// The mode, owner, and group of what is at `path`, no link followed.
fn attrs_of(path: &Path) -> (u32, u32, u32) {
    let meta = std::fs::symlink_metadata(path).unwrap();
    (meta.mode() & 0o7777, meta.uid(), meta.gid())
}

/// A put that keeps what it leaves unset: a regular file at the path keeps its group
/// and mode, the mode less any set-id or sticky bit, and a declared mode stands; a new
/// file takes its directory's group (one that isn't set-group-id, so the kernel alone
/// wouldn't give it); a link at the path, or a file with a second name, is replaced by
/// a fresh file, what it named untouched; and anywhere below a directory anyone may put
/// an entry in, a file or a new name is fresh. A fresh put over the same file gives a plain
/// create's mode and the caller's group. Each owner a kept put sets is the `uid:gid` it
/// read, after `--`.
#[test]
fn a_kept_put_keeps_what_it_leaves_unset_under_both_shells() {
    let (_, gid) = a_gid_of_mine();
    let me = (
        nix::unistd::geteuid().as_raw(),
        nix::unistd::getegid().as_raw(),
    );
    let dir = crate::test_scratch::tempdir();
    let bin = recording_bin(dir.path());
    let mut checked = Vec::new();
    for leg in test_shells(dir.path(), APPLETS, Some(&bin)) {
        let label = leg.0;
        let case = tempfile::tempdir_in(dir.path()).unwrap();
        let at = |name: &str| case.path().join(name);
        let put_under_022 = |path: &Path, attrs: FileAttrs<'_>| {
            let script = format!(
                "umask 022; {}",
                file_put_command(RunAs::Root, &path.to_string_lossy(), attrs, PutCheck::None)
            );
            let (stdin, _) = framed(&script, &sha512_hex(b"NEW"), b"NEW");
            feed(&leg.1, leg.2.as_ref(), &stdin)
        };
        let existing = |name: &str, mode: u32| {
            std::fs::write(at(name), "OLD").unwrap();
            std::os::unix::fs::chown(at(name), None, Some(gid)).unwrap();
            std::fs::set_permissions(at(name), std::fs::Permissions::from_mode(mode)).unwrap();
        };
        let _ = chown_calls(&bin);

        existing("kept", 0o640);
        let output = put_under_022(&at("kept"), FileAttrs::NONE.keeping());
        assert!(output.status.success(), "{label}: {output:?}");
        assert_eq!(std::fs::read(at("kept")).unwrap(), b"NEW", "{label}");
        assert_eq!(attrs_of(&at("kept")), (0o640, me.0, gid), "{label}");
        assert_eq!(
            chown_calls(&bin),
            [format!("-- {}:{gid} /proc/self/fd/3", me.0)],
            "{label}: the ids read, as one spec"
        );

        for (name, mode) in [("setuid", 0o4755), ("setgid", 0o2755), ("sticky", 0o1640)] {
            existing(name, mode);
            let output = put_under_022(&at(name), FileAttrs::NONE.keeping());
            assert!(output.status.success(), "{label}: {name}: {output:?}");
            assert_eq!(
                attrs_of(&at(name)),
                (mode & 0o777, me.0, gid),
                "{label}: {name}: kept without its special bit"
            );
        }

        // A declared mode stands, the group still kept; a declared group stands too.
        existing("declared", 0o640);
        let output = put_under_022(&at("declared"), FileAttrs::mode("600").keeping());
        assert!(output.status.success(), "{label}: {output:?}");
        assert_eq!(attrs_of(&at("declared")), (0o600, me.0, gid), "{label}");
        let mine = nix::unistd::Group::from_gid(nix::unistd::Gid::from_raw(me.1))
            .unwrap()
            .unwrap()
            .name;
        let _ = chown_calls(&bin);
        let declared_group = FileAttrs {
            group: Some(&mine),
            ..FileAttrs::NONE
        };
        let output = put_under_022(&at("declared"), declared_group.keeping());
        assert!(output.status.success(), "{label}: {output:?}");
        assert_eq!(attrs_of(&at("declared")), (0o600, me.0, me.1), "{label}");
        assert_eq!(
            chown_calls(&bin),
            [format!("-- {}:{mine} /proc/self/fd/3", me.0)],
            "{label}: the declared group, the owner kept"
        );

        // Fresh, the same file: a plain create's mode and the caller's group, and no
        // owner change at all.
        existing("fresh", 0o640);
        let output = put_under_022(&at("fresh"), FileAttrs::NONE);
        assert!(output.status.success(), "{label}: {output:?}");
        assert_eq!(attrs_of(&at("fresh")), (0o644, me.0, me.1), "{label}");
        assert_eq!(chown_calls(&bin), Vec::<String>::new(), "{label}");

        // Nothing there: the directory's group, a plain create's mode.
        std::fs::create_dir(at("theirs")).unwrap();
        std::os::unix::fs::chown(at("theirs"), None, Some(gid)).unwrap();
        std::fs::set_permissions(at("theirs"), std::fs::Permissions::from_mode(0o755)).unwrap();
        let output = put_under_022(&at("theirs").join("new"), FileAttrs::NONE.keeping());
        assert!(output.status.success(), "{label}: {output:?}");
        assert_eq!(
            attrs_of(&at("theirs").join("new")),
            (0o644, me.0, gid),
            "{label}"
        );
        assert_eq!(
            chown_calls(&bin),
            [format!("-- {}:{gid} /proc/self/fd/3", me.0)],
            "{label}: the directory's ids"
        );

        // A link at the path: replaced by a fresh file, its target untouched.
        existing("victim", 0o600);
        symlink(at("victim"), at("linked")).unwrap();
        let output = put_under_022(&at("linked"), FileAttrs::NONE.keeping());
        assert!(output.status.success(), "{label}: {output:?}");
        assert_eq!(attrs_of(&at("linked")), (0o644, me.0, me.1), "{label}");
        assert_eq!(attrs_of(&at("victim")), (0o600, me.0, gid), "{label}");
        assert_eq!(std::fs::read(at("victim")).unwrap(), b"OLD", "{label}");
        assert_eq!(chown_calls(&bin), Vec::<String>::new(), "{label}");

        // A file with a second name (a hard link) is no file to keep from: replaced by
        // a fresh one, the other name's file untouched.
        existing("first", 0o640);
        std::fs::hard_link(at("first"), at("second")).unwrap();
        let output = put_under_022(&at("second"), FileAttrs::NONE.keeping());
        assert!(output.status.success(), "{label}: {output:?}");
        assert_eq!(attrs_of(&at("second")), (0o644, me.0, me.1), "{label}");
        assert_eq!(attrs_of(&at("first")), (0o640, me.0, gid), "{label}");
        assert_eq!(std::fs::read(at("first")).unwrap(), b"OLD", "{label}");
        assert_eq!(chown_calls(&bin), Vec::<String>::new(), "{label}");

        // A directory anyone may put an entry in — sticky like `/tmp`, or writable by
        // all — gives nothing: a file there and a new name there are both fresh.
        for (shared, mode) in [("sticky-dir", 0o1777), ("open-dir", 0o777)] {
            std::fs::create_dir(at(shared)).unwrap();
            std::os::unix::fs::chown(at(shared), None, Some(gid)).unwrap();
            std::fs::set_permissions(at(shared), std::fs::Permissions::from_mode(mode)).unwrap();
            let planted = at(shared).join("planted");
            std::fs::write(&planted, "OLD").unwrap();
            std::os::unix::fs::chown(&planted, None, Some(gid)).unwrap();
            std::fs::set_permissions(&planted, std::fs::Permissions::from_mode(0o640)).unwrap();
            for name in ["planted", "new"] {
                let path = at(shared).join(name);
                let output = put_under_022(&path, FileAttrs::NONE.keeping());
                assert!(
                    output.status.success(),
                    "{label}: {shared}/{name}: {output:?}"
                );
                assert_eq!(
                    attrs_of(&path),
                    (0o644, me.0, me.1),
                    "{label}: {shared}/{name}: the writer's, fresh"
                );
            }
            assert_eq!(chown_calls(&bin), Vec::<String>::new(), "{label}: {shared}");

            // A directory of another's inside it, open to no one itself, gives nothing
            // either: anyone could have made it, or renamed it in.
            let cache = at(shared).join("cache");
            std::fs::create_dir(&cache).unwrap();
            std::os::unix::fs::chown(&cache, None, Some(gid)).unwrap();
            std::fs::set_permissions(&cache, std::fs::Permissions::from_mode(0o755)).unwrap();
            let planted = cache.join("planted");
            std::fs::write(&planted, "OLD").unwrap();
            std::os::unix::fs::chown(&planted, None, Some(gid)).unwrap();
            std::fs::set_permissions(&planted, std::fs::Permissions::from_mode(0o640)).unwrap();
            for name in ["planted", "new"] {
                let path = cache.join(name);
                let output = put_under_022(&path, FileAttrs::NONE.keeping());
                assert!(
                    output.status.success(),
                    "{label}: {shared}/cache/{name}: {output:?}"
                );
                assert_eq!(
                    attrs_of(&path),
                    (0o644, me.0, me.1),
                    "{label}: {shared}/cache/{name}: the writer's, fresh"
                );
            }
            assert_eq!(
                chown_calls(&bin),
                Vec::<String>::new(),
                "{label}: {shared}/cache"
            );
        }

        // An attribute rule the script doesn't know is refused, with nothing made.
        let fresh = file_put_command(
            RunAs::Root,
            &at("unknown").to_string_lossy(),
            FileAttrs::NONE,
            PutCheck::None,
        );
        let script = format!("{} 'keep-all'", fresh.strip_suffix(" ''").unwrap());
        let (stdin, _) = framed(&script, &sha512_hex(b"NEW"), b"NEW");
        let output = feed(&leg.1, leg.2.as_ref(), &stdin);
        assert_eq!(
            output.status.code(),
            Some(REFUSED_EXIT),
            "{label}: {output:?}"
        );
        assert!(
            stderr(&output).contains("unknown attribute rule"),
            "{label}"
        );
        assert!(!at("unknown").exists(), "{label}");
        assert!(
            !entries(case.path())
                .iter()
                .any(|name| name.starts_with(".zap.")),
            "{label}"
        );
        checked.push(label);
    }
    eprintln!("kept put checked under: {checked:?}");
}

/// Run `setfacl` with `args` on `path`: `false` when there is no `setfacl` on this
/// machine (the test then checks nothing, and `tests/required_programs.rs` fails unless
/// `ZAP_TEST_ALLOW_NO_SETFACL=1`). A `setfacl` that is there and fails panics — a
/// filesystem without access lists can't run these tests, rather than skip them.
pub(super) fn run_setfacl(args: &[&str], path: &Path) -> bool {
    match Command::new("setfacl")
        .args(args)
        .arg("--")
        .arg(path)
        .output()
    {
        Ok(output) => {
            assert!(
                output.status.success(),
                "setfacl {args:?} {path:?}: {output:?}"
            );
            true
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
        Err(error) => panic!("setfacl: {error}"),
    }
}

/// Give the file at `path` an extended POSIX access list (`setfacl -m u:nobody:rw`):
/// `false` when there is no `setfacl` ([`run_setfacl`]).
pub(super) fn give_access_list(path: &Path) -> bool {
    run_setfacl(&["-m", "u:nobody:rw"], path)
}

/// Whether the file at `path` has an extended access list, by `getfacl -cs`.
fn has_access_list(path: &Path) -> bool {
    let output = Command::new("getfacl")
        .args(["-cs", "--"])
        .arg(path)
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    !output.stdout.is_empty()
}

/// A mode to keep from a file with an extended POSIX access list is refused, the file
/// as it was and nothing staged: its mode bits show the list's mask, so a kept mode
/// would hand the group what the list gave one account. The list is seen through
/// `getfacl` on the `PATH` and, without it, through GNU `ls`'s `+`; `BusyBox` `ls`
/// shows none, so with only its applets the mode is kept. A declared mode installs,
/// the new file with no list.
#[test]
fn a_kept_mode_from_a_file_with_an_access_list_is_refused_under_both_shells() {
    let dir = crate::test_scratch::tempdir();
    let probe = dir.path().join("probe");
    std::fs::write(&probe, "").unwrap();
    if !give_access_list(&probe) || Command::new("getfacl").arg("--version").output().is_err() {
        eprintln!("a kept mode under an access list not checked: no setfacl or getfacl");
        return;
    }
    let bin = stand_in_bin(dir.path());
    let mut checked = Vec::new();
    for leg in test_shells(dir.path(), APPLETS, Some(&bin)) {
        let label = leg.0;
        let case = tempfile::tempdir_in(dir.path()).unwrap();
        let listed = case.path().join("listed");
        let fresh_list = || {
            std::fs::write(&listed, "OLD").unwrap();
            std::fs::set_permissions(&listed, std::fs::Permissions::from_mode(0o640)).unwrap();
            assert!(give_access_list(&listed));
            // The mask, widened by the entry for `nobody`, is what the group bits show.
            assert_eq!(mode_of(&listed), 0o660, "{label}");
        };
        fresh_list();
        let output = put(&leg, &listed, FileAttrs::NONE.keeping(), b"NEW");
        if label == "busybox" {
            assert!(output.status.success(), "{label}: {output:?}");
            assert_eq!(mode_of(&listed), 0o660, "{label}: unseen, the mode is kept");
            fresh_list();
        } else {
            assert_eq!(
                output.status.code(),
                Some(REFUSED_EXIT),
                "{label}: {output:?}"
            );
            assert!(
                stderr(&output).contains("has an access list (ACL)")
                    && stderr(&output).contains("declare its mode"),
                "{label}: {output:?}"
            );
            assert_eq!(std::fs::read(&listed).unwrap(), b"OLD", "{label}");
            assert!(has_access_list(&listed), "{label}");
            assert_eq!(entries(case.path()), ["listed"], "{label}: nothing staged");

            // Without `getfacl`, GNU `ls` shows the list.
            let mut tools = vec![
                "mktemp",
                "cat",
                "sha512sum",
                "chown",
                "chmod",
                "sync",
                "stat",
                "mv",
                "rm",
                "id",
                "ls",
            ];
            let gnu = only_tools(dir.path(), leg.2.as_ref(), &tools);
            let mut stdin = format!("{}\n", sha512_hex(b"NEW")).into_bytes();
            stdin.extend_from_slice(b"NEW");
            let args = [&*listed.to_string_lossy(), "", "", "", "keep"].map(str::to_owned);
            let args: Vec<&str> = args.iter().map(String::as_str).collect();
            let output = run_text(&gnu.join("sh"), &gnu, FILE_PUT, &args, &stdin);
            assert_eq!(
                output.status.code(),
                Some(REFUSED_EXIT),
                "{label}: by ls: {output:?}"
            );
            assert_eq!(std::fs::read(&listed).unwrap(), b"OLD", "{label}");
            // And with `getfacl` there too, it is the one asked.
            tools.push("getfacl");
            let both = only_tools(dir.path(), leg.2.as_ref(), &tools);
            let output = run_text(&both.join("sh"), &both, FILE_PUT, &args, &stdin);
            assert_eq!(
                output.status.code(),
                Some(REFUSED_EXIT),
                "{label}: by getfacl: {output:?}"
            );
        }

        // A declared mode: installed, with no list.
        let output = put(&leg, &listed, FileAttrs::mode("640").keeping(), b"NEW");
        assert!(output.status.success(), "{label}: {output:?}");
        assert_eq!(std::fs::read(&listed).unwrap(), b"NEW", "{label}");
        assert_eq!(mode_of(&listed), 0o640, "{label}");
        assert!(
            !has_access_list(&listed),
            "{label}: the new file has no list"
        );
        checked.push(label);
    }
    eprintln!("a kept mode under an access list checked under: {checked:?}");
}

/// As root (`fakeroot`'s), a kept put keeps an owner and group that aren't the
/// writer's — another account's file, a new file in another account's directory — and
/// fills only what a partial declaration leaves out; a fresh put gives root's, and so
/// does a kept one in a sticky directory, where another account planted the file.
#[test]
fn as_root_a_kept_put_keeps_another_accounts_owner_under_both_shells() {
    let Some(fakeroot) = super::extract::fakeroot() else {
        eprintln!("a kept owner not checked: no working fakeroot");
        return;
    };
    let dir = crate::test_scratch::tempdir();
    let bin = stand_in_bin(dir.path());
    let fed = format!(
        "{{ printf '%s\\n' {}; printf NEW; }} | ",
        sha512_hex(b"NEW")
    );
    let mut checked = Vec::new();
    for leg in test_shells(dir.path(), APPLETS, Some(&bin)) {
        let label = leg.0;
        let case = tempfile::tempdir_in(dir.path()).unwrap();
        let at = |name: &str| case.path().join(name).to_string_lossy().into_owned();
        let put_of = |name: &str, attrs: FileAttrs<'_>| {
            format!(
                "{fed}{}",
                file_put_command(RunAs::Root, &at(name), attrs, PutCheck::None)
            )
        };
        let names = [
            "kept",
            "owner",
            "group",
            "fresh",
            "theirs/new",
            "shared/planted",
            "shared/new",
        ];
        let script = format!(
            "umask 022; cd {case} && mkdir theirs shared && chown 1234:5678 theirs shared && \
             chmod 1777 shared && for f in kept owner group fresh shared/planted; do \
             echo OLD > $f && chown 1234:5678 $f && chmod 640 $f; done && {kept} && \
             {owner} && {group} && {fresh} && {new} && {planted} && {shared_new} && \
             stat -c '%n %u:%g %a' {names}",
            case = single_quote(&case.path().to_string_lossy()),
            kept = put_of("kept", FileAttrs::NONE.keeping()),
            owner = put_of(
                "owner",
                FileAttrs {
                    owner: Some("0"),
                    ..FileAttrs::NONE
                }
                .keeping()
            ),
            group = put_of(
                "group",
                FileAttrs {
                    group: Some("0"),
                    ..FileAttrs::NONE
                }
                .keeping()
            ),
            fresh = put_of("fresh", FileAttrs::NONE),
            new = put_of("theirs/new", FileAttrs::NONE.keeping()),
            planted = put_of("shared/planted", FileAttrs::NONE.keeping()),
            shared_new = put_of("shared/new", FileAttrs::NONE.keeping()),
            names = names.join(" "),
        );
        let output = super::extract::run_as_fake_root(&fakeroot, &leg, &script);
        assert!(output.status.success(), "{label}: {output:?}");
        assert_eq!(
            String::from_utf8_lossy(&output.stdout),
            "kept 1234:5678 640\nowner 0:5678 640\ngroup 1234:0 640\nfresh 0:0 644\n\
             theirs/new 1234:5678 644\nshared/planted 0:0 644\nshared/new 0:0 644\n",
            "{label}"
        );
        checked.push(label);
    }
    eprintln!("kept owner checked under: {checked:?}");
}

/// The native install and the put script agree on what a write gives what it leaves
/// out: over the same files — one to keep, a set-id one, a link, a hard-linked one, a
/// name in a directory of another group, a file and a name in a sticky directory, and a
/// fresh write over a file — each lands with the same mode,
/// owner, and group, the script under the umask this process runs with.
#[tokio::test]
async fn the_native_install_and_the_put_script_keep_the_same_attributes_under_both_shells() {
    use crate::connection::local_put::{LocalSource, put as native_put};

    let (_, gid) = a_gid_of_mine();
    let dir = crate::test_scratch::tempdir();
    let bin = stand_in_bin(dir.path());
    std::fs::write(dir.path().join("probe"), "").unwrap();
    let umask = 0o666 & !mode_of(&dir.path().join("probe"));
    let cases: [(&str, FileAttrs<'static>); 9] = [
        ("kept", FileAttrs::NONE.keeping()),
        ("setuid", FileAttrs::NONE.keeping()),
        ("declared", FileAttrs::mode("600").keeping()),
        ("linked", FileAttrs::NONE.keeping()),
        ("second", FileAttrs::NONE.keeping()),
        ("theirs/new", FileAttrs::NONE.keeping()),
        ("shared/planted", FileAttrs::NONE.keeping()),
        ("shared/new", FileAttrs::NONE.keeping()),
        ("fresh", FileAttrs::NONE),
    ];
    let fixture = |root: &Path| {
        let at = |name: &str| root.join(name);
        for (name, mode) in [("kept", 0o640), ("setuid", 0o4755), ("declared", 0o640)] {
            std::fs::write(at(name), "OLD").unwrap();
            std::os::unix::fs::chown(at(name), None, Some(gid)).unwrap();
            std::fs::set_permissions(at(name), std::fs::Permissions::from_mode(mode)).unwrap();
        }
        std::fs::write(at("fresh"), "OLD").unwrap();
        std::fs::set_permissions(at("fresh"), std::fs::Permissions::from_mode(0o640)).unwrap();
        std::fs::write(at("victim"), "OLD").unwrap();
        std::fs::set_permissions(at("victim"), std::fs::Permissions::from_mode(0o600)).unwrap();
        symlink(at("victim"), at("linked")).unwrap();
        std::fs::create_dir(at("theirs")).unwrap();
        std::os::unix::fs::chown(at("theirs"), None, Some(gid)).unwrap();
        std::fs::write(at("first"), "OLD").unwrap();
        std::os::unix::fs::chown(at("first"), None, Some(gid)).unwrap();
        std::fs::set_permissions(at("first"), std::fs::Permissions::from_mode(0o640)).unwrap();
        std::fs::hard_link(at("first"), at("second")).unwrap();
        std::fs::create_dir(at("shared")).unwrap();
        std::os::unix::fs::chown(at("shared"), None, Some(gid)).unwrap();
        std::fs::set_permissions(at("shared"), std::fs::Permissions::from_mode(0o1777)).unwrap();
        std::fs::write(at("shared/planted"), "OLD").unwrap();
        std::os::unix::fs::chown(at("shared/planted"), None, Some(gid)).unwrap();
    };
    let mut checked = Vec::new();
    for leg in test_shells(dir.path(), APPLETS, Some(&bin)) {
        let label = leg.0;
        let (scripted, native) = (
            tempfile::tempdir_in(dir.path()).unwrap(),
            tempfile::tempdir_in(dir.path()).unwrap(),
        );
        fixture(scripted.path());
        fixture(native.path());
        for (name, attrs) in cases {
            let path = scripted.path().join(name);
            let script = format!(
                "umask {umask:03o}; {}",
                file_put_command(RunAs::Root, &path.to_string_lossy(), attrs, PutCheck::None)
            );
            let (stdin, _) = framed(&script, &sha512_hex(b"NEW"), b"NEW");
            let output = feed(&leg.1, leg.2.as_ref(), &stdin);
            assert!(output.status.success(), "{label}: {name}: {output:?}");
            native_put(
                &native.path().join(name).to_string_lossy(),
                LocalSource::Bytes(b"NEW".to_vec()),
                attrs,
            )
            .await
            .unwrap();
        }
        for name in [
            "kept",
            "setuid",
            "declared",
            "linked",
            "first",
            "second",
            "theirs/new",
            "shared/planted",
            "shared/new",
            "fresh",
            "victim",
        ] {
            assert_eq!(
                attrs_of(&scripted.path().join(name)),
                attrs_of(&native.path().join(name)),
                "{label}: {name}"
            );
        }
        checked.push(label);
    }
    eprintln!("native and scripted kept attributes checked under: {checked:?}");
}

/// Run [`MAKE_DIRS`] for `path` as root would (the stand-in `sudo`), under `umask 022`.
fn make_dirs(leg: &Leg, path: &Path) -> Output {
    let (_, shell, env_path) = leg;
    let script = format!(
        "umask 022; {}",
        make_dirs_command(RunAs::Root, &path.to_string_lossy())
    );
    let mut command = Command::new(shell);
    if let Some(env_path) = env_path {
        command.env("PATH", env_path);
    }
    command.args(["-c", &script]).output().unwrap()
}

/// The directory script makes what is missing and gives each directory it makes the
/// owner and group of the nearest one that was there (here a group of the test's that
/// isn't set-group-id, so `mkdir` alone wouldn't give it), at `mkdir`'s mode; with
/// nothing missing it changes nothing; a link to a directory above is followed; and
/// what isn't a directory, a link at the name, a relative path, and a missing `.`,
/// `..`, or empty component are refused with nothing made.
#[test]
fn the_directory_script_makes_what_is_missing_with_its_ancestors_owner_under_both_shells() {
    let (_, gid) = a_gid_of_mine();
    let me = nix::unistd::geteuid().as_raw();
    let dir = crate::test_scratch::tempdir();
    let bin = recording_bin(dir.path());
    let mut checked = Vec::new();
    for leg in test_shells(dir.path(), APPLETS, Some(&bin)) {
        let label = leg.0;
        let case = tempfile::tempdir_in(dir.path()).unwrap();
        let at = |name: &str| case.path().join(name);
        std::fs::create_dir(at("base")).unwrap();
        std::os::unix::fs::chown(at("base"), None, Some(gid)).unwrap();
        std::fs::set_permissions(at("base"), std::fs::Permissions::from_mode(0o750)).unwrap();
        let _ = chown_calls(&bin);

        let output = make_dirs(&leg, &at("base/it's a/-rf b/c/"));
        assert!(output.status.success(), "{label}: {output:?}");
        for made in ["base/it's a", "base/it's a/-rf b", "base/it's a/-rf b/c"] {
            assert_eq!(attrs_of(&at(made)), (0o755, me, gid), "{label}: {made}");
        }
        assert_eq!(
            chown_calls(&bin),
            vec![format!("-- {me}:{gid} /proc/self/fd/3"); 3],
            "{label}: one change per directory made, through its descriptor"
        );

        // Nothing missing: nothing changed, nothing run.
        let output = make_dirs(&leg, &at("base/it's a"));
        assert!(output.status.success(), "{label}: {output:?}");
        assert_eq!(chown_calls(&bin), Vec::<String>::new(), "{label}");
        assert_eq!(attrs_of(&at("base")), (0o750, me, gid), "{label}");

        // A link to a directory above what is missing is followed.
        symlink(at("base"), at("alias")).unwrap();
        let output = make_dirs(&leg, &at("alias/through"));
        assert!(output.status.success(), "{label}: {output:?}");
        assert_eq!(attrs_of(&at("base/through")), (0o755, me, gid), "{label}");
        let _ = chown_calls(&bin);

        // Refused, nothing made.
        std::fs::write(at("file"), "").unwrap();
        symlink(at("nowhere"), at("dangling")).unwrap();
        let before = entries(case.path());
        for (refused, says) in [
            (at("file"), "not a directory"),
            (at("file/sub"), "not a directory"),
            (at("dangling"), "not a directory"),
            (at("dangling/sub"), "not a directory"),
            (at("new/../x"), "not a name to make"),
            (at("new/./x"), "not a name to make"),
            (at("new//x"), "not a name to make"),
            (PathBuf::from("relative/x"), "not an absolute path"),
        ] {
            let output = make_dirs(&leg, &refused);
            assert_eq!(
                output.status.code(),
                Some(REFUSED_EXIT),
                "{label}: {refused:?}: {output:?}"
            );
            assert!(
                stderr(&output).contains(says),
                "{label}: {refused:?}: {output:?}"
            );
            assert_eq!(entries(case.path()), before, "{label}: {refused:?}");
        }
        assert!(!at("nowhere").exists(), "{label}");
        assert_eq!(chown_calls(&bin), Vec::<String>::new(), "{label}");
        checked.push(label);
    }
    eprintln!("directory script checked under: {checked:?}");
}

/// A directory the script made, swapped for a link to another directory before it is
/// opened (a `mkdir` stand-in does it), is refused: nothing is made where the link
/// leads, and its owner isn't changed.
#[test]
fn a_swapped_component_takes_nothing_through_it_under_both_shells() {
    let dir = crate::test_scratch::tempdir();
    let bin = recording_bin(dir.path());
    let mut checked = Vec::new();
    for (label, shell, env_path) in test_shells(dir.path(), APPLETS, Some(&bin)) {
        let case = tempfile::tempdir_in(dir.path()).unwrap();
        let at = |name: &str| case.path().join(name);
        std::fs::create_dir(at("victim")).unwrap();
        std::fs::set_permissions(at("victim"), std::fs::Permissions::from_mode(0o700)).unwrap();
        let victim = attrs_of(&at("victim"));
        let real = on_path(env_path.as_ref(), "mkdir");
        let lead = tempfile::tempdir_in(dir.path()).unwrap();
        executable(
            &lead.path().join("mkdir"),
            &format!(
                "{} \"$@\" && mv \"$2\" \"$2.moved\" && ln -s {} \"$2\"",
                single_quote(&real.to_string_lossy()),
                single_quote(&at("victim").to_string_lossy())
            ),
        );
        let _ = chown_calls(&bin);
        let script = make_dirs_command(RunAs::Root, &at("made/deeper").to_string_lossy());
        let output = Command::new(&shell)
            .env("PATH", led_by(lead.path(), env_path.as_ref()))
            .args(["-c", &script])
            .output()
            .unwrap();
        assert_eq!(
            output.status.code(),
            Some(REFUSED_EXIT),
            "{label}: {output:?}"
        );
        assert!(
            stderr(&output).contains("made is not a directory of its own"),
            "{label}: {output:?}"
        );
        assert!(
            entries(&at("victim")).is_empty(),
            "{label}: nothing through it"
        );
        assert_eq!(attrs_of(&at("victim")), victim, "{label}");
        assert_eq!(chown_calls(&bin), Vec::<String>::new(), "{label}");
        checked.push(label);
    }
    eprintln!("swapped component checked under: {checked:?}");
}

/// A directory of the cwd owner's renamed over the one just made, before the script
/// opens it (a `mkdir` stand-in does it, `mv -T`), passes the same-inode check — so,
/// as root (`fakeroot`'s), it is held to being the empty directory the script made: one
/// the caller doesn't own, or one with something in it, is refused with no owner given
/// and nothing made inside it; so is one whose listing fails, said as such. Unmoved,
/// the same call gives each its owner.
#[test]
fn as_root_a_directory_renamed_over_the_one_made_is_given_no_owner_under_both_shells() {
    let Some(fakeroot) = super::extract::fakeroot() else {
        eprintln!("a renamed-over directory not checked: no working fakeroot");
        return;
    };
    let dir = crate::test_scratch::tempdir();
    let bin = stand_in_bin(dir.path());
    let mut checked = Vec::new();
    for leg in test_shells(dir.path(), APPLETS, Some(&bin)) {
        let label = leg.0;
        let real_mkdir = on_path(leg.2.as_ref(), "mkdir");
        let real_mv = on_path(leg.2.as_ref(), "mv");
        let lead = tempfile::tempdir_in(dir.path()).unwrap();
        // Renames `./victim`, when there, over what was just made.
        executable(
            &lead.path().join("mkdir"),
            &format!(
                "{} \"$@\" || exit; [ ! -d ./victim ] || {} -T ./victim \"$2\"",
                single_quote(&real_mkdir.to_string_lossy()),
                single_quote(&real_mv.to_string_lossy()),
            ),
        );
        let led = (
            label,
            leg.1.clone(),
            Some(led_by(lead.path(), leg.2.as_ref())),
        );
        for (name, victim) in [
            ("not ours", "theirs"),
            ("not empty", "inside"),
            ("unmoved", ""),
        ] {
            let case = tempfile::tempdir_in(dir.path()).unwrap();
            let theirs = case.path().join("theirs");
            let quoted = single_quote(&theirs.to_string_lossy());
            std::fs::create_dir(&theirs).unwrap();
            // An empty directory another account owns, or one of root's with something in.
            let plant = match victim {
                "theirs" => format!("mkdir {quoted}/victim && chown 4321:8765 {quoted}/victim && "),
                "inside" => format!("mkdir {quoted}/victim && echo x > {quoted}/victim/kept && "),
                _ => String::new(),
            };
            let script = format!(
                "umask 022; chown 1234:5678 {quoted} && {plant}{}; echo \"exit=$?\"; \
                 cd {quoted} && stat -c '%n %u:%g' a && ls -A a",
                make_dirs_command(RunAs::Root, &theirs.join("a/b").to_string_lossy())
            );
            let output = super::extract::run_as_fake_root(&fakeroot, &led, &script);
            let out = String::from_utf8_lossy(&output.stdout);
            assert!(output.status.success(), "{label} {name}: {output:?}");
            let expected = match victim {
                "theirs" => format!("exit={REFUSED_EXIT}\na 4321:8765\n"),
                "inside" => format!("exit={REFUSED_EXIT}\na 0:0\nkept\n"),
                _ => "exit=0\na 1234:5678\nb\n".to_owned(),
            };
            assert_eq!(
                out, expected,
                "{label} {name}: no owner given, nothing made in it"
            );
            if !victim.is_empty() {
                assert!(
                    stderr(&output).contains("a is not the empty directory just made"),
                    "{label} {name}: {output:?}"
                );
            }
        }
        // A listing that fails (an `ls` stand-in) gives nothing either, and the refusal
        // says the listing failed.
        let case = tempfile::tempdir_in(dir.path()).unwrap();
        let theirs = case.path().join("theirs");
        let quoted = single_quote(&theirs.to_string_lossy());
        std::fs::create_dir(&theirs).unwrap();
        let lead = tempfile::tempdir_in(dir.path()).unwrap();
        executable(
            &lead.path().join("ls"),
            "echo 'ls: cannot open' >&2; exit 2",
        );
        let led = (
            label,
            leg.1.clone(),
            Some(led_by(lead.path(), leg.2.as_ref())),
        );
        let script = format!(
            "umask 022; chown 1234:5678 {quoted} && {}; echo \"exit=$?\"; \
             cd {quoted} && stat -c '%n %u:%g' a",
            make_dirs_command(RunAs::Root, &theirs.join("a/b").to_string_lossy())
        );
        let output = super::extract::run_as_fake_root(&fakeroot, &led, &script);
        assert!(output.status.success(), "{label} unlisted: {output:?}");
        assert_eq!(
            String::from_utf8_lossy(&output.stdout),
            format!("exit={REFUSED_EXIT}\na 0:0\n"),
            "{label} unlisted: no owner given, nothing made in it"
        );
        assert!(
            stderr(&output).contains("a could not be listed, so it is given no owner"),
            "{label} unlisted: {output:?}"
        );
        checked.push(label);
    }
    eprintln!("renamed-over directory checked under: {checked:?}");
}

/// Anywhere below a directory with its sticky bit set or that every account may write,
/// the directories made are the caller's: no owner is given any of them — not the shared
/// directory's child, not one below a directory of another's inside it (an attacker's
/// `/tmp/cache`) — as root (`fakeroot`'s) over another account's `/tmp`-like directory
/// too.
#[test]
fn below_a_directory_anyone_may_write_the_directories_made_are_the_callers_under_both_shells() {
    let (_, gid) = a_gid_of_mine();
    let me = (
        nix::unistd::geteuid().as_raw(),
        nix::unistd::getegid().as_raw(),
    );
    let dir = crate::test_scratch::tempdir();
    let bin = recording_bin(dir.path());
    let fakeroot = super::extract::fakeroot();
    let mut checked = Vec::new();
    for leg in test_shells(dir.path(), APPLETS, Some(&bin)) {
        let label = leg.0;
        let case = tempfile::tempdir_in(dir.path()).unwrap();
        for (shared, mode) in [("sticky", 0o1777), ("open", 0o777)] {
            let at = case.path().join(shared);
            std::fs::create_dir(&at).unwrap();
            std::os::unix::fs::chown(&at, None, Some(gid)).unwrap();
            std::fs::set_permissions(&at, std::fs::Permissions::from_mode(mode)).unwrap();
            // A directory of another's group inside it, not itself open to anyone.
            let cache = at.join("cache");
            std::fs::create_dir(&cache).unwrap();
            std::os::unix::fs::chown(&cache, None, Some(gid)).unwrap();
            std::fs::set_permissions(&cache, std::fs::Permissions::from_mode(0o755)).unwrap();
            for below in [at.join("a/b"), cache.join("a/b")] {
                let _ = chown_calls(&bin);
                let output = make_dirs(&leg, &below);
                assert!(output.status.success(), "{label} {below:?}: {output:?}");
                for made in [below.parent().unwrap(), below.as_path()] {
                    assert_eq!(
                        attrs_of(made),
                        (0o755, me.0, me.1),
                        "{label} {made:?}: the caller's"
                    );
                }
                assert_eq!(
                    chown_calls(&bin),
                    Vec::<String>::new(),
                    "{label} {below:?}: no owner given below it"
                );
            }
        }
        if let Some(fakeroot) = &fakeroot {
            let shared = case.path().join("root-shared");
            let quoted = single_quote(&shared.to_string_lossy());
            let script = format!(
                "umask 022; mkdir {quoted} {quoted}/cache && chown 1234:5678 {quoted} {quoted}/cache && \
                 chmod 1777 {quoted} && {} && {} && cd {quoted} && stat -c '%n %u:%g' a a/b cache/a",
                make_dirs_command(RunAs::Root, &shared.join("a/b").to_string_lossy()),
                make_dirs_command(RunAs::Root, &shared.join("cache/a").to_string_lossy())
            );
            let output = super::extract::run_as_fake_root(fakeroot, &leg, &script);
            assert!(output.status.success(), "{label}: {output:?}");
            assert_eq!(
                String::from_utf8_lossy(&output.stdout),
                "a 0:0\na/b 0:0\ncache/a 0:0\n",
                "{label}: root's, not the sticky directory's owner's nor its child's"
            );
        }
        checked.push(label);
    }
    eprintln!("directories below a shared one checked under: {checked:?}");
}

/// A link planted in a shared directory passes on nothing: with `cache` in a directory
/// with its sticky bit set, or one every account may write, a link to a directory open
/// to no one (an attacker's own, here one of another group's), a kept put through it
/// keeps neither the mode nor the group of the file there, and the directories made
/// through it are given no owner. The walk up from where the link leads never passes
/// the shared directory; the path as declared does. The same link in a directory of the
/// caller's own passes both on.
#[test]
fn a_link_planted_in_a_shared_directory_passes_on_nothing_under_both_shells() {
    let (_, gid) = a_gid_of_mine();
    let me = (
        nix::unistd::geteuid().as_raw(),
        nix::unistd::getegid().as_raw(),
    );
    let dir = crate::test_scratch::tempdir();
    let bin = recording_bin(dir.path());
    let mut checked = Vec::new();
    for leg in test_shells(dir.path(), APPLETS, Some(&bin)) {
        let label = leg.0;
        let case = tempfile::tempdir_in(dir.path()).unwrap();
        let theirs = case.path().join("theirs");
        std::fs::create_dir(&theirs).unwrap();
        std::os::unix::fs::chown(&theirs, None, Some(gid)).unwrap();
        std::fs::set_permissions(&theirs, std::fs::Permissions::from_mode(0o755)).unwrap();
        for (holder, mode, passes) in [
            ("sticky", 0o1777, false),
            ("open", 0o777, false),
            ("own", 0o755, true),
        ] {
            let at = case.path().join(holder);
            std::fs::create_dir(&at).unwrap();
            std::fs::set_permissions(&at, std::fs::Permissions::from_mode(mode)).unwrap();
            symlink(&theirs, at.join("cache")).unwrap();
            let planted = theirs.join("planted");
            std::fs::write(&planted, "OLD").unwrap();
            std::os::unix::fs::chown(&planted, None, Some(gid)).unwrap();
            std::fs::set_permissions(&planted, std::fs::Permissions::from_mode(0o640)).unwrap();
            let _ = chown_calls(&bin);

            let script = format!(
                "umask 022; {}",
                file_put_command(
                    RunAs::Root,
                    &at.join("cache/planted").to_string_lossy(),
                    FileAttrs::NONE.keeping(),
                    PutCheck::None
                )
            );
            let (stdin, _) = framed(&script, &sha512_hex(b"NEW"), b"NEW");
            let output = feed(&leg.1, leg.2.as_ref(), &stdin);
            assert!(output.status.success(), "{label} {holder}: {output:?}");
            assert_eq!(std::fs::read(&planted).unwrap(), b"NEW", "{label} {holder}");
            if passes {
                assert_eq!(attrs_of(&planted), (0o640, me.0, gid), "{label} {holder}");
                assert_eq!(
                    chown_calls(&bin),
                    [format!("-- {}:{gid} /proc/self/fd/3", me.0)],
                    "{label} {holder}"
                );
            } else {
                assert_eq!(
                    attrs_of(&planted),
                    (0o644, me.0, me.1),
                    "{label} {holder}: the writer's, fresh"
                );
                assert_eq!(chown_calls(&bin), Vec::<String>::new(), "{label} {holder}");
            }

            let made = at.join("cache").join(holder).join("b");
            let output = make_dirs(&leg, &made);
            assert!(output.status.success(), "{label} {holder}: {output:?}");
            let group = if passes { gid } else { me.1 };
            for made in [theirs.join(holder), theirs.join(holder).join("b")] {
                assert_eq!(
                    attrs_of(&made),
                    (0o755, me.0, group),
                    "{label} {holder}: {made:?}"
                );
            }
            assert_eq!(
                chown_calls(&bin).len(),
                if passes { 2 } else { 0 },
                "{label} {holder}: owners given through the link"
            );
        }
        checked.push(label);
    }
    eprintln!("a link planted in a shared directory checked under: {checked:?}");
}

/// As root (`fakeroot`'s), the directories made take another account's owner and
/// group from the nearest one that was there.
#[test]
fn as_root_the_directories_made_take_another_accounts_owner_under_both_shells() {
    let Some(fakeroot) = super::extract::fakeroot() else {
        eprintln!("another account's directories not checked: no working fakeroot");
        return;
    };
    let dir = crate::test_scratch::tempdir();
    let bin = stand_in_bin(dir.path());
    let mut checked = Vec::new();
    for leg in test_shells(dir.path(), APPLETS, Some(&bin)) {
        let label = leg.0;
        let case = tempfile::tempdir_in(dir.path()).unwrap();
        let theirs = case.path().join("theirs");
        let quoted = single_quote(&theirs.to_string_lossy());
        let script = format!(
            "umask 022; mkdir {quoted} && chown 1234:5678 {quoted} && {} && \
             cd {quoted} && stat -c '%n %u:%g %a' a a/b",
            make_dirs_command(RunAs::Root, &theirs.join("a/b").to_string_lossy())
        );
        let output = super::extract::run_as_fake_root(&fakeroot, &leg, &script);
        assert!(output.status.success(), "{label}: {output:?}");
        assert_eq!(
            String::from_utf8_lossy(&output.stdout),
            "a 1234:5678 755\na/b 1234:5678 755\n",
            "{label}"
        );
        checked.push(label);
    }
    eprintln!("another account's directories checked under: {checked:?}");
}

/// The native form and the script make the same directories with the same mode,
/// owner, and group, and agree on what they refuse. A `..` in what is there is followed,
/// as `mkdir -p` follows it; one in what is missing is refused.
#[tokio::test]
async fn the_native_and_scripted_directories_agree_under_both_shells() {
    use crate::connection::local_put::make_dirs as native_dirs;

    let (_, gid) = a_gid_of_mine();
    let dir = crate::test_scratch::tempdir();
    let bin = stand_in_bin(dir.path());
    std::fs::create_dir(dir.path().join("probe")).unwrap();
    let umask = 0o777 & !mode_of(&dir.path().join("probe"));
    let fixture = |root: &Path| {
        std::fs::create_dir(root.join("base")).unwrap();
        std::os::unix::fs::chown(root.join("base"), None, Some(gid)).unwrap();
        symlink(root.join("base"), root.join("alias")).unwrap();
        std::fs::write(root.join("file"), "").unwrap();
        std::fs::create_dir(root.join("shared")).unwrap();
        std::os::unix::fs::chown(root.join("shared"), None, Some(gid)).unwrap();
        std::fs::set_permissions(root.join("shared"), std::fs::Permissions::from_mode(0o1777))
            .unwrap();
    };
    let mut checked = Vec::new();
    for leg in test_shells(dir.path(), APPLETS, Some(&bin)) {
        let label = leg.0;
        let (scripted, native) = (
            tempfile::tempdir_in(dir.path()).unwrap(),
            tempfile::tempdir_in(dir.path()).unwrap(),
        );
        fixture(scripted.path());
        fixture(native.path());
        for (name, ok) in [
            ("base/a/b", true),
            ("alias/c/d", true),
            ("base", true),
            ("file/x", false),
            ("base/../y", true),
            ("gone/../z", false),
            ("shared/e/f", true),
        ] {
            let script = format!(
                "umask {umask:03o}; {}",
                make_dirs_command(RunAs::Root, &scripted.path().join(name).to_string_lossy())
            );
            let output = Command::new(&leg.1)
                .envs(leg.2.as_ref().map(|path| ("PATH", path)))
                .args(["-c", &script])
                .output()
                .unwrap();
            let made = native_dirs(&native.path().join(name).to_string_lossy()).await;
            assert_eq!(output.status.success(), ok, "{label}: {name}: {output:?}");
            assert_eq!(made.is_ok(), ok, "{label}: {name}: {made:?}");
        }
        for name in [
            "base",
            "base/a",
            "base/a/b",
            "base/c",
            "base/c/d",
            "y",
            "shared/e",
            "shared/e/f",
        ] {
            assert_eq!(
                attrs_of(&scripted.path().join(name)),
                attrs_of(&native.path().join(name)),
                "{label}: {name}"
            );
        }
        assert_eq!(entries(scripted.path()), entries(native.path()), "{label}");
        checked.push(label);
    }
    eprintln!("native and scripted directories checked under: {checked:?}");
}

/// A `link` is made under a fresh name beside its path and renamed over it: a link at
/// the path is replaced, a link to a directory included and with a link to a file
/// (which `BusyBox` `mv -T` won't rename over), and nothing of the fresh name is left. A
/// real directory at the path is refused, and so is one put there after the check: the
/// rename refuses it, where `ln -sfn` would make the link inside it and exit 0.
#[test]
fn a_link_put_renames_over_the_path_and_never_links_into_a_directory_under_both_shells() {
    let dir = crate::test_scratch::tempdir();
    let mut checked = Vec::new();
    for leg in test_shells(
        dir.path(),
        &["mktemp", "rm", "rmdir", "ln", "mv", "mkdir"],
        None,
    ) {
        let (label, shell, env_path) = &leg;
        let case = tempfile::tempdir_in(dir.path()).unwrap();
        let at = |name: &str| case.path().join(name);
        std::fs::create_dir(at("d1")).unwrap();
        std::fs::create_dir(at("d2")).unwrap();
        std::fs::write(at("f1"), "f").unwrap();
        std::fs::create_dir(at("w")).unwrap();
        let path = at("w").join("l");
        let link_put = |target: &Path, env_path: Option<&OsString>| {
            let mut command = Command::new(shell);
            if let Some(env_path) = env_path {
                command.env("PATH", env_path);
            }
            command
                .args([
                    "-c",
                    &zap_types::put::link_put_command(
                        "",
                        &path.to_string_lossy(),
                        &target.to_string_lossy(),
                    ),
                ])
                .output()
                .unwrap()
        };
        let points_at = || std::fs::read_link(&path).ok();

        for target in [at("d1"), at("d2"), at("f1"), at("d1"), at("nowhere")] {
            let output = link_put(&target, env_path.as_ref());
            assert!(output.status.success(), "{label}: {output:?}");
            assert_eq!(points_at(), Some(target), "{label}");
            assert_eq!(
                entries(&at("w")),
                ["l"],
                "{label}: nothing of the fresh name"
            );
        }

        std::fs::remove_file(&path).unwrap();
        std::fs::create_dir(&path).unwrap();
        let output = link_put(&at("d1"), env_path.as_ref());
        assert!(!output.status.success(), "{label}: {output:?}");
        assert!(
            stderr(&output).contains("is a directory, not a link"),
            "{label}"
        );
        assert!(entries(&path).is_empty(), "{label}: nothing linked into it");
        assert_eq!(entries(&at("w")), ["l"], "{label}");

        // A directory put at the path after the check: an `ln` that makes it first.
        std::fs::remove_dir(&path).unwrap();
        let lead = tempfile::tempdir_in(dir.path()).unwrap();
        executable(
            &lead.path().join("ln"),
            &format!(
                "mkdir -- {} && exec {} \"$@\"",
                single_quote(&path.to_string_lossy()),
                single_quote(&on_path(env_path.as_ref(), "ln").to_string_lossy())
            ),
        );
        let output = link_put(&at("d1"), Some(&led_by(lead.path(), env_path.as_ref())));
        assert!(!output.status.success(), "{label}: {output:?}");
        assert!(
            stderr(&output).contains("is a directory, not a link"),
            "{label}"
        );
        assert!(
            path.is_dir() && entries(&path).is_empty(),
            "{label}: {:?}",
            entries(&path)
        );
        assert_eq!(
            entries(&at("w")),
            ["l"],
            "{label}: nothing of the fresh name"
        );
        checked.push(*label);
    }
    assert!(checked.contains(&"sh"), "{checked:?}");
}
