//! The plan steps that install a root-owned file whole through the put — an
//! `apt_repo`'s sources list and a `swap`'s `/etc/fstab` entry, fed from a command on
//! the target (`zap_types::put::put_text_step`), and the nftables ruleset, whose text
//! the plan holds — and the check a `swap` file's creation runs first, run for real: what the planner's own step runs, under the system
//! `sh` and under `BusyBox` with only its applets on `PATH` (when installed), with a
//! stand-in `sudo`. The ruleset and the table live under `/etc`, so each step is run
//! with that one path renamed into the test's directory.

use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _, symlink};
use std::path::Path;
use std::process::{Command, Output};

use zap_types::schema::{apt_source_command, inject_signed_by, table_lists_path};

use super::put::{Leg, Ran, absent_run_steps, entries, mode_of, printf_lines, stand_in_bin};
use super::support::test_shells;

/// The applets the steps run, beyond the batch's.
const APPLETS: &[&str] = &[
    "mktemp", "rm", "chown", "chmod", "sync", "mv", "awk", "grep", "id", "ls", "test", "mkdir",
    "ln",
];

fn run(leg: &Leg, step: &str) -> Output {
    let (_, shell, env_path) = leg;
    let mut command = Command::new(shell);
    if let Some(path) = env_path {
        command.env("PATH", path);
    }
    command.args(["-c", step]).output().unwrap()
}

/// `step` as the executor runs it.
fn run_step(leg: &Leg, step: &Ran) -> Output {
    let (_, shell, env_path) = leg;
    step.run(shell, env_path.as_ref())
}

/// `step` under a file-size limit of one block (512 bytes), standing in for a full
/// disk: a write past it fails instead of ending the shell.
fn run_short(leg: &Leg, step: &Ran) -> Output {
    run_step(
        leg,
        &step.with_text(|text| format!("trap '' XFSZ; ulimit -f 1; {text}")),
    )
}

/// The one step among `steps` naming `path`, with it renamed to `to`.
fn moved(steps: &[Ran], path: &str, to: &Path) -> Ran {
    let naming: Vec<&Ran> = steps
        .iter()
        .filter(|step| step.text.contains(path))
        .collect();
    let [step] = naming.as_slice() else {
        panic!("one step names {path}: {steps:?}");
    };
    step.with_text(|text| text.replace(path, &to.to_string_lossy()))
}

/// The nftables ruleset step installs the ruleset whole at mode `600`, as a new file
/// renamed into place: a link at the path is replaced, not written through, and a write
/// that fails partway leaves the ruleset that was there.
#[test]
fn the_nftables_ruleset_is_installed_whole_under_both_shells() {
    let dir = tempfile::tempdir().unwrap();
    let bin = stand_in_bin(dir.path());
    let steps = absent_run_steps(serde_json::json!({
        "id": "fw", "type": "firewall", "backend": "nftables",
        "allow": [{"port": 22, "proto": "tcp"}, {"port": 443, "proto": "tcp"}],
    }));
    let mut checked = Vec::new();
    for leg in test_shells(dir.path(), APPLETS, Some(&bin)) {
        let label = leg.0;
        let case = tempfile::tempdir_in(dir.path()).unwrap();
        let ruleset = case.path().join("nftables.nft");
        let step = moved(&steps[..1], "/etc/nftables.nft", &ruleset);

        let output = run_step(&leg, &step);
        assert!(output.status.success(), "{label}: {output:?}");
        let installed = std::fs::read_to_string(&ruleset).unwrap();
        // The text is the plan's own, sent with its digest — the bytes a `printf` of
        // the ruleset prints: the ruleset and one more newline.
        assert_eq!(step.content(), Some(installed.as_bytes()), "{label}");
        assert_eq!(
            printf_lines(
                &leg.1,
                leg.2.as_ref(),
                &[installed.strip_suffix('\n').unwrap()]
            ),
            installed.as_bytes(),
            "{label}"
        );
        assert!(
            installed.starts_with("#!/usr/sbin/nft -f\n"),
            "{label}: {installed}"
        );
        assert!(installed.contains("tcp dport 443 accept\n"), "{label}");
        assert!(installed.ends_with("}\n\n"), "{label}: {installed:?}");
        assert!(
            installed.len() > 512,
            "the short write below needs a ruleset past one block"
        );
        assert_eq!(mode_of(&ruleset), 0o600, "{label}");
        assert_eq!(entries(case.path()), ["nftables.nft"], "{label}");

        // Again: a new file each time, never a write into the old one.
        let before = std::fs::metadata(&ruleset).unwrap().ino();
        let output = run_step(&leg, &step);
        assert!(output.status.success(), "{label}: {output:?}");
        assert_ne!(
            std::fs::metadata(&ruleset).unwrap().ino(),
            before,
            "{label}"
        );

        // A write that fails partway: the old ruleset stays, whole, and no stage is left.
        std::fs::write(&ruleset, "OLD RULESET\n").unwrap();
        let output = run_short(&leg, &step);
        assert!(!output.status.success(), "{label}: {output:?}");
        assert_eq!(
            std::fs::read_to_string(&ruleset).unwrap(),
            "OLD RULESET\n",
            "{label}"
        );
        assert_eq!(entries(case.path()), ["nftables.nft"], "{label}");

        // A link at the path is replaced; what it named is untouched.
        std::fs::remove_file(&ruleset).unwrap();
        let victim = case.path().join("victim");
        std::fs::write(&victim, "ORIGINAL").unwrap();
        symlink(&victim, &ruleset).unwrap();
        let output = run_step(&leg, &step);
        assert!(output.status.success(), "{label}: {output:?}");
        assert!(
            std::fs::symlink_metadata(&ruleset).unwrap().is_file(),
            "{label}"
        );
        assert_eq!(std::fs::read(&victim).unwrap(), b"ORIGINAL", "{label}");
        checked.push(label);
    }
    eprintln!("nftables ruleset step checked under: {checked:?}");
}

/// The `apt_repo` list step installs exactly the line the detector's probe prints —
/// `/etc/os-release` resolved the same way — at mode `644`, replacing a list that was
/// there rather than writing into it.
#[test]
fn the_apt_list_is_the_probes_line_installed_whole_under_both_shells() {
    if !Path::new("/etc/os-release").is_file() {
        eprintln!("apt list step not checked: no /etc/os-release to resolve a source with");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let bin = stand_in_bin(dir.path());
    let mut checked = Vec::new();
    for leg in test_shells(dir.path(), APPLETS, Some(&bin)) {
        let label = leg.0;
        let case = tempfile::tempdir_in(dir.path()).unwrap();
        let list = case.path().join("it's a repo.list");
        let key = case.path().join("key.asc");
        let source = "deb https://example.invalid/apt $ID-$VERSION_CODENAME main";
        let steps = absent_run_steps(serde_json::json!({
            "id": "repo", "type": "apt_repo",
            "key_url": "https://example.invalid/key.asc",
            "source": source,
            "key_path": key.to_string_lossy(),
            "list_file": list.to_string_lossy(),
        }));
        let step = moved(&steps, "repo.list", Path::new("repo.list"));

        std::fs::write(&list, "deb https://old.invalid/apt stale main\n").unwrap();
        std::fs::set_permissions(&list, std::fs::Permissions::from_mode(0o600)).unwrap();
        let before = std::fs::metadata(&list).unwrap().ino();
        let output = run_step(&leg, &step);
        assert!(output.status.success(), "{label}: {output:?}");
        let probe = run(
            &leg,
            &apt_source_command(&inject_signed_by(source, &key.to_string_lossy())),
        );
        assert!(probe.status.success(), "{label}: {probe:?}");
        let installed = std::fs::read(&list).unwrap();
        assert_eq!(installed, probe.stdout, "{label}: the probe's line");
        assert!(
            String::from_utf8_lossy(&installed).starts_with("deb [signed-by="),
            "{label}"
        );
        assert!(
            !String::from_utf8_lossy(&installed).contains('$'),
            "{label}: the codename resolved"
        );
        assert_eq!(mode_of(&list), 0o644, "{label}");
        assert_ne!(std::fs::metadata(&list).unwrap().ino(), before, "{label}");
        assert_eq!(entries(case.path()), ["it's a repo.list"], "{label}");
        checked.push(label);
    }
    eprintln!("apt list step checked under: {checked:?}");
}

/// The `swap` fstab step adds its entry by installing a new table: on a line of its
/// own even after a last line with no newline, once (the detector's guard then finds
/// it, and a second run changes nothing), at the mode the table had — `644` for a
/// table that didn't exist. A table that can't be read, one with an access list (whose
/// mode can't be kept), and a write that fails partway, leave the table as it was.
#[test]
fn the_fstab_entry_is_added_by_installing_a_new_table_under_both_shells() {
    let dir = tempfile::tempdir().unwrap();
    let bin = stand_in_bin(dir.path());
    let steps = absent_run_steps(serde_json::json!({
        "id": "swap", "type": "swap", "size": "1G", "path": "/swapfile",
    }));
    let entry = "/swapfile none swap sw 0 0\n";
    let mut checked = Vec::new();
    for leg in test_shells(dir.path(), APPLETS, Some(&bin)) {
        let label = leg.0;
        let case = tempfile::tempdir_in(dir.path()).unwrap();
        let table = case.path().join("fstab");
        let step = moved(&steps, "/etc/fstab", &table);
        let listed = || {
            run(
                &leg,
                &table_lists_path(&table.to_string_lossy(), "/swapfile"),
            )
            .status
            .success()
        };

        // A last line with no newline: the entry gets a line of its own.
        let existing = "# static file system information\nUUID=abc / ext4 errors=remount-ro 0 1";
        std::fs::write(&table, existing).unwrap();
        std::fs::set_permissions(&table, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(!listed(), "{label}");
        let before = std::fs::metadata(&table).unwrap().ino();
        let output = run_step(&leg, &step);
        assert!(output.status.success(), "{label}: {output:?}");
        assert_eq!(
            std::fs::read_to_string(&table).unwrap(),
            format!("{existing}\n{entry}"),
            "{label}"
        );
        assert_eq!(mode_of(&table), 0o600, "{label}: the table keeps its mode");
        assert_ne!(
            std::fs::metadata(&table).unwrap().ino(),
            before,
            "{label}: a new table renamed into place, not an append"
        );
        assert!(listed(), "{label}: the detector's read finds the entry");
        assert_eq!(entries(case.path()), ["fstab"], "{label}");

        // Listed: the guard stops the step, and the table is the same file.
        let before = std::fs::metadata(&table).unwrap().ino();
        let output = run_step(&leg, &step);
        assert!(output.status.success(), "{label}: {output:?}");
        assert_eq!(std::fs::metadata(&table).unwrap().ino(), before, "{label}");
        assert_eq!(
            std::fs::read_to_string(&table).unwrap(),
            format!("{existing}\n{entry}"),
            "{label}"
        );

        // No table: one is made, holding the entry.
        std::fs::remove_file(&table).unwrap();
        let output = run_step(&leg, &step);
        assert!(output.status.success(), "{label}: {output:?}");
        assert_eq!(std::fs::read_to_string(&table).unwrap(), entry, "{label}");
        assert_eq!(mode_of(&table), 0o644, "{label}: a new table's mode");

        // Behind a link, the mode kept is the table's, not the link's own.
        std::fs::remove_file(&table).unwrap();
        let behind = case.path().join("behind");
        std::fs::write(&behind, existing).unwrap();
        std::fs::set_permissions(&behind, std::fs::Permissions::from_mode(0o640)).unwrap();
        symlink(&behind, &table).unwrap();
        let output = run_step(&leg, &step);
        assert!(output.status.success(), "{label}: {output:?}");
        assert_eq!(mode_of(&table), 0o640, "{label}");
        std::fs::remove_file(&behind).unwrap();

        // A write that fails partway leaves the table as it was — past one block, so
        // the table fits the limit only without the entry's rewrite.
        let mut full = String::new();
        while full.len() + entry.len() <= 512 {
            full.push_str("UUID=0123 /mnt/data ext4 defaults 0 2\n");
        }
        std::fs::write(&table, &full).unwrap();
        let output = run_short(&leg, &step);
        assert!(!output.status.success(), "{label}: {output:?}");
        assert_eq!(std::fs::read_to_string(&table).unwrap(), full, "{label}");
        assert_eq!(entries(case.path()), ["fstab"], "{label}");

        // A table with an access list is refused with nothing written: the mode it
        // shows is the list's mask, which the new table would hand its group. Seen
        // through `getfacl`, so not with `BusyBox`'s applets alone.
        std::fs::write(&table, existing).unwrap();
        std::fs::set_permissions(&table, std::fs::Permissions::from_mode(0o640)).unwrap();
        match super::put::give_access_list(&table) {
            true if label != "busybox" => {
                let before = std::fs::metadata(&table).unwrap().ino();
                let output = run_step(&leg, &step);
                assert_eq!(
                    output.status.code(),
                    Some(zap_types::put::REFUSED_EXIT),
                    "{label}: {output:?}"
                );
                assert!(
                    String::from_utf8_lossy(&output.stderr).contains("has an access list (ACL)"),
                    "{label}: {output:?}"
                );
                assert_eq!(std::fs::metadata(&table).unwrap().ino(), before, "{label}");
                assert_eq!(
                    std::fs::read_to_string(&table).unwrap(),
                    existing,
                    "{label}"
                );
                assert_eq!(entries(case.path()), ["fstab"], "{label}");
            }
            true => {}
            false => eprintln!("{label}: a table with an access list not checked: no setfacl"),
        }
        std::fs::remove_file(&table).unwrap();

        // A table that can't be read fails the step with nothing written. Root reads
        // anything, so only an unprivileged run can see this one.
        std::fs::write(&table, existing).unwrap();
        std::fs::set_permissions(&table, std::fs::Permissions::from_mode(0o000)).unwrap();
        if std::fs::read(&table).is_err() {
            let before = std::fs::metadata(&table).unwrap().ino();
            let output = run_step(&leg, &step);
            assert!(!output.status.success(), "{label}: {output:?}");
            assert_eq!(std::fs::metadata(&table).unwrap().ino(), before, "{label}");
            assert_eq!(mode_of(&table), 0o000, "{label}");
            assert_eq!(entries(case.path()), ["fstab"], "{label}");
        }
        checked.push(label);
    }
    eprintln!("fstab step checked under: {checked:?}");
}

/// The root-owned home `useradd` leaves as it was is given to the user by the
/// creation's own step, as root (`fakeroot`'s): the directory itself, to the user and
/// its login group (`<name>:`, read by GNU and `BusyBox` `chown` alike), with nothing
/// under it changed; a link at the name is changed itself, and where it points is left
/// root's. The user is the test's own account, whose login group the passwd database
/// names, planned as an absent one.
#[test]
fn a_created_users_root_owned_home_is_given_to_it_and_its_login_group_under_both_shells() {
    use zap_types::detected::Detection;

    let Some(fakeroot) = super::extract::fakeroot() else {
        eprintln!("the home owner change not checked: no working fakeroot");
        return;
    };
    let me = nix::unistd::User::from_uid(nix::unistd::geteuid())
        .unwrap()
        .expect("the test's account is in the passwd database");
    let name = me.name.clone();
    let home = format!("/home/{name}");
    let resource: zap_types::schema::Resource = serde_json::from_value(serde_json::json!({
        "id": "u", "type": "user", "username": name, "home_mode": "750"
    }))
    .unwrap();
    let detected = std::collections::BTreeMap::from([(resource.id.clone(), Detection::Absent)]);
    let planned = zap_types::plan::diff(zap_types::plan::DiffInputs {
        resources: std::slice::from_ref(&resource),
        detected: &detected,
        target: &serde_json::from_value(serde_json::json!({"local": true})).unwrap(),
        machine: &crate::test_support::local_machine(),
        lock: None,
        pending: &std::collections::BTreeMap::new(),
        var: &zap_types::last_run::ReportVar::unset,
    });
    let steps: Vec<String> = planned.plan.changes[0]
        .steps
        .iter()
        .filter_map(zap_types::plan::PlanStep::execution)
        .map(|execution| execution.text().to_owned())
        .filter(|text| text.contains("chown"))
        .collect();
    let [step] = steps.as_slice() else {
        panic!("one owner change: {steps:?}");
    };
    assert_eq!(
        *step,
        format!(
            "sudo chown -h -- {} {}",
            zap_types::shell::single_quote(&format!("{name}:")),
            zap_types::shell::single_quote(&home)
        )
    );
    let want = format!("{}:{}", me.uid, me.gid);
    let dir = crate::test_scratch::tempdir();
    let bin = stand_in_bin(dir.path());
    let mut checked = Vec::new();
    for leg in test_shells(dir.path(), APPLETS, Some(&bin)) {
        let label = leg.0;
        let case = tempfile::tempdir_in(dir.path()).unwrap();
        let at = |name: &str| case.path().join(name).to_string_lossy().into_owned();
        let quoted = |name: &str| zap_types::shell::single_quote(&at(name));
        let on = |name: &str| step.replace(&zap_types::shell::single_quote(&home), &quoted(name));
        let script = format!(
            "mkdir {home} {home}/sub {target} && chown -R 0:0 {home} {target} && \
             ln -s {target} {link} && chown -h 0:0 {link} && {to_home} && {to_link} && \
             stat -c '%n %u:%g' {home} {home}/sub {target} && stat -c '%n %u:%g' -- {link}",
            home = quoted("home"),
            target = quoted("target"),
            link = quoted("link"),
            to_home = on("home"),
            to_link = on("link"),
        );
        let output = super::extract::run_as_fake_root(&fakeroot, &leg, &script);
        assert!(output.status.success(), "{label}: {output:?}");
        assert_eq!(
            String::from_utf8_lossy(&output.stdout),
            format!(
                "{home} {want}\n{home}/sub 0:0\n{target} 0:0\n{link} {want}\n",
                home = at("home"),
                target = at("target"),
                link = at("link"),
            ),
            "{label}"
        );
        checked.push(label);
    }
    eprintln!("home owner change checked under: {checked:?}");
}

/// `mkdir -p` — what a non-local `make_dir` runs — makes nothing through a symbolic link
/// at the name it is given: a dangling one fails with nothing made where it points, and
/// one to a directory is left as it is. A link in a component above is followed.
#[test]
fn mkdir_p_makes_nothing_through_a_link_at_the_name_under_both_shells() {
    let dir = tempfile::tempdir().unwrap();
    let bin = stand_in_bin(dir.path());
    let mut checked = Vec::new();
    for leg in test_shells(dir.path(), &["mkdir"], Some(&bin)) {
        let label = leg.0;
        let case = tempfile::tempdir_in(dir.path()).unwrap();
        let at = |name: &str| case.path().join(name);
        let mkdir = |path: &Path| {
            run(
                &leg,
                &format!(
                    "sudo mkdir -p {}",
                    zap_types::shell::single_quote(&path.to_string_lossy())
                ),
            )
        };
        symlink(at("nowhere"), at("dangling")).unwrap();
        let output = mkdir(&at("dangling"));
        assert!(!output.status.success(), "{label}: {output:?}");
        assert!(!at("nowhere").exists(), "{label}");

        std::fs::create_dir(at("real")).unwrap();
        symlink(at("real"), at("alias")).unwrap();
        let output = mkdir(&at("alias"));
        assert!(output.status.success(), "{label}: {output:?}");
        assert!(
            std::fs::symlink_metadata(at("alias")).unwrap().is_symlink(),
            "{label}"
        );
        assert!(entries(&at("real")).is_empty(), "{label}");

        let output = mkdir(&at("alias").join("sub"));
        assert!(output.status.success(), "{label}: {output:?}");
        assert!(at("real").join("sub").is_dir(), "{label}");
        checked.push(label);
    }
    eprintln!("mkdir -p checked under: {checked:?}");
}

/// A `swap` file's first step, the planner's own, refuses a directory on the way to the
/// path, as declared or where it resolves, that isn't root's or that others may write,
/// and a link at the path, naming the path and why, before anything is allocated; a path in root's own directory, written by no one
/// else, passes, and the check makes nothing. The link is shown below a directory a
/// stand-in `stat` reports as root's, since the test can make none.
#[test]
fn the_swap_path_check_refuses_a_link_and_a_directory_others_write_under_both_shells() {
    let scratch = crate::test_scratch::tempdir();
    let dir = &std::fs::canonicalize(scratch.path()).unwrap();
    let bin = stand_in_bin(dir);
    let mine = dir.join("mine");
    std::fs::create_dir(&mine).unwrap();
    std::fs::set_permissions(&mine, std::fs::Permissions::from_mode(0o755)).unwrap();
    symlink("/etc/hostname", mine.join("link")).unwrap();
    let shared = dir.join("shared");
    std::fs::create_dir(&shared).unwrap();
    std::fs::set_permissions(&shared, std::fs::Permissions::from_mode(0o1777)).unwrap();
    std::fs::create_dir(mine.join("sub")).unwrap();
    // a declared path through a link to a directory elsewhere
    let elsewhere = dir.join("elsewhere");
    std::fs::create_dir_all(elsewhere.join("inner")).unwrap();
    let trusted = dir.join("trusted");
    std::fs::create_dir(&trusted).unwrap();
    symlink(elsewhere.join("inner"), trusted.join("link")).unwrap();
    let roots = dir.join("roots");
    std::fs::create_dir(&roots).unwrap();
    super::put::executable(&roots.join("stat"), "echo 0:755");
    let root_is_roots =
        std::fs::metadata("/").is_ok_and(|meta| meta.uid() == 0 && meta.mode() & 0o022 == 0);
    let first_step = |path: &str| {
        absent_run_steps(serde_json::json!({
            "id": "swap", "type": "swap", "size": "1G", "path": path,
        }))
        .swap_remove(0)
    };
    let mut checked = Vec::new();
    for leg in test_shells(dir, APPLETS, Some(&bin)) {
        let label = leg.0;
        let rooted = (
            label,
            leg.1.clone(),
            Some(super::put::led_by(&roots, leg.2.as_ref())),
        );
        let refused = |leg: &Leg, path: &Path, why: &str| {
            let output = run_step(leg, &first_step(&path.to_string_lossy()));
            let stderr = String::from_utf8_lossy(&output.stderr);
            assert_eq!(
                output.status.code(),
                Some(zap_types::put::REFUSED_EXIT),
                "{label} {path:?}: {stderr}"
            );
            assert!(
                stderr.contains(&format!("{}: {why}; no swap file was made", path.display())),
                "{label} {path:?}: {stderr}"
            );
        };
        let untrusted = |at: &Path| {
            format!(
                "the directory {} on its path can not be read, is not owned by root, or can be \
                 written by other accounts",
                at.display()
            )
        };
        for under in [mine.clone(), shared.clone(), mine.join("missing")] {
            refused(&leg, &under.join("swapfile"), &untrusted(&under));
        }
        // a directory further up, as declared, or where a link on the way leads, that
        // others may write; a stand-in `stat` answers root's `755` for every other one
        let only_open = |open_at: &Path| {
            let lead = tempfile::tempdir_in(dir).unwrap().keep();
            super::put::executable(
                &lead.join("stat"),
                &format!(
                    "for a; do :; done; case $a in {}) echo 0:775;; *) echo 0:755;; esac",
                    zap_types::shell::single_quote(&open_at.to_string_lossy())
                ),
            );
            (
                label,
                leg.1.clone(),
                Some(super::put::led_by(&lead, leg.2.as_ref())),
            )
        };
        refused(
            &only_open(&mine),
            &mine.join("sub").join("swapfile"),
            &untrusted(&mine),
        );
        refused(
            &only_open(&elsewhere),
            &trusted.join("link").join("swapfile"),
            &untrusted(&elsewhere),
        );
        let output = run_step(
            &only_open(&dir.join("unrelated")),
            &first_step(&trusted.join("link").join("swapfile").to_string_lossy()),
        );
        assert!(output.status.success(), "{label}: {output:?}");
        refused(
            &rooted,
            &mine.join("link"),
            "a symbolic link is not made into swap",
        );
        // root's, but writable by its group or by anyone
        for mode in ["1777", "775", "757"] {
            let open = tempfile::tempdir_in(dir).unwrap();
            super::put::executable(&open.path().join("stat"), &format!("echo 0:{mode}"));
            let opened = (
                label,
                leg.1.clone(),
                Some(super::put::led_by(open.path(), leg.2.as_ref())),
            );
            refused(&opened, &mine.join("swapfile"), &untrusted(&mine));
        }
        let output = run_step(
            &rooted,
            &first_step(&mine.join("swapfile").to_string_lossy()),
        );
        assert!(output.status.success(), "{label}: {output:?}");
        if root_is_roots {
            let free = Path::new("/zap-swap-check-never-made");
            let output = run_step(&leg, &first_step(&free.to_string_lossy()));
            assert!(output.status.success(), "{label}: {output:?}");
            assert!(!free.exists(), "{label}");
        }
        checked.push(label);
    }
    eprintln!("the swap path check checked under: {checked:?}");
}
