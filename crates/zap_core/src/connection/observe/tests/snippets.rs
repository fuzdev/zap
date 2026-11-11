use std::os::unix::fs::{PermissionsExt as _, symlink};
use std::path::Path;
use std::time::{Duration, Instant};

use zap_types::observe::{CommandOrigin, Observation, Privilege, Query};
use zap_types::var_ref::marker;

use super::support::{busybox_applets, run_one, running_pids, test_shells};
use crate::test_support::local_machine;

/// The `copy_from` snippet under both shells, against a passwd-like file of its own
/// (the snippet's `/etc/passwd` swapped for it) and a `sudo` stand-in that logs the
/// account it is asked to become and runs the read as the test's user: a source with
/// keys, one with no entry, an empty home, no key file, a key file that is a directory,
/// an empty one, one past the read bound, a home that begins with `-`, and — as anyone
/// but root — one it can't open. Every read of a key file is made as the source.
#[tokio::test]
async fn the_copy_source_snippet_reads_the_passwd_home_under_both_shells() {
    use std::fmt::Write as _;

    use zap_types::observe::user::{AUTHORIZED_KEYS_READ_MAX, copy_source_snippet};

    let dir = tempfile::tempdir().unwrap();
    let bin = dir.path().join("bin");
    std::fs::create_dir(&bin).unwrap();
    let sudo_log = dir.path().join("sudo.log");
    std::fs::write(
        bin.join("sudo"),
        format!(
            "#!/bin/sh\n[ \"$1\" = -u ] || exit 64\necho \"$2\" >> {}\nshift 2\nexec \"$@\"\n",
            zap_types::shell::single_quote(&sudo_log.to_string_lossy())
        ),
    )
    .unwrap();
    std::fs::set_permissions(bin.join("sudo"), std::fs::Permissions::from_mode(0o755)).unwrap();
    let root = dir.path().join("homes with 'quotes'");
    let home = |name: &str, keys: Option<&[u8]>| {
        let home = root.join(name);
        std::fs::create_dir_all(home.join(".ssh")).unwrap();
        if let Some(keys) = keys {
            std::fs::write(home.join(".ssh/authorized_keys"), keys).unwrap();
        }
        home.to_string_lossy().into_owned()
    };
    let over = vec![b'k'; usize::try_from(AUTHORIZED_KEYS_READ_MAX).unwrap() + 10];
    let entries = [
        (
            "keys",
            home(
                "keys",
                Some(b"ssh-ed25519 AAAA one\nssh-ed25519 BBBB two\n"),
            ),
        ),
        ("emptyhome", String::new()),
        ("nokeys", home("nokeys", None)),
        ("dirkeys", home("dirkeys", None)),
        ("blank", home("blank", Some(b""))),
        ("big", home("big", Some(&over))),
        ("locked", home("locked", Some(b"secret\n"))),
        // A relative home that reads as an option: the name follows `--`.
        ("dashed", "-n".to_owned()),
    ];
    std::fs::create_dir(root.join("dirkeys/.ssh/authorized_keys")).unwrap();
    std::fs::set_permissions(
        root.join("locked/.ssh/authorized_keys"),
        std::fs::Permissions::from_mode(0o000),
    )
    .unwrap();
    let passwd = dir.path().join("passwd");
    let lines = entries
        .iter()
        .fold(String::new(), |mut lines, (name, home)| {
            let _ = writeln!(lines, "{name}:x:1000:1000::{home}:/bin/sh");
            lines
        });
    std::fs::write(&passwd, lines).unwrap();

    let snippet = |name: &str| {
        let snippet = copy_source_snippet(name);
        assert!(snippet.contains(" /etc/passwd)"));
        Query::root_command(snippet.replace(
            " /etc/passwd)",
            &format!(
                " {})",
                zap_types::shell::single_quote(&passwd.to_string_lossy())
            ),
        ))
    };
    let mut checked = Vec::new();
    for (shell_name, shell, path) in test_shells(dir.path(), &["awk"], Some(&bin)) {
        let _ = std::fs::remove_file(&sudo_log);
        let answer = async |name: &str| match run_one(&shell, path.as_ref(), &snippet(name)).await {
            Ok(Observation::Command(observation)) => (observation.code, observation.stdout),
            other => panic!("{shell_name} {name}: {other:?}"),
        };
        assert_eq!(
            answer("keys").await,
            (0, b"ssh-ed25519 AAAA one\nssh-ed25519 BBBB two\n".to_vec()),
            "{shell_name}"
        );
        assert_eq!(answer("nosuch").await.0, 3, "{shell_name}");
        assert_eq!(answer("emptyhome").await.0, 3, "{shell_name}");
        for unreadable in ["nokeys", "dirkeys", "dashed"] {
            let (code, stdout) = answer(unreadable).await;
            assert!(
                code != 0 && stdout.is_empty(),
                "{shell_name} {unreadable}: {code}"
            );
        }
        assert_eq!(answer("blank").await, (0, Vec::new()), "{shell_name}");
        let (code, stdout) = answer("big").await;
        assert_eq!(code, 0, "{shell_name}");
        assert_eq!(
            stdout.len(),
            usize::try_from(AUTHORIZED_KEYS_READ_MAX).unwrap() + 1,
            "{shell_name}: one byte past the bound, so the verdict can tell"
        );
        if !nix::unistd::geteuid().is_root() {
            let (code, stdout) = answer("locked").await;
            assert!(code != 0 && stdout.is_empty(), "{shell_name}: {code}");
        }
        // Each key file was read as its source account; a source with no home was
        // never read at all.
        let became = std::fs::read_to_string(&sudo_log).unwrap();
        for name in ["keys", "nokeys", "dirkeys", "blank", "big", "dashed"] {
            assert!(
                became.lines().any(|line| line == name),
                "{shell_name}: {name}: {became}"
            );
        }
        for name in ["nosuch", "emptyhome"] {
            assert!(
                !became.lines().any(|line| line == name),
                "{shell_name}: {name}: {became}"
            );
        }
        checked.push(shell_name);
    }
    std::fs::set_permissions(
        root.join("locked/.ssh/authorized_keys"),
        std::fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    eprintln!("copy source snippet checked under: {checked:?}");
}

/// A managed user's home read under both shells, against a passwd-like file of its own
/// (the probe's `/etc/passwd` swapped for it), and its answer through the verdict: a
/// `/home/<name>` home reads on, any other home (or none, or an account the file
/// doesn't list) holds the user, and a file `awk` can't read fails the probe.
#[tokio::test]
async fn the_user_home_read_holds_a_home_other_than_home_name_under_both_shells() {
    use zap_types::detected::Detection;
    use zap_types::observe::{CommandObservation, user};
    use zap_types::schema::UserResource;

    let dir = tempfile::tempdir().unwrap();
    let passwd = dir.path().join("passwd");
    std::fs::write(
        &passwd,
        "managed:x:1000:1000::/home/managed:/bin/sh\n\
         elsewhere:x:1001:1001::/srv/elsewhere:/bin/sh\n\
         nohome:x:1002:1002:::/bin/sh\n",
    )
    .unwrap();
    let unreadable = dir.path().join("no such passwd");
    let home_read = |resource: &UserResource, table: &Path| {
        let queries = user::queries(resource);
        // id, then the home: `home_mode` is the only other attribute declared.
        let Query::Command { snippet, .. } = &queries[1] else {
            panic!("the home read is a command: {queries:?}");
        };
        assert!(snippet.contains("{print $6}' /etc/passwd"), "{snippet}");
        Query::login_command(snippet.replace(
            " /etc/passwd",
            &format!(
                " {}",
                zap_types::shell::single_quote(&table.to_string_lossy())
            ),
        ))
    };
    let resource = |name: &str| -> UserResource {
        serde_json::from_value(serde_json::json!({"username": name, "home_mode": "750"})).unwrap()
    };
    let exited = |code: i32, stdout: &str| {
        Ok(Observation::Command(CommandObservation {
            code,
            stdout: stdout.as_bytes().to_vec(),
            stderr: Vec::new(),
        }))
    };
    let mut checked = Vec::new();
    for (shell_name, shell, path) in test_shells(dir.path(), &["awk"], None) {
        let verdict = async |name: &str, table: &Path| {
            let resource = resource(name);
            let home = run_one(&shell, path.as_ref(), &home_read(&resource, table)).await;
            // the home entry: a directory uid 1000 owns
            let entry = exited(0, "41ed 1000 1000\n");
            user::interpret(
                &resource,
                &[exited(0, "1000\n"), home, entry, exited(0, "750\n")],
            )
        };
        assert_eq!(
            verdict("managed", &passwd).await,
            Detection::Converged,
            "{shell_name}"
        );
        for (name, found) in [
            (
                "elsewhere",
                "elsewhere's home in /etc/passwd is /srv/elsewhere",
            ),
            ("nohome", "nohome has no home in /etc/passwd"),
            ("unlisted", "unlisted has no home in /etc/passwd"),
        ] {
            let Detection::Undetermined { reason } = verdict(name, &passwd).await else {
                panic!("{shell_name} {name}: held");
            };
            assert!(reason.starts_with(found), "{shell_name} {name}: {reason}");
        }
        let Detection::Undetermined { reason } = verdict("managed", &unreadable).await else {
            panic!("{shell_name}: an unreadable passwd holds");
        };
        assert!(
            reason.starts_with("detection failed: couldn't read managed's home from /etc/passwd"),
            "{shell_name}: {reason}"
        );
        checked.push(shell_name);
    }
    eprintln!("user home read checked under: {checked:?}");
}

/// What is at a managed user's home, read under both shells (the snippet's `/home`
/// and `/home/deploy` swapped for a directory of the test's) and through the verdict:
/// nothing there, the user's own directory, a link to one or to nothing, a file, a
/// missing `/home`, and — as anyone but root — a `/home` the probe can't search; the
/// last two hold naming `/home` rather than reading as nothing there. `stat` doesn't
/// follow the link.
#[tokio::test]
async fn the_home_entry_read_holds_a_link_or_a_file_under_both_shells() {
    use zap_types::detected::Detection;
    use zap_types::observe::{CommandObservation, user};
    use zap_types::schema::UserResource;

    let dir = tempfile::tempdir().unwrap();
    let uid = nix::unistd::geteuid().as_raw();
    let resource: UserResource =
        serde_json::from_value(serde_json::json!({"username": "deploy", "home_mode": "750"}))
            .unwrap();
    let homes = dir.path().join("homes");
    let home = homes.join("deploy");
    let snippet = user::home_entry_snippet("deploy");
    let localized = snippet
        .replace(
            "'/home/deploy'",
            &zap_types::shell::single_quote(&home.to_string_lossy()),
        )
        .replace(
            " /home ",
            &format!(
                " {} ",
                zap_types::shell::single_quote(&homes.to_string_lossy())
            ),
        );
    assert!(
        !localized.contains("/home/") && !localized.contains(" /home "),
        "{localized}"
    );
    let exited = |code: i32, stdout: &str| {
        Ok(Observation::Command(CommandObservation {
            code,
            stdout: stdout.as_bytes().to_vec(),
            stderr: Vec::new(),
        }))
    };
    let held = |found: &str| Detection::Undetermined {
        reason: format!(
            "{found}: zap manages a user's home as the directory /home/deploy, the user's own \
             or root's"
        ),
    };
    let link = held(
        "/home/deploy is a symbolic link, which zap doesn't follow; replace it with a \
         directory, or declare neither home_mode nor ssh_keys",
    );
    let unsearchable = Detection::Undetermined {
        reason: "detection failed: couldn't read what is at /home/deploy: /home is missing, \
                 or not a directory the connecting user can search"
            .to_owned(),
    };
    let mut checked = Vec::new();
    for (shell_name, shell, path) in test_shells(dir.path(), &[], None) {
        let verdict = async || {
            let entry = run_one(&shell, path.as_ref(), &Query::login_command(&localized)).await;
            user::interpret(
                &resource,
                &[
                    exited(0, &format!("{uid}\n")),
                    exited(0, "/home/deploy\n"),
                    entry,
                    exited(0, "750\n"),
                ],
            )
        };
        assert_eq!(verdict().await, unsearchable, "{shell_name}: no /home");
        std::fs::create_dir(&homes).unwrap();
        assert_eq!(
            verdict().await,
            Detection::Converged,
            "{shell_name}: nothing there"
        );
        std::fs::create_dir(&home).unwrap();
        assert_eq!(
            verdict().await,
            Detection::Converged,
            "{shell_name}: its own"
        );
        std::fs::remove_dir(&home).unwrap();
        let elsewhere = dir.path().join("elsewhere");
        std::fs::create_dir(&elsewhere).unwrap();
        symlink(&elsewhere, &home).unwrap();
        assert_eq!(verdict().await, link, "{shell_name}: a link to a directory");
        std::fs::remove_dir(&elsewhere).unwrap();
        assert_eq!(verdict().await, link, "{shell_name}: a dangling link");
        std::fs::remove_file(&home).unwrap();
        std::fs::write(&home, "").unwrap();
        assert_eq!(
            verdict().await,
            held("/home/deploy is not a directory; move it aside, or remove it"),
            "{shell_name}: a file"
        );
        std::fs::remove_file(&home).unwrap();
        if !nix::unistd::geteuid().is_root() {
            std::fs::set_permissions(&homes, std::fs::Permissions::from_mode(0o600)).unwrap();
            assert_eq!(
                verdict().await,
                unsearchable,
                "{shell_name}: an unsearchable /home"
            );
            std::fs::set_permissions(&homes, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        std::fs::remove_dir(&homes).unwrap();
        checked.push(shell_name);
    }
    eprintln!("home entry read checked under: {checked:?}");
}

/// The `/etc/passwd` and `/etc/shadow` field reads under both shells — and under the
/// system `sh` with each other `awk` installed (`mawk`, `gawk --posix`) — against
/// stand-ins of their own holding names that read as numbers (`inf`, `infinity`,
/// `nan`), all valid account names: each read prints its own entry's field and no
/// other's. A numeric compare there matches nothing (`BusyBox`) or matches `inf` to
/// the `infinity` line (`gawk --posix`).
#[tokio::test]
async fn the_passwd_and_shadow_reads_match_a_numeric_looking_name_exactly() {
    use std::fmt::Write as _;

    use zap_types::schema::{PasswdField, passwd_field, shadow_password_field};

    let dir = tempfile::tempdir().unwrap();
    let names = ["infinity", "inf", "nan"];
    let passwd = dir.path().join("passwd");
    let shadow = dir.path().join("shadow");
    let (mut passwd_lines, mut shadow_lines) = (String::new(), String::new());
    for name in names {
        let _ = writeln!(
            passwd_lines,
            "{name}:x:1000:1000::/home/{name}:/bin/{name}sh"
        );
        let _ = writeln!(shadow_lines, "{name}:{name}-hash:19000:0:99999:7:::");
    }
    std::fs::write(&passwd, passwd_lines).unwrap();
    std::fs::write(&shadow, shadow_lines).unwrap();
    let swapped = |command: String, table: &str, stand_in: &Path| {
        assert!(command.ends_with(table), "{command}");
        Query::login_command(command.replace(
            table,
            &format!(
                " {}",
                zap_types::shell::single_quote(&stand_in.to_string_lossy())
            ),
        ))
    };

    let mut shells = test_shells(dir.path(), &["awk"], None);
    for (label, awk, args) in [
        ("sh with mawk", "mawk", ""),
        ("sh with gawk --posix", "gawk", " --posix"),
    ] {
        let Some(found) = std::env::var_os("PATH").and_then(|path| {
            std::env::split_paths(&path)
                .map(|dir| dir.join(awk))
                .find(|candidate| candidate.is_file())
        }) else {
            continue;
        };
        let bin = dir.path().join(awk);
        std::fs::create_dir(&bin).unwrap();
        std::fs::write(
            bin.join("awk"),
            format!(
                "#!/bin/sh\nexec {}{args} \"$@\"\n",
                zap_types::shell::single_quote(&found.to_string_lossy())
            ),
        )
        .unwrap();
        std::fs::set_permissions(bin.join("awk"), std::fs::Permissions::from_mode(0o755)).unwrap();
        let system = std::env::var_os("PATH").unwrap();
        let path = std::env::join_paths(std::iter::once(bin).chain(std::env::split_paths(&system)))
            .unwrap();
        shells.push((label, "sh".into(), Some(path)));
    }

    let mut checked = Vec::new();
    for (shell_name, shell, path) in &shells {
        let answer = async |query: &Query| match run_one(shell, path.as_ref(), query).await {
            Ok(Observation::Command(observation)) => (
                observation.code,
                String::from_utf8(observation.stdout).unwrap(),
            ),
            other => panic!("{shell_name}: {other:?}"),
        };
        for name in names {
            let home = passwd_field(name, PasswdField::Home);
            let login_shell = passwd_field(name, PasswdField::Shell);
            let password = shadow_password_field(name);
            assert_eq!(
                answer(&swapped(home, " /etc/passwd", &passwd)).await,
                (0, format!("/home/{name}\n")),
                "{shell_name} {name}: home"
            );
            assert_eq!(
                answer(&swapped(login_shell, " /etc/passwd", &passwd)).await,
                (0, format!("/bin/{name}sh\n")),
                "{shell_name} {name}: shell"
            );
            assert_eq!(
                answer(&swapped(password, " /etc/shadow", &shadow)).await,
                (0, format!("{name}-hash\n")),
                "{shell_name} {name}: password"
            );
        }
        checked.push(*shell_name);
    }
    eprintln!("passwd and shadow reads checked under: {checked:?}");
}

/// A managed user's own `authorized_keys` read under both shells, its path swapped for
/// one of the test's, with a `sudo` stand-in that logs the account it becomes: a
/// regular file is read as the user, one byte past the bound at most; a symbolic link
/// (to a file or dangling), a directory, and a fifo exit `NOT_REGULAR_EXIT` with
/// nothing read and no `sudo` run; an absent file fails the read.
#[tokio::test]
async fn the_authorized_keys_snippet_reads_only_a_regular_file_as_its_owner_under_both_shells() {
    use zap_types::observe::batch::NOT_REGULAR_EXIT;
    use zap_types::observe::user::{AUTHORIZED_KEYS_READ_MAX, authorized_keys_snippet};
    use zap_types::schema::authorized_keys_path;

    let dir = tempfile::tempdir().unwrap();
    let bin = dir.path().join("bin");
    std::fs::create_dir(&bin).unwrap();
    let sudo_log = dir.path().join("sudo.log");
    std::fs::write(
        bin.join("sudo"),
        format!(
            "#!/bin/sh\n[ \"$1\" = -u ] || exit 64\necho \"$2\" >> {}\nshift 2\nexec \"$@\"\n",
            zap_types::shell::single_quote(&sudo_log.to_string_lossy())
        ),
    )
    .unwrap();
    std::fs::set_permissions(bin.join("sudo"), std::fs::Permissions::from_mode(0o755)).unwrap();
    let keys = dir.path().join("it's keys");
    std::fs::create_dir(&keys).unwrap();
    std::fs::write(keys.join("regular"), b"ssh-ed25519 AAAA one\n").unwrap();
    let over = vec![b'k'; usize::try_from(AUTHORIZED_KEYS_READ_MAX).unwrap() + 10];
    std::fs::write(keys.join("big"), &over).unwrap();
    symlink(keys.join("regular"), keys.join("link")).unwrap();
    symlink(keys.join("nowhere"), keys.join("dangling")).unwrap();
    std::fs::create_dir(keys.join("dir")).unwrap();
    let fifo = std::process::Command::new("mkfifo")
        .arg(keys.join("fifo"))
        .status()
        .is_ok_and(|status| status.success());

    let snippet = |name: &str| {
        let snippet = authorized_keys_snippet("deploy");
        let declared = zap_types::shell::single_quote(&authorized_keys_path("deploy"));
        assert!(snippet.contains(&declared));
        Query::root_command(snippet.replace(
            &declared,
            &zap_types::shell::single_quote(&keys.join(name).to_string_lossy()),
        ))
    };
    let mut checked = Vec::new();
    for (shell_name, shell, path) in test_shells(dir.path(), &[], Some(&bin)) {
        let _ = std::fs::remove_file(&sudo_log);
        let answer = async |name: &str| match run_one(&shell, path.as_ref(), &snippet(name)).await {
            Ok(Observation::Command(observation)) => (observation.code, observation.stdout),
            other => panic!("{shell_name} {name}: {other:?}"),
        };
        assert_eq!(
            answer("regular").await,
            (0, b"ssh-ed25519 AAAA one\n".to_vec()),
            "{shell_name}"
        );
        let (code, stdout) = answer("big").await;
        assert_eq!(code, 0, "{shell_name}");
        assert_eq!(
            stdout.len(),
            usize::try_from(AUTHORIZED_KEYS_READ_MAX).unwrap() + 1,
            "{shell_name}"
        );
        let became = std::fs::read_to_string(&sudo_log).unwrap();
        assert_eq!(became, "deploy\ndeploy\n", "{shell_name}: read as the user");
        let mut refused = vec!["link", "dangling", "dir"];
        if fifo {
            refused.push("fifo");
        }
        for name in refused {
            assert_eq!(
                answer(name).await,
                (NOT_REGULAR_EXIT, Vec::new()),
                "{shell_name} {name}"
            );
        }
        let (code, stdout) = answer("absent").await;
        assert!(
            code != 0 && code != NOT_REGULAR_EXIT && stdout.is_empty(),
            "{shell_name}: {code}"
        );
        assert_eq!(
            std::fs::read_to_string(&sudo_log).unwrap(),
            "deploy\ndeploy\ndeploy\n",
            "{shell_name}: only the absent file was asked of the user"
        );
        checked.push(shell_name);
    }
    eprintln!("authorized_keys snippet checked under: {checked:?}");
}

/// `FILE_BYTES` under both shells: a regular file's bytes, raw; a symbolic link (live
/// or dangling), a directory, a fifo, and a device refused with `REFUSED_EXIT` and
/// nothing printed; nothing at the path failed by `cat`.
#[test]
fn the_raw_read_script_reads_only_a_regular_file_under_both_shells() {
    use zap_types::put::{REFUSED_EXIT, file_bytes_command};

    let dir = tempfile::tempdir().unwrap();
    let at = |name: &str| dir.path().join(name).to_string_lossy().into_owned();
    std::fs::write(at("it's bin"), b"\0\xff\nELF").unwrap();
    symlink(at("it's bin"), at("link")).unwrap();
    symlink(at("nowhere"), at("dangling")).unwrap();
    std::fs::create_dir(at("dir")).unwrap();
    let mut refused = vec![
        at("link"),
        at("dangling"),
        at("dir"),
        "/dev/zero".to_owned(),
    ];
    if std::process::Command::new("mkfifo")
        .arg(at("fifo"))
        .status()
        .is_ok_and(|status| status.success())
    {
        refused.push(at("fifo"));
    }
    let mut checked = Vec::new();
    for (shell_name, shell, path) in test_shells(dir.path(), &[], None) {
        let run = |target: &str| {
            let mut command = std::process::Command::new(&shell);
            if let Some(path) = &path {
                command.env("PATH", path);
            }
            command
                .args(["-c", &file_bytes_command("", target)])
                .output()
                .unwrap()
        };
        let output = run(&at("it's bin"));
        assert!(output.status.success(), "{shell_name}: {output:?}");
        assert_eq!(output.stdout, b"\0\xff\nELF", "{shell_name}");
        for target in &refused {
            let output = run(target);
            assert_eq!(
                output.status.code(),
                Some(REFUSED_EXIT),
                "{shell_name} {target}"
            );
            assert!(output.stdout.is_empty(), "{shell_name} {target}");
        }
        let output = run(&at("absent"));
        assert!(
            !output.status.success() && output.status.code() != Some(REFUSED_EXIT),
            "{shell_name}: {output:?}"
        );
        checked.push(shell_name);
    }
    eprintln!("raw read script checked under: {checked:?}");
}

/// The deploy's read of the live release (`server_version_command`) under both shells:
/// a link names its release; nothing at `current` in an app path that can be entered,
/// or no app path at all, is never deployed; something else at `current` is no link;
/// and something at the app path that can't be entered — a file, a dangling link, and
/// as anyone but root a directory it can't search — is an exit of its own, never
/// "never deployed". An app path below a directory that can't be searched still reads
/// as never deployed, the residual the command documents. A directory it may search but
/// not list is entered.
#[test]
fn the_live_release_read_tells_an_app_it_cant_enter_under_both_shells() {
    use crate::commands::deploy::live::{
        NOT_A_LINK_EXIT, NOT_DEPLOYED_EXIT, UNENTERABLE_EXIT, server_version_command,
    };

    let dir = tempfile::tempdir().unwrap();
    let at = |name: &str| dir.path().join(name);
    let release = |app: &str| at(app).join("releases/abc1234");
    for app in [
        "live", "fresh", "notalink", "locked", "listless", "ancestor",
    ] {
        std::fs::create_dir(at(app)).unwrap();
    }
    for app in ["live", "locked", "listless"] {
        symlink(release(app), at(app).join("current")).unwrap();
    }
    std::fs::create_dir(at("notalink").join("current")).unwrap();
    std::fs::create_dir(at("ancestor").join("app")).unwrap();
    std::fs::write(at("afile"), "").unwrap();
    symlink(at("nowhere"), at("dangling")).unwrap();
    symlink(at("fresh"), at("linked")).unwrap();
    let mut cases = vec![
        ("live", 0, format!("{}\n", release("live").display())),
        ("fresh", NOT_DEPLOYED_EXIT, String::new()),
        ("missing", NOT_DEPLOYED_EXIT, String::new()),
        ("linked", NOT_DEPLOYED_EXIT, String::new()),
        ("notalink", NOT_A_LINK_EXIT, String::new()),
        ("afile", UNENTERABLE_EXIT, String::new()),
        ("dangling", UNENTERABLE_EXIT, String::new()),
    ];
    let mode = |name: &str, mode: u32| {
        std::fs::set_permissions(at(name), std::fs::Permissions::from_mode(mode)).unwrap();
    };
    let confined = !nix::unistd::geteuid().is_root();
    if confined {
        mode("locked", 0o600);
        mode("listless", 0o100);
        mode("ancestor", 0o000);
        cases.extend([
            ("locked", UNENTERABLE_EXIT, String::new()),
            (
                "listless",
                0,
                format!("{}\n", release("listless").display()),
            ),
            ("ancestor/app", NOT_DEPLOYED_EXIT, String::new()),
        ]);
    }
    let mut checked = Vec::new();
    for (shell_name, shell, path) in test_shells(dir.path(), &[], None) {
        for (app, code, stdout) in &cases {
            let mut command = std::process::Command::new(&shell);
            if let Some(path) = &path {
                command.env("PATH", path);
            }
            let read = server_version_command(&at(app).to_string_lossy());
            let output = command.args(["-c", &read]).output().unwrap();
            assert_eq!(
                output.status.code(),
                Some(*code),
                "{shell_name} {app}: {output:?}"
            );
            assert_eq!(
                String::from_utf8_lossy(&output.stdout),
                *stdout,
                "{shell_name} {app}"
            );
            assert!(output.stderr.is_empty(), "{shell_name} {app}: {output:?}");
        }
        checked.push(shell_name);
    }
    if confined {
        for name in ["locked", "listless", "ancestor"] {
            mode(name, 0o755);
        }
    }
    eprintln!("live release read checked under: {checked:?}");
}

/// The raw read script and a batch's content reads check what they opened: when the
/// name no longer names the file held open — here a `stat` stand-in that answers
/// another inode for the name, as a name swapped for a link between the tests and the
/// open would — nothing is read, and the read is refused as no regular file of its own.
#[tokio::test]
async fn a_content_read_refuses_a_name_that_no_longer_names_what_it_opened() {
    use zap_types::observe::{PathFacet, PathObservation};
    use zap_types::put::{REFUSED_EXIT, file_bytes_command};

    use super::put::{led_by, on_path};
    use super::support::path_query;

    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("it's bin");
    std::fs::write(&file, b"ELF").unwrap();
    let file = file.to_string_lossy().into_owned();
    let mut checked = Vec::new();
    for (shell_name, shell, path) in test_shells(dir.path(), &[], None) {
        // A `stat` that answers truly through a descriptor (`-L`) and with another
        // inode for a name.
        let bin = tempfile::tempdir_in(dir.path()).unwrap();
        let real = on_path(path.as_ref(), "stat");
        std::fs::write(
            bin.path().join("stat"),
            format!(
                "#!/bin/sh\nfor a do [ \"$a\" = -L ] && exec {} \"$@\"; done\necho 0:0\n",
                zap_types::shell::single_quote(&real.to_string_lossy())
            ),
        )
        .unwrap();
        std::fs::set_permissions(
            bin.path().join("stat"),
            std::fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        let swapped = led_by(bin.path(), path.as_ref());

        let output = std::process::Command::new(&shell)
            .env("PATH", &swapped)
            .args(["-c", &file_bytes_command("", &file)])
            .output()
            .unwrap();
        assert_eq!(
            output.status.code(),
            Some(REFUSED_EXIT),
            "{shell_name}: {output:?}"
        );
        assert!(output.stdout.is_empty(), "{shell_name}");

        for facet in [PathFacet::Digest, PathFacet::Read { max: 8 }] {
            let answer = run_one(&shell, Some(&swapped), &path_query(&file, facet)).await;
            assert_eq!(
                answer,
                Ok(Observation::Path(PathObservation::NotRegular)),
                "{shell_name} {facet:?}"
            );
            // The same read with the true `stat` reads the file.
            let answer = run_one(&shell, path.as_ref(), &path_query(&file, facet)).await;
            assert!(
                matches!(
                    answer,
                    Ok(Observation::Path(
                        PathObservation::Digest(_) | PathObservation::Contents { .. }
                    ))
                ),
                "{shell_name} {facet:?}: {answer:?}"
            );
        }
        checked.push(shell_name);
    }
    eprintln!("swapped-name content reads checked under: {checked:?}");
}

/// The `apt_repo` source line under both shells, against an `os-release` of its own:
/// the codename expands, and a backslash in the source is printed as it is written —
/// `echo` would read `\n` as a line break under `dash` and print it under `BusyBox`
/// `ash`, so the list written and the line detection expects would differ by shell.
#[tokio::test]
async fn the_apt_source_line_prints_the_same_text_under_both_shells() {
    use zap_types::schema::{apt_source_command, inject_signed_by};

    let dir = tempfile::tempdir().unwrap();
    let os_release = dir.path().join("os-release");
    std::fs::write(&os_release, "VERSION_CODENAME=trixie\n").unwrap();
    let source = r"deb https://e.x/a\nb\tc\\d ${VERSION_CODENAME}-x $VERSION_CODENAME %s main";
    let line = apt_source_command(&inject_signed_by(source, "/k/x.asc"));
    assert!(line.starts_with(". /etc/os-release && printf '%s\\n' \""));
    let query = Query::login_command(line.replacen(
        "/etc/os-release",
        &zap_types::shell::single_quote(&os_release.to_string_lossy()),
        1,
    ));
    let mut checked = Vec::new();
    for (shell_name, shell, path) in test_shells(dir.path(), &["printf"], None) {
        match run_one(&shell, path.as_ref(), &query).await {
            Ok(Observation::Command(observation)) => assert_eq!(
                (
                    observation.code,
                    String::from_utf8_lossy(&observation.stdout).into_owned()
                ),
                (
                    0,
                    "deb [signed-by=/k/x.asc] https://e.x/a\\nb\\tc\\d trixie-x trixie %s main\n"
                        .to_owned()
                ),
                "{shell_name}"
            ),
            other => panic!("{shell_name}: {other:?}"),
        }
        checked.push(shell_name);
    }
    eprintln!("apt source line checked under: {checked:?}");
}

/// An `installer`'s step under both shells, with a stand-in `curl` and a stand-in for
/// the shell the script is piped to: a fetch that fails fails the step with `curl`'s own
/// status and the shell is never started; one that succeeds with nothing, or with
/// newlines only, fails the step saying the script is empty, the shell never started;
/// one that succeeds with a script hands the shell that script on its stdin, byte for
/// byte — on no argv — and the step's status is the shell's.
#[test]
fn the_installer_step_runs_its_shell_only_when_the_fetch_succeeded_under_both_shells() {
    use zap_types::detected::Detection;
    use zap_types::last_run::ReportVar;
    use zap_types::plan::{DiffInputs, diff};
    use zap_types::schema::{Resource, Target};

    /// The script the stand-in `curl` serves: a tab, a written `\n`, and a `printf`
    /// directive, each of which a `printf` given the script as its format would rewrite.
    const SCRIPT: &str = "echo installing\n\tprintf 'a\\nb %s 100%%\\n' x\nexit 0";

    let dir = tempfile::tempdir().unwrap();
    let bin = dir.path().join("bin");
    std::fs::create_dir(&bin).unwrap();
    let executable = |path: &Path, body: &str| {
        std::fs::write(path, format!("#!/bin/sh\n{body}\n")).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
    };
    let quote = |path: &Path| zap_types::shell::single_quote(&path.to_string_lossy());
    let ran = dir.path().join("ran");
    let argv = dir.path().join("argv");
    // The shell the script is piped to: it records that it ran, what it was handed on
    // its argv, and what arrived on its stdin, then exits as its first argument says.
    let installer_shell = bin.join("installer-shell");
    executable(
        &installer_shell,
        &format!(
            "printf '%s\\n' \"$@\" > {}\ncat > {}\nexit \"$1\"",
            quote(&argv),
            quote(&ran)
        ),
    );
    let step = |status: u8| {
        let resource: Resource = serde_json::from_value(serde_json::json!({
            "id": "tool", "type": "installer", "url": "https://e.x/install.sh",
            "check": "/opt/tool",
            "shell": format!("{} {status}", installer_shell.to_string_lossy()),
        }))
        .unwrap();
        let plan = diff(DiffInputs {
            resources: std::slice::from_ref(&resource),
            detected: &[(resource.id.clone(), Detection::Absent)].into(),
            target: &Target::local(),
            machine: &local_machine(),
            lock: None,
            pending: &std::collections::BTreeMap::new(),
            var: &ReportVar::unset,
        })
        .plan;
        plan.changes[0].steps[0]
            .execution()
            .unwrap()
            .text()
            .to_owned()
    };
    let mut checked = Vec::new();
    for (label, shell, path) in test_shells(dir.path(), &["printf"], Some(&bin)) {
        let run = |step: &str| {
            let mut command = std::process::Command::new(&shell);
            if let Some(path) = &path {
                command.env("PATH", path);
            }
            command.args(["-c", step]).output().unwrap()
        };
        // The fetch fails — after printing part of a script: nothing is run.
        executable(
            &bin.join("curl"),
            "echo 'rm -rf /nothing'\necho 'curl: (22) The requested URL returned error: 404' >&2\nexit 22",
        );
        let _ = std::fs::remove_file(&ran);
        let output = run(&step(0));
        assert_eq!(output.status.code(), Some(22), "{label}: {output:?}");
        assert!(!ran.exists(), "{label}: the shell ran on a failed fetch");
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("curl: (22)"),
            "{label}: {output:?}"
        );
        // The fetch succeeds with no script — nothing at all, or only newlines, which
        // the capture drops: the step fails and nothing is run.
        for body in ["", "\n\n"] {
            executable(
                &bin.join("curl"),
                &format!("printf '%s' {}", zap_types::shell::single_quote(body)),
            );
            let output = run(&step(0));
            assert_eq!(
                output.status.code(),
                Some(1),
                "{label} {body:?}: {output:?}"
            );
            assert!(
                !ran.exists(),
                "{label} {body:?}: the shell ran on an empty script"
            );
            assert_eq!(
                String::from_utf8_lossy(&output.stderr),
                "zap: the installer script is empty\n",
                "{label} {body:?}"
            );
        }
        // The fetch succeeds: the shell reads the script, and its status is the step's.
        executable(
            &bin.join("curl"),
            &format!(
                "[ \"$*\" = \"--proto =https --proto-redir =https -fsSL -- https://e.x/install.sh\" ] \
                 || exit 64\nprintf '%s\\n' {}",
                zap_types::shell::single_quote(SCRIPT)
            ),
        );
        for status in [0, 7] {
            let output = run(&step(status));
            assert_eq!(
                output.status.code(),
                Some(i32::from(status)),
                "{label}: {output:?}"
            );
            assert_eq!(
                std::fs::read_to_string(&ran).unwrap(),
                format!("{SCRIPT}\n"),
                "{label}"
            );
            assert_eq!(
                std::fs::read_to_string(&argv).unwrap(),
                format!("{status}\n"),
                "{label}: the script is on no argv"
            );
        }
        checked.push(label);
    }
    eprintln!("installer step checked under: {checked:?}");
}

/// A script's composed check under both shells, through a real batch: the `env` is
/// seen by every command of a compound check (an `&&` list, a later pipeline stage, a
/// `;` list, a subshell) and carries any value byte for byte; the check runs in its
/// `cwd` (a quoted name, a symlink read physically); a check that fails there reads
/// absent; a `cwd` that can't be entered — missing, a file, untraversable — reads
/// absent too, the check never run; and a check whose first line doesn't parse reads
/// absent, with or without a `cwd`.
#[tokio::test]
async fn the_script_check_enters_its_cwd_and_exports_its_env_under_both_shells() {
    use zap_types::detected::Detection;
    use zap_types::observe::script::{ScriptCheck, interpret, queries};

    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().canonicalize().unwrap();
    let work = root.join("work 'dir' $HOME");
    std::fs::create_dir(&work).unwrap();
    std::fs::write(work.join("marker"), "").unwrap();
    symlink(&work, root.join("link")).unwrap();
    std::fs::write(root.join("file"), "").unwrap();
    let locked = root.join("locked");
    std::fs::create_dir(&locked).unwrap();
    std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000)).unwrap();
    let at = |name: &str| root.join(name).to_string_lossy().into_owned();
    let work_path = work.to_string_lossy().into_owned();
    let ran = at("ran");
    let touch_ran = format!("touch {}", zap_types::shell::single_quote(&ran));

    let value = "it's '' a `$HOME` \"q\" ; \\ ~ * value\n second line ";
    let env = [("ZAP_T_A", value), ("ZAP_T_B", "b")];
    let mut checked = Vec::new();
    for (shell_name, shell, path) in
        test_shells(dir.path(), &["test", "printf", "pwd", "touch"], None)
    {
        let run = async |check: &str, cwd: Option<&str>, env: &[(&str, &str)]| {
            let check = ScriptCheck::new(check, cwd, env);
            let results = [run_one(&shell, path.as_ref(), &queries(&check)[0]).await];
            let stdout = match &results[0] {
                Ok(Observation::Command(observation)) => observation.stdout.clone(),
                other => panic!("{shell_name} {}: {other:?}", check.snippet),
            };
            (interpret(&results), stdout)
        };
        let converged = |stdout: &str| (Detection::Converged, stdout.as_bytes().to_vec());

        // Every command of a compound check sees the env, and the check its cwd.
        for check in [
            r#"test "$ZAP_T_B" = b && test "$ZAP_T_B" = b && test -f marker"#,
            r#"true | test "$ZAP_T_B" = b"#,
            r#":; test "$ZAP_T_B" = b"#,
            r#"( test "$ZAP_T_B" = b ) && { test "$ZAP_T_B" = b; }"#,
            r#"sh -c 'test "$ZAP_T_B" = b'"#,
            r#"if test "$ZAP_T_B" = b; then test -f marker; else false; fi"#,
            "test \"$ZAP_T_B\" = b &&\n  test -f marker",
        ] {
            assert_eq!(
                run(check, Some(&work_path), &env).await,
                converged(""),
                "{shell_name}: {check}"
            );
            // Without the cwd the env still reaches each of them.
            let nowhere = check.replace("test -f marker", "true");
            assert_eq!(
                run(&nowhere, None, &env).await,
                converged(""),
                "{shell_name}: {nowhere}"
            );
            // And each reads the env, not a default: with none, it fails — not applied.
            assert_eq!(
                run(&nowhere, None, &[]).await.0,
                Detection::Absent,
                "{shell_name}: {nowhere}"
            );
        }

        // A value round-trips byte for byte.
        for cwd in [Some(work_path.as_str()), None] {
            assert_eq!(
                run(r#"printf '%s' "$ZAP_T_A""#, cwd, &env).await,
                converged(value),
                "{shell_name}"
            );
        }

        // The directory is the one declared, entered physically: a symlink reads as
        // the directory it names.
        assert_eq!(
            run("pwd", Some(&at("link")), &[]).await,
            converged(&format!("{work_path}\n")),
            "{shell_name}"
        );

        // A check that ran in its cwd and failed is not applied, whatever it printed and
        // whether or not it read its stdin (detached: nothing to read).
        for check in ["test -f absent", "echo noise; cat; exit 3", "false"] {
            assert_eq!(
                run(check, Some(&work_path), &env).await.0,
                Detection::Absent,
                "{shell_name}: {check}"
            );
        }

        // A cwd that can't be entered reads not applied — and the check never runs
        // anywhere else: it prints nothing and touches nothing, whatever it would exit.
        let mut unenterable = vec![at("gone"), at("file"), at("gone/deeper")];
        if !nix::unistd::geteuid().is_root() {
            unenterable.push(at("locked"));
        }
        for cwd in &unenterable {
            for check in ["true", "echo ran; exit 0", touch_ran.as_str()] {
                assert_eq!(
                    run(check, Some(cwd), &env).await,
                    (Detection::Absent, Vec::new()),
                    "{shell_name}: {check} in {cwd:?}"
                );
            }
        }
        assert!(!Path::new(&ran).exists(), "{shell_name}");
        // The same check does run where its cwd is.
        assert_eq!(
            run(&touch_ran, Some(&work_path), &env).await.0,
            Detection::Converged,
            "{shell_name}"
        );
        std::fs::remove_file(&ran).unwrap();

        // A check whose first line doesn't parse is a check that failed — with a cwd,
        // with env, with neither; and with an unenterable cwd it still isn't reached.
        for check in ["if true; then", "test -f marker )", "fi\ntrue"] {
            for (cwd, env) in [
                (Some(work_path.as_str()), &env[..]),
                (Some(work_path.as_str()), &[][..]),
                (None, &env[..]),
                (None, &[][..]),
                (Some(unenterable[0].as_str()), &env[..]),
            ] {
                assert_eq!(
                    run(check, cwd, env).await,
                    (Detection::Absent, Vec::new()),
                    "{shell_name}: {check:?} in {cwd:?}"
                );
            }
        }
        checked.push(shell_name);
    }
    std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o700)).unwrap();
    eprintln!("script check snippet checked under: {checked:?}");
}

/// The `database` snippet under both shells, with stand-ins on `PATH` — `sudo`
/// printing a canned catalog row (or failing, or hanging, as `psql` would) and running
/// the rules read it is handed for `postgres` as the test's own user, `id`
/// answering for the `postgres` account, and a `grep` that logs each call before
/// running the real one — so the `hba_file` split and the `grep`s run for real:
/// a path with spaces, one holding the `|` separator, an empty setting, no declared
/// rules, a rules read `sudo` refuses, a failed query, a failed query exiting with the
/// no-`PostgreSQL` status itself, no `psql`, no `postgres` account, output past the one
/// row (a `psqlrc`'s `\timing` line — nothing is grepped), and a hung query its own
/// `timeout` stops.
/// Each shell's `PATH` holds only the stand-ins and the batch's tools, so what is
/// installed is the test's call.
#[tokio::test]
async fn the_database_snippet_splits_the_catalog_row_and_greps_under_both_shells() {
    use zap_types::detected::{CurrentState, DatabaseDrift, Detection, PgHbaMissing};
    use zap_types::observe::database;
    use zap_types::schema::DatabaseResource;

    /// The declared hosts as detection passes them, references resolved (none here).
    fn declared_hosts(resource: &DatabaseResource) -> Vec<String> {
        resource
            .auth_hosts()
            .iter()
            .map(|host| host.as_inert().to_owned())
            .collect()
    }

    /// What the target looks like to the snippet.
    enum Target {
        /// `psql -X` prints this output.
        Prints(String),
        /// `psql` fails with this status.
        Exits(i32),
        /// `psql` never returns.
        Hangs,
        /// No `psql` installed.
        NoPsql,
        /// `psql` installed, but no `postgres` account.
        NoAccount,
        /// `psql -X` prints this output, and nothing else can be run as `postgres`.
        RulesUnread(String),
    }

    let dir = tempfile::tempdir().unwrap();
    let bin = dir.path().join("bin");
    std::fs::create_dir(&bin).unwrap();
    // The system leg's tools, alone on its `PATH` — so a `psql` or `postgres` account
    // the host happens to have isn't found.
    let tools = dir.path().join("tools");
    std::fs::create_dir(&tools).unwrap();
    let system_path = std::env::var_os("PATH").unwrap_or_default();
    let system_tool = |tool: &str| {
        std::env::split_paths(&system_path)
            .map(|dir| dir.join(tool))
            .find(|candidate| candidate.is_file())
            .unwrap_or_else(|| panic!("no {tool} on PATH"))
    };
    for tool in [
        "sh", "timeout", "od", "tr", "head", "cat", "stat", "readlink", "sleep", "setsid",
    ] {
        symlink(system_tool(tool), tools.join(tool)).unwrap();
    }
    let mut shells = vec![(
        "sh",
        tools.join("sh"),
        system_tool("grep"),
        std::env::join_paths([&bin, &tools]).ok(),
    )];
    if let Some(applets) = busybox_applets(dir.path(), &["grep"]) {
        shells.push((
            "busybox",
            applets.join("sh"),
            applets.join("grep"),
            std::env::join_paths([&bin, &applets]).ok(),
        ));
    }

    let hba = dir.path().join("pg hba.conf");
    std::fs::write(
        &hba,
        "local all postgres peer\nhost app app 127.0.0.1/32 scram-sha-256\n",
    )
    .unwrap();
    let piped = dir.path().join("a|b.conf");
    std::fs::write(
        &piped,
        "host app app 127.0.0.1/32 scram-sha-256\nhost app app 10.0.0.0/8 scram-sha-256\n",
    )
    .unwrap();
    let grep_log = dir.path().join("grep.log");
    let resource = |hosts: &[&str]| -> DatabaseResource {
        serde_json::from_value(serde_json::json!({
            "engine": "postgresql", "database_name": "app", "username": "app",
            "auth": {"method": "scram-sha-256", "hosts": hosts},
        }))
        .unwrap()
    };
    let executable = |path: &Path, body: &str| {
        std::fs::write(path, format!("#!/bin/sh\n{body}\n")).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
    };
    let quote = |text: &str| zap_types::shell::single_quote(text);
    // The stand-ins answer only the invocations the snippet makes; `psql` itself is
    // only ever looked up, never run.
    let install = |target: &Target, real_grep: &Path| {
        let _ = std::fs::remove_file(bin.join("psql"));
        let _ = std::fs::remove_file(&grep_log);
        let query = match target {
            Target::Prints(out) | Target::RulesUnread(out) => {
                format!("printf '%s\\n' {}", quote(out))
            }
            Target::Exits(code) => {
                format!("echo 'psql: error: connection to server failed' >&2; exit {code}")
            }
            Target::Hangs => "exec sleep 47".to_owned(),
            Target::NoPsql | Target::NoAccount => "exit 98".to_owned(),
        };
        if !matches!(target, Target::NoPsql) {
            executable(&bin.join("psql"), "exit 99");
        }
        let account = u8::from(matches!(target, Target::NoAccount));
        let rules = if matches!(target, Target::RulesUnread(_)) {
            "exit 1; "
        } else {
            ""
        };
        executable(
            &bin.join("id"),
            &format!("[ \"$1 $2\" = '-u postgres' ] || exit 99\nexit {account}"),
        );
        executable(
            &bin.join("sudo"),
            &format!(
                "[ \"$1 $2\" = '-u postgres' ] || exit 99\n\
                 if [ \"$3 $4\" = 'sh -c' ]; then {rules}shift 2; exec \"$@\"; fi\n\
                 [ \"$3 $4 $5\" = 'psql -X -tAc' ] || exit 99\n{query}"
            ),
        );
        executable(
            &bin.join("grep"),
            &format!(
                "echo x >> {}\nexec {} \"$@\"",
                quote(&grep_log.to_string_lossy()),
                quote(&real_grep.to_string_lossy())
            ),
        );
    };
    let two = ["127.0.0.1/32", "10.0.0.0/8"];
    let missing = |host: &str| PgHbaMissing {
        host: host.to_owned(),
        method: "scram-sha-256".to_owned(),
    };
    let drifted = |pg_hba_missing| Detection::Drifted {
        current: CurrentState::Database {
            drift: DatabaseDrift {
                owner: None,
                pg_hba_missing,
            },
        },
    };
    let held = |reason: &str| Detection::Undetermined {
        reason: format!("detection failed: {reason}"),
    };
    let failed = |code: i32| held(&format!("the PostgreSQL catalog query exited {code}"));
    let row = |path: &Path| format!("t|t|617070|{}", path.display());
    // (target, declared hosts, expected verdict, `grep`s run)
    let cases: Vec<(Target, &[&str], Detection, usize)> = vec![
        (
            Target::Prints(row(&hba)),
            &two,
            drifted(vec![missing("10.0.0.0/8")]),
            2,
        ),
        (Target::Prints(row(&piped)), &two, Detection::Converged, 2),
        (
            Target::Prints("t|t|617070|".to_owned()),
            &two,
            held("the pg_hba.conf file PostgreSQL reports (its hba_file setting) couldn't be read"),
            2,
        ),
        (Target::Prints(row(&hba)), &[], Detection::Converged, 0),
        (
            Target::Prints(format!("{}\nTime: 0.312 ms", row(&piped))),
            &two,
            held("the probe's output didn't parse"),
            0,
        ),
        // A rules read that never ran reads no rule as missing: it holds.
        (
            Target::RulesUnread(row(&piped)),
            &two,
            held("the probe's output didn't parse"),
            0,
        ),
        (Target::Exits(2), &two, failed(2), 0),
        // A query's own exit status can't pass for the no-`PostgreSQL` checks, nor
        // for its timeout's expiry.
        (
            Target::Exits(database::NO_POSTGRES_EXIT),
            &two,
            failed(1),
            0,
        ),
        (
            Target::Exits(database::CATALOG_TIMED_OUT_EXIT),
            &two,
            failed(1),
            0,
        ),
        (Target::NoPsql, &two, Detection::Absent, 0),
        (Target::NoAccount, &two, Detection::Absent, 0),
    ];
    let greps_run = || std::fs::read_to_string(&grep_log).map_or(0, |log| log.lines().count());
    let mut checked = Vec::new();
    for (shell_name, shell, real_grep, path) in &shells {
        for (target, hosts, expected, greps) in &cases {
            install(target, real_grep);
            let resource = resource(hosts);
            let query = &database::queries(&resource, "app", "app", &declared_hosts(&resource))[0];
            let answer = run_one(shell, path.as_ref(), query).await;
            assert_eq!(
                database::interpret(&resource, "app", std::slice::from_ref(&answer)),
                *expected,
                "{shell_name} {hosts:?}: {answer:?}"
            );
            assert_eq!(greps_run(), *greps, "{shell_name} {hosts:?}: grep calls");
        }

        // A hung query: its own `timeout` (shortened here) stops it — under `BusyBox`
        // too, whose probe `timeout` signals only the probe's reporter — and the
        // snippet reports the expiry as its own status, which reads timed out.
        install(&Target::Hangs, real_grep);
        let resource = resource(&two);
        let Query::Command { snippet, .. } =
            &database::queries(&resource, "app", "app", &declared_hosts(&resource))[0]
        else {
            unreachable!()
        };
        let hung = Query::Command {
            snippet: snippet.replace("timeout 50 ", "timeout 1 "),
            privilege: Privilege::Root,
            timeout_secs: std::num::NonZeroU32::new(30).unwrap(),
            origin: CommandOrigin::Zap,
        };
        let started = Instant::now();
        let answer = run_one(shell, path.as_ref(), &hung).await;
        let elapsed = started.elapsed();
        // What a stop that failed would leave of the stand-in's sleep.
        for pid in running_pids("sleep 47") {
            let _ = nix::sys::signal::kill(
                nix::unistd::Pid::from_raw(pid),
                nix::sys::signal::Signal::SIGKILL,
            );
        }
        assert!(
            elapsed < Duration::from_secs(20),
            "{shell_name}: the hung query outlived its timeout ({elapsed:?})"
        );
        assert_eq!(
            database::interpret(&resource, "app", std::slice::from_ref(&answer)),
            held("timed out after 50s"),
            "{shell_name}: {answer:?}"
        );
        checked.push(*shell_name);
    }
    eprintln!("database snippet checked under: {checked:?}");
}

/// The `database` `pg_hba` step (`zap_types::postgres::pg_hba_rule_step`) run for real
/// under both shells, with stand-ins on `PATH`: a `sudo` that runs its command as the
/// test's own user — and only a command for `postgres`, so a rewrite under a bare `sudo`
/// fails — and a `psql` that answers `SHOW hba_file` from a file the test writes (or
/// fails), `SELECT pg_reload_conf()` from another, logging each reload, the
/// `pg_hba_file_rules` check from a third, and `pg_conf_load_time()` from a fourth (by
/// default a time that moves with each reload logged); a `sleep` that only logs. The
/// `BusyBox` leg's `PATH` holds only the stand-ins and its own applets, so the rewrite
/// runs on `BusyBox`'s `grep`, `mktemp`, `chown`, and `mv`.
///
/// The rule lands exactly once — before the first `host` line, or at the end of a file
/// with none — and one reload is requested, after the file is checked, and waited for
/// until the load time moves; a present rule leaves the file untouched and reloads
/// nothing. A reload the server doesn't confirm (`f`, or a failed query) fails the
/// step, and so does a file the server can't parse (`f`, or a failed check, with no
/// reload), a load time that can't be read or never moves, a file that no longer
/// parses once the reload has loaded (checked again then), and output from the rewrite
/// other than `added`; a failing rewrite or check's status is the step's. The file keeps its mode,
/// its group, and its place behind a symlink. A step that can't find or rewrite the file
/// exits nonzero and leaves it as it was: so does one whose file belongs to another
/// account than the one it runs as (an `id` stand-in answering another uid), and one
/// whose file holds a NUL. Names planted where the rewrite stages its
/// copy are neither followed nor reused, a staged name swapped for a link is refused
/// with the link's target untouched, and a file swapped in at the `pg_hba` name is
/// installed with its own mode, never the original's.
///
/// What only root can show is not shown here: an owner other than the test's own.
#[test]
fn the_pg_hba_step_adds_a_rule_once_under_both_shells() {
    use std::os::unix::fs::MetadataExt;

    use zap_types::postgres::pg_hba_rule_step;

    let dir = tempfile::tempdir().unwrap();
    let bin = dir.path().join("bin");
    std::fs::create_dir(&bin).unwrap();
    let executable = |path: &Path, body: &str| {
        std::fs::write(path, format!("#!/bin/sh\n{body}\n")).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
    };
    // `sudo -u postgres psql …` and `sudo -u postgres sh -c …` both run as the test's
    // user; nothing runs under a bare `sudo`. While `rewrite-answer` exists, it stands
    // in for the rewrite itself.
    let rewrite_answer = dir.path().join("rewrite-answer");
    executable(
        &bin.join("sudo"),
        &format!(
            "[ \"$1 $2\" = '-u postgres' ] || exit 64\nshift 2\n\
             if [ \"$1\" = sh ] && [ -e {0} ]; then . {0}; exit; fi\nexec \"$@\"",
            zap_types::shell::single_quote(&rewrite_answer.to_string_lossy()),
        ),
    );
    // What `psql` does is a file the test rewrites: the stand-in's whole body. A
    // reload is answered from a file of its own, and logged; so are the file check
    // and the load time. `sleep` only logs.
    let answer = dir.path().join("psql-answer");
    let reload_answer = dir.path().join("psql-reload-answer");
    let parses_answer = dir.path().join("psql-parses-answer");
    let load_answer = dir.path().join("psql-load-answer");
    let reload_log = dir.path().join("reloads.log");
    let sleep_log = dir.path().join("sleeps.log");
    let quoted = |path: &Path| zap_types::shell::single_quote(&path.to_string_lossy());
    executable(
        &bin.join("psql"),
        &format!(
            "[ \"$1 $2\" = '-X -tAc' ] || exit 64\n\
             if [ \"$3\" = 'SELECT pg_reload_conf()' ]; then echo reload >> {}; . {}; exit; fi\n\
             if [ \"$3\" = {} ]; then . {}; exit; fi\n\
             if [ \"$3\" = {} ]; then . {}; exit; fi\n\
             . {}",
            quoted(&reload_log),
            quoted(&reload_answer),
            zap_types::shell::single_quote(zap_types::postgres::PG_HBA_FILE_PARSES),
            quoted(&parses_answer),
            zap_types::shell::single_quote(zap_types::postgres::PG_CONF_LOAD_TIME),
            quoted(&load_answer),
            quoted(&answer)
        ),
    );
    executable(
        &bin.join("sleep"),
        &format!("echo slept >> {}", quoted(&sleep_log)),
    );
    // The load time a server gives: one that moves with each reload.
    let moving = format!(
        "n=0; [ ! -e {0} ] || n=$(wc -l < {0}); echo \"2026-01-01 00:00:0$n+00\"",
        quoted(&reload_log)
    );
    std::fs::write(&reload_answer, "echo t").unwrap();
    std::fs::write(&parses_answer, "echo t").unwrap();
    std::fs::write(&load_answer, &moving).unwrap();
    let count = |log: &Path| {
        std::fs::read_to_string(log)
            .unwrap_or_default()
            .lines()
            .count()
    };
    let reloads = || count(&reload_log);
    let sleeps = || count(&sleep_log);
    let answers = |path: &Path| {
        std::fs::write(
            &answer,
            format!(
                "printf '%s\\n' {}",
                zap_types::shell::single_quote(&path.to_string_lossy())
            ),
        )
        .unwrap();
    };

    let shells = test_shells(
        dir.path(),
        &[
            "grep", "mktemp", "chown", "chmod", "rm", "sync", "mv", "ln", "id", "wc", "tail", "ls",
        ],
        Some(&bin),
    );
    let mut checked = Vec::new();
    for (label, shell, path) in &shells {
        let run = |step: &str| {
            let mut command = std::process::Command::new(shell);
            if let Some(path) = path {
                command.env("PATH", path);
            }
            command.args(["-c", step]).output().unwrap()
        };
        // Each case gets a directory of its own, so a leftover temp file shows.
        let case = tempfile::tempdir_in(dir.path()).unwrap();
        let conf = case.path().join("pg hba.conf");
        let entries = |dir: &Path| {
            let mut names: Vec<String> = std::fs::read_dir(dir)
                .unwrap()
                .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
                .collect();
            names.sort();
            names
        };
        let write = |contents: &str| {
            std::fs::write(&conf, contents).unwrap();
            std::fs::set_permissions(&conf, std::fs::Permissions::from_mode(0o640)).unwrap();
            answers(&conf);
        };
        let rule = |host: &str| pg_hba_rule_step("app", "app", host, "scram-sha-256");
        let line = |host: &str| format!("host    app    app    {host}    scram-sha-256\n");
        let add = |host: &str| {
            let output = run(&rule(host));
            assert!(output.status.success(), "{label}: {host}: {output:?}");
            assert_eq!(entries(case.path()), ["pg hba.conf"], "{label}: {host}");
            assert_eq!(
                std::fs::metadata(&conf).unwrap().mode() & 0o7777,
                0o640,
                "{label}: {host}: the file keeps its mode"
            );
            std::fs::read_to_string(&conf).unwrap()
        };

        // No `host` line: the rule goes at the end.
        write("# TYPE DATABASE USER ADDRESS METHOD\nlocal all postgres peer\n");
        assert_eq!(
            add("10.0.0.0/8"),
            format!(
                "# TYPE DATABASE USER ADDRESS METHOD\nlocal all postgres peer\n{}",
                line("10.0.0.0/8")
            ),
            "{label}"
        );

        // Exactly one: immediately before it — as a new file renamed into place, so
        // no reader (or interrupted run) ever sees the old one half written.
        write("local all postgres peer\nhost all all 127.0.0.1/32 md5\n");
        let replaced = std::fs::metadata(&conf).unwrap().ino();
        assert_eq!(
            add("10.0.0.0/8"),
            format!(
                "local all postgres peer\n{}host all all 127.0.0.1/32 md5\n",
                line("10.0.0.0/8")
            ),
            "{label}"
        );
        assert_ne!(
            std::fs::metadata(&conf).unwrap().ino(),
            replaced,
            "{label}: the file is replaced by rename, not written in place"
        );

        // Many (every `host*` type, a last line with no newline, lines `read` and
        // `printf` could mangle): once, before the first, the rest as they were. The
        // first is indented — a rule to PostgreSQL all the same, and one the new line
        // must not land below.
        let many = "local all postgres peer\n# a \\backslash, a %s, a trailing space \n\
                    # host in a comment\n \thostnogssenc all all 10.1.0.0/16 md5\n\
                    hostssl all all 0.0.0.0/0 md5\nhost all all 127.0.0.1/32 md5\n\
                    hostnossl all all ::1/128 md5\n-e host all all 10.0.0.0/8 trust";
        write(many);
        let first = many.find(" \thostnogssenc").unwrap();
        let once = format!(
            "{}{}{}\n",
            &many[..first],
            line("10.0.0.0/8"),
            &many[first..]
        );
        assert_eq!(add("10.0.0.0/8"), once, "{label}");

        // Already present: nothing is rewritten — the same file, not a new one — and
        // nothing is reloaded. The rule just added was reloaded once.
        let before = std::fs::metadata(&conf).unwrap();
        let reloaded = reloads();
        assert_eq!(add("10.0.0.0/8"), once, "{label}: a second run");
        let after = std::fs::metadata(&conf).unwrap();
        assert_eq!(
            (before.ino(), before.mtime(), before.mtime_nsec()),
            (after.ino(), after.mtime(), after.mtime_nsec()),
            "{label}: a present rule leaves the file untouched"
        );
        assert_eq!(
            reloads(),
            reloaded,
            "{label}: a present rule reloads nothing"
        );
        write("host all all 127.0.0.1/32 md5\n");
        let reloaded = reloads();
        add("10.0.0.0/8");
        assert_eq!(
            reloads(),
            reloaded + 1,
            "{label}: an added rule reloads once"
        );

        // A reload the server doesn't confirm, a file it can't parse, or a load time
        // that never moves fails the step with the rule written: it is in the file, not
        // known to be in force. The file is checked before the reload is asked for, and
        // the load time read before it. The next run reads the rule present and reloads
        // nothing; the reload is by hand.
        let never = "echo '2026-01-01 00:00:00+00'";
        for (what, reload, parses, load, status, said, reloaded, slept) in [
            (
                "a reload answered f",
                "echo f",
                "echo t",
                moving.as_str(),
                1,
                "zap: PostgreSQL did not reload its configuration",
                1,
                0,
            ),
            (
                "a failed reload",
                "echo 'psql: error: connection failed' >&2; exit 2",
                "echo t",
                moving.as_str(),
                1,
                "zap: PostgreSQL did not reload its configuration",
                1,
                0,
            ),
            (
                "a file it can't parse",
                "echo t",
                "echo f",
                moving.as_str(),
                1,
                "zap: PostgreSQL can not parse its pg_hba.conf, so it was not reloaded and the \
                 old rules stay in force",
                0,
                0,
            ),
            (
                "a failed file check",
                "echo t",
                "echo 'ERROR:  relation \"pg_hba_file_rules\" does not exist' >&2; exit 3",
                moving.as_str(),
                3,
                "pg_hba_file_rules",
                0,
                0,
            ),
            (
                "an empty file check",
                "echo t",
                "true",
                moving.as_str(),
                1,
                "zap: unexpected output from the pg_hba_file_rules check",
                0,
                0,
            ),
            (
                "an unread load time",
                "echo t",
                "echo t",
                "exit 2",
                1,
                "zap: could not read when PostgreSQL last loaded its configuration",
                0,
                0,
            ),
            (
                "an empty load time",
                "echo t",
                "echo t",
                "true",
                1,
                "zap: could not read when PostgreSQL last loaded its configuration",
                0,
                0,
            ),
            (
                "a load time that never moves",
                "echo t",
                "echo t",
                never,
                1,
                "zap: PostgreSQL did not load its configuration within 30 seconds of the \
                 reload, so the rule may not be in force; a postgresql.conf it can not parse \
                 keeps the load time from moving",
                1,
                30,
            ),
        ] {
            write("host all all 127.0.0.1/32 md5\n");
            std::fs::write(&reload_answer, reload).unwrap();
            std::fs::write(&parses_answer, parses).unwrap();
            std::fs::write(&load_answer, load).unwrap();
            let (reloads_before, sleeps_before) = (reloads(), sleeps());
            let output = run(&rule("10.0.0.0/8"));
            assert_eq!(
                output.status.code(),
                Some(status),
                "{label}: {what}: {output:?}"
            );
            assert!(
                String::from_utf8_lossy(&output.stderr).contains(said),
                "{label}: {what}: {output:?}"
            );
            assert_eq!(
                std::fs::read_to_string(&conf).unwrap(),
                format!("{}host all all 127.0.0.1/32 md5\n", line("10.0.0.0/8")),
                "{label}: {what}"
            );
            assert_eq!(
                (reloads() - reloads_before, sleeps() - sleeps_before),
                (reloaded, slept),
                "{label}: {what}: reloads and waits"
            );
        }
        std::fs::write(&reload_answer, "echo t").unwrap();
        std::fs::write(&parses_answer, "echo t").unwrap();

        // A reload the server takes a while to handle: the step waits, a second at a
        // time, for the load time to move, and goes on when it does.
        let polls = dir.path().join("polls.log");
        std::fs::write(
            &load_answer,
            format!(
                "echo poll >> {0}; if [ \"$(wc -l < {0})\" -le 3 ]; then \
                 echo '2026-01-01 00:00:00+00'; else echo '2026-01-01 00:00:01+00'; fi",
                quoted(&polls)
            ),
        )
        .unwrap();
        write("host all all 127.0.0.1/32 md5\n");
        let (reloads_before, sleeps_before) = (reloads(), sleeps());
        let output = run(&rule("10.0.0.0/8"));
        assert!(
            output.status.success(),
            "{label}: a slow reload: {output:?}"
        );
        assert_eq!(
            (reloads() - reloads_before, sleeps() - sleeps_before),
            (1, 2),
            "{label}: a slow reload is waited for"
        );
        std::fs::remove_file(&polls).unwrap();
        std::fs::write(&load_answer, &moving).unwrap();

        // A file another writer changed between the check and the reload, so the server
        // loaded one it can't parse: the check after the load time moves reads `f`, and
        // the step fails saying the rule may not be in force.
        let checks = dir.path().join("checks.log");
        std::fs::write(
            &parses_answer,
            format!(
                "echo check >> {0}; if [ \"$(wc -l < {0})\" -le 1 ]; then echo t; else echo f; fi",
                quoted(&checks)
            ),
        )
        .unwrap();
        write("host all all 127.0.0.1/32 md5\n");
        let reloads_before = reloads();
        let output = run(&rule("10.0.0.0/8"));
        assert_eq!(
            output.status.code(),
            Some(1),
            "{label}: a changed file: {output:?}"
        );
        assert!(
            String::from_utf8_lossy(&output.stderr).contains(
                "zap: PostgreSQL can not parse its pg_hba.conf, which changed \
                 after it was checked, so the rule may not be in force"
            ),
            "{label}: {output:?}"
        );
        assert_eq!(reloads() - reloads_before, 1, "{label}: a changed file");
        assert_eq!(count(&checks), 2, "{label}: checked before and after");
        std::fs::remove_file(&checks).unwrap();
        std::fs::write(&parses_answer, "echo t").unwrap();

        // The rewrite's own status is the step's, and output other than `added` or
        // nothing fails the step without a reload.
        write("host all all 127.0.0.1/32 md5\n");
        let reloaded = reloads();
        for (what, rewrite, status, said) in [
            ("a failed rewrite", "exit 7", 7, ""),
            (
                "unexpected output",
                "echo addd",
                1,
                "zap: unexpected output from the pg_hba rewrite",
            ),
        ] {
            std::fs::write(&rewrite_answer, rewrite).unwrap();
            let output = run(&rule("10.0.0.0/8"));
            assert_eq!(
                output.status.code(),
                Some(status),
                "{label}: {what}: {output:?}"
            );
            assert!(
                String::from_utf8_lossy(&output.stderr).contains(said),
                "{label}: {what}: {output:?}"
            );
        }
        std::fs::remove_file(&rewrite_answer).unwrap();
        assert_eq!(reloads(), reloaded, "{label}: no reload without `added`");
        write(many);
        add("10.0.0.0/8");

        // A second, distinct rule after the first: each present once.
        let both = add("192.168.0.0/16");
        assert_eq!(
            both,
            format!(
                "{}{}{}{}\n",
                &many[..first],
                line("192.168.0.0/16"),
                line("10.0.0.0/8"),
                &many[first..]
            ),
            "{label}"
        );
        assert_eq!(add("10.0.0.0/8"), both, "{label}: both rules now present");
        assert_eq!(add("192.168.0.0/16"), both, "{label}");

        // Debian's stock file, both old default hosts added and added again: each rule
        // once, above the first `host` record (a later rule above an earlier one), never
        // before every `host` record.
        let stock = "# Database administrative login by Unix domain socket\n\
                     local   all             postgres                                peer\n\
                     \n\
                     # TYPE  DATABASE        USER            ADDRESS                 METHOD\n\
                     \n\
                     # \"local\" is for Unix domain socket connections only\n\
                     local   all             all                                     peer\n\
                     # IPv4 local connections:\n\
                     host    all             all             127.0.0.1/32            scram-sha-256\n\
                     # IPv6 local connections:\n\
                     host    all             all             ::1/128                 scram-sha-256\n\
                     # Allow replication connections from localhost, by a user with the\n\
                     # replication privilege.\n\
                     local   replication     all                                     peer\n\
                     host    replication     all             127.0.0.1/32            scram-sha-256\n\
                     host    replication     all             ::1/128                 scram-sha-256\n";
        write(stock);
        add("127.0.0.1/32");
        add("::1/128");
        let first_host = stock.find("host    all").unwrap();
        let expected = format!(
            "{}{}{}{}",
            &stock[..first_host],
            line("::1/128"),
            line("127.0.0.1/32"),
            &stock[first_host..]
        );
        for _ in 0..2 {
            assert_eq!(add("127.0.0.1/32"), expected, "{label}: stock, once each");
            assert_eq!(add("::1/128"), expected, "{label}: stock, once each");
        }
        for host in ["127.0.0.1/32", "::1/128"] {
            assert_eq!(expected.matches(&line(host)).count(), 1, "{label}: {host}");
        }

        // An indented rule already there is the rule: the guard sees it as the detector
        // does, and nothing is added.
        let indented = format!("local all postgres peer\n\t  {}", line("10.0.0.0/8"));
        write(&indented);
        assert_eq!(add("10.0.0.0/8"), indented, "{label}");

        // Fields a shell, `printf`, or a regex could read as more than text arrive as
        // text, and the guard still finds the line it wrote.
        write("host all all 127.0.0.1/32 md5\n");
        let odd = pg_hba_rule_step("a b", "o'br\\ien%d$(id)", "::1/128", "trust");
        for _ in 0..2 {
            let output = run(&odd);
            assert!(output.status.success(), "{label}: {output:?}");
            assert_eq!(
                std::fs::read_to_string(&conf).unwrap(),
                "host    a b    o'br\\ien%d$(id)    ::1/128    trust\n\
                 host all all 127.0.0.1/32 md5\n",
                "{label}"
            );
        }

        // A symlinked `hba_file`: the file behind it is rewritten, the link stays.
        write("host all all 127.0.0.1/32 md5\n");
        let link = case.path().join("link.conf");
        symlink(&conf, &link).unwrap();
        answers(&link);
        let output = run(&rule("10.0.0.0/8"));
        assert!(output.status.success(), "{label}: {output:?}");
        assert!(std::fs::symlink_metadata(&link).unwrap().is_symlink());
        assert_eq!(
            std::fs::read_to_string(&conf).unwrap(),
            format!("{}host all all 127.0.0.1/32 md5\n", line("10.0.0.0/8")),
            "{label}"
        );
        std::fs::remove_file(&link).unwrap();

        // Failures exit nonzero and change nothing: no path, a failed query, a path
        // that names no file, and a directory the new file can't be created in.
        let unchanged = "host all all 127.0.0.1/32 md5\n";
        let fails = |what: &str| {
            let output = run(&rule("10.0.0.0/8"));
            assert!(!output.status.success(), "{label}: {what}: {output:?}");
            assert_eq!(
                std::fs::read_to_string(&conf).unwrap(),
                unchanged,
                "{label}: {what}"
            );
            assert_eq!(entries(case.path()), ["pg hba.conf"], "{label}: {what}");
            String::from_utf8_lossy(&output.stderr).into_owned()
        };
        write(unchanged);
        std::fs::write(&answer, "echo").unwrap();
        assert!(fails("an empty answer").contains("no hba_file"), "{label}");
        std::fs::write(&answer, "echo 'psql: error: connection failed' >&2; exit 2").unwrap();
        fails("a failed query");
        answers(&case.path().join("absent.conf"));
        assert!(
            fails("a missing file").contains("pg_hba file not found"),
            "{label}"
        );
        answers(&conf);
        std::fs::set_permissions(case.path(), std::fs::Permissions::from_mode(0o555)).unwrap();
        // Root creates files anywhere, so only an unprivileged run can see this one.
        if std::fs::File::create(case.path().join("probe")).is_err() {
            // Said by the script, with its one failure status — not a shell's own
            // redirection error, which differs by shell.
            let said = fails("an unwritable directory");
            assert!(
                said.starts_with("zap: ") && said.contains(" can not write "),
                "{label}: {said}"
            );
            assert_eq!(
                run(&rule("10.0.0.0/8")).status.code(),
                Some(1),
                "{label}: an unwritable directory"
            );
        }
        std::fs::set_permissions(case.path(), std::fs::Permissions::from_mode(0o755)).unwrap();

        // A file holding a NUL is left as it was: the shell's `read` would drop the
        // byte, and the copy is installed only when every byte of the file arrived.
        let binary = b"local all postgres peer\n# a \0 byte\nhost all all 127.0.0.1/32 md5\n";
        std::fs::write(&conf, binary).unwrap();
        answers(&conf);
        let output = run(&rule("10.0.0.0/8"));
        assert!(!output.status.success(), "{label}: a NUL: {output:?}");
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("left unchanged"),
            "{label}: {output:?}"
        );
        assert_eq!(std::fs::read(&conf).unwrap(), binary, "{label}");
        assert_eq!(entries(case.path()), ["pg hba.conf"], "{label}");
        write(unchanged);

        // A guard `grep` that fails for any reason but "no match" fails the step: an
        // unanswered guard is never read as "absent". Here a reference resolved, as the
        // command runner resolves it, to a value the pattern can't compile with.
        let uncompilable = pg_hba_rule_step("app", &marker("ROLE"), "10.0.0.0/8", "trust")
            .replace(&marker("ROLE"), "a(b");
        let output = run(&uncompilable);
        assert!(
            !output.status.success(),
            "{label}: a failed guard: {output:?}"
        );
        assert_eq!(
            std::fs::read_to_string(&conf).unwrap(),
            unchanged,
            "{label}"
        );
        assert_eq!(entries(case.path()), ["pg hba.conf"], "{label}");

        // A write that fails partway (a file-size limit standing in for a full disk:
        // the file fits, the file plus the rule doesn't) fails the step, leaves the
        // file as it was, and leaves no temp file behind — whether the rule goes before
        // a `host` line or at the end of a file with none.
        for (first, pad, last) in [
            (
                "host all all 127.0.0.1/32 md5\n",
                "host all all 10.9.8.0/24 scram-sha-256\n",
                "host all all 0.0.0.0/0 reject\n",
            ),
            (
                "local all postgres peer\n",
                "local sameuser all peer map=users\n",
                "local all all reject\n",
            ),
        ] {
            let mut full = String::from(first);
            while full.len() + pad.len() + last.len() <= 512 {
                full.push_str(pad);
            }
            full.push_str(last);
            assert!(full.len() <= 512 && full.len() + line("10.0.0.0/8").len() > 512);
            write(&full);
            let output = run(&format!(
                "trap '' XFSZ; ulimit -f 1; {}",
                rule("10.0.0.0/8")
            ));
            assert!(
                !output.status.success(),
                "{label}: a short write: {output:?}"
            );
            assert_eq!(std::fs::read_to_string(&conf).unwrap(), full, "{label}");
            assert_eq!(entries(case.path()), ["pg hba.conf"], "{label}");
        }

        // The new file is installed only when it holds one line more than the old one.
        // A `grep` that miscounts (a stand-in, ahead of the real one) stands in for a
        // read that ended early: the step fails and the file stays as it was.
        let real_grep = path
            .as_ref()
            .map(std::env::split_paths)
            .into_iter()
            .flatten()
            .map(|dir| dir.join("grep"))
            .find(|candidate| candidate.is_file())
            .expect("a grep on the leg's PATH");
        // Too few lines is the early read; too many is checked the same way.
        // The BusyBox leg can't pass vacuously: an `ash` that ran its `grep` applet
        // directly would ignore the stand-in, the step would succeed, and the assertion
        // below would fail.
        for count in [1, 7] {
            let lying = tempfile::tempdir_in(dir.path()).unwrap();
            executable(
                &lying.path().join("grep"),
                &format!(
                    "if [ \"$1\" = -c ] && [ \"$3\" = /proc/self/fd/3 ]; then echo {count}; exit 0; fi\n\
                     exec {} \"$@\"",
                    zap_types::shell::single_quote(&real_grep.to_string_lossy())
                ),
            );
            write(unchanged);
            let lying_path = std::env::join_paths(
                std::iter::once(lying.path().to_path_buf()).chain(
                    path.as_ref()
                        .map(std::env::split_paths)
                        .into_iter()
                        .flatten(),
                ),
            )
            .unwrap();
            let output = std::process::Command::new(shell)
                .env("PATH", lying_path)
                .args(["-c", &rule("10.0.0.0/8")])
                .output()
                .unwrap();
            assert!(
                !output.status.success(),
                "{label}: a file miscounted as {count}: {output:?}"
            );
            assert!(
                String::from_utf8_lossy(&output.stderr).contains("left unchanged"),
                "{label}: {output:?}"
            );
            assert_eq!(
                std::fs::read_to_string(&conf).unwrap(),
                unchanged,
                "{label}"
            );
            assert_eq!(entries(case.path()), ["pg hba.conf"], "{label}");
        }

        // The rewrite carries the file's group as well as its mode.
        let primary = nix::unistd::getegid();
        let other = nix::unistd::getgroups()
            .unwrap_or_default()
            .into_iter()
            .find(|gid| *gid != primary);
        if let Some(gid) = other {
            write(unchanged);
            std::os::unix::fs::chown(&conf, None, Some(gid.as_raw())).unwrap();
            add("10.0.0.0/8");
            assert_eq!(
                std::fs::metadata(&conf).unwrap().gid(),
                gid.as_raw(),
                "{label}: the file keeps its group"
            );
        }

        // A stand-in directory led onto the leg's `PATH`, and the step run under it.
        let led = |lead: &Path| {
            std::env::join_paths(
                std::iter::once(lead.to_path_buf()).chain(
                    path.as_ref()
                        .map(std::env::split_paths)
                        .into_iter()
                        .flatten(),
                ),
            )
            .unwrap()
        };
        let run_led = |lead: &Path| {
            std::process::Command::new(shell)
                .env("PATH", led(lead))
                .args(["-c", &rule("10.0.0.0/8")])
                .output()
                .unwrap()
        };
        let on_leg = |tool: &str| {
            path.as_ref()
                .map(std::env::split_paths)
                .into_iter()
                .flatten()
                .map(|dir| dir.join(tool))
                .find(|candidate| candidate.is_file())
                .unwrap_or_else(|| panic!("a {tool} on the leg's PATH"))
        };
        let victim = case.path().join("victim");
        std::fs::write(&victim, "ORIGINAL\n").unwrap();
        std::fs::set_permissions(&victim, std::fs::Permissions::from_mode(0o600)).unwrap();
        let victim_untouched = |what: &str| {
            assert_eq!(
                std::fs::read_to_string(&victim).unwrap(),
                "ORIGINAL\n",
                "{label}: {what}"
            );
            assert_eq!(
                std::fs::metadata(&victim).unwrap().mode() & 0o7777,
                0o600,
                "{label}: {what}"
            );
        };

        // A file that belongs to another account than the one the rewrite runs as (an
        // `id` stand-in answering a uid that isn't the file's): refused before anything
        // is staged, by name — the rewrite never falls back to more privilege.
        let stranger = tempfile::tempdir_in(dir.path()).unwrap();
        executable(
            &stranger.path().join("id"),
            "case $1 in -u) echo 4294967294;; -un) echo postgres;; *) exit 64;; esac",
        );
        write(unchanged);
        let output = run_led(stranger.path());
        assert!(
            !output.status.success(),
            "{label}: another's file: {output:?}"
        );
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("pg hba.conf does not belong to postgres, the account its rewrite runs as; left unchanged"),
            "{label}: {stderr}"
        );
        assert_eq!(
            std::fs::read_to_string(&conf).unwrap(),
            unchanged,
            "{label}"
        );
        assert_eq!(entries(case.path()), ["pg hba.conf", "victim"], "{label}");

        // The staged copy's name, already taken (a `mktemp` that answers a fixed name):
        // a link to another file, a dangling link, a regular file. None is written
        // through, reused, or removed, and the file stays as it was.
        let taken = tempfile::tempdir_in(dir.path()).unwrap();
        executable(&taken.path().join("mktemp"), "echo ./.zap.taken");
        let staged = case.path().join(".zap.taken");
        let plant: [(&str, &dyn Fn()); 3] = [
            ("a link to another file", &|| {
                symlink(&victim, &staged).unwrap();
            }),
            ("a dangling link", &|| {
                symlink(case.path().join("nowhere"), &staged).unwrap();
            }),
            ("a regular file", &|| {
                std::fs::write(&staged, "THEIRS").unwrap();
            }),
        ];
        for (what, plant) in plant {
            write(unchanged);
            plant();
            let before = std::fs::symlink_metadata(&staged).unwrap().ino();
            let output = run_led(taken.path());
            assert!(!output.status.success(), "{label}: {what}: {output:?}");
            assert_eq!(
                std::fs::read_to_string(&conf).unwrap(),
                unchanged,
                "{label}: {what}"
            );
            assert_eq!(
                std::fs::symlink_metadata(&staged).unwrap().ino(),
                before,
                "{label}: {what}: a name the step didn't create is not its to remove"
            );
            assert!(!case.path().join("nowhere").exists(), "{label}: {what}");
            victim_untouched(what);
            std::fs::remove_file(&staged).unwrap();
        }

        // A default access list on the directory overrides the umask a shell's own
        // create would apply; the staged copy is still the account's alone (`0600`)
        // while the rewrite is in it (a `grep` stand-in reads its mode at the line
        // count), and the installed file has the file's own mode.
        let listed = tempfile::tempdir_in(dir.path()).unwrap();
        if super::put::run_setfacl(&["-d", "-m", "u::rw,g::rw,o::rw"], listed.path()) {
            let listed_conf = listed.path().join("pg_hba.conf");
            std::fs::write(&listed_conf, unchanged).unwrap();
            std::fs::set_permissions(&listed_conf, std::fs::Permissions::from_mode(0o640)).unwrap();
            answers(&listed_conf);
            let seeing = tempfile::tempdir_in(dir.path()).unwrap();
            let seen = seeing.path().join("staged-mode");
            executable(
                &seeing.path().join("grep"),
                &format!(
                    "if [ \"$1\" = -c ] && [ \"$3\" = /proc/self/fd/3 ]; then \
                     stat -c %a ./.zap.* > {}; fi\n\
                     exec {} \"$@\"",
                    quoted(&seen),
                    quoted(&on_leg("grep"))
                ),
            );
            let output = run_led(seeing.path());
            assert!(
                output.status.success(),
                "{label}: a default ACL: {output:?}"
            );
            assert_eq!(std::fs::read_to_string(&seen).unwrap(), "600\n", "{label}");
            assert_eq!(
                std::fs::metadata(&listed_conf).unwrap().mode() & 0o7777,
                0o640,
                "{label}: a default ACL"
            );
            assert_eq!(
                std::fs::read_to_string(&listed_conf).unwrap(),
                format!("{}{unchanged}", line("10.0.0.0/8")),
                "{label}: a default ACL"
            );
            answers(&conf);
        } else {
            eprintln!("a default access list not checked: no setfacl");
        }

        // The staged name swapped for a link once the copy is written: a `grep` stand-in
        // moves the copy aside at the line count and leaves a link to the victim. The
        // owner and mode go to the copy through its descriptor, the swap is refused, and
        // nothing is installed.
        let swapping = tempfile::tempdir_in(dir.path()).unwrap();
        executable(
            &swapping.path().join("grep"),
            &format!(
                "if [ \"$1\" = -c ] && [ \"$3\" = /proc/self/fd/3 ]; then \
                 for f in ./.zap.*; do mv \"$f\" ./moved && ln -s {} \"$f\"; done; fi\n\
                 exec {} \"$@\"",
                zap_types::shell::single_quote(&victim.to_string_lossy()),
                zap_types::shell::single_quote(&on_leg("grep").to_string_lossy())
            ),
        );
        write(unchanged);
        let output = run_led(swapping.path());
        assert!(
            !output.status.success(),
            "{label}: a swapped stage: {output:?}"
        );
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("was replaced"),
            "{label}: {output:?}"
        );
        assert_eq!(
            std::fs::read_to_string(&conf).unwrap(),
            unchanged,
            "{label}"
        );
        victim_untouched("a swapped stage name");
        let moved = case.path().join("moved");
        assert_eq!(
            std::fs::metadata(&moved).unwrap().mode() & 0o7777,
            0o640,
            "{label}: the mode went to the copy the step created"
        );
        std::fs::remove_file(&moved).unwrap();
        assert_eq!(
            entries(case.path()),
            ["pg hba.conf", "victim"],
            "{label}: the planted link is removed with the stage's name"
        );

        // The file's own name swapped for a link once it was resolved (a `readlink`
        // stand-in does it): the contents the link leads to are installed with *their*
        // mode — the victim's `600`, not the `640` of the file that was there — so what
        // root read is no more readable than it was. The victim itself is untouched.
        let relinking = tempfile::tempdir_in(dir.path()).unwrap();
        executable(
            &relinking.path().join("readlink"),
            &format!(
                "out=$({} \"$@\") || exit 1\nrm -f \"$out\" && ln -s {} \"$out\" || exit 1\n\
                 printf '%s\\n' \"$out\"",
                zap_types::shell::single_quote(&on_leg("readlink").to_string_lossy()),
                zap_types::shell::single_quote(&victim.to_string_lossy()),
            ),
        );
        write(unchanged);
        let output = run_led(relinking.path());
        assert!(
            output.status.success(),
            "{label}: a relinked file: {output:?}"
        );
        let installed = std::fs::symlink_metadata(&conf).unwrap();
        assert!(installed.is_file(), "{label}: the link is replaced");
        assert_eq!(
            installed.mode() & 0o7777,
            0o600,
            "{label}: contents and mode come from the one open file"
        );
        assert_eq!(
            std::fs::read_to_string(&conf).unwrap(),
            format!("ORIGINAL\n{}", line("10.0.0.0/8")),
            "{label}"
        );
        victim_untouched("a relinked file");
        std::fs::remove_file(&victim).unwrap();
        checked.push(*label);
    }
    eprintln!("pg_hba step checked under: {checked:?}");
}

/// An apt `package`'s detection through a real batch.
async fn apt_package(
    shell: &Path,
    path: Option<&std::ffi::OsString>,
    name: &str,
) -> zap_types::detected::Detection {
    use zap_types::observe::package::{PackageCheck, interpret, queries};
    use zap_types::schema::{PackageManager, PackageResource};

    let package: PackageResource =
        serde_json::from_value(serde_json::json!({"from": {"apt": name}})).unwrap();
    let check = PackageCheck::from_manager(&package, Some(PackageManager::Apt));
    let queries = queries(&check);
    let [query] = queries.as_slice() else {
        panic!("one query: {queries:?}");
    };
    interpret(&check, &[run_one(shell, path, query).await])
}

/// The apt `package` query under both shells, with a stand-in `dpkg-query` that
/// records its arguments and prints canned lines: the package is named without the
/// version, suite or architecture `apt-get install` takes, it is installed when any
/// instance of it is — a multi-arch package prints one status per architecture — and
/// only a whole `installed` line counts. A declared version is installed only at exactly
/// that version: the line is matched whole and as a fixed string, so another revision, a
/// missing epoch, a prefix, and a version a pattern would match are not it. A declared
/// architecture is that architecture's instance, or an `all` one when the architecture
/// is the target's own (a stand-in `dpkg --print-architecture`).
#[tokio::test]
async fn the_apt_package_query_reads_whole_status_lines_under_both_shells() {
    use zap_types::detected::Detection;

    let dir = tempfile::tempdir().unwrap();
    let bin = dir.path().join("bin");
    std::fs::create_dir(&bin).unwrap();
    let argv = dir.path().join("argv");
    let printed = dir.path().join("printed");
    let native = dir.path().join("native");
    std::fs::write(&native, "amd64\n").unwrap();
    let quote = |path: &Path| zap_types::shell::single_quote(&path.to_string_lossy());
    let tool = |name: &str, body: String| {
        std::fs::write(bin.join(name), format!("#!/bin/sh\n{body}")).unwrap();
        std::fs::set_permissions(bin.join(name), std::fs::Permissions::from_mode(0o755)).unwrap();
    };
    // It fails as `dpkg-query` does for a name it has no package of: nothing printed
    // but a complaint, exit 1.
    tool(
        "dpkg-query",
        format!(
            "printf '%s\\n' \"$@\" > {}\n[ -s {printed} ] || \
             {{ echo 'dpkg-query: no packages found' >&2; exit 1; }}\ncat {printed}\n",
            quote(&argv),
            printed = quote(&printed),
        ),
    );
    tool(
        "dpkg",
        format!(
            "[ \"$*\" = --print-architecture ] || exit 9\ncat {}\n",
            quote(&native)
        ),
    );
    let detected = |installed: bool| {
        if installed {
            Detection::Converged
        } else {
            Detection::Absent
        }
    };

    let mut checked = Vec::new();
    for (label, shell, path) in test_shells(dir.path(), &["grep"], Some(&bin)) {
        for (statuses, installed) in [
            ("installed\n", true),
            ("installed\ninstalled\n", true),
            ("config-files\ninstalled\n", true),
            ("installed\nconfig-files\n", true),
            ("config-files\n", false),
            ("half-installed\n", false),
            ("not-installed\n", false),
            ("unpacked\nhalf-configured\n", false),
            // Statuses run together with nothing between them are no line of the word.
            ("installedinstalled\n", false),
            ("", false),
        ] {
            std::fs::write(&printed, statuses).unwrap();
            assert_eq!(
                apt_package(&shell, path.as_ref(), "curl").await,
                detected(installed),
                "{label}: {statuses:?}"
            );
            assert_eq!(
                std::fs::read_to_string(&argv).unwrap(),
                "-W\n-f=${db:Status-Status}\\n\ncurl\n",
                "{label}"
            );
        }
        std::fs::write(&printed, "installed\n").unwrap();
        for (declared, asked) in [
            ("nginx/bookworm-backports", "nginx"),
            ("g++", "g++"),
            ("memtest86+", "memtest86+"),
        ] {
            assert_eq!(
                apt_package(&shell, path.as_ref(), declared).await,
                Detection::Converged,
                "{label}: {declared}"
            );
            assert_eq!(
                std::fs::read_to_string(&argv).unwrap(),
                format!("-W\n-f=${{db:Status-Status}}\\n\n{asked}\n"),
                "{label}: {declared}"
            );
        }
        // A declared version or architecture: the status and each, one line an instance.
        for (declared, asked, lines, installed) in [
            ("nginx=1.24.0-1", "nginx", "installed 1.24.0-1\n", true),
            ("nginx=1.24.0-1", "nginx", "installed 1.24.0-2\n", false),
            // a prefix either way
            ("nginx=1.24.0-1", "nginx", "installed 1.24.0-10\n", false),
            ("nginx=1.24.0-10", "nginx", "installed 1.24.0-1\n", false),
            ("nginx=1.24.0", "nginx", "installed 1.24.0-1\n", false),
            // the epoch is part of the version
            ("nginx=1:1.24.0-1", "nginx", "installed 1:1.24.0-1\n", true),
            ("nginx=1.24.0-1", "nginx", "installed 1:1.24.0-1\n", false),
            ("nginx=1:1.24.0-1", "nginx", "installed 1.24.0-1\n", false),
            // a `.` and a `+` are themselves, not a pattern's
            ("nginx=1.24+b1", "nginx", "installed 1x24+b1\n", false),
            ("nginx=1.24+b1", "nginx", "installed 1.24+b1\n", true),
            ("g++=4:12.2.0-3", "g++", "installed 4:12.2.0-3\n", true),
            // at that version, and not installed
            ("nginx=1.24.0-1", "nginx", "config-files 1.24.0-1\n", false),
            (
                "nginx=1.24.0-1",
                "nginx",
                "half-installed 1.24.0-1\n",
                false,
            ),
            // any instance at that version
            (
                "libx=1.0-1",
                "libx",
                "installed 1.0-2\ninstalled 1.0-1\n",
                true,
            ),
            (
                "libx=1.0-1",
                "libx",
                "config-files 1.0-1\ninstalled 1.0-2\n",
                false,
            ),
            // an architecture: that one's instance, or an `all` one for the native
            // architecture (`amd64` here) alone
            ("libc6:i386", "libc6", "installed i386\n", true),
            ("libc6:i386", "libc6", "installed amd64\n", false),
            (
                "libc6:i386",
                "libc6",
                "config-files i386\ninstalled amd64\n",
                false,
            ),
            ("adduser:amd64", "adduser", "installed all\n", true),
            ("adduser:i386", "adduser", "installed all\n", false),
            ("adduser:amd64", "adduser", "half-installed all\n", false),
            ("libc6:amd64", "libc6", "installed amd64x\n", false),
            (
                "libc6:i386=2.36-9",
                "libc6",
                "installed i386 2.36-9\n",
                true,
            ),
            (
                "libc6:i386=2.36-9",
                "libc6",
                "installed amd64 2.36-9\n",
                false,
            ),
            (
                "adduser:amd64=3.134",
                "adduser",
                "installed all 3.134\n",
                true,
            ),
            (
                "adduser:amd64=3.134",
                "adduser",
                "installed all 3.135\n",
                false,
            ),
            (
                "adduser:i386=3.134",
                "adduser",
                "installed all 3.134\n",
                false,
            ),
            // apt takes a version or a suite, never both: no package is asked about
            // by its name, and a line that happens to answer is not read as it
            ("nginx=1.24.0-1/bookworm", "nginx=1.24.0-1", "", false),
            (
                "nginx/bookworm=1.24.0-1",
                "nginx/bookworm",
                "installed 1.24.0-2\n",
                false,
            ),
        ] {
            std::fs::write(&printed, lines).unwrap();
            assert_eq!(
                apt_package(&shell, path.as_ref(), declared).await,
                detected(installed),
                "{label}: {declared} over {lines:?}"
            );
            let versioned = declared.rfind('=') > declared.rfind('/');
            let arch = declared
                .split(['=', '/'])
                .next()
                .is_some_and(|name| name.contains(':'));
            let format = match (arch, versioned) {
                (false, false) => "-f=${db:Status-Status}\\n",
                (false, true) => "-f=${db:Status-Status} ${Version}\\n",
                (true, false) => "-f=${db:Status-Status} ${Architecture}\\n",
                (true, true) => "-f=${db:Status-Status} ${Architecture} ${Version}\\n",
            };
            assert_eq!(
                std::fs::read_to_string(&argv).unwrap(),
                format!("-W\n{format}\n{asked}\n"),
                "{label}: {declared}"
            );
        }
        checked.push(label);
    }
    eprintln!("apt package query checked under: {checked:?}");
    // `:all` is no form the query reads: apt installs the native architecture's package
    // for it, so it is refused before any query is made.
    assert_apt_all_refused();
}

/// A read that fails holds the package under both shells: a `dpkg-query` that exits
/// other than 0 or 1 — its status database locked or unreadable (2), the tool missing
/// (127) or not runnable (126) — is no answer, whatever it printed, and neither is a
/// `dpkg --print-architecture` that fails for a declared architecture. Its 0 and 1 still
/// answer.
#[tokio::test]
async fn a_failed_apt_package_query_holds_under_both_shells() {
    use zap_types::detected::Detection;

    let dir = tempfile::tempdir().unwrap();
    let bin = dir.path().join("bin");
    std::fs::create_dir(&bin).unwrap();
    let status = dir.path().join("status");
    let native = dir.path().join("native");
    let quote = |path: &Path| zap_types::shell::single_quote(&path.to_string_lossy());
    let tool = |name: &str, body: String| {
        std::fs::write(bin.join(name), format!("#!/bin/sh\n{body}")).unwrap();
        std::fs::set_permissions(bin.join(name), std::fs::Permissions::from_mode(0o755)).unwrap();
    };
    // It prints an installed line for every form asked about, then exits as told.
    tool(
        "dpkg-query",
        format!(
            "printf 'installed\\ninstalled 1.0\\ninstalled amd64\\ninstalled amd64 1.0\\n'\n\
             exit $(cat {})\n",
            quote(&status)
        ),
    );
    tool(
        "dpkg",
        format!(
            "read -r code < {n}.code\necho amd64\nexit $code\n",
            n = quote(&native)
        ),
    );
    let held = |code: i32| Detection::Undetermined {
        reason: format!("detection failed: the probe exited {code}"),
    };

    let mut checked = Vec::new();
    for (label, shell, path) in test_shells(dir.path(), &["grep"], Some(&bin)) {
        std::fs::write(native.with_extension("code"), "0\n").unwrap();
        for declared in ["curl", "curl=1.0", "curl:amd64", "curl:amd64=1.0"] {
            for (code, detection) in [
                (0, Detection::Converged),
                (1, Detection::Converged),
                (2, held(zap_types::package_managers::QUERY_FAILED_EXIT)),
                (126, held(zap_types::package_managers::QUERY_FAILED_EXIT)),
                (127, held(zap_types::package_managers::QUERY_FAILED_EXIT)),
                (3, held(zap_types::package_managers::QUERY_FAILED_EXIT)),
            ] {
                std::fs::write(&status, format!("{code}\n")).unwrap();
                assert_eq!(
                    apt_package(&shell, path.as_ref(), declared).await,
                    detection,
                    "{label}: {declared} exiting {code}"
                );
            }
        }
        std::fs::write(&status, "0\n").unwrap();
        std::fs::write(native.with_extension("code"), "2\n").unwrap();
        assert_eq!(
            apt_package(&shell, path.as_ref(), "curl:amd64").await,
            held(zap_types::package_managers::QUERY_FAILED_EXIT),
            "{label}: the architecture unread"
        );
        // A name with no architecture doesn't read it.
        assert_eq!(
            apt_package(&shell, path.as_ref(), "curl").await,
            Detection::Converged,
            "{label}"
        );
        checked.push(label);
    }
    eprintln!("failed apt package query checked under: {checked:?}");
}

/// `name:all` is refused when a `package` is parsed: apt reads `all` as the native
/// architecture, so `apt-get install name:all` installs `name:<native>`, which an
/// `installed all` line would never match.
fn assert_apt_all_refused() {
    for name in ["tzdata:all", "plain:all", "libc6:all=2.36-9"] {
        let error = serde_json::from_value::<zap_types::schema::PackageResource>(
            serde_json::json!({"from": {"apt": name}}),
        )
        .unwrap_err()
        .to_string();
        assert!(
            error.contains("names `:all`, which apt reads as the native architecture"),
            "{name}: {error}"
        );
    }
}

/// The apt `package` query against the host's own `dpkg-query`, reading a status
/// database of the test's (`DPKG_ADMINDIR`): the fields it asks for are ones this
/// `dpkg-query` has, a held package and a package installed for one architecture of two
/// are installed, a half-installed or removed one isn't, a name with a suite is found
/// by its name, and a name with a version is installed only at exactly that version —
/// its epoch and revision included; a name with an architecture is installed by that
/// architecture's instance, or an `all` one for the native architecture alone. Each
/// answer is the exit 0 or 1 the package detector reads, and a status database
/// `dpkg-query` can't parse exits [`QUERY_FAILED_EXIT`], which holds. Checks nothing on
/// a host without `dpkg-query`.
#[test]
fn the_apt_package_query_reads_a_real_status_database() {
    use std::fmt::Write as _;
    use zap_types::package_managers::QUERY_FAILED_EXIT;

    let has_dpkg_query = std::process::Command::new("dpkg-query")
        .arg("--version")
        .output()
        .is_ok_and(|output| output.status.success());
    if !has_dpkg_query {
        eprintln!("apt package query not checked against dpkg-query: none on PATH");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir(dir.path().join("updates")).unwrap();
    std::fs::create_dir(dir.path().join("info")).unwrap();
    std::fs::write(dir.path().join("arch"), "amd64\ni386\n").unwrap();
    let mut status = String::new();
    for (package, state, architecture, version) in [
        ("plain", "install ok installed", "all", "1.0-1"),
        ("epoch", "install ok installed", "all", "1:4.17.4-2"),
        ("dotless", "install ok installed", "all", "1x0-1"),
        ("held", "hold ok installed", "all", "1.0-1"),
        ("half", "install ok half-installed", "all", "1.0-1"),
        ("unpacked", "install ok unpacked", "all", "1.0-1"),
        ("gone", "deinstall ok config-files", "all", "1.0-1"),
        ("both", "install ok installed", "amd64", "1.0-1"),
        ("both", "install ok installed", "i386", "1.0-1"),
        ("mixed", "deinstall ok config-files", "amd64", "1.0-1"),
        ("mixed", "install ok installed", "i386", "1.0-2"),
    ] {
        let multi_arch = if architecture == "all" {
            ""
        } else {
            "Multi-Arch: same\n"
        };
        write!(
            status,
            "Package: {package}\nStatus: {state}\nPriority: optional\nSection: misc\n\
             Installed-Size: 1\nMaintainer: zap <zap@example.invalid>\n\
             Architecture: {architecture}\n{multi_arch}Version: {version}\nDescription: {package}\n\n"
        )
        .unwrap();
    }
    std::fs::write(dir.path().join("status"), status).unwrap();

    for (declared, installed) in [
        ("plain", true),
        ("plain/stable", true),
        ("held", true),
        ("half", false),
        ("unpacked", false),
        ("gone", false),
        ("both", true),
        ("mixed", true),
        ("mixed:i386", true),
        ("mixed:amd64", false),
        ("both:i386", true),
        ("absent", false),
        // A declared version is that version, whole: another revision, a prefix either
        // way, and a version with or without the epoch the package has are not it.
        ("plain=1.0-1", true),
        ("plain=1.0-2", false),
        ("plain=2.0-1", false),
        ("plain=1.0", false),
        ("plain=1.0-10", false),
        ("plain=1x0-1", false),
        // a `.` in the declared version is a dot, not any character
        ("dotless=1.0-1", false),
        ("dotless=1x0-1", true),
        ("epoch=1:4.17.4-2", true),
        ("epoch=4.17.4-2", false),
        ("plain=1:1.0-1", false),
        ("held=1.0-1", true),
        ("held=1.0-2", false),
        ("half=1.0-1", false),
        ("gone=1.0-1", false),
        ("both=1.0-1", true),
        // one instance at the version, installed; the other at it, removed
        ("mixed=1.0-2", true),
        ("mixed=1.0-1", false),
        ("mixed:i386=1.0-2", true),
        ("mixed:amd64=1.0-1", false),
        ("absent=1.0-1", false),
        // a version and a suite together name no package, as apt reads them
        ("plain=1.0-1/stable", false),
        ("plain/stable=1.0-1", false),
    ] {
        let query =
            zap_types::package_managers::query(zap_types::schema::PackageManager::Apt, declared)
                .unwrap();
        let output = std::process::Command::new("sh")
            .args(["-c", &query])
            .env("DPKG_ADMINDIR", dir.path())
            .output()
            .unwrap();
        assert_eq!(
            output.status.code(),
            Some(i32::from(!installed)),
            "{declared}: {query}: {output:?}"
        );
    }

    // `name:all` is refused at parse, so no query of it runs against the database.
    assert_apt_all_refused();
    // An `all` package is the native architecture's, and no other's.
    let native = std::process::Command::new("dpkg")
        .arg("--print-architecture")
        .output()
        .unwrap();
    let native = String::from_utf8(native.stdout).unwrap();
    let native = native.trim();
    let foreign = if native == "i386" { "amd64" } else { "i386" };
    // A status database `dpkg-query` can't parse is a read that failed, whatever the form.
    let broken = tempfile::tempdir().unwrap();
    std::fs::create_dir(broken.path().join("updates")).unwrap();
    std::fs::write(broken.path().join("status"), "garbage\n").unwrap();
    for (declared, admin, code) in [
        (format!("plain:{native}"), dir.path(), 0),
        (format!("plain:{native}=1.0-1"), dir.path(), 0),
        (format!("plain:{foreign}"), dir.path(), 1),
        ("plain".to_owned(), broken.path(), QUERY_FAILED_EXIT),
        ("plain=1.0-1".to_owned(), broken.path(), QUERY_FAILED_EXIT),
        (format!("plain:{native}"), broken.path(), QUERY_FAILED_EXIT),
    ] {
        let query =
            zap_types::package_managers::query(zap_types::schema::PackageManager::Apt, &declared)
                .unwrap();
        let output = std::process::Command::new("sh")
            .args(["-c", &query])
            .env("DPKG_ADMINDIR", admin)
            .output()
            .unwrap();
        assert_eq!(
            output.status.code(),
            Some(code),
            "{declared}: {query}: {output:?}"
        );
    }
}
