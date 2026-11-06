use std::ffi::OsString;
use std::os::unix::fs::{PermissionsExt as _, symlink};
use std::time::Duration;

use zap_types::observe::{
    FileKind, Lane, Observation, PathFacet, PathObservation, Privilege, Query, QueryError,
};

use super::support::{busybox_applets, path_query, run_under};
use crate::connection::observe::local::observe_local;
use crate::connection::observe::{by_privilege, in_order, run_lanes};
use crate::digest::sha512_hex;

/// The parity guard for the Local runner: every path fact read natively must equal
/// what the rendered shell probe reads through the batch — under the system `sh` with
/// its tools, and under `BusyBox` with only its applets on `PATH` — over files,
/// directories, symlinks (live, dangling, to a directory), a fifo, a character
/// device, setuid / setgid / sticky modes, names with spaces and quotes, a `0700`
/// parent the test user owns, directories it may list but not traverse, and a parent it
/// can't traverse at all (`BusyBox`'s `ls` can't list a non-empty directory it can't
/// traverse; that read holds). An unknown owner id isn't covered: making one needs
/// `chown`, which needs root.
#[tokio::test]
async fn native_path_answers_match_the_shell_probes() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("tree");
    std::fs::create_dir(&root).unwrap();
    let file = root.join("it's a file.txt");
    std::fs::write(&file, "x").unwrap();
    std::fs::write(root.join("longer"), "0123456789\n").unwrap();
    std::fs::write(root.join("exact"), "0123").unwrap();
    std::fs::write(root.join("empty"), "").unwrap();
    std::fs::write(root.join("binary"), b"\0\xff\n\x80").unwrap();
    std::fs::write(root.join("hard linked"), "x").unwrap();
    std::fs::hard_link(root.join("hard linked"), root.join("hard linked twin")).unwrap();
    let sub = root.join("a dir");
    std::fs::create_dir(&sub).unwrap();
    symlink(&file, root.join("link to file")).unwrap();
    symlink(&sub, root.join("link to dir")).unwrap();
    symlink(root.join("nowhere"), root.join("dangling")).unwrap();
    // Targets whose blanks are their own: `readlink`'s line break is the only one off.
    symlink("/srv/app ", root.join("blank after")).unwrap();
    symlink(" /srv/app", root.join("blank before")).unwrap();
    symlink("/srv/app\n", root.join("newline after")).unwrap();
    let fifo_made = std::process::Command::new("mkfifo")
        .arg(root.join("fifo"))
        .status()
        .is_ok_and(|status| status.success());
    for (name, mode) in [("setuid", 0o4755), ("setgid", 0o2755)] {
        std::fs::write(root.join(name), "x").unwrap();
        std::fs::set_permissions(root.join(name), std::fs::Permissions::from_mode(mode)).unwrap();
    }
    std::fs::create_dir(root.join("sticky")).unwrap();
    std::fs::set_permissions(root.join("sticky"), std::fs::Permissions::from_mode(0o1777)).unwrap();
    let private = root.join("private");
    std::fs::create_dir(&private).unwrap();
    std::fs::write(private.join("inside"), "x").unwrap();
    std::fs::set_permissions(&private, std::fs::Permissions::from_mode(0o700)).unwrap();
    // Readable, not traversable: listing needs only the read bit, natively and for `ls`.
    let listable = [root.join("listable"), root.join("listable empty")];
    std::fs::create_dir(&listable[0]).unwrap();
    std::fs::write(listable[0].join("inside"), "x").unwrap();
    std::fs::create_dir(&listable[1]).unwrap();
    for dir in &listable {
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o400)).unwrap();
    }
    let locked = root.join("locked");
    std::fs::create_dir(&locked).unwrap();
    std::fs::write(locked.join("inside"), "x").unwrap();
    symlink(&file, locked.join("link")).unwrap();
    std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000)).unwrap();

    let mut paths: Vec<String> = [
        "it's a file.txt",
        "a dir",
        "link to file",
        "link to dir",
        "dangling",
        "blank after",
        "blank before",
        "newline after",
        "absent",
        "setuid",
        "setgid",
        "sticky",
        "private",
        "private/inside",
        "listable",
        "listable empty",
        "locked",
        "locked/inside",
        "locked/link",
        "longer",
        "exact",
        "empty",
        "binary",
        "hard linked",
    ]
    .iter()
    .map(|name| root.join(name).to_string_lossy().into_owned())
    .collect();
    paths.push("/dev/null".to_owned());
    let mut queries: Vec<Query> = paths
        .iter()
        .flat_map(|path| {
            [
                PathFacet::Kind,
                PathFacet::Lstat,
                PathFacet::LinkTarget,
                PathFacet::Digest,
                PathFacet::Read { max: 4 },
                PathFacet::Empty,
            ]
            .map(|facet| path_query(path, facet))
        })
        .collect();
    // A fifo's content reads open nothing on either side; its emptiness read would
    // block `ls`, never the native read, and isn't asked.
    if fifo_made {
        let fifo = root.join("fifo").to_string_lossy().into_owned();
        queries.extend(
            [
                PathFacet::Kind,
                PathFacet::Lstat,
                PathFacet::LinkTarget,
                PathFacet::Digest,
                PathFacet::Read { max: 4 },
            ]
            .map(|facet| path_query(&fifo, facet)),
        );
    }

    let native = observe_local(&queries).await;
    let mut shells: Vec<(&str, std::path::PathBuf, Option<OsString>)> =
        vec![("sh", "sh".into(), None)];
    // `ls` answers the emptiness reads; a batch without one doesn't need it.
    if let Some(applets) = busybox_applets(dir.path(), &["ls"]) {
        shells.push((
            "busybox",
            applets.join("sh"),
            Some(applets.into_os_string()),
        ));
    }
    let listable_full = listable[0].to_string_lossy().into_owned();
    let mut mismatches = Vec::new();
    for (name, shell, path) in &shells {
        let run = |_lane: Lane, script: String, _deadline: Duration| {
            run_under(shell, path.clone(), script)
        };
        let (answered, batches, _) =
            run_lanes(&by_privilege(&queries, Privilege::local_lane), run).await;
        if batches.len() != 1 {
            mismatches.push(format!("{name}: {} batches, expected one", batches.len()));
        }
        let shelled = in_order(queries.len(), answered);
        for ((query, native), shelled) in queries.iter().zip(&native.results).zip(&shelled) {
            // `BusyBox` `ls` stats each entry it lists, which a directory it can't
            // traverse denies, so it fails where the native read and GNU `ls` list it:
            // the read holds either way.
            let busybox_denied = *name == "busybox"
                && *query == path_query(&listable_full, PathFacet::Empty)
                && *shelled == Ok(Observation::Path(PathObservation::Failed));
            if native != shelled && !busybox_denied {
                mismatches.push(format!(
                    "{name}: {query:?}\n  native {native:?}\n  shell  {shelled:?}"
                ));
            }
        }
    }
    // Restore traversal before asserting, so the tempdir can clean up either way.
    for dir in listable.iter().chain([&locked]) {
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    assert!(mismatches.is_empty(), "{}", mismatches.join("\n"));
    eprintln!(
        "parity checked under: {:?}",
        shells.iter().map(|s| s.0).collect::<Vec<_>>()
    );

    // The sanity half: the fixture really exercises what it claims.
    let answer = |path: &str, facet| {
        let index = queries
            .iter()
            .position(|q| *q == path_query(path, facet))
            .unwrap();
        native.results[index].clone()
    };
    let at = |name: &str| root.join(name).to_string_lossy().into_owned();
    assert_eq!(
        answer(&at("link to dir"), PathFacet::Kind),
        Ok(Observation::Path(PathObservation::Kind(
            FileKind::Directory
        )))
    );
    assert_eq!(
        answer("/dev/null", PathFacet::Kind),
        Ok(Observation::Path(PathObservation::Kind(FileKind::Other)))
    );
    assert!(matches!(
        answer(&at("setuid"), PathFacet::Lstat),
        Ok(Observation::Path(PathObservation::Metadata(m))) if m.mode == "4755"
    ));
    assert_eq!(
        answer(&at("dangling"), PathFacet::LinkTarget),
        Ok(Observation::Path(PathObservation::LinkTarget(
            at("nowhere").into_bytes()
        )))
    );
    for (name, target) in [
        ("blank after", &b"/srv/app "[..]),
        ("blank before", b" /srv/app"),
        ("newline after", b"/srv/app\n"),
    ] {
        assert_eq!(
            answer(&at(name), PathFacet::LinkTarget),
            Ok(Observation::Path(PathObservation::LinkTarget(
                target.to_vec()
            ))),
            "{name}"
        );
    }
    assert_eq!(
        answer(&at("dangling"), PathFacet::Kind),
        Ok(Observation::Path(PathObservation::Failed))
    );
    // A directory's emptiness, through a link too; anything else isn't listed.
    for (name, empty) in [
        ("a dir", true),
        ("link to dir", true),
        ("private", false),
        ("listable", false),
        ("listable empty", true),
    ] {
        assert_eq!(
            answer(&at(name), PathFacet::Empty),
            Ok(Observation::Path(PathObservation::Empty(empty))),
            "{name}"
        );
    }
    assert_eq!(
        answer(&at("it's a file.txt"), PathFacet::Empty),
        Ok(Observation::Path(PathObservation::Failed))
    );
    // As anyone but root, the untraversable parent hides its entries.
    if !nix::unistd::geteuid().is_root() {
        assert_eq!(
            answer(&at("locked/inside"), PathFacet::Lstat),
            Ok(Observation::Path(PathObservation::Failed))
        );
    }
    assert_eq!(
        answer(&at("exact"), PathFacet::Read { max: 4 }),
        Ok(Observation::Path(PathObservation::Contents {
            bytes: b"0123".to_vec(),
            truncated: false,
        }))
    );
    assert_eq!(
        answer(&at("longer"), PathFacet::Read { max: 4 }),
        Ok(Observation::Path(PathObservation::Contents {
            bytes: b"0123".to_vec(),
            truncated: true,
        }))
    );
    assert_eq!(
        answer(&at("it's a file.txt"), PathFacet::Digest),
        Ok(Observation::Path(PathObservation::Digest(sha512_hex(b"x"))))
    );
    // The content reads open only a regular file of its own: a link to one, a dangling
    // link, a directory, and a device are each no regular file, and an absent path is
    // nothing at all.
    for name in ["link to file", "dangling", "link to dir", "a dir"] {
        for facet in [PathFacet::Digest, PathFacet::Read { max: 4 }] {
            assert_eq!(
                answer(&at(name), facet),
                Ok(Observation::Path(PathObservation::NotRegular)),
                "{name} {facet:?}"
            );
        }
    }
    assert_eq!(
        answer("/dev/null", PathFacet::Digest),
        Ok(Observation::Path(PathObservation::NotRegular))
    );
    // A regular file with a second hard link is read by neither: it holds, whoever owns
    // it.
    for facet in [PathFacet::Digest, PathFacet::Read { max: 4 }] {
        assert_eq!(
            answer(&at("hard linked"), facet),
            Err(QueryError::HardLinked),
            "{facet:?}"
        );
    }
    if fifo_made {
        assert_eq!(
            answer(&at("fifo"), PathFacet::Read { max: 4 }),
            Ok(Observation::Path(PathObservation::NotRegular))
        );
    }
    assert_eq!(
        answer(&at("absent"), PathFacet::Digest),
        Ok(Observation::Path(PathObservation::Failed))
    );
}
