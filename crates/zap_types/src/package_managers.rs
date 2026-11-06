//! Package-manager command templates (pure).
//!
//! **apt** and **apk** (Alpine) are implemented (the supported hosts are
//! Debian/Ubuntu and Alpine); `brew`/`pacman` have no backend
//! (their arms return `None`). Each is a
//! pure command-string builder, consumed two ways: detection reads `query`; the
//! planner reads `install` / `update_cache` to populate `Change.steps` so the
//! dry-run shows the exact commands.
//!
//! Commands carry **no** `sudo` — the planner adds it where the operation needs it
//! (detection's `query` doesn't). This is the one home for that per-manager
//! knowledge, shared by the pure planner and `zap_core`'s detector.
//!
//! Version probing (`dpkg-query -f='${Version}'`) is **not** here yet — it returns
//! with the lock subsystem, whose `installed_version` entry is its real consumer.
//!
//! TODO: as the remaining targets (pacman/brew) appear, add backend arms to these
//! matches (the typed `PackageManager` enum forces each builder to handle every
//! variant).

use crate::schema::PackageManager;
use crate::shell::single_quote;

/// Command that exits 0 if `pkg` is installed under manager `pm` and 1 if it isn't;
/// any other status is a query that failed, which reads nothing. `None` for a manager
/// without a backend.
///
/// `pkg` is the name as the manager's install command takes it. For apt that may say
/// more than a name — `name=version`, `name/suite`, `name:arch` — which `dpkg-query`
/// matches no package by, so the query asks about the name (`AptPackage`) and prints,
/// one a line, the status word of each instance of the name dpkg has a record of — a
/// multi-arch package has one per architecture, and a removed package whose
/// configuration is left has one too. Any instance that satisfies it will do:
///
/// - A name, with or without a suite: a line that is `installed`, whole — so a
///   `half-installed` package isn't — and whatever the package is marked for (a held
///   package is installed). dpkg records no suite, so one is not compared.
/// - `name:arch`: a line that is `installed arch`, or — when `arch` is the target's own
///   (`dpkg --print-architecture`) — `installed all`: a package built for every
///   architecture is recorded as `all`, and counts as the native one's, as dpkg reads
///   it in a dependency and apt installs it for `name:<native>`.
/// - `name=version`: a line that is `installed <version>`, whole and as written:
///   the full version, its epoch and revision included, letter for letter, with no
///   ordering and no prefix. A package installed at any other version reads as not
///   installed, and the install that follows asks apt for the declared one: apt
///   upgrades to it, and refuses to downgrade to it, which fails the step.
///
/// `dpkg-query` exits 0 when it prints a record and 1 when it has none of the name; its
/// output is read only after one of those, and any other status — the status database
/// unreadable, `dpkg-query` missing — exits [`QUERY_FAILED_EXIT`], as does a
/// `dpkg --print-architecture` that fails. A read that fails
/// holds the package; it is never read as not installed.
///
/// [`apt_name_problem`] refuses, at parse, the apt forms this query would never find.
#[must_use]
pub fn query(pm: PackageManager, pkg: &str) -> Option<String> {
    match pm {
        PackageManager::Apt => {
            let AptPackage {
                name,
                arch,
                version,
            } = AptPackage::of(pkg);
            let mut fields = String::from("${db:Status-Status}");
            if arch.is_some() {
                fields.push_str(" ${Architecture}");
            }
            if version.is_some() {
                fields.push_str(" ${Version}");
            }
            // A whole line of the output, quoted: `installed`, then each of `words`.
            let line = |words: &[&str]| {
                single_quote(
                    &std::iter::once("installed")
                        .chain(words.iter().copied())
                        .collect::<Vec<_>>()
                        .join(" "),
                )
            };
            let version: Vec<&str> = version.into_iter().collect();
            let (native, read) = match arch {
                None if version.is_empty() => (String::new(), "grep -qx installed".to_owned()),
                None => (String::new(), format!("grep -qxF -e {}", line(&version))),
                // An `all` package counts as the native architecture's, as dpkg reads one
                // in a dependency: `$n` is `all` when the named architecture is native,
                // and the named one again when it isn't.
                Some(arch) => {
                    let quoted = single_quote(arch);
                    let tail = version
                        .first()
                        .map_or_else(String::new, |version| single_quote(&format!(" {version}")));
                    (
                        format!(
                            "n=$(dpkg --print-architecture 2>/dev/null) || exit \
                             {QUERY_FAILED_EXIT}; [ \"$n\" = {quoted} ] && n={APT_ARCH_ALL} || \
                             n={quoted}; "
                        ),
                        format!(
                            "grep -qxF -e {} -e \"installed $n\"{tail}",
                            line(&[&[arch], &version[..]].concat())
                        ),
                    )
                }
            };
            Some(format!(
                "s=$(dpkg-query -W -f='{fields}\\n' {name} 2>/dev/null); \
                 case $? in 0|1) ;; *) exit {QUERY_FAILED_EXIT};; esac; \
                 {native}printf '%s\\n' \"$s\" | {read}"
            ))
        }
        // `apk info -e <pkg>` exits with the count of the names it was given that aren't
        // installed, so for the one name here 0 if it is installed and 1 if not — the
        // contract the `package` detector reads (`observe::package`), verbatim. A name
        // ending in a version operator with no version after it is dropped, not counted,
        // so it exits 0: `apk_name_problem` refuses those at parse.
        PackageManager::Apk => Some(format!("apk info -e {pkg}")),
        PackageManager::Pacman | PackageManager::Brew => None,
    }
}

/// The status the apt [`query`] exits with when `dpkg-query` failed: neither 0 nor 1,
/// so the package holds.
pub const QUERY_FAILED_EXIT: i32 = 2;

/// The architecture dpkg records for a package built for every one.
const APT_ARCH_ALL: &str = "all";

/// What makes `pkg` an apt name the [`query`] would never find installed, or `None`.
///
/// apt reads these forms and installs a package for them, but `dpkg-query` records
/// none by them, so the package would read missing after every install:
///
/// - `name=` — a version that is empty;
/// - `name:` — an architecture that is empty;
/// - `name:any` and `name:native` — words apt resolves to an architecture, which dpkg
///   records no package under;
/// - `name:all` — apt reads `all` as the native architecture, so it installs the
///   native one's package, while dpkg records `all` only for a package built for every
///   architecture;
/// - `name:<arch>` where the architecture isn't one word of lowercase letters, digits
///   and `-`.
///
/// A trailing `+` is not refused: apt reads `name+` as `name` only when no package is
/// named `name+`, and Debian has packages that are (`memtest86+`), so the name is
/// asked about as written.
#[must_use]
pub fn apt_name_problem(pkg: &str) -> Option<String> {
    let AptPackage { arch, version, .. } = AptPackage::of(pkg);
    if version == Some("") {
        return Some("has an empty version after `=`".to_owned());
    }
    let arch = arch?;
    if arch.is_empty() {
        return Some("has an empty architecture after `:`".to_owned());
    }
    if arch == APT_ARCH_ALL {
        return Some(
            "names `:all`, which apt reads as the native architecture (name that \
             architecture, or none)"
                .to_owned(),
        );
    }
    if matches!(arch, "any" | "native") {
        return Some(format!(
            "names `:{arch}`, an architecture apt resolves and dpkg records nothing \
             under (name one, or none)"
        ));
    }
    let word = arch
        .bytes()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
    if !word || arch.starts_with('-') {
        return Some(format!("names `:{arch}`, which is no architecture"));
    }
    None
}

/// What makes `pkg` an apk name the [`query`] would read installed whether or not it
/// is, or `None`.
///
/// apk reads a name as `name(@tag)([<>~=]version)`, and the [`PackageName`] charset
/// leaves `=` and `~` of the operators. A name that ends in an operator, or a run of
/// them (`name=`, `name~`, `name==`, `name~=`, `name@tag=`), has an empty version:
/// `apk info -e` exits 0 for it with the package absent, as for no name at all, and
/// `apk add` refuses it as no valid dependency. The package would read converged and
/// never be installed.
///
/// Not refused, as `apk info -e` answers each truthfully:
///
/// - `name=version` and `name~version`: the query reads the constraint as apk does, so
///   a package installed at another version reads missing.
/// - `name@tag`: the query reads the name alone and ignores the tag, as the apt query
///   ignores a suite; the tag chooses where a first install comes from.
/// - `cmd:…`, `so:…`, `pc:…`: the query answers whether any installed package provides
///   it.
///
/// [`PackageName`]: crate::scalar::PackageName
#[must_use]
pub fn apk_name_problem(pkg: &str) -> Option<String> {
    let version_at = pkg.trim_end_matches(['=', '~']).len();
    let operator = &pkg[version_at..];
    (!operator.is_empty()).then(|| {
        format!("has an empty version after `{operator}` (write a version after it, or drop it)")
    })
}

/// What `apt-get install` was given, as apt reads it: the package `dpkg-query` is asked
/// about, the architecture a `name:arch` names, and the version a `name=version` pins.
#[derive(Debug, PartialEq, Eq)]
struct AptPackage<'a> {
    /// The package's name, without an architecture.
    name: &'a str,
    /// The architecture after a `:` in the name.
    arch: Option<&'a str>,
    /// The version after a `=`.
    version: Option<&'a str>,
}

impl<'a> AptPackage<'a> {
    /// Split `pkg` where apt does: at its last `=` or `/`, then the name at its `:`.
    /// What follows a `=` is a version; what follows a `/` is a suite, which is dropped;
    /// what follows the name's `:` is an architecture.
    ///
    /// apt takes one of `=` and `/`, never both: in `name/suite=version` the name it
    /// looks for is `name/suite`, and in `name=version/suite` it is `name=version`.
    /// Neither is a package, so `dpkg-query` finds none by it, the package reads as not
    /// installed, and the install that follows fails with apt's own message.
    fn of(pkg: &'a str) -> Self {
        let (name, version) = match pkg.rfind(['=', '/']) {
            Some(at) if pkg[at..].starts_with('=') => (&pkg[..at], Some(&pkg[at + 1..])),
            Some(at) => (&pkg[..at], None),
            None => (pkg, None),
        };
        let (name, arch) = name
            .split_once(':')
            .map_or((name, None), |(name, arch)| (name, Some(arch)));
        Self {
            name,
            arch,
            version,
        }
    }
}

/// Command that installs `pkgs` (one or more space-joined names) under manager
/// `pm`. `None` for a manager without a backend. Caller prepends `sudo`.
#[must_use]
pub fn install(pm: PackageManager, pkgs: &str) -> Option<String> {
    match pm {
        PackageManager::Apt => Some(format!(
            "DEBIAN_FRONTEND=noninteractive apt-get install -y {pkgs}"
        )),
        // Plain `apk add` (not `--no-cache`): the `update_cache` → `install` split
        // mirrors apt and uses the index `apk update` just refreshed; `--no-cache`
        // is for ephemeral containers and would defeat the batching's cache-update.
        PackageManager::Apk => Some(format!("apk add {pkgs}")),
        PackageManager::Pacman | PackageManager::Brew => None,
    }
}

/// Command that refreshes the package index under manager `pm`. `None` for a
/// manager without a backend. Caller prepends `sudo`.
#[must_use]
pub fn update_cache(pm: PackageManager) -> Option<String> {
    match pm {
        PackageManager::Apt => Some("apt-get update".to_owned()),
        PackageManager::Apk => Some("apk update".to_owned()),
        PackageManager::Pacman | PackageManager::Brew => None,
    }
}

#[cfg(test)]
mod tests {
    use super::{AptPackage, apk_name_problem, apt_name_problem, query};
    use crate::schema::PackageManager;

    /// The query's text before its `grep`, for `fields` over `name`, with `native`'s
    /// lines between.
    fn read_of(fields: &str, name: &str, native: &str) -> String {
        format!(
            "s=$(dpkg-query -W -f='{fields}\\n' {name} 2>/dev/null); \
             case $? in 0|1) ;; *) exit 2;; esac; {native}printf '%s\\n' \"$s\" | "
        )
    }

    /// What reads the target's architecture, for a name of the architecture `arch`.
    fn native_of(arch: &str) -> String {
        format!(
            "n=$(dpkg --print-architecture 2>/dev/null) || exit 2; \
             [ \"$n\" = '{arch}' ] && n=all || n='{arch}'; "
        )
    }

    #[test]
    fn the_apt_query_reads_the_status_word_of_each_instance() {
        assert_eq!(
            query(PackageManager::Apt, "curl").unwrap(),
            read_of("${db:Status-Status}", "curl", "") + "grep -qx installed"
        );
    }

    /// A declared version is asked for whole, as a fixed string: its epoch, its
    /// revision, and the `.` and `+` a pattern would read as something else.
    #[test]
    fn the_apt_query_of_a_declared_version_matches_the_status_and_the_version_whole() {
        assert_eq!(
            query(PackageManager::Apt, "nginx=1:1.24.0-1+b2~bookworm").unwrap(),
            read_of("${db:Status-Status} ${Version}", "nginx", "")
                + "grep -qxF -e 'installed 1:1.24.0-1+b2~bookworm'"
        );
        assert_eq!(
            query(PackageManager::Apt, "libc6:i386=2.36-9").unwrap(),
            read_of(
                "${db:Status-Status} ${Architecture} ${Version}",
                "libc6",
                &native_of("i386")
            ) + "grep -qxF -e 'installed i386 2.36-9' -e \"installed $n\"' 2.36-9'"
        );
        // The version is one quoted word whatever it holds.
        assert!(
            query(PackageManager::Apt, "a=1'; touch pwned; '")
                .unwrap()
                .ends_with(r"grep -qxF -e 'installed 1'\''; touch pwned; '\'''")
        );
    }

    /// An architecture is read from the record, not the name: an instance for it is
    /// installed, and so is one built for every architecture (`all`) when the one named
    /// is the target's own.
    #[test]
    fn the_apt_query_of_an_architecture_reads_it_or_all_when_native() {
        assert_eq!(
            query(PackageManager::Apt, "adduser:amd64").unwrap(),
            read_of(
                "${db:Status-Status} ${Architecture}",
                "adduser",
                &native_of("amd64")
            ) + "grep -qxF -e 'installed amd64' -e \"installed $n\""
        );
    }

    /// `dpkg-query` matches a package by its name, so what `apt-get install` takes
    /// beside one is no part of the name asked about: a suite is dropped, a version and
    /// an architecture are compared — split where apt splits.
    #[test]
    fn an_apt_package_is_split_where_apt_splits_it() {
        for (pkg, name, arch, version) in [
            ("nginx", "nginx", None, None),
            (
                "nginx=1.24.0-1~bookworm",
                "nginx",
                None,
                Some("1.24.0-1~bookworm"),
            ),
            ("nginx=1:1.24.0-1", "nginx", None, Some("1:1.24.0-1")),
            ("nginx/bookworm-backports", "nginx", None, None),
            ("libc6:amd64", "libc6", Some("amd64"), None),
            ("libc6:amd64=2.36-9", "libc6", Some("amd64"), Some("2.36-9")),
            ("libc6:i386/bookworm", "libc6", Some("i386"), None),
            ("g++", "g++", None, None),
            ("memtest86+", "memtest86+", None, None),
            ("python3.11", "python3.11", None, None),
            ("nginx=", "nginx", None, Some("")),
            ("nginx:", "nginx", Some(""), None),
            // apt takes a version or a suite, never both: the name it looks for holds
            // the other, and is no package.
            (
                "nginx/bookworm=1.24.0-1",
                "nginx/bookworm",
                None,
                Some("1.24.0-1"),
            ),
            ("nginx=1.24.0-1/bookworm", "nginx=1.24.0-1", None, None),
            ("a=b=c", "a=b", None, Some("c")),
        ] {
            assert_eq!(
                AptPackage::of(pkg),
                AptPackage {
                    name,
                    arch,
                    version
                },
                "{pkg}"
            );
            let query = query(PackageManager::Apt, pkg).unwrap();
            assert!(
                query.contains(&format!("\\n' {name} 2>/dev/null")),
                "{pkg}: {query}"
            );
            assert_eq!(query.contains("${Version}"), version.is_some(), "{pkg}");
            assert_eq!(query.contains("${Architecture}"), arch.is_some(), "{pkg}");
        }
        // A suite alone asks what the bare name asks.
        assert_eq!(
            query(PackageManager::Apt, "nginx/bookworm-backports"),
            query(PackageManager::Apt, "nginx")
        );
    }

    /// The apt forms `dpkg-query` never finds are refused, each by what it is; the
    /// forms the query reads, and a trailing `+`, are not.
    #[test]
    fn an_apt_name_the_query_never_finds_is_a_problem() {
        for (pkg, problem) in [
            ("nginx=", "has an empty version after `=`"),
            ("libc6:i386=", "has an empty version after `=`"),
            ("nginx:", "has an empty architecture after `:`"),
            ("nginx:=1.0", "has an empty architecture after `:`"),
            (
                "python3:any",
                "names `:any`, an architecture apt resolves and dpkg records nothing under \
                 (name one, or none)",
            ),
            (
                "libc6:native/bookworm",
                "names `:native`, an architecture apt resolves and dpkg records nothing \
                 under (name one, or none)",
            ),
            ("libc6:AMD64", "names `:AMD64`, which is no architecture"),
            ("libc6:-x", "names `:-x`, which is no architecture"),
            ("a:b:c", "names `:b:c`, which is no architecture"),
            (
                "tzdata:all",
                "names `:all`, which apt reads as the native architecture (name that \
                 architecture, or none)",
            ),
            (
                "tzdata:all=2024a-1",
                "names `:all`, which apt reads as the native architecture (name that \
                 architecture, or none)",
            ),
        ] {
            assert_eq!(apt_name_problem(pkg).as_deref(), Some(problem), "{pkg}");
        }
        for pkg in [
            "nginx",
            "g++",
            "memtest86+",
            "nginx=1:1.24.0-1",
            "libc6:amd64",
            "libc6:i386=2.36-9",
            "tzdata",
            "nginx/bookworm-backports",
            "linux-image-6.1.0-18-arm64:arm64",
        ] {
            assert_eq!(apt_name_problem(pkg), None, "{pkg}");
        }
    }

    /// An apk name that ends in a version operator, `=` or `~` or a run of them, with
    /// no version after it is refused, the operator named; the forms `apk info -e`
    /// reads, a tagged name included, are not.
    #[test]
    fn an_apk_name_the_query_always_finds_is_a_problem() {
        for (pkg, operator) in [
            ("nginx=", "="),
            ("nginx~", "~"),
            ("nginx==", "=="),
            ("nginx=~", "=~"),
            ("nginx~=", "~="),
            ("nginx~~", "~~"),
            ("nginx@edge=", "="),
            ("nginx@=", "="),
            ("cmd:git=", "="),
        ] {
            assert_eq!(
                apk_name_problem(pkg),
                Some(format!(
                    "has an empty version after `{operator}` (write a version after it, \
                     or drop it)"
                )),
                "{pkg}"
            );
        }
        for pkg in [
            "nginx",
            "busybox=1.37.0-r31",
            "busybox~1",
            "busybox~1.37.0-r31",
            "nginx@edge",
            "nginx@",
            "busybox@community=1.37.0-r31",
            "cmd:sh",
            "so:libc.musl-x86_64.so.1",
            "g++",
        ] {
            assert_eq!(apk_name_problem(pkg), None, "{pkg}");
        }
    }

    #[test]
    fn the_apk_query_is_the_name_as_declared() {
        // `apk info -e` is handed what `apk add` is: nothing is cut from it.
        assert_eq!(
            query(PackageManager::Apk, "nginx=1.24.0-r1").as_deref(),
            Some("apk info -e nginx=1.24.0-r1")
        );
        assert_eq!(query(PackageManager::Pacman, "nginx"), None);
        assert_eq!(query(PackageManager::Brew, "nginx"), None);
    }
}
