//! `cargo xtask differential` argument parsing (manual, like the rest of xtask).

use std::path::PathBuf;

use super::compare::Level;
use super::oracle::{DEFAULT_REV, OracleSource};
use super::runner::Side;
use super::vm::Distro;

pub const USAGE: &str = "\
cargo xtask differential — oracle vs candidate zap over a VM scenario matrix

Usage:
  cargo xtask differential [--oracle <path> | --oracle-rev <rev>] [options]

Runs two zap binaries — a trusted ORACLE and a CANDIDATE — against the same
target states and fails if their `detect --no-cache`, `plan --no-cache --diff`,
or `plan --no-cache` output differs. Each distro's VM is reverted to a converged
kitchen-sink snapshot, one scenario's mutation is applied, and both binaries
detect and plan it. Each binary evaluates its own copy of the fixtures and reads
the `zap.lock` it minted there.

The snapshot is built by one of the two binaries (`--base-by`): from `pristine`
it previews the kitchen sink and applies the previewed plan, in the rounds the
fixture declares, and a further apply must plan nothing.

A scenario is an ERROR rather than a verdict when it proves nothing: the oracle's
output isn't a well-formed report, the oracle didn't see exactly the resources
move that the scenario expects, a run timed out, the runs fetched remote content
or wrote to the target, or the candidate's own output is inconsistent (its plans
of one state disagree on `plan_hash`, a plan doesn't name its machine, or a line
holds a raw control character).

Some scenarios then reconverge: the candidate alone applies the drifted state
back (a preview that plans exactly the drifted resources, its wetrun, a further
preview that plans nothing but `pipeline`, a `detect` that reads every resource
but the `pipeline` ok), and a probe that never goes through zap must read what
it read on the base. A failure there is an ERROR tagged [reconverge].

One scenario, bootstrap-replace, compares nothing: the candidate alone replaces
the VM's bootstrap user in place. It provisions `zapnext` with `apply --bootstrap`
as `ops`, proves the new user logs in and holds zap's sudo grant and `ops`'s keys,
retires `ops` over `zapnext`'s own login (`userdel -r`, never forced), and then
plans as `zapnext`. The revert after it brings `ops` back.

Options:
  --oracle <path>      the reference zap binary: one that keeps its ssh control
                       sockets under its ZAP_HOME, or the run stops
  --oracle-rev <rev>   build the oracle from this committed revision instead
                       (default: origin/main, as the local ref stands; nothing is
                       fetched). The build is kept as ~/.zap/oracle/zap-<short-rev>
                       and reused while it is there (delete it to rebuild);
                       otherwise the revision's tree is `git archive`d into a
                       temporary directory under ~/.cache/zap-differential,
                       linked to the sibling checkouts its Cargo.toml names — as
                       they stand now, uncommitted changes included, not at the
                       revision — built with `cargo build --release -p zap` under
                       the revision's own toolchain, copied into place, and
                       removed
  --candidate <path>   the zap under test (default: `cargo build --release -p zap`
                       from the working tree, then the executable cargo built)
  --distro <name>      alpine | debian; repeatable (default: both)
  --scenario <name>    run only this scenario; repeatable (default: all)
  --compare <level>    exact | semantic (default: exact). `exact` compares the
                       output byte for byte. `semantic` compares what was decided
                       and leaves out how it is rendered: each plan's machine
                       block, the lines under a change other than its trigger and
                       `--diff` attribute lines, and the value of `plan_hash`; for
                       an oracle that renders a plan differently by design
  --base-by <side>     oracle | candidate (default: oracle): the binary that
                       builds the base snapshot. What a fixture declares held
                       from `pristine` is expected of whichever side builds
  --keep               leave the VM as the run left it: in the last scenario's
                       state (no final revert to the base, and no reconverge, so
                       a reconverging scenario stays drifted), or half-built
                       after a failed base build (no revert to pristine).
                       bootstrap-replace stops before it retires `ops`: a VM
                       left without `ops` stops the next run before any revert
  --rebase             rebuild the base snapshot even if its hash is unchanged
                       (the hash covers `pristine`, the fixtures and what they
                       import, the builder, the fgro build, the test CA, and the
                       distro's preparation)
  -h, --help           show this help

Prerequisites:
  the libvirt VMs `alpine-zap` (192.168.122.10) and `debian-zap` (192.168.122.11),
  each with a `pristine` snapshot and an `ops` user with NOPASSWD sudo that your
  SSH key reaches — see docs/testing.md. `ZAP_FGRO`, the absolute path of the
  fgro build both binaries evaluate the fixtures with: each run is given it as
  `--fgro`, the Debian VM a copy in the local bundle, and every staged config a
  `zap.lock` pinning it. Both binaries must evaluate through fgro (one that takes
  no `--fgro` is refused before a VM is touched). GNU `tar`
  and `gzip` (the served tarball), `ping` (waiting out a revert), and — the first
  time — `openssl`: what a guest fetches is served over https under a test CA made
  once and kept in ~/.cache/zap-differential/pki, which the fixtures install in each
  guest's trust store. The libvirt `default` network must be active: the origin
  listens on its address (192.168.122.1).

Exit status: 0 when every scenario matches, 1 on any divergence or harness error,
2 on a usage error.
";

/// Parsed `differential` arguments.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Args {
    pub oracle: OracleSource,
    pub candidate: Option<PathBuf>,
    pub distros: Vec<Distro>,
    pub scenarios: Vec<String>,
    pub level: Level,
    pub base_by: Side,
    pub keep: bool,
    pub rebase: bool,
}

/// What the command line asked for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Parsed {
    Run(Args),
    Help,
}

/// Parse the arguments after `differential`.
///
/// # Errors
/// A usage error, as a message.
pub fn parse(args: &[String]) -> Result<Parsed, String> {
    let mut oracle = None;
    let mut oracle_rev = None;
    let mut candidate = None;
    let mut distros = Vec::new();
    let mut scenarios = Vec::new();
    let (mut level, mut base_by) = (Level::Exact, Side::Oracle);
    let (mut keep, mut rebase) = (false, false);

    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        let (flag, inline) = match arg.split_once('=') {
            Some((flag, value)) if flag.starts_with("--") => (flag, Some(value.to_owned())),
            _ => (arg.as_str(), None),
        };
        let mut value = || {
            inline
                .clone()
                .or_else(|| iter.next().cloned())
                .filter(|v| !v.is_empty())
                .ok_or_else(|| format!("`{flag}` needs a value"))
        };
        match flag {
            "-h" | "--help" => return Ok(Parsed::Help),
            "--oracle" => oracle = Some(PathBuf::from(value()?)),
            "--oracle-rev" => oracle_rev = Some(value()?),
            "--candidate" => candidate = Some(PathBuf::from(value()?)),
            "--distro" => {
                let name = value()?;
                let distro = Distro::parse(&name)
                    .ok_or_else(|| format!("unknown distro `{name}` (alpine | debian)"))?;
                if !distros.contains(&distro) {
                    distros.push(distro);
                }
            }
            "--scenario" => scenarios.push(value()?),
            "--compare" => {
                let name = value()?;
                level = Level::parse(&name)
                    .ok_or_else(|| format!("unknown compare level `{name}` (exact | semantic)"))?;
            }
            "--base-by" => {
                let name = value()?;
                base_by = Side::parse(&name)
                    .ok_or_else(|| format!("unknown base builder `{name}` (oracle | candidate)"))?;
            }
            "--keep" | "--rebase" if inline.is_some() => {
                return Err(format!("`{flag}` takes no value"));
            }
            "--keep" => keep = true,
            "--rebase" => rebase = true,
            other => return Err(format!("unknown argument `{other}`")),
        }
    }
    let oracle = match (oracle, oracle_rev) {
        (Some(_), Some(_)) => {
            return Err("`--oracle` and `--oracle-rev` each name the oracle: give one".to_owned());
        }
        (Some(path), None) => OracleSource::Binary(path),
        (None, rev) => OracleSource::Rev(rev.unwrap_or_else(|| DEFAULT_REV.to_owned())),
    };
    if distros.is_empty() {
        distros = Distro::ALL.to_vec();
    }
    distros.sort();
    Ok(Parsed::Run(Args {
        oracle,
        candidate,
        distros,
        scenarios,
        level,
        base_by,
        keep,
        rebase,
    }))
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::{Args, Parsed, parse};
    use crate::differential::compare::Level;
    use crate::differential::oracle::OracleSource;
    use crate::differential::runner::Side;
    use crate::differential::vm::Distro;

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| (*s).to_owned()).collect()
    }

    fn run(list: &[&str]) -> Args {
        match parse(&args(list)) {
            Ok(Parsed::Run(args)) => args,
            other => panic!("expected a run, got {other:?}"),
        }
    }

    #[test]
    fn defaults_to_every_distro_and_scenario() {
        let parsed = run(&[]);
        assert_eq!(parsed.oracle, OracleSource::Rev("origin/main".to_owned()));
        assert_eq!(parsed.candidate, None);
        assert_eq!(parsed.distros, Distro::ALL);
        assert!(parsed.scenarios.is_empty());
        assert!(!parsed.keep && !parsed.rebase);
        assert_eq!(parsed.level, Level::Exact);
        assert_eq!(parsed.base_by, Side::Oracle);
    }

    #[test]
    fn the_oracle_is_a_path_or_a_revision() {
        assert_eq!(
            run(&["--oracle", "/o/zap"]).oracle,
            OracleSource::Binary(PathBuf::from("/o/zap"))
        );
        assert_eq!(
            run(&["--oracle-rev", "v0.3.0"]).oracle,
            OracleSource::Rev("v0.3.0".to_owned())
        );
        assert_eq!(
            run(&["--oracle-rev=abc1234"]).oracle,
            OracleSource::Rev("abc1234".to_owned())
        );
    }

    #[test]
    fn compare_level_and_base_builder_parse() {
        let parsed = run(&[
            "--oracle",
            "o",
            "--compare",
            "semantic",
            "--base-by=candidate",
        ]);
        assert_eq!(parsed.level, Level::Semantic);
        assert_eq!(parsed.base_by, Side::Candidate);
        let parsed = run(&["--oracle", "o", "--compare=exact", "--base-by", "oracle"]);
        assert_eq!(parsed.level, Level::Exact);
        assert_eq!(parsed.base_by, Side::Oracle);
        // the last one given wins, like every other single-valued flag
        let parsed = run(&["--oracle", "o", "--compare=semantic", "--compare=exact"]);
        assert_eq!(parsed.level, Level::Exact);
    }

    #[test]
    fn accepts_separate_and_inline_values() {
        let parsed = run(&[
            "--oracle=/o",
            "--candidate",
            "/c",
            "--distro=debian",
            "--scenario",
            "swap-off",
            "--scenario=converged",
            "--keep",
            "--rebase",
        ]);
        assert_eq!(parsed.oracle, OracleSource::Binary(PathBuf::from("/o")));
        assert_eq!(parsed.candidate, Some(PathBuf::from("/c")));
        assert_eq!(parsed.distros, [Distro::Debian]);
        assert_eq!(parsed.scenarios, ["swap-off", "converged"]);
        assert!(parsed.keep && parsed.rebase);
    }

    #[test]
    fn distros_dedupe_and_sort() {
        let parsed = run(&[
            "--oracle", "o", "--distro", "debian", "--distro", "alpine", "--distro", "debian",
        ]);
        assert_eq!(parsed.distros, [Distro::Alpine, Distro::Debian]);
    }

    #[test]
    fn help_wins() {
        assert_eq!(parse(&args(&["--help"])), Ok(Parsed::Help));
        assert_eq!(
            parse(&args(&["--distro", "alpine", "-h"])),
            Ok(Parsed::Help)
        );
    }

    #[test]
    fn usage_errors() {
        let error = |list: &[&str]| parse(&args(list)).expect_err("usage error");
        assert!(error(&["--oracle"]).contains("needs a value"));
        assert!(error(&["--oracle-rev"]).contains("needs a value"));
        assert!(error(&["--oracle-rev="]).contains("needs a value"));
        assert!(error(&["--oracle", "o", "--oracle-rev", "main"]).contains("give one"));
        assert!(error(&["--oracle-rev=main", "--oracle=o"]).contains("give one"));
        assert!(error(&["--oracle", "o", "--distro", "arch"]).contains("unknown distro"));
        assert!(error(&["--oracle", "o", "--bogus"]).contains("unknown argument"));
        assert!(error(&["--oracle", "o", "--keep=yes"]).contains("takes no value"));
        assert!(error(&["--oracle", "o", "--compare", "loose"]).contains("unknown compare level"));
        assert!(error(&["--oracle", "o", "--compare"]).contains("needs a value"));
        assert!(error(&["--oracle", "o", "--base-by", "both"]).contains("unknown base builder"));
        assert!(error(&["--oracle", "o", "--base-by="]).contains("needs a value"));
    }
}
