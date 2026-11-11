//! Building the `differential-base` snapshot: from `pristine`, prepare the host
//! (quiet Debian's background jobs, put Alpine's postgres in the state its fixture
//! expects), converge the kitchen sink(s) with the builder — one of the two binaries —
//! through reviewed applies, prove a further apply is a no-op, and snapshot.
//!
//! A fixture converges in the rounds it declares ([`FromPristine`]): one reviewed
//! apply when nothing is held from `pristine`, two when the builder's first pass
//! holds a declared set of resources that its second pass plans. The declaration is
//! expected of whichever side builds.

use std::time::Duration;

use super::compare;
use super::process::Captured;
use super::reviewed::{
    PREVIEW, WETRUN, change_of, check_idempotent, check_preview, plans_exactly, prints_plan_hash,
    summary_problem, with_report,
};
use super::runner::{self, HostRun, REMOTE_HARNESS_DIR, VmHome, VmRun, ZAP_TIMEOUT};
use super::scenarios::Suite;
use super::vm::{self, Distro};
use super::{Context, fixture};

const APPLY_TIMEOUT: Duration = Duration::from_mins(30);

/// Debian's periodic apt jobs, masked (and stopped) before the base apply. Left
/// alone they wake after a revert — the resumed guest's clock jump makes
/// `Persistent=` timers fire — and take the dpkg lock mid-apply or mid-scenario,
/// and write package state no scenario asked for.
const DEBIAN_QUIET: &str = "systemctl mask --now apt-daily.timer apt-daily-upgrade.timer \
     apt-daily.service apt-daily-upgrade.service unattended-upgrades.service";

/// The postgres major the Alpine fixture declares (`postgresql18`,
/// `alpine_postgres_setup({ version: 18 })` in `fixtures/differential/alpine/zap.ts`).
const ALPINE_POSTGRES_VERSION: &str = "18";

/// The file whose presence says the Alpine cluster is initialized: the one the
/// fixture's `alpine_postgres_setup` check tests.
fn alpine_cluster_marker() -> String {
    format!("/var/lib/postgresql/{ALPINE_POSTGRES_VERSION}/data/PG_VERSION")
}

/// The root script that puts Alpine's postgres in the state the fixture's
/// [`FromPristine`] expectation describes, whatever `pristine` held: the packages
/// installed (from a fresh index: the one `pristine` carries may name a build its
/// mirror has dropped), the cluster initialized (`marker` present), the service
/// stopped. Idempotent. The stop comes before the `setup`, which needs the server down
/// (the check and the action are the fixture's `alpine_postgres_setup` pair); the last
/// lines assert the state rather than trust the steps.
///
/// Stopped is `rc-service status` exiting 3 and nothing else: a crashed service
/// exits 32, and `OpenRC` still counts it started, so a later `start` would do nothing.
/// Written for busybox `ash` under `set -eu`.
fn alpine_prepare_script(marker: &str) -> String {
    let version = ALPINE_POSTGRES_VERSION;
    format!(
        "apk add --update-cache postgresql{version} postgresql{version}-openrc >/dev/null\n\
         state=0\n\
         rc-service postgresql status >/dev/null 2>&1 || state=$?\n\
         if [ \"$state\" -ne 3 ]; then\n\
         \x20 rc-service postgresql stop >/dev/null\n\
         fi\n\
         if ! test -e {marker}; then\n\
         \x20 rc-service postgresql setup >/dev/null\n\
         fi\n\
         if ! test -e {marker}; then\n\
         \x20 echo 'the cluster is not initialized: no {marker}' >&2\n\
         \x20 exit 1\n\
         fi\n\
         state=0\n\
         rc-service postgresql status >/dev/null 2>&1 || state=$?\n\
         if [ \"$state\" -ne 3 ]; then\n\
         \x20 echo \"postgresql is not stopped: its status exited $state\" >&2\n\
         \x20 exit 1\n\
         fi"
    )
}

/// The root script that prepares `distro`'s machine ahead of the base apply. It
/// decides what the base holds, so the base's identity covers it
/// (`fixture::base_hash`).
pub fn prepare_script(distro: Distro) -> String {
    match distro {
        Distro::Debian => DEBIAN_QUIET.to_owned(),
        Distro::Alpine => alpine_prepare_script(&alpine_cluster_marker()),
    }
}

/// A resource the builder's first pass from `pristine` holds, and the reason its
/// `UNDETERMINED` banner gives.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Hold {
    id: &'static str,
    reason: &'static str,
}

impl Hold {
    /// The line zap prints for it under the `UNDETERMINED` banner.
    fn line(self) -> String {
        format!("      {} — {}", self.id, self.reason)
    }
}

/// What the builder's first pass over a fixture reads from `pristine`, which is the
/// number of rounds the fixture converges in. It describes the fixture and its machine,
/// not a side: the oracle and the candidate are each held to it when they build, and a
/// zap that reads the machine differently fails the build.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FromPristine {
    /// Nothing is held: one reviewed apply converges it.
    Converges,
    /// These resources are held, and only these: detection can't read `first` and
    /// `rest` (never empty), and `behind` are the changes held behind them. The first
    /// apply makes them readable and a second reviewed apply plans them all.
    Holds {
        first: Hold,
        rest: &'static [Hold],
        behind: &'static [Hold],
    },
}

impl FromPristine {
    /// What a fixture's SSH kitchen sink declares. Alpine's starts with postgres
    /// installed and stopped ([`alpine_prepare_script`]), which zap reads as a
    /// `database` it can't determine until the fixture's service resource starts it.
    const fn of_ssh_fixture(distro: Distro) -> Self {
        match distro {
            Distro::Alpine => Self::Holds {
                first: Hold {
                    id: "database",
                    reason: "detection failed: the PostgreSQL catalog query exited 2",
                },
                rest: &[],
                behind: &[],
            },
            Distro::Debian => Self::Converges,
        }
    }

    /// What the local-connection fixture declares.
    const LOCAL_FIXTURE: Self = Self::Converges;

    /// The resources detection can't read.
    fn holds(self) -> Vec<Hold> {
        match self {
            Self::Converges => Vec::new(),
            Self::Holds { first, rest, .. } => {
                std::iter::once(first).chain(rest.iter().copied()).collect()
            }
        }
    }

    /// The changes held behind [`holds`](Self::holds).
    const fn behind(self) -> &'static [Hold] {
        match self {
            Self::Converges => &[],
            Self::Holds { behind, .. } => behind,
        }
    }
}

/// The ids of `holds`, for a message.
fn hold_ids(holds: &[Hold]) -> String {
    holds
        .iter()
        .map(|hold| hold.id)
        .collect::<Vec<_>>()
        .join(", ")
}

/// The base build's progress line for a converged fixture.
fn converged_line(fixture: &str, by: &str, expected: FromPristine) -> String {
    match expected {
        FromPristine::Converges => {
            format!("  base     {fixture} previewed and applied{by}; second apply is a no-op")
        }
        FromPristine::Holds { .. } => format!(
            "  base     {fixture} previewed and applied{by} in two rounds ({} held from \
             pristine); a further apply is a no-op",
            hold_ids(&every_hold(&expected.holds(), expected.behind()))
        ),
    }
}

/// Converge from `pristine` with the builder and snapshot the result as the base.
pub fn build_base(context: &Context, distro: Distro, hash: &str) -> Result<(), String> {
    let builder = context.base_by;
    vm::revert(distro, vm::PRISTINE)?;
    vm::wait_for_ssh(distro, Duration::from_secs(60))?;
    if distro == Distro::Debian {
        let quieted = vm::root_shell(distro, &prepare_script(distro), Duration::from_secs(120))?;
        if !quieted.success() {
            return Err(format!(
                "masking the apt timers failed: {}",
                quieted.describe_failure()
            ));
        }
        println!("  base     apt-daily timers and unattended-upgrades masked");
    }
    if distro == Distro::Alpine {
        let prepared = vm::root_shell(distro, &prepare_script(distro), Duration::from_secs(300))?;
        if !prepared.success() {
            return Err(format!(
                "preparing PostgreSQL failed: {}",
                prepared.describe_failure()
            ));
        }
        println!(
            "  base     postgresql{ALPINE_POSTGRES_VERSION} installed, its cluster initialized, \
             its service stopped"
        );
    }
    let home = context.homes.home(&format!("{}/base", distro.name()));
    let staged = context.staged(builder);
    let config = staged.ssh_config(distro);
    let content_url = context.content_url(Suite::Ssh);
    // the target's own fetches (the installer's script, an apt key) go to the origin,
    // which it trusts once the fixture has installed the test CA
    let origin_url = context.origin.base_url();
    let run = HostRun {
        distro,
        config: &config,
        cwd: &staged.root,
        content_url: &content_url,
        origin_url: &origin_url,
        fgro: &context.fgro,
        env: &[],
    };
    let expected = FromPristine::of_ssh_fixture(distro);
    // one `ZAP_HOME` for every apply: each wetrun binds to the preview recorded there
    apply_reviewed(
        &format!("the {}'s ssh kitchen sink", builder.name()),
        expected,
        |args, timeout| runner::run_host_zap(run, context.binary(builder), &home, args, timeout),
    )?;
    println!(
        "{}",
        converged_line(
            "ssh kitchen sink",
            &format!(" by the {}", builder.name()),
            expected
        )
    );

    if distro.has_local_suite() {
        build_local_base(context, distro)?;
    }

    vm::replace_snapshot(distro, vm::BASE, &fixture::base_description(hash))
}

/// Converge the local-connection fixture on the VM with the builder. The zap on the
/// VM fetches its `remote` content from the https origin on the libvirt gateway
/// address (the loopback server is unreachable from the guest, and plain `http` to
/// another machine is refused), which the guest trusts by now: the SSH kitchen sink,
/// converged first, installed the test CA in its trust store.
fn build_local_base(context: &Context, distro: Distro) -> Result<(), String> {
    let builder = context.base_by;
    let bundle = fixture::local_bundle(
        &context.repo,
        &context.scratch.join(distro.name()).join("local-base"),
        &context.pins,
        &fixture::toolchain_lock(&context.fgro_blake3),
        &[
            (&format!("bin/{}", builder.name()), context.binary(builder)),
            (fixture::BUNDLE_FGRO, &context.fgro),
        ],
        None,
    )?;
    vm::push_tar(distro, REMOTE_HARNESS_DIR, &bundle)?;
    let url = context.content_url(Suite::Local);
    // the first apply starts from an empty `ZAP_HOME`; the rest keep it, so the wetrun
    // finds the preview it binds to
    let first = std::cell::Cell::new(true);
    let expected = FromPristine::LOCAL_FIXTURE;
    apply_reviewed(
        &format!("the {}'s local fixture", builder.name()),
        expected,
        |args, timeout| {
            let state = if first.replace(false) {
                VmHome::Fresh
            } else {
                VmHome::Kept
            };
            let run = VmRun {
                distro,
                side: builder,
                home: "base",
                content_url: &url,
                state,
            };
            runner::run_vm_zap(run, args, timeout)
        },
    )?;
    println!("{}", converged_line("local fixture", "", expected));
    // the base carries converged state only; each scenario pushes a fresh bundle
    let cleaned = vm::ssh(
        distro,
        &format!("rm -rf {REMOTE_HARNESS_DIR}"),
        None,
        Duration::from_secs(60),
    )?;
    if cleaned.success() {
        Ok(())
    } else {
        Err(format!(
            "cleaning the harness dir failed: {}",
            cleaned.describe_failure()
        ))
    }
}

/// Converge a fixture the way an operator does, through `apply` (which runs
/// `zap <args> <config>` with one `ZAP_HOME` across its calls), in the rounds
/// `expected` declares. A round is a dry `apply` — the preview — and then
/// `apply --wetrun`, which a zap with a review gate runs only because its plan is the
/// one the preview in that `ZAP_HOME` recorded.
///
/// [`FromPristine::Converges`], one round:
///
/// 1. the preview must exit 0 or 2 (nothing held, nothing unverifiable) and print a
///    `plan_hash:` ([`check_preview`]);
/// 2. the wetrun must exit 0.
///
/// [`FromPristine::Holds`], two rounds:
///
/// 1. the preview must exit 1 for the declared holds alone and print a `plan_hash:`
///    ([`check_held_preview`]);
/// 2. the wetrun must exit 1 for the same holds alone, every change it ran completed
///    ([`check_held_wetrun`]);
/// 3. the second preview must exit 2 with no verdict, planning the held resources
///    and nothing else ([`check_second_preview`]);
/// 4. the second wetrun must exit 0.
///
/// Then, either way, a dry `apply` that must plan nothing ([`check_idempotent`]).
///
/// Every call passes `--no-cache`, so no call reads what an earlier one cached about
/// the config or the target: a wetrun runs the plan it computes itself. `what` names
/// the fixture and builder in an error.
fn apply_reviewed(
    what: &str,
    expected: FromPristine,
    apply: impl Fn(&[&str], Duration) -> Result<Captured, String>,
) -> Result<(), String> {
    match expected {
        FromPristine::Converges => {
            let preview = apply(PREVIEW, APPLY_TIMEOUT)?;
            check_preview(&preview)
                .map_err(|problem| format!("{what}: the preview apply {problem}"))?;
            let applied = apply(WETRUN, APPLY_TIMEOUT)?;
            if !applied.success() {
                return Err(format!(
                    "{what}: the base apply failed: {}",
                    applied.describe_failure()
                ));
            }
        }
        FromPristine::Holds { .. } => {
            let (holds, behind) = (expected.holds(), expected.behind());
            let preview = apply(PREVIEW, APPLY_TIMEOUT)?;
            check_held_preview(&preview, &holds, behind)
                .map_err(|problem| format!("{what}: round 1: the preview apply {problem}"))?;
            let applied = apply(WETRUN, APPLY_TIMEOUT)?;
            check_held_wetrun(&applied, &holds, behind)
                .map_err(|problem| format!("{what}: round 1: the base apply {problem}"))?;
            let preview = apply(PREVIEW, APPLY_TIMEOUT)?;
            check_second_preview(&preview, &every_hold(&holds, behind))
                .map_err(|problem| format!("{what}: round 2: the preview apply {problem}"))?;
            let applied = apply(WETRUN, APPLY_TIMEOUT)?;
            if !applied.success() {
                return Err(format!(
                    "{what}: round 2: the base apply failed: {}\n{}",
                    applied.describe_failure(),
                    applied.stdout
                ));
            }
        }
    }
    let again = apply(PREVIEW, ZAP_TIMEOUT)?;
    check_idempotent(&again).map_err(|problem| {
        format!("{what} doesn't converge on a second apply (a fixture bug): {problem}")
    })
}

/// The first round's preview of a fixture that declares `holds` and the changes
/// `behind` them: a dry `apply` that exited 1 for those holds alone
/// ([`exactly_held`]), printed a `plan_hash:` (a held plan is still one a wetrun binds
/// to), and plans none of the resources it holds.
/// A preview that held nothing (exit 0 or 2) fails: the declaration no longer
/// describes the fixture.
fn check_held_preview(apply: &Captured, holds: &[Hold], behind: &[Hold]) -> Result<(), String> {
    held_preview_problem(apply, holds, behind).map_err(|problem| with_report(&problem, apply))
}

fn held_preview_problem(apply: &Captured, holds: &[Hold], behind: &[Hold]) -> Result<(), String> {
    match apply.code {
        Some(1) => {}
        Some(code @ (0 | 2)) => {
            return Err(format!(
                "held nothing (exit {code}): expected {} held from pristine; nothing was",
                hold_ids(holds)
            ));
        }
        _ => return Err(format!("failed: {}", apply.describe_failure())),
    }
    if !prints_plan_hash(&apply.stdout) {
        return Err("printed no plan_hash:".to_owned());
    }
    exactly_held(&apply.stdout, holds, behind)?;
    let every = every_hold(holds, behind);
    let planned: Vec<&str> = apply
        .stdout
        .lines()
        .filter(|line| compare::is_change_line(line))
        .filter(|line| change_of(line).is_some_and(|(id, _)| is_held(&every, id)))
        .map(str::trim)
        .collect();
    if planned.is_empty() {
        Ok(())
    } else {
        Err(format!("plans a resource it holds: {}", planned.join("; ")))
    }
}

/// The first round's wetrun: an `apply --wetrun` that exited 1 for the declared holds
/// alone. Its verdict is the one `UNDETERMINED` banner ([`exactly_held`]; a
/// `RESIDUAL` or `REFUSED` fails it), no change failed or was skipped, and none of
/// the held resources ran.
///
/// A wetrun prints one outcome line per change — `  ok    <id>`,
/// `  FAIL  <id>  [<code>]  — …`, or `  skip  <id>  — …` — and then
/// `applied: <n> ok, <n> failed, <n> skipped (of <n>)` at column 0.
fn check_held_wetrun(apply: &Captured, holds: &[Hold], behind: &[Hold]) -> Result<(), String> {
    held_wetrun_problem(apply, holds, behind).map_err(|problem| with_report(&problem, apply))
}

fn held_wetrun_problem(apply: &Captured, holds: &[Hold], behind: &[Hold]) -> Result<(), String> {
    match apply.code {
        Some(1) => {}
        Some(0) => {
            return Err(format!(
                "held nothing (exit 0): expected {} held from pristine; nothing was",
                hold_ids(holds)
            ));
        }
        _ => return Err(format!("failed: {}", apply.describe_failure())),
    }
    exactly_held(&apply.stdout, holds, behind)?;
    summary_problem(&apply.stdout)?;
    let every = every_hold(holds, behind);
    let ran: Vec<&str> = apply
        .stdout
        .lines()
        .filter(|line| {
            line.strip_prefix("  ok    ")
                .is_some_and(|id| is_held(&every, id))
        })
        .map(str::trim)
        .collect();
    if ran.is_empty() {
        Ok(())
    } else {
        Err(format!("ran a resource it holds: {}", ran.join("; ")))
    }
}

/// The second round's preview: a dry `apply` that exited 2 with no verdict banner,
/// printed a `plan_hash:`, and plans every resource the first round held (as a create
/// or an update) and nothing else but `pipeline` resources, which plan on every run
/// by design.
fn check_second_preview(apply: &Captured, holds: &[Hold]) -> Result<(), String> {
    let ids: Vec<&str> = holds.iter().map(|hold| hold.id).collect();
    plans_exactly(apply, &ids, "held").map_err(|problem| with_report(&problem, apply))
}

fn is_held(holds: &[Hold], id: &str) -> bool {
    holds.iter().any(|hold| hold.id == id)
}

/// `holds` and the changes `behind` them: every resource the first round holds.
fn every_hold(holds: &[Hold], behind: &[Hold]) -> Vec<Hold> {
    holds.iter().chain(behind).copied().collect()
}

/// A report's verdict is the declared holds and nothing else: its one banner is
/// `UNDETERMINED` — any other (`UNVERIFIABLE`, `RESIDUAL`, `LOCK`, `UNBINDABLE`,
/// `UNRECORDED`, `REFUSED`, or one this list doesn't know) fails it, as a second
/// `UNDETERMINED` does — the lines under it are exactly `holds`' lines, and the lines
/// under its `held behind them —` line exactly `behind`'s, ids and reasons, each block
/// in any order. With nothing expected behind, there is no such line.
///
/// Read by zap's own columns: a held resource's line stands six spaces in, directly
/// under the banner; the banner's closing line stands two in and ends them, and the
/// `held behind them —` line, two in, follows it directly, its own entries six in.
fn exactly_held(stdout: &str, holds: &[Hold], behind: &[Hold]) -> Result<(), String> {
    let lines: Vec<&str> = stdout.lines().collect();
    let banners: Vec<(usize, &str)> = lines
        .iter()
        .enumerate()
        .filter_map(|(index, line)| compare::banner_name(line).map(|name| (index, name)))
        .collect();
    let [(at, "UNDETERMINED")] = banners[..] else {
        let names: Vec<&str> = banners.iter().map(|&(_, name)| name).collect();
        return Err(if names.is_empty() {
            "reports no UNDETERMINED".to_owned()
        } else {
            format!(
                "reports {} where one UNDETERMINED is expected",
                names.join(", ")
            )
        });
    };
    let entries = |from: usize| -> Vec<&str> {
        lines
            .get(from..)
            .unwrap_or_default()
            .iter()
            .copied()
            .take_while(|line| line.starts_with("      "))
            .collect()
    };
    let roots = entries(at + 1);
    let behind_at: Vec<usize> = lines
        .iter()
        .enumerate()
        .filter(|(_, line)| line.starts_with("  held behind them — "))
        .map(|(index, _)| index)
        .collect();
    let found_behind = match behind_at[..] {
        [] => Vec::new(),
        [index] if index == at + 1 + roots.len() + 1 => entries(index + 1),
        _ => return Err("reports a `held behind them —` line out of place".to_owned()),
    };
    same_lines("holds", holds, roots)?;
    same_lines("holds behind them", behind, found_behind)
}

/// `found` is exactly `expected`'s lines, in any order; `what` names the block.
fn same_lines(what: &str, expected: &[Hold], mut found: Vec<&str>) -> Result<(), String> {
    let mut wanted: Vec<String> = expected.iter().map(|hold| hold.line()).collect();
    found.sort_unstable();
    wanted.sort_unstable();
    if found == wanted {
        Ok(())
    } else {
        Err(format!(
            "{what} other than what is expected from pristine:\n  expected:\n{}\n  held:\n{}",
            wanted.join("\n"),
            found.join("\n")
        ))
    }
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::collections::VecDeque;
    use std::process::Command;
    use std::time::Duration;

    use super::{
        ALPINE_POSTGRES_VERSION, APPLY_TIMEOUT, FromPristine, Hold, alpine_cluster_marker,
        alpine_prepare_script, apply_reviewed, change_of, check_held_preview, check_held_wetrun,
        check_second_preview, converged_line, every_hold, held_preview_problem,
        held_wetrun_problem, plans_exactly,
    };
    use crate::differential::compare::is_change_line;
    use crate::differential::process::{self, Captured};
    use crate::differential::reviewed::tests::{
        PIPELINE_ONLY, PIPELINE_ONLY_WITH_SUBJECT, captured,
    };
    use crate::differential::runner::ZAP_TIMEOUT;
    use crate::differential::scenarios::scenarios;
    use crate::differential::vm::Distro;

    const DATABASE: Hold = Hold {
        id: "database",
        reason: "detection failed: the PostgreSQL catalog query exited 2",
    };
    const HOLDS_DATABASE: FromPristine = FromPristine::Holds {
        first: DATABASE,
        rest: &[],
        behind: &[],
    };
    const SWAP: Hold = Hold {
        id: "swap",
        reason: "detection failed: the swap read exited 1",
    };
    /// [`DATABASE`]'s line under the banner, as zap printed it.
    const DATABASE_LINE: &str =
        "      database — detection failed: the PostgreSQL catalog query exited 2\n";

    /// A first-round preview: the header, banner, and footer lines of a dry `apply`
    /// over the Alpine kitchen sink from `pristine`, with some of its changes.
    const HELD_PREVIEW: &str = r#"apply — target {env:ZAPDIFF_HOST} (dry-run)
  host: 192.168.122.10
  user: ops
  target: {"local":false,"host":{"$env":"ZAPDIFF_HOST"},"user":{"$env":"ZAPDIFF_USER"},"home":"/home/ops","package_manager":"apk","service_manager":"openrc"}
  UNDETERMINED — 1 resource(s) could not be probed, so no change is planned for them and this changeset is partial:
      database — detection failed: the PostgreSQL catalog query exited 2
  their live state is unknown: neither converged nor drifted. resolve the probe failure and re-run.
  [+] etc-dir  (directory)
      path: /etc/zapdiff
      mode: 755
  [+] pipeline  (pipeline)
      > true
  [~] postgresql-service  (service)
      > sudo rc-update add postgresql default
      > sudo rc-service postgresql start
  (dry-run — re-run with --wetrun to apply)
plan_hash: 3be8125a32b88bef942292360d093ec49b4ba4803a3329c46b0e7605d36bbb10
"#;

    /// The wetrun of [`HELD_PREVIEW`], as `render_apply` prints an executed apply.
    const HELD_WETRUN: &str = r#"apply — target {env:ZAPDIFF_HOST} (wetrun)
  host: 192.168.122.10
  user: ops
  target: {"local":false,"host":{"$env":"ZAPDIFF_HOST"},"user":{"$env":"ZAPDIFF_USER"},"home":"/home/ops","package_manager":"apk","service_manager":"openrc"}
  UNDETERMINED — 1 resource(s) could not be probed, so no change is planned for them and this changeset is partial:
      database — detection failed: the PostgreSQL catalog query exited 2
  their live state is unknown: neither converged nor drifted. resolve the probe failure and re-run.
  ok    etc-dir
  ok    pipeline
  ok    postgresql-service
applied: 3 ok, 0 failed, 0 skipped (of 3)
plan_hash: 3be8125a32b88bef942292360d093ec49b4ba4803a3329c46b0e7605d36bbb10
"#;

    /// The second round's preview: what was held, and the pipeline.
    const SECOND_PREVIEW: &str = r#"apply — target {env:ZAPDIFF_HOST} (dry-run)
  host: 192.168.122.10
  user: ops
  target: {"local":false,"host":{"$env":"ZAPDIFF_HOST"},"user":{"$env":"ZAPDIFF_USER"},"home":"/home/ops","package_manager":"apk","service_manager":"openrc"}
  [+] database  (database)
  [+] pipeline  (pipeline)
      > true
  (dry-run — re-run with --wetrun to apply)
plan_hash: 7a1c0f3e5b88bef942292360d093ec49b4ba4803a3329c46b0e7605d36bbb1077
"#;

    const CONVERGED: &str = "apply — target {env:ZAPDIFF_HOST} (dry-run)\n  \
        (no changes — converged)\nplan_hash: 1de19df0\n";

    const WHAT: &str = "the candidate's fixture";
    const PREVIEW: &str = "apply --no-cache";
    const WETRUN: &str = "apply --wetrun --no-cache";

    /// Run `apply_reviewed` against a scripted zap: each call takes the next reply.
    /// Returns its result and the calls it made, in order.
    fn scripted(
        expected: FromPristine,
        replies: Vec<Captured>,
    ) -> (Result<(), String>, Vec<(String, Duration)>) {
        let replies = RefCell::new(VecDeque::from(replies));
        let calls = RefCell::new(Vec::new());
        let result = apply_reviewed(WHAT, expected, |args, timeout| {
            calls.borrow_mut().push((args.join(" "), timeout));
            replies
                .borrow_mut()
                .pop_front()
                .ok_or_else(|| "no reply scripted for this call".to_owned())
        });
        (result, calls.into_inner())
    }

    fn two_rounds() -> Vec<Captured> {
        vec![
            captured(1, HELD_PREVIEW),
            captured(1, HELD_WETRUN),
            captured(2, SECOND_PREVIEW),
            captured(0, HELD_WETRUN),
            captured(2, PIPELINE_ONLY_WITH_SUBJECT),
        ]
    }

    #[test]
    fn one_round_is_a_preview_its_wetrun_and_a_no_op() {
        let (result, calls) = scripted(
            FromPristine::Converges,
            vec![
                captured(2, PIPELINE_ONLY_WITH_SUBJECT),
                captured(0, ""),
                captured(0, CONVERGED),
            ],
        );
        assert_eq!(result, Ok(()));
        assert_eq!(
            calls,
            [
                (PREVIEW.to_owned(), APPLY_TIMEOUT),
                (WETRUN.to_owned(), APPLY_TIMEOUT),
                (PREVIEW.to_owned(), ZAP_TIMEOUT),
            ]
        );
    }

    /// A fixture that declares no hold gets no second round, whatever it holds.
    #[test]
    fn one_round_stops_at_a_held_preview() {
        let (result, calls) = scripted(FromPristine::Converges, two_rounds());
        let error = result.expect_err("a held preview");
        assert!(
            error.starts_with("the candidate's fixture: the preview apply failed: exit 1"),
            "{error}"
        );
        assert!(error.ends_with(HELD_PREVIEW), "{error}");
        assert_eq!(calls.len(), 1);

        let (result, calls) = scripted(
            FromPristine::Converges,
            vec![captured(2, PIPELINE_ONLY), captured(1, HELD_WETRUN)],
        );
        let error = result.expect_err("a failed wetrun");
        assert!(
            error.starts_with("the candidate's fixture: the base apply failed: exit 1"),
            "{error}"
        );
        assert_eq!(calls.len(), 2);
    }

    #[test]
    fn two_rounds_are_two_previews_each_with_its_wetrun_and_a_no_op() {
        let (result, calls) = scripted(HOLDS_DATABASE, two_rounds());
        assert_eq!(result, Ok(()));
        assert_eq!(
            calls,
            [
                (PREVIEW.to_owned(), APPLY_TIMEOUT),
                (WETRUN.to_owned(), APPLY_TIMEOUT),
                (PREVIEW.to_owned(), APPLY_TIMEOUT),
                (WETRUN.to_owned(), APPLY_TIMEOUT),
                (PREVIEW.to_owned(), ZAP_TIMEOUT),
            ]
        );
    }

    /// Each step's failure stops the build there, names its round and check, and
    /// carries the step's whole report.
    #[test]
    fn two_rounds_stop_at_the_first_step_that_fails() {
        let failed = HELD_WETRUN.replace("applied: 3 ok, 0 failed", "applied: 2 ok, 1 failed");
        for (step, reply, prefix) in [
            (
                0,
                captured(2, PIPELINE_ONLY_WITH_SUBJECT),
                "the candidate's fixture: round 1: the preview apply held nothing (exit 2): \
                 expected database held from pristine; nothing was\n",
            ),
            (
                1,
                captured(1, &failed),
                "the candidate's fixture: round 1: the base apply did not complete every \
                 change: applied: 2 ok, 1 failed, 0 skipped (of 3)\n",
            ),
            (
                2,
                captured(1, HELD_PREVIEW),
                "the candidate's fixture: round 2: the preview apply failed: expected exit 2 \
                 (a plan of database), got exit 1",
            ),
            (
                3,
                captured(1, HELD_WETRUN),
                "the candidate's fixture: round 2: the base apply failed: exit 1",
            ),
            (
                4,
                captured(2, SECOND_PREVIEW),
                "the candidate's fixture doesn't converge on a second apply (a fixture bug): \
                 still planned: [+] database  (database)",
            ),
        ] {
            let mut replies = two_rounds();
            let report = reply.stdout.clone();
            replies[step] = reply;
            let (result, calls) = scripted(HOLDS_DATABASE, replies);
            let error = result.expect_err("a failed step");
            assert!(error.starts_with(prefix), "step {step}: {error}");
            assert_eq!(calls.len(), step + 1, "step {step}");
            if step < 4 {
                assert!(error.ends_with(&report), "step {step}: {error}");
            }
        }
        // a zap that can't be run at all
        let (result, calls) = scripted(HOLDS_DATABASE, Vec::new());
        assert_eq!(result, Err("no reply scripted for this call".to_owned()));
        assert_eq!(calls.len(), 1);
    }

    fn held_preview(stdout: &str, holds: &[Hold]) -> Result<(), String> {
        held_preview_problem(&captured(1, stdout), holds, &[])
    }

    #[test]
    fn a_held_preview_holds_exactly_what_is_declared() {
        assert_eq!(held_preview(HELD_PREVIEW, &[DATABASE]), Ok(()));
        assert_eq!(
            check_held_preview(&captured(1, HELD_PREVIEW), &[DATABASE], &[]),
            Ok(())
        );

        // one more held than declared
        let extra = HELD_PREVIEW.replace(
            DATABASE_LINE,
            &format!("{DATABASE_LINE}      swap — detection failed: the swap read exited 1\n"),
        );
        assert_eq!(
            held_preview(&extra, &[DATABASE]),
            Err(
                "holds other than what is expected from pristine:\n  expected:\n      \
                 database — detection failed: the PostgreSQL catalog query exited 2\n  \
                 held:\n      database — detection failed: the PostgreSQL catalog query \
                 exited 2\n      swap — detection failed: the swap read exited 1"
                    .to_owned()
            )
        );
        // both declared, in either order
        assert_eq!(held_preview(&extra, &[SWAP, DATABASE]), Ok(()));
        // one fewer held than declared
        assert!(held_preview(HELD_PREVIEW, &[DATABASE, SWAP]).is_err());
        // another resource held in its place
        let other = HELD_PREVIEW.replace("      database — ", "      swap — ");
        assert!(held_preview(&other, &[DATABASE]).is_err());
        // held for another reason
        let reason = HELD_PREVIEW.replace("exited 2\n", "exited 1\n");
        assert!(held_preview(&reason, &[DATABASE]).is_err());
        // a reason that runs on to a second line
        let longer = HELD_PREVIEW.replace(
            DATABASE_LINE,
            &format!("{DATABASE_LINE}                 and more\n"),
        );
        assert!(held_preview(&longer, &[DATABASE]).is_err());
        // a held line is one directly under the banner
        let elsewhere = HELD_PREVIEW
            .replace(DATABASE_LINE, "")
            .replace("      mode: 755\n", DATABASE_LINE);
        assert!(held_preview(&elsewhere, &[DATABASE]).is_err());
    }

    const DATA_DIR: Hold = Hold {
        id: "data-dir",
        reason: "waits on `database`, which is held",
    };
    /// The banner's closing line, which the `held behind them —` block follows.
    const FOOTER: &str = "  their live state is unknown: neither converged nor drifted. resolve the \
        probe failure and re-run.\n";
    const BEHIND_BLOCK: &str = "  held behind them — 1 resource(s) can't change until they do:\n      \
        data-dir — waits on `database`, which is held\n";

    /// `report` with [`DATA_DIR`] held behind its roots.
    fn with_behind(report: &str) -> String {
        assert!(report.contains(FOOTER));
        report.replace(FOOTER, &format!("{FOOTER}{BEHIND_BLOCK}"))
    }

    #[test]
    fn a_held_report_holds_exactly_what_is_declared_behind() {
        let preview = with_behind(HELD_PREVIEW);
        let holds = |stdout: &str, behind: &[Hold]| {
            held_preview_problem(&captured(1, stdout), &[DATABASE], behind)
        };
        assert_eq!(holds(&preview, &[DATA_DIR]), Ok(()));
        // held behind, and not declared
        assert_eq!(
            holds(&preview, &[]),
            Err(
                "holds behind them other than what is expected from pristine:\n  expected:\n\n  \
                 held:\n      data-dir — waits on `database`, which is held"
                    .to_owned()
            )
        );
        // declared, and not held behind
        assert!(holds(HELD_PREVIEW, &[DATA_DIR]).is_err());
        // held behind for another reason
        let other = preview.replace("waits on `database`", "would restart `database`");
        assert!(holds(&other, &[DATA_DIR]).is_err());
        // a root's line is not one held behind
        let as_root = HELD_PREVIEW.replace(
            DATABASE_LINE,
            &format!("{DATABASE_LINE}      data-dir — waits on `database`, which is held\n"),
        );
        assert!(holds(&as_root, &[DATA_DIR]).is_err());
        // the block stands directly after the banner's closing line
        let moved = HELD_PREVIEW.replace("  (dry-run", &format!("{BEHIND_BLOCK}  (dry-run"));
        assert_eq!(
            holds(&moved, &[DATA_DIR]),
            Err("reports a `held behind them —` line out of place".to_owned())
        );
        // a change held behind is planned
        let planned = preview.replace(
            "  [+] pipeline  (pipeline)\n",
            "  [+] data-dir  (directory)\n  [+] pipeline  (pipeline)\n",
        );
        assert_eq!(
            holds(&planned, &[DATA_DIR]),
            Err("plans a resource it holds: [+] data-dir  (directory)".to_owned())
        );

        let wetrun = with_behind(HELD_WETRUN);
        let ran = |stdout: &str, behind: &[Hold]| {
            held_wetrun_problem(&captured(1, stdout), &[DATABASE], behind)
        };
        assert_eq!(ran(&wetrun, &[DATA_DIR]), Ok(()));
        assert!(ran(&wetrun, &[]).is_err());
        let ran_behind = wetrun
            .replace("  ok    pipeline\n", "  ok    data-dir\n  ok    pipeline\n")
            .replace("applied: 3 ok", "applied: 4 ok")
            .replace("(of 3)", "(of 4)");
        assert_eq!(
            ran(&ran_behind, &[DATA_DIR]),
            Err("ran a resource it holds: ok    data-dir".to_owned())
        );

        // the second round plans what was held behind as well as the roots
        let every = every_hold(&[DATABASE], &[DATA_DIR]);
        let second = SECOND_PREVIEW.replace(
            "  [+] pipeline  (pipeline)\n",
            "  [+] data-dir  (directory)\n  [+] pipeline  (pipeline)\n",
        );
        assert_eq!(check_second_preview(&captured(2, &second), &every), Ok(()));
        assert!(check_second_preview(&captured(2, SECOND_PREVIEW), &every).is_err());
    }

    // `{env:NAME}` is the notation a reference is shown in, written out here as text.
    #[allow(clippy::literal_string_with_formatting_args)]
    #[test]
    fn a_held_preview_reports_no_other_verdict() {
        for banner in [
            "  UNVERIFIABLE — 1 referenced variable(s) are unset",
            "  LOCK — the pin ledger does not answer for 1 resource(s)",
            "  RESIDUAL — 1 resource(s) do not read converged",
            "  UNBINDABLE — the target host `{env:H}` references `{env:H}`, a secret name",
            "  UNRECORDED — no last run is kept for this target",
            "  REFUSED — nothing ran: this plan was not reviewed.",
            "  NOVEL — a verdict this harness has not met",
            "  UNDETERMINED — 1 resource(s) could not be probed",
        ] {
            let name = banner.trim_start().split(' ').next().expect("a name");
            // after the changes, and ahead of the expected banner
            for text in [
                HELD_PREVIEW.replace("  (dry-run", &format!("{banner}\n  (dry-run")),
                HELD_PREVIEW.replace("  UNDETERMINED", &format!("{banner}\n  UNDETERMINED")),
            ] {
                let error = held_preview(&text, &[DATABASE]).expect_err(banner);
                assert!(
                    error.starts_with("reports ") && error.contains(name),
                    "{banner}: {error}"
                );
                assert!(
                    error.ends_with(" where one UNDETERMINED is expected"),
                    "{banner}: {error}"
                );
            }
        }
        // a real plan with several banners, one of them an UNDETERMINED
        let real = include_str!("testdata/real/held.plan.new.out");
        assert_eq!(
            held_preview(real, &[DATABASE]),
            Err(
                "reports LOCK, UNVERIFIABLE, UNDETERMINED where one UNDETERMINED is expected"
                    .to_owned()
            )
        );
        // exit 1 with nothing held
        let unheld: String = HELD_PREVIEW
            .split_inclusive('\n')
            .filter(|line| {
                !["UNDETERMINED", "database — ", "their live state"]
                    .iter()
                    .any(|part| line.contains(part))
            })
            .collect();
        assert_eq!(
            held_preview(&unheld, &[DATABASE]),
            Err("reports no UNDETERMINED".to_owned())
        );
    }

    #[test]
    fn a_held_preview_plans_nothing_it_holds_and_prints_a_hash() {
        let planned = HELD_PREVIEW.replace(
            "  [+] pipeline  (pipeline)\n",
            "  [+] database  (database)\n  [+] pipeline  (pipeline)\n",
        );
        assert_eq!(
            held_preview(&planned, &[DATABASE]),
            Err("plans a resource it holds: [+] database  (database)".to_owned())
        );
        // an id that only starts like a held one is another resource
        let prefixed =
            HELD_PREVIEW.replace("[+] etc-dir  (directory)", "[~] database-2  (database)");
        assert_eq!(held_preview(&prefixed, &[DATABASE]), Ok(()));

        let unbound = HELD_PREVIEW.replace("plan_hash: ", "      plan_hash: ");
        assert_eq!(
            held_preview(&unbound, &[DATABASE]),
            Err("printed no plan_hash:".to_owned())
        );
    }

    /// A declared hold that doesn't happen is a failure, not a shorter build.
    #[test]
    fn a_declared_hold_that_is_not_held_fails() {
        for (code, stdout) in [(2, PIPELINE_ONLY_WITH_SUBJECT), (0, CONVERGED)] {
            let error = check_held_preview(&captured(code, stdout), &[DATABASE, SWAP], &[])
                .expect_err("nothing held");
            assert_eq!(
                error,
                format!(
                    "held nothing (exit {code}): expected database, swap held from pristine; \
                     nothing was\n{stdout}"
                )
            );
        }
        let error = check_held_wetrun(&captured(0, HELD_WETRUN), &[DATABASE], &[])
            .expect_err("nothing held");
        assert!(
            error.starts_with("held nothing (exit 0): expected database held from pristine"),
            "{error}"
        );
        // neither a hold nor a plan: another exit code, a timeout
        let mut timed_out = captured(1, HELD_PREVIEW);
        timed_out.code = None;
        for odd in [captured(3, HELD_PREVIEW), timed_out] {
            for error in [
                check_held_preview(&odd, &[DATABASE], &[]).expect_err("an odd exit"),
                check_held_wetrun(&odd, &[DATABASE], &[]).expect_err("an odd exit"),
            ] {
                assert!(error.starts_with("failed: "), "{error}");
            }
        }
        // a wetrun never exits 2
        assert!(check_held_wetrun(&captured(2, HELD_WETRUN), &[DATABASE], &[]).is_err());
    }

    /// A zap that stopped on an error exits 1 with its reason on stderr and no report:
    /// the reason is in the failure.
    #[test]
    fn a_run_that_stopped_on_an_error_says_why() {
        let stopped = Captured {
            code: Some(1),
            stdout: String::new(),
            stderr: "error: ssh: connect to host 192.168.122.10 port 22: refused\n".to_owned(),
            timed_out: false,
        };
        let stderr = "\nstderr: error: ssh: connect to host 192.168.122.10 port 22: refused\n";
        assert_eq!(
            check_held_preview(&stopped, &[DATABASE], &[]),
            Err(format!("printed no plan_hash:{stderr}"))
        );
        assert_eq!(
            check_held_wetrun(&stopped, &[DATABASE], &[]),
            Err(format!("reports no UNDETERMINED{stderr}"))
        );
        let unhashed = Captured {
            code: Some(2),
            ..stopped
        };
        assert_eq!(
            check_second_preview(&unhashed, &[DATABASE]),
            Err(format!("printed no plan_hash:{stderr}"))
        );
    }

    fn held_wetrun(stdout: &str) -> Result<(), String> {
        held_wetrun_problem(&captured(1, stdout), &[DATABASE], &[])
    }

    #[test]
    fn a_held_wetrun_exits_1_for_the_hold_alone() {
        assert_eq!(held_wetrun(HELD_WETRUN), Ok(()));
        assert_eq!(
            check_held_wetrun(&captured(1, HELD_WETRUN), &[DATABASE], &[]),
            Ok(())
        );

        let failed = HELD_WETRUN
            .replace(
                "  ok    postgresql-service\n",
                "  FAIL  postgresql-service  [ExecutionFailed]  — exit 1\n",
            )
            .replace("3 ok, 0 failed", "2 ok, 1 failed");
        assert_eq!(
            held_wetrun(&failed),
            Err(
                "did not complete every change: FAIL  postgresql-service  [ExecutionFailed]  — \
                 exit 1"
                    .to_owned()
            )
        );
        let skipped = HELD_WETRUN
            .replace(
                "  ok    postgresql-service\n",
                "  skip  postgresql-service  — an earlier change failed\n",
            )
            .replace("3 ok, 0 failed, 0 skipped", "2 ok, 0 failed, 1 skipped");
        assert!(held_wetrun(&skipped).is_err());
        // the counts alone
        for counts in ["2 ok, 1 failed, 0 skipped", "2 ok, 0 failed, 1 skipped"] {
            let summary = HELD_WETRUN.replace("3 ok, 0 failed, 0 skipped", counts);
            assert_eq!(
                held_wetrun(&summary),
                Err(format!(
                    "did not complete every change: applied: {counts} (of 3)"
                ))
            );
        }
        let unreadable = HELD_WETRUN.replace("0 failed", "no failed");
        assert!(
            held_wetrun(&unreadable)
                .expect_err("a summary")
                .starts_with("printed a summary that can't be read: ")
        );
        let none = HELD_WETRUN.replace("applied: ", "      applied: ");
        let twice = HELD_WETRUN.replace(
            "plan_hash: ",
            "applied: 3 ok, 0 failed, 0 skipped (of 3)\nplan_hash: ",
        );
        for summaries in [none, twice] {
            assert_eq!(
                held_wetrun(&summaries),
                Err("did not print one `applied:` summary line".to_owned())
            );
        }
        let ran = HELD_WETRUN.replace("  ok    etc-dir\n", "  ok    database\n");
        assert_eq!(
            held_wetrun(&ran),
            Err("ran a resource it holds: ok    database".to_owned())
        );
    }

    #[test]
    fn a_held_wetrun_reports_no_other_verdict() {
        for banner in [
            "  RESIDUAL — 1 resource(s) do not read converged after this apply:",
            "  RESIDUAL — the post-apply re-detection failed, so convergence was not established: x",
            "  REFUSED — nothing ran: this plan was not reviewed.",
            "  UNRECORDED — no last run is kept for this target",
        ] {
            let text = HELD_WETRUN.replace("plan_hash: ", &format!("{banner}\nplan_hash: "));
            assert!(
                held_wetrun(&text)
                    .expect_err(banner)
                    .ends_with(" where one UNDETERMINED is expected"),
                "{banner}"
            );
        }
        let other = HELD_WETRUN.replace("      database — ", "      swap — ");
        assert!(held_wetrun(&other).is_err());
        assert_eq!(
            held_wetrun(
                "apply — target local (wetrun)\n  ok    x\n\
                 applied: 1 ok, 0 failed, 0 skipped (of 1)\n"
            ),
            Err("reports no UNDETERMINED".to_owned())
        );
    }

    fn second_preview(stdout: &str, holds: &[Hold]) -> Result<(), String> {
        let ids: Vec<&str> = holds.iter().map(|hold| hold.id).collect();
        plans_exactly(&captured(2, stdout), &ids, "held")
    }

    #[test]
    fn a_second_preview_plans_what_was_held_and_nothing_else() {
        assert_eq!(second_preview(SECOND_PREVIEW, &[DATABASE]), Ok(()));
        // a pipeline plans on every run, and a plan without one is as good
        let bare = SECOND_PREVIEW.replace("  [+] pipeline  (pipeline)\n      > true\n", "");
        assert_eq!(second_preview(&bare, &[DATABASE]), Ok(()));
        // an update is a plan of it too
        let update = SECOND_PREVIEW.replace("[+] database", "[~] database");
        assert_eq!(second_preview(&update, &[DATABASE]), Ok(()));

        let extra = SECOND_PREVIEW.replace(
            "  [+] pipeline  (pipeline)\n",
            "  [~] inline  (file)\n      path: /etc/x\n  [+] pipeline  (pipeline)\n",
        );
        assert_eq!(
            second_preview(&extra, &[DATABASE]),
            Err("plans more than the resources that were held: [~] inline  (file)".to_owned())
        );
        let fewer = SECOND_PREVIEW.replace("  [+] database  (database)\n", "");
        assert_eq!(
            second_preview(&fewer, &[DATABASE]),
            Err("does not plan a resource that was held: database".to_owned())
        );
        assert_eq!(
            second_preview(SECOND_PREVIEW, &[DATABASE, SWAP]),
            Err("does not plan a resource that was held: swap".to_owned())
        );
        // a pipeline that takes a held resource's id is not that resource
        let disguised =
            SECOND_PREVIEW.replace("[+] database  (database)", "[+] database  (pipeline)");
        assert_eq!(
            second_preview(&disguised, &[DATABASE]),
            Err("does not plan a resource that was held: database".to_owned())
        );
        // lines under a change are not changes
        let under = SECOND_PREVIEW.replace(
            "      > true\n",
            "      > echo\n        [+] inline  (file)\n",
        );
        assert_eq!(second_preview(&under, &[DATABASE]), Ok(()));
    }

    #[test]
    fn a_second_preview_exits_2_with_a_hash_and_no_verdict() {
        assert_eq!(
            check_second_preview(&captured(2, SECOND_PREVIEW), &[DATABASE]),
            Ok(())
        );
        for (code, stdout) in [(0, CONVERGED), (1, HELD_PREVIEW), (1, SECOND_PREVIEW)] {
            let error =
                check_second_preview(&captured(code, stdout), &[DATABASE]).expect_err("not a plan");
            assert!(
                error.starts_with(&format!(
                    "failed: expected exit 2 (a plan of database), got exit {code}"
                )),
                "{error}"
            );
            assert!(error.ends_with(stdout), "{error}");
        }
        let still_held = SECOND_PREVIEW.replace(
            "  [+] database",
            "  UNDETERMINED — 1 resource(s) could not be probed\n  [+] database",
        );
        assert_eq!(
            second_preview(&still_held, &[DATABASE]),
            Err("reports UNDETERMINED".to_owned())
        );
        let unbound = SECOND_PREVIEW.replace("plan_hash: ", "      plan_hash: ");
        assert_eq!(
            second_preview(&unbound, &[DATABASE]),
            Err("printed no plan_hash:".to_owned())
        );
    }

    /// The stopped-server scenario expects the hold the Alpine base declares, in the
    /// plan's own words: the same `database` line, a `?` from `detect`, and no change
    /// line for it.
    #[test]
    fn the_stopped_postgres_scenario_expects_the_declared_hold() {
        let held = DATABASE.line();
        for distro in Distro::ALL {
            let scenario = scenarios(distro)
                .into_iter()
                .find(|scenario| scenario.name == "postgres-stopped")
                .expect("the scenario");
            assert!(scenario.expect.contains(&(DATABASE.id, "?")), "{distro}");
            let (shown, lacking): (Vec<_>, Vec<_>) = scenario
                .expect_plan
                .into_iter()
                .partition(|&(_, shown)| shown);
            assert_eq!(shown, [(held.as_str(), true)], "{distro}");
            let [(change, _)] = lacking[..] else {
                panic!("{distro}: one change line the plan must lack");
            };
            assert!(is_change_line(change), "{distro}: {change}");
            assert_eq!(
                change_of(change),
                Some((DATABASE.id, "database")),
                "{distro}"
            );
        }
    }

    /// Only the Alpine SSH kitchen sink declares a hold.
    #[test]
    fn only_the_alpine_ssh_fixture_declares_a_hold() {
        assert_eq!(FromPristine::of_ssh_fixture(Distro::Alpine), HOLDS_DATABASE);
        assert_eq!(
            FromPristine::of_ssh_fixture(Distro::Debian),
            FromPristine::Converges
        );
        assert_eq!(FromPristine::LOCAL_FIXTURE, FromPristine::Converges);
        assert_eq!(FromPristine::Converges.holds(), []);
        let both = FromPristine::Holds {
            first: DATABASE,
            rest: &[SWAP],
            behind: &[],
        };
        assert_eq!(both.holds(), [DATABASE, SWAP]);
        assert_eq!(format!("{}\n", DATABASE.line()), DATABASE_LINE);
    }

    #[test]
    fn the_progress_line_says_how_many_rounds_it_took() {
        assert_eq!(
            converged_line(
                "ssh kitchen sink",
                " by the oracle",
                FromPristine::Converges
            ),
            "  base     ssh kitchen sink previewed and applied by the oracle; second apply is a \
             no-op"
        );
        assert_eq!(
            converged_line("local fixture", "", FromPristine::Converges),
            "  base     local fixture previewed and applied; second apply is a no-op"
        );
        assert_eq!(
            converged_line("ssh kitchen sink", " by the candidate", HOLDS_DATABASE),
            "  base     ssh kitchen sink previewed and applied by the candidate in two rounds \
             (database held from pristine); a further apply is a no-op"
        );
    }

    /// The preparation names the packages and the cluster the fixture declares, stops
    /// the service before the `setup` that needs it down, and parses as POSIX `sh`.
    #[test]
    fn the_alpine_preparation_matches_its_fixture() {
        let fixture = include_str!("../../fixtures/differential/alpine/zap.ts");
        for declared in [
            format!("from: {{ apk: 'postgresql{ALPINE_POSTGRES_VERSION}' }}"),
            format!("from: {{ apk: 'postgresql{ALPINE_POSTGRES_VERSION}-openrc' }}"),
            format!("alpine_postgres_setup({{ version: {ALPINE_POSTGRES_VERSION} }})"),
        ] {
            assert!(fixture.contains(&declared), "{declared}");
        }
        let script = alpine_prepare_script(&alpine_cluster_marker());
        assert!(script.starts_with("apk add --update-cache postgresql18 postgresql18-openrc "));
        assert!(script.contains("test -e /var/lib/postgresql/18/data/PG_VERSION"));
        // a shell that isn't installed checks nothing
        for shell in [&["sh", "-n", "-c"][..], &["busybox", "sh", "-n", "-c"][..]] {
            let Ok(checked) = Command::new(shell[0])
                .args(&shell[1..])
                .arg(&script)
                .output()
            else {
                continue;
            };
            assert!(
                checked.status.success(),
                "{shell:?}: {}",
                String::from_utf8_lossy(&checked.stderr)
            );
        }
    }

    /// A stand-in for `apk`: every install succeeds.
    const STUB_APK: &str = "#!/bin/sh\nexit 0\n";

    /// A stand-in for `rc-service` that keeps one service's state in `$STUB/state`
    /// (`started`, `stopped`, or `crashed`), answers `status` as `OpenRC` does (0
    /// started, 3 stopped, 32 crashed), refuses a `setup` unless stopped, and records
    /// each action in `$STUB/calls`. A file named `<action>-is-a-no-op` makes that
    /// action succeed and change nothing.
    const STUB_RC_SERVICE: &str = r#"#!/bin/sh
state=$(cat "$STUB/state")
echo "$2" >>"$STUB/calls"
[ ! -e "$STUB/$2-is-a-no-op" ] || exit 0
case $2 in
status) case $state in started) exit 0 ;; stopped) exit 3 ;; *) exit 32 ;; esac ;;
stop) echo stopped >"$STUB/state" ;;
setup) [ "$state" = stopped ] && mkdir "$STUB/data" && : >"$STUB/data/PG_VERSION" ;;
esac
"#;

    /// What a run of the preparation left: its exit, the service's state, whether the
    /// cluster's marker exists, and the `rc-service` actions it took.
    struct Prepared {
        run: Captured,
        state: String,
        initialized: bool,
        calls: Vec<String>,
    }

    /// Run the preparation the way `vm::root_shell` delivers it — whole on stdin,
    /// under `set -eu` — in `shell`, against the stand-ins, from a service in `state`
    /// with or without a cluster. `no_op` names an action that changes nothing.
    ///
    /// The shell writes the stand-ins itself, from `$STUB_APK` and `$STUB_RC_SERVICE`,
    /// before it runs anything. Written from this process, an executable's write fd
    /// can be inherited by another test thread's fork in the moment before that
    /// child execs, and running the stand-in then fails with `Text file busy`.
    fn prepare(shell: &[&str], state: &str, initialized: bool, no_op: Option<&str>) -> Prepared {
        let stub = tempfile::tempdir().expect("tempdir");
        let dir = stub.path();
        std::fs::write(dir.join("state"), format!("{state}\n")).expect("write");
        let marker = dir.join("data/PG_VERSION");
        if initialized {
            std::fs::create_dir(dir.join("data")).expect("mkdir");
            std::fs::write(&marker, "").expect("write");
        }
        if let Some(action) = no_op {
            std::fs::write(dir.join(format!("{action}-is-a-no-op")), "").expect("write");
        }
        let script = format!(
            "set -eu\ncd /\n{}\n",
            alpine_prepare_script(&marker.to_string_lossy())
        );
        let mut command = Command::new(shell[0]);
        command
            .args(&shell[1..])
            .args([
                "-c",
                concat!(
                    "printf %s \"$STUB_APK\" >\"$STUB/apk\" && ",
                    "printf %s \"$STUB_RC_SERVICE\" >\"$STUB/rc-service\" && ",
                    "chmod 755 \"$STUB/apk\" \"$STUB/rc-service\" && ",
                    "unset STUB_APK STUB_RC_SERVICE && ",
                    "script=$(cat) && exec </dev/null && eval \"$script\""
                ),
            ])
            .env("PATH", format!("{}:/usr/bin:/bin", dir.display()))
            .env("STUB", dir)
            .env("STUB_APK", STUB_APK)
            .env("STUB_RC_SERVICE", STUB_RC_SERVICE);
        let run = process::run(command, Some(script.as_bytes()), Duration::from_secs(60))
            .expect("the shell runs");
        let read = |name: &str| std::fs::read_to_string(dir.join(name)).unwrap_or_default();
        Prepared {
            run,
            state: read("state").trim().to_owned(),
            initialized: marker.exists(),
            calls: read("calls").lines().map(str::to_owned).collect(),
        }
    }

    /// From any state the preparation leaves the cluster initialized and the service
    /// stopped, or fails: it never reports a state it did not reach.
    #[test]
    fn the_alpine_preparation_ends_initialized_and_stopped_or_fails() {
        let busybox = Command::new("busybox").arg("true").output().is_ok();
        let shells: &[&[&str]] = if busybox {
            &[&["sh"], &["busybox", "sh"]]
        } else {
            &[&["sh"]]
        };
        for shell in shells {
            for state in ["stopped", "started", "crashed"] {
                for initialized in [true, false] {
                    let left = prepare(shell, state, initialized, None);
                    let case = format!("{shell:?} from {state}, initialized {initialized}");
                    assert!(left.run.success(), "{case}: {}", left.run.stderr);
                    assert_eq!(left.state, "stopped", "{case}");
                    assert!(left.initialized, "{case}");
                    let acted: Vec<&str> = left
                        .calls
                        .iter()
                        .map(String::as_str)
                        .filter(|call| *call != "status")
                        .collect();
                    let mut expected = Vec::new();
                    if state != "stopped" {
                        expected.push("stop");
                    }
                    if !initialized {
                        expected.push("setup");
                    }
                    assert_eq!(acted, expected, "{case}");
                }
            }
            // a `setup` that initialises nothing
            let left = prepare(shell, "stopped", false, Some("setup"));
            assert_eq!(left.run.code, Some(1), "{shell:?}");
            assert!(
                left.run.stderr.contains("the cluster is not initialized"),
                "{shell:?}: {}",
                left.run.stderr
            );
            // a `stop` that leaves it started, or crashed
            for state in ["started", "crashed"] {
                let left = prepare(shell, state, true, Some("stop"));
                assert_eq!(left.run.code, Some(1), "{shell:?} from {state}");
                assert!(
                    left.run.stderr.contains("postgresql is not stopped"),
                    "{shell:?} from {state}: {}",
                    left.run.stderr
                );
            }
        }
    }
}
