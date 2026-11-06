//! The bootstrap-replace scenario ([`NAME`], `scenarios::Kind::ReplaceBootstrap`):
//! rehearse replacing a host's bootstrap account in place, the way an operator brings a
//! host up and then retires the stock account (`docs/targets.md` § The bootstrap user).
//!
//! It compares nothing: the **candidate alone** runs it, against its own staged copy of
//! the scenario's two configs (`crates/xtask/fixtures/bootstrap/`, outside the kitchen
//! sinks, so the base snapshot doesn't depend on them). From the base:
//!
//! 1. **Provision.** [`NEXT_USER`] doesn't exist yet. The `provision` config, whose
//!    target connects as [`NEXT_USER`] and, under `--bootstrap`, as `ops`, declares one
//!    `user`: the new account, with `ops`'s keys (`copy_from`), a `nopasswd` sudo grant,
//!    and `/bin/sh`. It is locked (`zap lock`), previewed with `apply --bootstrap`, which
//!    must plan the user's creation and nothing else and name `ops` as the connecting
//!    user, applied with `apply --bootstrap --wetrun` bound to that preview, and
//!    previewed again, which must plan nothing.
//! 2. **Prove.** Over a login of its own, the new user is who it says, its `sudo -n`
//!    works, and that grant is zap's: `/etc/sudoers.d/<user>` holds zap's line, root's
//!    at `440`, and the user is in no `sudo`, `wheel`, or `admin` group. Its
//!    `authorized_keys` is `ops`'s, byte for byte.
//! 3. **Retire**, out of band, as root through the new user's login (an `ops` session
//!    can't remove `ops`): `ops`'s sessions are ended and its processes killed, a
//!    bounded wait sees none left, and `userdel -r ops` runs without `-f`, so a
//!    straggler fails it. On Debian, cloud-init's `90-cloud-init-users`, which grants
//!    `ops` sudo by name, is checked to grant nothing else and removed.
//! 4. **After.** As the new user: `ops` has no account, no home, no sudoers line, and
//!    no group; `visudo -c` passes; the new user's keys are the ones it was given. An
//!    `ssh ops@…` is refused, and a login as the new user right after succeeds, so a
//!    VM that went down can't pass as a refusal.
//! 5. **Plan as the new user** (no `--bootstrap`): the `retired` config, the same user
//!    with its keys as the list it holds (a module generated from its `authorized_keys`
//!    read before the retire, never checked in), reads converged, the plan naming the
//!    new user. The `provision` config reads its user drifted, `ssh keys unreadable`:
//!    with the `copy_from` source gone, zap plans to re-apply rather than read it
//!    converged.
//!
//! Every step after the retire reaches the VM as the new user, `ops` being gone. The
//! read-only audit doesn't run (it reaches the VM as `ops`, and this scenario writes on
//! purpose); what stands in for it is the scenario's own checks, root's reading of the
//! accounts and sudoers above, and the run fetching nothing (the configs hold no
//! remote content). The revert that starts the next scenario, or the run's final one,
//! brings `ops` back: a revert sets the clock as `ops` only after the snapshot is back.
//!
//! Under `--keep`, the scenario stops after step 2, `ops` left in place: a run kept
//! with `ops` gone would stop the next one before any revert, which waits for the VM
//! as `ops`.

use std::fmt::Write as _;
use std::time::{Duration, Instant};

use super::compare;
use super::process::Captured;
use super::reconverge::{probe_reading, probe_script};
use super::reviewed::{
    check_idempotent, one_plan_hash, plans_exactly, wetrun_problem, with_report,
};
use super::runner::{self, APPLY_HEADER, HostRun, Machine, PLAN_HEADER, Side, ZAP_TIMEOUT};
use super::vm::{self, Distro};
use super::{Context, DistroSetup, Trace, Verdict, fetch_count};

/// The scenario's name, selectable with `--scenario`.
pub const NAME: &str = "bootstrap-replace";

/// The user that replaces `ops`. Mirrored in the fixtures' `common.ts`.
pub const NEXT_USER: &str = "zapnext";

/// The operator variable the fixtures' target connects as, set to [`NEXT_USER`] on
/// every host run (`runner::host_zap_command`).
pub const NEXT_USER_VAR: &str = "ZAPDIFF_NEXT_USER";

/// The new user's resource id in both configs.
const USER_ID: &str = "next-user";

/// The bootstrap account being retired: the harness's own SSH user.
const OPS: &str = vm::SSH_USER;

/// Debian cloud-init's sudoers file, which grants `ops` by name.
const CLOUD_INIT_SUDOERS: &str = "/etc/sudoers.d/90-cloud-init-users";

/// How long a VM-side shell of the scenario's may take.
const SHELL_TIMEOUT: Duration = Duration::from_secs(120);

/// Run the scenario on `setup`'s distro. `Ok` carries the verdict; every failed check
/// is an `ERROR` naming it.
pub fn run(
    context: &Context,
    setup: &DistroSetup<'_>,
    trace: &mut Trace,
) -> Result<Verdict, String> {
    let distro = setup.distro;
    trace.revert = vm::revert(distro, vm::BASE)?;
    let fetched_before = fetch_count(context);
    let outcome = replace(context, setup, trace);
    let fetched = fetch_count(context) - fetched_before;
    let mut problems: Vec<String> = outcome.err().into_iter().collect();
    if fetched > 0 {
        problems.push(format!(
            "the scenario fetched remote content {fetched} time(s); its configs hold none"
        ));
    }
    Ok(if problems.is_empty() {
        Verdict::Pass
    } else {
        Verdict::Error(problems.join("\n"))
    })
}

/// Record phase `name`, begun at `started`, in the trace.
fn phase(trace: &mut Trace, name: &'static str, started: Instant) {
    trace.phases.push((name, started.elapsed()));
}

fn replace(context: &Context, setup: &DistroSetup<'_>, trace: &mut Trace) -> Result<(), String> {
    let distro = setup.distro;
    let started = Instant::now();
    absent_before(distro)?;
    let candidate = context.binary(Side::Candidate);
    let staged = context.staged(Side::Candidate);
    let base_run = setup.runs[Side::Candidate.index()];
    let home = |name: &str| {
        context
            .homes
            .home(&format!("{}/ssh/{NAME}/{name}", distro.name()))
    };

    let provision = staged.bootstrap_config("provision");
    let run = HostRun {
        config: &provision,
        ..base_run
    };
    let provision_home = home("provision");
    let zap =
        |args: &[&str]| runner::run_host_zap(run, candidate, &provision_home, args, ZAP_TIMEOUT);
    locked(&zap(&["lock"])?, "the provision config")?;
    let preview = zap(&["apply", "--no-cache", "--bootstrap"])?;
    creates_only_the_user(&preview)
        .and_then(|()| machine_named(&preview.stdout, APPLY_HEADER, distro.host(), OPS))
        .map_err(|problem| {
            format!(
                "the --bootstrap preview apply {}",
                with_report(&problem, &preview).trim_end()
            )
        })?;
    let reviewed = one_plan_hash(&preview.stdout)
        .ok_or("the --bootstrap preview apply printed no one plan_hash")?
        .to_owned();
    let applied = zap(&["apply", "--wetrun", "--no-cache", "--bootstrap"])?;
    wetrun_problem(&applied, &reviewed).map_err(|problem| {
        format!(
            "the --bootstrap apply --wetrun {}",
            with_report(&problem, &applied).trim_end()
        )
    })?;
    let again = zap(&["apply", "--no-cache", "--bootstrap"])?;
    check_idempotent(&again)
        .map_err(|problem| format!("a further --bootstrap preview apply plans more: {problem}"))?;
    phase(trace, "provision", started);

    let started = Instant::now();
    let keys = prove_next_user(distro)?;
    trace.notes.push(format!(
        "{NEXT_USER} logs in, its sudo is zap's grant alone, and it holds {OPS}'s keys"
    ));
    phase(trace, "prove", started);
    if context.keep {
        trace
            .notes
            .push(format!("retire skipped (--keep): {OPS} is left in place"));
        return Ok(());
    }

    let started = Instant::now();
    let retired = vm::root_shell_as(distro, NEXT_USER, &retire_script(distro), SHELL_TIMEOUT)?;
    if !retired.success() {
        return Err(format!(
            "retiring {OPS} failed: {}\n{}",
            retired.describe_failure(),
            retired.stdout.trim_end()
        ));
    }
    phase(trace, "retire", started);

    let started = Instant::now();
    ops_gone(distro, &keys.digest)?;
    login_pair_problem(distro)?;
    trace.notes.push(format!(
        "{OPS} retired: no account, home, sudoers line, or group; its login is refused"
    ));

    // the keys the new user holds, as the list the steady-state config declares
    std::fs::write(
        staged.bootstrap_keys_module(),
        render_keys_module(&keys.text)?,
    )
    .map_err(|error| format!("writing the keys module failed: {error}"))?;
    let retired_config = staged.bootstrap_config("retired");
    let run = HostRun {
        config: &retired_config,
        ..base_run
    };
    let retired_home = home("retired");
    let zap =
        |args: &[&str]| runner::run_host_zap(run, candidate, &retired_home, args, ZAP_TIMEOUT);
    locked(&zap(&["lock"])?, "the retired config")?;
    let plan = zap(&["plan", "--no-cache"])?;
    converged_problem(&plan)
        .and_then(|()| machine_named(&plan.stdout, PLAN_HEADER, distro.host(), NEXT_USER))
        .map_err(|problem| {
            format!(
                "the retired config's plan as {NEXT_USER} {}",
                with_report(&problem, &plan).trim_end()
            )
        })?;

    let run = HostRun {
        config: &provision,
        ..base_run
    };
    let after_home = home("provision-after");
    let zap = |args: &[&str]| runner::run_host_zap(run, candidate, &after_home, args, ZAP_TIMEOUT);
    let plan = zap(&["plan", "--no-cache"])?;
    plans_the_user_again(&plan)
        .and_then(|()| machine_named(&plan.stdout, PLAN_HEADER, distro.host(), NEXT_USER))
        .map_err(|problem| {
            format!(
                "the provision config's plan as {NEXT_USER}, {OPS} gone, {}",
                with_report(&problem, &plan).trim_end()
            )
        })?;
    let detect = zap(&["detect", "--no-cache"])?;
    unreadable_source_problem(&detect).map_err(|problem| {
        format!(
            "the provision config's detect as {NEXT_USER}, {OPS} gone, {}",
            with_report(&problem, &detect).trim_end()
        )
    })?;
    trace.notes.push(format!(
        "as {NEXT_USER}: the retired config reads converged; the provision config's \
         copy_from source reads unreadable, not converged"
    ));
    phase(trace, "after", started);
    Ok(())
}

/// `zap lock` succeeded on `what`.
fn locked(lock: &Captured, what: &str) -> Result<(), String> {
    if lock.success() {
        Ok(())
    } else {
        Err(format!(
            "`zap lock` on {what} failed: {}",
            lock.describe_failure()
        ))
    }
}

/// The base doesn't hold [`NEXT_USER`] (the kitchen sink's own `zapdiff` already
/// copies `ops`'s keys, so the scenario's user must be one nothing else made).
fn absent_before(distro: Distro) -> Result<(), String> {
    let checked = vm::root_shell(
        distro,
        &probe_script(
            "absent",
            &format!(
                "if id {NEXT_USER}; then exit 1; fi\n\
                 if [ -e /home/{NEXT_USER} ]; then ls -ld /home/{NEXT_USER}; exit 1; fi"
            ),
        ),
        SHELL_TIMEOUT,
    )?;
    probe_reading(&checked.stdout, "absent")
        .map(drop)
        .map_err(|error| format!("{NEXT_USER} already exists on the base: {error}"))
}

/// What the new user's keys were before the retire.
struct Keys {
    /// Its `authorized_keys`, as root read it.
    text: String,
    /// Its `sha256sum`, to read it unchanged after.
    digest: String,
}

/// The new user stands on its own (module docs, step 2); its keys, for after.
fn prove_next_user(distro: Distro) -> Result<Keys, String> {
    let own = vm::shell_as(
        distro,
        NEXT_USER,
        &[
            probe_script("whoami", "id -un"),
            probe_script("groups", "id -nG"),
            probe_script("sudo", "sudo -n true"),
        ]
        .join("\n"),
        SHELL_TIMEOUT,
    )?;
    if !own.success() {
        return Err(format!(
            "a shell as {NEXT_USER} failed: {}",
            own.describe_failure()
        ));
    }
    let reading = |stdout: &str, label: &str| {
        probe_reading(stdout, label).map_err(|error| format!("as {NEXT_USER}, `{label}`: {error}"))
    };
    let whoami = reading(&own.stdout, "whoami")?;
    if whoami != format!("{NEXT_USER}\n") {
        return Err(format!("a login as {NEXT_USER} is {whoami:?}"));
    }
    if let Some(problem) = groups_problem(&reading(&own.stdout, "groups")?) {
        return Err(problem);
    }
    reading(&own.stdout, "sudo")?;

    let sudoers = format!("/etc/sudoers.d/{NEXT_USER}");
    let keys = format!("/home/{NEXT_USER}/.ssh/authorized_keys");
    let root = vm::root_shell_as(
        distro,
        NEXT_USER,
        &[
            probe_script(
                "sudoers",
                &format!("stat -c '%a %U:%G' {sudoers}\ncat {sudoers}"),
            ),
            probe_script(
                "keys",
                &format!("cmp /home/{OPS}/.ssh/authorized_keys {keys}\nsha256sum < {keys}"),
            ),
            probe_script("key-text", &format!("cat {keys}")),
        ]
        .join("\n"),
        SHELL_TIMEOUT,
    )?;
    if !root.success() {
        return Err(format!(
            "a root shell as {NEXT_USER} failed: {}",
            root.describe_failure()
        ));
    }
    let granted = reading(&root.stdout, "sudoers")?;
    let expected = format!("440 root:root\n{NEXT_USER} ALL=(ALL) NOPASSWD: ALL\n");
    if granted != expected {
        return Err(format!(
            "{sudoers} isn't zap's grant, root's at 440:\n{}",
            compare::labeled_diff(("zap's", &expected), ("found", &granted), 1)
        ));
    }
    let digest = reading(&root.stdout, "keys")
        .map_err(|error| format!("{NEXT_USER}'s keys aren't {OPS}'s, byte for byte: {error}"))?;
    let text = reading(&root.stdout, "key-text")?;
    Ok(Keys { text, digest })
}

/// A user whose sudo comes from a group would prove nothing about zap's grant: `id -nG`
/// must name no `sudo`, `wheel`, or `admin` group.
fn groups_problem(groups: &str) -> Option<String> {
    let granting: Vec<&str> = groups
        .split_whitespace()
        .filter(|group| matches!(*group, "sudo" | "wheel" | "admin"))
        .collect();
    (!granting.is_empty()).then(|| {
        format!(
            "{NEXT_USER} is in {}, so its sudo needn't be zap's grant: {}",
            granting.join(", "),
            groups.trim()
        )
    })
}

/// The root script that retires `ops`, run through the new user's login (module docs,
/// step 3). It prints what it found and fails loud: a process that outlives the kill,
/// a cloud-init file that grants anything but `ops`, a `userdel` that refuses.
fn retire_script(distro: Distro) -> String {
    let (end_sessions, check_cloud_init, remove_cloud_init) = match distro {
        Distro::Debian => (
            format!("loginctl terminate-user {OPS} || true\n"),
            format!(
                "f={CLOUD_INIT_SUDOERS}\n\
                 if [ ! -f \"$f\" ]; then echo \"$f is missing: the VM's sudo for {OPS} is \
                 not what this scenario retires\"; exit 1; fi\n\
                 foreign=$(awk '!/^[ \\t]*(#|$)/ && $1 != \"{OPS}\"' \"$f\")\n\
                 if [ -n \"$foreign\" ]; then echo \"$f grants more than {OPS}:\"; \
                 echo \"$foreign\"; exit 1; fi\n"
            ),
            "rm -- \"$f\"\n".to_owned(),
        ),
        Distro::Alpine => (String::new(), String::new(), String::new()),
    };
    format!(
        "echo '{OPS} processes before the retire:'\n\
         pgrep -l -u {OPS} || true\n\
         {check_cloud_init}\
         {end_sessions}\
         pkill -KILL -u {OPS} || true\n\
         waited=0\n\
         while pgrep -u {OPS} >/dev/null; do\n  \
         waited=$((waited + 1))\n  \
         if [ \"$waited\" -gt 50 ]; then\n    \
         echo '{OPS} still has processes after the kill:'\n    \
         pgrep -l -u {OPS} || true\n    \
         exit 1\n  \
         fi\n  \
         sleep 0.2\n\
         done\n\
         userdel -r {OPS}\n\
         {remove_cloud_init}"
    )
}

/// `ops` is gone, and the new user's keys are as they were (module docs, step 4).
fn ops_gone(distro: Distro, keys_digest: &str) -> Result<(), String> {
    let keys = format!("/home/{NEXT_USER}/.ssh/authorized_keys");
    let checks = [
        (
            "account",
            format!("if id {OPS}; then exit 1; fi\necho none"),
        ),
        (
            "home",
            format!(
                "if [ -e /home/{OPS} ] || [ -L /home/{OPS} ]; then ls -ld /home/{OPS}; exit 1; fi\necho none"
            ),
        ),
        (
            "sudoers",
            format!(
                "found=$(grep -rnw {OPS} /etc/sudoers /etc/sudoers.d) || [ $? -eq 1 ]\n\
                 if [ -n \"$found\" ]; then echo \"$found\"; exit 1; fi\necho none"
            ),
        ),
        (
            "group",
            format!(
                "found=$(awk -F: '$1 == \"{OPS}\" || (\",\" $4 \",\") ~ /,{OPS},/' /etc/group)\n\
                 if [ -n \"$found\" ]; then echo \"$found\"; exit 1; fi\necho none"
            ),
        ),
        ("visudo", "visudo -c".to_owned()),
        ("keys", format!("sha256sum < {keys}")),
    ];
    let script: Vec<String> = checks
        .iter()
        .map(|(label, probe)| probe_script(label, probe))
        .collect();
    let checked = vm::root_shell_as(distro, NEXT_USER, &script.join("\n"), SHELL_TIMEOUT)?;
    if !checked.success() {
        return Err(format!(
            "a root shell as {NEXT_USER} after the retire failed: {}",
            checked.describe_failure()
        ));
    }
    for (label, _) in &checks {
        let reading = probe_reading(&checked.stdout, label)
            .map_err(|error| format!("after the retire, `{label}` doesn't hold: {error}"))?;
        if *label == "keys" && reading != keys_digest {
            return Err(format!(
                "{NEXT_USER}'s keys changed across the retire: {} then {}",
                keys_digest.trim(),
                reading.trim()
            ));
        }
    }
    Ok(())
}

/// `ssh ops@…` is refused, and a login as the new user right after succeeds: the pair,
/// so a VM that is down can't read as `ops` refused.
fn login_pair_problem(distro: Distro) -> Result<(), String> {
    let ops = vm::ssh_as(distro, OPS, "true", None, Duration::from_secs(30))?;
    let next = vm::ssh_as(distro, NEXT_USER, "id -un", None, Duration::from_secs(30))?;
    login_pair(&ops, &next)
}

/// See [`login_pair_problem`]: `ops`'s login exits 255 with sshd's refusal
/// (`Permission denied`), and the new user's prints its name.
fn login_pair(ops: &Captured, next: &Captured) -> Result<(), String> {
    if !(ops.code == Some(255) && ops.stderr.contains("Permission denied")) {
        return Err(format!(
            "a login as {OPS} after the retire isn't refused: {}",
            ops.describe_failure()
        ));
    }
    if next.code == Some(0) && next.stdout == format!("{NEXT_USER}\n") {
        Ok(())
    } else {
        Err(format!(
            "a login as {NEXT_USER} right after {OPS}'s refusal failed, so the refusal \
             proves nothing: {}",
            next.describe_failure()
        ))
    }
}

/// The `--bootstrap` preview creates the user and plans nothing else
/// (`reviewed::plans_exactly`), its change line a create.
fn creates_only_the_user(preview: &Captured) -> Result<(), String> {
    plans_exactly(preview, &[USER_ID], "declared")?;
    let create = format!("  [+] {USER_ID}  (user)");
    if preview.stdout.lines().any(|line| line == create) {
        Ok(())
    } else {
        Err(format!("plans the user, but not as a create ({create:?})"))
    }
}

/// What a report of the `header` kind (`runner::APPLY_HEADER`, `runner::PLAN_HEADER`)
/// lacks to name its machine: the header itself, and directly under it `host`, `user`,
/// and the declared target (`runner::subject_problem`).
fn machine_named(stdout: &str, header: &str, host: &str, user: &str) -> Result<(), String> {
    if !stdout.lines().any(|line| line.starts_with(header)) {
        return Err(format!("prints no `{}` header", header.trim_end()));
    }
    runner::subject_problem(header, stdout, Some(Machine { host, user })).map_or(Ok(()), Err)
}

/// A plan that reads converged: exit 0, no verdict banner, the converged marker, no
/// change line, and one `plan_hash`.
fn converged_problem(plan: &Captured) -> Result<(), String> {
    if plan.code != Some(0) {
        return Err(format!("failed: {}", plan.describe_failure()));
    }
    if let Some(banner) = plan.stdout.lines().find_map(compare::banner_name) {
        return Err(format!("reports {banner}"));
    }
    let changes: Vec<&str> = plan
        .stdout
        .lines()
        .filter(|line| compare::is_change_line(line))
        .map(str::trim)
        .collect();
    if !changes.is_empty() {
        return Err(format!("plans {}", changes.join("; ")));
    }
    if !plan
        .stdout
        .lines()
        .any(|line| line == "  (no changes — converged)")
    {
        return Err("doesn't read converged".to_owned());
    }
    one_plan_hash(&plan.stdout)
        .map(drop)
        .ok_or_else(|| "prints no one plan_hash".to_owned())
}

/// The `provision` config's plan once its `copy_from` source is gone: exit 0, no
/// verdict banner, one change, the user's update, and one `plan_hash`. Why it plans the
/// update is `detect`'s to say ([`unreadable_source_problem`]).
fn plans_the_user_again(plan: &Captured) -> Result<(), String> {
    if plan.code != Some(0) {
        return Err(format!("failed: {}", plan.describe_failure()));
    }
    if let Some(banner) = plan.stdout.lines().find_map(compare::banner_name) {
        return Err(format!("reports {banner}"));
    }
    let changes: Vec<&str> = plan
        .stdout
        .lines()
        .filter(|line| compare::is_change_line(line))
        .collect();
    let update = format!("  [~] {USER_ID}  (user)");
    if changes != [update.as_str()] {
        return Err(format!(
            "expected the one change {update:?}, found {changes:?}"
        ));
    }
    one_plan_hash(&plan.stdout)
        .map(drop)
        .ok_or_else(|| "prints no one plan_hash".to_owned())
}

/// The `provision` config's `detect` once its `copy_from` source is gone: a
/// well-formed report of its one resource, exit 0, the user read drifted for exactly
/// one reason, `ssh keys unreadable`. That is the drift that re-applies it (and the
/// apply's copy then fails loud), never a read of the copy as converged.
fn unreadable_source_problem(detect: &Captured) -> Result<(), String> {
    runner::well_formed("detect", detect, 1)?;
    if detect.code != Some(0) {
        return Err(format!("failed: {}", detect.describe_failure()));
    }
    let moved = runner::detect_movers(&detect.stdout);
    if moved != [(USER_ID.to_owned(), "drift".to_owned())] {
        return Err(format!("expected {USER_ID}(drift) alone, read {moved:?}"));
    }
    let reason = format!("  drift  {USER_ID}  user  — drifted (ssh keys unreadable)");
    if detect.stdout.lines().any(|line| line == reason) {
        Ok(())
    } else {
        Err(format!("doesn't read the one drift {reason:?}"))
    }
}

/// The keys module the `retired` config imports: each line of `authorized_keys` (the
/// new user's, as root read it) as one entry of `NEXT_USER_KEYS`, a JSON string
/// literal, which is a JS one. So `render_authorized_keys` of the list is the file
/// again, and a line can only ever be a string.
///
/// # Errors
/// The file holds no key, a blank line (zap refuses a blank entry), or a control
/// character (a key is one line of text).
fn render_keys_module(authorized_keys: &str) -> Result<String, String> {
    let body = authorized_keys
        .strip_suffix('\n')
        .unwrap_or(authorized_keys);
    if body.trim().is_empty() {
        return Err(format!("{NEXT_USER}'s authorized_keys holds no key"));
    }
    let mut entries = String::new();
    for (index, line) in body.split('\n').enumerate() {
        if line.trim().is_empty() {
            return Err(format!(
                "{NEXT_USER}'s authorized_keys line {} is blank: no keys entry can hold it",
                index + 1
            ));
        }
        if let Some(control) = line.chars().find(|c| c.is_control()) {
            return Err(format!(
                "{NEXT_USER}'s authorized_keys line {} holds U+{:04X}: a key is one line of text",
                index + 1,
                u32::from(control)
            ));
        }
        let literal = serde_json::to_string(line)
            .map_err(|error| format!("rendering a key failed: {error}"))?;
        let _ = writeln!(entries, "\t{literal},");
    }
    Ok(format!(
        "// Generated by `cargo xtask differential` for one run: the keys {NEXT_USER} holds.\n\
         export const NEXT_USER_KEYS: string[] = [\n{entries}];\n"
    ))
}

#[cfg(test)]
mod tests {
    use std::process::Command;

    use super::{
        NEXT_USER, converged_problem, creates_only_the_user, groups_problem, login_pair,
        machine_named, plans_the_user_again, render_keys_module, retire_script,
        unreadable_source_problem,
    };
    use crate::differential::process::Captured;
    use crate::differential::reviewed::tests::captured;
    use crate::differential::runner::{APPLY_HEADER, PLAN_HEADER};
    use crate::differential::vm::Distro;

    /// The retire parses as `sh`, ends `ops`'s processes before `userdel`, never
    /// forces it, and touches cloud-init's file on Debian alone, checking it first.
    #[test]
    fn the_retire_script_parses_and_never_forces() {
        for distro in Distro::ALL {
            let script = retire_script(distro);
            let checked = Command::new("sh")
                .args(["-n", "-c", &script])
                .output()
                .expect("sh runs");
            assert!(
                checked.status.success(),
                "{distro}: {}",
                String::from_utf8_lossy(&checked.stderr)
            );
            let at = |needle: &str| {
                script
                    .find(needle)
                    .unwrap_or_else(|| panic!("{distro}: {needle}"))
            };
            assert!(at("pkill -KILL -u ops") < at("userdel -r ops"));
            assert!(at("while pgrep -u ops") < at("userdel -r ops"));
            assert!(
                script.lines().any(|line| line == "userdel -r ops"),
                "{script}"
            );
            assert!(!script.contains("userdel -f") && !script.contains("-rf ops"));
            match distro {
                Distro::Debian => {
                    assert!(at("loginctl terminate-user ops") < at("pkill"));
                    assert!(at("grants more than ops") < at("userdel"));
                    assert!(at("userdel -r ops") < at("rm -- \"$f\""));
                }
                Distro::Alpine => {
                    assert!(!script.contains("loginctl") && !script.contains("cloud-init"));
                }
            }
        }
    }

    /// The retire's cloud-init check passes a file granting `ops` alone and stops at
    /// one that grants anyone else, before any process is killed.
    #[test]
    fn the_cloud_init_check_refuses_a_foreign_grant() {
        let script = retire_script(Distro::Debian);
        let check: String = script
            .lines()
            .skip_while(|line| !line.starts_with("f="))
            .take_while(|line| !line.starts_with("loginctl"))
            .fold(String::new(), |check, line| check + line + "\n");
        let scratch = tempfile::tempdir().expect("tempdir");
        let file = scratch.path().join("90-cloud-init-users");
        let run = |content: &str| {
            std::fs::write(&file, content).expect("write");
            let check = check.replace(super::CLOUD_INIT_SUDOERS, &file.to_string_lossy());
            Command::new("sh")
                .args(["-eu", "-c", &check])
                .output()
                .expect("sh runs")
        };
        let ops_only =
            "# Created by cloud-init\n\n# User rules for ops\nops ALL=(ALL) NOPASSWD:ALL\n";
        assert!(run(ops_only).status.success());
        let foreign = run(&format!("{ops_only}deploy ALL=(ALL) ALL\n"));
        assert!(!foreign.status.success());
        assert!(String::from_utf8_lossy(&foreign.stdout).contains("deploy ALL=(ALL) ALL"));
        std::fs::remove_file(&file).expect("rm");
        let missing = Command::new("sh")
            .args([
                "-eu",
                "-c",
                &check.replace(super::CLOUD_INIT_SUDOERS, &file.to_string_lossy()),
            ])
            .output()
            .expect("sh runs");
        assert!(!missing.status.success());
    }

    const KEY: &str =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGRpZmZlcmVudGlhbC1oYXJuZXNzLWtleQ op@dev";

    /// Each line is one entry, a string literal whatever it holds: a quote or a
    /// backslash can't end it, and the entries are the file's lines again.
    #[test]
    fn the_keys_module_holds_each_line_as_a_string() {
        let module = render_keys_module(&format!("{KEY}\n")).expect("a module");
        assert_eq!(
            module,
            format!(
                "// Generated by `cargo xtask differential` for one run: the keys zapnext \
                 holds.\nexport const NEXT_USER_KEYS: string[] = [\n\t\"{KEY}\",\n];\n"
            )
        );
        let hostile = "ssh-ed25519 AAAA x\"]; import evil from \"./evil.ts\"; //\\";
        let module = render_keys_module(&format!("{KEY}\n{hostile}")).expect("a module");
        let entries: Vec<String> = module
            .lines()
            .filter_map(|line| line.strip_prefix('\t')?.strip_suffix(','))
            .map(|literal| serde_json::from_str(literal).expect("a JSON string"))
            .collect();
        assert_eq!(entries, [KEY, hostile]);
        assert!(!module.contains("import evil from \"./evil.ts\""));
        assert_eq!(
            module
                .lines()
                .filter(|line| line.contains("import"))
                .count(),
            1
        );
    }

    #[test]
    fn the_keys_module_refuses_what_no_entry_can_hold() {
        for (text, refusal) in [
            (String::new(), "holds no key"),
            ("\n".to_owned(), "holds no key"),
            (format!("{KEY}\n\n{KEY}\n"), "line 2 is blank"),
            (format!("{KEY}\r\n"), "line 1 holds U+000D"),
            (format!("{KEY}\n{KEY}\0x\n"), "line 2 holds U+0000"),
            (format!("{KEY}\tx\n"), "line 1 holds U+0009"),
        ] {
            let error = render_keys_module(&text).expect_err(&text);
            assert!(error.contains(refusal), "{text:?}: {error}");
        }
        // a file with no final newline is the same key list
        assert_eq!(
            render_keys_module(KEY),
            render_keys_module(&format!("{KEY}\n"))
        );
    }

    #[test]
    fn a_granting_group_is_named() {
        assert_eq!(groups_problem("zapnext\n"), None);
        assert_eq!(groups_problem("zapnext users sudoers\n"), None);
        for group in ["sudo", "wheel", "admin"] {
            let problem = groups_problem(&format!("zapnext {group} video\n")).expect(group);
            assert!(
                problem.starts_with(&format!("zapnext is in {group}, ")),
                "{problem}"
            );
        }
    }

    fn ssh(code: i32, stdout: &str, stderr: &str) -> Captured {
        Captured {
            code: Some(code),
            stdout: stdout.to_owned(),
            stderr: stderr.to_owned(),
            timed_out: false,
        }
    }

    /// `ops` refused by sshd, then the new user in: a VM that is down, or an `ops`
    /// that still logs in, fails it.
    #[test]
    fn the_login_pair_needs_a_refusal_then_a_login() {
        let refused = ssh(
            255,
            "",
            "ops@192.168.122.10: Permission denied (publickey).\n",
        );
        let next = ssh(0, &format!("{NEXT_USER}\n"), "");
        assert_eq!(login_pair(&refused, &next), Ok(()));
        let down = ssh(
            255,
            "",
            "ssh: connect to host 192.168.122.10 port 22: No route to host\n",
        );
        assert!(login_pair(&down, &next).is_err());
        assert!(login_pair(&ssh(0, "", ""), &next).is_err());
        let next_down = ssh(
            255,
            "",
            "ssh: connect to host 192.168.122.10 port 22: timed out\n",
        );
        let error = login_pair(&refused, &next_down).expect_err("down");
        assert!(error.contains("proves nothing"), "{error}");
        assert!(login_pair(&refused, &ssh(0, "root\n", "")).is_err());
    }

    const PREVIEW: &str = "apply — target {env:ZAPDIFF_HOST} (dry-run)\n  host: 192.168.122.10\n  \
        user: ops\n  target: {\"local\":false}\n  [+] next-user  (user)\n      username: zapnext\n  \
        (dry-run — re-run with --wetrun to apply)\nplan_hash: 1de19df0\n";

    #[test]
    fn the_preview_creates_the_user_alone_as_ops() {
        let preview = captured(2, PREVIEW);
        assert_eq!(creates_only_the_user(&preview), Ok(()));
        let named = |stdout: &str, host, user| machine_named(stdout, APPLY_HEADER, host, user);
        assert_eq!(named(PREVIEW, "192.168.122.10", "ops"), Ok(()));
        assert!(named(PREVIEW, "192.168.122.10", "zapnext").is_err());
        assert!(named(PREVIEW, "192.168.122.11", "ops").is_err());
        // a preview isn't a plan
        assert_eq!(
            machine_named(PREVIEW, PLAN_HEADER, "192.168.122.10", "ops"),
            Err("prints no `plan — target` header".to_owned())
        );
        let update = PREVIEW.replace("[+] next-user", "[~] next-user");
        assert!(creates_only_the_user(&captured(2, &update)).is_err());
        let more = PREVIEW.replace("  (dry-run", "  [+] other  (file)\n  (dry-run");
        assert!(creates_only_the_user(&captured(2, &more)).is_err());
        // the machine lines are the ones directly under the header, not the first that
        // spell one: a `host:` further down (here, inside a step) names nothing
        let buried = PREVIEW
            .replace("  host: 192.168.122.10\n  user: ops\n  target", "  target")
            .replace(
                "      username: zapnext\n",
                "      username: zapnext\n  host: 192.168.122.10\n  user: ops\n",
            );
        let error = named(&buried, "192.168.122.10", "ops").expect_err("buried");
        assert!(error.starts_with("doesn't name its machine"), "{error}");
        // nor is a host line with no target under it enough
        let untargeted = PREVIEW.replace("  target: {\"local\":false}\n", "");
        let error = named(&untargeted, "192.168.122.10", "ops").expect_err("no target");
        assert!(
            error.starts_with("doesn't print its declared target"),
            "{error}"
        );
    }

    const CONVERGED: &str = "plan — target {env:ZAPDIFF_HOST} (0 change(s): +0 ~0)\n  \
        host: 192.168.122.10\n  user: zapnext\n  target: {\"local\":false}\n  \
        (no changes — converged)\nplan_hash: ab\n";

    #[test]
    fn a_converged_plan_plans_nothing() {
        assert_eq!(converged_problem(&captured(0, CONVERGED)), Ok(()));
        assert_eq!(
            machine_named(CONVERGED, PLAN_HEADER, "192.168.122.10", "zapnext"),
            Ok(())
        );
        assert!(converged_problem(&captured(1, CONVERGED)).is_err());
        let drift = CONVERGED.replace("  (no changes — converged)\n", "  [~] next-user  (user)\n");
        assert!(converged_problem(&captured(0, &drift)).is_err());
        let banner = format!("  UNDETERMINED — 1 resource(s) could not be probed\n{CONVERGED}");
        assert!(converged_problem(&captured(0, &banner)).is_err());
        assert!(
            converged_problem(&captured(0, &CONVERGED.replace("plan_hash: ab\n", ""))).is_err()
        );
    }

    #[test]
    fn an_unreadable_source_plans_the_user_again() {
        let again = CONVERGED.replace(
            "  (no changes — converged)\n",
            "  [~] next-user  (user)\n      > sudo usermod -p '*' -- 'zapnext'\n",
        );
        assert_eq!(plans_the_user_again(&captured(0, &again)), Ok(()));
        assert!(plans_the_user_again(&captured(0, CONVERGED)).is_err());
        assert!(plans_the_user_again(&captured(1, &again)).is_err());
        let more = again.replace("plan_hash", "  [+] x  (file)\nplan_hash");
        assert!(plans_the_user_again(&captured(0, &more)).is_err());

        let detect = "detected live state — target x (pkg: apk, service: none)\n\
            1 resource(s):\n  drift  next-user  user  — drifted (ssh keys unreadable)\n";
        assert_eq!(unreadable_source_problem(&captured(0, detect)), Ok(()));
        for other in [
            "drifted (ssh keys content differs)",
            "drifted (ssh keys unreadable, shell differs)",
        ] {
            let read = detect.replace("drifted (ssh keys unreadable)", other);
            assert!(
                unreadable_source_problem(&captured(0, &read)).is_err(),
                "{other}"
            );
        }
        let converged = detect.replace(
            "  drift  next-user  user  — drifted (ssh keys unreadable)",
            "  ok     next-user  user  — converged",
        );
        assert!(unreadable_source_problem(&captured(0, &converged)).is_err());
        assert!(unreadable_source_problem(&captured(1, detect)).is_err());
    }
}
