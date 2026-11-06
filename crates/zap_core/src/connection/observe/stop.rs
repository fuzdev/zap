//! Stopping a batch past its deadline or output limit, per [`BatchProcess`]: over SSH
//! its process group and session killed on the target, then the ssh client; a local
//! login batch's process group killed; a local root batch's `sudo` sent `SIGTERM` then
//! `SIGKILL`.

use super::process::{BatchProcess, ROOT_TERM_GRACE};

/// Stop a batch — the local child still held, so its ID is still reserved — then reap it.
/// Best-effort throughout: a process may already be gone. `pgid` is the process group the
/// batch reported, if it reported one yet.
pub(super) async fn stop(
    child: &mut tokio::process::Child,
    process: BatchProcess<'_>,
    pgid: Option<u32>,
) {
    use nix::sys::signal::{Signal, kill, killpg};
    use nix::unistd::Pid;

    let pid = child
        .id()
        .and_then(|id| i32::try_from(id).ok())
        .map(Pid::from_raw);
    match (process, pid) {
        // The target-side kill first, then the client. The client doesn't reserve the
        // target's id: the kernel won't reissue pid P while any process still has P as
        // its process group or session, so the id can name another process only once
        // the whole batch has exited and the pid space wrapped — within the kill's own
        // round-trip. A check of `/proc/P` first would narrow nothing (it races the same
        // way) and would skip the case the kill is for: the batch shell gone, a hung
        // probe of its session still running.
        (BatchProcess::Ssh { conn, lane }, _) => {
            if let Some(pgid) = pgid {
                conn.kill_batch(lane, pgid).await;
            }
        }
        (BatchProcess::LocalLogin, Some(pid)) => {
            // The batch's descendants, listed while each is still its parent's child: a
            // command runs in a session of its own, and GNU `timeout` in a process group
            // of its own, which the batch's group kill doesn't reach.
            // Only a group a descendant *leads* (its id is the descendant's own pid) is
            // killed whole: a group a descendant merely sits in may be the operator's
            // own, since the batch shares the terminal's session.
            let below = descendants(pid.as_raw());
            let _ = killpg(pid, Signal::SIGKILL);
            for &(child, group) in &below {
                if group == child {
                    let _ = killpg(Pid::from_raw(group), Signal::SIGKILL);
                }
                let _ = kill(Pid::from_raw(child), Signal::SIGKILL);
            }
        }
        (BatchProcess::LocalRoot, Some(pid)) => {
            let _ = kill(pid, Signal::SIGTERM);
            if tokio::time::timeout(ROOT_TERM_GRACE, child.wait())
                .await
                .is_ok()
            {
                return;
            }
        }
        (BatchProcess::LocalLogin | BatchProcess::LocalRoot, None) => {}
    }
    let _ = child.kill().await;
}

/// Every descendant of process `root`, with its process group — read from `/proc`, so
/// only on Linux; elsewhere, and for a process gone meanwhile, nothing.
fn descendants(root: i32) -> Vec<(i32, i32)> {
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return Vec::new();
    };
    // (pid, parent, group) for every process whose `stat` reads.
    let table: Vec<(i32, i32, i32)> = entries
        .flatten()
        .filter_map(|entry| {
            let pid = entry.file_name().to_str()?.parse::<i32>().ok()?;
            let stat = std::fs::read_to_string(entry.path().join("stat")).ok()?;
            // After the command name, which may hold spaces and parentheses: state,
            // parent, group.
            let mut fields = stat.rsplit_once(')')?.1.split_whitespace().skip(1);
            let parent = fields.next()?.parse().ok()?;
            let group = fields.next()?.parse().ok()?;
            Some((pid, parent, group))
        })
        .collect();
    let mut found = Vec::new();
    let mut frontier = vec![root];
    while let Some(parent) = frontier.pop() {
        for &(pid, of, group) in &table {
            if of == parent && !found.iter().any(|&(seen, _)| seen == pid) {
                found.push((pid, group));
                frontier.push(pid);
            }
        }
    }
    found
}
