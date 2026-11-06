//! What a scenario must *not* do, checked around its zap runs: write to the target,
//! change its runtime state, or fetch remote content (the commands under test are
//! read-only and network-free). Plus the per-run `zap.lock`s: the operator-side
//! scenario edits to them, and the comparison of the two the binaries minted.
//!
//! The audit is built to fail loud: a failed `find`/`stat`, an audited root missing
//! from its output, or a missing positive control (a canary file the audit touches
//! itself and must then report — exactly once) is an error, never an empty "clean".

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::time::Duration;

use super::compare;
use super::vm::{self, Distro};

/// Trees where a write by `detect` / `plan` would be a finding (plus `/` itself and
/// every regular file directly under it, like a swap file — a deleted top-level file
/// shows as `/`'s changed ctime). `/usr` holds `/usr/share/keyrings`
/// and, with `/lib` (Alpine's apk database is `/lib/apk/db`), where packages land.
const AUDITED: &[&str] = &[
    "/etc", "/opt", "/home", "/root", "/srv", "/usr", "/lib", "/var/lib",
];

/// Subtrees with proven writes that aren't zap's, pruned from the audit.
/// `/var/lib/zap` (zap's own target state) is deliberately *not* here: `plan` and
/// `detect` must leave it untouched too.
const CHURN: &[&str] = &[
    // the harness's own dir on the VM: the local suite's bundle and its ZAP_HOMEs
    "/home/ops/.zapdiff-harness",
    // the user's own cache on the VM: the local suite's zap runs there as `ops`, and
    // `fgro` evaluates with no module cache, so nothing of the eval lands here; kept
    // pruned for what the login session's tools write
    "/home/ops/.cache",
    // the postgres server's own data files (stats, WAL) under a running cluster
    "/var/lib/postgresql",
    // systemd-timesyncd saving the clock (Debian), which the post-revert clock set
    // brings forward
    "/var/lib/systemd/timesync",
];

/// The positive control: created with the mutation (before the stamp), touched by
/// the audit itself, which must then report it — and nothing else it didn't expect.
const CANARY: &str = "/usr/local/.zapdiff-audit-canary";

/// Output markers between the scripts' sections.
const SECTION: &str = "@@zapdiff section ";
const FAILED: &str = "@@zapdiff audit-failed";
const MISSING_ROOT: &str = "@@zapdiff missing-root ";

/// The runtime-state digest: state no file write shows. Each section's output is
/// compared verbatim between the post-mutation and post-run snapshots. Services are
/// captured with an **identity** per running service — systemd's `MainPID` + start
/// timestamp, each `openrc` daemon's pid + `/proc` start time, plus `/run` pidfiles — so a
/// restart moves the digest (a reload doesn't, but the fixture's reloadable service
/// writes a file on reload, which the write audit sees). The ruleset is listed with
/// handles (`nft -a`), which a reload renumbers. Proven churn only is dropped:
///
/// - iptables-nft rule counters (`nft list ruleset` shows ufw's `ip filter` tables
///   on Alpine, where ufw runs beside the nftables table): they count the harness's
///   own traffic;
/// - `/proc/swaps`' `Used` column: it moves when the local suite's zap and fgro runs
///   press the guest's memory;
/// - `user@<uid>.service`: the login user's systemd manager, restarted between the
///   harness's own ssh sessions.
const DIGEST: &str = r#"cd /
# a probe that fails (psql against a stopped server) is state too, not an abort
set +e
echo '@@zapdiff section firewall'
if command -v ufw >/dev/null 2>&1; then ufw status verbose 2>&1; fi
if command -v nft >/dev/null 2>&1; then
  nft -a list ruleset 2>&1 | sed -E 's/counter packets [0-9]+ bytes [0-9]+/counter/'
fi
echo '@@zapdiff section services'
if command -v systemctl >/dev/null 2>&1; then
  systemctl list-units --type=service --state=running --no-legend --plain 2>&1 \
    | awk '$1 !~ /^user@/ {print $1}'
  echo '-- enabled'
  systemctl list-unit-files --state=enabled --no-legend 2>&1 | awk '{print $1}'
  echo '-- identity'
  systemctl list-units --type=service --state=running --no-legend --plain 2>&1 \
    | awk '$1 !~ /^user@/ {print $1}' \
    | xargs -r systemctl show -p Id,MainPID,ExecMainStartTimestampMonotonic 2>&1
fi
if command -v rc-status >/dev/null 2>&1; then
  rc-status -a 2>&1
  ls /etc/runlevels/* 2>&1
  echo '-- identity'
  for d in /run/openrc/daemons/*/*; do
    [ -f "$d" ] || continue
    pid=$(head -n 1 "$(sed -n 's/^pidfile=//p' "$d")" 2>/dev/null)
    echo "${d#/run/openrc/daemons/} pid=$pid start=$(awk '{print $22}' "/proc/$pid/stat" 2>/dev/null)"
  done
  for f in /run/*.pid /run/*/*.pid; do [ -f "$f" ] && echo "$f $(cat "$f")"; done
fi
echo '@@zapdiff section swaps'
awk '{print $1, $2, $3, $5}' /proc/swaps
echo '@@zapdiff section postgres'
sudo -u postgres psql -tAc 'select rolname from pg_roles order by 1' 2>&1
sudo -u postgres psql -tAc "select datname || ' ' || pg_get_userbyid(datdba) from pg_database order by 1" 2>&1
true
"#;

/// Appended to every scenario's mutation: plant the canary, record the second the
/// target was put in its state and wait that second out, then snapshot the runtime
/// state. The audit flags anything written in a *later* second. busybox has neither
/// `find -cnewer` nor sub-second `stat`, so the stamp is an integer epoch and the
/// guard sleep keeps a mutation's own writes (all in or before the stamp's second)
/// from reading as the zap runs'.
pub fn after_mutation() -> String {
    format!(": > {CANARY}\ndate +%s > /run/zapdiff-stamp\nsleep 1\n{DIGEST}")
}

/// The root shell script run after the zap runs: touch the canary, list every
/// audited path whose mtime or ctime is after the stamp's second (failing loud),
/// remove the canary, then snapshot the runtime state again.
pub fn audit_script() -> String {
    let prune = CHURN
        .iter()
        .map(|path| format!("-path '{path}'"))
        .collect::<Vec<_>>()
        .join(" -o ");
    let roots = AUDITED.join(" ");
    format!(
        "touch {CANARY}\n\
         stamp=$(cat /run/zapdiff-stamp)\n\
         if {{ find {roots} \\( {prune} \\) -prune -o -exec stat -c '%Y %Z %n' {{}} + && \
         find / -maxdepth 1 -xdev \\( -type f -o -path / \\) -exec stat -c '%Y %Z %n' {{}} + ; }} \
         > /run/zapdiff-audit.stat 2> /run/zapdiff-audit.err && [ ! -s /run/zapdiff-audit.err ]; \
         then :; else\n  \
         echo '{FAILED}'; head -c 2000 /run/zapdiff-audit.err; fi\n\
         for root in {roots}; do\n  \
         grep -q \" $root\\$\" /run/zapdiff-audit.stat || echo \"{MISSING_ROOT}$root\"\n\
         done\n\
         echo '{SECTION}writes'\n\
         awk -v s=\"$stamp\" '$1 > s || $2 > s {{ sub(/^[0-9]+ [0-9]+ /, \"\"); print }}' \
         /run/zapdiff-audit.stat\n\
         rm -f {CANARY} /run/zapdiff-audit.stat /run/zapdiff-audit.err\n\
         {DIGEST}"
    )
}

/// Split script output into its `@@zapdiff section` bodies; text before the first
/// marker goes under `""`.
pub fn sections(stdout: &str) -> BTreeMap<String, String> {
    let mut out: BTreeMap<String, String> = BTreeMap::new();
    let mut current = String::new();
    for line in stdout.lines() {
        if let Some(name) = line.strip_prefix(SECTION) {
            name.clone_into(&mut current);
            out.entry(current.clone()).or_default();
        } else {
            let body = out.entry(current.clone()).or_default();
            body.push_str(line);
            body.push('\n');
        }
    }
    out
}

/// What the post-mutation digest must show. A probe that fails the same way before
/// and after the runs (a missing tool, a stopped server, an identity loop that
/// printed nothing) would otherwise leave its section equal — and blind. A scenario
/// that deliberately stops the sleeper or postgres, or removes the firewall, drops
/// that anchor.
#[derive(Debug, Clone, Copy)]
pub struct Anchors {
    /// Whether the services section must carry the fixture sleeper's live identity.
    pub sleeper: bool,
    /// Text the firewall section must contain.
    pub firewall: Option<&'static str>,
    /// Whether the postgres section must list the `postgres` role.
    pub postgres: bool,
}

/// The anchors `before` (the post-mutation digest) lacks.
pub fn anchor_problems(before: &BTreeMap<String, String>, anchors: Anchors) -> Vec<String> {
    let section = |name: &str| before.get(name).map_or("", String::as_str);
    let mut problems = Vec::new();
    if anchors.sleeper && !has_sleeper_identity(section("services")) {
        problems.push(
            "the runtime digest's services section has no live identity for zapdiff-sleeper"
                .to_owned(),
        );
    }
    if anchors.postgres && !section("postgres").lines().any(|line| line == "postgres") {
        problems.push("the runtime digest's postgres section lists no `postgres` role".to_owned());
    }
    if let Some(anchor) = anchors.firewall
        && !section("firewall").contains(anchor)
    {
        problems.push(format!(
            "the runtime digest's firewall section lacks `{anchor}`"
        ));
    }
    problems
}

/// Whether `services` carries the sleeper's identity with a real pid: `openrc`'s
/// `zapdiff-sleeper/<n> pid=<digits> start=<digits>`, or a systemd `show` block
/// holding `Id=zapdiff-sleeper.service` and a non-zero `MainPID`.
fn has_sleeper_identity(services: &str) -> bool {
    let digits = |s: &str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit());
    let openrc = services.lines().any(|line| {
        let Some(rest) = line.strip_prefix("zapdiff-sleeper/") else {
            return false;
        };
        let mut fields = rest.split(' ');
        let (Some(index), Some(pid), Some(start), None) =
            (fields.next(), fields.next(), fields.next(), fields.next())
        else {
            return false;
        };
        digits(index)
            && pid.strip_prefix("pid=").is_some_and(digits)
            && start.strip_prefix("start=").is_some_and(digits)
    });
    let systemd = services.split("\n\n").any(|block| {
        let lines: Vec<&str> = block.lines().collect();
        lines.contains(&"Id=zapdiff-sleeper.service")
            && lines.iter().any(|line| {
                line.strip_prefix("MainPID=")
                    .is_some_and(|pid| digits(pid) && pid != "0")
            })
    });
    openrc || systemd
}

/// Run the post-run audit script and return its output sections.
pub fn run_audit(distro: Distro) -> Result<BTreeMap<String, String>, String> {
    let output = vm::root_shell(distro, &audit_script(), Duration::from_secs(180))?;
    if !output.success() {
        return Err(format!(
            "the target audit failed: {}",
            output.describe_failure()
        ));
    }
    Ok(sections(&output.stdout))
}

/// Judge the audit: every problem with its evidence (empty when clean). `before`
/// is the post-mutation output, `after` the post-run audit's.
pub fn judge(before: &BTreeMap<String, String>, after: &BTreeMap<String, String>) -> Vec<String> {
    let mut problems = Vec::new();
    let preamble = after.get("").map_or("", String::as_str);
    if let Some(index) = preamble.find(FAILED) {
        problems.push(format!(
            "the write audit's find/stat failed: {}",
            preamble[index + FAILED.len()..].trim()
        ));
    }
    for line in preamble.lines() {
        if let Some(root) = line.strip_prefix(MISSING_ROOT) {
            problems.push(format!("the write audit never listed {root}"));
        }
    }
    let mut writes: Vec<&str> = after
        .get("writes")
        .map(|w| w.lines().collect())
        .unwrap_or_default();
    let canaries = writes.iter().filter(|w| **w == CANARY).count();
    if canaries == 1 {
        writes.retain(|w| *w != CANARY);
    } else {
        problems.push(format!(
            "the write audit's positive control failed: {CANARY} reported {canaries} time(s), \
             expected once"
        ));
    }
    if !writes.is_empty() {
        problems.push(format!(
            "the read-only commands wrote to the target: {}",
            writes.join(", ")
        ));
    }
    for (name, was) in before.iter().filter(|(name, _)| !name.is_empty()) {
        match after.get(name) {
            Some(now) if now == was => {}
            Some(now) => {
                let mut problem = format!("the read-only commands changed runtime state: {name}\n");
                let _ = write!(
                    problem,
                    "{}",
                    compare::labeled_diff(("after the mutation", was), ("after the runs", now), 1)
                );
                problems.push(problem.trim_end().to_owned());
            }
            None => problems.push(format!(
                "the post-run runtime digest has no `{name}` section"
            )),
        }
    }
    if before.keys().filter(|name| !name.is_empty()).count() < 4 {
        problems.push("the post-mutation runtime digest is incomplete".to_owned());
    }
    problems
}

/// An edit to one binary's per-run `zap.lock`, undone on drop so the next scenario
/// sees the lock `zap lock` minted. A scenario makes the same edit to both binaries'
/// locks.
#[derive(Debug)]
pub struct LockEdit {
    path: PathBuf,
    original: Vec<u8>,
}

impl LockEdit {
    /// Remove the `drop` entries and give the `stale` entries a `config_hash` no
    /// config produces.
    pub fn apply(path: &Path, drop: &[&str], stale: &[&str]) -> Result<Self, String> {
        let original = std::fs::read(path)
            .map_err(|error| format!("reading {} failed: {error}", path.display()))?;
        let edited = edit_lock(&original, drop, stale)?;
        std::fs::write(path, edited)
            .map_err(|error| format!("writing {} failed: {error}", path.display()))?;
        Ok(Self {
            path: path.to_path_buf(),
            original,
        })
    }
}

impl Drop for LockEdit {
    fn drop(&mut self) {
        if let Err(error) = std::fs::write(&self.path, &self.original) {
            eprintln!("warning: restoring {} failed: {error}", self.path.display());
        }
    }
}

/// The pure half of [`LockEdit::apply`].
pub fn edit_lock(lock: &[u8], drop: &[&str], stale: &[&str]) -> Result<Vec<u8>, String> {
    let mut value: serde_json::Value =
        serde_json::from_slice(lock).map_err(|error| format!("zap.lock isn't JSON: {error}"))?;
    let entries = value
        .get_mut("entries")
        .and_then(serde_json::Value::as_object_mut)
        .ok_or("zap.lock has no `entries` object")?;
    for id in drop {
        entries
            .remove(*id)
            .ok_or_else(|| format!("zap.lock has no `{id}` entry to drop"))?;
    }
    for id in stale {
        let entry = entries
            .get_mut(*id)
            .and_then(serde_json::Value::as_object_mut)
            .ok_or_else(|| format!("zap.lock has no `{id}` entry to make stale"))?;
        entry.insert("config_hash".to_owned(), "0".repeat(64).into());
    }
    serde_json::to_vec_pretty(&value).map_err(|error| format!("re-encoding zap.lock: {error}"))
}

/// How the two binaries' freshly minted `zap.lock`s compare.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct LockComparison {
    /// Differences in what is pinned: the `version`, the set of ids, an entry's `kind`
    /// or its `blake3`. The two binaries locked different things.
    pub pins: Vec<String>,
    /// Entries whose `config_hash` differs, with both values. The pin is the same; the
    /// two binaries address the config that produced it differently.
    pub addresses: Vec<String>,
}

/// Compare the `zap.lock` each binary minted from the same config and content.
///
/// Both write the same `version` (a binary stamps its own on every write, so a
/// difference is a format change, not a leftover) and must pin the same ids, each with
/// the same `kind` and `blake3`. An entry's `config_hash` — 64 lowercase hex digits on
/// both sides — is reported apart: it is each binary's own address of the declaring
/// config, and whether a difference there is a divergence is the compare level's call.
///
/// # Errors
/// A lock that isn't the shape above: not JSON, no numeric `version`, no `entries`
/// object, an entry without a string `kind` / `blake3`, or a malformed `config_hash`.
pub fn compare_locks(oracle: &[u8], candidate: &[u8]) -> Result<LockComparison, String> {
    let oracle = parse_lock("oracle", oracle)?;
    let candidate = parse_lock("candidate", candidate)?;
    let mut comparison = LockComparison::default();
    if oracle.version != candidate.version {
        comparison.pins.push(format!(
            "version: oracle {} vs candidate {}",
            oracle.version, candidate.version
        ));
    }
    // both evaluate with the one fgro the harness gives them, so both pin it
    if oracle.toolchain != candidate.toolchain {
        comparison.pins.push(format!(
            "toolchain: oracle {} vs candidate {}",
            oracle.toolchain.as_deref().unwrap_or("none"),
            candidate.toolchain.as_deref().unwrap_or("none")
        ));
    }
    for (id, entry) in &oracle.entries {
        let Some(other) = candidate.entries.get(id) else {
            comparison
                .pins
                .push(format!("`{id}`: pinned by the oracle only"));
            continue;
        };
        for (field, a, b) in [
            ("kind", &entry.kind, &other.kind),
            ("blake3", &entry.blake3, &other.blake3),
        ] {
            if a != b {
                comparison
                    .pins
                    .push(format!("`{id}` {field}: oracle {a} vs candidate {b}"));
            }
        }
        if entry.config_hash != other.config_hash {
            comparison.addresses.push(format!(
                "`{id}` config_hash: oracle {} vs candidate {}",
                entry.config_hash, other.config_hash
            ));
        }
    }
    for id in candidate.entries.keys() {
        if !oracle.entries.contains_key(id) {
            comparison
                .pins
                .push(format!("`{id}`: pinned by the candidate only"));
        }
    }
    Ok(comparison)
}

/// The fields of a `zap.lock` that [`compare_locks`] reads.
struct ParsedLock {
    version: u64,
    /// `toolchain.fgro_blake3`, when the lock pins one.
    toolchain: Option<String>,
    entries: BTreeMap<String, ParsedEntry>,
}

struct ParsedEntry {
    kind: String,
    blake3: String,
    config_hash: String,
}

fn parse_lock(side: &str, lock: &[u8]) -> Result<ParsedLock, String> {
    let value: serde_json::Value = serde_json::from_slice(lock)
        .map_err(|error| format!("the {side}'s zap.lock isn't JSON: {error}"))?;
    let version = value
        .get("version")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| format!("the {side}'s zap.lock has no numeric `version`"))?;
    let entries = value
        .get("entries")
        .and_then(serde_json::Value::as_object)
        .ok_or_else(|| format!("the {side}'s zap.lock has no `entries` object"))?;
    let entries = entries
        .iter()
        .map(|(id, entry)| {
            let field = |name: &str| {
                entry
                    .get(name)
                    .and_then(serde_json::Value::as_str)
                    .map(str::to_owned)
                    .ok_or_else(|| {
                        format!("the {side}'s zap.lock entry `{id}` has no string `{name}`")
                    })
            };
            let config_hash = field("config_hash")?;
            let well_formed = config_hash.len() == 64
                && config_hash
                    .bytes()
                    .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'));
            if !well_formed {
                return Err(format!(
                    "the {side}'s zap.lock entry `{id}` has a malformed config_hash: \
                     {config_hash:?}"
                ));
            }
            let parsed = ParsedEntry {
                kind: field("kind")?,
                blake3: field("blake3")?,
                config_hash,
            };
            Ok((id.clone(), parsed))
        })
        .collect::<Result<_, String>>()?;
    let toolchain = value
        .get("toolchain")
        .and_then(|toolchain| toolchain.get("fgro_blake3"))
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned);
    Ok(ParsedLock {
        version,
        toolchain,
        entries,
    })
}

#[cfg(test)]
mod tests {
    use super::{
        Anchors, CANARY, FAILED, LockComparison, MISSING_ROOT, anchor_problems, audit_script,
        compare_locks, edit_lock, has_sleeper_identity, judge, sections,
    };

    /// A `zap.lock` with one `remote_file` and one `build` entry.
    fn lock(version: u32, blob: (&str, &str), build: (&str, &str)) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "version": version,
            "entries": {
                "blob-tracked": {"kind": "remote_file", "config_hash": blob.0, "blake3": blob.1},
                "build-tracked": {"kind": "build", "config_hash": build.0, "blake3": build.1},
            }
        }))
        .expect("json")
    }

    fn hex(digit: char) -> String {
        digit.to_string().repeat(64)
    }

    #[test]
    fn equal_locks_compare_clean_whatever_their_layout() {
        let a = lock(1, (&hex('a'), "p1"), (&hex('b'), "p2"));
        let pretty = serde_json::to_vec_pretty(
            &serde_json::from_slice::<serde_json::Value>(&a).expect("json"),
        )
        .expect("json");
        assert_eq!(compare_locks(&a, &pretty), Ok(LockComparison::default()));
    }

    #[test]
    fn a_config_hash_difference_is_an_address_difference_only() {
        let oracle = lock(1, (&hex('a'), "p1"), (&hex('b'), "p2"));
        let candidate = lock(1, (&hex('c'), "p1"), (&hex('b'), "p2"));
        let comparison = compare_locks(&oracle, &candidate).expect("well-formed");
        assert!(comparison.pins.is_empty(), "{comparison:?}");
        assert_eq!(
            comparison.addresses,
            [format!(
                "`blob-tracked` config_hash: oracle {} vs candidate {}",
                hex('a'),
                hex('c')
            )]
        );
    }

    #[test]
    fn a_pin_kind_version_or_id_difference_is_a_pin_difference() {
        let oracle = lock(1, (&hex('a'), "p1"), (&hex('b'), "p2"));
        let candidate = lock(2, (&hex('a'), "other"), (&hex('b'), "p2"));
        let comparison = compare_locks(&oracle, &candidate).expect("well-formed");
        assert_eq!(
            comparison.pins,
            [
                "version: oracle 1 vs candidate 2",
                "`blob-tracked` blake3: oracle p1 vs candidate other"
            ]
        );
        assert!(comparison.addresses.is_empty());

        let mut value: serde_json::Value = serde_json::from_slice(&oracle).expect("json");
        value["entries"]["build-tracked"]["kind"] = "remote_file".into();
        value["entries"]
            .as_object_mut()
            .expect("entries")
            .remove("blob-tracked");
        value["entries"]["extra"] =
            serde_json::json!({"kind": "build", "config_hash": hex('d'), "blake3": "p3"});
        let candidate = serde_json::to_vec(&value).expect("json");
        let comparison = compare_locks(&oracle, &candidate).expect("well-formed");
        assert_eq!(
            comparison.pins,
            [
                "`blob-tracked`: pinned by the oracle only",
                "`build-tracked` kind: oracle build vs candidate remote_file",
                "`extra`: pinned by the candidate only"
            ]
        );
    }

    /// Both binaries evaluate with one `fgro`, so a toolchain pin that differs — or
    /// is missing on one side — is a pin difference; an edit keeps the pin.
    #[test]
    fn a_toolchain_pin_difference_is_a_pin_difference() {
        let pinned = |pin: Option<&str>| {
            let mut value: serde_json::Value =
                serde_json::from_slice(&lock(2, (&hex('a'), "p1"), (&hex('b'), "p2")))
                    .expect("json");
            if let Some(pin) = pin {
                value["toolchain"] = serde_json::json!({"fgro_blake3": pin});
            }
            serde_json::to_vec(&value).expect("json")
        };
        assert_eq!(
            compare_locks(&pinned(Some("f1")), &pinned(Some("f1"))),
            Ok(LockComparison::default())
        );
        assert_eq!(
            compare_locks(&pinned(Some("f1")), &pinned(Some("f2")))
                .expect("well-formed")
                .pins,
            ["toolchain: oracle f1 vs candidate f2"]
        );
        assert_eq!(
            compare_locks(&pinned(Some("f1")), &pinned(None))
                .expect("well-formed")
                .pins,
            ["toolchain: oracle f1 vs candidate none"]
        );
        let edited = edit_lock(&pinned(Some("f1")), &["blob-tracked"], &[]).expect("edit");
        let value: serde_json::Value = serde_json::from_slice(&edited).expect("json");
        assert_eq!(value["toolchain"]["fgro_blake3"], "f1");
    }

    #[test]
    fn a_malformed_lock_is_an_error_naming_its_side() {
        let good = lock(1, (&hex('a'), "p1"), (&hex('b'), "p2"));
        let error = |oracle: &[u8], candidate: &[u8]| {
            compare_locks(oracle, candidate).expect_err("malformed")
        };
        assert!(error(b"not json", &good).contains("the oracle's zap.lock isn't JSON"));
        assert!(
            error(&good, br#"{"entries":{}}"#).contains("the candidate's zap.lock has no numeric")
        );
        assert!(error(&good, br#"{"version":1}"#).contains("no `entries` object"));
        // uppercase, short, and non-hex config hashes
        for bad in [hex('A'), "ab".to_owned(), "g".repeat(64)] {
            let lock = lock(1, (&bad, "p1"), (&hex('b'), "p2"));
            assert!(
                error(&good, &lock).contains("malformed config_hash"),
                "{bad}"
            );
        }
        let missing = br#"{"version":1,"entries":{"a":{"kind":"build","config_hash":"0"}}}"#;
        assert!(error(missing, &good).contains("malformed config_hash"));
        let no_pin = format!(
            r#"{{"version":1,"entries":{{"a":{{"kind":"build","config_hash":"{}"}}}}}}"#,
            hex('0')
        );
        assert!(error(no_pin.as_bytes(), &good).contains("no string `blake3`"));
    }

    #[test]
    fn edit_lock_drops_and_stales_entries() {
        let lock = br#"{"version":1,"entries":{
            "a":{"kind":"remote_file","config_hash":"11","blake3":"22"},
            "b":{"kind":"build","config_hash":"33","blake3":"44"}}}"#;
        let edited = edit_lock(lock, &["a"], &["b"]).expect("edit");
        let value: serde_json::Value = serde_json::from_slice(&edited).expect("json");
        let entries = value["entries"].as_object().expect("entries");
        assert!(!entries.contains_key("a"));
        assert_eq!(entries["b"]["config_hash"], "0".repeat(64));
        assert_eq!(entries["b"]["blake3"], "44");
        assert!(edit_lock(lock, &["missing"], &[]).is_err());
        assert!(edit_lock(b"not json", &[], &[]).is_err());
    }

    #[test]
    fn the_audit_keeps_zap_state_in_scope() {
        let script = audit_script();
        assert!(script.contains(" /var/lib \\("), "{script}");
        assert!(!script.contains("/var/lib/zap"), "{script}");
        assert!(script.contains("-path '/var/lib/postgresql'"));
        assert!(script.contains("find / -maxdepth 1 -xdev \\( -type f -o -path / \\)"));
        assert!(script.contains("[ ! -s /run/zapdiff-audit.err ]"));
    }

    fn digest(firewall: &str) -> String {
        format!(
            "@@zapdiff section firewall\n{firewall}\n@@zapdiff section services\nsshd\n\
             @@zapdiff section swaps\n/swapfile\n@@zapdiff section postgres\npostgres\nzapdiff\n"
        )
    }

    fn clean_audit(writes: &str, firewall: &str) -> String {
        format!("@@zapdiff section writes\n{writes}{}", digest(firewall))
    }

    #[test]
    fn a_clean_audit_reports_only_the_canary() {
        let before = sections(&format!("mutation noise\n{}", digest("policy drop")));
        let after = sections(&clean_audit(&format!("{CANARY}\n"), "policy drop"));
        assert_eq!(judge(&before, &after), Vec::<String>::new());
    }

    #[test]
    fn writes_runtime_changes_and_a_missing_canary_are_problems() {
        let before = sections(&digest("policy drop"));
        let after = sections(&clean_audit("/etc/zapdiff/x\n", "policy accept"));
        let problems = judge(&before, &after);
        assert_eq!(problems.len(), 3, "{problems:?}");
        assert!(problems[0].contains("positive control failed"));
        assert!(problems[1].contains("/etc/zapdiff/x"));
        assert!(problems[2].contains("runtime state: firewall"));
        assert!(problems[2].contains("+ policy accept"));
    }

    #[test]
    fn missing_anchors_are_problems() {
        let anchors = Anchors {
            sleeper: false,
            firewall: Some("table inet filter"),
            postgres: true,
        };
        let good = sections(&digest("table inet filter {"));
        assert_eq!(anchor_problems(&good, anchors), Vec::<String>::new());
        let blind = sections(
            &digest("nft: command not found").replace("\npostgres\nzapdiff\n", "\npsql: error\n"),
        );
        let problems = anchor_problems(&blind, anchors);
        assert_eq!(problems.len(), 2, "{problems:?}");
        let relaxed = Anchors {
            sleeper: false,
            firewall: None,
            postgres: false,
        };
        assert_eq!(anchor_problems(&blind, relaxed), Vec::<String>::new());
    }

    #[test]
    fn the_sleeper_anchor_needs_a_live_identity() {
        let openrc = "Runlevel: default\n-- identity\nzapdiff-sleeper/001 pid=3826 start=182580\n";
        let systemd = "-- identity\nMainPID=751\nExecMainStartTimestampMonotonic=1\nId=dbus.service\n\n\
                       MainPID=5444\nExecMainStartTimestampMonotonic=2\nId=zapdiff-sleeper.service\n";
        assert!(has_sleeper_identity(openrc));
        assert!(has_sleeper_identity(systemd));
        // headers only, an empty pid, a zero MainPID, another unit's pid
        assert!(!has_sleeper_identity(
            "Runlevel: default\nRunlevel: boot\n-- identity\n"
        ));
        assert!(!has_sleeper_identity("zapdiff-sleeper/001 pid= start=\n"));
        assert!(!has_sleeper_identity(
            "MainPID=0\nId=zapdiff-sleeper.service\n"
        ));
        assert!(!has_sleeper_identity(
            "MainPID=751\nId=dbus.service\n\nMainPID=0\nId=zapdiff-sleeper.service\n"
        ));
        assert!(!has_sleeper_identity("Failed to connect to bus\n"));
    }

    #[test]
    fn a_failed_or_partial_audit_is_a_problem() {
        let before = sections(&digest("x"));
        let after = sections(&format!(
            "{FAILED}\nfind: boom\n{MISSING_ROOT}/usr\n{}",
            clean_audit(&format!("{CANARY}\n"), "x")
        ));
        let problems = judge(&before, &after);
        assert!(
            problems[0].contains("find/stat failed: find: boom"),
            "{problems:?}"
        );
        assert!(problems[1].contains("never listed /usr"));
        assert_eq!(problems.len(), 2);
        assert!(
            !judge(&sections(""), &after).is_empty(),
            "an empty digest is incomplete"
        );
    }
}
