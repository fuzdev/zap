//! `firewall` — active, with the declared default policies and every allow rule present
//! (ufw or nftables).
//!
//! One read per backend, a [`Query::root_command`] (both tools need root to list the
//! ruleset) that `exec`s its tool:
//!
//! - **ufw** — `ufw status verbose`. Only the verbose form prints the `Default:` line,
//!   the one way to observe the default incoming / outgoing policy, so an out-of-band
//!   `ufw default allow incoming` drifts rather than reading converged. The allow-rule
//!   table is *not* identical in both forms — verbose renders a named profile as
//!   `<ports>/<proto> (<name>)` where the bare form prints `<name>` — which is why
//!   the rule match takes the whole parsed "To" column and accepts either shape. A rule
//!   is present only as the row `ufw allow` writes — an inbound `ALLOW` from anywhere —
//!   and a status with no readable `Default:` line holds. ufw prints prose, parsed in
//!   English: the batch runs every probe under `LC_ALL=C`.
//! - **nftables** — `nft list table inet filter`. nftables is fully declarative — the
//!   table is loaded or it isn't, with no "enabled but inactive" state to tell apart. A
//!   rule is present only as a whole rule line of the `input` chain (set aside its handle, a
//!   comment, or a counter), so a narrower rule ending in the same words isn't it, and a
//!   missing base chain drifts.
//!
//! A probe that **fails** — exits nonzero — reads `absent` for both backends: a
//! deliberate exception to "a failed probe must never read as absent". The dominant
//! cause is the fresh-host bring-up: the config installs the `ufw` / `nftables` package
//! before this resource, but `depends_on` orders execution only, so the first pass
//! probes before the tool exists (holding there left the firewall unconfigured by the
//! first apply). The causes can't be told apart anyway — `nft` exits nonzero for a table
//! that doesn't exist, ufw's `sudo` maps command-not-found to exit 1, the same code as a
//! broken ufw. `absent` is safe for all of them because the firewall steps are
//! declarative, idempotent, and identical for create and update: a create on a mis-read
//! probe either re-asserts the declared ruleset or fails loudly at execution — never a
//! silent clobber of unread state (the harm the hold rule exists to prevent, in
//! detectors like `file` where a probe failure proves state *exists* that a create would
//! overwrite). A probe with no answer at all — timed out, or its batch failed — still
//! holds.

use super::{Query, QueryResult, command_answer, drifted_or_converged};
use crate::detected::{CurrentState, Detection, FirewallDrift};
use crate::schema::{FirewallAllowRule, FirewallBackend, FirewallResource};

/// The hold reason when a ufw status carries no readable `Default:` line.
const UFW_DEFAULTS_UNREADABLE: &str = "detection failed: ufw's status has no readable `Default:` line, so the default policies couldn't be checked";

/// The observed default policy of an nftables base chain missing from the listing.
const NFT_CHAIN_MISSING: &str = "missing";

/// The ufw status probe.
///
/// `exec`'d, like a path read's tool, so the probe's `timeout`
/// signals the tool itself — under `BusyBox`, which signals only the probe's shell, a
/// child the shell merely started could outlive it.
pub const UFW_STATUS: &str = "exec ufw status verbose";

/// The nftables ruleset probe, `exec`'d as [`UFW_STATUS`] is.
pub const NFT_LIST_TABLE: &str = "exec nft list table inet filter";

/// Index of the status probe in [`queries`].
const STATUS: usize = 0;

/// A firewall's one read — its backend's status probe, as root.
#[must_use]
pub fn queries(firewall: &FirewallResource) -> Vec<Query> {
    vec![Query::root_command(match firewall.backend {
        FirewallBackend::Ufw => UFW_STATUS,
        FirewallBackend::Nftables => NFT_LIST_TABLE,
    })]
}

/// The verdict for a firewall from the answer to [`queries`] (see the module docs).
///
/// `Absent` when the probe failed (or ufw is inactive), else converged or drifted on the
/// default policies and the allow rules.
#[must_use]
pub fn interpret(firewall: &FirewallResource, results: &[QueryResult]) -> Detection {
    let status = match command_answer(results, STATUS) {
        Ok(status) => status,
        Err(held) => return held,
    };
    // Probe failed → the firewall needs setting up (see the module docs) — create.
    if !status.succeeded() {
        return Detection::Absent;
    }
    let stdout = String::from_utf8_lossy(&status.stdout);
    match firewall.backend {
        FirewallBackend::Ufw => interpret_ufw(firewall, &stdout),
        FirewallBackend::Nftables => interpret_nftables(firewall, &stdout),
    }
}

/// A ufw firewall from its `ufw status verbose`: active, with the declared default
/// policies set and every allow rule present.
fn interpret_ufw(firewall: &FirewallResource, stdout: &str) -> Detection {
    // Installed but inactive: the whole firewall needs setting up — create.
    if !stdout.contains("Status: active") {
        return Detection::Absent;
    }
    // Each declared rule is matched against the parsed rows — an inbound `ALLOW` from
    // anywhere whose whole To column *equals* the rule — never a substring, so a declared
    // `allow 80` can't read present against an `8080/tcp` line (or inside an IP /
    // comment), nor against a `DENY`, outbound, or source-restricted row for the port.
    let missing_rules = firewall
        .allow
        .iter()
        .filter(|rule| !ufw_rule_present(stdout, rule))
        .map(FirewallAllowRule::ufw_target)
        .collect();

    // Default-policy drift from the `Default:` line. One that can't be parsed (an
    // unrecognized ufw format) holds: the default policy is half of what this security
    // control declares, and an unread policy is not a converged one.
    let Some((incoming, outgoing)) = parse_ufw_default_policies(stdout) else {
        return Detection::Undetermined {
            reason: UFW_DEFAULTS_UNREADABLE.to_owned(),
        };
    };
    let default_incoming = policy_drift(&incoming, firewall.default_incoming.as_str());
    let default_outgoing = policy_drift(&outgoing, firewall.default_outgoing.as_str());

    drifted_or_converged(CurrentState::Firewall {
        drift: FirewallDrift {
            default_incoming,
            default_outgoing,
            missing_rules,
        },
    })
}

/// An nftables firewall from its `nft list table inet filter`: every declared allow rule
/// present, with the declared default policies.
fn interpret_nftables(firewall: &FirewallResource, stdout: &str) -> Detection {
    let missing_rules = firewall
        .allow
        .iter()
        .filter(|rule| !nft_rule_present(stdout, rule))
        // A `Named` rule has no nft form (gated out under nftables); fall back to its ufw
        // identity for the drift display rather than dropping it.
        .map(|rule| rule.nft_rule().unwrap_or_else(|| rule.ufw_target()))
        .collect();

    // Default-policy drift from each base chain's *effective* policy — the binary
    // `policy <verb>;` line refined by the trailing bare `reject` rule the step builder
    // appends, so `reject` and `deny` are distinguishable (comparing the policy verb
    // alone collapsed them, leaving an undetectable drift dimension on a security
    // control). A chain absent from the listing (or one with no policy — not a base
    // chain, so it filters nothing) is itself drift: the hook it should filter isn't.
    let chain_drift = |chain: &str, desired: &str| {
        parse_nft_effective_policy(stdout, chain).map_or_else(
            || Some(NFT_CHAIN_MISSING.to_owned()),
            |observed| policy_drift(&observed, desired),
        )
    };
    let default_incoming = chain_drift("input", firewall.default_incoming.nft_effective_policy());
    let default_outgoing = chain_drift("output", firewall.default_outgoing.nft_effective_policy());

    drifted_or_converged(CurrentState::Firewall {
        drift: FirewallDrift {
            default_incoming,
            default_outgoing,
            missing_rules,
        },
    })
}

/// Is `rule` present in the `nft list table inet filter` output?
///
/// Matches the rule's rendered nft line — the shared [`FirewallAllowRule::nft_rule`],
/// the exact text the step builder writes into the `input` chain — against each whole
/// rule line of that chain's body, whitespace-normalized, after dropping only what doesn't
/// change what it admits ([`nft_listed_rule`]). Never a substring: a narrower
/// rule that ends in the same words — `ip saddr 1.2.3.4 tcp dport 22 accept`,
/// `iifname "lo" tcp dport 22 accept` — admits less than the declared
/// allow-from-anywhere, and reading it as the declared rule would be a false converged.
/// Only the `input` chain counts: the same `accept` in `output` or `forward` admits
/// nothing inbound. A `Named` rule has no nft form (`None`) and is never present — the
/// structural gate rejects it under nftables, so this is defensive.
fn nft_rule_present(ruleset_stdout: &str, rule: &FirewallAllowRule) -> bool {
    let Some(needle) = rule.nft_rule() else {
        return false;
    };
    let needle = needle.split_whitespace().collect::<Vec<_>>().join(" ");
    nft_chain_body(ruleset_stdout, "input")
        .is_some_and(|body| body.lines().any(|line| nft_listed_rule(line) == needle))
}

/// A rule line of an nft listing reduced to what it matches and decides:
/// whitespace-normalized, with what doesn't change what the rule admits dropped. Pure.
///
/// Three things are dropped: the `# handle <n>` an `-a` listing ends a rule with; a
/// `comment "<text>"` after the verdict (a comment holds no `"`); and a `counter` just
/// before the `accept`, bare or with the running totals a listing shows (`counter packets
/// <n> bytes <n>`). Only those, in those places: anything else on the line — a match, a
/// `log`, another statement — is part of the rule.
fn nft_listed_rule(line: &str) -> String {
    let mut rule = line.trim();
    if let Some((before, handle)) = rule.rsplit_once(" # handle ")
        && !handle.is_empty()
        && handle.bytes().all(|byte| byte.is_ascii_digit())
    {
        rule = before.trim_end();
    }
    if let Some(open) = rule.strip_suffix('"')
        && let Some((before, text)) = open.rsplit_once(" comment \"")
        && !text.contains('"')
    {
        rule = before.trim_end();
    }
    let mut tokens: Vec<&str> = rule.split_whitespace().collect();
    let numeric = |token: &str| !token.is_empty() && token.bytes().all(|b| b.is_ascii_digit());
    match tokens.as_slice() {
        [.., "counter", "packets", packets, "bytes", bytes, "accept"]
            if numeric(packets) && numeric(bytes) =>
        {
            let verdict = tokens.len() - 1;
            tokens.drain(verdict - 5..verdict);
        }
        [.., "counter", "accept"] => {
            let verdict = tokens.len() - 1;
            tokens.remove(verdict - 1);
        }
        _ => {}
    }
    tokens.join(" ")
}

/// Is `rule` present in the `ufw status` output?
///
/// ufw lists one rule per line. A row counts only when it is what `ufw allow <target>`
/// writes — an `ALLOW`, inbound (`IN`, or no direction: the bare `ufw status` prints
/// none for an inbound rule), from `Anywhere` ([`UfwRow::is_allow_in_from_anywhere`]) —
/// so an out-of-band `ufw deny 22/tcp` (which rewrites the rule in place), an outbound
/// allow, or an allow from one address drifts rather than reading the declared rule
/// present. The match is against the row's whole "To" column, never a substring of it,
/// so `80` can't match `8080/tcp` and `OpenSSH` can't match `OpenSSHd`:
/// - `PortProto { proto: Any }` → To column exactly `<port>` (ufw renders a no-proto
///   rule as the bare port). It deliberately does **not** match a `<port>/tcp` line: a
///   declared any-proto rule and a tcp-only rule are distinct ufw rules.
/// - `PortProto { proto: tcp|udp }` → To column exactly `<port>/<proto>`.
/// - `Named(name)` → either rendering of the profile (see below).
///
/// The two status forms diverge on **named profiles**, which is why the whole column is
/// parsed rather than its first token. The bare `ufw status` prints the profile name as
/// the target (`OpenSSH`), while the `ufw status verbose` this detector actually probes
/// prints the resolved ports with the name parenthesized (`22/tcp (OpenSSH)`, and
/// `22/tcp (OpenSSH (v6))` on the v6 row). Matching only the first token read every named
/// rule as missing against the verbose output — the whole point of the resource — and a
/// multi-word profile (`Nginx Full`) failed against *both* forms. Port rules render
/// identically in both, modulo the v6 row's ` (v6)` suffix, whose v4 sibling matches.
fn ufw_rule_present(status_stdout: &str, rule: &FirewallAllowRule) -> bool {
    let target = rule.ufw_target();
    status_stdout
        .lines()
        .filter_map(ufw_row)
        .filter(UfwRow::is_allow_in_from_anywhere)
        .any(|row| match rule {
            FirewallAllowRule::Named(name) => {
                row.to == *name
                    || row.to.ends_with(&format!("({name})"))
                    || row.to.ends_with(&format!("({name} (v6))"))
            }
            FirewallAllowRule::PortProto { .. } => row.to == target,
        })
}

/// One rule row of a ufw status table: `<to…> <ACTION> [<DIRECTION>] <from…> [# comment]`.
#[derive(Debug, PartialEq, Eq)]
struct UfwRow<'a> {
    /// The "To" column, whitespace-normalized.
    to: String,
    /// `ALLOW`, `DENY`, `REJECT`, or `LIMIT`.
    action: &'a str,
    /// `IN`, `OUT`, or `FWD` — `None` where the bare `ufw status` prints no direction
    /// (an inbound rule).
    direction: Option<&'a str>,
    /// The "From" column, whitespace-normalized, without a trailing rule comment.
    from: String,
}

impl UfwRow<'_> {
    /// Whether the row is the rule `ufw allow <target>` writes: an inbound `ALLOW` from
    /// anywhere (either address family's row).
    fn is_allow_in_from_anywhere(&self) -> bool {
        self.action == "ALLOW"
            && matches!(self.direction, None | Some("IN"))
            && matches!(self.from.as_str(), "Anywhere" | "Anywhere (v6)")
    }
}

/// A ufw status table row, split at its action verb.
///
/// `None` for any line without one — the `Status:` / `Default:` / `Logging:` preamble,
/// the `To  Action  From` header and its `--` rule, and blanks — so only real rule rows
/// reach the match. Whitespace is normalized to single spaces, because the columns are
/// space-padded to align the table and a multi-word profile name (`Nginx Full`) would
/// otherwise carry that padding into the comparison.
fn ufw_row(line: &str) -> Option<UfwRow<'_>> {
    const ACTIONS: [&str; 4] = ["ALLOW", "DENY", "REJECT", "LIMIT"];
    const DIRECTIONS: [&str; 3] = ["IN", "OUT", "FWD"];
    let mut tokens = line.split_whitespace().peekable();
    let mut to: Vec<&str> = Vec::new();
    let action = loop {
        let token = tokens.next()?;
        if ACTIONS.contains(&token) {
            break token;
        }
        to.push(token);
    };
    if to.is_empty() {
        return None;
    }
    let direction = tokens.next_if(|token| DIRECTIONS.contains(token));
    // A rule's comment (`ufw allow … comment 'x'`) trails the From column after a `#`.
    let from: Vec<&str> = tokens.take_while(|token| !token.starts_with('#')).collect();
    Some(UfwRow {
        to: to.join(" "),
        action,
        direction,
        from: from.join(" "),
    })
}

/// `Some(observed)` when the observed policy verb differs from the desired one, else
/// `None` (converged). Pure — the shared default-policy drift decision for both backends.
fn policy_drift(observed: &str, desired: &str) -> Option<String> {
    (observed != desired).then(|| observed.to_owned())
}

/// Parse ufw's `Default:` line into `(incoming, outgoing)` policy verbs. Pure.
///
/// The line — present only in `ufw status verbose` — reads
/// `Default: deny (incoming), allow (outgoing), disabled (routed)`; each policy verb is
/// the last whitespace token before its `(direction)` marker. Returns `None` if the line
/// (or a direction marker) is absent.
fn parse_ufw_default_policies(stdout: &str) -> Option<(String, String)> {
    let line = stdout
        .lines()
        .map(str::trim_start)
        .find(|line| line.starts_with("Default:"))?;
    let incoming = policy_before(line, "(incoming)")?;
    let outgoing = policy_before(line, "(outgoing)")?;
    Some((incoming, outgoing))
}

/// The policy verb immediately preceding `marker` on a ufw `Default:` line.
fn policy_before(line: &str, marker: &str) -> Option<String> {
    let idx = line.find(marker)?;
    line[..idx]
        .split_whitespace()
        .next_back()
        .map(str::to_owned)
}

/// The body of the named chain in an `nft list table inet filter` rendering — the text
/// between `chain <name> {` and the chain's closing brace. Pure.
///
/// Scoping every chain-level read to its own body is what keeps a fact read off one
/// chain from being attributed to another: nft closes each chain with a `}` on its own
/// line and indents every rule, so the first such line ends the body unambiguously.
/// `None` if the chain isn't in the listing.
fn nft_chain_body<'a>(ruleset_stdout: &'a str, chain: &str) -> Option<&'a str> {
    let marker = format!("chain {chain} {{");
    let start = ruleset_stdout.find(&marker)? + marker.len();
    let after = &ruleset_stdout[start..];
    let mut offset = 0;
    for line in after.split_inclusive('\n') {
        if line.trim() == "}" {
            return Some(&after[..offset]);
        }
        offset += line.len();
    }
    Some(after)
}

/// The base-chain `policy` verb (`accept`/`drop`) of the named chain in an
/// `nft list table inet filter` rendering. Pure.
///
/// nft prints each base chain as `chain <name> {` then `type … priority …; policy <verb>;`
/// on the next line, so the verb is the first `policy <token>` in the chain's own body.
/// Returns `None` if the chain (or its policy line) isn't present — a non-base chain has
/// no policy, and must not borrow the next chain's.
fn parse_nft_chain_policy(ruleset_stdout: &str, chain: &str) -> Option<String> {
    let body = nft_chain_body(ruleset_stdout, chain)?;
    let policy_idx = body.find("policy ")?;
    let verb = body[policy_idx + "policy ".len()..]
        .split([';', ' ', '\t', '\n'])
        .next()?;
    (!verb.is_empty()).then(|| verb.to_owned())
}

/// Whether the named chain ends in a bare `reject` rule — the trailing rule the step
/// builder appends for a `reject` default (nftables base-chain policy is binary, so
/// `reject` is `policy drop` *plus* this rule). Pure.
///
/// Matches a line that is exactly `reject`, so a per-rule rejection (`tcp dport 25
/// reject`) is never mistaken for the chain default.
fn nft_chain_rejects(ruleset_stdout: &str, chain: &str) -> bool {
    nft_chain_body(ruleset_stdout, chain)
        .is_some_and(|body| body.lines().any(|line| line.trim() == "reject"))
}

/// The named chain's **effective** default policy — `accept` / `drop` / `reject`. Pure.
///
/// The counterpart of [`FirewallPolicy::nft_effective_policy`](crate::schema::FirewallPolicy::nft_effective_policy)
/// on the observed side, so the drift comparison is between two values in the same
/// three-valued space. Without it the comparison ran in nftables' binary policy space,
/// where a desired `reject` is indistinguishable from `drop` — the firewall reported
/// converged with its active ICMP rejection silently gone.
fn parse_nft_effective_policy(ruleset_stdout: &str, chain: &str) -> Option<String> {
    let policy = parse_nft_chain_policy(ruleset_stdout, chain)?;
    if policy == "drop" && nft_chain_rejects(ruleset_stdout, chain) {
        return Some("reject".to_owned());
    }
    Some(policy)
}

#[cfg(test)]
mod tests {
    use super::{
        UfwRow, interpret, nft_rule_present, parse_nft_chain_policy, parse_nft_effective_policy,
        parse_ufw_default_policies, policy_drift, queries, ufw_row, ufw_rule_present,
    };
    use crate::detected::{CurrentState, Detection, FirewallDrift};
    use crate::observe::testing::exited;
    use crate::observe::{COMMAND_TIMEOUT, Lane, Query, QueryError};
    use crate::schema::{FirewallAllowRule, FirewallPolicy, FirewallResource, Protocol};

    fn firewall(backend: &str) -> FirewallResource {
        serde_json::from_value(
            serde_json::json!({"backend": backend, "allow": [{"port": 22, "proto": "tcp"}]}),
        )
        .unwrap()
    }

    #[test]
    fn each_backend_reads_its_status_as_root() {
        assert_eq!(
            queries(&firewall("ufw")),
            [Query::root_command("exec ufw status verbose")]
        );
        assert_eq!(
            queries(&firewall("nftables")),
            [Query::root_command("exec nft list table inet filter")]
        );
    }

    #[test]
    fn a_failed_probe_needs_setting_up_but_an_unanswered_one_holds() {
        for backend in ["ufw", "nftables"] {
            let resource = firewall(backend);
            assert_eq!(interpret(&resource, &[exited(1, "")]), Detection::Absent);
            for error in [
                QueryError::TimedOut {
                    secs: COMMAND_TIMEOUT,
                },
                QueryError::Batch {
                    lane: Lane::Root,
                    reason: "sudo authentication failed".to_owned(),
                },
            ] {
                assert!(matches!(
                    interpret(&resource, &[Err(error)]),
                    Detection::Undetermined { .. }
                ));
            }
        }
        // An installed but inactive ufw needs setting up too.
        assert_eq!(
            interpret(&firewall("ufw"), &[exited(0, "Status: inactive\n")]),
            Detection::Absent
        );
        assert_eq!(
            interpret(
                &firewall("ufw"),
                &[exited(
                    0,
                    "Status: active\nDefault: deny (incoming), allow (outgoing), disabled (routed)\n\
                     22/tcp                     ALLOW IN    Anywhere\n"
                )]
            ),
            Detection::Converged
        );
    }

    const STATUS: &str = "Status: active\n\nTo                         Action      From\n\
        --                         ------      ----\n\
        OpenSSH                    ALLOW       Anywhere\n\
        443/tcp                    ALLOW       Anywhere\n\
        OpenSSH (v6)               ALLOW       Anywhere (v6)\n\
        443/tcp (v6)               ALLOW       Anywhere (v6)\n";

    fn port(port: u16, proto: Protocol) -> FirewallAllowRule {
        FirewallAllowRule::PortProto {
            port: std::num::NonZeroU16::new(port).unwrap(),
            proto,
        }
    }

    fn named(name: &str) -> FirewallAllowRule {
        FirewallAllowRule::Named(name.to_owned())
    }

    /// What the detector actually probes. Verbatim `ufw status verbose` from a Debian/
    /// Ubuntu host with the `OpenSSH` + `Nginx Full` profiles allowed: a named profile
    /// renders as its resolved ports with the name parenthesized, so the first token is
    /// `22/tcp`, not `OpenSSH`.
    const STATUS_VERBOSE: &str = "Status: active\n\
        Logging: on (low)\n\
        Default: deny (incoming), allow (outgoing), disabled (routed)\n\
        New profiles: skip\n\n\
        To                         Action      From\n\
        --                         ------      ----\n\
        22/tcp (OpenSSH)           ALLOW IN    Anywhere\n\
        80,443/tcp (Nginx Full)    ALLOW IN    Anywhere\n\
        22/tcp (OpenSSH (v6))      ALLOW IN    Anywhere (v6)\n\
        80,443/tcp (Nginx Full (v6)) ALLOW IN    Anywhere (v6)\n";

    #[test]
    fn named_rule_matches_the_verbose_parenthesized_rendering() {
        // The detector probes `ufw status verbose`, where a profile's
        // name is parenthesized after the resolved ports. Matching the first token alone
        // read every named rule as missing, so an apply reported permanent RESIDUAL drift
        // and a deploy preflight refused to run against a correctly-configured firewall.
        assert!(ufw_rule_present(STATUS_VERBOSE, &named("OpenSSH")));
        // A multi-word profile: `Nginx Full` never matched a first token in *either* form.
        assert!(ufw_rule_present(STATUS_VERBOSE, &named("Nginx Full")));
        // Still a whole-column match, so a longer or shorter name is not present.
        assert!(!ufw_rule_present(STATUS_VERBOSE, &named("OpenSSHd")));
        assert!(!ufw_rule_present(STATUS_VERBOSE, &named("Nginx")));
    }

    #[test]
    fn named_rule_matches_the_bare_status_rendering_too() {
        // The bare `ufw status` prints the profile name as the target. Both forms match.
        assert!(ufw_rule_present(STATUS, &named("OpenSSH")));
        let bare_multiword = "Status: active\nNginx Full                 ALLOW       Anywhere\n";
        assert!(ufw_rule_present(bare_multiword, &named("Nginx Full")));
    }

    #[test]
    fn port_rule_matches_the_verbose_rendering() {
        // A port rule renders the same in both forms, so the v4 row matches exactly.
        let verbose_port = "Status: active\n\
            443/tcp                    ALLOW IN    Anywhere\n\
            443/tcp (v6)               ALLOW IN    Anywhere (v6)\n";
        assert!(ufw_rule_present(verbose_port, &port(443, Protocol::Tcp)));
        // A named rule whose resolved ports happen to equal a declared port rule is still
        // a different rule — the To column carries the parenthetical, so it can't match.
        assert!(!ufw_rule_present(STATUS_VERBOSE, &port(22, Protocol::Tcp)));
    }

    #[test]
    fn rows_are_only_parsed_for_real_rule_rows() {
        // Preamble, header, and separator carry no action verb.
        for line in [
            "Status: active",
            "Default: deny (incoming), allow (outgoing), disabled (routed)",
            "To                         Action      From",
            "--                         ------      ----",
            "",
        ] {
            assert_eq!(ufw_row(line), None, "{line}");
        }
        // A rule row's columns are normalized, so alignment padding never reaches a match,
        // and a trailing rule comment is no part of the From column.
        assert_eq!(
            ufw_row("80,443/tcp (Nginx Full)    ALLOW IN    Anywhere (v6)    # web"),
            Some(UfwRow {
                to: "80,443/tcp (Nginx Full)".to_owned(),
                action: "ALLOW",
                direction: Some("IN"),
                from: "Anywhere (v6)".to_owned(),
            })
        );
        assert_eq!(
            ufw_row("OpenSSH                    ALLOW       Anywhere").map(|row| row.direction),
            Some(None)
        );
    }

    /// Only the row `ufw allow <target>` writes counts — an out-of-band deny (ufw rewrites
    /// the rule in place), an outbound allow, a rate limit, or an allow from one address
    /// is the declared rule missing.
    #[test]
    fn only_an_inbound_allow_from_anywhere_is_the_declared_rule() {
        let rule = port(22, Protocol::Tcp);
        let status = |row: &str| format!("Status: active\n{row}\n");
        assert!(ufw_rule_present(
            &status("22/tcp                     ALLOW IN    Anywhere"),
            &rule
        ));
        assert!(ufw_rule_present(
            &status("22/tcp                     ALLOW IN    Anywhere                   # ssh"),
            &rule
        ));
        for row in [
            "22/tcp                     DENY IN     Anywhere",
            "22/tcp                     REJECT IN   Anywhere",
            "22/tcp                     LIMIT IN    Anywhere",
            "22/tcp                     ALLOW OUT   Anywhere",
            "22/tcp                     ALLOW FWD   Anywhere",
            "22/tcp                     ALLOW IN    10.0.0.1",
            "22/tcp                     ALLOW IN    10.0.0.0/8",
        ] {
            assert!(!ufw_rule_present(&status(row), &rule), "{row}");
        }
    }

    /// A deny row beside the declared allow row doesn't hide it: zap isn't authoritative
    /// over rules it doesn't declare.
    #[test]
    fn an_extra_deny_row_does_not_hide_the_declared_allow() {
        let status = "Status: active\n\
            22/tcp                     DENY IN     10.0.0.1\n\
            22/tcp                     ALLOW IN    Anywhere\n";
        assert!(ufw_rule_present(status, &port(22, Protocol::Tcp)));
    }

    #[test]
    fn named_rule_matches_its_column_token_including_v6_row() {
        assert!(ufw_rule_present(
            STATUS,
            &FirewallAllowRule::Named("OpenSSH".to_owned())
        ));
        // A substring of the profile name must NOT match the whole-token target.
        assert!(!ufw_rule_present(
            STATUS,
            &FirewallAllowRule::Named("OpenSSHd".to_owned())
        ));
        assert!(!ufw_rule_present(
            STATUS,
            &FirewallAllowRule::Named("Open".to_owned())
        ));
    }

    #[test]
    fn proto_port_matches_exact_token_not_a_longer_one() {
        assert!(ufw_rule_present(STATUS, &port(443, Protocol::Tcp)));
        // `8443/tcp` would substring-contain `443/tcp` — the whole-token match rejects it.
        let only_8443 = "Status: active\n8443/tcp                   ALLOW       Anywhere\n";
        assert!(!ufw_rule_present(only_8443, &port(443, Protocol::Tcp)));
        // Wrong proto is a different rule.
        assert!(!ufw_rule_present(STATUS, &port(443, Protocol::Udp)));
    }

    #[test]
    fn any_proto_port_matches_a_bare_port_line() {
        let status = "Status: active\n80                         ALLOW       Anywhere\n\
            80 (v6)                    ALLOW       Anywhere (v6)\n";
        assert!(ufw_rule_present(status, &port(80, Protocol::Any)));
    }

    #[test]
    fn any_proto_port_does_not_substring_match_a_longer_port() {
        // The regression case: declared `allow 80` (any proto) against a status listing
        // only `8080/tcp`. A substring match on `80` would read `8080/tcp` as converged.
        let status = "Status: active\n8080/tcp                   ALLOW       Anywhere\n";
        assert!(!ufw_rule_present(status, &port(80, Protocol::Any)));
    }

    #[test]
    fn any_proto_port_does_not_match_a_typed_line() {
        // A declared any-proto `80` and a listed `80/tcp` are distinct ufw rules.
        let status = "Status: active\n80/tcp                     ALLOW       Anywhere\n";
        assert!(!ufw_rule_present(status, &port(80, Protocol::Any)));
    }

    // --- nftables presence (`nft list table inet filter` output) ---

    // A representative `nft list table inet filter` rendering (tabs as nft emits them).
    const NFT_RULESET: &str = "table inet filter {\n\
        \tchain input {\n\
        \t\ttype filter hook input priority 0; policy drop;\n\
        \t\tct state established,related accept\n\
        \t\tiif \"lo\" accept\n\
        \t\ttcp dport 22 accept\n\
        \t\ttcp dport 443 accept\n\
        \t\tudp dport 53 accept\n\
        \t}\n\
        }\n";

    #[test]
    fn nft_present_matches_declared_port_rules() {
        assert!(nft_rule_present(NFT_RULESET, &port(22, Protocol::Tcp)));
        assert!(nft_rule_present(NFT_RULESET, &port(443, Protocol::Tcp)));
        assert!(nft_rule_present(NFT_RULESET, &port(53, Protocol::Udp)));
    }

    #[test]
    fn nft_present_rejects_absent_and_substring_ports() {
        // 80 isn't in the ruleset.
        assert!(!nft_rule_present(NFT_RULESET, &port(80, Protocol::Tcp)));
        // A declared `22` must not match a listed `2222` (the ` accept` suffix won't align).
        let ruleset = "table inet filter {\n\tchain input {\n\t\ttcp dport 2222 accept\n\t}\n}\n";
        assert!(!nft_rule_present(ruleset, &port(22, Protocol::Tcp)));
        // Wrong proto is a different rule.
        assert!(!nft_rule_present(NFT_RULESET, &port(22, Protocol::Udp)));
    }

    #[test]
    fn nft_present_is_false_for_a_named_rule() {
        // `Named` has no nft form — never present (the gate rejects it under nftables).
        assert!(!nft_rule_present(
            NFT_RULESET,
            &FirewallAllowRule::Named("OpenSSH".to_owned())
        ));
    }

    /// `nft list chain inet filter input` from the Alpine VM (nftables v1.1.6): the
    /// differential fixture's chain as the step builder loads it, then rules added by
    /// hand — narrower than an allow-from-anywhere, or carrying what nft appends to a
    /// listed rule (a counter's totals, a comment).
    const NFT_LISTED: &str = "table inet filter {\n\
        \tchain input {\n\
        \t\ttype filter hook input priority filter; policy drop;\n\
        \t\tct state established,related accept\n\
        \t\tct state invalid drop\n\
        \t\tiif \"lo\" accept\n\
        \t\tip protocol icmp accept\n\
        \t\tip6 nexthdr ipv6-icmp accept\n\
        \t\ttcp dport 22 accept\n\
        \t\ttcp dport 80 accept\n\
        \t\ttcp dport 443 accept\n\
        \t\tudp dport 5353 accept\n\
        \t\tmeta l4proto { tcp, udp } th dport 8443 accept\n\
        \t\tip saddr 1.2.3.4 tcp dport 2201 accept\n\
        \t\tiifname \"lo\" tcp dport 2202 accept\n\
        \t\ttcp dport 2203 counter packets 0 bytes 0 accept\n\
        \t\ttcp dport 2204 accept comment \"ssh alt\"\n\
        \t\ttcp dport 2205 counter packets 0 bytes 0 accept comment \"both\"\n\
        \t\ttcp dport 2206 log accept\n\
        \t\ttcp dport 2207 ct state new accept\n\
        \t\tmeta l4proto { tcp, udp } th dport 2208 counter packets 0 bytes 0 accept\n\
        \t\ttcp dport 2209 drop comment \"x accept\"\n\
        \t\ttcp dport 2210 accept comment \"a # handle 3\"\n\
        \t\ttcp dport 2211 counter packets 0 bytes 0 accept comment \"\"\n\
        \t}\n\
        }\n";

    /// The same chain from `nft -a list chain inet filter input`: each rule ends in its
    /// handle, and so does the chain's opening line.
    const NFT_LISTED_HANDLES: &str = "table inet filter {\n\
        \tchain input { # handle 1\n\
        \t\ttype filter hook input priority filter; policy drop;\n\
        \t\tct state established,related accept # handle 4\n\
        \t\tiif \"lo\" accept # handle 6\n\
        \t\ttcp dport 22 accept # handle 9\n\
        \t\tmeta l4proto { tcp, udp } th dport 8443 accept # handle 14\n\
        \t\tip saddr 1.2.3.4 tcp dport 2201 accept # handle 17\n\
        \t\tiifname \"lo\" tcp dport 2202 accept # handle 18\n\
        \t\ttcp dport 2203 counter packets 0 bytes 0 accept # handle 19\n\
        \t\ttcp dport 2204 accept comment \"ssh alt\" # handle 20\n\
        \t\ttcp dport 2205 counter packets 0 bytes 0 accept comment \"both\" # handle 21\n\
        \t\ttcp dport 2206 log accept # handle 24\n\
        \t}\n\
        }\n";

    /// A rule other than the declared allow-from-anywhere — from one address, on one
    /// interface, new connections only, or carrying a statement such as `log` — is not
    /// the declared rule, whatever words it ends in; nor is a `drop` whose comment says
    /// `accept`.
    #[test]
    fn a_narrower_nft_rule_is_not_the_declared_one() {
        for listing in [NFT_LISTED, NFT_LISTED_HANDLES] {
            for port_number in [2201, 2202, 2206, 2207] {
                assert!(
                    !nft_rule_present(listing, &port(port_number, Protocol::Tcp)),
                    "{port_number}"
                );
            }
        }
        assert!(!nft_rule_present(NFT_LISTED, &port(2209, Protocol::Tcp)));
    }

    /// A counter's totals, a comment, and a handle are nft's own, and the rule under them
    /// is the declared one.
    #[test]
    fn what_nft_appends_to_a_listed_rule_is_not_part_of_it() {
        for listing in [NFT_LISTED, NFT_LISTED_HANDLES] {
            for port_number in [22, 2203, 2204, 2205] {
                assert!(
                    nft_rule_present(listing, &port(port_number, Protocol::Tcp)),
                    "{port_number}"
                );
            }
            assert!(nft_rule_present(listing, &port(8443, Protocol::Any)));
        }
        for (port_number, proto) in [
            (80, Protocol::Tcp),
            (443, Protocol::Tcp),
            (5353, Protocol::Udp),
            (2208, Protocol::Any),
            (2210, Protocol::Tcp),
            (2211, Protocol::Tcp),
        ] {
            assert!(
                nft_rule_present(NFT_LISTED, &port(port_number, proto)),
                "{port_number}"
            );
        }
        // the counter `nft -s` lists without its totals
        let stateless = "table inet filter {\n\tchain input {\n\
            \t\ttcp dport 2203 counter accept\n\
            \t\ttcp dport 2205 counter accept comment \"both\"\n\t}\n}\n";
        assert!(nft_rule_present(stateless, &port(2203, Protocol::Tcp)));
        assert!(nft_rule_present(stateless, &port(2205, Protocol::Tcp)));
        // a counter anywhere but just before the verdict is a statement of the rule's
        assert!(!nft_rule_present(
            "table inet filter {\n\tchain input {\n\t\tcounter tcp dport 22 accept\n\t}\n}\n",
            &port(22, Protocol::Tcp)
        ));
    }

    /// An extra rule is not a finding: the declared rules are all present, so the
    /// firewall reads converged beside the hand-added ones.
    #[test]
    fn an_extra_nft_rule_is_not_drift() {
        let resource: FirewallResource = serde_json::from_value(serde_json::json!({
            "backend": "nftables",
            "allow": [{"port": 22, "proto": "tcp"}, {"port": 8443, "proto": "any"}],
            "default_outgoing": "allow",
        }))
        .unwrap();
        let listing = format!(
            "{}\tchain output {{\n\
             \t\ttype filter hook output priority filter; policy accept;\n\t}}\n}}\n",
            NFT_LISTED.trim_end().trim_end_matches('}')
        );
        assert_eq!(
            interpret(&resource, &[exited(0, &listing)]),
            Detection::Converged
        );
    }

    // --- default-policy parsing ---

    #[test]
    fn policy_drift_flags_only_a_difference() {
        assert_eq!(policy_drift("deny", "deny"), None);
        assert_eq!(policy_drift("allow", "deny"), Some("allow".to_owned()));
        // nft verb space.
        assert_eq!(policy_drift("drop", "drop"), None);
        assert_eq!(policy_drift("accept", "drop"), Some("accept".to_owned()));
    }

    #[test]
    fn ufw_default_line_parses_both_directions() {
        let verbose = "Status: active\nLogging: on (low)\n\
            Default: deny (incoming), allow (outgoing), disabled (routed)\n\
            New profiles: skip\n\nTo                         Action      From\n";
        assert_eq!(
            parse_ufw_default_policies(verbose),
            Some(("deny".to_owned(), "allow".to_owned()))
        );
    }

    #[test]
    fn ufw_default_line_parses_a_reject_incoming() {
        let verbose = "Status: active\n\
            Default: reject (incoming), deny (outgoing), disabled (routed)\n";
        assert_eq!(
            parse_ufw_default_policies(verbose),
            Some(("reject".to_owned(), "deny".to_owned()))
        );
    }

    #[test]
    fn ufw_non_verbose_status_has_no_default_line() {
        // The bare `ufw status` omits the `Default:` line — parsing returns None, and the
        // detector holds: an unread default policy is not a converged one (it probes
        // `verbose`, so this is the defensive path, not the live one).
        let bare = "Status: active\n\nTo                         Action      From\n\
            --                         ------      ----\nOpenSSH                    ALLOW       Anywhere\n";
        assert_eq!(parse_ufw_default_policies(bare), None);
        let resource: FirewallResource =
            serde_json::from_value(serde_json::json!({"backend": "ufw", "allow": ["OpenSSH"]}))
                .unwrap();
        assert!(matches!(
            interpret(&resource, &[exited(0, bare)]),
            Detection::Undetermined { .. }
        ));
    }

    /// A table missing a base chain drifts on that chain's default policy, even with
    /// nothing declared to allow: the hook it should filter isn't filtered.
    #[test]
    fn an_nft_table_missing_a_base_chain_drifts() {
        let resource: FirewallResource =
            serde_json::from_value(serde_json::json!({"backend": "nftables", "allow": []}))
                .unwrap();
        let no_input = "table inet filter {\n\tchain output {\n\
            \t\ttype filter hook output priority filter; policy accept;\n\t}\n}\n";
        assert_eq!(
            interpret(&resource, &[exited(0, no_input)]),
            Detection::Drifted {
                current: CurrentState::Firewall {
                    drift: FirewallDrift {
                        default_incoming: Some("missing".to_owned()),
                        default_outgoing: None,
                        missing_rules: Vec::new(),
                    },
                },
            }
        );
    }

    /// An `accept` for the port in another chain admits nothing inbound.
    #[test]
    fn an_nft_rule_counts_only_in_the_input_chain() {
        let ruleset = "table inet filter {\n\
            \tchain input {\n\t\ttype filter hook input priority filter; policy drop;\n\t}\n\
            \tchain output {\n\t\ttype filter hook output priority filter; policy accept;\n\
            \t\ttcp dport 22 accept\n\t}\n}\n";
        assert!(!nft_rule_present(ruleset, &port(22, Protocol::Tcp)));
    }

    #[test]
    fn nft_effective_policy_distinguishes_reject_from_drop() {
        // nftables' base-chain policy is binary (accept/drop), so a desired `reject`
        // rides a `policy drop` chain *plus* the trailing bare `reject` rule the step
        // builder appends. Comparing the policy verb alone made the two identical — a
        // firewall declared `reject` read converged against a plain `drop`, an
        // undetectable drift dimension on a security control.
        let rejecting = "table inet filter {\n\tchain input {\n\
            \t\ttype filter hook input priority 0; policy drop;\n\
            \t\ttcp dport 22 accept\n\
            \t\treject\n\t}\n}\n";
        assert_eq!(
            parse_nft_effective_policy(rejecting, "input").as_deref(),
            Some("reject")
        );
        // The same chain with the trailing rule gone is a plain drop, not a reject.
        let dropping = "table inet filter {\n\tchain input {\n\
            \t\ttype filter hook input priority 0; policy drop;\n\
            \t\ttcp dport 22 accept\n\t}\n}\n";
        assert_eq!(
            parse_nft_effective_policy(dropping, "input").as_deref(),
            Some("drop")
        );
        // So the drift comparison separates them, in both directions.
        assert_eq!(
            policy_drift("drop", FirewallPolicy::Reject.nft_effective_policy()),
            Some("drop".to_owned())
        );
        assert_eq!(
            policy_drift("reject", FirewallPolicy::Deny.nft_effective_policy()),
            Some("reject".to_owned())
        );
        assert_eq!(
            policy_drift("reject", FirewallPolicy::Reject.nft_effective_policy()),
            None
        );
    }

    #[test]
    fn nft_reject_rule_is_scoped_to_its_own_chain() {
        // A `reject` in the *output* chain must not make the input chain read as
        // rejecting — the body scan stops at the chain's closing brace.
        let ruleset = "table inet filter {\n\tchain input {\n\
            \t\ttype filter hook input priority 0; policy drop;\n\t}\n\
            \tchain output {\n\t\ttype filter hook output priority 0; policy drop;\n\
            \t\treject\n\t}\n}\n";
        assert_eq!(
            parse_nft_effective_policy(ruleset, "input").as_deref(),
            Some("drop")
        );
        assert_eq!(
            parse_nft_effective_policy(ruleset, "output").as_deref(),
            Some("reject")
        );
        // A per-rule reject (`tcp dport 25 reject`) is a rule, not the chain default.
        let per_rule = "table inet filter {\n\tchain input {\n\
            \t\ttype filter hook input priority 0; policy drop;\n\
            \t\ttcp dport 25 reject\n\t}\n}\n";
        assert_eq!(
            parse_nft_effective_policy(per_rule, "input").as_deref(),
            Some("drop")
        );
    }

    #[test]
    fn nft_chain_policy_is_scoped_to_its_own_chain() {
        // A chain whose policy line is missing must read `None`, not inherit the *next*
        // chain's policy — the unscoped scan searched the rest of the whole listing.
        let ruleset = "table inet filter {\n\tchain input {\n\
            \t\ttcp dport 22 accept\n\t}\n\
            \tchain output {\n\t\ttype filter hook output priority 0; policy accept;\n\t}\n}\n";
        assert_eq!(parse_nft_chain_policy(ruleset, "input"), None);
    }

    #[test]
    fn nft_chain_policy_reads_each_base_chain() {
        assert_eq!(
            parse_nft_chain_policy(NFT_RULESET, "input").as_deref(),
            Some("drop")
        );
        // An output chain with `policy accept;`.
        let ruleset = "table inet filter {\n\tchain input {\n\
            \t\ttype filter hook input priority 0; policy drop;\n\t}\n\
            \tchain output {\n\t\ttype filter hook output priority 0; policy accept;\n\t}\n}\n";
        assert_eq!(
            parse_nft_chain_policy(ruleset, "output").as_deref(),
            Some("accept")
        );
    }

    #[test]
    fn nft_chain_policy_is_none_for_an_absent_chain() {
        assert_eq!(parse_nft_chain_policy(NFT_RULESET, "output"), None);
    }
}
