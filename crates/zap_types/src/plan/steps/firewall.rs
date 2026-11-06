//! `firewall` step builder — ufw or nftables, dispatched on the declared backend.

use crate::plan::{PlanStep, PutAs, PutSource, PutStep, PutText};
use crate::put::PutCheck;
use crate::scalar::Mode;
use crate::schema::{
    FirewallAllowRule, FirewallBackend, FirewallPolicy, FirewallResource, NFTABLES_RULESET_PATH,
};
use crate::shell::single_quote;

/// Steps to converge a `firewall`, dispatched on its backend.
pub(super) fn firewall_steps(firewall: &FirewallResource) -> Vec<PlanStep> {
    match firewall.backend {
        FirewallBackend::Ufw => ufw_steps(firewall),
        FirewallBackend::Nftables => nftables_steps(firewall),
    }
}

/// ufw default-policy + per-rule `allow` + `--force enable` steps.
fn ufw_steps(firewall: &FirewallResource) -> Vec<PlanStep> {
    let mut steps = vec![
        PlanStep::run(format!(
            "sudo ufw default {} incoming",
            firewall.default_incoming.as_str()
        )),
        PlanStep::run(format!(
            "sudo ufw default {} outgoing",
            firewall.default_outgoing.as_str()
        )),
    ];
    for rule in &firewall.allow {
        // A profile name can contain spaces (`Nginx Full`), so quote it; a port/proto
        // target (digits + `/`) needs no quoting and reads cleaner unquoted in a dry-run.
        // The target identity is `FirewallAllowRule::ufw_target` — one definition the
        // detector also matches against, so probe and mutation can't render it differently.
        // `ufw` reads its own arguments and takes no `--`: the structural gate refuses a
        // profile name that begins with `-`.
        let target = match rule {
            FirewallAllowRule::Named(name) => single_quote(name),
            FirewallAllowRule::PortProto { .. } => rule.ufw_target(),
        };
        steps.push(PlanStep::run(format!("sudo ufw allow {target}")));
    }
    steps.push(PlanStep::run("sudo ufw --force enable"));
    steps
}

/// nftables steps: write the declarative `inet filter` ruleset to `/etc/nftables.nft`,
/// then load it atomically with `nft -f`.
///
/// Boot persistence is the separate nftables service (the config enables it; it loads
/// the same file at boot); these steps own the ruleset content and the immediate apply,
/// the nftables analogue of ufw's self-applying `--force enable`.
fn nftables_steps(firewall: &FirewallResource) -> Vec<PlanStep> {
    let ruleset = nftables_ruleset(firewall);
    vec![
        // Install the ruleset whole, a blank line after it: staged, checked, and renamed
        // into place, so the file the service loads at boot is never a ruleset cut off
        // partway.
        PlanStep::Put(PutStep {
            path: NFTABLES_RULESET_PATH.to_owned(),
            run_as: PutAs::Root,
            check: PutCheck::None,
            source: PutSource::Text(PutText {
                mode: Mode::fixed("600"),
                content: format!("{ruleset}\n"),
            }),
        }),
        PlanStep::run(format!("sudo nft -f {NFTABLES_RULESET_PATH}")),
    ]
}

/// Render the declarative nftables ruleset for `firewall` (the `inet filter` table).
///
/// Two safety properties this generator is responsible for:
/// - **No lockout.** The input chain accepts established/related and loopback *before*
///   the default-drop policy takes effect, so loading the ruleset never severs the live
///   SSH session or the host's own return traffic (ufw adds these implicitly; a
///   hand-rolled ruleset must too).
/// - **Scoped + idempotent.** The table is declared, deleted, then defined — so `nft -f`
///   replaces exactly this table and is fully idempotent, without `flush ruleset` (which
///   would clobber other tables, e.g. fail2ban's `inet f2b-table`).
fn nftables_ruleset(firewall: &FirewallResource) -> String {
    let mut s = String::new();
    s.push_str("#!/usr/sbin/nft -f\n");
    s.push_str("# Managed by zap. Declarative ruleset for the inet filter table, scoped\n");
    s.push_str("# to this table only so nft -f reloads leave other tables untouched.\n");
    s.push('\n');
    // Ensure the table exists, delete it, then define it fresh — idempotent + scoped.
    s.push_str("table inet filter\n");
    s.push_str("delete table inet filter\n");
    s.push('\n');
    s.push_str("table inet filter {\n");

    s.push_str("\tchain input {\n");
    s.push_str("\t\ttype filter hook input priority 0; policy ");
    s.push_str(firewall.default_incoming.nft_chain_policy());
    s.push_str(";\n");
    s.push_str("\t\tct state established,related accept\n");
    s.push_str("\t\tct state invalid drop\n");
    s.push_str("\t\tiif \"lo\" accept\n");
    s.push_str("\t\tip protocol icmp accept\n");
    s.push_str("\t\tip6 nexthdr ipv6-icmp accept\n");
    for line in firewall
        .allow
        .iter()
        .filter_map(FirewallAllowRule::nft_rule)
    {
        s.push_str("\t\t");
        s.push_str(&line);
        s.push('\n');
    }
    // `reject` default → an explicit trailing reject (active ICMP rejection); `deny`'s
    // bare `policy drop` already drops silently.
    if firewall.default_incoming == FirewallPolicy::Reject {
        s.push_str("\t\treject\n");
    }
    s.push_str("\t}\n");

    s.push_str("\tchain forward {\n");
    s.push_str("\t\ttype filter hook forward priority 0; policy drop;\n");
    s.push_str("\t}\n");

    s.push_str("\tchain output {\n");
    s.push_str("\t\ttype filter hook output priority 0; policy ");
    s.push_str(firewall.default_outgoing.nft_chain_policy());
    s.push_str(";\n");
    // Keep the host functional even under a default-drop output policy.
    s.push_str("\t\tct state established,related accept\n");
    s.push_str("\t\toif \"lo\" accept\n");
    if firewall.default_outgoing == FirewallPolicy::Reject {
        s.push_str("\t\treject\n");
    }
    s.push_str("\t}\n");

    s.push_str("}\n");
    s
}

#[cfg(test)]
mod tests {
    use super::{NFTABLES_RULESET_PATH, firewall_steps, nftables_ruleset};
    use crate::plan::{PlanStep, PutAs, PutSource, PutStep, PutText, StepExecution};
    use crate::put::{FILE_PUT, PutCheck};
    use crate::scalar::Mode;
    use crate::schema::{FirewallAllowRule, FirewallResource, Protocol};
    use crate::shell::single_quote;

    fn firewall(json: serde_json::Value) -> FirewallResource {
        serde_json::from_value(json).expect("valid firewall json")
    }

    fn runs(firewall: &FirewallResource) -> Vec<String> {
        firewall_steps(firewall)
            .iter()
            .filter_map(PlanStep::execution)
            .map(|execution| execution.text().to_owned())
            .collect()
    }

    #[test]
    fn default_policies_lead_and_force_enable_trails() {
        // Defaults (deny incoming, allow outgoing) are the first two steps; `--force
        // enable` is always the last, so the rules are applied before the firewall is
        // brought up.
        let runs = runs(&firewall(serde_json::json!({
            "backend": "ufw", "allow": [{"port": 22, "proto": "tcp"}]
        })));
        assert_eq!(
            runs.first().map(String::as_str),
            Some("sudo ufw default deny incoming")
        );
        assert_eq!(
            runs.get(1).map(String::as_str),
            Some("sudo ufw default allow outgoing")
        );
        assert_eq!(
            runs.last().map(String::as_str),
            Some("sudo ufw --force enable")
        );
    }

    #[test]
    fn explicit_default_policies_are_rendered() {
        let runs = runs(&firewall(serde_json::json!({
            "backend": "ufw",
            "default_incoming": "reject", "default_outgoing": "deny",
            "allow": []
        })));
        assert!(runs.contains(&"sudo ufw default reject incoming".to_owned()));
        assert!(runs.contains(&"sudo ufw default deny outgoing".to_owned()));
    }

    #[test]
    fn port_proto_rules_render_their_ufw_target_unquoted() {
        // A digits+`/` target needs no quoting: tcp/udp render `<port>/<proto>`, an
        // any-proto rule the bare port (ufw omits the suffix). Probe↔mutation parity: the
        // `ufw allow` argument is exactly `FirewallAllowRule::ufw_target`, the same
        // identity the detector greps for, so the two can't render the rule differently.
        let rules = [
            FirewallAllowRule::PortProto {
                port: std::num::NonZeroU16::new(443).unwrap(),
                proto: Protocol::Tcp,
            },
            FirewallAllowRule::PortProto {
                port: std::num::NonZeroU16::new(53).unwrap(),
                proto: Protocol::Udp,
            },
            FirewallAllowRule::PortProto {
                port: std::num::NonZeroU16::new(8080).unwrap(),
                proto: Protocol::Any,
            },
        ];
        let runs = runs(&firewall(serde_json::json!({
            "backend": "ufw", "allow": rules
        })));
        for rule in &rules {
            assert!(
                runs.contains(&format!("sudo ufw allow {}", rule.ufw_target())),
                "allow target must be the shared ufw_target: {runs:?}"
            );
        }
        // The concrete renderings, pinned exactly.
        assert!(runs.contains(&"sudo ufw allow 443/tcp".to_owned()));
        assert!(runs.contains(&"sudo ufw allow 53/udp".to_owned()));
        assert!(runs.contains(&"sudo ufw allow 8080".to_owned()));
    }

    #[test]
    fn named_profile_is_single_quoted_around_its_ufw_target() {
        // A profile name can carry spaces (`Nginx Full`), so the `ufw allow` argument is
        // single-quoted for the shell. The quoted text is exactly `ufw_target()` (the
        // verbatim name), which is also the whole-token needle the detector matches
        // against the parsed `ufw status` column — quoting is the only difference.
        let runs = runs(&firewall(serde_json::json!({
            "backend": "ufw", "allow": ["OpenSSH", "Nginx Full"]
        })));
        assert!(runs.contains(&"sudo ufw allow 'OpenSSH'".to_owned()));
        assert!(runs.contains(&"sudo ufw allow 'Nginx Full'".to_owned()));
        let named = FirewallAllowRule::Named("Nginx Full".to_owned());
        assert!(runs.contains(&format!(
            "sudo ufw allow {}",
            single_quote(&named.ufw_target())
        )));
    }

    // --- nftables backend ---

    #[test]
    fn nftables_writes_then_loads_the_ruleset() {
        // Two steps: put `/etc/nftables.nft` whole at `600` — the text a
        // `printf '%s\n' '<ruleset>'` prints, the ruleset and one more newline — then
        // load it atomically with `nft -f`.
        let declared = firewall(serde_json::json!({
            "backend": "nftables", "allow": [{"port": 22, "proto": "tcp"}]
        }));
        let steps = firewall_steps(&declared);
        let content = format!("{}\n", nftables_ruleset(&declared));
        assert!(content.ends_with("}\n\n"));
        let put = PlanStep::Put(PutStep {
            path: NFTABLES_RULESET_PATH.to_owned(),
            run_as: PutAs::Root,
            check: PutCheck::None,
            source: PutSource::Text(PutText {
                mode: Mode::new("600").unwrap(),
                content: content.clone(),
            }),
        });
        assert_eq!(
            steps,
            [
                put.clone(),
                PlanStep::run(format!("sudo nft -f {NFTABLES_RULESET_PATH}"))
            ]
        );
        assert_eq!(
            put.execution(),
            Some(StepExecution::Put {
                command: format!("sudo sh -c '{FILE_PUT}' sh '/etc/nftables.nft' '600' '' '' ''"),
                content: &content,
            })
        );
    }

    #[test]
    fn nftables_ruleset_is_byte_exact_for_a_web_server() {
        // The deny-in / allow-out / 22,80,443-tcp case (a web server's firewall), pinned
        // verbatim — this is the host-bricking-if-wrong artifact.
        let ruleset = nftables_ruleset(&firewall(serde_json::json!({
            "backend": "nftables",
            "allow": [
                {"port": 22, "proto": "tcp"},
                {"port": 80, "proto": "tcp"},
                {"port": 443, "proto": "tcp"}
            ]
        })));
        let expected = "#!/usr/sbin/nft -f\n\
# Managed by zap. Declarative ruleset for the inet filter table, scoped\n\
# to this table only so nft -f reloads leave other tables untouched.\n\
\n\
table inet filter\n\
delete table inet filter\n\
\n\
table inet filter {\n\
\tchain input {\n\
\t\ttype filter hook input priority 0; policy drop;\n\
\t\tct state established,related accept\n\
\t\tct state invalid drop\n\
\t\tiif \"lo\" accept\n\
\t\tip protocol icmp accept\n\
\t\tip6 nexthdr ipv6-icmp accept\n\
\t\ttcp dport 22 accept\n\
\t\ttcp dport 80 accept\n\
\t\ttcp dport 443 accept\n\
\t}\n\
\tchain forward {\n\
\t\ttype filter hook forward priority 0; policy drop;\n\
\t}\n\
\tchain output {\n\
\t\ttype filter hook output priority 0; policy accept;\n\
\t\tct state established,related accept\n\
\t\toif \"lo\" accept\n\
\t}\n\
}\n";
        assert_eq!(ruleset, expected);
    }

    #[test]
    fn nftables_accepts_established_and_loopback_before_the_default_drop() {
        // The no-lockout guarantee: established/related + loopback are accepted before
        // any port rule, so loading a default-drop ruleset can't sever the live SSH
        // session. Assert the order structurally (not just presence).
        let ruleset = nftables_ruleset(&firewall(serde_json::json!({
            "backend": "nftables", "allow": [{"port": 22, "proto": "tcp"}]
        })));
        let established = ruleset.find("ct state established,related accept").unwrap();
        let loopback = ruleset.find("iif \"lo\" accept").unwrap();
        let first_port = ruleset.find("tcp dport 22 accept").unwrap();
        let drop_policy = ruleset.find("policy drop;").unwrap();
        assert!(established < first_port && loopback < first_port);
        // The input chain is default-drop (the policy line precedes the accepts).
        assert!(drop_policy < established);
    }

    #[test]
    fn nftables_renders_each_proto_via_the_shared_helper() {
        let rules = [
            FirewallAllowRule::PortProto {
                port: std::num::NonZeroU16::new(443).unwrap(),
                proto: Protocol::Tcp,
            },
            FirewallAllowRule::PortProto {
                port: std::num::NonZeroU16::new(53).unwrap(),
                proto: Protocol::Udp,
            },
            FirewallAllowRule::PortProto {
                port: std::num::NonZeroU16::new(8080).unwrap(),
                proto: Protocol::Any,
            },
        ];
        let ruleset = nftables_ruleset(&firewall(serde_json::json!({
            "backend": "nftables", "allow": rules
        })));
        // Each rule's line is exactly its shared `nft_rule()` (the detector's needle).
        for rule in &rules {
            let line = rule.nft_rule().expect("port rule renders");
            assert!(ruleset.contains(&line), "missing {line:?} in {ruleset}");
        }
        assert!(ruleset.contains("tcp dport 443 accept"));
        assert!(ruleset.contains("udp dport 53 accept"));
        assert!(ruleset.contains("meta l4proto { tcp, udp } th dport 8080 accept"));
    }

    #[test]
    fn nftables_reject_default_appends_a_trailing_reject() {
        let ruleset = nftables_ruleset(&firewall(serde_json::json!({
            "backend": "nftables",
            "default_incoming": "reject", "default_outgoing": "reject",
            "allow": []
        })));
        // reject → `policy drop` plus an explicit trailing `reject` in each chain.
        assert!(ruleset.contains("policy drop;"));
        assert_eq!(
            ruleset.matches("\t\treject\n").count(),
            2,
            "one trailing reject per chain (input + output): {ruleset}"
        );
    }
}
