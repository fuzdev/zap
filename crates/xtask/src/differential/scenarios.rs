//! The scenario matrix: each scenario puts the converged base into a known state —
//! a root shell snippet on the VM, and/or an operator-side change (the per-run
//! `zap.lock`, an env var) — before the oracle and candidate detect and plan it.
//!
//! Every scenario states what it **expects the oracle to see**: the resources its
//! `detect` reports as anything but `ok`, with their mark. A mismatch is a harness
//! error, not a divergence — it means the mutation didn't do what the scenario
//! claims (or the oracle isn't of the engine generation this table describes), so the
//! comparison would prove less than it says. A candidate that reads a state
//! differently still meets the oracle's expectation here; its different verdict is a
//! divergence, accepted only through the `intended` table.
//!
//! A scenario that **reconverges** carries a probe: a root shell snippet that never
//! goes through zap and prints the state the scenario drifts. After the read-only
//! phase, the candidate applies the drifted state back, and the probe must read what
//! it read on the base (`reconverge`). Only an SSH scenario whose every expected mark
//! is `drift` or `absent`, with no operator-side change and no `remote` content,
//! reconverges: a held `?` stops the preview at exit 1, and the apply fetches nothing.
//!
//! One scenario is of another **kind** ([`Kind::ReplaceBootstrap`]): it compares
//! nothing and changes the machine on purpose, replacing the VM's bootstrap user in
//! place, with the candidate alone (`bootstrap`). It mutates nothing ahead of its runs
//! and expects nothing of the oracle.
//!
//! The paths here mirror the fixtures under `crates/xtask/fixtures/differential/`;
//! change them together. Independent mutations share a scenario to keep the run
//! short; resources that interact (a `verify` whose assertion reads a mutated file, a
//! database whose server is stopped) get their own.
//!
//! The things the expectations pin that read as defects, each marked where it is
//! expected:
//!
//! - **E3** — `link` and `directory` existence probes and `verify`'s `path_exists`
//!   run unprivileged (over SSH and on a Local connection alike), so under a
//!   root-only directory a link or directory reads `absent` (not `?`) — a create
//!   would be planned over state nobody read — and the assertion fails.

use super::vm::Distro;

/// Where a scenario's zap runs happen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Suite {
    /// zap on the dev machine, driving the VM over SSH (the kitchen-sink fixture).
    Ssh,
    /// zap on the VM itself, as the SSH user, against a `local: true` fixture.
    Local,
}

impl Suite {
    pub const fn name(self) -> &'static str {
        match self {
            Self::Ssh => "ssh",
            Self::Local => "local",
        }
    }
}

/// An operator-side change, applied for the scenario's zap runs only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Operator {
    None,
    /// Edit the per-run `zap.lock`: remove the `drop` entries, and give the `stale`
    /// entries a `config_hash` that no config produces.
    Lock {
        drop: &'static [&'static str],
        stale: &'static [&'static str],
    },
    /// Override (`Some`) or unset (`None`) an operator env var.
    Env(&'static str, Option<&'static str>),
}

/// What a scenario does with the state it starts from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// Both binaries detect and plan the mutated base, read-only, and their output is
    /// compared (then, with a probe, the candidate reconverges it).
    Compare,
    /// The candidate replaces the VM's bootstrap user in place (`bootstrap`): no
    /// comparison, and the target is changed on purpose.
    ReplaceBootstrap,
}

/// A runtime-digest anchor a scenario may knowingly remove (see `audit::Anchors`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Anchor {
    /// The fixture's sleeper service is running (its identity is in the digest).
    Sleeper,
    /// The firewall is active / its table exists.
    Firewall,
    /// The postgres server answers.
    Postgres,
}

/// One state of the matrix.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Scenario {
    pub name: &'static str,
    pub suite: Suite,
    pub kind: Kind,
    /// What the mutation does, for the report.
    pub about: &'static str,
    /// The root shell snippet (`set -eu`; empty for none).
    pub mutation: String,
    pub operator: Operator,
    /// Whether `remote` resources are in play, so the scenario also runs with a
    /// warm content cache.
    pub remote: bool,
    /// The oracle `detect`'s expected non-`ok` resources as `(id, mark)`, sorted.
    pub expect: Vec<(&'static str, &'static str)>,
    /// Text the oracle's `plan` must (`true`) or must not (`false`) contain.
    pub expect_plan: Vec<(&'static str, bool)>,
    /// Runtime-digest anchors this scenario's mutation removes on purpose.
    pub without: Vec<Anchor>,
    /// The probe, when the candidate reconverges the drifted state after the read-only
    /// phase: a root shell snippet (run under `sh -eu -o pipefail`, from `/`) that
    /// prints the state the mutation drifts, without zap and without writing anything.
    pub reconverge: Option<String>,
}

impl Scenario {
    fn new(
        name: &'static str,
        suite: Suite,
        about: &'static str,
        mutation: &str,
        expect: &[(&'static str, &'static str)],
    ) -> Self {
        let mut expect = expect.to_vec();
        expect.sort_unstable();
        Self {
            name,
            suite,
            kind: Kind::Compare,
            about,
            mutation: mutation.trim().to_owned(),
            operator: Operator::None,
            remote: false,
            expect,
            expect_plan: Vec::new(),
            without: Vec::new(),
            reconverge: None,
        }
    }

    /// The candidate applies the drifted state back, and `probe` must then read what
    /// it read on the base.
    fn reconverges(mut self, probe: &str) -> Self {
        self.reconverge = Some(probe.trim().to_owned());
        self
    }

    fn without(mut self, anchor: Anchor) -> Self {
        self.without.push(anchor);
        self
    }

    fn plan_shows(mut self, text: &'static str) -> Self {
        self.expect_plan.push((text, true));
        self
    }

    fn plan_lacks(mut self, text: &'static str) -> Self {
        self.expect_plan.push((text, false));
        self
    }

    const fn remote(mut self) -> Self {
        self.remote = true;
        self
    }

    const fn operator(mut self, operator: Operator) -> Self {
        self.operator = operator;
        self
    }

    /// The bootstrap-replace scenario (`bootstrap`): no mutation, nothing expected of
    /// the oracle, nothing compared.
    fn replaces_bootstrap(name: &'static str, about: &'static str) -> Self {
        Self {
            kind: Kind::ReplaceBootstrap,
            ..Self::new(name, Suite::Ssh, about, "", &[])
        }
    }
}

/// The operator env var the `script-var` check compares against, and its value.
pub const EXPECT_VAR: (&str, &str) = ("ZAPDIFF_EXPECT", "expected-value");

/// Per-distro spellings of the mutations that go through a manager or backend.
struct Managers {
    remove_jq: &'static str,
    stop_sleeper: &'static str,
    disable_sleeper: &'static str,
    start_idle: &'static str,
    disable_ssh_boot: &'static str,
    stop_postgres: &'static str,
    open_default_incoming: &'static str,
    deny_default_outgoing: &'static str,
    delete_rules: &'static str,
    remove_firewall: &'static str,
    /// The firewall's live policy and rules, and what loads them at boot.
    firewall_probe: &'static str,
}

const fn managers(distro: Distro) -> Managers {
    match distro {
        Distro::Debian => Managers {
            remove_jq: "DEBIAN_FRONTEND=noninteractive apt-get remove -y -q jq >/dev/null",
            stop_sleeper: "systemctl stop zapdiff-sleeper",
            disable_sleeper: "systemctl disable -q zapdiff-sleeper",
            start_idle: "systemctl start zapdiff-idle",
            // disabling at boot doesn't stop the running sshd
            disable_ssh_boot: "systemctl disable -q ssh",
            stop_postgres: "systemctl stop postgresql",
            open_default_incoming: "ufw default allow incoming >/dev/null",
            deny_default_outgoing: "ufw default deny outgoing >/dev/null",
            delete_rules: "ufw delete allow 443/tcp >/dev/null\nufw delete allow 5353/udp >/dev/null",
            remove_firewall: "ufw disable >/dev/null",
            // the kernel's chains first: `ufw status` reports ufw's files, which are what
            // detection reads, so an apply that rewrote them without loading them would
            // pass on those alone. `-S` prints no counters; the policies, ufw's fixed
            // jumps, and the user chains read the same across a `ufw` reload. Then the
            // files, which `ufw default` rewrites and ufw loads at boot
            firewall_probe: "iptables -S INPUT\nip6tables -S INPUT\niptables -S OUTPUT\n\
                 ip6tables -S OUTPUT\niptables -S ufw-user-input\n\
                 ip6tables -S ufw6-user-input\nufw status verbose\n\
                 grep '^DEFAULT_' /etc/default/ufw\n\
                 sha256sum /etc/ufw/user.rules /etc/ufw/user6.rules",
        },
        Distro::Alpine => Managers {
            remove_jq: "apk del -q jq",
            stop_sleeper: "rc-service -q zapdiff-sleeper stop",
            disable_sleeper: "rc-update -q del zapdiff-sleeper default",
            start_idle: "rc-service -q zapdiff-idle start",
            disable_ssh_boot: "rc-update -q del sshd default",
            stop_postgres: "rc-service -q postgresql stop",
            open_default_incoming: "nft 'chain inet filter input { policy accept; }'",
            // established replies (the harness's ssh) are accepted before the policy
            deny_default_outgoing: "nft 'chain inet filter output { policy drop; }'",
            delete_rules: "for port in 'tcp dport 443 ' 'udp dport 5353 '; do\n  \
                 nft delete rule inet filter input handle \
                 \"$(nft -a list chain inet filter input | grep -F \"$port\" | awk '{print $NF}')\"\n\
                 done",
            remove_firewall: "nft delete table inet filter",
            // without handles, which an `nft -f` reload renumbers; the file is what the
            // nftables service loads at boot
            firewall_probe: "nft list table inet filter\nsha256sum /etc/nftables.nft",
        },
    }
}

/// The `user-access` probe: each touched user's `/etc/shadow` password field (an
/// `ssh_keys` user's is held at the disabled `*`, which `usermod -L` locks to `!*`)
/// and their `authorized_keys`' mode, owner, and digest.
const USER_ACCESS_PROBE: &str = r#"
for user in zapdiff zapdiff2; do
  # verbatim: the fixture users hold no password hash, only the disabled `*`
  awk -F: -v u="$user" '$1 == u { print u, "password field", $2 }' /etc/shadow
  keys="/home/$user/.ssh/authorized_keys"
  stat -c '%a %U:%G %n' "$keys"
  sha256sum "$keys"
done
"#;

/// The `database-pg-hba` probe: the hba file's mode and owner, and the database's
/// own rules in it, sorted. The declaration governs which rules are there, not where:
/// zap puts a missing rule ahead of the first `host` line, so a rule restored among
/// another database's comes back above them, and the file's bytes and line numbers
/// differ from the base's.
const PG_HBA_PROBE: &str = r#"
hba=$(sudo -u postgres psql -tAc 'SHOW hba_file')
stat -c '%a %U:%G %n' "$hba"
awk '$1 == "host" && $2 == "zapdiff" && $3 == "zapdiff"' "$hba" | sort
"#;

/// Every scenario for `distro`, SSH suite first.
pub fn scenarios(distro: Distro) -> Vec<Scenario> {
    let m = managers(distro);
    let ssh = |name, about, mutation: &str, expect: &[(&'static str, &'static str)]| {
        Scenario::new(name, Suite::Ssh, about, mutation, expect)
    };
    let alpine = distro == Distro::Alpine;
    let mut all = vec![
        ssh("converged", "no mutation — the base as converged", "", &[]).remote(),
        ssh(
            "file-content",
            "same-size in-place edit, template, source copy, and a home file rewritten",
            r"
sed -i 's/zapdiff inline/ZAPDIFF INLINE/' /etc/zapdiff/inline.conf
printf 'name=zapdiff\nport=9090\n' > /etc/zapdiff/template.conf
printf 'hand-edited copy\n' > /etc/zapdiff/source-copy.conf
printf 'hand edit\n' > /home/ops/zapdiff/home.txt
",
            &[
                ("inline", "drift"),
                ("template", "drift"),
                ("source-copy", "drift"),
                ("home-file", "drift"),
            ],
        ),
        ssh(
            "file-source-changed",
            "the file a `source` copy reads from changes",
            r"printf 'the origin moved on\n' > /etc/zapdiff/source-origin.conf",
            &[("source-origin", "drift"), ("source-copy", "drift")],
        ),
        ssh(
            "file-metadata",
            "chmod / chown on files and dirs, including a parent made root-only",
            r"
chmod 600 /etc/zapdiff/inline.conf
chown ops /etc/zapdiff/template.conf
chmod 644 /opt/zapdiff/private/secret.conf
chmod 755 /opt/zapdiff/private
chmod 700 '/opt/zapdiff/zap diff'
",
            &[
                ("spaced-dir", "drift"),
                ("private-dir", "drift"),
                ("inline", "drift"),
                ("template", "drift"),
                ("private-file", "drift"),
                // `verify` asserts inline.conf's mode 644
                ("verify", "absent"),
                // E3: unprivileged probes under the now root-only 'zap diff' dir
                ("spaced-link", "absent"),
                ("spaced-subdir", "absent"),
                ("verify-spaced", "absent"),
            ],
        ),
        ssh(
            "absent",
            "a file with a space and a quote, a dir, a link, and a home file removed",
            r#"
rm "/opt/zapdiff/zap diff/it's here.txt" "/opt/zapdiff/zap diff/link to it"
rmdir /opt/zapdiff/empty-dir
rm /home/ops/zapdiff/home.txt
"#,
            &[
                ("empty-dir", "absent"),
                ("spaced-file", "absent"),
                ("spaced-link", "absent"),
                ("home-file", "absent"),
                // asserts the removed file exists
                ("verify-spaced", "absent"),
            ],
        ),
        ssh(
            "link-repointed",
            "the managed link points elsewhere",
            r#"ln -sfn /etc/hostname "/opt/zapdiff/zap diff/link to it""#,
            &[("spaced-link", "drift")],
        ),
        ssh(
            "file-edge-cases",
            "no-EOL and CRLF content changed, source origin removed, a dir at a file \
             path, the tar sentinel removed",
            r"
printf '\n' >> /etc/zapdiff/no-eol.txt
sed -i 's/\r$//' /etc/zapdiff/crlf.txt
rm /etc/zapdiff/source-origin.conf
rm /home/ops/zapdiff/home.txt && mkdir /home/ops/zapdiff/home.txt
rm /opt/zapdiff/tree/.zap_remote_hash
",
            &[
                ("inline-no-eol", "drift"),
                ("inline-crlf", "drift"),
                ("source-origin", "absent"),
                ("source-copy", "?"),
                // a directory where the file belongs can't be read: held, not guessed
                ("home-file", "?"),
                // an extracted tree that holds files and no sentinel is held: nothing
                // shows zap made it, so extracting over it would be refused
                ("tree", "?"),
            ],
        )
        .remote(),
        ssh(
            "remote-content",
            "vendored blob edited in place (same size), tracked blob truncated",
            r"
printf 'ZAPDIFF' | dd of=/opt/zapdiff/blob.bin bs=1 seek=1024 conv=notrunc 2>/dev/null
dd if=/dev/null of=/opt/zapdiff/blob-tracked.bin bs=1 seek=1000 2>/dev/null
",
            &[("blob", "drift"), ("blob-tracked", "drift")],
        )
        .remote(),
        ssh(
            "remote-removed",
            "vendored blob deleted, tar sentinel and build provenance sidecar altered",
            r"
rm /opt/zapdiff/blob.bin
printf 'not the pin\n' > /opt/zapdiff/tree/.zap_remote_hash
printf 'not the pin\n' > /home/ops/.local/bin/zapdiff-built.zap-build
",
            &[("blob", "absent"), ("tree", "drift"), ("build", "drift")],
        )
        .remote(),
        ssh(
            "remote-tree-inner",
            "a binary inside the extracted tree deleted",
            "rm /opt/zapdiff/tree/bin/zapdiff-tool",
            // detection compares the extract sentinel, not the extracted tree
            &[],
        )
        .remote(),
        ssh(
            "build-absent",
            "a build output removed, a tracked build's provenance sidecar removed",
            r"
rm /home/ops/.local/bin/zapdiff-built
rm /home/ops/.local/bin/zapdiff-built-tracked.zap-build
",
            &[("build", "absent"), ("build-tracked", "absent")],
        )
        .remote(),
        ssh(
            "lock-pins",
            "operator side: the tracked blob's lock entry dropped, the tracked build's \
             made stale",
            "",
            &[("blob-tracked", "?"), ("build-tracked", "?")],
        )
        .operator(Operator::Lock {
            drop: &["blob-tracked"],
            stale: &["build-tracked"],
        })
        .remote(),
        ssh(
            "package-removed",
            "jq uninstalled",
            m.remove_jq,
            // `pkg-login-check`'s own `check` still passes: a check replaces the query
            &[("jq", "absent"), ("jq-path-check", "absent")],
        ),
        ssh(
            "service-stopped",
            "the sleeper service stopped",
            m.stop_sleeper,
            &[("sleeper", "drift")],
        )
        .without(Anchor::Sleeper),
        ssh(
            "service-disabled",
            "the sleeper service disabled at boot",
            m.disable_sleeper,
            &[("sleeper", "drift")],
        ),
        ssh(
            "service-flags",
            "a service desired stopped + disabled is started; sshd (running unmanaged) \
             is disabled at boot",
            &format!("{}\n{}", m.start_idle, m.disable_ssh_boot),
            &[("idle", "drift"), ("ssh-boot", "drift")],
        ),
        ssh(
            "swap-off",
            "the swap file deactivated",
            "swapoff /swapfile-zapdiff",
            &[("swap", "drift")],
        ),
        ssh(
            "swap-fstab",
            "the swap line removed from /etc/fstab",
            r"sed -i '\#/swapfile-zapdiff#d' /etc/fstab",
            &[("swap", "drift")],
        ),
        ssh(
            "swap-absent",
            "the swap file deactivated and deleted",
            "swapoff /swapfile-zapdiff\nrm /swapfile-zapdiff",
            &[("swap", "absent")],
        ),
        ssh(
            "firewall-policy",
            "default incoming policy flipped to allow",
            m.open_default_incoming,
            &[("firewall", "drift")],
        )
        .reconverges(m.firewall_probe),
        ssh(
            "firewall-outgoing",
            "default outgoing policy flipped to deny",
            m.deny_default_outgoing,
            &[("firewall", "drift")],
        ),
        ssh(
            "firewall-rule",
            "the 443/tcp and 5353/udp allow rules deleted",
            m.delete_rules,
            &[("firewall", "drift")],
        ),
        ssh(
            "firewall-absent",
            "the firewall disabled (ufw) / its table deleted (nftables)",
            m.remove_firewall,
            &[("firewall", "absent")],
        )
        .without(Anchor::Firewall),
        ssh(
            "user-attributes",
            "shell, home mode, a supplementary group, and a sudoers file changed",
            r"
usermod -s /sbin/nologin zapdiff
chmod 755 /home/zapdiff
gpasswd -d zapdiff video >/dev/null
rm /etc/sudoers.d/zapdiff2
",
            &[("user-copy", "drift"), ("user-keys", "drift")],
        ),
        ssh(
            "user-access",
            "a copied authorized key removed, a password field `!`-locked",
            r"
: > /home/zapdiff/.ssh/authorized_keys
usermod -L zapdiff2
",
            &[("user-copy", "drift"), ("user-keys", "drift")],
        )
        .reconverges(USER_ACCESS_PROBE),
        ssh(
            "user-content",
            "a key appended to a keys-managed file and to a copy source, a sudoers file \
             rewritten",
            r"
echo 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHN0cmF5LWtleS1mb3ItZGlmZmVyZW50aWFs stray' >> /home/zapdiff2/.ssh/authorized_keys
echo 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGNvcHktc291cmNlLWdyZXctYS1rZXk-extra source' >> /home/ops/.ssh/authorized_keys
echo 'zapdiff ALL=(ALL) ALL' > /etc/sudoers.d/zapdiff
",
            // zapdiff3 copies zapdiff2's keys, so it moves with them
            &[
                ("user-copy", "drift"),
                ("user-keys", "drift"),
                ("user-copy-keys", "drift"),
            ],
        ),
        ssh(
            "user-copy-unreadable",
            "a copy source's authorized_keys removed",
            "rm /home/zapdiff2/.ssh/authorized_keys",
            &[("user-keys", "drift"), ("user-copy-keys", "drift")],
        ),
        ssh(
            "user-deleted",
            "a managed user deleted (a copy target's source)",
            "userdel -r zapdiff2 2>/dev/null",
            &[("user-keys", "absent"), ("user-copy-keys", "drift")],
        ),
        ssh(
            "database-pg-hba",
            "a pg_hba rule removed",
            r#"
hba=$(sudo -u postgres psql -tAc 'SHOW hba_file')
sed -i '/10\.0\.0\.0\/8/d' "$hba"
"#,
            &[("database", "drift")],
        )
        .reconverges(PG_HBA_PROBE),
        ssh(
            "database-owner",
            "the database's owner changed",
            "sudo -u postgres psql -qc 'ALTER DATABASE zapdiff OWNER TO postgres'",
            &[("database", "drift")],
        ),
        ssh(
            "database-role-dropped",
            "the database's role dropped (ownership and grants moved off it first)",
            "sudo -u postgres psql -q -c 'ALTER DATABASE zapdiff OWNER TO postgres' \
             -c 'REVOKE ALL ON DATABASE zapdiff FROM zapdiff' -c 'DROP ROLE zapdiff'",
            // a missing role plans the (guarded, idempotent) create path
            &[("database", "absent")],
        ),
        ssh(
            "postgres-stopped",
            "the postgres server stopped",
            m.stop_postgres,
            // postgres is installed and its catalog query fails: held, not read absent
            &[("postgresql-service", "drift"), ("database", "?")],
        )
        .without(Anchor::Postgres)
        .plan_shows("      database — detection failed: the PostgreSQL catalog query exited 2")
        .plan_lacks("  [+] database  (database)"),
        ssh(
            "checks-failing",
            "script checks (stdin-reading, slow, relative to `cwd`) and the installer \
             check path fail",
            "rm /opt/zapdiff/stdin-check.marker /opt/zapdiff/slow-check.marker \
             /opt/zapdiff/cwd.marker /opt/zapdiff/installer.marker",
            &[
                ("installer", "absent"),
                ("script-stdin", "absent"),
                ("script-slow", "absent"),
                ("script-cwd", "absent"),
            ],
        ),
        ssh(
            "operator-var-changed",
            "operator side: the var a script check compares against differs",
            "",
            &[("script-var", "absent")],
        )
        .operator(Operator::Env(EXPECT_VAR.0, Some("another-value"))),
        ssh(
            "operator-var-unset",
            "operator side: the var a script check references is unset",
            "",
            &[("script-var", "absent")],
        )
        .operator(Operator::Env(EXPECT_VAR.0, None)),
        ssh(
            "verify-failing",
            "a verify command assertion fails (and its flag file drifts)",
            r"printf 'broken\n' > /etc/zapdiff/verify.flag",
            &[("verify", "absent"), ("verify-flag", "drift")],
        ),
        ssh(
            "pending-trigger",
            "a pending reload marker for the sleeper, and one for an unmanaged service",
            r"
mkdir -p /var/lib/zap/pending
echo reload > /var/lib/zap/pending/zapdiff-sleeper
echo restart > /var/lib/zap/pending/not-managed
",
            // markers show in `plan`, not `detect`
            &[],
        )
        .plan_shows("(pending reload from an earlier apply)")
        .plan_shows("a pending restart of `not-managed` is recorded on the target"),
        ssh(
            "pending-unknown-kind",
            "a pending marker whose content is no known kind (honored as a restart)",
            r"
mkdir -p /var/lib/zap/pending
echo frobnicate > /var/lib/zap/pending/zapdiff-sleeper
",
            &[],
        )
        .plan_shows("(pending restart from an earlier apply)"),
        ssh(
            "pending-unreadable",
            "a pending reload marker in a pending dir only root can read",
            r"
mkdir -p /var/lib/zap
rm -rf /var/lib/zap/pending
mkdir -m 700 /var/lib/zap/pending
echo reload > /var/lib/zap/pending/zapdiff-sleeper
",
            &[],
        )
        // the markers are read as root, so a root-only pending dir still owes its reload
        .plan_shows("(pending reload from an earlier apply)"),
        ssh(
            "trailing-whitespace",
            "a trailing newline appended to each file detection compares trimmed",
            &format!(
                "{trim_compared}\nfor f in $files; do printf '\\n' >> \"$f\"; done",
                trim_compared = if distro == Distro::Debian {
                    "files='/etc/sudoers.d/zapdiff /home/zapdiff/.ssh/authorized_keys \
                     /home/zapdiff2/.ssh/authorized_keys /opt/zapdiff/tree/.zap_remote_hash \
                     /home/ops/.local/bin/zapdiff-built.zap-build \
                     /etc/apt/sources.list.d/zapdiff-repo.list'"
                } else {
                    "files='/etc/sudoers.d/zapdiff /home/zapdiff/.ssh/authorized_keys \
                     /home/zapdiff2/.ssh/authorized_keys /opt/zapdiff/tree/.zap_remote_hash \
                     /home/ops/.local/bin/zapdiff-built.zap-build'"
                }
            ),
            // today these compare trimmed, so the oracle reads everything converged;
            // a later detector must keep this tolerance or record the change as an
            // intended divergence
            &[],
        ),
        // ahead of the distro's own scenarios, so one always follows it and starts from
        // the revert that brings `ops` back
        Scenario::replaces_bootstrap(
            super::bootstrap::NAME,
            "the bootstrap user replaced in place: zapnext provisioned with --bootstrap, \
             then ops retired over zapnext's own login",
        ),
    ];
    if alpine {
        all.push(ssh(
            "firewall-reject",
            "a trailing bare `reject` makes the input chain's effective policy reject",
            "nft add rule inet filter input reject",
            &[("firewall", "drift")],
        ));
    }
    if distro == Distro::Debian {
        all.push(ssh(
            "apt-repo-edited",
            "the apt_repo sources line edited",
            r"sed -i 's# \./$# stable main#' /etc/apt/sources.list.d/zapdiff-repo.list",
            &[("zapdiff-repo", "drift")],
        ));
        all.push(ssh(
            "apt-repo-absent",
            "one repo's signing key removed, another's .list removed",
            r"
rm /usr/share/keyrings/zapdiff-repo.asc
rm /etc/apt/sources.list.d/zapdiff-repo2.list
",
            &[("zapdiff-repo", "absent"), ("zapdiff-repo2", "drift")],
        ));
        // The oracle's expectation for an oracle that carries the pinned apt_repo key
        // (detection compares the key's blake3 with its pin). No run spans that change:
        // an older oracle refuses the v3 lock and the fixtures' operator-side `http`
        // key URL, so this table describes only oracles that include it.
        all.push(ssh(
            "apt-repo-key-replaced",
            "the apt_repo signing key replaced by other bytes",
            "echo 'not the pinned key' > /usr/share/keyrings/zapdiff-repo.asc",
            &[("zapdiff-repo", "drift")],
        ));
    }
    if distro.has_local_suite() {
        all.extend(local_scenarios());
    }
    all
}

/// The local-connection suite (Debian only). Paths mirror `debian-local/zap.ts`.
fn local_scenarios() -> Vec<Scenario> {
    let local = |name, about, mutation: &str, expect: &[(&'static str, &'static str)]| {
        Scenario::new(name, Suite::Local, about, mutation, expect)
    };
    vec![
        local(
            "local-converged",
            "no mutation — the local base as converged",
            "",
            &[],
        )
        .remote(),
        local(
            "local-files",
            "home file content, home template mode, root-owned source copy mode + content",
            r#"
printf 'appended\n' >> "/home/ops/zapdiff-local/it's a file.txt"
chmod 644 /home/ops/zapdiff-local/template.conf
printf 'edited\n' > /etc/zapdiff-local/source-copy.conf
chmod 600 /etc/zapdiff-local/source-copy.conf
"#,
            &[
                ("home-file", "drift"),
                ("home-template", "drift"),
                ("root-source-copy", "drift"),
            ],
        ),
        local(
            "local-private",
            "a file under a root-only dir rewritten",
            r"printf 'changed\n' > /etc/zapdiff-local/private/secret.conf",
            &[("private-file", "drift")],
        ),
        local(
            "local-parent-locked",
            "the parent of managed-mode resources made root-only",
            "chmod 700 /etc/zapdiff-local",
            &[
                // `root-file` and `root-source-copy` stay `ok`: a metadata read the login
                // user is denied escalates to `sudo`
                ("root-dir", "drift"),
                // E3: the directory's existence probe is unprivileged
                ("private-dir", "absent"),
                // its `cat` runs as the login user
                ("verify", "absent"),
            ],
        ),
        local(
            "local-absent",
            "a home link, a home remote file, and a root-only dir + file removed",
            r"
rm /home/ops/zapdiff-local/link /home/ops/zapdiff-local/blob.bin
rm -r /etc/zapdiff-local/private
",
            &[
                ("home-link", "absent"),
                ("home-blob", "absent"),
                ("private-dir", "absent"),
                ("private-file", "absent"),
            ],
        )
        .remote(),
        local(
            "local-remote",
            "a home remote file edited in place",
            r"printf 'X' | dd of=/home/ops/zapdiff-local/blob.bin bs=1 seek=10 conv=notrunc 2>/dev/null",
            &[("home-blob", "drift")],
        )
        .remote(),
        local(
            "local-probes",
            "user shell + stray sudoers, service stopped, package removed, script check failing",
            r"
usermod -s /sbin/nologin zapdifflocal
echo 'zapdifflocal ALL=(ALL) ALL' > /etc/sudoers.d/zapdifflocal
chmod 440 /etc/sudoers.d/zapdifflocal
systemctl stop zapdiff-sleeper
DEBIAN_FRONTEND=noninteractive apt-get remove -y -q jq >/dev/null
rm /home/ops/zapdiff-local/script.marker
",
            &[
                ("jq", "absent"),
                ("sleeper", "drift"),
                ("user", "drift"),
                ("script", "absent"),
            ],
        )
        .without(Anchor::Sleeper),
    ]
}

/// The scenarios for `distro` matching `filter` (every scenario when empty).
pub fn select(distro: Distro, filter: &[String]) -> Vec<Scenario> {
    scenarios(distro)
        .into_iter()
        .filter(|s| filter.is_empty() || filter.iter().any(|name| name == s.name))
        .collect()
}

/// The names in `filter` that match no scenario on any of `distros`.
pub fn unknown_names(distros: &[Distro], filter: &[String]) -> Vec<String> {
    filter
        .iter()
        .filter(|name| {
            !distros
                .iter()
                .any(|&d| scenarios(d).iter().any(|s| s.name == name.as_str()))
        })
        .cloned()
        .collect()
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::{Kind, Operator, Suite, scenarios, select, unknown_names};
    use crate::differential::vm::Distro;

    #[test]
    fn names_are_unique_per_distro() {
        for distro in Distro::ALL {
            let all = scenarios(distro);
            let names: BTreeSet<_> = all.iter().map(|s| s.name).collect();
            assert_eq!(
                names.len(),
                all.len(),
                "duplicate scenario name on {distro}"
            );
        }
    }

    #[test]
    fn every_distro_starts_with_the_converged_baseline() {
        for distro in Distro::ALL {
            let first = &scenarios(distro)[0];
            assert_eq!(first.name, "converged");
            assert!(first.mutation.is_empty());
            assert!(first.expect.is_empty());
            assert!(first.remote, "the baseline also runs warm");
        }
    }

    #[test]
    fn every_scenario_changes_something_or_expects_nothing() {
        for distro in Distro::ALL {
            for s in scenarios(distro) {
                let acts = !s.mutation.is_empty() || s.operator != Operator::None;
                assert!(
                    acts || s.expect.is_empty(),
                    "{distro}/{} expects movement without acting",
                    s.name
                );
                let marks_ok = s
                    .expect
                    .iter()
                    .all(|(_, mark)| matches!(*mark, "drift" | "absent" | "?"));
                assert!(
                    marks_ok,
                    "{distro}/{} uses a mark detect never renders",
                    s.name
                );
                let mut sorted = s.expect.clone();
                sorted.sort_unstable();
                assert_eq!(sorted, s.expect);
            }
        }
    }

    /// A reconverging scenario is one a single reviewed apply can put back, offline,
    /// with nothing but the target to restore: an SSH run, every expected mark a drift
    /// or an absence (a held `?` stops the preview at exit 1), no operator-side change
    /// (the apply would converge the edited operator state, not the target), no
    /// `remote` content (the apply would fetch), and a probe. Both distros reconverge
    /// the same set.
    #[test]
    fn a_reconverging_scenario_is_one_apply_can_put_back() {
        let reconverging = |distro| -> BTreeSet<&'static str> {
            scenarios(distro)
                .into_iter()
                .filter(|s| s.reconverge.is_some())
                .map(|s| s.name)
                .collect()
        };
        for distro in Distro::ALL {
            for s in scenarios(distro) {
                let Some(probe) = &s.reconverge else { continue };
                let name = format!("{distro}/{}", s.name);
                assert_eq!(s.suite, Suite::Ssh, "{name}");
                assert!(!s.expect.is_empty(), "{name} expects nothing to put back");
                assert!(
                    s.expect
                        .iter()
                        .all(|(_, mark)| matches!(*mark, "drift" | "absent")),
                    "{name}: {:?}",
                    s.expect
                );
                assert_eq!(s.operator, Operator::None, "{name}");
                assert!(!s.remote, "{name}");
                assert!(!s.mutation.is_empty(), "{name}");
                assert!(!probe.is_empty(), "{name}");
            }
            assert!(!reconverging(distro).is_empty(), "{distro}");
        }
        assert_eq!(reconverging(Distro::Alpine), reconverging(Distro::Debian));
    }

    /// The bootstrap replacement is one SSH scenario on each distro, carrying nothing
    /// of a compared one, and another scenario follows it in the table, so a run of the
    /// matrix shows the revert after it bringing `ops` back.
    #[test]
    fn the_bootstrap_replacement_is_one_scenario_on_each_distro() {
        for distro in Distro::ALL {
            let all = scenarios(distro);
            let at: Vec<usize> = all
                .iter()
                .enumerate()
                .filter(|(_, s)| s.kind == Kind::ReplaceBootstrap)
                .map(|(at, _)| at)
                .collect();
            let [at] = at[..] else {
                panic!("{distro}: {at:?}");
            };
            let s = &all[at];
            assert_eq!(s.name, crate::differential::bootstrap::NAME);
            assert_eq!(s.suite, Suite::Ssh);
            assert!(s.mutation.is_empty() && s.expect.is_empty() && s.expect_plan.is_empty());
            assert_eq!(s.operator, Operator::None);
            assert!(!s.remote && s.reconverge.is_none() && s.without.is_empty());
            assert!(at + 1 < all.len(), "{distro}: nothing follows it");
            assert!(all.iter().filter(|s| s.kind == Kind::Compare).count() > 1);
        }
    }

    #[test]
    fn the_local_suite_is_debian_only() {
        let has_local = |d| scenarios(d).iter().any(|s| s.suite == Suite::Local);
        assert!(has_local(Distro::Debian));
        assert!(!has_local(Distro::Alpine));
    }

    #[test]
    fn select_filters_by_exact_name() {
        let all = select(Distro::Alpine, &[]);
        assert_eq!(all.len(), scenarios(Distro::Alpine).len());
        let picked = select(
            Distro::Debian,
            &["swap-off".to_owned(), "local-converged".to_owned()],
        );
        let names: Vec<_> = picked.iter().map(|s| s.name).collect();
        assert_eq!(names, ["swap-off", "local-converged"]);
        assert!(select(Distro::Alpine, &["local-converged".to_owned()]).is_empty());
    }

    #[test]
    fn unknown_names_respects_the_selected_distros() {
        let filter = ["apt-repo-edited".to_owned(), "nope".to_owned()];
        assert_eq!(unknown_names(&Distro::ALL, &filter), ["nope"]);
        assert_eq!(
            unknown_names(&[Distro::Alpine], &filter),
            ["apt-repo-edited", "nope"]
        );
    }
}
