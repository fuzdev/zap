//! [`Detection`] — the result of detecting one resource (pure data).
//!
//! Detection's IO lives in `zap_core`; what it produces is this, which pure
//! plan-diff consumes. It is the evidence diffed *against* — deliberately kept
//! out of the plan fact, joined back only for the `--diff` view and the run
//! report.
//!
//! The outcome is a four-arm enum rather than a `{exists, desired_state_met}`
//! boolean pair, which can't tell *absent* from *detection-failed* or
//! *unsupported* — all are `{false, false}`, and a planner over it reads a failed
//! probe as "create". The enum names those outcomes: a
//! non-determinable probe is [`Detection::Undetermined`], which the planner holds
//! rather than silently creating. Drift carries a typed per-kind [`CurrentState`]
//! (the observed current state) exactly where the `--diff` before-state and the
//! service-stop warning need it.
//!
//! There is no wrapper struct pairing this with a `resource_id`: a detection is
//! always held against its id in a `BTreeMap<ResourceId, Detection>` (plan input)
//! or alongside its `Resource` (the `detect` render), so the id
//! is the map key / the resource's own field, never a duplicated struct field.

use serde::{Deserialize, Serialize};

/// The outcome of detecting one resource — the diff's decision input.
///
/// Maps directly onto the planner's decision: [`Absent`](Self::Absent) → create,
/// [`Drifted`](Self::Drifted) → update, [`Converged`](Self::Converged) → skip,
/// [`Undetermined`](Self::Undetermined) → hold (warn, change nothing). Serialized
/// internally-tagged on `outcome` (`{outcome, current?}`).
///
/// [`exists`](Self::exists) is **derived** (half of the boolean pair this replaced),
/// and a human render message is derived via [`describe`](Self::describe) — none are
/// stored. The only string carried is [`Undetermined`](Self::Undetermined)'s `reason`,
/// a runtime diagnostic. A detection is never persisted: the last-run report keeps
/// only its [`Verdict`](crate::last_run::Verdict), with no current state and no
/// reason.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum Detection {
    /// Exists and matches desired state — the only outcome `status` reports as
    /// converged.
    Converged,
    /// Exists but diverges from desired, carrying the typed observed current state
    /// (the `--diff` before-state, and the service-stop warning's `is_running`).
    Drifted {
        /// The observed current state, typed per kind.
        current: CurrentState,
    },
    /// Does not exist on the target — will be created.
    Absent,
    /// The probe couldn't determine the state: an IO failure (sudo prompt, blip,
    /// unreadable file), an unsupported/misconfigured target (no service manager,
    /// unknown backend/engine), or a path the engine can't resolve against the
    /// target (e.g. a remote path with no declared `target.home`). The
    /// planner **holds** — never silently creates — and surfaces the reason (a
    /// transient diagnostic, never persisted).
    Undetermined {
        /// Why the state couldn't be determined (render + planner warning only).
        reason: String,
    },
}

/// The observed current state of a *drifted* resource, typed per kind.
///
/// Carried only in [`Detection::Drifted`] — it exists exactly when there is drift
/// to describe. Holds observed *current* values (facts about the machine), never
/// resolved desired-config values, so rendering or serializing it (`detect`, `--diff`,
/// an apply report's residual) can't leak a reference's value. Kinds that can only be converged or
/// absent (`package` / `installer` / `script` / `verify` / `pipeline`) never
/// construct a `CurrentState`, so they have no variant here.
///
/// The `--diff` renderer ([`diff_view`](crate::diff_view)) joins this current state
/// with the desired config to show `current → desired`; [`describe`](Self::describe)
/// renders the current side only (the `detect` / `apply` summary, where there is no
/// desired side to join). This is the observed-state type, deliberately separate from
/// the desired-config
/// `ResourceKind` variants (it must serialize uniformly), so each
/// variant is hand-synced with its kind's interpreter in `zap_types::observe` — only
/// 10 of 15 kinds can drift, so a forced per-kind arm would be noise. A `file`'s
/// divergence is further typed by [`FileDrift`] (content / metadata / pin), a
/// `user`'s by [`UserDrift`], and a `database`'s by [`DatabaseDrift`].
///
/// These typed shapes follow the model's own rule: *struct for co-present facts*
/// (a `user` can drift on shell **and** sudo at once — like [`Directory`](Self::Directory)),
/// *enum for mutually-exclusive ones* (a `file` drifts in exactly one mode — [`FileDrift`]).
/// An *absent desired rule* carries its identity only — a firewall missing-rule needle is
/// the rule's whole-token identity (an opaque string, matched against the live ruleset),
/// `pg_hba` is the rule's two real fields ([`PgHbaMissing`]); both are inert config-derived
/// labels, never resolved values, so rendering them can't leak a reference's value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CurrentState {
    /// A directory's observed mode/owner/group (from `stat`).
    Directory {
        /// Observed octal mode.
        mode: String,
        /// Observed owner.
        owner: String,
        /// Observed group.
        group: String,
    },
    /// A file that diverges from desired, carrying *what* diverged as a typed
    /// [`FileDrift`] — content, managed metadata, or a `remote` content-addressed
    /// pin. The kind is the discriminator, so `describe` (and the [`diff_view`](crate::diff_view) `--diff` renderer)
    /// can state the divergence precisely instead of guessing from which fields are set.
    File {
        /// What diverged, with exactly the observed payload that kind needs.
        drift: FileDrift,
    },
    /// A `build` output whose provenance digest (recorded in the `.zap-build` sidecar,
    /// over the source pin and how it is built) differs from desired, carrying the recorded
    /// digest as the `--diff` before-state. A build only ever drifts on its provenance —
    /// output/sidecar absence reads `Absent` — so this is the lone build drift shape.
    Build {
        /// The provenance digest recorded in the output's sidecar.
        observed: String,
    },
    /// A symlink pointing somewhere other than desired.
    Link {
        /// Where the symlink currently points.
        points_to: String,
    },
    /// A service whose enabled/running state diverges. `is_running` drives the
    /// service-stop footgun warning in the planner.
    Service {
        /// Whether the service is currently active.
        is_running: bool,
        /// Whether the service is currently enabled at boot.
        is_enabled: bool,
    },
    /// A swap file that exists but isn't fully active/persisted.
    Swap {
        /// Whether the swap is currently active (`swapon`).
        is_active: bool,
        /// Whether the swap is persisted in `/etc/fstab`.
        in_fstab: bool,
    },
    /// An active firewall whose default policy and/or allow rules diverge, typed as a
    /// [`FirewallDrift`] — the observed default incoming/outgoing policy (when it differs)
    /// plus the desired allow rules found missing. Several can drift at once (co-present),
    /// so it is a struct of optionals, mirroring [`UserDrift`] / [`DatabaseDrift`]. The
    /// missing-rule needles *are* the rules' identities — opaque tokens, not lossy renders.
    Firewall {
        /// What diverged: default-policy and/or missing allow rules.
        drift: FirewallDrift,
    },
    /// A database whose role + database exist but some managed attribute diverges,
    /// typed as a [`DatabaseDrift`] — the observed owner and/or the desired `pg_hba`
    /// rules found missing.
    Database {
        /// What diverged across the managed attributes.
        drift: DatabaseDrift,
    },
    /// An apt repo whose key exists but the sources list diverges, typed as an
    /// [`AptRepoDrift`] — the key differs from its pin, or the `.list` is missing or
    /// present-but-different.
    AptRepo {
        /// How the sources list diverges.
        drift: AptRepoDrift,
    },
    /// A user that exists but some managed attribute diverges, typed as a
    /// [`UserDrift`] — observed shell / home mode, or an absent-state marker for SSH
    /// keys / sudoers. Several can drift at once (co-present), so it is a struct of
    /// optionals, mirroring [`Directory`](Self::Directory) rather than the
    /// mutually-exclusive [`FileDrift`].
    User {
        /// What diverged across the managed attributes.
        drift: UserDrift,
    },
}

/// What diverged on a drifted [`File`](CurrentState::File).
///
/// The discriminator that lets the render name the divergence precisely. Each variant
/// carries only the observed payload its kind has (content drift carries nothing — the
/// content side is the operator's config and the bytes are deliberately not carried;
/// metadata drift carries the observed triple; pin drift carries the observed blake3,
/// digest drift the observed SHA-512).
/// Holding the payload on the variant keeps the "no metadata on a pin drift" invariant
/// unrepresentable rather than enforced by convention.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum FileDrift {
    /// The file's content differs from desired (inline/template/source). The
    /// observed bytes are not carried — `describe` states the fact; `--diff`
    /// ([`diff_view`](crate::diff_view)) shows the desired content *source* descriptor
    /// (the content is detection's evidence, kept out of the reported state, and never
    /// re-hashed here — the bytes are never rendered).
    Content,
    /// Content matches but managed mode/owner/group drifted, carrying the observed
    /// triple (from `stat`) as the `--diff` before-state. Mirrors
    /// [`Directory`](CurrentState::Directory).
    Metadata {
        /// Observed octal mode.
        mode: String,
        /// Observed owner.
        owner: String,
        /// Observed group.
        group: String,
    },
    /// A `remote` file's bytes hash to another blake3 than the declared/locked pin,
    /// carrying the observed blake3 as the `--diff` before-state. A content hash is a
    /// machine fact, not a secret, so rendering it can't leak a reference's value.
    Pin {
        /// The observed blake3 of the target file.
        observed: String,
    },
    /// An extracted `remote` tree's sentinel records another provenance than desired
    /// (another tarball pin or extract strategy), carrying what it records as the
    /// `--diff` before-state. A digest, not a pin, so it is kept apart from
    /// [`Pin`](Self::Pin) and can't render as one.
    Provenance {
        /// What the sentinel records, surrounding whitespace trimmed.
        observed: String,
    },
    /// A `remote` file's bytes differ from its pin's, established by comparing the
    /// target's SHA-512 against that of the pinned bytes — so the observed side is a
    /// SHA-512, never a blake3, and is kept apart from [`Pin`](Self::Pin) so it can't
    /// render as one.
    Digest {
        /// The observed SHA-512 of the target file, lowercase hex.
        sha512: String,
    },
}

/// What diverged on a drifted [`User`](CurrentState::User).
///
/// A struct of optionals, not an enum: a user's managed attributes drift
/// *independently and co-presently* (shell and sudo can both be wrong in one run),
/// so each field is `Some` exactly when that attribute drifted. Observed machine
/// values where one exists (`shell` / `home_mode`); an absent-state marker
/// otherwise (`ssh_keys` / `sudo`), since there is no observed value for a missing
/// thing — only *which* state it is in. The desired side (the configured shell,
/// mode, sudoers content) joins from config at `--diff` render time.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct UserDrift {
    /// The observed login shell, when it differs from desired.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shell: Option<String>,
    /// The observed home-directory octal mode, when it differs from desired.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub home_mode: Option<String>,
    /// The SSH-keys drift state, when managed `ssh_keys` aren't satisfied.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ssh_keys: Option<SshKeysDrift>,
    /// The sudoers drift state, when a managed `sudo` policy isn't satisfied.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sudo: Option<SudoDrift>,
    /// The shadow-password drift state, when an `ssh_keys` user's `/etc/shadow`
    /// password field isn't the disabled sentinel `*` (re-converged to `*` so sshd
    /// accepts pubkey login).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shadow_password: Option<ShadowPasswordDrift>,
    /// Desired supplementary groups the user is **not** yet a member of (additive — a
    /// group the config omits is never stripped). Config-derived group names only, never
    /// a resolved value, so rendering it can't leak a reference's value.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub groups: Vec<String>,
}

/// How a managed user's `ssh_keys` diverge — the three mutually-exclusive outcomes
/// the content comparison distinguishes.
///
/// The detector renders the desired `authorized_keys` (the explicit keys, or the
/// `copy_from` source's file) and compares it against the target's, so a
/// rotated/added/removed key — or a changed `copy_from` source — drifts as
/// [`ContentDiffers`](Self::ContentDiffers) instead of reading converged forever once
/// the file is merely non-empty.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SshKeysDrift {
    /// `authorized_keys` is missing or empty.
    MissingOrEmpty,
    /// `authorized_keys` exists but its content differs from desired.
    ContentDiffers,
    /// `authorized_keys` (or, for `copy_from`, the source's) couldn't be read to compare.
    Unreadable,
}

/// How a managed user's `sudo` policy diverges — the four mutually-exclusive
/// outcomes the detector distinguishes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SudoDrift {
    /// `sudo` is disabled but a sudoers file exists and should be removed.
    ShouldBeAbsent,
    /// A sudoers file is required but missing.
    Missing,
    /// The sudoers file exists but its content differs from desired.
    ContentDiffers,
    /// The sudoers file exists but couldn't be read to compare.
    Unreadable,
}

/// How an `ssh_keys` user's shadow password field diverges from the disabled `*`.
///
/// A single-variant **state marker** — the make-impossible-states idiom (it rejects
/// typos and forces the `match` when a second variant is added). zap manages the
/// field authoritatively: it must be the disabled sentinel `*` (no password, *not*
/// locked), and ANY other value is drift — a `!`-lock (`useradd` leaves a passwordless
/// account locked, which Alpine's sshd refuses pubkey login to), an empty field
/// (passwordless login — a security hole), or a real password hash. The planner
/// re-converges all of them to `*`.
///
/// It carries **no observed value** on purpose: that value could be a password hash (a
/// secret), which must never enter the drift/diff — the same leak vector the typed
/// drifts close everywhere else.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ShadowPasswordDrift {
    /// The shadow password field isn't the disabled `*` (it's `!`-locked, empty, or
    /// carries a hash); re-converge it to `*`.
    NotDisabled,
}

/// What diverged on a drifted [`Database`](CurrentState::Database).
///
/// A struct of independent drifts: the observed owner role (when it differs) and
/// the desired `pg_hba` rules found missing. Both can be present in one run, so —
/// like [`UserDrift`] — this is a struct, not an enum.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct DatabaseDrift {
    /// The observed owning role, when it differs from desired.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner: Option<String>,
    /// The desired `pg_hba` rules not found on the target.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub pg_hba_missing: Vec<PgHbaMissing>,
}

/// A desired `pg_hba` rule the detector didn't find on the target.
///
/// Carried by its two real fields rather than a synthesized label — identifies
/// *which* desired rule is absent for the database's fixed `(db, user)`. The fields
/// are inert config-derived values (a CIDR host and an auth method), never resolved
/// secrets.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PgHbaMissing {
    /// The rule's host (a CIDR or hostname), e.g. `127.0.0.1/32`.
    pub host: String,
    /// The rule's auth method, e.g. `scram-sha-256`.
    pub method: String,
}

/// How a drifted [`AptRepo`](CurrentState::AptRepo) diverges: its signing key, or its
/// sources list.
///
/// The mutually-exclusive states the detector distinguishes once the GPG key is present
/// (a missing key reads [`Absent`](Detection::Absent), not drift), read in order: a key
/// whose bytes aren't its pin's is that, whatever the list holds — the apply installs
/// both whole either way. An enum, so the states name themselves — the same move as
/// [`FileDrift`] / [`SudoDrift`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AptRepoDrift {
    /// The key file's bytes don't hash to its pin (another key, or a rotated one).
    KeyDiffers,
    /// The `.list` file is absent (the desired source line must be written).
    ListMissing,
    /// The `.list` exists but its content differs from the desired source line.
    ListContentDiffers,
}

/// What diverged on a drifted [`Firewall`](CurrentState::Firewall).
///
/// A struct of independent drifts — the default incoming/outgoing policy and the set of
/// missing allow rules can each diverge in one run — so, like [`UserDrift`] and
/// [`DatabaseDrift`], it is a struct of optionals, not an enum. Each policy field holds
/// the **observed** policy verb when it differs from desired (`deny`/`allow`/`reject` for
/// ufw, `accept`/`drop`/`reject` for nftables — the *effective* policy the backend's
/// probe reports, or `missing` for an nftables base chain absent from the listing);
/// `missing_rules` are the desired allow rules not found in the live ruleset (for ufw, as
/// an inbound `ALLOW` from anywhere; for nftables, in the `input` chain). Every value is an inert machine fact or config-derived rule identity, never a
/// reference's resolved value, so rendering it can't leak a secret.
///
/// The nftables policy is read in a three-valued space, not the binary base-chain verb:
/// `reject` is `policy drop` plus a trailing bare `reject` rule, so comparing the policy
/// line alone made `reject` and `deny` indistinguishable and reported a firewall whose
/// active ICMP rejection had been removed as converged. See
/// [`FirewallPolicy::nft_effective_policy`](crate::schema::FirewallPolicy::nft_effective_policy).
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct FirewallDrift {
    /// The observed default-incoming policy verb, when it differs from desired.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_incoming: Option<String>,
    /// The observed default-outgoing policy verb, when it differs from desired.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_outgoing: Option<String>,
    /// The desired allow rules not found in the live ruleset, each as the rule-identity
    /// needle the detector matched whole-token (`"OpenSSH"`, `"443/tcp"`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub missing_rules: Vec<String>,
}

impl Detection {
    /// This detection with every free-text field passed through `f`: an undetermined
    /// reason, and each value a drift observed on the target — a mode, an owner, a
    /// link's target, a recorded pin, a policy verb, a missing rule. The outcome and
    /// drift tags, the state markers, and the flags are kept as they are.
    ///
    /// How a detection is masked for display: a typed map with no serialized form in
    /// between, so there is nothing that can fail and hand back the detection unmapped,
    /// and a field added to an observed state doesn't compile until it is placed here.
    #[must_use]
    pub fn map_text(&self, f: impl Fn(&str) -> String) -> Self {
        match self {
            Self::Converged => Self::Converged,
            Self::Drifted { current } => Self::Drifted {
                current: current.map_text(f),
            },
            Self::Absent => Self::Absent,
            Self::Undetermined { reason } => Self::Undetermined { reason: f(reason) },
        }
    }
}

impl CurrentState {
    /// This observed state with every free-text field passed through `f`
    /// ([`Detection::map_text`] states the rule).
    #[must_use]
    pub fn map_text(&self, f: impl Fn(&str) -> String) -> Self {
        let option = |field: &Option<String>| field.as_deref().map(&f);
        let list = |field: &[String]| field.iter().map(|item| f(item)).collect::<Vec<_>>();
        match self {
            Self::Directory { mode, owner, group } => Self::Directory {
                mode: f(mode),
                owner: f(owner),
                group: f(group),
            },
            Self::File { drift } => Self::File {
                drift: match drift {
                    FileDrift::Content => FileDrift::Content,
                    FileDrift::Metadata { mode, owner, group } => FileDrift::Metadata {
                        mode: f(mode),
                        owner: f(owner),
                        group: f(group),
                    },
                    FileDrift::Pin { observed } => FileDrift::Pin {
                        observed: f(observed),
                    },
                    FileDrift::Provenance { observed } => FileDrift::Provenance {
                        observed: f(observed),
                    },
                    FileDrift::Digest { sha512 } => FileDrift::Digest { sha512: f(sha512) },
                },
            },
            Self::Build { observed } => Self::Build {
                observed: f(observed),
            },
            Self::Link { points_to } => Self::Link {
                points_to: f(points_to),
            },
            Self::Service {
                is_running,
                is_enabled,
            } => Self::Service {
                is_running: *is_running,
                is_enabled: *is_enabled,
            },
            Self::Swap {
                is_active,
                in_fstab,
            } => Self::Swap {
                is_active: *is_active,
                in_fstab: *in_fstab,
            },
            Self::Firewall {
                drift:
                    FirewallDrift {
                        default_incoming,
                        default_outgoing,
                        missing_rules,
                    },
            } => Self::Firewall {
                drift: FirewallDrift {
                    default_incoming: option(default_incoming),
                    default_outgoing: option(default_outgoing),
                    missing_rules: list(missing_rules),
                },
            },
            Self::Database {
                drift:
                    DatabaseDrift {
                        owner,
                        pg_hba_missing,
                    },
            } => Self::Database {
                drift: DatabaseDrift {
                    owner: option(owner),
                    pg_hba_missing: pg_hba_missing
                        .iter()
                        .map(|PgHbaMissing { host, method }| PgHbaMissing {
                            host: f(host),
                            method: f(method),
                        })
                        .collect(),
                },
            },
            Self::AptRepo { drift } => Self::AptRepo {
                drift: match drift {
                    AptRepoDrift::KeyDiffers => AptRepoDrift::KeyDiffers,
                    AptRepoDrift::ListMissing => AptRepoDrift::ListMissing,
                    AptRepoDrift::ListContentDiffers => AptRepoDrift::ListContentDiffers,
                },
            },
            Self::User {
                drift:
                    UserDrift {
                        shell,
                        home_mode,
                        ssh_keys,
                        sudo,
                        shadow_password,
                        groups,
                    },
            } => Self::User {
                drift: UserDrift {
                    shell: option(shell),
                    home_mode: option(home_mode),
                    // The state markers hold no text; each is matched in full, so a
                    // variant that came to hold some would not compile until placed.
                    ssh_keys: ssh_keys.as_ref().map(|drift| match drift {
                        SshKeysDrift::MissingOrEmpty => SshKeysDrift::MissingOrEmpty,
                        SshKeysDrift::ContentDiffers => SshKeysDrift::ContentDiffers,
                        SshKeysDrift::Unreadable => SshKeysDrift::Unreadable,
                    }),
                    sudo: sudo.as_ref().map(|drift| match drift {
                        SudoDrift::ShouldBeAbsent => SudoDrift::ShouldBeAbsent,
                        SudoDrift::Missing => SudoDrift::Missing,
                        SudoDrift::ContentDiffers => SudoDrift::ContentDiffers,
                        SudoDrift::Unreadable => SudoDrift::Unreadable,
                    }),
                    shadow_password: shadow_password.as_ref().map(|drift| match drift {
                        ShadowPasswordDrift::NotDisabled => ShadowPasswordDrift::NotDisabled,
                    }),
                    groups: list(groups),
                },
            },
        }
    }
}

impl FirewallDrift {
    /// Whether any managed aspect drifted — the detector's converged-vs-drifted gate
    /// (a [`Firewall`](CurrentState::Firewall) is only constructed when this is true).
    #[must_use]
    pub const fn has_drift(&self) -> bool {
        self.default_incoming.is_some()
            || self.default_outgoing.is_some()
            || !self.missing_rules.is_empty()
    }

    /// A terse description of the firewall drift, for the drift render. Observed current
    /// side only; the desired side joins in at `--diff` render time.
    #[must_use]
    pub fn describe(&self) -> String {
        let mut parts = Vec::new();
        if let Some(incoming) = &self.default_incoming {
            parts.push(format!("default incoming {incoming}"));
        }
        if let Some(outgoing) = &self.default_outgoing {
            parts.push(format!("default outgoing {outgoing}"));
        }
        if !self.missing_rules.is_empty() {
            parts.push(format!("missing rules: {}", self.missing_rules.join(", ")));
        }
        parts.join(", ")
    }
}

impl UserDrift {
    /// Whether any managed attribute drifted — the detector's converged-vs-drifted
    /// gate (a [`User`](CurrentState::User) is only constructed when this is true).
    #[must_use]
    pub const fn has_drift(&self) -> bool {
        self.shell.is_some()
            || self.home_mode.is_some()
            || self.ssh_keys.is_some()
            || self.sudo.is_some()
            || self.shadow_password.is_some()
            || !self.groups.is_empty()
    }

    /// A terse description of the user drift, for the drift render. Observed current
    /// side only; the desired side joins in at `--diff` render time.
    #[must_use]
    pub fn describe(&self) -> String {
        let mut parts = Vec::new();
        if let Some(shell) = &self.shell {
            parts.push(format!("shell {shell}"));
        }
        if let Some(mode) = &self.home_mode {
            parts.push(format!("home mode {mode}"));
        }
        if let Some(ssh_keys) = &self.ssh_keys {
            parts.push(ssh_keys.describe().to_owned());
        }
        if let Some(sudo) = &self.sudo {
            parts.push(sudo.describe().to_owned());
        }
        if let Some(shadow_password) = &self.shadow_password {
            parts.push(shadow_password.describe().to_owned());
        }
        if !self.groups.is_empty() {
            parts.push(format!("not in groups {}", self.groups.join(", ")));
        }
        parts.join(", ")
    }
}

impl SshKeysDrift {
    /// A terse description of the SSH-keys drift.
    #[must_use]
    pub const fn describe(&self) -> &'static str {
        match self {
            Self::MissingOrEmpty => "ssh keys missing or empty",
            Self::ContentDiffers => "ssh keys content differs",
            Self::Unreadable => "ssh keys unreadable",
        }
    }
}

impl SudoDrift {
    /// A terse description of the sudoers drift.
    #[must_use]
    pub const fn describe(&self) -> &'static str {
        match self {
            Self::ShouldBeAbsent => "sudoers present but should be removed",
            Self::Missing => "sudoers missing",
            Self::ContentDiffers => "sudoers content differs",
            Self::Unreadable => "sudoers unreadable",
        }
    }
}

impl ShadowPasswordDrift {
    /// A terse description of the shadow-password drift.
    #[must_use]
    pub const fn describe(&self) -> &'static str {
        match self {
            Self::NotDisabled => "shadow password not disabled (expected `*`)",
        }
    }
}

impl DatabaseDrift {
    /// Whether any managed attribute drifted — the detector's converged-vs-drifted
    /// gate (a [`Database`](CurrentState::Database) is only constructed when this is
    /// true).
    #[must_use]
    pub const fn has_drift(&self) -> bool {
        self.owner.is_some() || !self.pg_hba_missing.is_empty()
    }

    /// A terse description of the database drift, for the drift render. Observed
    /// owner plus the absent `pg_hba` rules; the desired side joins in at `--diff`
    /// render time.
    #[must_use]
    pub fn describe(&self) -> String {
        let mut parts = Vec::new();
        if let Some(owner) = &self.owner {
            parts.push(format!("owner {owner}"));
        }
        for rule in &self.pg_hba_missing {
            parts.push(format!("pg_hba missing {} for {}", rule.method, rule.host));
        }
        parts.join(", ")
    }
}

impl Detection {
    /// Whether the resource exists on the target (converged or drifted). Derived —
    /// absent and undetermined are both "not known to exist."
    #[must_use]
    pub const fn exists(&self) -> bool {
        matches!(self, Self::Converged | Self::Drifted { .. })
    }

    /// A human-readable summary for the `detect` / `apply` renders. Derived from
    /// the typed outcome (and current state for drift). Shows the observed *current* side; the desired side is
    /// in the operator's config and joins in at `--diff` render time via
    /// [`diff_view`](crate::diff_view).
    #[must_use]
    pub fn describe(&self) -> String {
        match self {
            Self::Converged => "converged".to_owned(),
            Self::Absent => "absent".to_owned(),
            Self::Undetermined { reason } => format!("undetermined: {reason}"),
            Self::Drifted { current } => format!("drifted ({})", current.describe()),
        }
    }
}

impl CurrentState {
    /// Whether this current state actually represents divergence — the single
    /// source of truth for the *drifted ⟹ real detail* invariant.
    ///
    /// Most kinds are only ever constructed on real drift, so they are unconditionally
    /// `true`; the open-ended attribute kinds delegate to their inner drift
    /// ([`UserDrift`] / [`DatabaseDrift`]), and [`Firewall`](Self::Firewall) is `true`
    /// when a default policy drifted or some rule is missing. The match is exhaustive on
    /// purpose: a new variant is a compile error here until its author declares whether
    /// it can be empty. The open-ended kinds' verdicts go through
    /// [`drifted_or_converged`](crate::observe::drifted_or_converged), so a detector
    /// physically can't emit a [`Drifted`](Detection::Drifted) carrying no divergence.
    #[must_use]
    pub const fn has_drift(&self) -> bool {
        match self {
            Self::User { drift } => drift.has_drift(),
            Self::Database { drift } => drift.has_drift(),
            Self::Firewall { drift } => drift.has_drift(),
            Self::Directory { .. }
            | Self::File { .. }
            | Self::Build { .. }
            | Self::Link { .. }
            | Self::Service { .. }
            | Self::Swap { .. }
            | Self::AptRepo { .. } => true,
        }
    }

    /// A terse description of the observed current state, for the drift render.
    #[must_use]
    pub fn describe(&self) -> String {
        match self {
            Self::Directory { mode, owner, group } => {
                format!("mode {mode}, owner {owner}, group {group}")
            }
            // The drift kind names the divergence; the desired side joins in at
            // `--diff` render time.
            Self::File { drift } => drift.describe(),
            Self::Build { observed } => {
                format!(
                    "build provenance differs (observed {})",
                    short_pin(observed)
                )
            }
            Self::Link { points_to } => format!("points to {points_to}"),
            Self::Service {
                is_running,
                is_enabled,
            } => format!("running={is_running}, enabled={is_enabled}"),
            Self::Swap {
                is_active,
                in_fstab,
            } => format!("active={is_active}, in_fstab={in_fstab}"),
            Self::Firewall { drift } => drift.describe(),
            Self::Database { drift } => drift.describe(),
            Self::User { drift } => drift.describe(),
            Self::AptRepo { drift } => match drift {
                AptRepoDrift::KeyDiffers => "signing key differs from its pin".to_owned(),
                AptRepoDrift::ListContentDiffers => "sources list content differs".to_owned(),
                AptRepoDrift::ListMissing => "sources list file missing".to_owned(),
            },
        }
    }
}

impl FileDrift {
    /// A terse description of the file drift, for the drift render. Shows the
    /// observed current side; the desired side joins in at `--diff` render time.
    #[must_use]
    pub fn describe(&self) -> String {
        match self {
            Self::Content => "content differs".to_owned(),
            Self::Metadata { mode, owner, group } => {
                format!("metadata differs (observed mode {mode}, owner {owner}, group {group})")
            }
            Self::Pin { observed } => {
                format!(
                    "remote content pin differs (observed {})",
                    short_pin(observed)
                )
            }
            Self::Provenance { observed } => {
                format!(
                    "extracted tree's provenance differs (observed {})",
                    short_pin(observed)
                )
            }
            Self::Digest { sha512 } => {
                format!(
                    "remote content differs from its pin (observed sha512 {})",
                    short_pin(sha512)
                )
            }
        }
    }
}

/// Abbreviate a blake3 pin for a terse render — the first 12 hex chars plus an
/// ellipsis, or the whole string when it's already short. Shared with
/// [`diff_view`](crate::diff_view) for the desired-pin side of a `--diff`.
pub(crate) fn short_pin(pin: &str) -> String {
    match pin.get(..12) {
        Some(prefix) if prefix.len() < pin.len() => format!("{prefix}…"),
        _ => pin.to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        AptRepoDrift, CurrentState, DatabaseDrift, Detection, FileDrift, FirewallDrift,
        PgHbaMissing, ShadowPasswordDrift, SshKeysDrift, SudoDrift, UserDrift,
    };
    use crate::plan::{ResidualResource, ResidualState};
    use crate::schema::ResourceId;

    fn strings(value: &serde_json::Value, out: &mut Vec<String>) {
        match value {
            serde_json::Value::String(text) => out.push(text.clone()),
            serde_json::Value::Array(items) => items.iter().for_each(|v| strings(v, out)),
            serde_json::Value::Object(map) => map.values().for_each(|v| strings(v, out)),
            _ => {}
        }
    }

    /// Every observed state, each field holding text.
    fn states() -> Vec<CurrentState> {
        let text = || "observed".to_owned();
        vec![
            CurrentState::Directory {
                mode: text(),
                owner: text(),
                group: text(),
            },
            CurrentState::File {
                drift: FileDrift::Content,
            },
            CurrentState::File {
                drift: FileDrift::Metadata {
                    mode: text(),
                    owner: text(),
                    group: text(),
                },
            },
            CurrentState::File {
                drift: FileDrift::Pin { observed: text() },
            },
            CurrentState::File {
                drift: FileDrift::Provenance { observed: text() },
            },
            CurrentState::File {
                drift: FileDrift::Digest { sha512: text() },
            },
            CurrentState::Build { observed: text() },
            CurrentState::Link { points_to: text() },
            CurrentState::Service {
                is_running: true,
                is_enabled: false,
            },
            CurrentState::Swap {
                is_active: true,
                in_fstab: false,
            },
            CurrentState::Firewall {
                drift: FirewallDrift {
                    default_incoming: Some(text()),
                    default_outgoing: Some(text()),
                    missing_rules: vec![text(), text()],
                },
            },
            CurrentState::Database {
                drift: DatabaseDrift {
                    owner: Some(text()),
                    pg_hba_missing: vec![PgHbaMissing {
                        host: text(),
                        method: text(),
                    }],
                },
            },
            CurrentState::AptRepo {
                drift: AptRepoDrift::ListContentDiffers,
            },
            CurrentState::User {
                drift: UserDrift {
                    shell: Some(text()),
                    home_mode: Some(text()),
                    ssh_keys: Some(SshKeysDrift::ContentDiffers),
                    sudo: Some(SudoDrift::Missing),
                    shadow_password: Some(ShadowPasswordDrift::NotDisabled),
                    groups: vec![text()],
                },
            },
        ]
    }

    /// `map_text` reaches every observed value and every reason, and nothing else:
    /// mapped to a marker, no observed text is left in a detection's serialized form,
    /// and what is left besides the marker is the tags and state markers.
    #[test]
    fn map_text_reaches_every_observed_text_and_only_it() {
        let detections: Vec<Detection> = states()
            .into_iter()
            .map(|current| Detection::Drifted { current })
            .chain([
                Detection::Converged,
                Detection::Absent,
                Detection::Undetermined {
                    reason: "observed".to_owned(),
                },
            ])
            .collect();
        let mut left = Vec::new();
        for detection in &detections {
            let mapped = detection.map_text(|_| "X".to_owned());
            strings(&serde_json::to_value(&mapped).unwrap(), &mut left);
            assert_eq!(&detection.map_text(str::to_owned), detection);

            // A residual maps as the detection it is read from.
            let residual = |detection: &Detection| {
                ResidualState::from_detection(detection).map(|state| ResidualResource {
                    resource_id: ResourceId("observed".to_owned()),
                    state,
                })
            };
            assert_eq!(
                residual(detection).map(|residual| residual.map_text(|_| "X".to_owned())),
                residual(&mapped)
            );
        }
        left.sort();
        left.dedup();
        assert_eq!(
            left,
            [
                "X",
                "absent",
                "apt_repo",
                "build",
                "content",
                "content_differs",
                "converged",
                "database",
                "digest",
                "directory",
                "drifted",
                "file",
                "firewall",
                "link",
                "list_content_differs",
                "metadata",
                "missing",
                "not_disabled",
                "pin",
                "provenance",
                "service",
                "swap",
                "undetermined",
                "user",
            ]
        );
    }
}
