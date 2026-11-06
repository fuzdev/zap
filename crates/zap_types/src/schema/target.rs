//! The Target wire-bridge — the connection descriptor + the local/remote location enum.

use std::num::NonZeroU16;

use serde::{Deserialize, Serialize};

use super::{PackageManager, ServiceManager};
use crate::text::Text;

/// Where a [`Target`] executes — the local machine or a remote SSH host.
///
/// An enum, not a `local: bool` + sibling `host`/`user`/… bag, so the contradictory
/// `local: true` *with* remote connection fields is **unrepresentable** rather than
/// merely rejected by a runtime check: the connection fields live only on
/// [`Remote`](Self::Remote), and `home` with them (it's a remote-only value — a local
/// target reads the operator's `$HOME`). The flat `zap.target({...})` wire shape is
/// preserved by [`Target`]'s `try_from`/`into` against [`TargetWire`], so configs and
/// the builder API are unchanged. `host`/`user` stay `Option`: a remote target that
/// declares no `host` is the structural gate's finding
/// ([`crate::validate::missing_target_host`]), and one whose `host` resolves to nothing
/// errors at connection bind.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TargetLocation {
    /// The operator's local machine — no SSH connection fields.
    Local,
    /// A remote SSH host.
    Remote {
        /// Remote host (SSH). May be a reference, resolved at apply time.
        host: Option<Text>,
        /// Remote user (SSH). May be a reference.
        user: Option<Text>,
        /// An alternate connecting user for the initial provisioning run, selected by
        /// the `--bootstrap` CLI switch instead of [`user`](Self::Remote::user).
        ///
        /// The motivating case is the SSH-hardening transition: a stock bootstrap
        /// account provisions a dedicated service user, then SSH hardening locks the
        /// bootstrap account out. One config + one env file expresses both phases —
        /// `DEPLOY_USER` and `BOOTSTRAP_USER` are both set from the start, and
        /// `--bootstrap` (on the first provisioning run only) connects as this user
        /// instead of the primary one. May be a reference, resolved at apply
        /// time. Remote-only — a local target has no connecting user. Selection is
        /// **explicit** (the flag), never an automatic fallback on a connectivity blip.
        bootstrap_user: Option<Text>,
        /// Remote SSH port (`ssh`'s own default when unset): 1–65535.
        port: Option<NonZeroU16>,
        /// Path to the SSH private key, if not using default key resolution.
        key_path: Option<String>,
        /// The target's home directory — the declared source of truth for `~` /
        /// `$HOME` in a remote target's path fields. Optional: absolute-path configs
        /// need it not at all; when a remote path references the home and this is
        /// unset, resolution fails with a clear error rather than guessing. Left out
        /// of the content hash (the home is target environment, not desired state).
        home: Option<String>,
    },
}

impl Default for TargetLocation {
    /// An empty target is remote with no host, which the structural gate refuses.
    fn default() -> Self {
        Self::Remote {
            host: None,
            user: None,
            bootstrap_user: None,
            port: None,
            key_path: None,
            home: None,
        }
    }
}

/// The target machine descriptor — the `zap.target({...})` config block.
///
/// Config-level, not a `Resource`. The execution side that runs commands against it
/// is `zap_core`'s `Connection`. The location is a [`TargetLocation`] enum (local vs
/// remote-with-connection-fields), so an impossible `local + host` combination can't
/// be written. Managers are typed (`PackageManager` / `ServiceManager`) but kept
/// `Option`: a config
/// omitting one surfaces as an `Undetermined` detection rather than a parse failure.
///
/// (De)serialization goes through [`TargetWire`] (the flat wire shape the config-eval
/// sidecar emits) via `try_from`/`into`, so the authoring API is unchanged while the
/// in-memory model is the safe enum.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "TargetWire", into = "TargetWire")]
pub struct Target {
    /// Where the target executes (local or a remote SSH host).
    pub location: TargetLocation,
    /// Package manager (e.g. `apt`).
    pub package_manager: Option<PackageManager>,
    /// Service manager (e.g. `systemd`), when service/database resources exist.
    pub service_manager: Option<ServiceManager>,
}

impl Target {
    /// This target with every free-text field passed through `f` — the connection
    /// fields a config writes. A field that takes a reference has the text around its
    /// references mapped and each reference kept ([`Text::map_literals`]), so `f` never
    /// reaches a reference's name. The closed-set fields (the managers, the port) hold
    /// no text and are kept as they are.
    #[must_use]
    pub fn map_text(&self, f: impl Fn(&str) -> String) -> Self {
        let Self {
            location,
            package_manager,
            service_manager,
        } = self;
        let string = |field: &Option<String>| field.as_deref().map(&f);
        let text = |field: &Option<Text>| field.as_ref().map(|text| text.map_literals(&f));
        Self {
            location: match location {
                TargetLocation::Local => TargetLocation::Local,
                TargetLocation::Remote {
                    host,
                    user,
                    bootstrap_user,
                    port,
                    key_path,
                    home,
                } => TargetLocation::Remote {
                    host: text(host),
                    user: text(user),
                    bootstrap_user: text(bootstrap_user),
                    port: *port,
                    key_path: string(key_path),
                    home: string(home),
                },
            },
            package_manager: *package_manager,
            service_manager: *service_manager,
        }
    }
}

/// The flat wire shape of [`Target`] — the raw `zap.target({...})` object the
/// config-eval sidecar emits.
///
/// [`Target`] (de)serializes through this via `try_from`/`into`; the conversion
/// routes the connection fields into [`TargetLocation`] and rejects the contradictory
/// `local: true` + remote-field combination. `deny_unknown_fields` rejects a
/// misspelled target field at parse.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TargetWire {
    /// `true` for a local target; absent or `false` means remote (SSH).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub local: Option<bool>,
    /// Remote host (SSH). May be a reference, resolved at apply time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<Text>,
    /// Remote user (SSH). May be a reference.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user: Option<Text>,
    /// Alternate connecting user for the initial provisioning run (`--bootstrap`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bootstrap_user: Option<Text>,
    /// Remote SSH port (`ssh`'s own default when unset): 1–65535.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<NonZeroU16>,
    /// Path to the SSH private key, if not using default key resolution.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_path: Option<String>,
    /// The target's declared remote home (resolves `~` / `$HOME` in remote paths).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub home: Option<String>,
    /// Package manager (e.g. `apt`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub package_manager: Option<PackageManager>,
    /// Service manager (e.g. `systemd`), when service/database resources exist.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service_manager: Option<ServiceManager>,
}

impl TryFrom<TargetWire> for Target {
    type Error = String;

    fn try_from(wire: TargetWire) -> Result<Self, Self::Error> {
        let location = if wire.local == Some(true) {
            // A local target carries no remote connection fields — reject the
            // contradiction at the boundary (it was silently ignored before).
            if wire.host.is_some()
                || wire.user.is_some()
                || wire.bootstrap_user.is_some()
                || wire.port.is_some()
                || wire.key_path.is_some()
                || wire.home.is_some()
            {
                return Err(
                    "a local target (`local: true`) cannot also set `host` / `user` / \
                     `bootstrap_user` / `port` / `key_path` / `home` — those are \
                     remote-only fields"
                        .to_owned(),
                );
            }
            TargetLocation::Local
        } else {
            TargetLocation::Remote {
                host: wire.host,
                user: wire.user,
                bootstrap_user: wire.bootstrap_user,
                port: wire.port,
                key_path: wire.key_path,
                home: wire.home,
            }
        };
        Ok(Self {
            location,
            package_manager: wire.package_manager,
            service_manager: wire.service_manager,
        })
    }
}

impl From<Target> for TargetWire {
    fn from(target: Target) -> Self {
        // Emit `local` explicitly (`true` local / `false` remote) so an input
        // `local: false` round-trips; remote connection fields ride the variant.
        let (local, host, user, bootstrap_user, port, key_path, home) = match target.location {
            TargetLocation::Local => (Some(true), None, None, None, None, None, None),
            TargetLocation::Remote {
                host,
                user,
                bootstrap_user,
                port,
                key_path,
                home,
            } => (
                Some(false),
                host,
                user,
                bootstrap_user,
                port,
                key_path,
                home,
            ),
        };
        Self {
            local,
            host,
            user,
            bootstrap_user,
            port,
            key_path,
            home,
            package_manager: target.package_manager,
            service_manager: target.service_manager,
        }
    }
}

impl Target {
    /// A local target with no managers set — the ergonomic constructor for the common
    /// `{local: true, …}` case (override `package_manager` / `service_manager` with
    /// struct-update syntax: `Target { package_manager: …, ..Target::local() }`).
    #[must_use]
    pub const fn local() -> Self {
        Self {
            location: TargetLocation::Local,
            package_manager: None,
            service_manager: None,
        }
    }

    /// Whether this target executes on the local machine.
    #[must_use]
    pub const fn is_local(&self) -> bool {
        matches!(self.location, TargetLocation::Local)
    }

    /// The remote host, if a remote target declares one (`None` for local).
    #[must_use]
    pub const fn host(&self) -> Option<&Text> {
        match &self.location {
            TargetLocation::Remote { host, .. } => host.as_ref(),
            TargetLocation::Local => None,
        }
    }

    /// The remote user, if declared (`None` for local).
    #[must_use]
    pub const fn user(&self) -> Option<&Text> {
        match &self.location {
            TargetLocation::Remote { user, .. } => user.as_ref(),
            TargetLocation::Local => None,
        }
    }

    /// The alternate bootstrap connecting user, if declared (`None` for local).
    ///
    /// The `--bootstrap` switch connects as this user instead of [`user`](Self::user) —
    /// see [`TargetLocation::Remote::bootstrap_user`] for the SSH-hardening transition
    /// it serves.
    #[must_use]
    pub const fn bootstrap_user(&self) -> Option<&Text> {
        match &self.location {
            TargetLocation::Remote { bootstrap_user, .. } => bootstrap_user.as_ref(),
            TargetLocation::Local => None,
        }
    }

    /// The remote SSH port, if declared (`None` for local).
    #[must_use]
    pub const fn port(&self) -> Option<u16> {
        match &self.location {
            TargetLocation::Remote {
                port: Some(port), ..
            } => Some(port.get()),
            TargetLocation::Remote { port: None, .. } | TargetLocation::Local => None,
        }
    }

    /// The remote SSH key path, if declared (`None` for local).
    #[must_use]
    pub fn key_path(&self) -> Option<&str> {
        match &self.location {
            TargetLocation::Remote { key_path, .. } => key_path.as_deref(),
            TargetLocation::Local => None,
        }
    }

    /// The declared remote home, if any (`None` for local — it reads the operator's).
    #[must_use]
    pub fn home(&self) -> Option<&str> {
        match &self.location {
            TargetLocation::Remote { home, .. } => home.as_deref(),
            TargetLocation::Local => None,
        }
    }
}
