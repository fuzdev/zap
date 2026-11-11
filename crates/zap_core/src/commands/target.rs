//! The eval seams every core reads its config through (`eval_target`, `eval_untargeted`),
//! the config gates they both run, and binding the target: its connection, its
//! connecting user, and the machine a plan is for.

use std::path::Path;

use zap_types::last_run::{MaskedRef, ReportVar, masked_refs};
use zap_types::plan::{LocalAccount, Machine};
use zap_types::scalar::ContentHash;
use zap_types::schema::{Target, ZapConfig};
use zap_types::secrecy::{SecretReason, is_secret_var_name};
use zap_types::text::Text;
use zap_types::var_ref::{self};

use crate::config::eval::PinnedFgro;
use crate::config::fgro::{locked_pin, pin_cache_dir, require_fgro};
use crate::config::{eval_cached, mode_from_env};
use crate::connection::{Connection, SshConnection};
use crate::error::{Error, Result};
use crate::escape::escape_line;
use crate::last_run::report_var;
use crate::resolve::{env_var, resolve_env_vars};
use crate::secret::SecretMasker;

use super::validate_config_structure;

/// Eval a config and bind a connection — `Local` for a local target, `Ssh` (over the
/// `ssh` subprocess) for a remote one. The shared front half of `plan` / `detect` /
/// `apply`. Connectivity is verified later, by `detect_all`, before any probing.
///
/// `fgro` is the operator's `fgro` binary (`--fgro`, else `ZAP_FGRO`), and the config's
/// `zap.lock` holds the toolchain pin it must hash to; the lock is read before the eval
/// ([`eval_pinned`]).
///
/// `zap_home` (the `~/.zap` root) feeds the L0 eval-cache: [`eval_cached`] serves a
/// cached `ZapConfig` on a re-validated manifest hit (in `Skip` mode), else evals fresh
/// and persists. The posture comes from [`mode_from_env`] (conservative `Shadow`
/// default; `ZAP_EVAL_CACHE=skip` opts into the real skip); `bust` (`--no-cache`) forces
/// a fresh eval + re-persist for this run. Fully advisory — a cache problem never
/// affects this result.
///
/// `bootstrap` selects the target's `bootstrap_user` (the `--bootstrap` switch) as the
/// SSH connecting identity instead of the primary `user` — the initial provisioning run
/// before SSH hardening creates the primary user. It is a no-op for a `Local` target
/// (local has no connecting user). This is the one seam every target-connecting command
/// evals through, so a *new* command that connects to a target must surface `--bootstrap`
/// and thread it here — the four convergence/deploy commands do; the offline
/// `status` / `lock` / `update` don't connect, so they correctly don't.
///
/// The gates run **before** the connection is bound, so a machine-free config error
/// (a literal secret, a dependency cycle) outranks a target-shaped one (a remote target
/// with no `host`). Binding is IO-free — connectivity is `detect_all`'s job — so this
/// costs nothing and reports the more fundamental problem first.
///
/// # Errors
/// Propagates config-eval failures; the two `config_gates`; [`Error::ConfigParse`]-style
/// validation for a remote target that declares no `host`; [`Error::Config`] when
/// `bootstrap` is set but the target declares no `bootstrap_user`.
pub(super) async fn eval_target(
    config_path: &Path,
    zap_home: Option<&Path>,
    fgro: Option<&Path>,
    bust: bool,
    bootstrap: bool,
) -> Result<(ZapConfig, Connection, SecretMasker)> {
    let config = eval_pinned(zap_home, fgro, config_path, PinFrom::Lock, bust).await?;
    let (conn, masker) = bind_target(&config, bootstrap)?;
    Ok((config, conn, masker))
}

/// Which toolchain pin an eval holds the `fgro` binary to.
#[derive(Debug, Clone, Copy)]
pub(super) enum PinFrom<'a> {
    /// The config's `zap.lock` ([`locked_pin`]): every command but `zap lock`.
    Lock,
    /// A pin the caller computed: `zap lock`, which records it, and `zap lock --check`,
    /// which has checked it against the lock.
    Given(&'a ContentHash),
}

/// Evaluate `config_path` through the L0 cache with the operator's `fgro`, held to its
/// pin: the one eval both seams share.
///
/// The config's state is claimed first ([`claim_state`]), then the config is found
/// ([`require_config`]), then the `fgro` setting and the pin are read — a missing
/// config before either, and a missing setting before a missing pin, since `zap lock`
/// needs the setting to pin one.
///
/// # Errors
/// [`Error::ConfigNotFound`] with no config at `config_path`; [`Error::FgroUnset`] with
/// no `fgro`; [`Error::ToolchainUnpinned`] (or the lock's read error) for
/// [`PinFrom::Lock`] with no pin; the eval's errors.
async fn eval_pinned(
    zap_home: Option<&Path>,
    fgro: Option<&Path>,
    config_path: &Path,
    pin: PinFrom<'_>,
    bust: bool,
) -> Result<ZapConfig> {
    claim_state(zap_home, config_path)?;
    require_config(config_path)?;
    let path = require_fgro(fgro)?;
    let locked;
    let pin = match pin {
        PinFrom::Lock => {
            locked = locked_pin(config_path)?;
            &locked
        }
        PinFrom::Given(pin) => pin,
    };
    let pin_cache = pin_cache_dir(zap_home);
    let fgro = PinnedFgro {
        path,
        pin,
        pin_cache: pin_cache.as_deref(),
    };
    eval_cached(zap_home, config_path, fgro, mode_from_env(), bust).await
}

/// Refuse a config that isn't there, as the eval would ([`Error::ConfigNotFound`]), before
/// the lock's toolchain pin is read: a config path that names nothing is told so, rather
/// than to pin a toolchain beside it. Only that it resolves is checked here; the eval
/// resolves it again and settles its project.
///
/// # Errors
/// [`Error::ConfigNotFound`] when `config_path` doesn't resolve on disk.
pub(super) fn require_config(config_path: &Path) -> Result<()> {
    std::fs::canonicalize(config_path)
        .map(drop)
        .map_err(|source| Error::ConfigNotFound {
            path: config_path.display().to_string(),
            source,
        })
}

/// Hold the config's state under `zap_home`, when there is one, to being zap's own
/// (`crate::home::claim_state_dirs`) — before the eval cache, the last-run report, or a
/// deploy preview is read from it. Both eval seams start here, so no command reads a
/// record out of a directory that is a link to, or belongs to, somewhere else.
///
/// A config that has its own lock's name is refused here too
/// (`crate::lock::refuse_lock_named_config`), before it is evaluated.
fn claim_state(zap_home: Option<&Path>, config_path: &Path) -> Result<()> {
    crate::lock::refuse_lock_named_config(config_path)?;
    zap_home.map_or(Ok(()), |home| {
        crate::home::claim_state_dirs(home, config_path)
    })
}

/// The gates, then the connection an evaluated `config` binds: [`eval_target`] past the
/// config eval. An error of the bind is masked like every error past the gates
/// ([`masking_errors`]).
pub(super) fn bind_target(
    config: &ZapConfig,
    bootstrap: bool,
) -> Result<(Connection, SecretMasker)> {
    let masker = config_gates(config)?;
    let conn = if config.target.is_local() {
        Connection::Local
    } else {
        Connection::Ssh(
            build_ssh(&config.target, bootstrap).map_err(|error| error.masked(&masker))?,
        )
    };
    Ok((conn, masker))
}

/// `run`'s result, an error masked: what a command core returns for everything it does
/// past the config gates.
///
/// A report masks the values it shows; an error is the other thing a command prints,
/// and past the gates it can quote a value a reference resolved to — the `user@host` a
/// connection failed for, a path, what `ssh` or the target said. Every core that holds a
/// masker returns through here, so no error it returns prints a registered secret
/// ([`Error::masked`] states the limit: masking is by value).
pub(super) async fn masking_errors<T>(
    masker: &SecretMasker,
    run: impl Future<Output = Result<T>>,
) -> Result<T> {
    run.await.map_err(|error| error.masked(masker))
}

/// The two pure, machine-free config gates, returning the secret masker the first one
/// builds along the way.
///
/// - **secret** ([`build_validated_masker`](crate::secret::build_validated_masker)) —
///   rejects a secret hardcoded as a literal, best-effort: it fires when a value is both
///   referenced and resolvable in the current env, so it never spuriously
///   fails on a machine that simply lacks the secret.
/// - **structural** ([`validate_config_structure`]) — duplicate ids, dangling
///   `depends_on` / trigger references, dependency cycles, `pipeline` features the
///   sequential executor would drop, a `file` `validate` that can't be honored, the
///   firewall guards.
///
/// Both are config *invariants* rather than per-command behavior — a config that is bad
/// is bad for every verb — so both run for every command that evals one, and both being
/// pure means they run before any connection or probe.
///
/// Deliberately **private**, reachable only through `eval_target` and
/// `eval_untargeted`: that is what makes running one gate and forgetting the other
/// unrepresentable at the command layer, rather than a convention each new core has to
/// remember. A core cannot obtain a `ZapConfig` through those seams ungated.
///
/// The masker is returned rather than discarded because the four target-binding commands
/// all need it — each renders at least one string carrying a seam-resolved value (a held
/// resource's `reason`, a masked `Detection`, the wetrun outcome + event streams), and
/// each masks the values its last-run report hashes. `status` needs it to recompute
/// those; the other target-free callers drop it.
fn config_gates(config: &ZapConfig) -> Result<SecretMasker> {
    let masker = crate::secret::build_validated_masker(config, env_var)?;
    validate_config_structure(config)?;
    Ok(masker)
}

/// Eval a config through the L0 cache for a command that binds **no target** — the
/// offline `status`, the lock verbs (`lock` / `lock --check` / `update`), and
/// `config validate`. The target-free sibling of `eval_target`, so the engine has one eval
/// path rather than a cached one and a bypass.
///
/// Routing these through the cache is not mainly about the saved eval: an eval
/// that goes around [`eval_cached`] is also outside the shadow-mismatch detector, and
/// that detector running on *every* eval is what justifies
/// [`Shadow`](crate::config::EvalCacheMode::Shadow) as the default posture. A command
/// that quietly opts out weakens the evidence the default rests on.
///
/// `pin` is [`PinFrom::Lock`] for every command but the lock verbs that settle the pin
/// themselves (`zap lock`, `zap lock --check`).
///
/// Takes no `bust`: none of these commands exposes `--no-cache`, and none needs to. The
/// manifest is re-validated on every lookup, so a hit here is sound on the same argument
/// `plan` / `apply` already rely on, and under the default `Shadow` posture the eval runs
/// fresh anyway. `status` deliberately stays flagless: its subject is the last-run
/// report, so a switch documented as "ignore the cache" would read as forcing a live
/// probe — which `status` never does, offline by definition.
///
/// Runs the same `config_gates` as `eval_target` and returns the masker: `status` needs
/// it to recompute the last-run report's hashes, which mask every registered secret out
/// of the values they cover; the lock verbs and `config validate` drop it. For them the
/// secret gate is pure rejection — but a config with a hardcoded secret is invalid for
/// every verb, so it is rejected uniformly rather than only where a leak could surface.
///
/// # Errors
/// Propagates config-eval failures — no `fgro`, no pin or a binary that isn't it, a
/// throwing config, or JSON that doesn't match the schema — and the two `config_gates`.
pub(super) async fn eval_untargeted(
    zap_home: Option<&Path>,
    fgro: Option<&Path>,
    config_path: &Path,
    pin: PinFrom<'_>,
) -> Result<(ZapConfig, SecretMasker)> {
    let config = eval_pinned(zap_home, fgro, config_path, pin, false).await?;
    let masker = config_gates(&config)?;
    Ok((config, masker))
}

/// Map a remote [`Target`] descriptor to an [`SshConnection`], resolving references in
/// `host` and the connecting user against the operator env (the same resolution the rest
/// of the engine uses for operator-machine values).
///
/// `bootstrap` selects the connecting user: the target's `bootstrap_user` when set (the
/// `--bootstrap` switch), else the primary `user`. The selection is **explicit** — there
/// is no automatic fallback from one identity to the other on a connectivity failure (a
/// transient blip silently switching identity is unsafe).
///
/// The destination — `user@host`, or the bare host when no user is declared — is one
/// argument of `ssh` and `scp`, read by no shell; but one that starts with `-` they would
/// read as an option, so a user or host that resolves to such a value is refused. So is
/// a host in brackets (`ssh` takes an IPv6 address bare, and the connection brackets it
/// for `scp` itself), a host holding `@` (`ssh` takes what precedes the last one as the
/// account, and an `ssh://user@host:port` form brings a port too) and a user holding `:` (`scp` reads
/// the destination up to its first one as the machine): either would reach an account
/// or a machine other than the ones the plan names.
///
/// A user the target declares and that resolves to nothing is refused like a host that
/// does, on a dry run too: `ssh` would pick an account of its own, and every probe —
/// an operator's `check` among them — would run as that account, which is not the one
/// the config names nor the one a wetrun would connect as. A target that declares no
/// user at all says so, and its plan names none.
///
/// # Errors
/// [`Error::Config`] for a remote target that resolves no `host`, when `bootstrap` is
/// set but the target declares no `bootstrap_user`, when the declared connecting user
/// resolves to nothing, or when the connecting user or the host resolves to a value
/// starting with `-` or holding a reference delimiter, the host to one holding `@`, `[`
/// or `]`, or the user to one holding `:`.
pub(super) fn build_ssh(target: &Target, bootstrap: bool) -> Result<SshConnection> {
    let host = target
        .host()
        .map(|host| resolve_env_vars(host))
        .unwrap_or_default();
    if host.is_empty() {
        return Err(Error::Config(no_host_message(target)));
    }
    let declared_user = connecting_user(target, bootstrap)?;
    let user = declared_user
        .map(|user| resolve_env_vars(user))
        .unwrap_or_default();
    if let Some(declared) = declared_user
        && user.is_empty()
    {
        return Err(Error::Config(no_user_message(declared, bootstrap)));
    }
    for (field, value) in [("connecting user", &user), ("host", &host)] {
        if value.starts_with('-') {
            return Err(Error::Config(format!(
                "the target's {field} resolves to a value starting with `-`, which `ssh` \
                 would read as an option"
            )));
        }
        if var_ref::holds_delimiter(value) {
            return Err(Error::Config(format!(
                "the target's {field} resolves to a value holding a reference delimiter \
                 (U+FDD0 or U+FDD1), which names no machine or account"
            )));
        }
    }
    // The destination is `user@host`, and `host:path` to `scp`: a host that brings an
    // account of its own, or a user that ends the host early, would connect as an
    // account — or copy to a machine — the plan doesn't name.
    if host.contains('@') {
        return Err(Error::Config(
            "the target's host resolves to a value holding `@`, which `ssh` would read as \
             an account ahead of the host; name the account in `target.user`"
                .to_owned(),
        ));
    }
    if host.contains(['[', ']']) {
        return Err(Error::Config(
            "the target's host resolves to a value holding `[` or `]`, which `ssh` reads \
             as part of a name; write an IPv6 address bare (`fe80::1`) — zap brackets it \
             where `scp` needs it"
                .to_owned(),
        ));
    }
    if user.contains(':') {
        return Err(Error::Config(
            "the target's connecting user resolves to a value holding `:`, where `scp` \
             would end the name of the machine it copies to"
                .to_owned(),
        ));
    }
    Ok(SshConnection {
        host,
        user,
        port: target.port(),
        key_path: target.key_path().map(str::to_owned),
        home: target.home().map(str::to_owned),
    })
}

/// Why a remote `target` names no host: it declares none, the one it declares is
/// empty, or — the references shown as `{env:NAME}`, named and never resolved — the
/// one it declares resolves to nothing in this environment.
fn no_host_message(target: &Target) -> String {
    const DECLARE: &str = "(set `target.host`, or `target.local: true`)";
    let Some(host) = target.host() else {
        return format!("remote target declares no `host` {DECLARE}");
    };
    let names: Vec<String> = host.ref_names().map(var_ref::shown).collect();
    if names.is_empty() {
        return format!("the target's `host` is empty {DECLARE}");
    }
    format!(
        "the target's `host` is declared as {} and resolves to nothing: {} unset or empty \
         in the environment — set what it references and re-run",
        host.resolve(var_ref::shown),
        names.join(", ")
    )
}

/// Why the user a run would connect as names no account: `user` — the target's `user`,
/// or its `bootstrap_user` on a `--bootstrap` run — resolves to nothing in this
/// environment. Its references are shown as `{env:NAME}`, named and never resolved.
fn no_user_message(user: &Text, bootstrap: bool) -> String {
    let field = if bootstrap { "bootstrap_user" } else { "user" };
    let names: Vec<String> = user.ref_names().map(var_ref::shown).collect();
    if names.is_empty() {
        // Left out, a `user` leaves the account to `ssh`; a `--bootstrap` run has no
        // account to connect as without its `bootstrap_user`.
        let remedy = if bootstrap {
            "name the account a `--bootstrap` run connects as"
        } else {
            "name the account, or leave it out"
        };
        return format!("the target's `{field}` is empty ({remedy})");
    }
    format!(
        "the target's `{field}` is declared as {} and resolves to nothing: {} unset or empty \
         in the environment — set what it references and re-run (with no user `ssh` would \
         connect as an account of its own choosing, not the one the config names)",
        user.resolve(var_ref::shown),
        names.join(", ")
    )
}

/// The user a run connects to `target` as, as declared (references unresolved): its
/// `bootstrap_user` on a `--bootstrap` run, else its `user`. `None` when the run's
/// identity isn't declared — a local target, or a remote one with no `user`.
///
/// The one selection the connection ([`build_ssh`]) and the plan's [`Machine`]
/// ([`resolve_machine`]) both read, so a plan names the user its run connects as.
///
/// # Errors
/// [`Error::Config`] when `bootstrap` is set but the target declares no `bootstrap_user`.
pub(super) fn connecting_user(target: &Target, bootstrap: bool) -> Result<Option<&Text>> {
    if target.is_local() {
        return Ok(None);
    }
    if bootstrap {
        return target.bootstrap_user().map(Some).ok_or_else(|| {
            Error::Config(
                "--bootstrap given but the target declares no `bootstrap_user`".to_owned(),
            )
        });
    }
    Ok(target.user())
}

/// What follows from a plan label that holds a masking token: the closing clause of an
/// unbindable reason ([`masked_label_refs`] supplies the labels).
pub(super) const NAMES_NO_ONE_MACHINE: &str = "; the plan holds a masking token in its place, \
    so it names no one machine and its hash is the same for every value the reference takes";

/// The labels among `labels` — each a name for what it labels (`target host`) and its
/// declared text — that resolve through a reference `var` masks, as one clause per
/// label naming the reference and the way out for its own cause: one that is secret by
/// its name or its value's form is unmasked or replaced by a literal, one the config
/// masks loses its `mask`, a fetch credential is replaced by another variable; one whose
/// value carries a secret can only stop carrying it. `None` when every label resolves by
/// value.
///
/// A label holding a masking token stands for every value its reference could take, so
/// it identifies nothing: a plan built on it can't be reviewed for one machine, and a
/// report filed under it would be every such machine's.
pub(super) fn masked_label_refs(
    labels: &[(&str, Option<&Text>)],
    var: &impl Fn(&str) -> ReportVar,
) -> Option<String> {
    let masked: Vec<String> = labels
        .iter()
        .filter_map(|(what, declared)| {
            let declared = (*declared)?;
            let refs: Vec<String> = masked_refs(declared, var)
                .iter()
                .map(|masked| match masked {
                    MaskedRef::Secret { name, reason } => {
                        let name = escape_line(name);
                        let shown = var_ref::shown(&name);
                        let unmask = format!(
                            "call `zap.unmask('{name}')` if it is not a secret, or declare \
                             the value literally"
                        );
                        match reason {
                            SecretReason::Name => format!("`{shown}`, a secret name ({unmask})"),
                            SecretReason::Value(shape) => {
                                format!("`{shown}`, whose value is {} ({unmask})", shape.describe())
                            }
                            // Its name would read as a secret's once the `mask` is
                            // gone, so the whole way out is said at once.
                            SecretReason::Declared if is_secret_var_name(&name) => format!(
                                "`{shown}`, which the config declares a secret and whose \
                                 name reads as one too (if it is not a secret, replace its \
                                 `zap.mask('{name}')` with `zap.unmask('{name}')`; or declare \
                                 the value literally)"
                            ),
                            SecretReason::Declared => format!(
                                "`{shown}`, which the config declares a secret (drop its \
                                 `zap.mask('{name}')` if it is not one, or declare the value \
                                 literally)"
                            ),
                            SecretReason::Credential => format!(
                                "`{shown}`, which the config also uses as a fetch credential, \
                                 a secret wherever it is used (reference another variable \
                                 here, or declare the value literally)"
                            ),
                        }
                    }
                    MaskedRef::CarriesSecret { name, secrets } => {
                        let secrets: Vec<String> = secrets
                            .iter()
                            .map(|secret| format!("`{}`", var_ref::shown(&escape_line(secret))))
                            .collect();
                        format!(
                            "`{}`, whose value carries the secret {} (a {what} must not \
                             hold a secret's value: declare it literally, or through a \
                             variable that carries none)",
                            var_ref::shown(&escape_line(name)),
                            secrets.join(", ")
                        )
                    }
                })
                .collect();
            (!refs.is_empty()).then(|| {
                format!(
                    "the {what} `{}` references {}",
                    escape_line(declared),
                    refs.join(" and ")
                )
            })
        })
        .collect();
    (!masked.is_empty()).then(|| masked.join("; "))
}

/// Why no last-run report is kept for `target`, if none is: its host resolves through a
/// reference `var` masks, so the label a report is filed and looked up under is a token
/// shared by every machine the reference names — one machine's verdicts would read as
/// another's. `None` when the host resolves by value (or the target is local).
pub(super) fn unidentified_host_message(
    target: &Target,
    var: &impl Fn(&str) -> ReportVar,
) -> Option<String> {
    masked_label_refs(&[("target host", target.host())], var).map(|refs| {
        format!(
            "{refs}; a report filed under a masking token would stand for every machine \
             the reference names"
        )
    })
}

/// The machine a command's passes read, as a plan and a last-run report name it.
#[derive(Debug, Clone)]
pub(super) struct ResolvedMachine {
    /// The target's host and connecting user, resolved for this environment.
    pub machine: Machine,
    /// Why no last-run report is kept for it ([`unidentified_host_message`]), when none
    /// is.
    pub unidentified_host: Option<String>,
    /// Why a plan for it can't be bound to, when it can't: the host or the connecting
    /// user resolves through a masked reference, so the plan names no one machine. No
    /// hash is shown or recorded for such a plan, and no wetrun of it runs.
    pub unbindable: Option<String>,
}

/// Resolve the machine `config`'s target names in this environment, connecting as the
/// primary user or — with `bootstrap` — the bootstrap one. References resolve as a
/// last-run report resolves them ([`report_var`]), so the result holds a masking token
/// wherever a secret would be, never its value; the reasons are masked too.
///
/// # Errors
/// [`Error::Config`] for a remote host or a declared connecting user that resolves to
/// nothing, or `bootstrap` with no `bootstrap_user` declared;
/// [`Error::HomeNotAbsolute`] for a local target whose `HOME` is a relative path.
pub(super) fn resolve_machine(
    config: &ZapConfig,
    masker: &SecretMasker,
    bootstrap: bool,
) -> Result<ResolvedMachine> {
    let target = &config.target;
    let var = report_var(config, masker);
    let user = connecting_user(target, bootstrap)?;
    // Read only for a local target: a remote run's machine doesn't depend on `HOME`.
    let home = if target.is_local() {
        local_home()?
    } else {
        None
    };
    let machine = Machine::resolve(target, user, || local_account(home, masker), &var)
        .ok_or_else(|| Error::Config(no_host_message(target)))?;
    // A declared user that resolves to nothing would leave the account to `ssh`.
    if let Some(declared) = user
        && machine.user().is_none()
    {
        return Err(Error::Config(no_user_message(declared, bootstrap)));
    }
    let unbindable = masked_label_refs(
        &[("target host", target.host()), ("connecting user", user)],
        &var,
    )
    .map(|refs| masker.mask(&format!("{refs}{NAMES_NO_ONE_MACHINE}")));
    let unidentified_host =
        unidentified_host_message(target, &var).map(|reason| masker.mask(&reason));
    Ok(ResolvedMachine {
        machine,
        unidentified_host,
        unbindable,
    })
}

/// The home a `~` in a local path resolves to: `HOME` as the run reads it ([`env_var`],
/// an `--env-file` included), through the one reading of a home variable
/// (`crate::home::home_from`), so the plan names the home path expansion uses. `None`
/// when it is unset or empty.
///
/// # Errors
/// [`Error::HomeNotAbsolute`] when it is a relative path, which path expansion refuses
/// too.
fn local_home() -> Result<Option<String>> {
    Ok(
        crate::home::home_from("HOME", env_var("HOME").map(Into::into))?
            .map(|home| home.to_string_lossy().into_owned()),
    )
}

/// The account this process runs as on the machine it runs on, as a local plan names it
/// ([`LocalAccount`]): the effective user's name — its uid in decimal when the password
/// database names none — and `home` ([`local_home`]), masked like any value a plan
/// holds.
fn local_account(home: Option<String>, masker: &SecretMasker) -> LocalAccount {
    let uid = nix::unistd::geteuid();
    let user = match nix::unistd::User::from_uid(uid) {
        Ok(Some(user)) => user.name,
        _ => uid.as_raw().to_string(),
    };
    LocalAccount {
        user,
        home: home.map(|home| masker.mask(&home)),
    }
}
