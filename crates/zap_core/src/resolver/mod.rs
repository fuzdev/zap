//! Content resolution for a `remote` file's content and a `build`'s source.
//!
//! Fetch a URL, verify its blake3 (and, for a `build` source that declares `verify`, its
//! minisign signature), and cache the verified bytes under
//! `<zap_home>/cache/files/<blake3>/<name>` ([`content_cache_path`]).
//!
//! Resolution is **fetch-and-hash**: GET the resolved url
//! (errors name the declared one, references intact), compute blake3, and — for a
//! *vendored* pin (a declared one) or a locked one — verify the bytes against it. The cache is content-addressed by the computed hash, so a hit is
//! self-verifying (the bytes at `<blake3>/…` must re-hash to `<blake3>`); a corrupt
//! entry is a miss, never trusted. Binary-safe and **streamed** — the body is written
//! to disk and hashed incrementally (one fixed buffer, never the whole artifact in
//! memory), under a size cap that aborts a runaway/hostile download.
//!
//! Operator-side: the resolver fetches + caches on the operator's machine; execution
//! pushes the verified bytes to the target via `Connection::copy_file`. A private
//! byte-host is addressed with an optional [`RemoteAuth`] credential — resolved at
//! this IO boundary (its token's reference reads operator env) and attached as a request
//! header; never hashed.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::time::Duration;

use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use zap_types::scalar::ContentHash;
use zap_types::schema::{MinisignVerify, RemoteAuth, SourceVerify};
use zap_types::var_ref;

use crate::error::{Error, Result};
use crate::resolve::{env_var, resolve_env_vars, var_names_in};
use crate::tls::build_http_client;
use zap_types::fetch_url::{FetchSide, fetch_url_problem};

/// How long to wait for a content download before giving up.
const FETCH_TIMEOUT: Duration = Duration::from_secs(300);

/// Hard cap on a fetched artifact's size. A `Content-Length` header is a hint, not a
/// bound, so the streamed download enforces this independently and aborts past it
/// (the staging dir then unlinks the partial). Generous headroom for tool binaries and
/// source tarballs while preventing an unbounded-body OOM from a hostile/misconfigured
/// byte-host.
const MAX_CONTENT_BYTES: u64 = 4 * 1024 * 1024 * 1024; // 4 GiB

/// Hard cap on a fetched minisign signature — they're ~100 bytes; this is absurd
/// headroom that still bounds a hostile `.minisig` response read into memory.
const MAX_SIGNATURE_BYTES: u64 = 64 * 1024; // 64 KiB

/// Streaming buffer size for the download and the cache-hit re-hash — the only memory
/// held regardless of artifact size.
const STREAM_CHUNK_BYTES: usize = 64 * 1024;

/// A resolved remote file: the verified bytes' blake3 and SHA-512, and their cached
/// path.
///
/// For a tracked file the `blake3` is the freshly-computed pin the caller records in
/// the lock; for a vendored file it equals the declared pin. Both digests come from the
/// one read that verified the bytes, so the SHA-512 is the pinned bytes' digest, which
/// a target-side check of an upload compares against.
#[derive(Debug, Clone)]
pub struct ResolvedContent {
    /// blake3 of the cached bytes (the content pin).
    pub blake3: ContentHash,
    /// SHA-512 of the same bytes, lowercase hex.
    pub sha512: String,
    /// Path to the verified bytes under `<zap_home>/cache/files/<blake3>/<name>`.
    pub path: PathBuf,
}

/// The content-cache directory for a hash: `<zap_home>/cache/files/<blake3>`.
fn content_dir(zap_home: &Path, blake3: &str) -> PathBuf {
    zap_home.join("cache").join("files").join(blake3)
}

/// Where the content cache holds the bytes of `declared_url` whose blake3 is `blake3`.
///
/// `<zap_home>/cache/files/<blake3>/<name>`, the name from `cache_name`: the one
/// layout every reader and writer of the cache uses, and the one a harness that seeds a
/// warm cache writes to.
#[must_use]
pub fn content_cache_path(zap_home: &Path, blake3: &str, declared_url: &str) -> PathBuf {
    content_dir(zap_home, blake3).join(cache_name(declared_url))
}

/// The cache file name for a url **as declared** — its last path segment (query and
/// fragment stripped), or `content` when it has none.
///
/// Only a human-readable label inside the content-addressed `<blake3>/` dir; the
/// blake3 is the real key. It is taken from the declared text, never a resolved one: a
/// reference in the segment is spelled in its shown form (`{env:NAME}`), so a secret in
/// the url's last segment is on no path (and in no error that names one) and the file's
/// name holds no delimiter. Always one safe path component — a segment holds no `/`,
/// and an empty one, `.`, or `..` falls back to `content`.
///
/// Every reader and writer of the cache takes the declared url and names the file
/// through here, so they can't disagree about where a url's bytes are.
fn cache_name(declared_url: &str) -> String {
    let path = declared_url
        .split(['?', '#'])
        .next()
        .unwrap_or(declared_url);
    let segment = path
        .rsplit('/')
        .find(|segment| !segment.is_empty())
        .filter(|segment| !matches!(*segment, "." | ".."))
        .unwrap_or("content");
    var_ref::map_literals(&var_ref::map_refs(segment, var_ref::shown), |literal| {
        literal.replace([var_ref::OPEN, var_ref::CLOSE], "_")
    })
}

/// A fetch location: the url as the config declares it, and as it resolves here.
///
/// The request is sent to `resolved`; every error names `declared`. A url can carry a
/// secret (a `SECRET_TOKEN` reference in its query), and an error is printed, so it
/// holds the inert form — nothing a resolved value could reach.
struct Location<'a> {
    /// The url as declared, references intact.
    declared: &'a str,
    /// The url with each reference resolved from the operator env.
    resolved: String,
}

impl<'a> Location<'a> {
    /// Resolve `declared` for a fetch, refusing one whose references aren't all set.
    ///
    /// An unset or empty reference would resolve to nothing and the request would go to
    /// another url — whose bytes would then be pinned or installed as this one's.
    fn of(declared: &'a str) -> Result<Self> {
        let unset = unset_refs(declared, env_var);
        if !unset.is_empty() {
            return Err(Error::FetchVarUnset {
                url: declared.to_owned(),
                vars: unset.join(", "),
            });
        }
        let resolved = resolve_env_vars(declared);
        // The rule the structural gate holds a written url to, on the url as it
        // resolved: what a reference contributes is known only here.
        if let Some(problem) = fetch_url_problem(&resolved, FetchSide::Operator) {
            return Err(Error::Config(format!(
                "cannot fetch {declared}: the URL {problem}"
            )));
        }
        Ok(Self { declared, resolved })
    }

    /// A fetch error for this location, naming the declared url.
    fn fetch_failed(&self, message: String) -> Error {
        Error::Fetch {
            url: self.declared.to_owned(),
            message,
        }
    }
}

/// The variable names in `declared` that `env_get` has no value for — unset, or set to
/// the empty string, which resolves to the same nothing (sorted).
fn unset_refs(declared: &str, env_get: impl Fn(&str) -> Option<String>) -> Vec<String> {
    let mut names = BTreeSet::new();
    var_names_in(declared, &mut names);
    names
        .into_iter()
        .filter(|name| env_get(name).is_none_or(|value| value.is_empty()))
        .collect()
}

/// A `reqwest` error's text without the request url it would otherwise quote — the
/// resolved one.
fn transport_message(error: reqwest::Error) -> String {
    error.without_url().to_string()
}

/// Resolve remote content: serve the cached bytes when present and self-verifying,
/// else fetch, verify, and cache.
///
/// `url` is the location as declared: its references are resolved here, for
/// the request, while the cache file's name (`cache_name`) and every error keep the
/// declared form. A fetch whose url has an unset or empty reference is
/// refused ([`Error::FetchVarUnset`]); a cache hit needs none of them.
///
/// `expected` is the *vendored* pin — `Some` means the bytes must hash to it (a
/// mismatch is an error) and enables a network-free cache hit; `None` (tracked)
/// returns the freshly-computed hash for the caller to pin in the lock. `auth` is the
/// optional fetch credential (a private byte-host); a network-free cache hit needs no
/// credential (it short-circuits before the fetch).
///
/// `verify` is an optional upstream-signature check (minisign) run **only on a
/// cache-miss fetch**, before the bytes are cached — so a tampered upstream fails at
/// fetch/mint and its bytes never get a pin. This is where upstream-signature trust is
/// established; the blake3 pin is the trust anchor thereafter.
///
/// A cache entry is trusted by its **content**, not its provenance: bytes that hash to
/// the pin *are* the pinned bytes, whichever path stored them — a fetch (verified or
/// not), or detection storing a target read that matched its pin. So a hit is never
/// taken as proof that a signature was checked for those bytes, and it needn't be:
/// - a *tracked* pin exists only because its bytes passed `verify` when it was minted
///   (`expected` is `None` then, so minting always fetches and verifies), and a hit is
///   those same bytes;
/// - a *vendored* pin is the operator's own statement of exactly which bytes to trust —
///   a stronger claim than a signature — so identical bytes are sound to use even if
///   they arrived another way and minisign never ran on them.
///
/// # Errors
/// A typed content-resolution error: [`Error::Fetch`] (transport / non-success HTTP),
/// [`Error::FetchVarUnset`] (an unset reference in the url), [`Error::AuthUnset`] (empty
/// credential), [`Error::ContentHashMismatch`] (the integrity
/// check against the declared pin), [`Error::SignatureVerification`] (minisign), or
/// [`Error::CacheWrite`] (local cache IO).
pub async fn resolve_content(
    zap_home: &Path,
    url: &str,
    expected: Option<&str>,
    auth: Option<&RemoteAuth>,
    verify: Option<&SourceVerify>,
) -> Result<ResolvedContent> {
    resolve_content_within(zap_home, url, expected, auth, verify, None).await
}

/// [`resolve_content`], with the fetch held to `max` bytes when given.
///
/// Without `max` the content cap holds. A fetch stops as soon as its body passes it,
/// and fails. A cache hit is not measured here; a caller that bounds its bytes checks
/// what it reads.
///
/// # Errors
/// [`resolve_content`]'s, and [`Error::Fetch`] for a body past `max`.
pub async fn resolve_content_within(
    zap_home: &Path,
    url: &str,
    expected: Option<&str>,
    auth: Option<&RemoteAuth>,
    verify: Option<&SourceVerify>,
    max: Option<u64>,
) -> Result<ResolvedContent> {
    // Network-free cache hit: the pin gives the content-addressed path up front, and
    // stream-re-hashing the file proves these are the pinned bytes. A hit skips signature
    // verification because the pin, not a past check, is the trust anchor (see above).
    if let Some(pin) = expected {
        let cached = content_cache_path(zap_home, pin, url);
        if let Ok((actual, sha512)) = hash_file(&cached).await
            && actual.as_str() == pin
        {
            return Ok(ResolvedContent {
                blake3: actual,
                sha512,
                path: cached,
            });
        }
    }

    // Cache miss: stream the body into a private staging dir *inside the cache
    // filesystem* (random 0700 name — no predictable-path swap — so the promote is an
    // atomic same-fs rename). The tempdir auto-removes on any early return below,
    // unlinking a partial, oversized, mismatched, or unverified download.
    let staging = staging_dir(zap_home)?;
    let artifact = staging.path().join("artifact");

    let location = Location::of(url)?;
    let cap = max.map_or(MAX_CONTENT_BYTES, |max| max.min(MAX_CONTENT_BYTES));
    let (computed, sha512) = fetch_to_file(&location, auth, &artifact, cap).await?;

    if let Some(pin) = expected
        && computed.as_str() != pin
    {
        return Err(Error::ContentHashMismatch {
            url: location.declared.to_owned(),
            declared: pin.to_owned(),
            fetched: computed.as_str().to_owned(),
        });
    }

    // Upstream-signature verification (cache-miss path only): minisign reads the staged
    // file directly. A tampered fetch fails here, before the bytes are promoted.
    if let Some(verify) = verify {
        verify_signature(&location, &artifact, auth, verify).await?;
    }

    let path = promote(zap_home, &artifact, &computed, &cache_name(url))?;
    Ok(ResolvedContent {
        blake3: computed,
        sha512,
        path,
    })
}

/// The content-cache write error for `path`.
fn cache_failed(path: &Path, error: std::io::Error) -> Error {
    Error::CacheWrite {
        path: path.display().to_string(),
        source: error,
    }
}

/// A fresh private staging dir inside `<zap_home>/cache/files` — on the cache's own
/// filesystem, so promoting from it is an atomic rename. The directories above it are
/// established as zap's own on the way (`crate::home::ensure_state_dir`).
fn staging_dir(zap_home: &Path) -> Result<tempfile::TempDir> {
    let files_root = zap_home.join("cache").join("files");
    crate::home::ensure_state_dir(zap_home, &files_root)
        .map_err(|e| cache_failed(&files_root, e))?;
    tempfile::Builder::new()
        .prefix(".staging-")
        .tempdir_in(&files_root)
        .map_err(|e| cache_failed(&files_root, e))
}

/// Create the file a staging dir holds content in: new, and owner-only (`0600` on unix)
/// — the mode it keeps when it is promoted into the cache.
async fn create_staged(path: &Path) -> std::io::Result<tokio::fs::File> {
    let mut options = tokio::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);
    options.open(path).await
}

/// Promote a staged, verified file to its content-addressed home,
/// `<zap_home>/cache/files/<blake3>/<name>` (an atomic same-filesystem rename).
fn promote(zap_home: &Path, staged: &Path, blake3: &ContentHash, name: &str) -> Result<PathBuf> {
    let dir = content_dir(zap_home, blake3.as_str());
    crate::home::ensure_state_dir(zap_home, &dir).map_err(|e| cache_failed(&dir, e))?;
    let final_path = dir.join(name);
    std::fs::rename(staged, &final_path).map_err(|e| cache_failed(&final_path, e))?;
    Ok(final_path)
}

/// The SHA-512 of the cached bytes for `pin` fetched from `url` (as declared; lowercase
/// hex).
///
/// Read from `<zap_home>/cache/files/<pin>/<name>` — `None` when there are none, they
/// can't be read, or they don't hash to `pin` (a corrupt entry is a miss, never trusted).
/// Detection's desired side for a `remote` file: the target's SHA-512 is compared against
/// this, so only a digest crosses the wire. Streamed (one chunk in memory), both hashes
/// in one pass.
pub async fn cached_sha512(zap_home: &Path, pin: &str, url: &str) -> Option<String> {
    let mut file = tokio::fs::File::open(content_cache_path(zap_home, pin, url))
        .await
        .ok()?;
    let mut blake3 = blake3::Hasher::new();
    let mut sha512 = crate::digest::Sha512::new();
    let mut buf = vec![0u8; STREAM_CHUNK_BYTES];
    loop {
        let n = file.read(&mut buf).await.ok()?;
        if n == 0 {
            break;
        }
        blake3.update(&buf[..n]);
        sha512.update(&buf[..n]);
    }
    (ContentHash::of_hash(blake3.finalize()).as_str() == pin).then(|| sha512.finish_hex())
}

/// Store `bytes` in the content cache under their own blake3, as the bytes of `url` (as
/// declared).
///
/// Through the same private staging dir and atomic promote as a fetch — how detection
/// warms the cache from a target read whose bytes matched their pin, so the next pass
/// compares digests instead. Returns the bytes' blake3.
///
/// # Errors
/// [`Error::CacheWrite`] when the staging dir, the write, or the promote fails.
pub async fn store_content(zap_home: &Path, url: &str, bytes: &[u8]) -> Result<ContentHash> {
    let staging = staging_dir(zap_home)?;
    let artifact = staging.path().join("artifact");
    let mut file = create_staged(&artifact)
        .await
        .map_err(|e| cache_failed(&artifact, e))?;
    file.write_all(bytes)
        .await
        .map_err(|e| cache_failed(&artifact, e))?;
    file.flush().await.map_err(|e| cache_failed(&artifact, e))?;
    drop(file);
    let blake3 = ContentHash::of_bytes(bytes);
    promote(zap_home, &artifact, &blake3, &cache_name(url))?;
    Ok(blake3)
}

/// Verify a staged artifact file against an upstream signature.
///
/// The scheme is minisign. Fetches the signature (`signature_url`, else the url with
/// `.minisig` appended to its path, before any query,
/// bounded by [`MAX_SIGNATURE_BYTES`]) — with the source's `auth` only when the
/// signature's origin is the source's ([`same_origin`]), anonymously otherwise, since a
/// config names no credential of the signature's own — and shells out to
/// `minisign -Vm <file> -P <key>` — zap adds no crypto dependency, surfacing the
/// upstream's own trust mechanism. `artifact` is the already-staged download (in the
/// caller's private `0700` temp dir — random name, so no predictable-path symlink/TOCTOU
/// swap between our write and minisign's read); the signature is written to the sibling
/// `<artifact>.minisig` that minisign reads.
async fn verify_signature(
    location: &Location<'_>,
    artifact: &Path,
    auth: Option<&RemoteAuth>,
    verify: &SourceVerify,
) -> Result<()> {
    let SourceVerify::Minisign(MinisignVerify {
        public_key,
        signature_url,
    }) = verify;
    let default_declared;
    let sig_location = if let Some(url) = signature_url {
        Location::of(url.as_inert())?
    } else {
        default_declared = path_suffixed(location.declared, MINISIG_SUFFIX);
        let mut resolved = reqwest::Url::parse(&location.resolved)
            .map_err(|error| location.fetch_failed(format!("not a URL: {error}")))?;
        let path = format!("{}{MINISIG_SUFFIX}", resolved.path());
        resolved.set_path(&path);
        Location {
            declared: &default_declared,
            resolved: resolved.into(),
        }
    };
    let sig_auth = auth.filter(|_| same_origin(&location.resolved, &sig_location.resolved));
    let signature = fetch_bytes(&sig_location, sig_auth, MAX_SIGNATURE_BYTES).await?;

    let sig_failed = |message: String| Error::SignatureVerification {
        url: location.declared.to_owned(),
        message,
    };
    let sig_path = PathBuf::from(format!("{}.minisig", artifact.display()));
    std::fs::write(&sig_path, &signature)
        .map_err(|error| sig_failed(format!("failed to stage signature for minisign: {error}")))?;

    let minisign = minisign_binary(
        MINISIGN_SETTING.get().and_then(Option::as_deref),
        std::env::var_os("PATH").as_deref(),
        owner_and_mode,
    )
    .map_err(sig_failed)?;
    let result = tokio::process::Command::new(&minisign)
        .arg("-Vm")
        .arg(artifact)
        .arg("-P")
        .arg(public_key.as_str())
        .output()
        .await;
    minisign_verdict(&minisign, result).map_err(sig_failed)
}

/// What a `minisign -Vm` run at `minisign` says of a signature: its exit 0 verifies it,
/// and anything else — a run that failed to start, or a nonzero exit — refuses it,
/// saying why.
fn minisign_verdict(
    minisign: &Path,
    result: std::io::Result<std::process::Output>,
) -> std::result::Result<(), String> {
    let output = result.map_err(|error| {
        format!(
            "minisign at {} could not run ({error}) — install `minisign`",
            minisign.display()
        )
    })?;
    if !output.status.success() {
        return Err(format!(
            "minisign at {}: {}",
            minisign.display(),
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Ok(())
}

/// The environment variable that names the `minisign` binary, an absolute path, over a
/// `PATH` lookup. The bin reads it ([`set_minisign_setting`]); the engine doesn't.
pub const MINISIGN_VAR: &str = "ZAP_MINISIGN";

/// The `ZAP_MINISIGN` the bin read at startup, if any.
static MINISIGN_SETTING: std::sync::OnceLock<Option<std::ffi::OsString>> =
    std::sync::OnceLock::new();

/// Record the `ZAP_MINISIGN` the bin read (`None` when unset).
///
/// It names the binary every signature check this process makes runs. The bin calls it
/// once, before any work; a call never made is no setting. Its value is checked where it
/// is used (`minisign_binary`), so an empty or relative one fails the verification
/// that needs it, saying why.
pub fn set_minisign_setting(setting: Option<std::ffi::OsString>) {
    let first = MINISIGN_SETTING.set(setting).is_ok();
    debug_assert!(first, "set_minisign_setting called twice");
}

/// The `minisign` whose exit status is the signature verdict: `ZAP_MINISIGN` (`setting`)
/// when set, which must be non-empty and absolute, else the first executable `minisign`
/// in an absolute directory of `path` (a relative entry names wherever zap runs, and is
/// skipped). It is found once and run by that path.
///
/// Its exit 0 is what lets a source be cached and pinned, so the binary must be one only
/// root or the operator could have put there. Refused:
///
/// - when its path as found, as it resolves, or any link it passes through, has a
///   `node_modules` component (an npm script's `PATH` leads with `node_modules/.bin`,
///   which any installed package can fill);
/// - when the binary, or any directory that decides what the path reaches, is owned by
///   an account other than root and the effective user, or writable by its group or by
///   others: every directory from the binary's resolved one up to `/`, and the same
///   for the directory holding each component of the path as found and each link it
///   passes through, each read where it resolves (`stat` is `stat_of`, owner and mode).
///
/// The binary still runs by path after the check, and a file swapped in at that path in
/// between would be run; once every directory on the way is root's or the operator's
/// and no one else's to write, only those accounts can make that swap, and they could
/// replace the binary anyway.
///
/// # Errors
/// Why there is no `minisign` to trust, naming the path.
fn minisign_binary(
    setting: Option<&std::ffi::OsStr>,
    path: Option<&std::ffi::OsStr>,
    stat_of: impl Fn(&Path) -> std::io::Result<(u32, u32)>,
) -> std::result::Result<PathBuf, String> {
    use std::os::unix::fs::PermissionsExt as _;

    let found = if let Some(setting) = setting {
        if setting.is_empty() {
            return Err(format!(
                "`{MINISIGN_VAR}` is set but empty; name the minisign binary by absolute \
                 path, or unset it to look minisign up on PATH"
            ));
        }
        let named = PathBuf::from(setting);
        if !named.is_absolute() {
            return Err(format!(
                "`{MINISIGN_VAR}` names {}, which is not an absolute path",
                named.display()
            ));
        }
        named
    } else {
        path.into_iter()
            .flat_map(std::env::split_paths)
            .filter(|dir| dir.is_absolute())
            .map(|dir| dir.join("minisign"))
            .find(|candidate| {
                std::fs::metadata(candidate)
                    .is_ok_and(|meta| meta.is_file() && meta.permissions().mode() & 0o111 != 0)
            })
            .ok_or_else(|| {
                format!(
                    "minisign unavailable (no `minisign` in an absolute directory on PATH) — \
                     install `minisign`, or name it with `{MINISIGN_VAR}`"
                )
            })?
    };
    let failed = |at: &Path, error: &dyn std::fmt::Display| {
        format!("minisign at {}: {}: {error}", found.display(), at.display())
    };
    let real = std::fs::canonicalize(&found).map_err(|error| failed(&found, &error))?;

    // Every path the lookup goes through: as found, then each link's target, with the
    // directories that decide each of their components.
    let mut paths = vec![found.clone(), real.clone()];
    let mut held: BTreeSet<PathBuf> = BTreeSet::new();
    held.insert(real);
    let mut work = vec![found.clone()];
    let mut hops = 0;
    while let Some(walked) = work.pop() {
        let mut prefix = PathBuf::new();
        for part in walked.components() {
            prefix.push(part);
            if let Some(parent) = prefix.parent() {
                let resolved =
                    std::fs::canonicalize(parent).map_err(|error| failed(parent, &error))?;
                held.extend(resolved.ancestors().map(Path::to_path_buf));
            }
            let link = std::fs::symlink_metadata(&prefix)
                .map_err(|error| failed(&prefix, &error))?
                .file_type()
                .is_symlink();
            if link {
                hops += 1;
                if hops > 40 {
                    return Err(failed(&prefix, &"too many symbolic links"));
                }
                let target =
                    std::fs::read_link(&prefix).map_err(|error| failed(&prefix, &error))?;
                let target = prefix
                    .parent()
                    .map_or_else(|| target.clone(), |dir| dir.join(&target));
                paths.push(target.clone());
                work.push(target);
            }
        }
    }
    for at in &paths {
        if at
            .components()
            .any(|part| part.as_os_str() == "node_modules")
        {
            return Err(format!(
                "minisign at {} is inside a `node_modules` directory ({}), which any \
                 installed package can fill; install `minisign` elsewhere, or name it with \
                 `{MINISIGN_VAR}`",
                found.display(),
                at.display()
            ));
        }
    }
    let me = nix::unistd::geteuid().as_raw();
    for at in &held {
        let (uid, mode) = stat_of(at).map_err(|error| failed(at, &error))?;
        if uid != 0 && uid != me {
            return Err(format!(
                "minisign at {}: {} belongs to uid {uid}, neither root nor this user, who \
                 could replace it",
                found.display(),
                at.display(),
            ));
        }
        if mode & 0o022 != 0 {
            return Err(format!(
                "minisign at {}: {} can be written by its group or by others, who could \
                 replace it",
                found.display(),
                at.display()
            ));
        }
    }
    Ok(found)
}

/// The owner and mode of what `path` resolves to: [`minisign_binary`]'s `stat_of`.
fn owner_and_mode(path: &Path) -> std::io::Result<(u32, u32)> {
    use std::os::unix::fs::MetadataExt as _;
    std::fs::metadata(path).map(|meta| (meta.uid(), meta.mode()))
}

/// What a signature's default url adds to the source url's path.
const MINISIG_SUFFIX: &str = ".minisig";

/// `url` with `suffix` appended to its path: before the first `?` or `#`, so a query or
/// a fragment stays one. A reference's marker holds neither character, so the split
/// falls in the declared text itself.
fn path_suffixed(url: &str, suffix: &str) -> String {
    let at = url.find(['?', '#']).unwrap_or(url.len());
    format!("{}{suffix}{}", &url[..at], &url[at..])
}

/// Whether two resolved urls share an origin: scheme, host, and port (a scheme's
/// default port when none is written). Either one unparseable shares none — its own
/// fetch then fails to parse, with no credential sent anywhere — and so does a url
/// with no host to compare, whose origin is opaque and equals no other.
fn same_origin(a: &str, b: &str) -> bool {
    match (reqwest::Url::parse(a), reqwest::Url::parse(b)) {
        (Ok(a), Ok(b)) => a.origin() == b.origin(),
        _ => false,
    }
}

/// Build the client, attach `auth`, GET `url`, and check the status — the request half
/// shared by the streamed artifact download and the small signature fetch.
///
/// The `auth` credential's token reference is resolved here (operator env) and attached
/// as a request header; an empty resolution is a clear error rather than a malformed
/// `Bearer ` header. The resolved credential never appears in an error (the header isn't
/// echoed), and neither does the resolved url ([`transport_message`]).
async fn send_request(
    location: &Location<'_>,
    auth: Option<&RemoteAuth>,
) -> Result<reqwest::Response> {
    let fetch_failed = |message: String| location.fetch_failed(message);
    let client = build_http_client(FETCH_TIMEOUT)
        .map_err(|error| fetch_failed(format!("failed to build HTTP client: {error}")))?;
    let mut request = client.get(&location.resolved);
    if let Some(auth) = auth {
        let (name, value) = auth
            .to_header(resolve_env_vars)
            .ok_or_else(|| Error::AuthUnset {
                url: location.declared.to_owned(),
            })?;
        request = request.header(name, value);
    }
    let response = request
        .send()
        .await
        .map_err(|error| fetch_failed(transport_message(error)))?;
    if !response.status().is_success() {
        return Err(fetch_failed(format!("HTTP {}", response.status())));
    }
    Ok(response)
}

/// Stream a GET body to `dest`, hashing incrementally and capping the total size.
///
/// Holds only one [`STREAM_CHUNK_BYTES`] chunk in memory regardless of artifact size,
/// and aborts past `cap` bytes, at most [`MAX_CONTENT_BYTES`] (the caller's staging
/// dir unlinks the partial). Returns the computed pin so the caller never re-reads the
/// file to hash it.
async fn fetch_to_file(
    location: &Location<'_>,
    auth: Option<&RemoteAuth>,
    dest: &Path,
    cap: u64,
) -> Result<(ContentHash, String)> {
    let fetch_failed = |message: String| location.fetch_failed(message);
    let mut response = send_request(location, auth).await?;
    let mut file = create_staged(dest)
        .await
        .map_err(|error| fetch_failed(format!("failed to open staging file: {error}")))?;
    let mut hasher = blake3::Hasher::new();
    let mut sha512 = crate::digest::Sha512::new();
    let mut total: u64 = 0;
    while let Some(chunk) = response.chunk().await.map_err(|error| {
        fetch_failed(format!("failed to read body: {}", transport_message(error)))
    })? {
        total = total.saturating_add(chunk.len() as u64);
        if total > cap {
            return Err(fetch_failed(format!("content exceeds the {cap}-byte cap")));
        }
        hasher.update(&chunk);
        sha512.update(&chunk);
        file.write_all(&chunk)
            .await
            .map_err(|error| fetch_failed(format!("failed to write staging file: {error}")))?;
    }
    file.flush()
        .await
        .map_err(|error| fetch_failed(format!("failed to flush staging file: {error}")))?;
    Ok((ContentHash::of_hash(hasher.finalize()), sha512.finish_hex()))
}

/// GET a small, bounded resource (a minisign signature) fully into memory, aborting
/// past `cap` so a hostile response can't balloon.
async fn fetch_bytes(
    location: &Location<'_>,
    auth: Option<&RemoteAuth>,
    cap: u64,
) -> Result<Vec<u8>> {
    let fetch_failed = |message: String| location.fetch_failed(message);
    let mut response = send_request(location, auth).await?;
    let mut out = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|error| {
        fetch_failed(format!("failed to read body: {}", transport_message(error)))
    })? {
        if out.len().saturating_add(chunk.len()) as u64 > cap {
            return Err(fetch_failed(format!("response exceeds the {cap}-byte cap")));
        }
        out.extend_from_slice(&chunk);
    }
    Ok(out)
}

/// Stream-hash an on-disk file (chunked, never the whole file in memory) — the cache-hit
/// integrity check — giving its blake3 and its SHA-512 from the one read. An open/read error surfaces as `Err`, which the caller treats as a
/// cache miss.
async fn hash_file(path: &Path) -> std::io::Result<(ContentHash, String)> {
    let mut file = tokio::fs::File::open(path).await?;
    let mut hasher = blake3::Hasher::new();
    let mut sha512 = crate::digest::Sha512::new();
    let mut buf = vec![0u8; STREAM_CHUNK_BYTES];
    loop {
        let n = file.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        sha512.update(&buf[..n]);
    }
    Ok((ContentHash::of_hash(hasher.finalize()), sha512.finish_hex()))
}

#[cfg(test)]
mod tests {
    /// The `minisign` whose verdict zap trusts: the absolute `ZAP_MINISIGN`, else the
    /// first executable one in an absolute `PATH` directory, and never one a package or
    /// another account could have put there, anywhere on the way to it. The directories
    /// above the test's own are read as root's (`stat_of`), since where the test runs is
    /// not the test's to choose; inside it, owners and modes are the real ones.
    #[test]
    fn minisign_is_resolved_once_and_only_from_where_no_one_else_writes() {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

        let dir = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(dir.path()).unwrap();
        let mode = |path: &std::path::Path, mode: u32| {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
        };
        let bin = |name: &str| {
            let at = dir.path().join(name);
            std::fs::create_dir_all(&at).unwrap();
            let mut up = at.clone();
            while up.starts_with(dir.path()) {
                mode(&up, 0o755);
                if !up.pop() {
                    break;
                }
            }
            let minisign = at.join("minisign");
            std::fs::write(&minisign, "#!/bin/sh\n").unwrap();
            mode(&minisign, 0o755);
            at
        };
        mode(dir.path(), 0o755);
        let good = bin("good");
        let paths = |dirs: &[&std::path::Path]| Some(std::env::join_paths(dirs).unwrap());
        let stat_of = |at: &std::path::Path| {
            if at.starts_with(&root) {
                std::fs::metadata(at).map(|meta| (meta.uid(), meta.mode()))
            } else {
                Ok((0, 0o40755))
            }
        };
        let resolve = |setting: Option<&str>, path: Option<std::ffi::OsString>| {
            super::minisign_binary(setting.map(std::ffi::OsStr::new), path.as_deref(), stat_of)
        };

        assert_eq!(
            resolve(None, paths(&[std::path::Path::new("rel"), &good])).unwrap(),
            good.join("minisign"),
            "a relative entry is skipped"
        );
        // the override wins over PATH, and must be absolute and not empty
        let other = bin("other");
        assert_eq!(
            resolve(
                Some(other.join("minisign").to_str().unwrap()),
                paths(&[&good])
            )
            .unwrap(),
            other.join("minisign")
        );
        let error = resolve(Some("minisign"), paths(&[&good])).unwrap_err();
        assert!(
            error.contains("`ZAP_MINISIGN` names minisign, which is not an absolute path"),
            "{error}"
        );
        let error = resolve(Some(""), paths(&[&good])).unwrap_err();
        assert!(error.contains("`ZAP_MINISIGN` is set but empty"), "{error}");
        let error = resolve(None, paths(&[std::path::Path::new("rel")])).unwrap_err();
        assert!(
            error.contains("no `minisign` in an absolute directory on PATH"),
            "{error}"
        );

        // an npm script's `node_modules/.bin`, found there or reached through a link
        let npm = bin("project/node_modules/.bin");
        let error = resolve(None, paths(&[&npm, &good])).unwrap_err();
        assert!(
            error.contains("inside a `node_modules` directory"),
            "{error}"
        );
        assert!(
            error.contains(&npm.join("minisign").display().to_string()),
            "{error}"
        );
        let linked = bin("linked");
        std::fs::remove_file(linked.join("minisign")).unwrap();
        std::os::unix::fs::symlink(npm.join("minisign"), linked.join("minisign")).unwrap();
        let error = resolve(None, paths(&[&linked])).unwrap_err();
        assert!(
            error.contains("inside a `node_modules` directory"),
            "{error}"
        );

        // writable by a group or by anyone: the binary, or the directory holding it
        let open = bin("open");
        for bits in [0o775, 0o757] {
            mode(&open, bits);
            let error = resolve(None, paths(&[&open])).unwrap_err();
            assert!(
                error.contains(&format!(
                    "{}: {} can be written by its group or by others",
                    open.join("minisign").display(),
                    open.display()
                )),
                "{error}"
            );
        }
        mode(&open, 0o755);
        mode(&open.join("minisign"), 0o777);
        let error = resolve(None, paths(&[&open])).unwrap_err();
        assert!(
            error.contains("can be written by its group or by others"),
            "{error}"
        );
        mode(&open.join("minisign"), 0o755);
        assert!(resolve(None, paths(&[&open])).is_ok());

        // an ancestor further up that others may write
        let deep = bin("up/deep/bin");
        mode(&dir.path().join("up"), 0o775);
        let error = resolve(None, paths(&[&deep])).unwrap_err();
        assert!(
            error.contains(&format!(
                "{} can be written by its group or by others",
                root.join("up").display()
            )),
            "{error}"
        );

        // the directory holding a link the lookup passes through
        let hop = bin("hop");
        std::fs::remove_file(hop.join("minisign")).unwrap();
        std::os::unix::fs::symlink(good.join("minisign"), hop.join("minisign")).unwrap();
        let via = bin("via");
        std::fs::remove_file(via.join("minisign")).unwrap();
        std::os::unix::fs::symlink(hop.join("minisign"), via.join("minisign")).unwrap();
        assert!(resolve(None, paths(&[&via])).is_ok(), "trusted all the way");
        mode(&hop, 0o775);
        let error = resolve(None, paths(&[&via])).unwrap_err();
        assert!(
            error.contains(&format!(
                "{} can be written by its group or by others",
                root.join("hop").display()
            )),
            "{error}"
        );

        // a directory another account owns, as `stat_of` reads it
        let theirs = |at: &std::path::Path| {
            if at == root.join("good") {
                Ok((4242, 0o40755))
            } else {
                stat_of(at)
            }
        };
        let error = super::minisign_binary(None, paths(&[&good]).as_deref(), theirs).unwrap_err();
        assert!(
            error.contains("belongs to uid 4242, neither root nor this user"),
            "{error}"
        );
    }

    /// A suffix lands at the end of the path, before a query or a fragment, whatever
    /// the url holds after them.
    #[test]
    fn a_path_suffix_goes_before_the_query_and_the_fragment() {
        for (url, suffixed) in [
            ("https://h/a.tgz", "https://h/a.tgz.minisig"),
            ("https://h/a.tgz?t=1", "https://h/a.tgz.minisig?t=1"),
            ("https://h/a.tgz#f", "https://h/a.tgz.minisig#f"),
            ("https://h/a.tgz?t=1#f?x", "https://h/a.tgz.minisig?t=1#f?x"),
        ] {
            assert_eq!(super::path_suffixed(url, ".minisig"), suffixed);
        }
    }

    use zap_types::schema::{RemoteAuth, SourceVerify};
    use zap_types::text::Text;
    use zap_types::var_ref::Segment::{Ref, Text as Lit};
    use zap_types::var_ref::{marker, shown};

    use super::{
        cache_name, cached_sha512, content_dir, minisign_verdict, resolve_content, store_content,
        unset_refs,
    };
    use crate::error::Error;

    /// A throwaway one-shot HTTP/1.1 server: serves `body` once and returns the url.
    /// Dep-free (a std `TcpListener` on a worker thread — no wiremock/httptest); we
    /// only need a single GET.
    fn serve_once(body: Vec<u8>) -> String {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            if let Ok((mut socket, _)) = listener.accept() {
                let mut buf = [0u8; 1024];
                let _ = socket.read(&mut buf); // consume the request; we don't route
                let header = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = socket.write_all(header.as_bytes());
                let _ = socket.write_all(&body);
                let _ = socket.flush();
            }
        });
        format!("http://{addr}/zig.tar.xz")
    }

    /// Cached content is owner-only, whichever way it arrived — fetched or stored —
    /// and so is every directory above it.
    #[cfg(unix)]
    #[tokio::test]
    async fn cached_content_is_owner_only() {
        use std::os::unix::fs::PermissionsExt as _;

        let mode =
            |path: &std::path::Path| std::fs::metadata(path).unwrap().permissions().mode() & 0o777;
        let home = tempfile::tempdir().unwrap();
        let body = b"hello zap".to_vec();
        let pin = blake3::hash(&body).to_hex().to_string();
        let url = serve_once(body.clone());
        let fetched = resolve_content(home.path(), &url, Some(&pin), None, None)
            .await
            .unwrap();
        assert_eq!(mode(&fetched.path), 0o600);

        let stored = store_content(home.path(), "https://x.example/other.bin", b"stored")
            .await
            .unwrap();
        let stored_dir = content_dir(home.path(), stored.as_str());
        assert_eq!(mode(&stored_dir.join("other.bin")), 0o600);
        for dir in [
            home.path().join("cache"),
            home.path().join("cache/files"),
            content_dir(home.path(), &pin),
            stored_dir,
        ] {
            assert_eq!(mode(&dir), 0o700, "{}", dir.display());
        }
    }

    #[tokio::test]
    async fn fetches_verifies_and_caches() {
        let home = tempfile::tempdir().unwrap();
        let body = b"hello zap".to_vec();
        let pin = blake3::hash(&body).to_hex().to_string();
        let url = serve_once(body.clone());

        let resolved = resolve_content(home.path(), &url, Some(&pin), None, None)
            .await
            .unwrap();
        assert_eq!(resolved.blake3.as_str(), pin.as_str());
        assert_eq!(std::fs::read(&resolved.path).unwrap(), body);
        assert!(
            resolved
                .path
                .ends_with(format!("cache/files/{pin}/zig.tar.xz"))
        );
    }

    #[tokio::test]
    async fn rejects_hash_mismatch() {
        let home = tempfile::tempdir().unwrap();
        let url = serve_once(b"actual bytes".to_vec());
        let wrong = "0".repeat(64);
        let error = resolve_content(home.path(), &url, Some(&wrong), None, None)
            .await
            .unwrap_err();
        assert!(matches!(error, Error::ContentHashMismatch { .. }));
    }

    #[tokio::test]
    async fn tracked_returns_the_computed_hash() {
        let home = tempfile::tempdir().unwrap();
        let body = b"tracked bytes".to_vec();
        let url = serve_once(body.clone());
        let resolved = resolve_content(home.path(), &url, None, None, None)
            .await
            .unwrap();
        assert_eq!(
            resolved.blake3.as_str(),
            blake3::hash(&body).to_hex().as_str()
        );
    }

    /// Like `serve_once`, but captures the raw request bytes (so a test can assert
    /// the headers we sent) and serves `body` from an `/art` path.
    fn serve_once_capture(body: Vec<u8>) -> (String, std::sync::mpsc::Receiver<Vec<u8>>) {
        use std::io::{Read, Write};
        let (tx, rx) = std::sync::mpsc::channel();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            if let Ok((mut socket, _)) = listener.accept() {
                let mut buf = [0u8; 4096];
                let n = socket.read(&mut buf).unwrap_or(0);
                let _ = tx.send(buf[..n].to_vec());
                let header = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = socket.write_all(header.as_bytes());
                let _ = socket.write_all(&body);
                let _ = socket.flush();
            }
        });
        (format!("http://{addr}/art"), rx)
    }

    #[tokio::test]
    async fn attaches_bearer_auth_header() {
        let home = tempfile::tempdir().unwrap();
        let body = b"private bytes".to_vec();
        let (url, rx) = serve_once_capture(body.clone());
        // A literal token (no reference) resolves to itself — no env needed.
        let auth = RemoteAuth::Bearer {
            token: Text::literal("secret-tok"),
        };
        let resolved = resolve_content(home.path(), &url, None, Some(&auth), None)
            .await
            .unwrap();
        assert_eq!(
            resolved.blake3.as_str(),
            blake3::hash(&body).to_hex().as_str()
        );
        // Header names are case-insensitive on the wire — lowercase before matching.
        let request = String::from_utf8_lossy(&rx.recv().unwrap()).to_lowercase();
        assert!(
            request.contains("authorization: bearer secret-tok"),
            "request must carry the bearer header: {request}"
        );
    }

    /// Like `serve_once_capture`, for one request per body in turn, each on its own
    /// connection.
    fn serve_capture(bodies: Vec<Vec<u8>>) -> (String, std::sync::mpsc::Receiver<Vec<u8>>) {
        use std::io::{Read, Write};
        let (tx, rx) = std::sync::mpsc::channel();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            for body in bodies {
                let Ok((mut socket, _)) = listener.accept() else {
                    return;
                };
                let mut buf = [0u8; 4096];
                let n = socket.read(&mut buf).unwrap_or(0);
                let _ = tx.send(buf[..n].to_vec());
                let header = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = socket.write_all(header.as_bytes());
                let _ = socket.write_all(&body);
                let _ = socket.flush();
            }
        });
        (format!("http://{addr}/art"), rx)
    }

    /// A source's `auth` goes to the signature fetch only on the source's own origin: a
    /// `signature_url` on another one is fetched with no `authorization` header, and the
    /// derived `<url>.minisig` and an explicit url on the source's origin carry it.
    #[tokio::test]
    async fn auth_reaches_a_signature_only_on_the_sources_origin() {
        let home = tempfile::tempdir().unwrap();
        let auth = RemoteAuth::Bearer {
            token: Text::literal("secret-tok"),
        };
        let verify = |signature_url: Option<&str>| -> SourceVerify {
            let mut verify = serde_json::json!({
                "scheme": "minisign",
                "public_key": "RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3",
            });
            if let Some(url) = signature_url {
                verify["signature_url"] = serde_json::json!(Text::literal(url));
            }
            serde_json::from_value(verify).unwrap()
        };
        let carries_auth = |request: Vec<u8>| {
            String::from_utf8_lossy(&request)
                .to_lowercase()
                .contains("authorization:")
        };

        // Two loopback servers are two origins (their ports differ).
        let (url, source) = serve_once_capture(b"source".to_vec());
        let (signature_url, signature) = serve_once_capture(b"not a signature".to_vec());
        let error = resolve_content(
            home.path(),
            &url,
            None,
            Some(&auth),
            Some(&verify(Some(&signature_url))),
        )
        .await
        .unwrap_err();
        assert!(
            matches!(error, Error::SignatureVerification { .. }),
            "{error:?}"
        );
        assert!(carries_auth(source.recv().unwrap()));
        assert!(!carries_auth(signature.recv().unwrap()));

        // One server: the source, then its signature, derived or named.
        let (url, requests) = serve_capture(vec![b"source".to_vec(), b"no sig".to_vec()]);
        let error = resolve_content(home.path(), &url, None, Some(&auth), Some(&verify(None)))
            .await
            .unwrap_err();
        assert!(
            matches!(error, Error::SignatureVerification { .. }),
            "{error:?}"
        );
        let (first, second) = (requests.recv().unwrap(), requests.recv().unwrap());
        assert!(String::from_utf8_lossy(&second).starts_with("GET /art.minisig "));
        assert!(carries_auth(first) && carries_auth(second));
        let (url, requests) = serve_capture(vec![b"source".to_vec(), b"no sig".to_vec()]);
        let named = format!("{url}/sig");
        let error = resolve_content(
            home.path(),
            &url,
            None,
            Some(&auth),
            Some(&verify(Some(&named))),
        )
        .await
        .unwrap_err();
        assert!(
            matches!(error, Error::SignatureVerification { .. }),
            "{error:?}"
        );
        assert!(carries_auth(requests.recv().unwrap()) && carries_auth(requests.recv().unwrap()));

        // The origins compared are the resolved ones: a signature url whose host is a
        // reference resolving to the source's host and port is on the source's origin.
        let (url, requests) = serve_capture(vec![b"source".to_vec(), b"no sig".to_vec()]);
        let host = url
            .trim_start_matches("http://")
            .trim_end_matches("/art")
            .to_owned();
        let _env = crate::resolve::test_env::set(&[("ZAP_T_SIGNATURE_HOST", &host)]);
        let named = Text::of_pieces([Lit("http://"), Ref("ZAP_T_SIGNATURE_HOST"), Lit("/sig")]);
        let mut by_reference = serde_json::to_value(verify(None)).unwrap();
        by_reference["signature_url"] = serde_json::json!(named);
        let by_reference: SourceVerify = serde_json::from_value(by_reference).unwrap();
        let error = resolve_content(home.path(), &url, None, Some(&auth), Some(&by_reference))
            .await
            .unwrap_err();
        assert!(
            matches!(error, Error::SignatureVerification { .. }),
            "{error:?}"
        );
        let (first, second) = (requests.recv().unwrap(), requests.recv().unwrap());
        assert!(String::from_utf8_lossy(&second).starts_with("GET /sig "));
        assert!(carries_auth(first) && carries_auth(second));
    }

    /// A redirect to another origin drops the credential: `reqwest` strips the
    /// `authorization` header from a hop to another scheme, host, or port, whatever the
    /// redirect policy (`tls::build_http_client`'s follows the hop).
    #[tokio::test]
    async fn a_redirect_to_another_origin_drops_the_auth() {
        use std::io::{Read, Write};
        let home = tempfile::tempdir().unwrap();
        let (end, end_requests) = serve_once_capture(b"bytes".to_vec());
        let (start_tx, start_requests) = std::sync::mpsc::channel();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let start = format!("http://{}/art", listener.local_addr().unwrap());
        std::thread::spawn(move || {
            if let Ok((mut socket, _)) = listener.accept() {
                let mut buf = [0u8; 4096];
                let n = socket.read(&mut buf).unwrap_or(0);
                let _ = start_tx.send(buf[..n].to_vec());
                let _ = socket.write_all(
                    format!(
                        "HTTP/1.1 302 Found\r\nLocation: {end}\r\nContent-Length: 0\r\n\
                         Connection: close\r\n\r\n"
                    )
                    .as_bytes(),
                );
            }
        });
        let auth = RemoteAuth::Bearer {
            token: Text::literal("secret-tok"),
        };
        resolve_content(home.path(), &start, None, Some(&auth), None)
            .await
            .unwrap();
        let header = |request: Vec<u8>| {
            String::from_utf8_lossy(&request)
                .to_lowercase()
                .contains("authorization: bearer secret-tok")
        };
        assert!(header(start_requests.recv().unwrap()));
        assert!(!header(end_requests.recv().unwrap()));
    }

    #[test]
    fn an_origin_is_a_scheme_a_host_and_a_port() {
        use super::same_origin;
        for (a, b, same) in [
            ("https://h.example/a", "https://h.example/b.minisig", true),
            ("https://h.example/a", "https://h.example:443/b", true),
            ("https://H.example/a", "https://h.example/b", true),
            ("https://h.example/a", "https://h.example:8443/b", false),
            ("https://h.example/a", "http://h.example/b", false),
            ("https://h.example:8443/a", "http://h.example:8443/b", false),
            ("x-zap://h.example/a", "x-zap://h.example/a", false),
            ("https://h.example/a", "https://sigs.h.example/b", false),
            ("https://h.example/a", "https://other.example/b", false),
            ("http://127.0.0.1:8000/a", "http://localhost:8000/b", false),
            ("https://h.example/a", "not a url", false),
        ] {
            assert_eq!(same_origin(a, b), same, "{a} ~ {b}");
        }
    }

    #[tokio::test]
    async fn empty_auth_credential_errors() {
        let home = tempfile::tempdir().unwrap();
        // A token referencing an unset variable resolves empty — a clear error, not a bogus
        // `Bearer ` header. The check fires before any network dial.
        let auth = RemoteAuth::Bearer {
            token: Text::reference("ZAP_UNSET_TOKEN_FOR_TEST_xyz"),
        };
        let error = resolve_content(
            home.path(),
            "http://127.0.0.1:1/art",
            None,
            Some(&auth),
            None,
        )
        .await
        .unwrap_err();
        assert!(matches!(error, Error::AuthUnset { .. }));
    }

    #[tokio::test]
    async fn cache_hit_is_network_free() {
        let home = tempfile::tempdir().unwrap();
        let body = b"cached bytes".to_vec();
        let pin = blake3::hash(&body).to_hex().to_string();
        // Pre-populate the content-addressed cache.
        let dir = content_dir(home.path(), &pin);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("art"), &body).unwrap();
        // A url that would fail if dialed — the hit must short-circuit before fetch.
        let resolved = resolve_content(
            home.path(),
            "http://127.0.0.1:1/art",
            Some(&pin),
            None,
            None,
        )
        .await
        .unwrap();
        assert_eq!(resolved.blake3.as_str(), pin.as_str());
    }

    /// A cached file is trusted only as far as it re-hashes to its pin: corrupt bytes
    /// under the pin's name are a miss, refetched and replaced, and digest nothing.
    #[tokio::test]
    async fn a_corrupt_cache_entry_is_a_miss() {
        let home = tempfile::tempdir().unwrap();
        let body = b"pinned bytes".to_vec();
        let pin = blake3::hash(&body).to_hex().to_string();
        let url = serve_once(body.clone());
        let cached = super::content_cache_path(home.path(), &pin, &url);
        std::fs::create_dir_all(cached.parent().unwrap()).unwrap();
        std::fs::write(&cached, b"tampered").unwrap();
        assert_eq!(cached_sha512(home.path(), &pin, &url).await, None);

        let resolved = resolve_content(home.path(), &url, Some(&pin), None, None)
            .await
            .unwrap();
        assert_eq!(resolved.blake3.as_str(), pin);
        assert_eq!(resolved.path, cached);
        assert_eq!(resolved.sha512, crate::digest::sha512_hex(&body));
        assert_eq!(std::fs::read(&cached).unwrap(), body);
        assert_eq!(
            cached_sha512(home.path(), &pin, &url).await,
            Some(crate::digest::sha512_hex(&body))
        );
    }

    /// Only minisign's exit 0 verifies a signature: a nonzero exit refuses it with what
    /// minisign printed, and a run that never started refuses it too.
    #[test]
    fn only_a_minisign_exit_0_verifies() {
        use std::os::unix::process::ExitStatusExt as _;

        let at = std::path::Path::new("/usr/bin/minisign");
        let output = |code: i32, stderr: &str| {
            Ok(std::process::Output {
                status: std::process::ExitStatus::from_raw(code << 8),
                stdout: Vec::new(),
                stderr: stderr.as_bytes().to_vec(),
            })
        };
        assert_eq!(minisign_verdict(at, output(0, "")), Ok(()));
        assert_eq!(
            minisign_verdict(at, output(1, "Signature verification failed\n")),
            Err("minisign at /usr/bin/minisign: Signature verification failed".to_owned())
        );
        let unstarted = minisign_verdict(at, Err(std::io::ErrorKind::NotFound.into())).unwrap_err();
        assert!(
            unstarted.starts_with("minisign at /usr/bin/minisign could not run ("),
            "{unstarted}"
        );
    }

    /// A signature is read up to 64 KiB and no further: one byte past the cap is
    /// refused as a fetch, naming the cap, and one at the cap reaches the check, which
    /// fails closed either way — no `minisign` to run, or one that rejects the bytes.
    #[tokio::test]
    async fn a_signature_past_its_cap_is_refused_before_the_check() {
        let home = tempfile::tempdir().unwrap();
        let verify = |signature_url: &str| -> SourceVerify {
            serde_json::from_value(serde_json::json!({
                "scheme": "minisign",
                "public_key": "RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3",
                "signature_url": Text::literal(signature_url),
            }))
            .unwrap()
        };
        for (len, over) in [(64 * 1024, false), (64 * 1024 + 1, true)] {
            let url = serve_once(b"source".to_vec());
            let signature = serve_once(vec![b'x'; len]);
            let error = resolve_content(home.path(), &url, None, None, Some(&verify(&signature)))
                .await
                .unwrap_err();
            if over {
                assert!(
                    matches!(&error, Error::Fetch { .. })
                        && error.to_string().contains("exceeds the 65536-byte cap"),
                    "{error:?}"
                );
            } else {
                assert!(
                    matches!(error, Error::SignatureVerification { .. }),
                    "{error:?}"
                );
            }
        }
    }

    /// A one-shot server answering `status` with an empty body; returns its base url.
    fn serve_status(status: &str) -> String {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let status = status.to_owned();
        std::thread::spawn(move || {
            if let Ok((mut socket, _)) = listener.accept() {
                let mut buf = [0u8; 4096];
                let _ = socket.read(&mut buf);
                let _ = socket.write_all(
                    format!("HTTP/1.1 {status}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                        .as_bytes(),
                );
                let _ = socket.flush();
            }
        });
        format!("http://{addr}")
    }

    /// Assert `text` names the url by its reference to `PATH`, spelled `reference` — the
    /// way a text of that kind holds one — and holds none of what `PATH` — set in every
    /// test process, standing in for a secret — resolves to: neither the value nor its
    /// percent-encoded form, the one a url carries it in. The whole value, not its
    /// segments: an error may rightly name a program found on `PATH`
    /// (`minisign at /usr/bin/minisign`), which shares a segment and leaks nothing.
    fn assert_names_only_the_reference(text: &str, reference: &str) {
        assert!(text.contains(reference), "the declared url: {text}");
        let path = std::env::var("PATH").expect("PATH is set");
        let encoded = path.replace(':', "%3A");
        assert!(
            !text.contains(&path) && !text.contains(&encoded),
            "resolved value {path:?} in: {text}"
        );
    }

    /// The reference to `PATH` as a `Debug` form of text holding it spells it.
    fn debugged_reference() -> String {
        format!("{:?}", marker("PATH")).trim_matches('"').to_owned()
    }

    #[tokio::test]
    async fn no_fetch_error_holds_the_resolved_url() {
        let path_ref = marker("PATH");
        let home = tempfile::tempdir().unwrap();
        let wrong = "0".repeat(64);

        // A refused request: the status error.
        let url = format!("{}/zig?token={path_ref}", serve_status("403 Forbidden"));
        let error = resolve_content(home.path(), &url, None, None, None)
            .await
            .unwrap_err();
        assert!(matches!(error, Error::Fetch { .. }), "{error:?}");
        assert!(error.to_string().contains("HTTP 403"), "{error}");
        assert_names_only_the_reference(&error.to_string(), &path_ref);
        assert_names_only_the_reference(&format!("{error:?}"), &debugged_reference());

        // A request that can't be sent: the transport error, which quotes its url.
        let error = resolve_content(
            home.path(),
            &format!("http://127.0.0.1:1/zig?token={path_ref}"),
            None,
            None,
            None,
        )
        .await
        .unwrap_err();
        assert!(matches!(error, Error::Fetch { .. }), "{error:?}");
        assert_names_only_the_reference(&error.to_string(), &path_ref);
        assert_names_only_the_reference(&format!("{error:?}"), &debugged_reference());

        // Bytes that aren't the pinned ones.
        let url = format!("{}?token={path_ref}", serve_once(b"other bytes".to_vec()));
        let error = resolve_content(home.path(), &url, Some(&wrong), None, None)
            .await
            .unwrap_err();
        assert!(
            matches!(error, Error::ContentHashMismatch { .. }),
            "{error:?}"
        );
        assert_names_only_the_reference(&error.to_string(), &path_ref);

        // A credential that resolves empty.
        let auth = RemoteAuth::Bearer {
            token: Text::reference("ZAP_UNSET_TOKEN_FOR_TEST_xyz"),
        };
        let error = resolve_content(
            home.path(),
            &format!("http://127.0.0.1:1/zig?token={path_ref}"),
            None,
            Some(&auth),
            None,
        )
        .await
        .unwrap_err();
        assert!(matches!(error, Error::AuthUnset { .. }), "{error:?}");
        assert_names_only_the_reference(&error.to_string(), &path_ref);

        // A signature that doesn't verify (or no `minisign` to check it with), and one
        // that can't be fetched — its own url is declared too.
        let url = format!("{}?token={path_ref}", serve_once(b"source".to_vec()));
        let verify = |signature_url: String| -> SourceVerify {
            serde_json::from_value(serde_json::json!({
                "scheme": "minisign",
                "public_key": "RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3",
                "signature_url": Text::from_inert(signature_url).unwrap(),
            }))
            .unwrap()
        };
        let signature = format!(
            "{}?token={path_ref}",
            serve_once(b"not a signature".to_vec())
        );
        let error = resolve_content(home.path(), &url, None, None, Some(&verify(signature)))
            .await
            .unwrap_err();
        assert!(
            matches!(error, Error::SignatureVerification { .. }),
            "{error:?}"
        );
        assert_names_only_the_reference(&error.to_string(), &path_ref);

        let url = format!("{}?token={path_ref}", serve_once(b"source".to_vec()));
        let signature = format!("{}/sig?token={path_ref}", serve_status("404 Not Found"));
        let error = resolve_content(home.path(), &url, None, None, Some(&verify(signature)))
            .await
            .unwrap_err();
        assert!(matches!(error, Error::Fetch { .. }), "{error:?}");
        assert_names_only_the_reference(&error.to_string(), &path_ref);

        // The signature url zap derives (`.minisig` appended to the path, before the
        // query) is derived from the declared one: the artifact is served, the signature
        // isn't, and the query stays a query.
        let default_signature: SourceVerify = serde_json::from_value(serde_json::json!({
            "scheme": "minisign",
            "public_key": "RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3",
        }))
        .unwrap();
        let url = format!("{}?token={path_ref}", serve_then_refuse(b"source".to_vec()));
        let error = resolve_content(home.path(), &url, None, None, Some(&default_signature))
            .await
            .unwrap_err();
        assert!(matches!(error, Error::Fetch { .. }), "{error:?}");
        assert!(
            error
                .to_string()
                .contains(&format!(".minisig?token={path_ref}")),
            "{error}"
        );
        assert_names_only_the_reference(&error.to_string(), &path_ref);

        // A body that ends before its declared length: the read error.
        let url = format!("{}?token={path_ref}", serve_short_body());
        let error = resolve_content(home.path(), &url, None, None, None)
            .await
            .unwrap_err();
        assert!(matches!(error, Error::Fetch { .. }), "{error:?}");
        assert!(error.to_string().contains("failed to read body"), "{error}");
        assert_names_only_the_reference(&error.to_string(), &path_ref);
    }

    /// A server answering its first request with `body` and its second with a 404;
    /// returns the url.
    fn serve_then_refuse(body: Vec<u8>) -> String {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            for answer in [Some(body), None] {
                let Ok((mut socket, _)) = listener.accept() else {
                    return;
                };
                let mut buf = [0u8; 4096];
                let _ = socket.read(&mut buf);
                let (status, body) =
                    answer.map_or(("404 Not Found", Vec::new()), |b| ("200 OK", b));
                let _ = socket.write_all(
                    format!(
                        "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        body.len()
                    )
                    .as_bytes(),
                );
                let _ = socket.write_all(&body);
                let _ = socket.flush();
            }
        });
        format!("http://{addr}/zig.tar.xz")
    }

    /// A one-shot server that declares a longer body than it sends; returns the url.
    fn serve_short_body() -> String {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            if let Ok((mut socket, _)) = listener.accept() {
                let mut buf = [0u8; 4096];
                let _ = socket.read(&mut buf);
                let _ = socket.write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\nConnection: close\r\n\r\nshort",
                );
                let _ = socket.flush();
            }
        });
        format!("http://{addr}/zig.tar.xz")
    }

    #[tokio::test]
    async fn a_fetch_whose_url_has_an_unset_reference_is_refused() {
        // Fetched anyway, the reference would resolve to nothing and the bytes of
        // another url would be returned as this one's. The server would answer: the
        // refusal is what keeps the request from being made.
        let home = tempfile::tempdir().unwrap();
        for name in ["ZAP_TEST_UNSET_SECRET_TOKEN", "ZAP_TEST_UNSET_BASE"] {
            let url = format!("{}?v={}", serve_once(b"bytes".to_vec()), marker(name));
            let error = resolve_content(home.path(), &url, None, None, None)
                .await
                .unwrap_err();
            assert!(
                matches!(&error, Error::FetchVarUnset { vars, .. } if vars == name),
                "{error:?}"
            );
            assert_eq!(error.exit_code(), 2);
            assert!(error.to_string().contains(&url), "{error}");
        }

        // A signature url is fetched too.
        let url = serve_once(b"source".to_vec());
        let verify: SourceVerify = serde_json::from_value(serde_json::json!({
            "scheme": "minisign",
            "public_key": "RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3",
            "signature_url": Text::of_pieces([
                Lit("http://127.0.0.1:1/sig?t="),
                Ref("ZAP_TEST_UNSET_SECRET_TOKEN"),
            ]),
        }))
        .unwrap();
        let error = resolve_content(home.path(), &url, None, None, Some(&verify))
            .await
            .unwrap_err();
        assert!(matches!(error, Error::FetchVarUnset { .. }), "{error:?}");

        // A cache hit fetches nothing, so it needs no reference set.
        let body = b"cached bytes".to_vec();
        let pin = blake3::hash(&body).to_hex().to_string();
        let dir = content_dir(home.path(), &pin);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("art"), &body).unwrap();
        resolve_content(
            home.path(),
            &format!(
                "http://127.0.0.1:1/art?t={}",
                marker("ZAP_TEST_UNSET_SECRET_TOKEN")
            ),
            Some(&pin),
            None,
            None,
        )
        .await
        .unwrap();
    }

    #[test]
    fn an_empty_reference_is_as_unset_as_a_missing_one() {
        let env = |name: &str| match name {
            "SET" => Some("value".to_owned()),
            "EMPTY" => Some(String::new()),
            _ => None,
        };
        assert_eq!(
            unset_refs(
                &format!(
                    "https://{set}/{missing}/zig?t={empty}&u={set}",
                    set = marker("SET"),
                    missing = marker("MISSING"),
                    empty = marker("EMPTY")
                ),
                env
            ),
            ["EMPTY", "MISSING"]
        );
        assert!(unset_refs("https://files.example.com/zig", env).is_empty());
    }

    #[test]
    fn the_cache_name_is_one_safe_component_of_the_declared_url() {
        assert_eq!(cache_name("https://x/artifacts/zig.tar.xz"), "zig.tar.xz");
        assert_eq!(
            cache_name("https://x/artifacts/zig.tar.xz?v=1/2#a/b"),
            "zig.tar.xz"
        );
        assert_eq!(cache_name("https://x/a/b/ghostty/"), "ghostty");
        // A reference is named, never resolved — its value is no part of a file name —
        // and the name it is given holds no delimiter.
        assert_eq!(
            cache_name(&format!(
                "https://x/dl/{}?sig={}",
                marker("DOWNLOAD_TOKEN"),
                marker("SIG")
            )),
            shown("DOWNLOAD_TOKEN")
        );
        assert_eq!(
            cache_name(&format!("https://x/dl/v{}.tar.xz", marker("VERSION"))),
            "v{env:VERSION}.tar.xz"
        );
        for malformed in ["https://x/a\u{fdd0}b", "https://x/\u{fdd1}", "\u{fdd0}X"] {
            assert!(
                !zap_types::var_ref::holds_delimiter(&cache_name(malformed)),
                "{malformed:?}"
            );
        }
        // Nothing that names another directory, or none.
        for url in [
            "",
            "/",
            "///",
            "?q",
            "https://x/a/..",
            "https://x/a/./",
            "..",
        ] {
            assert_eq!(cache_name(url), "content", "{url:?}");
        }
    }

    #[tokio::test]
    async fn a_secret_in_the_urls_last_segment_is_on_no_cache_path() {
        // `PATH` stands in for the secret; the one-shot server answers any path.
        let path_ref = marker("PATH");
        let named = shown("PATH");
        let home = tempfile::tempdir().unwrap();
        let body = b"downloaded".to_vec();
        let pin = blake3::hash(&body).to_hex().to_string();
        let base = serve_once(body.clone());
        let base = base.trim_end_matches("/zig.tar.xz");
        let url = format!("{base}/dl/{path_ref}");

        let resolved = resolve_content(home.path(), &url, None, None, None)
            .await
            .unwrap();
        assert_eq!(resolved.path, content_dir(home.path(), &pin).join(&named));
        assert_names_only_the_reference(&resolved.path.to_string_lossy(), &named);

        // Detection reads and warms the cache by the same url, so it finds those bytes…
        assert_eq!(
            cached_sha512(home.path(), &pin, &url).await,
            Some(crate::digest::sha512_hex(&body))
        );
        // …and a read it stores is the file a fetch would have written.
        let other = tempfile::tempdir().unwrap();
        store_content(other.path(), &url, &body).await.unwrap();
        assert!(content_dir(other.path(), &pin).join(&named).is_file());
        let hit = resolve_content(other.path(), &url, Some(&pin), None, None)
            .await
            .unwrap();
        assert_eq!(hit.path, content_dir(other.path(), &pin).join(&named));

        // A cache write that fails names its path: the declared segment again.
        let blocked = tempfile::tempdir().unwrap();
        let taken = content_dir(blocked.path(), &pin).join(&named);
        std::fs::create_dir_all(taken.join("occupied")).unwrap();
        let url = format!("{}/dl/{path_ref}", {
            let base = serve_once(body.clone());
            base.trim_end_matches("/zig.tar.xz").to_owned()
        });
        let error = resolve_content(blocked.path(), &url, None, None, None)
            .await
            .unwrap_err();
        assert!(matches!(error, Error::CacheWrite { .. }), "{error:?}");
        assert_names_only_the_reference(&error.to_string(), &named);
    }

    /// A url is held to the fetch rule as it resolved, before any request: the error
    /// names the url as declared, says what is wrong, and holds no resolved value.
    #[tokio::test]
    async fn a_url_zap_would_not_fetch_is_refused_before_any_request() {
        let home = tempfile::tempdir().unwrap();
        for (url, problem) in [
            (
                "http://192.0.2.1/a.tar.gz".to_owned(),
                "is not an `https://` URL",
            ),
            ("file:///etc/passwd".to_owned(), "is not an `https://` URL"),
            (
                "https://user:pass@192.0.2.1/a".to_owned(),
                "holds a user or a password before its host",
            ),
            // `CARGO_PKG_NAME` is set while tests run: the url resolves to `zap_core://…`.
            (
                format!("{}://192.0.2.1/a", marker("CARGO_PKG_NAME")),
                "is not an `https://` URL",
            ),
        ] {
            let error = resolve_content(home.path(), &url, None, None, None)
                .await
                .unwrap_err();
            assert!(matches!(error, Error::Config(_)), "{error:?}");
            assert_eq!(error.exit_code(), 2);
            let message = error.to_string();
            assert!(
                message.contains(&format!("cannot fetch {url}: the URL {problem}")),
                "{message}"
            );
            assert!(!message.contains("zap_core"), "{message}");
        }
    }
}
