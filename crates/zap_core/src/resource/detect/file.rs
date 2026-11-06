//! `file` — the IO half of its observe → interpret detection: the desired side its
//! queries compare against, and the one read the batch can't make.
//!
//! The reads and the verdict are pure (`zap_types::observe::file`). This module builds
//! the [`FileDesired`] they compare against:
//!
//! - `inline` / `template`: the SHA-512 of the rendered bytes (references resolved from
//!   the operator's env; `~` / `$HOME` stay literal — content text, not a target path);
//!   a template value the executor would refuse (`resolve_template`) holds the file;
//! - `source`: the resolved source path, whose digest the batch reads beside the target's;
//! - `remote`: the pin — the declared `blake3` (vendored) wins, else the lock's (tracked),
//!   else nothing to compare against, which holds. For `extract: none` it looks the pinned
//!   bytes up in the content cache (`<zap_home>/cache/files/<blake3>/<name>`, the
//!   resolver's layout): bytes that hash to the pin give the SHA-512 the target's digest
//!   must match, so only a digest crosses the wire. With none cached, the target's bytes
//!   are read raw after the batch (hex framing would double the transfer), their blake3
//!   compared to the pin, and — when they match — stored in the content cache, so the
//!   next pass compares digests. Never a fetch: detection is network-free.

use std::path::{Path, PathBuf};

use zap_types::config_hash::extract_provenance;
use zap_types::detected::Detection;
use zap_types::observe::QueryResult;
use zap_types::observe::file::{self as observe_file, FileDesired, FileStep};
use zap_types::scalar::ContentHash;
use zap_types::schema::{ExtractMode, FileContent, FileResource, ResourceId};
use zap_types::text::Text;

use crate::connection::Connection;
use crate::digest::sha512_hex;
use crate::resolve::resolve_template;
use crate::resolver;

/// A `file` resource ready to detect: its resolved path and desired side.
#[derive(Debug)]
pub(super) struct FileCheck<'a> {
    /// The declared resource (its managed mode/owner/group).
    pub file: &'a FileResource,
    /// The resolved target path.
    pub path: String,
    /// What the target is compared against.
    pub desired: FileDesired,
    /// Where an uncached `remote` file's matching bytes are stored: the content-cache
    /// root and the url, as declared, they are the bytes of.
    warm: Option<(PathBuf, Text)>,
}

impl<'a> FileCheck<'a> {
    /// Build the desired side for `file` at its resolved `path`. `lock_pin` is a tracked
    /// `remote` file's pin from the lock; `zap_home` the `~/.zap` root whose content
    /// cache an `extract: none` file's pin is looked up in (`None`: no cache, so the
    /// target's bytes are compared directly).
    pub(super) async fn new(
        conn: &Connection,
        file: &'a FileResource,
        id: &ResourceId,
        path: String,
        lock_pin: Option<&str>,
        zap_home: Option<&Path>,
    ) -> Self {
        let mut warm = None;
        let desired = match &file.content {
            FileContent::Remote(remote) => {
                match remote.blake3.as_deref().or(lock_pin) {
                    None => FileDesired::Unpinned { id: id.0.clone() },
                    Some(pin) => match remote.extract {
                        ExtractMode::TarXz { .. } | ExtractMode::TarGz { .. } => {
                            FileDesired::Extracted {
                                provenance: extract_provenance(pin, remote.extract),
                            }
                        }
                        ExtractMode::None => {
                            // The resolver finds a url's cached bytes by the url as
                            // declared, the way it stores a fetch.
                            let cached = match zap_home {
                                Some(home) => resolver::cached_sha512(home, pin, &remote.url).await,
                                None => None,
                            };
                            cached.map_or_else(
                                || {
                                    warm = zap_home
                                        .map(|home| (home.to_path_buf(), remote.url.clone()));
                                    FileDesired::RemoteUncached {
                                        pin: pin.to_owned(),
                                    }
                                },
                                |sha512| FileDesired::Remote { sha512 },
                            )
                        }
                    },
                }
            }
            FileContent::Source { path: source } => match conn.apply_home(source) {
                Ok(path) => FileDesired::Source { path },
                Err(error) => FileDesired::SourceUnresolved {
                    error: error.to_string(),
                },
            },
            FileContent::Inline { content } => FileDesired::Rendered {
                sha512: sha512_hex(content.as_bytes()),
            },
            // A value the executor would refuse to write holds the file, by the variable
            // that holds it: no bytes it could write to compare against.
            FileContent::Template(template) => match resolve_template(template) {
                Ok(content) => FileDesired::Rendered {
                    sha512: sha512_hex(content.as_bytes()),
                },
                Err(error) => FileDesired::Unrenderable {
                    reason: format!("detection failed: the template was not rendered: {error}"),
                },
            },
        };
        Self {
            file,
            path,
            desired,
            warm,
        }
    }

    /// The verdict from the answers to this file's queries — reading the target's bytes
    /// first when the batch can't settle the content (an uncached `remote` file).
    pub(super) async fn conclude(&self, conn: &Connection, results: &[QueryResult]) -> Detection {
        match observe_file::interpret(self.file, &self.path, &self.desired, results) {
            FileStep::Done(detection) => detection,
            FileStep::CompareBytes => {
                let FileDesired::RemoteUncached { pin } = &self.desired else {
                    return zap_types::observe::unexpected_answer(0);
                };
                let observed = match conn.read_bytes(&self.path).await {
                    Ok(bytes) => {
                        let observed = ContentHash::of_bytes(&bytes);
                        if observed.as_str() == pin
                            && let Some((home, url)) = &self.warm
                        {
                            // Advisory: a failed write leaves the next pass reading raw.
                            let _ = resolver::store_content(home, url, &bytes).await;
                        }
                        Some(observed)
                    }
                    Err(_) => None,
                };
                observe_file::interpret_pin(
                    self.file,
                    &self.path,
                    &self.desired,
                    observed.as_ref().map(ContentHash::as_str),
                    results,
                )
            }
        }
    }
}
