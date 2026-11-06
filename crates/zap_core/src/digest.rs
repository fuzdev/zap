//! SHA-512 digests as lowercase hex — the one spelling the batch records, the `file`
//! detector's desired side, the content cache, and the Local runner's native reads share,
//! so a digest computed in any of them compares equal to `sha512sum`'s.

use std::fmt::Write as _;

/// SHA-512 of `bytes`, lowercase hex.
pub fn sha512_hex(bytes: &[u8]) -> String {
    let mut sha512 = Sha512::new();
    sha512.update(bytes);
    sha512.finish_hex()
}

/// A streaming SHA-512, for content read in chunks.
///
/// The one place zap computes SHA-512 — through `ring`, already in the graph as the TLS
/// provider (`crate::tls`) — so the backend is this module's choice alone.
pub struct Sha512(ring::digest::Context);

impl Sha512 {
    /// An empty digest.
    pub fn new() -> Self {
        Self(ring::digest::Context::new(&ring::digest::SHA512))
    }

    /// Feed the next chunk.
    pub fn update(&mut self, chunk: &[u8]) {
        self.0.update(chunk);
    }

    /// The digest of everything fed, lowercase hex.
    pub fn finish_hex(self) -> String {
        hex(self.0.finish().as_ref())
    }
}

impl Default for Sha512 {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for Sha512 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Sha512")
    }
}

/// `bytes` as lowercase hex.
pub fn hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut hex, byte| {
            let _ = write!(hex, "{byte:02x}");
            hex
        })
}

#[cfg(test)]
mod tests {
    use super::sha512_hex;

    /// Chunked input digests as the whole does.
    #[test]
    fn streaming_matches_one_shot() {
        let mut sha512 = super::Sha512::new();
        sha512.update(b"h");
        sha512.update(b"");
        sha512.update(b"i\n");
        assert_eq!(sha512.finish_hex(), sha512_hex(b"hi\n"));
    }

    #[test]
    fn matches_sha512sum() {
        // `printf 'hi\n' | sha512sum`
        assert_eq!(
            sha512_hex(b"hi\n"),
            "d78abb0542736865f94704521609c230dac03a2f369d043ac212d6933b91410e\
             06399e37f9c5cc88436a31737330c1c8eccb2c2f9f374d62f716432a32d50fac"
        );
    }
}
