//! Layer-1 conformance: the TypeScript authoring library's kitchen-sink config
//! must round-trip through the `fgro` eval and parse against the serde schema.
//!
//! This is the Rust half of the harness that keeps the hand-written TypeScript types
//! (`src/lib/{zap,schema}.ts`) honest against `zap_types::schema` with no codegen
//! dependency (no schemars / ts-rs):
//!
//!   - **Honesty** — `eval_config` on `src/test/fixtures/kitchen_sink_config.ts`
//!     must be `Ok`. The fixture is typechecked against `ZapBuilder` by
//!     `gro typecheck`; here it is *also* eval'd and parsed against `ZapConfig`,
//!     so a shape the TS types accept but the schema rejects (or vice-versa) fails
//!     loudly here.
//!   - **Coverage** — the fixture exercises every `ResourceType` variant, asserted
//!     against `ResourceType::ALL`, so the honesty check can't pass by omission (a
//!     kind the fixture never declares is never round-tripped).
//!
//! fgro-gated like `config_eval.rs`: it checks nothing where `ZAP_FGRO` is unset, and
//! `required_programs.rs` fails there.

#![expect(
    clippy::panic,
    reason = "test helpers outside `#[test]` fns panic on a failed setup or check"
)]

mod common;
mod scratch;

use std::collections::BTreeSet;
use std::path::PathBuf;

use common::{fgro_available, pinned};
use zap_core::config::eval_config;
use zap_types::schema::ResourceType;

/// Resolve the TS library's kitchen-sink fixture from this crate's manifest dir
/// (`crates/zap_core` → repo root → `src/test/fixtures/...`), canonicalized so a
/// missing fixture fails loudly here rather than as a confusing eval error.
fn kitchen_sink_path() -> PathBuf {
    let raw = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../src/test/fixtures/kitchen_sink_config.ts");
    std::fs::canonicalize(&raw)
        .unwrap_or_else(|e| panic!("kitchen-sink fixture not found at {}: {e}", raw.display()))
}

/// The kitchen-sink config must eval + parse against the schema (honesty), and the
/// parsed resources must cover every `ResourceType` variant (coverage). One test so
/// the two assertions share the single (fgro-spawning) eval.
#[tokio::test]
async fn kitchen_sink_round_trips_and_covers_every_resource_type() {
    if !fgro_available() {
        eprintln!(
            "skipping kitchen_sink_round_trips_and_covers_every_resource_type: ZAP_FGRO not set"
        );
        return;
    }
    let path = kitchen_sink_path();

    // Honesty: a shape the TS types accept but the serde schema rejects fails here.
    let config = match eval_config(&path, pinned()).await {
        Ok(config) => config,
        Err(error) => panic!(
            "kitchen-sink config must eval + parse against the schema, but failed: {error}\n\
             (a shape the TS `ZapBuilder` types accept that the Rust `ZapConfig` schema \
             rejects is the finding — fix the divergent side, don't loosen the fixture)"
        ),
    };

    // Loud floor: every resource kind appears at least once (15 variants), plus the
    // duplicate-exercising resources (two users, four files). A missing fixture or a
    // truncated config trips this before the per-variant check below.
    assert!(
        config.resources.len() >= 15,
        "kitchen-sink must declare at least one resource per kind (>= 15), got {}",
        config.resources.len()
    );

    // Coverage: collect the kind of each parsed resource and require every variant.
    let kinds: BTreeSet<&'static str> =
        config.resources.iter().map(|r| r.kind().as_str()).collect();
    for variant in ResourceType::ALL {
        assert!(
            kinds.contains(variant.as_str()),
            "kitchen-sink missing {} — the conformance fixture must exercise every \
             ResourceType so the honesty round-trip can't pass by omission",
            variant.as_str()
        );
    }
}
