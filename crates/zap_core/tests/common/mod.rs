//! Shared test helpers for the `zap_core` integration suite.

#![allow(dead_code)] // each suite uses its own share of these

use std::sync::OnceLock;

use zap_core::config::eval::PinnedFgro;
use zap_types::plan::{LocalAccount, Machine};
use zap_types::scalar::ContentHash;

use crate::scratch;

pub use crate::scratch::fgro;

/// Is there a test `fgro` (`ZAP_FGRO`)? The config-eval tests require it and check
/// nothing without it; `required_programs.rs` is the test that fails there.
pub fn fgro_available() -> bool {
    fgro().is_some()
}

/// The test `fgro` with its pin and no pin cache, for a direct `eval_config`. Panics
/// without a test `fgro`: call it only past an [`fgro_available`] gate.
pub fn pinned() -> PinnedFgro<'static> {
    static PIN: OnceLock<ContentHash> = OnceLock::new();
    PinnedFgro {
        path: fgro().expect("ZAP_FGRO names an fgro build"),
        pin: PIN.get_or_init(|| ContentHash::new(scratch::fgro_pin()).expect("a blake3")),
        pin_cache: None,
    }
}

/// The test `fgro`'s toolchain pin, for a lock a test writes itself.
pub fn toolchain() -> Option<zap_types::lock::Toolchain> {
    fgro_available().then(|| zap_types::lock::Toolchain {
        fgro_blake3: ContentHash::new(scratch::fgro_pin()).expect("a blake3"),
    })
}

/// The machine zap runs on, as a fixture names it.
pub fn local_machine() -> Machine {
    Machine::Local(LocalAccount {
        user: "op".to_owned(),
        home: Some("/home/op".to_owned()),
    })
}
