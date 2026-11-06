//! Shared test helpers for the `zap` integration suite.

#![allow(dead_code)] // each suite uses its own share of these

pub use crate::scratch::fgro;

/// Is there a test `fgro` (`ZAP_FGRO`, which the `zap` the tests run reads too)? The
/// config-eval tests require it and check nothing without it; `required_programs.rs`
/// is the test that fails there.
pub fn fgro_available() -> bool {
    fgro().is_some()
}
