//! Shared test helpers for the `zap_types` integration suites.

use zap_types::plan::{LocalAccount, Machine};

/// The machine zap runs on, as a fixture names it.
pub fn local_machine() -> Machine {
    Machine::Local(local_account())
}

/// The account the local fixture machine runs as.
pub fn local_account() -> LocalAccount {
    LocalAccount {
        user: "op".to_owned(),
        home: Some("/home/op".to_owned()),
    }
}
