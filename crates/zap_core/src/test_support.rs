//! Fixtures the unit tests share.

use zap_types::plan::{LocalAccount, Machine};

/// The machine zap runs on, as a fixture names it.
pub fn local_machine() -> Machine {
    Machine::Local(LocalAccount {
        user: "op".to_owned(),
        home: Some("/home/op".to_owned()),
    })
}
