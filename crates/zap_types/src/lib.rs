//! `zap_types` — the pure domain model for Zap convergence.
//!
//! IO-free by construction: no `tokio`, process, or network, and no `uuid` /
//! `time` / `getrandom`. This is the crate that *produces the plan fact*, so it
//! carries no ambient authority and cannot gain any — everything here is data or
//! a pure transform (the Describe + Plan halves of Describe → Detect → Plan →
//! Apply → Observe). Determinism is enforced by the crate graph: with no clock
//! and no RNG in the dependency set, a plan literally cannot vary run-to-run.
//!
//! The module map, the plan fact, and the modeling principles are in this crate's
//! `CLAUDE.md`.

pub mod claim;
pub mod config_hash;
pub mod deploy;
pub mod deploy_preview;
pub mod detected;
pub mod diff_view;
pub mod error_code;
pub mod eval_inputs;
pub mod event;
pub mod extract;
pub mod fetch_url;
pub mod last_run;
pub mod lock;
pub mod observe;
pub mod package_managers;
pub mod plan;
pub mod postgres;
pub mod put;
pub mod scalar;
pub mod schema;
pub mod secrecy;
pub mod service_managers;
pub mod shell;
pub mod text;
pub mod validate;
pub mod var_ref;
