//! `zap_core` — the IO convergence engine over the pure `zap_types` plan.
//!
//! Everything that touches a clock, the filesystem, a process, or the network
//! lives here: config eval (a pinned `fgro eval`), detection, the planner's
//! IO half, execution over a `Connection`, secrets, the lock, the last-run
//! report, content resolution, and event emission. The pure plan fact comes from
//! `zap_types`.
//!
//! Command *cores* (`run_plan`, `run_status`, …) live in `commands` and return
//! data; the `zap` binary parses args, calls a core, and renders.

pub mod commands;
pub mod config;
pub mod connection;
pub mod deploy_preview;
mod digest;
pub mod error;
pub mod escape;
pub mod event;
pub mod home;
pub mod last_run;
pub mod lock;
pub mod resolve;
pub mod resolver;
pub mod resource;
pub mod secret;
#[cfg(test)]
mod test_scratch;
#[cfg(test)]
mod test_support;
mod tls;

// Not built:
//   dag       — layered scheduler (resources / detection / pipeline steps)
// `event` streams to stdout JSON-lines; no run log is kept.
