# zap_core

> The IO convergence engine over the pure `zap_types` plan.

Everything with ambient authority lives here: config eval (a pinned `fgro eval`
via the shared `fuz_eval` crate), detection, the planner's IO half,
execution over a `Connection`, secrets, the lock, the last-run report, content
resolution, and event emission. The pure plan fact comes from `zap_types`; this
crate detects, diffs (via `zap_types`), executes, and emits.

Deps: `zap_types`, `fuz_eval`, `thiserror`, `tokio`, `serde` / `serde_json`,
`blake3`, `time`, `reqwest` + `rustls` (with `ring` as the provider, installed by
`tls.rs`), `ring` (operator-side SHA-512, only through `digest.rs`), `nix`, `rustix`
(`lgetxattr` only, for a file's access list), `tempfile`. The
`[dependencies]` comments in `Cargo.toml` say what each is for.

## Modules

A map; each module's `//!` doc and its items' rustdoc are the detail.

- `commands` (`commands/`) — the command cores (`run_plan`, `run_apply`,
  `run_detect`, `run_status`, `run_deploy`, `run_lock`, `run_lock_check`,
  `run_update`, `run_config_validate`). Each convergence, deploy, lock-check and
  update core returns a report with its own `exit_code`; `run_lock` and
  `run_config_validate` succeed or return an `Error`. The `render_*` builders
  are pure. `deploy/` is the release push,
  `prompt.rs` the terminal confirmation rule. The pieces the cores share:
  `target.rs` (the two eval seams, the private `config_gates`, and binding the
  target), `detect_pass.rs` (the detection pass, its record, and the diff),
  `checks.rs` (the structural and env gates, the plan's findings, and the
  verdict and refusal banners), and `render.rs` (the plan renders).
- `config` (`config/`) — `eval` (`eval_config`: the raw `fuz_eval` call with
  `DRIVER_JS` read from `builder_fgro.js`, `map_eval_error` onto Zap's `Error`, the
  `ZapConfig` parse), `eval_cache` (`eval_cached`, the L0 eval cache every command
  core goes through: a manifest from fgro's module graph, re-validated on lookup),
  and `fgro` (the `--fgro` / `ZAP_FGRO` setting, the lock's toolchain pin, the pin
  cache). `builder.js` and the driver's roles: `DRIVER_JS`'s rustdoc.
- `connection` (`connection/`) — the `Connection` enum (`Local` / `Ssh` / `Mock`):
  command runs, the native-first local file ops (`local_put.rs`: writes, directory
  creation, directory attributes) and the `sudo` scripts over SSH, and `observe/`,
  which runs a pass's batches per lane under their deadlines.
- `resource` (`resource/`) — detection and execution of each kind over a
  `Connection`; `pending.rs` is the pending-trigger markers under
  `/var/lib/zap/pending/`.
- `resolve` — runtime string resolution: the checked command, `env` value, and SQL
  identifier forms (refusing by variable name), and the strict env-file reader.
- `resolver` — content resolution for `remote` files, `build` sources and `apt_repo` keys (`resolve_content_within` caps a fetch):
  fetch-and-hash into the content-addressed cache, minisign verification.
- `lock` (`lock/`) — `zap.lock` IO (`update_zap_lock` / `write_zap_lock`, under one
  `flock` on the lock file confirmed to still be the file at its path), the cold-start mint (`resolve_lock`), and
  `inspect_lock` / `classify_lock` for the read-only commands.
- `secret` (`secret/`) — the masker: registers each secret reference's value and
  masks it out of everything printed or written.
- `last_run`, `deploy_preview` — the IO of the two records under `~/.zap` (shapes and
  review rules: `zap_types`).
- `home` — the `~/.zap` layout and its ownership checks.
- `escape` — what makes printed text safe to read (`escape_line`, `render_block`,
  `escape_json_line`).
- `event` — event emission (`EventHandler`, masked at the boundary by
  `mask_handler`).
- `error` — the engine `Error`, its exit codes, `hint()`, masking, and `render()`;
  `error_code()` and `io_error_code` classify a failed change (a native io error by
  its kind, a script's exit status and stderr, or bare text, by
  `zap_types::error_code::classify_error`).
- `digest` — Zap's only operator-side SHA-512 (the target computes its own with
  `sha512sum`). `tls` — `build_http_client`, the one HTTP client
  seam and its redirect policy.

Not built: `dag` (one layered scheduler shared by resources and pipeline steps);
execution is sequential. The `event` module streams to stdout JSON-lines and keeps
no run log under `~/.zap`.

## Command invariants

- **Two tiers.** `plan` / `apply` / `status` are the convergence roles; `detect` is a
  stage inspector one level down (the detect half of `run_plan`, rendered raw).
  `deploy` is a sibling imperative act with a pure `DeployPlan`. `lock` / `update`
  are the lock verbs.
- **One gate seam.** Every core reads its config through `eval_target` or
  `eval_untargeted`, which read the toolchain pin from `zap.lock` first (`zap lock` passes the
  pin it computed, `zap lock --check` the lock's once checked: `PinFrom::Given`), and both run the private `config_gates` (the secret gate and
  the structural gate, `validate_config_structure`), so no core holds an ungated
  `ZapConfig`. `zap config validate` is that seam plus a resource count. A wetrun
  adds the env gate (`unresolved_env_message`); `--skip-preflight` skips none of
  these.
- **Not-established outranks established.** A comparing dry run with an unset
  reference is `unverifiable`; a resource detection couldn't read is held
  (`PlanResult::held`) as `undetermined`, and so is each change held behind it
  (`HoldCause`). Both lead the render and exit 1, outranking
  0 and 2; deploy's preflight bails with exit 2. Warnings carry only narrative.
- **Read-only commands validate the lock, never mint it.** `plan`, `detect`,
  `status`, and `deploy` inspect it and withhold any pin that isn't current, so its
  resource holds; only `apply` (and the lock verbs) mint. Apply's `LockStale` /
  `LockUnverifiable` are errors (exit 2), not verdicts.
- **Every detection pass over an identified host writes the last-run report**
  (none for a masked host or a failed pass; the write is advisory), and every
  command's exit code comes from its report, or from the `Error` it returns —
  the bin maps, it doesn't decide. The codes are `docs/cli.md`'s.
- **The engine reads no configuration-bearing env var.** Everything
  environment-dependent is a config-declared reference; its own reads (`HOME`,
  `PATH`, `ZAP_HOME`, `ZAP_EVAL_CACHE*`) feed no plan. `ZAP_FGRO` is read
  through `config::fgro::fgro_setting` (tests aside), which the bin calls, and
  passed to the cores as a parameter. `ZAP_MINISIGN` is read by the bin and
  recorded once for the process (`resolver::set_minisign_setting`), which the
  signature check reads.

## Testing

The suite is **hermetic — no external/remote network dependency**. Command execution
mocks through `MockConnection`; fetch tests serve bytes from a one-shot
`std::net::TcpListener` on loopback. Tests that need `busybox`, `git`, `setfacl`,
or `getfacl` skip without it, and tests that evaluate a config skip without
`ZAP_FGRO` (an `fgro` build, passed to the cores as their `fgro` parameter;
`scratch_tempdir` and `scratch_write_config` give a config its project and its
lock's toolchain pin); `tests/required_programs.rs` fails when one is missing
unless `ZAP_TEST_ALLOW_NO_FGRO=1` / `ZAP_TEST_ALLOW_NO_BUSYBOX=1` /
`ZAP_TEST_ALLOW_NO_GIT=1` / `ZAP_TEST_ALLOW_NO_SETFACL=1` /
`ZAP_TEST_ALLOW_NO_GETFACL=1` is set. Real targets are the VM procedure in
`docs/testing.md` and `cargo xtask differential` (`docs/differential.md`). A
network-mock or live-fetch dep is a dependency-gate decision. Shell snippets, the
put/extract scripts, and command framing run under the system sh and under
BusyBox in `connection/observe/tests/` (`parity.rs`, `snippets.rs`, `steps.rs`,
`put.rs`, `extract.rs`, `framing.rs`); a new probe snippet or root script gets
a case there. A test of what a write keeps or a made directory inherits takes its
directory from `test_scratch::tempdir` (under the build's target directory), since
below `/tmp` nothing is kept. `tests/renders.rs` fails for a render fn missing from its
hostile-string table.

## Conventions

See the [fuz-stack skill](https://docs.fuz.dev/skills/fuz-stack) for shared Rust/workspace conventions. snake_case functions,
PascalCase types; `# Errors` docs on fallible public functions.
