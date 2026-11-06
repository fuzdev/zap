# Contributing

How to build, check, and test Zap when you are changing it. The project-wide
guidelines and code of conduct are at
[fuz.dev/contributing](https://www.fuz.dev/contributing). To install Zap for
use, see [install.md](./install.md).

## Builds

| Command | Produces |
|---|---|
| `cargo xtask install` | a release build at `~/.zap/bin/zap`, the binary on your `PATH` |
| `cargo build -p zap` | a debug binary at `target/debug/zap` |
| `cargo xtask build-musl` | static binaries for `x86_64` and `aarch64` Linux at `target/<triple>/release/zap`, with no glibc dependency (needs `zig` and `cargo-zigbuild`); evaluating a config still needs an `fgro` that runs on that machine |

## Checks

```sh
cargo clippy --workspace --all-targets -- -D warnings   # the engine's lints
cargo test --workspace                   # the engine's suite
gro check                                # the site and the TypeScript surface
cargo fmt -p zap -p zap_core -p zap_types -p xtask   # format the engine
cargo xtask check-release                # production binaries link no test or audit crate
RUSTDOCFLAGS='-D warnings' cargo doc --workspace --no-deps --all-features --document-private-items  # the docs build
```

CI runs each of these as a gate, a warning from clippy or rustdoc included, and
runs the suite a second time under `umask 000`, since a mode the tests assert is
only as strict as the umask their files are made under.

Run `npm ci` before `gro check`. After an engine change, run
`cargo xtask install`: the `zap` on your `PATH` is whatever was last installed,
and a stale one mis-plans in ways that look like config bugs.

Format with the packages named, never `cargo fmt --all`: rustfmt follows the
path dependencies into the sibling `fuz` checkout and would reformat its files.

### The hermetic suites

Nothing in them reaches a remote host. A test that runs an external program
checks nothing where the program is missing, so each crate's
`required_programs` test fails there instead, unless `ZAP_TEST_ALLOW_NO_<NAME>=1`
says the absence is expected:

| Crate | Programs |
|---|---|
| `zap` | `fgro` (`ZAP_FGRO`), `git` |
| `zap_core` | `fgro` (`ZAP_FGRO`), `busybox`, `git`, `setfacl`, `getfacl` |
| `xtask` | `openssl`, `curl`, `busybox` |

`fgro` is the one not looked up on `PATH`: the tests that evaluate a config run
the build `ZAP_FGRO` names, by absolute path
(`ZAP_FGRO=/abs/path/to/fgro cargo test --workspace`). The site's
`zap config validate` e2e needs `ZAP_FGRO` and a built `target/debug/zap`
(`cargo build -p zap`), and skips without them. Legs that need `fakeroot` run
only where it is installed; a missing one is noted on stderr (`--nocapture`) and
the test passes.

CI has no `fgro` build to give the suite, so the tests that evaluate a config,
and the e2e, don't run there: CI sets `ZAP_TEST_ALLOW_NO_FGRO=1`, and the e2e
reports itself skipped. Run them locally with `ZAP_FGRO` set before you push a
change to config evaluation.

Validating against real machines is separate:
[testing.md](./testing.md) for the VMs, [differential.md](./differential.md)
for the harness that compares two `zap` builds on them.

## Adding a resource kind

A new kind touches every crate; the module maps are `crates/zap_types/CLAUDE.md`
and `crates/zap_core/CLAUDE.md`.

1. **Schema**: in `crates/zap_types/src/schema/`, the `ResourceKind` variant
   (`mod.rs`) and its payload struct (`resources.rs`). `tests/fidelity.rs` guards
   the round trip.
2. **Detection**: `crates/zap_types/src/observe/<kind>.rs`, typed read-only
   `queries` and a pure `interpret` returning a `Detection`, wired in
   `Observed::for_resource` (`crates/zap_core/src/resource/detect/observed.rs`;
   the match is exhaustive, so a missing arm fails to compile). Every kind is read
   live on every pass.
3. **Execution**: the kind's arm in `change_commands`
   (`crates/zap_core/src/resource/execute.rs`; the match is exhaustive), which
   `run_change`'s match dispatches on: a kind with command steps runs them, a
   native one gets an arm in `run_native`, and `file` and `build` have their own
   executors.
4. **Steps and hashing**: `crates/zap_types/src/plan/steps/<kind>.rs`, with inline
   command goldens, and the field selection in `crates/zap_types/src/config_hash.rs`.
5. **Builder**: `src/lib/zap.ts`, `src/lib/schema.ts`, and the driver
   (`crates/zap_core/src/config/builder_fgro.js`). Mirror the change in `builder.js`
   beside it; the drift tests fail otherwise.
6. **Tests**: detection goldens (`crates/zap_core/tests/fixtures/detection/`) and the
   fidelity round trip.
7. **Docs**: the kind's entry in [resources.md](./resources.md).

## Recipes

The shipped recipes follow the design rules in
[recipes.md](./recipes.md#design-rules).
