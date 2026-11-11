# zap ↯

> convergent machine-state management: set up and ship to Linux machines from TypeScript
> describe → detect → plan → apply → observe.

**Package**: `@fuzdev/zap` | **Domain**: zap.fuz.dev (docs site) | **CLI**: `zap` |
**Status**: pre-alpha — pure-Rust convergence engine (local + SSH), Debian/Ubuntu and
Alpine

For coding conventions, see the [fuz-stack skill](https://docs.fuz.dev/skills/fuz-stack). For what Zap is and how it behaves, the
`docs/` directory is canonical and public; this file is the orientation for working
on the repo.

## What Zap is

A config declares what should be true of a machine. Zap reads the machine live, plans
the difference, shows it with a hash, and changes nothing until `--wetrun`, which
executes only the reviewed plan and then reads the machine again. `zap deploy` ships
an application to the host as a versioned release. The config is TypeScript,
evaluated by a pinned `fgro eval` (Gro's runtime, in its kernel sandbox) to inert JSON. Scope and non-goals:
`docs/introduction.md`; positioning: `docs/comparison.md`.

## This repo holds two things

1. **The convergence CLI**: the pure-Rust `zap` binary, a Cargo workspace under
   `crates/`.
2. **The docs website and the TypeScript authoring surface**: a static SvelteKit site
   on the Fuz stack under `src/`, which also exports the `zap.ts` builder types
   (`src/lib/zap.ts`, `src/lib/schema.ts`) and the `recipe_*.ts` library. It is not an
   app; there is no web UI.

```
docs/                 # the public docs: one markdown file per page, rendered on the site
src/
├── routes/           # the site; docs/*.md become tomes via src/routes/docs/docs.gen.ts
└── lib/              # the authoring surface: zap.ts, schema.ts, recipe_*.ts
crates/
├── zap/              # the `zap` binary: a thin argh shell over zap_core::commands
├── zap_core/         # the IO engine: config eval, detection, execution, lock, deploy
├── zap_types/        # the pure domain model: schema, plan fact, hashing, verdicts
└── xtask/            # dev automation (cargo xtask), differential fixtures
Cargo.toml            # workspace manifest
```

## Where truth lives

- **Behavior and contracts**: `docs/*.md`. `concepts.md` is the model; `cli.md` every
  command, flag, exit code, and event; `resources.md` every kind; `detection.md` the
  full detection contract; `security.md` the threat model; `comparison.md` the
  positioning.
- **Engine architecture**: `crates/zap_core/CLAUDE.md` and `crates/zap_types/CLAUDE.md`
  map the modules; each module's `//!` doc is the detail. Update both with the code.
- **The site**: `src/routes/docs/docs.gen.ts` holds the ordered list of docs pages
  (`DOCS`); a new or renamed `docs/*.md` is added there, then `gro gen`.

## Engine invariants

Each is stated in full where it points; know them before touching the engine.

- **Config eval.** `zap.ts` is evaluated by the sibling `fuz_eval` crate, a thin
  client of `fgro eval` (trust root, uid drop, the binary's pin, the envelope);
  the walls are fgro's own. Zap supplies the driver (`DRIVER_JS`,
  `builder_fgro.js`), the `fgro` path (`--fgro` / `ZAP_FGRO`, threaded through
  the `run_*_in` cores), the toolchain pin from `zap.lock` (`zap lock` writes it),
  and the `ZapConfig` parse (`zap_core::config`). The
  walls and the project rules are `docs/security.md` § The config can only
  describe; update it with any change to them.
- **A wetrun executes only the reviewed plan.** Rule: `zap_types::last_run::review_plan`;
  gate: `zap_core::commands::apply` (`zap deploy` has its own preview). On a terminal
  the bin injects its `TerminalPrompt` (the `zap_core::commands::prompt::Prompt`
  trait; the confirmation rule is that module's), and a text-mode wetrun's live
  progress goes to the `StderrProgress` it injects (`zap_core::progress::ProgressSink`,
  carried by `EventHandler::Progress`); the engine prints nothing.
  Statement: `docs/concepts.md`; prompt UX: `docs/cli.md`.
- **Detection reads live.** No detection cache: every pass reads through typed
  queries batched per privilege lane, and a failed read holds the resource
  (`undetermined`, exit 1). The last-run report under `~/.zap` is the only memory.
  `docs/detection.md`.
- **The schema makes bad states unrepresentable.** `crates/zap_types/CLAUDE.md`
  § Modeling principles.
- **State.** `zap.lock` (only `apply --wetrun`, `zap lock`, and `zap update` write
  it) and, on the target, `/var/lib/zap/pending/<service>`. `docs/lock.md`,
  `docs/concepts.md`.
- **Authority is SSH plus `sudo`.** Privileged commands carry `sudo`; on a local
  target file operations try natively first, over SSH they run under `sudo`.
  `docs/targets.md`.

## Recipes

`src/lib/recipe_*.ts` are pure functions and constants giving config fragments,
imported by full path (`@fuzdev/zap/recipe_ssh.ts`). Distro-divergent recipes come in
symmetric `debian_*` / `alpine_*` pairs over a shared neutral core; neutral recipes
keep bare names. Generic recipes have generic names (`spa_csp`,
`debian_nginx_spa_site`, `WEB_FIREWALL_ALLOW`); only the `fuz_app_*` recipes carry an
app's name. The catalog and the design rules are `docs/recipes.md`.

## Commands

Website and TS surface:

```bash
gro check     # typecheck, test, gen --check, lint, format check (run before committing)
gro gen       # regenerate the docs tomes after editing docs/*.md or docs.gen.ts
gro build     # static build
gro deploy    # build and push to the deploy branch
```

Engine (`rust-toolchain.toml` pins the toolchain for local builds and CI):

```bash
cargo check --workspace      # typecheck the Rust workspace
cargo clippy --workspace --all-targets   # lints (pedantic + nursery)
cargo test --workspace       # the Rust suite
cargo fmt -p zap -p zap_core -p zap_types -p xtask   # format (see below)
cargo xtask install          # release build → ~/.zap/bin/zap (the global binary)
cargo xtask build-musl       # static musl binaries (x86_64 + aarch64; needs zig + cargo-zigbuild)
cargo xtask check-release    # release-readiness audit
cargo xtask differential     # oracle (origin/main) vs candidate on the VMs (docs/differential.md)
```

Format with the packages named, not `cargo fmt --all`: rustfmt follows the path-dep'd
sibling crates and would reformat files in the `fuz` checkout. `check` / `clippy` /
`test` are safe with `--workspace`.

**Keep the global binary current.** The `zap` on `PATH` is `~/.zap/bin/zap`, whatever
was last installed; `cargo build` doesn't update it. After any engine change run
`cargo xtask install`, or a consumer config fails or mis-plans against a stale binary
in ways that look like config bugs. Recipe edits need no build: the package `exports`
carry a `gro` condition pointing at `src/lib/*.ts`, which `fgro` resolves a config's
recipe imports through; run `gro build` for the types.
`ZAP_FGRO` names a copy of `fgro` updated deliberately (`docs/install.md`), and
each consumer's `zap.lock` pins it: after updating the copy, `zap lock` re-pins.

## Working on the docs

- A page per `docs/*.md`; the site renders them through mdz, which is strict: italics
  are `_x_` (a single `*x*` stays literal), raw HTML isn't rendered, tables need
  leading and trailing pipes, and a heading that will be linked shouldn't contain `+`,
  `/`, or `--` (GitHub and mdz slug those differently). One heading per id within a
  page.
- Real output beats described output: paste what the binary prints.
- No incidental counts, no dates, no "landed"/"fixed"/"used to", no internal host names,
  no private-repo paths. The docs describe the tool, not its history.

## Testing

Hermetic: nothing in the suite reaches a remote host. Tests gated on an external
program skip without it, and a crate's `tests/required_programs.rs` fails unless
the program is present or `ZAP_TEST_ALLOW_NO_<NAME>=1`. Config-eval tests need
`ZAP_FGRO`, an absolute path to a runnable build, set for the test run (`ZAP_FGRO=<abs
path to gro/target/gro_snapshot/release/fgro> cargo test --workspace`). The
per-crate gates: `docs/contributing.md`; the VMs: `docs/testing.md`; the
differential harness: `docs/differential.md`.

## Relationships

- **Fuz**: the sibling repository whose `fuz_eval` crate Zap's engine depends on by
  relative path (`../fuz`), and the curated installer for first-party binaries.
- **Gro**: builds `fgro`, the runtime every config is evaluated with; Zap runs it
  as a separate binary, never links it.
- **fuz_app**: Zap's `fuz_app_*` recipes and `deploy` conventions (`/ready`,
  `shared/.env.production`) match fuz_app servers. Zap runs the Fuz project's own
  servers and is validated against them.
