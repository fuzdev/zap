# zap_types

> The pure domain model for Zap convergence — IO-free by construction.

Zero ambient authority: no `tokio`, process, or network, and no `uuid` / `time` /
`getrandom`. So the plan-producing path has no clock and no RNG: given the same
declaration, detections, and lock, the plan cannot vary run to run — the
determinism enforced by the dependency graph.
Everything here is data or a pure transform: the Describe and Plan halves of
Describe → Detect → Plan → Apply → Observe. The IO engine that consumes these types
is `zap_core`.

Deps: `serde`, `serde_json`, `blake3`, `thiserror`.

## Modules

A map; each module's `//!` doc and its items' rustdoc are the detail.

- `schema` (`schema/`) — the config contract: `ZapConfig`, `Target`, and `Resource`
  (flat identity plus a `ResourceKind` enum of typed per-kind payloads); the wire
  parse and its precise errors.
- `text` — `Text`, the type of a field that takes a reference: the inert string with
  well-formed markers, resolved explicitly, no `Display`.
- `var_ref` — the inert reference marker (`OPEN` name `CLOSE`, two noncharacters),
  scanned once into segments.
- `scalar` — format-constrained scalar newtypes (`AccountName`, `EnvVarName`, …),
  validated at the config-eval boundary; `ContentHash` is a blake3 pin, exactly 64
  lowercase hex, and `MinisignKey` a minisign public key's text form.
- `plan` (`plan.rs`, `plan/step.rs`, `plan/steps/`) — the plan fact (`Plan`,
  `Change`, typed `PlanStep`s), the machine and references it is for, the pure `diff`
  that builds it, and the held (`HeldResource`, `HoldCause`) and residual verdicts.
- `config_hash` — deterministic JSON plus blake3 (64 lowercase hex), one `HashDomain`
  version axis per artifact:
  - `Resource` (`RESOURCE_HASH_VERSION`): a resource's desired state, the lock
    entry's `config_hash`;
  - `Plan` (`PLAN_HASH_VERSION`): the changeset, `plan_hash`;
  - `Deploy` (`DEPLOY_PLAN_HASH_VERSION`): the deploy plan and its preflight digest;
  - `LastRun` (`LAST_RUN_VERSION`): the last-run report's per-resource hashes.

  Outside the domains, the provenance digests (`build_provenance`,
  `extract_provenance`, `PROVENANCE_VERSION`, a fixed tag first) are what a target
  records beside a build output and in an extracted tree.
- `observe` (`observe/`, one module per kind, plus `batch.rs`) — the pure half of
  batched detection: each kind's typed `queries` and the `interpret` verdict over
  their answers; `batch` composes and parses a lane's framed script.
- `detected` — the `Detection` verdict and the typed per-kind `CurrentState`.
- `diff_view` — the `zap plan --diff` join of observed state and desired kind.
- `last_run` — the last-run report's on-disk contract and `review_plan`, the
  wetrun review rule.
- `deploy_preview` — the deploy preview's on-disk contract and its review rule.
- `deploy` — the pure deploy plan (`plan_deploy`), the release scripts it builds from
  the values it holds (`DeployPlan::swap_script`), and the auto-rollback's
  compare-and-swap (`rollback_swap_command`) under the app's deploy lock
  (`deploy_lock_path`).
- `lock` — the `zap.lock` schema (`ZapLock`, its `Toolchain` pin, `LockEntry`,
  `LOCK_VERSION`).
- `secrecy` — the one rule for which reference is a secret (`SecretRule::classify`).
- `claim` — what each resource manages that no other may; the duplicate-claim gate's
  input.
- `fetch_url` — the one rule for a URL Zap or the target fetches.
- `validate` — config validators the type system can't express, behind `zap_core`'s
  structural gate.
- `put`, `extract` — the constant scripts every privileged write, directory
  creation, snapshot, raw read, and archive extract goes through; values arrive as arguments or on stdin. `FileAttrs`
  carries a write's declared mode and owner, and `Unset` what it gives the rest
  (`Keep` only for a `file` resource's own write).
- `shell` — `single_quote` and `run_context`, the one way a command gets its `cwd`
  and `env`.
- `postgres` — SQL and `pg_hba` command primitives shared by the `database` detector
  and step builder.
- `package_managers`, `service_managers` — pure per-manager command templates (no
  `sudo`; the planner adds it), and `service_managers`' readings of its probes
  (`read_active` / `read_enabled`: a failed read is no answer).
- `event` — execution outcomes (`ChangeOutcome`, `StepOutcome`, `RunSummary`) and
  the `--json` `Event` stream.
- `error_code` — the execution error taxonomy and `classify_error`.
- `eval_inputs` — the L0 eval-cache key (`EvalInputs`) and its pure re-validation
  policy.

Output types carry their own masking seam: `Event`, `ChangeOutcome`, `StepOutcome`,
`Detection`, `CurrentState`, and `ResidualResource` each have a `map_text(f)` over
exactly their free text, destructured in full, so an added field doesn't compile
until it is placed.

## The plan fact

A `Change` carries only what the executor needs; detection narrative (`before`,
`reason`, skips) and execution state stay out, rejoined at render time or held on
`event::ChangeOutcome`. The desired side is resolved into the fact (a tracked pin
folded in), while environment values stay inert in each change and are recorded
beside them (`Plan::references`, a secret only as the fact). The two hashes and what
each covers: `plan.rs` and `config_hash.rs` module docs.

## Modeling principles

This crate is the schema, so it carries the load of making bad states
unrepresentable — magic strings and "valid only when…" invariants become Rust
types, validated where the JSON is parsed.

- **Closed sets are enums, not strings.** Every fixed-value field is a
  `#[serde(rename_all)]` enum; an unknown value is rejected at config-eval with a
  precise `unknown variant` error. A single-variant enum still earns its keep
  (`DatabaseEngine`).
- **Leniency only for genuine extensibility.** A `String` (or catch-all variant) is
  justified *only* for a value passed through verbatim to an external system with an
  open set we don't dispatch on.
- **The TS mirror is part of the boundary.** `src/lib/schema.ts` mirrors this crate
  1:1; a field the engine hard-rejects (`validate.rs`) carries the rejection in its
  TSDoc, and a scalar newtype's format is noted wherever the TS side degrades to
  `string`.
- **Impossible states unrepresentable.** *Mutually exclusive → enum* (`FileDrift`,
  `SudoDrift`); *co-present → struct of `Option`s* (`UserDrift`). A field meaningful
  for only some variants lives **inside** them (`strip_components` in `ExtractMode`'s
  tar variants, a sudo command list in `UserSudo::Restricted`). `UserSudo`'s
  hand-rolled serde rejects `sudo: true`, which a derived `bool` arm would read as a
  removal.
- **Defensive fallbacks fail closed.** An unreachable or defensive arm errors (or
  holds) rather than returning a neutral value that reads as a finding: a neutral
  default in a defensive arm is a guessed fact.

See the [fuz-stack skill](https://docs.fuz.dev/skills/fuz-stack)'s `rust-patterns.md` §Idioms for the cross-ecosystem statement.

## Testing

Each `plan/steps/*.rs` builder carries inline command goldens (exact
`PlanStep` strings, the injection surface); a new step or kind adds them.
`tests/fidelity.rs` guards the wire round-trip and pins which paths take a
reference.

## Conventions

See the [fuz-stack skill](https://docs.fuz.dev/skills/fuz-stack) for the shared Rust/workspace conventions. snake_case
functions, PascalCase types; `# Errors` docs on fallible public functions.
