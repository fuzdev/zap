# What you can rely on

Zap is pre-1.0. Anything can change between minor versions, and nothing is kept
for compatibility: no deprecation period, no aliases for renamed things. What
this page promises is narrower: which surfaces count as Zap's interface, so a
change to one is named in the release notes, and what an upgrade throws away on
purpose.

## The interface

A change to any of these is a breaking change, and the release notes name it.

| Surface | Where it's defined |
| --- | --- |
| The `zap.ts` config: the builder (`zap.pkg`, `zap.file`, …), every resource kind and field, and `zap.env('NAME')` references | `@fuzdev/zap/zap.ts`, `@fuzdev/zap/schema.ts`, [resources.md](./resources.md), [env.md](./env.md) |
| How a config is evaluated: a pure function of the builder, in a sandbox, and what it can't reach | [configs.md](./configs.md#the-sandbox) |
| Recipe module paths and their exported functions, including the `debian_*` / `alpine_*` pairs | [recipes.md](./recipes.md) |
| CLI commands, flags, and exit codes | [cli.md](./cli.md) |
| The `--json` event schema a wetrun emits | [cli.md](./cli.md#json-events) |
| The `zap.lock` format (`"version": 2`) | [lock.md](./lock.md) |
| The env file `--env-file` reads | [env.md](./env.md#the-env-file) |
| The deploy layout on the target (`releases/` and its release names, `current`, `shared/`, `deploy_info.json`, the `.zap-deploy.lock` file) and the health and readiness contract | [deploy.md](./deploy.md) |
| Zap's state on the target: one marker per owed restart or reload under `/var/lib/zap/pending/`, a `build`'s `<output>.zap-build` provenance sidecar, and an extracted `remote` file's `.zap_remote_hash` sentinel | [concepts.md](./concepts.md), [detection.md](./detection.md) |

`zap.lock` is the one file Zap writes that you commit, so it carries the one
migration promise: if its format version ever moves, Zap will read the old
version and rewrite it in the new one, so you won't re-mint it by hand.

## Discarded on upgrade, by design

These are derived by the binary that made them. A new version may compute them
differently, and when it does the old ones stop matching. None of them breaks
silently: Zap plans again, and the review gate asks for a new review.

- **Plan hashes.** A `plan_hash` from one Zap version may not bind a wetrun on
  another. After an upgrade, a recorded preview or an `--expect-plan <hash>` can
  refuse; preview again and review the new plan.
- **The last-run report and the deploy preview under `~/.zap`.** A record in
  another format is ignored, the same as having none.
- **Each lock entry's `config_hash`.** When the way a declaration is hashed
  moves, every tracked entry reads stale: `zap apply` stops with an error naming
  `zap update <id>`, and the read-only commands hold those resources until it
  runs. `zap update` fetches again and re-mints. Because it fetches, a source
  whose bytes changed upstream comes back with a new pin, so read the lock's
  diff before you commit it.
- **Provenance sidecars and extract sentinels on the target.** When what they
  record moves, each `build` rebuilds and each extracted `remote` file
  re-extracts once, on the next wetrun.
- **The evaluation cache.** Internal, and rebuilt as needed.

## Not part of the interface

- The human-readable output: plan rendering, wording, banners, layout. A script
  should read exit codes and `--json` events, not text.
- The Rust crates. They aren't published; the `zap` binary is the interface.
- Anything the docs describe as internal or as a current limitation.
