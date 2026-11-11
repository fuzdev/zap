# zap ↯

[<img src="https://zap.fuz.dev/logo.svg" alt="a friendly orange spider haloed by lightning bolts" align="right" width="192" height="192">](https://zap.fuz.dev/)

> convergent machine-state management: set up and ship to Linux machines from TypeScript ↯ pre-alpha

[**zap.fuz.dev**](https://zap.fuz.dev/)

In a TypeScript file, you declare what should be true of a machine: these
packages, this file with this content, this user with these keys, this service
running, this firewall. Zap reads the machine, shows you exactly what it would
change, and changes nothing until you pass `--wetrun`. Run it again tomorrow and
it touches only what drifted. The same tool then ships your app to that machine
as a versioned release with a health check and rollback.

Think Terraform's plan-then-apply for the inside of a machine: one Rust binary
beside `fgro`, the runtime that evaluates your config, with no agent on the host,
no server, no state backend, over SSH or on your own laptop.
Debian/Ubuntu and Alpine.

```ts
// zap.ts
export default (zap) => {
	zap.target({local: true, package_manager: 'apt', service_manager: 'systemd'});
	zap.pkg({id: 'ripgrep', from: {apt: 'ripgrep'}});
	zap.file({
		id: 'gitconfig',
		path: '~/.gitconfig',
		content: {type: 'inline', content: '[user]\n\tname = Ada\n'},
	});
};
```

```
$ zap apply
apply — target local (dry-run)
  user: ada
  home: /home/ada
  target: {"local":true,"package_manager":"apt","service_manager":"systemd"}
  [+] cache-update-apt  (script)
      check: true
      > sudo apt-get update
  [+] gitconfig  (file)
      path: ~/.gitconfig
      content: inline (19 bytes, sha512 0435b012ac1a81df…)
  [+] ripgrep  (package)
      > sudo DEBIAN_FRONTEND=noninteractive apt-get install -y ripgrep
  (dry-run — re-run with --wetrun to apply)
plan_hash: d317a15e82f2f1117f0d9fa1fdafc079b70f9e3ac5e3103c4b3333f1b6afeab0

$ zap apply --wetrun
apply — target local (wetrun)
  user: ada
  home: /home/ada
  target: {"local":true,"package_manager":"apt","service_manager":"systemd"}
  ok    cache-update-apt
  ok    gitconfig
  ok    ripgrep
applied: 3 ok, 0 failed, 0 skipped (of 3)
plan_hash: d317a15e82f2f1117f0d9fa1fdafc079b70f9e3ac5e3103c4b3333f1b6afeab0
```

Point the target at a host instead and the same config converges a server.

Zap is part of the Fuz stack
([fuz.dev](https://www.fuz.dev/), [@fuzdev](https://github.com/fuzdev)).

AI disclosure: this codebase is LLM-generated with uneven human review.

## The npm package

`@fuzdev/zap` on npm is the authoring surface for a config: the builder types
(`zap.ts`), the schema (`schema.ts`), and the recipes (`recipe_*.ts`), each as
TypeScript source and built `dist/` files. Install it in your config's project
with `npm i -D --save-exact @fuzdev/zap` and import each module by its full path
(`@fuzdev/zap/recipe_ssh.ts`).

It is not the tool. The `zap` CLI and `fgro`, the runtime that evaluates a
config, are built from source ([install](https://zap.fuz.dev/docs/install)):
a Rust toolchain, Linux with Landlock ABI 6 or later (kernel 6.12) for the
sandbox `fgro` evaluates in, and an `fgro` built on x86_64 Linux.

## What it does differently

- **A wetrun executes only the plan you reviewed.** Dry run is the default, with
  no flag to auto-approve. `--wetrun` re-plans against the live machine and
  refuses unless the hash matches the plan you name or the last preview Zap
  printed; on a terminal, when the plan
  isn't the reviewed one, it shows you the plan and asks for the start of its
  hash first.
- **Unknown means hold.** A resource Zap can't read is left out of the plan and
  reported, exit 1. It never reads as "converged" because a probe failed.
- **Every run reads the live machine.** No detection cache, no stored copy of the machine.
  Firewall rules, SSH keys, sudoers, and database auth are read live because they are
  what gets changed by hand.
- **Apply checks its own work.** After acting, Zap reads the machine again and
  fails on anything that didn't converge. A reload a failed run owed is
  remembered on the host and re-fired.
- **The config can only describe.** `zap.ts` runs in a sandbox with no network,
  no writes, no environment, no clock, and emits a JSON declaration. Secrets are
  references, resolved when Zap acts and masked everywhere else.

Built so an AI assistant can drive it for you: the default is harmless, the plan
is a fact with a hash, and the output is typed events, not log soup.

## Scope

Zap converges Debian/Ubuntu and Alpine hosts: packages, apt repos,
files (inline, templated, copied, fetched and pinned), directories, symlinks, users,
services (systemd, OpenRC) with triggers, PostgreSQL databases, swap, firewalls
(ufw, nftables), from-source builds pinned to their source, installers, scripts,
pipelines, and assertions; and it deploys releases with a health gate and
rollback. It runs the servers of the project it comes from and the maintainer's
own machines.

**Planned**: plan-time inputs (`ctx`) so a config can take explicit host facts,
prebuilt binaries and an install script, macOS for personal machines, parallel
execution. **Not planned**: cloud resources, orchestration, agents on the host,
fleets.

**Status**: pre-alpha, one maintainer. The schema and CLI change without
compatibility layers. Read [the threat model](https://zap.fuz.dev/docs/security) before pointing
it at a machine you care about.

## Install

Zap is built from source; see [install](https://zap.fuz.dev/docs/install). You need a Rust
toolchain, `fgro` from [Gro](https://github.com/fuzdev/gro) (it runs your config,
on Linux), and `ssh`. Zap depends on crates from the sibling
[Fuz](https://github.com/fuzdev/fuz) repository, resolved by relative path, so
clone the two next to each other:

```sh
git clone https://github.com/fuzdev/fuz
git clone https://github.com/fuzdev/zap
cd zap && cargo xtask install      # → ~/.zap/bin/zap
```

Then follow [getting started](https://zap.fuz.dev/docs/getting-started): your own machine
first, then a server.

## Docs

| page | what's there |
|---|---|
| [introduction](https://zap.fuz.dev/docs/introduction) | what Zap is, who it's for, what it is not |
| [install](https://zap.fuz.dev/docs/install), [getting started](https://zap.fuz.dev/docs/getting-started) | from zero to a converged machine |
| [concepts](https://zap.fuz.dev/docs/concepts) | the model: convergence, verdicts, the plan, the review |
| [configs](https://zap.fuz.dev/docs/configs) | writing `zap.ts` |
| [resources](https://zap.fuz.dev/docs/resources), [recipes](https://zap.fuz.dev/docs/recipes) | every resource kind; the shipped fragments |
| [targets](https://zap.fuz.dev/docs/targets), [env](https://zap.fuz.dev/docs/env), [lock](https://zap.fuz.dev/docs/lock) | SSH and privilege; references and secrets; pinning and `~/.zap` |
| [deploy](https://zap.fuz.dev/docs/deploy) | shipping releases |
| [cli](https://zap.fuz.dev/docs/cli) | every command, flag, exit code, and event |
| [comparison](https://zap.fuz.dev/docs/comparison) | against Ansible, pyinfra, Terraform, Pulumi, NixOS, Puppet, Kamal, and more |
| [security](https://zap.fuz.dev/docs/security), [stability](https://zap.fuz.dev/docs/stability) | the threat model; what a release promises |
| [faq](https://zap.fuz.dev/docs/faq), [glossary](https://zap.fuz.dev/docs/glossary) | the first questions; every term |
| [detection](https://zap.fuz.dev/docs/detection) | the full detection contract |
| [contributing](https://zap.fuz.dev/docs/contributing), [testing](https://zap.fuz.dev/docs/testing), [differential](https://zap.fuz.dev/docs/differential) | building and checking Zap; validating against real VMs |

The same pages render at [zap.fuz.dev/docs](https://zap.fuz.dev/docs), with the
API reference for the TypeScript authoring surface.

## The repo

Two things live here. The convergence engine is a Rust workspace under
`crates/`: `zap` (the CLI), `zap_core` (the engine), `zap_types` (the pure
domain model), and `xtask` (dev automation). The website and the
TypeScript authoring surface (`@fuzdev/zap`: `zap.ts` types, `recipe_*.ts`) are a static
SvelteKit site under `src/`.

```sh
cargo check --workspace      # typecheck the engine
ZAP_FGRO=<abs path> cargo test --workspace   # the engine's tests (docs/contributing.md)
cargo xtask install          # release build → ~/.zap/bin/zap
cargo xtask build-musl       # static Linux binaries (x86_64, aarch64)
gro check                    # the site and TS surface
```

## Credits 🐢<sub>🐢</sub><sub><sub>🐢</sub></sub>

[Rust](https://www.rust-lang.org/) ∙
[V8](https://v8.dev/) ∙
[Svelte](https://github.com/sveltejs/svelte) ∙
[SvelteKit](https://github.com/sveltejs/kit) ∙
[Vite](https://github.com/vitejs/vite) ∙
[fuz_css](https://github.com/fuzdev/fuz_css) ∙
[fuz_ui](https://github.com/fuzdev/fuz_ui) ∙
[Gro](https://github.com/fuzdev/gro) ∙
& [more](package.json)

## Contributing

[fuz.dev/contributing](https://www.fuz.dev/contributing);
building and checking Zap is in [contributing](https://zap.fuz.dev/docs/contributing).

## Security

Report vulnerabilities through the [fuzdev security policy](https://github.com/fuzdev/.github/blob/main/SECURITY.md).

## License [🐦](https://wikipedia.org/wiki/Free_and_open-source_software)

[0BSD](LICENSE)
