# Install

Zap is built from source, and so is `fgro`, Gro's runtime, which evaluates your
TypeScript config. Zap never runs a config without it.

## What you need on your machine

| Tool | Why | Check |
|---|---|---|
| **Rust** via rustup (it installs the toolchain pinned in `rust-toolchain.toml`) | to build the `zap` binary | `cargo --version` |
| **fgro**, Gro's runtime | every command that reads a config evaluates `zap.ts` with `fgro eval`, in its kernel sandbox | `fgro --version` |
| **Linux** with Landlock ABI 6 or later (6.12) | the sandbox `fgro` evaluates in | `uname -r` |
| **ssh** | remote targets | `ssh -V` |
| scp | a `remote` archive or a `build` source on a remote target | |
| git, tar | `zap deploy` | |
| minisign | only for a `build` source with `verify`; on `PATH`, or named by `ZAP_MINISIGN` | |
| Node and npm | only to import the shipped recipes and get editor types | `npm --version` |

## Build

Zap depends on crates from the sibling `fuz` repository, resolved by relative
path, so the two checkouts sit next to each other:

```sh
git clone https://github.com/fuzdev/fuz
git clone https://github.com/fuzdev/zap
cd zap
cargo xtask install
```

`cargo xtask install` makes a release build and puts the binary at
`~/.zap/bin/zap`. Add that directory to your `PATH`:

```sh
export PATH="$HOME/.zap/bin:$PATH"   # bash / zsh
fish_add_path ~/.zap/bin             # fish
```

Then:

```
$ zap version
zap <version>
```

Debug and static musl builds are in
[contributing.md](./contributing.md#builds).

The binary on your `PATH` doesn't update when you pull. Run
`cargo xtask install` again after pulling changes.

## Getting fgro

Build `fgro` from a checkout of
[Gro](https://github.com/fuzdev/gro), on x86_64 Linux. The build downloads and
verifies a pinned V8 first, and the binary must carry its startup snapshot,
which `cargo xtask build` embeds:

```sh
git clone https://github.com/fuzdev/gro
cd gro
cargo xtask fetch-v8
cargo xtask build --release
```

The binary is `target/gro_snapshot/release/fgro`. Don't point `ZAP_FGRO` at it there:
each build replaces it, and a project's `zap.lock` pins the exact binary its
configs are evaluated with ([lock.md](./lock.md#the-toolchain-pin)), so a
rebuild would make every pin stale. Copy it to a place you update deliberately,
and name that copy:

```sh
install -D -m 755 target/gro_snapshot/release/fgro ~/.zap/bin/fgro
export ZAP_FGRO="$HOME/.zap/bin/fgro"   # bash / zsh
set -gx ZAP_FGRO ~/.zap/bin/fgro         # fish
```

Zap takes the binary by absolute path, from `--fgro <path>` or `ZAP_FGRO`, and
never looks it up on `PATH`. `sudo` resets the environment, so under `sudo`
only `--fgro` reaches Zap: `sudo zap apply --fgro ~/.zap/bin/fgro`. Name the
binary itself, not a link to it or a wrapper script.

Then pin it in each project: `zap lock` evaluates the config with that binary
and records its blake3 in `zap.lock`; commit the lock. When you update the copy,
run `zap lock` again in each project.

Zap and fgro talk through a versioned eval protocol. An fgro that answers in a
version this `zap` doesn't read is refused, exit 2, whatever the pin says: update
the older of the two, then `zap lock`.

## Types and recipes for your config

A config needs a project of its own: a `package.json` beside it, or in a
directory above it that you own and no other user can write. One holding only
`"type"` or `"sideEffects"` doesn't count; a `"name"` is enough. A `.js` module
the config imports needs `"type": "module"`:

```json
{"name": "infra", "private": true, "type": "module"}
```

A bare config needs nothing else installed:

```ts
export default (zap) => {
	zap.target({local: true});
	// …
};
```

For editor completion and type checking, import the builder type. The import is
type-only, so the evaluator strips it and needs nothing resolvable at run time:

```ts
import type {ZapBuilder} from '@fuzdev/zap/zap.ts';

export default (zap: ZapBuilder) => {
	// …
};
```

To use the shipped **recipes** (nginx sites, hardened systemd units, SSH
hardening, certbot, firewalls), your project needs the `@fuzdev/zap` package resolvable
under `node_modules/@fuzdev/zap`. The package isn't published to npm; point a path
dependency at your checkout:

```json
{
	"devDependencies": {
		"@fuzdev/zap": "../zap"
	}
}
```

`npm install` then symlinks the checkout into `node_modules`. That link, in the
config's own project, is the one way its import of `@fuzdev/zap` resolves: a
`node_modules` above the project is never searched ([security.md](./security.md#the-config-can-only-describe)). The
checkout must not sit under a directory every user can write. fgro resolves
recipe imports through the package's `exports`, which carry a `gro` condition
pointing at the TypeScript sources, so a recipe edit in the checkout reaches
your next plan with no build step. TypeScript and your editor resolve
the same imports through the built `dist/`, so run
`npm install && npm run build` in the `zap` checkout once (and after pulling) to
keep types current.

```ts
import type {ZapBuilder} from '@fuzdev/zap/zap.ts';
import {ssh_hardening} from '@fuzdev/zap/recipe_ssh.ts';
```

See [recipes.md](./recipes.md) for the catalog.

## What a target needs

A local target needs `sudo` only if the config touches files you don't own or
runs privileged commands. A remote target needs `sshd`, a POSIX shell with
coreutils or BusyBox, and a `sudo` that works without a password for the user
Zap connects as. Details per distro:
[targets.md](./targets.md#what-the-target-needs).

## Uninstall

Remove `~/.zap` (the binary and, unless `ZAP_HOME` moved them, the caches,
last-run reports, deploy previews, SSH sockets), and `$ZAP_HOME` if you set one;
a `zap` run under `sudo` keeps its own, in the home `sudo` gives it (root's
`~/.zap`). Zap keeps no other state on your machine. On a target it
leaves only what your config declared, plus any pending-trigger markers under
`/var/lib/zap/pending/`, a `build`'s `<output>.zap-build` provenance sidecar,
an extracted `remote` file's `.zap_remote_hash` sentinel, and in a deploy's
`path`, `deploy_info.json` and the `.zap-deploy.lock` file. A run killed outright
can also leave a `.zap.*` staged file beside a file it was writing, or a
release archive (`.zap-deploy-<user>-<version>.tar.gz`) in a deploy's `path`. A
killed deploy can leave `releases/.zap-stage` and `releases/.zap-old-*` there
too, which the next deploy to that `path` cleans up.
