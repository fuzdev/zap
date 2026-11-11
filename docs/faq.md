# FAQ

## The config

**Why TypeScript for the config?** Because the config needs loops, constants,
functions, and types, and inventing a DSL for those is how YAML grows a template
language. TypeScript has them, editors understand it, and the shipped recipes
are ordinary functions. The config only _describes_: it runs in a sandbox and
emits JSON. Zap evaluates it once, before it reads the machine; what executes is the plan
built from that JSON, and none of your TypeScript runs on the target.

**What runs the config? Can I use Node, Deno, or Bun?** `fgro eval`, Gro's
runtime. Zap is a compiled Rust binary and can't run TypeScript itself, so
`fgro` evaluates the config in a kernel sandbox that reads only the config's
project and the packages it links ([the sandbox](./configs.md#the-sandbox)).
Each project pins one `fgro` build by hash in `zap.lock`. Node, Deno, and Bun
have no such sandbox, so Zap doesn't support them. Nothing runs on the target
but shell.

**Where are secrets stored?** Nowhere Zap owns. They live in your environment
or an env file you keep out of version control, referenced with `zap.env('NAME')`, and
resolved when Zap acts. Resolved values are masked in every output, and the lock
file and last-run report hold a fixed token for each recognized secret
([env.md](./env.md#secrets); list others with `zap.mask()`).

**What is `zap.lock` and should I commit it?** It pins the `fgro` build that
evaluates the config, and fetched content (a `remote` file, a `build` source) to
the hash of the bytes you approved. Commit
it with `zap.ts`. It changes only when you run `zap update`, `zap lock`, or an
`apply --wetrun` that has a tracked source to pin.
[lock.md](./lock.md).

## Running it

**Why is the dry run the default?** So the safe thing is the zero-effort thing,
and so a script, a CI job, or an assistant can't act by accident. Tools that
default to acting rely on an interactive prompt, which is exactly what gets
auto-approved. Here `--wetrun` is the act, and a wetrun with nothing reviewed
asks for the first characters of the plan's hash, which nothing can type before
the plan is on the screen.

**What does `--wetrun` refusing mean?** A wetrun executes only the plan you
reviewed. If its fresh plan doesn't match the most recent preview on that host,
or the hash given to `--expect-plan`, it shows the plan, changes nothing, and
exits 2; running it again executes if nothing moved. On an interactive terminal
without `--expect-plan`, it asks instead: type the start of the plan's hash to
run it.
[concepts.md](./concepts.md#a-wetrun-executes-only-the-plan-you-reviewed).

**Why did `zap plan` exit 0 when there are changes, but `zap apply` exit 2?**
`plan` reports; it doesn't judge. `apply` judges: 0 converged, 2 changes pending,
1 something couldn't be established. Use `apply` in a script that needs the
verdict. [cli.md](./cli.md#exit-codes-all-commands).

**What is `undetermined`?** Zap couldn't read the resource and refuses to guess.
It is held out of the plan, reported with its reason, and the run exits 1. The
usual causes: a remote path using `~` with no `home` declared, a tracked
`remote` file with no lock entry, a probe that failed or timed out, `sudo` that
wouldn't authenticate. Fix the cause and plan again; nothing carries over.
[concepts.md](./concepts.md#detection).

**Why does a `script` run on every apply?** Its `check` fails on a converged
host. The `check` is the whole idempotency contract: make it exit 0 exactly
when the work is done. After a wetrun Zap runs the check again and reports
`RESIDUAL` if it still fails.

**Why does `apply` write to `/var/lib/zap/pending/` on my host?** Each marker
there is a restart or reload a service still owes, written before the change that
triggers it and cleared after. It is how a reload a failed run owed survives to
the next plan ([concepts.md](./concepts.md#triggers)). The rest of what Zap leaves
on a target, beside what you declared, is listed in
[install.md](./install.md#uninstall).

## Scope

**Does Zap need anything installed on the target?** `sshd`, a POSIX shell with
coreutils or BusyBox, and `sudo`. No agent, no Python, no runtime.
[targets.md](./targets.md#what-the-target-needs) has the per-distro list.

**I removed a resource from the config. Why is it still on the machine?** Zap
never removes what you stop declaring; it reports it as orphaned in `zap status`.
To remove something, declare the removal (a `script` whose `check` confirms it
is gone, or `sudo: false` on a user). This is the same posture as Ansible and
Puppet, and the opposite of Terraform and NixOS.

**Can one config manage several hosts?** One target per config. For a few hosts,
one config per host (sharing modules), one env file per host, a shell loop. For a
fleet with parallel execution, Zap is the wrong tool; see
[comparison.md](./comparison.md).

**Does Zap work on macOS, Arch, Fedora, Windows?** No. Debian/Ubuntu and
Alpine. `pacman`, `brew`, and `launchd` parse in the schema but have no backend,
so their resources read undetermined, and the TypeScript types leave them out. Running Zap _from_ macOS against a Linux
host is unsupported: `fgro`'s sandbox needs Linux, so your side does too.

**Is Zap stable?** No: pre-alpha, one maintainer, and the schema and CLI change
without compatibility layers. [stability.md](./stability.md) names the surfaces
whose breaks a release calls out. Read [security.md](./security.md) before
pointing Zap at a machine you care about.

## Agents and alternatives

**Can an AI agent run Zap?** Yes, and it is designed for that: the default
command is read-only, the plan is a hash-named fact the agent can show you, a
wetrun given that hash executes only that plan, and `--json` streams typed
events. Give the agent `zap plan` and `zap apply` freely and keep `--wetrun` for
the human, or let it wetrun with `--expect-plan` set to the hash you approved.
Without the flag, a wetrun binds to the last preview Zap printed on that host,
whether or not anyone read it: a preview an agent cut short with `head` still
binds once the pipe took it whole, and the hash is its last line.

**How is this different from a shell script with `if` guards?** That script is
reaching toward what Zap declares: detection (skip what's done), idempotent
re-runs, a preview before acting, and a report after. Zap adds the parts a
script never grows: a refusal to guess when a read fails, a re-read after acting,
secrets masked everywhere, and a review bound to the act. `script` resources let
you keep the shell where it is the right tool.

**How is this different from Ansible / Terraform / NixOS / Kamal?**
[comparison.md](./comparison.md), with tables.
