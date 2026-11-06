# Introduction

Zap sets up and ships to Linux machines you own, from a TypeScript file.

You have a few Linux machines, and each one has to be set up a particular way
and kept that way as its needs change. With Zap you declare what should be true
of a machine: these packages installed, this file with this content, this user
with these SSH keys, this service running, this firewall. Zap reads the machine,
shows you exactly what it would change, and changes nothing until you pass
`--wetrun`. Run it again tomorrow and it touches only what drifted. The same
tool then ships your app to that machine as a versioned release with a health
check and rollback.

If you know Terraform, Zap brings its plan-then-apply discipline to the inside
of a machine. If you know a virtual DOM, it works the same way: you describe the
whole result, and it works out the smallest set of changes to get there. Unlike
both, Zap keeps no stored copy of the machine: it diffs against the
machine itself, read fresh on every run, so a change someone made by hand shows
up in the plan.

Zap is a Rust binary that works over SSH or on the machine it runs on, with no
agent on the host and no server. It evaluates your `zap.ts` with `fgro`, Gro's
sandboxed JS runtime ([install.md](./install.md)).

## Who it's for

- **You run a few Linux machines by hand.** A laptop, a VPS or two, a home
  server. You want them described in one place and set up the same way every
  time, without learning a fleet tool.
- **You ship your own services.** A web app behind nginx with PostgreSQL on the
  box, deployed as release directories with an atomic swap, where the deploy
  refuses to ship onto a host whose config has drifted.
- **You let an assistant drive.** An AI agent, or a teammate who isn't an ops
  engineer, runs the tool for you. Planning changes nothing, so they can do it
  freely; you review the plan, and a wetrun executes only that plan. Every run ends
  in an exit code that says what was established, and `--json` streams a wetrun
  as typed events rather than free-form logs.

## What a run looks like

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

The `cache-update-apt` change is the package index refresh Zap puts in front of
an install. The wetrun planned again, got the same `plan_hash` the dry run
printed, and only then acted. Had the machine changed in between, it would have
shown the new plan and refused it, or, on a terminal, asked before running it.

Point the target at a host instead and the same config converges a server over
SSH. [Getting started](./getting-started.md) walks through both.

## What Zap does differently

1. **A wetrun executes only the plan you reviewed.** Dry run is the default,
   with no flag to auto-approve. `--wetrun` re-plans against the live machine,
   then refuses unless the plan matches the one you saw, by hash; on a
   terminal, when the plan isn't the reviewed one, it shows you the plan and asks first.
2. **Unknown means hold, not guess.** A resource Zap can't read is left out of
   the plan and reported as undetermined, with exit 1. It never reads as
   "converged" because a probe failed. (A few kinds whose create step is
   idempotent read a failed probe as `absent`; see
   [detection.md](./detection.md#kinds-that-read-a-failed-probe-as-absent).)
3. **Every run reads the live machine.** No detection cache, no stored copy of the machine. The
   security controls (firewall rules, SSH keys, sudoers, database auth) are read
   live every time, because they are what gets changed by hand.
4. **Apply checks its own work.** After acting, Zap reads the machine again and
   fails the run if anything didn't converge.
5. **The config can only describe.** `zap.ts` runs in a sandbox with no network, no
   writes, no environment, no clock, and emits a JSON declaration. Secrets are
   references, resolved by Zap when it acts and masked everywhere
   else.

Plus: a reload a failed run owed is remembered on the host and re-fired, and
fetched content is pinned by hash in a lock file next to the config.

## What Zap converges

- **Software**: apt and apk packages, apt repositories, and from-source builds
  pinned to their source archive.
- **Files**: files (inline, templated, copied, or fetched and pinned),
  directories, and symlinks.
- **Users**: shell, home mode, SSH keys, sudoers, and groups.
- **Services**: systemd and OpenRC, with restart and reload triggers.
- **PostgreSQL**: databases and roles, with `pg_hba` rules.
- **System**: swap files and firewalls (ufw, nftables).
- **Everything else**: idempotent scripts, installers, assertions, and
  pipelines.

The full reference is [resources.md](./resources.md).

Hosts: **Debian/Ubuntu** and **Alpine**. Zap manages real servers in both
families, and the firewall, user, and database controls are read live on both.

## What Zap is not

- **Not a cloud provisioner.** No VPCs, load balancers, DNS, or managed
  databases, and no provider ecosystem. Zap converges the inside of machines you
  already have. Pair it with OpenTofu or Pulumi for the outside.
- **Not an orchestrator.** No data-dependent branching mid-run. A `script`'s
  shell can do anything, but Zap doesn't model it.
- **Not a fleet tool.** One host per config, resources applied in order. Loop a
  shell over configs for a handful of hosts; reach for Ansible or pyinfra for
  hundreds.
- **Not an agent platform.** Nothing runs on the host between runs.
- **Not a remover.** Delete a resource from the config and the thing stays;
  Zap reports it as orphaned. Declare removals explicitly.
- **Not macOS or Windows.** Zap manages Linux hosts only.

The full picture, against each alternative: [comparison.md](./comparison.md).

## Status

Zap is pre-alpha and has one maintainer. It runs the servers of the project it
comes from and the maintainer's own machines. The resource set is small and
fixed, there is no plugin system, and the config schema will change before 1.0
without a compatibility layer. Read [security.md](./security.md) before pointing
it at a machine you care about, and [faq.md](./faq.md) for the questions that
come up first.

## Where next

- [install.md](./install.md), then [getting-started.md](./getting-started.md)
- [concepts.md](./concepts.md): the model, in one page
- [configs.md](./configs.md): writing `zap.ts`
- [cli.md](./cli.md): every command and exit code
