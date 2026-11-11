# Getting started

Two walks: your own machine first, then a server over SSH. Each takes a few
minutes. [Install](./install.md) Zap and `fgro` before you start.

## 1. Your own machine

Make a directory for the config, give it a `package.json`, which marks it as the
config's project, and write a `zap.ts` that manages a directory and a file you
own, so nothing needs `sudo`:

```json
{"name": "infra", "private": true}
```

```ts
// zap.ts
export default (zap) => {
	zap.target({local: true});
	zap.directory({id: 'notes', path: '~/notes', mode: '755'});
	zap.file({
		id: 'hello',
		path: '~/notes/hello.txt',
		content: {type: 'inline', content: 'hello from zap\n'},
		depends_on: ['notes'],
	});
};
```

A config is a function. It receives a builder and declares a target and
resources; it returns nothing. Every resource has an `id` you choose, which is
how other resources and Zap's output refer to it.

**Pin the evaluator.** `zap lock` records the `fgro` build that evaluates the
config in `zap.lock`; every other command that reads the config refuses until it does:

```
$ zap lock
pinned fgro c8a3d0effbcb7ca4540fa9197dfff499c385547b10cff6931644d6450446dcb7
wrote zap.lock (no eligible resources)
```

**Preview.** `zap apply` without `--wetrun` reads the machine and shows what it
would change. It changes nothing, and exits 2 to say changes are pending:

```
$ zap apply
apply — target local (dry-run)
  user: ops
  home: /home/ops
  target: {"local":true}
  [+] notes  (directory)
      path: ~/notes
      mode: 755
  [+] hello  (file)
      path: ~/notes/hello.txt
      content: inline (15 bytes, sha512 0c7463f032f1dc98…)
  (dry-run — re-run with --wetrun to apply)
plan_hash: 5bb79cc9141942676c784abba55826f12be51b3feb86f5f0cf77666545674d61
$ echo $?   # $status in fish
2
```

`[+]` is a create, `[~]` an update, and the lines under each say what the change
declares: a file's content shows as its length and the start of its SHA-512,
never the bytes. The `plan_hash` names this exact plan. `zap plan` prints the
same plan with a change count and exits 0: it reports, where `apply` judges.

**Apply.** Now act:

```
$ zap apply --wetrun
→ notes: create directory
→ hello: create file
→ re-detect: reading 2 declared resources back to confirm what the changes left
apply — target local (wetrun)
  user: ops
  home: /home/ops
  target: {"local":true}
  ok    notes
  ok    hello
applied: 2 ok, 0 failed, 0 skipped (of 2)
plan_hash: 5bb79cc9141942676c784abba55826f12be51b3feb86f5f0cf77666545674d61
```

The `→` lines are progress, printed to standard error as each change and the
re-detection start; the report under them is standard output. After the changes
ran, Zap read both resources again and found them converged,
which is why the exit was 0. Had anything still read wrong, the report would
say `RESIDUAL` and exit 1.

The wetrun went through because your preview a moment ago bound it: a wetrun
executes only the plan you reviewed.

Had you run `zap apply --wetrun` first, with no preview behind it, it would
have shown the plan and asked:

```
$ zap apply --wetrun
apply — target local (wetrun, awaiting confirmation)
  …

  UNREVIEWED — nothing has run: this plan runs only once it is confirmed below.
    no plan has been previewed on this host.
plan_hash: 5bb79cc9141942676c784abba55826f12be51b3feb86f5f0cf77666545674d61
Apply this plan? Type 5bb79cc9, the start of its plan_hash, to confirm: n
apply — target local (wetrun, declined)
  …

  DECLINED — nothing ran: this plan was not confirmed.
    no plan has been previewed on this host.
  …
```

Typing `5bb79cc9` would have run exactly that plan: the answer is the start of a hash
you can only know by looking at the plan. Declined, it changed nothing, exited 2,
and became the preview: running it again executes if nothing moved. Without a
terminal (a script, CI, `< /dev/null`) the wetrun doesn't ask; it renders the
same plan under a `REFUSED` banner and stops the same way.
`--expect-plan <hash>` binds explicitly. [concepts.md](./concepts.md#a-wetrun-executes-only-the-plan-you-reviewed)
has the rules.

**Status.** `zap status` tells you what the last run saw, offline:

```
$ zap status
target local (pkg: none, service: none)
last run on local: zap apply --wetrun, after its changes ran, at 2026-10-11T21:09:26Z — offline; `zap plan` reads the target live
  a 0 exit means every declared resource read converged in the last run and its config is unchanged since — not that the target still is
  converged    notes  directory
  converged    hello  file
```

**Again.** Preview once more:

```
$ zap apply
apply — target local (dry-run)
  user: ops
  home: /home/ops
  target: {"local":true}
  (no changes — converged)
plan_hash: 2d374e262633aebd2273acc69efc3122cff2bdbb6dc36f98d7d4bbc6cde5cb44
```

Now edit `hello.txt` by hand, add a line, and run `zap plan --diff`: the file
reads `[~] hello` with `~ content: differs → inline (15 bytes)`. That is drift,
and `zap apply --wetrun` would put the declared content back.

### Add a package

Declare the package manager on the target and a package:

```ts
zap.target({local: true, package_manager: 'apt'});
zap.pkg({id: 'ripgrep', from: {apt: 'ripgrep'}});
```

`zap apply` now plans two changes: `cache-update-apt`, the index refresh Zap
puts in front of an install, and the `apt-get install -y ripgrep` itself, both
run under `sudo` on the wetrun.
Packages are detected by existence: Zap asks `dpkg-query` whether `ripgrep` is
installed, not which version. An entry written `name=version` pins a version
instead ([package names](./resources.md#package-names)).

### Add types

For completion in your editor, import the builder type (type-only, so the
evaluator needs nothing installed):

```ts
import type {ZapBuilder} from '@fuzdev/zap/zap.ts';

export default (zap: ZapBuilder) => {
	// …
};
```

See [install.md](./install.md#types-and-recipes-for-your-config) for resolving
the import.

## 2. A server over SSH

You need a Debian, Ubuntu, or Alpine host you can reach as a user who has
password-less `sudo`. On a fresh Debian cloud image the stock user usually
qualifies. On Alpine, as root:

```sh
setup-apkrepos -c -f
apk update && apk add sudo
adduser ops        # skip if the account exists
adduser ops wheel
echo '%wheel ALL=(ALL) NOPASSWD: ALL' > /etc/sudoers.d/wheel
chmod 0440 /etc/sudoers.d/wheel
```

Install your key and check that plain `ssh` works silently:

```sh
ssh-copy-id ops@<host>
ssh ops@<host> true
```

**The config.** It lives in a project of its own, with a `package.json` as
before. The host and user are [references](./env.md#references): they come from your
environment when Zap runs, never from the config file, so the config can be
committed and reused. The user's variable is `USER_NAME` and not `USER` on
purpose: your shell already sets `USER`, so a run that forgot the env file would
connect as your local login name where an unset `USER_NAME` fails.

```ts
// zap.ts
export default (zap) => {
	zap.target({
		host: zap.env('HOST'),
		user: zap.env('USER_NAME'),
		home: '/home/ops', // that user's home on the host
		package_manager: 'apt', // 'apk' on Alpine
		service_manager: 'systemd', // 'openrc' on Alpine
	});
	zap.pkg({id: 'chrony', from: {apt: 'chrony', apk: 'chrony'}});
	zap.service({
		id: 'chronyd',
		service: 'chrony', // 'chronyd' on Alpine
		enabled: true,
		running: true,
		depends_on: ['chrony'],
	});
	zap.file({
		id: 'probe',
		path: '/etc/zap-probe',
		content: {type: 'inline', content: 'managed by zap\n'},
		mode: '644',
	});
};
```

**The env file.** Put the variables in a file Zap loads with `--env-file`. Keep
it out of version control; commit a `.example` instead.

```sh
# zap.env
HOST=203.0.113.10
USER_NAME=ops
```

**Drive it.**

```sh
zap lock --env-file zap.env            # pin the evaluator
zap detect --env-file zap.env          # what the host looks like now
zap apply --env-file zap.env           # the plan
zap apply --env-file zap.env --wetrun  # converge
zap apply --env-file zap.env           # idempotency: (no changes — converged)
```

The dry run shows the `apt-get update` and the `apt-get install`, the
`systemctl enable` and `start`, each with the exact command, and the file it
will write. The wetrun reports `4 ok`: the three resources plus the index
refresh.

Edit the probe file on the host, or `systemctl stop chrony`, and `zap plan`
shows the drift. That loop, plan then wetrun, is all of Zap.

## What to commit

| File | Commit? |
|---|---|
| `zap.ts` | yes |
| `zap.lock` | yes, it records the `fgro` build and any fetched bytes you approved |
| `zap.env` and friends | **no**; commit a `.example` |
| `~/.zap/` | no, it's your machine's cache and last-run reports |

## Where to go next

- **A real server.** The [recipes](./recipes.md) carry the standard pieces: SSH
  hardening, a hardened systemd or OpenRC service, an nginx site with a CSP, a
  firewall, certbot, fail2ban, PostgreSQL. [configs.md](./configs.md) shows how
  to compose them.
- **Shipping an app.** `zap deploy` releases a build to the host you just
  converged, with a health gate and rollback: [deploy.md](./deploy.md).
- **A host that locks itself down.** When SSH hardening changes the user Zap
  connects as, declare both users and run the first apply with `--bootstrap`:
  [targets.md](./targets.md#the-bootstrap-user).
- **What every command and exit code means.** [cli.md](./cli.md).
