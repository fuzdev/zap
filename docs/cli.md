# CLI reference

Every zap command, its flags, what it reads and writes, and its exit codes. For
what the commands mean, see [concepts.md](./concepts.md); for a first run, see
[getting-started.md](./getting-started.md).

```
zap <command> [flags] [config]
```

Every command that takes a config defaults it to `./zap.ts`. `zap` with no
command prints the loop and exits 0; `zap --help` prints the command list, and
`--help` on any command prints its flags.

## Commands at a glance

| Command | Does | Touches the target | Writes |
|---|---|---|---|
| `zap plan` | detect, then diff desired against live | reads | last-run report |
| `zap apply` | dry run: the plan, as `apply` would run it | reads | last-run report |
| `zap apply --wetrun` | execute the reviewed plan, then re-detect | **changes it** | `zap.lock`, pending-trigger markers on the target, last-run report |
| `zap deploy` | dry run: the release plan, every step in full | reads `current` over SSH | the deploy preview |
| `zap deploy --wetrun` | execute the reviewed release plan: build, upload, swap, restart, health-check | **changes it** | releases, `current`, `deploy_info.json` and the deploy lock on the target, last-run report (preflight); withdraws the deploy preview |
| `zap detect` | the live verdict per resource, no diff | reads | last-run report |
| `zap status` | the last run's verdicts, offline | no | nothing |
| `zap config validate` | eval the config and run the machine-free gates | no | nothing |
| `zap lock` | pin the `fgro` build and rebuild `zap.lock` from upstream | no (fetches URLs) | `zap.lock` |
| `zap lock --check` | classify `zap.lock` against the config | no | nothing |
| `zap update [ids…]` | re-fetch and advance lock pins | no (fetches URLs) | `zap.lock` |
| `zap version` | print the version | no | nothing |

All of them but `version` evaluate the config first, with the `fgro` build
`zap.lock` pins (`zap lock` pins the one it is given), and run the two
machine-free gates: a hardcoded secret literal or a structural error (a duplicate id, a
dangling `depends_on`, a cycle, service intent on a target with no
`service_manager`, …) fails every command with the same message. See
[configs.md](./configs.md#what-the-gates-reject).

## Shared flags

| Flag | On | Meaning |
|---|---|---|
| `--fgro <path>` | every config command | the `fgro` binary that evaluates the config, by absolute path; overrides `ZAP_FGRO`. Under `sudo`, which resets the environment, the flag is the only way to name it ([install.md](./install.md#getting-fgro)). |
| `--env-file <path>` | every config command | load `NAME=VALUE` lines into the operator environment before anything resolves ([env.md](./env.md#the-env-file)) |
| `--no-cache` | `detect`, `plan`, `apply`, `deploy` | re-evaluate the config even under `ZAP_EVAL_CACHE=skip`, which otherwise serves a cache hit; by default every command evaluates fresh. The other commands that read a config take no `--no-cache` and serve a hit under `skip`. Only the config's evaluation is cached; the target is always read live. |
| `--bootstrap` | `detect`, `plan`, `apply`, `deploy` | connect as the target's `bootstrap_user` instead of `user`; a different plan from the primary user's ([targets.md](./targets.md#the-bootstrap-user)) |
| `--json` | `apply`, `deploy` | stream events as JSON lines to stdout during a wetrun (no effect on a dry run); a wetrun that ends before its first event prints its text report to stderr |
| `--wetrun` | `apply`, `deploy` | execute. Without it neither changes the target. |

## `zap plan`

```
zap plan [--diff] [--no-cache] [--bootstrap] [--fgro <p>] [--env-file <p>] [config]
```

Detects every declared resource live and renders the changeset: one `[+]`
(create) or `[~]` (update) line per resource, its steps under it, and the
`plan_hash` at the end. `--diff` adds per-resource `current → desired`
attribute lines above a drifted resource's steps; every change still shows its
steps, so the view prints everything the `plan_hash` covers, as `zap plan` does.

Under the header come the lines naming the machine and environment the plan is
for. They are part of the plan and its hash, so a preview made as one user or
under one `HOME` doesn't bind a wetrun as another: `sudo zap apply --wetrun`
runs as root and refuses a review made without it.

| Line | Printed | Shows |
|---|---|---|
| `host:` | remote, when the declared host is a reference | the host it resolves to |
| `user:` | remote | the connecting user, or `(none — ssh chooses)` |
| `user:` | local | the user Zap runs as |
| `home:` | local | the `HOME` a `~` resolves to (an `--env-file`'s value included), or `(none — HOME is unset)` |
| `target:` | always | the declared target as one line of JSON (`{"local":true}`), a reference in its exact form (`{"$env":"NAME"}`) |
| `references:` | when the changes use references | one line each: `NAME = value`, `NAME is a secret: …`, or `NAME is unset or empty: …`. A value past 200 characters is cut, with the rest's length and the start of the whole value's blake3. |

Under each change come the lines that say what it declares (its `name:` when it
has one, a file's `path:`, `mode:`, and `content:` descriptor, a link's `to:`, a
script's `check:`, `cwd:`, and `env:`, an `apt_repo`'s `key:` URL and the `pin:`
its bytes must have, a swap's `size:`, a pipeline's `max_concurrency:` and its
`step:` ids and `step name:` labels), then its steps. A `content:` descriptor's
SHA-512 is of the text as written: for a template, the template before its
variables are filled, followed on the same line by its `vars` and their
`kinds`, each as JSON.
Multi-line text prints indented under its first line, and control and invisible
characters print as `<U+XXXX>`
([security.md](./security.md#escaped-output)).

A step line starts with `>`, `#`, or `=`. `>` is a command Zap runs as written.
`#` is never run as written: it is a `verify` assertion Zap checks itself, or a
step the target's manager has no command for. `=` is one of Zap's own
operations, named with what it acts on and never printed as the script that
performs it:

```
  [+] deploy  (user)
      > id -u -- 'deploy' >/dev/null 2>&1 || sudo useradd -m -d '/home/deploy' -s '/bin/bash' -- 'deploy'
      > sudo chown -h -- 'deploy:' '/home/deploy'
      > sudo usermod -s '/bin/bash' -- 'deploy'
      = dir /home/deploy/.ssh  (mode 700, owner deploy:deploy, as root, created if missing)
      = put /home/deploy/.ssh/authorized_keys  (mode 600, as deploy; 126 bytes, sha512 ef415c5c6a4db94b…)
          text: ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExampleKeyOne deploy@laptop
                ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExampleKeyTwo deploy@ci
      > sudo usermod -p '*' -- 'deploy'
      = put /etc/sudoers.d/deploy  (mode 440, as root, checked by visudo; 86 bytes, sha512 2434fdb3c08c85f2…)
          text: deploy ALL=(ALL) NOPASSWD: /usr/bin/systemctl restart app, /usr/bin/journalctl -u app
  [+] pgdg  (apt_repo)
      key: fetched from https://www.postgresql.org/media/keys/ACCC4CF8.asc
      pin: blake3 bb84ad7105529a9bf29a01dca1d2e400576031b070e396a9f0c669bf75457192
      = put /etc/apt/sources.list.d/pgdg.list  (mode 644, as root)
          from: the line below, as the target's shell reads it inside double quotes after reading /etc/os-release: a variable in it expands and a $(…) in it runs, at every plan too
          line: deb [signed-by=/usr/share/keyrings/pgdg.asc] https://apt.postgresql.org/pub/repos/apt $VERSION_CODENAME-pgdg main
      > sudo apt-get update
```

- `= put <path>` installs a file ([security.md](./security.md#writes-on-the-host)).
  The parentheses give its mode, the account the write runs as, and a check the
  staged file must pass. Text Zap holds prints whole under `text:`, less its
  final newline, with its length and the start of its SHA-512; a text with no
  final newline says so in the parentheses. Text the target produces has a `from:`
  line saying where it comes from and what skips the put. Text the config
  supplies for it prints under `line:`: an apt source line (which the target's
  shell expands, at every plan as well as on apply, so a `$VERSION_CODENAME` in
  it is read there and a `$(…)` in it runs), an `/etc/fstab` entry.
- `= run the script fetched from <url>  (piped to <shell>)` is an `installer`:
  the URL and the shell as the config declares them.
- `= dir <path>` creates a directory if it is missing and sets its mode and
  owner.
- `= check <path>  (not a link, below directories only root writes, as root)`
  comes first in a `swap` file's creation, and refuses a link at the path or a
  directory on the way to it that another account can write
  ([resources.md](./resources.md#swap)).
- `= pg_hba rule: <line>` adds the line to the server's `pg_hba.conf`, as the
  `postgres` account, unless it is already there. A line it adds is put in
  force by reloading the server's configuration; a line already there reloads
  nothing. A file that doesn't belong to `postgres` is left unchanged and the
  step fails, and so does a file the server can't parse (`pg_hba_file_rules`
  lists an `error`, checked before the reload), a reload it doesn't confirm, or
  a reload it doesn't load within 30 seconds.

A `=` step that fails is reported by the same words, in the run's report and in
the `change_failed` event's `error`:
`put /etc/sudoers.d/deploy (mode 440, as root, checked by visudo) exited 93: …`.

A pass that can't establish a verdict says so before the plan, under an
`UNDETERMINED`, `UNVERIFIABLE`, or `LOCK` [banner](#banners).

Exit codes:

| Code | Meaning |
|---|---|
| 0 | every resource was read, and every reference and pin resolved. Pending changes still exit 0: `plan` reports, it doesn't judge. |
| 1 | something is unestablished: a held resource, an unresolved reference, or a lock standing error |

The pass is recorded as a preview, so a following `zap apply --wetrun` binds to
its plan ([concepts.md](./concepts.md#a-wetrun-executes-only-the-plan-you-reviewed)).
A plan whose host or connecting user resolves through a masked reference names
no one machine: it is shown under an `UNBINDABLE` note with no `plan_hash`, and
is not a preview. When it is the host, the pass also keeps no last-run report
and says so under an `UNRECORDED` note.

## `zap apply`

```
zap apply [--wetrun] [--expect-plan <hash>] [--json] [--no-lock]
          [--no-cache] [--bootstrap] [--fgro <p>] [--env-file <p>] [config]
```

Without `--wetrun`, the same pass as `plan`, rendered as what `apply` would do,
and exit codes that judge the result (below). It also resolves any missing
tracked pin over the network and reports it as
`resolved, not yet written to zap.lock`; the write waits for a wetrun.

`--no-lock` leaves the lock's entries alone: no tracked pin is read, nothing is
fetched to pin a tracked source, and nothing is written. A tracked source then
has no pin, so its resource holds; a config with none runs as usual, offline.
The toolchain pin is still read, and without one the command refuses as any
other does.

With `--wetrun`, apply:

1. rejects the run if any variable the config references is unset or empty, or
   if the target's host or connecting user resolves through a masked reference;
2. detects and plans;
3. **checks the plan against the review** (next section) and refuses if it
   doesn't match, or on an interactive terminal shows the plan and asks;
4. refuses if any planned command can't take a value its reference resolves to
   (a single quote in a command, for one), naming the resource and the variable;
   `zap plan` and a dry run warn about the same thing ahead of time;
5. claims the preview it bound to, so one preview covers one wetrun: of two
   wetruns started on one preview, the one that claims it first goes on and the
   other stops with nothing changed (exit 2);
6. re-checks that every reference the plan recorded still resolves to the
   recorded value, refusing (exit 2) if one moved while the run was in progress;
7. writes `zap.lock` when the config has tracked pins;
8. executes the changes in dependency order, stopping at the first failure,
   writing a pending-trigger marker on the target before the first source of a
   triggered service and clearing it after the service's change;
9. re-detects every resource and reports any that still isn't converged as
   `RESIDUAL`.

While steps 8 and 9 run, each change and the re-detection print one line to
standard error as they start (`→ notes: create directory`); the report, on
standard output when the run ends, holds every outcome. `--json` prints no such
line.

### Binding to the review

A wetrun executes only the plan you reviewed: the plan it computes must equal,
hash for hash, the one named by `--expect-plan <hash>` or the one in the most
recent preview on this host. Otherwise it **refuses**, changes nothing, and
exits 2. A preview binds once Zap has printed it, read or not: one sent to
`/dev/null` or cut short by `head` binds the same. The rules are in
[concepts.md](./concepts.md#a-wetrun-executes-only-the-plan-you-reviewed).

On an interactive terminal, a wetrun whose plan has no review (no preview, or a
preview of a different plan) and no `--expect-plan` shows the plan and asks instead:

```
$ zap apply --wetrun
apply — target local (wetrun, awaiting confirmation)
  user: ops
  home: /home/ops
  target: {"local":true}
  [+] notes  (directory)
      path: ~/notes
      mode: 755
  [+] hello  (file)
      path: ~/notes/hello.txt
      content: inline (15 bytes, sha512 0c7463f032f1dc98…)

  UNREVIEWED — nothing has run: this plan runs only once it is confirmed below.
    no plan has been previewed on this host.
plan_hash: 5bb79cc9141942676c784abba55826f12be51b3feb86f5f0cf77666545674d61
Apply this plan? Type 5bb79cc9, the start of its plan_hash, to confirm: 5bb79cc9
→ notes: create directory
→ hello: create file
→ re-detect: reading 2 declared resources back to confirm what the changes left
apply — target local (wetrun, confirmed)
  user: ops
  home: /home/ops
  target: {"local":true}
  ok    notes
  ok    hello
applied: 2 ok, 0 failed, 0 skipped (of 2)
plan_hash: 5bb79cc9141942676c784abba55826f12be51b3feb86f5f0cf77666545674d61
```

The plan and the question go to standard error, as do the `→` lines a wetrun
prints as each change and the re-detection starts; the report goes where it
always does. The answer is the first eight characters of the plan's
`plan_hash`, in either case. Input typed before the question appears is
discarded, so neither a `y` nor an earlier run's answer typed ahead while Zap
reads the machine runs anything. Those
characters execute the plan shown and nothing else; any other answer (a `y`,
the whole hash, an empty line, the end of the input) declines: the plan is
rendered again under a `DECLINED` banner, recorded as the preview, and the exit
is 2, as for a refusal. There is no flag that answers for you. Interrupting at
the question (Ctrl-C) ends the run with nothing executed and nothing recorded
as a preview, so the next wetrun asks again. It never asks under `--json`, for
a mismatched `--expect-plan`, for a plan with no hash, or for a plan a command
can't run.

**Scripting.** The question appears only on an interactive terminal, for
a plan with no review. A script stays non-interactive by previewing first (a dry run,
then the wetrun), by passing `--expect-plan <hash>`, or by running with
standard input that isn't a terminal (`< /dev/null`). A non-interactive wetrun
with no review of its plan refuses, and `--json` never asks.

`--expect-plan` makes the binding explicit: the hash from the plan you reviewed,
perhaps in a pull request or an agent's transcript. It is the binding to use
when the preview's output may be truncated, or when the one who reads it isn't
the one who runs the wetrun. The match is exact. A dry run
rejects the flag. `zap deploy` follows the same rule against its own preview
([below](#zap-deploy)).

Exit codes:

| Code | Dry run | Wetrun |
|---|---|---|
| 0 | no changes pending | every change completed, and the re-detection read everything converged |
| 2 | changes pending; `--expect-plan` without `--wetrun` | refused: the plan was not the reviewed one (or was declined at the prompt), its preview was claimed by another wetrun first, or a command can't take a resolved value; or an error before anything runs: the host or connecting user is behind a masked reference |
| 1 | a held resource or an unresolved reference | a failed change, a residual resource, a failed re-detection, a held resource, or a preview that couldn't be withdrawn |

## `zap deploy`

```
zap deploy [--wetrun] [--expect-plan <hash>] [--force] [--skip-build]
           [--skip-preflight] [--json] [--no-cache] [--bootstrap]
           [--fgro <p>] [--env-file <p>] [config]
```

Ships a release to a remote target: build locally, tarball the artifacts,
upload, extract into `releases/<version>`, swap the `current` symlink, restart
the service, poll health. Full mechanism: [deploy.md](./deploy.md).

A dry run reads `zap.lock`, connects over SSH to read the live `current`
symlink, prints the plan (the version and the release it replaces, the commit's
subject, the resolved host and connecting user, the declared target, the tree
and preflight state, and every step with its command, script, paths, or URL),
closes with a recap of the commit, version, host, user, tree, and preflight, ends
with the `plan_hash`, records the plan as this host's **deploy preview**, and
exits 0. If the live release is already this version it reports
`server already at this version`, prints no hash, records nothing, and exits 0,
on a dry run too; `--force` deploys anyway.

A dry run prints no `plan_hash` and records no preview when:

- the host, connecting user, or health domain resolves through a masked
  reference;
- the checkout has uncommitted changes or untracked files and no `--force`
  (never reported as already at this version, since the tree isn't what the
  live release holds).

A wetrun of either is refused.

A wetrun executes only the reviewed plan, as `zap apply`'s does, but against the
deploy preview: its plan's hash must equal `--expect-plan` or the recorded
preview's, or it refuses before the preflight and any step, becomes the new
preview, and exits 2 (on an interactive terminal with no `--expect-plan` it asks
for the start of the `plan_hash` instead). A wetrun that passes withdraws the
preview before its first step, so one recorded preview covers one execution.
`zap status` doesn't show the deploy preview. The rules are in
[deploy.md](./deploy.md#binding-a-wetrun-to-a-reviewed-plan).

A wetrun prints one line to standard error as each phase starts (the drift
preflight, each step, a rollback), and its report to standard output when it
ends: a table of the preflight, each step, and any rollback, each with its
status and how long it took, then a closing line naming the version live on the
host, or, after a failure, the step that failed and the state the target is in. Samples:
[deploy.md](./deploy.md#what-a-wetrun-prints).

Flags:

| Flag | Meaning |
|---|---|
| `--expect-plan <hash>` | bind to this hash instead of the recorded preview: execute only if the plan has exactly it. Wetrun only, and not single-use. |
| `--force` | deploy an unchanged version, and version a dirty tree `<hash>-dirty-<id>`, named by its changes. Without it a wetrun of a dirty tree is refused. |
| `--skip-build` | leave `deploy.build` out of the plan; ship the artifacts as they are |
| `--skip-preflight` | skip the drift preflight. The machine-free gates and the env check still run. |

`--skip-build`, `--skip-preflight`, `--force` on a dirty tree, and `--bootstrap`
each change the plan, and so its hash: a wetrun binds to a preview made with
the same flags.

Exit codes:

| Code | Meaning |
|---|---|
| 0 | dry run rendered, release deployed, or already deployed |
| 2 | refused: the plan was not the reviewed one, was declined at the prompt, or its preview was spent by another run first |
| 2 | the preflight found drift, or couldn't read every resource |
| 2 | a wetrun whose host, connecting user, or health domain resolves through a masked reference, or from a dirty checkout without `--force` |
| 2 | `--expect-plan` on a dry run; a `zap.lock` that doesn't parse |
| 1 | a step failed, including the release script finding another deploy of the app holding its deploy lock or having swapped since this plan was made (rollback may have restored the previous release; the exit stays 1); the recorded preview couldn't be withdrawn; `zap.lock` couldn't be opened |

## `zap detect`

```
zap detect [--no-cache] [--bootstrap] [--fgro <p>] [--env-file <p>] [config]
```

The detection half of `plan`, rendered raw: one line per resource with its
mark (`ok`, `drift`, `absent`, or `?` for undetermined), its id and kind, and,
for drift, what was observed. For validating that a probe reads a real target
correctly. Over a host that resolves through a masked
reference it keeps no last-run report and ends with an `UNRECORDED` note.

| Code | Meaning |
|---|---|
| 0 | every resource was read and every reference and pin resolved; drift and absence still exit 0 |
| 1 | a resource marked `?`, an unresolved reference, or a lock standing error |

## `zap status`

```
zap status [--fgro <p>] [--env-file <p>] [config]
```

Offline: evaluates the config, reads the last-run report for the host the target
resolves to ([detection.md](./detection.md#the-last-run-report)) and the on-disk
`zap.lock`, and never touches the target. It says what the last run saw, never
what the target is now; the live signal is `zap plan`. A referenced host needs
its env (`--env-file`), as for a run. For an exact answer it needs the same env
as the run that wrote the report, secrets included: a secret it can't mask reads
as "config changed since", never as a false "unchanged".

```
$ zap status
target local (pkg: none, service: none)
last run on local: zap apply --wetrun, after its changes ran, at 2026-10-11T21:09:26Z — offline; `zap plan` reads the target live
  a 0 exit means every declared resource read converged in the last run and its config is unchanged since — not that the target still is
  converged    notes  directory
  converged    hello  file
```

Each line is a resource's verdict in that run, with a note when:

| Note | Meaning |
|---|---|
| `config changed since; this verdict predates it` | the resource's hash no longer matches: it was edited, an ordinary variable it references resolves differently, or its pin moved. When the target itself changed (its package or service manager, home, user), a note names it and every verdict predates it. |
| `depends on a secret; a changed value isn't visible offline` | it references a secret |
| `not read` (`not in the last run`) | declared, but not in the last run: added since, or there is none |
| `orphaned` (`read …, no longer declared`) | in the last run, no longer declared; warn-only |

A preview's `plan_hash` is printed as the plan `zap apply --wetrun` binds to. The
lock standing and an `UNVERIFIABLE` banner, for the last run or for now, lead
the render. With no last run every resource is `not read`, so `status` exits 1
unless nothing is declared.

| Code | Meaning |
|---|---|
| 0 | every declared resource read converged in the last run and its config is unchanged since (a secret's value excepted); lock clean; nothing unverifiable |
| 2 | the last run read drift or absence |
| 1 | anything unestablished: not read, changed since, undetermined, unverifiable then or now, a lock error, no last run, or a host that keeps none (one behind a masked reference) |

## `zap config validate`

```
zap config validate [--fgro <p>] [--env-file <p>] [config]
```

Evaluates the config and runs the two gates, nothing else. Prints
`ok: N resource(s)` and exits 0, or the gate's message and exits 2. The fast
check for CI and editors: no target, no network, no secrets needed, but a copy
of the pinned `fgro` build ([lock.md](./lock.md#the-toolchain-pin)).

## `zap lock`

```
zap lock [--check] [--fgro <p>] [--env-file <p>] [config]
```

The verbs over `zap.lock`, the ledger for the toolchain pin and the tracked
`remote` files and `build` sources ([lock.md](./lock.md)).

`zap lock` pins the toolchain, the blake3 of the `fgro` binary it evaluates the
config with, re-fetches every tracked source, re-mints every entry, drops
orphans, and rewrites the file. All or nothing. It is the only command that
evaluates with a binary the lock doesn't pin, and the only one that moves the
toolchain pin ([lock.md](./lock.md#the-toolchain-pin)).

`zap lock --check` first holds the `fgro` binary to the toolchain pin: with a
binary that hashes to something else it reports the pin stale without
evaluating the config, so the entries go unchecked. Otherwise it classifies
each entry offline as current, missing, stale (the resource changed since the
pin), unverifiable (a variable the hash takes by value is unset), or orphaned.
Its 1 is a read-only verdict, like `plan`'s held resources; `apply`, which
refuses to act on a stale or unverifiable entry, treats the same finding as an
error and exits 2, as does a `deploy` wetrun's preflight.

| Code | Meaning |
|---|---|
| 0 | `zap lock`: the lock was written. `--check`: every entry is current; orphans only warn. |
| 2 | no toolchain pin (`--check`); a tracked URL that references an unset or empty variable (`zap lock`, which then fetches nothing) |
| 1 | `--check`: a pin missing, stale, or unverifiable. Either: a fetch or another operational error ([all commands](#exit-codes-all-commands)) |

Both print a `note:` for each reference the lock addresses by name only, because
its name or the form of its value reads as a secret ([lock.md](./lock.md)).

## `zap update`

```
zap update [--config <p>] [--fgro <p>] [--env-file <p>] [ids…]
```

Re-fetches the named resources, or every tracked one, and rewrites each entry
whose pin advanced or whose recorded config hash is stale. Each advance is
written as it happens, so a later failure keeps the earlier ones. A tracked URL
that references an unset or empty variable is never fetched, and that entry
fails. The config is `--config <path>` here, since the positional arguments are
ids. A failed entry keeps the code its error has everywhere else: exit 1 if any
failure is operational (a fetch, a write), else 2 if any entry failed on an
input to fix (an unset reference in its URL or credential, a signature that
doesn't verify). It prints the same `note:` lines as `zap lock`.

## `zap version`

Prints `zap <version>`.

## Banners

What a pass couldn't establish, or why it didn't act, leads its report:

| Banner | Means | Exit |
|---|---|---|
| `UNDETERMINED` | resources detection couldn't read, each with why, then the changes held behind them, each with what it waits on or would trigger; all held out of the plan | 1; 2 in a deploy's preflight |
| `UNVERIFIABLE` | referenced variables that were unset or empty | 1; a wetrun refuses with 2 |
| `LOCK` | a tracked pin that is missing, stale, or unverifiable | 1; `apply` and a deploy wetrun refuse with 2 |
| `UNREVIEWED` | a wetrun's plan has no review; on a terminal, Zap asks | |
| `REFUSED` | a wetrun that didn't execute; its plan becomes the preview | 2 (1 when a resource is held) |
| `DECLINED` | the confirmation wasn't the plan's hash prefix | 2 |
| `RESIDUAL` | resources that still don't read converged after a wetrun | 1 |
| `UNBINDABLE` | the host, connecting user, or (deploy) health domain is behind a masked reference: no `plan_hash`, not a preview | |
| `UNRECORDED` | the host is behind a masked reference: no last-run report kept | |

## Exit codes, all commands

The pattern across commands. The tables list 2 before 1 because 2 is still an
established answer and 1 is not:

| Code | Family |
|---|---|
| 0 | established and fine: converged, deployed, nothing to do |
| 2 | established and needs a decision: changes pending (for the commands that judge them: `apply`, `status`), a refused or declined wetrun, preflight drift, a config error |
| 1 | unestablished or failed: a held or unverifiable resource, a failed change, a failed step, an operational error |

`plan`, `detect`, and a deploy dry run report rather than judge: pending changes
exit 0 there.

A report that can't be written (standard output a pipe whose reader has gone,
or a full device) prints `error: the report could not be written:` and the
reason on standard error.
A run whose report is its answer (`plan`, `detect`, `status`, `lock --check`,
`config validate`, `version`, the help, a dry run, a refused wetrun) then exits
1 where it would have exited 0. A preview whose report couldn't be written was
still recorded, and binds the next wetrun run without `--expect-plan`. A run
that changed something keeps its own code, which describes the machine or the
lock: an `apply` wetrun that ran changes or pinned what the lock lacked, a
`deploy` wetrun that reached its steps, `lock`, and an `update` that advanced or
refreshed an entry. An `apply` wetrun with nothing to do, or an `update` that
moved no entry, only answered. A non-zero code is kept either way. An error or a
usage error that standard error can't take is lost, and exits with its own code
all the same.

An error prints as `error:` and its message; a message of several lines is
indented under it, and any advice Zap adds follows at the left margin.

Errors raised before a report exists follow the same split.

Exit 2, a problem in your inputs:

- `fgro`: none named; a path that isn't absolute; one that is missing, a link, a
  script or set-ID file, or doesn't hash to the toolchain pin; one that answers in
  an eval protocol or graph version this `zap` doesn't read; no toolchain pin; an `fgro` pin
  cache under `~/.zap` that isn't yours.
- `zap.lock`: one that doesn't parse or is newer than this `zap` reads; a lock
  stale or unverifiable; a content-hash or signature mismatch.
- The config: not found; named as its own lock would be (`*.lock`); it or its
  directory writable by every user; no project; a `package.json` on the way up
  that can't be read or isn't valid; no user the evaluation may run as (a project
  root owns, a project that is or holds that user's home, a directory on the way
  it can't search, a group or passwd entry it can't use); eval failure; a schema
  error.
- The environment: an env-file error; a `ZAP_HOME` or `HOME` unset where needed
  or not absolute; a state directory that isn't Zap's own; an unresolved
  reference on a wetrun.
- A wetrun refused before its first change: a plan that names no one machine, a
  command that can't take a value its reference resolves to, or a reference that
  moved while the run was in progress.
- A `deploy` wetrun from a checkout with uncommitted changes or untracked files
  and no `--force`.
- A usage error: an unknown flag, or `--expect-plan` without `--wetrun`.

Exit 1, a problem in the world: connectivity, a command that can't spawn, a file
operation, a fetch, a git error; an `fgro` that crashed, wrote output that isn't
its protocol, or couldn't be spawned; an `fgro` binary written while Zap hashed
it or before it ran, which a retry clears once nothing writes it.

## JSON events

`--json` on a wetrun of `apply` or `deploy` streams one JSON object per line to
stdout, instead of the text report. A wetrun that ends before its first event (a
refusal, a preflight bail, an already-deployed release) leaves stdout empty and
prints its text report to stderr. Control and invisible characters in a value
are written as JSON `\u` escapes, so the stream decodes to the same values and
is safe to watch. Each event carries an `event` tag:

| `event` | Fields | When |
|---|---|---|
| `run_started` | `target`, `wetrun`, `plan_hash`, `total` | once, before any change |
| `change_started` | `resource_id`, `action` (`create` / `update`), `kind` | a change is about to run |
| `change_completed` | `resource_id`, `output` | it finished |
| `change_failed` | `resource_id`, `error`, `code` | it failed; execution stops |
| `change_skipped` | `resource_id`, `reason` | not run, because an earlier change failed |
| `step_started` | `step`, `name` | a deploy step is about to run |
| `step_completed` / `step_failed` / `step_skipped` | `step`, plus `output` / `error` / `reason` | the deploy step's outcome |
| `run_finished` | `summary` (total / completed / failed / skipped counts) | once, at the end |

A step skipped after an earlier failure has no `step_started`, but a started
step's outcome can be `step_skipped` too: a readiness check the target doesn't
serve, or a rollback whose swap back finds nothing to do (another deploy holds
the app's lock, `current` no longer names the failed release, or names nothing, or the previous
release is gone). A rollback with nothing to return to is skipped without
starting.

`code` on a failure is a triage category: `transient`, `permission`,
`not_found`, `conflict`, `permanent`, or `execution_failed` (`permission`
includes `sudo`'s own refusals). A file operation Zap makes itself is classified
by the error the system returned (a symbolic link or anything else in the way,
or a full disk, is `conflict`; a timeout is `transient`); a command, or `ssh`,
by its exit code and what it printed. Every value is masked: a resolved secret
never appears in an event.

Events carry no duration: a consumer reading the stream live can time it by
when each line arrives. The `→` progress lines a text-mode wetrun prints to
standard error are not events and are not in the stream.

A run that streamed events doesn't print its text report, and the report's
`warning:` lines go with it: the stream carries a warning only where an event
holds it. A deploy's rollback is always one: rolled back, failed, or skipped,
with nothing to return to (a broken release left live) among the skips. The
others, such as a deploy's repairs of an unfinished one or a failed prune,
aren't in the stream.

## Environment variables Zap reads

| Variable | Meaning |
|---|---|
| `ZAP_HOME` | where Zap keeps operator-side state (default `~/.zap`): the eval cache, the `fgro` pin cache, the content cache, last-run reports, deploy previews, SSH multiplexing sockets. An absolute path; empty counts as unset. See [lock.md](./lock.md#on-disk-state). |
| `ZAP_FGRO` | the `fgro` binary that evaluates configs, by absolute path (an empty one is an error, not unset); never looked up on `PATH`. `--fgro` overrides it, and is the one that survives `sudo`. Name a copy you update deliberately, not Gro's build output ([install.md](./install.md#getting-fgro)). |
| `ZAP_MINISIGN` | the `minisign` binary a `build` source's `verify` runs, by absolute path (an empty or relative one fails the verification, saying so); unset, the first `minisign` in an absolute directory on `PATH`. Either is refused when it, or a directory on the way to it, is writable by a group or others or owned by anyone but root and you, or it sits in `node_modules` ([resources.md](./resources.md#verification)) |
| `ZAP_EVAL_CACHE` | `shadow` (default: eval fresh, compare against the cache, report a mismatch) or `skip` (serve a cache hit whose files are unchanged without running `fgro`; a change the evaluation's record doesn't name isn't seen: a symbolic link, in `node_modules` or the project, pointed at other files, or a directory turned world-writable) |
| `ZAP_EVAL_CACHE_LOG` | set to print eval-cache hit/miss observations |

Nothing that shapes a plan comes from Zap's own environment. Values a config
needs come from references resolved from the operator environment or
`--env-file`.
