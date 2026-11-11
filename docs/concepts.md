# Concepts

The ideas behind every zap command. Read this once; the other docs assume it.

## The loop

```
describe → detect → plan → apply → observe
```

You **describe** a machine in `zap.ts`: these packages, this file with this
content, this user with these keys, this service running. Zap **detects** what
the machine looks like now, **plans** the difference, **applies** only that
difference when you say so, and **observes** the result by reading the machine
again. Every command is a slice of that loop.

A task fits Zap when it can be put as: _I want the machine to look like X. What
does it look like now? What needs to change? Do it. Tell me what happened._

## Convergence

A **resource** is one typed piece of desired state with a stable `id`. Most
resources are **convergent**: Zap reads their current state, compares it to the
declaration, and changes only what differs. Re-running is always safe. A
converged resource contributes nothing to the plan.

How much of the live state a declaration claims depends on the field:

| A field that is | Means | For example |
|---|---|---|
| **authoritative** | made exactly the declared value; anything added by hand is removed | a user's `authorized_keys`, a file's content |
| **additive** | each declared entry must be present; an entry added by hand is neither detected nor removed | a firewall's allow rules, a database's `pg_hba` rules, a user's groups |
| **unset** | unmanaged: Zap neither sets it nor reverts it, and a rewrite keeps it | a `file` with no `mode` |

One resource kind is **imperative**: a `pipeline` runs every time, as does
`zap deploy`, which produces a new release every run. You make their steps safe
to repeat.

**Drift** is the gap between the live machine and the declaration: a file edited
on the host, a service stopped, a firewall's default policy flipped at the
console. Zap doesn't
track drift; it finds it by reading the machine on every run, and the plan is the
repair.

What Zap doesn't do: it never removes something you stop declaring. Delete a
`package` resource from the config and the package stays installed. `zap status`
lists such resources as orphaned, as a warning. To remove something, declare
the removal (a `script` whose `check` confirms it's gone).

## Detection

For each resource, detection answers one question, _does the desired state
already exist?_, with one of four verdicts:

| Verdict | Meaning | The planner |
|---|---|---|
| `converged` | the desired state is present | skips it |
| `drifted` | present but wrong; carries what was observed | plans an update |
| `absent` | not present | plans a create |
| `undetermined` | couldn't tell, with a reason | **holds** it out of the plan |

When Zap can't read a resource (a probe failed, a remote path's home isn't
declared, a tracked pin has no lock entry), it doesn't guess: the resource is
held, the command leads with an `UNDETERMINED` banner naming it and why, and the
exit code is 1 (deploy's preflight refuses with 2), never 0. Nothing carries over
between passes; the next run reads it again.

The hold spreads to what can't run without the held resource: a change that
depends on it (directly, or through resources that are converged) and a change
that would restart or reload it are held behind it, and the banner lists them
under it. [detection.md](./detection.md#a-hold-spreads-to-what-cant-run-without-it)

A few kinds on the bring-up path read a failed probe as `absent` instead,
because on a fresh host the probe fails for the reason the config exists
(`ufw status` fails before the same run installs ufw). Which kinds, and how
`database` splits the two cases:
[detection.md](./detection.md#kinds-that-read-a-failed-probe-as-absent).

**Depth follows idempotency.** If re-running a change is a true no-op, shallow
detection is fine: a `package` is checked for existence (or, when its name pins a version, that
version), because installing it again does nothing. If re-running has side effects, detection goes deeper: a
`file` is compared by digest, mode, and owner; a `user`'s keys and sudoers by
content; a `firewall` rule by rule. A `script`'s depth is yours: its `check`
command is the whole idempotency contract.

**Everything is read live, every time.** Zap keeps no detection cache. A stored
answer is only sound when nothing else could have changed the machine, and Zap
never assumes it is the only writer. The security controls make the point:
`firewall`, `user`, and `database` guard the host's access surface and are
exactly what gets changed by hand.

## Dry run and wetrun

No command changes the target unless you pass `--wetrun`. `zap apply` shows what
would change and exits 2 when something would; `zap apply --wetrun` changes it.
Most tools make the dry run the option. Zap makes it the default, and gives the
flag that acts an unusual name so it isn't typed by accident or appended by a
script's `--yes` habit. The default is safe with no terminal and no prompt,
which is what makes Zap safe to hand to a script or an AI assistant.

## The plan

A plan is the changeset for one run: per resource, the action (`create` or
`update`), the steps, the desired state (its references kept as written), and
the dependency order. It is content-addressed: `plan_hash` is the blake3 of the plan's
canonical JSON and of the text Zap's own steps execute, printed at the end of
every `plan` and `apply`.

Two things with different stability go into it. The **declaration** is a function
of your config and the files it reads: the same `zap.ts` over the same files
evaluates to the same desired state, because the config runs in a sandbox with
no network and no environment, with the clock and randomness closed and the time
zone and locale fixed ([configs.md](./configs.md#the-sandbox)). The
**changeset** also depends on what detection found. So the hash addresses "what
this run decided to do against this target."

The plan is for one machine. Its header names the target it resolves to; a
local plan also names the user Zap runs as and the `HOME` a `~` resolves to:

```
$ zap plan
plan — target local (2 change(s): +2 ~0)
  user: ops
  home: /home/ops
  target: {"local":true}
  [+] notes  (directory)
      path: ~/notes
      mode: 755
  [+] hello  (file)
      path: ~/notes/hello.txt
      content: inline (15 bytes, sha512 0c7463f032f1dc98…)
plan_hash: 5bb79cc9141942676c784abba55826f12be51b3feb86f5f0cf77666545674d61
```

A remote plan prints the connecting user in a `user:` line, and the host in a
`host:` line when the declared host is a reference. All of it is in the hash, so
one config under two env files is two plans, and so is the same host with and
without `--bootstrap`. A local plan's hash covers the user Zap runs as and its
`HOME`, so a review made as you binds no local wetrun under `sudo`, which runs
as root, or under another `HOME`.

The plan is for one environment too. A reference in a resource stays written as
its reference (`{env:NAME}`), and the plan records beside it what each reference
its changes use resolves to, printed in a `references:` block under the target:
the value of a plain one, and for a [secret](./env.md#secrets) only that it is
one. So `plan_hash` covers those values: the same config under another value of
`APP_DIR` is another plan. A secret reference's value is never in the plan or its hash,
so rotating one changes neither.

### A wetrun executes only the plan you reviewed

A wetrun doesn't take a saved plan as input; it detects and plans again, because
the machine may have moved. What it guarantees instead is that the plan it
executes is a reviewed one: a plan whose hash you named, or one Zap printed as a
preview. Before it changes anything, it compares its fresh `plan_hash` against
the reviewed plan:

- `--expect-plan <hash>` names the reviewed plan explicitly, and the wetrun
  executes only if the fresh plan has exactly that hash;
- with no flag, the reviewed plan is the one in this host's
  [last-run report](#the-last-run-report), when the pass that wrote it was a
  **preview**: `zap plan`, a dry `zap apply`, or a wetrun that refused. Its
  recorded `plan_hash` must equal the fresh one.

Otherwise the wetrun **refuses**. It changes nothing, renders the plan it would
have run under a `REFUSED` banner that says why (no preview yet, the last run
wasn't a preview, or the plan changed since the preview), records that render as
the new preview, and exits 2. The everyday flow is `zap apply`, read
it, `zap apply --wetrun`. A wetrun fired cold becomes the preview, and the next
one executes if nothing moved. A preview covers one wetrun: one that executes,
whether its changes succeed or fail, spends it, and of two started on one
preview only one goes on. An agent given `--expect-plan` with the hash it
showed you can execute only that plan: the same changes, on the same machine,
as the same user, with the same values for every reference that isn't a secret.
An empty plan needs no review.

A preview is recorded when Zap prints it, not when anyone reads it: Zap knows
what it wrote, not what reached a reader. A preview sent to `/dev/null`, cut
short by `head`, or whose output couldn't be written at all still binds the
next wetrun run without `--expect-plan`. When the output may be truncated, or
the one who reads the preview isn't the one who runs the wetrun, bind with
`--expect-plan`: its hash is the preview's last line, the first one a
cut-short preview loses.

On an interactive terminal, a wetrun whose plan has no review asks for the
first eight characters of its `plan_hash` instead of refusing
([cli.md](./cli.md#binding-to-the-review)).

A plan can only be reviewed if it names its machine. A plan whose host or
connecting user resolves through a reference Zap masks has no `plan_hash`:
`zap plan` and a dry `zap apply` show it under an `UNBINDABLE` note, and
`zap apply --wetrun` is an error before anything runs, even when nothing would
change. The ways out are in [env.md](./env.md#masked-hosts-and-review).

`zap deploy` has its own plan, hash, and recorded preview, and its wetrun
follows the same rule against them
([deploy.md](./deploy.md#binding-a-wetrun-to-a-reviewed-plan)).

## Apply asserts convergence

A wetrun doesn't stop at command success. After the changes run, it reads every
resource again. Any resource that still doesn't read converged is reported as
`RESIDUAL` and the run exits 1: a `script` whose `check` still fails after its
`run`, a mutation that read back wrong. A change that failed or was skipped is
the run's failure already, a held resource its `undetermined`, and a `pipeline`
never reads converged (it always runs), so none of them is residual.
"Applied: N ok" alone would be a claim about commands; the re-detection makes it
a claim about the machine. If the re-detection itself fails, the run says so and
exits 1 too, because "converged" was not established.

## The last-run report

Every detection pass writes a **last-run report** under `~/.zap`, one per config
and host, latest only (none for a host that resolves through a masked reference,
since it would stand for every machine the reference names): when it ran, which command, the host, each resource's
verdict and a hash of its declaration, the names of the references it couldn't resolve,
the batches it ran, and the `plan_hash` when the pass planned. Nothing the
target returned is in it, and no secret's value reaches any hash
([env.md](./env.md#secrets)).

Detection never reads it. `zap status` renders it offline, marking each resource
whose config changed since the run, and it holds the preview a wetrun binds to. Exit
codes are about the last run, not the live machine; the live answer is always
`zap plan`.

## Triggers

Service detection reads running and enabled, not whether the service's config
is fresh. Triggers close that gap: a `file` names the services it `triggers`, or
a `service` names the resources it `restart_on` / `reload_on`. When a source
changes in the current plan, the service is promoted from skip to restart or
reload. A trigger restarts or reloads only a running service: a stopped one is
left stopped and starts on the new state when it starts. A trigger on a service
declared `running: false` is a config error.

A trigger fires only on a change in the current plan, so a failed reload would
be lost: next run the file is converged and the service is running, on the old
config. Zap keeps one marker per owed service on the target under
`/var/lib/zap/pending/`, written before the first source changes and cleared
after the service's change completes. A failed reload stays owed and re-fires on
the next plan. At least once, never zero.

A held service, whether detection can't read it or it is held behind another,
holds every source whose change would trigger it: run alone, the source would owe
a restart that no change in the plan performs. Both wait for a plan that can run
the service.

## The lock file

A moving reference makes intent ambiguous in time: a tracked `remote` file's URL
or a `build`'s source archive can serve different bytes tomorrow. `zap.lock`,
next to `zap.ts` and committed with it, pins each tracked reference to the
blake3 of its resolved bytes. Detection compares the target against that pin, and
only an explicit act moves it: `zap update` (advance one or all), `zap lock`
(rebuild), or a wetrun recording a pin that was missing. A pin that isn't current is withheld from the read-only commands, so
the resource holds rather than being compared against stale bytes. Full detail:
[lock.md](./lock.md).

## Targets and privilege

A config has one **target**: your own machine (`local: true`) or a host over SSH.
Your authority on a remote host is SSH: Zap connects as the user you declare,
with your keys, and escalates with the host's `sudo`. Commands that are
privileged by nature (`apt-get`, `systemctl`, `ufw`) carry `sudo`. On a local
target file operations try natively first and escalate only when denied; over
SSH they run under `sudo`. There is no agent,
no server, and no shared secret. See [targets.md](./targets.md).

## Secrets and references

A config never reads the environment. Anything that varies per machine or is
secret is written as a reference, which the plan's steps keep as written and
Zap resolves when it acts; the plan records what each plain one resolves to, so
a review covers it. A secret's value is masked out of every output, event, and
report. A secret written literally into a config is rejected when Zap can tell
(its value is referenced and set in the environment).
See [env.md](./env.md).

## Deploy

`zap deploy` is the one imperative command: it ships a versioned release to a
remote host as `releases/<version>` plus a `current` symlink, restarts the
service, polls health, and rolls back if the health gate fails. Before shipping,
its preflight runs the convergence pass and refuses to ship onto a host that has
drifted from its config. The same tool that built the machine ships the app.
See [deploy.md](./deploy.md).
