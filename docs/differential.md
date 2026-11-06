# The differential harness

`cargo xtask differential` runs two `zap` binaries against identical states of
the two VMs in [testing.md](./testing.md) and fails if they report anything differently. One is a trusted
**oracle**, by default a release build of `origin/main`. The other is a
**candidate**, by default the working tree.

It proves behavioral **equivalence**, not correctness: a refactor that passes it
changed nothing an operator can observe, across real apt, systemd, and ufw
hosts and real apk, OpenRC, and nftables hosts, over SSH and (on Debian)
through the local connection. What it establishes about the candidate alone,
whatever the oracle says:

- with `--base-by candidate`, that the candidate converges the whole kitchen
  sink from `pristine` through its own review gate, in the fixture's rounds,
  and that a further apply then plans nothing but a `pipeline`;
- that it puts back the drifted state of every scenario that reconverges, and
  that a check which never goes through Zap then reads the machine as it did on
  the base;
- that it can replace a host's bootstrap user in place, and plan as the user
  that replaced it ([Replacing the bootstrap user](#replacing-the-bootstrap-user));
- that its plans of one target state agree with each other and name the machine
  they are for;
- that nothing it prints holds a raw control character.

The mechanics are in the module docs, starting at
`crates/xtask/src/differential/mod.rs`; `cargo xtask differential --help`
summarizes them.

## What it runs

**1. Base.** From `pristine`, one of the two binaries (`--base-by`, the oracle
by default) converges a kitchen-sink config,
`crates/xtask/fixtures/differential/<distro>/zap.ts`, the way an operator does:
a dry `apply`, then `apply --wetrun` bound to that preview, in the rounds the
fixture declares (a fixture may declare resources held from `pristine`, such as
Alpine's `database` before its service starts). Whichever side builds is held
to that declaration, so an oracle that reads `pristine` differently can't build
the base; build with `--base-by candidate`. A last dry `apply` must then
plan nothing but a `pipeline`. The config holds every resource kind that
converges on that distro, with edge cases: paths with spaces and quotes, content
with no final newline or with CRLF endings, `script` checks that read stdin, run
slowly, or carry a reference, tracked and vendored pins, a triggered service, a
firewall that allows `22/tcp` (the harness's own connection is the lockout
test), and privilege canaries that read `ok` only when a probe runs in its
expected lane.

The result is snapshotted as `differential-base` and reused until a hash of its
inputs changes (the `pristine` snapshot, the fixtures, the `src/lib` modules,
the distro's preparation, the test CA, the builder, and the `fgro` build). `--rebase` forces a
rebuild.

**2. Scenarios.** For each scenario, the harness reverts to the base and puts
the target in the scenario's state: a root shell mutation (a same-size edit, a
`chmod`, a removed package, a stopped service, `swapoff`, a flipped firewall
policy, a dropped `pg_hba` line, a pending-trigger marker), an operator-side
change (a `zap.lock` entry dropped or made stale, an env var changed or unset),
or both. Then it runs both binaries, each with its own fresh `ZAP_HOME` and its
own staged copy of the fixtures, over `detect --no-cache`,
`plan --no-cache --diff`, and `plan --no-cache`. Scenarios with `remote` files
run twice, with a cold and a warm content cache. One scenario,
`bootstrap-replace`, is of its own kind: it compares nothing
([Replacing the bootstrap user](#replacing-the-bootstrap-user)).

**3. Reconverge.** A scenario that drifts declared state Zap can put back in one
offline round carries a **probe**: a root shell snippet that never goes through
Zap and prints the state the scenario touches (the firewall's policy and rules,
as the kernel holds them and as their files say, a user's password field and
`authorized_keys`, the database's `pg_hba` rules), read where it is in force
rather than only where detection reads it.
The probe reads the base before the mutation and the target right after it,
where it must read differently, or the drift didn't take. Once the read-only
runs are compared and audited, the candidate alone, with its own staged tree and
a fresh `ZAP_HOME`, applies the drifted state back the way an operator does: a
dry `apply` that must plan exactly the scenario's expected resources and nothing
else but a `pipeline`, then `apply --wetrun` bound to it, which must complete
every change and run the reviewed `plan_hash`. A further dry `apply` must then
plan nothing but a `pipeline`, `detect` must read every resource but the
`pipeline` `ok` (a `pipeline` reads `absent` by design), and the
probe must read what it read on the base. The probe is the check that isn't
circular: a detector that misreads wrong state as converged passes Zap's own
checks and fails it. The candidate alone applies because the read-only phase has
already compared its plan of that state with the oracle's; executing it is the
candidate's own property.

**4. Remote content** is generated deterministically and served from inside
xtask: plain HTTP on loopback for the Zap runs on your machine, and an https
origin on the libvirt gateway address for everything a guest fetches, under a
test CA the harness makes once with `openssl` and keeps in
`~/.cache/zap-differential/pki`. The CA is name-constrained to the names the
origin serves, and only the `differential-base` snapshots trust it, never your
machine or `pristine`. There is no external fetch.

**5. Locks.** Each binary mints its own `zap.lock` with `zap lock`, and the two
are compared: a different version, toolchain pin, or entry pin is an `ERROR`;
the same pins with a different `config_hash` are a divergence under
`--compare exact` and only reported under `--compare semantic`.

**6. Local suite** (Debian only). Both binaries, and the `fgro` build, are
copied to the VM and run there as `ops`, with `--fgro`, against a `local: true`
fixture (`debian-local/zap.ts`), covering
the local connection's native reads and its `sudo` fallback.

Each binary's fixtures, and the local suite's bundle on the VM, are staged as a
project of their own: a `package.json` at the root and the `src/lib` modules
copied in, so the configs' project, and the box they evaluate in, is that tree. A
run's scratch tree is a directory under `~/.cache/zap-differential/runs`, named
for its process. It is removed when the run ends, and a killed run's is removed
by the next run.

Each VM is left at `differential-base` afterwards, or at `pristine` if no base
could be built. A run writes nothing into the repo.

## What makes a scenario count

Two binaries that fail the same way would match, so a compared scenario is an
`ERROR`, and the run fails, unless:

- the oracle's output is a well-formed report: exit 0 or 1, a `detect` that
  reports every fixture resource, and a `plan_hash:` line on each plan;
- no run timed out;
- the oracle's `detect` moved exactly the resources the scenario expects, with
  their marks (some expectations pin a known oracle defect; the scenario table
  labels each);
- the runs were read-only and network-free: neither listener saw a connection,
  no file changed under the audited roots (`/etc`, `/opt`, `/home`, `/root`,
  `/srv`, `/usr`, `/lib`, `/var/lib`, any regular file directly under `/`, and
  `/` itself), and the runtime state no
  file shows (the firewall ruleset with handles, running services with their
  identity, `/proc/swaps`, the postgres roles and databases) reads the same.
  Only proven churn is excluded, and the audit must show its own anchors (the
  fixture's sleeper service, the `postgres` role, an active firewall), so a
  probe failing the same way before and after can't pass blind;
- the candidate's own output is consistent: its `plan` and `plan --diff` of one
  state (and its cold and warm runs) print one and the same `plan_hash`; each
  plan names its machine directly under the header (over SSH, `host:` and
  `user:` lines, then `target:`; on the local suite, `user:` and `home:` lines,
  then `target:`); and no line of its output holds a control character;
- in a scenario that reconverges, every check of the reconverge phase holds,
  the apply fetched no remote content, and it left the candidate's `zap.lock` as
  `zap lock` minted it. A failure here is tagged `[reconverge]`, so it reads
  apart from a failure of the read-only phase.

Only an SSH scenario reconverges, and only one whose expected marks are all
`drift` or `absent` (a held `?` stops the preview at exit 1), with no
operator-side change and no `remote` content: the apply fetches nothing.

## Replacing the bootstrap user

`bootstrap-replace` rehearses what an operator does once a host is up: replace
the stock account it was brought up with
([The bootstrap user](./targets.md#the-bootstrap-user)) by a user of its own,
then remove the stock account. It runs on both distros, in the default matrix,
with the candidate alone and its own small configs,
`crates/xtask/fixtures/bootstrap/`, kept apart from the kitchen sinks so the
base doesn't depend on them. From the base:

1. **Provision.** `zapnext` doesn't exist yet. A config whose target connects
   as `zapnext`, with `ops` as its `bootstrap_user`, declares that user with
   `ssh_keys: {copy_from: 'ops'}`, `sudo: 'nopasswd'`, and `/bin/sh`. It is
   locked, previewed with `apply --bootstrap`, which must plan the user's
   creation and nothing else and name `ops` as its user, applied with
   `apply --bootstrap --wetrun` bound to that preview, and previewed again,
   which must plan nothing.
2. **Prove.** Over its own login, `zapnext` is who it says, `sudo -n true`
   works, and the grant is Zap's: `/etc/sudoers.d/zapnext` holds Zap's line,
   root's at `440`, and `zapnext` is in no `sudo`, `wheel`, or `admin` group.
   Its `authorized_keys` is `ops`'s, byte for byte.
3. **Retire.** As root through `zapnext`'s login (a session of `ops` can't
   remove `ops`), `ops`'s sessions are ended and its processes killed, a
   bounded wait sees none left, and `userdel -r ops` runs without `-f`, so a
   process that outlives the kill fails it. On Debian, cloud-init's
   `/etc/sudoers.d/90-cloud-init-users`, which grants `ops` by name, must grant
   no one else, and is removed.
4. **After.** As `zapnext`: `ops` has no account, no home, no sudoers line, and
   no group, `visudo -c` passes, and `zapnext`'s keys are unchanged. A login as
   `ops` is refused, and a login as `zapnext` right after succeeds, so a VM
   that went down can't read as the refusal.
5. **Plan as `zapnext`.** A second config declares the same user with the same
   attributes, its keys as the list it holds (a module the harness writes from
   `zapnext`'s `authorized_keys`, never checked in). Its `plan`, without
   `--bootstrap`, reads `(no changes — converged)` and names `zapnext` as its
   user. The first config, its `copy_from` source gone, plans the user again,
   and its `detect` gives the reason, `ssh keys unreadable`: a missing source
   reads as drift to apply, never as converged.

```
  PASS     ssh/bootstrap-replace           11.1s  (revert 7.5s, provision 1.3s, prove 0.8s, retire 0.5s, after 1.0s)
           the bootstrap user replaced in place: zapnext provisioned with --bootstrap, then ops retired over zapnext's own login
           zapnext logs in, its sudo is zap's grant alone, and it holds ops's keys
           ops retired: no account, home, sudoers line, or group; its login is refused
           as zapnext: the retired config reads converged; the provision config's copy_from source reads unreadable, not converged
```

It proves that sequence on these VMs, not every host's: a host whose sshd
admits only some users (`AllowUsers`), or whose stock account holds sudo some
other way, needs its own steps. It doesn't compare the two binaries or run
the read-only audit: it writes on purpose, and the audit reaches the VM as
`ops`. Its own checks stand in: root's reading of the accounts and sudoers
after the retire, and the run fetching nothing. Every step after the retire
reaches the VM as `zapnext`. The revert that starts the next scenario, or the
run's last one, brings `ops` back.

Under `--keep` it stops after step 2, leaving `ops` in place: a VM left
without `ops` stops the next run before any revert, since the harness waits
for the VM as `ops`. A run killed after the retire leaves it that way; revert
the VM by hand:

```sh
virsh -c qemu:///system snapshot-revert <domain> differential-base
```

## Prerequisites

- Both VMs from [testing.md](./testing.md), each with a `pristine` snapshot and your key in
  `ops`'s `authorized_keys`.
- `ZAP_FGRO`, the absolute path of the `fgro` build both binaries evaluate the
  fixtures with. Each run is given it as `--fgro`; each staged config, and the
  local bundle's, starts beside a `zap.lock` pinning it, generated from that
  binary rather than checked in, since an `fgro` build names one machine's
  bytes; and the local bundle carries a copy to the Debian VM, whose kernel
  must hold `fgro`'s sandbox (Landlock ABI 6 or later).
- GNU `tar` and `gzip`, and `ping`.
- `openssl` on `PATH`, the first time, to make the test CA.
- The libvirt `default` network active, and guests able to reach a TCP port on
  its gateway address ([the firewall note](./testing.md#gotchas) applies to this too).
- An oracle that evaluates through `fgro` (it takes `--fgro`), and keeps its SSH
  control socket under its `ZAP_HOME`, as the working tree does. The harness
  checks both before it starts a VM: a `zap` build that predates `fgro` can't read the
  staged locks.
- No root: your user in the `libvirt` group
  ([Prerequisites](./testing.md#prerequisites)).

## Running it

```sh
cargo xtask differential                                  # origin/main vs the working tree, both VMs
cargo xtask differential --distro alpine --scenario firewall-policy
cargo xtask differential --oracle-rev <rev>               # the oracle built from another revision
cargo xtask differential --oracle ./zap-reference         # a binary you built
cargo xtask differential --candidate ./zap-under-test --keep
cargo xtask differential --base-by candidate              # the candidate builds the base
cargo xtask differential --compare semantic               # compare decisions, not rendering
cargo xtask differential --help                           # every flag
```

| Flag | Default | Meaning |
|---|---|---|
| `--oracle <path>` | a build of `--oracle-rev` | the reference binary |
| `--oracle-rev <rev>` | `origin/main` | the committed revision the oracle is built from; not with `--oracle` |
| `--candidate <path>` | a release build of the working tree | the binary under test |
| `--distro <name>` | both | `alpine` or `debian`; repeatable |
| `--scenario <name>` | all | an exact scenario name; repeatable. An unknown name lists the valid ones. |
| `--compare <level>` | `exact` | `exact` or `semantic`; see [compare levels](#compare-levels) |
| `--base-by <side>` | `oracle` | `oracle` or `candidate`: which binary builds the base |
| `--rebase` | off | rebuild the base even when its hash matches |
| `--keep` | off | skip the final revert and every reconverge phase, so you can inspect the VM in the last scenario's state (drifted, for a scenario that reconverges), or, after a failed base build, in the state the builder left it; `bootstrap-replace` stops before it retires `ops` |

Without `--oracle`, the oracle is `~/.zap/oracle/zap-<short-rev>` for the commit
the revision names, as the local ref stands (nothing is fetched). It is reused
while that file is there; delete it to force a rebuild. Otherwise the harness
builds it the way you would by hand: the revision's tree from `git archive` in a
temporary directory under `~/.cache/zap-differential`, beside a link to each
sibling checkout its `Cargo.toml` names by relative path, then
`cargo build --release -p zap` there under the revision's own
`rust-toolchain.toml` (`CARGO_BUILD_JOBS` applies), and the executable copied
into place. A sibling such as `../fuz` is linked as it stands now,
uncommitted changes included, not as it was at the revision. The temporary
directory is removed afterwards; one an interrupted build left behind is removed
by the next build. The run prints which oracle it used:

```
oracle rev origin/main = 6cab2de (reused /home/ops/.zap/oracle/zap-6cab2de)
```

The default is `origin/main` rather than the checked-out branch's upstream: the
oracle is what has landed, whatever branch the working tree is on.

| Exit status | Meaning |
|---|---|
| 0 | every scenario matched |
| 1 | any divergence or harness error |
| 2 | a usage error |

The run prints both binaries' blake3 and warns when they are byte-identical:
such a run checks the harness and the targets, but proves nothing about a
change.

## Reading the output

Each scenario prints `PASS`, `DIVERGED`, or `ERROR`, its phase times, what its
mutation does, and the resources the **oracle's** `detect` saw leave `ok`; a
scenario that reconverges also times that phase and says when the candidate put
the state back:

```
  PASS     ssh/firewall-policy             25.1s  (revert 5.0s, zap runs 6.0s, audit 0.3s, reconverge 12.4s)
           default incoming policy flipped to allow
           oracle detect moved: firewall(drift)
           candidate reconverged it: the probe reads the base again
```

A reconverge failure is an `ERROR` whose message starts `[reconverge]` and names
the check that failed; a probe that doesn't read the base again prints the
difference, `-` for the base and `+` for after the apply. A probe reads what the
declaration governs, no more: the `pg_hba` probe reads which of the database's
rules are present, not where, since Zap puts a missing rule ahead of the first
`host` line rather than back where it stood.

A divergence prints, per command and stream, a unified diff with `-` for the
oracle and `+` for the candidate, tagged `[cold]`, `[warm]`, or `[local]`:

```
  DIVERGED ssh/converged                   14.2s  (revert 6.5s, zap runs 7.7s, audit 0.3s)
           oracle detect moved: nothing
  [cold] detect:
    stdout:
        --- oracle
        +++ candidate
          …
            ok     sleeper-init  file  — converged
        -   ok     sleeper  service  — converged
        +   drift  sleeper  service  — drifted (running=false, enabled=true)
            ok     postgresql  package  — converged
          …
```

Only what differs between the runs by construction is normalized: each run's
`ZAP_HOME` path (`<ZAP_HOME>`), the binary's own path (`<ZAP>`), and its staged
fixture tree (`<STAGE>`). Everything else, exit codes and stderr included, is
compared verbatim, so every diff line is a behavior change: either the intended
one, which you record, or a regression.

An `ERROR` is not a verdict; the message says which check above failed, or that
the VM was unreachable, the base didn't converge, the two locks pinned different
things, or an intended-divergence entry went stale.

## Compare levels

`--compare exact`, the default, compares byte for byte. `--compare semantic` is
for an oracle that renders a plan differently by design: it projects both sides
down to what each command decided (verdicts, banners, held resources, the set
and order of changes with their action, triggers, `--diff` attribute lines,
warnings, exit codes) and leaves out each plan's machine and `references:`
block, the lines under a change, and the value of `plan_hash`. So a semantic
`PASS` doesn't establish that the two binaries would run the same commands or
compute the same hash. The projection is `compare::project_lines`.

A change to what a plan's steps run, such as an extraction script, moves the
`plan_hash` of every plan that runs it, and that hash also binds the plan's
references, among them the per-run port of the harness's loopback content server,
so no entry can record it. Against an oracle that predates such a change, an exact
run diverges on those lines by design: compare at the semantic level, where the
intended entries still apply. The exact level passes again once the oracle is a
build that carries the change.

## Intended divergences

A candidate that changes behavior on purpose diverges by construction. Each such
change is an entry in `crates/xtask/src/differential/intended.rs`: the distro,
suite, scenario, cold or warm variant, command, the exact oracle and candidate
lines, the resource, and the reason. Matching is whole lines, exact bytes, and
only for the run the entry names; an accepted line prints as an `INTENDED` block
and doesn't fail the scenario:

```
  PASS     ssh/file-edge-cases             19.9s  (revert 4.8s, zap runs 13.4s, audit 0.4s)
           …
  INTENDED [cold] detect Stdout source-copy: the unreadable-source hold names the path, not the old `cat` stderr
    -   ?      source-copy  file  — undetermined: failed to render content: failed to read file …
    +   ?      source-copy  file  — undetermined: failed to read the content source: …
```

An entry whose lines aren't among its run's changed lines is an `ERROR`, so
when the oracle is replaced by a build that already behaves the new way, its
entries fail and the table empties itself out. The table is reviewed like code.
