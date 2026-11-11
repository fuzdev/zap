# Detection

How Zap reads the current state of a target: the verdicts, how deeply each
resource kind is read, the batched reads behind every pass, and the last-run
report. [concepts.md](./concepts.md#detection) is the short version.

Detection is the **detect** step of describe → detect → plan → apply → observe.
For each declared resource it answers one question, _does the desired state
already exist?_, with one of four verdicts, defined in
[concepts.md](./concepts.md#detection). This page is how each is reached.

A fifth word, `residual`, describes a resource that still doesn't read converged
after a wetrun acted on it. It is covered
[below](#the-residual-verdict).

## The governing principle

**Detection depth should match execution idempotency.** If re-executing a
resource is a true no-op, shallow detection is fine. If re-execution has side
effects even when the state is already correct (it restarts a service,
downloads bytes again, fires a `restart_on` chain), detection must be deep
enough to skip when nothing needs to change.

Detection runs at one of three depths:

| Depth | Question | Trust |
|---|---|---|
| Existence | does the thing exist at all? | low: misses attribute drift |
| Attribute | does it exist with the right properties? | medium: catches most drift |
| Content | is the full content or state correct? | high: catches all of it |

## Per-resource depth

| Kind | Depth | Reads |
|---|---|---|
| `file` | content | existence, SHA-512 digest, mode, owner, group |
| `link` | content | the symlink's target, as the login user |
| `build` | content | the provenance sidecar ([below](#build-exact-provenance-not-a-version-string)) |
| `swap` | attribute | the file, its `/proc/swaps` entry, its `/etc/fstab` line; not `size`, so a resize isn't drift; a drifted swap repairs only the missing parts |
| `database` | attribute | the role, the database, its owner, its `pg_hba` rules |
| `firewall` | attribute | active, the default policies, each declared allow rule |
| `apt_repo` | content | the key's blake3 against its pin, and the whole list file against the resolved, `signed-by` source line |
| `service` | attribute | running and enabled ([below](#service-probes)); config freshness through [triggers](#service-triggers-close-the-config-freshness-gap) |
| `directory` | attribute | existence; mode, owner, group when declared |
| `user` | attribute | each declared attribute |
| `package` | existence | the manager's query ([which forms compare a version](./resources.md#package-names)) |
| `installer` | existence | the `check` path; no version or integrity probe |
| `script` | yours | its `check` command's exit |
| `verify` | assertions | each assertion, at detect time ([below](#verify-assertions-at-detect-time)) |
| `pipeline` | none | nothing: always `absent`, so a dry run of a config with one always has a pending change (exit 2), and `zap status` reads it absent |

Notes on the kinds that need them:

- `file`
  - A file that exists but can't be read holds as `undetermined`. So does an
    unreadable `stat` when any of mode, owner, or group is declared. Neither
    reads absent or converged.
  - With a mode, owner, or group declared, the path itself must be a regular
    file. A symlink there drifts even when what it points at matches, and the
    write replaces it.
  - The content is compared by SHA-512 digest, so only the digest crosses the
    wire. See [content is compared by digest](#content-is-compared-by-digest).
  - One carve-out: an extracted `remote` file (`extract: tar.*`) is compared
    through its extract sentinel, a `.zap_remote_hash` file in the tree, and the
    extracted tree is not hashed again. The sentinel records a digest of the
    tarball pin and the `extract` form with its `strip_components`, so a new pin
    or strip count re-extracts.
  - An extracted tree is read the way the extraction treats it, so a plan never
    offers a change the wetrun refuses. Nothing at the path reads `absent`. A
    symlink, or anything but a directory, at the path holds. The sentinel
    counts only as a regular file, not a link. A directory without one reads
    `absent` when it is empty, and otherwise holds: Zap didn't extract it, and
    won't replace it.
- `link`: read as the login user. A path that isn't a symlink, or one the login user
  can't reach, reads `absent`, and a regular file there is replaced by the link
  on apply; a directory there fails the step. See [how detection reads the target](#how-detection-reads-the-target).
- `database`
  - One `psql -X` query as the `postgres` role reads the first three and the
    `hba_file` setting. `-X` means no `~/.psqlrc` adds to its output.
  - Each declared rule is then a `grep -qE` of that file. No matching line reads
    the rule as missing, and a file `grep` can't read holds.
  - The query runs under a `timeout` of its own (50 seconds), which stops `psql`
    itself and not only the shell that started it.
- `firewall`
  - A rule is matched against the whole rule target in the live ruleset, never a
    substring, so `allow 80` is not satisfied by an `8080/tcp` line, and a
    default-policy flip made out of band drifts.
  - **ufw**: a rule counts only as the row `ufw allow` writes, an inbound
    `ALLOW` from `Anywhere`, matched on its parsed `To` column in
    `ufw status verbose` (`verbose` for the `Default:` line). A named profile
    matches either its bare name or the verbose `<ports>/<proto> (<name>)`
    rendering, multi-word names like `Nginx Full` included. So an out-of-band
    `ufw deny 22/tcp`, an outbound allow, or an allow from one address drifts.
    The status is read in the `C` locale so its prose parses the same whatever
    the operator's locale. A status with no readable `Default:` line holds, and
    does not read the policies as converged.
  - **nftables**: the read is `nft list table inet filter`. A rule counts only
    as a whole rule line of the `input` chain, set aside only what doesn't change what it
    admits (a `counter` and its totals, a `comment`, a `# handle`). So
    `ip saddr 1.2.3.4 tcp dport 22 accept` or `iifname "lo" tcp dport 22 accept`
    doesn't satisfy a declared `22/tcp`. Each base chain's _effective_ policy is read: the
    `policy` verb refined by the trailing bare `reject` rule, so a desired
    `reject` is distinguishable from `drop`. A missing `input` or `output` chain
    drifts as `missing`.
  - Allow rules are **additive**: each declared rule must be present, but a rule
    added out of band is neither detected nor removed.
- `directory`
  - An unreadable `stat` holds as `undetermined` when any of mode, owner, or
    group is declared. With none declared, existence is the whole desired state.
  - Existence is read as the login user and follows a symlink (`test -d`
    semantics), so a directory the login user can't reach reads `absent`.
  - With a mode, owner, or group declared, a symlink to a directory drifts, and
    the change fails without touching what it points at.
  - The mode, owner, and group are read only when one of them is declared: as
    root over SSH, and as the operator locally.
- `user`
  - With `home_mode` or `ssh_keys` declared, the account's `/etc/passwd` home is
    read: a home other than `/home/<username>`, or none, holds the user, since
    Zap acts on paths under `/home/<username>`
    ([resources.md](./resources.md#user)).
  - With either declared, what is at `/home/<username>` is read with a `stat`
    that doesn't follow a link, for an account that doesn't exist yet too:
    nothing there, or a directory the user or root owns, reads on (an existing
    account's root-owned home is left as it is; the creation of an absent one
    gives it to the user). Any other owner, a link, or anything but a directory
    holds the user. A `/home` that is missing, or that the connecting user
    can't search, holds the user naming `/home`, rather than reading as nothing
    there.
  - SSH `authorized_keys` and sudoers, compared by content with surrounding
    whitespace trimmed. Up to 1 MiB of `authorized_keys` and 64 KiB of sudoers
    are read; past that the file drifts.
  - Supplementary group membership (`id -nG`). It is additive: a desired group
    that isn't present drifts.
  - An `ssh_keys` account's `/etc/shadow` password field is held
    authoritatively at the disabled `*`. Any other value drifts: a `!` lock, an
    empty field, or a hash.
  - A probe of a declared attribute that exits nonzero (a `stat` of a missing
    home, with `home_mode` declared) holds the user: the attribute wasn't read,
    so it isn't called converged. An attribute the config doesn't declare isn't
    read at all. A key file that can't be read is drift.
  - A `copy_from` source's `authorized_keys` is found through that user's
    `/etc/passwd` home and read as that user, the way apply reads it, so a
    source file that user can't read drifts on every plan and fails on every
    apply.
- `package`: a package held back, or installed for any architecture, is
  installed; one half-installed or removed with its configuration left is not.
  A query that fails holds the package.

The shallow rows are deliberate, not unfinished. A `package` install or an
`installer` re-run is idempotent, so existence detection is enough. `script`
hands the depth to you: make its `check` precise or it runs on every apply.

### `build`: exact provenance, not a version string

A `build` is content-addressed by the blake3 of its **source archive**, the
pin: the vendored `source.blake3`, or else the `zap.lock` entry. After a
successful build Zap writes a `<output>.zap-build` sidecar recording its
**provenance**: 64 lowercase hex, the blake3 of a fixed tag, a format version,
and the pin with the build's `extract`, `run`, `cwd`, and `env` as declared.
Detection computes the desired provenance the same way and compares:

| What detection finds | Verdict |
|---|---|
| output or sidecar missing | `absent` |
| sidecar differs from the desired provenance | `drifted`: the upstream moved or the build changed, so rebuild |
| sidecar equals the desired provenance | `converged` |
| no usable pin (a tracked source with no lock entry, or a stale one) | `undetermined` in `plan`, `detect`, `status` and a deploy's preflight (which bails, exit 2); `apply` mints a missing pin and refuses a stale one (exit 2) |

A reference in `run` or `env` is part of the provenance as written, not as
resolved: a secret's value never reaches the target, and a new value for a
variable alone does not rebuild.

This is why a `--version` check isn't the drift signal. The provenance is exact
and language-independent, so a moved upstream is caught even when the installed
binary still runs. See [resources.md](./resources.md#build).

### `verify`: assertions at detect time

A `verify` resource runs its assertions during detection. If all pass, it
reports `converged` and is skipped. If any fail, it becomes a pending change; on
a wetrun its assertions run again at its place in the dependency order, and one
still failing **fails the run there**, so an earlier change in the same run can
satisfy it. A dry run shows it as a pending change and runs nothing. A verify
never executes anything of its own. It is a guard rail, and changes ordered
before it have already run, so order it with `depends_on` to put the guard where
it belongs.
Because the answer is live state, a verify is checked again on every pass.

For a gate that should run only after something else applies, use a `script`
with `check` and `run`, ordered by `depends_on`. That keeps `depends_on` meaning
ordering, not a detection special case.

### Service probes

A service's two probes read what the manager reports, and a probe that fails to
read holds the service: a failed read is no evidence of a stopped or disabled
service, and reading it so would take `running: false` or `enabled: false` as
converged.

- systemd: `systemctl is-active` exiting 0 is running, 3 (inactive or failed)
  and 4 (no such unit) not running; `systemctl is-enabled` exiting 0 is enabled,
  and a non-zero exit is not enabled only when it prints `disabled`, `masked`,
  `masked-runtime`, `linked`, `linked-runtime`, or `not-found`.
- OpenRC: `rc-service <svc> status` exiting 0 is started, 3 (stopped, or no such
  script) and 32 (crashed) not running. 64 (unsupervised: a `supervise-daemon`
  service whose supervisor died, its daemon perhaps still running) holds, and
  the reason says to check for the daemon and run `rc-service <svc> zap` by
  hand. Enabled is an entry for the service in
  any runlevel under `/etc/runlevels`, as `rc-update add <svc> <runlevel>`
  makes; a disable removes it from each runlevel it is in.

Any other exit holds the service as `undetermined`.

### Service triggers close the config-freshness gap

Service detection checks running and enabled, not whether the service's config
is fresh. The trigger model closes that gap by reacting to changes, not by
deepening detection: a `file` lists `triggers` (push), or a `service` lists
`restart_on` or `reload_on` (pull). When the referenced resource changes, the
planner promotes the service from skip to a restart or reload.

## Holding: the `undetermined` verdict

When Zap cannot establish current state, it refuses to guess. The usual causes
are a probe that couldn't be reached, a remote path whose target home wasn't
declared, a path or name whose reference resolves to a value Zap won't use (one
holding a reference delimiter, a path that isn't absolute or spans lines, a
`database` name or host a `pg_hba.conf` line would misread), and, in `plan`,
`detect`, `status` and a deploy's preflight (which bails, exit 2), a tracked pin
with no lock entry or a stale one (`apply` mints a missing pin and refuses a
stale one, exit 2). The planner holds the
resource and does not propose a create that might clobber live state. The next
pass reads it again: no verdict carries over from one pass to the next.

A held resource contributes no change, so it simply isn't in the changeset. An
empty plan would hide it, which is why every command that compares reports the
hold as a **verdict**:

- `plan` and `apply` (dry or wet) show an `UNDETERMINED` banner naming each
  held resource and why, and `detect` marks each one `?`. All three exit
  **1**: "converged" is a claim about the target that was never established
  for the resources nobody could read, and for a dry `apply` 1 outranks 2
  ("drifted") too.
- `deploy`'s drift preflight bails (exit 2): a gate that couldn't check
  everything must not pass by default.

Exit codes in full: [cli.md](./cli.md#exit-codes-all-commands).

### A hold spreads to what can't run without it

A change that waits on a held resource is held behind it: it could act on
state the held resource was meant to set up. This follows `depends_on`
forward, including the implicit edge from a service to its trigger sources,
and passes through a converged resource unreported, since that resource
changes nothing. A change that would restart or reload a held service is held
too: its change would owe the service the action with nothing to run it, so
the action would never happen. This follows trigger edges in reverse (a
file's `triggers`, a service's `restart_on` and `reload_on`), and never a
plain `depends_on`: what a held resource depends on still runs. The two rules
repeat until nothing changes, so a source held for its trigger also holds what
waits on it, and a source that is itself a service holds its own sources.

One exception: a converged service whose only change is the restart or reload a
[pending marker](./concepts.md#triggers) owes waits only on what it declares, so a
trigger source detection couldn't read doesn't hold it; the owed action runs. A
source that changed and is held behind another still holds the service its
change fires.

The banner lists the resources detection couldn't read first, then the ones
held behind them, each with what it waits on or would trigger:

```
  UNDETERMINED — 1 resource could not be probed, so no change is planned for it and this changeset is partial:
      web — detection failed: the unit read exited 1
  its live state is unknown: neither converged nor drifted. resolve the probe failure and re-run.
  held behind it — 2 resources can't change until it does:
      after — waits on `web`, which is held
      site — would reload `web`, which is held
```

Resolving the probe failure releases the whole chain on the next pass.

`undetermined` is about the observed side. Its twin on the desired side is the
`unverifiable` verdict ([env.md](./env.md)), where the declaration is the half
that couldn't be built.

### Kinds that read a failed probe as absent

A few detectors deliberately map a _failed probe_ to `absent`:

- `firewall`, on both backends;
- `script`, when its `check` fails, and a `verify` assertion that fails;
- `link`, `directory`, and `swap`, for a path the login user can't reach (and,
  for a `link`, one that isn't a symlink).

For these, a probe failure almost always means "not set up yet" (the fresh
host, before the same config installs ufw or nftables), and their create steps
are idempotent and identical to their update steps, so a misread probe either
re-asserts the declared state or fails loudly at execution. The one
consequence to know: a regular file sitting where a `link` is declared reads
`absent` and is replaced by the link (a directory there fails the step instead).

A `file` is the opposite case and holds. "Exists but unreadable" _proves_ there
is state a create would clobber, which is the harm the hold exists to prevent.

`database` splits the two cases:

- **No PostgreSQL reads `absent`.** That means no `psql`, or no `postgres`
  account (a client-only host). Both are checked before the query runs, in the
  same root environment the query runs in, so this is a detected fact. Zap's
  probes and steps run as `postgres`, and there is no cluster they could reach,
  so the fresh host's first apply creates it. A cluster run under another
  account name reads `absent` too; its create steps then fail loudly under
  `sudo -u postgres`.
- **A failed query holds.** With both present, a query that fails (the server is
  stopped, or `postgres` can't authenticate) reads nothing about the role, the
  database, or its `pg_hba` rules. Output that isn't the query's one row also
  holds, and so does a `pg_hba.conf` the server names that the `postgres` account
  can't read: the rules are read as that account, never as root.

## The `residual` verdict

A wetrun closes the loop on the other side too. After executing, `apply`
**re-detects** the target. This is the observe pass, and it becomes the
[last-run report](#the-last-run-report). Any resource that still
doesn't read converged is reported as the **residual** verdict, exit 1.

A change can exit 0 without converging its resource: a `script` whose `check`
still fails after `run`, or a mutation whose probe reads back differently. So
"applied: N ok" alone is command success, not convergence. The residual banner
is what makes the wetrun's final claim an _observed_ fact. If the re-detection
itself fails (connectivity dropped after execution), the apply reports that and
still exits 1, because "converged" was not established.

Three cases are exempt, because "not converged" is impossible or already
reported more loudly:

- a `pipeline`, which detects `absent` by construction;
- a change that **failed**, or was skipped by stop-on-first-failure, which is
  already the run's headline and exit 1;
- a **held** resource, which is already the `undetermined` verdict.

A `script` runs its `check` twice per wetrun, once detecting and once verifying
convergence. That is the price of its user-defined depth.

## How detection reads the target

Every kind detects through **batched queries**. (A `pipeline` reads nothing: it
always runs.) A kind declares the reads its verdict needs as typed queries, and
a pure function turns the answers into the verdict. The function sees nothing
but those answers, so a detector can't read anything it didn't declare. The
queries are:

- the type of what a path resolves to;
- a path's own mode and ownership;
- a symlink's target;
- the SHA-512 of a file's bytes;
- the first few bytes of a small file;
- a command Zap owns: a package manager's query, a service manager's probe, an
  `awk` match in `/proc/swaps`, `ufw status verbose`, a `psql` query;
- an operator's command: a `script`'s `check`, each of a `verify`'s assertions,
  a `package`'s `check` that is a command.

The pending-trigger markers
([resources.md](./resources.md#pending-triggers)) are read the same way, as one
more query of the plan's pass.

Every batched query is known before anything is read from the target: from the
config, `zap.lock`, and the operator's content cache. (An uncached `remote` file's
bytes are read after the batch; see below.) The two reads that depend on another
read's answer compose in the target shell, inside one command: a `database`'s
`pg_hba` `grep`s run against the `hba_file` its catalog query just reported, and
a `copy_from` user's source `authorized_keys` is read from the home its
`/etc/passwd` entry names.

### Privilege

Every query names the privilege its read runs under. It is the privilege the
equivalent single-command probe would have, so a kind sees the same thing
whether it is read alone or in a batch.

- **login**: as the connecting user, unprivileged, on every connection. Read
  this way:
  - a `directory`'s existence and a `link`'s target;
  - a package manager's query and a service manager's two probes;
  - the `swap` file's `test -f` and its `/proc/swaps` and `/etc/fstab` matches;
  - an `apt_repo`'s source line, resolved against `/etc/os-release`;
  - a `user`'s `id -u`, `/etc/passwd` shell and home, what is at its home and
    who owns it, the home-directory mode, and `id -nG`;
  - a `verify`'s assertions: a `path_exists` chain of `test` and `stat` (Zap's
    own command; one under a directory the connecting user can't search fails)
    and a `command`'s `run`;
  - the other operator's commands: a `script`'s `check` and a `package`'s
    command `check`;
  - the pending-marker read.
- **root**: as root on every connection. It is the privilege of a probe that
  carries its own `sudo`, written without it. A local target runs these through
  `sudo`. Read this way:
  - a `firewall`'s status (`ufw status verbose`, `nft list table inet filter`);
  - a `database`'s catalog query and `pg_hba` greps, each run as the `postgres`
    account through `sudo -u postgres` from root;
  - a `user`'s `/etc/shadow` password field and sudoers `test -f`;
  - a `copy_from` source's `authorized_keys`, read as the source account
    through `sudo -u` from root;
  - a `user`'s own `authorized_keys`, read as that user through `sudo -u` from
    root, the account the file belongs to and is written as. A symbolic link or
    anything but a regular file there is not read; it drifts, and apply writes
    the file in its place.
- **elevated**: as root over SSH, where the login user isn't assumed to own what
  Zap manages. On a local target the read is tried as the operator first,
  directly. A read that fails any way other than the path not being there (a
  root-only parent, a file only root can read) is asked again as root, through
  `sudo`, in one batch for all of them. A local config that touches only the
  operator's own files never invokes `sudo`. Read this way:
  - every read of a `file`: its existence, content, and mode, owner, and group;
  - a `directory`'s managed mode, owner, and group;
  - a `package`'s or an `installer`'s `check` path;
  - an `apt_repo`'s key and sources list;
  - a `build`'s output and provenance sidecar;
  - a `user`'s sudoers contents.

Because a `file`'s content is compared by digest and not read as text, a file
whose bytes aren't valid UTF-8 reads like any other. It doesn't send a local
read to `sudo`.

A content read (a digest, or a bounded read of a sentinel or sudoers file) opens
only a regular file of its own. A symbolic link at the path, dangling or not, is
not followed, and a directory, a device, or a fifo is not opened: at root's
privilege, opening a device can act on the machine, and a fifo holds the read
until its timeout. The read reports the path as not a regular file instead, and
each resource says what that means: a `file` whose path is a symbolic link to a
regular file drifts, since its write replaces the link with the file; anything
else there that isn't a regular file holds it. A regular file with more than one
hard link, its link count read from the descriptor, is read by no content read
and holds the resource, saying to replace it with a copy of its own (a single
link): a hard link is the file under another name, which could make a root read
of the declared path read a file someone else linked there. A name swapped
between the check and the open is opened as it then is, under the read's
timeout.

### Content is compared by digest

A `file`'s content is never shipped back to compare. The target runs `sha512sum`
over the file and only the digest crosses the wire, however large the file. What
the digest is compared against depends on the content:

- **`inline` and `template`**: the SHA-512 of the rendered content. Inline
  content and a template's body are compared as declared; a template's `vars`
  have their references resolved from the operator's environment.
- **`source`**: the digest of the source path, read in the same batch as the
  target's. A source that can't be read, or that is not a regular file of its
  own (a symbolic link included), holds the resource.
- **`remote`, `extract: none`**: the SHA-512 of the pinned bytes, taken from
  Zap's content cache (`~/.zap/cache/files/<blake3>/<name>`, where fetching them
  put them), after checking that those bytes still hash to the pin.
  - The pin is the declared `blake3`, or else the `zap.lock` entry. With
    neither, or with a stale lock entry, the file holds in `plan`, `detect`,
    `status` and a deploy's preflight (which bails, exit 2); `apply` mints a
    missing pin and refuses a stale one (exit 2).
  - When the content cache doesn't hold the pinned bytes (a fresh `ZAP_HOME`,
    another machine), Zap reads the target's bytes directly, after the batch,
    and compares their blake3 to the pin. Only a regular file of its own is
    read: a symbolic link or anything else at the path holds the resource. When they match, it stores them in the
    content cache, so the next pass compares digests.
  - Detection never fetches the url.
- **`remote`, `extract: tar.*`**: the extract sentinel's first 4 KiB, compared,
  with surrounding whitespace trimmed, to the desired provenance (the digest of
  the pin and the `extract` form). A sentinel longer than that
  drifts.

A drifted `remote` file reports what it observed: the target's blake3 when its
bytes were read, or its SHA-512 when only the digest was. The message is
`remote content differs from its pin (observed sha512 …)`, and `--diff` shows it
as a replacement of the content pin, not as a pin of its own.

### Batches

Over SSH, all of a pass's login reads run as **one shell script** in one
command, and all of its root and elevated reads as a second, under `sudo`: the
login and root **lanes**. The two run concurrently. A detection pass costs one
round trip per lane, however many batched resources the config declares. A
target missing a tool a lane's batch needs, or the `/proc/self/fd` its content
reads check what they opened through, fails that whole lane.

**Connectivity.** The batches are also the pass's connectivity check. An `ssh`
that can't reach the target (it exits 255, or can't start) fails the command
with a `cannot connect` error before any verdict is printed. The error carries
`ssh`'s own message, with a hint when the host key changed. A pass with nothing
to batch checks connectivity with an `ssh true` of its own.

**One authentication.** A pass authenticates once. When no connection to the
target is already open for Zap to share (its `ControlMaster`), the login batch
waits for the root batch to be under way and shares the connection it opened,
so no second one is opened.

**What adds a round.** Two things:

- an unextracted `remote` file whose pinned bytes aren't in the content cache.
  Its bytes are read with a command of their own, after the batch. See
  [content is compared by digest](#content-is-compared-by-digest).
- on a local target, the elevated reads the operator was denied. A local target
  answers login and elevated path reads natively, without a shell, and asks the
  denied elevated ones again as root in one `sudo` batch after that. Its login
  command reads run as one local batch, as the operator, and its root reads run
  in the root batch.

**Local `sudo`.** A local root batch runs under `sudo -n`, after Zap has made
sure `sudo` won't prompt; operator commands run with no terminal, locally as
over SSH ([targets.md](./targets.md#local-sudo)). If `sudo` won't authenticate,
every resource with a read in that batch holds, with the fixed reason
`sudo authentication failed`.

**The script travels on stdin**, never the argv, and each probe's output comes
back framed, so bytes a probe prints (newlines and NULs included) can't be
mistaken for another probe's answer, and nothing a probe prints reaches the
stderr Zap shows when `ssh` itself fails. A probe's exit status travels apart
from its output, so nothing the probe writes can forge it; a command runs in a
session and process group of its own, so a command that signals its group
reaches only itself. The target's `sudo` log records one constant wrapper per
lane ([security.md](./security.md#authority-on-the-host)).

**Locale.** Zap's own probes run under `LC_ALL=C`, so what they print parses the
same on every target. An operator's command runs in the target's own locale, as
it would by hand.

**Operator commands** (a `script`'s `check` with its references resolved, its
`cwd` and `env`) travel inside the script too, so a resolved value is on no
argv. The check's exit decides: 0 is applied, anything else (a `cwd` that can't
be entered and a check that doesn't parse included) is `absent`. The script
holds only when the check produced no exit status (a timeout, a failed lane) or
a reference can't be carried.

**What the target needs.** `timeout`, `od`, `tr`, `head`, `cat`, `stat`, and
`readlink`; `sha512sum` when the batch reads a digest; `ls` when it reads
whether an extracted tree is empty; and `setsid` and `sleep` when it runs a
command. Over SSH, `setsid` is needed in any case. These come
from GNU coreutils and util-linux, or BusyBox (validated on 1.37). A target missing
one fails the batch, and does not read every path as absent. Writes need a few
more ([targets.md](./targets.md#what-the-target-needs)); a write that lacks one
refuses, naming it, with nothing changed.

**Output limit.** Zap reads at most 64 MiB of a batch's output. Past that it
stops the batch and holds every resource in it.

**Local content reads.** A local target answers content reads natively too,
except of something that is neither a regular file nor a directory (a fifo, a
device), which its probe answers under its timeout.

### What a read can conclude

**Commands answer with their exit status.**

- An operator's command: a `script`'s or `package`'s `check` exiting 0 is
  applied or installed, and anything else is not. A `verify` assertion holds
  when its command exits 0 and, with an `expect`, its stdout contains it.
- A command Zap owns: the package manager's query and the service manager's
  probes exit 0 if and only if the state holds; `test -f`, the swap's `awk`
  match, and a `pg_hba` `grep` exit 0 if and only if the file or line is there. The package manager's query answers "not
  installed" with exit 1 alone: any other status is a query that failed
  (`dpkg-query` unable to read its database, or missing), and the package holds.

Some commands also print what they read (a firewall's ruleset, a user's shell or
groups, a database's catalog row), which the verdict parses. A failure means
what it meant to that probe: a firewall probe that fails needs setting up, and a
`user` attribute probe that fails holds the user.

Otherwise, what holds is an answer that is missing (a timeout, a garbled record,
a failed batch) or output that doesn't parse. A `database` also holds when its
catalog query failed with PostgreSQL installed, or when its `pg_hba.conf`
couldn't be read.

**A path read concludes "nothing there" from one failure only.** That is the
failure `stat` and `readlink` report for it (their exit status 1), and the
content reads, which open the path with a redirect that exits 1 when it can't be
opened. It means the path is absent, can't be reached at the read's privilege,
or, for a symlink's target, isn't a symlink. For a content read, it means the
path can't be read (a directory); for an extracted tree's emptiness read, that
it isn't a directory the read's privilege can list. A `file` that exists but whose content read
finds nothing holds, and does not read absent.

Anything else holds the resource as `undetermined` and does not guess:

- a probe that failed another way (it couldn't run, or was killed);
- output that doesn't parse (an owner or group name containing whitespace);
- a missing or garbled answer.

A resource needs only the answers its verdict reads: the mode of a directory
that doesn't exist is never consulted. But a batch that failed as a whole holds
every resource with a read in it, with a fixed reason that quotes none of the
batch's output. That covers a dropped connection, a refused `sudo`, output that
stopped before its end marker, and a missing tool. So does a pass whose answers
don't line up with its reads one for one (a layout mismatch): no answer in it is
read, and the reason names the read left without one. None of these ever reads
as `absent`.

### Timeouts

Each probe runs under `timeout` and reads `undetermined` ("timed out after 10s")
when it runs out:

| Read | Limit | Why |
|---|---|---|
| Zap's own path reads | 10 seconds | a healthy `stat` takes milliseconds; a slow one is a hung mount |
| the mode and ownership read | 30 seconds | it resolves owner and group names, which may go through a network name service |
| a digest | 60 seconds | it reads the whole file |
| a command, Zap's own or an operator's | 60 seconds | it may do real work |
| a database's catalog query, inside its command's limit | 50 seconds | its own `timeout` stops `psql`, and leaves the `pg_hba` greps room |

Zap's own commands are a package manager's query, a service manager's probe, a
firewall's status, and a database's catalog query with its `pg_hba` greps.

A command's timeout stops its whole process group, children included, with
`SIGTERM` and then `SIGKILL` a second later. A command that exits 124 or 143 on
its own reads as that exit; what reads as timed out is a command with no
report. Because something can outlive a probe's timeout (a process that left
the command's group, or one a command backgrounds), each batch also runs under a
deadline, the sum of its probes' limits plus a margin. When that passes, Zap
stops the batch, kills what it can of it on the target, and holds every resource
with a read in it, so a stuck probe costs at most the deadline.

## Nothing is cached

Every pass reads every resource. A stored answer is sound only when nothing
outside Zap could have changed the target since it was read, and Zap never
assumes that; and a pass costs one round trip per lane however many
resources the config declares, so a stored answer would save nothing.

That matters most for the controls people change by hand:
[security.md](./security.md#security-controls-are-read-live-every-time).

The **pending-trigger markers** (`/var/lib/zap/pending/`) follow the same rule:
they are read on every plan for a config that declares a trigger, in the same
batch as the plan's detection reads
([resources.md](./resources.md#pending-triggers)).

The caches Zap does keep are on the operator machine and never stand in for the
target: the config eval cache, whose manifest is validated again on every
lookup, and the content cache, whose bytes are checked against their blake3 on
every read ([lock.md](./lock.md#on-disk-state)).

## The last-run report

Every detection pass records what it read in a **last-run report**, and
[`zap status`](./cli.md#zap-status) renders it offline. The passes that write it:

- `detect` and `plan`;
- `apply`: a dry run's pass; a wetrun's pass before its changes, then its
  re-detection after them, which is the last word; and a refused wetrun's pass,
  recorded as the preview it was;
- `deploy`'s drift preflight.

Detection never reads it. The wetrun's review gate reads only which pass wrote
it and its `plan_hash`.

The report is latest-only, one file per config and host, under `~/.zap`
([lock.md](./lock.md#on-disk-state)). It holds:

- when the pass ran (RFC 3339, UTC), which command pass it was, and the host
  (`local`, or the resolved remote host);
- the names of any references the pass's comparison couldn't resolve,
  names only. This is the pass's [`unverifiable`](./env.md) finding.
- per resource read: its verdict (`converged`, `drifted`, `absent`, or
  `undetermined`), its hash, and whether it references a secret. It never holds
  the observed state, an `undetermined` reason, or anything else the target
  returned.
- the pass's [batches](#batches): each one's lane and query count;
- the `plan_hash` of the plan the pass computed, when it planned (`detect`
  doesn't). For a pass that **previewed** that plan (`zap plan`, a dry
  `zap apply`, a refused wetrun), this is the reviewed plan the next
  `zap apply --wetrun` binds to
  ([concepts.md](./concepts.md#a-wetrun-executes-only-the-plan-you-reviewed)).

### What a resource's hash covers

A resource's hash covers its declaration as written, less its identity (`id`,
`name`, `depends_on`) and a fetch credential; the value of each reference in a
field that takes one; and the pin `zap.lock` holds for it. A reference resolves
in one of two ways:

- a secret one ([env.md](./env.md#secrets)) resolves to a fixed
  `[MASKED:NAME]` token, so a `DATABASE_URL` holding a password hashes as its
  own token;
- any other resolves to its value, with every registered secret in that value
  masked.

So a changed value of an ordinary variable, wherever the resource takes a
reference (a `script`'s `check`, a path, a template var), reads as a changed
config. A `verify` command is hashed as written.

What the hash excludes is the value of every _registered_ secret, whether
referenced by name or carried inside another variable. So the report can't be
used to test a guess at one, and a changed secret value can't be seen offline.
There is one exception to the first: a short secret that also happens to occur
inside a known non-secret value, where whether the masker masked that value
depends on the secret.

A value the masker doesn't know as a secret is hashed as it is. That means an
unregistered name, or text written literally into the config, which the secret
gate rejects when it can.

The host a report is filed under is always a resolved value: a host that
resolves through a masked reference keeps no report, every pass says so
(`UNRECORDED`), and `zap status` reports that none is kept and exits 1. The
report also records a **target hash** over the whole `zap.target(...)` (host,
users, port, key path, home, package and service manager), its references
resolved the way a resource's are, since every verdict was read against it. A
file that isn't a report of the current format version reads as no last run.
