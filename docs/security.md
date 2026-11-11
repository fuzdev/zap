# Security model

What Zap trusts, what it refuses to trust, and where the walls are.

## The threat model in one paragraph

The operator is trusted: whoever runs `zap apply --wetrun` already holds SSH and
`sudo` on the target, and could do anything by hand. Zap's job is to make what
that person (or the assistant working for them) does **reviewable, bounded, and
observable**: a config can't act on its own, nothing Zap does to the target
goes unshown except the checks a config declares (they run as written on every
pass, [before any review](#what-an-approved-hash-doesnt-fix), and Zap can't make
them read-only), a read that fails never passes as "fine", and secrets don't
leak into the places people and agents read. Zap is not a sandbox for hostile
configs you didn't write; see [the config is first-party](#the-config-is-first-party).

## The config can only describe

What this means for writing a config is in
[configs.md](./configs.md#the-sandbox). The walls themselves: `zap.ts` runs in
`fgro eval`, Gro's runtime, a separate binary Zap runs once per evaluation. Its
walls are its own, set up before any of the config's code, or V8 itself, runs:

- **a kernel box**: Landlock admits reads only under the config's project and
  the packages linked into its `node_modules`, and seccomp narrows the system
  calls. No write anywhere, no network socket, no exec, no read outside those
  directories (`/proc` and `/dev` included; metadata such as whether a path
  exists stays visible), and no signal to another process. There is no
  setting that weakens it, and on a host that can't hold it (Linux below
  Landlock ABI 6, an architecture its filters aren't built for) the evaluation
  fails rather than run without it;
- **no environment**: the evaluator starts with `TZ=UTC` and nothing else of
  yours, reads no variable for its own settings, and gives the config no
  `process` and no environment API. A variable in your shell can't
  loosen the sandbox or reach the declaration except through `zap.env()`, which
  is a reference resolved later by Zap, never a value;
- **only static imports**: every `import()` is refused, and a `node:` built-in
  doesn't resolve. Resolution is strict ESM: a relative import names its
  extension, and a bare import resolves through the `node_modules` of the
  project and the `exports` of the package found there (never its `main`),
  under the conditions `gro`, `import` and `default`;
- **no clock, no randomness, no timers**: reading the clock, a random source, or
  a fact of the machine throws, and there are no timers; the time zone is UTC
  and the locale `en-US` ([configs.md](./configs.md#the-sandbox) lists what is
  refused);
- **jitless**: V8 runs in its interpreter, so `WebAssembly` is absent;
- **no code from strings**: `eval` and `new Function` throw;
- **bounds**: a capped heap and process memory, a 30 second timeout, and a cap
  on the JSON it may emit.

The config's only output is a JSON declaration that Zap validates against a
strict schema. It cannot run commands, write files, or call back into the
engine.

**The config needs a project.** The project is the nearest directory at or above
the config whose `package.json` holds more than `"type"` and `"sideEffects"` (a
`{"type": "module"}` marker in a subdirectory is passed over), outside any
`node_modules`, looking only through directories you own that no other user can
write. Zap finds it before the evaluator runs and refuses, exit 2, when:

- the config file or its directory is writable by every user (for a config
  reached through a link, the mode of the file it leads to);
- a `package.json` on the way up can't be read or isn't valid: not a JSON
  object, a `"name"` or `"type"` that isn't a string, a FIFO, socket or device
  (refused unopened), a link to nothing, or a path through something that isn't
  a directory;
- the walk stops below a directory another user owns (the evaluator's own walk
  would go past it) or every user can write, or reaches `/`, with no project
  `package.json` found. The refusal names where it stopped and why.

The evaluator then finds the project itself and must report the same one, or
nothing it wrote is used. Its box admits the project and the packages its
`node_modules` links in from outside it; a package reached through a directory
every user can write isn't read. A package that isn't installed in the project
doesn't resolve: the search for a bare import stops at the project's
`package.json`, so a `node_modules` above the project is never searched. npm and
yarn workspaces aren't supported: a workspace member with its own
`package.json` is its own project, and the workspace's `node_modules` above it
isn't searched.

"You own" means the user Zap runs as. Run as root, that is root, and under
`sudo` also the user who ran `sudo` (`SUDO_UID`), so `sudo zap apply` on a
config in your own project walks your directories as it would without `sudo`.

**The evaluator never runs as root.** Run as root, Zap runs it as the user who
ran `sudo` when that user owns the project, and otherwise as the project's
owner; a project root owns is refused, exit 2, since no user who could already
edit the config is there to run it as. A project that is the evaluating user's
home directory, or holds it, is refused too: the box would admit all of it. The
user it runs as must be able to search every directory down to the project, and
is never dropped into group 0: a drop whose group would be root's is refused.
Dropped to the user who ran `sudo` (who owns the project), its group is
`SUDO_GID` (the group you ran `sudo` with; unset or not a number is refused);
otherwise, dropped to the project's owner, that owner's primary group. A drop
keeps no supplementary groups. Its home, and the primary group, come from the
passwd database; a static (musl) `zap` reads only `/etc/passwd` and `nscd`, so a user
known only through LDAP, sssd, or systemd-homed can have no entry there, and the
evaluation is then refused.

**The evaluator is pinned.** Zap runs the `fgro` binary `--fgro` or `ZAP_FGRO`
names, by absolute path, never one found on `PATH`, and only when its blake3 is
the toolchain pin in the config's `zap.lock`; `zap lock` is the one command that
records the pin rather than checking it ([lock.md](./lock.md#the-toolchain-pin)).
The binary is opened once and run through the descriptor that was checked, so
a binary replaced at its path afterward isn't what runs. Its blake3 is read
through that descriptor, or, once the file has settled, from the pin cache
(`~/.zap/cache/fgro_pins/`, private to the user Zap runs as): an entry there
names the blake3 of a file by its device, inode, size, and modification and
change times, and a file whose metadata matches an entry isn't hashed again.
A write moves the change time, but only to the filesystem's timestamp
granularity, so an entry is written only for a file whose times are a couple of
seconds old, and a clock set back across that margin, or a network filesystem
whose server's clock lags, defeats it. A write to the file itself between the
check and the exec, by anyone who can write it, is caught only on a best-effort
basis. A link at the binary's own name, a wrapper
script, or a set-ID binary is refused.

**Reads are the project's.** A config reads nothing but the modules it imports,
from its project and the packages the project links. What stays the operator's:
the files in the project and the linked packages are trusted as they are, a
package installed as a directory included. The ownership walk doesn't read ACLs,
and the evaluator reads the disk again after Zap's walk: a project that changed
in between is caught by its report, not prevented. With `ZAP_EVAL_CACHE=skip`, a
cache hit is served without running the evaluator, so the project walk and the
evaluator's report aren't checked on a hit; the `fgro` binary is still held to
its pin ([cli.md](./cli.md#environment-variables-zap-reads)).

### The config is first-party

Zap assumes the config and everything it imports are yours. If you ever evaluate
a config you don't trust, the plan it emits is the attack surface: review it as
you would a shell script, because its `script` resources are shell. A config
can't pull code from the network or import dynamically, and its imports stay
inside its project and the packages it links, so it can't take a project or a
package from a directory every user can write. A linked package is otherwise
trusted wherever it lives and whoever owns it.

## What the gates reject before anything runs

Every command that reads a config, including `config validate`, runs two machine-free gates on the
declaration:

- **the secret gate**: a secret written literally into the config is rejected
  when Zap can tell (the same value is both referenced and
  resolvable in the current environment);
- **the structural gate**: a malformed or contradictory declaration, such as a
  NUL byte in a string a shell would see, a duplicate id, or a dangling or
  cyclic dependency. The full list is in
  [configs.md](./configs.md#what-the-gates-reject).

A wetrun adds an env gate: any referenced variable that is unset or empty fails
the run before any side effect, so an empty secret never gets written into a
`.env` file.

## Zap changes nothing without a wetrun

No command changes the target unless you pass `--wetrun`, and no flag approves a
plan for you. A dry run connects, reads, and renders. Reading runs Zap's own
read-only probes and the commands the config declares as checks (a `script`'s
`check`, a `verify`'s assertions, a package's command `check`, an apt `source`
line's expansion), [before any review](#what-an-approved-hash-doesnt-fix). Zap
runs them as written: a check that writes, writes. Its only other network
traffic is fetching a missing content pin into the cache on your machine. This
holds with no terminal, in CI, and in an agent loop. `zap lock` and `zap update`
write `zap.lock` on your machine, which is their job.

## A wetrun executes only the plan you reviewed

A wetrun's fresh plan must match a reviewed one hash for hash, or it refuses
before any side effect; on an interactive terminal it asks you to type the start
of the hash instead, a question nothing typed earlier can answer. The rule, and
what `plan_hash` binds (the host, the connecting user, a local `HOME`, every
plain reference's value), is in
[concepts.md](./concepts.md#a-wetrun-executes-only-the-plan-you-reviewed);
`zap deploy` binds its own plan the same way
([deploy.md](./deploy.md#binding-a-wetrun-to-a-reviewed-plan)). So an agent given
`--expect-plan` with the hash you approved, or a pipeline given the hash approved
in a pull request, can execute only that plan. Without `--expect-plan`, the
reviewed plan is the host's last recorded preview, which Zap records when it
prints it, not when anyone reads it. A plan whose host, connecting
user, or deploy health domain resolves through a masked reference gets no hash,
and its wetrun is an error ([env.md](./env.md#masked-hosts-and-review)).

The host a hash binds is the name the config resolves it to, not where `ssh`
takes that name: an `ssh` config whose `HostName`, `User`, or `Port` for it
changes between the review and the wetrun sends the reviewed plan to the machine
it now names, if that machine's key is a known one. What `ssh -G` prints is
configuration, not the machine, so the hash doesn't bind it; the machine itself
is held by host-key checking. Binding the machine to a plan would take its host
key's fingerprint, which the hash doesn't hold.

### What the hash covers that a preview doesn't print

A preview prints the target and, under each change, what it declares and every
step, with a file's content as a descriptor: its kind, length, and the start of
its SHA-512 (for a template, of the template text as written). `plan_hash` also
covers:

- a `file`'s content bytes, and any literal credential;
- a resource's `depends_on`, and trigger sources;
- package names for managers the target doesn't use;
- the text of the scripts Zap's own operations run (the put, link, directory,
  extract, snapshot, `pg_hba.conf`, and swap-path scripts, and an installer's
  fetch) and the command each runs in, with its arguments, privilege, and limits,
  so a `zap` build whose scripts, or the way it calls them, differ from the one that
  previewed computes a different hash.

The hash is not a fingerprint of the zap binary: what it does natively on a
local target, and the few commands it composes directly around a path (the
`rm -f` that clears a pending marker or removes what a failed validated write
created), are its own.

### What an approved hash doesn't fix

What Zap can't know when it plans:

- a secret's value (the plan says only that the reference is one);
- the state of the target between the read and the change;
- what the target's shell expands inside a command (`$HOME`, a variable in an
  apt `source` line), which on a local target is Zap's own environment, whose
  `HOME` an `--env-file` doesn't set;
- the bytes of a `source` file already on the target;
- what an `installer` URL serves that day;
- the path PostgreSQL reports for its `pg_hba.conf`;
- in a deploy, the artifact bytes and the environment your `build` and
  `prepare` commands run in.

Some commands also run before any review, as the connecting user, on every pass
that reads the machine (`plan`, `detect`, `apply` dry or wet, the deploy
preflight): a `script`'s `check`, a `verify`'s `command` assertions, a package's `check`
when it is a command, and an apt `source` line, which the target's shell expands
to compare with the list, so a `$(…)` in it runs at `zap plan`. This is one
reason [the config is first-party](#the-config-is-first-party).

### Escaped output

A review is only as good as the text it reads. Everything Zap prints as text
writes what it takes from the config, the environment, the command line, the
checkout (a deploy's commit subject, what `git` said), `zap.lock`, a file under
`~/.zap`, or the target with control, bidirectional,
and default-ignorable characters (every control character but tab, the line and
paragraph separators, zero-width characters and the like) spelled out as
`<U+XXXX>`, and a tab as spaces, so such text can't move the cursor, overwrite
output, reorder what is shown, or sit in a line unseen. Text that is a block (a
command, a script, what a failed command printed) keeps its lines, each
indented under its first. The `--json` event stream writes the same characters
as JSON `\u` escapes. The escape doesn't make look-alikes distinguishable:
homoglyphs, wide or blank spaces, and combining marks print as they are, a long
line still wraps, and text that spells `<U+000D>` or `{env:NAME}` prints the
same as what Zap writes for one.

## Secrets

- A config never reads the environment. Values are references
  (`zap.env('NAME')`), resolved by Zap when it acts. A reference holds a name,
  never a value. No value a reference resolves to, nothing a command prints,
  and no file's bytes can turn into one.
- Which references are secrets, and the forms masking looks for:
  [env.md](./env.md#secrets). A secret's value is **masked** out of every
  output: the text report, the JSON events, warnings, held reasons, drift
  observations, deploy step output, and errors. Masking is by value: a secret a
  tool prints in another form (the address `ssh` resolved a secret host name to)
  isn't found, and a secret under an ordinary name with an ordinary-looking
  value isn't known to be one until `mask()` lists it.
- Zap hands every command to its shell on **stdin**, detection and apply alike.
  No command text, `env` value, or working directory is on the argv of `ssh`,
  the login shell, or `sh`, on either machine, so none shows in `ps`. File
  content travels on stdin too. A program a command starts still shows its own
  arguments while it runs, and that includes the ones Zap starts (`curl <url>`,
  `psql -c <sql>`). Give a program a secret through an `env` value or a file it
  reads, not as an argument.
- A value is substituted into a command as text, into whatever quoting
  surrounds the reference. Zap **refuses** a value holding a single quote, a
  NUL, or a reference delimiter (U+FDD0 or U+FDD1) in a command, and a double
  quote in a `database` identifier, before anything runs:
  a wetrun checks every planned command first and exits 2 with nothing changed; `zap plan` and a dry run warn. That makes a reference safe
  **inside single quotes**, where a shell reads every other byte literally, and
  Zap and the shipped recipes put every value there, except the options
  documented as shell words (`psql_args`, `command_args`, a stop or reload
  command). A reference a config author writes outside single quotes, bare or
  inside double quotes, is read by the shell like the text around it, and
  keeping it safe there is the author's job. An `env` value is quoted after it
  resolves and carries anything but a NUL and the reference delimiters U+FDD0
  and U+FDD1.
- The **last-run report** and **`zap.lock`** hash a secret reference as a fixed
  token, and the report masks every registered secret out of any other value,
  so neither can be used to test a guess at a secret. A secret the rule doesn't
  recognize is hashed by value until `mask()` lists it
  ([lock.md](./lock.md#what-an-entry-holds)).
- A fetch error names the URL as the config declares it, its references unresolved,
  and the content cache names a file from the declared URL, so a token in a URL
  reaches neither a message nor a path.
- `remote` and `build` sources can carry a bearer `auth` token; it attaches as a
  request header to the source's own origin (scheme, host, and port) only: a
  `signature_url` on another origin is fetched without it, and a redirect to
  another origin drops it. Its resolved value is never hashed and never reaches
  the lock.
- There is no `--show-secrets`.

## Content Zap fetches

Every URL in a config is `https://`: a plain `http://`, `file://`, or any other
scheme doesn't validate, and neither does a URL carrying `user:password@`. The
one allowance is `http://` to a loopback host for the fetches Zap makes itself,
for a local mirror. Zap follows a redirect only to another `https://` URL (a
fetch that has stayed on loopback may be redirected on loopback), so a remote
server can't send a fetch to a plain-`http` port of the machine Zap runs on,
and a bearer `auth` goes only to the origin the config names.

Fetched bytes are pinned by blake3, verified against the pin before placement,
and cached by content address. A vendored pin is your own statement of which
bytes to trust. A tracked pin is trust on first fetch: `zap lock`, `zap update`,
or the first `zap apply --wetrun` records the hash of what the URL served then, and every
later fetch must match it. What authenticates that first fetch is TLS, plus a
minisign signature when a `build` source declares `verify`, checked before the
bytes are cached or pinned. A signature doesn't fix the version: an older
release the same key signed is caught only by the pin
([resources.md](./resources.md#verification)). The recorded pin is in
`zap.lock` and in the plan hash, so it is reviewed like any other change.
`minisign`'s exit status is that verdict, so the binary is found once (the
absolute path `ZAP_MINISIGN` names, else `PATH`) and run by that path, and one
inside a `node_modules` directory, or where it or any directory on the way to it
(every one up to `/`, links followed) is in reach of a group, another account,
or anyone but root and you, is refused; a refusal or a failed check names its
path. With those directories trusted, the gap between the check and the run is
only root's and yours.

`zap.lock` is reviewed input, like the config: its `config_hash` detects
staleness, not forgery, so review the lock's diff before committing it
([lock.md](./lock.md#what-an-entry-holds)).

One thing reaches the target with no pin. An `installer` is a script fetched
whole over https and then run: whatever its URL serves today, gated only by a
`check` path. A fetch that fails fails the step, and so does one that
serves an empty script; nothing runs. Prefer a `build` or a pinned `remote`
file when the upstream offers one. An `apt_repo`'s signing key is pinned like
`remote` content: Zap installs only bytes whose blake3 is the pin, and
detection compares the installed key with it
([resources.md](./resources.md#apt_repo)).

## Writes on the host

Zap installs a file by staging it under a new name in the file's own directory,
setting owner and mode on the open file, and renaming it into place; it never
follows a link at the file's name or at the staged name, and a `file`'s or
`directory`'s mode and owner are never set by name. The bytes are checked
against their SHA-512 before the rename, so a transfer cut short installs nothing. A directory's owner
and mode are set on the directory itself; a link at its name is refused. A
`file` keeps the owner, group, and mode it leaves unset from the regular file it
replaces, read from the name without following a link, never with a set-id or
sticky bit; a new one takes its directory's owner and group. A file with a second
name (a hard link) keeps nothing, and neither does anything below a directory
with its sticky bit set or that every account may write (`/tmp`, `/var/tmp`,
`/dev/shm`), however deep — Zap walks up from the file's directory by `..` to the
root, and checks every directory on the path as written, a link read as what it
leads to: there a `file` takes what Zap's own write gives, as root over SSH or as
you locally. A mode is never kept from a file with an extended POSIX access list
(ACL), whose mode bits show the list's mask: the write is refused until the
config declares `mode`. Zap sees a list through `getfacl`, else through GNU
`ls`'s `+`; a target with neither (stock Alpine) can't show one, and keeps the
mode. Elsewhere, whoever can write the directory can choose what is
kept, as they could replace the file; the files Zap's steps install never keep a
planted owner. So a `file` with a `mode` but no `owner`, written into a directory
another account can write, can end up readable by that account: it inherits that
account's directory, or the account plants a file there of its own for Zap to
keep. Declare `mode`, `owner`, and `group` on any file whose content the
directory's owner or group must not read: a planted file's mode is kept even
when the owner and group are declared, so without a `mode` the content can land
readable by everyone. A
`user`'s `authorized_keys` is written as that user, and a sudoers file is
installed only after `visudo -c` accepts it.

A file with a `validate` command is read before its write, so a failed check can
put it back. One script holds the file open and reads its bytes, mode, and
owner through that descriptor: as root over SSH, and locally as you, escalating
when refused. The change fails with nothing written when the name holds a link,
anything but a regular file (a fifo is refused without waiting on it), or a file
over 16 MiB. A rollback restores the bytes with the owner and group they had,
and their mode without any set-id or sticky bit the declared `mode` doesn't
carry, so root never makes a file set-id that the config didn't.

One window stays open: between the read's checks and its open, a link swapped
in is opened (not read) and the read refused, unless it leads to a fifo, which
holds the open until the read's five-minute timeout fails the change. A
directory's owner and mode change has the same window and timeout.

Missing directories are made one at a time, each inside the one before it held
open, and given, through its descriptor, the owner and group of the directory it
was made in, so it belongs to someone who could have made it; a link swapped in
for one is refused, with nothing made through it. The owner is given only to the
empty directory Zap just made: a directory renamed over it before it was opened,
by the owner of the directory it was made in, is refused and given nothing.
Anywhere below a directory with its sticky bit set or that every account may
write (`/tmp`), however deep, on the path as written or where its links lead,
what Zap makes stays its own, as root over SSH or as you locally: an account
that made `/tmp/cache`, as a directory or as a link to one of its own, can't
have the directories Zap makes there given to it.

Reads of a file's bytes, as root over SSH, read only a regular file of its own:
a name that is a symbolic link, a directory, a device, or a fifo is refused
before it is opened, and what was opened is read only when it is a regular file
and still the file at the name, so no byte comes through a symbolic link. The
checks can't close the instant before the open: an account that can write where
a managed file lives and swaps the name for a symbolic link in that instant has
Zap open what the link names, though not read it, and opening some devices acts
on the machine (a watchdog's), while a fifo holds the read until its timeout. A
regular file with more than one hard link is not read either, whoever owns it:
a hard link is the same file under another name, which an account can make in a
directory it writes, so a root read of the name could read a file that account
linked there. The link count is read from what was opened, and such a file
holds its resource, with the fix: replace it with a copy of its own (a single
link). Keep managed files in directories only root can write all the same. A
`file`'s `source` is read the same way, and a `user`'s own `authorized_keys` is
read as that user.

Zap does follow a link in a directory component of the path, so a managed path
under a directory someone else can write can be redirected to another
directory: keep root-managed files in directories only root can write. One
such redirection also slips past the shared-directory checks above: a link on
the path that leads through a second link sitting in a directory every account
may write, off both the path as written and the directories it resolves to
(`/srv/app` a link to `/var/shared/app`, itself a link the account that can
write `/var/shared` points at a directory of its own). Neither check passes
through `/var/shared`, so what is kept there, or given to directories made
there, is that account's choice. Keep the links on a managed path out of
directories others can write. The staged file is made by `mktemp`, mode `600`
whatever the umask or a default access list on the directory would give, and
held open; before a byte is written it must be a regular file of the writer's,
empty, with one name, and still the file at the staged name. A local user who
can write the directory could make the write fail, or stall it by swapping the
staged name for a fifo; they could not send the content, mode, or owner
anywhere, nor have root create a file where a link of theirs points. A run killed outright, or one refused at
its stage check, can leave a `.zap.*` file beside its target. A target needs
`/proc`.

The same holds for the files Zap's steps install: an apt sources list, the
nftables ruleset, and `/etc/fstab` are each installed whole by rename, never
edited in place, and so is an `apt_repo`'s signing key. `pg_hba.conf` is too,
but as the `postgres` account, not root:
PostgreSQL names the file and `postgres` owns its directory, so a rewrite as
root would write wherever that account pointed it. The rewrite keeps the file's
group and mode, and refuses a file that doesn't belong to `postgres` or a
directory it can't write; detection reads the file as `postgres` as well.

A `remote` file's or `build` source's archive is extracted only into a directory
at its own name: a link there is refused. `tar` runs in a new directory inside a
private staging directory (mode `0700`, the extracting user's) beside the
destination. The staging directory is held open from the moment it is checked:
a fresh, empty directory of the extracting user's, mode `0700`, at its name,
and not a link. Everything inside it is then reached through the descriptor, so
an account that can write the destination's parent may rename the staging
directory, or put a link at its name, but can't steer where `tar` writes or
what is removed. What `tar` extracts belongs to the extracting user, with no
set-id bit on a file and nothing group- or world-writable, whatever the archive
records. Before the rename, still inside the staging directory, the new tree is
given the owner, group, and mode of the destination it replaces, read without
following a link and set on the directory held open, never with a set-id or
sticky bit; then it is renamed into place. Below a directory with its sticky bit
set or that every account may write, checked as for a `file` (the parent's path
as written and where it resolves), nothing is kept: the new tree stays the
extracting user's, at the mode `mkdir` gives it. A destination that has an
extended or default access list is refused, a declared `mode` or not; the list
must be removed (`setfacl -b`). Such an account can still move the destination
itself, or the tree once it is in place: a parent another account can write is
trusted to that extent. The
archive's contents are trusted as pinned: its author chooses the names inside
it. Neither `tar` writes through a symbolic link the archive carries. BusyBox
`tar` will make a hard link to a file outside the archive that a member names, so
a new tree holding a file linked from outside it is refused, and removed before
it is renamed into place; hard links among the archive's own files extract.

A `remote` or `build` archive is uploaded as the connecting user into a
private staging directory of the run, then extracted as root. The extraction
opens it once and goes on only when the file it holds is a regular file, not a
link, owned by the account that ran `sudo`, with one link and writable by no one
else. It then copies what it holds into its own staging directory, which only
root reaches, and extracts that copy only when its SHA-512 is the digest of the
pinned bytes Zap passed, so a process running as the connecting user can't
swap or rewrite the archive between the upload and the extraction.

`hardened_openrc_service` never sources an `env_file`: its init script runs as
root, so root never parses it: `start_pre` has the service user check every
line (`su`, under a 10-second `timeout`), assigning nothing, and the daemon's own
process, already dropped to that user, exports the values before it runs the
command ([recipes.md](./recipes.md#env-files-under-openrc)). A service user that
can write its env file changes its own environment, as under systemd, and can
make a start wait out the timeout or fail; the refusal `start_pre` prints is
that user's process's words.

A release archive sits in no shared directory on either machine. On yours it is
a file in a private directory of the run; on the target it is installed into
the app path as the connecting user, and the release script extracts only the
file it has open, after checking that it belongs to that user, is writable by
no one else, and has the digest Zap sent. So another account on the host can't
swap or alter it between the upload and the extraction. Nothing checks what
your build put in it. A deploy trusts whoever can write the app path as much as
it trusts the connecting user: they can re-point `current`. Deploying as `root`
into a path another account can write lets that account redirect what root
creates there, so deploy as the path's owner. A run killed outright, or a
connection dropped between the upload and the script, can leave the archive at
mode `600` in the app path or in your temporary directory.

## Authority on the host

Zap's authority is SSH plus the host's `sudo`. There is no agent, server, API,
or role system to compromise. Privileged commands carry an explicit `sudo`; on a
local target file operations escalate only when denied, and over SSH they run
under `sudo` ([targets.md](./targets.md#two-tier-privilege-escalation)). Host
keys are trusted on first use and refused when changed, which holds only while
`ssh` records them: Zap reads your effective `ssh` config once per target
(`ssh -G`) and refuses to connect when every `UserKnownHostsFile` is
`/dev/null`. Every session has agent, X11, and port forwarding, a tunnel
device, a terminal, and `LocalCommand` turned off, whatever your config says. The host's own `sudo`
I/O log (`Defaults log_input`, replayed with `sudoreplay`) is the audit trail of
what ran as root: the plain `sudo` log records one constant wrapper per
detection batch, and the I/O log captures the script, resolved reference values
included. It never sees the unprivileged login lane, where operator commands
run. A file write appears in the `sudo` log as one `sh -c` command carrying
Zap's constant install script, with the path as its argument; the mode and owner
are arguments too, and the content and its digest arrive on stdin, so a host
that logs sudo's input records them.

## Fail closed

- A resource Zap can't read is **held**, not guessed. The run exits 1, and
  `deploy`'s preflight refuses to ship (exit 2). A "converged" that wasn't
  established is never reported.
- A pin that isn't current is **withheld**, so a stale lock can't make a changed
  resource read converged.
- A reference the comparison needs but can't resolve makes the whole pass
  **unverifiable**, exit 1: an empty string can both hide drift and invent it.
- A `file` write with `validate` is rolled back when the check fails, so a
  service is never reloaded onto a rejected config.
- A failed reload is remembered on the target and re-fired on the next plan.

## Security controls are read live, every time

`firewall`, `user`, and `database` guard the host's access surface and are
exactly what gets changed by hand: a `ufw default allow incoming` at the console,
or a key appended to `authorized_keys`. Zap keeps no detection cache, so such a
change shows on the next plan rather than hiding behind a stored verdict. The
same holds for security-relevant files: an `sshd` drop-in, a fail2ban jail, an
nginx site carrying a CSP. The exception is the lists Zap treats as additive
([below](#limits-and-defaults-to-know)): a declared entry that went missing
drifts, but an extra one, such as an injected `pg_hba` `trust` line, isn't
read.

## Limits and defaults to know

- Firewall allow rules, a database's `pg_hba` rules, and a user's groups are
  **additive**. Zap asserts that each declared entry is present (and, for a
  firewall, that the default policies match); an entry added out of band is
  neither detected nor removed.
- A `database` resource writes no `pg_hba` rule unless it declares
  `auth.hosts`, and never a `trust` one: the role is reached over the Unix socket
  by the OS account of the same name. A `trust` rule already in the file (one an
  older config added) stays until it is removed by hand; on Alpine,
  `alpine_postgres_setup` rewrites `initdb`'s, and any other `trust` line, to
  `peer` / `scram-sha-256`.
- A `link` whose path is a regular file reads as absent and is replaced.
- A `file` with no managed mode, owner, or group whose path is a symlink to
  matching content reads converged; the link is left as it is.
- Zap follows a symlink in a **directory component** of a managed path (see
  [Writes on the host](#writes-on-the-host)).
- A `swap`'s `size` is not compared after creation.

## Reporting a vulnerability

See the repository's security policy for how to report an issue privately.
