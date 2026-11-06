# The lock file and Zap's state

How Zap pins the evaluator that runs the config and the content it fetches,
what `zap.lock` holds, the commands that move it, and what Zap keeps under
`~/.zap`. Background: [concepts.md](./concepts.md#the-lock-file).

`zap.lock` is **declared intent**, not cached state. It belongs in version
control with the config. It records the toolchain pin and the tracked pins;
everything else Zap knows about a machine it reads live. The file is the
config's name with `.lock` for its extension, a regular file: a config itself named `*.lock` is refused
(the lock would overwrite it), and so is a symlink where the lock goes, by every
read and every write.

## The toolchain pin

Every command but `zap lock` evaluates the config only with the `fgro` build
(Gro's runtime) whose blake3 the lock's `toolchain` records:

```json
{
  "version": 3,
  "toolchain": {
    "fgro_blake3": "…"
  },
  "entries": {}
}
```

`zap lock` writes it: it hashes the binary `--fgro` or `ZAP_FGRO` names,
evaluates the config with that binary, and records its blake3, whatever the
lock pinned before. It prints the pin, and the one it replaced when the pin
moved:

```
$ zap lock
pinned fgro d5d10656aab9b1126949c67260afe0f06fbb208230306efd245186f2c4462c22
wrote zap.lock (no eligible resources)
```

A moved pin reads `pinned fgro <new> (was <old>)`. Every other command reads the
pin before it evaluates:

- **no pin**, because there is no lock or no `zap lock` has pinned one in it,
  refuses the evaluation, exit 2, saying to run `zap lock`;
- **a binary that hashes to something else** refuses, exit 2: run `zap lock` to
  pin the build you mean to use, or point `--fgro` at the pinned one.
  `zap update` doesn't re-pin it: moving the evaluator is `zap lock`'s alone, so
  it shows up in the lock's diff by itself;
- `zap lock --check` reports a binary off its pin as a stale toolchain pin, exit
  1, and evaluates nothing, so the entries go unchecked until it is pinned.

A build of `fgro` is not reproducible across machines, so the pin names one
binary: another machine evaluates the config only with a copy of the same
bytes, or after its own `zap lock`, which shows in the lock's diff. An
unchanged binary isn't hashed in full on every command
([On-disk state](#on-disk-state)).

A `"version": 1` lock has no toolchain pin: it reads, and every command refuses
until `zap lock` rewrites it. A `"version": 2` lock reads as it is; the next
write records it as version 3, which a `zap` build that reads only version 2 refuses. A
lock with a `version` newer than this `zap` reads is refused, `zap lock`
included.

## Two kinds of fetched content

A `file` with `remote` content, a `build`, whose source archive is fetched and
built, and an `apt_repo`, whose signing key is fetched and installed, take bytes
from a URL. Each is pinned by the **blake3 of the
fetched bytes**, so the same declaration always resolves to the same bytes. The
pin lives in one of two places:

| | Where the pin lives | Lock entry | How it moves |
|---|---|---|---|
| **Vendored** | in the config: `blake3: '…'` on the `remote` content or the `source`, `key_blake3: '…'` on an `apt_repo` | none | edit the hash in `zap.ts` |
| **Tracked** | in `zap.lock`, next to `zap.ts` | one per resource | `zap update <id>` or `zap lock` |

Vendored is self-contained: a URL and a hash, both in the config, and editing
the version means editing the hash. Tracked is the reviewed-upgrade path: bump
the version in the config, run `zap update`, and read the new pin in the lock
diff before committing both.

## What an entry holds

```json
{
  "version": 3,
  "toolchain": {
    "fgro_blake3": "…"
  },
  "entries": {
    "pgdg": {
      "kind": "apt_key",
      "config_hash": "…",
      "blake3": "…"
    },
    "zig": {
      "kind": "remote_file",
      "config_hash": "…",
      "blake3": "…"
    }
  }
}
```

`kind` is `remote_file`, `build`, or `apt_key`. `blake3` is the pin, 64 lowercase hex with no prefix. `config_hash`, in the
same form, is the blake3 of the resource's declaration with the pin folded in
and Zap's resource-hash version ahead of it: the fixed point the entry was
minted for. It is how Zap knows an entry is **stale**: edit what the hash covers
(the URL, a `strip_components`, a `build`'s `run`, an `apt_repo`'s `source`) and the recomputed hash no
longer matches, so the pin is no longer known to be the pin for _this_
declaration. It leaves out what doesn't change what the pin is the pin for: the
resource's identity (`id`, `name`, `depends_on`), an `auth` credential, and a
`file`'s `validate` command. A new Zap version that changes what the hash covers
reads every entry stale once, until `zap update`.

The hash is unkeyed. It tells a stale entry from a current one, not a genuine
entry from a forged one: whoever can edit `zap.lock` can write a matching
`config_hash` for any pin. The lock is trusted as reviewed input, like the
config beside it, so review its diff before committing it.

`zap.lock` is committed, so the hash must not be a way to test a guess at a
secret. A reference that is a [secret](./env.md#secrets) (by its use as an
`auth` credential, by `mask()`, by its name, or by the form of its value) is
hashed as the fixed token `[MASKED:NAME]`, whatever its value. Consequences:

- Rotating a token in a tracked URL doesn't make the entry stale. The lock
  verifies on a machine that doesn't have the secret when the entry's URL and
  path hold no non-secret reference, and when the secret is one by more than the
  form of its value (a variable secret only by that form has to be set).
- A reference that only _looks_ like a secret (`KEYCLOAK_VERSION`) loses its
  staleness signal too. `zap lock`, `zap update`, and `zap lock --check` print a
  `note:` naming each reference addressed this way because of its name or the
  form of its value, with the reason; `zap.unmask('NAME')` makes a non-secret
  one count again.
- Whether a reference is a secret can depend on its value: a URL is one only
  while it holds a password, and a secret-named variable isn't one while it
  holds a switch (`true`, `1`). An entry minted under one reading and checked
  under the other never reads current: it reads stale, or unverifiable when the
  variable is unset and only its value would make it a secret.

Any other reference is hashed by its resolved value, with every secret value
the config references anywhere replaced by its token where it occurs inside it,
as the output masking replaces it: a `DOWNLOAD_URL` that carries the value of a
`SIGNING_SECRET` the config also uses is hashed with that part as
`[MASKED:SIGNING_SECRET]`, so its entry moves when the rest of the URL does and
not when the secret is rotated with it. A secret shorter than 8 characters, or any
form of it shorter than that (trimmed, or with its `\n` decoded), is not replaced:
replacing `zig` wherever it occurs would move unrelated addresses with the
secret's value, and so few characters are guessable anyway. A secret can only
be replaced while it is set. While a variable the config uses as a secret (by its
use as a credential, `mask()`, or its name) is unset, `zap lock` and `zap update`
don't mint an entry whose URL or path holds a non-secret reference, and name the
variable to set. Such an entry already in the lock is still checked: an address
that matches reads current, and only one that changed reads unverifiable, naming
the variable, since the change may be the secret's. A value that carries a secret
under an ordinary name (a `BASE_URL` with a token in it) that no secret reference
names should be listed in `mask()`. A `build`'s `run`, `env` values, and `verify`
block are hashed as declared: a reference there counts as the reference, whatever
its value, so the entry moves only when the declaration does.

## Standing

Every command that reads the lock classifies each tracked resource:

| Standing | Meaning |
|---|---|
| current | the entry's `config_hash` matches the resource |
| missing | the resource is tracked but has no entry |
| stale | the resource changed since the entry was minted |
| unverifiable | a variable the hash depends on is unset: a non-secret reference, or a secret a non-secret value could hold |
| orphan | an entry for a resource the config no longer declares (warn only) |

`zap lock --check` reports the standing as its gate and exits 1 for missing,
stale, or unverifiable. The read-only commands (`plan`, `detect`, `status`, the
deploy preflight) lead their output with a `LOCK` banner for the same findings.
`apply` refuses a stale or unverifiable entry instead, as does a `deploy`
wetrun's preflight, with exit 2 ([cli.md](./cli.md) has every command's exit
codes).

## Who writes, who reads

Only `apply --wetrun` and the lock verbs write the file. Each keeps the
toolchain pin it found, except `zap lock`, which sets it. Every other command but
`zap version` validates the file, and refuses one that doesn't parse.

A write takes an exclusive `flock` on `zap.lock` itself, opened for writing, so
concurrent writers take turns. `apply --wetrun` and `zap update` merge into the
file as it stands when they hold it, so neither loses entries another wrote;
`zap lock` rewrites the file whole, reading the old one only for the pin it
replaces and to refuse one newer than it reads, so it rebuilds one that no
longer parses, such as one left with merge-conflict markers. A `zap.lock` is
refused (`zap.lock is not writable`) for a user who can't write it, rather than
replaced, and a lock Zap can't create says its directory isn't writable. A
`zap.lock` that is empty reads as no lock.

- **`zap apply`**: a dry run resolves any _missing_ tracked pin over the
  network, the one network read a dry run does, and reports it as
  `resolved, not yet written to zap.lock`. A wetrun writes the resolved lock
  before executing, so an apply is never recorded without its intent. A
  **stale** or **unverifiable** entry is an error on apply, never
  auto-reconciled: the message says what to run.
- **No pin is minted from a URL Zap can't fully resolve.** If a tracked URL
  references a variable that is unset or empty, `zap lock` refuses (exit 2) and
  `zap update` fails that entry, naming the variable; nothing is fetched with
  the reference blank. A dry `zap apply` holds the resource instead (exit 1),
  and a wetrun's env gate has already stopped the run.
- **`zap lock`**: rebuild. Pins the toolchain, re-fetches every tracked source,
  re-mints every entry, drops orphans, rewrites the file. All or nothing. The
  only verb that prunes, and the only one that moves the toolchain pin.
- **`zap lock --check`**: offline classification, no network, no detection,
  after the toolchain pin is checked against the binary.
- **`zap update [ids…]`**: re-fetch the named resources, or all tracked ones.
  An entry is rewritten when its pin advanced _or_ when its `config_hash` was
  stale (same bytes, edited resource), so the `zap update <id>` the stale error
  prescribes always clears it. Each advance is written as it happens; a failure
  later in the run keeps the earlier advances.
- **`plan`, `detect`, `status`, deploy's preflight**: read-only. They never
  mint, and they **withhold** any pin that isn't current. The resource then
  behaves exactly like one with no pin: `undetermined`, held out of the
  changeset, exit 1 (the preflight bails with exit 2), so a stale pin can't make
  `plan` report "converged" for a config `apply` refuses.

## What detection compares

The pin is the desired side of the comparison; detection never fetches. An
unextracted `remote` file is compared by digest against the pinned bytes; an
extracted one (`extract: tar.*`) through its **extract sentinel**, a
`.zap_remote_hash` file in the destination recording a digest of the tarball pin
and the extract form; a `build` through its **provenance sidecar**,
`<output>.zap-build`, recording a digest of the source pin and how it is built
(`extract`, `run`, `cwd`, `env`); an `apt_repo`'s key by the blake3 of the key
file's bytes against its pin. A pin change re-extracts, rebuilds, or reinstalls
the key, and so does an edit to what the digest covers. The details are in
[detection.md](./detection.md#content-is-compared-by-digest) and
[detection.md](./detection.md#build-exact-provenance-not-a-version-string).

## Verification

A `build` source that declares `verify` (minisign) has its signature checked
**before** the archive is cached or pinned, so a tampered fetch never becomes a
pin; a cache hit re-hashes the bytes against the pin instead. The fields and
the trust argument: [resources.md](./resources.md#verification).

## What the lock does not cover

Package versions, installer versions, and anything else that isn't a tracked
`remote` file, `build` source, or `apt_repo` key. A `package` is detected by the manager's query through
the package manager; an `installer` by its `check` path. Drift detection for
every other kind is the kind's own live reads.

## On-disk state

Zap keeps its own working state under `~/.zap`, or `$ZAP_HOME`, separate from
the config and the env file. Either path must be absolute; an empty `ZAP_HOME`
counts as unset. Every directory Zap keeps state in (the root, `cache/` and
everything under it, `ssh/`) is yours alone (mode `700`) and every file it
writes there is `600`; `bin/` is the installer's, and yours. Zap tightens a state
directory it finds looser, and refuses to run (exit 2) over one that is a
symlink, isn't a directory, belongs to another user, or can't be opened, since
the records in it decide what a wetrun may execute:

| Path | Holds |
|---|---|
| `bin/zap` | the installed binary |
| `bin/fgro` | where [install.md](./install.md#getting-fgro) suggests keeping the `fgro` build `ZAP_FGRO` names, apart from Gro's build output; Zap never writes it |
| `cache/<config-slug>/last_run/<host>.json` | the last-run report for this config on this host, latest only. A host that isn't a safe file name (a path separator, say) is filed as `host-<short-hash>.json`. No report is kept for a host that resolves through a masked reference. |
| `cache/<config-slug>/deploy_preview/<host>.json` | the deploy preview for this config on this host: the `plan_hash` the last `zap deploy` dry run (or refused wetrun) showed, when, and which pass. Withdrawn by a deploy wetrun before its first step. |
| `cache/<config-slug>/eval/` | the eval cache: the config's evaluated JSON beside a manifest of its path, the driver and `fgro` build it ran on, each file the evaluation read with its blake3, each path a resolution found empty, and the evaluated JSON's own blake3; an entry is served only for the config it was evaluated from, and only the JSON its manifest names. See `ZAP_EVAL_CACHE` in [cli.md](./cli.md#environment-variables-zap-reads); `--no-cache` bypasses it. |
| `cache/fgro_pins/` | the `fgro` binary's blake3, keyed by the file's inode, size and times, so an unchanged binary isn't hashed in full on every command ([The toolchain pin](#the-toolchain-pin)) |
| `cache/files/<blake3>/<name>` | the content cache: bytes for `remote` files and `build` sources, by content address, checked against their blake3 on every read |
| `ssh/` | SSH `ControlMaster` sockets for remote targets ([targets.md](./targets.md#how-zap-reaches-a-remote-host)) |

`bin/` is always `~/.zap/bin`: `cargo xtask install` doesn't read `ZAP_HOME`.

`ZAP_FGRO`, which names the `fgro` binary every config is evaluated with, is held
tighter than `ZAP_HOME`: it must be an absolute path, and an empty one is an
error (exit 2), not an unset one, since it names what runs your config
([install.md](./install.md#getting-fgro)). Under `sudo`, the state home, pin
cache included, is the one `sudo`'s `HOME` gives Zap.

None of this is part of the declared state or the plan hash, and none of it
stands in for reading the target. `zap.lock` is the exception by design: it
lives next to `zap.ts` and is committed, because it records intent.
