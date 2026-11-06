# Resources

A Zap config (`zap.ts`) declares **resources**: typed descriptions of desired
machine state. Zap detects the live state, compares it to the declared
resources, and applies the smallest set of changes that converges them. Each
resource has a stable `id`, an optional `name`, an optional `depends_on` list,
and a kind, set by the builder method you call (it becomes the `type` in the JSON
the config evaluates to).

```ts
export default (zap) => {
	zap.target({local: true});
	zap.pkg({id: 'ripgrep', from: {apt: 'ripgrep'}});
	zap.build({
		id: 'ghostty',
		source: {type: 'remote', url: 'https://example.com/ghostty.tar.gz', extract: {type: 'tar.gz', strip_components: 1}},
		run: 'zig build -p $HOME/.local -Doptimize=ReleaseFast',
		output: '$HOME/.local/bin/ghostty',
	});
};
```

## Resource types

| Builder method | Type | What it declares |
|---|---|---|
| `zap.pkg` | `package` | an OS package, through the target's package manager |
| `zap.apt_repo` | `apt_repo` | an apt source list and its signing key |
| `zap.script` | `script` | a command gated by an idempotency `check` |
| `zap.installer` | `installer` | a script fetched with `curl` and run by a shell, gated by a `check` |
| `zap.user` | `user` | a Unix user: shell, home mode, SSH keys, sudo |
| `zap.directory` | `directory` | a directory at `path`, with mode and owner |
| `zap.file` | `file` | a file with inline, template, source, or remote content |
| `zap.link` | `link` | a symlink from `path` to `target` |
| `zap.service` | `service` | a system service: enabled, started, stopped |
| `zap.database` | `database` | a PostgreSQL database and its role |
| `zap.swap` | `swap` | a swap file in `/etc/fstab` |
| `zap.firewall` | `firewall` | default policies and allow rules |
| `zap.verify` | `verify` | detection-time assertions, with no execution of its own |
| `zap.pipeline` | `pipeline` | an ordered imperative workflow of steps |
| `zap.build` | `build` | a verified source archive, built and installed |

Each section below gives the resource's purpose, its fields, and any structure
specific to the type. In path fields, references resolve against the
operator environment, and `~` and `$HOME` resolve against the target's home.
Both happen when Zap reads or changes the machine, and the plan holds both as
written ([env.md](./env.md#target-categorized-resolution)).

### One resource per thing

Two resources that manage one thing would undo each other on every apply, so a
config that declares them doesn't validate; the message names both ids and the
thing. What a resource manages:

| Type | Manages |
|---|---|
| `file`, `directory`, `link`, `swap` | its `path` |
| `build` | its `output` and the record beside it |
| `apt_repo` | its key file and its list file |
| `user` | the account, its `~/.ssh` directory and `authorized_keys` when `ssh_keys` is set, and its sudoers file when `sudo` is set |
| `service` | the service |
| `database` | the database (several databases may share a role) |
| `firewall` | the machine's firewall (a config declares at most one), and under nftables `/etc/nftables.nft` |

A `package`, a `script`, an `installer`, a `pipeline`, and a `verify` manage
nothing exclusive, so the same package may be declared twice. Two resources
at one path conflict even when they declare the same thing, so a directory two
recipes both need is declared once. Paths are
compared as written, after `//`, `/./`, and a trailing `/` are dropped and
`$HOME` is read as `~`; two spellings that only meet on the machine (`~/x` and
`/home/ops/x`, a `..` component, `nginx` and `nginx.service`) aren't caught.

### URLs

A URL in a config is `https://` with a host, and holds no `user:password@`
(a credential goes in `auth`, where it is a reference). Any other scheme is
refused, `http://` and `file://` included, when the config is read and again on
the resolved value when the URL holds a reference. For the URLs Zap itself
fetches (a `remote` file's, a `build` source's and its signature's, an
`apt_repo`'s `key_url`), `http://` is accepted for a loopback host
(`localhost`, `127.0.0.0/8`, `[::1]`), which is what a local mirror or a test
uses. A redirect is followed only to another `https://` URL; a fetch that has
stayed on loopback may be redirected on loopback. The URL the target fetches
(`installer.url`) is `https://` only.

### Account names

`username`, `groups`, and every `owner` and `group` field take an account
**name**, such as `'deploy'`, not a numeric uid or gid. Zap compares ownership
against the name from `stat`, so a numeric value is rejected when the config is
read.

The name must be a portable Unix account name: a lowercase letter or `_`, then
lowercase letters, digits, `_`, or `-`, optionally ending in `$`. That is the
`useradd` default on Debian and Alpine. Anything else (an uppercase letter, a
space, `/`, a comma, a backslash) is rejected there too. The name is
interpolated into `awk`, `usermod -aG`, a sudoers drop-in, and `/home/<name>`
paths, where a stray character would break out of the form.

## `package`

An OS package, installed through the target's package manager: **apt**
(Debian/Ubuntu) or **apk** (Alpine). The other managers (`pacman`, `brew`) parse
but have no backend, so their packages detect as undetermined.

```ts
zap.pkg({id: 'ripgrep', from: {apt: 'ripgrep'}});
```

- `from` (required): a map from package manager to package name, such as
  `{apt: 'ripgrep'}`. The target's `package_manager` selects the entry. A name
  takes no reference; see [Package names](#package-names).
- `check` (optional): a custom check, either a path (tested for existence) or a
  command (exit 0). It defaults to the manager's own query. A check beginning
  `/`, `~`, or `$HOME` is a path, and its references resolve; anything
  else is a command, run as written, and takes no reference. With no `check`, a
  package with no entry for the target's `package_manager`, or a target that
  declares none, holds (`undetermined`).

Installs are batched, after an automatic cache-update step. A package that waits
on another resource that waits on a package installs in a later batch
(`batch-install-<manager>-2`, …), after that resource. Detection is by
existence through the manager's query: a package held back, or installed for any
architecture, is installed. A query that fails (the database unreadable, the
tool missing) holds the package as undetermined rather than reading it missing.

### Package names

A name is one word in the manager's syntax: a letter or a digit, then letters,
digits, and `+ . _ - = ~ : / @`, not ending in `-`. Zap writes it into the
manager's command line unquoted, so a space or a shell character is refused.
The form decides what reads as installed:

| Form | Manager | Installed when |
|---|---|---|
| `name` | apt, apk | the query finds it, at any version |
| `name=version` | apt | it is at exactly that version, epoch and revision included. apt upgrades to it and refuses to downgrade to it, which fails the step. |
| `name/suite` | apt | `name` is installed; the suite chooses where a first install comes from |
| `name:arch` | apt | it is installed for that architecture; a package built for every architecture (`all`) counts as the target's own |
| `name=version`, `name~version` | apk | the installed version matches, as apk compares them |
| `name@tag` | apk | `name` is installed; the tag chooses where a first install comes from |

A version and a suite together name no package apt knows. Refused, because the
query would never find the package installed or the form isn't one word:

- apt: an empty version (`name=`) or architecture (`name:`); `name:any` and
  `name:native`, which apt resolves to an architecture and dpkg records no
  package under; `name:all`, which apt reads as the native architecture while
  dpkg records `all` only for a package built for every one (name the
  architecture, or none); an architecture that isn't one word of lowercase
  letters, digits, and `-`.
- apk: `name>=1.2`, `!name`, `.name`; a version operator with nothing after it
  (`name=`, `name~`, `name==`, `name@tag=`), which apk's query reads installed
  whether or not it is and `apk add` refuses.

A trailing `+` is part of the name, since Debian has packages named so
(`memtest86+`). apt's own `name+` install marker on a package with no `+`
installs it but never reads installed, so write the name without it.

## `apt_repo`

An apt repository: a GPG signing key plus a sources-list entry. Zap installs
the key, writes the `.list` file, and injects `signed-by=<key_path>` into the
source line automatically, so the key and the repo can't drift apart.

```ts
zap.apt_repo({
	id: 'pgdg',
	key_url: 'https://www.postgresql.org/media/keys/ACCC4CF8.asc',
	source: 'deb https://apt.postgresql.org/pub/repos/apt bookworm-pgdg main',
});
```

- `key_url` (required): the URL Zap fetches the GPG signing key from
  ([URLs](#urls)). It may carry a reference.
- `key_blake3` (optional): the key's pin, the blake3 of its bytes, 64 lowercase
  hex. Without it the pin is tracked in `zap.lock`
  ([lock.md](./lock.md#two-kinds-of-fetched-content)).
- `source` (required): the `deb` or `deb-src` source line. `signed-by=` is
  injected from `key_path`.
- `key_path` (optional): where the key is stored. It defaults to
  `/usr/share/keyrings/<id>.asc`.
- `list_file` (optional): the `.list` file path. It defaults to
  `/etc/apt/sources.list.d/<id>.list`. The list is installed whole, mode `644`.

`key_path` and `list_file` take no reference; `key_url` may carry one. Each of
the two paths is absolute and holds no whitespace and none of `"`, `$`, a
backtick, or `\`.

`source` is written through a shell with `/etc/os-release` sourced, so it can
reference the distro's variables for portability. For example,
`deb … $VERSION_CODENAME main` resolves to `bookworm`, `noble`, and so on, on
the target. `key_path` is written into that line, so the shell reads it too.
`list_file` is passed literally; `key_url` is fetched by Zap on the operator's
machine and never reaches the target. The detector resolves `source` the same
way, so a templated line still converges. Because the shell reads the line,
`source` takes no reference.

The key is pinned content, like a `remote` file's. Zap fetches it on the
operator's machine, checks the bytes against the pin, and installs those bytes
whole at `key_path`, mode `644`, owned by `root:root`: staged beside the key,
checked against their SHA-512, and renamed over it, so the live key is only
ever replaced by the pinned bytes. A fetch whose bytes aren't the pin's fails
the change before anything on the target is touched, naming both digests:

```
content hash mismatch for https://www.postgresql.org/media/keys/ACCC4CF8.asc: declared <pin>, fetched <blake3 of what was served>
```

Detection reads the key and compares its blake3 with the pin: a key that
isn't the pinned bytes drifts (`signing key differs from its pin`), and the
apply installs the pinned one. A rotated upstream key is not drift until the
pin moves: `zap update <id>` fetches the key again and advances the pin, which
shows in the lock's diff. A key with no pin yet is held (`undetermined`) by the
read-only commands, a dry `apply` mints its pin, and a wetrun records it in
`zap.lock` before it runs, as for any tracked content. A `key_path` that is a
symbolic link, a hard link, or not a regular file, or a key over 1 MiB, is held
too: its bytes aren't compared.

## `script`

An imperative command guarded by an idempotency `check`. Zap runs `check` first.
An exit code of 0 means the script is already applied and `run` is skipped.
Otherwise `run` executes.

```ts
zap.script({
	id: 'enable-lingering',
	check: 'loginctl show-user $USER | grep -q Linger=yes',
	run: 'sudo loginctl enable-linger $USER',
});
```

- `check` (required): a command whose exit 0 means "already applied", which
  skips `run`.
- `run` (required): the command run when `check` fails.
- `cwd` (optional): the working directory for `check` and `run`. An absolute
  path, taken as written: a reference is rejected when the config is read, and
  a `~` or a relative path by the structural gate.
- `env` (optional): extra environment for the whole of `check` and `run`.
  Values resolve references and can hold any byte but NUL (and the two
  characters Zap marks a reference with, U+FDD0 and U+FDD1), so `env` is how a
  script takes a value with a `'` in it, or a secret. A name can't begin with
  `__zap_`.

The `check` carries the whole idempotency contract. Make it precise, or the
script runs on every apply.

`cwd` and `env` apply to both commands, the same way on a local target and over
SSH: Zap enters `cwd`, exports `env` for the whole command (every command of a
compound sees it), then runs your text on a line of its own. The plan shows
them, and the `check`, above the command:

```
  [+] migrate  (script)
      cwd: /srv/app
      env: DATABASE_URL={env:DATABASE_URL}
      env: MODE=prod
      check: test -f .migrated
      > ./migrate.sh
```

A `check` that can't enter `cwd` reads as not applied, like any failing check, so
a script whose `cwd` another resource creates converges in one apply. A `run`
that can't enter it fails the change with nothing run. A `sudo` inside either
command resets the environment by default, so `env` doesn't cross it.

## `installer`

Software installed by running a downloaded script, the `curl … | sh` pattern,
gated by a `check` so it runs only once. Zap fetches the script whole first and
hands it to the shell only if the fetch succeeded and the script isn't empty, so
a failed download fails the step and nothing runs.

```ts
zap.installer({
	id: 'deno',
	url: 'https://deno.land/install.sh',
	check: '~/.deno/bin/deno',
});
```

- `url` (required): the install script's `https://` URL ([URLs](#urls)), piped
  into `shell`.
- `check` (required): a path, absolute or beginning with `~` or `$HOME`, tested
  for existence to confirm installation.
- `shell` (optional): the command the script is piped into (default `sh`). It is
  one line, shown in the step as written and read by the target's shell like a
  `script`'s `run`, so `bash -s -- --yes` passes arguments.

An installer executes remote code on the target, so prefer a pinned, trusted
URL. For content that should be verified and pinned, a `build` or a `file` with
`remote` content is the stronger choice.

## `user`

A Unix user account. Zap creates the account if it doesn't exist, with
`useradd -m -d /home/<username>`, so the home is `/home/<username>` whatever the
distro's default. Zap then detects and reconciles
each managed attribute independently. An attribute left unset is unmanaged: Zap
neither sets nor reverts it.

Zap manages a user's home as `/home/<username>`: the paths `home_mode` and
`ssh_keys` act on are derived from the name, not read from the machine. The
cases where that would be wrong fail loudly instead:

- A `user` with `username: 'root'`, whose home is `/root`, is **rejected by the
  structural gate** before any run, whatever it declares. Manage root's files
  with `file` and `directory` resources.
- An existing account whose home in `/etc/passwd` is anything else, or that has
  none there, is **held** (`undetermined`) when the user declares `home_mode` or
  `ssh_keys`, and the reason names the home it found:

  ```
  deploy's home in /etc/passwd is /srv/deploy, not /home/deploy: zap manages a user's home as /home/<name>, so its `home_mode` and `ssh_keys` would miss the account's own
  ```

  An account that doesn't exist yet has no `/etc/passwd` home to hold it: Zap
  creates it.
- What is at `/home/<username>` is read too, without following a link, whether
  the account exists or not. `useradd` leaves a directory already there as it
  was, owned by root typically, and copies no skeleton files into it:
  - when Zap creates the account, the creation gives the directory
    itself, not what it holds, to the user and its login group after `useradd`:
    `sudo chown -h -- 'deploy:' '/home/deploy'`, a no-op when `useradd` made
    the directory;
  - for an existing account, a directory the user owns or root owns is as
    declared and keeps its owner, so a home sshd's `ChrootDirectory` needs root
    to own stays root's;
  - a directory owned by any other uid, a live account's or one no account
    has, holds the user, existing or not;
  - a symbolic link at `/home/<username>` holds the user and is not followed:
    Zap acts through no link it didn't make, so a layout that links the home
    elsewhere declares neither `home_mode` nor `ssh_keys`; anything else that
    isn't a directory holds too;
  - a `/home` that is missing, or that the connecting user can't search,
    holds the user, naming `/home`, rather than reading as nothing there.

  ```
  /home/deploy is owned by uid 1002 (deploy's uid is 1001); chown it to deploy, or remove it: zap manages a user's home as the directory /home/deploy, the user's own or root's
  ```

  A user that declares neither `home_mode` nor `ssh_keys` isn't read for its
  home.

```ts
zap.user({
	id: 'deploy',
	username: 'deploy',
	shell: '/bin/bash',
	ssh_keys: {copy_from: 'root'},
	sudo: 'nopasswd',
});
```

- `username` (required): the Unix username to manage. It must be a portable
  account name; see [Account names](#account-names).
  `groups` entries follow the same rule.
- `shell` (optional): the login shell, such as `/bin/bash`. The system default
  applies when unset. It takes no reference.
- `home_mode` (optional): the octal mode for the home directory, such as `711`.
- `ssh_keys` (optional): the SSH `authorized_keys`, as either
  `{copy_from: '<user>'}` or `{keys: ['ssh-ed25519 …', …]}`, never both: an
  object with both is rejected before any run. A `keys` list needs at least one
  key, and no entry may be blank. See [SSH keys](#ssh-keys).
- `sudo` (optional): the user's sudo grant. See [Sudo](#sudo).
- `groups` (optional): supplementary groups the user must belong to, such as
  `['docker', 'postgres']`. It is additive: listed groups are added
  (`usermod -aG`) and groups not listed are left untouched. The primary and
  system groups are never stripped. Names only, like `owner`.

### SSH keys

`ssh_keys` is authoritative. Zap writes `authorized_keys` to exactly the
declared set and detects drift by comparing the file's content. A key added out
of band is removed on the next apply, and a rotated or removed key is applied
again.

A key is installed as written and takes no reference; one is rejected
before any run. An entry is one key on one line: an entry that ends in a line
break doesn't validate. A config reads no file but its imports, so for keys that
differ per environment, have the config import them from a module in the project
(`export const OPS_KEYS = ['ssh-ed25519 AAAA… ops'];`).

For `copy_from`, the source user's `authorized_keys` is the desired content. If
it can't be read, the user is applied again and does not read converged.

Zap gives the account its `~/.ssh` (mode `700`, owned by the user; a symlink
there is refused, not followed) and then writes `authorized_keys` **as that
user**, mode `600`, so nothing the user plants in its own `.ssh` can redirect
the write anywhere the user couldn't already write. A `copy_from` source is read
as the source user at apply. Other files in `.ssh` are left as they are.

Setting `ssh_keys` also normalizes the account's `/etc/shadow` password field to
`*`, which means no password and _not_ locked. This is authoritative too: any
other value drifts and converges back to `*`. That covers:

- a `!` lock. `useradd` leaves a passwordless account locked, and Alpine's sshd
  refuses pubkey login to a locked account ("account is locked").
- an empty field, which allows passwordless login and is a security hole;
- a set password.

### Sudo

- `'nopasswd'` or `'password'` grants sudo for all commands.
- `{mode: 'nopasswd' | 'password', commands: ['<sudoers spec>', …]}` restricts
  the grant to the listed commands. A spec is written into the file as declared
  and takes no reference. The list can't be empty, and a spec can't be blank or
  hold a control character (a tab counts): each is rejected when the config is
  read. For a grant of every command, write the mode alone. A spec is sudoers
  text, so a `,` in one ends a command and begins another.
- `false` removes the user's sudoers file.
- `true` is rejected at parse. It grants nothing, and would otherwise read as a
  removal.

The sudoers file is installed at mode `440` only after `visudo -c` accepts it;
a file `visudo` rejects is never installed, and the old one stays.

## `directory`

A directory at `path`, with optional managed permissions.

```ts
zap.directory({id: 'app-dir', path: '/opt/app', mode: '755'});
```

- `path` (required): the directory path, absolute or under `~`. It may carry a
  reference, and the value it resolves to is held to the same rule.
- `mode` (optional): the octal mode, such as `'755'`, `7777` at most.
- `owner` (optional): the owner.
- `group` (optional): the group.

Zap makes the directory and any missing parents. Each one it makes, the
directory itself included, takes the owner and group of the nearest directory
that was already there, and the mode a plain `mkdir` gives; then the declared
mode, owner, and group are set. So an owner or group left unset is inherited
from above, and an existing directory keeps its own. Anywhere below a directory
with its sticky bit set or that every account may write (`/tmp`, `/var/tmp`,
`/dev/shm`), however deep, on the path as written or where its links lead,
nothing is inherited: what Zap makes there is the writer's. On a local target,
directories that take another account's owner, or a group you aren't in, are
made through `sudo`.

With a managed mode, owner, or group, a symlink at `path` reads as drift and
fails the change: Zap sets a directory's attributes on the directory itself and
never through a link. Use [`link`](#link) for a symlink.

## `file`

A file with managed content and optional permissions. Content comes from one of
these sources, selected by `content.type`: `inline`, `template`, `source`, or
`remote`.

The file's parent directory is created automatically if missing, like
`mkdir -p`: each directory made takes the owner and group of the nearest one
that was already there (the writer's, below a directory anyone may write, as in
[`directory`](#directory)), and the mode a plain `mkdir` gives; an existing one
is left as it is. A separate `directory` resource is only needed when the directory
itself wants a managed mode or owner.

A `file` is a regular file, written whole: Zap stages the content under a new
name beside it (`.zap.XXXXXX`, mode `600` until a declared mode is set), checks
over SSH or `sudo` that the bytes that arrived are the bytes it sent, sets the declared owner and mode on that staged file, and
renames it into place. So the file never exists at its path with partial
content or the wrong mode, a mode or owner drift rewrites it, and a symlink at
the path is replaced by the file, not followed (a symlink to a directory fails
the change on Alpine; with a managed mode, owner, or group, a symlink there
reads as drift). Use [`link`](#link) for a symlink.

A mode, owner, or group the file leaves unset is kept: a rewrite gives the new
content the owner and group of the file it replaces, and its mode without any
set-id or sticky bit. A new file takes its directory's owner and group, and the
mode a plain create gives (`0666` less the writer's umask). A symlink at the
path, or a file with a second name (a hard link), keeps nothing; the file that
replaces it is the writer's. Nothing is kept anywhere below a directory with its
sticky bit set or that every account may write (`/tmp`, `/var/tmp`, `/dev/shm`),
however deep, on the path as written or where its links lead: anyone could have
put what is there, or made a directory or a link on the way, so the file is the
writer's.

A mode is never kept from a file with an extended POSIX access list (ACL): its
mode bits show the list's mask rather than its group's, and the rewrite carries
no list, so a kept mode would hand the group what the list gave one account. A
`file` that leaves `mode` unset over such a file fails the change, with the file
as it was, asking for a declared `mode`. Zap reads the list with `getfacl`, else
from the `+` GNU `ls -l` prints after the mode; a target with neither, such as
stock Alpine (BusyBox `ls`, no `acl` package), can't show one, and there the mode
is kept. On a local target,
keeping an owner or group you can't give, such as another account's file or a
new file in a directory root owns, goes through `sudo`.

Declare `mode`, `owner`, and `group` on any file whose content the directory's
owner or group must not read. Without them, a file written into a directory
another account can write can end up readable by that account: it takes that
account's directory's owner and group, or the owner, group, and mode of the file
that account planted at the path. A declared owner and group don't replace a
planted file's mode, so without a `mode` the content can land readable by
everyone ([security.md](./security.md#writes-on-the-host)).

```ts
zap.file({
	id: 'motd',
	path: '/etc/motd',
	content: {type: 'inline', content: 'Managed by zap.\n'},
	mode: '644',
});
```

- `path` (required): the target path. It may carry a reference and `~`.
- `content` (required): the content source. See [`content`](#content).
- `mode` (optional): the octal mode, such as `'644'`.
- `owner` (optional): the owner, as a user name and not a numeric uid. See
  [Account names](#account-names).
- `group` (optional): the group, as a group name and not a numeric gid.
- `triggers` (optional): ids of `service` resources notified when this file
  changes; naming any other kind doesn't validate. This is
  the push side of the trigger model; see [`service`](#service).
- `validate` (optional): a command that must exit 0 after the write, such as
  `sudo nginx -t` (exported as `NGINX_VALIDATE` from `recipe_nginx.ts`). See
  [Validated writes](#validated-writes).

### Validated writes

With `validate` set, apply snapshots the file (its bytes, mode, and owner, read
through one open descriptor and held in memory: as root over SSH, and locally
as you, escalating when refused), writes, then runs the
command against the file in place. A symlink at the path, anything there that
isn't a regular file, and a file over 16 MiB can't be snapshotted, so the change
fails before the write. If the check fails, the snapshot goes back as a regular
file with the owner and group the old content had, and its mode without any
set-id or sticky bit the declared `mode` doesn't carry; a file that didn't
exist is removed; and the change fails. So any service the file `triggers` is never reloaded onto the
bad config. A write that fails before installing leaves the file as it was, and
restores nothing.

Checking in place is what lets it cover a file some larger config includes:
`nginx -t` can't check a site file on its own.

```ts
zap.file({
	id: 'nginx-config',
	path: '/etc/nginx/sites-available/example.com',
	content: {type: 'inline', content: site},
	validate: NGINX_VALIDATE,
});
```

What it doesn't cover:

- **One file at a time.** Each file is checked against whatever else is on disk.
  An edit that has to land in two files at once (renaming a zone one file defines
  and another uses) fails the first file's check and rolls it back. Stage the
  edit across applies: add the new name, switch the user, drop the old.
- **Not yet active.** The check only sees what the parent config loads. An nginx
  site in `sites-available/` isn't checked until its `sites-enabled/` link exists,
  so on a fresh host the first real check is the reload.
- **The write-to-restore window.** The rejected content is on disk for one
  command's round trip. A run killed inside it leaves that content in place, and
  detection reads it as converged, since the bytes match what was declared.

The last two, plus hand edits on the host, are what a [`verify`](#verify)
running the same command closes. It is checked again on every plan. A config the
running service couldn't reload onto then shows up as a pending change and does
not read as converged, and `zap deploy`'s preflight refuses to ship over it:

```ts
zap.verify({
	id: 'nginx-config-valid',
	...nginx_config_verify(), // {assertions: [{type: 'command', run: NGINX_VALIDATE}]}
	depends_on: ['nginx-service'],
});
```

`validate` is apply-time behavior, not desired state: detection doesn't read
it, and changing it alone plans no change. It is still part of the declaration:
the last-run report's hash covers it, and so does `plan_hash` whenever the file
has a change in the plan. The lock's `config_hash` leaves it out. It is for text config
(`inline`, `template`, `source`), and is rejected on `remote` content and when
blank.

### `content`

The content source is discriminated on `type`.

**`inline`**: literal content, written verbatim.

- `type` (required): `'inline'`.
- `content` (required): the file's content, installed as declared. It takes
  no reference.

**`template`**: a `{{key}}` template with per-variable substitution.

- `type` (required): `'template'`.
- `template` (required): the template body, with `{{key}}` placeholders. A
  placeholder is a variable's name between the braces and nothing else; braces
  around anything that isn't a name (`{{ .Values.port }}`) are text.
- `vars` (optional): the values substituted for each `{{key}}`, after a
  reference in a string value resolves. A value that isn't a string is
  substituted as its compact JSON text and takes no reference at any depth; pass
  the value as a string var of its own. A reference can't stand for the whole
  `vars` map. A value with no kind is substituted as text, so it has to be safe
  where it lands: in a file a shell or systemd's `EnvironmentFile=` reads, a
  value holding a `'` ends its quoting.
- `kinds` (optional): the kind of value a variable must render to, by its
  name. Each key names a variable in `vars`. A variable not named here declares
  no kind: a reference in its value is still held to the `text` rule, and a
  value written out is substituted unchecked.

Placeholders and variables match one for one: a `{{name}}` whose name is
letters, digits, and `_` (not starting with a digit) and that has no variable of
that name doesn't validate, and neither does a variable no placeholder names, so
a misspelled name is caught in either direction. The body is substituted in one
pass and a value is never read again, so a value may hold `{{…}}` as text; that
is also how a literal `{{name}}` is written.

A reference's value can't hold a line break (CR or LF) or a NUL: the files a
template makes are read a line at a time, and a line break in a value would add
a line of its own (another variable in an environment file, another directive
in a config). Detection holds the file and names the variable, and a wetrun is
refused before anything changes.

Within its line, what a value may hold is the file's grammar: a `;` or a `}`
in an nginx `server_name {{domain}}` ends the directive or the block. A kind
holds a variable's whole rendered value to a form whose alphabet has none of
that:

| Kind | A value is |
|---|---|
| `text` | any one line: no line break, NUL, or reference delimiter; every kind keeps this rule, and a reference's value is held to it with no kind declared |
| `hostname` | dot-separated labels of ASCII letters, digits, and `-`, each 1 to 63 bytes, no leading or trailing `-`, at most 253 bytes; no trailing dot, wildcard, or `_` |
| `port` | a decimal number from 1 to 65535, with no sign or leading zero |
| `path` | an absolute path whose names are ASCII letters, digits, `.`, `_`, `-`, `+`, and `@`, with no empty, `.`, or `..` name |
| `email` | a local part of ASCII letters, digits, `.`, `_`, `%`, `+`, and `-` (no leading, trailing, or doubled `.`), an `@`, and a `hostname` |
| `env_value` | a value inside single quotes in an env file: `text` with no `'` |

```ts
zap.file({
	id: 'nginx-site',
	path: '/etc/nginx/sites-available/app',
	content: {
		type: 'template',
		template: site,
		vars: {domain: zap.env('DEPLOY_DOMAIN'), port: 4040},
		kinds: {domain: 'hostname', port: 'port'},
	},
});
```

A value written out is checked when the config is read. One carrying a
reference is checked once it resolves: detection holds the file, and a wetrun
is refused before anything changes, naming the variable and its kind, never the
value. The nginx site and env recipes return their templates whole, with the
kinds of the variables they place ([recipes.md](./recipes.md)).

**`source`**: content copied from a file already on the target at apply time.

- `type` (required): `'source'`.
- `path` (required): a path on the target, absolute or under `~`. It may carry
  a reference.

The source is read as root over SSH, byte for byte, so a binary file copies
whole. It must be a regular file of its own at that path: a symbolic link there
is never read through, and neither is a directory, a device, or a fifo. Detection
holds the resource on any of them, and apply refuses them with nothing written.
The bytes are held in memory while they are written, so a source larger than
16 MiB is refused at apply.

**`remote`**: content fetched from a URL, content-addressed and verified the
same way a [`build`](#build) source is.

- `type` (required): `'remote'`.
- `url` (required): the fetch location ([URLs](#urls)). It may carry a
  reference, resolved when Zap fetches; how the lock addresses it is in
  [lock.md](./lock.md#what-an-entry-holds).
- `extract` (optional): how the bytes are materialized. `{type: 'none'}` is the
  default; `{type: 'tar.xz' | 'tar.gz', strip_components?: N}` extracts an
  archive. `strip_components` lives inside the tar form (beside `none` it is
  rejected), and strips leading path components: `1` flattens a tarball's single top
  directory.
- `auth` (optional): a bearer credential for a private byte host, resolved at
  the IO boundary and never hashed. See [Remote auth](#remote-auth).
- `blake3` (optional): a vendored content pin. Present, the file pins itself;
  absent, it tracks through `zap.lock`. See
  [lock.md](./lock.md#two-kinds-of-fetched-content).

**How a remote file is detected.** An unextracted file by digest against the
pinned bytes, an extracted one through its `.zap_remote_hash` sentinel;
detection never fetches. See
[detection.md](./detection.md#content-is-compared-by-digest).

**Placement and ownership.** Placement and extraction escalate as needed: a
`none` placement or an archive extract into a root-owned destination (such as
`/opt/zig`) runs under `sudo`. When `extract` produces a directory tree, a
declared `mode`, `owner`, or `group` applies to the **top-level** destination
only (a symlink there holds the resource, and nothing is extracted through it).
The extracted contents below it belong to the extracting user, which is root
when the extract escalated, whatever owners the archive records, and carry no
set-id bit on a file and no group or world write bit. The archive is extracted
into a private directory beside the destination, which then takes the
destination's name; a failed extraction leaves the destination as it was. A new
pin replaces the old tree whole, and the new one gets the owner, group, and
mode the old one had (without a set-id or sticky bit) before it takes the name,
so what the resource leaves unset there is kept, and a failure to set them
leaves the old tree in place. Below a directory with its sticky bit set or that
every account may write, nothing is kept, as for a [`file`](#file): the new tree
is the extracting user's, at the mode `mkdir` gives it. A replaced tree that
has a POSIX access list (ACL), a default one included, fails the change with the
old tree in place, whatever `mode` declares; remove the list (`setfacl -b`) to
let Zap replace it. The archive never sets the destination's mode, whatever it
records for its top directory: a new destination keeps what `mkdir` gives it. Zap replaces only a tree it extracted (one holding its sentinel) or an
empty directory; a destination holding anything else holds the resource
(`undetermined`), and nothing is extracted into it. If the whole tree needs a
specific owner, apply it with a `script` running a recursive `chown`.

The swap needs room for the old and the new tree at once, and the archive sits
on the target three times while it extracts: the upload in a private directory
under `/tmp`, the copy the extraction checks and reads, on the destination's
parent filesystem, and the tree it extracts. A run that is killed
can leave a mode `0700` `.<name>.zap-XXXXXX` directory of the extracting user's
(root's, when it escalated) beside the destination; killed between the two
renames, it holds the old tree. One is also left, empty, where an account that
can write the parent renamed it. The staging name is 12 bytes longer than the
destination's, so a destination name within 12 bytes of the filesystem's
`NAME_MAX` can't be extracted.

#### Remote auth

For a private byte host, attach a bearer credential. Its token is typically a
reference, resolved on the operator side at fetch time. It is never
written to the content hash, and an empty resolution is an error, not a bogus
request.

```ts
auth: {scheme: 'bearer', token: zap.env('API_TOKEN')}
```

## `link`

A symbolic link at `path` pointing to `target`.

```ts
zap.link({id: 'vim', path: '~/.local/bin/vim', target: '/usr/bin/nvim'});
```

- `path` (required): the symlink path. It may carry a reference and `~`.
- `target` (required): what the link points to, resolved the same way.

A regular file sitting at `path` reads as absent and is replaced by the link. A
directory there also reads absent, but the step fails rather than putting the
link inside it: move the directory, or point the resource at another path.

## `service`

A system service managed through the target's service manager (**systemd** or
**OpenRC**). It controls whether the service is enabled at boot and whether it
is running, and it can restart or reload in response to other resources
changing. That is the pull side of the trigger model; [`file`](#file)'s
`triggers` is the push side.

```ts
zap.service({id: 'nginx', service: 'nginx', running: true, reload_on: ['nginx-conf']});
```

- `service` (required): the service name, as the target's service manager knows
  it. It takes no reference, and is one word: a letter or a digit, then letters,
  digits, and `_ . @ : -` (`nginx`, `getty@tty1.service`). Zap writes it into
  the manager's command line unquoted, so a systemd name escaped with a
  backslash isn't accepted.
- `enabled` (optional): whether the service is enabled at boot (default `true`).
- `running` (optional): whether it should be running now. Omit it to leave
  runtime state unmanaged. On OpenRC, starting a crashed service (its daemon
  died while it was marked started) first resets it with
  `rc-service <svc> zap`, since a plain start of a crashed service does nothing. OpenRC reads a
  service as crashed when the process its pidfile names isn't running, so a
  daemon still running under a stale pidfile gets a second copy beside it.
- `restart_on` (optional): resource ids whose change triggers a restart of
  this service: `systemctl try-restart` on systemd,
  `rc-service --ifstarted <svc> restart` on OpenRC.
- `reload_on` (optional): resource ids whose change triggers a reload of this
  service. That is `try-reload-or-restart` on systemd and
  `rc-service --ifstarted <svc> reload` on OpenRC, where a service that can't
  reload fails the step.

A trigger acts only on a running service. A service that isn't running is left
as it is, and starts on the new state when something starts it, so a unit file
written on a first deploy restarts nothing before its binary is there. A service
converged but for its trigger runs the trigger alone (after systemd's
`daemon-reload`), never its enable or start again. A trigger on a service
declared `running: false` (its `restart_on` / `reload_on`, or a file's
`triggers` naming it) is a structural error: it could never act.

The target must declare a `service_manager`. The structural gate rejects, in
every command, a config with **service intent** on a target that declares none,
and doesn't guess `systemctl` on a host that may run OpenRC. Service intent is any of:

- a `service` resource;
- a `file` with `triggers`;
- `deploy.service`.

A declared manager with no backend (`launchd`) parses. Its services detect as
`undetermined`, and their verbs plan as notes, not commands.

### Pending triggers

A trigger fires when one of its sources changes in the current plan. On its own,
a failed reload would be lost: the next plan reads the source as converged (its
bytes match) and the service as running (on the old config).

So Zap keeps a record on the target. Before the first source of a triggered
service runs, apply writes a marker to `/var/lib/zap/pending/<service>` holding
the owed action. It removes the marker only after the service's own change
completes. If the reload fails, or the run dies anywhere in between, the marker
stays, and the next plan fires the action again:

```
  [~] nginx-service  (service)
      (pending reload from an earlier apply)
      > sudo systemctl daemon-reload
      > sudo systemctl try-reload-or-restart nginx
```

A pending restart outranks a reload fired this run. The markers are read live,
as root, on every plan for a config that declares a trigger, and a marker for a
service the config doesn't manage is reported as a warning. A marker directory
that can't be read fails the plan rather than reading as owing nothing. Zap
gives `/var/lib/zap` and `pending/` mode `755` and each marker `644`, whatever
the umask. The service's change clears its marker whether or not the service was
running: a stopped service owes nothing, since it starts on the new state.

Zap keeps its state in `/var/lib/zap`, and refuses the declarations that would
manage it. A structural error is any resource whose path is at or under it as
written (`.` and `..` taken as written), a home-rooted path with a `..`
component, a `link` whose target is `/var/lib/zap`, under it, or a directory
above it (`/`, `/var`, `/var/lib`, so no path below the link leads there), a
`link` placed at one of those directories above it (which it would replace),
and a `deploy.path` there. A path or link target that reaches it only once a
reference or `~` resolves holds the resource in detection and is refused by the
wetrun. What isn't a declared path isn't checked: the commands a `script`,
`pipeline`, `installer`, or `build` runs can write anywhere, and a symbolic
link already on the target that leads into `/var/lib/zap` is followed like any
other directory link.

The record is written first, so the guarantee is at-least-once. A run that fails
after the marker but before any source changed fires one reload or restart it
didn't strictly need. It never drops one it did.

A held service, whether detection can't read it or it is held behind another,
gets no marker, so each source whose change would trigger it is held too, with
the reason "would restart (or reload) the service, which is held". Running the
source alone would owe a restart nothing records. The next plan that can run the
service plans both.

## `database`

A **PostgreSQL** database and its owning role. Zap creates the role and database
idempotently, sets the database's owner back to the role when it has drifted, and manages the declared `pg_hba.conf` auth rules.
It never restarts PostgreSQL, so the target needs no `service_manager` for it.

```ts
zap.database({id: 'app-db', engine: 'postgresql', database_name: 'app', username: 'app'});
```

- `engine` (required): `'postgresql'`.
- `database_name` (required): the database to create.
- `username` (required): the role to create, which owns the database.
- `auth` (optional): the `pg_hba.conf` rules. See
  [Database auth](#database-auth).

Both names, and each `auth.hosts` entry, are written into a `pg_hba.conf` line
as they are, so none may hold whitespace, `#`, `"`, `,`, or a control character. A name doesn't begin
with `+`, `@`, `/`, or `-`, a database isn't named with a word `pg_hba.conf`
reads as a keyword in that column (`all`, `sameuser`, `samerole`, `samegroup`,
`replication`), and a role isn't named `all`. The rule holds for the value a
reference resolves to as well: one that breaks it holds the resource.

Both identifiers are taken literally and never shell-expanded. They accept
references, resolved on the operator's machine. A dev config that
wants "the role matching the OS user" on every machine declares
`username: zap.env('USER')`. A shell-style `username: '$USER'` would never resolve.

### Database auth

- `hosts` (required in `auth`): the client addresses a rule admits, each an IP
  address with its prefix length (`'127.0.0.1/32'`, `'::1/128'`), at least one.
  A keyword (`all`, `samehost`, `samenet`) or a host name is refused, as written
  and as a reference resolves. A `database` with no `auth` writes no rule.
- `method` (optional): the `pg_hba` auth method of those rules (default
  `'scram-sha-256'`). A rule Zap writes is a plain TCP `host` line with no
  options, so a method that can't work on one is refused: `'trust'`, since a
  trusted TCP rule lets any account on the machine, any service among them,
  connect as the role with no credential; `'peer'`, which PostgreSQL accepts
  only on a Unix-socket (`local`) line, the route a database with no `auth`
  already takes; `'cert'`, accepted only on a `hostssl` line; `'ldap'` and
  `'radius'`, which need options Zap doesn't write; and `'sspi'` and `'bsd'`,
  which PostgreSQL doesn't build on Linux.

With no `auth`, the role is reached the way the stock `pg_hba.conf` allows a
local account: over the Unix socket, by the OS account of the same name
(`local all all peer` on Debian, and on Alpine once `alpine_postgres_setup` has
initialized the cluster). A service running as that account
connects with `postgres://<role>@/<database>?host=/run/postgresql` and needs no
password.

Each rule is a `host` line in the `pg_hba.conf` the server reports. A missing
rule is inserted once, above the first `host`-type record (indented ones
included), or appended when the file has none, so it takes precedence over the
rules already there. Detection only asks whether each rule's line is present,
anywhere in the file: the rest of the file isn't judged. A rule already there
below a broader one that matches first (a `host all all 0.0.0.0/0 trust`, say)
reads present, though the earlier line decides those connections, and a
`trust` line, a duplicate, or any other rule of the file's own is neither
reported nor removed. Review a `pg_hba.conf` Zap didn't write. The rewrite runs as the `postgres` account, which must own
the file and be able to write its directory, as a stock install has it; a
`pg_hba.conf` owned by anyone else is left alone and the step fails saying so.
The file is replaced by rename, keeping its group and mode; if the rewritten
copy isn't the original plus that one line, Zap leaves the file alone and the
step fails. A rule Zap added is put in force by reloading the server's
configuration (`SELECT pg_reload_conf()`, as `postgres`); a rule already there
reloads nothing. Before the reload the step reads `pg_hba_file_rules`
(PostgreSQL 10 or later; on an older server the step fails), which parses the
file on disk, and fails without reloading if any line of it has an `error`. The
reload is only a signal, so after it the step waits, up to 30 seconds, for
`pg_conf_load_time()` to move, read from a new connection each second; once it
moves, every new connection, a dependent's included, sees the rule. A
`postgresql.conf` the server can't parse keeps that time from moving, so the
step fails then too, saying so. A reload the server doesn't confirm, a file it
can't parse, or a load time that doesn't move fails the step with the rule in
the file, and the next run's plan reads it present and reloads nothing: fix the
file the server can't parse, then reload by hand
(`sudo -u postgres psql -c 'SELECT pg_reload_conf()'`) once the server can. Zap
reads only that one file: a rule
inside an `include`d file isn't seen, and an `include` above the first `host`
line still orders ahead of Zap's rule.

## `swap`

A swap file, recorded in `/etc/fstab`.

```ts
zap.swap({id: 'swap', size: '2G'});
```

- `size` (required): the swap size, such as `'2G'`, used when the file is
  created. It is not compared afterwards: resizing means removing the file by
  hand first.
- `path` (optional): the swap file path (default `/swapfile`): absolute, with
  no whitespace, since it is a field of an `/etc/fstab` line. It is not
  `~`-expanded and takes no reference.

A swap file that drifted is repaired part by part: an active one isn't allocated,
formatted, or enabled again, and one already in `/etc/fstab` isn't listed again,
so an active swap file missing from `/etc/fstab` is only listed. One that isn't
active is allocated again before it is formatted, so a short file a full disk
left behind is made whole.

Before the file is allocated, formatted, and enabled, as root, its path is
checked: a symbolic link there is refused, since `mkswap` would format whatever
it points at, and so is any directory on the way to it, up to `/`, as declared
and as it resolves, that root doesn't own or that a group or other account can
write, where someone else could put a link at the path, or re-point a directory
above it, between the check and the format. The refusal names the path, the
directory, and the reason, and nothing is made.

Adding the entry rewrites `/etc/fstab` whole: the table as it reads plus the
entry, installed by rename with the table's mode kept and `root` as its owner.
A table the connecting user can't read fails the step with nothing written, and
so does one with a POSIX access list (ACL), whose mode can't be kept
([`file`](#file)); remove the list (`setfacl -b /etc/fstab`) to let Zap add the
entry. An
edit someone else
makes between the read and the rename is lost, and a symlinked `/etc/fstab` is
replaced by a regular file.

## `firewall`

Firewall configuration: default incoming and outgoing policies plus a list of
allow rules. There are two backends, **ufw** (Debian/Ubuntu) and **nftables**
(the native backend on Alpine).

Allow rules are **additive**. Zap asserts that each declared rule is present and
that the default policies match. A rule added out of band is neither detected
nor removed.

```ts
zap.firewall({
	id: 'fw',
	backend: 'ufw',
	allow: ['OpenSSH', {port: 443, proto: 'tcp'}],
});
```

- `backend` (required): `'ufw'` or `'nftables'`.
- `allow` (required): the allow rules. See [Allow rules](#allow-rules).
- `default_incoming` (optional): the default incoming policy, `'allow'`,
  `'deny'`, or `'reject'` (default `'deny'`).
- `default_outgoing` (optional): the default outgoing policy, same values
  (default `'allow'`).

### Allow rules

Each entry in `allow` is either a named ufw profile (a string, such as
`'OpenSSH'`, which takes no reference and can't begin with `-`) or a port and
protocol object:

- `port` (required): the port number, 1 to 65535.
- `proto` (optional): `'tcp'` (default), `'udp'`, or `'any'`.

### Backends

**`ufw`** applies `ufw default …` policies and a `ufw allow` per rule, then
`ufw --force enable`. Named application profiles (`'OpenSSH'`, `'Nginx Full'`)
and port rules both work.

**`nftables`** installs a single declarative `inet filter` ruleset at
`/etc/nftables.nft` (whole, mode `600`) and loads it with `nft -f`.

- The ruleset accepts established connections and loopback before the
  default-drop policy, so applying it never severs the live SSH session.
- It is scoped to its own table. It does not `flush ruleset`, so other tables
  such as fail2ban's are untouched.
- nftables has **no application profiles**. Use port rules only; a named profile
  is a config error.
- Boot persistence is the separate nftables service. Declare a `service`
  resource (`service: 'nftables'`, `enabled: true`) alongside the firewall,
  which loads the same `/etc/nftables.nft` at boot. This companion service is
  **required**: the structural gate rejects an nftables firewall with no enabled
  `service: 'nftables'` in the same config, because a firewall that silently
  vanishes on reboot is a security regression. The `alpine_web_firewall` recipe
  bundles both.

For both backends, a status probe that **fails** (exits nonzero), or an inactive
ufw, detects as `absent` (needs setting up) rather than holding; a probe that
times out, or whose batch fails, still holds. This is the fresh-host case, where the probe runs before
the same config installs ufw or nftables. See
[detection.md](./detection.md#kinds-that-read-a-failed-probe-as-absent).

## `verify`

Assertions checked at detection and again on a wetrun. A `verify` resource
executes nothing of its own. It checks that conditions hold and, if any
assertion fails, becomes a pending change; on a wetrun its assertions run again at its place in the dependency
order, and one still failing **fails the run there**: changes ordered before it
have already run, and the rest are skipped.
Use it as a guard rail, ordered with `depends_on` ("this token file must exist
before we proceed"). Like every resource, it is checked
again on every pass.

```ts
zap.verify({
	id: 'token-present',
	assertions: [{type: 'path_exists', path: '/home/deploy/.zap/api_token', file_type: 'file', not_empty: true}],
});
```

- `assertions` (required): the assertions to check. All must pass.

### Assertions

Each assertion is discriminated on `type`.

**`path_exists`**: assert a path exists, optionally with a required type, mode,
owner, or non-emptiness.

- `type` (required): `'path_exists'`.
- `path` (required): the absolute path to check, as written: it takes no
  reference, and a `~` or relative path is rejected.
- `file_type` (optional): the required type, `'file'` or `'directory'`.
- `mode` (optional): the required octal mode; `0644` and `644` are the same.
- `owner` (optional): the required owner, as a user name and not a numeric uid.
  A link at `path` is followed: the type, mode and owner are its target's.
- `not_empty` (optional): whether the path's size must be above zero
  (`test -s`, default false). A directory's size depends on its filesystem, so
  this doesn't reliably check that a directory has entries.

**`command`**: assert a command exits 0, optionally with a substring in its
stdout.

- `type` (required): `'command'`.
- `run` (required): the command to run.
- `expect` (optional): a substring that must appear in stdout.

## `pipeline`

An ordered, imperative workflow of steps run **sequentially** in declared order.
Reach for it when a procedure really is multi-step and doesn't map onto a single
declarative resource.

A pipeline has no state to converge to. So it runs on **every** wetrun, a dry
run of a config that declares one always has a pending change (exit 2), and
`zap status` always reads it absent.

```ts
zap.pipeline({
	id: 'migrate',
	steps: [
		{id: 'backup', run: 'pg_dump app > /tmp/app.sql'},
		{id: 'apply', run: './migrate.sh'},
	],
});
```

- `steps` (required): the pipeline steps. See [Steps](#steps).

### Steps

- `id` (required): an id for the step, unique within the pipeline. Two steps
  with one id are **rejected by the structural gate**.
- `run` (required): the command this step runs.
- `name` (optional): a display name for the step. A plan lists each step by its `id`, then its `name`, above the steps' `run` commands.

Steps run in declared order. Concurrent execution and dependencies between steps
aren't supported, so a pipeline-level `env`, a `max_concurrency` above 1, or a
step's `cwd`, `env`, or `depends_on` is **rejected by the structural gate** and
not silently ignored. Order steps by position, and inline any per-step environment or working
directory into the step's `run` (`cd … && FOO=bar cmd`).

## `build`

Builds a tool from a fetched source archive and installs it, for upstreams that
ship source and no prebuilt binary (zig, ghostty). The source is
**content-addressed and provenance-pinned**: Zap records which exact source
produced the installed artifact, so a moved upstream is detected as drift and
not silently accepted. It is unrelated to `deploy.build`, the local command
`zap deploy` runs before packaging ([deploy.md](./deploy.md#configuration)).

```ts
zap.build({
	id: 'ghostty',
	source: {
		type: 'remote',
		url: 'https://release.files.ghostty.org/1.3.1/ghostty-1.3.1.tar.gz',
		extract: {type: 'tar.gz', strip_components: 1},
		verify: {
			scheme: 'minisign',
			public_key: 'RWQlAjJC23149WL2sEpT/l0QKy7hMIFhYdQOFy0Z7z7PbneUgvlsnYcV',
		},
		// blake3: '…',  // vendored pin (see below); omit to track via zap.lock
	},
	run: 'zig build -p $HOME/.local -Doptimize=ReleaseFast',
	output: '$HOME/.local/bin/ghostty',
});
```

### Fields

- `source` (required): where the source comes from and how its integrity is
  verified. See [`source`](#source).
- `run` (required): the build command, run in the extracted source directory,
  such as `zig build -p $HOME/.local`. It runs as the connecting user,
  unprivileged, so an `output` under a root-owned directory needs the command's
  own `sudo`.
- `output` (required): a path that exists if and only if the build is installed.
  It is the detection probe.
- `cwd` (optional): the working directory for `run`, taken as written (no
  reference, no `~` expansion): an absolute path, or a path relative to the
  extracted source directory, which is the default.
- `env` (optional): extra environment for the whole of `run`, on a remote
  target as on a local one. Values resolve references and can hold any byte but U+FDD0, U+FDD1, and
  NUL, so `env` is how a build takes a secret. A name can't begin with `__zap_`.

The build toolchain itself (zig, GTK dev packages, and so on) is **not** this
resource's job. Declare it with sibling `package` or `installer` resources and
order with `depends_on`.

### `source`

The source is a remote archive:

- `type` (required): `'remote'`.
- `url` (required): the fetch location ([URLs](#urls)). It may carry a
  reference, resolved when Zap fetches; how the lock addresses it is in
  [lock.md](./lock.md#what-an-entry-holds).
- `extract` (optional): how the archive is unpacked. `{type: 'none'}` is the
  default; the other form is
  `{type: 'tar.xz' | 'tar.gz', strip_components?: N}`. `strip_components` lives
  inside the tar form (beside `none` it is rejected), and strips leading path
  components: `1` flattens a tarball's single top directory.
- `auth` (optional): a bearer credential for a private byte host, resolved at
  the IO boundary and never hashed.
- `verify` (optional): upstream-signature verification. See
  [Verification](#verification).
- `blake3` (optional): a vendored source pin. Present, the source pins itself;
  absent, it tracks through `zap.lock`, where `zap update <id>` advances it; a
  tracked source with no lock entry, or with an entry gone stale (the declaration
  changed since it was minted), holds the build (`undetermined`, exit 1) in the read-only commands. See
  [lock.md](./lock.md#two-kinds-of-fetched-content).

### Verification

When `source.verify` is set, the fetched archive is verified **before** it is
cached or pinned, so a tampered fetch can never become a build. The supported
scheme is minisign:

- `scheme` (required): `'minisign'`.
- `public_key` (required): the pinned minisign public key, the 56 base64
  characters beginning `RW` on the key line of a `.pub` file. Any other shape
  fails at config eval.
- `signature_url` (optional): an explicit signature URL, which may carry a
  reference. It defaults to the source URL with `.minisig` appended to its
  path, before any query or fragment. The source's `auth` goes
  with the signature request only when the signature URL has the source's
  origin (scheme, host, and port); a signature on another origin is fetched
  without it.

Verification shells out to the `minisign` binary: the one `ZAP_MINISIGN` names,
an absolute path, else the first in an absolute directory on `PATH`. Its exit
status is the verdict that lets the bytes be cached and pinned, so Zap refuses a
`minisign` inside a `node_modules` directory (an npm script's `PATH` leads with
`node_modules/.bin`, which any installed package can fill), and one where the
binary, or any directory from where it resolves up to `/` (and the same for the
directory it was found in and for each link on the way), is writable by a group
or others, or owned by an account other than root and you. Once those
directories are trusted, only root or you could swap the binary between the
check and the run. A refusal or a failed verification names the binary's path. Zap adds no crypto dependency of
its own and uses the upstream's trust mechanism.

A good signature says the key's holder signed these bytes, not that they are
the version the URL names: any archive the same key signed verifies, an older
release included. The pin is what fixes the version, and a tracked pin is
minted from whatever verified archive the URL served at that fetch, so read the
pin change in the lock diff as you would a version bump.

It runs once, at the fetch on a cache miss. A cache hit hashes the bytes against
the pin again. Bytes that hash to the pin are the pinned bytes, however they
reached the cache: a tracked pin is only ever minted from a verified fetch, and
a vendored pin is your own statement of exactly which bytes to trust.

### Detection

After a successful build Zap writes a provenance sidecar, `<output>.zap-build`:
a blake3 over the source pin and the build's `extract`, `run`, `cwd`, and `env`
as declared. Detection compares it with the desired provenance, so a moved
upstream or a changed build rebuilds
([detection.md](./detection.md#build-exact-provenance-not-a-version-string)).

## See also

- [concepts.md](./concepts.md): the model and the verdicts.
- [configs.md](./configs.md): writing a config; ordering, triggers, the gates.
- [detection.md](./detection.md): how each resource type's current state is
  read.
- [lock.md](./lock.md): pins, `zap.lock`, and the sentinel and sidecar files.
- [env.md](./env.md): references, the env file, secrets.
- [deploy.md](./deploy.md): the `zap deploy` release mechanism.
- [recipes.md](./recipes.md): the shipped config fragments.
