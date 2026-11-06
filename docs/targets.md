# Targets, SSH, and privilege

Where a config acts, how Zap gets there, and what the target needs. What your
own machine needs is in [install.md](./install.md#what-you-need-on-your-machine).

## The target

A config declares exactly one target with `zap.target({…})`: your own machine,
or a host over SSH.

```ts
// your own machine
zap.target({local: true, package_manager: 'apt', service_manager: 'systemd'});

// a host over SSH
zap.target({
	host: zap.env('DEPLOY_HOST'),
	user: zap.env('DEPLOY_USER'),
	home: '/home/deploy',
	package_manager: 'apt',
	service_manager: 'systemd',
});
```

| Field | Local | Remote | Meaning |
|---|---|---|---|
| `local` | `true` | omit or `false` | which kind of target |
| `host` | rejected | required | the SSH host; usually a reference. A name or an address alone: it can't begin with `-` or hold `@`, and an IPv6 address is written without brackets. A remote target without one doesn't validate |
| `user` | rejected | optional | the SSH user; `ssh`'s default when the target declares none. It can't begin with `-` or hold `:`, and a declared one that resolves to nothing is an error in every command that connects (`plan`, `detect`, `apply`, `deploy`) |
| `bootstrap_user` | rejected | optional | the alternate user `--bootstrap` connects as (below) |
| `port` | rejected | optional | SSH port, 1 to 65535. Unset (or 22), `ssh`'s own choice applies, your `~/.ssh/config` included |
| `key_path` | rejected | optional | an SSH private key, passed to `ssh -i` |
| `home` | rejected | optional | the remote home that `~` and `$HOME` in paths resolve against |
| `package_manager` | `apt`, `apk` | same | selects the `package` backend. `pacman` and `brew` parse but have no backend. |
| `service_manager` | `systemd`, `openrc` | same | required whenever the config has service intent (a `service`, a `file` with `triggers`, or `deploy.service`); `launchd` parses but has no backend |

A local target with any remote field is rejected at parse. A remote path that
uses `~` or `$HOME` with no `home` declared is `undetermined`: Zap never guesses
a remote home.

`host`, `user`, and `bootstrap_user` are **connection context**, not desired
state: they are left out of every resource's hash, so changing the connecting
user never reads as a config change. The plan does name them: `plan_hash` covers
the host and the connecting user the target resolves to, and on a local target
the user Zap runs as and its `HOME`. A target that declares
no `user` leaves the choice to `ssh`, and the plan prints
`user: (none — ssh chooses)` instead of a name.

## How Zap reaches a remote host

Your authority to act on a host is **SSH**. Zap shells out to the `ssh` and
`scp` on your machine with your keys and your `~/.ssh/config`, so anything that
works for `ssh user@host` works for Zap: agents, jump hosts, per-host keys. The
options Zap sets:

| Option | Why |
|---|---|
| `BatchMode=yes` | never prompt for a password; key authentication only |
| `StrictHostKeyChecking=accept-new` | a new host is trusted on first use; a changed key is refused, with a hint in the error |
| `ConnectTimeout=10` | an unreachable host fails fast |
| `ServerAliveInterval=30`, `ServerAliveCountMax=3` | a connection that goes silent is dropped, not waited on |
| `ForwardAgent=no`, `ForwardX11=no`, `ClearAllForwardings=yes` | no session, root's included, gets your agent, your display, or a port forward, whatever your config says |
| `RequestTTY=no`, `PermitLocalCommand=no` | no terminal on the host, and no `LocalCommand` run on your machine |
| `Tunnel=no` | no tunnel device forwarded, whatever your config says |
| `ControlMaster=auto`, `ControlPersist=300`, `ControlPath="<zap home>/ssh/…"` | one authenticated connection per run, shared by every command, and kept warm for five minutes, so a run in that window reuses it rather than authenticating again. Left off when the socket's path would be too long for one (a Zap home over 38 bytes) or the home holds a double quote, a backslash, or a control character; Zap says so once |

`ssh` keeps the first value it reads for an option, and the command line comes
before every config file, so these hold over your `~/.ssh/config`. A changed key
is refused only when the first one was recorded, so before it connects to a host
Zap reads your effective config once (`ssh -G`, with the same options) and
refuses, naming the setting, when every `UserKnownHostsFile` is `/dev/null`.

There is no agent on the host, no daemon, no server, and no shared secret. A pass
authenticates once: detection runs as one or two batched shell scripts, and the
login batch waits for the root batch's connection to be up rather than opening a
second one.

## The bootstrap user

A config that hardens SSH often changes the connecting user partway through
bring-up: the host's stock account creates a dedicated service user, then SSH
hardening locks the stock account out. Declare both:

```ts
zap.target({
	host: zap.env('DEPLOY_HOST'),
	user: zap.env('DEPLOY_USER'), // the hardened service user, steady state
	bootstrap_user: zap.env('BOOTSTRAP_USER'), // the stock account, first run only
});
```

Pass `--bootstrap` on the first run to connect as `bootstrap_user`, and omit it
afterward. It never engages on its own, so a connectivity failure can't silently
switch identity. The first bring-up is `zap apply --bootstrap`, then
`zap apply --bootstrap --wetrun`: it provisions and hardens as the stock
account, which the hardening then locks out, and every later command connects
as the service user. A `--bootstrap` run is its own plan, so preview it with
`zap apply --bootstrap`; a preview made as the service user doesn't bind it.

Keep both variables in one env file, set from the start and kept set: a host or
connecting user that resolves to nothing stops every command before it
connects, and an unset reference in the other user makes a dry run unverifiable
and stops a wetrun.

## What the target needs

| | Debian / Ubuntu | Alpine |
|---|---|---|
| shell and tools | `sh`, GNU coreutils (`timeout`), util-linux (`setsid`) | BusyBox, validated on 1.37 (Alpine 3.24): its `timeout` must take the duration without `-t`, and its `mv` must take `-T` |
| escalation | `sudo`, working without a password for the connecting user (or you connect as `root`) | `sudo` (not `doas`) |
| for `file` content checks and every file write | `sha512sum` and a mounted `/proc` | the same |
| for a file or directory write | `mktemp`, `stat`, `sync`, `mv -T`, `ls`, `id`, and a mounted `/proc` | the same, as BusyBox applets |
| for a `remote` archive or a `build` source | sshd's SFTP subsystem (what `scp` uses from OpenSSH 9.0; an older `scp` needs `scp` on the target), `mktemp -d` | the same |
| for an extracted archive or a deploy | `tar` with `--no-same-owner`, `--no-same-permissions`, and `--strip-components`; `id`; `rmdir` and `ls` for an extracted archive | the same |
| for a deploy | `flock` (util-linux), and `sort` to prune old releases | the BusyBox `flock` and `sort` applets |
| for a `user` | `useradd` and `usermod` | `useradd` and `usermod` from the `shadow` package (`apk add shadow`): BusyBox's `adduser` isn't used |
| for `user.sudo` | `visudo` | `visudo` (the `sudo` package ships it) |
| for `installer` | `curl` | `curl` |
| for `firewall` | `ufw` (the config may install it) | `nft` plus an `nftables` service |
| for `database` | PostgreSQL with a `postgres` system account | same |

Zap needs `sudo` on the target even when you connect as root: privileged
commands carry an explicit `sudo` so one plan runs under either user. A fresh
Debian cloud image usually has it; a minimal Alpine needs `apk add sudo` by
hand or through a bootstrap user that already has it.

## Two-tier privilege escalation

Which commands run as root is decided by what they are, not by who you are.

1. **Intrinsically privileged commands carry `sudo`.** `apt-get install`,
   `systemctl`, `rc-service`, `ufw`, `nft`, `useradd`, and the like are baked into
   the plan with an explicit `sudo` prefix. The plan reads the same for a root
   login and a sudoer.
2. **Filesystem operations run under `sudo` over SSH, and escalate per
   operation locally.** Over SSH the connecting user isn't assumed to own what
   Zap manages, so writing a file, making a directory, placing a fetched file,
   or creating a symlink goes through `sudo` directly. On a local target each is
   tried **natively** first and falls back to a `sudo` shell op only when
   denied, so a config that touches only your own files never invokes `sudo`.
   A file's mode and owner are part of its write, and a directory's are set the
   same way: natively, else by one elevated command that refuses a symlink at
   the path. A `file` keeps the owner and group it leaves unset, so locally a
   file another account owns, or a new one in a directory another account owns,
   is written under `sudo`; so are directories made under another account's,
   which take its owner. Anywhere below a directory with its sticky bit set or
   that every account may write, such as `/tmp`, nothing is kept or taken and
   your own write stands. Local reads and existence checks follow the same rule: a root-owned
   file is read under `sudo` rather than misread as absent.

A `user`'s `authorized_keys` is written as that user (`sudo -u <user>`), a
`copy_from` source is read as the source user, and a `database`'s SQL runs as
`postgres` (`sudo -u postgres`), so the connecting user's sudo rule has to
allow running as them. `root` and an unrestricted sudoer do. What ran as root is in the host's `sudo`
I/O log ([security.md](./security.md#authority-on-the-host)).

The exception is a `build`: its source is extracted into a private temporary
directory and the build command runs **unprivileged**, as the connecting user. A
root-owned scratch dir would be unrepairable, and a build shouldn't need root.

### Local `sudo`

On a local target, before a root batch runs, Zap checks that `sudo` will work
without a prompt (`sudo -n`). If it won't, Zap runs `sudo -v` on your terminal,
with no deadline, so you can enter a password before anything is timed. The
batch itself then runs under `sudo -n`. If `sudo` won't authenticate, every
resource that needed root is held with the reason `sudo authentication failed`.

An operator command (a `script`'s `check`, a `verify` assertion) runs without a
terminal, locally as over SSH. A `sudo` inside it that needs a password fails at
once and the check reads as failed. Give such a command a `NOPASSWD` rule, or
keep `sudo` out of checks.

## Detection privilege

Every detection read runs under a declared privilege: **login** (the
connecting user, unprivileged), **root** (root on every connection), or
**elevated** (root over SSH; locally, you first and `sudo` for a read that
failed). Which reads run in which lane, and how batches are framed, killed, and
timed out: [detection.md](./detection.md#privilege).
