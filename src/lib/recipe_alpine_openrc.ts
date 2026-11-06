/**
 * Recipe for a hardened OpenRC service — the Alpine
 * sibling of `recipe_debian_systemd.ts`'s `hardened_systemd_unit`.
 *
 * `hardened_openrc_service` builds the `/etc/init.d/<name>` script for a
 * long-running network service (a compiled Rust daemon, a Deno process, a fuz_app
 * server), driven by
 * `supervise-daemon` so OpenRC restarts it on failure.
 *
 * ## Hardening tiers
 *
 * OpenRC's ceiling is below systemd's: it replicates the **privilege** axis
 * natively but not the **filesystem-isolation** axis.
 *
 * - **Tier A (default, OpenRC-native):** `command_user` (drop to the service
 *   account), `capabilities` (the ambient set the option names, and every other
 *   capability dropped from the bounding set), `no_new_privs`, `umask` (`0077` unless
 *   loosened), `rc_ulimit`, and `supervise-daemon` respawn — the privilege axis. No extra packages. Tier A
 *   also self-provisions the service-owned log directory in a `start_pre()`
 *   `checkpath` hook (which runs as root, before the privilege drop), so the
 *   non-root service can write its `output_log` with no external directory resource.
 * - **Tier B (opt-in via `isolation`):** filesystem isolation (`ProtectSystem=strict`
 *   / `PrivateTmp` / `ReadWritePaths`) has no OpenRC-native equivalent, so the command
 *   is wrapped in `bubblewrap`: a read-only root, a private `/tmp`, and the declared
 *   `read_write_paths` bound read-write. It layers over Tier A (the sandboxed process
 *   still drops to `command_user`, holds no capabilities (bwrap empties the bounding
 *   set, so an ambient set `capabilities` raises doesn't reach the command), and sets
 *   `no_new_privs`). Under `supervise-daemon` the wrap must be launched via
 *   `sh -c 'exec bwrap … -- cmd'`
 *   (passing bwrap as `command=`/`command_args=` mangles its `--` separator), and
 *   `--die-with-parent` tears the sandbox down cleanly on stop. Needs `bubblewrap` on
 *   the target and a kernel allowing unprivileged user namespaces (Alpine's default).
 *   The syscall-filter residual (`SystemCallFilter`) has no OpenRC analogue and is
 *   documented and accepted.
 *
 * ## Quoting
 *
 * `openrc-run` sources the init script as a shell script, so every value is
 * written as one single-quoted word (`single_quote`): the sourcing reads it
 * literally, whatever it holds. OpenRC's `supervise-daemon` start then rebuilds
 * its command line from these variables and `eval`s it (that is how
 * `command_args` carries quoted words), so a value it splices in — `command`,
 * `user`, `group`, `working_directory`, `capabilities`, `log_file`,
 * `respawn_delay`, and under Tier B `bwrap_path` — is read by a shell a second
 * time. Those must be one word of `[A-Za-z0-9_./:@%+,=^!-]` and are refused at
 * eval otherwise (`!` is there for a capability dropped from the bounding set,
 * `^cap_net_bind_service,!cap_sys_admin`), and `command` must be absolute, so it
 * can't read as a `supervise-daemon` option. `command_args` is shell words by
 * design: OpenRC's `eval` splits it and reads its quotes, as a shell would a command
 * line, so quote a value inside it yourself. OpenRC also expands it unquoted before
 * that `eval`, so a run of blanks collapses to one, even inside quotes, and a word
 * holding `*`, `?` or `[` globs against the working directory.
 *
 * ## Environment injection
 *
 * OpenRC has no `EnvironmentFile=` parser, and the init script runs as root, so the
 * script never sources `env_file`: root reading it as shell would run whatever the
 * file says, and exporting its names into root's shell would hand them to root's own
 * commands (`PATH`, `LD_PRELOAD`, OpenRC's `command`). The file is read as data, by
 * one reader the script carries (`_zap_env_read`, built from `case` and parameter
 * expansion: nothing in the file is run or expanded), twice:
 *
 * - `start_pre()` runs it as the service user (`su -s /bin/sh … <user>`), under
 *   `timeout` (`ENV_CHECK_TIMEOUT_SECS`), checking every line and assigning nothing,
 *   so a line it can't read refuses the start, naming the line number, and so does a
 *   file the service user can't read (a root-owned `600` file), naming the user, or
 *   one it doesn't finish reading in time (a FIFO, a huge file). Root runs the check
 *   and never parses the file's bytes. The check's output lands in a file in a
 *   directory `mktemp -d` made for root under `/run`, so the service user can't fill
 *   the directory's filesystem beforehand to stop the start (as it could `/tmp`), and
 *   nothing it leaves running can hold the start open the way it could hold a pipe.
 *   Root bounds only what it reads (`head -c`), not what a lingering writer, still
 *   holding the file, can grow it to;
 * - the daemon's own process, after `supervise-daemon` dropped it to
 *   `command_user`, reads the file again and exports each assignment before it
 *   `exec`s the command, which runs under `/bin/sh -c` as Tier B's wrap does
 *   (`command` and `command_args` follow the wrap's script as its arguments). So
 *   the file must be readable by the service user, as a deploy's
 *   `shared/.env.production` owned by it is.
 *
 * The check needs `su` and `timeout` on the target (`BusyBox` gives both on Alpine);
 * root's `su -s` runs the shell for an account whose login shell is `nologin`.
 *
 * The format is a subset of what systemd's `EnvironmentFile=` reads, chosen so a file
 * the subset accepts gives the daemon the same environment under both:
 *
 * - a blank line, or one whose first non-blank character is `#` or `;`, is skipped;
 * - every other line is `NAME=VALUE`, `NAME` matching `[A-Za-z_][A-Za-z0-9_]*`
 *   with nothing before it, and not beginning `_zap_` (the reader's own names);
 * - a value starting with `'` is single-quoted: it ends the line with its closing
 *   `'`, holds no other `'`, and every byte between is literal (`\` and `$`
 *   included), as systemd reads it;
 * - any other value is literal as written (`$`, a later quote, a `#`, interior
 *   blanks), as systemd reads an unquoted value without a backslash; it may not
 *   start or end with a blank, start with `"`, or hold a `\`, which systemd
 *   strips or reads as quoting and escapes;
 * - an empty value (`NAME=`) sets the empty string; a later line for a name wins.
 *
 * Every other line is refused, where systemd differs: it skips a line without `=`
 * or with an invalid name, strips blanks around the name and the value, reads
 * double-quoted values and backslash escapes, continues a line ending in `\`, and
 * lets a quoted value span lines. A carriage return anywhere refuses the line (a
 * CRLF file). A file a `fuz_app_env_base` / `fuz_app_trusted_proxies` template
 * renders is in the subset.
 *
 * Recipes are imported at config eval time inside zap's sandboxed config eval
 * (`fgro eval`), which has no network, no writes, and no environment, and where the
 * clock and randomness throw.
 * This module is therefore a **pure function**: it only assembles a string from
 * its arguments. The output is deterministic for given inputs (stable ordering,
 * trailing newline), so it stays a reliable content-addressed plan artifact.
 *
 * The caller wraps the result in a file resource at `/etc/init.d/<name>` with
 * mode `755`, e.g.
 * `zap.file({id: 'myapp-init', path: '/etc/init.d/myapp', mode: '755', content: {type: 'inline', content: hardened_openrc_service({...})}})`.
 *
 * @module
 */

import { single_quote } from './shell.ts';

/** One word OpenRC's start line can `eval` as itself: no blank, quote, or shell syntax. */
const OPENRC_WORD = /^[A-Za-z0-9_./:@%+,=^!-]+$/;

/** Refuse `value` for `field` unless it is an `OPENRC_WORD`. */
const openrc_word = (field: string, value: string): void => {
	if (!OPENRC_WORD.test(value)) {
		throw new Error(
			`hardened_openrc_service: ${field} ${JSON.stringify(
				value
			)} must be one word of [A-Za-z0-9_./:@%+,=^!-], because OpenRC's supervise-daemon start evals it as shell.`
		);
	}
};

/**
 * The roots a service's log directory may sit under: each holds one directory per
 * service, so the directory directly under one is the service's own when its name says
 * so. Everything else (`/etc`, `/usr`, `/root`, `/home`, `/boot`, `/bin`, `/sbin`,
 * `/lib`, `/tmp`, …) is refused.
 */
const LOG_ROOTS = ['/var/log', '/var/lib', '/srv', '/opt', '/run'];

/** Whether `component` is one of `owners`, alone or followed by `_`, `-` or `.`. */
const names_owner = (component: string, owners: Array<string>): boolean =>
	owners.some(
		(owner) =>
			owner !== '' &&
			(component === owner ||
				(component.startsWith(owner) && '_-.'.includes(component.charAt(owner.length))))
	);

/**
 * Whether `log_file` sits in a directory of the service's own: absolute, with no empty,
 * `.` or `..` component (so no trailing `/`), and its parent `log_dir` at or under a
 * directory that sits directly under one of `LOG_ROOTS` and is named for one of `owners`
 * (the service's name and its user), alone or followed by `_`, `-` or `.`
 * (`/var/log/<name>`, `/srv/<user>/logs`). The prefix form stays allowed
 * (`/var/log/<name>_api`, `/var/log/<name>-worker`): the operator names both the service
 * and its log directory, so a prefix names the service's own family, not another
 * account's directory.
 */
const log_dir_is_own = (log_file: string, log_dir: string, owners: Array<string>): boolean => {
	if (!log_file.startsWith('/')) return false;
	if (
		log_file
			.split('/')
			.slice(1)
			.some((p) => p === '' || p === '.' || p === '..')
	)
		return false;
	return LOG_ROOTS.some((root) => {
		if (!log_dir.startsWith(`${root}/`)) return false;
		const owned = log_dir.slice(root.length + 1).split('/', 1)[0] ?? '';
		return names_owner(owned, owners);
	});
};

/** `path` with its `.`, `..` and empty components resolved, for a containment check. */
const normalize_path = (path: string): string => {
	const out: Array<string> = [];
	for (const part of path.split('/')) {
		if (part === '' || part === '.') continue;
		if (part === '..') out.pop();
		else out.push(part);
	}
	return `/${out.join('/')}`;
};

/**
 * How long, in seconds, `start_pre` waits for the service user's check of `env_file`.
 * A real env file is a few kilobytes, which the reader takes milliseconds over even on a
 * slow host; the bound is for a file that never ends (a FIFO, a device) or a huge one,
 * which the service user controls and root's start must not wait on.
 */
const ENV_CHECK_TIMEOUT_SECS = 10;

/**
 * The most bytes of the service user's env-file check `start_pre` reads back for its
 * error: the check prints one line, and a longer output is the service user's own.
 */
const ENV_CHECK_OUTPUT_BYTES = 4096;

/**
 * Every capability libcap names, in number order (an index is the capability's
 * number), through `cap_checkpoint_restore`: what `hardened_openrc_service` drops from
 * the bounding set by name unless its `capabilities` names one.
 */
const CAPABILITY_NAMES = [
	'chown',
	'dac_override',
	'dac_read_search',
	'fowner',
	'fsetid',
	'kill',
	'setgid',
	'setuid',
	'setpcap',
	'linux_immutable',
	'net_bind_service',
	'net_broadcast',
	'net_admin',
	'net_raw',
	'ipc_lock',
	'ipc_owner',
	'sys_module',
	'sys_rawio',
	'sys_chroot',
	'sys_ptrace',
	'sys_pacct',
	'sys_admin',
	'sys_boot',
	'sys_nice',
	'sys_resource',
	'sys_time',
	'sys_tty_config',
	'mknod',
	'lease',
	'audit_write',
	'audit_control',
	'setfcap',
	'mac_override',
	'mac_admin',
	'syslog',
	'wake_alarm',
	'block_suspend',
	'audit_read',
	'perfmon',
	'bpf',
	'checkpoint_restore'
].map((name) => `cap_${name}`);

/**
 * `capabilities` with every capability it doesn't name, or names only to drop, dropped
 * from the bounding set: its own entries (less a bare `^`, which names nothing), then
 * `!cap_…` for each other one of `CAPABILITY_NAMES`, then `!<n>` for each number past
 * them up to 63, so a capability a newer kernel adds is dropped too (libcap ignores a
 * number above the kernel's last one).
 */
const with_bounding_drops = (capabilities: string): string => {
	const entries = capabilities.split(',').filter((entry) => entry.replace(/^[\^%!]+/, '') !== '');
	const named = new Set(entries.map((entry) => entry.replace(/^[\^%!]+/, '').toLowerCase()));
	const drops = [
		...CAPABILITY_NAMES.filter((name) => !named.has(name)).map((name) => `!${name}`),
		...Array.from(
			{ length: 64 - CAPABILITY_NAMES.length },
			(_, i) => `!${CAPABILITY_NAMES.length + i}`
		)
	];
	return [...entries, ...drops].join(',');
};

/** The letters a name may hold, spelled out so no locale widens a bracket range. */
const ENV_ALPHA = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';

/**
 * The shell text of `env_file`'s reader: `_zap_env_read <setter>` reads the file as
 * data (`case` and parameter expansion only: no `eval`, no `.`, no expansion of what
 * a line holds), and calls `<setter> NAME=VALUE` for each assignment, `:` to check
 * and `export` to load; on a line outside the format it sets `_zap_env_why`, naming
 * the line number, and returns 1. `_zap_env_exec <command…>` loads and `exec`s the
 * command, and exits 1 with that message on stderr when the file can't be read.
 * The format is the module doc's.
 */
const env_reader = (env_file: string): string => {
	const bad = (reason: string): string =>
		`_zap_env_why="$_zap_f: line $_zap_n: ${reason}"; return 1`;
	return `_zap_env_read() {
	_zap_f=${single_quote(env_file)}
	_zap_n=0
	_zap_cr=$(printf '\\r')
	if [ ! -f "$_zap_f" ] || [ ! -r "$_zap_f" ]; then
		_zap_env_why="$_zap_f is missing or unreadable"
		return 1
	fi
	while IFS= read -r _zap_l || [ -n "$_zap_l" ]; do
		_zap_n=$((_zap_n + 1))
		_zap_t=\${_zap_l#"\${_zap_l%%[!\t ]*}"}
		case $_zap_t in
		'' | '#'* | ';'*) continue ;;
		esac
		case $_zap_l in
		*"$_zap_cr"*) ${bad('it holds a carriage return')} ;;
		*=*) ;;
		*) ${bad('it is not NAME=VALUE')} ;;
		esac
		_zap_k=\${_zap_l%%=*}
		_zap_v=\${_zap_l#*=}
		case $_zap_k in
		'' | [!${ENV_ALPHA}_]* | *[!${ENV_ALPHA}0123456789_]* | _zap_*)
			${bad('the name is not [A-Za-z_][A-Za-z0-9_]*, or begins _zap_')} ;;
		esac
		case $_zap_v in
		\\'*)
			_zap_v=\${_zap_v#?}
			case $_zap_v in
			*\\') _zap_v=\${_zap_v%?} ;;
			*) ${bad('a single-quoted value must end the line with its closing quote')} ;;
			esac
			case $_zap_v in
			*\\'*) ${bad('a single-quoted value holds no other quote')} ;;
			esac
			;;
		\\"*) ${bad('a double-quoted value is not read; single-quote it')} ;;
		*\\\\*) ${bad('an unquoted value holds no backslash; single-quote it')} ;;
		[\\ \\\t]* | *[\\ \\\t]) ${bad('an unquoted value neither starts nor ends with a blank')} ;;
		esac
		"$1" "$_zap_k=$_zap_v"
	done < "$_zap_f"
}
_zap_env_exec() {
	_zap_env_read export || { printf '%s\\n' "$_zap_env_why" >&2; exit 1; }
	unset _zap_env_load
	exec "$@"
}`;
};

/**
 * Options for `hardened_openrc_service`.
 *
 * The required fields are the per-service variations (`name`, `description`,
 * `command`, `user`); everything else defaults to the shared hardened baseline.
 * `description` / `command` / `user` / `env_file` are the subset shared in spirit
 * with `HardenedSystemdUnitOptions`, so a deploy can present one options shape and
 * pick the artifact by import.
 */
export interface HardenedOpenrcServiceOptions {
	/** The init-script name (`/etc/init.d/<name>`); also the default log basename. */
	name: string;
	/** Human-readable `description=` (e.g. the domain). */
	description: string;
	/** Absolute path to the executable (`command=`). */
	command: string;
	/**
	 * Arguments string passed as `command_args=`: shell words, which OpenRC splits and
	 * whose quotes it reads (see the module doc). Omitted when unset.
	 */
	command_args?: string;
	/** The service account (`command_user=<user>`), by name: a numeric uid and `root` are refused. Also the default for `group`. */
	user: string;
	/** The service group (`command_user=<user>:<group>`), by name, not `root`. Defaults to `user`. */
	group?: string;
	/** `directory=` — the process working directory (typically the `current` release symlink). Omitted when unset. */
	working_directory?: string;
	/**
	 * Read as data into the daemon's environment — OpenRC's stand-in for systemd
	 * `EnvironmentFile=`. `start_pre()` has the service user check it, and the
	 * daemon's process, as `command_user`, exports it before it `exec`s the command,
	 * so it must be readable by the service user. It must be an absolute path outside the
	 * log directory (which is chowned to the service user), or it is refused at eval.
	 * Omitted means no environment file. The format, and where it differs from systemd's,
	 * is in the module doc.
	 */
	env_file?: string;
	/**
	 * The `capabilities=` value, in libcap's IAB text, which `supervise-daemon` applies:
	 * `^cap_x` raises `cap_x` as an ambient capability, `!cap_x` drops it from the
	 * bounding set. Defaults to `'^'`, no ambient capability (a daemon listening on a
	 * high port behind nginx needs none); pass `'^cap_net_bind_service'` for one that
	 * binds below 1024. Whatever it names, the recipe appends `!cap_…` for every other
	 * capability (`CAPABILITY_NAMES` by name, then every higher number up to 63, so one
	 * a newer kernel adds is dropped too; the names need a libcap that knows
	 * `cap_checkpoint_restore`), so the bounding set holds only the capabilities the value
	 * names without `!`: a `'^'` alone leaves it empty. libcap's IAB text has no word
	 * for "all", so each is named. Under `isolation` the command holds none.
	 */
	capabilities?: string;
	/**
	 * `umask=`, which `supervise-daemon` sets for the daemon (`--umask`): four octal
	 * digits. Defaults to `'0077'`, as the systemd unit does, so what the service creates
	 * is its own; pass `'0022'` (or `'0027'` for a group) when another account reads what
	 * it writes, such as nginx serving a store through `X-Accel-Redirect`.
	 */
	umask?: string;
	/** `rc_ulimit="-n <n>"` open-file cap. Omitted when unset. */
	ulimit_nofile?: number;
	/** `respawn_delay` seconds between `supervise-daemon` restarts. Defaults to `5`. */
	respawn_delay?: number;
	/** `depend()` `need` entries. Defaults to `['net']`. */
	needs?: Array<string>;
	/** `depend()` `use` entries (soft deps). Defaults to none; add `'postgresql'` for an app on a local database. */
	uses?: Array<string>;
	/**
	 * Combined stdout+stderr log path (`output_log`/`error_log`). Defaults to
	 * `/var/log/<name>/<name>.log`. **`supervise-daemon` opens this as `command_user`**
	 * (after the privilege drop), so for a non-root service the path's _directory_ must be
	 * writable by that user. The recipe handles this: it creates and chowns `log_file`'s
	 * parent directory to the service user in a `start_pre()` `checkpath` hook (which runs
	 * as root, before the privilege drop), so the default works for a non-root service out
	 * of the box with no external directory resource. Because the parent is chowned to the
	 * service user, it must be the service's own: at or under a directory that sits
	 * directly under `/var/log`, `/var/lib`, `/srv`, `/opt` or `/run` and is named `name` or
	 * `user`, alone or followed by one of `_`, `-`, `.` (`/var/log/<name>/server.log`,
	 * `/srv/<user>/logs/server.log`), and `env_file` must not sit inside it, nor may `command` or, under `isolation`, the `bwrap` binary, which the
	 * service user could otherwise replace. Any other path is refused at eval.
	 *
	 * At start, the hook also refuses (`eerror`, `start_pre` fails) a log directory that
	 * already exists unless it is a directory, not a symlink, owned by the service user:
	 * an absent one is created, and anything else (root's, another daemon's — a name
	 * `nginx` meeting `/var/log/nginx`) is someone else's, which the hook never re-owns.
	 * A root-owned directory is refused too, since the hook didn't make it; chown it to
	 * the service user, or remove it, to adopt it. The residual: only the log directory
	 * itself is checked, and `checkpath` follows a symlink in the path's intermediate
	 * components, creating through it and chowning where it points; a symlink as the
	 * last component it refuses, failing the start. So below an owner-named directory
	 * the service user already owns, a symlink it plants at an intermediate component
	 * (`/srv/<user>/a/logs`, replacing `a`) could redirect the root-run create and chown,
	 * while one swapped in for the log directory itself between the check and
	 * `checkpath` is refused. Where that matters, make the log directory the owner-named
	 * directory itself (`/var/log/<user>`).
	 */
	log_file?: string;
	/**
	 * Tier-B filesystem isolation via `bubblewrap`. When set, the service command runs
	 * inside a `bwrap` sandbox — a read-only root, a private `/tmp` (tmpfs), and the
	 * declared `read_write_paths` bound read-write — the OpenRC stand-in for systemd's
	 * `ProtectSystem=strict` + `PrivateTmp` + `ReadWritePaths`. It layers over the Tier-A
	 * privilege hardening (the sandboxed process still drops to `command_user`, holds no
	 * capabilities, whatever `capabilities` names (bwrap empties the bounding set), and
	 * sets `no_new_privs`).
	 * Requires `bubblewrap` on the target (declare it as a `zap.pkg`) and a kernel
	 * permitting unprivileged user namespaces (Alpine's default). Omit for Tier-A only.
	 */
	isolation?: HardenedOpenrcIsolation;
}

/** Tier-B `bubblewrap` filesystem-isolation options for `hardened_openrc_service`. */
export interface HardenedOpenrcIsolation {
	/**
	 * Absolute paths bind-mounted **read-write** inside the otherwise read-only root —
	 * everything the service writes at runtime (its app/data directory, a database socket
	 * directory, …). The `working_directory` should fall under one of these. `/tmp` is
	 * always a private tmpfs and need not be listed.
	 *
	 * Each entry must be an absolute path of `[A-Za-z0-9_./-]` only — no whitespace or
	 * shell metacharacters — validated at eval. They're embedded unquoted into the `bwrap`
	 * command line, so an unsafe path would word-split and silently break the sandbox.
	 */
	read_write_paths: Array<string>;
	/** The `bwrap` binary path. Defaults to `/usr/bin/bwrap`. */
	bwrap_path?: string;
}

/**
 * Build the hardened OpenRC init-script text for `options`.
 *
 * Produces an `openrc-run` script supervised by `supervise-daemon`, with the
 * Tier-A privilege hardening (drop to `command_user`, the capability bounding set
 * kept to what `capabilities` names, `no_new_privs`, `umask`, `rc_ulimit`, the
 * service user's check of `env_file`, and the log-directory guard) and
 * respawn-on-failure. Given a
 * service's inputs it reproduces that service's init script deterministically.
 *
 * @returns the complete init-script text, terminated by a trailing newline.
 */
export function hardened_openrc_service(options: HardenedOpenrcServiceOptions): string {
	const {
		name,
		description,
		command,
		command_args,
		user,
		group = user,
		working_directory,
		env_file,
		capabilities = '^',
		umask = '0077',
		ulimit_nofile,
		respawn_delay = 5,
		needs = ['net'],
		uses = [],
		log_file = `/var/log/${name}/${name}.log`,
		isolation
	} = options;

	// The log directory is `log_file`'s parent. `supervise-daemon` opens the log as
	// `command_user` (after the privilege drop), so a `start_pre()` `checkpath` hook
	// (which runs as root, before the drop) creates and chowns it to the service user.
	const log_dir = log_file.slice(0, log_file.lastIndexOf('/'));
	// The root-run `checkpath` chowns `log_dir` to the service user, so it must be the
	// service's own directory, never a shared one.
	if (!log_dir_is_own(log_file, log_dir, [name, user])) {
		throw new Error(
			`hardened_openrc_service: log_file ${JSON.stringify(log_file)} must be an absolute file path in a directory of the service's own: its parent is chowned to the service user, so it must sit at or under a directory directly under /var/log, /var/lib, /srv, /opt or /run that is named for the service's name or user, alone or followed by one of \`_\`, \`-\`, \`.\``
		);
	}
	const in_log_dir = (path: string): boolean => {
		const normalized = normalize_path(path);
		return normalized === log_dir || normalized.startsWith(`${log_dir}/`);
	};
	// `env_file` is read by `start_pre`'s check and by the daemon, from different
	// working directories, so it must be absolute to name one file for both; and it
	// stays out of the directory chowned to the service user, so a root-owned file
	// placed there to keep the daemon from rewriting it does.
	if (env_file !== undefined) {
		if (!env_file.startsWith('/')) {
			throw new Error(
				`hardened_openrc_service: env_file ${JSON.stringify(env_file)} must be an absolute path (begin with \`/\`), because root's start hook and the daemon read it from different working directories`
			);
		}
		if (in_log_dir(env_file)) {
			throw new Error(
				`hardened_openrc_service: env_file ${JSON.stringify(env_file)} must not sit inside the log directory ${JSON.stringify(log_dir)}, which is chowned to the service user`
			);
		}
	}
	// Command + args. Tier A runs the binary directly. Tier B wraps it in a `bwrap`
	// sandbox (read-only root, private `/tmp`, the declared rw binds), launched via
	// `sh -c 'exec bwrap … -- cmd'` — passing bwrap as `command=`/`command_args=` mangles
	// its `--` separator under `supervise-daemon`; `--die-with-parent` tears the sandbox
	// down cleanly on stop. The Tier-A privilege directives below apply to the sandboxed
	// process unchanged.
	// OpenRC's start line `eval`s these, so each must be one plain word, and `command`
	// an absolute path, which no option looks like.
	openrc_word('command', command);
	if (!command.startsWith('/')) {
		throw new Error(
			`hardened_openrc_service: command ${JSON.stringify(command)} must be an absolute path (begin with \`/\`)`
		);
	}
	// The start hook compares the log directory's owner by name (`stat -c %U`), so a
	// numeric user would read as someone else's directory on every start after the first;
	// and a name is what lets `root` be refused, which `0` would stand in for.
	for (const [field, account] of [
		['user', user],
		['group', group]
	] as const) {
		if (!/^[a-z_][a-z0-9_-]*$/i.test(account)) {
			throw new Error(
				`hardened_openrc_service: ${field} ${JSON.stringify(account)} must be an account name, not a numeric id: a letter or \`_\`, then letters, digits, \`_\` or \`-\``
			);
		}
		if (account === 'root') {
			throw new Error(
				`hardened_openrc_service: ${field} "root" is root, and the script's hardening is for an unprivileged account`
			);
		}
	}
	if (!/^[0-7]{4}$/.test(umask)) {
		throw new Error(
			`hardened_openrc_service: umask ${JSON.stringify(umask)} must be four octal digits, such as '0077'`
		);
	}
	openrc_word('user', user);
	openrc_word('group', group);
	if (working_directory !== undefined) openrc_word('working_directory', working_directory);
	openrc_word('capabilities', capabilities);
	openrc_word('log_file', log_file);
	openrc_word('respawn_delay', String(respawn_delay));

	// An executable inside the service-owned log directory could be replaced by the
	// service user, so the next start runs its bytes.
	const executables: Array<[string, string]> = [['command', command]];
	if (isolation !== undefined) {
		executables.push(['isolation.bwrap_path', isolation.bwrap_path ?? '/usr/bin/bwrap']);
	}
	for (const [field, path] of executables) {
		if (in_log_dir(path)) {
			throw new Error(
				`hardened_openrc_service: ${field} ${JSON.stringify(path)} must not sit inside the log directory ${JSON.stringify(log_dir)}, which is chowned to the service user, who could replace it`
			);
		}
	}

	// With an env file, the daemon's process loads it before it `exec`s the command:
	// `sh -c` defines the reader from `_zap_env_load` (exported by `start_pre`) and
	// `_zap_env_exec` reads, exports, and `exec`s its arguments. OpenRC expands
	// `command_args` unquoted before its `eval`, so the reader rides in the
	// environment, not on the command line, where its `case` patterns would glob.
	const env_exec = 'eval "$_zap_env_load" && _zap_env_exec';
	let command_line: string;
	let command_args_line: string;
	if (isolation === undefined) {
		if (env_file === undefined) {
			command_line = `command=${single_quote(command)}\n`;
			command_args_line =
				command_args === undefined ? '' : `command_args=${single_quote(command_args)}\n`;
		} else {
			// `command` is one plain word (checked above), so it rides bare as `$1`.
			const args = command_args === undefined ? '' : ` ${command_args}`;
			command_line = `command='/bin/sh'\n`;
			command_args_line = `command_args=${single_quote(
				`-c ${single_quote(`${env_exec} "$@"`)} zap-env ${command}${args}`
			)}\n`;
		}
	} else {
		const bwrap_path = isolation.bwrap_path ?? '/usr/bin/bwrap';
		openrc_word('isolation.bwrap_path', bwrap_path);
		// Each rw bind is embedded unquoted into the `bwrap` command line (which is itself
		// nested inside `command_args="-c '…'"`), so a path with whitespace or a shell
		// metacharacter would word-split at the final `sh -c` and silently produce a broken
		// sandbox. Fail fast at config eval with a strict absolute-path allowlist instead.
		for (const path of isolation.read_write_paths) {
			if (!/^\/[A-Za-z0-9_./-]+$/.test(path)) {
				throw new Error(
					`hardened_openrc_service: read_write_paths entry ${JSON.stringify(
						path
					)} must be an absolute path containing only [A-Za-z0-9_./-] (no whitespace or shell metacharacters), because Tier-B bind paths are embedded unquoted into the bwrap command line.`
				);
			}
		}
		const rw_binds = isolation.read_write_paths.map((path) => `--bind ${path} ${path}`).join(' ');
		const chdir_flag = working_directory === undefined ? '' : ` --chdir ${working_directory}`;
		const inner_args = command_args === undefined ? '' : ` ${command_args}`;
		const bwrap = `${bwrap_path} --ro-bind / / --dev /dev --proc /proc --tmpfs /tmp ${
			rw_binds
		}${chdir_flag} --die-with-parent -- ${command}${inner_args}`;
		const wrap = env_file === undefined ? `exec ${bwrap}` : `${env_exec} ${bwrap}`;
		// Quoted twice: once for OpenRC's `eval`, which hands `sh` the whole wrap as one
		// word, and once for the sourcing of the assignment.
		command_line = `command='/bin/sh'\n`;
		command_args_line = `command_args=${single_quote(`-c ${single_quote(wrap)}`)}\n`;
	}

	// Optional directives — each its own line only when its input is set, so the
	// generated script carries no empty `key=` noise.
	const directory_line =
		working_directory === undefined ? '' : `directory=${single_quote(working_directory)}\n`;
	const ulimit_line =
		ulimit_nofile === undefined ? '' : `rc_ulimit=${single_quote(`-n ${ulimit_nofile}`)}\n`;

	// The env file's reader, assigned at the top and run by `start_pre` (as the service
	// user, assigning nothing) and by the daemon's process (`export`); see the module doc.
	const env_block =
		env_file === undefined
			? ''
			: `
# The env file's reader (OpenRC has no EnvironmentFile=): every line is data, never
# run or expanded. start_pre has the service user check it; the daemon's process
# exports it.
_zap_env_load=${single_quote(env_reader(env_file))}
`;

	// The service user checks every line, under a timeout, so a line the reader can't read
	// or a file that user can't read refuses the start; root runs the check and never
	// parses the file. Its output goes to a file in a directory of root's own under
	// `/run`, which the service user can't fill beforehand to stop the start as it could
	// `/tmp` (a writer it leaves running still holds the file and can grow it: root bounds
	// only what it reads), and never a
	// pipe: a process the service user leaves running could hold a pipe's write end open
	// past the timeout, and root reading it to its end would wait as long. Root reads a
	// bounded prefix of the file, which ends whatever is still writing. Then it hands the
	// reader to the daemon's process through the environment.
	const env_check =
		env_file === undefined
			? ''
			: `\t_zap_tmp=$(mktemp -d /run/zap-env-check.XXXXXX) || { eerror 'no private directory to check the env file in'; return 1; }
\ttimeout -s KILL ${ENV_CHECK_TIMEOUT_SECS} su -s /bin/sh -c "$_zap_env_load"'
_zap_env_read : || { printf "%s\\n" "$_zap_env_why"; exit 1; }' ${single_quote(user)} >"$_zap_tmp/out" 2>&1
\t_zap_rc=$?
\t_zap_out=$(head -c ${ENV_CHECK_OUTPUT_BYTES} "$_zap_tmp/out")
\trm -rf -- "$_zap_tmp"
\tif [ "$_zap_rc" -ne 0 ]; then
\t\t{ [ "$_zap_rc" -lt 128 ] && [ -n "$_zap_out" ]; } || _zap_out=${single_quote(`${env_file} was not read within ${ENV_CHECK_TIMEOUT_SECS} seconds`)}
\t\teerror "$_zap_out"${single_quote(` (read as ${user})`)}
\t\treturn 1
\tfi
\texport _zap_env_load
`;

	// `checkpath` re-owns an existing directory, so refuse one the service user doesn't
	// already own: an absent one is created, anything else is someone else's.
	const log_dir_q = single_quote(log_dir);
	const owner_q = single_quote(user);
	const log_dir_guard = `\tif [ -L ${log_dir_q} ] || { [ -e ${log_dir_q} ] && { [ ! -d ${log_dir_q} ] || [ "$(stat -c %U ${log_dir_q})" != ${owner_q} ]; }; }; then\n\t\teerror ${single_quote(`${log_dir} exists and is not a directory owned by ${user}; refusing to re-own it`)}\n\t\treturn 1\n\tfi\n`;

	const need_lines = needs.map((d) => `\tneed ${single_quote(d)}`).join('\n');
	const use_lines = uses.map((d) => `\tuse ${single_quote(d)}`).join('\n');
	const depend_body = [need_lines, use_lines].filter((s) => s !== '').join('\n');
	// A function with an empty body is a syntax error to `sh`, so with nothing to
	// depend on the script declares no `depend()` at all.
	const depend_block = depend_body === '' ? '' : `\ndepend() {\n${depend_body}\n}\n`;

	const tier_label =
		isolation === undefined
			? 'Tier A: privilege hardening'
			: 'Tier A privilege hardening + Tier B bwrap FS isolation';

	return `#!/sbin/openrc-run
# Managed by zap — hardened OpenRC service (${tier_label}).

name=${single_quote(name)}
description=${single_quote(description)}

${command_line}${command_args_line}command_user=${single_quote(`${user}:${group}`)}
${directory_line}supervisor='supervise-daemon'
respawn_delay=${single_quote(String(respawn_delay))}

# Hardening (Tier A — OpenRC-native privilege drop; applies to the sandboxed process
# when Tier-B bwrap isolation is enabled. Syscall filtering is the accepted residual).
no_new_privs='yes'
capabilities=${single_quote(with_bounding_drops(capabilities))}
umask=${single_quote(umask)}
${ulimit_line}output_log=${single_quote(log_file)}
error_log=${single_quote(log_file)}
${env_block}${depend_block}
start_pre() {
${env_check}${log_dir_guard}	checkpath --directory --owner ${single_quote(`${user}:${group}`)} --mode 0755 ${log_dir_q}
}
`;
}
