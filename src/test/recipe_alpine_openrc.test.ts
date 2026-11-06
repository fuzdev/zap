import { spawnSync } from 'node:child_process';
import {
	chmodSync,
	existsSync,
	mkdirSync,
	mkdtempSync,
	readFileSync,
	rmSync,
	symlinkSync,
	writeFileSync
} from 'node:fs';
import { tmpdir, userInfo } from 'node:os';
import { join } from 'node:path';
import { assert, describe, test } from 'vitest';

import { hardened_openrc_service } from '#lib/recipe_alpine_openrc.ts';
import { single_quote } from '#lib/shell.ts';

test('renders a supervise-daemon script with the Tier-A hardening directives', () => {
	const script = hardened_openrc_service({
		name: 'fuz_forge',
		description: 'app.example.com',
		command: '/home/fuz_forge/app/current/dist_artifacts/fuzfd',
		command_args: 'start',
		user: 'fuz_forge',
		working_directory: '/home/fuz_forge/app/current',
		ulimit_nofile: 65535
	});

	assert.ok(script.startsWith('#!/sbin/openrc-run\n'), 'openrc-run shebang');
	assert.ok(script.includes("supervisor='supervise-daemon'"), 'supervised');
	assert.ok(
		script.includes("command_user='fuz_forge:fuz_forge'"),
		'drop to the service account (group defaults to user)'
	);
	assert.ok(script.includes("no_new_privs='yes'"), 'no_new_privs');
	assert.ok(
		script.includes(`capabilities='!cap_chown,!cap_dac_override,`) &&
			script.includes(',!cap_bpf,!cap_checkpoint_restore,!41,') &&
			script.includes(",!62,!63'\n"),
		'no ambient capability, and every one dropped from the bounding set, by number past the named ones'
	);
	assert.ok(script.includes("rc_ulimit='-n 65535'"), 'ulimit');
	assert.ok(
		script.includes("command='/home/fuz_forge/app/current/dist_artifacts/fuzfd'") &&
			script.includes("command_args='start'"),
		'command + args'
	);
	assert.ok(script.includes("directory='/home/fuz_forge/app/current'"), 'working directory');
	assert.ok(
		script.includes("output_log='/var/log/fuz_forge/fuz_forge.log'"),
		'default log file in a service-owned subdir'
	);
	assert.ok(
		script.includes(
			"\tcheckpath --directory --owner 'fuz_forge:fuz_forge' --mode 0755 '/var/log/fuz_forge'\n}"
		),
		'start_pre provisions the service-owned log dir'
	);
	assert.ok(script.endsWith('\n'), 'trailing newline');
});

test('the default log file lives in a service-owned subdir provisioned by start_pre', () => {
	const script = hardened_openrc_service({
		name: 'svc',
		description: 'svc',
		command: '/usr/bin/svc',
		user: 'svc'
	});

	assert.ok(
		script.includes("output_log='/var/log/svc/svc.log'"),
		'default log file is /var/log/<name>/<name>.log'
	);
	assert.ok(
		script.includes("error_log='/var/log/svc/svc.log'"),
		'error log shares the default path'
	);
	assert.ok(
		script.includes(
			`start_pre() {\n\tif [ -L '/var/log/svc' ] || { [ -e '/var/log/svc' ] && { [ ! -d '/var/log/svc' ] || [ "$(stat -c %U '/var/log/svc')" != 'svc' ]; }; }; then\n\t\teerror '/var/log/svc exists and is not a directory owned by svc; refusing to re-own it'\n\t\treturn 1\n\tfi\n\tcheckpath --directory --owner 'svc:svc' --mode 0755 '/var/log/svc'\n}`
		),
		'start_pre chowns the default log dir to the service user'
	);
});

test("start_pre provisions a custom log file's parent dir", () => {
	const script = hardened_openrc_service({
		name: 'svc',
		description: 'svc',
		command: '/usr/bin/svc',
		user: 'svc',
		group: 'web',
		log_file: '/srv/svc/logs/server.log'
	});

	assert.ok(script.includes("output_log='/srv/svc/logs/server.log'"), 'honors the custom log file');
	assert.ok(
		script.includes(
			`start_pre() {\n\tif [ -L '/srv/svc/logs' ] || { [ -e '/srv/svc/logs' ] && { [ ! -d '/srv/svc/logs' ] || [ "$(stat -c %U '/srv/svc/logs')" != 'svc' ]; }; }; then\n\t\teerror '/srv/svc/logs exists and is not a directory owned by svc; refusing to re-own it'\n\t\treturn 1\n\tfi\n\tcheckpath --directory --owner 'svc:web' --mode 0755 '/srv/svc/logs'\n}`
		),
		"start_pre provisions the custom log file's parent dir with the service group"
	);
});

test('the env file is read as data by root and the daemon, never sourced', () => {
	const script = hardened_openrc_service({
		name: 'svc',
		description: 'svc',
		command: '/usr/bin/svc',
		command_args: 'start',
		user: 'svc',
		env_file: '/srv/.env'
	});

	assert.ok(!script.includes('set -a'), 'no set -a');
	assert.ok(!/^\s*\. /m.test(script), 'nothing is sourced');
	assert.ok(
		script.includes(
			`start_pre() {\n\t_zap_tmp=$(mktemp -d /run/zap-env-check.XXXXXX) || { eerror 'no private directory to check the env file in'; return 1; }\n\ttimeout -s KILL 10 su -s /bin/sh -c "$_zap_env_load"'\n_zap_env_read : || { printf "%s\\n" "$_zap_env_why"; exit 1; }' 'svc' >"$_zap_tmp/out" 2>&1\n\t_zap_rc=$?\n`
		) && script.includes('\t\treturn 1\n\tfi\n\texport _zap_env_load\n'),
		'the service user checks every line, under a timeout; then the reader goes to the daemon'
	);
	assert.ok(!script.includes('\teval "$_zap_env_load"\n'), 'root never runs the reader');
	assert.ok(script.includes("command='/bin/sh'"), 'the daemon loads the file itself');
	assert.ok(
		script.includes(
			`command_args='-c '\\''eval "$_zap_env_load" && _zap_env_exec "$@"'\\'' zap-env /usr/bin/svc start'`
		),
		'the command and its args follow the loader'
	);
});

test('omits optional lines when their inputs are unset', () => {
	const script = hardened_openrc_service({
		name: 'svc',
		description: 'svc',
		command: '/usr/bin/svc',
		user: 'svc'
	});

	assert.ok(!script.includes('command_args='), 'no command_args line');
	assert.ok(!script.includes('directory='), 'no directory line');
	assert.ok(!script.includes('rc_ulimit='), 'no ulimit line');
	assert.ok(!script.includes('_zap_env'), 'no env file reader');
	assert.ok(script.includes("command='/usr/bin/svc'"), 'the command runs directly');
});

test('depend() defaults to need net alone', () => {
	const script = hardened_openrc_service({
		name: 'svc',
		description: 'svc',
		command: '/usr/bin/svc',
		user: 'svc'
	});

	assert.ok(script.includes("depend() {\n\tneed 'net'\n}"), 'default depend block');
});

test('a service binding a low port can request a capability', () => {
	const script = hardened_openrc_service({
		name: 'svc',
		description: 'svc',
		command: '/usr/bin/svc',
		user: 'svc',
		capabilities: '^cap_net_bind_service'
	});

	const line = /^capabilities='(.*)'$/m.exec(script)?.[1];
	assert.ok(line, script);
	const entries = line.split(',');
	// the ambient one first, then every other capability dropped from the bounding set
	assert.equal(entries[0], '^cap_net_bind_service');
	assert.ok(!entries.includes('!cap_net_bind_service'));
	assert.ok(entries.includes('!cap_sys_admin') && entries.includes('!cap_checkpoint_restore'));
	assert.deepEqual(
		entries.slice(-23),
		Array.from({ length: 23 }, (_, i) => `!${41 + i}`)
	);
	assert.equal(entries.length, 64);

	// a capability the value already drops is not dropped twice, and a bare `^` names none
	const dropped = hardened_openrc_service({
		name: 'svc',
		description: 'svc',
		command: '/usr/bin/svc',
		user: 'svc',
		capabilities: '^,!CAP_SYS_ADMIN'
	});
	const all = /^capabilities='(.*)'$/m.exec(dropped)?.[1]?.split(',') ?? [];
	assert.equal(all[0], '!CAP_SYS_ADMIN');
	assert.ok(!all.includes('!cap_sys_admin') && !all.includes('^'), all.join(','));
	assert.equal(all.length, 64);
});

test('Tier-B isolation wraps the command in a bwrap sandbox via sh -c exec', () => {
	const script = hardened_openrc_service({
		name: 'fuz_forge',
		description: 'app.example.com',
		command: '/home/fuz_forge/app/current/dist_artifacts/fuzfd',
		command_args: 'start',
		user: 'fuz_forge',
		working_directory: '/home/fuz_forge/app/current',
		isolation: {
			read_write_paths: ['/home/fuz_forge/app', '/home/fuz_forge/.fuz_forge']
		}
	});

	// Launched via `sh -c 'exec bwrap … -- cmd'` — a `command="…/bwrap"` form mangles
	// bwrap's `--` separator under supervise-daemon. Pinned exactly (the load-bearing
	// artifact): read-only root, private /tmp, the rw binds, --chdir, --die-with-parent.
	assert.ok(script.includes("command='/bin/sh'"), 'command is /bin/sh');
	assert.ok(
		script.includes(
			`command_args='-c '\\''exec /usr/bin/bwrap --ro-bind / / --dev /dev --proc /proc --tmpfs /tmp --bind /home/fuz_forge/app /home/fuz_forge/app --bind /home/fuz_forge/.fuz_forge /home/fuz_forge/.fuz_forge --chdir /home/fuz_forge/app/current --die-with-parent -- /home/fuz_forge/app/current/dist_artifacts/fuzfd start'\\'''`
		),
		'exact bwrap invocation'
	);
	// Tier-A hardening still applies to the sandboxed process.
	assert.ok(
		script.includes("command_user='fuz_forge:fuz_forge'"),
		'still drops to the service account'
	);
	assert.ok(script.includes("no_new_privs='yes'"), 'still no_new_privs');
	assert.ok(
		script.includes("capabilities='!cap_chown,"),
		'still drops every capability from the bounding set'
	);
	// The raw binary is never run unsandboxed.
	assert.ok(
		!script.includes("command='/home/fuz_forge/app/current/dist_artifacts/fuzfd'"),
		'no direct (unsandboxed) command line'
	);
	assert.ok(
		script.includes('Tier A privilege hardening + Tier B bwrap FS isolation'),
		'header notes the isolation tier'
	);
});

test('Tier-B with empty read_write_paths renders the base mounts but no --bind', () => {
	const script = hardened_openrc_service({
		name: 'svc',
		description: 'svc',
		command: '/usr/bin/svc',
		user: 'svc',
		working_directory: '/srv/svc',
		isolation: {
			read_write_paths: []
		}
	});

	// The base sandbox mounts are still present.
	assert.ok(script.includes('--tmpfs /tmp'), 'private /tmp tmpfs');
	assert.ok(script.includes('--ro-bind / /'), 'read-only root');
	assert.ok(script.includes('--dev /dev'), 'device mount');
	assert.ok(script.includes('--proc /proc'), 'proc mount');
	// A working directory still yields --chdir, and the wrap stays self-tearing-down.
	assert.ok(script.includes('--chdir /srv/svc'), 'chdir to the working dir');
	assert.ok(script.includes('--die-with-parent'), 'die-with-parent');
	assert.ok(script.includes('-- /usr/bin/svc'), 'the command after the separator');
	// No rw binds were declared, so no --bind segment is rendered.
	assert.ok(!script.includes('--bind'), 'no --bind segment when read_write_paths is empty');
});

test('Tier-B with a single read_write_path renders exactly one --bind', () => {
	const script = hardened_openrc_service({
		name: 'svc',
		description: 'svc',
		command: '/usr/bin/svc',
		user: 'svc',
		isolation: {
			read_write_paths: ['/srv/app']
		}
	});

	assert.ok(script.includes('--bind /srv/app /srv/app'), 'the single rw bind');
	assert.equal(script.split('--bind').length - 1, 1, 'exactly one --bind occurrence');
});

test('Tier-B renders one --bind per read_write_path in declared order', () => {
	const script = hardened_openrc_service({
		name: 'svc',
		description: 'svc',
		command: '/usr/bin/svc',
		user: 'svc',
		isolation: {
			read_write_paths: ['/a', '/b', '/c']
		}
	});

	assert.ok(
		script.includes('--bind /a /a --bind /b /b --bind /c /c'),
		'three rw binds in declared order'
	);
	assert.equal(script.split('--bind').length - 1, 3, 'exactly three --bind occurrences');
});

test('Tier-B rejects a read_write_path with a space (fail-fast at eval)', () => {
	assert.throws(
		() =>
			hardened_openrc_service({
				name: 'svc',
				description: 'svc',
				command: '/usr/bin/svc',
				user: 'svc',
				isolation: {
					read_write_paths: ['/srv/My App']
				}
			}),
		/\/srv\/My App/,
		'the error message names the offending path'
	);
});

test('Tier-B accepts a normal read_write_path set and renders the --bind segments', () => {
	const script = hardened_openrc_service({
		name: 'svc',
		description: 'svc',
		command: '/usr/bin/svc',
		user: 'svc',
		isolation: {
			read_write_paths: ['/home/svc/app', '/var/log/svc']
		}
	});

	assert.ok(
		script.includes('--bind /home/svc/app /home/svc/app --bind /var/log/svc /var/log/svc'),
		'both rw binds render in declared order'
	);
});

test('Tier-B honors a custom bwrap path and omits --chdir without a working dir', () => {
	const script = hardened_openrc_service({
		name: 'svc',
		description: 'svc',
		command: '/usr/bin/svc',
		user: 'svc',
		isolation: {
			read_write_paths: ['/srv/svc'],
			bwrap_path: '/usr/local/bin/bwrap'
		}
	});

	assert.ok(script.includes('exec /usr/local/bin/bwrap '), 'custom bwrap path');
	assert.ok(script.includes('--bind /srv/svc /srv/svc '), 'rw bind');
	assert.ok(!script.includes('--chdir'), 'no --chdir without a working directory');
});

test('a missing env file refuses the start; a shared log dir is refused at eval', () => {
	const script = hardened_openrc_service({
		name: 'svc',
		description: 'svc',
		command: '/usr/bin/svc',
		user: 'svc',
		env_file: '/etc/svc/env'
	});
	assert.ok(
		script.includes(
			`start_pre() {\n\t_zap_tmp=$(mktemp -d /run/zap-env-check.XXXXXX) || { eerror 'no private directory to check the env file in'; return 1; }\n\ttimeout -s KILL 10 su -s /bin/sh -c "$_zap_env_load"'\n_zap_env_read : || { printf "%s\\n" "$_zap_env_why"; exit 1; }' 'svc' >"$_zap_tmp/out" 2>&1\n\t_zap_rc=$?\n`
		),
		'start_pre refuses an env file it cannot read'
	);
	assert.ok(script.includes(`_zap_env_why="$_zap_f is missing or unreadable"`));
	for (const log_file of [
		'/var/log/svc.log',
		'svc.log',
		'/x.log',
		'/tmp/svc.log',
		'/etc/x.log',
		'/usr/x.log',
		'/var/lib/x.log',
		'/home/x.log',
		'/var/log/nginx/x.log',
		'/var/log/svcx/x.log',
		'/svc/x.log',
		'/var/log/svc/../x.log',
		'/var/log//svc/x.log'
	]) {
		assert.throws(
			() =>
				hardened_openrc_service({
					name: 'svc',
					description: 'svc',
					command: '/usr/bin/svc',
					user: 'svc',
					log_file
				}),
			/log_file/,
			log_file
		);
	}
	for (const log_file of [
		'/var/log/svc/svc.log',
		'/var/log/svc/server.log',
		'/var/log/svc_api/server.log',
		'/srv/svc/logs/server.log'
	]) {
		assert.doesNotThrow(
			() =>
				hardened_openrc_service({
					name: 'svc',
					description: 'svc',
					command: '/usr/bin/svc',
					user: 'svc',
					log_file
				}),
			log_file
		);
	}
	// the owner-named directory must sit directly under an allowed root
	const anchored: Array<[string, string, string]> = [
		['log', 'svc', '/var/log/nginx/x.log'],
		['var', 'svc', '/var/spool/x.log'],
		['etc', 'svc', '/etc/ssh/x.log'],
		['home', 'svc', '/home/alice/x.log'],
		['local', 'svc', '/usr/local/bin/x.log'],
		['share', 'svc', '/usr/share/x/y.log'],
		['svc', 'root', '/root/.ssh/x.log'],
		['svc', 'svc', '/etc/svc/x.log'],
		['svc', 'svc', '/home/svc/x.log'],
		['svc', 'svc', '/usr/svc/x.log'],
		['svc', 'svc', '/boot/svc/x.log'],
		['svc', 'svc', '/var/log/other/svc/x.log'],
		['svc', 'svc', '/var/log/svc/'],
		['svc', 'svc', '/var/log/svc/..'],
		['svc', 'svc', '/var/log/svc/.']
	];
	for (const [name, user, log_file] of anchored) {
		assert.throws(
			() =>
				hardened_openrc_service({
					name,
					description: name,
					command: '/usr/bin/svc',
					user,
					log_file
				}),
			/hardened_openrc_service: log_file /,
			`${name}/${user}: ${log_file}`
		);
	}
	// the env file never sits in the directory chowned to the service user
	for (const [log_file, env_file] of [
		['/srv/svc/x.log', '/srv/svc/env'],
		['/srv/svc/server.log', '/srv/svc/.env'],
		['/srv/svc/server.log', '/srv/svc/conf/env'],
		['/srv/svc/logs/server.log', '/srv/svc/logs/env'],
		['/srv/svc/logs/server.log', '/srv/x/../svc/logs/env']
	] as const) {
		assert.throws(
			() =>
				hardened_openrc_service({
					name: 'svc',
					description: 'svc',
					command: '/usr/bin/svc',
					user: 'svc',
					log_file,
					env_file
				}),
			/hardened_openrc_service: env_file .* must not sit inside the log directory/,
			`${log_file} + ${env_file}`
		);
	}
	for (const log_file of [
		'/var/lib/svc/logs/server.log',
		'/opt/svc/server.log',
		'/run/svc/server.log',
		'/var/log/svc-worker/server.log'
	]) {
		assert.doesNotThrow(
			() =>
				hardened_openrc_service({
					name: 'svc',
					description: 'svc',
					command: '/usr/bin/svc',
					user: 'svc',
					log_file,
					env_file: '/etc/svc/env'
				}),
			log_file
		);
	}
	// a directory named for the service user is the service's own too
	assert.doesNotThrow(() =>
		hardened_openrc_service({
			name: 'svc',
			description: 'svc',
			command: '/usr/bin/svc',
			user: 'app',
			log_file: '/srv/app/logs/server.log'
		})
	);
});

test('env_file must be absolute, since root and the daemon read it from different directories', () => {
	for (const env_file of ['env', 'svc/env', './env', '../srv/svc/logs/env', '']) {
		assert.throws(
			() =>
				hardened_openrc_service({
					name: 'svc',
					description: 'svc',
					command: '/usr/bin/svc',
					user: 'svc',
					env_file
				}),
			/hardened_openrc_service: env_file .* must be an absolute path/,
			env_file
		);
	}
});

test('an executable inside the service-owned log directory is refused at eval', () => {
	for (const command of [
		'/var/log/svc/svc',
		'/var/log/svc/bin/svc',
		'/var/log/x/../svc/svc',
		'/var/log/svc'
	]) {
		assert.throws(
			() =>
				hardened_openrc_service({
					name: 'svc',
					description: 'svc',
					command,
					user: 'svc'
				}),
			/hardened_openrc_service: command .* must not sit inside the log directory/,
			command
		);
	}
	assert.throws(
		() =>
			hardened_openrc_service({
				name: 'svc',
				description: 'svc',
				command: '/usr/bin/svc',
				user: 'svc',
				log_file: '/srv/svc/server.log',
				isolation: { read_write_paths: ['/srv/svc'], bwrap_path: '/srv/svc/bin/bwrap' }
			}),
		/hardened_openrc_service: isolation\.bwrap_path .* must not sit inside the log directory/
	);
	// a sibling of the log directory, and a name it prefixes, are outside it
	for (const command of ['/var/log/svc_bin/svc', '/var/log/svcx', '/srv/svc/bin/svc']) {
		assert.doesNotThrow(
			() =>
				hardened_openrc_service({
					name: 'svc',
					description: 'svc',
					command,
					user: 'svc',
					log_file: '/srv/svc/logs/server.log'
				}),
			command
		);
	}
});

test('start_pre refuses an existing log directory the service user does not own', () => {
	const script = hardened_openrc_service({
		name: 'postgresql',
		description: 'pg',
		command: '/usr/bin/svc',
		user: 'app',
		log_file: '/var/lib/postgresql/server.log',
		env_file: '/etc/svc/env'
	});
	const guard =
		`\tif [ -L '/var/lib/postgresql' ] || { [ -e '/var/lib/postgresql' ] && { [ ! -d '/var/lib/postgresql' ] || [ "$(stat -c %U '/var/lib/postgresql')" != 'app' ]; }; }; then\n` +
		`\t\teerror '/var/lib/postgresql exists and is not a directory owned by app; refusing to re-own it'\n` +
		`\t\treturn 1\n\tfi\n`;
	// root-run, after the env check, before checkpath re-owns the directory
	assert.ok(
		script.includes(
			`\texport _zap_env_load\n${guard}\tcheckpath --directory --owner 'app:app' --mode 0755 '/var/lib/postgresql'\n}`
		),
		'the ownership guard precedes checkpath'
	);
});

test('a numeric user is refused; a relative command fails as relative', () => {
	assert.throws(
		() =>
			hardened_openrc_service({
				name: 'svc',
				description: 'svc',
				command: '/usr/bin/svc',
				user: '1000'
			}),
		/must be an account name/
	);
	assert.throws(
		() =>
			hardened_openrc_service({
				name: 'svc',
				description: 'svc',
				command: 'var/log/svc/svc',
				user: 'svc'
			}),
		/must be an absolute path/
	);
});

test('start_pre refuses a log directory the service user does not own, under sh', () => {
	const user = userInfo().username;
	const script = hardened_openrc_service({
		name: 'svc',
		description: 'svc',
		command: '/usr/bin/svc',
		user
	});
	const start_pre = /\nstart_pre\(\) \{\n[\s\S]*?\n\}\n/.exec(script)?.[0];
	assert.ok(start_pre, 'the script defines start_pre');
	const dir = mkdtempSync(join(tmpdir(), 'zap-openrc-'));
	try {
		const log_dir = join(dir, 'logs');
		const log = join(dir, 'calls');
		// `start_pre` as rendered, aimed at the test's directory; `checkpath` and
		// `eerror` are OpenRC's, stood in for by functions that log their calls, and a
		// `stat` stand-in answers another owner where one is asked for.
		const run = (stat_owner?: string): { status: number | null; calls: string } => {
			writeFileSync(log, '');
			const stand_ins = [
				`checkpath() { printf 'checkpath %s\\n' "$*" >> ${single_quote(log)}; }`,
				`eerror() { printf 'eerror %s\\n' "$*" >> ${single_quote(log)}; }`,
				stat_owner === undefined ? '' : `stat() { echo ${single_quote(stat_owner)}; }`
			].join('\n');
			const body = start_pre.replaceAll(`'/var/log/svc'`, single_quote(log_dir));
			assert.notEqual(body, start_pre, 'the log directory was aimed at the test');
			const shell = spawnSync('sh', ['-c', `${stand_ins}\n${body}\nstart_pre`], {
				encoding: 'utf8'
			});
			return { status: shell.status, calls: readFileSync(log, 'utf8') };
		};
		const refused = (what: string, stat_owner?: string): void => {
			const { status, calls } = run(stat_owner);
			assert.equal(status, 1, what);
			assert.ok(calls.startsWith('eerror '), `${what}: ${calls}`);
			assert.ok(!calls.includes('checkpath'), `${what}: nothing is re-owned`);
		};
		const provisioned = (what: string): void => {
			const { status, calls } = run();
			assert.equal(status, 0, what);
			assert.equal(
				calls,
				`checkpath --directory --owner ${user}:${user} --mode 0755 ${log_dir}\n`,
				what
			);
		};

		provisioned('a missing directory is made');
		mkdirSync(log_dir);
		provisioned("the user's own directory is kept");
		refused('a directory another account owns', 'root');
		rmSync(log_dir, { recursive: true });
		const elsewhere = join(dir, 'elsewhere');
		mkdirSync(elsewhere);
		symlinkSync(elsewhere, log_dir);
		refused('a symlink, even to a directory of its own');
		rmSync(log_dir);
		writeFileSync(log_dir, '');
		refused('a file');
	} finally {
		rmSync(dir, { recursive: true, force: true });
	}
});

/** The shells the env file reader runs under: `sh`, and BusyBox's when it is here (Alpine's). */
const READER_SHELLS: Array<Array<string>> = [
	['sh'],
	...(spawnSync('busybox', ['sh', '-c', 'true']).status === 0 ? [['busybox', 'sh']] : [])
];

describe('the env file reader, under a real shell', () => {
	/**
	 * Render a script for `contents` (or no file when `null`), then run what OpenRC
	 * would: `start_pre`'s root check, and the daemon's `sh -c` wrap with `command` a
	 * recorder of its environment and arguments.
	 */
	const run_reader = (
		shell: Array<string>,
		contents: string | null
	): {
		check: { status: number | null; why: string };
		child: { status: number | null; stderr: string };
		env: Map<string, string> | null;
		args: Array<string> | null;
	} => {
		const dir = mkdtempSync(join(tmpdir(), 'zap-openrc-env-'));
		try {
			const env_file = join(dir, 'env');
			if (contents !== null) writeFileSync(env_file, contents);
			const recorder = join(dir, 'recorder');
			writeFileSync(
				recorder,
				`#!/bin/sh\n/usr/bin/env -0 > ${single_quote(join(dir, 'env.out'))}\nprintf '%s\\0' "$@" > ${single_quote(join(dir, 'args.out'))}\n`
			);
			chmodSync(recorder, 0o755);
			const init = join(dir, 'init');
			writeFileSync(
				init,
				hardened_openrc_service({
					name: 'svc',
					description: 'svc',
					command: recorder,
					command_args: "one 'two  words'",
					user: 'svc',
					env_file
				})
			);
			const [program = 'sh', ...pre] = shell;
			const sh = (text: string) =>
				spawnSync(program, [...pre, '-c', text], {
					cwd: dir,
					encoding: 'utf8',
					env: { PATH: process.env.PATH }
				});
			const check = sh(
				`. ${single_quote(init)}; eval "$_zap_env_load"; _zap_env_read : || { printf %s "$_zap_env_why"; exit 3; }`
			);
			// OpenRC's start line: `command_args` expanded and `eval`ed, `command` ahead of it
			const child = sh(
				`. ${single_quote(init)}; eval "$_zap_env_load"; export _zap_env_load; eval set -- $command_args; shift; s=$1; shift; exec ${shell.join(' ')} -c "$s" "$@"`
			);
			assert.ok(!existsSync(join(dir, 'canary')), 'a line ran as code');
			const read = (name: string): Array<string> | null =>
				existsSync(join(dir, name))
					? readFileSync(join(dir, name), 'utf8').split('\0').slice(0, -1)
					: null;
			const records = read('env.out');
			return {
				check: { status: check.status, why: check.stdout },
				child: { status: child.status, stderr: child.stderr },
				env:
					records === null
						? null
						: new Map(
								records.map((r) => [r.slice(0, r.indexOf('=')), r.slice(r.indexOf('=') + 1)])
							),
				args: read('args.out')
			};
		} finally {
			rmSync(dir, { recursive: true, force: true });
		}
	};

	/**
	 * Run `start_pre` as rendered for an env file holding `contents` (none when `null`):
	 * `su` and `timeout` are stand-ins on `PATH` (`su -s <sh> -c <cmd> <user>` runs the
	 * command as the test's own user and files the user; `timeout` gives the real one
	 * `timeout_secs`), and `checkpath`, `eerror` and `ewarn` are functions that file
	 * their calls.
	 */
	const run_start_pre = (
		shell: Array<string>,
		contents: string | { sparse: string } | null,
		timeout_secs = 10,
		held_for_secs = 0
	): { status: number | null; calls: string; su: string } => {
		const dir = mkdtempSync(join(tmpdir(), 'zap-openrc-start-'));
		try {
			const env_file = join(dir, 'env');
			if (typeof contents === 'string') writeFileSync(env_file, contents);
			else if (contents !== null) {
				assert.equal(spawnSync('truncate', ['-s', contents.sparse, env_file]).status, 0);
			}
			const bin = join(dir, 'bin');
			mkdirSync(bin);
			const calls = join(dir, 'calls');
			const su_log = join(dir, 'su');
			writeFileSync(calls, '');
			writeFileSync(su_log, '');
			const real_timeout = spawnSync('sh', ['-c', 'command -v timeout'], {
				encoding: 'utf8'
			}).stdout.trim();
			writeFileSync(
				join(bin, 'su'),
				`#!/bin/sh\n[ "$1" = -s ] || exit 125\nsh=$2\n[ "$3" = -c ] || exit 125\ncmd=$4\nprintf '%s\\n' "$5" >> ${single_quote(su_log)}\n${
					held_for_secs > 0 ? `sleep ${held_for_secs} &\n` : ''
				}exec "$sh" -c "$cmd"\n`
			);
			writeFileSync(
				join(bin, 'timeout'),
				`#!/bin/sh\n[ "$1" = -s ] && [ "$2" = KILL ] || exit 125\nshift 3\nexec ${single_quote(real_timeout)} -s KILL ${timeout_secs} "$@"\n`
			);
			chmodSync(join(bin, 'su'), 0o755);
			chmodSync(join(bin, 'timeout'), 0o755);
			const init = join(dir, 'init');
			const rendered = hardened_openrc_service({
				name: 'svc',
				description: 'svc',
				command: '/usr/bin/svc',
				user: 'svc',
				env_file
			});
			// the check's private directory is made under the test's own stand-in for `/run`
			const run_dir = join(dir, 'run');
			mkdirSync(run_dir);
			const aimed = rendered.replaceAll('/run/zap-env-check.', `${run_dir}/zap-env-check.`);
			assert.notEqual(aimed, rendered, 'the check directory was aimed at the test');
			writeFileSync(init, aimed);
			const record = (name: string) =>
				`${name}() { printf '${name} %s\\n' "$*" >> ${single_quote(calls)}; }`;
			const [program = 'sh', ...pre] = shell;
			const run = spawnSync(
				program,
				[
					...pre,
					'-c',
					`. ${single_quote(init)}; ${record('checkpath')}; ${record('eerror')}; ${record('ewarn')}; start_pre`
				],
				{
					cwd: dir,
					encoding: 'utf8',
					env: { PATH: `${bin}:${process.env.PATH}` },
					// a check with no timeout of its own would read the huge file for minutes
					timeout: 30_000,
					killSignal: 'SIGKILL'
				}
			);
			assert.ok(!existsSync(join(dir, 'canary')), 'a line ran as code');
			return {
				status: run.status,
				calls: readFileSync(calls, 'utf8').replaceAll(dir, '<dir>'),
				su: readFileSync(su_log, 'utf8')
			};
		} finally {
			rmSync(dir, { recursive: true, force: true });
		}
	};

	for (const shell of READER_SHELLS) {
		const label = shell.join(' ');

		test(`${label}: start_pre checks the file as the service user, never as root`, () => {
			const ok = run_start_pre(shell, "A='$(touch canary)'\nB=1\n");
			assert.equal(ok.status, 0, ok.calls);
			assert.equal(ok.su, 'svc\n', 'the check ran through su, as the service user');
			assert.equal(ok.calls, 'checkpath --directory --owner svc:svc --mode 0755 /var/log/svc\n');

			const bad = run_start_pre(shell, '# first\nOK=1\nA="double"\n');
			assert.equal(bad.status, 1, bad.calls);
			assert.equal(
				bad.calls,
				'eerror <dir>/env: line 3: a double-quoted value is not read; single-quote it (read as svc)\n'
			);

			const missing = run_start_pre(shell, null);
			assert.equal(missing.status, 1);
			assert.equal(missing.calls, 'eerror <dir>/env is missing or unreadable (read as svc)\n');
		});

		test(`${label}: start_pre doesn't wait on what the service user leaves holding the check's output`, () => {
			// the service user's side leaves a process holding the check's stdout and stderr
			// for longer than the test waits: start_pre reads the output it has and goes on
			const started = Date.now();
			const held = run_start_pre(shell, 'A=1\n', 10, 12);
			assert.equal(held.status, 0, held.calls);
			assert.equal(held.calls, 'checkpath --directory --owner svc:svc --mode 0755 /var/log/svc\n');
			assert.ok(Date.now() - started < 6000, 'nothing waited for the holder');
			const bad = run_start_pre(shell, 'A="double"\n', 10, 12);
			assert.equal(bad.status, 1, bad.calls);
			assert.equal(
				bad.calls,
				'eerror <dir>/env: line 1: a double-quoted value is not read; single-quote it (read as svc)\n'
			);
		});

		test(`${label}: start_pre refuses a file it doesn't finish reading in time`, () => {
			// a sparse file of one line a gigabyte long, which the reader takes far longer
			// than the stand-in's second over: killed, and refused naming the file and user
			const started = Date.now();
			const huge = run_start_pre(shell, { sparse: '1G' }, 1);
			assert.equal(huge.status, 1, huge.calls);
			assert.equal(huge.calls, 'eerror <dir>/env was not read within 10 seconds (read as svc)\n');
			assert.ok(Date.now() - started < 8000, 'the timeout ended it');
		});
	}

	for (const shell of READER_SHELLS) {
		const label = shell.join(' ');

		test(`${label}: every value is literal and nothing in the file runs`, () => {
			const contents = [
				'# a comment',
				'   ; another',
				'',
				'\t ',
				'PLAIN=plain',
				`SQ='$(touch canary) \`touch canary\`; touch canary \\ "q" $HOME # kept'`,
				`UNQ=$(touch canary);\`touch canary\` it's "q" $HOME # kept`,
				'EMPTY=',
				"EMPTY_SQ=''",
				'DUP=first',
				'DUP=second',
				'LAST=no trailing newline'
			].join('\n');
			const { check, child, env, args } = run_reader(shell, contents);
			assert.equal(check.status, 0, check.why);
			assert.equal(child.status, 0, child.stderr);
			assert.ok(env, 'the command ran');
			const expected: Array<[string, string]> = [
				['PLAIN', 'plain'],
				['SQ', '$(touch canary) `touch canary`; touch canary \\ "q" $HOME # kept'],
				['UNQ', `$(touch canary);\`touch canary\` it's "q" $HOME # kept`],
				['EMPTY', ''],
				['EMPTY_SQ', ''],
				['DUP', 'second'],
				['LAST', 'no trailing newline']
			];
			for (const [name, value] of expected) assert.equal(env.get(name), value, name);
			assert.deepEqual(
				[...env.keys()].filter((name) => name.startsWith('_zap')),
				[],
				'the reader leaves nothing of its own in the environment'
			);
			// OpenRC's `eval` reads `command_args` as shell words, blanks collapsing
			assert.deepEqual(args, ['one', 'two words']);
		});

		test(`${label}: a line outside the format is refused by its number, and nothing starts`, () => {
			const cases: Array<[string, string]> = [
				['NOEQUALS', 'it is not NAME=VALUE'],
				['export A=1', 'the name is not'],
				[' A=1', 'the name is not'],
				['A =1', 'the name is not'],
				['1A=1', 'the name is not'],
				['A-B=1', 'the name is not'],
				['=1', 'the name is not'],
				['_zap_n=1', 'the name is not'],
				["A='open", 'must end the line with its closing quote'],
				["A='a' ", 'must end the line with its closing quote'],
				["A='a'b'", 'holds no other quote'],
				["A='", 'must end the line with its closing quote'],
				['A="double"', 'a double-quoted value is not read'],
				['A=back\\slash', 'holds no backslash'],
				['A=continued \\', 'holds no backslash'],
				['A= lead', 'neither starts nor ends with a blank'],
				['A=trail ', 'neither starts nor ends with a blank'],
				['A=tab\t', 'neither starts nor ends with a blank'],
				['A=crlf\r', 'it holds a carriage return'],
				["A='crlf'\r", 'it holds a carriage return']
			];
			for (const [line, reason] of cases) {
				const { check, child, env } = run_reader(shell, `# first\nOK=1\n${line}\nLATER=1\n`);
				const what = JSON.stringify(line);
				assert.equal(check.status, 3, what);
				const [path, why] = check.why.split(': line 3: ');
				assert.ok(path?.endsWith('/env'), `${what}: ${check.why}`);
				assert.ok(why?.includes(reason), `${what}: ${check.why}`);
				assert.equal(child.status, 1, what);
				assert.ok(child.stderr.includes(': line 3: '), `${what}: ${child.stderr}`);
				assert.equal(env, null, `${what}: the command never ran`);
			}
		});

		test(`${label}: a missing env file refuses the start`, () => {
			const { check, child, env } = run_reader(shell, null);
			assert.equal(check.status, 3);
			assert.ok(check.why.endsWith('/env is missing or unreadable'), check.why);
			assert.equal(child.status, 1);
			assert.equal(env, null);
		});
	}
});

const OPENRC_BASE = { name: 'svc', description: 'svc', command: '/usr/bin/svc', user: 'svc' };

test('refuses root, and any user or group that is not an account name', () => {
	assert.throws(
		() => hardened_openrc_service({ ...OPENRC_BASE, user: 'root' }),
		/user "root" is root/
	);
	assert.throws(
		() => hardened_openrc_service({ ...OPENRC_BASE, group: 'root' }),
		/group "root" is root/
	);
	for (const name of [' root', 'root ', '+0', '0', 'a b', '-x', '', 'host$']) {
		for (const field of ['user', 'group']) {
			assert.throws(
				() => hardened_openrc_service({ ...OPENRC_BASE, [field]: name }),
				new RegExp(`${field} .* must be an account name`),
				`${field}=${JSON.stringify(name)}`
			);
		}
	}
});

test('sets an owner-only umask unless loosened', () => {
	assert.ok(hardened_openrc_service(OPENRC_BASE).includes("\numask='0077'\n"));
	assert.ok(
		hardened_openrc_service({ ...OPENRC_BASE, umask: '0022' }).includes("\numask='0022'\n")
	);
	for (const umask of ['022', '0088', "0077'; x"]) {
		assert.throws(
			() => hardened_openrc_service({ ...OPENRC_BASE, umask }),
			/umask .* must be four octal digits/,
			umask
		);
	}
});
