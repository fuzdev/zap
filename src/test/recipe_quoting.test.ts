import { spawnSync } from 'node:child_process';
import {
	chmodSync,
	existsSync,
	mkdirSync,
	mkdtempSync,
	readFileSync,
	writeFileSync
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { assert, describe, test } from 'vitest';

import {
	hardened_openrc_service,
	type HardenedOpenrcServiceOptions
} from '#lib/recipe_alpine_openrc.ts';
import { alpine_postgres_setup } from '#lib/recipe_alpine_postgres.ts';
import { fuz_app_bootstrap_token } from '#lib/recipe_bootstrap.ts';
import { certbot_webroot_switch } from '#lib/recipe_certbot.ts';
import { debian_certbot_standalone_issue } from '#lib/recipe_debian_certbot.ts';
import { deno_install } from '#lib/recipe_deno.ts';
import { fuz_app_env_base, fuz_app_trusted_proxies } from '#lib/recipe_env.ts';
import { nginx_remove_default_core } from '#lib/recipe_nginx.ts';
import { ssh_hardening_verify } from '#lib/recipe_ssh.ts';
import { single_quote } from '#lib/shell.ts';

// Each recipe's command text runs under a real `sh`, with every program it names
// replaced by a stand-in that records its arguments and runs nothing — `sudo` above
// all, so no test reaches the real one. A value that left its quoting would run the
// `touch` it carries and create `canary` in the working directory.

/** A value that runs `touch canary` wherever a shell reads it as code. */
const HOSTILE = 'x\'y $(touch canary) `touch canary`; touch canary "q" $HOME\ntouch canary';

/** The programs the recipes name, each replaced by a recording stand-in. */
const STAND_INS = [
	'sudo',
	'certbot',
	'psql',
	'openssl',
	'tee',
	'chmod',
	'chown',
	'rm',
	'nginx',
	'curl',
	'unzip',
	'install',
	'mktemp',
	'grep',
	'rc-service',
	'systemctl'
];

/** The one address the `getent` stand-in resolves every name to. */
const GETENT_ADDRESS = '203.0.113.7';

interface Shell {
	dir: string;
	/** Run `text` with `sh -c` in `dir`; the stand-ins exit `status`. */
	run: (text: string, status?: number) => Array<Array<string>>;
}

/** A scratch directory with the stand-ins on a `PATH` ahead of the system's. */
const create_shell = (): Shell => {
	const dir = mkdtempSync(join(tmpdir(), 'zap-recipe-quoting-'));
	const bin = join(dir, 'bin');
	mkdirSync(bin);
	// One record per call: the program's name, then each argument, unit-separated. The
	// record is built first and written by one `printf`, so the two sides of a pipeline,
	// which run at once, can't interleave inside each other's records.
	const stand_in =
		'#!/bin/sh\n' +
		"us=$(printf '\\037'); r=${0##*/}\n" +
		'for a; do r="$r$us$a"; done\n' +
		'printf \'%s\\036\' "$r" >> "$STAND_IN_LOG"\n' +
		'exit "${STAND_IN_EXIT:-0}"\n';
	for (const name of STAND_INS) {
		writeFileSync(join(bin, name), stand_in);
		chmodSync(join(bin, name), 0o755);
	}
	// the certbot DNS preflight's lookups (`ahosts` and `hosts`): every name resolves to
	// `GETENT_ADDRESS`
	writeFileSync(
		join(bin, 'getent'),
		`#!/bin/sh\nprintf '%s STREAM %s\\n' ${GETENT_ADDRESS} "$2"\n`
	);
	chmodSync(join(bin, 'getent'), 0o755);
	const log = join(dir, 'calls.log');
	return {
		dir,
		run: (text, status = 0) => {
			writeFileSync(log, '');
			const shell = spawnSync('sh', ['-c', text], {
				cwd: dir,
				encoding: 'utf8',
				env: {
					PATH: `${bin}:${process.env.PATH}`,
					STAND_IN_LOG: log,
					STAND_IN_EXIT: String(status)
				}
			});
			assert.equal(shell.error, undefined);
			assert.ok(!existsSync(join(dir, 'canary')), `a value ran as code:\n${text}`);
			return readFileSync(log, 'utf8')
				.split('\x1e')
				.filter((record) => record !== '')
				.map((record) => record.split('\x1f'));
		}
	};
};

describe('script recipes pass each value as one word', () => {
	test('certbot', () => {
		const { run } = create_shell();
		const issue = debian_certbot_standalone_issue({ domain: HOSTILE, email: HOSTILE });
		const live = ['sudo', 'test', '-f', `/etc/letsencrypt/live/${HOSTILE}/fullchain.pem`];
		assert.deepEqual(run(issue.check), [live]);
		// the DNS preflight refuses a hostile name or address before anything runs
		assert.deepEqual(run(issue.run), []);
		const addressed = { domain: 'example.org', expected_addresses: [GETENT_ADDRESS] };
		assert.deepEqual(
			run(debian_certbot_standalone_issue({ ...addressed, expected_addresses: [HOSTILE] }).run),
			[]
		);
		assert.deepEqual(run(debian_certbot_standalone_issue({ ...addressed, email: HOSTILE }).run), [
			['sudo', 'systemctl', 'stop', 'nginx'],
			[
				'sudo',
				'certbot',
				'certonly',
				'--standalone',
				'-d',
				'example.org',
				'--non-interactive',
				'--agree-tos',
				'--email',
				HOSTILE
			]
		]);
		const webroot = certbot_webroot_switch({
			domain: HOSTILE,
			email: HOSTILE,
			webroot: HOSTILE,
			deploy_hook: { path: HOSTILE }
		});
		assert.deepEqual(run(webroot.check), [
			['sudo', 'grep', '-q', 'authenticator = webroot', `/etc/letsencrypt/renewal/${HOSTILE}.conf`]
		]);
		assert.deepEqual(run(webroot.run), []);
		const addressed_webroot = certbot_webroot_switch({
			...addressed,
			email: HOSTILE,
			webroot: HOSTILE,
			deploy_hook: { path: HOSTILE }
		});
		assert.deepEqual(run(addressed_webroot.run), [
			[
				'sudo',
				'certbot',
				'certonly',
				'--webroot',
				'-w',
				HOSTILE,
				'-d',
				'example.org',
				'--cert-name',
				'example.org',
				'--non-interactive',
				'--agree-tos',
				'--email',
				HOSTILE,
				'--force-renewal'
			],
			['sudo', '--', HOSTILE]
		]);
	});

	test('ssh_hardening_verify', () => {
		const { run } = create_shell();
		// A user name is one word, so the hostile value is one with no whitespace.
		const user = HOSTILE.replaceAll(/\s/g, '${IFS}');
		const { assertions } = ssh_hardening_verify({ user });
		const allow = assertions.find((a) => a.type === 'command' && a.run.includes('allowusers'));
		assert.ok(allow?.type === 'command');
		// The two sides of the pipe run at once, so their records come in either order;
		// the value itself goes to the shell's own `test`, as one word.
		const calls = run(allow.run).sort((a, b) => a[0]!.localeCompare(b[0]!));
		const effective = [
			'sudo',
			'sshd',
			'-T',
			'-C',
			`user=${user},host=192.0.2.1,addr=192.0.2.1,lport=22`
		];
		assert.deepEqual(calls, [['grep', '^allowusers '], effective]);
		const tunable = assertions.find(
			(a) => a.type === 'command' && a.run.includes('permitrootlogin')
		);
		assert.ok(tunable?.type === 'command');
		assert.deepEqual(
			run(tunable.run).sort((a, b) => a[0]!.localeCompare(b[0]!)),
			[['grep', '-qxF', 'permitrootlogin no'], effective]
		);
	});

	test('alpine_postgres_setup', () => {
		// the version is a number, so a hostile one never reaches a command
		assert.throws(() => alpine_postgres_setup({ version: HOSTILE }), /major version number/);
		const { run } = create_shell();
		assert.deepEqual(run(alpine_postgres_setup({ version: 18 }).check)[0], [
			'sudo',
			'test',
			'-e',
			'/var/lib/postgresql/18/data/PG_VERSION'
		]);
	});

	test('nginx_remove_default_core', () => {
		const { run } = create_shell();
		const script = nginx_remove_default_core(HOSTILE);
		assert.deepEqual(run(script.check), []);
		assert.deepEqual(run(script.run), [
			['sudo', 'rm', '-f', '--', HOSTILE],
			['sudo', 'nginx', '-t']
		]);
	});

	test('fuz_app_bootstrap_token', () => {
		const { run } = create_shell();
		const script = fuz_app_bootstrap_token({
			user: HOSTILE,
			service: HOSTILE,
			config_dir: `/opt/${HOSTILE}`
		});
		const token = `/opt/${HOSTILE}/secret_bootstrap_token`;
		// The stand-ins fail, so the check goes on past `sudo test` to the probe. The two
		// sides of a pipeline run at once, so their calls are compared in either order.
		const check = run(script.check, 1);
		assert.deepEqual(check[0], [
			'sudo',
			'test',
			'-f',
			token,
			'-a',
			'!',
			'-h',
			token,
			'-a',
			'-s',
			token
		]);
		assert.sameDeepMembers(check.slice(1), [
			['psql', '-d', HOSTILE, '-tAc', 'SELECT bootstrapped FROM bootstrap_lock WHERE id = 1'],
			['grep', '-qx', 't']
		]);
		const calls = run(script.run);
		assert.deepEqual(calls, [
			['openssl', 'rand', '-hex', '32'],
			['sudo', '-u', HOSTILE, 'tee', token],
			['sudo', '-u', HOSTILE, 'chmod', '600', token]
		]);
		// A failing `openssl` stops the run before anything is written.
		assert.deepEqual(run(script.run, 1), [['openssl', 'rand', '-hex', '32']]);
	});

	test('deno_install', () => {
		const { run } = create_shell();
		const bin_path = `/opt/${HOSTILE}/deno`;
		const script = deno_install({ version: HOSTILE, bin_path, user: HOSTILE });
		// the two sides of the check's pipe start together, so either may record first
		assert.sameDeepMembers(run(script.check), [
			['sudo', '-u', HOSTILE, bin_path, '--version'],
			['grep', '-q', `^deno ${HOSTILE} `]
		]);
		const calls = run(script.run);
		assert.deepEqual(calls.at(-2), ['sudo', '-u', HOSTILE, bin_path, '--version']);
		assert.deepEqual(calls.slice(0, 2), [
			['mktemp', '-d'],
			[
				'curl',
				'-fsSL',
				'-o',
				'/deno.zip',
				`https://github.com/denoland/deno/releases/download/v${HOSTILE}/deno-x86_64-unknown-linux-gnu.zip`
			]
		]);
		assert.deepEqual(
			calls.find((call) => call.includes('install')),
			['sudo', '-u', HOSTILE, 'install', '-D', '-m', '755', '/deno', bin_path]
		);
	});
});

describe('hardened_openrc_service', () => {
	test('the sourced script reads each value back literally', () => {
		const { dir, run } = create_shell();
		const env_file = join(dir, "e nv's $(touch canary)");
		writeFileSync(env_file, 'FROM_ENV_FILE=1\n');
		const script = hardened_openrc_service({
			name: HOSTILE,
			description: HOSTILE,
			command: '/usr/bin/svc',
			command_args: HOSTILE,
			user: 'svc',
			log_file: '/var/log/svc/svc.log',
			env_file
		});
		const init = join(dir, 'init');
		writeFileSync(init, script);
		const read_back = (names: Array<string>) =>
			`. ${single_quote(init)}; for v in ${names.map((n) => `"$${n}"`).join(' ')}; do sudo "$v"; done`;
		assert.deepEqual(run(read_back(['name', 'description'])), [
			['sudo', HOSTILE],
			['sudo', HOSTILE]
		]);
		// the env file's path rides in the reader, which reads the file as data
		assert.deepEqual(
			run(
				`. ${single_quote(init)}; eval "$_zap_env_load"; record() { sudo "$1"; }; _zap_env_read record`
			),
			[['sudo', 'FROM_ENV_FILE=1']]
		);
	});

	test('the Tier-B wrap reaches sh as one word, with command_args as shell words', () => {
		const { dir, run } = create_shell();
		const script = hardened_openrc_service({
			name: 'svc',
			description: 'svc',
			command: '/usr/bin/svc',
			command_args: "start --label 'it''s here'",
			user: 'svc',
			working_directory: '/srv/svc',
			isolation: { read_write_paths: ['/srv/svc'] }
		});
		const init = join(dir, 'init');
		writeFileSync(init, script);
		// What OpenRC's start does with the variable — `eval` it — with `sudo` standing in
		// for the `sh` it is handed to, then that `sh`'s own reading of the wrap.
		const wrap =
			'exec /usr/bin/bwrap --ro-bind / / --dev /dev --proc /proc --tmpfs /tmp --bind /srv/svc /srv/svc ' +
			"--chdir /srv/svc --die-with-parent -- /usr/bin/svc start --label 'it''s here'";
		assert.deepEqual(
			run(
				`. ${single_quote(init)}; eval sudo $command_args; eval set -- $command_args; eval "sudo \${2#exec }"`
			),
			[
				['sudo', '-c', wrap],
				[
					'sudo',
					...'/usr/bin/bwrap --ro-bind / / --dev /dev --proc /proc --tmpfs /tmp'.split(' '),
					...'--bind /srv/svc /srv/svc --chdir /srv/svc --die-with-parent'.split(' '),
					...['--', '/usr/bin/svc', 'start', '--label', 'its here']
				]
			]
		);
	});

	test('a value OpenRC evals as shell is refused unless it is one plain word', () => {
		const base = { name: 'svc', description: 'svc', command: '/usr/bin/svc', user: 'svc' };
		const cases: Array<[string, Partial<HardenedOpenrcServiceOptions>]> = [
			['command', { command: '/usr/bin/my svc' }],
			['command', { command: '/usr/bin/svc;reboot' }],
			['user', { user: 'svc$(id)' }],
			['group', { group: "web'" }],
			['working_directory', { working_directory: '/srv/a b' }],
			['capabilities', { capabilities: '^`id`' }],
			['log_file', { log_file: '/var/log/svc/$x.log' }],
			['log_file', { name: 'my svc' }],
			['command', { command: 'usr/bin/svc' }],
			['command', { command: '-x' }],
			['respawn_delay', { respawn_delay: '5;id' as unknown as number }],
			['isolation.bwrap_path', { isolation: { read_write_paths: [], bwrap_path: '/b w' } }]
		];
		for (const [field, options] of cases) {
			assert.throws(
				() => hardened_openrc_service({ ...base, ...options }),
				new RegExp(`hardened_openrc_service: ${field.replace('.', '\\.')} `),
				field
			);
		}
	});

	test('a capability dropped from the bounding set stays literal through OpenRC eval', () => {
		const { dir, run } = create_shell();
		const capabilities = '^cap_net_bind_service,!cap_sys_admin';
		const init = join(dir, 'init');
		writeFileSync(
			init,
			hardened_openrc_service({
				name: 'svc',
				description: 'svc',
				command: '/usr/bin/svc',
				user: 'svc',
				capabilities
			})
		);
		// As OpenRC's start line splices it: the value as one word, then `eval`.
		const [call] = run(`. ${single_quote(init)}; eval sudo --capabilities "$capabilities"`);
		assert.deepEqual(call?.slice(0, 2), ['sudo', '--capabilities']);
		assert.ok(call?.[2]?.startsWith(`${capabilities},!cap_chown,`), call?.[2]);
		assert.equal(call?.length, 3);
	});

	test('with nothing to depend on, the script declares no depend() and parses', () => {
		const script = hardened_openrc_service({
			name: 'svc',
			description: 'svc',
			command: '/usr/bin/svc',
			user: 'svc',
			needs: [],
			uses: []
		});
		assert.ok(!script.includes('depend()'), script);
		const parsed = spawnSync('sh', ['-n', '-c', script], { encoding: 'utf8' });
		assert.equal(parsed.status, 0, parsed.stderr);
	});
});

test('deno_install refuses a bin_path that is not absolute', () => {
	for (const bin_path of ['deno', '~/.deno/bin/deno', '$HOME/.deno/bin/deno', '']) {
		assert.throws(
			() => deno_install({ version: '2.8.2', bin_path }),
			/deno_install: bin_path .* must be an absolute path/,
			bin_path
		);
	}
});

describe('fuz_app env recipes', () => {
	// What an env file can hold: everything HOSTILE does but the `'` and the line
	// break, which systemd's `EnvironmentFile=` reads differently from a shell.
	const ENV_HOSTILE = HOSTILE.replaceAll("'", '').replaceAll('\n', ' ');

	test("OpenRC's env file reader reads each value back literally", () => {
		const { dir, run } = create_shell();
		const env = join(dir, 'env');
		writeFileSync(
			env,
			// the role and database are names in a URL, refused unless plain
			fuz_app_env_base({
				user: 'app',
				service: 'app',
				config_dir: ENV_HOSTILE,
				port: '4040',
				cookie_keys: 'keys'
			}).template + fuz_app_trusted_proxies({ env_prefix: 'FORGE', value: ENV_HOSTILE })
		);
		const init = join(dir, 'init');
		writeFileSync(
			init,
			hardened_openrc_service({
				name: 'svc',
				description: 'svc',
				command: '/usr/bin/svc',
				user: 'svc',
				env_file: env
			})
		);
		assert.deepEqual(
			run(
				`. ${single_quote(init)}; eval "$_zap_env_load"; record() { sudo "$1"; }; _zap_env_read record`
			),
			[
				['sudo', 'NODE_ENV=production'],
				['sudo', 'PORT={{port}}'],
				['sudo', 'HOST=127.0.0.1'],
				['sudo', 'DATABASE_URL=postgres://app@/app?host=/run/postgresql'],
				['sudo', 'SECRET_FUZ_COOKIE_KEYS={{cookie_keys}}'],
				['sudo', `FUZ_BOOTSTRAP_TOKEN_PATH=${ENV_HOSTILE}/secret_bootstrap_token`],
				['sudo', `FUZ_FORGE_TRUSTED_PROXIES=${ENV_HOSTILE}`]
			]
		);
	});

	test('a value holding a quote or a line break is refused, by field', () => {
		const base = {
			user: 'app',
			service: 'app',
			config_dir: '/home/app/.app',
			port: '4040',
			cookie_keys: 'keys'
		};
		for (const bad of ["it's", 'two\nlines', 'cr\r', 'nul\0']) {
			for (const field of ['user', 'service', 'config_dir'] as const) {
				assert.throws(
					() => fuz_app_env_base({ ...base, [field]: bad }),
					new RegExp(`fuz_app_env_base: ${field} .* must hold no ' or line break`),
					`${field} ${JSON.stringify(bad)}`
				);
			}
			assert.throws(
				() => fuz_app_trusted_proxies({ env_prefix: 'FORGE', value: bad }),
				/fuz_app_trusted_proxies: value .* must hold no ' or line break/,
				JSON.stringify(bad)
			);
		}
	});

	test('an env_prefix that is not part of a name is refused', () => {
		for (const env_prefix of ['', 'A B', 'X=1\nY', 'A-B']) {
			assert.throws(
				() => fuz_app_trusted_proxies({ env_prefix }),
				/fuz_app_trusted_proxies: env_prefix/,
				env_prefix
			);
		}
	});
});
