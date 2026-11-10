import { spawnSync } from 'node:child_process';
import { chmodSync, mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { assert, test } from 'vitest';

import { env_ref } from '#lib/env_ref.ts';
import { fuz_app_bootstrap_token } from '#lib/recipe_fuz_app_bootstrap.ts';

const options = {
	user: 'app',
	service: 'app',
	config_dir: '/home/app/.fuz_forge'
};

test('reproduces the fuz_app bootstrap-token script byte-for-byte', () => {
	const script = fuz_app_bootstrap_token(options);

	assert.equal(
		script.check,
		`sudo test -f '/home/app/.fuz_forge/secret_bootstrap_token' ` +
			`-a ! -h '/home/app/.fuz_forge/secret_bootstrap_token' ` +
			`-a -s '/home/app/.fuz_forge/secret_bootstrap_token' || ` +
			`psql -d 'app' -tAc "SELECT bootstrapped FROM bootstrap_lock WHERE id = 1" ` +
			`2>/dev/null | grep -qx t`
	);

	assert.equal(
		script.run,
		`set -e
umask 077
token=$(openssl rand -hex 32)
printf '%s\\n' "$token" | sudo -u 'app' tee '/home/app/.fuz_forge/secret_bootstrap_token' > /dev/null
sudo -u 'app' chmod 600 '/home/app/.fuz_forge/secret_bootstrap_token'
echo "Bootstrap token created"`
	);
});

/**
 * The `test` programs `sudo test` can reach on the supported distros: GNU coreutils'
 * on Debian, BusyBox's on Alpine. A missing one is left out, and the test says so.
 */
const test_programs = (): Array<[string, string]> => {
	const programs: Array<[string, string]> = [];
	// coreutils' `test` takes `--version` as a string to test; its `[` prints the version
	if (spawnSync('/usr/bin/[', ['--version'], { encoding: 'utf8' }).stdout?.includes('coreutils')) {
		programs.push(['coreutils', 'exec /usr/bin/test "$@"']);
	}
	if (spawnSync('busybox', ['--list'], { encoding: 'utf8' }).stdout?.split('\n').includes('test')) {
		programs.push(['busybox', 'exec busybox test "$@"']);
	}
	return programs;
};

test('the check reads converged only for a non-empty regular file, never through a link', ({
	onTestFinished
}) => {
	const dir = mkdtempSync(join(tmpdir(), 'zap-recipe-bootstrap-'));
	onTestFinished(() => rmSync(dir, { recursive: true, force: true }));
	const bin = join(dir, 'bin');
	mkdirSync(bin);
	// `sudo` runs its command as given; the database probe finds no row
	const stand_in = (name: string, body: string) => {
		writeFileSync(join(bin, name), `#!/bin/sh\n${body}\n`);
		chmodSync(join(bin, name), 0o755);
	};
	stand_in('sudo', 'exec "$@"');
	stand_in('psql', 'exit 1');
	const files = join(dir, 'files');
	mkdirSync(files);
	writeFileSync(join(files, 'full'), 'token\n');
	writeFileSync(join(files, 'empty'), '');
	mkdirSync(join(files, 'dir'));
	const cases: Array<[string, (path: string) => void, boolean]> = [
		['a regular file', (p) => writeFileSync(p, 'token\n'), true],
		['an empty file', (p) => writeFileSync(p, ''), false],
		['a link to a regular file', (p) => symlinkSync(join(files, 'full'), p), false],
		['a link to an empty file', (p) => symlinkSync(join(files, 'empty'), p), false],
		['a dangling link', (p) => symlinkSync(join(files, 'nothing'), p), false],
		['a directory', (p) => mkdirSync(p), false],
		['a link to a directory', (p) => symlinkSync(join(files, 'dir'), p), false],
		['nothing', () => {}, false]
	];
	const programs = test_programs();
	assert.ok(programs.length > 0, 'no `test` program to check against');
	if (programs.length < 2) console.warn(`checked only under ${programs.map(([n]) => n)}`);
	for (const [program, body] of programs) {
		stand_in('test', body);
		for (const [i, [label, make, converged]] of cases.entries()) {
			const config_dir = join(dir, `${program}-${i}`);
			mkdirSync(config_dir);
			make(join(config_dir, 'secret_bootstrap_token'));
			const { check } = fuz_app_bootstrap_token({ ...options, config_dir });
			const result = spawnSync('sh', ['-c', check], {
				encoding: 'utf8',
				env: { PATH: `${bin}:${process.env.PATH}` }
			});
			assert.equal(result.error, undefined);
			assert.equal(result.status === 0, converged, `${program}: ${label}: ${result.stderr}`);
		}
	}
});

test('psql_args defaults to peer/trust auth as the service role', () => {
	const script = fuz_app_bootstrap_token(options);
	assert.ok(script.check.includes("psql -d 'app' -tAc"), 'default `-d <service>`');
});

test('psql_args override threads into the fallback probe', () => {
	const script = fuz_app_bootstrap_token({
		...options,
		psql_args: '-U app -h localhost -d app'
	});
	assert.ok(
		script.check.includes('psql -U app -h localhost -d app -tAc'),
		'explicit TCP form replaces the default'
	);
});

test('the token path and owner track the options', () => {
	const script = fuz_app_bootstrap_token({
		user: 'deploy',
		service: 'forge',
		config_dir: '/srv/forge'
	});
	assert.ok(
		script.run.includes("'/srv/forge/secret_bootstrap_token'"),
		'token path is <config_dir>/secret_bootstrap_token'
	);
	assert.ok(
		script.run.includes("sudo -u 'deploy' tee '/srv/forge/secret_bootstrap_token'"),
		'the service user writes the token'
	);
	assert.ok(!script.run.includes('chown'), 'no root write to hand over');
});

test('refuses a `user` sudo would read as a uid', () => {
	assert.throws(
		() => fuz_app_bootstrap_token({ ...options, user: '#0' }),
		/fuz_app_bootstrap_token: user "#0"/
	);
	assert.throws(
		() => fuz_app_bootstrap_token({ ...options, user: '#1000' }),
		/fuz_app_bootstrap_token: user "#1000"/
	);
	assert.throws(
		() => fuz_app_bootstrap_token({ ...options, user: '#-1' }),
		/fuz_app_bootstrap_token: user "#-1"/
	);
});

test('refuses a `user` that is a reference, whose value sudo could read as a uid', () => {
	for (const user of [env_ref('APP_USER'), `app${env_ref('SUFFIX')}`]) {
		assert.throws(
			() => fuz_app_bootstrap_token({ ...options, user }),
			/fuz_app_bootstrap_token: user must be written out, not a reference/
		);
	}
});

test('refuses an empty `user`', () => {
	assert.throws(
		() => fuz_app_bootstrap_token({ ...options, user: '' }),
		/fuz_app_bootstrap_token: user ""/
	);
});

test('accepts a `user` holding `#` past its first character', () => {
	assert.doesNotThrow(() => fuz_app_bootstrap_token({ ...options, user: 'app#1' }));
});

test('refuses a relative `config_dir`', () => {
	for (const config_dir of ['home/app/.fuz_forge', './srv', '~/.fuz_forge', '']) {
		assert.throws(
			() => fuz_app_bootstrap_token({ ...options, config_dir }),
			/fuz_app_bootstrap_token: config_dir .* must be an absolute path/,
			config_dir
		);
	}
});
