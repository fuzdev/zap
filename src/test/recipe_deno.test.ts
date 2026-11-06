import { assert, test } from 'vitest';

import { env_ref } from '#lib/env_ref.ts';
import { deno_install } from '#lib/recipe_deno.ts';

const version = '2.8.2';

test('deno_install pins the check to the exact version at bin_path', () => {
	const script = deno_install({
		version,
		bin_path: '/usr/local/bin/deno',
		privileged: true
	});

	assert.equal(
		script.check,
		`'/usr/local/bin/deno' --version 2>/dev/null | grep -q '^deno 2.8.2 '`
	);
});

test('privileged install sudoes into the system dir', () => {
	const script = deno_install({
		version,
		bin_path: '/usr/local/bin/deno',
		privileged: true
	});

	assert.equal(
		script.run,
		`set -e
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
curl -fsSL -o "$tmp/deno.zip" 'https://github.com/denoland/deno/releases/download/v2.8.2/deno-x86_64-unknown-linux-gnu.zip'
unzip -q -o "$tmp/deno.zip" -d "$tmp"
chmod 0755 "$tmp" "$tmp/deno"
sudo install -D -m 755 "$tmp/deno" '/usr/local/bin/deno'
'/usr/local/bin/deno' --version`
	);
});

test('user install installs and runs the binary only as the service user', () => {
	const script = deno_install({
		version,
		bin_path: '/home/app/.deno/bin/deno',
		user: 'app'
	});

	// the service user owns the binary and could replace it, so the connecting user,
	// who has sudo, never runs it: not in the check, not after the install
	assert.equal(
		script.check,
		`sudo -u 'app' '/home/app/.deno/bin/deno' --version 2>/dev/null | grep -q '^deno 2.8.2 '`
	);
	assert.match(
		script.run,
		/\nsudo -u 'app' install -D -m 755 "\$tmp\/deno" '\/home\/app\/\.deno\/bin\/deno'\nsudo -u 'app' '\/home\/app\/\.deno\/bin\/deno' --version$/
	);
	for (const line of `${script.check}\n${script.run}`.split('\n')) {
		if (line.includes("'/home/app/.deno/bin/deno' --version")) {
			assert.ok(line.startsWith("sudo -u 'app' "), line);
		}
	}
});

test('refuses a `user` sudo would not read as the account', () => {
	for (const user of ['', '#0', '#1000', env_ref('DENO_USER'), `app${env_ref('X')}`]) {
		assert.throws(
			() => deno_install({ version, bin_path: '/home/app/.deno/bin/deno', user }),
			/^deno_install: user /
		);
	}
	assert.doesNotThrow(() =>
		deno_install({ version, bin_path: '/home/app/.deno/bin/deno', user: 'app#1' })
	);
});

test('same-user install needs no sudo (no user, not privileged)', () => {
	const script = deno_install({ version, bin_path: '/home/u/.deno/bin/deno' });

	assert.match(script.run, /\ninstall -D -m 755 "\$tmp\/deno" '\/home\/u\/\.deno\/bin\/deno'\n/);
	assert.notMatch(script.run, /sudo/);
});

test('target triple is overridable, defaulting to x86_64 linux gnu', () => {
	assert.match(
		deno_install({ version, bin_path: '/usr/local/bin/deno' }).run,
		/deno-x86_64-unknown-linux-gnu\.zip/
	);
	assert.match(
		deno_install({
			version,
			bin_path: '/usr/local/bin/deno',
			target: 'aarch64-unknown-linux-gnu'
		}).run,
		/deno-aarch64-unknown-linux-gnu\.zip/
	);
});
