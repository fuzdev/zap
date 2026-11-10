import { spawnSync } from 'node:child_process';
import { chmodSync, existsSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { assert, test } from 'vitest';

import {
	SSHD_VALIDATE,
	ssh_hardening,
	ssh_hardening_verify,
	ssh_service_core,
	to_ssh_port
} from '#lib/recipe_ssh.ts';

test('reproduces the reference SSH_HARDENED_CONFIG byte-for-byte', () => {
	const config = ssh_hardening({ user: 'fuz_forge' });

	const expected = `# SSH hardened - root login disabled, only deploy user allowed
PermitRootLogin no
AllowUsers fuz_forge

# Disable password authentication (key-only)
PasswordAuthentication no
KbdInteractiveAuthentication no

# Other hardening
X11Forwarding no
MaxAuthTries 3
LoginGraceTime 20
`;

	assert.equal(config, expected);
});

test('AllowUsers reflects the user input', () => {
	const config = ssh_hardening({ user: 'app' });
	assert.ok(config.includes('AllowUsers app'), 'AllowUsers is the input user');
});

test('max_auth_tries and login_grace_time render when overridden', () => {
	const config = ssh_hardening({
		user: 'svc',
		max_auth_tries: 5,
		login_grace_time: 30
	});
	assert.ok(config.includes('MaxAuthTries 5'), 'MaxAuthTries from input');
	assert.ok(config.includes('LoginGraceTime 30'), 'LoginGraceTime from input');
});

test('applies the default tunables', () => {
	const config = ssh_hardening({ user: 'svc' });
	assert.ok(config.includes('MaxAuthTries 3'), 'MaxAuthTries default');
	assert.ok(config.includes('LoginGraceTime 20'), 'LoginGraceTime default');
});

test('SSHD_VALIDATE is `sudo sshd -t`', () => {
	assert.equal(SSHD_VALIDATE, 'sudo sshd -t');
});

// The config sshd applies to the allowed user's login, `Match` blocks included.
const EFFECTIVE = "sudo sshd -T -C 'user=fuz_forge,host=192.0.2.1,addr=192.0.2.1,lport=22'";

test('ssh_hardening_verify asserts each hardened line of the effective config', () => {
	const grep = (line: string) => ({
		type: 'command' as const,
		run: `${EFFECTIVE} | grep -qxF '${line}'`
	});
	assert.deepEqual(ssh_hardening_verify({ user: 'fuz_forge' }), {
		assertions: [
			grep('permitrootlogin no'),
			grep('passwordauthentication no'),
			grep('kbdinteractiveauthentication no'),
			grep('x11forwarding no'),
			{
				type: 'command',
				run: `test "$(${EFFECTIVE} | grep '^allowusers ')" = 'allowusers fuz_forge'`
			},
			grep('maxauthtries 3'),
			grep('logingracetime 20')
		]
	});
});

/** Whether `user`'s `AllowUsers` assertion passes when `sshd -T` prints `effective`. */
const allow_passes = (user: string, effective: string): boolean => {
	const allow = ssh_hardening_verify({ user }).assertions.find(
		(a) => a.type === 'command' && a.run.includes('allowusers')
	);
	assert.ok(allow?.type === 'command');
	const dir = mkdtempSync(join(tmpdir(), 'zap-ssh-verify-'));
	// A `sudo` stand-in that prints the effective config given in `SSHD_T`.
	writeFileSync(join(dir, 'sudo'), '#!/bin/sh\nprintf %s "$SSHD_T"\n');
	chmodSync(join(dir, 'sudo'), 0o755);
	const status = spawnSync('sh', ['-c', allow.run], {
		cwd: dir,
		env: { PATH: `${dir}:${process.env.PATH}`, SSHD_T: effective }
	}).status;
	assert.ok(!existsSync(join(dir, 'canary')), `a user name ran as code: ${user}`);
	return status === 0;
};

test('ssh_hardening_verify passes only when the user is the one allowed', () => {
	const passes = (effective: string) => allow_passes('fuz_forge', effective);
	assert.ok(passes('port 22\nallowusers fuz_forge\nmaxauthtries 3\n'));
	// Another drop-in's `AllowUsers` adds a user: sshd allows both.
	assert.ok(!passes('allowusers fuz_forge\nallowusers other\n'));
	assert.ok(!passes('allowusers other\nallowusers fuz_forge\n'));
	assert.ok(!passes('allowusers other\n'));
	assert.ok(!passes('port 22\n'), 'no AllowUsers allows everyone');
	assert.ok(!passes(''), 'sshd -T printing nothing');
	// The `$` an account name may end in is compared as text, not expanded.
	assert.ok(allow_passes('svc$', 'allowusers svc$\n'));
	assert.ok(!allow_passes('svc$', 'allowusers svc\n'));
});

test('ssh_hardening and ssh_hardening_verify refuse a user that is not an account name', () => {
	for (const user of [
		'',
		'a b',
		'a\tb',
		'a\nb',
		' a',
		// sshd patterns, which would allow other accounts
		'*',
		'a*',
		'a?',
		'!a',
		// a `user@host` entry limits by client; a `,` would add a key to the
		// verify's connection spec
		'a@10.0.0.1',
		'a,addr=10.0.0.1',
		'a,',
		// a uid, and a name a shell would read as code
		'0',
		'#0',
		"it's",
		'a$(touch canary)',
		// the schema's account names are lowercase
		'Svc',
		'SVC',
		'svc_A'
	]) {
		for (const recipe of [ssh_hardening, ssh_hardening_verify]) {
			assert.throws(
				() => recipe({ user }),
				/ssh_hardening: user .* must be an account name/,
				JSON.stringify(user)
			);
		}
	}
	for (const user of ['svc', '_svc', 'svc-1', 'svc_2', 'svc$']) {
		ssh_hardening({ user });
		ssh_hardening_verify({ user });
	}
});

test('ssh_port is the port the verify connects on, and the drop-in sets none', () => {
	for (const assertion of ssh_hardening_verify({ user: 'svc', ssh_port: 2222 }).assertions) {
		assert.ok(assertion.type === 'command');
		assert.include(assertion.run, "'user=svc,host=192.0.2.1,addr=192.0.2.1,lport=2222'");
	}
	assert.equal(ssh_hardening({ user: 'svc', ssh_port: 2222 }), ssh_hardening({ user: 'svc' }));
	assert.notMatch(ssh_hardening({ user: 'svc', ssh_port: 2222 }), /^port/im);
	assert.equal(to_ssh_port('r'), 22);
	assert.equal(to_ssh_port('r', { ssh_port: 65535 }), 65535);
	for (const ssh_port of [0, -22, 65536, 22.5, Number.NaN]) {
		assert.throws(
			() => ssh_hardening_verify({ user: 'svc', ssh_port }),
			/ssh_hardening: ssh_port .* must be a port/,
			String(ssh_port)
		);
	}
	// a string, as an untyped config might pass, is refused and shown quoted
	const loose = { user: 'svc', ssh_port: '22' } as unknown as { user: string; ssh_port: number };
	assert.throws(() => ssh_hardening_verify(loose), /ssh_hardening: ssh_port "22" must be a port/);
	assert.throws(() => to_ssh_port('r', { ssh_port: 2.5 }), /^r: ssh_port 2\.5 must be a port/);
});

test('ssh_hardening_verify reads the config sshd applies to the allowed user, Match blocks included', () => {
	for (const assertion of ssh_hardening_verify({ user: 'svc' }).assertions) {
		assert.ok(assertion.type === 'command');
		assert.ok(
			assertion.run.includes(
				"sudo sshd -T -C 'user=svc,host=192.0.2.1,addr=192.0.2.1,lport=22' | "
			),
			assertion.run
		);
		assert.ok(!assertion.run.includes('sshd -T |'), assertion.run);
	}
});

test('ssh_hardening_verify asserts the tunables the drop-in was given', () => {
	const options = { user: 'svc', max_auth_tries: 5, login_grace_time: 30 };
	const runs = ssh_hardening_verify(options).assertions.map((a) =>
		a.type === 'command' ? a.run : ''
	);
	const config = ssh_hardening(options);
	assert.ok(config.includes('MaxAuthTries 5') && config.includes('LoginGraceTime 30'));
	const effective = "sudo sshd -T -C 'user=svc,host=192.0.2.1,addr=192.0.2.1,lport=22'";
	assert.ok(runs.includes(`${effective} | grep -qxF 'maxauthtries 5'`), 'MaxAuthTries');
	assert.ok(runs.includes(`${effective} | grep -qxF 'logingracetime 30'`), 'LoginGraceTime');
});

test('ssh_hardening_verify matches the user name as one quoted word', () => {
	const runs = ssh_hardening_verify({ user: 'svc$' }).assertions.map((a) =>
		a.type === 'command' ? a.run : ''
	);
	assert.ok(
		runs.includes(
			`test "$(sudo sshd -T -C 'user=svc$,host=192.0.2.1,addr=192.0.2.1,lport=22' | grep '^allowusers ')" = 'allowusers svc$'`
		),
		runs.join('\n')
	);
});

test('ssh_hardening leaves UsePAM to the distro', () => {
	assert.ok(!/usepam/i.test(ssh_hardening({ user: 'svc' })));
});

test('ssh_service_core keeps sshd enabled and running, reloading on the given ids', () => {
	assert.deepEqual(ssh_service_core('sshd', { reload_on: ['a', 'b'] }), {
		service: 'sshd',
		enabled: true,
		running: true,
		reload_on: ['a', 'b']
	});
});
