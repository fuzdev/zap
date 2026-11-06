import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { assert, test } from 'vitest';

import {
	LINK_PROTECTION_SYSCTL_PATH,
	LINK_PROTECTION_SYSCTLS,
	sysctl_apply,
	sysctl_conf,
	type SysctlValues
} from '#lib/recipe_sysctl.ts';

test('the link protections are the four systemd ships', () => {
	assert.deepEqual(LINK_PROTECTION_SYSCTLS, {
		'fs.protected_hardlinks': '1',
		'fs.protected_symlinks': '1',
		'fs.protected_fifos': '1',
		'fs.protected_regular': '2'
	});
	assert.equal(LINK_PROTECTION_SYSCTL_PATH, '/etc/sysctl.d/60-link-protection.conf');
});

test('sysctl_conf writes one line per parameter, persisted under sysctl.d', () => {
	assert.equal(
		sysctl_conf(LINK_PROTECTION_SYSCTLS),
		`# Managed by zap
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
fs.protected_fifos = 1
fs.protected_regular = 2
`
	);
});

test('sysctl_apply checks the live values and loads the file when one differs', () => {
	const script = sysctl_apply(LINK_PROTECTION_SYSCTL_PATH, {
		'fs.protected_hardlinks': '1',
		'fs.protected_regular': '2'
	});
	const check =
		"test \"$(tr -s '\\t ' '  ' < '/proc/sys/fs/protected_hardlinks')\" = '1' && test \"$(tr -s '\\t ' '  ' < '/proc/sys/fs/protected_regular')\" = '2'";
	assert.equal(script.check, check);
	assert.equal(
		script.run,
		`set -e\nsudo sysctl -p '/etc/sysctl.d/60-link-protection.conf' >/dev/null\n${check}`
	);
});

test('refuses a parameter or value that is not one', () => {
	const cases: Array<SysctlValues> = [
		{},
		{ 'fs.protected_hardlinks\nkernel.x': '1' },
		{ protected_hardlinks: '1' },
		{ 'fs/protected_hardlinks': '1' },
		{ 'fs.protected_hardlinks': '1\nkernel.modules_disabled = 0' },
		{ 'fs.protected_hardlinks': '' },
		{ 'fs.protected_hardlinks': "1'" }
	];
	for (const values of cases) {
		assert.throws(() => sysctl_conf(values), /sysctl_conf/, JSON.stringify(values));
		assert.throws(() => sysctl_apply('/etc/sysctl.d/x.conf', values), /sysctl_apply/);
	}
	assert.throws(() => sysctl_apply('x.conf', LINK_PROTECTION_SYSCTLS), /must be absolute/);
});

/** Whether `check` passes in a real shell, against this machine's `/proc/sys`. */
const passes = (check: string): boolean => {
	try {
		execFileSync('sh', ['-c', check], { stdio: 'pipe' });
		return true;
	} catch {
		return false;
	}
};

test('the check passes against the live value, a multi-value one read with its tabs', () => {
	const key = 'net.ipv4.ip_local_port_range';
	const raw = readFileSync('/proc/sys/net/ipv4/ip_local_port_range', 'utf8');
	assert.ok(
		raw.includes('\t'),
		`/proc/sys separates the values with a tab: ${JSON.stringify(raw)}`
	);
	const live = raw.trim().split(/\s+/).join(' ');
	assert.ok(passes(sysctl_apply('/etc/sysctl.d/x.conf', { [key]: live }).check), live);
	const [low, high] = live.split(' ').map(Number);
	assert.ok(!passes(sysctl_apply('/etc/sysctl.d/x.conf', { [key]: `${low! + 1} ${high}` }).check));
	const hardlinks = readFileSync('/proc/sys/fs/protected_hardlinks', 'utf8').trim();
	assert.ok(
		passes(sysctl_apply('/etc/sysctl.d/x.conf', { 'fs.protected_hardlinks': hardlinks }).check)
	);
});
