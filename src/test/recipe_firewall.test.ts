import { assert, test } from 'vitest';

import { alpine_web_firewall } from '#lib/recipe_alpine_firewall.ts';
import { debian_web_firewall } from '#lib/recipe_debian_firewall.ts';
import { fail2ban_jail } from '#lib/recipe_fail2ban.ts';
import { WEB_FIREWALL_ALLOW, web_firewall_allow_rules } from '#lib/recipe_firewall.ts';
import { ssh_hardening_verify } from '#lib/recipe_ssh.ts';

test('web_firewall_allow_rules is the SSH/HTTP/HTTPS baseline as ports', () => {
	assert.deepEqual(web_firewall_allow_rules(), [
		{ port: 22, proto: 'tcp' },
		{ port: 80, proto: 'tcp' },
		{ port: 443, proto: 'tcp' }
	]);
});

test('allow_extra is appended after the baseline', () => {
	assert.deepEqual(web_firewall_allow_rules({ allow_extra: [{ port: 9090, proto: 'tcp' }] }), [
		{ port: 22, proto: 'tcp' },
		{ port: 80, proto: 'tcp' },
		{ port: 443, proto: 'tcp' },
		{ port: 9090, proto: 'tcp' }
	]);
});

test('returns a fresh array — the baseline const is not mutated', () => {
	web_firewall_allow_rules().push({ port: 1, proto: 'tcp' });
	assert.equal(web_firewall_allow_rules().length, 3);
});

test('ssh_port moves the SSH rule, and is refused unless a port', () => {
	assert.deepEqual(web_firewall_allow_rules({ ssh_port: 2222 }), [
		{ port: 2222, proto: 'tcp' },
		{ port: 80, proto: 'tcp' },
		{ port: 443, proto: 'tcp' }
	]);
	assert.deepEqual(web_firewall_allow_rules({ ssh_port: 22 }), [...WEB_FIREWALL_ALLOW]);
	for (const ssh_port of [0, 65536, 2.5]) {
		assert.throws(
			() => web_firewall_allow_rules({ ssh_port }),
			/web_firewall_allow_rules: ssh_port .* must be a port/
		);
	}
});

test('one ssh_port reaches the firewall, the fail2ban jail, and the ssh verify alike', () => {
	const ssh = { ssh_port: 2222 };
	for (const firewall of [debian_web_firewall(ssh), alpine_web_firewall(ssh).firewall]) {
		assert.deepEqual(firewall.allow?.[0], { port: 2222, proto: 'tcp' });
		assert.ok(!firewall.allow?.some((rule) => typeof rule !== 'string' && rule.port === 22));
	}
	assert.include(fail2ban_jail(ssh), '\n[sshd]\nenabled = true\nport = 2222\n');
	for (const assertion of ssh_hardening_verify({ user: 'svc', ...ssh }).assertions) {
		assert.ok(assertion.type === 'command');
		assert.include(assertion.run, ',lport=2222');
	}
});
