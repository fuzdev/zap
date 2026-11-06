import { assert, test } from 'vitest';

import { web_firewall_allow_rules } from '#lib/recipe_firewall.ts';

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
