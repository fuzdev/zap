import { assert, test } from 'vitest';

import { alpine_web_firewall } from '#lib/recipe_alpine_firewall.ts';

test('alpine_web_firewall returns an nftables firewall + a persistence service', () => {
	const fw = alpine_web_firewall();

	assert.deepEqual(fw.firewall, {
		backend: 'nftables',
		allow: [
			{ port: 22, proto: 'tcp' },
			{ port: 80, proto: 'tcp' },
			{ port: 443, proto: 'tcp' }
		]
	});
	// the companion service the plan-time validator requires for boot persistence
	assert.deepEqual(fw.service, { service: 'nftables', enabled: true, running: true });
});

test('allow_extra threads into the nftables rules', () => {
	const fw = alpine_web_firewall({ allow_extra: [{ port: 9090, proto: 'tcp' }] });
	assert.deepEqual(fw.firewall.allow.at(-1), { port: 9090, proto: 'tcp' });
});
