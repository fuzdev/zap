import { assert, test } from 'vitest';

import { debian_web_firewall } from '#lib/recipe_debian_firewall.ts';

test('debian_web_firewall builds a ufw firewall with the baseline allow set', () => {
	assert.deepEqual(debian_web_firewall(), {
		backend: 'ufw',
		allow: [
			{ port: 22, proto: 'tcp' },
			{ port: 80, proto: 'tcp' },
			{ port: 443, proto: 'tcp' }
		]
	});
});

test('allow_extra threads through to the ufw allow list', () => {
	assert.deepEqual(
		debian_web_firewall({ allow_extra: [{ port: 25, proto: 'tcp' }] }).allow.at(-1),
		{
			port: 25,
			proto: 'tcp'
		}
	);
});
