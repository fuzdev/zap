import { assert, test } from 'vitest';

import { debian_ssh_service } from '#lib/recipe_debian_ssh.ts';

test("debian_ssh_service runs systemd's ssh unit, reloading on the given ids", () => {
	assert.deepEqual(debian_ssh_service({ reload_on: ['ssh-hardened-config'] }), {
		service: 'ssh',
		enabled: true,
		running: true,
		reload_on: ['ssh-hardened-config']
	});
});
