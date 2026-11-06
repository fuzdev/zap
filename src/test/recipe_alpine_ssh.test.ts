import { assert, test } from 'vitest';

import { alpine_ssh_service } from '#lib/recipe_alpine_ssh.ts';

test("alpine_ssh_service runs OpenRC's sshd service, reloading on the given ids", () => {
	// only the service name differs from Debian (OpenRC `sshd`, not systemd `ssh`)
	assert.deepEqual(alpine_ssh_service({ reload_on: ['ssh-hardened-config', 'other'] }), {
		service: 'sshd',
		enabled: true,
		running: true,
		reload_on: ['ssh-hardened-config', 'other']
	});
});
