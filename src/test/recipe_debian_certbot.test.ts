import { assert, test } from 'vitest';

import { env_ref } from '#lib/env_ref.ts';
import {
	debian_certbot_reload_nginx_hook,
	debian_certbot_standalone_issue
} from '#lib/recipe_debian_certbot.ts';

const domain = env_ref('DEPLOY_DOMAIN');
const email = env_ref('DEPLOY_CERTBOT_EMAIL');
const expected_addresses = [env_ref('DEPLOY_HOST')];

test('debian_certbot_standalone_issue stops nginx via systemd, then issues', () => {
	const script = debian_certbot_standalone_issue({
		domain,
		email,
		expected_addresses,
		extra_domains: ['www.example.org']
	});

	assert.equal(script.check, `sudo test -f '/etc/letsencrypt/live/${domain}/fullchain.pem'`);
	const call = script.run.slice(script.run.lastIndexOf('\n}\n') + 3);
	assert.ok(script.run.startsWith('zap_certbot_dns_preflight() {\n'), script.run);
	assert.equal(
		call,
		`zap_certbot_dns_preflight 1 '${env_ref('DEPLOY_HOST')}' '${domain}' 'www.example.org' && { sudo systemctl stop nginx || true; } && sudo certbot certonly --standalone -d '${domain}' -d 'www.example.org' --non-interactive --agree-tos --email '${env_ref('DEPLOY_CERTBOT_EMAIL')}'`
	);
});

test('debian_certbot_reload_nginx_hook reloads a running nginx via systemd', () => {
	assert.deepEqual(debian_certbot_reload_nginx_hook(), {
		path: '/etc/letsencrypt/renewal-hooks/deploy/reload-nginx',
		mode: '755',
		content: {
			type: 'inline',
			content: `#!/bin/sh
# Managed by zap — certbot runs this after it renews a certificate.
exec systemctl try-reload-or-restart nginx
`
		}
	});
});

test('debian_certbot_reload_nginx_hook takes a file name', () => {
	assert.equal(
		debian_certbot_reload_nginx_hook({ name: '10-nginx' }).path,
		'/etc/letsencrypt/renewal-hooks/deploy/10-nginx'
	);
});
