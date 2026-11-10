import { assert, test } from 'vitest';

import { env_ref } from '#lib/env_ref.ts';
import {
	alpine_certbot_reload_nginx_hook,
	alpine_certbot_renew_cron,
	alpine_certbot_standalone_issue,
	alpine_periodic_daily_file
} from '#lib/recipe_alpine_certbot.ts';

const domain = env_ref('DEPLOY_DOMAIN');
const email = env_ref('DEPLOY_CERTBOT_EMAIL');
const expected_addresses = [env_ref('DEPLOY_HOST')];

test('alpine_certbot_standalone_issue stops nginx via OpenRC, then issues', () => {
	const script = alpine_certbot_standalone_issue({
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
		`zap_certbot_dns_preflight 1 '${env_ref('DEPLOY_HOST')}' '${domain}' 'www.example.org' && { sudo rc-service nginx stop || true; } && sudo certbot certonly --standalone -d '${domain}' -d 'www.example.org' --non-interactive --agree-tos --email '${env_ref('DEPLOY_CERTBOT_EMAIL')}'`
	);
});

test('alpine_certbot_renew_cron renews and leaves the reload to the deploy hook', () => {
	assert.equal(
		alpine_certbot_renew_cron(),
		`#!/bin/sh
# Managed by zap — daily certbot renewal (Alpine ships no certbot.timer).
certbot renew --quiet
`
	);
});

test('alpine_certbot_reload_nginx_hook reloads a started nginx via OpenRC', () => {
	assert.deepEqual(alpine_certbot_reload_nginx_hook(), {
		path: '/etc/letsencrypt/renewal-hooks/deploy/reload-nginx',
		mode: '755',
		content: {
			type: 'inline',
			content: `#!/bin/sh
# Managed by zap — certbot runs this after it renews a certificate.
exec /sbin/rc-service --ifstarted nginx reload
`
		}
	});
});

test('alpine_certbot_reload_nginx_hook takes a file name', () => {
	assert.equal(
		alpine_certbot_reload_nginx_hook({ name: 'nginx' }).path,
		'/etc/letsencrypt/renewal-hooks/deploy/nginx'
	);
	assert.throws(() => alpine_certbot_reload_nginx_hook({ name: 'reload.sh' }), /letters, digits/);
});

test('alpine_periodic_daily_file places a job under /etc/periodic/daily mode 755', () => {
	const body = alpine_certbot_renew_cron();
	const file = alpine_periodic_daily_file({ name: 'certbot-renew', body });

	assert.equal(file.path, '/etc/periodic/daily/certbot-renew');
	assert.equal(file.mode, '755');
	assert.deepEqual(file.content, { type: 'inline', content: body });
});

test('alpine_periodic_daily_file refuses a name run-parts would skip or that leaves the directory', () => {
	for (const name of ['', 'a/b', '../x', 'renew.sh', 'a b']) {
		assert.throws(
			() => alpine_periodic_daily_file({ name, body: '' }),
			/alpine_periodic_daily_file: name .*\(run-parts skips any other name\)/,
			name
		);
	}
});
