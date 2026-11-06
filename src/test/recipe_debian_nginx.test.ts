import { assert, test } from 'vitest';

import { debian_nginx_spa_site, debian_nginx_catch_all } from '#lib/recipe_debian_nginx.ts';
import { nginx_catch_all_server, SSL_PARAMS_PATH } from '#lib/recipe_nginx.ts';

const CSP = "default-src 'self'";

test('debian_nginx_spa_site wires the Debian snippets SSL include', () => {
	const site = debian_nginx_spa_site({
		domain: 'app.example.com',
		port: '4040',
		root: '/srv/build',
		csp: CSP
	}).template;

	assert.ok(
		site.includes('    include /etc/nginx/snippets/ssl_params.conf;\n'),
		'Debian snippets include'
	);
	assert.ok(!site.includes('/etc/nginx/http.d/'), 'no Alpine http.d path');
});

test('debian_nginx_catch_all removes the stock default and adds a catch-all after it', () => {
	const { remove_default, catch_all } = debian_nginx_catch_all();

	assert.equal(
		remove_default.check,
		"test ! -e '/etc/nginx/sites-enabled/default' && test ! -L '/etc/nginx/sites-enabled/default' && test -e '/etc/nginx/nginx.conf'"
	);
	assert.equal(
		remove_default.run,
		`set -e
sudo rm -f -- '/etc/nginx/sites-enabled/default'
sudo nginx -t`
	);
	assert.equal(catch_all.path, '/etc/nginx/conf.d/00-catch-all.conf');
	assert.equal(catch_all.validate, 'sudo nginx -t');
	assert.deepEqual(catch_all.content, {
		type: 'inline',
		content: nginx_catch_all_server({ ssl_snippet_path: SSL_PARAMS_PATH })
	});
	// the site's SSL parameters, which the default server's handshakes start from
	const text = catch_all.content.type === 'inline' ? catch_all.content.content : '';
	assert.ok(text.includes(`\n    include ${SSL_PARAMS_PATH};\n`), text);
	const certbot = debian_nginx_catch_all({ ssl: 'certbot' }).catch_all.content;
	assert.ok(
		certbot.type === 'inline' &&
			certbot.content.includes('\n    include /etc/letsencrypt/options-ssl-nginx.conf;\n') &&
			!certbot.content.includes(SSL_PARAMS_PATH),
		JSON.stringify(certbot)
	);
});
