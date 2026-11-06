import { assert, test } from 'vitest';

import { alpine_nginx_spa_site, alpine_nginx_catch_all } from '#lib/recipe_alpine_nginx.ts';
import { nginx_catch_all_server, SSL_PARAMS_PATH } from '#lib/recipe_nginx.ts';

const CSP = "default-src 'self'";

test('alpine_nginx_spa_site keeps the SSL snippet outside auto-included http.d', () => {
	const site = alpine_nginx_spa_site({
		domain: 'app.example.com',
		port: '4040',
		root: '/srv/build',
		csp: CSP
	}).template;

	// The snippet lives in snippets/ (not http.d/), or nginx -t fails on the
	// re-declared `shared:SSL` zone — verified live against Alpine nginx.
	assert.ok(
		site.includes('    include /etc/nginx/snippets/ssl_params.conf;\n'),
		'snippet include outside http.d'
	);
});

test('alpine_nginx_catch_all removes the stock default and adds a catch-all after it', () => {
	const { remove_default, catch_all } = alpine_nginx_catch_all();

	assert.equal(
		remove_default.check,
		"test ! -e '/etc/nginx/http.d/default.conf' && test ! -L '/etc/nginx/http.d/default.conf' && test -e '/etc/nginx/nginx.conf'"
	);
	assert.equal(
		remove_default.run,
		`set -e
sudo rm -f -- '/etc/nginx/http.d/default.conf'
sudo nginx -t`
	);
	assert.equal(catch_all.path, '/etc/nginx/http.d/00-catch-all.conf');
	assert.equal(catch_all.validate, 'sudo nginx -t');
	assert.deepEqual(catch_all.content, {
		type: 'inline',
		content: nginx_catch_all_server({ ssl_snippet_path: SSL_PARAMS_PATH })
	});
	// the site's SSL parameters, which the default server's handshakes start from
	const text = catch_all.content.type === 'inline' ? catch_all.content.content : '';
	assert.ok(text.includes(`\n    include ${SSL_PARAMS_PATH};\n`), text);
	const certbot = alpine_nginx_catch_all({ ssl: 'certbot' }).catch_all.content;
	assert.ok(
		certbot.type === 'inline' &&
			certbot.content.includes('\n    include /etc/letsencrypt/options-ssl-nginx.conf;\n') &&
			!certbot.content.includes(SSL_PARAMS_PATH),
		JSON.stringify(certbot)
	);
});
