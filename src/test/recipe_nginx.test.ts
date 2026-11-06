import { assert, test } from 'vitest';

import { env_ref } from '#lib/env_ref.ts';
import {
	NGINX_VALIDATE,
	type NginxSiteCoreOptions,
	nginx_catch_all_server,
	nginx_config_verify,
	nginx_site_core,
	rate_limit_zone,
	SECURITY_HEADER_DIRECTIVES,
	SSL_PARAMS_PATH,
	site_security_header_directives,
	ssl_params
} from '#lib/recipe_nginx.ts';

// The core takes the distro-varying `ssl_snippet_path`; these tests pin the
// Debian path (the byte-for-byte goldens were captured from the Debian deploys).
// The wrapper-specific paths are covered in `recipe_{debian,alpine}_nginx.test.ts`.
const build_site = (
	options: Omit<NginxSiteCoreOptions, 'ssl_snippet_path' | 'domain' | 'port'>
): string =>
	nginx_site_core({
		ssl_snippet_path: '/etc/nginx/snippets/ssl_params.conf',
		domain: 'app.example.com',
		port: '4040',
		...options
	}).template;

// The fuz_app SPA Content-Security-Policy, shared by the fuz_app sites.
// `{{domain}}` stays a literal placeholder for zap's template engine.
const CSP =
	"default-src 'self'; " +
	"script-src 'self' 'unsafe-inline' 'wasm-unsafe-eval'; " +
	"style-src 'self' 'unsafe-inline'; " +
	"img-src 'self' data:; " +
	"font-src 'self'; " +
	"connect-src 'self' wss://{{domain}}; " +
	"object-src 'none'; " +
	"base-uri 'self'; " +
	"form-action 'self'; " +
	"frame-ancestors 'self'";

test('ssl_params reproduces the reference SSL_PARAMS snippet byte-for-byte', () => {
	const expected = `ssl_protocols TLSv1.2 TLSv1.3;
ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384;
ssl_prefer_server_ciphers off;
ssl_session_cache shared:fuz_app_SSL:10m;
ssl_session_timeout 1d;
ssl_session_tickets off;
`;

	assert.equal(ssl_params(), expected);
});

test('rate_limit_zone reproduces the reference nginx-rate-limit content byte-for-byte', () => {
	assert.equal(
		rate_limit_zone(),
		'limit_req_zone $binary_remote_addr zone=global:10m rate=10r/s;\n'
	);
});

test('rate_limit_zone renders overrides for size and rate', () => {
	assert.equal(
		rate_limit_zone({ size: '20m', rate: '30r/s' }),
		'limit_req_zone $binary_remote_addr zone=global:20m rate=30r/s;\n'
	);
});

test('nginx_site_core reproduces a reference fuz_app site byte-for-byte', () => {
	const site = build_site({
		root: '/home/app/app/current/build',
		csp: CSP,
		ssl: 'snippet',
		client_max_body_size: '4m',
		client_max_body_size_comment: 'the app has no large uploads — keep request bodies modest.',
		spa_try_files: '$uri $uri/index.html /200.html'
	});

	const expected = `# Main HTTPS server
server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name {{domain}};

    ssl_certificate /etc/letsencrypt/live/{{domain}}/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/{{domain}}/privkey.pem;
    include /etc/nginx/snippets/ssl_params.conf;

    server_tokens off;

    # Rate limiting is scoped to the dynamic /api surface (see location /api),
    # NOT applied server-wide. A global limit_req here also throttles the
    # static /_app/* chunks, and the SPA cold-loads dozens of them in one
    # parallel burst — exceeding the burst and rejecting assets, which breaks
    # hydration ("context value is not set"). Static assets are fingerprinted
    # and immutable; they don't need request-rate protection.

    # Throttling answers 429, not nginx's default 503. A throttled client is
    # being asked to slow down, not told the server is unavailable: 429 is the
    # status clients back off on, and it keeps rate limiting out of the 5xx
    # bucket that uptime monitoring reads as an outage. Set server-level so
    # every limit_req below inherits it.
    limit_req_status 429;

    # the app has no large uploads — keep request bodies modest.
    client_max_body_size 4m;

    root /home/app/app/current/build;

    # Security headers
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header Content-Security-Policy "${CSP}" always;

    # API and health routes -> backend. The /api prefix covers /api/rpc and the
    # /api/ws WebSocket upgrade; the upgrade headers below carry both.
    location /api {
        # Rate limit dynamic API traffic only. burst is generous to absorb
        # the dashboard's RPC fan-out on load; auth endpoints also have their
        # own app-level per-IP limiters as the real backstop.
        limit_req zone=global burst=50 nodelay;

        proxy_pass http://127.0.0.1:{{port}};
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_cache_bypass $http_upgrade;

        # Forward bearer auth so API-token clients work through nginx.
        #
        # Browser token leakage is covered by the backend's is_browser_context
        # guard (rejects a bearer when Origin/Referer is present), and cookie/
        # browser requests carry no Authorization — so stripping here buys
        # nothing against XSS exfiltration while silently breaking every
        # API-token client.
        #
        # It is NOT a no-op in general, though: stripping would also block
        # replay of a token stolen from CI, an env var, or a config file —
        # that client sends no Origin, so the guard admits it. Forwarding is a
        # deliberate trade (working API tokens for a wider replay surface),
        # not a free one. Compensating controls are token revocation, the
        # bearer IP limiter, and per-spec credential_types gating on anything
        # sensitive. Revisit if a deployment wants bearer disabled at the edge.
        proxy_set_header Authorization $http_authorization;

        # Timeouts
        proxy_connect_timeout 60s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
    }

    location /health {
        proxy_pass http://127.0.0.1:{{port}};
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    # Readiness deploy gate — the spine /ready schema-drift probe. zap's
    # post-deploy poll targets it (503 => rollback); proxy it like /health so
    # it reaches the daemon rather than 404ing at nginx.
    location = /ready {
        limit_req zone=global burst=5 nodelay;
        proxy_pass http://127.0.0.1:{{port}};
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    # Static files with caching
    location /_app {
        expires 1y;
        add_header Cache-Control "public, immutable";
        add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
        add_header X-Frame-Options "SAMEORIGIN" always;
        add_header X-Content-Type-Options "nosniff" always;
        add_header Referrer-Policy "strict-origin-when-cross-origin" always;
        add_header Content-Security-Policy "${CSP}" always;
        try_files $uri =404;
    }

    # Serve static files, fall back to 200.html for SPA routes.
    #
    # Cache-Control on the HTML entry point: force revalidation on every
    # request (browser sends If-None-Match, server returns 304 if unchanged
    # ~ a few hundred bytes). Without this, browsers apply heuristic
    # caching to 200.html, which after a deploy means they serve the OLD
    # shell — and the old shell references OLD hashed /_app/* asset URLs
    # that no longer exist in the new release directory. Result: broken
    # page until the user hard-refreshes one or more times. The /_app/*
    # assets above are content-hashed and immutable, so they can stay
    # cached forever — only the entry point needs to revalidate.
    location / {
        # nginx drops inherited add_header directives in any location that sets
        # its own, so the security headers + CSP must be repeated here — this is
        # the HTML shell (prerendered routes + 200.html), where they matter most.
        add_header Cache-Control "no-cache, must-revalidate" always;
        add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
        add_header X-Frame-Options "SAMEORIGIN" always;
        add_header X-Content-Type-Options "nosniff" always;
        add_header Referrer-Policy "strict-origin-when-cross-origin" always;
        add_header Content-Security-Policy "${CSP}" always;
        # Serve prerendered route HTML when present (public-read: real <title>,
        # content, SEO); fall back to the 200.html SPA shell for dynamic routes.
        try_files $uri $uri/index.html /200.html;
    }
}

# HTTP -> HTTPS redirect
server {
    listen 80;
    listen [::]:80;
    server_name {{domain}};

    # ACME HTTP-01 challenge (certbot --webroot). Served over plain HTTP and
    # NOT redirected, so certbot renew works with nginx running on port 80
    # (the old --standalone authenticator couldn't bind 80 while nginx held it).
    location /.well-known/acme-challenge/ {
        root /var/www/certbot;
        default_type "text/plain";
        try_files $uri =404;
    }

    location / {
        return 301 https://{{domain}}$request_uri;
    }
}
`;

	assert.equal(site, expected);
});

test('ssl: certbot emits the certbot-managed SSL lines and not the snippet include', () => {
	const site = build_site({
		root: '/home/app/app/current/build',
		csp: CSP,
		ssl: 'certbot'
	});

	assert.ok(
		site.includes('    include /etc/letsencrypt/options-ssl-nginx.conf;\n'),
		'certbot options include'
	);
	assert.ok(
		site.includes('    ssl_dhparam /etc/letsencrypt/ssl-dhparams.pem;\n'),
		'certbot ssl_dhparam'
	);
	assert.ok(
		!site.includes('/etc/nginx/snippets/ssl_params.conf'),
		'no snippet include in certbot mode'
	);
});

test('ssl defaults to the snippet include', () => {
	const site = build_site({ root: '/srv/build', csp: CSP });

	assert.ok(
		site.includes('    include /etc/nginx/snippets/ssl_params.conf;\n'),
		'snippet include by default'
	);
	assert.ok(!site.includes('options-ssl-nginx.conf'), 'no certbot options by default');
});

test('omitting client_max_body_size omits the directive', () => {
	const site = build_site({ root: '/srv/build', csp: CSP });

	assert.ok(!site.includes('client_max_body_size'), 'no client_max_body_size line');
	// The rate-limit paragraph still flows straight into `root` — the omitted
	// block leaves no stray blank line behind it.
	assert.ok(
		site.includes('    limit_req_status 429;\n\n    root /srv/build;'),
		'rate-limit paragraph flows into root with one blank line'
	);
});

test('error_page_404 renders before the SPA catch-all', () => {
	const site = build_site({
		root: '/srv/build',
		csp: CSP,
		error_page_404: '/404.html'
	});

	assert.ok(site.includes('    error_page 404 /404.html;\n'), 'error_page line present');
	// It sits between the `/_app` block's `try_files` and the SPA catch-all comment.
	const error_index = site.indexOf('error_page 404');
	const app_index = site.indexOf('location /_app');
	const catchall_index = site.indexOf('# Serve static files, fall back to 200.html');
	assert.ok(error_index > app_index, 'error_page after the /_app block');
	assert.ok(error_index < catchall_index, 'error_page before the SPA catch-all');
});

test('error_page_404 is omitted by default', () => {
	const site = build_site({ root: '/srv/build', csp: CSP });
	assert.ok(!site.includes('error_page'), 'no error_page line by default');
});

test('extra_locations are injected verbatim before the /_app static block', () => {
	const extra = `    # app-specific block
    location /custom {
        return 404;
    }`;
	const site = build_site({
		root: '/srv/build',
		csp: CSP,
		extra_locations: extra
	});

	assert.ok(site.includes(extra), 'extra_locations rendered verbatim');
	const extra_index = site.indexOf('location /custom');
	const health_index = site.indexOf('location /health');
	const app_index = site.indexOf('location /_app');
	assert.ok(extra_index > health_index, 'extra_locations after /health');
	assert.ok(extra_index < app_index, 'extra_locations before /_app');
});

test('http2 defaults on, on both HTTPS sockets and nowhere else', () => {
	const site = build_site({ root: '/srv/build', csp: CSP });
	// The `listen` parameter, not the `http2 on;` directive: the directive needs
	// nginx >= 1.25.1 and the fleet runs 1.24, where it fails `nginx -t`.
	assert.ok(!site.includes('http2 on;'), 'not the 1.25.1+ directive form');
	assert.ok(site.includes('    listen 443 ssl http2;\n'), 'ipv4 socket');
	assert.ok(site.includes('    listen [::]:443 ssl http2;\n'), 'ipv6 socket');
	// the redirect server is plaintext HTTP/1.1; h2 there would be h2c, not this
	assert.equal(site.match(/http2/g)?.length, 2, 'HTTPS server only');
});

test('http2: false omits the parameter', () => {
	const site = build_site({ root: '/srv/build', csp: CSP, http2: false });
	assert.ok(!site.includes('http2'), 'no http2 anywhere');
	assert.ok(site.includes('    listen 443 ssl;\n    listen [::]:443 ssl;\n'), 'listen pair intact');
});

test('api_burst overrides the /api limit_req burst', () => {
	const site = build_site({
		root: '/srv/build',
		csp: CSP,
		api_burst: 100
	});
	assert.ok(site.includes('limit_req zone=global burst=100 nodelay;'), 'burst from input');
});

test('acme_webroot overrides the challenge root in the redirect server', () => {
	const site = build_site({
		root: '/srv/build',
		csp: CSP,
		acme_webroot: '/srv/acme'
	});
	assert.ok(site.includes('        root /srv/acme;\n'), 'acme_webroot from input');
});

test('redirect_domains adds an HTTPS redirect server and joins the HTTP server_name', () => {
	const site = build_site({
		root: '/srv/build',
		csp: CSP,
		redirect_domains: ['www.{{domain}}', 'old.example.org']
	});

	const expected_redirect = `
# HTTPS redirect to the canonical domain
server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name www.{{domain}} old.example.org;

    ssl_certificate /etc/letsencrypt/live/{{domain}}/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/{{domain}}/privkey.pem;
    include /etc/nginx/snippets/ssl_params.conf;

    server_tokens off;

    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;

    location / {
        return 301 https://{{domain}}$request_uri;
    }
}

# HTTP -> HTTPS redirect
`;
	assert.ok(
		site.includes(expected_redirect),
		'redirect server sits between the main and HTTP servers'
	);
	assert.ok(
		site.includes('    server_name {{domain}} www.{{domain}} old.example.org;\n'),
		'HTTP server answers for every name'
	);
	assert.equal(
		site.split('server_name {{domain}};').length - 1,
		1,
		'the main HTTPS server keeps the canonical name alone'
	);
});

test('redirect_domains omitted emits no redirect server', () => {
	const site = build_site({ root: '/srv/build', csp: CSP });

	assert.ok(!site.includes('# HTTPS redirect to the canonical domain'));
	assert.equal(site.split('server_name {{domain}};').length - 1, 2, 'HTTPS + HTTP servers');
});

test('the output ends with a trailing newline', () => {
	const site = build_site({ root: '/srv/build', csp: CSP });
	assert.ok(site.endsWith('\n'), 'trailing newline');
});

test('nginx_config_verify runs NGINX_VALIDATE as its one assertion', () => {
	assert.deepEqual(nginx_config_verify(), {
		assertions: [{ type: 'command', run: NGINX_VALIDATE }]
	});
});

test('every HTTPS location that sets its own headers carries the full set, the CSP included', () => {
	const site = build_site({ root: '/srv/app/build', csp: CSP });
	const https = site.slice(0, site.indexOf('# HTTP -> HTTPS redirect'));
	const blocks = https.split(/\n {4}location /).slice(1);
	let checked = 0;
	for (const block of blocks) {
		const body = block.slice(0, block.indexOf('\n    }'));
		if (!body.includes('add_header')) continue;
		checked++;
		for (const directive of site_security_header_directives(CSP)) {
			assert.ok(body.includes(directive), `${body.split('\n', 1)[0]}: ${directive}`);
		}
	}
	assert.equal(checked, 2, 'the /_app and SPA blocks set their own headers');
});

test('site_security_header_directives is the base set plus the site CSP', () => {
	assert.deepEqual(site_security_header_directives(CSP), [
		...SECURITY_HEADER_DIRECTIVES,
		`add_header Content-Security-Policy "${CSP}" always;`
	]);
	assert.ok(
		!SECURITY_HEADER_DIRECTIVES.some((directive) => directive.includes('Content-Security'))
	);
	assert.throws(() => site_security_header_directives('a"; add_header X y'), /must hold no/);
	assert.throws(() => site_security_header_directives('a\nb'), /must hold no/);
});

test('refuses an extra_locations block that sets a header but no CSP', () => {
	const site = (extra_locations: string) =>
		build_site({ root: '/srv/app/build', csp: CSP, extra_locations });
	const headers = site_security_header_directives(CSP)
		.map((d) => `        ${d}`)
		.join('\n');
	// none set: the block inherits the server's set
	site(`    location /a {\n        proxy_pass http://127.0.0.1:1;\n    }`);
	// the full set, or a policy of its own
	site(`    location /a {\n        add_header Cache-Control "no-store" always;\n${headers}\n    }`);
	site(
		`    location /f {\n        add_header content-security-policy "sandbox" always;\n        add_header X-Content-Type-Options "nosniff" always;\n    }`
	);
	// a `\${name}` variable's braces are part of its word, not a block holding it
	site(
		`    location /a {\n        add_header X-A "1";\n        add_header Content-Security-Policy default-src\${x};\n    }`
	);
	for (const extra of [
		`    location /mapdata/ {\n        add_header Cache-Control "public, max-age=3600" always;\n    }`,
		// a CSP in a comment or a nested block is not this block's
		`    location /a {\n        # add_header Content-Security-Policy "x";\n        add_header X-A "1";\n    }`,
		`    location /a {\n        add_header X-A "1";\n        location /a/b {\n            add_header Content-Security-Policy "x";\n        }\n    }`,
		`    location /a {\n        if ($x) {\n            add_header X-A "1";\n        }\n${headers}\n    }`,
		// an escaped quote doesn't end a quoted value early, and the block after is read
		`    location /a { add_header X-A "a\\"b" always; add_header X-B "1"; } location /b { add_header X-C "1"; }`,
		`    location /a { add_header X-A 'a\\'b' always; add_header X-B "1"; } location /b { add_header X-C "1"; }`,
		// an empty policy is none
		`    location /a {\n        add_header Content-Security-Policy "" always;\n    }`,
		`    location /a {\n        add_header Content-Security-Policy " " always;\n    }`
	]) {
		assert.throws(
			() => site(extra),
			/sets add_header but no non-empty Content-Security-Policy.*site_security_header_directives\(csp\)/,
			extra
		);
	}
});

test('refuses a CSP that would end or escape its quoted value', () => {
	for (const csp of ['a"b', 'a\\', "default-src 'self' $host", 'a\rb']) {
		assert.throws(() => site_security_header_directives(csp), /must hold no/, csp);
	}
});

test('the catch-all is the default_server on every socket the site listens on, with its http2', () => {
	const sockets = (text: string) =>
		[...text.matchAll(/^\s*listen (.*);$/gm)].map((m) => m[1]!.replace(' default_server', ''));
	for (const http2 of [true, false]) {
		const site = build_site({ root: '/srv/app/build', csp: CSP, http2 });
		const catch_all = nginx_catch_all_server({ http2, ssl_snippet_path: SSL_PARAMS_PATH });
		assert.deepEqual(
			new Set(sockets(catch_all)),
			new Set(sockets(site)),
			`the catch-all listens where the site does, with the same parameters (http2 ${http2})`
		);
		assert.ok(
			sockets(catch_all).length === catch_all.match(/default_server/g)?.length,
			'every catch-all socket is the default'
		);
		assert.ok(!site.includes('default_server'), 'the site claims none');
	}
	const text = nginx_catch_all_server({ ssl_snippet_path: SSL_PARAMS_PATH });
	assert.ok(text.includes('\n    ssl_reject_handshake on;\n    return 444;\n'), text);
	// the site's SSL parameters, as the site includes them, in either mode
	for (const ssl of ['snippet', 'certbot'] as const) {
		const site = build_site({ root: '/srv/app/build', csp: CSP, ssl });
		const catch_all = nginx_catch_all_server({ ssl, ssl_snippet_path: SSL_PARAMS_PATH });
		const params = (t: string) =>
			t.split('\n').filter((l) => /^ {4}(include|ssl_dhparam) /.test(l));
		assert.deepEqual(params(catch_all), [...new Set(params(site))], ssl);
		assert.ok(params(catch_all).length > 0, ssl);
	}
	assert.ok(!text.includes('ssl_certificate'), 'no certificate to show');
});

test('nginx_site_core returns the template content with its two values and their kinds', () => {
	const content = nginx_site_core({
		ssl_snippet_path: '/etc/nginx/snippets/ssl_params.conf',
		domain: 'app.example.com',
		port: 4040,
		root: '/home/app/app/current/build',
		csp: CSP,
		ssl: 'certbot',
		redirect_domains: ['www.{{domain}}']
	});
	assert.equal(content.type, 'template');
	assert.deepEqual(content.vars, { domain: 'app.example.com', port: 4040 });
	assert.deepEqual(content.kinds, { domain: 'hostname', port: 'port' });
	const placeholders = new Set([...content.template.matchAll(/\{\{(\w+)\}\}/g)].map((m) => m[1]));
	assert.deepEqual(placeholders, new Set(Object.keys(content.kinds)));
});

/** The core with the test's fixed domain and port, returning the whole content. */
const build_content = (
	options: Omit<NginxSiteCoreOptions, 'ssl_snippet_path' | 'domain' | 'port'>
) =>
	nginx_site_core({
		ssl_snippet_path: '/etc/nginx/snippets/ssl_params.conf',
		domain: env_ref('DEPLOY_DOMAIN'),
		port: '4040',
		...options
	});

test('a redirect_domains reference becomes its own hostname variable', () => {
	const mirror = env_ref('MIRROR_DOMAIN');
	const content = build_content({ root: '/srv/build', csp: CSP, redirect_domains: [mirror] });

	assert.deepEqual(content.vars, {
		domain: env_ref('DEPLOY_DOMAIN'),
		port: '4040',
		redirect_domain_0: mirror
	});
	assert.deepEqual(content.kinds, {
		domain: 'hostname',
		port: 'port',
		redirect_domain_0: 'hostname'
	});
	assert.ok(!content.template.includes('\uFDD0'), 'the template carries no reference');
	assert.ok(
		content.template.includes('    server_name {{redirect_domain_0}};\n'),
		'redirect server'
	);
	assert.ok(
		content.template.includes('    server_name {{domain}} {{redirect_domain_0}};\n'),
		'HTTP server'
	);
});

test('redirect_domains mixes literal names and references, each variable named by its index', () => {
	const mirror = env_ref('MIRROR_DOMAIN');
	const legacy = `old.${env_ref('LEGACY_ZONE')}`;
	const content = build_content({
		root: '/srv/build',
		csp: CSP,
		redirect_domains: ['www.{{domain}}', mirror, 'old.example.org', legacy]
	});

	assert.deepEqual(content.vars, {
		domain: env_ref('DEPLOY_DOMAIN'),
		port: '4040',
		redirect_domain_1: mirror,
		redirect_domain_3: legacy
	});
	assert.deepEqual(content.kinds, {
		domain: 'hostname',
		port: 'port',
		redirect_domain_1: 'hostname',
		redirect_domain_3: 'hostname'
	});
	assert.ok(
		content.template.includes(
			'    server_name www.{{domain}} {{redirect_domain_1}} old.example.org {{redirect_domain_3}};\n'
		),
		'redirect server, in entry order'
	);
	assert.ok(
		content.template.includes(
			'    server_name {{domain}} www.{{domain}} {{redirect_domain_1}} old.example.org {{redirect_domain_3}};\n'
		),
		'HTTP server, in entry order'
	);
	const placeholders = new Set([...content.template.matchAll(/\{\{(\w+)\}\}/g)].map((m) => m[1]));
	assert.deepEqual(placeholders, new Set(Object.keys(content.vars)));
});

test('a literal redirect_domains placeholder naming no site variable is left for the structural gate', () => {
	const content = build_content({
		root: '/srv/build',
		csp: CSP,
		redirect_domains: ['{{mirror}}']
	});

	assert.ok(content.template.includes('    server_name {{mirror}};\n'), 'written as given');
	assert.deepEqual(Object.keys(content.vars), ['domain', 'port'], 'no variable fills it');
	assert.deepEqual(Object.keys(content.kinds), ['domain', 'port']);
});

test('refuses a redirect_domains reference that also holds a placeholder', () => {
	assert.throws(
		() =>
			build_content({
				root: '/srv/build',
				csp: CSP,
				redirect_domains: [`www.${env_ref('ZONE')}.{{domain}}`]
			}),
		/redirect_domains\[0\] carries a reference and a `\{\{`/
	);
});

test('refuses another input writing a redirect_domains reference placeholder', () => {
	assert.throws(
		() =>
			build_content({
				root: '/srv/build',
				csp: CSP,
				redirect_domains: [env_ref('MIRROR_DOMAIN')],
				extra_locations: `    location /m {\n        return 301 https://{{redirect_domain_0}};\n    }`
			}),
		/the placeholder `\{\{redirect_domain_0\}\}` is the redirect_domains reference's own/
	);
});
