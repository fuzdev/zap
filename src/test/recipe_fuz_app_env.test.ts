import { assert, test } from 'vitest';

import {
	type FuzAppEnvBaseOptions,
	type FuzAppEnvExtra,
	fuz_app_env_base,
	fuz_app_trusted_proxies
} from '#lib/recipe_fuz_app_env.ts';
import { env_ref } from '#lib/env_ref.ts';

const KEYS = env_ref('SECRET_FUZ_COOKIE_KEYS');
const VALUES = { port: '4040', cookie_keys: KEYS };

/** The env file text `fuz_app_env_base` gives for `options`, with stand-in values. */
const env_text = (
	options: Omit<FuzAppEnvBaseOptions, 'port' | 'cookie_keys'> &
		Partial<Pick<FuzAppEnvBaseOptions, 'port' | 'cookie_keys'>>
): string => fuz_app_env_base({ ...VALUES, ...options }).template;

test('fuz_app_env_base reproduces the shared fuz_app .env.production header byte-for-byte', () => {
	const base = env_text({
		user: 'fuz_forge',
		service: 'fuz_forge',
		config_dir: '/home/fuz_forge/.fuz_forge'
	});

	const expected = `# Production environment configuration

NODE_ENV=production
PORT='{{port}}'
HOST=127.0.0.1

# Database - PostgreSQL over its Unix socket, peer auth as the service's own account
DATABASE_URL='postgres://fuz_forge@/fuz_forge?host=/run/postgresql'

# Auth - cookie signing keys (for key rotation, separate with __)
SECRET_FUZ_COOKIE_KEYS='{{cookie_keys}}'

# Bootstrap - one-shot token for first-time keeper account creation
FUZ_BOOTSTRAP_TOKEN_PATH='/home/fuz_forge/.fuz_forge/secret_bootstrap_token'
`;

	assert.equal(base, expected);
});

test('fuz_app_env_base interpolates user/service/config_dir', () => {
	const base = env_text({
		user: 'app',
		service: 'app',
		config_dir: '/home/app/.app'
	});
	assert.ok(
		base.includes("DATABASE_URL='postgres://app@/app?host=/run/postgresql'"),
		'DATABASE_URL'
	);
	assert.ok(
		base.includes("FUZ_BOOTSTRAP_TOKEN_PATH='/home/app/.app/secret_bootstrap_token'"),
		'token path'
	);
	// `{{port}}` / `{{cookie_keys}}` stay literal for zap's template engine.
	assert.ok(base.includes("PORT='{{port}}'"), 'port placeholder');
	assert.ok(base.includes("SECRET_FUZ_COOKIE_KEYS='{{cookie_keys}}'"), 'cookie placeholder');
});

test('fuz_app_trusted_proxies reproduces the loopback-proxy stanza byte-for-byte', () => {
	const stanza = fuz_app_trusted_proxies({ env_prefix: 'FORGE' });

	const expected = `# Trust the loopback nginx reverse proxy so the backend resolves the real
# client IP from X-Forwarded-For (nginx connects from 127.0.0.1). Without this
# every request is attributed to 127.0.0.1 — per-IP rate limits collapse into a
# single shared bucket and audit_log.ip is useless. nginx is the only hop and
# sets X-Forwarded-For to the client's address.
FUZ_FORGE_TRUSTED_PROXIES='127.0.0.1'
`;

	assert.equal(stanza, expected);
});

test('fuz_app_trusted_proxies keys the var by env_prefix and honors a value override', () => {
	assert.ok(
		fuz_app_trusted_proxies({ env_prefix: 'WEB' }).includes("FUZ_WEB_TRUSTED_PROXIES='127.0.0.1'"),
		'env_prefix infix'
	);
	assert.ok(
		fuz_app_trusted_proxies({
			env_prefix: 'FORGE',
			value: '10.0.0.1'
		}).includes("FUZ_FORGE_TRUSTED_PROXIES='10.0.0.1'"),
		'value override'
	);
});

test('fuz_app_env_base reaches the database over the socket, never TCP', () => {
	const base = env_text({ user: 'app', service: 'app', config_dir: '/home/app/.app' });
	const url = /^DATABASE_URL='(.*)'$/m.exec(base)?.[1];
	assert.ok(url !== undefined, base);
	assert.ok(!url.includes('localhost') && !url.includes('127.0.0.1'), url);
	assert.ok(url.endsWith('?host=/run/postgresql'), url);
});

test('fuz_app_env_base refuses a role or database name the URL reads as structure', () => {
	for (const [field, value] of [
		['user', 'app@evil'],
		['user', 'a/b'],
		['service', 'app?host=/tmp'],
		['service', 'app%2F'],
		['service', 'a:b'],
		['user', '']
	]) {
		const options = { user: 'app', service: 'app', config_dir: '/home/app/.app', [field!]: value };
		assert.throws(
			() => env_text(options),
			new RegExp(`${field} .* because it is a name in DATABASE_URL`),
			`${field}=${value}`
		);
	}
});

test('fuz_app_env_base returns the template content, the kinds of its values its own', () => {
	const content = fuz_app_env_base({
		user: 'app',
		service: 'app',
		config_dir: '/home/app/.app',
		port: 4040,
		cookie_keys: KEYS,
		extra: {
			template: "FUZ_ALLOWED_ORIGINS='https://{{domain}}'\nPORT_AGAIN={{port}}\n",
			vars: { domain: 'app.example.com' },
			kinds: { domain: 'hostname' }
		}
	});
	assert.equal(content.type, 'template');
	assert.ok(
		content.template.endsWith("FUZ_ALLOWED_ORIGINS='https://{{domain}}'\nPORT_AGAIN={{port}}\n")
	);
	assert.deepEqual(content.vars, { port: 4040, cookie_keys: KEYS, domain: 'app.example.com' });
	assert.deepEqual(content.kinds, { port: 'port', cookie_keys: 'env_value', domain: 'hostname' });
	// every placeholder has a var, and every var a placeholder
	const placeholders = new Set([...content.template.matchAll(/\{\{(\w+)\}\}/g)].map((m) => m[1]));
	assert.deepEqual(placeholders, new Set(Object.keys(content.vars!)));
	// both of the base's placeholders sit inside single quotes, which `env_value` and
	// `port` keep a value inside
	assert.ok(content.template.includes("PORT='{{port}}'\n"));
	assert.ok(content.template.includes("SECRET_FUZ_COOKIE_KEYS='{{cookie_keys}}'\n"));
});

test("fuz_app_env_base refuses extra vars or kinds that name the base's own", () => {
	const base = { user: 'app', service: 'app', config_dir: '/home/app/.app', ...VALUES };
	// the types refuse these too; the runtime check is what a JS caller meets
	const extras: Array<FuzAppEnvExtra> = [
		// @ts-expect-error `port` is the base's
		{ template: '', vars: { port: '1' } },
		// @ts-expect-error `cookie_keys` is the base's
		{ template: '', kinds: { cookie_keys: 'text' as const } },
		// @ts-expect-error `port` is the base's
		{ template: '', kinds: { port: 'text' as const } }
	];
	for (const extra of extras) {
		assert.throws(() => fuz_app_env_base({ ...base, extra }), /is the base's own/);
	}
});

test('fuz_app_env_base refuses a cookie_keys written out, which would put the secret in the plan', () => {
	const base = { user: 'app', service: 'app', config_dir: '/home/app/.app', port: 4040 };
	for (const cookie_keys of ['keys', '', 'a__b']) {
		assert.throws(
			() => fuz_app_env_base({ ...base, cookie_keys }),
			/fuz_app_env_base: cookie_keys must carry a reference/,
			cookie_keys
		);
	}
	// a reference, whole or interpolated
	fuz_app_env_base({ ...base, cookie_keys: KEYS });
	fuz_app_env_base({ ...base, cookie_keys: `${KEYS}__${env_ref('OLD_KEYS')}` });
});
