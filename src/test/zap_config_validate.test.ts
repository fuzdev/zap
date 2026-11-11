/**
 * Layer-2 e2e smoke: the full shipped `zap config validate` path.
 *
 * Where the Rust `config_conformance` test exercises `eval_config` in-process,
 * this shells out to the **built binary** to prove the whole path end to end:
 * binary → argh → `zap lock` pinning `fgro` → `fgro eval` → schema parse → exit
 * code. It is the integration counterpart to the typed-fixture round-trip.
 *
 * Skips cleanly (mirroring the Rust suite's gating) when `ZAP_FGRO` doesn't name an
 * `fgro` build or the `zap` binary isn't built — a green suite on a machine that
 * hasn't built the Rust side, not a red one.
 */

import { assert, test } from 'vitest';
import { spawnSync } from 'node:child_process';
import { existsSync, mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { isAbsolute, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { env_ref } from '#lib/env_ref.ts';
import { nginx_site_core } from '#lib/recipe_nginx.ts';

/** Repo root — this file lives at `src/test/`, so two levels up. */
const repo_root = fileURLToPath(new URL('../../', import.meta.url));

/**
 * Does `ZAP_FGRO` name an `fgro` build? The binary evaluates configs with it, and
 * reads it from the environment it inherits.
 */
const fgro_available = (): boolean => {
	const fgro = process.env.ZAP_FGRO;
	return !!fgro && isAbsolute(fgro) && existsSync(fgro);
};

/**
 * The built `zap` binary (debug preferred, release fallback), or `null` when the
 * Rust side hasn't been built — the test skips in that case rather than failing.
 */
const zap_binary = (): string | null => {
	for (const profile of ['debug', 'release']) {
		const candidate = join(repo_root, 'target', profile, 'zap');
		const result = spawnSync(candidate, ['version'], { encoding: 'utf8' });
		// `status === 0` ⇒ the binary exists and ran; ENOENT leaves `error` set.
		if (!result.error && result.status === 0) return candidate;
	}
	return null;
};

/**
 * Run `zap config validate <path>` and return the normalized result. `stderr` /
 * `stdout` are coerced to `string` (they're strings at runtime under
 * `encoding: 'utf8'`, but typed as `string | Buffer`).
 *
 * `ZAP_HOME` is pointed at the case's own temp dir: `config validate` evals through
 * the L0 eval cache, so an inherited `ZAP_HOME` would have every run leave a cache
 * directory behind in the developer's real `~/.zap` (a fresh config path each time,
 * so they accumulate). Mirrors the Rust CLI test's isolation.
 */
const run_zap = (
	zap: string,
	args: Array<string>,
	zap_home: string
): { status: number | null; stdout: string; stderr: string } => {
	const result = spawnSync(zap, args, {
		encoding: 'utf8',
		env: { ...process.env, ZAP_HOME: zap_home }
	});
	return {
		status: result.status,
		stdout: result.stdout ?? '',
		stderr: result.stderr ?? ''
	};
};

/** `zap config validate <config_path>`. */
const validate = (zap: string, config_path: string, zap_home: string) =>
	run_zap(zap, ['config', 'validate', config_path], zap_home);

/** A config that declares nothing, which `zap lock` evaluates to pin `fgro`. */
const EMPTY_CONFIG = `export default (zap) => {
	zap.target({local: true});
};
`;

/**
 * Make a fresh temp project (a `package.json`, which a config needs), pin `fgro` in
 * its lock with `zap lock` over an empty config, then write `body` as its `zap.ts`.
 * Returns the config's path, an isolated `ZAP_HOME` beside it, and a cleanup fn that
 * removes both.
 */
const temp_config = (
	zap: string,
	body: string
): { path: string; zap_home: string; cleanup: () => void } => {
	const dir = mkdtempSync(join(tmpdir(), 'zap-validate-'));
	writeFileSync(join(dir, 'package.json'), '{"name": "zap-validate", "private": true}');
	const path = join(dir, 'zap.ts');
	const zap_home = join(dir, 'zap_home');
	writeFileSync(path, EMPTY_CONFIG);
	const locked = run_zap(zap, ['lock', path], zap_home);
	assert.strictEqual(locked.status, 0, `zap lock failed: ${locked.stderr}`);
	writeFileSync(path, body);
	return {
		path,
		zap_home,
		cleanup: () => rmSync(dir, { recursive: true, force: true })
	};
};

/**
 * The built `zap` when the e2e can run, else `null` — and then the reason is
 * printed to stderr and the tests are reported skipped, so a run that checked
 * nothing says so in its summary.
 */
const runnable = ((): { zap: string } | null => {
	const why = !fgro_available()
		? 'ZAP_FGRO not set'
		: zap_binary() === null
			? 'zap binary not built (run `cargo build -p zap`)'
			: null;
	if (why !== null) {
		console.warn(`SKIPPED zap config validate e2e: ${why}`);
		return null;
	}
	return { zap: zap_binary()! };
})();

test.skipIf(runnable === null)('config validate exits 0 on a minimal valid config', () => {
	const ctx = runnable!;
	const { path, zap_home, cleanup } = temp_config(
		ctx.zap,
		`export default (zap) => {
	zap.target({local: true, package_manager: 'apt'});
	zap.pkg({id: 'curl', name: 'curl', from: {apt: 'curl'}});
};
`
	);
	try {
		const result = validate(ctx.zap, path, zap_home);
		assert.strictEqual(
			result.status,
			0,
			`expected exit 0, got ${result.status}; stderr: ${result.stderr}`
		);
	} finally {
		cleanup();
	}
});

test.skipIf(runnable === null)(
	'config validate exits nonzero on an unknown field (deny_unknown_fields)',
	() => {
		const ctx = runnable!;
		const { path, zap_home, cleanup } = temp_config(
			ctx.zap,
			`export default (zap) => {
	zap.target({local: true, package_manager: 'apt'});
	zap.pkg({id: 'x', from: {apt: 'curl'}, bogus_field: true});
};
`
		);
		try {
			const result = validate(ctx.zap, path, zap_home);
			assert.notStrictEqual(result.status, 0, 'a bogus field must fail validation');
			assert.match(
				result.stderr,
				/unknown field|did not match the zap schema/,
				`stderr should mention the parse error; got: ${result.stderr}`
			);
		} finally {
			cleanup();
		}
	}
);

/**
 * A config declaring the nginx site recipe's content, as `nginx_site_core` returns it
 * for `redirect_domains`, in a file resource.
 */
const nginx_site_config = (
	redirect_domains: Array<string>,
	edit: (template: string) => string = (template) => template
): string => {
	const site = nginx_site_core({
		ssl_snippet_path: '/etc/nginx/snippets/ssl_params.conf',
		domain: env_ref('DEPLOY_DOMAIN'),
		port: '4040',
		root: '/srv/app/build',
		csp: "default-src 'self'",
		redirect_domains
	});
	const content = { ...site, template: edit(site.template) };
	return `export default (zap) => {
	zap.target({local: true, package_manager: 'apt'});
	zap.file({id: 'nginx-site', path: '/etc/nginx/sites-available/app', content: ${JSON.stringify(content)}});
};
`;
};

test.skipIf(runnable === null)(
	'config validate accepts the nginx site with literal and reference redirect_domains',
	() => {
		const ctx = runnable!;
		const { path, zap_home, cleanup } = temp_config(
			ctx.zap,
			nginx_site_config(['www.{{domain}}', env_ref('MIRROR_DOMAIN')])
		);
		try {
			const result = validate(ctx.zap, path, zap_home);
			assert.strictEqual(
				result.status,
				0,
				`expected exit 0, got ${result.status}; stderr: ${result.stderr}`
			);
		} finally {
			cleanup();
		}
	}
);

// The recipe refuses a `{{mirror}}` redirect name itself (`recipe_nginx.test.ts`), so the
// placeholder is put into the template after the recipe built it: what this pins is the
// engine's refusal, of a template placeholder its vars don't name, at the binary's exit.
test.skipIf(runnable === null)(
	'config validate refuses an nginx site template placeholder naming no variable',
	() => {
		const ctx = runnable!;
		const config = nginx_site_config(['mirror.example.com'], (template) => {
			assert.include(template, 'mirror.example.com');
			return template.replaceAll('mirror.example.com', '{{mirror}}');
		});
		const { path, zap_home, cleanup } = temp_config(ctx.zap, config);
		try {
			const result = validate(ctx.zap, path, zap_home);
			assert.notStrictEqual(result.status, 0, 'a foreign placeholder must fail validation');
			assert.match(
				result.stderr,
				/holds the placeholder `\{\{mirror\}\}`/,
				`stderr should name the placeholder; got: ${result.stderr}`
			);
		} finally {
			cleanup();
		}
	}
);
