/**
 * Recipe for a single-page app's Content-Security-Policy.
 *
 * `spa_csp` builds the `Content-Security-Policy` header value for a prerendered
 * SvelteKit SPA behind nginx. The
 * baseline is fixed and security-sensitive — `script-src`/`style-src` permit
 * `'unsafe-inline'` because adapter-static emits inline bootstrap scripts whose
 * content changes every build (a strict nonce/hash CSP would need SvelteKit's
 * build-time `csp`, not an nginx header), `'wasm-unsafe-eval'` is for the blake3
 * WASM, and everything else is locked down. What varies per app is a handful of
 * extra sources (a site that uses `blob:` images + web workers), so those are
 * options defaulting to the locked-down baseline.
 *
 * The value is consumed as the `csp` option of the site recipes
 * (`{debian,alpine}_nginx_spa_site`), which interpolate it into the
 * `add_header Content-Security-Policy "..." always;` lines. `connect-src` carries the WS
 * endpoint as the zap template placeholder `wss://{{domain}}`, substituted at
 * apply time alongside the rest of the site config.
 *
 * Recipes are imported at config eval time inside `fgro eval`'s sandbox,
 * which has no network, no writes, and no environment, and where the clock and
 * randomness throw. This module is therefore a **pure function**: it only assembles a
 * string from its arguments — no I/O, no clock, no randomness, no imports beyond
 * types. The output is deterministic for given inputs, so it stays a reliable
 * content-addressed plan artifact.
 *
 * @module
 */

/**
 * Options for `spa_csp`.
 *
 * Every field defaults to the locked-down baseline, so `spa_csp()` with no
 * argument is the locked-down baseline; pass sources to widen a single directive
 * (a site that uses `blob:` images and a web worker).
 */
export interface SpaCspOptions {
	/**
	 * The `connect-src` WebSocket endpoint, appended after `'self'`. Defaults to
	 * the zap template placeholder `wss://{{domain}}` (substituted at apply time).
	 */
	websocket?: string;
	/** Extra `connect-src` sources appended after `'self'` and `websocket`. */
	connect_src_extra?: Array<string>;
	/** Extra `img-src` sources appended after the `'self' data:` baseline (e.g. `['blob:']`). */
	img_src_extra?: Array<string>;
	/**
	 * `worker-src` sources beyond the implicit `'self'`. Emits a `worker-src`
	 * directive (placed after `connect-src`) only when set (e.g. `['blob:']`).
	 */
	worker_src_extra?: Array<string>;
}

// Each entry is a literal CSP source token — keyword sources stay quoted
// (`'self'`), scheme/host sources do not (`data:`, `blob:`, `https://cdn…`); the
// recipe concatenates verbatim rather than guessing the quoting.

/**
 * Build the SPA `Content-Security-Policy` header value for `options`.
 *
 * Assembles the fixed directive order — `default-src` / `script-src` /
 * `style-src` / `img-src` / `font-src` / `connect-src` / (optional `worker-src`)
 * / `object-src` / `base-uri` / `form-action` / `frame-ancestors` — joined by
 * `'; '` with no trailing separator.
 *
 * @returns the single-line CSP header value (no trailing semicolon).
 */
export function spa_csp(options?: SpaCspOptions): string {
	const {
		websocket = 'wss://{{domain}}',
		connect_src_extra = [],
		img_src_extra = [],
		worker_src_extra
	} = options ?? {};

	const img_src = [`'self'`, 'data:', ...img_src_extra].join(' ');
	const connect_src = [`'self'`, websocket, ...connect_src_extra].join(' ');

	const directives = [
		`default-src 'self'`,
		`script-src 'self' 'unsafe-inline' 'wasm-unsafe-eval'`,
		`style-src 'self' 'unsafe-inline'`,
		`img-src ${img_src}`,
		`font-src 'self'`,
		`connect-src ${connect_src}`
	];

	if (worker_src_extra !== undefined) {
		const worker_src = [`'self'`, ...worker_src_extra].join(' ');
		directives.push(`worker-src ${worker_src}`);
	}

	directives.push(
		`object-src 'none'`,
		`base-uri 'self'`,
		`form-action 'self'`,
		`frame-ancestors 'self'`
	);

	return directives.join('; ');
}
