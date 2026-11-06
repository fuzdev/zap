/**
 * The neutral nginx core shared by the `recipe_debian_nginx` /
 * `recipe_alpine_nginx` wrappers.
 *
 * These build the nginx config fragments for a single-page app behind nginx — a
 * prerendered SvelteKit frontend
 * served as static files, with `/api`, `/health` and `/ready` reverse-proxied to a loopback
 * backend, SSL terminated by nginx, and an HTTP→HTTPS redirect:
 *
 * - `ssl_params` — the shared `ssl_protocols`/`ssl_ciphers`/session snippet
 *   content, identical across distros, written at `SSL_PARAMS_PATH` on both.
 * - `rate_limit_zone` — the `limit_req_zone` line for the http-context rate
 *   limiter, identical across distros.
 * - `nginx_site_core` — the full site: the HTTPS `server { listen 443 ssl }`
 *   block (SSL, security headers, the `/api` proxy, `/health`, `/ready`, `/_app`,
 *   the SPA catch-all, plus any app-specific `extra_locations`) and the HTTP→HTTPS
 *   redirect `server { listen 80 }` block (ACME challenge + 301), plus an HTTPS
 *   redirect block when `redirect_domains` names aliases (`www.`). The wrapper
 *   supplies `ssl_snippet_path` — where the `ssl: 'snippet'` `include` points —
 *   which is `SSL_PARAMS_PATH` on both distros.
 *
 * The server-block _content_ and the snippet path are the same on both distros. What
 * differs is placement: the caller writes the site to `sites-available/` (linked into
 * `sites-enabled/`) on Debian and to `http.d/` on Alpine, and the `rate_limit_zone`
 * file to `conf.d/` or `http.d/`; and the stock default site sits in `sites-enabled/`
 * or `http.d/`. The public site recipes are the thin `debian_nginx_spa_site` /
 * `alpine_nginx_spa_site` wrappers (with the matching `*_nginx_catch_all`)
 * rather than this core.
 *
 * ## Templating boundary
 *
 * The site config is zap `template` content: the site recipes return the whole
 * `{type: 'template', template, vars, kinds}` object, the caller's `domain` and `port`
 * as its `vars`, so a caller writes `zap.file({..., content: debian_nginx_spa_site({...})})`
 * with `domain: zap.env('DEPLOY_DOMAIN')`, `port: '4040'`, `root`, and `csp`. The body holds
 * `{{domain}}` / `{{port}}` as placeholders, substituted at apply time once their
 * references resolve, while eval-time values (the document `root`, the `csp` header
 * value, …) are interpolated here.
 *
 * `{{domain}}` lands in `server_name`, `return 301 https://…` and the certificate
 * paths, and `{{port}}` in `proxy_pass`: a `;`, `{` or `}` in either would end the
 * directive or the block. The content declares them a `hostname` and a `port`, so zap
 * refuses a value that is neither. Used whole, the content carries its kinds;
 * overriding `kinds` or rebuilding the content drops them. A `redirect_domains` entry
 * that carries a reference adds one more variable, `redirect_domain_<i>` (`i` its
 * index in `redirect_domains`), held to `hostname` too. Beyond those, a placeholder in
 * `extra_locations` or a literal `redirect_domains` entry uses `{{domain}}` or
 * `{{port}}`, and any other is a structural error when the config is read.
 *
 * Recipes are imported at config eval time inside zap's sandboxed config eval
 * (`fgro eval`), which has no network, no writes, and no environment, and where
 * the clock and randomness throw. This module is therefore a set of **pure functions**: each only
 * assembles a string from its arguments — no I/O, no clock, no randomness, no
 * imports beyond types and the pure `single_quote` and `letsencrypt_live_path`. The
 * output is deterministic for given inputs (stable ordering, trailing newline), so it
 * stays a reliable content-addressed plan artifact.
 *
 * The caller wraps each result in a file resource, e.g. for Debian
 * `zap.file({id: 'nginx-ssl-params', path: SSL_PARAMS_PATH, content: {type: 'inline', content: ssl_params()}})`
 * (Alpine writes the same content at the same path).
 *
 * @module
 */

import { letsencrypt_live_path } from './recipe_certbot.ts';
import type { FileResource, ScriptResource, TemplateContent, VerifyResource } from './schema.ts';
import { single_quote } from './shell.ts';

/**
 * The `validate` command for a `file` holding nginx config — a site, a snippet, or an
 * http-context include. `nginx -t` checks the whole tree the running config loads, so
 * a write that would make the next reload fail is rolled back instead of left on disk.
 * `sudo` because the check reads the TLS private keys.
 */
export const NGINX_VALIDATE = 'sudo nginx -t';

/**
 * The `verify` payload that re-checks the on-disk nginx config with
 * `NGINX_VALIDATE` on every plan (detection reads every resource live).
 *
 * The files' `validate` gates each write, but a config the running nginx can't
 * reload onto can still reach disk — a hand edit, an apply killed mid-rollback,
 * a site that only becomes active when its `sites-enabled` link lands — and its
 * bytes match the declared ones, so the files alone read as converged. A failing
 * check shows as a pending change and blocks `zap deploy`'s preflight. Spread it
 * into a `zap.verify` that depends on the nginx service.
 *
 * @returns the `verify` `assertions`.
 */
export function nginx_config_verify(): VerifyResource {
	return { assertions: [{ type: 'command', run: NGINX_VALIDATE }] };
}

/**
 * The on-disk path of the `ssl_params` snippet, the same on Debian and Alpine: the
 * distro site wrappers pass it as `ssl_snippet_path`, and a config writes the
 * `ssl_params` file here. Under `snippets/`, never Alpine's auto-included `http.d/`,
 * which would declare the session zone a second time.
 */
export const SSL_PARAMS_PATH = '/etc/nginx/snippets/ssl_params.conf';

/**
 * Build the shared SSL-parameters snippet content.
 *
 * The `ssl_protocols`/`ssl_ciphers`/`ssl_prefer_server_ciphers` +
 * `ssl_session_*` block both server contexts include to avoid duplication. The
 * value is fixed across distros, and so is its path (`SSL_PARAMS_PATH`), so this
 * takes no parameters.
 *
 * The session-cache zone is named `fuz_app_SSL`, not the conventional `SSL`, because
 * Alpine's stock `nginx.conf` already declares `ssl_session_cache shared:SSL:2m` in the
 * http block — a second `SSL` zone at a different size makes `nginx -t` fail with a
 * zone-size conflict. A unique name sidesteps any distro's built-in zone (Debian's
 * `nginx.conf` declares none, so it's harmless there).
 *
 * @returns the complete snippet text, terminated by a trailing newline.
 */
export function ssl_params(): string {
	return `ssl_protocols TLSv1.2 TLSv1.3;
ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384;
ssl_prefer_server_ciphers off;
ssl_session_cache shared:fuz_app_SSL:10m;
ssl_session_timeout 1d;
ssl_session_tickets off;
`;
}

/**
 * The single rate-limit zone name, shared by `rate_limit_zone` (which _defines_ the
 * zone) and `nginx_site_core` (whose `/api` + `/ready` `limit_req` directives
 * _reference_ it). One constant so the definition and the references can't drift — a
 * `limit_req` naming a zone no `limit_req_zone` defined fails `nginx -t`. (This is why
 * the zone name isn't an option: it would let the two sides diverge silently.)
 *
 * A fixed name assumes one zap-managed site per host. Two of them would write the same
 * `rate_limit.conf` path with each other's rate — fighting on every apply — and
 * co-declaring the zone in one http context fails `nginx -t` on the duplicate.
 * Co-hosting needs a per-site zone name (and path) before it needs anything else here.
 *
 * Exported so a config's own `limit_req` (in an `extra_locations` block) references
 * the zone by this constant rather than repeating its name.
 */
export const RATE_LIMIT_ZONE = 'global';

/** Options for `rate_limit_zone`. */
export interface RateLimitZoneOptions {
	/** Shared-memory zone size. Defaults to `'10m'`. */
	size?: string;
	/** `rate=` cap. Defaults to `'10r/s'`. */
	rate?: string;
}

/**
 * Build the http-context rate-limit zone line (`rate_limit.conf`, which the caller
 * writes under `conf.d/` on Debian and `http.d/` on Alpine).
 *
 * Emits the single directive the `/api` and `/ready` `limit_req` directives reference,
 * `limit_req_zone $binary_remote_addr zone=<zone>:<size> rate=<rate>;`, keyed on the client
 * IP; the defaults suit a single-page app's API.
 *
 * @returns the directive text, terminated by a trailing newline.
 */
export function rate_limit_zone(options?: RateLimitZoneOptions): string {
	const { size = '10m', rate = '10r/s' } = options ?? {};

	return `limit_req_zone $binary_remote_addr zone=${RATE_LIMIT_ZONE}:${size} rate=${rate};\n`;
}

/**
 * Options for the public site recipes (`debian_nginx_spa_site` /
 * `alpine_nginx_spa_site`) — the portable, distro-agnostic inputs. The
 * `ssl_snippet_path` is supplied by the wrapper, not here.
 */
export interface NginxSpaSiteOptions {
	/**
	 * The site's host name, `{{domain}}`'s value — typically a reference,
	 * `zap.env('DEPLOY_DOMAIN')`. Held to `hostname` once it resolves.
	 */
	domain: string;
	/** The backend's loopback port, `{{port}}`'s value. Held to `port`. */
	port: string | number;
	/** Document `root` for the static frontend, e.g. `` `${CURRENT_LINK}/build` ``. */
	root: string;
	/**
	 * The `Content-Security-Policy` header value (interpolated, not a placeholder). One
	 * holding a `"`, a `\`, a `$`, or a line break is refused: inside the quoted header
	 * value the first three end it or read as an escape or an nginx variable.
	 */
	csp: string;
	/**
	 * How SSL is wired into the HTTPS server.
	 *
	 * - `'snippet'` (default) — `include <ssl_snippet_path>;` (paired with the
	 *   `ssl_params` recipe written to that path; zap owns the full config).
	 * - `'certbot'` — `include /etc/letsencrypt/options-ssl-nginx.conf;` +
	 *   `ssl_dhparam /etc/letsencrypt/ssl-dhparams.pem;` (certbot-managed params).
	 */
	ssl?: 'snippet' | 'certbot';
	/**
	 * Serve HTTP/2 in the HTTPS server. Defaults to `true`.
	 *
	 * On by default because the alternative is a worse baseline for every site:
	 * without it a browser is capped at six connections per origin and repeats
	 * every request and response header uncompressed, which dominates the wire
	 * cost of any page serving many small assets. HPACK plus multiplexing
	 * removes both, and ALPN falls back to HTTP/1.1 for clients that can't
	 * negotiate h2, so there is no client-compatibility cost.
	 *
	 * Emitted as the `listen ... http2` parameter rather than the `http2 on;`
	 * directive. The directive is the modern spelling, but it only exists from
	 * nginx 1.25.1; on anything older it is an unknown directive that fails
	 * `nginx -t` outright, and Ubuntu 24.04 LTS ships nginx 1.24. The parameter form
	 * works on both sides of 1.25.1 (deprecated above it, still honored, one
	 * warning logged at start), so it is the spelling that delivers h2 on every
	 * supported host.
	 *
	 * One thing to know before turning it off — and the reason this is an option
	 * at all rather than unconditional:
	 *
	 * - **`limit_req` `burst=` absorbs arrival pattern, and h2 changes it.**
	 *   The `/api` burst was sized against requests trickling in six at a time;
	 *   over one multiplexed connection a page's whole RPC fan-out can arrive at
	 *   once. The zone rate is unaffected (`limit_req` counts requests, not
	 *   connections), but a site with a heavy fan-out on load may need a larger
	 *   `api_burst` than it did on HTTP/1.1.
	 */
	http2?: boolean;
	/**
	 * Server-level `client_max_body_size` cap. Emitted as its own line (with the
	 * surrounding blank lines) only when set; omit for nginx's default.
	 */
	client_max_body_size?: string;
	/**
	 * App-specific comment line rendered directly above `client_max_body_size`
	 * (without the leading `# `, which is added here). Ignored unless
	 * `client_max_body_size` is set; omit for no comment.
	 */
	client_max_body_size_comment?: string;
	/** `/api` `limit_req` `burst=`. Defaults to `50`. */
	api_burst?: number;
	/**
	 * The `location /` `try_files` arguments (the SPA fallback chain).
	 * Defaults to `'$uri $uri/index.html /200.html'`.
	 */
	spa_try_files?: string;
	/**
	 * `error_page 404 <target>;` in the HTTPS server, e.g. `'/404.html'`.
	 * Emitted only when set.
	 */
	error_page_404?: string;
	/**
	 * App-specific `location` blocks injected into the HTTPS server verbatim
	 * (already indented to the server-block level, no leading/trailing blank
	 * lines), placed just before the `/_app` static block. A block with no
	 * `add_header` inherits the server's security headers and CSP; one with its own
	 * inherits none, so it renders `site_security_header_directives(csp)` beside them,
	 * or a `Content-Security-Policy` of its own. A block (a `location`, or an `if` in
	 * one) that sets `add_header` with no `Content-Security-Policy` is refused.
	 */
	extra_locations?: string;
	/** ACME HTTP-01 challenge webroot for the redirect server. Defaults to `/var/www/certbot`. */
	acme_webroot?: string;
	/**
	 * Further host names that 301 to `https://{{domain}}` — e.g. `['www.{{domain}}']`
	 * to send `www.` to the apex. Each joins the HTTP server's `server_name` (so the
	 * ACME challenge is served for it too) and gets a lean HTTPS `server` that only
	 * redirects, on the site's certificate, so the cert must cover them: pass the
	 * same names to the certbot recipes' `extra_domains`. Defaults to none.
	 *
	 * A literal name may use the `{{domain}}` placeholder, substituted with the rest
	 * of the template. A name that carries a reference (`zap.env('MIRROR_DOMAIN')`,
	 * whole or interpolated) becomes its own variable, `redirect_domain_<i>` for the
	 * entry at index `i`, held to `hostname` once it resolves; it takes no placeholder,
	 * since a variable's value is never read for one.
	 */
	redirect_domains?: ReadonlyArray<string>;
}

/**
 * Options for `nginx_site_core` — the public-recipe inputs plus the path the
 * wrapper supplies.
 */
export interface NginxSiteCoreOptions extends NginxSpaSiteOptions {
	/**
	 * The on-disk path the `ssl: 'snippet'` `include` points at — the one bit of
	 * the site config the distro wrappers supply, `SSL_PARAMS_PATH` on both.
	 * Unused when `ssl === 'certbot'`.
	 */
	ssl_snippet_path: string;
}

/**
 * The kinds of the site template's variables: `domain` a host name and `port` a port,
 * the forms `server_name`, the certificate paths, and `proxy_pass` take.
 */
const NGINX_SITE_KINDS = { domain: 'hostname', port: 'port' } as const;

/**
 * The variable a `redirect_domains` entry carrying a reference becomes, named for the
 * entry's index.
 */
export type NginxRedirectDomainVar = `redirect_domain_${number}`;

/**
 * The `template` content a site recipe returns: the body, its values, their kinds —
 * `domain` and `port`, plus one `redirect_domain_<i>` per `redirect_domains` entry
 * carrying a reference.
 */
export interface NginxSiteContent extends TemplateContent {
	vars: { domain: string; port: string | number } & Record<NginxRedirectDomainVar, string>;
	kinds: typeof NGINX_SITE_KINDS & Record<NginxRedirectDomainVar, 'hostname'>;
}

/** Whether `value` carries a reference: a reference marker's opening delimiter. */
const carries_reference = (value: string): boolean => value.includes('\uFDD0');

/** The `redirect_domains` names as the template writes them, and the variables they add. */
interface NginxRedirectNames {
	names: Array<string>;
	vars: Record<NginxRedirectDomainVar, string>;
	kinds: Record<NginxRedirectDomainVar, 'hostname'>;
}

/**
 * Write each `redirect_domains` entry as the template holds it: a literal entry as
 * given, an entry carrying a reference as the placeholder of a variable of its own.
 *
 * @throws Error if an entry carrying a reference also holds a placeholder
 */
const redirect_names = (redirect_domains: ReadonlyArray<string>): NginxRedirectNames => {
	const result: NginxRedirectNames = { names: [], vars: {}, kinds: {} };
	redirect_domains.forEach((entry, i) => {
		if (!carries_reference(entry)) {
			result.names.push(entry);
			return;
		}
		if (entry.includes('{{')) {
			throw new Error(
				`nginx_site_core: redirect_domains[${i}] carries a reference and a \`{{\`: it becomes a variable, whose value is never read for placeholders; write the name the reference resolves to whole`
			);
		}
		const name: NginxRedirectDomainVar = `redirect_domain_${i}`;
		result.names.push(`{{${name}}}`);
		result.vars[name] = entry;
		result.kinds[name] = 'hostname';
	});
	return result;
};

/**
 * The site-independent security-header `add_header … always;` directives: HSTS,
 * `X-Frame-Options`, `nosniff`, and `Referrer-Policy`, in render order, unindented.
 * The `Content-Security-Policy` is per site, so it is not here:
 * `site_security_header_directives` appends it.
 *
 * nginx drops inherited `add_header` directives in any block that sets its own,
 * so the set can't be declared once at the server level. A block that sets its
 * own headers repeats the whole set, the CSP included, or it serves without them:
 * an `extra_locations` block renders `site_security_header_directives(csp)`. A
 * block with a policy of its own (a sandboxing CSP for user-uploaded bytes) renders
 * these and its own `Content-Security-Policy` instead.
 */
export const SECURITY_HEADER_DIRECTIVES: ReadonlyArray<string> = [
	'add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;',
	'add_header X-Frame-Options "SAMEORIGIN" always;',
	'add_header X-Content-Type-Options "nosniff" always;',
	'add_header Referrer-Policy "strict-origin-when-cross-origin" always;'
];

/**
 * The full security-header set a site's server block declares, as the directives a
 * block that sets its own `add_header` repeats: `SECURITY_HEADER_DIRECTIVES` and the
 * site's `Content-Security-Policy`, in render order, unindented.
 *
 * @param csp - the site's `Content-Security-Policy` value, the `csp` the site recipe is given
 * @returns the directives, one per entry.
 */
export function site_security_header_directives(csp: string): Array<string> {
	if (/["\\\r\n$]/.test(csp)) {
		throw new Error(
			`site_security_header_directives: csp ${JSON.stringify(csp)} must hold no \`"\`, \`\\\`, \`$\` or line break: the first three end the quoted header value or read as an escape or an nginx variable there`
		);
	}
	return [...SECURITY_HEADER_DIRECTIVES, `add_header Content-Security-Policy "${csp}" always;`];
}

/** One `{ … }` block of nginx config: its opening words and its own directives' names. */
interface NginxBlock {
	/** The words before `{`, e.g. `location /mapdata/`. */
	head: string;
	/** Each directive directly in the block, by its words, nested blocks excluded. */
	directives: Array<Array<string>>;
}

/**
 * Split nginx config text into its blocks, as nginx tokenizes it: `#` to the end of a
 * line is a comment, a quoted string is part of a word (a `\` in it escapes the next
 * character, a quote included), a `\` escapes the next character, `${name}` is a
 * variable whose braces stay in the word, and a word ends at a blank, `;`, `{` or `}`.
 */
const nginx_blocks = (text: string): Array<NginxBlock> => {
	const blocks: Array<NginxBlock> = [];
	const stack: Array<NginxBlock> = [];
	let words: Array<string> = [];
	let word: string | null = null;
	// inside a `${name}` variable, whose braces are part of the word
	let in_variable = false;
	const end_word = () => {
		if (word !== null) words.push(word);
		word = null;
		in_variable = false;
	};
	for (let i = 0; i < text.length; i++) {
		const c = text[i]!;
		if (c === '\\') {
			word = (word ?? '') + (text[i + 1] ?? '');
			i++;
		} else if (c === '"' || c === "'") {
			// one character at a time, so an escaped quote doesn't end the string
			let value = '';
			for (i++; i < text.length && text[i] !== c; i++) {
				if (text[i] === '\\' && i + 1 < text.length) i++;
				value += text[i];
			}
			word = (word ?? '') + value;
		} else if (c === '#' && word === null) {
			const eol = text.indexOf('\n', i);
			i = eol === -1 ? text.length : eol;
		} else if (/\s/.test(c)) {
			end_word();
		} else if (c === ';') {
			end_word();
			if (words.length > 0) stack.at(-1)?.directives.push(words);
			words = [];
		} else if (c === '{' && word?.endsWith('$')) {
			word += c;
			in_variable = true;
		} else if (c === '}' && in_variable) {
			word = (word ?? '') + c;
			in_variable = false;
		} else if (c === '{') {
			end_word();
			const block: NginxBlock = { head: words.join(' '), directives: [] };
			blocks.push(block);
			stack.push(block);
			words = [];
		} else if (c === '}') {
			end_word();
			stack.pop();
			words = [];
		} else {
			word = (word ?? '') + c;
		}
	}
	return blocks;
};

/**
 * Refuse an `extra_locations` block that sets a header of its own but no
 * `Content-Security-Policy`: nginx gives a block with any `add_header` none of the
 * server's, so such a block serves without the site's CSP.
 */
const assert_extra_locations_keep_csp = (extra_locations: string): void => {
	for (const block of nginx_blocks(extra_locations)) {
		const headers = block.directives.filter((words) => words[0] === 'add_header');
		if (headers.length === 0) continue;
		if (
			headers.some(
				(words) =>
					words[1]?.toLowerCase() === 'content-security-policy' && (words[2] ?? '').trim() !== ''
			)
		) {
			continue;
		}
		throw new Error(
			`nginx_site_core: the extra_locations block \`${block.head}\` sets add_header but no non-empty Content-Security-Policy, and nginx gives a block with any add_header none of the server's, so it would serve without the site's CSP; render site_security_header_directives(csp) in it, or a Content-Security-Policy of its own`
		);
	}
};

/**
 * The security-header block at `indent`: `site_security_header_directives(csp)`, or
 * `SECURITY_HEADER_DIRECTIVES` alone where `csp` is omitted (a redirect-only server).
 * Lines are joined by newlines with no trailing newline — the caller's template
 * supplies the surrounding lines.
 */
function security_headers(indent: string, csp?: string): string {
	const directives =
		csp === undefined ? SECURITY_HEADER_DIRECTIVES : site_security_header_directives(csp);
	return directives.map((directive) => `${indent}${directive}`).join('\n');
}

/**
 * The SSL-parameter lines of a server block at the server-block indent, no trailing
 * newline: the `ssl_params` snippet's `include` (`'snippet'`), or certbot's options file
 * and DH parameters (`'certbot'`).
 */
function ssl_params_lines(ssl: 'snippet' | 'certbot', ssl_snippet_path: string): string {
	return ssl === 'certbot'
		? `    include /etc/letsencrypt/options-ssl-nginx.conf;
    ssl_dhparam /etc/letsencrypt/ssl-dhparams.pem;`
		: `    include ${ssl_snippet_path};`;
}

/**
 * Build the full nginx site config for a single-page app behind nginx — the neutral
 * core the distro wrappers call.
 *
 * Composes the HTTPS `server` block — SSL cert + the SSL params (snippet or
 * certbot), HTTP/2 unless `http2` is off, `server_tokens off`, an optional
 * server-level `client_max_body_size`,
 * the document `root`, the security-header set with the CSP (repeated in the
 * `/_app` and `location /` blocks, which set headers of their own and so inherit
 * none; the proxied locations inherit it), a rate-limited `/api` reverse
 * proxy (with WebSocket upgrade headers + `Authorization` forward + timeouts),
 * `/health`, the `/ready` deploy-readiness gate (zap's post-deploy poll target),
 * the immutable `/_app` static block, any `extra_locations`, an
 * optional `error_page 404`, and the SPA catch-all `location /` (no-cache +
 * the `try_files` fallback) — plus the
 * HTTP→HTTPS redirect `server` block (ACME challenge served plain, everything
 * else 301'd), and, for any `redirect_domains`, an HTTPS `server` that 301s them
 * to `{{domain}}`.
 *
 * Neither server is a `default_server`: the `*_nginx_catch_all` recipes add one that
 * gives a request for any other host name no answer, so the proxied locations forward
 * only this site's names to the backend as `$host`.
 *
 * `{{domain}}` / `{{port}}` are placeholders for zap's template engine, their values
 * the options' `domain` and `port`; `root`/`csp`/etc. are interpolated from the
 * options. Prefer the `debian_nginx_spa_site` / `alpine_nginx_spa_site` wrappers,
 * which supply `ssl_snippet_path` for you.
 *
 * @returns the `template` content: the complete site config (terminated by a trailing
 * newline), `domain` and `port` as its `vars` with a `redirect_domain_<i>` for each
 * `redirect_domains` entry carrying a reference, and their kinds.
 * @throws Error if `csp` holds a `"`, a `\`, a `$`, or a line break, if an
 * `extra_locations` block sets `add_header` with no non-empty
 * `Content-Security-Policy`, if a `redirect_domains` entry carrying a reference holds a
 * placeholder, or if another input writes a `redirect_domain_<i>` placeholder such an
 * entry fills
 */
export function nginx_site_core(options: NginxSiteCoreOptions): NginxSiteContent {
	const {
		domain,
		port,
		root,
		csp,
		ssl = 'snippet',
		ssl_snippet_path,
		http2 = true,
		client_max_body_size,
		client_max_body_size_comment,
		api_burst = 50,
		spa_try_files = '$uri $uri/index.html /200.html',
		error_page_404,
		extra_locations,
		acme_webroot = '/var/www/certbot',
		redirect_domains = []
	} = options;

	// HTTP/2 as a `listen` parameter on both sockets, not the `http2 on;`
	// directive — see the `http2` option's docs for why the older spelling is
	// the one that runs on every supported host.
	const http2_param = http2 ? ' http2' : '';

	const ssl_include = ssl_params_lines(ssl, ssl_snippet_path);

	// Server-level body-size cap: its own paragraph with a leading blank line
	// when present (an optional app-specific comment above the directive),
	// nothing at all when omitted.
	const client_max_body_size_comment_line =
		client_max_body_size_comment === undefined ? '' : `    # ${client_max_body_size_comment}\n`;
	const client_max_body_size_block =
		client_max_body_size === undefined
			? ''
			: `
${client_max_body_size_comment_line}    client_max_body_size ${client_max_body_size};
`;

	// App-specific blocks: a leading blank line + the verbatim content, placed
	// before the `/_app` static block. Nothing when omitted.
	if (extra_locations !== undefined) assert_extra_locations_keep_csp(extra_locations);
	const extra_locations_block =
		extra_locations === undefined
			? ''
			: `
${extra_locations}
`;

	// `error_page 404` in the HTTPS server: its own paragraph with surrounding
	// blank lines, nothing when omitted.
	const error_page_block =
		error_page_404 === undefined
			? ''
			: `
    error_page 404 ${error_page_404};
`;

	// the HTTP server answers for the redirect names too, so one `server_name`
	// line carries every name and the ACME challenge works for each
	const redirect = redirect_names(redirect_domains);
	const http_server_names = ['{{domain}}', ...redirect.names].join(' ');

	// HTTPS redirect server for the extra names: same cert and SSL params, and the
	// site-independent security headers (HSTS among them, so a browser remembers
	// HTTPS for the name; no CSP, since it serves only redirects). Nothing when
	// there are no redirect names.
	const redirect_server_block =
		redirect_domains.length === 0
			? ''
			: `
# HTTPS redirect to the canonical domain
server {
    listen 443 ssl${http2_param};
    listen [::]:443 ssl${http2_param};
    server_name ${redirect.names.join(' ')};

    ssl_certificate ${letsencrypt_live_path('{{domain}}', 'fullchain.pem')};
    ssl_certificate_key ${letsencrypt_live_path('{{domain}}', 'privkey.pem')};
${ssl_include}

    server_tokens off;

${security_headers('    ')}

    location / {
        return 301 https://{{domain}}$request_uri;
    }
}
`;

	const template = `# Main HTTPS server
server {
    listen 443 ssl${http2_param};
    listen [::]:443 ssl${http2_param};
    server_name {{domain}};

    ssl_certificate ${letsencrypt_live_path('{{domain}}', 'fullchain.pem')};
    ssl_certificate_key ${letsencrypt_live_path('{{domain}}', 'privkey.pem')};
${ssl_include}

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
${client_max_body_size_block}
    root ${root};

    # Security headers
${security_headers('    ', csp)}

    # API and health routes -> backend. The /api prefix covers /api/rpc and the
    # /api/ws WebSocket upgrade; the upgrade headers below carry both.
    location /api {
        # Rate limit dynamic API traffic only. burst is generous to absorb
        # the dashboard's RPC fan-out on load; auth endpoints also have their
        # own app-level per-IP limiters as the real backstop.
        limit_req zone=${RATE_LIMIT_ZONE} burst=${api_burst} nodelay;

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
        limit_req zone=${RATE_LIMIT_ZONE} burst=5 nodelay;
        proxy_pass http://127.0.0.1:{{port}};
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
${extra_locations_block}
    # Static files with caching
    location /_app {
        expires 1y;
        add_header Cache-Control "public, immutable";
${security_headers('        ', csp)}
        try_files $uri =404;
    }
${error_page_block}
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
${security_headers('        ', csp)}
        # Serve prerendered route HTML when present (public-read: real <title>,
        # content, SEO); fall back to the 200.html SPA shell for dynamic routes.
        try_files ${spa_try_files};
    }
}
${redirect_server_block}
# HTTP -> HTTPS redirect
server {
    listen 80;
    listen [::]:80;
    server_name ${http_server_names};

    # ACME HTTP-01 challenge (certbot --webroot). Served over plain HTTP and
    # NOT redirected, so certbot renew works with nginx running on port 80
    # (the old --standalone authenticator couldn't bind 80 while nginx held it).
    location /.well-known/acme-challenge/ {
        root ${acme_webroot};
        default_type "text/plain";
        try_files $uri =404;
    }

    location / {
        return 301 https://{{domain}}$request_uri;
    }
}
`;
	assert_redirect_placeholders_own(template, redirect.vars);
	return {
		type: 'template',
		template,
		vars: { domain, port, ...redirect.vars },
		kinds: { ...NGINX_SITE_KINDS, ...redirect.kinds }
	};
}

/**
 * Refuse a `redirect_domain_<i>` placeholder written by another input: each such
 * variable fills the two `server_name` lines its entry is placed on, and nowhere else.
 */
const assert_redirect_placeholders_own = (
	template: string,
	vars: Record<NginxRedirectDomainVar, string>
): void => {
	for (const name of Object.keys(vars)) {
		const count = template.split(`{{${name}}}`).length - 1;
		if (count !== 2) {
			throw new Error(
				`nginx_site_core: the placeholder \`{{${name}}}\` is the redirect_domains reference's own, and another input, or a literal redirect_domains entry, writes it; rename it there`
			);
		}
	}
};

/**
 * The main nginx config, the same path on Debian and Alpine: the package installs it, so
 * the stock default site can only be there to remove once it is. The recipe assumes the
 * distro package's `/etc/nginx` layout.
 */
const NGINX_CONF_PATH = '/etc/nginx/nginx.conf';

/** The `check`/`run` pair of the stock-default removal `nginx_catch_all_core` returns. */
export type NginxRemoveDefaultScript = Pick<ScriptResource, 'check' | 'run'>;

/**
 * The neutral core of the stock-default removal: remove the default-site file at
 * `default_path` (so it can't shadow the real site, or claim `default_server` beside
 * the catch-all) and validate the config with `nginx -t`. The `check` reads converged
 * once nginx is installed (its `nginx.conf` is on disk) and nothing is at the path,
 * not even a dangling link; before nginx is installed it reads pending, so a fresh host
 * plans the removal and runs it after the package it is ordered behind, instead of
 * reading the not-yet-installed default as already gone. The distro wrappers differ
 * only in that path — Debian's `sites-enabled/default` symlink vs Alpine's
 * `http.d/default.conf`.
 *
 * @returns the `script` `check`/`run` pair.
 */
export function nginx_remove_default_core(default_path: string): NginxRemoveDefaultScript {
	return {
		check: `test ! -e ${single_quote(default_path)} && test ! -L ${single_quote(default_path)} && test -e ${single_quote(NGINX_CONF_PATH)}`,
		run: `set -e
sudo rm -f -- ${single_quote(default_path)}
${NGINX_VALIDATE}`
	};
}

/** Options for the `*_nginx_catch_all` recipes. */
export interface NginxCatchAllOptions {
	/**
	 * Whether the site serves HTTP/2: pass the site recipe's `http2`. The catch-all's
	 * `listen 443` sockets carry the same `http2` parameter as the site's, so the two
	 * servers on one address and port agree on it. Defaults to `true`, the site's default.
	 */
	http2?: boolean;
	/**
	 * How the site wires its SSL parameters: pass the site recipe's `ssl`. Defaults to
	 * `'snippet'`, the site's default. The catch-all `include`s the same parameters,
	 * because as the `default_server` it is the server whose SSL settings nginx starts
	 * every handshake with — its protocols, ciphers and session cache apply to the
	 * site's handshakes too, and without them a distro's own defaults would (Debian's
	 * allow TLS 1.2 ciphers without forward secrecy). That file must be on disk before the
	 * catch-all is written, or its `nginx -t` fails: order the catch-all after the
	 * `ssl_params` file (`'snippet'`) or the certificate issuance (`'certbot'`).
	 */
	ssl?: 'snippet' | 'certbot';
}

/** The two payloads the `*_nginx_catch_all` recipes return, each spread into its resource. */
export interface NginxCatchAll {
	/** The stock-default removal, for a `zap.script`. */
	remove_default: NginxRemoveDefaultScript;
	/** The catch-all server, for a `zap.file` ordered after the removal. */
	catch_all: Required<Pick<FileResource, 'path' | 'content' | 'validate'>>;
}

/**
 * Build the catch-all server text: the `default_server` on every socket the site
 * recipe listens on (port 80 and 443, IPv4 and IPv6), answering any request for a
 * name no other server has with nginx's `444` (the connection closed, no response),
 * and refusing the TLS handshake (`ssl_reject_handshake`), so it needs no certificate
 * and shows none. It carries the site's SSL parameters (see `NginxCatchAllOptions.ssl`),
 * `ssl_snippet_path` being where the `'snippet'` ones are, as the site recipe takes it.
 *
 * @returns the server block text, terminated by a trailing newline.
 */
export function nginx_catch_all_server(
	options: NginxCatchAllOptions & { ssl_snippet_path: string }
): string {
	const { http2 = true, ssl = 'snippet', ssl_snippet_path } = options;
	const http2_param = http2 ? ' http2' : '';
	return `# Managed by zap: any host name no site serves gets no answer
server {
    listen 80 default_server;
    listen [::]:80 default_server;
    listen 443 ssl${http2_param} default_server;
    listen [::]:443 ssl${http2_param} default_server;
    server_name _;
${ssl_params_lines(ssl, ssl_snippet_path)}
    ssl_reject_handshake on;
    return 444;
}
`;
}

/**
 * The neutral core of the `*_nginx_catch_all` recipes: the stock-default removal at
 * `default_path` and the catch-all server at `catch_all_path`.
 *
 * The site recipes declare no `default_server`, so without a catch-all nginx answers a
 * request for any other name (or none) with the first server on the port, the site,
 * and the proxied locations forward that name to the backend as `$host`. The
 * catch-all closes those requests instead. Order its file after the removal (the
 * stock default site is itself a `default_server`, and two fail `nginx -t`, the file's
 * `validate`) and after the SSL parameters it includes. A site meant to answer any host
 * name declares only the removal.
 *
 * @returns the removal `script` payload and the catch-all `file` payload.
 */
export function nginx_catch_all_core(
	default_path: string,
	catch_all_path: string,
	options?: NginxCatchAllOptions
): NginxCatchAll {
	const content = nginx_catch_all_server({ ...options, ssl_snippet_path: SSL_PARAMS_PATH });
	return {
		remove_default: nginx_remove_default_core(default_path),
		catch_all: {
			path: catch_all_path,
			content: { type: 'inline', content },
			validate: NGINX_VALIDATE
		}
	};
}
