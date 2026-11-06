/**
 * Recipes for a fuz_app server's `.env.production` content.
 *
 * Every fuz_app server shares the same `.env.production` preamble — the
 * `NODE_ENV`/`PORT`/`HOST` header, the Unix-socket `DATABASE_URL`, the
 * cookie-signing key, and the bootstrap-token path — plus, behind a reverse
 * proxy, the load-bearing trusted-proxies comment block. These build that shared
 * content once so a config concatenates it with its app-specific vars instead of
 * re-typing security-relevant prose that must converge:
 *
 * - `fuz_app_env_base` — the common header through `FUZ_BOOTSTRAP_TOKEN_PATH`.
 * - `fuz_app_trusted_proxies` — the `FUZ_<infix>_TRUSTED_PROXIES` stanza (the
 *   comment explaining why a missing value collapses per-IP rate limits and
 *   ruins `audit_log.ip`), keyed by the service's env-var infix.
 *
 * ## Templating boundary
 *
 * `fuz_app_env_base` returns the whole zap `template` content,
 * `{type: 'template', template, vars, kinds}`: the caller passes the values
 * (`port`, `cookie_keys`) and its own lines (`extra`), and gives the result as the
 * file's `content`. The header
 * holds `{{port}}` / `{{cookie_keys}}` as placeholders, substituted at apply time,
 * while eval-time values (`user`, `service`, `config_dir`) are interpolated here. A
 * caller's lines (allowed origins, facts dirs, SMTP, …) bring their own variables and
 * kinds; `fuz_app_trusted_proxies` returns text for them.
 *
 * ## Quoting
 *
 * The file has two readers: systemd reads it as an `EnvironmentFile=`, and OpenRC's
 * init script reads it as data by a subset of those rules (see
 * `recipe_alpine_openrc.ts`). So each value these interpolate or leave for the
 * template engine is one single-quoted word (`single_quote`), which both read
 * literally, `\` included. systemd honours a quote only where it opens the value, so
 * after the closing `'` it reads quotes as text and `\` as an escape (`'\''`
 * misreads), and it ends a value at a line break; the OpenRC reader refuses such a
 * line. A value holding a `'`, a line break, or a NUL is refused at eval
 * (`ENV_FILE_VALUE`), naming the field.
 *
 * A template value substituted into `'{{cookie_keys}}'` is the template engine's
 * text, not quoted again, since it resolves at apply time: a value holding a `'`
 * would end the quoting, so systemd would read a different value and OpenRC would
 * refuse to start the service. So `cookie_keys` is an `env_value`, which zap refuses
 * a `'` (and a line break), and `{{port}}` a `port`, which holds no quote. The lines
 * a caller appends are the caller's to quote, by the format `recipe_alpine_openrc.ts`
 * documents, and the placeholders in them the caller's to give a kind.
 *
 * Recipes are imported at config eval time inside zap's sandboxed config eval
 * (`fgro eval`), which has no network, no writes, and no environment, and where
 * the clock and randomness throw. This module is therefore a set of **pure functions**: each only
 * assembles a string from its arguments — no I/O, no clock, no randomness, no
 * imports beyond types and the pure `single_quote`. The output is deterministic for
 * given inputs (stable ordering, trailing newline), so it stays a reliable
 * content-addressed plan artifact.
 *
 * @module
 */

import type { TemplateContent, TemplateKind } from './schema.ts';
import { single_quote } from './shell.ts';

/**
 * What a value these write must be. Inside single quotes both readers take every byte
 * literally except these: systemd treats nothing after the closing `'` as quoting and
 * ends a value at a line break (a NUL ends it for both).
 */
const ENV_FILE_VALUE = /^[^'\n\r\0]*$/;

/** Refuse `value` for `field` of `recipe` unless it is an `ENV_FILE_VALUE`. */
const env_file_value = (recipe: string, field: string, value: string): void => {
	if (!ENV_FILE_VALUE.test(value)) {
		throw new Error(
			`${recipe}: ${field} ${JSON.stringify(
				value
			)} must hold no ' or line break, because systemd's EnvironmentFile= reads those differently and OpenRC's env file reader refuses them`
		);
	}
};

/**
 * What a role or database name in `DATABASE_URL` must be: a name with nothing the URL
 * reads as structure (`@`, `/`, `?`, `%`, `:`), which would point it elsewhere.
 */
const URL_NAME = /^[A-Za-z0-9_.-]+$/;

/** What `env_prefix` must be: part of an environment variable's name. */
const ENV_NAME_PART = /^[A-Za-z0-9_]+$/;

/** Options for `fuz_app_env_base`. */
export interface FuzAppEnvBaseOptions {
	/**
	 * The DB role in `DATABASE_URL`. The server connects over the Unix socket, where the
	 * stock `peer` rule admits only the OS account of the same name, so this is the
	 * account the service runs as. Letters, digits, `_`, `.`, and `-`, written out (no
	 * reference): it is a name in `DATABASE_URL`, refused at eval otherwise.
	 */
	user: string;
	/**
	 * The database name in `DATABASE_URL`. Letters, digits, `_`, `.`, and `-`, written
	 * out (no reference), refused at eval otherwise.
	 */
	service: string;
	/**
	 * Directory holding `secret_bootstrap_token`, e.g. `/home/<user>/.myapp`.
	 * The emitted `FUZ_BOOTSTRAP_TOKEN_PATH` is `<config_dir>/secret_bootstrap_token`.
	 */
	config_dir: string;
	/** The port the server listens on, `{{port}}`'s value (`PORT`). Held to `port`. */
	port: string | number;
	/**
	 * The cookie-signing keys, `{{cookie_keys}}`'s value (`SECRET_FUZ_COOKIE_KEYS`) —
	 * a reference, `zap.env('SECRET_FUZ_COOKIE_KEYS')`. Held to `env_value`: it sits
	 * inside single quotes.
	 */
	cookie_keys: string;
	/** The caller's own lines, appended after the base, with their variables. */
	extra?: FuzAppEnvExtra;
}

/**
 * A caller's own env-file lines, appended to `fuz_app_env_base`'s: their text, the
 * values of the placeholders they add, and those values' kinds.
 *
 * The lines may use the base's `{{port}}` and `{{cookie_keys}}`, but `vars` and
 * `kinds` can't name them: the base's values and kinds are its own. Used whole, the
 * content carries its kinds; overriding `kinds` or rebuilding the content drops them.
 * A variable `vars` adds and `kinds` leaves out declares no kind (a reference in its
 * value is still held to `text`; a value written out is substituted unchecked), so give
 * each the kind of the place it lands (`env_value` inside single quotes).
 */
export interface FuzAppEnvExtra {
	/** The lines, quoted by the format `recipe_alpine_openrc.ts` documents. */
	template: string;
	/** The values of the placeholders the lines add. */
	vars?: Record<string, unknown> & { port?: never; cookie_keys?: never };
	/** The kinds of the variables `vars` adds. */
	kinds?: Record<string, TemplateKind> & { port?: never; cookie_keys?: never };
}

/**
 * The kinds of the base's variables: both sit inside single quotes, and `port` is a
 * port, which holds no quote.
 */
const ENV_BASE_KINDS = { port: 'port', cookie_keys: 'env_value' } as const;

/**
 * Build a fuz_app server's `.env.production` content: the shared header, then the
 * caller's `extra` lines.
 *
 * The header emits `NODE_ENV`/`PORT`/`HOST`, the `DATABASE_URL` over the PostgreSQL
 * Unix socket in `/run/postgresql` (where Debian and Alpine both put it),
 * `SECRET_FUZ_COOKIE_KEYS`, and `FUZ_BOOTSTRAP_TOKEN_PATH` — the section identical
 * across fuz_app server deploys. `{{port}}` and `{{cookie_keys}}` are placeholders
 * whose values are `port` and `cookie_keys`, held to `port` and `env_value`.
 *
 * @returns the `template` content: the header (ending in a newline) and `extra`'s
 * lines, the variables of both, and their kinds.
 * @throws when `user`, `service`, or `config_dir` can't be written as they must be, or
 * `extra` names a variable of the base's
 */
export function fuz_app_env_base(options: FuzAppEnvBaseOptions): TemplateContent {
	const { user, service, config_dir, port, cookie_keys, extra } = options;
	for (const name of Object.keys(ENV_BASE_KINDS)) {
		for (const [field, map] of [
			['vars', extra?.vars],
			['kinds', extra?.kinds]
		] as const) {
			if (map !== undefined && Object.hasOwn(map, name)) {
				throw new Error(
					`fuz_app_env_base: extra.${field} names \`${name}\`, which is the base's own; give it through \`${name}\``
				);
			}
		}
	}
	env_file_value('fuz_app_env_base', 'user', user);
	env_file_value('fuz_app_env_base', 'service', service);
	env_file_value('fuz_app_env_base', 'config_dir', config_dir);
	const url_names: Array<[string, string]> = [
		['user', user],
		['service', service]
	];
	for (const [field, value] of url_names) {
		if (!URL_NAME.test(value)) {
			throw new Error(
				`fuz_app_env_base: ${field} ${JSON.stringify(value)} must be letters, digits, \`_\`, \`.\`, or \`-\`, because it is a name in DATABASE_URL`
			);
		}
	}

	const base = `# Production environment configuration

NODE_ENV=production
PORT='{{port}}'
HOST=127.0.0.1

# Database - PostgreSQL over its Unix socket, peer auth as the service's own account
DATABASE_URL=${single_quote(`postgres://${user}@/${service}?host=/run/postgresql`)}

# Auth - cookie signing keys (for key rotation, separate with __)
SECRET_FUZ_COOKIE_KEYS='{{cookie_keys}}'

# Bootstrap - one-shot token for first-time keeper account creation
FUZ_BOOTSTRAP_TOKEN_PATH=${single_quote(`${config_dir}/secret_bootstrap_token`)}
`;
	return {
		type: 'template',
		template: base + (extra?.template ?? ''),
		vars: { port, cookie_keys, ...extra?.vars },
		kinds: { ...extra?.kinds, ...ENV_BASE_KINDS }
	};
}

/** Options for `fuz_app_trusted_proxies`. */
export interface FuzAppTrustedProxiesOptions {
	/** The service infix in `FUZ_<infix>_TRUSTED_PROXIES`, e.g. `'FORGE'`. */
	env_prefix: string;
	/** The trusted proxy address(es). Defaults to `'127.0.0.1'` (the loopback nginx hop). */
	value?: string;
}

/**
 * Build the `FUZ_<infix>_TRUSTED_PROXIES` env stanza (comment + var line).
 *
 * The comment is the load-bearing rationale: without the var, the backend
 * attributes every request to `127.0.0.1` (nginx's loopback address), so per-IP
 * rate limits collapse into one shared bucket and `audit_log.ip` is useless.
 *
 * @returns the stanza text, terminated by a trailing newline.
 */
export function fuz_app_trusted_proxies(options: FuzAppTrustedProxiesOptions): string {
	const { env_prefix, value = '127.0.0.1' } = options;
	env_file_value('fuz_app_trusted_proxies', 'value', value);
	if (!ENV_NAME_PART.test(env_prefix)) {
		throw new Error(
			`fuz_app_trusted_proxies: env_prefix ${JSON.stringify(
				env_prefix
			)} must be letters, digits, or \`_\`, because it is part of a variable's name.`
		);
	}

	return `# Trust the loopback nginx reverse proxy so the backend resolves the real
# client IP from X-Forwarded-For (nginx connects from 127.0.0.1). Without this
# every request is attributed to 127.0.0.1 — per-IP rate limits collapse into a
# single shared bucket and audit_log.ip is useless. nginx is the only hop and
# sets X-Forwarded-For to the client's address.
FUZ_${env_prefix}_TRUSTED_PROXIES=${single_quote(value)}
`;
}
