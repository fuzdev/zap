/**
 * Debian/Ubuntu nginx site recipes — the `nginx_site_core` body wired to the
 * Debian layout (`sites-available` + `sites-enabled` symlink, `snippets/` for
 * the SSL include, `conf.d/` for the rate-limit zone).
 *
 * The neutral core (the server block) lives in `recipe_nginx.ts`;
 * these wrappers only supply the distro-specific paths, so the load-bearing
 * config isn't duplicated. The Alpine sibling is `recipe_alpine_nginx.ts`.
 *
 * Recipes are pure functions evaluated in zap's sandboxed config eval
 * (`fgro eval`: no I/O, clock, or randomness); the output is deterministic.
 *
 * @module
 */

import {
	type NginxSiteContent,
	type NginxSpaSiteOptions,
	type NginxCatchAll,
	type NginxCatchAllOptions,
	SSL_PARAMS_PATH,
	nginx_catch_all_core,
	nginx_site_core
} from './recipe_nginx.ts';

/**
 * Build the full Debian nginx site config for a single-page app.
 *
 * Delegates to `nginx_site_core` with the SSL-snippet path `SSL_PARAMS_PATH`. The
 * caller gives the result as the `content` of a file at
 * `/etc/nginx/sites-available/<domain>` and symlinks it
 * into `sites-enabled`.
 *
 * @returns the site's `template` content, `domain` and `port` its `vars`, plus any
 * `redirect_domain_<i>` (see `nginx_site_core`).
 */
export function debian_nginx_spa_site(options: NginxSpaSiteOptions): NginxSiteContent {
	return nginx_site_core({
		...options,
		ssl_snippet_path: SSL_PARAMS_PATH
	});
}

/**
 * Build the Debian catch-all: the removal of the stock `sites-enabled/default` symlink,
 * and the catch-all `default_server` file at `/etc/nginx/conf.d/00-catch-all.conf`
 * (`conf.d/`, which Debian's `nginx.conf` includes in its `http` block). See
 * `nginx_catch_all_core`: order the file after the removal and after the SSL
 * parameters, and give `http2` and `ssl` as the site recipe has them.
 *
 * @returns the removal `script` payload and the catch-all `file` payload.
 */
export function debian_nginx_catch_all(options?: NginxCatchAllOptions): NginxCatchAll {
	return nginx_catch_all_core(
		'/etc/nginx/sites-enabled/default',
		'/etc/nginx/conf.d/00-catch-all.conf',
		options
	);
}
