/**
 * Alpine nginx site recipes — the `nginx_site_core` body wired to the Alpine
 * layout. The Debian sibling is `recipe_debian_nginx.ts`.
 *
 * Alpine's stock `nginx.conf` auto-includes `/etc/nginx/http.d/*.conf` (inside
 * `http {}`) — there is no `sites-available`/`sites-enabled` split. So the
 * config author places:
 *
 * - the **site** config at `/etc/nginx/http.d/<domain>.conf` (auto-included);
 * - the **rate-limit zone** at `/etc/nginx/http.d/rate_limit.conf` — `http`
 *   context, NOT `/etc/nginx/conf.d/` (which Alpine includes at the _main_
 *   context, where `limit_req_zone` is invalid);
 * - the **SSL snippet** at `SSL_PARAMS_PATH` (`/etc/nginx/snippets/ssl_params.conf`,
 *   the path Debian uses too; the `file` makes the missing directory), not under
 *   `http.d/`. The server blocks that need it (the site's and the catch-all's)
 *   `include` it explicitly; under `http.d/` it would also be auto-included at the
 *   `http` level, where its settings would apply to every server on the host, not
 *   only to those.
 *
 * The default `nginx.conf` also runs as `user nginx` (not Debian's `www-data`),
 * which matters for file ownership in the config, not for this server-block text.
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
 * Build the full Alpine nginx site config for a single-page app.
 *
 * Delegates to `nginx_site_core` with the SSL-snippet path `SSL_PARAMS_PATH`
 * (outside the auto-included `http.d/`, see the module doc). The caller gives the
 * result as the `content` of a file at `/etc/nginx/http.d/<domain>.conf` (no symlink —
 * `http.d/` is auto-included).
 *
 * @returns the site's `template` content, `domain` and `port` its `vars`, plus any
 * `redirect_domain_<i>` (see `nginx_site_core`).
 */
export function alpine_nginx_spa_site(options: NginxSpaSiteOptions): NginxSiteContent {
	return nginx_site_core({
		...options,
		ssl_snippet_path: SSL_PARAMS_PATH
	});
}

/**
 * Build the Alpine catch-all: the removal of the stock `http.d/default.conf` the `nginx`
 * package ships, and the catch-all `default_server` file at
 * `/etc/nginx/http.d/00-catch-all.conf` (the auto-included `http.d/`). See
 * `nginx_catch_all_core`: order the file after the removal and after the SSL
 * parameters, and give `http2` and `ssl` as the site recipe has them.
 *
 * @returns the removal `script` payload and the catch-all `file` payload.
 */
export function alpine_nginx_catch_all(options?: NginxCatchAllOptions): NginxCatchAll {
	return nginx_catch_all_core(
		'/etc/nginx/http.d/default.conf',
		'/etc/nginx/http.d/00-catch-all.conf',
		options
	);
}
