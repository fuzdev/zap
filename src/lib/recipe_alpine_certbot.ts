/**
 * Alpine certbot bootstrap + renewal. The neutral issuance core and renewal-pin
 * script are in `recipe_certbot.ts`; the Debian sibling is `recipe_debian_certbot.ts`.
 *
 * The Alpine specifics:
 *
 * - `alpine_certbot_standalone_issue` stops nginx via OpenRC (`rc-service`) rather
 *   than systemd to free port 80 for the first `--standalone` issuance.
 * - `alpine_certbot_renew_cron` supplies a daily renewal script, because Alpine's
 *   `certbot` package ships **no** `certbot.timer`. Spread it through
 *   `alpine_periodic_daily_file` (which encodes the `/etc/periodic/daily` path + the
 *   executable `755` mode BusyBox `crond` runs daily, so neither is hand-typed) into a
 *   `zap.file`, and declare a `crond` service so the cron actually fires.
 * - `alpine_certbot_reload_nginx_hook` is the deploy hook that reloads nginx via
 *   OpenRC after a renewal; the cron script passes no hook of its own.
 *
 * Pure functions evaluated in zap's sandboxed config eval (`fgro eval`).
 *
 * @module
 */

import {
	type CertbotReloadNginxHookOptions,
	type CertbotScript,
	type CertbotStandaloneIssueOptions,
	RELOAD_NGINX_HOOK_NAME,
	certbot_deploy_hook_core,
	certbot_standalone_issue_core,
	validate_certbot_options
} from './recipe_certbot.ts';
import { type RunPartsFile, validate_run_parts_name } from './run_parts.ts';

/**
 * Build the `ssl-certificate` bootstrap script for Alpine (fresh-host bootstrap
 * only).
 *
 * The `check` short-circuits once the cert exists; `run` passes the DNS preflight,
 * stops nginx via OpenRC (best effort) so `certbot certonly --standalone` can bind
 * port 80, and issues the first certificate. A refusal leaves nginx running.
 *
 * @returns the `script` `check`/`run` pair.
 * @throws Error when `options.domain`, `options.email`, or `options.expected_addresses`
 *   is missing, or `options.expected_addresses` is empty
 */
export function alpine_certbot_standalone_issue(
	options: CertbotStandaloneIssueOptions
): CertbotScript {
	validate_certbot_options('alpine_certbot_standalone_issue', options);
	return certbot_standalone_issue_core('sudo rc-service nginx stop', options);
}

/**
 * Build the daily certbot-renewal script for `/etc/periodic/daily/certbot-renew`.
 *
 * BusyBox `crond` runs every executable in `/etc/periodic/daily`, so this stands
 * in for Debian's `certbot.timer`. `certbot renew` no-ops when nothing is due. It
 * reloads nothing itself: pair it with `alpine_certbot_reload_nginx_hook`, which
 * certbot runs after each renewal.
 *
 * @returns the script body (write it mode `755`; the caller also needs a running `crond`).
 */
export function alpine_certbot_renew_cron(): string {
	return `#!/bin/sh
# Managed by zap — daily certbot renewal (Alpine ships no certbot.timer).
certbot renew --quiet
`;
}

/**
 * Build the certbot deploy hook that reloads nginx via OpenRC after a renewal, ready
 * to spread into a `zap.file({...})`.
 *
 * `rc-service --ifstarted` exits 0 without running the command when the service isn't
 * started, so the hook is a successful no-op while nginx is stopped (the first
 * `--standalone` issuance). It is named by its full path, `/sbin/rc-service`, so the
 * hook doesn't rest on the `PATH` certbot was started with (BusyBox `crond`'s holds
 * `/sbin`; a hand-run certbot's may not). A failing hook is reported by certbot and
 * doesn't undo the renewal.
 *
 * @returns a spreadable `{path, mode, content}` for an inline `file` resource.
 * @throws when `options.name` holds a character outside `[A-Za-z0-9_-]`
 */
export function alpine_certbot_reload_nginx_hook(
	options?: CertbotReloadNginxHookOptions
): RunPartsFile {
	const { name = RELOAD_NGINX_HOOK_NAME } = options ?? {};
	return certbot_deploy_hook_core('/sbin/rc-service --ifstarted nginx reload', name);
}

/** The BusyBox `crond` daily-jobs directory — every executable here runs once a day. */
export const ALPINE_PERIODIC_DAILY = '/etc/periodic/daily';

/** Options for `alpine_periodic_daily_file`. */
export interface AlpinePeriodicDailyFileOptions {
	/** The job's file name under `/etc/periodic/daily` (e.g. `'certbot-renew'`). */
	name: string;
	/** The script body — a `#!/bin/sh` executable (e.g. `alpine_certbot_renew_cron()`). */
	body: string;
}

/**
 * Build the `path` / `mode` / `content` for a BusyBox `crond` daily job, ready to spread
 * into a `zap.file({...})`.
 *
 * Encodes the `/etc/periodic/daily` convention and the executable `755` mode once, so
 * neither is hand-typed at the callsite (getting the dir wrong — `daily` vs `hourly`,
 * say — silently changes the schedule). The job only fires if a `crond` service is also
 * declared and running. `name` is letters, digits, `_` and `-` only: BusyBox `run-parts`
 * skips any other name.
 *
 * @returns a spreadable `{path, mode, content}` for an inline `file` resource.
 * @throws when `name` holds a character outside `[A-Za-z0-9_-]`
 */
export function alpine_periodic_daily_file(options: AlpinePeriodicDailyFileOptions): RunPartsFile {
	const { name, body } = options;
	validate_run_parts_name(name, 'alpine_periodic_daily_file');

	return {
		path: `${ALPINE_PERIODIC_DAILY}/${name}`,
		mode: '755',
		content: { type: 'inline', content: body }
	};
}
