/**
 * Debian/Ubuntu certbot — the service-manager-specific certbot steps. The neutral
 * issuance core, the renewal-pin script and the deploy-hook core are in
 * `recipe_certbot.ts`; the Alpine sibling is `recipe_alpine_certbot.ts`.
 *
 * Debian's `certbot` package installs `certbot.timer`, which renews unattended (the
 * Alpine side needs `alpine_certbot_renew_cron`), but nothing reloads nginx after a
 * renewal: `debian_certbot_reload_nginx_hook` is the deploy hook that does.
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
	certbot_standalone_issue_core
} from './recipe_certbot.ts';
import type { RunPartsFile } from './run_parts.ts';

/**
 * Build the `ssl-certificate` bootstrap script for Debian (fresh-host bootstrap
 * only).
 *
 * The `check` short-circuits once the cert exists; `run` passes the DNS preflight,
 * stops nginx via systemd (best effort) so `certbot certonly --standalone` can bind
 * port 80, and issues the first certificate. A refusal leaves nginx running.
 *
 * @returns the `script` `check`/`run` pair.
 * @throws when `options.expected_addresses` is empty
 */
export function debian_certbot_standalone_issue(
	options?: CertbotStandaloneIssueOptions
): CertbotScript {
	return certbot_standalone_issue_core('sudo systemctl stop nginx', options);
}

/**
 * Build the certbot deploy hook that reloads nginx via systemd after a renewal, ready
 * to spread into a `zap.file({...})`.
 *
 * `systemctl try-reload-or-restart` acts only on a running unit, so the hook is a
 * successful no-op while nginx is stopped (the first `--standalone` issuance).
 *
 * @returns a spreadable `{path, mode, content}` for an inline `file` resource.
 * @throws when `options.name` holds a character outside `[A-Za-z0-9_-]`
 */
export function debian_certbot_reload_nginx_hook(
	options?: CertbotReloadNginxHookOptions
): RunPartsFile {
	const { name = RELOAD_NGINX_HOOK_NAME } = options ?? {};
	return certbot_deploy_hook_core('systemctl try-reload-or-restart nginx', name);
}
