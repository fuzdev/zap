/**
 * Recipes for the certbot bootstrap + renewal scripts.
 *
 * These build the `check`/`run` payloads of the certbot `script` resources a
 * TLS-terminating host declares:
 *
 * - `certbot_standalone_issue_core` — issues the first certificate via
 *   `certbot certonly --standalone`, stopping nginx first to free port 80; the
 *   `recipe_debian_certbot.ts` / `recipe_alpine_certbot.ts` wrappers
 *   (`{debian,alpine}_certbot_standalone_issue`) pass the service-manager stop
 *   command, the one step that differs by distro.
 * - `certbot_webroot_switch` — re-issues once via `--webroot` to pin the
 *   unattended renewal authenticator to webroot (so renewal works while nginx
 *   holds port 80), then runs the deploy hook it is given, so the server picks up
 *   the re-issued certificate.
 *
 * Both take `extra_domains` for the names beside the primary one a cert covers
 * (the `www.` alias a site redirects), matching the nginx site recipe's
 * `redirect_domains`.
 *
 * Both scripts that lead to a request to the CA — the first issuance and the
 * webroot switch — run a DNS preflight before they change anything: each name the
 * certificate covers must resolve, on the target, only to `expected_addresses`. A name that doesn't resolve, or resolves
 * anywhere else, refuses the script with the reason on stderr, so a host whose DNS
 * isn't pointed at it yet doesn't spend Let's Encrypt's failed-validation limit. The
 * issuance stops nginx inside the same `run`, after the preflight passes, so a
 * refusal never leaves nginx stopped, and the stop runs only once the names the
 * request covers have passed. The preflight reads the target's resolver, not the CA's:
 * see `CertbotDnsPreflightOptions.expected_addresses` for what that can't know.
 *
 * Renewal scheduling also differs by distro: Debian's `certbot` package installs
 * `certbot.timer` automatically; Alpine has none, so `recipe_alpine_certbot.ts`
 * supplies `alpine_certbot_renew_cron`.
 *
 * Neither schedule reloads anything after a renewal, so a server keeps serving the
 * old certificate until it restarts. `certbot_deploy_hook_core` builds the file that
 * closes that gap: an executable in `CERTBOT_DEPLOY_HOOKS_DIR`, which certbot runs
 * after every certificate it renews, whatever started the renewal. The distro
 * wrappers (`debian_certbot_reload_nginx_hook`, `alpine_certbot_reload_nginx_hook`)
 * pass the reload command.
 *
 * The caller passes the certificate's `domain`, the registration `email`, and the
 * `expected_addresses`, each written out or a reference
 * (`zap.env('DEPLOY_DOMAIN')`), which stays inert in the plan and is resolved by zap
 * at apply time. Every value is one single-quoted word of the command
 * (`single_quote`), so a value — a reference's or a literal — can't change what the
 * command runs. Both requests pass `--non-interactive --agree-tos`: running either
 * script agrees, for `email`, to the ACME server's terms (Let's Encrypt's subscriber
 * agreement) without asking.
 *
 * Recipes are imported at config eval time inside zap's sandboxed config eval
 * (`fgro eval`), which has no network, no writes, and no environment, and where
 * the clock and randomness throw. This module is therefore a set of **pure functions**: each only
 * assembles strings from its arguments — no I/O, no clock, no randomness, and no
 * import beyond types, `single_quote` and `validate_run_parts_name`, themselves pure. The output is deterministic for given inputs, so it
 * stays a reliable content-addressed plan artifact.
 *
 * The caller spreads each script result into a `script` resource, e.g.
 * `zap.script({id: 'ssl-certificate', name: '...', ...debian_certbot_standalone_issue({domain, email, expected_addresses}), depends_on: [...]})`
 * with `domain: zap.env('DEPLOY_DOMAIN')`, `email: zap.env('DEPLOY_CERTBOT_EMAIL')` and
 * `expected_addresses: [zap.env('DEPLOY_HOST')]`,
 * and a deploy hook into a `file`, e.g.
 * `zap.file({id: 'certbot-deploy-hook', name: '...', ...hook, depends_on: ['certbot']})` with
 * `const hook = debian_certbot_reload_nginx_hook()`, which the webroot switch also takes
 * (`certbot_webroot_switch({domain, email, expected_addresses, deploy_hook: hook})`, its
 * `script` depending on the hook's `file`).
 *
 * @module
 */

import type { ScriptResource } from './schema.ts';
import { type RunPartsFile, validate_run_parts_name } from './run_parts.ts';
import { single_quote } from './shell.ts';

/** The `check`/`run` pair the certbot recipes return (caller supplies `id`/`name`/`depends_on`). */
export type CertbotScript = Pick<ScriptResource, 'check' | 'run'>;

/** The `-d` arguments: `domain` first, so certbot names the cert for it, then each extra name. */
const domain_args = (domain: string, extra_domains: ReadonlyArray<string>): string =>
	[domain, ...extra_domains].map((name) => `-d ${single_quote(name)}`).join(' ');

/**
 * The path of one of the files certbot keeps for `domain`'s certificate, under
 * `/etc/letsencrypt/live/`. `domain` is spliced in as given, so a reference or a
 * `{{domain}}` template placeholder composes as a literal name does.
 *
 * @param domain - the certificate's name, its first `-d` domain
 * @param file - the certificate chain or its private key
 * @returns the path
 */
export function letsencrypt_live_path(
	domain: string,
	file: 'fullchain.pem' | 'privkey.pem'
): string {
	return `/etc/letsencrypt/live/${domain}/${file}`;
}

/**
 * The DNS preflight's shell function, defined at the head of each guarded `run`.
 *
 * `zap_certbot_dns_preflight <n> <address>… <name>…` takes the count of expected
 * addresses, the addresses, then the names. Each address must be an IP literal: IPv4
 * as four decimal octets with no leading zero, IPv6 checked only for its characters
 * (hex digits, `:` and `.`) and compared lowercased, so it must be written as the
 * target's `getent` prints it (compressed). Each name must be a DNS name (letters,
 * digits, `.` and `-`, not starting with `-`). The target resolves it through its own
 * resolver, `/etc/hosts` first, twice: `getent ahosts`, whose failure means the name
 * doesn't resolve, and `getent hosts`, whose failure is ignored. `ahosts` asks with
 * `AI_ADDRCONFIG`, so on a host with IPv6 disabled both glibc and musl drop the AAAA
 * records from it; `hosts` prints them still (glibc every one, musl only the first).
 * Every distinct address in the first column of the two outputs must be an expected
 * one, and output with no address in it refuses. Every problem is reported on stderr
 * before the function returns nonzero. A constant: values reach it only as arguments.
 */
const DNS_PREFLIGHT_FUNCTION = `zap_certbot_dns_preflight() {
	zap_n=$1
	shift
	zap_expected=
	while [ "$zap_n" -gt 0 ]; do
		zap_ip=$1
		shift
		zap_n=$((zap_n - 1))
		zap_ok=1
		case $zap_ip in
		*:*)
			case $zap_ip in *[!0-9A-Fa-f:.]*) zap_ok= ;; esac
			;;
		*[!0-9.]* | .* | *. | *..* | *.*.*.*.*) zap_ok= ;;
		*.*.*.*)
			zap_rest=$zap_ip.
			while [ -n "$zap_rest" ]; do
				zap_octet=\${zap_rest%%.*}
				zap_rest=\${zap_rest#*.}
				case $zap_octet in 0?* | ????*) zap_ok= ;; esac
				[ -n "$zap_ok" ] && [ "$zap_octet" -gt 255 ] && zap_ok=
			done
			;;
		*) zap_ok= ;;
		esac
		if [ -z "$zap_ok" ]; then
			printf 'certbot DNS preflight: the expected address "%s" is not an IP address literal (a reference resolves to what it names, which may be a host name); declare expected_addresses with the IP addresses the certificate names must resolve to\\n' "$zap_ip" >&2
			return 1
		fi
		zap_expected="$zap_expected $(printf '%s' "$zap_ip" | tr 'A-F' 'a-f')"
	done
	if [ -z "$zap_expected" ]; then
		printf 'certbot DNS preflight: no expected addresses; declare expected_addresses\\n' >&2
		return 1
	fi
	zap_refused=
	for zap_name in "$@"; do
		case $zap_name in
		'' | -* | *[!A-Za-z0-9.-]*)
			printf 'certbot DNS preflight: "%s" is not a DNS name certbot can validate\\n' "$zap_name" >&2
			zap_refused=1
			continue
			;;
		esac
		if zap_out=$(getent ahosts "$zap_name"); then zap_status=0; else zap_status=$?; fi
		if [ "$zap_status" -ne 0 ] || [ -z "$zap_out" ]; then
			printf 'certbot DNS preflight: %s does not resolve on the target (getent ahosts exit %s); point its A/AAAA records at the expected addresses (%s) before certbot runs\\n' "$zap_name" "$zap_status" "\${zap_expected# }" >&2
			zap_refused=1
			continue
		fi
		zap_hosts=$(getent hosts "$zap_name" 2>/dev/null) || zap_hosts=
		if zap_bad=$(printf '%s\\n%s\\n' "$zap_out" "$zap_hosts" | awk -v want="$zap_expected " '{ a = tolower($1) } a != "" { n++ } a != "" && index(want, " " a " ") == 0 && !(a in seen) { seen[a] = 1; printf "%s%s", sep, a; sep = " " } END { if (n == 0) exit 1 }'); then :; else
			printf 'certbot DNS preflight: could not read the addresses %s resolves to\\n' "$zap_name" >&2
			zap_refused=1
			continue
		fi
		if [ -n "$zap_bad" ]; then
			printf 'certbot DNS preflight: %s resolves to %s, outside the expected addresses (%s); the CA validates whichever address it picks, so point every A/AAAA record of the name at this host, or add the address to expected_addresses if it belongs to this host\\n' "$zap_name" "$zap_bad" "\${zap_expected# }" >&2
			zap_refused=1
		fi
	done
	if [ -n "$zap_refused" ]; then
		printf 'certbot DNS preflight: refused; nothing was run\\n' >&2
		return 1
	fi
}
`;

/**
 * The guarded form of `command`: the DNS preflight for `[domain, ...extra_domains]`
 * against `expected_addresses`, then `command` only if it passes. Every value is one
 * single-quoted word.
 */
const dns_guarded = (
	command: string,
	domain: string,
	extra_domains: ReadonlyArray<string>,
	expected_addresses: ReadonlyArray<string>
): string => {
	const args = [
		String(expected_addresses.length),
		...expected_addresses.map(single_quote),
		...[domain, ...extra_domains].map(single_quote)
	];
	return `${DNS_PREFLIGHT_FUNCTION}zap_certbot_dns_preflight ${args.join(' ')} && ${command}`;
};

/**
 * Refuse certbot options missing a required value, or with no expected address: the
 * one check of them, which each certbot recipe runs under its own name, so a refusal
 * names the function the config called. A config evaluated as JavaScript has no type
 * check to catch a missing value, which would reach the command as `undefined`.
 *
 * @param recipe - the recipe asking, named in the error
 * @param options - the options the recipe was given
 * @throws Error when `domain`, `email`, or `expected_addresses` is missing, or
 * `expected_addresses` is empty, which would refuse every name
 */
export function validate_certbot_options(
	recipe: string,
	options: Partial<CertbotStandaloneIssueOptions> | undefined
): void {
	for (const field of ['domain', 'email'] as const) {
		const value = options?.[field];
		if (typeof value !== 'string' || value === '') {
			throw new Error(
				`${recipe}: ${field} is required, e.g. zap.env('${field === 'domain' ? 'DEPLOY_DOMAIN' : 'DEPLOY_CERTBOT_EMAIL'}')`
			);
		}
	}
	if (!Array.isArray(options?.expected_addresses)) {
		throw new Error(
			`${recipe}: expected_addresses is required: the IP addresses the certificate names must resolve to, e.g. [zap.env('DEPLOY_HOST')]`
		);
	}
	if (options.expected_addresses.length === 0) {
		throw new Error(
			`${recipe}: expected_addresses is empty, so every name would be refused; list the IP addresses the certificate names resolve to`
		);
	}
}

/** The shared "certificate already issued" guard — `test -f <live>/fullchain.pem`. */
const cert_exists_check = (domain: string): string =>
	`sudo test -f ${single_quote(letsencrypt_live_path(domain, 'fullchain.pem'))}`;

/**
 * The DNS preflight's option, shared by every certbot script that leads to a CA
 * request.
 */
export interface CertbotDnsPreflightOptions {
	/**
	 * The IP addresses every name the certificate covers must resolve to, on the
	 * target. Before the script changes anything, the target resolves each name with
	 * `getent ahosts` and `getent hosts` — through its own resolver, so `/etc/hosts`
	 * first — and refuses when a name doesn't resolve, when no address can be read, or
	 * when any A/AAAA address either prints is outside this set: Let's Encrypt
	 * validates whichever address it picks, so an undeclared AAAA would fail the
	 * validation. The two lookups together see every A and AAAA but in one case: on a
	 * musl host (Alpine) with IPv6 disabled, `ahosts` drops the AAAA records and
	 * `hosts` prints only the first, so a name with several AAAA, the first of them
	 * declared, passes unseen.
	 *
	 * The guard reads the target's resolver, not the CA's. An `/etc/hosts` line, a
	 * split-horizon answer, or a cached one can pass while public DNS doesn't point
	 * at the host yet, or refuse while it does. A name `/etc/hosts` maps to a
	 * loopback address refuses, the safe direction. That includes the
	 * `127.0.1.1 <name>` line a Debian install writes for the host's own name, when
	 * that name is the domain: remove the line, or give the host a name that isn't
	 * the domain (a tool that manages `/etc/hosts` may write the line back).
	 *
	 * Each value is an IP literal, or a reference resolving to one at apply time; the
	 * target checks it and refuses anything else (a host name, say), asking for this
	 * option. An IPv6 address is compared as text, lowercased, so write it as
	 * `getent` prints it (the compressed form). A reference to the target's host
	 * (`[zap.env('DEPLOY_HOST')]`) serves when that is an IP literal; list the
	 * addresses when the host is reached by name or the names also carry an AAAA.
	 * Required, and not empty.
	 */
	expected_addresses: ReadonlyArray<string>;
}

/**
 * The directory certbot runs deploy hooks from: every executable here runs after a
 * certificate is renewed (with `certbot renew`, the command both distros schedule).
 * Since certbot 5.3.0 they also run after `certonly` gets a new certificate; certbot
 * 4.0.0, which Debian 13 and Alpine 3.22 ship, runs them for `renew` only, so
 * `certbot_webroot_switch` runs its hook itself.
 */
export const CERTBOT_DEPLOY_HOOKS_DIR = '/etc/letsencrypt/renewal-hooks/deploy';

/** The default file name of the distro `*_certbot_reload_nginx_hook` hooks. */
export const RELOAD_NGINX_HOOK_NAME = 'reload-nginx';

/**
 * Build the `path` / `mode` / `content` of a certbot deploy hook, ready to spread
 * into a `zap.file({...})`: an executable `#!/bin/sh` script at
 * `CERTBOT_DEPLOY_HOOKS_DIR/<name>` that `exec`s `command`.
 *
 * A hook file rather than a `--deploy-hook` flag, so the renewal schedule
 * (`certbot.timer`, a cron job) needs no arguments and any renewal, scheduled or run
 * by hand, picks it up. On a certbot that also runs deploy hooks after `certonly`,
 * the hook fires during the first `--standalone` issuance, while nginx is stopped, so
 * `command` must succeed as a no-op when the service isn't running; the distro
 * wrappers' commands do. A failing hook is reported by certbot but doesn't undo the
 * renewal.
 *
 * @param command - the command the hook runs, as shell words by design (the hook is a
 *   shell script); the caller's own literal, never a value from elsewhere
 * @param name - the hook's file name: letters, digits, `_` and `-` only, so
 *   `run-parts`-style runners don't skip it and it can't leave the directory
 * @returns a spreadable `{path, mode, content}` for an inline `file` resource.
 * @throws when `name` holds any other character
 */
export function certbot_deploy_hook_core(command: string, name: string): RunPartsFile {
	validate_run_parts_name(name, 'certbot_deploy_hook_core');

	return {
		path: `${CERTBOT_DEPLOY_HOOKS_DIR}/${name}`,
		mode: '755',
		content: {
			type: 'inline',
			content: `#!/bin/sh
# Managed by zap — certbot runs this after it renews a certificate.
exec ${command}
`
		}
	};
}

/**
 * Options for the distro `*_certbot_reload_nginx_hook` wrappers — neutral; the
 * wrappers differ in the service-manager reload command.
 */
export interface CertbotReloadNginxHookOptions {
	/** The hook's file name under `CERTBOT_DEPLOY_HOOKS_DIR`. Defaults to `RELOAD_NGINX_HOOK_NAME` (`'reload-nginx'`). */
	name?: string;
}

/**
 * Options for `certbot_standalone_issue_core` and its distro wrappers
 * (`{debian,alpine}_certbot_standalone_issue`) — neutral; the wrappers differ in the
 * service-manager stop command.
 */
export interface CertbotStandaloneIssueOptions extends CertbotDnsPreflightOptions {
	/** The certificate domain, e.g. `zap.env('DEPLOY_DOMAIN')`. */
	domain: string;
	/**
	 * Further names the certificate covers beside `domain`, one `-d` each — e.g.
	 * the `www.` name a site's `redirect_domains` 301s to `domain`. The cert stays
	 * named for `domain`. Defaults to none.
	 */
	extra_domains?: ReadonlyArray<string>;
	/**
	 * The registration email, e.g. `zap.env('DEPLOY_CERTBOT_EMAIL')`. The request passes
	 * `--agree-tos` for it: running the script agrees to the ACME server's terms.
	 */
	email: string;
}

/** Options for `certbot_webroot_switch`. */
export interface CertbotWebrootSwitchOptions extends CertbotDnsPreflightOptions {
	/** The certificate domain, e.g. `zap.env('DEPLOY_DOMAIN')`. */
	domain: string;
	/**
	 * Further names the certificate covers beside `domain` (see
	 * `CertbotStandaloneIssueOptions.extra_domains`). When set, the `check` also
	 * requires each name in the live cert's subjectAltName, so adding a name to a
	 * host whose cert predates it re-issues the cert to cover it. Defaults to none.
	 */
	extra_domains?: ReadonlyArray<string>;
	/**
	 * The registration email, e.g. `zap.env('DEPLOY_CERTBOT_EMAIL')`. The request passes
	 * `--agree-tos` for it, as the first issuance does.
	 */
	email: string;
	/** The ACME challenge webroot. Defaults to `/var/www/certbot`. */
	webroot?: string;
	/**
	 * The deploy hook the `run` executes after `certonly` succeeds — the file a
	 * `*_certbot_reload_nginx_hook` returns, or any with its `path` — so the server
	 * loads the re-issued certificate: certbot before 5.3.0 runs deploy hooks for
	 * `renew` only. On a later certbot the hook runs twice, which a reload tolerates.
	 * The switch's `script` must depend on the hook's `file`.
	 */
	deploy_hook: Pick<RunPartsFile, 'path'>;
}

/**
 * The neutral core of the `ssl-certificate` bootstrap scripts
 * (`{debian,alpine}_certbot_standalone_issue`), which differ only in `stop_command`.
 *
 * Issues the first certificate via `certbot certonly --standalone`. The `run` passes
 * the DNS preflight, then stops nginx with `stop_command` (best effort, `|| true`) to
 * free port 80, then runs certbot; the stop and the request take their names from
 * the one `options`, and a refusal stops nothing. The `check` short-circuits once
 * the cert exists.
 *
 * @param stop_command - the service manager's stop command, as shell words by design;
 *   the caller's own literal, never a value from elsewhere
 * @param options - the certificate's names, its registration email, and the addresses
 *   the names must resolve to
 * @returns the `script` `check`/`run` pair.
 * @throws Error when `stop_command`, `options.domain`, `options.email`, or
 *   `options.expected_addresses` is missing, or `options.expected_addresses` is empty
 */
export function certbot_standalone_issue_core(
	stop_command: string,
	options: CertbotStandaloneIssueOptions
): CertbotScript {
	validate_certbot_options('certbot_standalone_issue_core', options);
	if (typeof stop_command !== 'string' || stop_command.trim() === '') {
		throw new Error(
			"certbot_standalone_issue_core: stop_command is required, the service manager's command that stops nginx"
		);
	}
	const { domain, extra_domains = [], email, expected_addresses } = options;

	return {
		check: cert_exists_check(domain),
		run: dns_guarded(
			`{ ${stop_command} || true; } && sudo certbot certonly --standalone ${domain_args(
				domain,
				extra_domains
			)} --non-interactive --agree-tos --email ${single_quote(email)}`,
			domain,
			extra_domains,
			expected_addresses
		)
	};
}

/**
 * Build the `certbot-renewal-webroot` script.
 *
 * Re-issues once via `--webroot` to pin the unattended renewal authenticator to
 * webroot, then runs `deploy_hook`; the `check` short-circuits once the renewal
 * config records webroot (and the live cert covers each of `extra_domains`). The
 * re-issue is a CA request, for every name the certificate covers, so the `run`
 * passes the DNS preflight first.
 *
 * @returns the `script` `check`/`run` pair.
 * @throws Error when `options.domain`, `options.email`, or `options.expected_addresses`
 *   is missing, or `options.expected_addresses` is empty
 */
export function certbot_webroot_switch(options: CertbotWebrootSwitchOptions): CertbotScript {
	validate_certbot_options('certbot_webroot_switch', options);
	const {
		domain,
		extra_domains = [],
		email,
		webroot = '/var/www/certbot',
		deploy_hook,
		expected_addresses
	} = options;

	const webroot_check = `sudo grep -q 'authenticator = webroot' ${single_quote(
		`/etc/letsencrypt/renewal/${domain}.conf`
	)}`;
	// one exact-line match per extra name against the cert's SAN list, split one
	// entry per line so `www.a.org` can't match inside `www.a.org.evil`
	const san_checks = extra_domains.map(
		(name) =>
			` && sudo openssl x509 -noout -ext subjectAltName -in ${single_quote(
				letsencrypt_live_path(domain, 'fullchain.pem')
			)} | tr ',' '\\n' | sed 's/^ *//' | grep -qxF ${single_quote(`DNS:${name}`)}`
	);

	return {
		check: webroot_check + san_checks.join(''),
		run: dns_guarded(
			`sudo certbot certonly --webroot -w ${single_quote(webroot)} ${domain_args(
				domain,
				extra_domains
			)} --cert-name ${single_quote(domain)} --non-interactive --agree-tos --email ${single_quote(
				email
			)} --force-renewal && sudo -- ${single_quote(deploy_hook.path)}`,
			domain,
			extra_domains,
			expected_addresses
		)
	};
}
