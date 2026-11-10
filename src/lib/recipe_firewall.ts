/**
 * The neutral firewall allow-set shared by the `recipe_debian_firewall` /
 * `recipe_alpine_firewall` wrappers.
 *
 * A web host accepts the same inbound traffic on every distro — SSH, HTTP, and
 * HTTPS — so the _rule set_ is neutral; what differs is the backend (ufw self-persists,
 * nftables needs a companion service to reload its ruleset at boot), which is why the
 * public recipes are the thin `debian_web_firewall` / `alpine_web_firewall`
 * wrappers rather than this module.
 *
 * Pure functions evaluated in zap's sandboxed config eval (`fgro eval`: no I/O,
 * clock, or randomness); the output is deterministic.
 *
 * @module
 */

import { DEFAULT_SSH_PORT, type SshPortOptions, to_ssh_port } from './recipe_ssh.ts';
import type { FirewallAllowRule } from './schema.ts';

/** The HTTP and HTTPS rules of the web-host allow set. */
const HTTP_ALLOW: ReadonlyArray<FirewallAllowRule> = [
	{ port: 80, proto: 'tcp' },
	{ port: 443, proto: 'tcp' }
];

/**
 * The standard web-host inbound allow set with sshd on its default port: SSH (22),
 * HTTP (80), HTTPS (443), all tcp. `web_firewall_allow_rules` builds the set for
 * another `ssh_port`.
 *
 * Expressed as port/proto rules rather than ufw named profiles (`'OpenSSH'`,
 * `'Nginx Full'`) so the identical set works on **both** backends — nftables has no
 * application-profile concept (a named rule under it is a config error zap rejects at
 * plan). One source for "what a web host accepts," shared by both wrappers.
 */
export const WEB_FIREWALL_ALLOW: ReadonlyArray<FirewallAllowRule> = [
	{ port: DEFAULT_SSH_PORT, proto: 'tcp' },
	...HTTP_ALLOW
];

/**
 * Options shared by `debian_web_firewall` / `alpine_web_firewall`. `ssh_port` is the
 * port the SSH rule allows: give it the value `ssh_hardening_verify` and
 * `fail2ban_jail` get, or the deny-default firewall shuts sshd out.
 */
export interface WebFirewallOptions extends SshPortOptions {
	/**
	 * Extra allow rules appended after the SSH/HTTP/HTTPS baseline (e.g. a metrics
	 * port). Keep them port/proto pairs so they stay portable across both backends.
	 */
	allow_extra?: ReadonlyArray<FirewallAllowRule>;
}

/**
 * The baseline allow set, its SSH rule on `ssh_port`, plus any `allow_extra`, as a
 * fresh mutable array (the shared `firewall.allow` both wrappers build on).
 *
 * @returns a new `FirewallAllowRule[]` — the baseline is never mutated.
 * @throws Error if `ssh_port` is not a port
 */
export function web_firewall_allow_rules(options?: WebFirewallOptions): FirewallAllowRule[] {
	const ssh_port = to_ssh_port('web_firewall_allow_rules', options);
	return [{ port: ssh_port, proto: 'tcp' }, ...HTTP_ALLOW, ...(options?.allow_extra ?? [])];
}
