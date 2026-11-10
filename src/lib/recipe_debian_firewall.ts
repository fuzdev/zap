/**
 * Debian/Ubuntu firewall — the neutral web-host allow set wired to ufw. The neutral
 * rule set lives in `recipe_firewall.ts`; the Alpine sibling is `recipe_alpine_firewall.ts`.
 *
 * ufw persists its own rules across reboot (`ufw --force enable`), so — unlike the
 * Alpine/nftables sibling — this needs no companion persistence service.
 *
 * Pure function evaluated in zap's sandboxed config eval (`fgro eval`).
 *
 * @module
 */

import { type WebFirewallOptions, web_firewall_allow_rules } from './recipe_firewall.ts';
import type { FirewallResource } from './schema.ts';

/**
 * Build the ufw `firewall` payload for a web host (SSH on `ssh_port` + HTTP + HTTPS).
 *
 * Spread into a `zap.firewall({id, ...debian_web_firewall()})`. Leaves
 * `default_incoming` / `default_outgoing` at the schema defaults (deny in, allow out).
 *
 * @returns the `backend` + `allow` for a ufw `firewall` resource.
 * @throws Error if `ssh_port` is not a port
 */
export function debian_web_firewall(
	options?: WebFirewallOptions
): Pick<FirewallResource, 'backend' | 'allow'> {
	return { backend: 'ufw', allow: web_firewall_allow_rules(options) };
}
