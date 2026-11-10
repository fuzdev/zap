/**
 * Alpine firewall — the neutral web-host allow set wired to nftables, plus the companion
 * service that makes the ruleset survive a reboot. The neutral rule set lives in
 * `recipe_firewall.ts`; the Debian sibling is `recipe_debian_firewall.ts`.
 *
 * Unlike ufw (which self-persists), the nftables backend writes `/etc/nftables.nft` and
 * loads it once with `nft -f`; the `nftables` service is what reloads it at boot. So this
 * recipe returns **both** pieces — and zap rejects an nftables firewall with no enabled
 * `service: 'nftables'` at plan time, so bundling them here makes the correct shape the
 * default rather than something each config has to remember.
 *
 * Pure function evaluated in zap's sandboxed config eval (`fgro eval`).
 *
 * @module
 */

import { type WebFirewallOptions, web_firewall_allow_rules } from './recipe_firewall.ts';
import type { FirewallResource, ServiceResource } from './schema.ts';

/**
 * Build the nftables `firewall` payload **and** its companion persistence `service` for
 * a web host (SSH on `ssh_port` + HTTP + HTTPS).
 *
 * Spread each piece into its own resource, and make the service depend on the firewall
 * so the ruleset file is written before the service loads it:
 *
 * ```ts
 * const fw = alpine_web_firewall();
 * zap.firewall({id: 'firewall', ...fw.firewall});
 * zap.service({id: 'nftables', depends_on: ['firewall'], ...fw.service});
 * ```
 *
 * @returns `{firewall, service}` — the payloads for a `firewall` and a `service` resource.
 * @throws Error if `ssh_port` is not a port
 */
export function alpine_web_firewall(options?: WebFirewallOptions): {
	firewall: Pick<FirewallResource, 'backend' | 'allow'>;
	service: Pick<ServiceResource, 'service' | 'enabled' | 'running'>;
} {
	return {
		firewall: { backend: 'nftables', allow: web_firewall_allow_rules(options) },
		service: { service: 'nftables', enabled: true, running: true }
	};
}
