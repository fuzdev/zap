/**
 * Alpine sshd service — `ssh_service_core` wired to OpenRC. The neutral
 * `ssh_hardening` content, `SSHD_VALIDATE`, `ssh_hardening_verify`, and the core
 * live in `recipe_ssh.ts`; the Debian sibling is `recipe_debian_ssh.ts`.
 *
 * Alpine's OpenSSH service is named `sshd` (Debian's systemd unit is `ssh`).
 *
 * Pure function evaluated in zap's sandboxed config eval (`fgro eval`).
 *
 * @module
 */

import { type SshService, type SshServiceOptions, ssh_service_core } from './recipe_ssh.ts';

/**
 * Build the sshd `service` payload for Alpine: OpenRC's `sshd` service, enabled,
 * running, and reloaded when any of `options.reload_on` changes.
 *
 * @returns the `service` payload.
 */
export function alpine_ssh_service(options: SshServiceOptions): SshService {
	return ssh_service_core('sshd', options);
}
