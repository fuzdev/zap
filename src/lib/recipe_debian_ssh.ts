/**
 * Debian/Ubuntu sshd service — `ssh_service_core` wired to systemd's `ssh` unit.
 * The neutral `ssh_hardening` content, `SSHD_VALIDATE`, `ssh_hardening_verify`, and
 * the core live in `recipe_ssh.ts`; the Alpine sibling is `recipe_alpine_ssh.ts`.
 *
 * Pure function evaluated in zap's sandboxed config eval (`fgro eval`).
 *
 * @module
 */

import { type SshService, type SshServiceOptions, ssh_service_core } from './recipe_ssh.ts';

/**
 * Build the sshd `service` payload for Debian: systemd's `ssh` unit, enabled,
 * running, and reloaded when any of `options.reload_on` changes.
 *
 * It targets `ssh.service`, which Debian runs by default. On Ubuntu 22.10 and later,
 * where `ssh.socket` starts it, `ssh.service` is the daemon that takes the socket from
 * systemd, so enabling it only starts sshd at boot as well. The one conflict is a
 * hand-enabled `Accept=yes` socket on Debian (`ssh@.service` per connection), which
 * contends with `ssh.service` for port 22: disable that socket first.
 *
 * @returns the `service` payload.
 */
export function debian_ssh_service(options: SshServiceOptions): SshService {
	return ssh_service_core('ssh', options);
}
