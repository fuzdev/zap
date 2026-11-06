/**
 * Recipes for SSH hardening.
 *
 * - `ssh_hardening` builds the content of the `sshd_config.d` drop-in that
 *   disables root login, forces key-only auth, and restricts the login surface.
 *   `AllowUsers` (the deploy account) varies across hosts, and so may the
 *   `MaxAuthTries` and `LoginGraceTime` tunables (defaulting to the baseline);
 *   every other directive is the same fixed baseline. Distro-neutral
 *   (`sshd_config` is identical).
 * - `SSHD_VALIDATE` is the drop-in `file`'s `validate` command, so a config sshd
 *   rejects is rolled back before anything reloads onto it.
 * - `ssh_hardening_verify` re-asserts the hardening in sshd's effective config on
 *   every plan, from the same options.
 * - `ssh_service_core` builds the sshd `service` payload that reloads on a drop-in
 *   change. The service name is the one distro-varying value (systemd `ssh`,
 *   OpenRC `sshd`), so it's a parameter; the public wrappers are
 *   `recipe_debian_ssh.ts`'s `debian_ssh_service` and `recipe_alpine_ssh.ts`'s
 *   `alpine_ssh_service`.
 *
 * Recipes are imported at config eval time inside zap's sandboxed config eval
 * (`fgro eval`), which has no network, no writes, and no environment, and where
 * the clock and randomness throw. This module is therefore a set of **pure
 * functions**: each only assembles strings from its arguments — no I/O, no clock,
 * no randomness, no imports beyond types and `single_quote`, itself pure. The
 * output is deterministic for given inputs (stable ordering, trailing newline), so
 * it stays a reliable content-addressed plan artifact.
 *
 * The caller wraps `ssh_hardening` in a file resource, spreads a distro
 * `*_ssh_service` into a service resource that reloads on it, and orders the
 * verify after the service, both from one options object, e.g. with
 * `const hardening = {user}`:
 * `zap.file({id: 'ssh-hardened-config', path: '/etc/ssh/sshd_config.d/00-hardened.conf', content: {type: 'inline', content: ssh_hardening(hardening)}, validate: SSHD_VALIDATE})`,
 * `zap.service({id: 'ssh-service', ...debian_ssh_service({reload_on: ['ssh-hardened-config']}), depends_on: ['ssh-hardened-config']})`
 * and `zap.verify({id: 'ssh-hardening-valid', ...ssh_hardening_verify(hardening), depends_on: ['ssh-service']})`.
 *
 * @module
 */

import type { ServiceResource, VerifyResource } from './schema.ts';
import { single_quote } from './shell.ts';

/**
 * Options for `ssh_hardening` and `ssh_hardening_verify`.
 *
 * `user` is the per-deploy variation (the account allowed to log in);
 * `max_auth_tries` and `login_grace_time` default to the shared baseline.
 */
export interface SshHardeningOptions {
	/**
	 * `AllowUsers` — the sole account permitted to SSH in (the deploy user). One name,
	 * so no whitespace (sshd would read each word as another user) and no `,` (the
	 * verify names the user in `sshd -C`'s comma-separated connection spec).
	 */
	user: string;
	/** `MaxAuthTries` — auth attempts before the connection is dropped. Defaults to `3`. */
	max_auth_tries?: number;
	/** `LoginGraceTime` — seconds to complete authentication. Defaults to `20`. */
	login_grace_time?: number;
}

/**
 * `options` with the tunables' defaults filled in, the one home of those defaults.
 * Throws on a `user` that is empty or holds whitespace: sshd reads `AllowUsers`'s
 * words as one user each, so it would allow more than one, and the verify, which
 * asserts exactly the one, would fail on every plan. Throws on a `,` too, which would
 * split the verify's `sshd -C` connection spec.
 */
const hardening_values = (options: SshHardeningOptions): Required<SshHardeningOptions> => {
	const { user, max_auth_tries = 3, login_grace_time = 20 } = options;
	if (user === '' || /\s/.test(user)) {
		throw new Error(
			`ssh_hardening: user must be one name, with no whitespace, got ${JSON.stringify(user)}`
		);
	}
	// the verify names the user in `sshd -C`'s comma-separated connection spec
	if (user.includes(',')) {
		throw new Error(
			`ssh_hardening: user must be one name, with no \`,\`, got ${JSON.stringify(user)}`
		);
	}
	return { user, max_auth_tries, login_grace_time };
};

/**
 * The client address the verify connects from, in `sshd -C`'s connection spec: a
 * documentation address (RFC 5737), which no `Match Address` block that admits a real
 * network names, standing in for any client.
 */
const VERIFY_CLIENT_ADDRESS = '192.0.2.1';

/**
 * The command printing the config sshd would apply to `user` logging in from
 * `VERIFY_CLIENT_ADDRESS` on port 22, the port the drop-in leaves sshd on: `sshd -T`
 * with `-C`, so each `Match` block that applies to
 * that connection is applied first. The client's host name is its address, as sshd
 * has it with `UseDNS no`, the default.
 */
const sshd_effective = (user: string): string =>
	`sudo sshd -T -C ${single_quote(`user=${user},host=${VERIFY_CLIENT_ADDRESS},addr=${VERIFY_CLIENT_ADDRESS},lport=22`)}`;

/**
 * Build the hardened `sshd_config` drop-in text for `options`.
 *
 * The hardened baseline: root login disabled, password + keyboard-interactive
 * auth off, X11 forwarding off. Only `AllowUsers` and the tunables (`max_auth_tries`,
 * `login_grace_time`) come from inputs. It leaves `UsePAM` to the distro: Debian's and Ubuntu's stock
 * `sshd_config` sets it, and Alpine's sshd is built without PAM and warns on the
 * keyword; with password and keyboard-interactive auth off, PAM authenticates
 * nobody either way.
 *
 * sshd keeps the first value it reads for most keywords, and the stock
 * `sshd_config` includes `sshd_config.d/*.conf` in name order before its own
 * lines. So name the drop-in to sort first (`00-hardened.conf`): a later drop-in,
 * such as a cloud image's `50-cloud-init.conf` setting
 * `PasswordAuthentication yes`, then can't override it.
 *
 * @returns the complete drop-in text, terminated by a trailing newline.
 */
export function ssh_hardening(options: SshHardeningOptions): string {
	const { user, max_auth_tries, login_grace_time } = hardening_values(options);

	return `# SSH hardened - root login disabled, only deploy user allowed
PermitRootLogin no
AllowUsers ${user}

# Disable password authentication (key-only)
PasswordAuthentication no
KbdInteractiveAuthentication no

# Other hardening
X11Forwarding no
MaxAuthTries ${max_auth_tries}
LoginGraceTime ${login_grace_time}
`;
}

/**
 * The drop-in `file`'s `validate` command: `sshd -t` checks the whole config, drop-ins
 * and the body of every `Match` block included, so a write sshd would reject is
 * rolled back before the service reloads onto it. An unsupported keyword is a warning
 * to it, not an error.
 */
export const SSHD_VALIDATE = 'sudo sshd -t';

/**
 * Build the `verify` payload that re-asserts the hardening in sshd's effective
 * config for the allowed user on every plan, from the options `ssh_hardening` was given:
 * root login, password auth, keyboard-interactive auth, and X11 forwarding off,
 * `AllowUsers` the user and no one else, and the tunables at their values. Pass
 * both the same options object.
 *
 * sshd prints each keyword lowercase with its value, one `AllowUsers` entry per
 * line and `LoginGraceTime` in seconds. Each assertion but one matches one whole
 * line, fixed-string (`grep -qxF`), the expected line one single-quoted word, so a
 * value is matched as text. sshd adds up `AllowUsers` across every file it reads, so
 * a presence check would miss a user another drop-in allows: that one compares every
 * `allowusers` line together with the one expected (`test "$(…)" = '…'`).
 *
 * It reads what sshd would run with, not the drop-in's bytes, so it catches a
 * drop-in that sorts earlier and overrides the hardening, a hand edit, or a config
 * that no longer parses. A failing check shows as a pending change and blocks
 * `zap deploy`'s preflight. Spread it into a `zap.verify` that depends on the ssh
 * service.
 *
 * The config is read for a connection, `sshd -T -C user=<user>,host=…,addr=…,lport=22`, so a
 * `Match` block that applies to the allowed user (`Match User`, `Match Group`,
 * `Match All`, an address list that holds every client) and re-enables password
 * auth fails the verify; without `-C`, sshd prints only the global values. The client
 * address is `192.0.2.1`, a documentation address, so a `Match Address` block naming
 * one real network (an office, a VPN) isn't exercised: the other users it could
 * admit are refused by `AllowUsers`, but the allowed user from that network is not
 * checked. Nor are `Match LocalAddress` and `Match RDomain` blocks: the connection
 * names no local address or routing domain.
 *
 * @param options - the options given `ssh_hardening`
 * @returns the `verify` `assertions`.
 */
export function ssh_hardening_verify(options: SshHardeningOptions): VerifyResource {
	const { user, max_auth_tries, login_grace_time } = hardening_values(options);
	const line = (expected: string) => ({
		type: 'command' as const,
		run: `${sshd_effective(user)} | grep -qxF ${single_quote(expected)}`
	});
	return {
		assertions: [
			line('permitrootlogin no'),
			line('passwordauthentication no'),
			line('kbdinteractiveauthentication no'),
			line('x11forwarding no'),
			{
				type: 'command',
				run: `test "$(${sshd_effective(user)} | grep '^allowusers ')" = ${single_quote(`allowusers ${user}`)}`
			},
			line(`maxauthtries ${max_auth_tries}`),
			line(`logingracetime ${login_grace_time}`)
		]
	};
}

/** Options for the distro `*_ssh_service` wrappers. */
export interface SshServiceOptions {
	/**
	 * The ids whose change reloads sshd — the hardening drop-in, at least. Required:
	 * without it the service would never pick up a config change.
	 */
	reload_on: Array<string>;
}

/** The `service` fields the `*_ssh_service` recipes return (caller supplies `id`/`name`/`depends_on`). */
export type SshService = Required<
	Pick<ServiceResource, 'service' | 'enabled' | 'running' | 'reload_on'>
>;

/**
 * Build the sshd `service` payload: enabled, running, and reloaded when any of
 * `options.reload_on` changes. The service name is the one distro-varying value;
 * prefer the `debian_ssh_service` / `alpine_ssh_service` wrappers, which pass it.
 *
 * zap's reload is `systemctl try-reload-or-restart` on systemd and
 * `rc-service --ifstarted <name> reload` on OpenRC. Both distros' sshd reload runs
 * `sshd -t` first and leaves the running sshd untouched when the config is invalid.
 *
 * @param service - the service manager's name for sshd
 * @param options - the ids that reload sshd (`reload_on`)
 * @returns the `service` payload.
 */
export function ssh_service_core(service: string, options: SshServiceOptions): SshService {
	return { service, enabled: true, running: true, reload_on: options.reload_on };
}
