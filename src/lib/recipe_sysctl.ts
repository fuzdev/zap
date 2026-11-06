/**
 * Recipes for kernel parameters a hardened host keeps set: a `sysctl.d` file that
 * holds them across boots, and a `script` that puts them in force now.
 *
 * - `LINK_PROTECTION_SYSCTLS` — the link and file protections the kernel applies in
 *   world-writable directories: a hard link to a file the linker doesn't own, a
 *   symlink followed out of a sticky directory, and a FIFO or regular file opened with
 *   `O_CREAT` in one, each refused. They close the class of attack in which one account
 *   plants a link or file at a path a more privileged process (root's apply, a
 *   service) then opens. systemd sets all four on Debian and Ubuntu; Alpine sets only
 *   the first two, so an Alpine host declares them.
 * - `sysctl_conf` — the `sysctl.d` file text for a set of parameters.
 * - `sysctl_apply` — the `script` that loads that file when a parameter's live value
 *   differs from it.
 *
 * Distro-neutral: both families read `/etc/sysctl.d/*.conf` at boot (systemd's
 * `systemd-sysctl`, OpenRC's `sysctl` service in the `boot` runlevel), and both
 * `sysctl` commands (procps and BusyBox) load a file with `-p`.
 *
 * Pure functions evaluated in zap's sandboxed config eval (`fgro eval`: no I/O,
 * clock, or randomness); the output is deterministic.
 *
 * The caller writes the file and orders the script after it, e.g.
 * `zap.file({id: 'sysctl-links', path: LINK_PROTECTION_SYSCTL_PATH, content: {type: 'inline', content: sysctl_conf(LINK_PROTECTION_SYSCTLS)}})`
 * and
 * `zap.script({id: 'sysctl-links-applied', ...sysctl_apply(LINK_PROTECTION_SYSCTL_PATH, LINK_PROTECTION_SYSCTLS), depends_on: ['sysctl-links']})`.
 *
 * @module
 */

import type { ScriptResource } from './schema.ts';
import { single_quote } from './shell.ts';

/** Kernel parameters by `sysctl` name, each with the value it is set to. */
export type SysctlValues = Readonly<Record<string, string>>;

/**
 * The link and file protections: `protected_hardlinks` and `protected_symlinks` at
 * `1`, `protected_fifos` at `1`, and `protected_regular` at `2` (a group-writable
 * sticky directory counts too), the values systemd ships.
 */
export const LINK_PROTECTION_SYSCTLS: SysctlValues = {
	'fs.protected_hardlinks': '1',
	'fs.protected_symlinks': '1',
	'fs.protected_fifos': '1',
	'fs.protected_regular': '2'
};

/** Where a config writes `LINK_PROTECTION_SYSCTLS`. */
export const LINK_PROTECTION_SYSCTL_PATH = '/etc/sysctl.d/60-link-protection.conf';

/** What a parameter's name must be: dotted words, as `sysctl` and `/proc/sys` name it. */
const SYSCTL_NAME = /^[a-z0-9_]+(?:\.[a-z0-9_]+)+$/;

/** What a value must be: digits, one or several separated by single spaces. */
const SYSCTL_VALUE = /^[0-9]+(?: [0-9]+)*$/;

const checked = (recipe: string, values: SysctlValues): Array<[string, string]> => {
	const entries = Object.entries(values);
	if (entries.length === 0) {
		throw new Error(`${recipe}: no parameters given`);
	}
	for (const [name, value] of entries) {
		if (!SYSCTL_NAME.test(name)) {
			throw new Error(
				`${recipe}: ${JSON.stringify(name)} must be a dotted parameter name such as fs.protected_hardlinks`
			);
		}
		if (!SYSCTL_VALUE.test(value)) {
			throw new Error(
				`${recipe}: ${name}'s value ${JSON.stringify(value)} must be digits, several separated by single spaces`
			);
		}
	}
	return entries;
};

/**
 * Build the `sysctl.d` file text for `values`, one `name = value` line each, in the
 * order given.
 *
 * @returns the file text, terminated by a trailing newline.
 */
export function sysctl_conf(values: SysctlValues): string {
	const lines = checked('sysctl_conf', values).map(([name, value]) => `${name} = ${value}`);
	return `# Managed by zap\n${lines.join('\n')}\n`;
}

/** The `check`/`run` `sysctl_apply` returns (caller supplies `id`/`name`/`depends_on`). */
export type SysctlApplyScript = Pick<ScriptResource, 'check' | 'run'>;

/**
 * Build the `script` that puts `values` in force from the file at `path`.
 *
 * `check` reads each parameter's live value from `/proc/sys`, readable by any
 * account, with its tabs and runs of blanks read as one space (a multi-value
 * parameter such as `net.ipv4.ip_local_port_range` reads `32768<tab>60999` there),
 * and passes when every one is the declared value; `run` loads the file
 * with `sysctl -p` and fails when a value still differs. Pass the same `values` the
 * file was written from.
 *
 * @param path - the absolute path of the `sysctl.d` file
 * @param values - the parameters the file holds
 * @returns the `script` `check`/`run` pair.
 */
export function sysctl_apply(path: string, values: SysctlValues): SysctlApplyScript {
	const entries = checked('sysctl_apply', values);
	if (!path.startsWith('/')) {
		throw new Error(`sysctl_apply: path ${JSON.stringify(path)} must be absolute`);
	}
	const check = entries
		.map(
			([name, value]) =>
				`test "$(tr -s '\\t ' '  ' < ${single_quote(`/proc/sys/${name.replaceAll('.', '/')}`)})" = ${single_quote(value)}`
		)
		.join(' && ');
	return {
		check,
		run: `set -e\nsudo sysctl -p ${single_quote(path)} >/dev/null\n${check}`
	};
}
