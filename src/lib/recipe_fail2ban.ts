/**
 * Recipe for a fail2ban `jail.local`.
 *
 * `fail2ban_jail` builds the content of `/etc/fail2ban/jail.local` — the
 * `[DEFAULT]` + `[sshd]` jail config a hardened host carries. The defaults are a
 * complete baseline; callers only override a value to diverge intentionally.
 *
 * Recipes are imported at config eval time inside `fgro eval`'s sandbox,
 * which has no network, no writes, and no environment, and where the clock and
 * randomness throw. This module is therefore a **pure function**: it only assembles a
 * string from its arguments — no I/O, no clock, no randomness, no imports
 * beyond types. The output is deterministic for given inputs (stable ordering,
 * trailing newline), so it stays a reliable content-addressed plan artifact.
 *
 * The caller wraps the result in a file resource, e.g.
 * `zap.file({id: 'fail2ban-jail', path: '/etc/fail2ban/jail.local', content: {type: 'inline', content: fail2ban_jail()}})`.
 *
 * @module
 */

import { DEFAULT_SSH_PORT, type SshPortOptions, to_ssh_port } from './recipe_ssh.ts';

/**
 * The `sshd` filter's arguments for a log file: the stock filter, told about the
 * `facility.priority` word BusyBox `syslogd` writes after the host name
 * (`alpine-zap auth.info sshd-session[42]: …`), which its line prefix doesn't
 * otherwise read, and about OpenSSH's `sshd-session` process name, which older
 * filters don't know. Both are optional groups, so a plain syslog line still matches.
 */
const SSHD_FILE_FILTER = 'sshd[__kernel_prefix="\\S+\\.\\S+", _daemon="sshd(?:-session)?"]';

/**
 * The `sshd` filter's arguments for the journal: OpenSSH's `sshd-session` process
 * name, which older filters don't know.
 */
const SSHD_JOURNAL_FILTER = 'sshd[_daemon="sshd(?:-session)?"]';

/**
 * The journal entries the `sshd` jail reads: sshd's, by unit (`ssh.service` on Debian
 * and Ubuntu, `sshd.service` elsewhere) or by process name (`sshd-session` is the
 * per-connection process of OpenSSH 9.8 and later). `+` joins alternatives.
 */
const SSHD_JOURNAL_MATCH =
	'_SYSTEMD_UNIT=ssh.service + _SYSTEMD_UNIT=sshd.service + _COMM=sshd + _COMM=sshd-session';

/**
 * Options for `fail2ban_jail`.
 *
 * Every field defaults to the shared baseline, so `fail2ban_jail()` takes no
 * argument for the common case: a Debian or Ubuntu host whose sshd logs to the
 * journal on port 22 and whose firewall is ufw (iptables). `ssh_port` is the port the
 * jail bans on: give it the value the firewall and `ssh_hardening_verify` get, or a
 * ban blocks a port sshd isn't on.
 */
export interface Fail2banJailOptions extends SshPortOptions {
	/** `[DEFAULT] bantime` — how long a banned host stays banned. Defaults to `'1h'`. */
	ban_time?: string;
	/** `[DEFAULT] findtime` — the window failures are counted within. Defaults to `'10m'`. */
	find_time?: string;
	/** `[DEFAULT] maxretry` — failures within `find_time` before a ban. Defaults to `5`. */
	max_retry?: number;
	/** `[sshd] maxretry` — sshd-specific failure threshold. Defaults to `3`. */
	sshd_max_retry?: number;
	/** `[sshd] bantime` — sshd-specific ban duration. Defaults to `'24h'`. */
	sshd_ban_time?: string;
	/**
	 * `[DEFAULT] banaction` — the fail2ban action that blocks a banned address, which
	 * has to drive the firewall the host has. Defaults to `'iptables-multiport'`, for a
	 * ufw host (ufw depends on iptables, not on the `nft` command Debian's own
	 * `nftables` default needs). Pass `'nftables'` on an nftables host such as the one
	 * `alpine_web_firewall` sets up, which has no iptables. Without the command the
	 * action names, fail2ban counts and lists a ban but blocks nothing.
	 */
	banaction?: string;
	/**
	 * The file fail2ban watches for sshd auth failures. Unset, the jail reads the
	 * systemd journal (`backend = systemd`), where sshd logs on Debian and Ubuntu with
	 * or without rsyslog. On Alpine there is no journal: BusyBox `syslog` writes
	 * everything to `'/var/log/messages'`, so pass that (and ensure the `syslog`
	 * service is enabled); the jail then reads the file with the `sshd` filter set to
	 * read BusyBox's lines. fail2ban refuses to start a jail whose `logpath` doesn't
	 * exist ("Have not found any log file").
	 */
	sshd_logpath?: string;
}

/**
 * Build the fail2ban `jail.local` text for `options`.
 *
 * Writes a `[DEFAULT]` section with the global ban/find/retry tunables and the
 * `banaction`, and a stricter `[sshd]` jail reading the journal, or `sshd_logpath`
 * when one is given. jail.local is read after the distro's `jail.d/*.conf`, so its
 * values win over a packaged default, such as Debian's `nftables` banaction or
 * Alpine's `alpine-sshd` filter.
 *
 * The `[sshd]` jail bans on `port = ssh`, the service name for 22, unless `ssh_port`
 * names another port, which it then names.
 *
 * @returns the complete `jail.local` text, terminated by a trailing newline.
 * @throws Error if a text value holds a line break, or `ssh_port` is not a port
 */
export function fail2ban_jail(options?: Fail2banJailOptions): string {
	const {
		ban_time = '1h',
		find_time = '10m',
		max_retry = 5,
		sshd_max_retry = 3,
		sshd_ban_time = '24h',
		banaction = 'iptables-multiport',
		sshd_logpath
	} = options ?? {};
	const ssh_port = to_ssh_port('fail2ban_jail', options);

	const values: Array<[string, string]> = [
		['ban_time', ban_time],
		['find_time', find_time],
		['sshd_ban_time', sshd_ban_time],
		['banaction', banaction],
		['sshd_logpath', sshd_logpath ?? '']
	];
	for (const [field, value] of values) {
		if (/[\r\n]/.test(value)) {
			throw new Error(`fail2ban_jail: ${field} must be one line`);
		}
	}

	const source =
		sshd_logpath === undefined
			? `backend = systemd\nfilter = ${SSHD_JOURNAL_FILTER}\njournalmatch = ${SSHD_JOURNAL_MATCH}\n`
			: `backend = auto\nfilter = ${SSHD_FILE_FILTER}\nlogpath = ${sshd_logpath}\n`;

	return `[DEFAULT]
bantime = ${ban_time}
findtime = ${find_time}
maxretry = ${max_retry}
banaction = ${banaction}

[sshd]
enabled = true
port = ${ssh_port === DEFAULT_SSH_PORT ? 'ssh' : ssh_port}
${source}maxretry = ${sshd_max_retry}
bantime = ${sshd_ban_time}
`;
}
