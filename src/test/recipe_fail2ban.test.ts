import { assert, test } from 'vitest';

import { fail2ban_jail } from '#lib/recipe_fail2ban.ts';

test('reproduces the reference FAIL2BAN_CONFIG byte-for-byte', () => {
	const config = fail2ban_jail();

	const expected = `[DEFAULT]
bantime = 1h
findtime = 10m
maxretry = 5
banaction = iptables-multiport

[sshd]
enabled = true
port = ssh
backend = systemd
filter = sshd[_daemon="sshd(?:-session)?"]
journalmatch = _SYSTEMD_UNIT=ssh.service + _SYSTEMD_UNIT=sshd.service + _COMM=sshd + _COMM=sshd-session
maxretry = 3
bantime = 24h
`;

	assert.equal(config, expected);
});

test('overrides render in their directives', () => {
	const config = fail2ban_jail({
		ban_time: '2h',
		find_time: '5m',
		max_retry: 8,
		sshd_max_retry: 2,
		sshd_ban_time: '48h'
	});
	assert.ok(config.includes('bantime = 2h'), 'DEFAULT bantime override');
	assert.ok(config.includes('findtime = 5m'), 'findtime override');
	assert.ok(config.includes('maxretry = 8'), 'DEFAULT maxretry override');
	assert.ok(config.includes('maxretry = 2'), 'sshd maxretry override');
	assert.ok(config.includes('bantime = 48h'), 'sshd bantime override');
});

test('sshd_logpath reads a file with the filter set to read BusyBox syslog lines', () => {
	const config = fail2ban_jail({ sshd_logpath: '/var/log/messages', banaction: 'nftables' });
	assert.ok(config.includes('\nlogpath = /var/log/messages\n'), 'alpine logpath');
	assert.ok(config.includes('\nbackend = auto\n'), 'a file backend');
	assert.ok(
		config.includes(
			'\nfilter = sshd[__kernel_prefix="\\S+\\.\\S+", _daemon="sshd(?:-session)?"]\n'
		),
		config
	);
	assert.ok(!config.includes('journalmatch'), 'no journal');
	assert.ok(config.includes('\nbanaction = nftables\n'), 'banaction');
});

test('the jail reads the journal and bans through iptables by default', () => {
	const config = fail2ban_jail();
	// Debian's packaged default is `nftables`, whose `nft` command a ufw host lacks
	assert.ok(
		config.includes('[DEFAULT]\n') && config.includes('\nbanaction = iptables-multiport\n')
	);
	// a host without rsyslog has no auth.log, and the jail would refuse to start
	assert.ok(!config.includes('logpath'), config);
	assert.ok(config.includes('\nbackend = systemd\n'), config);
});

// BusyBox `syslogd` writes `<host> auth.info sshd-session[42]: …`; the stock filter's
// line prefix reads neither the `facility.priority` word nor the `sshd-session` name.
test('the file filter is told about BusyBox lines and sshd-session', () => {
	const config = fail2ban_jail({ sshd_logpath: '/var/log/messages' });
	assert.ok(config.includes(String.raw`__kernel_prefix="\S+\.\S+"`), config);
	assert.ok(config.includes('_daemon="sshd(?:-session)?"'), config);
});

test('refuses a line break in a value', () => {
	for (const options of [{ banaction: 'x\nignoreip = 0.0.0.0/0' }, { sshd_logpath: '/a\nb' }]) {
		assert.throws(() => fail2ban_jail(options), /must be one line/);
	}
});

test('ssh_port names the jail port, and 22 keeps the ssh service name', () => {
	assert.include(fail2ban_jail({ ssh_port: 2222 }), '\nport = 2222\n');
	assert.equal(fail2ban_jail({ ssh_port: 22 }), fail2ban_jail());
	for (const ssh_port of [0, 65536, 2.5]) {
		assert.throws(() => fail2ban_jail({ ssh_port }), /fail2ban_jail: ssh_port .* must be a port/);
	}
});
