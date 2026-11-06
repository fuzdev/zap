import { assert, test } from 'vitest';

import {
	hardened_systemd_unit,
	type HardenedSystemdUnitOptions
} from '#lib/recipe_debian_systemd.ts';

test('renders the key hardening directives and the canonical sections', () => {
	const unit = hardened_systemd_unit({
		description: 'app.example.com',
		exec_start: '/home/fuz_forge/app/current/dist_artifacts/fuzfd start',
		user: 'fuz_forge',
		working_directory: '/home/fuz_forge/app/current',
		read_write_paths: ['/home/fuz_forge/app', '/home/fuz_forge/.fuz_forge'],
		env_file: '/home/fuz_forge/app/shared/.env.production'
	});

	// Canonical sections.
	assert.ok(unit.includes('[Unit]'), 'has [Unit] section');
	assert.ok(unit.includes('[Service]'), 'has [Service] section');
	assert.ok(unit.includes('[Install]'), 'has [Install] section');

	// Per-service directives reflect the inputs.
	assert.ok(unit.includes('User=fuz_forge'), 'User from input');
	assert.ok(unit.includes('Group=fuz_forge'), 'Group defaults to user');
	assert.ok(
		unit.includes('ExecStart=/home/fuz_forge/app/current/dist_artifacts/fuzfd start'),
		'ExecStart is the input verbatim'
	);
	assert.ok(
		unit.includes('WorkingDirectory=/home/fuz_forge/app/current'),
		'WorkingDirectory is the input'
	);
	assert.ok(
		unit.includes('ReadWritePaths=/home/fuz_forge/app /home/fuz_forge/.fuz_forge'),
		'ReadWritePaths is space-joined'
	);

	// The constant hardening block.
	assert.ok(unit.includes('NoNewPrivileges=true'), 'NoNewPrivileges');
	assert.ok(unit.includes('ProtectSystem=strict'), 'ProtectSystem');
	assert.ok(unit.includes('ProtectHome=read-only'), 'ProtectHome');
	assert.ok(
		unit.includes('RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6'),
		'RestrictAddressFamilies default'
	);
	assert.ok(unit.includes('SystemCallArchitectures=native'), 'SystemCallArchitectures');

	// Output is deterministic with a trailing newline.
	assert.ok(unit.endsWith('\n'), 'ends with a trailing newline');
});

test('emits EnvironmentFile when env_file is set', () => {
	const unit = hardened_systemd_unit({
		description: 'app.example.com',
		exec_start: '/home/fuz_forge/app/current/dist_artifacts/fuzfd start',
		user: 'fuz_forge',
		working_directory: '/home/fuz_forge/app/current',
		read_write_paths: ['/home/fuz_forge/app'],
		env_file: '/home/fuz_forge/app/shared/.env.production'
	});
	assert.ok(
		unit.includes('EnvironmentFile=/home/fuz_forge/app/shared/.env.production'),
		'EnvironmentFile present'
	);
});

test('omits EnvironmentFile entirely when env_file is unset', () => {
	const unit = hardened_systemd_unit({
		description: 'Example app',
		exec_start: '/home/app/.deno/bin/deno run --allow-net --env=/x/.env.production server.ts',
		user: 'app',
		working_directory: '/home/app/app/current',
		read_write_paths: ['/home/app/app', '/home/app/.app']
	});
	assert.ok(!unit.includes('EnvironmentFile'), 'no EnvironmentFile line when env_file is unset');
});

test('applies defaults: group, Restart, RestartSec, WantedBy', () => {
	const unit = hardened_systemd_unit({
		description: 'svc',
		exec_start: '/usr/bin/svc',
		user: 'svc_user',
		working_directory: '/srv/svc',
		read_write_paths: ['/srv/svc']
	});
	assert.ok(unit.includes('Group=svc_user'), 'Group defaults to user');
	assert.ok(unit.includes('Restart=on-failure'), 'Restart default');
	assert.ok(unit.includes('RestartSec=5'), 'RestartSec default');
	assert.ok(unit.includes('After=network.target\n'), 'After default');
	assert.ok(!unit.includes('Wants='), 'no Wants line by default');
	assert.ok(unit.includes('WantedBy=multi-user.target'), 'WantedBy default');
});

test('renders a full unit byte-for-byte, comment included', () => {
	const unit = hardened_systemd_unit({
		description: 'app.example.com',
		exec_start: '/home/fuz_forge/app/current/dist_artifacts/fuzfd start',
		user: 'fuz_forge',
		working_directory: '/home/fuz_forge/app/current',
		read_write_paths: ['/home/fuz_forge/app', '/home/fuz_forge/.fuz_forge'],
		env_file: '/home/fuz_forge/app/shared/.env.production',
		after: ['network.target', 'postgresql.service'],
		wants: ['postgresql.service'],
		hardening_comment: `# Additional sandboxing — all safe for an Axum/tokio daemon that shells out to
# git http-backend + python3 hooks and talks to local PostgreSQL. (Not added:
# MemoryDenyWriteExecute / SystemCallFilter — too likely to break the git
# subprocess.) AF_UNIX+AF_INET[6] cover the TCP listener, the Postgres socket,
# and the hooks' loopback callbacks.`
	});

	const expected = `[Unit]
Description=app.example.com
After=network.target postgresql.service
Wants=postgresql.service

[Service]
Type=simple
User=fuz_forge
Group=fuz_forge
WorkingDirectory=/home/fuz_forge/app/current
EnvironmentFile=/home/fuz_forge/app/shared/.env.production
ExecStart=/home/fuz_forge/app/current/dist_artifacts/fuzfd start
Restart=on-failure
RestartSec=5
StandardOutput=journal
StandardError=journal

# Security hardening
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=/home/fuz_forge/app /home/fuz_forge/.fuz_forge
UMask=0077
CapabilityBoundingSet=
PrivateTmp=true
# Additional sandboxing — all safe for an Axum/tokio daemon that shells out to
# git http-backend + python3 hooks and talks to local PostgreSQL. (Not added:
# MemoryDenyWriteExecute / SystemCallFilter — too likely to break the git
# subprocess.) AF_UNIX+AF_INET[6] cover the TCP listener, the Postgres socket,
# and the hooks' loopback callbacks.
PrivateDevices=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectKernelLogs=true
ProtectControlGroups=true
ProtectClock=true
ProtectHostname=true
RestrictNamespaces=true
RestrictRealtime=true
RestrictSUIDSGID=true
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
LockPersonality=true
SystemCallArchitectures=native
SystemCallFilter=@system-service
SystemCallErrorNumber=EPERM

[Install]
WantedBy=multi-user.target
`;

	assert.equal(unit, expected);
});

test('omits the hardening comment entirely when unset', () => {
	const unit = hardened_systemd_unit({
		description: 'svc',
		exec_start: '/usr/bin/svc',
		user: 'svc_user',
		working_directory: '/srv/svc',
		read_write_paths: ['/srv/svc']
	});
	// PrivateTmp flows straight into PrivateDevices with no comment line between.
	assert.ok(unit.includes('PrivateTmp=true\nPrivateDevices=true'), 'no comment slot when unset');
});

test('refuses a line break in any spliced value', () => {
	const base = {
		description: 'svc',
		exec_start: '/usr/bin/svc',
		user: 'svc_user',
		working_directory: '/srv/svc',
		read_write_paths: ['/srv/svc']
	};
	const evil = 'x\nExecStartPre=/bin/evil';
	const cases: Array<[string, Partial<HardenedSystemdUnitOptions>]> = [
		['after', { after: ['network.target', evil] }],
		['wants', { wants: [evil] }],
		['restart', { restart: evil }],
		['restrict_address_families', { restrict_address_families: [evil] }],
		['wanted_by', { wanted_by: evil }],
		['description', { description: evil }]
	];
	for (const [field, overrides] of cases) {
		assert.throws(
			() => hardened_systemd_unit({ ...base, ...overrides }),
			new RegExp(`${field} must be one line`),
			field
		);
	}
});

const BASE: HardenedSystemdUnitOptions = {
	description: 'svc',
	exec_start: '/usr/bin/svc',
	user: 'svc_user',
	working_directory: '/srv/svc',
	read_write_paths: ['/srv/svc']
};

test('tightens by default: no capabilities, the system-service filter, an owner-only umask', () => {
	const unit = hardened_systemd_unit(BASE);
	assert.ok(unit.includes('\nCapabilityBoundingSet=\n'), 'empty bounding set');
	assert.ok(!unit.includes('AmbientCapabilities'), 'no ambient capabilities');
	assert.ok(
		unit.includes('\nSystemCallFilter=@system-service\nSystemCallErrorNumber=EPERM\n'),
		'system-service filter'
	);
	assert.ok(unit.includes('\nUMask=0077\n'), 'owner-only umask');
});

test('loosens each default through its option', () => {
	const unit = hardened_systemd_unit({
		...BASE,
		capabilities: ['CAP_NET_BIND_SERVICE'],
		system_call_filter: false,
		umask: '0022'
	});
	assert.ok(unit.includes('\nCapabilityBoundingSet=CAP_NET_BIND_SERVICE\n'), 'bounding set');
	assert.ok(unit.includes('\nAmbientCapabilities=CAP_NET_BIND_SERVICE\n'), 'ambient set');
	assert.ok(!unit.includes('SystemCallFilter'), 'no filter');
	assert.ok(!unit.includes('SystemCallErrorNumber'), 'no error number without a filter');
	assert.ok(unit.includes('\nUMask=0022\n'), 'umask');

	const widened = hardened_systemd_unit({
		...BASE,
		system_call_filter: ['@system-service', '@pkey']
	});
	assert.ok(widened.includes('\nSystemCallFilter=@system-service @pkey\n'), 'widened filter');
});

test('refuses a malformed loosening', () => {
	const cases: Array<[string, Partial<HardenedSystemdUnitOptions>, RegExp]> = [
		['capability', { capabilities: ['net_bind_service'] }, /capabilities entry/],
		['empty filter', { system_call_filter: [] }, /system_call_filter is empty/],
		['deny-list filter', { system_call_filter: ['~@privileged'] }, /system_call_filter entry/],
		['umask', { umask: '022' }, /umask "022" must be four octal digits/],
		['umask digit', { umask: '0088' }, /umask/]
	];
	for (const [label, overrides, pattern] of cases) {
		assert.throws(() => hardened_systemd_unit({ ...BASE, ...overrides }), pattern, label);
	}
});

test('refuses root, and any user or group that is not an account name', () => {
	assert.throws(() => hardened_systemd_unit({ ...BASE, user: 'root' }), /user "root" is root/);
	assert.throws(() => hardened_systemd_unit({ ...BASE, group: 'root' }), /group "root" is root/);
	for (const name of [' root', 'root ', '+0', '0', '1000', 'a b', '-x', 'a$b', '', 'ro\not']) {
		assert.throws(
			() => hardened_systemd_unit({ ...BASE, user: name }),
			/user .* must be an account name/,
			JSON.stringify(name)
		);
		assert.throws(
			() => hardened_systemd_unit({ ...BASE, group: name }),
			/group .* must be an account name/,
			JSON.stringify(name)
		);
	}
	for (const name of ['svc', '_svc', 'svc-1', 'Svc_2', 'host$']) {
		assert.ok(hardened_systemd_unit({ ...BASE, user: name }).includes(`\nUser=${name}\n`), name);
	}
});

test('refuses an exec_start prefix that escapes User=, the sandbox, or the restart', () => {
	for (const exec_start of [
		'+/usr/bin/svc',
		'!/usr/bin/svc',
		'!!/usr/bin/svc',
		'-/usr/bin/svc',
		'@+/usr/bin/svc svc',
		'|/usr/bin/svc',
		'svc',
		'@@/usr/bin/svc svc',
		'::/usr/bin/svc',
		'@:@/usr/bin/svc svc'
	]) {
		assert.throws(
			() => hardened_systemd_unit({ ...BASE, exec_start }),
			/exec_start .* must begin with the program's absolute path/,
			exec_start
		);
	}
	for (const exec_start of ['@/usr/bin/svc svc', ':/usr/bin/svc $LITERAL', ':@/usr/bin/svc svc']) {
		assert.ok(
			hardened_systemd_unit({ ...BASE, exec_start }).includes(`\nExecStart=${exec_start}\n`),
			exec_start
		);
	}
});

test('refuses a hardening_comment line that systemd would read as a directive', () => {
	for (const hardening_comment of [
		'ExecStartPre=+/bin/evil',
		'# fine\nUser=root',
		'# continued \\',
		'# fine\r\nUser=root',
		'# trailing blank line\n'
	]) {
		assert.throws(
			() => hardened_systemd_unit({ ...BASE, hardening_comment }),
			/hardening_comment line/,
			JSON.stringify(hardening_comment)
		);
	}
	assert.ok(
		hardened_systemd_unit({ ...BASE, hardening_comment: '# one\n#two' }).includes(
			'PrivateTmp=true\n# one\n#two\nPrivateDevices=true'
		)
	);
});

test('refuses a value ending in a line continuation', () => {
	assert.throws(
		() => hardened_systemd_unit({ ...BASE, exec_start: '/usr/bin/svc \\' }),
		/exec_start must be one line, not ending in/
	);
});
