// `cargo xtask differential` kitchen sink — Alpine (apk + OpenRC + nftables),
// driven over SSH. The harness supplies the `ZAPDIFF_*` values through the
// environment.

import { alpine_web_firewall } from '../../../../../src/lib/recipe_alpine_firewall.ts';
import { alpine_postgres_setup } from '../../../../../src/lib/recipe_alpine_postgres.ts';
import type { ZapBuilder } from '../../../../../src/lib/zap.ts';
import { declare_common } from '../common.ts';

export default (zap: ZapBuilder): void => {
	zap.target({
		host: zap.env('ZAPDIFF_HOST'),
		user: zap.env('ZAPDIFF_USER'),
		home: '/home/ops',
		package_manager: 'apk',
		service_manager: 'openrc'
	});

	// Alpine ships no curl; the installer fetches with it
	zap.pkg({ id: 'curl', from: { apk: 'curl' } });
	// useradd / usermod / gpasswd (busybox has only adduser)
	zap.pkg({ id: 'shadow', from: { apk: 'shadow' } });
	declare_common(zap, {
		sleeper_service_id: 'sleeper',
		curl_ids: ['curl'],
		account_tool_ids: ['shadow']
	});

	// --- firewall: nftables + its persistence service, allowing 22 ----------
	const fw = alpine_web_firewall({
		allow_extra: [
			{ port: 5353, proto: 'udp' },
			{ port: 8443, proto: 'any' }
		]
	});
	zap.pkg({ id: 'nftables', from: { apk: 'nftables' } });
	zap.firewall({ id: 'firewall', ...fw.firewall, depends_on: ['nftables'] });
	zap.service({ id: 'nftables-service', ...fw.service, depends_on: ['firewall'] });

	// --- the triggered service (pull via reload_on, push via the script's triggers).
	// Its reload touches a file under /var/lib, so the harness's write audit sees one.
	zap.file({
		id: 'sleeper-init',
		path: '/etc/init.d/zapdiff-sleeper',
		content: {
			type: 'inline',
			content:
				'#!/sbin/openrc-run\ndescription="zap differential sleeper"\ncommand="/bin/sleep"\ncommand_args="2147483647"\ncommand_background=true\npidfile="/run/${RC_SVCNAME}.pid"\nextra_started_commands="reload"\nreload() {\n\tebegin "Reloading ${RC_SVCNAME}"\n\tmkdir -p /var/lib/zapdiff-reloads && touch /var/lib/zapdiff-reloads/${RC_SVCNAME}\n\teend $?\n}\n'
		},
		mode: '755',
		triggers: ['sleeper']
	});
	zap.service({
		id: 'sleeper',
		service: 'zapdiff-sleeper',
		enabled: true,
		running: true,
		reload_on: ['sleeper-conf'],
		depends_on: ['sleeper-init', 'sleeper-conf']
	});

	// desired stopped + disabled
	zap.file({
		id: 'idle-init',
		path: '/etc/init.d/zapdiff-idle',
		content: {
			type: 'inline',
			content:
				'#!/sbin/openrc-run\ndescription="zap differential idle service"\ncommand="/bin/sleep"\ncommand_args="2147483647"\ncommand_background=true\npidfile="/run/${RC_SVCNAME}.pid"\n'
		},
		mode: '755'
	});
	zap.service({
		id: 'idle',
		service: 'zapdiff-idle',
		enabled: false,
		running: false,
		depends_on: ['idle-init']
	});
	// enabled at boot, running state unmanaged (and never stopped by a mutation)
	zap.service({ id: 'ssh-boot', service: 'sshd', enabled: true });

	// --- postgres (the harness starts it installed, initialized, and stopped) --
	zap.pkg({ id: 'postgresql', from: { apk: 'postgresql18' } });
	zap.pkg({ id: 'postgresql-openrc', from: { apk: 'postgresql18-openrc' } });
	zap.script({
		id: 'postgres-cluster-init',
		...alpine_postgres_setup({ version: 18 }),
		depends_on: ['postgresql', 'postgresql-openrc']
	});
	zap.service({
		id: 'postgresql-service',
		service: 'postgresql',
		enabled: true,
		running: true,
		depends_on: ['postgres-cluster-init']
	});
	zap.database({
		id: 'database',
		engine: 'postgresql',
		database_name: 'zapdiff',
		username: 'zapdiff',
		auth: { method: 'scram-sha-256', hosts: ['127.0.0.1/32', '10.0.0.0/8'] },
		depends_on: ['postgresql-service']
	});
};
