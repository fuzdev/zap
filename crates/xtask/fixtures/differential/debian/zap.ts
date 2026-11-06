// `cargo xtask differential` kitchen sink — Debian 13 (apt + systemd + ufw), driven
// over SSH. The harness supplies the `ZAPDIFF_*` values through the environment.

import { debian_web_firewall } from '../../../../../src/lib/recipe_debian_firewall.ts';
import type { ZapBuilder } from '../../../../../src/lib/zap.ts';
import { declare_common } from '../common.ts';

export default (zap: ZapBuilder): void => {
	zap.target({
		host: zap.env('ZAPDIFF_HOST'),
		user: zap.env('ZAPDIFF_USER'),
		home: '/home/ops',
		package_manager: 'apt',
		service_manager: 'systemd'
	});

	declare_common(zap, { sleeper_service_id: 'sleeper', curl_ids: [], account_tool_ids: [] });

	// --- firewall: ufw, allowing 22 so the harness can't lock itself out ----
	zap.pkg({ id: 'ufw', from: { apt: 'ufw' } });
	zap.firewall({
		id: 'firewall',
		...debian_web_firewall({
			allow_extra: [
				{ port: 5353, proto: 'udp' },
				{ port: 8443, proto: 'any' }
			]
		}),
		depends_on: ['ufw']
	});

	// --- the triggered service (pull via reload_on, push via the unit's triggers).
	// Its reload touches a file under /var/lib, so the harness's write audit sees one.
	zap.file({
		id: 'sleeper-unit',
		path: '/etc/systemd/system/zapdiff-sleeper.service',
		content: {
			type: 'inline',
			content:
				'[Unit]\nDescription=zap differential sleeper\n\n[Service]\nExecStart=/bin/sleep infinity\nExecReload=/bin/sh -c "mkdir -p /var/lib/zapdiff-reloads && touch /var/lib/zapdiff-reloads/zapdiff-sleeper"\n\n[Install]\nWantedBy=multi-user.target\n'
		},
		mode: '644',
		triggers: ['sleeper']
	});
	zap.service({
		id: 'sleeper',
		service: 'zapdiff-sleeper',
		enabled: true,
		running: true,
		reload_on: ['sleeper-conf'],
		depends_on: ['sleeper-unit', 'sleeper-conf']
	});

	// desired stopped + disabled
	zap.file({
		id: 'idle-unit',
		path: '/etc/systemd/system/zapdiff-idle.service',
		content: {
			type: 'inline',
			content:
				'[Unit]\nDescription=zap differential idle service\n\n[Service]\nExecStart=/bin/sleep infinity\n\n[Install]\nWantedBy=multi-user.target\n'
		},
		mode: '644'
	});
	zap.service({
		id: 'idle',
		service: 'zapdiff-idle',
		enabled: false,
		running: false,
		depends_on: ['idle-unit']
	});
	// enabled at boot, running state unmanaged (and never stopped by a mutation)
	zap.service({ id: 'ssh-boot', service: 'ssh', enabled: true });

	// --- postgres + a database with pg_hba rules ---------------------------
	zap.pkg({ id: 'postgresql', from: { apt: 'postgresql' } });
	zap.service({
		id: 'postgresql-service',
		service: 'postgresql',
		enabled: true,
		running: true,
		depends_on: ['postgresql']
	});
	zap.database({
		id: 'database',
		engine: 'postgresql',
		database_name: 'zapdiff',
		username: 'zapdiff',
		auth: { method: 'scram-sha-256', hosts: ['127.0.0.1/32', '10.0.0.0/8'] },
		depends_on: ['postgresql-service']
	});

	// --- apt_repo: a local flat repo; its key is a tracked pin zap fetches from the
	// harness's content server
	zap.file({
		id: 'apt-repo-packages',
		path: '/srv/zapdiff-repo/Packages',
		content: { type: 'inline', content: '' },
		mode: '644'
	});
	zap.apt_repo({
		id: 'zapdiff-repo',
		key_url: `${zap.env('ZAPDIFF_CONTENT')}/zapdiff-repo.key.asc`,
		source: 'deb [trusted=yes] file:/srv/zapdiff-repo ./',
		depends_on: ['apt-repo-packages']
	});

	zap.file({
		id: 'apt-repo2-packages',
		path: '/srv/zapdiff-repo2/Packages',
		content: { type: 'inline', content: '' },
		mode: '644'
	});
	zap.apt_repo({
		id: 'zapdiff-repo2',
		key_url: `${zap.env('ZAPDIFF_CONTENT')}/zapdiff-repo2.key.asc`,
		source: 'deb [trusted=yes] file:/srv/zapdiff-repo2 ./',
		depends_on: ['apt-repo2-packages', 'zapdiff-repo']
	});
};
