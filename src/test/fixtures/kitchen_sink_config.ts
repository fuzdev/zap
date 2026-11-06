/**
 * Kitchen-sink `zap.ts` config — the dual-gated conformance fixture.
 *
 * Exercises **every** `ZapBuilder` method at least once, plus the tricky nested
 * unions (file `remote` content with extract + auth, inline/template content, a
 * `build` with a minisign-verified remote source, a `user` with restricted sudo
 * and copied SSH keys, a `firewall` mixing named profiles and port/proto pairs,
 * a `verify` with both assertion kinds). This single file is gated twice:
 *
 *   1. svelte-check / `gro typecheck` checks it against `ZapBuilder` here — a
 *      shape the types wrongly reject is a real finding (the types are too
 *      strict), not something to loosen away.
 *   2. The Rust `config_conformance` test evaluates it through `fgro eval` and
 *      parses the emitted JSON against `ZapConfig`, and asserts every
 *      `ResourceType` variant is present — so the hand-written TS types stay
 *      honest against the serde schema.
 *
 * The `import type` is erased at runtime, so the evaluator needs no module
 * resolution. Pure literals only: no `Date.now()`, no bare `new Date()`, no
 * `Math.random()`, no `crypto.randomUUID()` — the eval wrapper's determinism
 * stubs would throw on those. `zap.env` references stay inert (resolved apply-time).
 */

import type { ZapBuilder } from '#lib/zap.ts';

export default (zap: ZapBuilder): void => {
	// Target — a remote SSH host driven by inert references. `home` takes none.
	zap.target({
		host: zap.env('DEPLOY_HOST'),
		user: zap.env('DEPLOY_USER'),
		port: 22,
		home: '/home/deploy',
		package_manager: 'apt',
		service_manager: 'systemd'
	});

	// 1. package
	zap.pkg({
		id: 'curl',
		name: 'curl',
		from: { apt: 'curl', brew: 'curl' },
		check: '/usr/bin/curl'
	});

	// 2. apt_repo
	zap.apt_repo({
		id: 'pgdg',
		name: 'PostgreSQL apt repo',
		key_url: 'https://www.postgresql.org/media/keys/ACCC4CF8.asc',
		key_path: '/usr/share/keyrings/pgdg.asc',
		source: 'deb https://apt.postgresql.org/pub/repos/apt bookworm-pgdg main',
		list_file: '/etc/apt/sources.list.d/pgdg.list',
		depends_on: ['curl']
	});

	// 3. script
	zap.script({
		id: 'enable-bbr',
		name: 'enable TCP BBR',
		check: 'sysctl net.ipv4.tcp_congestion_control | grep -q bbr',
		run: 'sysctl -w net.ipv4.tcp_congestion_control=bbr',
		cwd: '/root',
		env: { LANG: 'C' }
	});

	// 4. installer
	zap.installer({
		id: 'deno',
		name: 'Deno runtime',
		url: 'https://deno.land/install.sh',
		check: '~/.deno/bin/deno',
		shell: 'sh'
	});

	// 5. user — restricted sudo + copied SSH keys.
	zap.user({
		id: 'deploy-user',
		name: 'deploy user',
		username: 'deploy',
		shell: '/bin/bash',
		home_mode: '711',
		ssh_keys: { copy_from: 'root' },
		sudo: { mode: 'nopasswd', commands: ['/usr/bin/systemctl'] }
	});

	// 5b. a second user exercising the explicit-keys SshKeys variant + bare-mode sudo.
	zap.user({
		id: 'ci-user',
		name: 'ci user',
		username: 'ci',
		ssh_keys: { keys: ['ssh-ed25519 AAAA... ci@example'] },
		sudo: 'password'
	});

	// 6. directory
	zap.directory({
		id: 'app-dir',
		name: 'application root',
		path: '/srv/app',
		mode: '755',
		owner: 'deploy',
		group: 'deploy'
	});

	// 7. file — remote content with tar.xz extract, strip_components, and bearer auth.
	zap.file({
		id: 'app-bundle',
		name: 'application bundle',
		path: '/srv/app/bundle',
		content: {
			type: 'remote',
			url: zap.env('ARTIFACT_URL'),
			extract: { type: 'tar.xz', strip_components: 1 },
			auth: { scheme: 'bearer', token: zap.env('TOKEN') }
		},
		owner: 'deploy',
		group: 'deploy',
		mode: '644',
		triggers: ['app-service']
	});

	// 7b. file — inline content.
	zap.file({
		id: 'motd',
		name: 'message of the day',
		path: '/etc/motd',
		content: { type: 'inline', content: 'Managed by zap.\n' },
		mode: '644',
		validate: 'test -s /etc/motd'
	});

	// 7c. file — template content with vars.
	zap.file({
		id: 'app-env',
		name: 'app environment',
		path: '/srv/app/.env',
		content: {
			type: 'template',
			template: 'HOST={{host}}\nPORT={{port}}\n',
			vars: { host: zap.env('DEPLOY_HOST'), port: 8080 }
		},
		mode: '600',
		owner: 'deploy'
	});

	// 7d. file — source content (copied from a path on the target).
	zap.file({
		id: 'app-cert',
		name: 'app certificate',
		path: '/srv/app/cert.pem',
		content: { type: 'source', path: '/etc/ssl/certs/app.pem' }
	});

	// 8. link
	zap.link({
		id: 'app-current',
		name: 'current release link',
		path: '/srv/app/current',
		target: '/srv/app/releases/latest'
	});

	// 9. service
	zap.service({
		id: 'app-service',
		name: 'application service',
		service: 'app',
		enabled: true,
		running: true,
		restart_on: ['app-bundle'],
		reload_on: ['app-env']
	});

	// 10. database
	zap.database({
		id: 'app-db',
		name: 'application database',
		engine: 'postgresql',
		database_name: 'app',
		username: 'app',
		auth: { method: 'scram-sha-256', hosts: ['127.0.0.1/32', '::1/128'] }
	});

	// 11. swap
	zap.swap({
		id: 'swapfile',
		name: 'swap file',
		size: '2G',
		path: '/swapfile'
	});

	// 12. firewall — named profile + a port/proto pair.
	zap.firewall({
		id: 'fw',
		name: 'ufw firewall',
		backend: 'ufw',
		default_incoming: 'deny',
		default_outgoing: 'allow',
		allow: ['OpenSSH', { port: 443, proto: 'tcp' }]
	});

	// 13. verify — both a path_exists and a command assertion.
	zap.verify({
		id: 'smoke',
		name: 'smoke checks',
		assertions: [
			{
				type: 'path_exists',
				path: '/srv/app/current',
				file_type: 'directory',
				mode: '755',
				owner: 'deploy',
				not_empty: true
			},
			{ type: 'command', run: 'systemctl is-active app', expect: 'active' }
		]
	});

	// 14. pipeline — multi-step with shared env, per-step env/cwd, and a dep edge.
	zap.pipeline({
		id: 'build-pipeline',
		name: 'build pipeline',
		env: { CI: 'true' },
		max_concurrency: 2,
		steps: [
			{
				id: 'fetch',
				name: 'fetch sources',
				run: 'git fetch --all',
				cwd: '/srv/src'
			},
			{
				id: 'compile',
				name: 'compile',
				run: 'make',
				cwd: '/srv/src',
				env: { OPTIMIZE: 'release' },
				depends_on: ['fetch']
			}
		]
	});

	// 15. build — remote source verified with minisign.
	zap.build({
		id: 'ghostty',
		name: 'ghostty terminal',
		source: {
			type: 'remote',
			url: zap.env('GHOSTTY_URL'),
			extract: { type: 'tar.gz', strip_components: 1 },
			auth: { scheme: 'bearer', token: zap.env('TOKEN') },
			verify: {
				scheme: 'minisign',
				public_key: 'RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3'
			},
			blake3: '0000000000000000000000000000000000000000000000000000000000000000'
		},
		run: 'zig build -p $HOME/.local -Doptimize=ReleaseFast',
		output: '$HOME/.local/bin/ghostty',
		cwd: '/tmp/ghostty-src',
		env: { ZIG_GLOBAL_CACHE_DIR: '/tmp/zig-cache' }
	});

	// deploy() release-management block.
	zap.deploy({
		build: 'gro build',
		artifacts: ['dist', 'package.json'],
		path: '/srv/app',
		releases: 5,
		service: 'app',
		shared: ['.env.production'],
		prepare: ['deno cache main.ts'],
		health: {
			domain: zap.env('DEPLOY_DOMAIN'),
			path: '/health',
			attempts: 15,
			interval_ms: 2000
		}
	});

	// mask / unmask env-var opt-in / opt-out.
	zap.mask('OFF_CONVENTION_SECRET');
	zap.unmask('PUBLIC_LOOKING_BUT_SAFE');
};
