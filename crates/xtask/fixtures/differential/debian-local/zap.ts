// `cargo xtask differential` local-connection fixture — evaluated and converged *on*
// the Debian VM as `ops` (`target: {local: true}`), so the Local connection path is
// compared: native `std::fs` for what `ops` can read and write, the `sudo` fallback
// for root-owned and root-only paths. The SSH kitchen sink (`../debian/zap.ts`)
// provides the host prerequisites (jq, postgres, the sleeper service, and the
// harness's test CA in the trust store: this zap fetches `ZAPDIFF_CONTENT` over https
// from the dev machine); the bundle carries the `fgro` it evaluates with.
//
// Host-global kinds the SSH fixture already owns (firewall, swap, apt_repo) and the
// kinds that fetch for a build or on the target (build, installer) are covered over
// SSH only.

import type { ZapBuilder } from '../../../../../src/lib/zap.ts';
import { BLOB_BLAKE3 } from '../pins.ts';

export default (zap: ZapBuilder): void => {
	zap.target({ local: true, package_manager: 'apt', service_manager: 'systemd' });

	// --- under the operator's home: native reads and writes ----------------
	zap.directory({ id: 'home-dir', path: '~/zapdiff-local', mode: '755' });
	zap.file({
		id: 'home-file',
		path: "~/zapdiff-local/it's a file.txt",
		content: { type: 'inline', content: 'local home content\n' },
		mode: '644',
		depends_on: ['home-dir']
	});
	zap.file({
		id: 'home-template',
		path: '~/zapdiff-local/template.conf',
		content: { type: 'template', template: 'who={{who}}\n', vars: { who: 'local' } },
		mode: '600',
		depends_on: ['home-dir']
	});
	zap.link({
		id: 'home-link',
		path: '~/zapdiff-local/link',
		target: '/etc/zapdiff-local/root.conf',
		depends_on: ['home-dir', 'root-file']
	});
	zap.file({
		id: 'home-blob',
		path: '~/zapdiff-local/blob.bin',
		content: { type: 'remote', url: `${zap.env('ZAPDIFF_CONTENT')}/blob.bin`, blake3: BLOB_BLAKE3 },
		depends_on: ['home-dir']
	});

	// --- root-owned: native read, sudo-fallback write ----------------------
	zap.directory({ id: 'root-dir', path: '/etc/zapdiff-local', mode: '755', owner: 'root' });
	zap.file({
		id: 'root-file',
		path: '/etc/zapdiff-local/root.conf',
		content: { type: 'inline', content: 'local root content\n' },
		mode: '644',
		owner: 'root',
		group: 'root',
		depends_on: ['root-dir']
	});
	zap.file({
		id: 'root-source-copy',
		path: '/etc/zapdiff-local/source-copy.conf',
		content: { type: 'source', path: '/etc/zapdiff-local/root.conf' },
		mode: '644',
		depends_on: ['root-file']
	});

	// --- root-only: native read denied, sudo fallback ----------------------
	zap.directory({
		id: 'private-dir',
		path: '/etc/zapdiff-local/private',
		mode: '700',
		owner: 'root',
		group: 'root',
		depends_on: ['root-dir']
	});
	zap.file({
		id: 'private-file',
		path: '/etc/zapdiff-local/private/secret.conf',
		content: { type: 'inline', content: 'local root-only content\n' },
		// no mode/owner/group: Local reads metadata with an unprivileged `stat` and no
		// sudo retry, so a managed mode under a 0700 dir holds `undetermined` forever
		depends_on: ['private-dir']
	});

	// --- manager / account / database probes, run locally ------------------
	zap.pkg({ id: 'jq', from: { apt: 'jq' } });
	zap.service({ id: 'sleeper', service: 'zapdiff-sleeper', enabled: true, running: true });
	zap.user({
		id: 'user',
		username: 'zapdifflocal',
		shell: '/bin/sh',
		home_mode: '750',
		ssh_keys: {
			keys: ['ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGxvY2FsLWRpZmZlcmVudGlhbC1rZXk zapdifflocal']
		},
		sudo: false,
		groups: ['users']
	});
	zap.database({
		id: 'database',
		engine: 'postgresql',
		database_name: 'zapdifflocal',
		username: 'zapdifflocal',
		auth: { method: 'scram-sha-256', hosts: ['127.0.0.1/32', '::1/128'] }
	});
	zap.script({
		id: 'script',
		check: 'cat >/dev/null; test -f ~/zapdiff-local/script.marker',
		run: 'touch ~/zapdiff-local/script.marker',
		depends_on: ['home-dir']
	});
	// privilege canaries: pass only as the login user
	zap.pkg({ id: 'pkg-login-check', from: { apt: 'jq' }, check: 'test "$(id -un)" = ops' });
	zap.script({ id: 'script-login-user', check: 'test "$(id -un)" = ops', run: 'true' });
	zap.verify({
		id: 'verify-login-user',
		assertions: [{ type: 'command', run: 'id -un', expect: 'ops' }]
	});
	zap.verify({
		id: 'verify',
		assertions: [
			{
				type: 'path_exists',
				path: '/etc/zapdiff-local/root.conf',
				file_type: 'file',
				not_empty: true
			},
			{ type: 'command', run: 'cat /etc/zapdiff-local/root.conf', expect: 'local root' }
		],
		depends_on: ['root-file']
	});
};
