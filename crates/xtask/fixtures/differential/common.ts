// The distro-neutral half of the `cargo xtask differential` kitchen-sink configs.
//
// Every resource here converges on both Debian and Alpine; the per-distro
// `zap.ts` files add what diverges (firewall backend, service scripts, postgres
// bring-up, apt_repo) and call `declare_common`. The harness mutates these
// resources out-of-band by path, so the paths below are mirrored in
// `crates/xtask/src/differential/scenarios.rs` — change them together.
//
// `pins.ts` (the blake3 of the artifacts the harness's content server serves) and
// `origin_ca.ts` (the test CA its https origin is served under) are generated per run
// by the harness; they are not checked in.

import type { ZapBuilder } from '../../../../src/lib/zap.ts';
import { ORIGIN_CA_PEM } from './origin_ca.ts';
import { BLOB_BLAKE3, TREE_BLAKE3 } from './pins.ts';

/** Where a distro's `update-ca-certificates` reads a locally trusted CA from. */
const ORIGIN_CA_PATH = '/usr/local/share/ca-certificates/zapdiff.crt';

/** The bundle `update-ca-certificates` writes, which `curl` and zap's own client read. */
const CA_BUNDLE_PATH = '/etc/ssl/certs/ca-certificates.crt';

/**
 * One whole line of the CA's base64 body — the last full one, which is signature
 * bytes — as the mark of this certificate in the bundle: the bundle is the trusted
 * certificates' text, joined.
 */
const origin_ca_mark = (pem: string): string => {
	const full = pem.split('\n').filter((line) => /^[A-Za-z0-9+/=]{64}$/.test(line));
	const mark = full.at(-1);
	if (mark === undefined) throw new Error('origin_ca.ts holds no certificate');
	return mark;
};

/** Per-distro inputs to the shared resources. */
export interface CommonOptions {
	/** The resource id of the triggered sleeper service (declared per distro). */
	sleeper_service_id: string;
	/** Resource ids the installer's fetch waits on (`curl` on Alpine, which ships none). */
	curl_ids: string[];
	/** Resource ids the users wait on (`shadow` on Alpine, for useradd / usermod). */
	account_tool_ids: string[];
}

export const declare_common = (zap: ZapBuilder, options: CommonOptions): void => {
	const { sleeper_service_id, curl_ids, account_tool_ids } = options;

	// --- packages ---------------------------------------------------------
	zap.pkg({ id: 'jq', from: { apt: 'jq', apk: 'jq' } });
	// a path `check` instead of the manager query
	zap.pkg({ id: 'jq-path-check', from: { apt: 'jq', apk: 'jq' }, check: '/usr/bin/jq' });
	// privilege canary: a command `check` that only passes as the login user
	zap.pkg({
		id: 'pkg-login-check',
		from: { apt: 'jq', apk: 'jq' },
		check: 'test "$(id -un)" = ops'
	});

	// --- directories ------------------------------------------------------
	zap.directory({ id: 'opt-dir', path: '/opt/zapdiff', mode: '755', owner: 'root', group: 'root' });
	zap.directory({ id: 'etc-dir', path: '/etc/zapdiff', mode: '755' });
	zap.directory({ id: 'empty-dir', path: '/opt/zapdiff/empty-dir', depends_on: ['opt-dir'] });
	zap.directory({
		id: 'spaced-dir',
		path: '/opt/zapdiff/zap diff',
		mode: '755',
		depends_on: ['opt-dir']
	});
	zap.directory({
		id: 'spaced-subdir',
		path: '/opt/zapdiff/zap diff/sub dir',
		mode: '755',
		depends_on: ['spaced-dir']
	});
	// root-only: detection of anything below it needs privilege
	zap.directory({
		id: 'private-dir',
		path: '/opt/zapdiff/private',
		mode: '700',
		owner: 'root',
		group: 'root',
		depends_on: ['opt-dir']
	});
	zap.directory({ id: 'home-dir', path: '~/zapdiff', mode: '755' });

	// --- files ------------------------------------------------------------
	zap.file({
		id: 'inline',
		path: '/etc/zapdiff/inline.conf',
		content: { type: 'inline', content: 'zapdiff inline content\nsecond line\n' },
		mode: '644',
		owner: 'root',
		group: 'root',
		depends_on: ['etc-dir']
	});
	zap.file({
		id: 'inline-no-eol',
		path: '/etc/zapdiff/no-eol.txt',
		content: { type: 'inline', content: 'no newline at the end' },
		mode: '644',
		depends_on: ['etc-dir']
	});
	zap.file({
		id: 'inline-crlf',
		path: '/etc/zapdiff/crlf.txt',
		content: { type: 'inline', content: 'line one\r\nline two\r\n' },
		mode: '644',
		depends_on: ['etc-dir']
	});
	zap.file({
		id: 'template',
		path: '/etc/zapdiff/template.conf',
		content: {
			type: 'template',
			template: 'name={{name}}\nport={{port}}\n',
			vars: { name: 'zapdiff', port: 8080 }
		},
		mode: '640',
		owner: 'root',
		group: 'root',
		depends_on: ['etc-dir']
	});
	zap.file({
		id: 'source-origin',
		path: '/etc/zapdiff/source-origin.conf',
		content: { type: 'inline', content: 'origin of the source-copied file\n' },
		mode: '644',
		depends_on: ['etc-dir']
	});
	zap.file({
		id: 'source-copy',
		path: '/etc/zapdiff/source-copy.conf',
		content: { type: 'source', path: '/etc/zapdiff/source-origin.conf' },
		mode: '644',
		depends_on: ['source-origin']
	});
	zap.file({
		id: 'spaced-file',
		path: "/opt/zapdiff/zap diff/it's here.txt",
		content: { type: 'inline', content: "a path with a space and a single quote's worth\n" },
		mode: '644',
		depends_on: ['spaced-dir']
	});
	zap.file({
		id: 'private-file',
		path: '/opt/zapdiff/private/secret.conf',
		content: { type: 'inline', content: 'root-only content\n' },
		mode: '600',
		owner: 'root',
		group: 'root',
		depends_on: ['private-dir']
	});
	zap.file({
		id: 'home-file',
		path: '~/zapdiff/home.txt',
		content: { type: 'inline', content: 'a file under the target home\n' },
		mode: '644',
		depends_on: ['home-dir']
	});

	// --- links ------------------------------------------------------------
	zap.link({
		id: 'spaced-link',
		path: '/opt/zapdiff/zap diff/link to it',
		target: "/opt/zapdiff/zap diff/it's here.txt",
		depends_on: ['spaced-file']
	});

	// --- remote content (served by the harness's loopback content server) --
	zap.file({
		id: 'blob',
		path: '/opt/zapdiff/blob.bin',
		content: {
			type: 'remote',
			url: `${zap.env('ZAPDIFF_CONTENT')}/blob.bin`,
			extract: { type: 'none' },
			blake3: BLOB_BLAKE3
		},
		mode: '644',
		depends_on: ['opt-dir']
	});
	// tracked: no in-config pin, `zap.lock` holds it
	zap.file({
		id: 'blob-tracked',
		path: '/opt/zapdiff/blob-tracked.bin',
		content: { type: 'remote', url: `${zap.env('ZAPDIFF_CONTENT')}/blob-tracked.bin` },
		depends_on: ['opt-dir']
	});
	zap.file({
		id: 'tree',
		path: '/opt/zapdiff/tree',
		content: {
			type: 'remote',
			url: `${zap.env('ZAPDIFF_CONTENT')}/tree.tar.gz`,
			extract: { type: 'tar.gz', strip_components: 1 },
			blake3: TREE_BLAKE3
		},
		depends_on: ['opt-dir']
	});
	zap.build({
		id: 'build',
		source: {
			type: 'remote',
			url: `${zap.env('ZAPDIFF_CONTENT')}/tree.tar.gz`,
			extract: { type: 'tar.gz', strip_components: 1 },
			blake3: TREE_BLAKE3
		},
		run: 'mkdir -p $HOME/.local/bin && cp bin/zapdiff-tool $HOME/.local/bin/zapdiff-built && chmod 755 $HOME/.local/bin/zapdiff-built',
		output: '$HOME/.local/bin/zapdiff-built'
	});
	// tracked source: the pin lives in `zap.lock`
	zap.build({
		id: 'build-tracked',
		source: {
			type: 'remote',
			url: `${zap.env('ZAPDIFF_CONTENT')}/build-tracked.tar.gz`,
			extract: { type: 'tar.gz', strip_components: 1 }
		},
		run: 'mkdir -p $HOME/.local/bin && cp bin/zapdiff-tool $HOME/.local/bin/zapdiff-built-tracked',
		output: '$HOME/.local/bin/zapdiff-built-tracked'
	});

	// --- the harness's https origin, trusted the way an operator trusts a private CA:
	// its certificate in the distro's local CA directory, then the bundle rebuilt ----
	zap.pkg({
		id: 'ca-certificates',
		from: { apt: 'ca-certificates', apk: 'ca-certificates' }
	});
	zap.file({
		id: 'origin-ca',
		path: ORIGIN_CA_PATH,
		content: { type: 'inline', content: ORIGIN_CA_PEM },
		mode: '644',
		owner: 'root',
		group: 'root',
		depends_on: ['ca-certificates']
	});
	zap.script({
		id: 'origin-ca-trust',
		check: `grep -qxF '${origin_ca_mark(ORIGIN_CA_PEM)}' ${CA_BUNDLE_PATH}`,
		run: 'sudo /usr/sbin/update-ca-certificates',
		depends_on: ['origin-ca']
	});

	// --- installer (the target's curl fetches the script from the origin) ---
	zap.installer({
		id: 'installer',
		url: `${zap.env('ZAPDIFF_ORIGIN')}/installer.sh`,
		check: '/opt/zapdiff/installer.marker',
		depends_on: ['opt-dir', 'origin-ca-trust', ...curl_ids]
	});

	// --- scripts ----------------------------------------------------------
	// a check that drains stdin before answering
	zap.script({
		id: 'script-stdin',
		check: 'cat >/dev/null; test -f /opt/zapdiff/stdin-check.marker',
		run: 'sudo touch /opt/zapdiff/stdin-check.marker',
		depends_on: ['opt-dir']
	});
	// a check that takes ~2 s
	zap.script({
		id: 'script-slow',
		check: 'sleep 2; test -f /opt/zapdiff/slow-check.marker',
		run: 'sudo touch /opt/zapdiff/slow-check.marker',
		env: { ZAPDIFF_SCRIPT: 'slow' },
		depends_on: ['opt-dir']
	});

	// relative to `cwd`
	zap.script({
		id: 'script-cwd',
		check: 'test -f cwd.marker',
		cwd: '/opt/zapdiff',
		run: 'sudo touch /opt/zapdiff/cwd.marker',
		depends_on: ['opt-dir']
	});
	// a reference to an operator variable inside a check (the harness supplies it)
	zap.script({
		id: 'script-var',
		check: `test "${zap.env('ZAPDIFF_EXPECT')}" = expected-value`,
		run: 'true'
	});
	// privilege canary: only passes as the login user
	zap.script({ id: 'script-login-user', check: 'test "$(id -un)" = ops', run: 'true' });

	// --- users ------------------------------------------------------------
	zap.user({
		id: 'user-copy',
		username: 'zapdiff',
		shell: '/bin/sh',
		home_mode: '750',
		ssh_keys: { copy_from: 'ops' },
		sudo: 'nopasswd',
		groups: ['users', 'video'],
		depends_on: account_tool_ids
	});
	zap.user({
		id: 'user-keys',
		username: 'zapdiff2',
		shell: '/bin/sh',
		ssh_keys: {
			keys: ['ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGRpZmZlcmVudGlhbC1oYXJuZXNzLWtleQ zapdiff2']
		},
		sudo: { mode: 'password', commands: ['/usr/bin/true'] },
		depends_on: account_tool_ids
	});
	// copies another managed user's keys
	zap.user({
		id: 'user-copy-keys',
		username: 'zapdiff3',
		ssh_keys: { copy_from: 'zapdiff2' },
		depends_on: ['user-keys', ...account_tool_ids]
	});

	// --- swap -------------------------------------------------------------
	zap.swap({ id: 'swap', path: '/swapfile-zapdiff', size: '32M' });

	// --- the triggered service's config (push side) ------------------------
	zap.file({
		id: 'sleeper-conf',
		path: '/etc/zapdiff/sleeper.conf',
		content: { type: 'inline', content: 'sleeper settings\n' },
		mode: '644',
		triggers: [sleeper_service_id],
		depends_on: ['etc-dir']
	});

	// --- verify -----------------------------------------------------------
	zap.verify({
		id: 'verify',
		assertions: [
			{
				type: 'path_exists',
				// unprivileged: a path under the 0700 dir would never read as existing
				path: '/etc/zapdiff/inline.conf',
				file_type: 'file',
				mode: '644',
				owner: 'root',
				not_empty: true
			},
			{ type: 'command', run: 'cat /etc/zapdiff/verify.flag', expect: 'verified' }
		],
		depends_on: ['inline', 'verify-flag']
	});
	// privilege canary: the command runs as the login user
	zap.verify({
		id: 'verify-login-user',
		assertions: [{ type: 'command', run: 'id -un', expect: 'ops' }]
	});
	// a path under the 'zap diff' dir (unprivileged: reads missing once it's 0700)
	zap.verify({
		id: 'verify-spaced',
		assertions: [{ type: 'path_exists', path: "/opt/zapdiff/zap diff/it's here.txt" }],
		depends_on: ['spaced-file']
	});
	zap.file({
		id: 'verify-flag',
		path: '/etc/zapdiff/verify.flag',
		content: { type: 'inline', content: 'verified\n' },
		mode: '644',
		depends_on: ['etc-dir']
	});

	// --- pipeline (always plans: imperative by construction) ---------------
	zap.pipeline({ id: 'pipeline', steps: [{ id: 'noop', run: 'true' }] });
};
