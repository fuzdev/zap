/**
 * Recipe for installing a pinned Deno runtime as a `script` resource.
 *
 * `deno_install` builds the `check`/`run` payload, pinned and idempotent, for
 * either destination:
 *
 * - **system** (`privileged: true`) — `sudo install` into a root-owned dir like
 *   `/usr/local/bin/deno`, readable + executable under a hardened unit's
 *   `ProtectSystem=strict` and on the default systemd `PATH` (a subprocess a
 *   service starts per call).
 * - **user-home** (`user: '<svc>'`) — install as the service user into a path
 *   under their home (`/home/<svc>/.deno/bin/deno`), so a bootstrap apply
 *   running as `root` still lands Deno owned by the service user, not `/root` (a long-running Deno
 *   backend).
 *
 * The binary is fetched from the GitHub release zip of the pinned version (no
 * `curl | sh`). The zip is not checked against a digest: its bytes are trusted as
 * the release URL serves them over TLS. The `check` is the exact version pin, so a
 * re-apply reinstalls only on a version bump. Warming a module cache (`deno cache`) is intentionally
 * left to the caller — it's per-consumer (entrypoint + apply-vs-deploy timing).
 *
 * Recipes are imported at config eval time inside zap's sandboxed config eval
 * (`fgro eval`), which has no network, no writes, and no environment, and where the
 * clock and randomness throw, so this is a **pure function**: it only assembles
 * strings from its arguments. Deterministic output keeps it a reliable
 * content-addressed plan artifact.
 *
 * The caller spreads the result into a `script` resource, e.g.
 * `zap.script({id: 'deno-install', name: '...', ...deno_install({version: '2.8.2', bin_path: '/usr/local/bin/deno', privileged: true}), depends_on: ['curl', 'unzip']})`.
 * The host needs `curl` + `unzip` (declare them as `pkg` deps).
 *
 * @module
 */

import type { ScriptResource } from './schema.ts';
import { single_quote, sudo_as_user } from './shell.ts';

/** The `check`/`run` pair `deno_install` returns (caller supplies `id`/`name`/`depends_on`). */
export type DenoScript = Pick<ScriptResource, 'check' | 'run'>;

/** Options for `deno_install`. */
export interface DenoInstallOptions {
	/** Pinned Deno version, e.g. `'2.8.2'` (no leading `v`). */
	version: string;
	/**
	 * Absolute path the `deno` executable is installed to — e.g.
	 * `'/usr/local/bin/deno'` (system) or `'/home/svc/.deno/bin/deno'` (user-home).
	 * Parent dirs are created (`install -D`). Passed single-quoted, so it is taken
	 * literally: no `~` or `$HOME` expansion. Refused at eval unless it begins `/`.
	 */
	bin_path: string;
	/**
	 * Install as this user via `sudo -u <user>`, so `bin_path` (under their home)
	 * lands owned by them even when the apply runs as `root`. The `check` and the
	 * closing `--version` run the binary as this user too, never as the connecting
	 * user: the account owns the file, and could replace it. A user name written
	 * out: not empty, not `#<uid>`, and not a reference. Omit for a same-user or
	 * `privileged` system install. Mutually exclusive with `privileged`.
	 */
	user?: string;
	/**
	 * `sudo` the install into a root-owned system dir (e.g. `/usr/local/bin`).
	 * Defaults to `false`. Mutually exclusive with `user`.
	 */
	privileged?: boolean;
	/**
	 * Release-asset target triple. Defaults to `'x86_64-unknown-linux-gnu'`
	 * (glibc). On an Alpine/musl host pass `'x86_64-unknown-linux-musl'` — a glibc
	 * Deno binary won't run under musl without `gcompat` (this recipe is neutral,
	 * so the distro is the caller's to declare).
	 */
	target?: string;
}

/**
 * Build the `check`/`run` for a pinned-Deno install `script` resource.
 *
 * `check` passes once the pinned version is present at `bin_path` (so a
 * re-apply is a no-op until the version bumps); `run` downloads the pinned
 * release zip, extracts it, and installs the binary to `bin_path` per the
 * destination mode (`user` / `privileged` / same-user).
 *
 * @returns the `script` `check`/`run` pair.
 * @throws Error if `bin_path` isn't absolute, `user` and `privileged` are both given, or
 *   `user` is empty, starts with `#`, or is a reference
 */
export function deno_install(options: DenoInstallOptions): DenoScript {
	const {
		version,
		bin_path,
		user,
		privileged = false,
		target = 'x86_64-unknown-linux-gnu'
	} = options;

	if (!bin_path.startsWith('/')) {
		throw new Error(
			`deno_install: bin_path ${JSON.stringify(bin_path)} must be an absolute path (begin with \`/\`)`
		);
	}
	if (user !== undefined && privileged) {
		throw new Error('deno_install: `user` and `privileged` exclude each other; pass one');
	}

	const url = `https://github.com/denoland/deno/releases/download/v${version}/deno-${target}.zip`;

	// Only the install and who runs the binary vary by destination. For `user`, the temp
	// tree is world-readable (chmod below) so `sudo -u <user> install` can read it, and
	// the binary — which that user owns, and so can replace — is only ever run as that
	// user: run as the connecting user, who has sudo, a binary the service account
	// swapped would hand it root at the next plan's `check`.
	const bin = single_quote(bin_path);
	const as_user = user === undefined ? '' : sudo_as_user('deno_install', user);
	const install_line = user
		? `${as_user}install -D -m 755 "$tmp/deno" ${bin}`
		: privileged
			? `sudo install -D -m 755 "$tmp/deno" ${bin}`
			: `install -D -m 755 "$tmp/deno" ${bin}`;

	return {
		check: `${as_user}${bin} --version 2>/dev/null | grep -q ${single_quote(`^deno ${version} `)}`,
		run: `set -e
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
curl -fsSL -o "$tmp/deno.zip" ${single_quote(url)}
unzip -q -o "$tmp/deno.zip" -d "$tmp"
chmod 0755 "$tmp" "$tmp/deno"
${install_line}
${as_user}${bin} --version`
	};
}
