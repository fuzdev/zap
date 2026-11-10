/**
 * Recipe for a fuz_app server's first-admin bootstrap token.
 *
 * `fuz_app_bootstrap_token` builds the `check`/`run` of the
 * `bootstrap-token` `script` resource a fuz_app server deploy declares. On a
 * fresh deploy the fuz_app server exposes `/api/account/bootstrap` while a token
 * file exists at `FUZ_BOOTSTRAP_TOKEN_PATH`; this resource mints that token once.
 *
 * Idempotency comes entirely from the two-part `check`:
 *
 * - `test -f P -a ! -h P -a -s P` covers the freshly-minted case (the token file
 *   is still on disk). An empty file fails it, so a mint that wrote nothing is
 *   retried rather than read as converged; so does a directory at the token path,
 *   which `test -s` alone would pass, and a symlink, which `test -f` and `test -s`
 *   follow: the check runs as root, so a link at the path to any non-empty file
 *   would otherwise read as a minted token. It is no boundary against `user`, who
 *   owns `config_dir` and can write a regular file there that the server then reads
 *   as its token.
 * - the `bootstrap_lock` psql probe covers the case where the fuz_app handler
 *   already consumed and deleted the token file on success — the row marks the
 *   server bootstrapped, so a later apply skips `run` rather than re-minting an
 *   inert token with no consumer.
 *
 * On a brand-new server (no file, no lock row) the check fails, `run` mints the
 * token, and a re-apply converges. The `check` carries the whole idempotency
 * contract here, so keep it precise.
 *
 * To force a re-mint (e.g. rotating a stuck token), clear the target-side state
 * the `check` reads: remove `<config_dir>/secret_bootstrap_token` and reset the
 * `bootstrap_lock` row, so the next apply's check fails and `run` mints again.
 *
 * Recipes are imported at config eval time inside zap's sandboxed config eval
 * (`fgro eval`), which has no network, no writes, and no environment, and where
 * the clock and randomness throw. This module is therefore a **pure function**: it only assembles strings
 * from its arguments — no I/O, no clock, no randomness, no imports beyond types and
 * the pure `single_quote`, which quotes each value it splices into a command, and
 * `sudo_as_user`.
 * The `openssl rand` call runs on the _target_ at apply time, not at config
 * eval, so determinism of the plan is preserved. The target needs `openssl`;
 * without it `run` fails and writes nothing.
 *
 * `user` and `config_dir` are refused at config eval when they can't mean what
 * the recipe assumes: an empty `user`, one starting with `#`, which `sudo -u`
 * reads as a uid (`#0` is root), or a reference, whose value isn't known until it
 * runs (`sudo_as_user`); and a `config_dir` that isn't absolute.
 *
 * The caller spreads the result into a `script` resource, e.g.
 * `zap.script({id: 'bootstrap-token', name: '...', ...fuz_app_bootstrap_token({user, service, config_dir}), depends_on: [...]})`.
 *
 * @module
 */

import type { ScriptCommands } from './schema.ts';
import { single_quote, sudo_as_user } from './shell.ts';

/** Options for `fuz_app_bootstrap_token`. */
export interface FuzAppBootstrapTokenOptions {
	/**
	 * The service user that owns `config_dir` and writes the token file. `run` runs as
	 * them (`sudo -u <user>`), so the connecting user's sudo rule must allow running as
	 * them, even when it is the same user. A user name written out: not empty, not
	 * `#<uid>`, and not a reference.
	 */
	user: string;
	/** Database name probed by the `bootstrap_lock` fallback check (the `psql_args` default is `-d <service>`). */
	service: string;
	/**
	 * Absolute directory holding `secret_bootstrap_token`, e.g. `/home/<user>/.myapp`.
	 * The token path is `<config_dir>/secret_bootstrap_token`. Must already exist
	 * and be writable by `user` (declare the config-dir `directory` resource, owned by
	 * `user`, as a `depends_on`).
	 */
	config_dir: string;
	/**
	 * `psql` connection args for the `bootstrap_lock` fallback probe. Defaults to
	 * `-d <service>`: the Unix socket, as the connecting user, whom the stock `peer`
	 * rule admits when the user is the role (the deploy user running the service, as
	 * `fuz_app_env_base`'s `DATABASE_URL` assumes). These are shell words, spliced
	 * into the check as written: quote a value in them yourself. Every other option
	 * is passed as one single-quoted word.
	 */
	psql_args?: string;
}

/**
 * Build the `check`/`run` for a fuz_app `bootstrap-token` script.
 *
 * `check` passes when the token path is a non-empty regular file (not a symlink to one) or the `bootstrap_lock` row
 * already marks the server bootstrapped; `run` mints a token of 32 random bytes
 * as 64 lowercase hex characters at `<config_dir>/secret_bootstrap_token` (mode
 * 600, owned by `user`), ending in one LF, which fuz_app's reader strips.
 *
 * @returns the `script` `check`/`run` payload, ready to spread.
 * @throws Error if `user` is empty, starts with `#`, or is a reference, or `config_dir` isn't absolute
 */
export function fuz_app_bootstrap_token(options: FuzAppBootstrapTokenOptions): ScriptCommands {
	const { user, service, config_dir, psql_args = `-d ${single_quote(service)}` } = options;

	const as_user = sudo_as_user('fuz_app_bootstrap_token', user);
	if (!config_dir.startsWith('/')) {
		throw new Error(
			`fuz_app_bootstrap_token: config_dir ${JSON.stringify(
				config_dir
			)} must be an absolute path (begin with \`/\`)`
		);
	}

	const token_path = single_quote(`${config_dir}/secret_bootstrap_token`);

	return {
		check: `sudo test -f ${token_path} -a ! -h ${token_path} -a -s ${token_path} || psql ${
			psql_args
		} -tAc "SELECT bootstrapped FROM bootstrap_lock WHERE id = 1" 2>/dev/null | grep -qx t`,
		// The token is written as `user`, who owns `config_dir`: a root write would follow a
		// symlink `user` planted at the path, and a root `chown` after it would hand `user`
		// whatever file the link named. `umask 077` keeps the file owner-only from its
		// creation where sudo passes the caller's umask on; where sudoers or PAM sets one
		// instead (stock Debian lets PAM's win), the `chmod` narrows it, and a `config_dir`
		// no other user can enter keeps it out of reach until then. The token goes through a
		// variable so `set -e` sees `openssl` fail (a pipeline's status is its last
		// command's) and nothing is written; `printf` is a shell builtin, so the token is in
		// no argv.
		run: `set -e
umask 077
token=$(openssl rand -hex 32)
printf '%s\\n' "$token" | ${as_user}tee ${token_path} > /dev/null
${as_user}chmod 600 ${token_path}
echo "Bootstrap token created"`
	};
}
