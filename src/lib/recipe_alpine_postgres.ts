/**
 * Alpine PostgreSQL bootstrap. Alpine ships PostgreSQL in its own repos, so there
 * is no third-party-repo step (the Debian `postgres_apt_repo` has no Alpine
 * analogue); install it with `zap.pkg({id: 'postgres', from: {apk: 'postgresql<version>'}})` plus
 * `postgresql<version>-openrc` for the OpenRC service.
 *
 * The one thing `apk` does NOT do that Debian's `apt` does is initialize the data
 * cluster — `alpine_postgres_setup` supplies that as an idempotent `script`, run
 * once before the `postgresql` service starts. The OpenRC service is the
 * version-agnostic `postgresql` (Alpine's `postgresql-common` wrapper picks the
 * installed major).
 *
 * Pure function evaluated in zap's sandboxed config eval (`fgro eval`).
 *
 * @module
 */

import type { ScriptResource } from './schema.ts';
import { single_quote } from './shell.ts';

/** Options for `alpine_postgres_setup`. */
export interface AlpinePostgresSetupOptions {
	/**
	 * The installed PostgreSQL major version — matches `apk add postgresql<version>`
	 * and the `/var/lib/postgresql/<version>/data` cluster path. Pin it to the
	 * major your other hosts run, for replication and restore compatibility.
	 */
	version: number | string;
}

/** The `check`/`run` pair `alpine_postgres_setup` returns (caller supplies `id`/`name`/`depends_on`). */
export type AlpinePostgresSetupScript = Pick<ScriptResource, 'check' | 'run'>;

/**
 * The `grep -E` pattern for a `trust` rule in a `pg_hba.conf`: a line that isn't a
 * comment whose method field is `trust`.
 */
const TRUST_RULE = "'^[[:space:]]*[^#[:space:]].*[[:space:]]trust([[:space:]]|$)'";

/**
 * Build the `postgres-cluster-init` script's `check`/`run` for Alpine.
 *
 * `run` initializes the data cluster via the OpenRC `setup` action (Alpine's
 * `apk` install does not, unlike Debian's `apt`), then closes the `trust` rules
 * that action's `initdb` writes into the new `pg_hba.conf`: `local` lines become
 * `peer` (the OS account named like the role) and `host` lines `scram-sha-256` (a
 * password), so no account on the machine connects as any role, `postgres`
 * included, without a credential. Debian's cluster starts with those methods. The
 * rewrite runs as `postgres`, which owns the file and its directory (`sed -i` stages
 * its copy there), and the script fails if a `trust` rule is left. A
 * server already running is told to reload (`rc-service --ifstarted`), so the new
 * rules are in force.
 *
 * `check` passes once the cluster's `PG_VERSION` marker exists and its `pg_hba.conf`
 * holds no `trust` rule. So a run that failed after `setup` is retried on the next
 * apply, and that run skips `setup` (the cluster is there) and goes straight to the
 * rewrite; a cluster set up before this recipe, `trust` rules and all, is rewritten
 * the same way.
 *
 * **A client that relied on a `trust` rule stops connecting.** Every `trust` line in the
 * file is rewritten, not only `initdb`'s: a service that reaches PostgreSQL over TCP
 * with no password is refused once the rewrite is in force, and one on the socket is
 * admitted only as the OS account named like its role. Move such a client to the
 * socket as its own account (`fuz_app_env_base`'s `DATABASE_URL`), or give it a
 * password, before this runs on an existing cluster. Sequence it before the
 * `postgresql` service (the `setup` action requires the server stopped) and before any
 * `zap.database`.
 *
 * @returns the `script` `check`/`run` pair.
 */
export function alpine_postgres_setup(
	options: AlpinePostgresSetupOptions
): AlpinePostgresSetupScript {
	const { version } = options;
	if (!/^[0-9]+$/.test(String(version))) {
		throw new Error(
			`alpine_postgres_setup: version ${JSON.stringify(version)} must be a PostgreSQL major version number`
		);
	}
	const data_dir = `/var/lib/postgresql/${version}/data`;
	const marker = single_quote(`${data_dir}/PG_VERSION`);
	// `setup` moves `pg_hba.conf` to `/etc/postgresql` and links it from the data
	// directory, so the file is the link's target
	const resolve_hba = `hba=$(sudo readlink -f -- ${single_quote(`${data_dir}/pg_hba.conf`)})`;

	return {
		check: `sudo test -e ${marker} && ${resolve_hba} && [ -n "$hba" ] && ! sudo grep -Eq ${TRUST_RULE} "$hba"`,
		run: `set -e
sudo test -e ${marker} || sudo rc-service postgresql setup
${resolve_hba}
[ -n "$hba" ]
sudo -u postgres sed -i -E -e 's/^(local[[:space:]].*[[:space:]])trust[[:space:]]*$/\\1peer/' -e 's/^(host[[:space:]].*[[:space:]])trust[[:space:]]*$/\\1scram-sha-256/' "$hba"
if sudo grep -Eq ${TRUST_RULE} "$hba"; then
  echo "zap: a trust rule is left in $hba" >&2
  exit 1
fi
sudo rc-service --ifstarted postgresql reload`
	};
}
