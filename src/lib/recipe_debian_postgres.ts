/**
 * Recipe for the official PostgreSQL apt repository resource fields (Debian/Ubuntu).
 *
 * Alpine ships PostgreSQL in its own repos (no third-party repo), so there is no
 * Alpine analogue of this — `recipe_alpine_postgres.ts` instead supplies the
 * cluster-init the `apk` package omits (`alpine_postgres_setup`).
 *
 * `postgres_apt_repo` builds the `apt_repo` payload (minus `id`/`name`) for the
 * PostgreSQL Global Development Group's apt repository. The GPG key URL, the key's
 * pin (`PGDG_KEY_BLAKE3`), and the `deb` source line are constants; the on-disk key +
 * list paths vary by host convention (`/usr/share/keyrings` on a server;
 * `/usr/share/postgresql-common/pgdg` where PGDG's own install script put it), so
 * they're parameters defaulting to the `/usr/share/keyrings` convention.
 *
 * Recipes are imported at config eval time inside zap's sandboxed config eval
 * (`fgro eval`), which has no network, no writes, and no environment, and where
 * the clock and randomness throw. This module is therefore a **pure function**: it only assembles an
 * object from its arguments — no I/O, no clock, no randomness, no imports beyond
 * types. The output is deterministic for given inputs, so it stays a reliable
 * content-addressed plan artifact.
 *
 * The caller spreads the result into an `apt_repo` resource, e.g.
 * `zap.apt_repo({id: 'postgresql-repo', name: '...', ...postgres_apt_repo(), depends_on: ['curl']})`.
 *
 * @module
 */

import type { AptRepoResource } from './schema.ts';

/**
 * Options for `postgres_apt_repo`.
 *
 * Both fields default to the `/usr/share/keyrings` convention; pass them to match
 * a host that stores the key + list elsewhere (e.g. PGDG's own
 * `/usr/share/postgresql-common/pgdg/apt.postgresql.org.asc`).
 */
export interface PostgresAptRepoOptions {
	/** Where the GPG signing key is stored. Defaults to `/usr/share/keyrings/postgresql-pgdg.asc`. */
	key_path?: string;
	/** The `.list` file path. Defaults to `/etc/apt/sources.list.d/pgdg.list`. */
	list_file?: string;
}

/**
 * The blake3 of the PGDG signing key `postgres_apt_repo` fetches, vendored as its
 * `key_blake3`: zap installs only these bytes, so a config needs no lock entry for it.
 * When PGDG rotates the key, its fetch no longer matches and the apply fails naming
 * both digests; moving to the new key is an edit of this constant.
 */
export const PGDG_KEY_BLAKE3 = 'bb84ad7105529a9bf29a01dca1d2e400576031b070e396a9f0c669bf75457192';

/** The `apt_repo` fields `postgres_apt_repo` returns (caller supplies `id`/`name`). */
export type PostgresAptRepoFields = Pick<
	AptRepoResource,
	'key_url' | 'key_blake3' | 'source' | 'key_path' | 'list_file'
>;

/**
 * Build the PostgreSQL `apt_repo` fields for `options`.
 *
 * The `key_url` (the PGDG signing key), its pin, and `source` (the `pgdg main` deb line,
 * with `${VERSION_CODENAME}` left for the target's shell to expand, `/etc/os-release`
 * sourced, when zap writes the line) are fixed; the
 * key + list paths come from inputs, defaulting to the `/usr/share/keyrings` convention.
 *
 * @returns the `apt_repo` payload minus `id`/`name`, ready to spread.
 */
export function postgres_apt_repo(options?: PostgresAptRepoOptions): PostgresAptRepoFields {
	const {
		key_path = '/usr/share/keyrings/postgresql-pgdg.asc',
		list_file = '/etc/apt/sources.list.d/pgdg.list'
	} = options ?? {};

	return {
		key_url: 'https://www.postgresql.org/media/keys/ACCC4CF8.asc',
		key_blake3: PGDG_KEY_BLAKE3,
		source: 'deb https://apt.postgresql.org/pub/repos/apt ${VERSION_CODENAME}-pgdg main',
		key_path,
		list_file
	};
}
