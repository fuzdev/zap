import { assert, test } from 'vitest';

import { postgres_apt_repo } from '#lib/recipe_debian_postgres.ts';

test('reproduces the reference postgres apt_repo fields', () => {
	const fields = postgres_apt_repo();

	assert.deepEqual(fields, {
		key_url: 'https://www.postgresql.org/media/keys/ACCC4CF8.asc',
		key_blake3: 'bb84ad7105529a9bf29a01dca1d2e400576031b070e396a9f0c669bf75457192',
		source: 'deb https://apt.postgresql.org/pub/repos/apt ${VERSION_CODENAME}-pgdg main',
		key_path: '/usr/share/keyrings/postgresql-pgdg.asc',
		list_file: '/etc/apt/sources.list.d/pgdg.list'
	});
});

test('key_url and source are constants, paths come from options', () => {
	const fields = postgres_apt_repo({
		key_path: '/usr/share/postgresql-common/pgdg/apt.postgresql.org.asc',
		list_file: '/etc/apt/sources.list.d/app-pgdg.list'
	});

	assert.equal(
		fields.key_url,
		'https://www.postgresql.org/media/keys/ACCC4CF8.asc',
		'key_url is constant'
	);
	assert.equal(
		fields.source,
		'deb https://apt.postgresql.org/pub/repos/apt ${VERSION_CODENAME}-pgdg main',
		'source is constant'
	);
	assert.equal(
		fields.key_path,
		'/usr/share/postgresql-common/pgdg/apt.postgresql.org.asc',
		'key_path from input'
	);
	assert.equal(fields.list_file, '/etc/apt/sources.list.d/app-pgdg.list', 'list_file from input');
});
