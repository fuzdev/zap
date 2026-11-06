import { spawnSync } from 'node:child_process';
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { assert, test } from 'vitest';

import { alpine_postgres_setup } from '#lib/recipe_alpine_postgres.ts';

test('alpine_postgres_setup is done once the cluster exists and trusts no one', () => {
	const script = alpine_postgres_setup({ version: 18 });

	assert.equal(
		script.check,
		"sudo test -e '/var/lib/postgresql/18/data/PG_VERSION' && hba=$(sudo readlink -f -- '/var/lib/postgresql/18/data/pg_hba.conf') && [ -n \"$hba\" ] && ! sudo grep -Eq '^[[:space:]]*[^#[:space:]].*[[:space:]]trust([[:space:]]|$)' \"$hba\""
	);
	assert.ok(
		script.run.startsWith(
			"set -e\nsudo test -e '/var/lib/postgresql/18/data/PG_VERSION' || sudo rc-service postgresql setup\n"
		),
		script.run
	);
});

test('the version threads into the data-cluster path', () => {
	const { check } = alpine_postgres_setup({ version: '16' });
	assert.ok(check.startsWith("sudo test -e '/var/lib/postgresql/16/data/PG_VERSION' && "), check);
	assert.ok(check.includes("readlink -f -- '/var/lib/postgresql/16/data/pg_hba.conf'"), check);
	assert.throws(() => alpine_postgres_setup({ version: "18'; x" }), /major version number/);
});

// The `pg_hba.conf` `initdb` writes on Alpine, where the `setup` action passes no
// `--auth` option.
const INITDB_HBA = `# TYPE  DATABASE        USER            ADDRESS                 METHOD

# "local" is for Unix domain socket connections only
local   all             all                                     trust
# IPv4 local connections:
host    all             all             127.0.0.1/32            trust
# IPv6 local connections:
host    all             all             ::1/128                 trust
# Allow replication connections from localhost, by a user with the
# replication privilege.
local   replication     all                                     trust
host    replication     all             127.0.0.1/32            trust
host    replication     all             ::1/128                 trust
`;

/**
 * A scratch machine for the script: `sudo` runs its command as the caller, and
 * `rc-service` records its arguments, its `setup` making the cluster `initdb` would
 * (the marker and `INITDB_HBA`, in the data directory).
 */
const create_machine = () => {
	const dir = mkdtempSync(join(tmpdir(), 'zap-alpine-pg-'));
	const data = join(dir, 'data');
	mkdirSync(data);
	const bin = join(dir, 'bin');
	mkdirSync(bin);
	writeFileSync(join(bin, 'sudo'), '#!/bin/sh\n[ "$1" = -u ] && shift 2\nexec "$@"\n');
	writeFileSync(
		join(bin, 'rc-service'),
		`#!/bin/sh\necho "$*" >> ${JSON.stringify(join(dir, 'rc.log'))}\n` +
			`[ "$*" = 'postgresql setup' ] || exit 0\n` +
			`echo 18 > ${JSON.stringify(join(data, 'PG_VERSION'))}\n` +
			`cat ${JSON.stringify(join(dir, 'initdb_hba'))} > ${JSON.stringify(join(data, 'pg_hba.conf'))}\n`
	);
	chmodSync(join(bin, 'sudo'), 0o755);
	chmodSync(join(bin, 'rc-service'), 0o755);
	writeFileSync(join(dir, 'initdb_hba'), INITDB_HBA);
	const script = alpine_postgres_setup({ version: 18 });
	const localize = (text: string) => text.replaceAll('/var/lib/postgresql/18/data', data);
	const sh = (text: string): boolean =>
		spawnSync('sh', ['-c', localize(text)], {
			env: { ...process.env, PATH: `${bin}:${process.env.PATH}` },
			stdio: 'pipe'
		}).status === 0;
	return {
		dir,
		hba: join(data, 'pg_hba.conf'),
		marker: join(data, 'PG_VERSION'),
		check: () => sh(script.check),
		run: () => sh(script.run),
		rc_calls: (): Array<string> => {
			try {
				return readFileSync(join(dir, 'rc.log'), 'utf8').trim().split('\n');
			} catch {
				return [];
			}
		}
	};
};

const CLOSED_HBA = INITDB_HBA.replace(/^(local\s.*\s)trust$/gm, '$1peer').replace(
	/^(host\s.*\s)trust$/gm,
	'$1scram-sha-256'
);

test('a fresh host: setup, then every trust rule closed, peer on the socket and a password over TCP', () => {
	const machine = create_machine();
	try {
		assert.ok(!machine.check(), 'no cluster yet');
		assert.ok(machine.run(), 'run');
		assert.equal(readFileSync(machine.hba, 'utf8'), CLOSED_HBA);
		assert.deepEqual(machine.rc_calls(), ['postgresql setup', '--ifstarted postgresql reload']);
		assert.ok(machine.check(), 'converged');
	} finally {
		rmSync(machine.dir, { recursive: true, force: true });
	}
});

test('a cluster left with trust rules by a failed run is rewritten on the next, without a second setup', () => {
	const machine = create_machine();
	try {
		// what a run that failed after `setup` leaves: the cluster, with initdb's rules
		writeFileSync(machine.marker, '18\n');
		writeFileSync(machine.hba, INITDB_HBA);
		assert.ok(!machine.check(), 'a trust rule reads as not done');
		assert.ok(machine.run(), 'run');
		assert.deepEqual(machine.rc_calls(), ['--ifstarted postgresql reload'], 'no setup');
		assert.equal(readFileSync(machine.hba, 'utf8'), CLOSED_HBA);
		assert.ok(machine.check(), 'converged');
		// a rule the rewrite doesn't reach fails the run and keeps the check failing
		writeFileSync(machine.hba, 'host all all 127.0.0.1/32 trust clientcert=verify-ca\n');
		assert.ok(!machine.check());
		assert.ok(!machine.run(), 'a trust rule left fails the run');
		assert.ok(!machine.check());
	} finally {
		rmSync(machine.dir, { recursive: true, force: true });
	}
});
