import { spawnSync } from 'node:child_process';
import {
	chmodSync,
	existsSync,
	mkdirSync,
	mkdtempSync,
	readFileSync,
	rmSync,
	writeFileSync
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { assert, describe, test } from 'vitest';

import { alpine_certbot_standalone_issue } from '#lib/recipe_alpine_certbot.ts';
import { certbot_webroot_switch } from '#lib/recipe_certbot.ts';
import { debian_certbot_standalone_issue } from '#lib/recipe_debian_certbot.ts';
import { single_quote } from '#lib/shell.ts';

// The certbot scripts' DNS preflight, run under a real shell: `getent` is a stand-in
// answering from a table in the formats `getent ahosts` prints (address in the first
// column, one line per socktype, the name on the first line only) and `getent hosts`
// prints (address, then the name), exiting 2 for a name that doesn't resolve, and
// `sudo` records what it was asked to run and runs nothing.

/** The shells the scripts run under: `sh`, and BusyBox's when it is here (Alpine's). */
const SHELLS: Array<Array<string>> = [
	['sh'],
	...(spawnSync('busybox', ['sh', '-c', 'true']).status === 0 ? [['busybox', 'sh']] : [])
];

/** A value that runs `touch canary` wherever a shell reads it as code. */
const HOSTILE = 'x\'y $(touch canary) `touch canary`; touch canary "q" $HOME\ntouch canary';

/** What `getent ahosts` prints for a name resolving to `addresses`. */
const ahosts = (name: string, addresses: Array<string>): string =>
	addresses
		.flatMap((address) => [
			`${address.padEnd(15)} STREAM ${name}`,
			`${address.padEnd(15)} DGRAM  `,
			`${address.padEnd(15)} RAW    `
		])
		.map((line) => `${line}\n`)
		.join('');

/** What `getent hosts` prints for a name resolving to `addresses`. */
const hosts = (name: string, addresses: Array<string>): string =>
	addresses.map((address) => `${address.padEnd(15)} ${name}\n`).join('');

/**
 * A name's answers: the addresses both lookups print, or each lookup's own — an
 * `ahosts` given as text is printed as it is, and a `hosts` of `null` doesn't resolve.
 */
type Answer = Array<string> | { ahosts: Array<string> | string; hosts: Array<string> | null };

interface Outcome {
	status: number | null;
	stderr: string;
	/** Each `sudo` call's arguments, space-joined. */
	sudo: Array<string>;
	/** Each `getent` call's arguments, unit-separated. */
	getent: Array<string>;
}

/**
 * Run `text` under `shell` with `getent` answering from `table` (a name to its
 * answers; any other name doesn't resolve).
 */
const run_guarded = (
	shell: Array<string>,
	text: string,
	table: Record<string, Answer>
): Outcome => {
	const dir = mkdtempSync(join(tmpdir(), 'zap-certbot-dns-'));
	try {
		const bin = join(dir, 'bin');
		mkdirSync(bin);
		const cases = (database: 'ahosts' | 'hosts') =>
			Object.entries(table)
				.map(([name, answer]) => {
					const answered = Array.isArray(answer) ? answer : answer[database];
					if (answered === null) return `${single_quote(name)}) exit 2 ;;`;
					const output =
						typeof answered === 'string'
							? answered
							: (database === 'ahosts' ? ahosts : hosts)(name, answered);
					return `${single_quote(name)}) printf %s ${single_quote(output)} ;;`;
				})
				.join('\n');
		writeFileSync(
			join(bin, 'getent'),
			`#!/bin/sh\nus=$(printf '\\037'); r=; for a; do r="$r$us$a"; done\nprintf '%s\\036' "$r" >> ${single_quote(join(dir, 'getent.log'))}\ncase $1 in\nahosts)\ncase $2 in\n${cases('ahosts')}\n*) exit 2 ;;\nesac\n;;\nhosts)\ncase $2 in\n${cases('hosts')}\n*) exit 2 ;;\nesac\n;;\n*) exit 1 ;;\nesac\n`
		);
		writeFileSync(
			join(bin, 'sudo'),
			`#!/bin/sh\nprintf '%s\\n' "$*" >> ${single_quote(join(dir, 'sudo.log'))}\n`
		);
		chmodSync(join(bin, 'getent'), 0o755);
		chmodSync(join(bin, 'sudo'), 0o755);
		const [program = 'sh', ...pre] = shell;
		if (program === 'busybox') {
			// BusyBox's own `awk` and `tr`, as on Alpine
			for (const applet of ['awk', 'tr']) {
				writeFileSync(join(bin, applet), `#!/bin/sh\nexec busybox ${applet} "$@"\n`);
				chmodSync(join(bin, applet), 0o755);
			}
		}
		const result = spawnSync(program, [...pre, '-c', text], {
			cwd: dir,
			encoding: 'utf8',
			env: { PATH: `${bin}:${process.env.PATH}` }
		});
		assert.equal(result.error, undefined);
		assert.ok(!existsSync(join(dir, 'canary')), `a value ran as code:\n${text}`);
		const read = (name: string, separator: string) =>
			existsSync(join(dir, name))
				? readFileSync(join(dir, name), 'utf8')
						.split(separator)
						.filter((line) => line !== '')
				: [];
		return {
			status: result.status,
			stderr: result.stderr,
			sudo: read('sudo.log', '\n'),
			getent: read('getent.log', '\x1e').map((record) => record.slice(1))
		};
	} finally {
		rmSync(dir, { recursive: true, force: true });
	}
};

const deploy_hook = { path: '/etc/letsencrypt/renewal-hooks/deploy/reload-nginx' };
const email = 'ops@example.org';

for (const shell of SHELLS) {
	describe(`the certbot DNS preflight under ${shell.join(' ')}`, () => {
		test('every name resolving only to declared addresses runs the command', () => {
			const expected_addresses = ['203.0.113.7', '2001:DB8::7'];
			const table = {
				'example.org': ['203.0.113.7', '2001:db8::7'],
				'www.example.org': ['203.0.113.7']
			};
			const options = {
				domain: 'example.org',
				extra_domains: ['www.example.org'],
				expected_addresses
			};
			const issue = run_guarded(
				shell,
				debian_certbot_standalone_issue({ ...options, email }).run,
				table
			);
			assert.equal(issue.status, 0, issue.stderr);
			assert.equal(issue.stderr, '');
			assert.deepEqual(issue.sudo, [
				'systemctl stop nginx',
				`certbot certonly --standalone -d example.org -d www.example.org --non-interactive --agree-tos --email ${email}`
			]);
			assert.deepEqual(issue.getent, [
				'ahosts\x1fexample.org',
				'hosts\x1fexample.org',
				'ahosts\x1fwww.example.org',
				'hosts\x1fwww.example.org'
			]);

			const webroot = run_guarded(
				shell,
				certbot_webroot_switch({ ...options, email, deploy_hook }).run,
				table
			);
			assert.equal(webroot.status, 0, webroot.stderr);
			assert.equal(webroot.sudo.length, 2, webroot.sudo.join('\n'));

			const alpine = run_guarded(
				shell,
				alpine_certbot_standalone_issue({ ...options, email }).run,
				table
			);
			assert.equal(alpine.status, 0, alpine.stderr);
			assert.equal(alpine.sudo[0], 'rc-service nginx stop');
			assert.equal(alpine.sudo.length, 2, alpine.sudo.join('\n'));
		});

		test('an AAAA only getent hosts prints refuses, as with IPv6 disabled', () => {
			// `ahosts` drops the AAAA under AI_ADDRCONFIG; `hosts` still prints it
			const table = {
				'example.org': { ahosts: ['203.0.113.7'], hosts: ['2001:db8::7'] }
			};
			const outcome = run_guarded(
				shell,
				debian_certbot_standalone_issue({
					domain: 'example.org',
					email,
					expected_addresses: ['203.0.113.7']
				}).run,
				table
			);
			assert.notEqual(outcome.status, 0);
			assert.deepEqual(outcome.sudo, [], 'nginx was not stopped');
			assert.include(outcome.stderr, 'example.org resolves to 2001:db8::7, outside');

			const declared = run_guarded(
				shell,
				debian_certbot_standalone_issue({
					domain: 'example.org',
					email,
					expected_addresses: ['203.0.113.7', '2001:db8::7']
				}).run,
				table
			);
			assert.equal(declared.status, 0, declared.stderr);
		});

		test('a getent hosts failure is ignored when getent ahosts resolves', () => {
			const outcome = run_guarded(
				shell,
				debian_certbot_standalone_issue({
					domain: 'example.org',
					email,
					expected_addresses: ['203.0.113.7']
				}).run,
				{ 'example.org': { ahosts: ['203.0.113.7'], hosts: null } }
			);
			assert.equal(outcome.status, 0, outcome.stderr);
			assert.equal(outcome.stderr, '');
			assert.equal(outcome.sudo.length, 2, outcome.sudo.join('\n'));
		});

		test('lookups that succeed with no address in their output refuse', () => {
			const outcome = run_guarded(
				shell,
				debian_certbot_standalone_issue({
					domain: 'example.org',
					email,
					expected_addresses: ['203.0.113.7']
				}).run,
				{ 'example.org': { ahosts: ' \n\t\n', hosts: [] } }
			);
			assert.notEqual(outcome.status, 0);
			assert.deepEqual(outcome.sudo, []);
			assert.include(
				outcome.stderr,
				'certbot DNS preflight: could not read the addresses example.org resolves to'
			);
			assert.include(outcome.stderr, 'refused; nothing was run');
		});

		test('an undeclared AAAA refuses, naming the name, the address and the declared set', () => {
			const outcome = run_guarded(
				shell,
				debian_certbot_standalone_issue({
					domain: 'example.org',
					email,
					expected_addresses: ['203.0.113.7']
				}).run,
				{ 'example.org': ['203.0.113.7', '2001:db8::7'] }
			);
			assert.notEqual(outcome.status, 0);
			assert.deepEqual(outcome.sudo, [], 'certbot never ran');
			assert.include(
				outcome.stderr,
				'certbot DNS preflight: example.org resolves to 2001:db8::7, outside the expected addresses (203.0.113.7)'
			);
			assert.include(outcome.stderr, 'refused; nothing was run');
		});

		test('a loopback address from /etc/hosts refuses', () => {
			// `127.0.1.1` is the line a Debian install writes for the host's own name
			for (const loopback of ['127.0.0.1', '127.0.1.1']) {
				const outcome = run_guarded(
					shell,
					alpine_certbot_standalone_issue({
						domain: 'example.org',
						email,
						expected_addresses: ['203.0.113.7']
					}).run,
					{ 'example.org': [loopback] }
				);
				assert.notEqual(outcome.status, 0);
				assert.deepEqual(outcome.sudo, [], 'nginx was not stopped');
				assert.include(outcome.stderr, `example.org resolves to ${loopback}, outside`);
			}
		});

		test('a name that does not resolve refuses, with getent exit status', () => {
			const outcome = run_guarded(
				shell,
				debian_certbot_standalone_issue({
					domain: 'example.org',
					email,
					expected_addresses: ['203.0.113.7']
				}).run,
				{}
			);
			assert.notEqual(outcome.status, 0);
			assert.deepEqual(outcome.sudo, []);
			assert.include(
				outcome.stderr,
				'certbot DNS preflight: example.org does not resolve on the target (getent ahosts exit 2); point its A/AAAA records at the expected addresses (203.0.113.7)'
			);
		});

		test('an extra domain resolving elsewhere refuses, and nginx is left running', () => {
			const table = { 'example.org': ['203.0.113.7'], 'www.example.org': ['198.51.100.9'] };
			const options = {
				domain: 'example.org',
				extra_domains: ['www.example.org'],
				expected_addresses: ['203.0.113.7']
			};
			for (const run of [
				debian_certbot_standalone_issue({ ...options, email }).run,
				alpine_certbot_standalone_issue({ ...options, email }).run,
				certbot_webroot_switch({ ...options, email, deploy_hook }).run
			]) {
				const outcome = run_guarded(shell, run, table);
				assert.notEqual(outcome.status, 0);
				assert.deepEqual(outcome.sudo, []);
				assert.include(outcome.stderr, 'www.example.org resolves to 198.51.100.9, outside');
				assert.notInclude(outcome.stderr, 'example.org resolves to 203.0.113.7');
			}
		});

		test('an expected value that is not an IP literal refuses, asking for expected_addresses', () => {
			for (const value of [
				'deploy.example.org',
				'',
				'1.2.3',
				'1.2.3.4.5',
				'256.1.1.1',
				'01.2.3.4',
				'1..2.3',
				'.1.2.3',
				'1.2.3.4 ',
				'2001:db8::g'
			]) {
				const outcome = run_guarded(
					shell,
					debian_certbot_standalone_issue({
						domain: 'example.org',
						email,
						expected_addresses: [value]
					}).run,
					{ 'example.org': ['203.0.113.7'] }
				);
				assert.notEqual(outcome.status, 0, value);
				assert.deepEqual(outcome.sudo, [], value);
				assert.deepEqual(outcome.getent, [], `${value}: refused before any lookup`);
				assert.include(
					outcome.stderr,
					`the expected address "${value}" is not an IP address literal`,
					value
				);
				assert.include(outcome.stderr, 'declare expected_addresses', value);
			}
		});

		test('hostile names and addresses stay single words', () => {
			const by_name = run_guarded(
				shell,
				debian_certbot_standalone_issue({
					domain: HOSTILE,
					email,
					expected_addresses: ['203.0.113.7']
				}).run,
				{}
			);
			assert.notEqual(by_name.status, 0);
			assert.deepEqual(by_name.sudo, []);
			assert.deepEqual(by_name.getent, [], 'a name that is no DNS name is never looked up');
			assert.include(by_name.stderr, `"${HOSTILE}" is not a DNS name`);

			const by_address = run_guarded(
				shell,
				debian_certbot_standalone_issue({
					domain: 'example.org',
					email,
					expected_addresses: [HOSTILE]
				}).run,
				{ 'example.org': ['203.0.113.7'] }
			);
			assert.notEqual(by_address.status, 0);
			assert.deepEqual(by_address.sudo, []);
			assert.include(by_address.stderr, `the expected address "${HOSTILE}" is not`);

			const leading_dash = run_guarded(
				shell,
				debian_certbot_standalone_issue({
					domain: '-s',
					email,
					expected_addresses: ['203.0.113.7']
				}).run,
				{}
			);
			assert.notEqual(leading_dash.status, 0);
			assert.deepEqual(leading_dash.getent, [], 'never passed to getent as an option');
		});
	});
}
