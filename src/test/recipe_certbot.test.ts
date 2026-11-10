import { assert, test } from 'vitest';

import { env_ref } from '#lib/env_ref.ts';
import {
	alpine_certbot_reload_nginx_hook,
	alpine_certbot_standalone_issue
} from '#lib/recipe_alpine_certbot.ts';
import {
	CERTBOT_DEPLOY_HOOKS_DIR,
	RELOAD_NGINX_HOOK_NAME,
	certbot_deploy_hook_core,
	type CertbotStandaloneIssueOptions,
	certbot_standalone_issue_core,
	certbot_webroot_switch
} from '#lib/recipe_certbot.ts';
import {
	debian_certbot_reload_nginx_hook,
	debian_certbot_standalone_issue
} from '#lib/recipe_debian_certbot.ts';

const domain = env_ref('DEPLOY_DOMAIN');
const email = env_ref('DEPLOY_CERTBOT_EMAIL');
const deploy_hook = certbot_deploy_hook_core({
	command: 'systemctl try-reload-or-restart nginx',
	name: 'reload-nginx'
});
const reload = ` && sudo -- '/etc/letsencrypt/renewal-hooks/deploy/reload-nginx'`;
const host = env_ref('DEPLOY_HOST');
const expected_addresses = [host];

/** A guarded `run`'s last line: the preflight's call, then the command it guards. */
const call_line = (run: string): string => {
	assert.ok(run.startsWith('zap_certbot_dns_preflight() {\n'), run);
	return run.slice(run.lastIndexOf('\n}\n') + 3);
};

/** The preflight's call for `names` against `addresses`, as each guarded `run` leads with. */
const preflight = (names: Array<string>, addresses: Array<string> = [host]): string =>
	`zap_certbot_dns_preflight ${addresses.length} ${[...addresses, ...names]
		.map((value) => `'${value}'`)
		.join(' ')} && `;

/** A stop command of the test's own, so the core's output shows where it lands. */
const STOP = 'sudo service-stop nginx';

/** The issuance core with `STOP`. */
const issue = (options: CertbotStandaloneIssueOptions) =>
	certbot_standalone_issue_core({ ...options, stop_command: STOP });

/** What the issuance runs after the preflight: the best-effort stop, then certbot. */
const stopped = `{ ${STOP} || true; } && sudo certbot certonly --standalone`;

test('certbot_standalone_issue_core stops nginx, then issues, after the preflight', () => {
	const script = issue({ domain, email, expected_addresses });

	assert.equal(script.check, `sudo test -f '/etc/letsencrypt/live/${domain}/fullchain.pem'`);
	assert.equal(
		call_line(script.run),
		`${preflight([domain])}${stopped} -d '${domain}' --non-interactive --agree-tos --email '${email}'`
	);
});

test('certbot_webroot_switch reproduces the reference certbot-renewal-webroot script byte-for-byte', () => {
	const script = certbot_webroot_switch({ domain, email, deploy_hook, expected_addresses });

	assert.equal(
		script.check,
		`sudo grep -q 'authenticator = webroot' '/etc/letsencrypt/renewal/${domain}.conf'`
	);
	assert.equal(
		call_line(script.run),
		`${preflight([domain])}sudo certbot certonly --webroot -w '/var/www/certbot' -d '${domain}' --cert-name '${domain}' --non-interactive --agree-tos --email '${email}' --force-renewal${reload}`
	);
});

test('the certbot scripts refuse a missing domain, email, or expected_addresses', () => {
	const options = { domain, email, expected_addresses };
	for (const missing of ['domain', 'email', 'expected_addresses'] as const) {
		const partial: Record<string, unknown> = { ...options, deploy_hook };
		delete partial[missing];
		const pattern = new RegExp(`: ${missing} is required`);
		// as a config evaluated as JavaScript, with no type check, would pass them
		const loose = partial as unknown as Parameters<typeof certbot_webroot_switch>[0];
		assert.throws(() => issue(loose), pattern, missing);
		assert.throws(() => certbot_webroot_switch(loose), pattern, missing);
		// a wrapper's refusal names the wrapper, the function the config called
		assert.throws(
			() => debian_certbot_standalone_issue(loose),
			new RegExp(`^debian_certbot_standalone_issue: ${missing} is required`),
			missing
		);
		assert.throws(
			() => alpine_certbot_standalone_issue(loose),
			new RegExp(`^alpine_certbot_standalone_issue: ${missing} is required`),
			missing
		);
	}
	assert.throws(() => issue({ ...options, domain: '' }), /: domain is required/);
	assert.throws(() => issue({ ...options, email: '' }), /: email is required/);
	const none = undefined as unknown as CertbotStandaloneIssueOptions;
	assert.throws(() => issue(none), /: domain is required/);
	assert.throws(() => debian_certbot_standalone_issue(none), /: domain is required/);
});

test('the webroot switch defaults the standard webroot', () => {
	assert.include(
		certbot_webroot_switch({ domain, email, deploy_hook, expected_addresses }).run,
		` --webroot -w '/var/www/certbot' `
	);
});

test('certbot_webroot_switch runs the deploy hook only after certonly succeeds, quoted', () => {
	const script = certbot_webroot_switch({
		domain,
		email,
		expected_addresses,
		deploy_hook: { path: "/etc/hook's" }
	});
	assert.ok(script.run.endsWith(`--force-renewal && sudo -- '/etc/hook'\\''s'`), script.run);
});

test('extra_domains add a -d each after the primary domain', () => {
	const extra_domains = [`www.${domain}`];

	assert.equal(
		call_line(issue({ domain, email, extra_domains, expected_addresses }).run),
		`${preflight([domain, `www.${domain}`])}${stopped} -d '${domain}' -d 'www.${domain}' --non-interactive --agree-tos --email '${email}'`
	);
	assert.equal(
		call_line(
			certbot_webroot_switch({ domain, email, extra_domains, deploy_hook, expected_addresses }).run
		),
		`${preflight([domain, `www.${domain}`])}sudo certbot certonly --webroot -w '/var/www/certbot' -d '${domain}' -d 'www.${domain}' --cert-name '${domain}' --non-interactive --agree-tos --email '${email}' --force-renewal${reload}`
	);
});

test('extra_domains leave the standalone check on cert existence alone', () => {
	assert.equal(
		issue({ domain, email, extra_domains: ['www.example.org'], expected_addresses }).check,
		`sudo test -f '/etc/letsencrypt/live/${domain}/fullchain.pem'`
	);
});

test('extra_domains extend the webroot check with an exact SAN match per name', () => {
	const script = certbot_webroot_switch({
		domain,
		email,
		extra_domains: ['www.example.org', 'old.example.org'],
		deploy_hook,
		expected_addresses
	});

	const san = (name: string) =>
		` && sudo openssl x509 -noout -ext subjectAltName -in '/etc/letsencrypt/live/${domain}/fullchain.pem' | tr ',' '\\n' | sed 's/^ *//' | grep -qxF 'DNS:${name}'`;
	assert.equal(
		script.check,
		`sudo grep -q 'authenticator = webroot' '/etc/letsencrypt/renewal/${domain}.conf'` +
			san('www.example.org') +
			san('old.example.org')
	);
});

test('every guarded run carries the same preflight, with the declared addresses', () => {
	const expected_addresses = ['203.0.113.7', '2001:db8::7'];
	const runs = [
		issue({ domain, email, expected_addresses }).run,
		certbot_webroot_switch({ domain, email, deploy_hook, expected_addresses }).run,
		debian_certbot_standalone_issue({ domain, email, expected_addresses }).run,
		alpine_certbot_standalone_issue({
			domain,
			email,
			extra_domains: ['www.example.org'],
			expected_addresses
		}).run
	];
	const definition = (run: string) => run.slice(0, run.lastIndexOf('\n}\n') + 3);
	for (const run of runs) assert.equal(definition(run), definition(runs[0]!));
	assert.ok(call_line(runs[0]!).startsWith(`${preflight([domain], expected_addresses)}${stopped}`));
	assert.ok(
		call_line(runs[1]!).startsWith(
			`${preflight([domain], expected_addresses)}sudo certbot certonly --webroot`
		)
	);
	assert.ok(
		call_line(runs[3]!).startsWith(
			`${preflight([domain, 'www.example.org'], expected_addresses)}{ sudo rc-service nginx stop || true; } && sudo certbot certonly --standalone -d '${domain}' -d 'www.example.org' `
		)
	);
});

test('an empty expected_addresses throws, since it would refuse every name', () => {
	assert.throws(
		() => issue({ domain, email, expected_addresses: [] }),
		/certbot_standalone_issue_core: expected_addresses is empty/
	);
	assert.throws(
		() => certbot_webroot_switch({ domain, email, deploy_hook, expected_addresses: [] }),
		/certbot_webroot_switch: expected_addresses is empty/
	);
	assert.throws(
		() => alpine_certbot_standalone_issue({ domain, email, expected_addresses: [] }),
		/^alpine_certbot_standalone_issue: expected_addresses is empty/
	);
	assert.throws(
		() => debian_certbot_standalone_issue({ domain, email, expected_addresses: [] }),
		/^debian_certbot_standalone_issue: expected_addresses is empty/
	);
});

test('certbot_deploy_hook_core writes an executable hook that execs the command', () => {
	assert.deepEqual(
		certbot_deploy_hook_core({ command: 'service-reload app', name: 'reload-app' }),
		{
			path: `${CERTBOT_DEPLOY_HOOKS_DIR}/reload-app`,
			mode: '755',
			content: {
				type: 'inline',
				content: `#!/bin/sh
# Managed by zap — certbot runs this after it renews a certificate.
exec service-reload app
`
			}
		}
	);
	assert.equal(CERTBOT_DEPLOY_HOOKS_DIR, '/etc/letsencrypt/renewal-hooks/deploy');
});

test('certbot_deploy_hook_core refuses a name a hook runner would skip or that leaves the directory', () => {
	for (const name of ['', 'a/b', '../x', '.hidden', 'reload.sh', 'a b', 'x~']) {
		assert.throws(
			() => certbot_deploy_hook_core({ command: 'true', name }),
			/certbot_deploy_hook_core: name .* letters, digits/,
			name
		);
	}
});

test('the reload-nginx hooks share one default name', () => {
	assert.equal(RELOAD_NGINX_HOOK_NAME, 'reload-nginx');
	assert.equal(
		debian_certbot_reload_nginx_hook().path,
		`${CERTBOT_DEPLOY_HOOKS_DIR}/${RELOAD_NGINX_HOOK_NAME}`
	);
	assert.equal(
		alpine_certbot_reload_nginx_hook().path,
		`${CERTBOT_DEPLOY_HOOKS_DIR}/${RELOAD_NGINX_HOOK_NAME}`
	);
});

test('the issuance core refuses a missing or empty stop_command', () => {
	const options = { domain, email, expected_addresses };
	for (const stop_command of [undefined, '', '  ']) {
		assert.throws(
			() =>
				certbot_standalone_issue_core({ ...options, stop_command } as unknown as Parameters<
					typeof certbot_standalone_issue_core
				>[0]),
			/^certbot_standalone_issue_core: stop_command is required/,
			String(stop_command)
		);
	}
});
