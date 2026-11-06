import { assert, test } from 'vitest';

import { env_ref } from '#lib/env_ref.ts';

test('env_ref marks a name between the two delimiters, behind the case canary', () => {
	assert.equal(env_ref('DEPLOY_DOMAIN'), '\uFDD0aZ:DEPLOY_DOMAIN\uFDD1');
	assert.equal(env_ref('_x1'), '\uFDD0aZ:_x1\uFDD1');
});

test('env_ref is a pure function of the name', () => {
	assert.equal(env_ref('A'), env_ref('A'));
	assert.notEqual(env_ref('A'), env_ref('B'));
});

test('a reference rides whole through interpolation and concatenation', () => {
	const domain = env_ref('DEPLOY_DOMAIN');
	assert.equal(
		`/etc/nginx/sites-available/${domain}.conf`,
		'/etc/nginx/sites-available/\uFDD0aZ:DEPLOY_DOMAIN\uFDD1.conf'
	);
	assert.equal('https://' + domain, 'https://\uFDD0aZ:DEPLOY_DOMAIN\uFDD1');
	assert.equal([domain, domain].join(' '), `${domain} ${domain}`);
});

test('a case change breaks the canary rather than renaming the reference', () => {
	const reference = env_ref('Deploy_Domain');
	assert.ok(reference.includes('aZ:'));
	assert.ok(!reference.toLowerCase().includes('aZ:'));
	assert.ok(!reference.toUpperCase().includes('aZ:'));
});

test('env_ref rejects what is not an environment variable name', () => {
	for (const name of ['', '1X', 'A-B', 'a b', 'A.B', '$$X$$', 'X\n', env_ref('X')]) {
		assert.throws(() => env_ref(name), /is not an environment variable's name/, name);
	}
	assert.throws(() => env_ref(5 as unknown as string), /a number is not/);
	// The message names a reference passed as a name without printing a delimiter.
	try {
		env_ref(env_ref('X'));
		assert.fail('a reference is not a name');
	} catch (error) {
		assert.ok(error instanceof Error);
		assert.ok(!/[\uFDD0\uFDD1]/.test(error.message), error.message);
	}
});
