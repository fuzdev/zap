import { spawnSync } from 'node:child_process';
import { assert, test } from 'vitest';

import { env_ref } from '#lib/env_ref.ts';
import { single_quote, sudo_as_user } from '#lib/shell.ts';

test('single_quote wraps a value in single quotes, writing each quote as an escape', () => {
	assert.equal(single_quote('/srv/app'), "'/srv/app'");
	assert.equal(single_quote(''), "''");
	assert.equal(single_quote("it's"), "'it'\\''s'");
	assert.equal(single_quote("''"), "''\\'''\\'''");
});

test('a reference rides inside the quotes, whole', () => {
	const domain = env_ref('DEPLOY_DOMAIN');
	assert.equal(single_quote(`/live/${domain}`), `'/live/${domain}'`);
});

test('a shell reads the quoted word back as the value, whatever it holds', () => {
	for (const value of [
		'plain',
		'two words',
		"it's",
		"'",
		'$(echo no) `echo no` $HOME ${HOME} ; | & > < * ? ~ # \\ "',
		'line one\nline two\n',
		'\t leading and trailing blanks \t',
		'-n'
	]) {
		const shell = spawnSync('sh', ['-c', `printf %s ${single_quote(value)}`], {
			encoding: 'utf8'
		});
		assert.equal(shell.status, 0, shell.stderr);
		assert.equal(shell.stdout, value, JSON.stringify(value));
	}
});

test('sudo_as_user quotes a user name and refuses one sudo would not read as it', () => {
	assert.equal(sudo_as_user('r', "it's"), "sudo -u 'it'\\''s' ");
	assert.equal(sudo_as_user('r', 'app#1'), "sudo -u 'app#1' ");
	for (const user of ['', '#0', '#-1']) {
		assert.throws(() => sudo_as_user('r', user), /^r: user .* must be a user name/);
	}
	for (const user of [env_ref('U'), `a${env_ref('U')}b`]) {
		assert.throws(() => sudo_as_user('r', user), /^r: user must be written out, not a reference/);
	}
});
