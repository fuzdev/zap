import { assert, test } from 'vitest';

import { validate_run_parts_name } from '#lib/run_parts.ts';

test('validate_run_parts_name accepts letters, digits, `_` and `-` only', () => {
	for (const name of ['reload-nginx', 'certbot_renew', 'A9']) {
		validate_run_parts_name(name, 'r');
	}
	for (const name of ['', 'a/b', '.x', 'x.sh', 'a b', 'x\n']) {
		assert.throws(
			() => validate_run_parts_name(name, 'r'),
			/^r: name .*\(run-parts skips any other name\)$/,
			name
		);
	}
});
