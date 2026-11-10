import { assert, test } from 'vitest';

import { spa_csp } from '#lib/recipe_csp.ts';

test('reproduces the baseline CSP byte-for-byte', () => {
	const csp = spa_csp();

	const expected =
		`default-src 'self'; ` +
		`script-src 'self' 'unsafe-inline'; ` +
		`style-src 'self' 'unsafe-inline'; ` +
		`img-src 'self' data:; ` +
		`font-src 'self'; ` +
		`connect-src 'self' wss://{{domain}}; ` +
		`object-src 'none'; ` +
		`base-uri 'self'; ` +
		`form-action 'self'; ` +
		`frame-ancestors 'self'`;

	assert.equal(csp, expected);
});

test('no worker-src directive unless worker_src_extra is set', () => {
	assert.ok(!spa_csp().includes('worker-src'), 'absent by default');
});

test('websocket overrides the connect-src endpoint', () => {
	const csp = spa_csp({ websocket: 'wss://app.example.com' });
	assert.ok(
		csp.includes("connect-src 'self' wss://app.example.com;"),
		'connect-src carries the override'
	);
	assert.ok(!csp.includes('{{domain}}'), 'the placeholder is replaced');
});

test("connect_src_extra appends after 'self' and the websocket", () => {
	const csp = spa_csp({ connect_src_extra: ['https://api.example.com'] });
	assert.ok(
		csp.includes("connect-src 'self' wss://{{domain}} https://api.example.com;"),
		'extra sources follow the websocket'
	);
});

test("img_src_extra widens img-src after the 'self' data: baseline", () => {
	const csp = spa_csp({ img_src_extra: ['blob:'] });
	assert.ok(csp.includes("img-src 'self' data: blob:;"), 'blob: appended');
});

test('worker_src_extra emits a worker-src directive after connect-src', () => {
	const csp = spa_csp({ worker_src_extra: ['blob:'] });
	assert.ok(
		csp.includes("connect-src 'self' wss://{{domain}}; worker-src 'self' blob:;"),
		"worker-src is placed right after connect-src with 'self' implied"
	);
});

test('wasm_unsafe_eval adds the source to script-src only', () => {
	const csp = spa_csp({ wasm_unsafe_eval: true });
	assert.include(csp, "script-src 'self' 'unsafe-inline' 'wasm-unsafe-eval'; ");
	assert.equal(csp.split('wasm-unsafe-eval').length - 1, 1);
	assert.notInclude(spa_csp(), 'wasm-unsafe-eval');
	assert.equal(spa_csp({ wasm_unsafe_eval: false }), spa_csp());
});
