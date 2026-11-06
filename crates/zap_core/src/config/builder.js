// zap config eval wrapper, Deno form — the port of `builder_fgro.js` (beside this
// file, the driver zap embeds and the source of truth) to a `deno run` subprocess
// that evaluates `zap.ts`. zap doesn't run or embed this file: gro's eval
// benchmark runs it for its Deno row, and zap_core's tests keep the code it shares
// with the driver identical. A change to the driver is made here too. The config's
// default export is invoked as a pure `(zap, ctx) => void`; the builder collects
// declarations into plain JSON which the Rust parent parses into `zap_types::schema`.
//
// Beyond collection it carries these responsibilities:
//   1. Determinism — close the ambient inputs a config could read by mistake (the
//      clock, randomness, facts of this process, state kept between runs), so the
//      same config and the same files declare the same thing each time (the plan is
//      a content-addressed fact).
//   2. Scope — expose exactly the builder surface: one method per resource kind
//      the schema has. A call to any other name is a `TypeError`, never an
//      unknown kind collected.
//   3. References — `zap.env(name)` hands the config a marked string, and every
//      marked string in what the config declared is converted to its typed form
//      before the JSON is written, so no marker leaves this process.
//   4. Nothing lost — what a config declares is written, or the evaluation fails: the
//      default export is awaited, the builder fails a call made after the declaration
//      was read (unless the config suppresses the failure), and a declared value that
//      JSON can't spell is an error naming where it sits, never a field dropped or a
//      `null`.
//
// Must stay in sync with `zap_types::schema` (the JSON it emits is parsed there).

// --- 1. Determinism ---------------------------------------------------------
// The sandbox flags seal out the network, writes, the environment and subprocesses
// (authority). What is left is ambient: values a config can read with no permission
// that differ from one run, or one machine, to the next. Each is closed here by a
// table: the entry point throws, naming itself and what to write instead. The
// originals are replaced where they are defined (a prototype, with its `constructor`
// re-pointed), so one isn't recovered through `Object.getPrototypeOf` or a
// `.constructor`. A replacement is as writable and configurable as what it replaces,
// so code that assigns over an inherited method or a `constructor` still runs.
//
// Nothing here refuses what the runtime itself reads while it serves a config: a
// refusal a warning or an import can trip blames the config for what it never did.
// So the process ids stay readable (Node's warning and debug-log code reads them),
// `Deno.noColor` is pinned to `true` (colour libraries test it as they load), and
// `WeakRef` / `FinalizationRegistry` are inert stand-ins (generated WebAssembly
// bindings build a registry as they load).
//
// Not closed, because nothing is left to close: this machine's time zone and locale.
// `fuz_eval` pins `TZ=UTC` and `LC_ALL=C` for the child, so a local `Date` reads UTC
// and `Intl`, `toLocaleString()` and `navigator.language` answer the same on every
// machine.
//
// Not closed, by design: what a config reads from disk (file contents, directory
// listings, mtimes, its own path) — reads are unrestricted, and a config that reads
// a file declares what the file says. Not closed, and not closable from here: the
// `node:` built-in modules a config can import (`node:crypto`, `node:vm`,
// `node:worker_threads`, `node:v8`), whose exports are bindings this script can't
// replace; the process ids (`Deno.pid`, `process.pid`, their `ppid`s, `process.title`);
// facts of the Deno build (`Deno.build`, `Deno.version`, `navigator.userAgent`);
// timers. This is a guard against a mistake, not a wall against a config written to
// get around it.
const WHY = {
	clock:
		'reads the clock, so the config would declare something else each time it runs; ' +
		'write the date or time it needs as a literal with its offset ' +
		'(`new Date(\'2026-01-01T00:00:00Z\')`)',
	random:
		'is random, so the config would declare something else each time it runs; ' +
		'write the value as a literal, or derive it from text the config holds',
	machine:
		'is a fact of this process or machine, so the config would declare something ' +
		'else in another run; a config declares the same thing wherever it is evaluated',
	state:
		'keeps data on this machine between runs, which a config may neither read nor ' +
		'write; a config declares the same thing every time it is evaluated',
	realm:
		'runs code with globals of its own, which zap doesn\'t guard; ' +
		'compute what the config needs in the config module itself',
};
const refusal = (name, why) => new Error(`zap config eval: ${name} ${WHY[why]}`);
const refuse = (name, why) =>
	function () {
		throw refusal(name, why);
	};
const replaced = (value) => ({value, writable: true, configurable: true, enumerable: false});

// Functions that throw whenever they are called: [owner, property, shown as, why].
// An owner this Deno doesn't have is skipped.
const CLOSED_FUNCTIONS = [
	[() => Math, 'random', 'Math.random()', 'random'],
	[() => Crypto.prototype, 'getRandomValues', 'crypto.getRandomValues()', 'random'],
	[() => Crypto.prototype, 'randomUUID', 'crypto.randomUUID()', 'random'],
	[() => SubtleCrypto.prototype, 'generateKey', 'crypto.subtle.generateKey()', 'random'],
	[() => URL, 'createObjectURL', 'URL.createObjectURL()', 'random'],
	[() => Performance.prototype, 'now', 'performance.now()', 'clock'],
	[() => Performance.prototype, 'mark', 'performance.mark()', 'clock'],
	[() => Performance.prototype, 'measure', 'performance.measure()', 'clock'],
	[() => Performance.prototype, 'toJSON', 'performance.toJSON()', 'clock'],
	[() => Temporal.Now, 'instant', 'Temporal.Now.instant()', 'clock'],
	[() => Temporal.Now, 'plainDateTimeISO', 'Temporal.Now.plainDateTimeISO()', 'clock'],
	[() => Temporal.Now, 'zonedDateTimeISO', 'Temporal.Now.zonedDateTimeISO()', 'clock'],
	[() => Temporal.Now, 'plainDateISO', 'Temporal.Now.plainDateISO()', 'clock'],
	[() => Temporal.Now, 'plainTimeISO', 'Temporal.Now.plainTimeISO()', 'clock'],
	[() => Deno, 'memoryUsage', 'Deno.memoryUsage()', 'machine'],
	[() => Deno, 'openKv', 'Deno.openKv()', 'state'],
	[() => process, 'hrtime', 'process.hrtime()', 'clock'],
	[() => process, 'uptime', 'process.uptime()', 'clock'],
	[() => process, 'memoryUsage', 'process.memoryUsage()', 'machine'],
	[() => process, 'cpuUsage', 'process.cpuUsage()', 'machine'],
	[() => process, 'threadCpuUsage', 'process.threadCpuUsage()', 'machine'],
	[() => process, 'umask', 'process.umask()', 'machine'],
];
// Properties that throw when they are read: [owner, property, shown as, why].
const CLOSED_PROPERTIES = [
	[() => Performance.prototype, 'timeOrigin', 'performance.timeOrigin', 'clock'],
	[() => File.prototype, 'lastModified', 'File.prototype.lastModified', 'clock'],
	[() => Navigator.prototype, 'hardwareConcurrency', 'navigator.hardwareConcurrency', 'machine'],
	[() => globalThis, 'localStorage', '`localStorage`', 'state'],
	[() => globalThis, 'sessionStorage', '`sessionStorage`', 'state'],
	[() => globalThis, 'caches', '`caches`', 'state'],
];
// Constructors that throw: [global, why].
const CLOSED_CONSTRUCTORS = [
	['Worker', 'realm'],
	['PerformanceMark', 'clock'],
];

// The owner a table entry names, or `undefined` when this Deno has none.
const owner_of = (find) => {
	try {
		return find() ?? undefined;
	} catch {
		return undefined;
	}
};
// `Real` behind a function that runs `check` first, standing where `Real` stood: it
// shares `Real`'s prototype, and that prototype's `constructor` names it.
const guarded = (Real, check) => {
	const Guarded = function (...args) {
		check(args, new.target);
		return Reflect.construct(Real, args, new.target ?? Guarded);
	};
	Object.defineProperty(Guarded, 'name', {value: Real.name});
	Guarded.prototype = Real.prototype;
	Object.defineProperty(Real.prototype, 'constructor', replaced(Guarded));
	return Guarded;
};

// `Date`: no reading of the clock (`Date.now()`, `new Date()`, `Date()`).
{
	const RealDate = Date;
	const ZapDate = guarded(RealDate, (args, target) => {
		if (target === undefined) throw refusal('`Date()`', 'clock');
		if (args.length === 0) throw refusal('`new Date()`', 'clock');
	});
	Object.defineProperties(ZapDate, {
		now: replaced(refuse('Date.now()', 'clock')),
		UTC: replaced(RealDate.UTC),
		parse: replaced(RealDate.parse),
	});
	Object.defineProperty(globalThis, 'Date', replaced(ZapDate));
}

for (const [find, name, shown, why] of CLOSED_FUNCTIONS) {
	const owner = owner_of(find);
	if (owner === undefined || !(name in owner)) continue;
	Object.defineProperty(owner, name, replaced(refuse(shown, why)));
}
// `process.hrtime.bigint()` hangs off the function just replaced.
if (typeof process !== 'undefined') {
	process.hrtime.bigint = refuse('process.hrtime.bigint()', 'clock');
}
for (const [find, name, shown, why] of CLOSED_PROPERTIES) {
	const owner = owner_of(find);
	if (owner === undefined || !(name in owner)) continue;
	Object.defineProperty(owner, name, {get: refuse(shown, why), configurable: true});
}
// What a config's output is captured into is never a terminal: colour is off, whatever
// the environment says.
Object.defineProperty(Deno, 'noColor', {value: true, writable: true, configurable: true, enumerable: true});
// The garbage collector, made unobservable rather than refused: a `WeakRef` that
// holds its target, so `deref()` always returns it, and a registry whose callback
// never runs.
{
	const collectable = (target) => {
		const type = typeof target;
		if (target === null || (type !== 'object' && type !== 'function' && type !== 'symbol')) {
			throw new TypeError('Invalid value used as weak reference target');
		}
		return target;
	};
	class WeakRef {
		#target;
		constructor(target) {
			this.#target = collectable(target);
		}
		deref() {
			return this.#target;
		}
	}
	class FinalizationRegistry {
		#tokens = new Set();
		constructor(cleanup) {
			if (typeof cleanup !== 'function') {
				throw new TypeError('FinalizationRegistry: cleanup must be callable');
			}
		}
		register(target, held, token) {
			if (collectable(target) === held) {
				throw new TypeError('FinalizationRegistry.prototype.register: target and holdings must not be same');
			}
			if (token !== undefined) this.#tokens.add(token);
		}
		unregister(token) {
			return this.#tokens.delete(token);
		}
	}
	for (const Inert of [WeakRef, FinalizationRegistry]) {
		Object.defineProperty(Inert.prototype, Symbol.toStringTag, {value: Inert.name, configurable: true});
		Object.defineProperty(globalThis, Inert.name, replaced(Inert));
	}
}
for (const [name, why] of CLOSED_CONSTRUCTORS) {
	const Real = globalThis[name];
	if (typeof Real !== 'function') continue;
	const closed = guarded(Real, () => {
		throw refusal(`\`${name}\``, why);
	});
	Object.defineProperty(globalThis, name, replaced(closed));
}
// A formatter given no date formats the present one.
{
	const prototype = Intl.DateTimeFormat.prototype;
	const format = Object.getOwnPropertyDescriptor(prototype, 'format').get;
	const dated = (shown, real) =>
		function (...args) {
			if (args[0] === undefined) throw refusal(`${shown} with no date`, 'clock');
			return real.apply(this, args);
		};
	Object.defineProperty(prototype, 'format', {
		get() {
			const bound = format.call(this);
			return dated('`Intl.DateTimeFormat` `format()`', function (...args) {
				return bound(...args);
			});
		},
		configurable: true,
	});
	Object.defineProperty(
		prototype,
		'formatToParts',
		replaced(dated('`Intl.DateTimeFormat` `formatToParts()`', prototype.formatToParts)),
	);
}

// --- 1b. Output integrity --------------------------------------------------
// stdout carries exactly one thing: the final config JSON the Rust parent reads.
// What a config prints through the global `console` or `process.stdout` goes to
// stderr instead, so a stray `console.log` or `console.table` can't put text ahead of
// that JSON. `warn` / `error` / `trace` / `assert` already write there; `log` / `info`
// / `debug` are pointed at `error`; the rest of the stdout writers come from a console
// built over stderr; the timers print their label and say there is no clock (a
// refusal here would fail a config for a debugging line); `clear` does nothing; and
// `process.stdout`'s `write`, `end` and `_write` write to stderr.
//
// That is all that is routed. The default export of `node:console` is the global
// console, and a `Console` built over `process.stdout` writes through its `write`, so
// both are covered. A config that writes to stdout another way — a function
// `node:console` exports by name (`import {log} from 'node:console'`),
// `fs.writeSync(1, …)`, `Deno.stdout` itself, which the JSON is written through — puts
// its text beside the JSON, and the evaluation fails with a schema-parse error.
console.log = console.info = console.debug = console.error;
{
	const {Console} = await import('node:console');
	const to_stderr = new Console({stdout: process.stderr, stderr: process.stderr});
	for (const name of [
		'table',
		'dir',
		'dirxml',
		'count',
		'countReset',
		'group',
		'groupCollapsed',
		'groupEnd',
	]) {
		if (typeof console[name] === 'function') console[name] = to_stderr[name].bind(to_stderr);
	}
	console.time = () => {};
	console.timeLog = console.timeEnd = (label = 'default') =>
		console.error(`${label}: no time to show — a config is evaluated without a clock`);
	console.clear = () => {};
	process.stdout.write = (...args) => process.stderr.write(...args);
	// `process.stdout.end(text)` writes through `_write`, so it is routed with it.
	process.stdout._write = (...args) => process.stderr._write(...args);
}

// --- 2. References ---------------------------------------------------------
// A reference is a string a config can place like any other: interpolated,
// concatenated, passed to a recipe. It carries the variable's name between two
// Unicode noncharacters, behind a mixed-case canary — so a reference whose case was
// changed, or that was sliced, split or encoded, no longer reads as one and is an
// error here rather than a reference to another name. `env_ref` in
// `@fuzdev/zap/env_ref.ts` builds the same string for a recipe.
const REF_OPEN = '\uFDD0';
const REF_CLOSE = '\uFDD1';
const REF_CANARY = 'aZ:';
const REF_DELIMITER = /[\uFDD0\uFDD1]/;
const ENV_NAME = /^[A-Za-z_][A-Za-z0-9_]*$/;

// A value as an error names it: a reference as the call that made it, and never a
// raw delimiter.
const shown_value = (value) =>
	typeof value === 'string'
		? '`' +
			value
				.replace(/\uFDD0aZ:([A-Za-z_][A-Za-z0-9_]*)\uFDD1/g, `zap.env('$1')`)
				.replace(/[\uFDD0\uFDD1]/g, '?') +
			'`'
		: value === undefined || value === null
			? 'nothing'
			: `a ${typeof value}`;

// `name` when it is an environment variable's name, else an error naming `method`.
const env_name = (method, name) => {
	if (typeof name === 'string' && ENV_NAME.test(name)) return name;
	const a_reference = typeof name === 'string' && REF_DELIMITER.test(name);
	throw new Error(
		`zap.${method}: ${shown_value(name)} is not an environment variable's name ` +
			`(a letter or \`_\`, then letters, digits, or \`_\`)` +
			(a_reference ? ` — pass the variable's name, not a reference to it` : ''),
	);
};

// A declared string as its wire value: the string itself when it holds no
// reference, `{$env: name}` when it is one reference and nothing else, and
// `{$text: [...]}` — literal strings and `{$env}` pieces in order — otherwise.
const to_wire_text = (text, at) => {
	if (!REF_DELIMITER.test(text)) return text;
	const pieces = [];
	let rest = text;
	while (rest.length > 0) {
		const start = rest.search(REF_DELIMITER);
		if (start === -1) {
			pieces.push(rest);
			break;
		}
		if (start > 0) pieces.push(rest.slice(0, start));
		const end = rest.indexOf(REF_CLOSE, start + 1);
		const body = end === -1 ? '' : rest.slice(start + 1, end);
		const name = body.slice(REF_CANARY.length);
		if (rest[start] !== REF_OPEN || !body.startsWith(REF_CANARY) || !ENV_NAME.test(name)) {
			throw new Error(
				`${at} holds a damaged \`zap.env\` reference: ${shown_value(text)}. A ` +
					`reference is opaque while a config is evaluated — it can be placed ` +
					`whole in a string (interpolated or concatenated), not sliced, split, ` +
					`case-changed, or encoded`,
			);
		}
		pieces.push({$env: name});
		rest = rest.slice(end + 1);
	}
	return pieces.length === 1 ? pieces[0] : {$text: pieces};
};

// `value` with every string in it as its wire value. `at` names where it sits, for
// an error.
const to_wire = (value, at) => {
	if (typeof value === 'string') return to_wire_text(value, at);
	if (Array.isArray(value)) return value.map((item, index) => to_wire(item, `${at}[${index}]`));
	if (value === null || typeof value !== 'object') return value;
	const out = Object.create(null);
	for (const [key, item] of Object.entries(value)) {
		if (REF_DELIMITER.test(key)) {
			throw new Error(
				`${at} has a \`zap.env\` reference in a key (${shown_value(key)}); a ` +
					`reference is a value, never a name`,
			);
		}
		if (key === '$env' || key === '$text') {
			throw new Error(
				`${at} has the key \`${key}\`, which is reserved for a reference's own form`,
			);
		}
		out[key] = to_wire(item, `${at}.${key}`);
	}
	return out;
};

// A declared value as JSON data, copied: `null`, a boolean, a finite number, a string,
// an array of data, or a plain object of data. An object member that is `undefined` is
// left out — how an option is left unset — and anything else is an error naming `at`,
// where it sits: `JSON.stringify` would write `null` for it, or `{}`, or nothing. The
// copy is what is written, each member read once, so a value is what it was when it
// was checked; a copied object has no prototype, so no `toJSON` is found on one.
// `within` holds the objects the walk is inside of: a value that holds itself has no
// JSON form, while one object placed in two fields is two copies.
const KIND_OF = Object.prototype.toString;
const to_data = (value, at, within = new Set()) => {
	switch (typeof value) {
		case 'string':
		case 'boolean':
			return value;
		case 'number':
			if (Number.isFinite(value)) return value;
			throw new Error(`${at} is ${value}, which is not a number a config can declare`);
		case 'undefined':
			throw new Error(
				`${at} is undefined; an array holds a value at every position — leave the item out`,
			);
		case 'function':
			throw new Error(
				`${at} is a function; a config declares values — call the function, or write the value`,
			);
		case 'bigint':
			throw new Error(`${at} is a bigint; write it as a number or a string`);
		case 'symbol':
			throw new Error(`${at} is a symbol; a config declares values JSON can spell`);
	}
	if (value === null) return null;
	if (within.has(value)) {
		throw new Error(
			`${at} holds itself: it is a value that one of its own members leads back to, ` +
				`which a config can't declare`,
		);
	}
	within.add(value);
	if (Array.isArray(value)) {
		const items = Array.from(value, (item, index) => to_data(item, `${at}[${index}]`, within));
		within.delete(value);
		return items;
	}
	const prototype = Object.getPrototypeOf(value);
	if (prototype !== Object.prototype && prototype !== null) {
		const kind = value.constructor?.name || KIND_OF.call(value).slice(8, -1);
		throw new Error(
			`${at} is a \`${kind}\`, not a plain object; write what it holds as a plain ` +
				`object, an array, or a string`,
		);
	}
	const out = Object.create(null);
	for (const [key, item] of Object.entries(value)) {
		if (item !== undefined) out[key] = to_data(item, `${at}.${key}`, within);
	}
	within.delete(value);
	return out;
};

// --- 3. Builder ------------------------------------------------------------
const resources = [];
let target_config;
let deploy_config;
const mask_vars = [];
const unmask_vars = [];
// Which of the once-only blocks a config has declared.
const declared_once = {target: false, deploy: false};
// Set when the declaration is read (section 5). A builder call after that declares
// nothing, so it throws and sets the exit status: the evaluation fails, also when the
// config catches the error, unless the config goes on to reset the status or exit.
let sealed = false;
const open = (method) => {
	if (!sealed) return;
	Deno.exitCode = 1;
	const message =
		`zap.${method} was called after the config's default export had returned, so what ` +
		`it declares would be lost; the config has a promise it didn't wait for — make the ` +
		`default export \`async\` and \`await\` the work that calls zap.${method}`;
	console.error(`zap config eval: ${message}`);
	throw new Error(message);
};
const once = (method) => {
	open(method);
	if (declared_once[method]) {
		throw new Error(
			`zap.${method} was called twice; a config declares one ${method} — the second ` +
				`call would replace the first`,
		);
	}
	declared_once[method] = true;
};
// `name` for the list `method` keeps, refused when the opposite list holds it.
const listed_once = (method, name, other, opposite) => {
	if (opposite.includes(name)) {
		throw new Error(
			`zap.${method}: \`${name}\` was also passed to zap.${other}; a name is masked or ` +
				`it is not — remove one of the two calls`,
		);
	}
	return name;
};

// Resource kinds — builder method name → schema `type` discriminant.
const RESOURCE_TYPES = {
	pkg: 'package',
	apt_repo: 'apt_repo',
	script: 'script',
	installer: 'installer',
	user: 'user',
	directory: 'directory',
	file: 'file',
	link: 'link',
	service: 'service',
	database: 'database',
	swap: 'swap',
	firewall: 'firewall',
	verify: 'verify',
	pipeline: 'pipeline',
	build: 'build',
};

const builder = {
	target(config) {
		once('target');
		target_config = config;
		return builder;
	},
	deploy(config) {
		once('deploy');
		deploy_config = config;
		return builder;
	},
	env(name) {
		open('env');
		return REF_OPEN + REF_CANARY + env_name('env', name) + REF_CLOSE;
	},
	mask(...vars) {
		open('mask');
		for (const name of vars) {
			mask_vars.push(listed_once('mask', env_name('mask', name), 'unmask', unmask_vars));
		}
		return builder;
	},
	unmask(...vars) {
		open('unmask');
		for (const name of vars) {
			unmask_vars.push(listed_once('unmask', env_name('unmask', name), 'mask', mask_vars));
		}
		return builder;
	},
};
for (const [method, type] of Object.entries(RESOURCE_TYPES)) {
	builder[method] = (config) => {
		open(method);
		// `type` last so the builder method's kind is authoritative over any
		// stray `type` field a config object might carry.
		resources.push({...config, type});
		return builder;
	};
}

// --- 4. Evaluate the config ------------------------------------------------
// args[0] is an absolute filesystem path from the Rust parent. `pathToFileURL`
// percent-encodes every character of it that URL syntax would read (`%`, `#`, `?`,
// a space, a backslash, a newline), so the module imported is the file of that name;
// `new URL(path, 'file:///')` would decode a `%41` and cut the path at a `#` or `?`,
// importing another file. The wrapper never calls `Deno.cwd()` — args[0] is already
// absolute, so the config module needs no cwd-relative resolution.
const {pathToFileURL} = await import('node:url');
const module = await import(pathToFileURL(Deno.args[0]).href);
if (typeof module.default !== 'function') {
	throw new Error(
		'zap config must export a default function: `export default (zap) => { ... }`',
	);
}
// ctx is where plan-time inputs to a config would go; there are none, so it is empty.
const ctx = {};
// Awaited: an `async` default export has declared everything only once the promise
// it returns settles, and a rejection is the evaluation's error.
await module.default(builder, ctx);

// --- 5. Emit ---------------------------------------------------------------
// The declaration is read here, once, and the builder sealed: a call that arrives
// later — from a promise the config didn't wait for, a timer — would declare nothing,
// so it throws and sets the exit status. Deno runs what is still pending before it
// exits, so such a call fails the evaluation although the JSON is already written.
//
// The seal is a guard against a mistake, with two limits. A config that suppresses it
// — catches the error and then resets `Deno.exitCode` or `process.exitCode`, or calls
// `Deno.exit(0)` — exits successfully with the late declaration lost. And work that
// never completes never calls the builder, so nothing is seen of it.
//
// The declared config as plain JSON data first (`to_data`), then every reference in
// it converted — so what is written holds typed references and no marked string.
sealed = true;
const named = (resource, index) =>
	typeof resource.id === 'string' && !REF_DELIMITER.test(resource.id)
		? `resource \`${resource.id}\``
		: `resource ${index + 1}`;
const wire_of = (value, at) => to_wire(to_data(value, at), at);
const config = {
	target: target_config === undefined ? undefined : wire_of(target_config, 'target'),
	resources: resources.map((resource, index) => wire_of(resource, named(resource, index))),
	deploy: deploy_config === undefined ? undefined : wire_of(deploy_config, 'deploy'),
	mask_vars: mask_vars.length > 0 ? mask_vars : undefined,
	unmask_vars: unmask_vars.length > 0 ? unmask_vars : undefined,
};
Deno.stdout.writeSync(new TextEncoder().encode(JSON.stringify(config)));
