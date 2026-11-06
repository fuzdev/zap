# Writing configs

How a `zap.ts` is shaped, what it may and may not do, and the patterns that keep
one readable. The per-resource fields are in [resources.md](./resources.md).

## The shape

A config is a module whose default export is a function. It receives a builder,
declares one target plus any number of resources, and returns nothing:

```ts
import type {ZapBuilder} from '@fuzdev/zap/zap.ts';

export default (zap: ZapBuilder) => {
	zap.target({host: zap.env('HOST'), user: 'ops', home: '/home/ops', package_manager: 'apt', service_manager: 'systemd'});

	zap.pkg({id: 'nginx', from: {apt: 'nginx'}});
	zap.file({
		id: 'site',
		path: '/etc/nginx/sites-available/example',
		content: {type: 'inline', content: site_config},
		validate: 'sudo nginx -t',
		triggers: ['nginx-service'],
		depends_on: ['nginx'],
	});
	zap.service({id: 'nginx-service', service: 'nginx', enabled: true, running: true, depends_on: ['nginx']});
};
```

The builder has one method per resource kind (`pkg`, `apt_repo`, `script`,
`installer`, `user`, `directory`, `file`, `link`, `service`, `database`, `swap`,
`firewall`, `verify`, `pipeline`, `build`), plus `target`, `deploy`, `mask`,
`unmask`, and `env` (which returns a reference). Every other call returns the
builder, so chaining works, and every resource
takes these shared fields:

| Field | Required | Meaning |
|---|---|---|
| `id` | yes | a stable name, unique in the config: a letter, a digit, or `_`, then any of those and `. + : @ -`. Output, events, triggers, and `depends_on` all refer to it. Renaming an id makes Zap see a new resource. |
| `name` | no | a label for whoever reads the config. A plan prints it under the change's header; everything else (apply's progress, events, triggers) names a resource by its `id`. It is carried in a change, so changing it changes the `plan_hash` of a plan that changes the resource, but never the lock entry's `config_hash`. |
| `depends_on` | no | ids that must apply before this one |

The import is type-only. The evaluator strips it, so a config with no recipe
imports needs nothing installed. Without it, write `(zap) =>` and lose completion.

The function may be `async`: Zap waits for it, so a declaration after an
`await` counts. Once it returns, the builder closes, and a call that arrives
later (from a promise the config didn't await) fails the evaluation, even when
the config catches the error, so a forgotten `await` can't drop a resource
silently.

## Plain TypeScript is the templating language

There is no DSL for loops, conditionals, or includes; the language has them.

```ts
const PACKAGES = ['build-essential', 'pkg-config', 'libssl-dev'];
for (const pkg of PACKAGES) {
	zap.pkg({id: pkg, from: {apt: pkg}});
}

const USER = 'app';
const HOME = `/home/${USER}`;
zap.user({id: 'app-user', username: USER, ssh_keys: {copy_from: 'root'}, sudo: false});
zap.directory({id: 'app-dir', path: `${HOME}/app`, owner: USER, group: USER, depends_on: ['app-user']});
```

Keep every value two resources must agree on (a user name, a config directory,
a port) in one constant. Nothing fails when two copies drift apart.

Split a large config into local modules and import them by relative path from
the project. The shipped [recipes](./recipes.md) are the
same idea packaged: pure functions that return a string or a spreadable payload.

```ts
import {SSHD_VALIDATE, ssh_hardening, ssh_hardening_verify} from '@fuzdev/zap/recipe_ssh.ts';
import {debian_ssh_service} from '@fuzdev/zap/recipe_debian_ssh.ts';

const HARDENING = {user: USER};
zap.file({
	id: 'sshd-hardening',
	path: '/etc/ssh/sshd_config.d/00-hardened.conf',
	content: {type: 'inline', content: ssh_hardening(HARDENING)},
	mode: '644',
	validate: SSHD_VALIDATE,
});
zap.service({id: 'sshd', ...debian_ssh_service({reload_on: ['sshd-hardening']}), depends_on: ['sshd-hardening']});
zap.verify({id: 'sshd-hardened', ...ssh_hardening_verify(HARDENING), depends_on: ['sshd']});
```

## One target per config

A config declares one target. For several hosts, write one config per host (or
one module per role, imported by each host's config) and run `zap` once per host.
A `zap.env('HOST')` reference plus one env file per host is the usual shape.
A second `zap.target` call, or a second `zap.deploy`, fails the evaluation.

## References

A config never reads the environment. Anything that varies per machine or is
secret is a reference, `zap.env('NAME')`, left inert in the declaration and
resolved by Zap when it acts, from your environment or an `--env-file`:

```ts
zap.target({host: zap.env('DEPLOY_HOST'), user: zap.env('DEPLOY_USER')});
zap.file({id: 'env', path: '/srv/app/shared/.env', content: {type: 'template', template: 'DATABASE_URL={{url}}\n', vars: {url: zap.env('DATABASE_URL')}}});
```

Not every field takes a reference, a wetrun refuses one that is unset or empty,
and one Zap reads as a secret is masked out of every output; the rules are in
[env.md](./env.md).

`~` and `$HOME` in a path are different: they resolve against the **target's**
home (declared `home` for a remote target, your own locally), never the
operator's. A remote path that uses them with no `home` declared is
undetermined.

## `mask` and `unmask`

Zap treats a reference as a secret by where it is used (an `auth` credential),
by its name (`API_TOKEN`, `DB_PASS`), or by the form of its value (a URL with a
password, a private key); the rule is in [env.md](./env.md#secrets). Say so
where it reads one wrongly:

```ts
zap.mask('LICENSE_CODE'); // a secret the rule doesn't recognize
zap.unmask('SSH_KEY_COMMENT'); // not a secret despite the name
```

Both take variable names, not references: `zap.mask(zap.env('X'))` fails the
evaluation, and so does a name given to both.

## Order

Resources apply in dependency order: `depends_on` edges first, and among
resources with no edge between them, **alphabetically by id**, not in
declaration order. Declaration order is not a dependency. When one resource must
precede another, say so with `depends_on`; the structural gate rejects a
dangling id or a cycle. A trigger is an edge too: a service runs after each
resource it `restart_on` / `reload_on` and each file that `triggers` it, and a
cycle through those edges is rejected the same way.

Detection for the whole run happens before any change executes. So a probe
can't see a tool the same run installs; the detectors on the bring-up path read
that failure as "not set up yet" rather than holding
([detection.md](./detection.md#kinds-that-read-a-failed-probe-as-absent)), and the run both installs and
configures. [concepts.md](./concepts.md#detection) has the rule.

An edge is also how a hold travels: a resource detection can't read is held,
and every change that depends on it is held behind it rather than run ahead of
it ([detection.md](./detection.md#a-hold-spreads-to-what-cant-run-without-it)).

## Triggers

A `file` lists the services it `triggers`; a `service` lists the ids it
`restart_on` or `reload_on`. Either direction works; pick one per pair. When the
source changes in a plan, the service is promoted to a restart or a reload. A
reload the run couldn't complete is remembered on the host and re-fired next
plan ([concepts.md](./concepts.md#triggers)).

```ts
zap.file({id: 'unit', path: '/etc/systemd/system/app.service', content: {…}, triggers: ['app']});
zap.service({id: 'app', service: 'app', enabled: true, restart_on: ['env-file']});
```

## The sandbox

Your config runs in `fgro eval`, Gro's runtime, with no network, no writes, and
no environment: it can compute and import, and that is all. These rules shape
how you write one:

- **It lives in a project**: the nearest directory at or above it whose
  `package.json` holds more than `"type"` and `"sideEffects"`. The project can't
  be your home directory or a directory holding it.
- **Its imports are static**, from that project and the packages it links, and
  must all resolve: `import()` is refused, and so are `node:` built-ins.
- **Resolution is strict ESM**: a relative import names its extension, and a
  bare import goes through the package's `exports` (never its `main`) under the
  conditions `gro`, `import`, and `default`. No `deno.json` or import map is
  read.

Zap refuses a config that breaks one, exit 2, saying what to change. The walls
in full: [security.md](./security.md#the-config-can-only-describe).

The config's only output is a JSON declaration, which every command validates
against a strict schema: an unknown field, a wrong enum value, a value of the
wrong JSON type (an array where an object goes, a number where a name goes), or
a contradictory combination (a local target with a `host`, `sudo: true` on a
user) fails with a message that names it.

What a config declares is plain data: strings, finite numbers, booleans, arrays,
and plain objects. A `NaN`, a function, a `Map`, a `Date`, a class instance
inside a declaration, an `undefined` array item, or a value that holds itself
fails the evaluation with the field's name, where
`JSON.stringify` would have dropped it or written something else. A field is
left out by leaving it out, or by giving it `undefined` (so `mode: opts.mode`
forwards an option that may not be set). A `null` is an error that names the
field, since a `null` where a `mode`, a `sudo`, or a `blake3` pin goes would
otherwise read as "not managed". The one place a `null` is data is inside a
template variable's value.

Zap also closes what a config could read by mistake and get a different answer
from on another run or another machine: the clock, randomness, facts of the
machine, and timers. Each throws, naming itself and what to write instead, or
isn't there. The time zone and locale are fixed rather than closed: every
evaluation runs in UTC, and its default locale is `en-US`. A config reads no file
but the modules it imports, so the same files declare the same thing on every
machine.

Consequences worth knowing:

- The clock and randomness throw: `Date.now()`, `new Date()`,
  `performance.now()`, `Temporal.Now.instant()`, `Math.random()`. There is no
  `crypto`, no `setTimeout`, and no `Blob` or `File`. Write the value as a
  literal, or reference it.
- Local time is UTC: `new Date(2026, 0, 1)` and `getHours()` read the same
  as `Date.UTC(2026, 0, 1)` and `getUTCHours()` on every machine.
- Comparing and formatting with no locale given use `en-US`:
  `(1234.5).toLocaleString()` is `1,234.5`.
- There is no `process`, no `Deno`, and no environment API. Use
  `zap.env('NAME')`. A guarded read such as `globalThis.process?.env?.HOME`
  is `undefined`, not an error, so a config that falls back on it always
  takes the fallback.
- What a config prints is not part of the declaration: `console` writes to
  stderr, which Zap shows when the evaluation fails. `console.time`,
  `console.timeLog` and `console.timeEnd` print nothing.
- The evaluation is jitless, so `WebAssembly` is absent; separately, code
  generation from strings is off, so `eval()` and `new Function()` throw.
- `WeakRef` and `FinalizationRegistry` are inert: a weak reference never
  clears, and a cleanup callback never runs.
- `fetch` and remote `import` fail. Vendor what you need or import it from the
  project.
- A `script`'s `run` is shell that executes **on the target at apply time**. The
  sandbox bounds the config, not the commands it declares. Review them.

## What the gates reject

Every command that reads a config runs two machine-free gates before touching anything, and
`zap config validate` runs only them:

- **Secrets.** A literal that matches a resolvable secret is rejected; reference
  it with `zap.env('NAME')`.
- **Structure.** Each of these is rejected:
  - a NUL byte in a string a shell or path would see;
  - a duplicate id, or an id that isn't a name;
  - a blank string where a name, a path, a URL, or a command goes, and a line
    break or other control character in a field that is one line (a command, a
    `validate` included, a file's content and template variables, an `env`
    value, and a `verify` assertion's `expect` may span lines);
  - a path that must be absolute and isn't, and a path, link target, host, or
    user that begins with `-`;
  - a remote target with no `host`;
  - two resources that manage one thing: the same path, account, service, or
    database, or a second `firewall`
    ([resources.md](./resources.md#one-resource-per-thing));
  - a template whose placeholders and variables don't match
    ([resources.md](./resources.md#file));
  - a URL Zap or the target would fetch that isn't `https://`
    ([resources.md](./resources.md#urls));
  - a `database` name, role, or `auth.hosts` entry that `pg_hba.conf` would read
    as something else;
  - a `depends_on`, `triggers`, `restart_on`, or `reload_on` naming an id that
    doesn't exist, a `triggers` naming a resource that isn't a service, or a
    dependency cycle, trigger edges included;
  - a `user` whose `ssh_keys.keys` holds no key;
  - `pipeline` features the executor doesn't run (`env`, a `max_concurrency`
    above 1, a step's `cwd`, `env`, or `depends_on`);
  - a named firewall profile under nftables, or an nftables firewall with no
    enabled `nftables` service in the same config;
  - a `service`, a `file` with `triggers`, or `deploy.service` on
    a target with no `service_manager`;
  - a `validate` command that is blank or on `remote` content;
  - a `script` `cwd` or a `deploy.path` that isn't an absolute path;
  - a `deploy.shared` entry that isn't a plain relative name, or a
    `deploy.artifacts` entry beginning with `-` or `@` ([deploy.md](./deploy.md#configuration));
  - an `env` name beginning with `__zap_`;
  - a `deploy.releases` below 2;
  - a blank `deploy.health.domain`.

Two kinds of mistake fail earlier, when Zap reads the config, so the gates never
see them: a value of the wrong form (a package or service name that isn't one
word, a mode above `7777`, a port or a count of 0), and a reference in a field
that takes none ([env.md](./env.md#references)). An object key `$env` or `$text`
anywhere in a declaration is reserved and fails the evaluation.

Run `zap config validate` in CI and before committing; it needs no target, no
network, and no secrets.

## Checklist for a new config

1. `zap config validate` passes.
2. `zap plan --env-file …` reads every resource (no `UNDETERMINED`, no
   `UNVERIFIABLE`).
3. Every `script` has a `check` precise enough that a converged host plans no
   change. A check that always fails makes the script run on every apply and
   reads `RESIDUAL` after it.
4. Services that depend on files declare the trigger, and the files that must
   be valid before a reload declare `validate`.
5. A second `zap apply` after the wetrun prints `(no changes — converged)`.
6. `zap.ts` and `zap.lock` are committed and the env files aren't
   ([getting-started.md](./getting-started.md#what-to-commit)).
