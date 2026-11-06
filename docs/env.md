# Environment and secrets

How values that vary per machine, or must stay secret, reach a config without
being written into it. The sandbox that makes this necessary is described in
[configs.md](./configs.md#the-sandbox).

## References

A config never reads the environment. It writes a reference instead, with
`zap.env('NAME')`:

```ts
zap.target({host: zap.env('DEPLOY_HOST'), user: zap.env('DEPLOY_USER'), package_manager: 'apt'});
zap.file({
	id: 'env',
	path: '/srv/app/shared/.env',
	content: {type: 'template', template: 'DATABASE_URL={{url}}\n', vars: {url: zap.env('DATABASE_URL')}},
});
```

The reference stays inert in the declaration and in the plan. Zap resolves it
from the operator environment when it acts, in these fields only:

| | Resolves a reference | Takes none: write the value out |
|---|---|---|
| target | `host`, `user`, `bootstrap_user` | `port`, `key_path`, `home` |
| paths | resource paths; a `package`'s `check` and an `installer`'s `check` when they are paths | a `swap`'s `path`; an `apt_repo`'s `key_path` and `list_file`; a `script`'s or `build`'s `cwd`; `deploy.path` |
| content | a `template` file's `vars` values | inline content and a template's body (written as declared) |
| commands | `script`, `installer`, `build`, and `pipeline` commands; an `installer`'s `shell`; a `file`'s `validate`; a `script`'s and a `build`'s `env` values | a `verify` assertion and a `package`'s `check` when it is a command (run as written) |
| names | a `database`'s identifiers and `auth.hosts` | a package name, a service name, `deploy.service`, a `user`'s `shell`, `ssh_keys.keys`, and `sudo` `commands`, a named firewall profile |
| URLs | a `remote` URL and its `auth` token, a `build` source's signature URL, an `installer`'s URL, an `apt_repo`'s `key_url` | an `apt_repo`'s `source` |
| other | a `swap`'s `size`, `deploy.health.domain` | `deploy.health.path`, and every field not listed |

A reference where none is taken fails when Zap reads the config, naming the
resource, the field, and what to use instead:

```
error: config did not match the zap schema (/home/ops/infra/zap.ts): 2 references in fields that take none:
         - resource `motd`: `content.content` takes no reference: the content is written as declared; put the value in a template's `vars`, which resolve
         - resource `work`: `cwd` takes no reference: zap enters a working directory as declared and never resolves it; write the path out
```

A reference in a command is replaced as text: put it inside single quotes, or
hand the command an arbitrary value through `env`, which is quoted after it
resolves. The values Zap refuses in a command, and why:
[security.md](./security.md#secrets). A template's `vars` value can't hold a
line break, which would add a line to the file
([resources.md](./resources.md#content)). An env-file value can't hold a NUL. A
value holding U+FDD0 or
U+FDD1 is refused wherever it would be substituted, an `env` value included: a
value is substituted once and can't carry a reference of its own.

`zap.env('NAME')` returns a string, so a reference composes like one:

```ts
zap.directory({id: 'data', path: `/srv/${zap.env('APP')}/data`});
```

That path has a reference in it, and a recipe can splice a value it was handed
without knowing whether it is one. A recipe
makes its own with `env_ref('NAME')`, imported from `@fuzdev/zap/env_ref.ts`.
The name must be an environment variable name (letters, digits, and `_`, not
starting with a digit).

While the config is evaluated that string is opaque. It holds a marker, not
the value, so interpolating and concatenating it are the only things to do with
it:

- slicing it, splitting it, or changing its case damages the marker, and the
  config fails to evaluate, naming the field;
- a regular-expression replace that strips non-word characters, or
  `encodeURIComponent`, silently turns it into ordinary text;
- code that inspects a value (its length, its first character) sees the marker.

A reference is the string `zap.env` or `env_ref` returns. Text that merely
looks like one is text: `$$`, `$$NAME$$`, `${NAME}`, and `{env:NAME}` in a command
or a file are what they say. The two characters the marker is built from (U+FDD0 and U+FDD1) can't
appear in a config's own strings; content that holds them comes from a `source`
or `remote` file.

Previews and messages show a reference as `{env:NAME}`:

```
  [+] conf  (file)
      path: {env:APP_DIR}/app.conf
      content: template (47 bytes, sha512 527b3af39db7aeb8…), vars {"domain":{"$env":"DEPLOY_DOMAIN"},"key":{"$env":"API_KEY"},"port":8080}
```

What each reference a plan uses resolves to is printed once, in a `references:`
block under the target, and is part of the plan and its hash: a plain
reference's value, or for a [secret](#secrets) only that it is one. So a value
you wouldn't want in a preview or a CI log belongs under a name Zap reads as a
secret, or in `zap.mask`.

```
  references:
    API_KEY is a secret: its value is not shown, and no part of it is in the plan or its hash
    APP_DIR = /srv/app
    DEPLOY_DOMAIN = app.example.com
```

Text in a command can spell `{env:NAME}` too. Where it matters which it is, the
`target:` line and a template's `vars` print the exact form, `{"$env":"NAME"}`,
and `plan_hash` covers it.

A command, a path, or an SSH destination that still holds an unresolved
reference is never run, touched, or connected to: Zap refuses first.

### Target-categorized resolution

Two kinds of placeholder resolve against two different machines:

| Placeholder | Resolves against | In the plan |
|---|---|---|
| `zap.env('NAME')` | the **operator's** environment | as a reference; the value arrives when Zap acts |
| `~`, `$HOME` | the **target's** home: `target.home` remotely, your own locally | as written |

So a resource's part of the plan doesn't depend on the environment or the
target's home, and a remote path that needs a home with none declared is
undetermined rather than guessed. The home itself is part of the plan beside
it: a remote one as the declared target's `home`, your own as the local plan's
`home:` line. A resource's resolved values reach the hashes
of the last-run report and, for a tracked source, the lock.

The target's `host`, `user`, and `bootstrap_user` resolve from references too;
they are connection context ([targets.md](./targets.md#the-target)).

## The env file

Every config command accepts `--env-file <path>`, a file of `NAME=VALUE` lines
loaded into the operator environment before anything resolves. A name set in
both the file and your shell takes the file's value:

```sh
zap apply --env-file zap.env
zap deploy --env-file zap.env --wetrun
```

One explicit file, no auto-discovery, no `.env` plus `.env.<mode>` merging.
Keep env files out of version control and commit a `.example` with the names.
Name it for what it is, say `zap.env` or `zap.production.env`; don't reuse the
name of an env file your app reads on the host, which `deploy.shared` may be
linking into releases.

The format is a strict subset of dotenv: Zap reads only lines the common
loaders agree on, and a line it doesn't understand is an error instead of a
guess. (A loader that interpolates still reads a `$` its own way.)

| Line | Reads as |
|---|---|
| blank, or beginning `#` | nothing |
| `NAME=value` | the value to the end of the line, surrounding whitespace trimmed |
| `NAME='value'` | the value as written |
| `NAME="value"` | the value, with `\\`, `\"`, `\n`, and `\r` decoded |
| `export NAME=value` | the same as without `export` |

A name is letters, digits, and `_`, not starting with a digit. There is no
interpolation (`$OTHER` is text) and no value spanning lines. These don't load:
a line with no `=`, a name that isn't one (`export` counts only before a
space), a name assigned twice, a quote left open or followed by anything but a
comment, an unquoted value that begins with `#` or holds one after whitespace
(quote the value, or move the comment to its own line), an unquoted value
ending in a backslash or holding a control character other than a tab, or a
Unicode line or paragraph separator (U+2028, U+2029), and a NUL in an assignment. Whitespace around the `=` is
trimmed, and a byte-order mark at the start is skipped. The error names the
file, the line, and the name when the line has one, and never any part of a
value or of the line.

Zap warns, once per command, about an env file its group or everyone can write
(whoever can rewrite it chooses the host a deploy goes to), and about one they
can read when it holds a secret by its name or the form of its value (the file
is read before the config, so a variable only `mask()` lists doesn't count),
saying which. `chmod 600` answers both.

## Unset references

A reference with no value, or an empty one, is handled by what the command does:

- **A wetrun (`apply` or `deploy`) refuses to start.** Every referenced variable
  must be set and non-empty, or the run fails before any side effect. An empty
  `DATABASE_URL` would otherwise be written into a `.env` file as nothing.
- **A comparing dry run (`plan`, `apply`, `detect`) is unverifiable.** Detection
  resolves references into the desired side of its comparison, so an unset one
  makes the answer unsound in both directions: it can hide drift (the target
  already holds the empty value) and invent it (the target holds the real one).
  The command leads with the banner and exits 1:

  ```
  UNVERIFIABLE — 2 referenced variable(s) are unset or empty, so this comparison cannot be trusted:
      DATABASE_URL, SMTP_PASSWORD
  an unset reference resolves to an empty string, which can both hide real drift and invent drift that isn't there.
  provide them (--env-file or the environment) and re-run.
  ```

  The check covers what the comparison resolves: the resources, and the
  target's `host`, `user`, and `bootstrap_user`. The user the run connects as
  is held to more: if it resolves to nothing the command stops before it
  connects (below), since `ssh` would pick an account of its own. It ignores the
  `deploy` block and a fetch credential (the `auth` token of a `remote` file or
  a `build` source). A `database`'s `auth.hosts` is part of the comparison and
  is covered.
- **A deploy dry run warns.** It compares nothing (the preflight is
  wetrun-only), so its rendered plan is sound.
- **A remote `host`, or a declared connecting user, that resolves to nothing is
  an error before any connection.** Zap won't SSH to nowhere, or as whichever
  account `ssh` picks: `plan`, `detect`, `apply`, and `deploy` exit 2, naming
  the variable that is unset or empty.

### Unverifiable

The banner above is the `unverifiable` verdict: the desired side of a
comparison couldn't be built. It is the twin of `undetermined`, where the
observed side couldn't be read. Both outrank "converged" and "drifted" in the
exit code, because neither claim was established.

## Secrets

One rule decides whether a reference is a secret, and everything that treats
secrets differently asks it. In order:

1. **Where it is used.** A reference in a `remote` file's or a `build` source's
   `auth` is a secret, whatever it is called.
2. **What you said.** `zap.unmask('NAME')` makes a reference plain, and
   `zap.mask('NAME')` makes it a secret. Unmasking a reference used as an `auth`
   credential is an error.
3. **Its name**, by the rule in [Secret names](#secret-names) below.
4. **The form of its value.** A value is a secret, whatever its name, when it
   holds a URL with a password (`postgres://app:…@db/app`, so a `DATABASE_URL`
   needs no `mask`), an `http` or `https` URL with a user, `git+https` included
   (`https://<token>@git.example.com/…`: HTTP reads a user only as a credential,
   where `ssh://git@…` and `postgres://app@…` name an account), a PEM private
   key, or an HTTP authorization value (`Basic` with its encoded
   `user:password`, or `Bearer` with a token of 16 characters or more, alone or
   as an `Authorization:` or `Proxy-Authorization:` header line). A password
   holding an unencoded `?` or `#` still counts when no `@` comes before that
   character (`postgres://app:p#ss@db/app`, as libpq reads it: up to the first
   `@` after it), unless what precedes it is all digits, which reads as a port. A password
   in a query string or in `key=value` form, and a secret in a URL's path (a
   webhook's), aren't recognized: name the variable for what it is or
   `zap.mask` it.

What is masked is a value Zap resolves: a name no field references registers
nothing, so `zap.mask` doesn't scrub a value a command reads from the target's
own environment.

### Secret names

Case-insensitive. A name is a secret's when it:

| | Words |
|---|---|
| holds anywhere | `SECRET`, `PASSWORD`, `TOKEN`, `KEY`, `CREDENTIAL` |
| has a last word ending in | `PASS`, `PASSWD`, `PASSPHRASE`, `PASSCODE`, `PWD`, `BINDPW`, `ROOTPW` (ordinary words like `BYPASS` and `COMPASS`, and the shell's own `PWD` and `OLDPWD`, aside) |
| has a last word that is | `PW`, `PAT`, `DSN`, `AUTH`, `PRIVATE`, `SALT`, `COOKIE`, `SESSION`, `JWT`, `CRED`, `PSK`, `WEBHOOK`; or `URL` or `URI` after `WEBHOOK` or `WEBHOOKS` |

The last word is the part after the final `_`, passing over a trailing number
written apart or glued on (`SMTP_PASS_2`, `DB_PASS2`; `AUTH0` is a name, not
`AUTH`), a version (`DB_PASS_V2`), and a qualifier naming an environment or a
rotation (`PROD`, `PRODUCTION`, `STAGING`, `STAGE`, `DEV`, `DEVELOPMENT`,
`TEST`, `TESTING`, `QA`, `UAT`, `OLD`, `PREV`, `PREVIOUS`, `NEW`, `NEXT`,
`CURRENT`, `PRIMARY`, `SECONDARY`), so `DB_PASS_PROD` is a secret. A plural reads
as its word (`DB_CREDS`, `HASH_SALTS`), except for `AUTH`, `PRIVATE`, `SESSION`,
`COOKIE`, `WEBHOOK`, and a word ending in `PASS`, whose plurals count or switch
something (`MAX_SESSIONS`, `MAX_PASSES`).

So `DB_PASS`, `GITHUB_PAT`, `SENTRY_DSN`, and `SLACK_WEBHOOK_URL` are secrets,
and `AUTH_HOST`, `PRIVATE_IP`, and `SESSION_TIMEOUT` aren't. A secret-named
variable is plain while its value is a switch (`true`, `false`, `yes`, `no`,
`on`, `off`, or a single digit, in any case, whitespace around it ignored), so
`ENABLE_AUTH=true` masks nothing.

### Masked hosts and review

A `target.host`, a connecting user, or a `deploy.health.domain` behind a secret
reference makes a plan no review can bind, since its hash would name no one
machine or be computed from the secret. `zap apply --wetrun` and
`zap deploy --wetrun` refuse it before anything runs, a dry run shows the plan
under an `UNBINDABLE` note with no `plan_hash` and records no preview, and a
masked host keeps no last-run report. The message names the cause:

| The reference is a secret because of | Way out |
|---|---|
| its name or the form of its value | `zap.unmask('NAME')` if it isn't one, or write the value literally |
| the config's `zap.mask('NAME')` | drop the `mask` |
| its use as a fetch credential too | reference another variable in the host, user, or domain, or write the value literally |
| a registered secret carried in its value | take the value from a literal, or from a variable that carries none |

### What masking covers

A secret's resolved value is **masked** out of everything Zap prints or writes:
the text report, `--json` events, warnings, held reasons, drift observations,
deploy step output, and errors. Masking is by value. Besides the value itself
Zap looks for it trimmed, URL-encoded, JSON-escaped, and single-quoted for a
shell as Zap's own commands carry it (each `'` written `'\''`); for each line of 24
characters or more of a value that spans several (a PEM key, with its `\n`
decoded when it was written on one line; the `-----BEGIN…-----` lines aside);
and for the password or token inside a URL or an authorization value, when that
is 8 characters or more. A password that also appears elsewhere in its own
value (`postgres://app:postgres@db/app`) is an ordinary word and is masked only
as part of the whole. A secret a tool prints in any other form (the address `ssh` resolved a secret
host name to, a URL it rewrote around a short password) is not found.
The executor itself never sees a masked string; masking
happens where output is consumed. A plan's steps hold only the inert
reference; its `references:` block holds the value of a plain one, with any
secret inside that value masked, and for a secret only the fact. Commands reach their shell on stdin, so a
resolved value is on no `ssh` or shell argv
([security.md](./security.md#secrets)). There is no `--show-secrets`.

The same rule decides how `zap.lock` addresses a tracked source: a secret
reference is hashed as a fixed token, any other by its value
([lock.md](./lock.md)).

The **last-run report** on disk is masked the same way. Each resource's hash
takes a secret reference as a fixed `[MASKED:NAME]` token and masks every
registered secret out of any other value, so the report can't be used to test a
guess at a secret, and a changed secret value isn't visible to `zap status`
(which says so beside each resource that references one). `status` rebuilds
its masker from its own environment, so for an exact "unchanged since" it needs
the same env the run had, secrets included; without one it fails closed to
"changed since".

A **literal secret** in a config is rejected by every command: when a value that
is both referenced and resolvable in the current environment also
appears written out in the config, the secret gate fails, naming the field and
the variable and showing none of the text. It looks for a secret's whole value,
8 characters or more: a shorter one turns up in ordinary text by chance. It is
best-effort by design, so it never fails spuriously on a machine that simply
lacks the secret.
