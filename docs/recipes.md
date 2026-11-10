# Recipes

Reusable config fragments shipped with Zap: the standard pieces of a hardened
Linux server, so a config imports them instead of pasting an nginx block or a
systemd unit that drifts from the next one. Each is a **pure function** or a
constant (no I/O; it runs inside the config sandbox) that gives a string to put
in a `file`, or a payload to spread into a resource.

```ts
import {hardened_systemd_unit} from '@fuzdev/zap/recipe_debian_systemd.ts';
import {debian_web_firewall} from '@fuzdev/zap/recipe_debian_firewall.ts';

zap.file({id: 'unit', path: '/etc/systemd/system/app.service', content: {type: 'inline', content: hardened_systemd_unit({…})}});
zap.firewall({id: 'fw', ...debian_web_firewall()});
```

Import each by its full module path. Resolving the imports:
[install.md](./install.md#types-and-recipes-for-your-config). The generated API
reference on the site documents every option; this page is the map.

## Host families

Recipes that differ by distro come in symmetric `debian_*` / `alpine_*` pairs
over a shared neutral core, so a config imports **one family per machine**: a
Debian config can't pick up an OpenRC service by accident, because the names
differ. The neutral recipes, identical on every distro, keep bare names. A few
carry the family in the artifact's own name (`hardened_systemd_unit`,
`hardened_openrc_service`, `postgres_apt_repo`) rather than a prefix.

## Neutral

| Module | Exports | What it gives you |
|---|---|---|
| `recipe_nginx.ts` | `nginx_site_core` | the portable single-page-app server block: static root, `/api` proxy with a rate limit, security headers, CSP, and a redirect to it for alias names such as `www.`; returned as whole `template` content, the `domain` and `port` you pass held to `hostname` and `port`. An alias name is literal text, where `{{domain}}` may stand for the domain (`www.{{domain}}`), or carries a reference (`zap.env('MIRROR_DOMAIN')`), which becomes a variable of its own, `redirect_domain_<i>` for the entry at index `i`, held to `hostname` |
| `recipe_nginx.ts` | `nginx_catch_all_core`, `nginx_catch_all_server`, `nginx_remove_default_core` | the catch-all core: the stock default site removed, then a `default_server` on every socket the site listens on that closes a request for any other host name (`444`) and refuses its TLS handshake, carrying the site's SSL parameters |
| `recipe_nginx.ts` | `ssl_params`, `rate_limit_zone` | the TLS and rate-limit snippets |
| `recipe_nginx.ts` | `SSL_PARAMS_PATH` | where the TLS snippet goes, the same on both distros; the site wrappers include it from there |
| `recipe_nginx.ts` | `RATE_LIMIT_ZONE` | the rate-limit zone name an `extra_locations` block's own `limit_req` references |
| `recipe_nginx.ts` | `site_security_header_directives` | the security-header lines, the site's CSP included, an `extra_locations` block with its own `add_header` repeats |
| `recipe_nginx.ts` | `SECURITY_HEADER_DIRECTIVES` | those lines without the CSP, for a block that sets a policy of its own |
| `recipe_nginx.ts` | `NGINX_VALIDATE` | `sudo nginx -t`, for a `file`'s `validate` |
| `recipe_nginx.ts` | `nginx_config_verify` | a `verify` payload that re-checks the config every plan |
| `recipe_csp.ts` | `spa_csp` | a `Content-Security-Policy` value for a single-page app, with hooks for a websocket origin and extra `connect-src`, `img-src`, `worker-src` entries; pass it to the site recipe's `csp` |
| `recipe_ssh.ts` | `ssh_hardening` | an `sshd_config.d` drop-in (key-only, no root login, `AllowUsers` the given user, one name with no whitespace, tightened auth tries and grace time); name it to sort first, such as `00-hardened.conf`, since sshd keeps the first value it reads |
| `recipe_ssh.ts` | `SSHD_VALIDATE`, `ssh_hardening_verify` | `sudo sshd -t`, for the drop-in's `validate`, and a `verify` payload that asserts the hardening in the config sshd applies to the given user's login (`Match` blocks included) every plan, `AllowUsers` (the given user and no other, since sshd adds up `AllowUsers` across files) and the tunables included; give it the options `ssh_hardening` got |
| `recipe_ssh.ts` | `ssh_service_core` | the sshd `service` core: enabled, running, reloaded when its `reload_on` ids change |
| `recipe_certbot.ts` | `certbot_standalone_issue_core`, `certbot_webroot_switch` | the first-issue (standalone) core, which stops nginx with the stop command it is given and then requests the certificate, and the renewal (webroot) `script` payload, for the site's domain and any alias names. The webroot switch re-issues the certificate and then runs the deploy hook it is given, since certbot before 5.3 runs deploy hooks only on `renew`. Both run the [DNS preflight](#the-certbot-dns-preflight) first |
| `recipe_certbot.ts` | `certbot_deploy_hook_core`, `CERTBOT_DEPLOY_HOOKS_DIR`, `RELOAD_NGINX_HOOK_NAME` | the deploy-hook `file` core: an executable in `/etc/letsencrypt/renewal-hooks/deploy` that certbot runs after each renewal, whatever scheduled it, and the reload-nginx hooks' default file name |
| `recipe_certbot.ts` | `letsencrypt_live_path` | where certbot keeps a certificate's chain and key, `/etc/letsencrypt/live/<domain>/`; the nginx site and the certbot scripts both read it |
| `run_parts.ts` | `validate_run_parts_name`, `RunPartsFile` | the one check of a hook or job file name: letters, digits, `_` and `-` only, the names `run-parts` runs; and the spreadable `file` fields the hook and job builders return |
| `recipe_fail2ban.ts` | `fail2ban_jail` | `/etc/fail2ban/jail.local` with an sshd jail. It defaults to Debian's journal and a ufw host's `iptables-multiport` ban action; on Alpine set `sshd_logpath: '/var/log/messages'` and `banaction: 'nftables'`. |
| `recipe_sysctl.ts` | `LINK_PROTECTION_SYSCTLS`, `LINK_PROTECTION_SYSCTL_PATH`, `sysctl_conf`, `sysctl_apply` | the kernel's hard-link, symlink, FIFO and regular-file protections (systemd sets them on Debian; Alpine sets only the first two), as a `sysctl.d` file and a `script` that loads it when a live value differs |
| `recipe_firewall.ts` | `WEB_FIREWALL_ALLOW`, `web_firewall_allow_rules` | the SSH + HTTP + HTTPS allow set as port rules, so both backends read the same rules |
| `recipe_env.ts` | `fuz_app_env_base`, `fuz_app_trusted_proxies` | the `.env.production` content and trusted-proxies stanza for a server built on `fuz_app`: the header as whole `template` content (`port` held to `port`, `cookie_keys` to `env_value`), your own lines appended through `extra` with their variables and kinds; its `DATABASE_URL` reaches PostgreSQL over the Unix socket as the service's own account (`peer`) |
| `recipe_bootstrap.ts` | `fuz_app_bootstrap_token` | the one-shot first-admin bootstrap token `script` for a `fuz_app` server |

## Debian and Ubuntu (apt, systemd, ufw)

| Module | Exports | What it gives you |
|---|---|---|
| `recipe_debian_nginx.ts` | `debian_nginx_spa_site`, `debian_nginx_catch_all` | the SPA site's `template` content, for a file in `sites-available/` and link into `sites-enabled/`, and the catch-all: a `script` removing `sites-enabled/default` and a `file` at `conf.d/00-catch-all.conf`, ordered after it. A site meant to answer any host name declares only the `script` |
| `recipe_debian_systemd.ts` | `hardened_systemd_unit` | a unit with `NoNewPrivileges`, `ProtectSystem=strict`, `ProtectHome`, private tmp and devices, restricted address families, an explicit `ReadWritePaths` list, no capabilities, the `@system-service` syscall filter, and `UMask=0077` (each of the last three loosened by its own option); refuses `root` as its user or group and an `ExecStart` prefix that escapes `User=` or the sandbox |
| `recipe_debian_certbot.ts` | `debian_certbot_standalone_issue`, `debian_certbot_reload_nginx_hook` | the first-issue bootstrap `script`, stopping nginx with `systemctl`, and the deploy hook that reloads nginx after a renewal (`certbot.timer` renews, but reloads nothing) |
| `recipe_debian_ssh.ts` | `debian_ssh_service` | the sshd `service` on systemd's `ssh` unit, which Ubuntu's `ssh.socket` also starts; not for a Debian host with a hand-enabled `Accept=yes` socket |
| `recipe_debian_postgres.ts` | `postgres_apt_repo` | the PGDG `apt_repo` payload |
| `recipe_debian_firewall.ts` | `debian_web_firewall` | the ufw `firewall` payload (ufw persists itself) |

## Alpine (apk, OpenRC, nftables)

| Module | Exports | What it gives you |
|---|---|---|
| `recipe_alpine_nginx.ts` | `alpine_nginx_spa_site`, `alpine_nginx_catch_all` | the SPA site's `template` content, for a file at `http.d/<domain>.conf`, and the catch-all: a `script` removing `http.d/default.conf` and a `file` at `http.d/00-catch-all.conf`, ordered after it |
| `recipe_alpine_openrc.ts` | `hardened_openrc_service` | a `supervise-daemon` init script with capability bounding, `umask` `0077` (loosened by its option), `ulimit`, respawn, and an optional `bwrap` isolation tier with an explicit read-write path list; refuses `root` as its user or group |
| `recipe_alpine_certbot.ts` | `alpine_certbot_standalone_issue`, `alpine_certbot_renew_cron`, `alpine_certbot_reload_nginx_hook`, `alpine_periodic_daily_file`, `ALPINE_PERIODIC_DAILY` | the first-issue bootstrap `script`, stopping nginx with `rc-service`, the daily renewal script BusyBox `crond` runs, the deploy hook that reloads nginx after a renewal, and the `/etc/periodic/daily` placement helper |
| `recipe_alpine_ssh.ts` | `alpine_ssh_service` | the sshd `service` on OpenRC's `sshd` |
| `recipe_alpine_postgres.ts` | `alpine_postgres_setup` | the OpenRC cluster-init `script` (`apk` doesn't run `initdb` for you), with `initdb`'s `trust` rules turned to `peer` and `scram-sha-256` |
| `recipe_alpine_firewall.ts` | `alpine_web_firewall` | the nftables `firewall` **and** the `nftables` persistence `service` the structural gate requires |

## Writing your own

A recipe is an ordinary pure function, so a config can define its own. One that
needs a reference of its own (a default domain, say) makes it with
`env_ref('NAME')` from `@fuzdev/zap/env_ref.ts`, which returns what
`zap.env('NAME')` does. A value a caller passes in may be a reference too, so a
recipe splices values into strings and never inspects them beyond whether one
carries a reference: one that validates or slices an option fails on a reference. A value that ends up in a `file`'s
inline content can't be a reference; a recipe that takes a per-environment
value emits a `{{placeholder}}` for it and returns the whole `template`
content, the value in `vars` and its kind in `kinds`.

### Design rules

The shipped recipes follow these, and they keep your own composable too.

- **One value, one home.** Anything two recipes must agree on (a rate-limit zone
  name, a token path, the ACME webroot) is one constant or flows through one
  recipe's option. The nginx rate-limit zone is the precedent: `rate_limit_zone`
  defines it and `nginx_site_core` references it through one exported constant,
  `RATE_LIMIT_ZONE`, so the two can't drift.
- **A neutral recipe never defaults a distro-divergent value.** A default that
  differs by family either forces the `debian_*` / `alpine_*` split or becomes a
  required option. The neutral recipes that still carry a Debian default are
  flagged in the [catalog](#neutral): `fail2ban_jail`'s `sshd_logpath` and
  `banaction`.
- **Big divergence, two functions.** A one-verb or one-path difference shares a
  `*_core` with thin wrappers (the nginx catch-all, the sshd
  service). A whole-artifact difference (a systemd unit versus an OpenRC script)
  is two functions sharing only an options shape.
- **Pure.** No `fetch`, no file reads beyond imports, no clock. A recipe's
  output depends on its arguments alone, so the plan does too.
- **Every value a shell reads is one single-quoted word.** A recipe that splices
  a value into a command or a script quotes it with `single_quote`
  (`@fuzdev/zap/shell.ts`), whether the value is a reference or a literal, so no
  value can change what the command runs. An option that is shell words by
  design (`psql_args`, `command_args`, a stop or reload command) says so in its
  doc. A value a second shell reads again, as OpenRC's start line does, is held
  to a plain-word pattern and refused otherwise. An env file has two readers,
  systemd's `EnvironmentFile=` and, on Alpine, the init script's reader, so
  `fuz_app_env_base` and `fuz_app_trusted_proxies` single-quote their values, and
  refuse one holding a `'` or a line break, which systemd reads differently.
- **A recipe that owns a template owns its kinds.** A placeholder's value is
  substituted as text at apply time, so a `'` in `'{{cookie_keys}}'` would end
  the quoting (systemd would read another value, the OpenRC service would
  refuse to start), and a `;` or a `}` in a value placed in an nginx directive
  would end the directive. The site and env recipes return the whole `template`
  content, each variable with the kind of the place it lands
  ([resources.md](./resources.md#file)), so a caller passes values; used whole,
  the content carries its kinds, and overriding `kinds` or rebuilding the content
  drops them. `fuz_app_env_base`'s `extra` adds the caller's own lines,
  variables, and kinds, and can't name the base's; the site recipes take no
  variables but `domain` and `port`, and add a `redirect_domain_<i>` of their own
  for each `redirect_domains` reference.
- **A `user` that `sudo -u` runs a command as is written out.** `sudo -u` reads
  a name starting with `#` as a uid (`#0` is root), so a recipe that runs a
  command as a declared user refuses an empty one, one starting with `#`, and a
  reference, whose value it can't see (`sudo_as_user` in
  `@fuzdev/zap/shell.ts`).

## The certbot DNS preflight

Let's Encrypt limits failed validations, and a fresh host whose DNS isn't
pointed at it yet fails every one. So each certbot script that leads to a CA
request — the `--standalone` issuance and the webroot switch (a re-issue, and
a new name on the cert is a request for it) — first checks, on the target, that
every name the certificate covers (`domain` and each of `extra_domains`)
resolves only to `expected_addresses`. The `check`s are unchanged.

- Each name is resolved with `getent ahosts` and `getent hosts`, which both
  families have (glibc's on Debian, `musl-utils` on Alpine). A name `ahosts`
  can't resolve refuses, and so do lookups that print no address and any
  address either prints outside the expected set: the CA validates whichever A
  or AAAA it picks, so an undeclared AAAA refuses too.
- Both lookups, because `ahosts` asks with `AI_ADDRCONFIG`: on a host with IPv6
  disabled, glibc and musl both leave the AAAA records out of it, and
  `getent hosts` still prints them. glibc prints every one, musl only the
  first, so on a musl host with IPv6 disabled a name with several AAAA, the
  first of them declared, passes with the others unseen.
- `expected_addresses` defaults to a reference to `DEPLOY_HOST`, the target's
  host. Each value is an IP literal or a reference resolving to one; the target
  checks it when the script runs and refuses anything else, asking for
  `expected_addresses`. A `DEPLOY_HOST` holding a host name rather than an IP
  literal refuses until `expected_addresses` is declared; declare the set too
  when the names carry an AAAA. An IPv6 address is compared as lowercase text:
  write it as `getent` prints it, compressed.
- The issuance stops nginx to free port 80 inside the same `run`, after the
  preflight passes and before certbot runs, so the stop runs only once every
  name the request covers has passed, and a refusal leaves nginx running. If
  certbot then fails, nginx stays stopped; the resources after the certificate,
  nginx's own `service` among them, are skipped until a later apply's request
  succeeds.
- A refusal exits nonzero before nginx is stopped or certbot runs, with each
  reason on stderr:

```
certbot DNS preflight: example.org resolves to 2001:db8::7, outside the expected addresses (203.0.113.7); the CA validates whichever address it picks, so point every A/AAAA record of the name at this host, or add the address to expected_addresses if it belongs to this host
certbot DNS preflight: www.example.org does not resolve on the target (getent ahosts exit 2); point its A/AAAA records at the expected addresses (203.0.113.7) before certbot runs
certbot DNS preflight: refused; nothing was run
```

The preflight reads the target's resolver, not Let's Encrypt's, so it can be
wrong in both directions. An `/etc/hosts` line, a split-horizon answer, or a
cached one can pass while public DNS doesn't point at the host yet, and the
request then fails validation as it would have without the preflight; the same
sources can refuse while public DNS is right. `getent` reads `/etc/hosts`
first, so a name the host maps to a loopback address there refuses, among them
the `127.0.1.1 <name>` line a Debian install writes for the host's own name
when that name is the domain. Remove the line, or give the host a name that
isn't the domain; a tool that manages `/etc/hosts` may write the line back.

A script has no lock entry and is done once its `check` passes, so changing its
`run` re-runs nothing: a host whose certificate is issued and pinned to webroot
never runs the preflight, and one whose check fails, for a name newly added to
the cert, runs it before the re-issue.

## Env files under OpenRC

OpenRC has no `EnvironmentFile=`, and the init script runs as root, so
`hardened_openrc_service` never sources `env_file`. The script carries a reader
that takes each line as data. `start_pre` runs it as the service user
(`su -s /bin/sh`), under a 10-second `timeout`, to check every line and assign nothing.
The check writes to a file in a private directory of root's under `/run`
(`mktemp -d`), never to a pipe, so a process of the service user's that
outlives the `timeout` can't hold the start open, and the service user can't
fill the directory beforehand to stop the start, as it could `/tmp`. Root reads
only the first 4 KiB, which bounds what it reads, not what a lingering writer
can grow the file to;
and the daemon's own process, already dropped to the service user, runs it again
to export the values before it `exec`s the command. Nothing in the file is run
or expanded, root never parses it, and nothing in it reaches root's environment.
The file must be readable by the service user: one it can't read (a root-owned
`600` file), a line outside the format, or a file that isn't read in time (a
FIFO) refuses the start, naming the user or the line. The check needs `su` and
`timeout` on the target, which BusyBox gives Alpine.

The format is a subset of what systemd reads, so a file in it gives the daemon
the same environment under both:

- a blank line, or one whose first non-blank character is `#` or `;`, is skipped;
- every other line is `NAME=VALUE`, the name `[A-Za-z_][A-Za-z0-9_]*` with
  nothing before it, and not beginning `_zap_`;
- a value that starts with `'` ends the line with its closing `'` and holds no
  other; everything between is literal;
- any other value is literal as written, `$`, `#` and inner blanks included,
  and may not start or end with a blank, start with `"`, or hold a `\`;
- `NAME=` sets the empty string, and a later line for a name wins.

Any other line refuses the start, naming its line number, where systemd would
skip it (no `=`, an invalid name), strip blanks around the name or value, read
double quotes, backslash escapes or a continued line, or let a quoted value span
lines. A carriage return anywhere refuses its line.

## Recipes for fuz_app servers

`fuz_app_env_base`, `fuz_app_trusted_proxies`, and `fuz_app_bootstrap_token`
are specific to servers built on [fuz_app](https://github.com/fuzdev/fuz_app):
its environment layout and its first-admin bootstrap. Everything else on this page
is generic: an nginx site serving a static build with an `/api` proxy, a
hardened service, a firewall that allows 22, 80, and 443.
