# @fuzdev/zap

## 0.1.0

### Minor Changes

- feat: publish the authoring surface for `zap.ts` configs - the builder types, the schema, and the recipes ([e408111](https://github.com/fuzdev/zap/commit/e408111))
  
  - `zap.ts` types the builder a config's default export receives (`ZapBuilder`), and `schema.ts` every resource kind, target, and content form the `zap` binary reads, each type from its one module; the types name only the package and service managers with a backend (`apt`, `apk`; `systemd`, `openrc`) and admit none of the pipeline fields the engine always refuses
  - the `recipe_*.ts` modules are pure functions and constants giving config fragments, imported by full path (`@fuzdev/zap/recipe_ssh.ts`): nginx sites for a static single-page app with an `/api` backend (with an `hsts` option, `includeSubDomains` off by default), the catch-all, TLS and rate-limit snippets, `spa_csp`, SSH hardening and its verify, `ssh_port` shared by the verify, `fail2ban_jail`, and the web firewalls, hardened systemd units and OpenRC services, certbot issuance, renewal, and deploy hooks, PostgreSQL, sysctl link protections, and the `fuz_app_*` env and bootstrap recipes for fuz_app servers
  - every recipe takes one options object (a few take none) and returns one field's value or a `Pick` of one resource's payload to spread into a builder call (`ScriptCommands` for a script's `check` and `run`); distro-divergent recipes come in `debian_*` / `alpine_*` pairs over a public `*_core` that takes the distro's values in the same object; `security_header_directives({hsts})` and `site_security_header_directives({csp, hsts})` take the site's `hsts` with no default, so a block that repeats the headers sends the site's policy
  - the small helpers take their values directly: `env_ref(name)` makes a reference and `carries_reference(value)` recognizes one (`env_ref.ts`), `single_quote(value)` and `letsencrypt_live_path(domain, file)` each build one string, and the checks recipes compose (`sudo_as_user`, `to_ssh_port`, `validate_run_parts_name`, `validate_certbot_options`) take the name of the recipe asking first, then what they check
  - every module ships as TypeScript source, which `fgro` evaluates through the `gro` export condition, and as `dist/` JavaScript and declarations for TypeScript and editors, whose declaration maps resolve to the shipped `src/lib` sources
  - the `zap` CLI and `fgro` are built from source, not part of the package
