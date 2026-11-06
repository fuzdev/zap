/**
 * Recipe for a hardened systemd service unit.
 *
 * The Alpine/OpenRC sibling is `recipe_alpine_openrc.ts`'s
 * `hardened_openrc_service` — a different artifact with a different security
 * model (the two share only the broad options shape, not content).
 *
 * `hardened_systemd_unit` builds the unit-file text for a long-running network
 * service (a compiled Rust daemon, a Deno process, or any comparable service that
 * talks to a local PostgreSQL). It captures a security-hardening directive set
 * that server configs otherwise copy by hand —
 * `NoNewPrivileges`, `ProtectSystem=strict`, `ProtectHome=read-only`, the
 * kernel/namespace/realtime restrictions, an empty capability bounding set, the
 * `@system-service` syscall filter, `UMask=0077`, and
 * `SystemCallArchitectures=native` — as one reusable string builder so every
 * service converges on the same baseline.
 *
 * ## Loosening the baseline
 *
 * Three defaults are tight enough that a service may need one opened, each
 * through its own option, so the loosening is written where it is reviewed:
 *
 * - `capabilities` — the bounding set is empty unless the service names the
 *   capabilities it holds, which it is then also granted as ambient (a
 *   `CAP_NET_BIND_SERVICE` listener on a port below 1024).
 * - `system_call_filter` — `@system-service` with `EPERM` for anything outside
 *   it, so a refused call fails where the program can report it instead of
 *   killing the process. `false` drops the filter.
 * - `umask` — `0077`, so what the service creates is its own. A service whose
 *   files another account reads (an nginx `X-Accel-Redirect` or `alias` over a
 *   store the service writes) passes the mode that account needs, e.g. `'0022'`.
 *
 * The unit refuses `root` as its `user` or `group`, and either given as a number: the
 * hardening block assumes an unprivileged account, and root would make most of it moot.
 *
 * Recipes are imported at config eval time inside zap's sandboxed config eval
 * (`fgro eval`), which has no network, no writes, and no environment, and where
 * the clock and randomness throw. This module is therefore a **pure function**: it only assembles a
 * string from its arguments — no I/O, no clock, no randomness, no imports
 * beyond types. The output is deterministic for given inputs (stable ordering,
 * trailing newline), so it stays a reliable content-addressed plan artifact.
 *
 * The caller wraps the result in a file resource, e.g.
 * `zap.file({id: 'myapp-unit', path: '/etc/systemd/system/myapp.service', content: {type: 'inline', content: hardened_systemd_unit({...})}})`.
 *
 * ## Environment injection: `env_file` vs `--env`
 *
 * Two ways to get env into the service, mutually exclusive in practice:
 *
 * - Set `env_file` to emit an `EnvironmentFile=` directive — systemd loads the
 *   file and the process reads its env (the compiled-binary path, where the
 *   daemon reads process env, not a file).
 * - Omit `env_file` and bake `--env=<path>` (or equivalent) into `exec_start`
 *   — the runtime loads the file itself (the Deno path), so no
 *   `EnvironmentFile=` line is emitted at all.
 *
 * @module
 */

/**
 * What `user` and `group` must be: an account name, never a uid or gid, so `root` is
 * refused by name and `0` can't stand in for it.
 */
const ACCOUNT_NAME = /^[a-z_][a-z0-9_-]*\$?$/i;

/**
 * Options for `hardened_systemd_unit`.
 *
 * Required fields are the real per-service variations across deploys
 * (`description`, `exec_start`, `user`, `working_directory`,
 * `read_write_paths`); everything else defaults to the shared baseline.
 */
export interface HardenedSystemdUnitOptions {
	/** `Description=` — human-readable unit description (e.g. the domain). */
	description: string;
	/**
	 * `ExecStart=` — the full command line, already absolute and quoted as needed.
	 * It begins with the absolute path of the program, optionally after systemd's `@`
	 * (the next word is `argv[0]`) or `:` (no `$VAR` expansion) prefix. Every other
	 * prefix is refused: `+`, `!` and `!!` run the command outside `User=` or the
	 * sandbox, and `-` reads a failing exit as success, so `Restart=on-failure` never
	 * restarts it.
	 */
	exec_start: string;
	/**
	 * `User=` — the service account, by name. Also the default for `group`. Not `root`:
	 * the unit is for an unprivileged account.
	 */
	user: string;
	/** `Group=` — the service group, by name, not `root`. Defaults to `user`. */
	group?: string;
	/** `WorkingDirectory=` — the process working directory (typically the `current` release symlink). */
	working_directory: string;
	/**
	 * `ReadWritePaths=` — the read-write holes punched through `ProtectSystem=strict`
	 * + `ProtectHome=read-only`. Space-joined into a single directive; every path
	 * must already exist or systemd namespace setup fails with status 226.
	 */
	read_write_paths: Array<string>;
	/**
	 * `EnvironmentFile=` — emitted only when set. Leave unset when `exec_start`
	 * injects env itself (e.g. Deno's `--env=`); see the module doc.
	 */
	env_file?: string;
	/** `After=` units. Defaults to `['network.target']`; add `'postgresql.service'` for an app on a local database. */
	after?: Array<string>;
	/** `Wants=` units, the line emitted only when non-empty. Defaults to none. */
	wants?: Array<string>;
	/** `Restart=` policy. Defaults to `'on-failure'`. */
	restart?: string;
	/** `RestartSec=` seconds. Defaults to `5`. */
	restart_sec?: number;
	/**
	 * `RestrictAddressFamilies=` — space-joined. Defaults to
	 * `['AF_UNIX', 'AF_INET', 'AF_INET6']`, which covers a TCP listener, the
	 * Postgres socket, and loopback callbacks.
	 */
	restrict_address_families?: Array<string>;
	/** `WantedBy=` install target. Defaults to `'multi-user.target'`. */
	wanted_by?: string;
	/**
	 * The capabilities the service holds, as systemd names them (`CAP_NET_BIND_SERVICE`),
	 * written both as the `CapabilityBoundingSet=` and as `AmbientCapabilities=`.
	 * Defaults to none: an empty `CapabilityBoundingSet=` and no
	 * `AmbientCapabilities=` line.
	 */
	capabilities?: Array<string>;
	/**
	 * `SystemCallFilter=` — the syscall sets or names the service may call (an
	 * allow-list), written with `SystemCallErrorNumber=EPERM`. Defaults to
	 * `['@system-service']`; widen it for a workload that needs a set outside it, such
	 * as `@privileged`, `@mount`, `@debug` or `@pkey`
	 * (`systemd-analyze syscall-filter @system-service` lists what it holds), e.g.
	 * `['@system-service', '@pkey']`, or pass `false` to write no filter.
	 */
	system_call_filter?: Array<string> | false;
	/**
	 * `UMask=` — four octal digits. Defaults to `'0077'`; pass `'0022'` (or `'0027'` for
	 * a group) when another account reads what the service writes.
	 */
	umask?: string;
	/**
	 * Host-specific sandboxing-rationale comment, inserted verbatim after
	 * `PrivateTmp=true` and before `PrivateDevices=true`. Pass the full comment
	 * lines (each already prefixed with `# `, newline-separated, no trailing
	 * newline); omitted means no comment. A line that doesn't begin with `#` would be
	 * a directive, and one ending in `\` would continue onto the next directive, so
	 * both are refused. This is where a deploy documents _why_
	 * its address-family / syscall-filter choices are safe for its workload —
	 * genuinely per-host prose (a git-backend service explains its subprocesses; a
	 * pure-API service notes it has none), so it can't be a shared constant.
	 */
	hardening_comment?: string;
}

/**
 * Build the hardened systemd unit-file text for `options`.
 *
 * Produces a canonical `[Unit]` / `[Service]` / `[Install]` unit with the
 * standard security-hardening block (introduced by a `# Security hardening`
 * comment), from a service's inputs, including its per-host
 * `hardening_comment`.
 *
 * @returns the complete unit-file text, terminated by a trailing newline.
 */
export function hardened_systemd_unit(options: HardenedSystemdUnitOptions): string {
	const {
		description,
		exec_start,
		user,
		group = user,
		working_directory,
		read_write_paths,
		env_file,
		after = ['network.target'],
		wants = [],
		restart = 'on-failure',
		restart_sec = 5,
		restrict_address_families = ['AF_UNIX', 'AF_INET', 'AF_INET6'],
		wanted_by = 'multi-user.target',
		capabilities = [],
		system_call_filter = ['@system-service'],
		umask = '0077',
		hardening_comment
	} = options;

	for (const [field, name] of [
		['user', user],
		['group', group]
	] as const) {
		if (!ACCOUNT_NAME.test(name)) {
			throw new Error(
				`hardened_systemd_unit: ${field} ${JSON.stringify(name)} must be an account name: a letter or \`_\`, then letters, digits, \`_\` or \`-\`, optionally ending in \`$\``
			);
		}
		if (name === 'root') {
			throw new Error(
				`hardened_systemd_unit: ${field} "root" is root, and the unit's hardening is for an unprivileged account`
			);
		}
	}
	const program = exec_start.replace(/^(?:@:?|:@?)?(?=\/)/, '');
	if (!program.startsWith('/')) {
		throw new Error(
			`hardened_systemd_unit: exec_start ${JSON.stringify(exec_start)} must begin with the program's absolute path, after at most the \`@\` or \`:\` prefix (\`+\`, \`!\` and \`!!\` run it outside User= or the sandbox, and \`-\` reads a failing exit as success)`
		);
	}
	for (const capability of capabilities) {
		if (!/^CAP_[A-Z_]+$/.test(capability)) {
			throw new Error(
				`hardened_systemd_unit: capabilities entry ${JSON.stringify(capability)} must be a capability name such as CAP_NET_BIND_SERVICE`
			);
		}
	}
	const filter = system_call_filter === false ? [] : system_call_filter;
	if (system_call_filter !== false && filter.length === 0) {
		throw new Error(
			'hardened_systemd_unit: system_call_filter is empty, which systemd reads as no filter; pass `false` to say so'
		);
	}
	for (const entry of filter) {
		if (!/^@?[a-z0-9_-]+$/.test(entry)) {
			throw new Error(
				`hardened_systemd_unit: system_call_filter entry ${JSON.stringify(entry)} must be one syscall or \`@set\` name (an allow-list entry)`
			);
		}
	}
	if (!/^[0-7]{4}$/.test(umask)) {
		throw new Error(
			`hardened_systemd_unit: umask ${JSON.stringify(umask)} must be four octal digits, such as '0077'`
		);
	}
	if (hardening_comment !== undefined) {
		for (const line of hardening_comment.split('\n')) {
			if (!line.startsWith('#') || line.endsWith('\\') || line.includes('\r')) {
				throw new Error(
					`hardened_systemd_unit: hardening_comment line ${JSON.stringify(line)} must begin with \`#\` and not end in \`\\\`, or systemd reads it as a directive`
				);
			}
		}
	}

	const wants_line = wants.length === 0 ? '' : `Wants=${wants.join(' ')}\n`;

	// A line break in a value would add directives to the unit; a space in a path
	// would split `ReadWritePaths=`.
	const one_line: Array<[string, string]> = [
		['description', description],
		['exec_start', exec_start],
		['user', user],
		['group', group],
		['working_directory', working_directory],
		['env_file', env_file ?? ''],
		['restart', restart],
		['wanted_by', wanted_by],
		...read_write_paths.map((path): [string, string] => ['read_write_paths', path]),
		...after.map((entry): [string, string] => ['after', entry]),
		...wants.map((entry): [string, string] => ['wants', entry]),
		...restrict_address_families.map((entry): [string, string] => [
			'restrict_address_families',
			entry
		])
	];
	// A trailing `\` would continue the value onto the next directive.
	for (const [field, value] of one_line) {
		if (/[\r\n]/.test(value) || value.endsWith('\\')) {
			throw new Error(`hardened_systemd_unit: ${field} must be one line, not ending in \`\\\``);
		}
	}
	for (const path of read_write_paths) {
		if (/\s/.test(path)) {
			throw new Error(
				`hardened_systemd_unit: read_write_paths entry ${JSON.stringify(path)} holds whitespace, which splits ReadWritePaths=`
			);
		}
	}

	// `EnvironmentFile=` is emitted only when `env_file` is set; otherwise the
	// runtime injects env via `exec_start` (e.g. Deno's `--env=`).
	const environment_file_line = env_file === undefined ? '' : `EnvironmentFile=${env_file}\n`;

	// The per-host sandboxing-rationale comment sits between `PrivateTmp=true` and
	// `PrivateDevices=true`; omitted means no comment line at all.
	const hardening_comment_block = hardening_comment === undefined ? '' : `${hardening_comment}\n`;

	const ambient_line =
		capabilities.length === 0 ? '' : `AmbientCapabilities=${capabilities.join(' ')}\n`;
	const filter_lines =
		filter.length === 0
			? ''
			: `SystemCallFilter=${filter.join(' ')}\nSystemCallErrorNumber=EPERM\n`;

	return `[Unit]
Description=${description}
After=${after.join(' ')}
${wants_line}
[Service]
Type=simple
User=${user}
Group=${group}
WorkingDirectory=${working_directory}
${environment_file_line}ExecStart=${exec_start}
Restart=${restart}
RestartSec=${restart_sec}
StandardOutput=journal
StandardError=journal

# Security hardening
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=${read_write_paths.join(' ')}
UMask=${umask}
CapabilityBoundingSet=${capabilities.join(' ')}
${ambient_line}PrivateTmp=true
${hardening_comment_block}PrivateDevices=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectKernelLogs=true
ProtectControlGroups=true
ProtectClock=true
ProtectHostname=true
RestrictNamespaces=true
RestrictRealtime=true
RestrictSUIDSGID=true
RestrictAddressFamilies=${restrict_address_families.join(' ')}
LockPersonality=true
SystemCallArchitectures=native
${filter_lines}
[Install]
WantedBy=${wanted_by}
`;
}
