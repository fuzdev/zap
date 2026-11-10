/**
 * The `zap.ts` authoring schema — TypeScript types that mirror the Rust serde
 * JSON boundary in `crates/zap_types/src/schema/` (the authoritative source).
 *
 * These give a config author full type-checking against the same contract the
 * Rust engine parses: every resource payload, the nested content/source unions,
 * the closed-set enums, and the `deploy()` block. The Rust structs carry
 * `#[serde(deny_unknown_fields)]`, so these interfaces have **no index
 * signatures** — a misspelled field is a type error here exactly as it is a
 * parse error in the engine.
 *
 * Scalar newtypes on the Rust side (`Mode` / `ContentHash` / `AccountName` /
 * `ResourceId` / `EnvVarName`) serialize as plain `string`; they are typed as
 * `string` here with their format invariant noted, since TypeScript can't
 * express the runtime validation the engine applies at parse.
 *
 * A field is optional (`?`) here exactly when the Rust field is `Option<T>` or
 * carries `#[serde(default)]`. The dual-gated kitchen-sink fixture
 * (`src/test/fixtures/kitchen_sink_config.ts` — type-checked against these
 * types, then eval'd and parsed by the Rust `config_conformance` test) guards
 * this module and the Rust schema from drifting.
 *
 * @module
 */

// --- Manager / closed-set enums --------------------------------------------

/**
 * Package managers a `target` may declare: the ones with a backend. The Rust
 * `PackageManager` also parses `pacman` and `brew`, which have none (their packages
 * detect as undetermined), so the authoring type leaves them out.
 */
export type PackageManager = 'apt' | 'apk';

/**
 * Service managers a `target` may declare: the ones with a backend. The Rust
 * `ServiceManager` also parses `launchd`, which has none (its services detect as
 * undetermined), so the authoring type leaves it out.
 */
export type ServiceManager = 'systemd' | 'openrc';

/** Database engine for a `database` resource (only `postgresql`). */
export type DatabaseEngine = 'postgresql';

/**
 * Firewall backend for a `firewall` resource: `ufw` (Debian/Ubuntu — app
 * profiles + port rules) or `nftables` (the Alpine-native declarative
 * `inet filter` backend — port/proto rules only, no application profiles). Mirrors
 * the Rust `FirewallBackend`.
 */
export type FirewallBackend = 'ufw' | 'nftables';

/** A firewall default-policy verdict / allow disposition, on either backend. Mirrors `FirewallPolicy`. */
export type FirewallPolicy = 'allow' | 'deny' | 'reject';

/** The transport protocol of a firewall port rule. Mirrors `Protocol`. */
export type Protocol = 'tcp' | 'udp' | 'any';

/** The required type of a `path_exists` verify assertion's target. Mirrors `FileType`. */
export type FileType = 'file' | 'directory';

/** Sudo access mode for a `user` resource. Mirrors `SudoMode`. */
export type SudoMode = 'nopasswd' | 'password';

/**
 * A `PostgreSQL` `pg_hba.conf` auth method — the set `PostgreSQL` documents, but for
 * those that can't work on a plain TCP `host` line with no options, the only kind zap
 * writes: `trust` (it admits any account on the machine as the role), `peer` (accepted
 * only on a `local` line), `cert` (only on a `hostssl` line), `ldap` and `radius` (they
 * need options zap doesn't write), and `sspi` and `bsd` (not built on Linux). Mirrors
 * `PgAuthMethod`.
 */
export type PgAuthMethod =
	'reject' | 'scram-sha-256' | 'md5' | 'password' | 'gss' | 'ident' | 'pam';

// --- Shared resource identity ----------------------------------------------

/**
 * The common identity flattened onto every resource arg (`id` / `name?` /
 * `depends_on?`). Mirrors the flat fields of the Rust `Resource`.
 *
 * Each builder method takes `ResourceIdentity` intersected with the
 * kind-specific payload; the builder shim injects the `type` discriminant, so
 * authors never write `type`.
 */
export interface ResourceIdentity {
	/**
	 * Stable identity within the config. Mirrors `ResourceId` (a plain `string`
	 * on the wire). A name: a letter, a digit, or `_`, then any of those and
	 * `. + : @ -`; anything else is rejected by the structural gate.
	 */
	id: string;
	/**
	 * A label for whoever reads the config. A plan prints it under the change's
	 * header; everything else (apply's progress, events, triggers) names a resource by
	 * its `id`. It is carried in a change, so changing it changes the `plan_hash` of a
	 * plan that changes this resource, but never the lock entry's `config_hash`.
	 */
	name?: string;
	/** Resource ids this depends on (the resource-graph edges). */
	depends_on?: string[];
}

// --- Target (zap.target) ---------------------------------------------------

/**
 * The `zap.target({...})` machine descriptor. Modeled as a union so the
 * contradictory `local: true` _with_ remote connection fields is unrepresentable
 * — a local target rejects `host` / `user` / `bootstrap_user` / `port` / `key_path` / `home`.
 * Mirrors the Rust `Target` / `TargetWire` (local-vs-remote `TargetLocation`).
 */
export type TargetInput =
	| {
			/** `true` for a local target — no SSH connection fields allowed. */
			local: true;
			/** Package manager (e.g. `apt`). */
			package_manager?: PackageManager;
			/**
			 * Service manager (e.g. `systemd`). Required whenever the config has service
			 * intent — a `service`, a `file` with `triggers`, or `deploy.service` — or the
			 * structural gate rejects it; `launchd` parses but has no
			 * backend (its services detect as `undetermined`).
			 */
			service_manager?: ServiceManager;
	  }
	| {
			/** Absent or `false` means remote (SSH). */
			local?: false;
			/**
			 * Remote host (SSH): a name or an address alone. May be a reference, resolved
			 * at apply time; a value holding `@`, or an address in brackets, is refused
			 * when zap connects.
			 */
			host?: string;
			/**
			 * Remote user (SSH). May be a reference; one that resolves to nothing, or to a
			 * value holding `:`, is refused when zap connects.
			 */
			user?: string;
			/**
			 * Alternate connecting user for the initial provisioning run, selected by the
			 * `--bootstrap` switch instead of `user`. For an SSH-hardening bring-up: connect
			 * as the stock account to provision + harden (which creates the primary `user`
			 * and locks this one out), then omit `--bootstrap` for every later run. May be a
			 * reference.
			 */
			bootstrap_user?: string;
			/** Remote SSH port, 1 to 65535 (`ssh`'s own default when unset). */
			port?: number;
			/** Path to the SSH private key, if not using default key resolution. */
			key_path?: string;
			/** The target's declared remote home (resolves `~` / `$HOME` in remote paths). */
			home?: string;
			/** Package manager (e.g. `apt`). */
			package_manager?: PackageManager;
			/**
			 * Service manager (e.g. `systemd`). Required whenever the config has service
			 * intent — a `service`, a `file` with `triggers`, or `deploy.service` — or the
			 * structural gate rejects it; `launchd` parses but has no
			 * backend (its services detect as `undetermined`).
			 */
			service_manager?: ServiceManager;
	  };

// --- File content + nested unions ------------------------------------------

/**
 * The kind of value a `template` variable renders to, checked on its whole rendered
 * value. Mirrors the Rust `TemplateKind`.
 *
 * - `text` — any one line: no line break, NUL, or reference delimiter. Every kind keeps
 *   this rule. A reference's value is held to it whether or not its variable declares a
 *   kind; a value written out is held to it only when its variable declares one.
 * - `hostname` — a DNS host name (RFC 1123): dot-separated labels of ASCII letters,
 *   digits, and `-`, each 1 to 63 bytes, no leading or trailing `-`, at most 253 bytes,
 *   with no trailing dot, no wildcard, and no `_`.
 * - `port` — a decimal number from 1 to 65535, with no sign or leading zero.
 * - `path` — an absolute path whose names are ASCII letters, digits, `.`, `_`, `-`, `+`,
 *   and `@`, with no empty, `.`, or `..` name.
 * - `email` — a local part of ASCII letters, digits, `.`, `_`, `%`, `+`, and `-` (no
 *   leading, trailing, or doubled `.`), an `@`, and a `hostname`.
 * - `env_value` — a value written inside single quotes in an env file: `text` with no
 *   `'`, which would end the quoting.
 *
 * None of the `hostname`, `port`, `path`, or `email` alphabets holds a character a
 * config grammar reads as structure (`;`, `{`, `}`, a quote, a blank), which is what
 * a kind is for: a `{{domain}}` in an nginx `server_name` declared `hostname` can't
 * end the directive.
 */
export type TemplateKind = 'text' | 'hostname' | 'port' | 'path' | 'email' | 'env_value';

/**
 * `template` file content: a `{{key}}` template with per-variable substitution.
 * Mirrors the Rust `TemplateContent`. The site and env recipes return one whole, with
 * the kinds of the variables their templates place.
 */
export interface TemplateContent {
	/** A `{{key}}` template with per-variable substitution. */
	type: 'template';
	/**
	 * The template body, used as declared. It takes no reference. A placeholder is
	 * a variable's name between `{{` and `}}` and nothing else; one that names no
	 * variable is rejected by the structural gate.
	 */
	template: string;
	/**
	 * Variable values substituted for `{{key}}`, in one pass: a value is never read
	 * for placeholders. A string value may be or carry a reference, resolved before
	 * it is substituted. A value that isn't a string is substituted as its compact
	 * JSON text and takes no reference at any depth. A variable no placeholder names
	 * is rejected by the structural gate. A reference whose value holds a line break
	 * (CR or LF) or a NUL holds the file and refuses its write: it would add a line.
	 */
	vars?: Record<string, unknown>;
	/**
	 * The kind of value each named variable must render to (`TemplateKind`). Each key
	 * names a variable in `vars`, or the structural gate rejects it. A declared kind is
	 * checked on a value written out when the config is read, and on one carrying a
	 * reference once it resolves, which holds the file and refuses its write when it
	 * isn't its kind. A variable not named here declares no kind: a reference in its
	 * value is still held to `'text'` once it resolves, and a value written out is
	 * substituted unchecked.
	 */
	kinds?: Record<string, TemplateKind>;
}

/**
 * The `content` field of a `file` resource. Internally tagged on `type`.
 * Mirrors the Rust `FileContent`.
 */
export type FileContent =
	| {
			/** Literal content, used verbatim. */
			type: 'inline';
			/** The file's content, installed as declared. It takes no reference. */
			content: string;
	  }
	| TemplateContent
	| {
			/**
			 * Content copied from a file on the target at apply time: the regular file at the
			 * path, byte for byte, never through a symbolic link there; at most 16 MiB.
			 */
			type: 'source';
			/** The source path on the target (may carry a reference / `~`). */
			path: string;
	  }
	| ({
			/** Content fetched from a URL, addressed by content hash. */
			type: 'remote';
	  } & RemoteContent);

/** The payload of a `remote` `FileContent`. Mirrors the Rust `RemoteContent`. */
export interface RemoteContent {
	/**
	 * Fetch location: an `https://` URL with no `user:password@` (`http://` only for a
	 * loopback host), or the structural gate rejects it. It may carry a reference,
	 * resolved when zap fetches (the lock addresses a secret reference by its
	 * token, any other by its value).
	 */
	url: string;
	/**
	 * Vendored content pin. A declared pin self-pins (skips the lock); absent,
	 * the lock pins the resolved hash. Mirrors `ContentHash` — exactly 64
	 * lowercase hex on the wire.
	 */
	blake3?: string;
	/** How the fetched bytes are materialized on the target. */
	extract?: ExtractMode;
	/** Optional fetch credential for a private byte-host (never hashed). */
	auth?: RemoteAuth;
}

/**
 * How a fetched `remote` file / build source is materialized after fetch.
 * Internally tagged on `type`. Mirrors the Rust `ExtractMode`.
 */
export type ExtractMode =
	| {
			/** Write the fetched bytes verbatim (a file or binary). Takes no other key. */
			type: 'none';
	  }
	| {
			/** Extract a `.tar.xz` archive into the target path. */
			type: 'tar.xz';
			/** Leading path components to strip on extraction. `0` strips nothing. */
			strip_components?: number;
	  }
	| {
			/** Extract a `.tar.gz` archive into the target path. */
			type: 'tar.gz';
			/** Leading path components to strip on extraction. `0` strips nothing. */
			strip_components?: number;
	  };

/**
 * A credential for fetching a `remote` file's bytes from a private host. Tagged
 * on `scheme` (not `type`). Mirrors the Rust `RemoteAuth`.
 */
export interface RemoteAuth {
	/** `Authorization: Bearer <token>`. */
	scheme: 'bearer';
	/** The bearer token; typically a reference, never a literal. */
	token: string;
}

/**
 * SSH key configuration for a `user` resource: copy another user's
 * `authorized_keys`, or supply explicit keys. Untagged — distinguished by which
 * field is present. Exactly one of the two: an object with both `copy_from` and
 * `keys` type-checks here and is rejected when the config is read. Mirrors the Rust
 * `SshKeys`.
 */
export type SshKeys =
	| {
			/** Copy `authorized_keys` from another user (e.g. `root`). Mirrors
			 * `AccountName` — a portable Unix name (`[a-z_][a-z0-9_-]*`, optional trailing `$`; anything else is rejected at parse). */
			copy_from: string;
	  }
	| {
			/** The public-key lines written to `authorized_keys`. Every entry must be
			 * non-blank, and an empty list is rejected by the structural gate (it could never
			 * converge, and the account would take no login). A key takes no reference,
			 * also rejected when the config is read: zap installs the lines as declared and
			 * detection compares them as declared. An entry is one key on one line: one
			 * holding a line break (text read from a file, untrimmed) is rejected by the
			 * structural gate. */
			keys: string[];
	  };

/**
 * A `user` resource's `sudo` field: `false` to remove sudo, a bare mode string
 * to grant unrestricted, or `{mode, commands}` to grant command-restricted.
 * Untagged. Mirrors the Rust `UserSudo`.
 */
export type UserSudo =
	| false
	| SudoMode
	| {
			/** The grant mode. */
			mode: SudoMode;
			/** The sudoers command specs the grant is limited to: at least one, none
			 * blank or holding a control character (an empty list is rejected when the
			 * config is read, not read as every command — write the bare mode for that).
			 * A spec takes no reference, also rejected when the config is read. */
			commands: string[];
	  };

/**
 * A firewall allow rule: a named ufw application profile (e.g. `OpenSSH`, ufw
 * only — rejected under the `nftables` backend), or a port/proto pair (both
 * backends). A named profile takes no reference (rejected when the config is read:
 * detection reads it as declared) and can't begin with `-` (rejected by the
 * structural gate). Untagged. Mirrors the Rust `FirewallAllowRule`.
 */
export type FirewallAllowRule =
	| string
	| {
			/** The port number. */
			port: number;
			/** The protocol (default `tcp`). */
			proto?: Protocol;
	  };

/**
 * `PostgreSQL` auth config for a `database` resource's `pg_hba.conf` rules: one `host`
 * line per entry of `hosts`. A `database` without one declares no rule, so the role is
 * reached over the Unix socket by the OS account of the same name (the stock `peer`
 * rule). Mirrors
 * the Rust `DatabaseAuth`.
 */
export interface DatabaseAuth {
	/** Auth method (default `scram-sha-256`). */
	method?: PgAuthMethod;
	/**
	 * Allowed client addresses, each an IP address with its prefix length
	 * (`127.0.0.1/32`); a keyword (`all`, `samehost`, `samenet`) or a host name is
	 * refused. At least one: an `auth` that names none is refused, since it would
	 * write no rule.
	 */
	hosts: string[];
}

/**
 * A verify assertion — a path-existence check or a command check. Internally
 * tagged on `type`. Mirrors the Rust `VerifyAssertion`.
 */
export type VerifyAssertion =
	| ({
			/** Assert a path exists (optionally a specific type / mode / owner / non-empty). */
			type: 'path_exists';
	  } & PathExistsAssertion)
	| ({
			/** Assert a command exits 0 (optionally with `expect` in stdout). */
			type: 'command';
	  } & CommandAssertion);

/** The payload of a `path_exists` `VerifyAssertion`. Mirrors `PathExistsAssertion`. */
export interface PathExistsAssertion {
	/**
	 * The absolute path to check, as written: no reference; a `~` or relative path is
	 * rejected. A link is followed: type, mode and owner are its target's.
	 */
	path: string;
	/** Required type; absent accepts either. */
	file_type?: FileType;
	/**
	 * Required octal mode (e.g. `"600"`). Mirrors `Mode` — octal, `7777` at most.
	 * `0644` and `644` compare the same.
	 */
	mode?: string;
	/**
	 * Required owner. Mirrors `AccountName` — a portable Unix user/group name
	 * (`[a-z_][a-z0-9_-]*`, optional trailing `$`; a numeric uid/gid or any other
	 * character is rejected at parse).
	 */
	owner?: string;
	/**
	 * Whether the path's size must be above zero (`test -s`). A directory's size depends
	 * on its filesystem, so this doesn't reliably check that a directory has entries.
	 */
	not_empty?: boolean;
}

/** The payload of a `command` `VerifyAssertion`. Mirrors `CommandAssertion`. */
export interface CommandAssertion {
	/** The command to run. */
	run: string;
	/** A substring that must appear in stdout. */
	expect?: string;
}

/**
 * The source a `build` fetches + verifies. Internally tagged on `type` (only the
 * remote-tarball flavor exists). Mirrors the Rust `BuildSource`.
 */
export type BuildSource = {
	/** A fetched source archive — fetched, verified, and content-addressed. */
	type: 'remote';
} & RemoteSource;

/** The payload of a `remote` `BuildSource`. Mirrors the Rust `RemoteSource`. */
export interface RemoteSource {
	/**
	 * Fetch location: an `https://` URL with no `user:password@` (`http://` only for a
	 * loopback host), or the structural gate rejects it. It may carry a reference,
	 * resolved when zap fetches (the lock addresses a secret reference by its
	 * token, any other by its value).
	 */
	url: string;
	/** How the fetched source is unpacked before `run`. */
	extract?: ExtractMode;
	/** Optional fetch credential for a private byte-host (never hashed). */
	auth?: RemoteAuth;
	/**
	 * Optional upstream-signature verification, run when a fetch fills the content
	 * cache, before the bytes are pinned or built. A cache hit is not re-verified: it
	 * is re-hashed against the pin.
	 */
	verify?: SourceVerify;
	/**
	 * Vendored source pin. A declared pin self-pins; absent, the lock pins it.
	 * Mirrors `ContentHash` — exactly 64 lowercase hex on the wire.
	 */
	blake3?: string;
}

/**
 * Upstream-signature verification for a build source. Tagged on `scheme` (not
 * `type`); the one scheme is minisign. Mirrors the Rust `SourceVerify`.
 */
export type SourceVerify = {
	/** `minisign -V` against `public_key`. */
	scheme: 'minisign';
} & MinisignVerify;

/** The payload of a `minisign` `SourceVerify`. Mirrors the Rust `MinisignVerify`. */
export interface MinisignVerify {
	/**
	 * The pinned minisign public key: the 56 base64 characters beginning `RW` (the key
	 * line of a `.pub` file, without its comment). Mirrors the Rust `MinisignKey`; any
	 * other shape is rejected at config eval.
	 */
	public_key: string;
	/**
	 * Explicit signature URL, held to the rule `url` is; it may carry a reference.
	 * Defaults to the source URL with `.minisig` appended to its path, before any query or fragment.
	 */
	signature_url?: string;
}

/** One step in a `pipeline` resource. Mirrors the Rust `PipelineStep`. */
export interface PipelineStep {
	/**
	 * Identifier for this step, unique within the pipeline: a repeated id is rejected
	 * by the structural gate.
	 */
	id: string;
	/** Human-readable name for the step, printed under its `id` in a plan. */
	name?: string;
	/** The command this step runs. */
	run: string;
	/**
	 * Working directory for this step. Rejected by the structural gate — the
	 * sequential executor doesn't apply it; inline a `cd` into `run`. The engine parses
	 * a string here, and the authoring type admits none.
	 */
	cwd?: never;
	/**
	 * Environment variables for this step. Rejected by the structural gate — the
	 * sequential executor doesn't apply it; inline the vars into `run`. The engine
	 * parses a map here, and the authoring type admits none.
	 */
	env?: never;
	/**
	 * Step ids this depends on (within the pipeline). Rejected by the structural
	 * gate: steps run sequentially in declaration order. The engine parses a list here,
	 * and the authoring type admits none.
	 */
	depends_on?: never;
}

// --- Resource payloads ------------------------------------------------------

/** `package` resource payload — a system package via a package manager. */
export interface PackageResource {
	/**
	 * Package-manager → package-name mapping (e.g. `{apt: "curl"}`). A name takes no
	 * reference (rejected when the config is read): it is put into the manager's command
	 * unquoted, and detection asks the manager about it (under apt by the name
	 * alone, for `name=version` at exactly that version, and for `name:arch` by that
	 * architecture). So a name is one word in the manager's syntax — a letter or digit,
	 * then letters, digits, and `+ . _ - = ~ : / @`, not ending in `-` — and anything
	 * else is rejected when the config is read. An apt name `dpkg-query` would never find
	 * installed is rejected too: an empty version (`name=`) or architecture (`name:`),
	 * `name:any`, `name:native`, and `name:all` (apt reads `all` as the native
	 * architecture: name that one, or none), and an architecture that isn't one lowercase
	 * word. An apk name `apk info -e` would read installed whether or not it is, one
	 * ending in a version operator with no version after it (`name=`, `name~`,
	 * `name@tag=`), is rejected as well: write the version, or drop the operator.
	 */
	from: Partial<Record<PackageManager, string>>;
	/**
	 * Optional custom check (a path, or a command); defaults to the PM query. A check
	 * beginning `/`, `~`, or `$HOME` is a path and its references resolve;
	 * anything else is a command, run as written.
	 */
	check?: string;
}

/** `apt_repo` resource payload — a GPG key + sources list. */
export interface AptRepoResource {
	/**
	 * The URL zap fetches the GPG signing key from, on the operator's machine: `https://`,
	 * or `http://` to a loopback host; any other scheme is rejected by the structural gate.
	 * It may carry a reference. The key is pinned by the blake3 of its bytes, and only
	 * bytes that hash to the pin are installed.
	 */
	key_url: string;
	/**
	 * The key's vendored pin: the blake3 of its bytes, 64 lowercase hex. Absent, the pin
	 * is tracked in `zap.lock` (`zap lock` / `zap update` mint and advance it).
	 */
	key_blake3?: string;
	/**
	 * Where the GPG key is stored; default `/usr/share/keyrings/{id}.asc`. It takes no
	 * reference (rejected when the config is read): it is written into the source line,
	 * inside double quotes.
	 */
	key_path?: string;
	/**
	 * The deb source line (`signed-by` is auto-injected from `key_path`). It is expanded
	 * by the target shell inside double quotes, so `$VERSION_CODENAME` resolves there; it
	 * takes no reference (rejected when the config is read).
	 */
	source: string;
	/**
	 * The `.list` file path; default `/etc/apt/sources.list.d/{id}.list`. It takes no
	 * reference (rejected when the config is read): detection reads it as declared.
	 */
	list_file?: string;
}

/** `script` resource payload — an idempotent command (check / run). */
export interface ScriptResource {
	/** Check command — exit 0 means the script is already applied (skip). */
	check: string;
	/** The command the planner emits when the check fails. */
	run: string;
	/**
	 * Working directory for the `check` and for `run`. An absolute path, taken
	 * verbatim: no reference (rejected when the config is read) and no `~` (rejected
	 * by the structural gate). A check
	 * that can't enter it reads as not applied; a `run` that can't enter it fails
	 * without running.
	 */
	cwd?: string;
	/**
	 * Extra environment, exported to the `check` and to `run` (every command of a
	 * compound sees it). Keys are POSIX names
	 * (`[A-Za-z_][A-Za-z0-9_]*`), validated at config-eval; a name beginning with
	 * `__zap_` is rejected by the structural gate (zap's own wrapper variables). A value's
	 * references resolve before it is quoted, so it can hold any text but
	 * a NUL and the reference delimiters U+FDD0 and U+FDD1 (a value with a `'` goes here,
	 * not in the command text).
	 */
	env?: Record<string, string>;
}

/**
 * The `check` and `run` of a `script`, the part a script recipe returns for a config
 * to spread into `zap.script({id, name, ...commands, depends_on})`. A derived
 * authoring type, not a wire type: the engine reads `ScriptResource`.
 */
export type ScriptCommands = Pick<ScriptResource, 'check' | 'run'>;

/** `installer` resource payload — software via a curl-piped script. */
export interface InstallerResource {
	/** The install script's `https://` URL, piped into `shell`; any other scheme is rejected by the structural gate. */
	url: string;
	/** Path checked for existence to confirm installation (may carry `~`). */
	check: string;
	/**
	 * Command the fetched install script is piped into (default `sh`), run as
	 * written. The script is fetched whole first; a failed fetch, or an empty script,
	 * fails the step.
	 */
	shell?: string;
}

/** `user` resource payload — a Unix user (shell, home mode, SSH keys, sudoers). */
export interface UserResource {
	/**
	 * Unix username to create/manage. Mirrors `AccountName` — a portable Unix name (`[a-z_][a-z0-9_-]*`, optional trailing `$`; anything else is rejected at parse).
	 * zap manages the user's home as `/home/<username>`, so `'root'` (home `/root`) is
	 * rejected by the structural gate, and an existing account whose `/etc/passwd` home
	 * is anything else is held at detection when `home_mode` or `ssh_keys` is declared.
	 * With either declared, a `/home/<username>` directory root owns is given to the
	 * user when zap creates the account, and left as it is for an existing one; one
	 * another uid owns, a link, or a non-directory there holds the user.
	 */
	username: string;
	/**
	 * Login shell (e.g. `/bin/bash`); system default when absent. It takes no
	 * reference (rejected when the config is read): detection reads it as declared.
	 */
	shell?: string;
	/** Home-directory mode (e.g. `"711"`). Mirrors `Mode` — octal, `7777` at most. */
	home_mode?: string;
	/** SSH key configuration, if managed. */
	ssh_keys?: SshKeys;
	/** Sudo access: a grant, or `false` to remove. Absent = unmanaged. */
	sudo?: UserSudo;
	/**
	 * Supplementary groups the user must belong to (additive — listed groups are added,
	 * never removed). Mirrors `AccountName[]` — portable Unix names (see `AccountName`). Absent/empty =
	 * unmanaged.
	 */
	groups?: string[];
}

/** `directory` resource payload — a directory with managed permissions. */
export interface DirectoryResource {
	/** Directory path, absolute or under `~` (may carry a reference). */
	path: string;
	/** Desired octal mode (e.g. `"755"`). Mirrors `Mode` — octal, `7777` at most. */
	mode?: string;
	/** Desired owner. Mirrors `AccountName` — a portable Unix name (`[a-z_][a-z0-9_-]*`, optional trailing `$`; anything else is rejected at parse). */
	owner?: string;
	/** Desired group. Mirrors `AccountName` — a portable Unix name (`[a-z_][a-z0-9_-]*`, optional trailing `$`; anything else is rejected at parse). */
	group?: string;
}

/** `file` resource payload — a file with managed content. */
export interface FileResource {
	/** Target path (may carry a reference / `~`). */
	path: string;
	/** Content source. */
	content: FileContent;
	/** Desired octal mode (e.g. `"600"`). Mirrors `Mode` — octal, `7777` at most. */
	mode?: string;
	/** Desired owner. Mirrors `AccountName` — a portable Unix name (`[a-z_][a-z0-9_-]*`, optional trailing `$`; anything else is rejected at parse). */
	owner?: string;
	/** Desired group. Mirrors `AccountName` — a portable Unix name (`[a-z_][a-z0-9_-]*`, optional trailing `$`; anything else is rejected at parse). */
	group?: string;
	/** Ids of `service` resources notified when this file changes. */
	triggers?: string[];
	/**
	 * Command that must exit 0 after a write (e.g. `NGINX_VALIDATE`), or the write is
	 * rolled back — the previous bytes, owner, group, and mode restored, less any set-id or
	 * sticky bit the declared `mode` lacks (or a new file removed) — and the change fails.
	 * Runs against the file in place, so it suits a file some larger config includes. Text
	 * content only — rejected on `remote`.
	 */
	validate?: string;
}

/** `link` resource payload — a symbolic link. */
export interface LinkResource {
	/**
	 * Symlink path (may carry a reference / `~`). A real directory at the path fails
	 * the step.
	 */
	path: string;
	/** The target the symlink should point to (resolved the same way). */
	target: string;
}

/** `service` resource payload — service lifecycle management. */
export interface ServiceResource {
	/**
	 * Service name (interpreted by the target's service manager). Takes no
	 * reference (rejected when the config is read): it is put into the manager's command unquoted,
	 * and detection reads it as declared. So a name is one word — a letter or digit, then
	 * letters, digits, and `_ . @ : -` — and anything else is rejected when the config is
	 * read.
	 */
	service: string;
	/** Whether the service should be enabled at boot (default `true`). */
	enabled?: boolean;
	/** Whether the service should be running now; absent = don't manage runtime. */
	running?: boolean;
	/**
	 * Resource ids whose change triggers a restart of this service, if it is running
	 * (`try-restart` on systemd, `rc-service --ifstarted` on OpenRC). A trigger on a
	 * service with `running: false` is a config error.
	 */
	restart_on?: string[];
	/**
	 * Resource ids whose change triggers a reload of this service, if it is running:
	 * `try-reload-or-restart` on systemd, `rc-service --ifstarted <svc> reload` on OpenRC
	 * (a service that can't reload fails the step).
	 */
	reload_on?: string[];
}

/** `database` resource payload (`PostgreSQL` only). */
export interface DatabaseResource {
	/** Database engine (only `postgresql`). */
	engine: DatabaseEngine;
	/**
	 * Database name to create. Taken literally (never shell-expanded); a
	 * reference resolves on the operator's machine.
	 */
	database_name: string;
	/**
	 * Role/user to create and own the database. Taken literally (never
	 * shell-expanded); `zap.env('USER')` declares "the operator's OS user".
	 */
	username: string;
	/**
	 * `pg_hba.conf` auth config. Absent, zap writes no rule, and the role is reached over
	 * the Unix socket by the OS account of the same name. A rule zap adds is put in
	 * force with `pg_reload_conf()`; the server isn't restarted, and the target needs no
	 * `service_manager` for it.
	 */
	auth?: DatabaseAuth;
}

/** `swap` resource payload — a swap file. */
export interface SwapResource {
	/** Swap size (e.g. `"2G"`). */
	size: string;
	/**
	 * Swap file path (default `/swapfile`). Used verbatim — no `~` expansion, and no
	 * reference (rejected when the config is read: detection reads it as declared).
	 */
	path?: string;
}

/** `firewall` resource payload — host firewall configuration (ufw or nftables). */
export interface FirewallResource {
	/** Firewall backend (`ufw` or `nftables`). */
	backend: FirewallBackend;
	/** Default policy for incoming traffic (default `deny`). */
	default_incoming?: FirewallPolicy;
	/** Default policy for outgoing traffic (default `allow`). */
	default_outgoing?: FirewallPolicy;
	/** Allow rules (named profiles or port/proto pairs). */
	allow: FirewallAllowRule[];
}

/**
 * `verify` resource payload — assertions checked at detection and, on a wetrun, checked
 * again at its place in dependency order; one still failing there fails the run: changes
 * ordered before it have run, the rest are skipped.
 */
export interface VerifyResource {
	/** Assertions to check (all must pass for the resource to be met). */
	assertions: VerifyAssertion[];
}

/** `pipeline` resource payload — imperative multi-step execution. */
export interface PipelineResource {
	/**
	 * Environment variables shared across all steps. Rejected by the structural
	 * gate — the sequential executor doesn't apply it; inline the vars into each
	 * step's `run`. The engine parses a map here, and the authoring type admits none.
	 */
	env?: never;
	/** The pipeline steps. */
	steps: PipelineStep[];
	/**
	 * Max steps to run concurrently. The engine parses any whole number from 1, and
	 * the structural gate rejects any value above `1`: steps run sequentially. So
	 * `1`, the only value that passes, is the only one the authoring type admits.
	 */
	max_concurrency?: 1;
}

/** `build` resource payload — fetch a verified source, build it, install to `output`. */
export interface BuildResource {
	/** Where the source comes from + how its integrity is verified. */
	source: BuildSource;
	/** The build command (e.g. `zig build -p $HOME/.local -Doptimize=ReleaseFast`). */
	run: string;
	/** Path that exists iff the build is installed — the detection probe. */
	output: string;
	/**
	 * Working directory for `run`: absolute, or relative to the extracted source dir,
	 * which is the default. Takes no reference: zap rejects one here.
	 */
	cwd?: string;
	/**
	 * Build environment. Keys are POSIX names (`[A-Za-z_][A-Za-z0-9_]*`),
	 * validated at config-eval; a name beginning with `__zap_` is rejected by the
	 * structural gate (zap's own wrapper variables). A value's references resolve
	 * before it is quoted, so it can hold any text but a NUL and the reference delimiters
	 * U+FDD0 and U+FDD1.
	 */
	env?: Record<string, string>;
}

// --- Deploy (zap.deploy) ----------------------------------------------------

/**
 * The `deploy()` release-management block — what `zap deploy` packages and
 * ships. Mirrors the Rust `DeploySpec`.
 */
export interface DeploySpec {
	/** Build command run **locally** before packaging (e.g. `gro build`). */
	build?: string;
	/**
	 * Files/directories (relative to the operator cwd) to package into the tarball.
	 * An entry can't begin with `-` (write `./-name`) or with `@`; either is rejected
	 * by the structural gate.
	 */
	artifacts: string[];
	/**
	 * Remote application root — holds `releases/`, `shared/`, and the `current`
	 * symlink. An absolute path, written out: no reference (rejected when the
	 * config is read) and no `~` (rejected by the structural gate).
	 */
	path: string;
	/**
	 * Number of releases to retain on the target, the live one included (default 5).
	 * Below 2 is rejected by the structural gate: the release just deployed and the
	 * one it replaced, which a failed deploy rolls back to, are always kept.
	 */
	releases?: number;
	/**
	 * Service to restart after the symlink swap. Requires `target.service_manager`.
	 * Takes no reference (rejected when the config is read).
	 */
	service?: string;
	/**
	 * Files under the remote `shared/` directory to symlink into each release root.
	 * Each is a relative name of a file: no `..` component, no control character, not
	 * ending in `/` or in a `.` component (anything else is rejected by the structural gate).
	 */
	shared?: string[];
	/**
	 * Post-extract commands run on the target, in the new release directory, before swap,
	 * each in a shell of its own (`sh -ec`): an `exit` in one ends that command, not the
	 * deploy, and one that fails stops the deploy before the swap. The release is still
	 * under its hidden staging name then, so a command shouldn't record its absolute path.
	 */
	prepare?: string[];
	/** Optional post-restart HTTP health check. */
	health?: DeployHealth;
}

/**
 * Post-restart HTTP health check for a deploy. Mirrors the Rust `DeployHealth`.
 *
 * `domain` lives inside this block, so declaring a health gate with nothing to poll is
 * unrepresentable rather than a mistake caught at run time. Omit the whole block to
 * deploy without a health gate.
 */
export interface DeployHealth {
	/**
	 * Host polled over HTTPS (e.g. `app.example.com`, or a `zap.env('DEPLOY_DOMAIN')` reference
	 * resolved at execution).
	 */
	domain: string;
	/**
	 * Request path polled over HTTPS against `domain`, beginning with `/` (e.g.
	 * `/health`). Takes no reference: zap rejects one here.
	 */
	path: string;
	/** How many times to poll before failing the deploy, at least 1 (default 15). */
	attempts?: number;
	/** Delay between poll attempts, in milliseconds (default 2000). */
	interval_ms?: number;
}
