/**
 * The `zap.ts` authoring API — the builder a config's default export receives.
 *
 * A `@fuzdev/zap` config is a module whose default export is a
 * `(zap, ctx) => void | Promise<void>`: it calls the `ZapBuilder` methods to declare the target,
 * resources, and deploy block. The builder collects those declarations into the
 * JSON the Rust engine parses against `crates/zap_types/src/schema/` (mirrored
 * by `schema.ts`); the builder shim injects each resource's `type` discriminant,
 * so authors never write `type`.
 *
 * The builder's types live here; the payload types it takes live in `schema.ts`,
 * each imported from its own module:
 *
 * ```ts
 * import type {ZapBuilder} from '@fuzdev/zap/zap.ts';
 * import type {FileResource} from '@fuzdev/zap/schema.ts';
 * ```
 *
 * @module
 */

import type {
	TargetInput,
	DeploySpec,
	ResourceIdentity,
	PackageResource,
	AptRepoResource,
	ScriptResource,
	InstallerResource,
	UserResource,
	DirectoryResource,
	FileResource,
	LinkResource,
	ServiceResource,
	DatabaseResource,
	SwapResource,
	FirewallResource,
	VerifyResource,
	PipelineResource,
	BuildResource
} from './schema.ts';

/**
 * Plan-time inputs to a config's default export. There are none, so it is empty:
 * the same `zap.ts` always evals to the same declared state (the changeset built
 * from it then depends on what detection finds on the target).
 */
export interface ZapContext {} // eslint-disable-line @typescript-eslint/no-empty-object-type

/**
 * The builder a config declares against. Every method returns the builder for
 * chaining; the resource methods take `ResourceIdentity` intersected with the
 * kind-specific payload (the shim adds `type`).
 */
export interface ZapBuilder {
	/** Declare the `zap.target({...})` machine descriptor (local or remote SSH). */
	target(config: TargetInput): ZapBuilder;
	/** Declare the `zap.deploy({...})` release-management block `zap deploy` ships with. */
	deploy(config: DeploySpec): ZapBuilder;
	/**
	 * A reference to the operator environment variable `name`: the value is read
	 * from the environment of the machine zap runs on, when the field holding the
	 * reference is used — never while the config is evaluated, which has no
	 * environment.
	 *
	 * The result is a string to place in a field that takes a reference — whole
	 * (`host: zap.env('DEPLOY_HOST')`), interpolated into a template literal, or
	 * concatenated (`path: '/srv/' + zap.env('APP') + '/data'`). It is opaque:
	 * it holds a marker, not the value, so slicing, splitting, case-changing, or
	 * encoding it leaves something that is no longer a reference: the config fails
	 * to evaluate when part of the marker survives, and otherwise the result is
	 * ordinary text. A field that takes no reference rejects one, naming the
	 * field. A recipe, which has no builder, calls `env_ref` from
	 * `@fuzdev/zap/env_ref.ts` for the same string.
	 *
	 * @param name - the variable's name: a letter or `_`, then letters, digits, or `_`
	 * @returns a marked string standing for the variable's value
	 * @throws Error if `name` is not an environment variable's name
	 */
	env(name: string): string;
	/**
	 * Declare env-var names secret: ones zap doesn't recognize by where they are
	 * used, their name, or the form of their value. Each is a variable's name —
	 * `'LICENSE_CODE'`, not `zap.env('LICENSE_CODE')` — and POSIX
	 * (`[A-Za-z_][A-Za-z0-9_]*`); anything else throws when called.
	 */
	mask(...vars: string[]): ZapBuilder;
	/**
	 * Declare env-var names not secret, where zap reads one as a secret by its
	 * name or the form of its value and it isn't. Each is a variable's name, POSIX
	 * (`[A-Za-z_][A-Za-z0-9_]*`); anything else throws when called. Unmasking a
	 * variable the config uses as a fetch credential (`auth`) is rejected when the
	 * config is read.
	 */
	unmask(...vars: string[]): ZapBuilder;
	/** Declare a `package` resource — a system package via a package manager. */
	pkg(config: ResourceIdentity & PackageResource): ZapBuilder;
	/** Declare an `apt_repo` resource — a GPG key + sources list. */
	apt_repo(config: ResourceIdentity & AptRepoResource): ZapBuilder;
	/** Declare a `script` resource — an idempotent command (check / run). */
	script(config: ResourceIdentity & ScriptResource): ZapBuilder;
	/** Declare an `installer` resource — software via a curl-piped script. */
	installer(config: ResourceIdentity & InstallerResource): ZapBuilder;
	/** Declare a `user` resource — a Unix user (shell, home mode, SSH keys, sudoers). */
	user(config: ResourceIdentity & UserResource): ZapBuilder;
	/** Declare a `directory` resource — a directory with managed permissions. */
	directory(config: ResourceIdentity & DirectoryResource): ZapBuilder;
	/** Declare a `file` resource — a file with managed content. */
	file(config: ResourceIdentity & FileResource): ZapBuilder;
	/** Declare a `link` resource — a symbolic link. */
	link(config: ResourceIdentity & LinkResource): ZapBuilder;
	/** Declare a `service` resource — service lifecycle management. */
	service(config: ResourceIdentity & ServiceResource): ZapBuilder;
	/** Declare a `database` resource (`PostgreSQL` only). */
	database(config: ResourceIdentity & DatabaseResource): ZapBuilder;
	/** Declare a `swap` resource — a swap file. */
	swap(config: ResourceIdentity & SwapResource): ZapBuilder;
	/** Declare a `firewall` resource — firewall rules (ufw or nftables). */
	firewall(config: ResourceIdentity & FirewallResource): ZapBuilder;
	/**
	 * Declare a `verify` resource — assertions checked at detection and again at its place
	 * in dependency order on a wetrun; one still failing there fails the run.
	 */
	verify(config: ResourceIdentity & VerifyResource): ZapBuilder;
	/** Declare a `pipeline` resource — imperative multi-step execution. */
	pipeline(config: ResourceIdentity & PipelineResource): ZapBuilder;
	/** Declare a `build` resource — fetch a verified source, build it, install to `output`. */
	build(config: ResourceIdentity & BuildResource): ZapBuilder;
}

/**
 * The default-export signature of a `zap.ts` config — a pure `(zap, ctx)` function
 * with no ambient authority. It may be `async`: zap waits for the promise, and a
 * builder call made after it settles fails the evaluation, even when the config
 * catches the error (a guard against a forgotten `await`).
 */
export type ZapConfigModule = (zap: ZapBuilder, ctx: ZapContext) => void | Promise<void>;
