/**
 * `env_ref` — a reference to an operator environment variable, for a recipe.
 *
 * A config declares a reference with `zap.env('NAME')`. A recipe is a pure function
 * with no builder in hand, so it calls `env_ref('NAME')` for the same thing: the
 * two return the same string, and a recipe's result drops into a config's resource
 * as the config's own reference would.
 *
 * The string is a marker — the variable's name between two Unicode noncharacters,
 * behind a fixed mixed-case prefix. The config's builder converts every marked
 * string to a typed reference before the engine reads the config, and the engine
 * resolves it from the operator's environment when the value is used. Until then
 * the string is **opaque**: it can be interpolated into a template literal or
 * concatenated, and nothing else. A marker that was sliced, split, case-changed,
 * or encoded no longer reads as a reference: the config fails to evaluate when
 * part of the marker survives, and otherwise the result is ordinary text. It
 * never names another variable.
 *
 * @module
 */

/** What an environment variable's name looks like: POSIX `name`. */
const ENV_NAME = /^[A-Za-z_][A-Za-z0-9_]*$/;

/** A value as an error names it, never printing a reference's delimiters. */
const shown_value = (value: unknown): string =>
	typeof value === 'string'
		? `\`${value.replace(/[\uFDD0\uFDD1]/g, '?')}\``
		: value === undefined || value === null
			? 'nothing'
			: `a ${typeof value}`;

/**
 * A reference to the operator environment variable `name`, as a string a recipe
 * places in a field that takes a reference — whole, interpolated, or concatenated.
 *
 * @param name - the variable's name: a letter or `_`, then letters, digits, or `_`
 * @returns the marked string `zap.env(name)` returns
 * @throws Error if `name` is not an environment variable's name
 */
export function env_ref(name: string): string {
	if (typeof name !== 'string' || !ENV_NAME.test(name)) {
		throw new Error(
			`env_ref: ${shown_value(name)} is not an environment variable's name ` +
				'(a letter or `_`, then letters, digits, or `_`)'
		);
	}
	return `\uFDD0aZ:${name}\uFDD1`;
}
