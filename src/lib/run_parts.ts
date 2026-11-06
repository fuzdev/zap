/**
 * The file-name rule of `run-parts`-style directories, for recipes that place a file
 * in one: certbot's deploy-hook directory and BusyBox `crond`'s daily-jobs directory.
 *
 * A pure function, like the recipes that import it: it only checks a string.
 *
 * @module
 */

/**
 * The spreadable `file` fields of an executable placed in a `run-parts`-style
 * directory — a certbot deploy hook, a BusyBox `crond` daily job — ready to spread
 * into a `zap.file({...})`.
 */
export interface RunPartsFile {
	path: string;
	mode: string;
	content: { type: 'inline'; content: string };
}

/**
 * Throw unless `name` is a file name a `run-parts`-style runner runs: letters, digits,
 * `_` and `-` only. BusyBox `run-parts` (and Debian's, by default) skips any other
 * name, so a `.sh` job would never run, and a `/` would leave the directory. The one
 * check for the hook and job file names the recipes place in such a directory.
 *
 * @param name - the file name
 * @param recipe - the recipe asking, named in the error
 * @throws when `name` holds any other character, or is empty
 */
export function validate_run_parts_name(name: string, recipe: string): void {
	if (!/^[A-Za-z0-9_-]+$/.test(name)) {
		throw new Error(
			`${recipe}: name ${JSON.stringify(name)} must be letters, digits, \`_\` and \`-\` only (run-parts skips any other name)`
		);
	}
}
