/**
 * The file-name rule of `run-parts`-style directories, for recipes that place a file
 * in one: certbot's deploy-hook directory and BusyBox `crond`'s daily-jobs directory.
 *
 * A pure function, like the recipes that import it: it only checks a string.
 *
 * @module
 */

import type { FileContent, FileResource } from './schema.ts';

/**
 * The spreadable `file` fields of an executable placed in a `run-parts`-style
 * directory — a certbot deploy hook, a BusyBox `crond` daily job — ready to spread
 * into a `zap.file({...})`: its `path` and `mode`, and inline `content`.
 */
export type RunPartsFile = Required<Pick<FileResource, 'path' | 'mode'>> & {
	content: Extract<FileContent, { type: 'inline' }>;
};

/**
 * Throw unless `name` is a file name a `run-parts`-style runner runs: letters, digits,
 * `_` and `-` only. BusyBox `run-parts` (and Debian's, by default) skips any other
 * name, so a `.sh` job would never run, and a `/` would leave the directory. The one
 * check for the hook and job file names the recipes place in such a directory.
 *
 * @param recipe - the recipe asking, named in the error
 * @param name - the file name
 * @throws Error when `name` holds any other character, or is empty
 */
export function validate_run_parts_name(recipe: string, name: string): void {
	if (!/^[A-Za-z0-9_-]+$/.test(name)) {
		throw new Error(
			`${recipe}: name ${JSON.stringify(name)} must be letters, digits, \`_\` and \`-\` only (run-parts skips any other name)`
		);
	}
}
