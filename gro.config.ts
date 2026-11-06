import type { CreateGroConfig } from '@fuzdev/gro';
import type { ExportValue } from '@fuzdev/fuz_util/package_json.ts';

/**
 * Point `fgro` and Deno at the TypeScript source rather than the built `dist/`.
 *
 * zap evaluates every config with `fgro eval`, gro's runtime, which strips `.ts`
 * itself, so a `gro` condition on the module exports makes a config's recipe
 * imports read `src/lib/` — the package ships those files (see `files`). Without
 * it, a config path-dep'd on a local checkout evaluates whatever `dist/` was last
 * built, and a recipe fix never reaches a deploy until someone runs `gro build`.
 * The `deno` condition does the same for Deno tooling that reads the package.
 * Node and TypeScript match neither condition, so they still resolve `dist/`.
 * Both go first because conditions match in key order and each runtime also
 * matches `default` (Deno's type check matches `types` too).
 */
const config: CreateGroConfig = (base_config) => {
	base_config.map_package_json = (package_json) => {
		if (!package_json.exports || typeof package_json.exports !== 'object') return package_json;
		const exports: Record<string, ExportValue> = {};
		for (const [key, value] of Object.entries(package_json.exports)) {
			exports[key] =
				(key === './*.js' || key === './*.ts') && value && typeof value === 'object'
					? { gro: './src/lib/*.ts', deno: './src/lib/*.ts', ...value }
					: value;
		}
		return { ...package_json, exports };
	};
	return base_config;
};

export default config;
