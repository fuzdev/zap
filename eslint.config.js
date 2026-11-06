import { configs } from '@ryanatkn/eslint-config';

export default [
	...configs,
	// the config eval wrappers, run by the engine as text, outside the site's TypeScript project
	{ ignores: ['crates/zap_core/src/config/*.js'] }
];
