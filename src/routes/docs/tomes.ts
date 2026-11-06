import type { Tome } from '@fuzdev/fuz_ui/tome.ts';
import ApiPage from './api/+page.svelte';
import { docs_tomes } from './docs.ts';

export const tomes: Array<Tome> = [
	...docs_tomes,
	{
		slug: 'api',
		category: 'reference',
		Component: ApiPage,
		related_tomes: [],
		related_modules: [],
		related_declarations: []
	}
];
