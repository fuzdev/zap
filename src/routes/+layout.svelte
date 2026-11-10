<script lang="ts">
	import 'virtual:fuz.css';
	import '@fuzdev/fuz_code/theme.css';
	import './style.css';

	import ThemeRoot from '@fuzdev/fuz_ui/ThemeRoot.svelte';
	import { SiteState, site_context } from '@fuzdev/fuz_ui/site.svelte.ts';
	import type { Snippet } from 'svelte';
	import pkg_json from 'virtual:pkg.json';

	import { logo_zap } from '#routes/logos.ts';

	const {
		children
	}: {
		children: Snippet;
	} = $props();

	// `glyph` and `repo_url` derive from `pkg_json`; `icon` stays explicit (structured `SvgData`).
	site_context.set(new SiteState({ icon: logo_zap, pkg_json }));
</script>

<svelte:head>
	<title>@fuzdev/zap</title>
</svelte:head>

<ThemeRoot>
	{@render children()}
</ThemeRoot>
