<script lang="ts">
	import { resolve } from '$app/paths';
	import DocsFooter from '@fuzdev/fuz_ui/DocsFooter.svelte';
	import { site_context } from '@fuzdev/fuz_ui/site.svelte.ts';
	import { FUZ_DEV_URL } from '@fuzdev/fuz_ui/constants.ts';
	import EcosystemLinksPanel from '@fuzdev/fuz_ui/EcosystemLinksPanel.svelte';
	import Breadcrumb from '@fuzdev/fuz_ui/Breadcrumb.svelte';
	import Svg from '@fuzdev/fuz_ui/Svg.svelte';
	import { logo_zap } from '#routes/logos.ts';

	const site = site_context.get();
</script>

<svelte:head>
	<title>about — zap</title>
</svelte:head>

<main class="width_atmost_md pb_xl9">
	<section class="box">
		<header class="box pt_xl">
			<Svg data={logo_zap} size="var(--icon_size_xl)" />
			<h1 class="mt_xl2">zap</h1>
		</header>
		<div style:--font_size="var(--font_size_xl)">
			<Breadcrumb />
		</div>
	</section>
	<section class="box width_atmost_md">
		<div class="panel p_xl width:100%">
			<p>
				<!-- eslint-disable-next-line svelte/no-navigation-without-resolve -->
				Zap is part of <a href={FUZ_DEV_URL}>Fuz</a>, free software for human agency. It runs the
				servers of the Fuz project itself and its maintainer's own machines, which is where its
				resource set and recipes come from. It is pre-alpha with a single maintainer; the config
				schema and CLI change without compatibility layers until 1.0.
			</p>
			<p>
				Start with the <a href={resolve('/docs/introduction')}>introduction</a>, then
				<a href={resolve('/docs/getting-started')}>getting started</a>. Everything else is under
				<a href={resolve('/docs')}>docs</a>.
			</p>
		</div>
	</section>
	<EcosystemLinksPanel />
	<section class="box">
		<DocsFooter repo_url={site.repo_url} root_url={FUZ_DEV_URL} />
	</section>
</main>

<style>
	main {
		display: flex;
		flex-direction: column;
		align-items: center;
		margin: 0 auto;
	}
	h1 {
		display: flex;
		align-items: baseline;
		text-align: center;
	}
</style>
