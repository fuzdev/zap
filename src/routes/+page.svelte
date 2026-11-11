<script lang="ts">
	import { resolve } from '$app/paths';
	import Svg from '@fuzdev/fuz_ui/Svg.svelte';
	import Code from '@fuzdev/fuz_code/Code.svelte';
	import { logo_zap } from '#routes/logos.ts';

	const phases = [
		{ name: 'describe', text: 'declare what should be true of the machine, in TypeScript' },
		{ name: 'detect', text: 'read what the machine looks like now, live, every run' },
		{ name: 'plan', text: 'the difference, with a hash — the dry run' },
		{ name: 'apply', text: 'change only that difference, and only the plan you reviewed' },
		{ name: 'observe', text: 'read the machine again; typed events, not log soup' }
	];

	const config_example = `// zap.ts
export default (zap) => {
	zap.target({local: true, package_manager: 'apt', service_manager: 'systemd'});
	zap.pkg({id: 'ripgrep', from: {apt: 'ripgrep'}});
	zap.file({
		id: 'gitconfig',
		path: '~/.gitconfig',
		content: {type: 'inline', content: '[user]\\n\\tname = Ada\\n'},
	});
};
`;

	const run_example = `$ zap apply
apply — target local (dry-run)
  user: ada
  home: /home/ada
  target: {"local":true,"package_manager":"apt","service_manager":"systemd"}
  [+] cache-update-apt  (script)
      check: true
      > sudo apt-get update
  [+] gitconfig  (file)
      path: ~/.gitconfig
      content: inline (19 bytes, sha512 0435b012ac1a81df…)
  [+] ripgrep  (package)
      > sudo DEBIAN_FRONTEND=noninteractive apt-get install -y ripgrep
  (dry-run — re-run with --wetrun to apply)
plan_hash: d317a15e82f2f1117f0d9fa1fdafc079b70f9e3ac5e3103c4b3333f1b6afeab0

$ zap apply --wetrun
apply — target local (wetrun)
  user: ada
  home: /home/ada
  target: {"local":true,"package_manager":"apt","service_manager":"systemd"}
  ok    cache-update-apt  2.8s
  ok    gitconfig         0.0s
  ok    ripgrep           3.1s
applied: 3 ok, 0 failed, 0 skipped (of 3)
converged local in 6.4s, the re-detect included
plan_hash: d317a15e82f2f1117f0d9fa1fdafc079b70f9e3ac5e3103c4b3333f1b6afeab0
`;
</script>

<svelte:head>
	<title>zap — set up and ship to Linux machines from TypeScript</title>
</svelte:head>

<main>
	<section class="box">
		<header class="box pt_xl">
			<Svg data={logo_zap} size="var(--icon_size_xl)" />
			<h1 class="mt_xl2">zap <span class="glyph">↯</span></h1>
		</header>
		<p class="font_size_lg text-align:center width_atmost_sm">
			Set up and ship to Linux machines you own, from a TypeScript file. Zap reads the machine,
			shows you the diff, and changes nothing until you say <code>--wetrun</code>.
		</p>
		<p class="text-align:center width_atmost_sm text_70">
			Convergent machine-state management: a Rust binary and Gro's sandboxed runtime, no agent, no
			server, no state backend. Over SSH or on your own laptop. Debian/Ubuntu and Alpine. Pre-alpha.
		</p>
		<div class="row gap_md">
			<a href={resolve('/docs/introduction')} class="panel px_xl py_md font_size_lg">
				introduction
			</a>
			<a href={resolve('/docs/getting-started')} class="panel px_xl py_md font_size_lg">
				getting started
			</a>
			<a href={resolve('/docs')} class="panel px_xl py_md font_size_lg">docs</a>
		</div>
	</section>

	<section class="box width_atmost_md">
		<div class="panel p_xl box width:100%">
			<h2 class="mt_0">a config, a run</h2>
			<p>
				A <code>zap.ts</code> is a function that declares a target and resources. It runs in a
				sandbox with no network, no writes, no environment, no clock, and emits a JSON declaration;
				the engine does the rest.
			</p>
			<Code content={config_example} lang="ts" />
			<Code content={run_example} />
			<p class="text_70">
				Point the target at a host instead and the same config converges a server over SSH.
			</p>
		</div>
	</section>

	<section class="box width_atmost_md">
		<div class="panel p_xl box width:100%">
			<h2 class="mt_0">provision, then ship</h2>
			<p>
				<code>zap apply</code> converges the host: packages, files, users, services with restart
				triggers, PostgreSQL, swap, a firewall, from-source builds pinned to their source.
				<code>zap deploy</code> then ships your app to it as a versioned release with an atomic
				swap, a health gate, and rollback, and refuses to ship onto a host that has drifted. The
				shipped <a href={resolve('/docs/recipes')}>recipes</a> carry the standard pieces: SSH
				hardening, a hardened systemd or OpenRC unit, an nginx site with a CSP, certbot, fail2ban.
			</p>
		</div>
	</section>

	<section class="box width_atmost_md">
		<div class="panel p_xl box width:100%">
			<h2 class="mt_0">the loop</h2>
			<ol class="width:100%">
				{#each phases as phase (phase.name)}
					<li>
						<strong>{phase.name}</strong> — {phase.text}
					</li>
				{/each}
			</ol>
		</div>
	</section>

	<section class="box width_atmost_md">
		<div class="panel p_xl box width:100%">
			<h2 class="mt_0">what it does differently</h2>
			<ul class="width:100%">
				<li>
					<strong>A wetrun executes only the plan you reviewed.</strong> Dry run is the default,
					with no flag to auto-approve. <code>--wetrun</code> re-plans against the live machine and
					refuses unless the hash matches the plan you saw; on a terminal, when the plan isn't the
					reviewed one, it shows you the plan and asks for the start of its hash first.
				</li>
				<li>
					<strong>Unknown means hold.</strong> A resource Zap can't read is left out of the plan and
					reported, exit 1. It never reads as “converged” because a probe failed.
				</li>
				<li>
					<strong>Every run reads the live machine.</strong> No detection cache, no stored copy of
					the machine. Firewall rules, SSH keys, sudoers, and database auth are read live, because
					they're what gets changed by hand.
				</li>
				<li>
					<strong>Apply checks its own work.</strong> After acting, Zap reads the machine again and
					fails on anything that didn't converge. A reload a failed run owed is remembered on the
					host and re-fired.
				</li>
				<li>
					<strong>The config can only describe.</strong> Secrets are <code>zap.env('NAME')</code>
					references, resolved when Zap acts and masked everywhere else.
				</li>
			</ul>
		</div>
	</section>

	<section class="box width_atmost_md">
		<div class="panel p_xl box width:100%">
			<h2 class="mt_0">what Zap is not</h2>
			<ul class="width:100%">
				<li><strong>not a cloud provisioner</strong> — no VPCs or DNS; pair it with OpenTofu.</li>
				<li><strong>not an orchestrator</strong> — no branching on mid-run results.</li>
				<li><strong>not a fleet tool</strong> — one host per config, resources in order.</li>
				<li><strong>not an agent platform</strong> — nothing runs on the host between runs.</li>
			</ul>
			<p class="text_70">
				How it compares to Ansible, pyinfra, Terraform, Pulumi, NixOS, Puppet, and Kamal, with
				tables: <a href={resolve('/docs/comparison')}>comparison</a>.
			</p>
		</div>
	</section>
</main>

<style>
	main {
		display: flex;
		flex-direction: column;
		align-items: center;
		margin: 0 auto;
	}
	.glyph {
		color: #f4672f;
	}
	ol,
	ul {
		text-align: left;
	}
	li {
		margin-bottom: var(--space_sm);
	}
</style>
