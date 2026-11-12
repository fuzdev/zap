import{$ as e,E as t,G as n,J as r,K as i,Q as a,X as o,dt as s,ft as c,j as l,k as u,l as d,m as f,ot as p,st as m,v as h,z as g}from"../chunks/CkSeWg2M.js";import{t as _}from"../chunks/CJ6hHGax.js";import{t as v}from"../chunks/Cyt8LZpN.js";import"../chunks/BPVwp-J3.js";import{t as y}from"../chunks/DhAL6k45.js";import{t as b}from"../chunks/DH_LefOd.js";var x=l(`<li class="svelte-1uha8ag"><strong> </strong> </li>`),S=l(`<main class="svelte-1uha8ag"><section class="box"><header class="box pt_xl"><!> <h1 class="mt_xl2">zap <span class="glyph svelte-1uha8ag">↯</span></h1></header> <p class="font_size_lg text-align:center width_atmost_sm">Set up and ship to Linux machines you own, from a TypeScript file. Zap reads the machine,
			shows you the diff, and changes nothing until you say <code>--wetrun</code>.</p> <p class="text-align:center width_atmost_sm text_70">Convergent machine-state management: a Rust binary and Gro's sandboxed runtime, no agent, no
			server, no state backend. Over SSH or on your own laptop. Debian/Ubuntu and Alpine. Pre-alpha.</p> <div class="row gap_md"><a class="panel px_xl py_md font_size_lg">introduction</a> <a class="panel px_xl py_md font_size_lg">getting started</a> <a class="panel px_xl py_md font_size_lg">docs</a></div></section> <section class="box width_atmost_md"><div class="panel p_xl box width:100%"><h2 class="mt_0">a config, a run</h2> <p>A <code>zap.ts</code> is a function that declares a target and resources. It runs in a
				sandbox with no network, no writes, no environment, no clock, and emits a JSON declaration;
				the engine does the rest.</p> <!> <!> <p class="text_70">Point the target at a host instead and the same config converges a server over SSH.</p></div></section> <section class="box width_atmost_md"><div class="panel p_xl box width:100%"><h2 class="mt_0">provision, then ship</h2> <p><code>zap apply</code> converges the host: packages, files, users, services with restart
				triggers, PostgreSQL, swap, a firewall, from-source builds pinned to their source. <code>zap deploy</code> then ships your app to it as a versioned release with an atomic
				swap, a health gate, and rollback, and refuses to ship onto a host that has drifted. The
				shipped <a>recipes</a> carry the standard pieces: SSH
				hardening, a hardened systemd or OpenRC unit, an nginx site with a CSP, certbot, fail2ban.</p></div></section> <section class="box width_atmost_md"><div class="panel p_xl box width:100%"><h2 class="mt_0">the loop</h2> <ol class="width:100% svelte-1uha8ag"></ol></div></section> <section class="box width_atmost_md"><div class="panel p_xl box width:100%"><h2 class="mt_0">what it does differently</h2> <ul class="width:100% svelte-1uha8ag"><li class="svelte-1uha8ag"><strong>A wetrun executes only the plan you reviewed.</strong> Dry run is the default,
					with no flag to auto-approve. <code>--wetrun</code> re-plans against the live machine and
					refuses unless the hash matches the plan you saw; on a terminal, when the plan isn't the
					reviewed one, it shows you the plan and asks for the start of its hash first.</li> <li class="svelte-1uha8ag"><strong>Unknown means hold.</strong> A resource Zap can't read is left out of the plan and
					reported, exit 1. It never reads as “converged” because a probe failed.</li> <li class="svelte-1uha8ag"><strong>Every run reads the live machine.</strong> No detection cache, no stored copy of
					the machine. Firewall rules, SSH keys, sudoers, and database auth are read live, because
					they're what gets changed by hand.</li> <li class="svelte-1uha8ag"><strong>Apply checks its own work.</strong> After acting, Zap reads the machine again and
					fails on anything that didn't converge. A reload a failed run owed is remembered on the
					host and re-fired.</li> <li class="svelte-1uha8ag"><strong>The config can only describe.</strong> Secrets are <code>zap.env('NAME')</code> references, resolved when Zap acts and masked everywhere else.</li></ul></div></section> <section class="box width_atmost_md"><div class="panel p_xl box width:100%"><h2 class="mt_0">what Zap is not</h2> <ul class="width:100% svelte-1uha8ag"><li class="svelte-1uha8ag"><strong>not a cloud provisioner</strong> — no VPCs or DNS; pair it with OpenTofu.</li> <li class="svelte-1uha8ag"><strong>not an orchestrator</strong> — no branching on mid-run results.</li> <li class="svelte-1uha8ag"><strong>not a fleet tool</strong> — one host per config, resources in order.</li> <li class="svelte-1uha8ag"><strong>not an agent platform</strong> — nothing runs on the host between runs.</li></ul> <p class="text_70">How it compares to Ansible, pyinfra, Terraform, Pulumi, NixOS, Puppet, and Kamal, with
				tables: <a>comparison</a>.</p></div></section></main>`);function C(l,C){m(C,!0);let w=[{name:`describe`,text:`declare what should be true of the machine, in TypeScript`},{name:`detect`,text:`read what the machine looks like now, live, every run`},{name:`plan`,text:`the difference, with a hash — the dry run`},{name:`apply`,text:`change only that difference, and only the plan you reviewed`},{name:`observe`,text:`read the machine again; typed events, not log soup`}];var T=S();f(`1uha8ag`,e=>{n(()=>{r.title=`zap — set up and ship to Linux machines from TypeScript`})});var E=o(T),D=o(E),O=o(D);y(O,{get data(){return _},size:`var(--icon_size_xl)`}),s(2),c(D);var k=e(D,6),A=o(k),j=e(A,2),M=e(j,2);c(k),c(E);var N=e(E,2),P=o(N),F=e(o(P),4);b(F,{dangerous_raw_html:`<span class="token_comment">// zap.ts</span>
<span class="token_special_keyword">export</span> <span class="token_special_keyword">default</span> <span class="token_punctuation">(</span>zap<span class="token_punctuation">)</span> <span class="token_operator">=></span> <span class="token_punctuation">{</span>
	zap<span class="token_punctuation">.</span><span class="token_function">target</span><span class="token_punctuation">({</span>local<span class="token_operator">:</span> <span class="token_boolean">true</span><span class="token_punctuation">,</span> package_manager<span class="token_operator">:</span> <span class="token_string">'apt'</span><span class="token_punctuation">,</span> service_manager<span class="token_operator">:</span> <span class="token_string">'systemd'</span><span class="token_punctuation">});</span>
	zap<span class="token_punctuation">.</span><span class="token_function">pkg</span><span class="token_punctuation">({</span>id<span class="token_operator">:</span> <span class="token_string">'ripgrep'</span><span class="token_punctuation">,</span> <span class="token_special_keyword">from</span><span class="token_operator">:</span> <span class="token_punctuation">{</span>apt<span class="token_operator">:</span> <span class="token_string">'ripgrep'</span><span class="token_punctuation">}});</span>
	zap<span class="token_punctuation">.</span><span class="token_function">file</span><span class="token_punctuation">({</span>
		id<span class="token_operator">:</span> <span class="token_string">'gitconfig'</span><span class="token_punctuation">,</span>
		path<span class="token_operator">:</span> <span class="token_string">'~/.gitconfig'</span><span class="token_punctuation">,</span>
		content<span class="token_operator">:</span> <span class="token_punctuation">{</span>type<span class="token_operator">:</span> <span class="token_string">'inline'</span><span class="token_punctuation">,</span> content<span class="token_operator">:</span> <span class="token_string">'[user]\\n\\tname = Ada\\n'</span><span class="token_punctuation">},</span>
	<span class="token_punctuation">});</span>
<span class="token_punctuation">};</span>
`,lang:`ts`});var I=e(F,2);b(I,{dangerous_raw_html:`$ zap apply
apply — target local (dry-run)
  user: ada
  home: /home/ada
  target: <span class="token_svelte_expression"><span class="token_punctuation">{</span><span class="token_lang_ts"><span class="token_string">"local"</span><span class="token_operator">:</span><span class="token_boolean">true</span><span class="token_punctuation">,</span><span class="token_string_property token_property">"package_manager"</span><span class="token_operator">:</span><span class="token_string">"apt"</span><span class="token_punctuation">,</span><span class="token_string_property token_property">"service_manager"</span><span class="token_operator">:</span><span class="token_string">"systemd"</span></span><span class="token_punctuation">}</span></span>
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
  target: <span class="token_svelte_expression"><span class="token_punctuation">{</span><span class="token_lang_ts"><span class="token_string">"local"</span><span class="token_operator">:</span><span class="token_boolean">true</span><span class="token_punctuation">,</span><span class="token_string_property token_property">"package_manager"</span><span class="token_operator">:</span><span class="token_string">"apt"</span><span class="token_punctuation">,</span><span class="token_string_property token_property">"service_manager"</span><span class="token_operator">:</span><span class="token_string">"systemd"</span></span><span class="token_punctuation">}</span></span>
  ok    cache-update-apt  2.8s
  ok    gitconfig         0.0s
  ok    ripgrep           3.1s
applied: 3 ok, 0 failed, 0 skipped (of 3)
converged local in 6.4s, the re-detect included
plan_hash: d317a15e82f2f1117f0d9fa1fdafc079b70f9e3ac5e3103c4b3333f1b6afeab0
`}),s(2),c(P),c(N);var L=e(N,2),R=o(L),z=e(o(R),2),B=e(o(z),4);s(),c(z),c(R),c(L);var V=e(L,2),H=o(V),U=e(o(H),2);h(U,21,()=>w,e=>e.name,(n,r)=>{var s=x(),l=o(s),d=a(l,!0),f=e(l);c(s),i(()=>{t(d,g(r).name),t(f,` — ${g(r).text??``}`)}),u(n,s)}),c(U),c(H),c(V);var W=e(V,4),G=o(W),K=e(o(G),4),q=e(o(K));s(),c(K),c(G),c(W),c(T),i((e,t,n,r,i)=>{d(A,`href`,e),d(j,`href`,t),d(M,`href`,n),d(B,`href`,r),d(q,`href`,i)},[()=>v(`/docs/introduction`),()=>v(`/docs/getting-started`),()=>v(`/docs`),()=>v(`/docs/recipes`),()=>v(`/docs/comparison`)]),u(l,T),p()}export{C as component};