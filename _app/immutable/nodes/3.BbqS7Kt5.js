import{$ as e,B as t,E as n,K as r,Y as i,Z as a,ct as o,et as s,j as c,k as l,l as u,lt as d,m as f,mt as p,pt as m,q as h,v as g}from"../chunks/DGWDGHf_.js";import"../chunks/CMLJYHjj.js";import{t as _}from"../chunks/hWJyV7ZK.js";import{t as v}from"../chunks/BAFjihPA.js";import{t as y}from"../chunks/DCLBpiTL.js";import{t as b}from"../chunks/CJ6hHGax.js";var x=c(`<li class="svelte-1uha8ag"><strong> </strong> </li>`),S=c(`<main class="svelte-1uha8ag"><section class="box"><header class="box pt_xl"><!> <h1 class="mt_xl2">zap <span class="glyph svelte-1uha8ag">↯</span></h1></header> <p class="font_size_lg text-align:center width_atmost_sm">Set up and ship to Linux machines you own, from a TypeScript file. Zap reads the machine,
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
				tables: <a>comparison</a>.</p></div></section></main>`);function C(c,C){d(C,!0);let w=[{name:`describe`,text:`declare what should be true of the machine, in TypeScript`},{name:`detect`,text:`read what the machine looks like now, live, every run`},{name:`plan`,text:`the difference, with a hash — the dry run`},{name:`apply`,text:`change only that difference, and only the plan you reviewed`},{name:`observe`,text:`read the machine again; typed events, not log soup`}];var T=S();f(`1uha8ag`,e=>{r(()=>{i.title=`zap — set up and ship to Linux machines from TypeScript`})});var E=a(T),D=a(E),O=a(D);v(O,{get data(){return b},size:`var(--icon_size_xl)`}),m(2),p(D);var k=s(D,6),A=a(k),j=s(A,2),M=s(j,2);p(k),p(E);var N=s(E,2),P=a(N),F=s(a(P),4);y(F,{dangerous_raw_html:`<span class="token_comment">// zap.ts</span>
<span class="token_special_keyword">export</span> <span class="token_special_keyword">default</span> <span class="token_punctuation">(</span>zap<span class="token_punctuation">)</span> <span class="token_operator">=></span> <span class="token_punctuation">{</span>
	zap<span class="token_punctuation">.</span><span class="token_function">target</span><span class="token_punctuation">({</span>local<span class="token_operator">:</span> <span class="token_boolean">true</span><span class="token_punctuation">,</span> package_manager<span class="token_operator">:</span> <span class="token_string">'apt'</span><span class="token_punctuation">,</span> service_manager<span class="token_operator">:</span> <span class="token_string">'systemd'</span><span class="token_punctuation">});</span>
	zap<span class="token_punctuation">.</span><span class="token_function">pkg</span><span class="token_punctuation">({</span>id<span class="token_operator">:</span> <span class="token_string">'ripgrep'</span><span class="token_punctuation">,</span> <span class="token_special_keyword">from</span><span class="token_operator">:</span> <span class="token_punctuation">{</span>apt<span class="token_operator">:</span> <span class="token_string">'ripgrep'</span><span class="token_punctuation">}});</span>
	zap<span class="token_punctuation">.</span><span class="token_function">file</span><span class="token_punctuation">({</span>
		id<span class="token_operator">:</span> <span class="token_string">'gitconfig'</span><span class="token_punctuation">,</span>
		path<span class="token_operator">:</span> <span class="token_string">'~/.gitconfig'</span><span class="token_punctuation">,</span>
		content<span class="token_operator">:</span> <span class="token_punctuation">{</span>type<span class="token_operator">:</span> <span class="token_string">'inline'</span><span class="token_punctuation">,</span> content<span class="token_operator">:</span> <span class="token_string">'[user]\\n\\tname = Ada\\n'</span><span class="token_punctuation">},</span>
	<span class="token_punctuation">});</span>
<span class="token_punctuation">};</span>
`,lang:`ts`});var I=s(F,2);y(I,{dangerous_raw_html:`$ zap apply
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
`}),m(2),p(P),p(N);var L=s(N,2),R=a(L),z=s(a(R),2),B=s(a(z),4);m(),p(z),p(R),p(L);var V=s(L,2),H=a(V),U=s(a(H),2);g(U,21,()=>w,e=>e.name,(r,i)=>{var o=x(),c=a(o),u=e(c,!0),d=s(c);p(o),h(()=>{n(u,t(i).name),n(d,` — ${t(i).text??``}`)}),l(r,o)}),p(U),p(H),p(V);var W=s(V,4),G=a(W),K=s(a(G),4),q=s(a(K));m(),p(K),p(G),p(W),p(T),h((e,t,n,r,i)=>{u(A,`href`,e),u(j,`href`,t),u(M,`href`,n),u(B,`href`,r),u(q,`href`,i)},[()=>_(`/docs/introduction`),()=>_(`/docs/getting-started`),()=>_(`/docs`),()=>_(`/docs/recipes`),()=>_(`/docs/comparison`)]),l(c,T),o()}export{C as component};