import{K as e,Q as t,Y as n,Z as r,et as i,ht as a,j as o,k as s,l as c,lt as l,m as u,mt as d,q as f,ut as p}from"./qzjbwbTS.js";import{t as m}from"./hWJyV7ZK.js";import{t as h}from"./Bk6YI9cY.js";import{t as g}from"./Bxb5ARkv.js";import{n as _}from"./D7P638yv.js";import{t as v}from"./CBF1pNwD.js";import"./CMLJYHjj.js";var y=o(`<p>Zap sets up and ships to Linux machines you own, from a TypeScript file.</p><p> <code>--wetrun</code>. Run it again tomorrow and it touches only what drifted. The same
tool then ships your app to that machine as a versioned release with a health
check and rollback.</p><p>If you know Terraform, Zap brings its plan-then-apply discipline to the inside
of a machine. If you know a virtual DOM, it works the same way: you describe the
whole result, and it works out the smallest set of changes to get there. Unlike
both, Zap keeps no stored copy of the machine: it diffs against the
machine itself, read fresh on every run, so a change someone made by hand shows
up in the plan.</p><p>Zap is a Rust binary that works over SSH or on the machine it runs on, with no
agent on the host and no server. It evaluates your <code>zap.ts</code> with <code>fgro</code>, Gro's
sandboxed JS runtime (<a>install.md</a>).</p><h2>Who it's for</h2><ul><li><strong>You run a few Linux machines by hand.</strong> A laptop, a VPS or two, a home
server. You want them described in one place and set up the same way every
time, without learning a fleet tool.</li><li><strong>You ship your own services.</strong> A web app behind nginx with PostgreSQL on the
box, deployed as release directories with an atomic swap, where the deploy
refuses to ship onto a host whose config has drifted.</li><li><strong>You let an assistant drive.</strong> An AI agent, or a teammate who isn't an ops
engineer, runs the tool for you. Planning changes nothing, so they can do it
freely; you review the plan, and a wetrun executes only that plan. Every run ends
in an exit code that says what was established, and <code>--json</code> streams a wetrun
as typed events rather than free-form logs.</li></ul><h2>What a run looks like</h2><!><!><p>The <code>cache-update-apt</code> change is the package index refresh Zap puts in front of
an install. The wetrun planned again, got the same <code>plan_hash</code> the dry run
printed, and only then acted. Had the machine changed in between, it would have
shown the new plan and refused it, or, on a terminal, asked before running it.</p><p>Point the target at a host instead and the same config converges a server over
SSH. <a>Getting started</a> walks through both.</p><h2>What Zap does differently</h2><ol><li><strong>A wetrun executes only the plan you reviewed.</strong> Dry run is the default,
with no flag to auto-approve. <code>--wetrun</code> re-plans against the live machine,
then refuses unless the plan matches, by hash, the one you name or the last
preview Zap printed; on a
terminal, when the plan isn't the reviewed one, it shows you the plan and asks first.</li><li><strong>Unknown means hold, not guess.</strong> A resource Zap can't read is left out of
the plan and reported as undetermined, with exit 1. It never reads as
"converged" because a probe failed. (A few kinds whose create step is
idempotent read a failed probe as <code>absent</code> <a>detection.md</a>.)</li><li><strong>Every run reads the live machine.</strong> No detection cache, no stored copy of the machine. The
security controls (firewall rules, SSH keys, sudoers, database auth) are read
live every time, because they are what gets changed by hand.</li><li><strong>Apply checks its own work.</strong> After acting, Zap reads the machine again and
fails the run if anything didn't converge.</li><li><strong>The config can only describe.</strong> <code>zap.ts</code> runs in a sandbox with no network, no
writes, no environment, no clock, and emits a JSON declaration. Secrets are
references, resolved by Zap when it acts and masked everywhere
else.</li></ol><p>Plus: a reload a failed run owed is remembered on the host and re-fired, and
fetched content is pinned by hash in a lock file next to the config.</p><h2>What Zap converges</h2><ul><li><strong>Software</strong>: apt and apk packages, apt repositories, and from-source builds
pinned to their source archive.</li><li><strong>Files</strong>: files (inline, templated, copied, or fetched and pinned),
directories, and symlinks.</li><li><strong>Users</strong>: shell, home mode, SSH keys, sudoers, and groups.</li><li><strong>Services</strong>: systemd and OpenRC, with restart and reload triggers.</li><li><strong>PostgreSQL</strong>: databases and roles, with <code>pg_hba</code> rules.</li><li><strong>System</strong>: swap files and firewalls (ufw, nftables).</li><li><strong>Everything else</strong>: idempotent scripts, installers, assertions, and
pipelines.</li></ul><p>The full reference is <a>resources.md</a>.</p><p>Hosts: <strong>Debian/Ubuntu</strong> and <strong>Alpine</strong>. Zap manages real servers in both
families, and the firewall, user, and database controls are read live on both.</p><h2>What Zap is not</h2><ul><li><strong>Not a cloud provisioner.</strong> No VPCs, load balancers, DNS, or managed
databases, and no provider ecosystem. Zap converges the inside of machines you
already have. Pair it with OpenTofu or Pulumi for the outside.</li><li><strong>Not an orchestrator.</strong> No data-dependent branching mid-run. A <code>script</code>'s
shell can do anything, but Zap doesn't model it.</li><li><strong>Not a fleet tool.</strong> One host per config, resources applied in order. Loop a
shell over configs for a handful of hosts; reach for Ansible or pyinfra for
hundreds.</li><li><strong>Not an agent platform.</strong> Nothing runs on the host between runs.</li><li><strong>Not a remover.</strong> Delete a resource from the config and the thing stays;
Zap reports it as orphaned. Declare removals explicitly.</li><li><strong>Not macOS or Windows.</strong> Zap manages Linux hosts only.</li></ul><p>The full picture, against each alternative: <a>comparison.md</a>.</p><h2>Status</h2><p>Zap is pre-alpha and has one maintainer. It runs the servers of the project it
comes from and the maintainer's own machines. The resource set is small and
fixed, there is no plugin system, and the config schema will change before 1.0
without a compatibility layer. Read <a>security.md</a> before pointing
it at a machine you care about, and <a>faq.md</a> for the questions that
come up first.</p><h2>Where next</h2><ul><li><a>install.md</a>, then <a>getting-started.md</a></li><li><a>concepts.md</a>: the model, in one page</li><li><a>configs.md</a>: writing <code>zap.ts</code></li><li><a>cli.md</a>: every command and exit code</li></ul>`,1);function b(o,b){p(b,!0);let x=_(`introduction`);u(`1tljqsr`,t=>{e(()=>{n.title=`Introduction — zap`})}),g(o,{get tome(){return x},children:(e,n)=>{h(e,{children:(e,n)=>{var o=y(),l=i(t(o)),u=r(l);u.nodeValue=`You have a few Linux machines, and each one has to be set up a particular way
and kept that way as its needs change. With Zap you declare what should be true
of a machine: these packages installed, this file with this content, this user
with these SSH keys, this service running, this firewall. Zap reads the machine,
shows you exactly what it would change, and changes nothing until you pass
`,d(2),a(l);var p=i(l,2),h=i(r(p),5);d(),a(p);var g=i(p);c(g,`id`,`who-its-for`);var _=i(g,2);c(_,`id`,`what-a-run-looks-like`);var b=i(_);v(b,{lang:`ts`,dangerous_raw_html:`<span class="token_comment">// zap.ts</span>
<span class="token_special_keyword">export</span> <span class="token_special_keyword">default</span> <span class="token_punctuation">(</span>zap<span class="token_punctuation">)</span> <span class="token_operator">=></span> <span class="token_punctuation">{</span>
	zap<span class="token_punctuation">.</span><span class="token_function">target</span><span class="token_punctuation">({</span>local<span class="token_operator">:</span> <span class="token_boolean">true</span><span class="token_punctuation">,</span> package_manager<span class="token_operator">:</span> <span class="token_string">'apt'</span><span class="token_punctuation">,</span> service_manager<span class="token_operator">:</span> <span class="token_string">'systemd'</span><span class="token_punctuation">});</span>
	zap<span class="token_punctuation">.</span><span class="token_function">pkg</span><span class="token_punctuation">({</span>id<span class="token_operator">:</span> <span class="token_string">'ripgrep'</span><span class="token_punctuation">,</span> <span class="token_special_keyword">from</span><span class="token_operator">:</span> <span class="token_punctuation">{</span>apt<span class="token_operator">:</span> <span class="token_string">'ripgrep'</span><span class="token_punctuation">}});</span>
	zap<span class="token_punctuation">.</span><span class="token_function">file</span><span class="token_punctuation">({</span>
		id<span class="token_operator">:</span> <span class="token_string">'gitconfig'</span><span class="token_punctuation">,</span>
		path<span class="token_operator">:</span> <span class="token_string">'~/.gitconfig'</span><span class="token_punctuation">,</span>
		content<span class="token_operator">:</span> <span class="token_punctuation">{</span>type<span class="token_operator">:</span> <span class="token_string">'inline'</span><span class="token_punctuation">,</span> content<span class="token_operator">:</span> <span class="token_string">'[user]\\n\\tname = Ada\\n'</span><span class="token_punctuation">},</span>
	<span class="token_punctuation">});</span>
<span class="token_punctuation">};</span>`});var x=i(b);v(x,{lang:null,content:`$ zap apply
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
→ cache-update-apt: create script
→ gitconfig: create file
→ ripgrep: create package
→ re-detect: reading 2 declared resources back to confirm what the changes left
apply — target local (wetrun)
  user: ada
  home: /home/ada
  target: {"local":true,"package_manager":"apt","service_manager":"systemd"}
  ok    cache-update-apt  2.8s
  ok    gitconfig         0.0s
  ok    ripgrep           3.1s
applied: 3 ok, 0 failed, 0 skipped (of 3)
converged local in 6.4s, the re-detect included
plan_hash: d317a15e82f2f1117f0d9fa1fdafc079b70f9e3ac5e3103c4b3333f1b6afeab0`});var S=i(x,2),C=i(r(S));d(),a(S);var w=i(S);c(w,`id`,`what-zap-does-differently`);var T=i(w),E=i(r(T)),D=i(r(E),3);D.nodeValue=`; see
`;var O=i(D);d(),a(E),d(3),a(T);var k=i(T,2);c(k,`id`,`what-zap-converges`);var A=i(k,2),j=i(r(A));d(),a(A);var M=i(A,2);c(M,`id`,`what-zap-is-not`);var N=i(M,2),P=i(r(N));d(),a(N);var F=i(N);c(F,`id`,`status`);var I=i(F),L=i(r(I)),R=i(L,2);d(),a(I);var z=i(I);c(z,`id`,`where-next`);var B=i(z),V=r(B),H=r(V),U=i(H,2);a(V);var W=i(V),G=r(W);d(),a(W);var K=i(W),q=r(K);d(2),a(K);var J=i(K),Y=r(J);d(),a(J),a(B),f((e,t,n,r,i,a,o,s,l,u,d,f)=>{c(h,`href`,e),c(C,`href`,t),c(O,`href`,n),c(j,`href`,r),c(P,`href`,i),c(L,`href`,a),c(R,`href`,o),c(H,`href`,s),c(U,`href`,l),c(G,`href`,u),c(q,`href`,d),c(Y,`href`,f)},[()=>m(`docs/install`),()=>m(`docs/getting-started`),()=>m(`docs/detection#kinds-that-read-a-failed-probe-as-absent`),()=>m(`docs/resources`),()=>m(`docs/comparison`),()=>m(`docs/security`),()=>m(`docs/faq`),()=>m(`docs/install`),()=>m(`docs/getting-started`),()=>m(`docs/concepts`),()=>m(`docs/configs`),()=>m(`docs/cli`)]),s(e,o)},$$slots:{default:!0}})},$$slots:{default:!0}}),l()}export{b as t};