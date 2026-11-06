import{G as e,Q as t,W as n,X as r,Y as i,at as a,dt as o,j as s,k as c,l,m as u,ot as d,q as f,ut as p}from"./BTZoVLbz.js";import{t as m}from"./Cyt8LZpN.js";import{n as h}from"./DhdQKFKC.js";import"./BPVwp-J3.js";import{t as g}from"./B2l94Waq.js";import{t as _}from"./BTlkJFeB.js";import{t as v}from"./D23yn-ZR.js";var y=s(`<p>Zap sets up and ships to Linux machines you own, from a TypeScript file.</p><p>You have a few Linux machines, and each one has to be set up a particular way
and kept that way as its needs change. With Zap you declare what should be true
of a machine: these packages installed, this file with this content, this user
with these SSH keys, this service running, this firewall. Zap reads the machine,
shows you exactly what it would change, and changes nothing until you pass <code>--wetrun</code>. Run it again tomorrow and it touches only what drifted. The same
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
then refuses unless the plan matches the one you saw, by hash; on a
terminal, when the plan isn't the reviewed one, it shows you the plan and asks first.</li><li><strong>Unknown means hold, not guess.</strong> A resource Zap can't read is left out of
the plan and reported as undetermined, with exit 1. It never reads as
"converged" because a probe failed. (A few kinds whose create step is
idempotent read a failed probe as <code>absent</code>; see <a>detection.md</a>.)</li><li><strong>Every run reads the live machine.</strong> No detection cache, no stored copy of the machine. The
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
come up first.</p><h2>Where next</h2><ul><li><a>install.md</a>, then <a>getting-started.md</a></li><li><a>concepts.md</a>: the model, in one page</li><li><a>configs.md</a>: writing <code>zap.ts</code></li><li><a>cli.md</a>: every command and exit code</li></ul>`,1);function b(s,b){d(b,!0);let x=h(`introduction`);u(`1tljqsr`,e=>{n(()=>{f.title=`Introduction — zap`})}),g(s,{get tome(){return x},children:(n,a)=>{v(n,{children:(n,a)=>{var s=y(),u=t(r(s),3),d=t(i(u),5);p(),o(u);var f=t(u);l(f,`id`,`who-its-for`);var h=t(f,2);l(h,`id`,`what-a-run-looks-like`);var g=t(h);_(g,{lang:`ts`,dangerous_raw_html:`<span class="token_comment">// zap.ts</span>
<span class="token_special_keyword">export</span> <span class="token_special_keyword">default</span> <span class="token_punctuation">(</span>zap<span class="token_punctuation">)</span> <span class="token_operator">=></span> <span class="token_punctuation">{</span>
	zap<span class="token_punctuation">.</span><span class="token_function">target</span><span class="token_punctuation">({</span>local<span class="token_operator">:</span> <span class="token_boolean">true</span><span class="token_punctuation">,</span> package_manager<span class="token_operator">:</span> <span class="token_string">'apt'</span><span class="token_punctuation">,</span> service_manager<span class="token_operator">:</span> <span class="token_string">'systemd'</span><span class="token_punctuation">});</span>
	zap<span class="token_punctuation">.</span><span class="token_function">pkg</span><span class="token_punctuation">({</span>id<span class="token_operator">:</span> <span class="token_string">'ripgrep'</span><span class="token_punctuation">,</span> <span class="token_special_keyword">from</span><span class="token_operator">:</span> <span class="token_punctuation">{</span>apt<span class="token_operator">:</span> <span class="token_string">'ripgrep'</span><span class="token_punctuation">}});</span>
	zap<span class="token_punctuation">.</span><span class="token_function">file</span><span class="token_punctuation">({</span>
		id<span class="token_operator">:</span> <span class="token_string">'gitconfig'</span><span class="token_punctuation">,</span>
		path<span class="token_operator">:</span> <span class="token_string">'~/.gitconfig'</span><span class="token_punctuation">,</span>
		content<span class="token_operator">:</span> <span class="token_punctuation">{</span>type<span class="token_operator">:</span> <span class="token_string">'inline'</span><span class="token_punctuation">,</span> content<span class="token_operator">:</span> <span class="token_string">'[user]\\n\\tname = Ada\\n'</span><span class="token_punctuation">},</span>
	<span class="token_punctuation">});</span>
<span class="token_punctuation">};</span>`});var v=t(g);_(v,{lang:null,content:`$ zap apply
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
  ok    cache-update-apt
  ok    gitconfig
  ok    ripgrep
applied: 3 ok, 0 failed, 0 skipped (of 3)
plan_hash: d317a15e82f2f1117f0d9fa1fdafc079b70f9e3ac5e3103c4b3333f1b6afeab0`});var b=t(v,2),x=t(i(b));p(),o(b);var S=t(b);l(S,`id`,`what-zap-does-differently`);var C=t(S),w=t(i(C)),T=t(i(w),4);p(),o(w),p(3),o(C);var E=t(C,2);l(E,`id`,`what-zap-converges`);var D=t(E,2),O=t(i(D));p(),o(D);var k=t(D,2);l(k,`id`,`what-zap-is-not`);var A=t(k,2),j=t(i(A));p(),o(A);var M=t(A);l(M,`id`,`status`);var N=t(M),P=t(i(N)),F=t(P,2);p(),o(N);var I=t(N);l(I,`id`,`where-next`);var L=t(I),R=i(L),z=i(R),B=t(z,2);o(R);var V=t(R),H=i(V);p(),o(V);var U=t(V),W=i(U);p(2),o(U);var G=t(U),K=i(G);p(),o(G),o(L),e((e,t,n,r,i,a,o,s,c,u,f,p)=>{l(d,`href`,e),l(x,`href`,t),l(T,`href`,n),l(O,`href`,r),l(j,`href`,i),l(P,`href`,a),l(F,`href`,o),l(z,`href`,s),l(B,`href`,c),l(H,`href`,u),l(W,`href`,f),l(K,`href`,p)},[()=>m(`docs/install`),()=>m(`docs/getting-started`),()=>m(`docs/detection#kinds-that-read-a-failed-probe-as-absent`),()=>m(`docs/resources`),()=>m(`docs/comparison`),()=>m(`docs/security`),()=>m(`docs/faq`),()=>m(`docs/install`),()=>m(`docs/getting-started`),()=>m(`docs/concepts`),()=>m(`docs/configs`),()=>m(`docs/cli`)]),c(n,s)},$$slots:{default:!0}})},$$slots:{default:!0}}),a()}export{b as t};