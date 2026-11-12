import{$ as e,G as t,J as n,K as r,X as i,Z as a,dt as o,ft as s,j as c,k as l,l as u,m as d,ot as f,st as p}from"./CkSeWg2M.js";import{t as m}from"./Cyt8LZpN.js";import{n as h}from"./BbCw5KVU.js";import"./BPVwp-J3.js";import{t as g}from"./k6TRNp0w.js";import{t as _}from"./DH_LefOd.js";import{t as v}from"./CtsBFaJL.js";var y=c(`<p>Two walks: your own machine first, then a server over SSH. Each takes a few
minutes. <a>Install</a> Zap and <code>fgro</code> before you start.</p><h2>1. Your own machine</h2><p>Make a directory for the config, give it a <code>package.json</code>, which marks it as the
config's project, and write a <code>zap.ts</code> that manages a directory and a file you
own, so nothing needs <code>sudo</code>:</p><!><!><p>A config is a function. It receives a builder and declares a target and
resources; it returns nothing. Every resource has an <code>id</code> you choose, which is
how other resources and Zap's output refer to it.</p><p><strong>Pin the evaluator.</strong> <code>zap lock</code> records the <code>fgro</code> build that evaluates the
config in <code>zap.lock</code>; every other command that reads the config refuses until it does:</p><!><p><strong>Preview.</strong> <code>zap apply</code> without <code>--wetrun</code> reads the machine and shows what it
would change. It changes nothing, and exits 2 to say changes are pending:</p><!><p><code>[+]</code> is a create, <code>[~]</code> an update, and the lines under each say what the change
declares: a file's content shows as its length and the start of its SHA-512,
never the bytes. The <code>plan_hash</code> names this exact plan. <code>zap plan</code> prints the
same plan with a change count and exits 0: it reports, where <code>apply</code> judges.</p><p><strong>Apply.</strong> Now act:</p><!><p>The <code>→</code> <code>converged</code>. Had anything still read wrong, the report would say <code>RESIDUAL</code> and
exit 1.</p><p>The wetrun went through because your preview a moment ago bound it: a wetrun
executes only the plan you reviewed.</p><p>Had you run <code>zap apply --wetrun</code> first, with no preview behind it, it would
have shown the plan and asked:</p><!><p>Typing <code>5bb79cc9</code> would have run exactly that plan: the answer is the start of a hash
you can only know by looking at the plan. Declined, it changed nothing, exited 2,
and became the preview: running it again executes if nothing moved. Without a
terminal (a script, CI, <code>&lt; /dev/null</code>) the wetrun doesn't ask; it renders the
same plan under a <code>REFUSED</code> <code>--expect-plan &lt;hash></code> binds explicitly. <a>concepts.md</a> </p><p><strong>Status.</strong> <code>zap status</code> tells you what the last run saw, offline:</p><!><p><strong>Again.</strong> Preview once more:</p><!><p>Now edit <code>hello.txt</code> by hand, add a line, and run <code>zap plan --diff</code>: the file
reads <code>[~] hello</code> with <code>~ content: differs → inline (15 bytes)</code>. That is drift,
and <code>zap apply --wetrun</code> would put the declared content back.</p><h3>Add a package</h3><p>Declare the package manager on the target and a package:</p><!><p><code>zap apply</code> now plans two changes: <code>cache-update-apt</code>, the index refresh Zap
puts in front of an install, and the <code>apt-get install -y ripgrep</code> itself, both
run under <code>sudo</code> on the wetrun.
Packages are detected by existence: Zap asks <code>dpkg-query</code> whether <code>ripgrep</code> is
installed, not which version. An entry written <code>name=version</code> pins a version
instead (<a>package names</a>).</p><h3>Add types</h3><p>For completion in your editor, import the builder type (type-only, so the
evaluator needs nothing installed):</p><!><p>See <a>install.md</a> for resolving
the import.</p><h2>2. A server over SSH</h2><p>You need a Debian, Ubuntu, or Alpine host you can reach as a user who has
password-less <code>sudo</code>. On a fresh Debian cloud image the stock user usually
qualifies. On Alpine, as root:</p><!><p>Install your key and check that plain <code>ssh</code> works silently:</p><!><p><strong>The config.</strong> It lives in a project of its own, with a <code>package.json</code> as
before. The host and user are <a>references</a>: they come from your
environment when Zap runs, never from the config file, so the config can be
committed and reused. The user's variable is <code>USER_NAME</code> and not <code>USER</code> on
purpose: your shell already sets <code>USER</code>, so a run that forgot the env file would
connect as your local login name where an unset <code>USER_NAME</code> fails.</p><!><p><strong>The env file.</strong> Put the variables in a file Zap loads with <code>--env-file</code>. Keep
it out of version control; commit a <code>.example</code> instead.</p><!><p><strong>Drive it.</strong></p><!><p>The dry run shows the <code>apt-get update</code> and the <code>apt-get install</code> <code>systemctl enable</code> and <code>start</code>, each with the exact command, and the file it
will write. The wetrun reports <code>4 ok</code>: the three resources plus the index
refresh.</p><p>Edit the probe file on the host, or <code>systemctl stop chrony</code>, and <code>zap plan</code> </p><h2>What to commit</h2><table><thead><tr><th>File</th><th>Commit?</th></tr></thead><tbody><tr><td><code>zap.ts</code></td><td>yes</td></tr><tr><td><code>zap.lock</code></td><td>yes, it records the <code>fgro</code> build and any fetched bytes you approved</td></tr><tr><td><code>zap.env</code> and friends</td><td><strong>no</strong>; commit a <code>.example</code></td></tr><tr><td><code>~/.zap/</code></td><td>no, it's your machine's cache and last-run reports</td></tr></tbody></table><h2>Where to go next</h2><ul><li><strong>A real server.</strong> The <a>recipes</a> carry the standard pieces: SSH
hardening, a hardened systemd or OpenRC service, an nginx site with a CSP, a
firewall, certbot, fail2ban, PostgreSQL. <a>configs.md</a> shows how
to compose them.</li><li><strong>Shipping an app.</strong> <code>zap deploy</code> releases a build to the host you just
converged, with a health gate and rollback: <a>deploy.md</a>.</li><li><strong>A host that locks itself down.</strong> When SSH hardening changes the user Zap
connects as, declare both users and run the first apply with <code>--bootstrap</code> <a>targets.md</a>.</li><li><strong>What every command and exit code means.</strong> <a>cli.md</a>.</li></ul>`,1);function b(c,b){p(b,!0);let x=h(`getting-started`);d(`di86c5`,e=>{t(()=>{n.title=`Getting started — zap`})}),g(c,{get tome(){return x},children:(t,n)=>{v(t,{children:(t,n)=>{var c=y(),d=a(c),f=e(i(d));o(3),s(d);var p=e(d);u(p,`id`,`1-your-own-machine`);var h=e(p,2);_(h,{lang:`json`,dangerous_raw_html:`<span class="token_punctuation">{</span><span class="token_property">"name"</span><span class="token_operator">:</span> <span class="token_string">"infra"</span><span class="token_punctuation">,</span> <span class="token_property">"private"</span><span class="token_operator">:</span> <span class="token_boolean">true</span><span class="token_punctuation">}</span>`});var g=e(h);_(g,{lang:`ts`,dangerous_raw_html:`<span class="token_comment">// zap.ts</span>
<span class="token_special_keyword">export</span> <span class="token_special_keyword">default</span> <span class="token_punctuation">(</span>zap<span class="token_punctuation">)</span> <span class="token_operator">=></span> <span class="token_punctuation">{</span>
	zap<span class="token_punctuation">.</span><span class="token_function">target</span><span class="token_punctuation">({</span>local<span class="token_operator">:</span> <span class="token_boolean">true</span><span class="token_punctuation">});</span>
	zap<span class="token_punctuation">.</span><span class="token_function">directory</span><span class="token_punctuation">({</span>id<span class="token_operator">:</span> <span class="token_string">'notes'</span><span class="token_punctuation">,</span> path<span class="token_operator">:</span> <span class="token_string">'~/notes'</span><span class="token_punctuation">,</span> mode<span class="token_operator">:</span> <span class="token_string">'755'</span><span class="token_punctuation">});</span>
	zap<span class="token_punctuation">.</span><span class="token_function">file</span><span class="token_punctuation">({</span>
		id<span class="token_operator">:</span> <span class="token_string">'hello'</span><span class="token_punctuation">,</span>
		path<span class="token_operator">:</span> <span class="token_string">'~/notes/hello.txt'</span><span class="token_punctuation">,</span>
		content<span class="token_operator">:</span> <span class="token_punctuation">{</span>type<span class="token_operator">:</span> <span class="token_string">'inline'</span><span class="token_punctuation">,</span> content<span class="token_operator">:</span> <span class="token_string">'hello from zap\\n'</span><span class="token_punctuation">},</span>
		depends_on<span class="token_operator">:</span> <span class="token_punctuation">[</span><span class="token_string">'notes'</span><span class="token_punctuation">],</span>
	<span class="token_punctuation">});</span>
<span class="token_punctuation">};</span>`});var v=e(g,3);_(v,{lang:null,content:`$ zap lock
pinned fgro c8a3d0effbcb7ca4540fa9197dfff499c385547b10cff6931644d6450446dcb7
wrote zap.lock (no eligible resources)`});var b=e(v,2);_(b,{lang:null,content:`$ zap apply
apply — target local (dry-run)
  user: ops
  home: /home/ops
  target: {"local":true}
  [+] notes  (directory)
      path: ~/notes
      mode: 755
  [+] hello  (file)
      path: ~/notes/hello.txt
      content: inline (15 bytes, sha512 0c7463f032f1dc98…)
  (dry-run — re-run with --wetrun to apply)
plan_hash: 5bb79cc9141942676c784abba55826f12be51b3feb86f5f0cf77666545674d61
$ echo $?   # $status in fish
2`});var x=e(b,3);_(x,{lang:null,content:`$ zap apply --wetrun
→ notes: create directory
→ hello: create file
→ re-detect: reading 2 declared resources back to confirm what the changes left
apply — target local (wetrun)
  user: ops
  home: /home/ops
  target: {"local":true}
  ok    notes  0.0s
  ok    hello  0.0s
applied: 2 ok, 0 failed, 0 skipped (of 2)
converged local in 0.0s, the re-detect included
plan_hash: 5bb79cc9141942676c784abba55826f12be51b3feb86f5f0cf77666545674d61`});var S=e(x),ee=e(i(S),2);ee.nodeValue=` lines are progress, printed to standard error as each change and the
re-detection start; the report under them is standard output. Each row says how
long its change took. After the changes ran, Zap read both resources again and
found them converged, which is why the exit was 0 and the last line says
`,o(4),s(S);var C=e(S,3);_(C,{lang:null,content:`$ zap apply --wetrun
apply — target local (wetrun, awaiting confirmation)
  …

  UNREVIEWED — nothing has run: this plan runs only once it is confirmed below.
    no plan has been previewed on this host.
plan_hash: 5bb79cc9141942676c784abba55826f12be51b3feb86f5f0cf77666545674d61
Apply this plan? Type 5bb79cc9, the start of its plan_hash, to confirm: n
apply — target local (wetrun, declined)
  …

  DECLINED — nothing ran: this plan was not confirmed.
    no plan has been previewed on this host.
  …`});var w=e(C),T=e(i(w),6);T.nodeValue=` banner and stops the same way.
`;var E=e(T,3),D=e(E);D.nodeValue=`
has the rules.`,s(w);var O=e(w,2);_(O,{lang:null,content:`$ zap status
target local (pkg: none, service: none)
last run on local: zap apply --wetrun, after its changes ran, at 2026-10-11T21:09:26Z — offline; \`zap plan\` reads the target live
  a 0 exit means every declared resource read converged in the last run and its config is unchanged since — not that the target still is
  converged    notes  directory
  converged    hello  file`});var k=e(O,2);_(k,{lang:null,content:`$ zap apply
apply — target local (dry-run)
  user: ops
  home: /home/ops
  target: {"local":true}
  (no changes — converged)
plan_hash: 2d374e262633aebd2273acc69efc3122cff2bdbb6dc36f98d7d4bbc6cde5cb44`});var A=e(k,2);u(A,`id`,`add-a-package`);var j=e(A,2);_(j,{lang:`ts`,dangerous_raw_html:`zap<span class="token_punctuation">.</span><span class="token_function">target</span><span class="token_punctuation">({</span>local<span class="token_operator">:</span> <span class="token_boolean">true</span><span class="token_punctuation">,</span> package_manager<span class="token_operator">:</span> <span class="token_string">'apt'</span><span class="token_punctuation">});</span>
zap<span class="token_punctuation">.</span><span class="token_function">pkg</span><span class="token_punctuation">({</span>id<span class="token_operator">:</span> <span class="token_string">'ripgrep'</span><span class="token_punctuation">,</span> <span class="token_special_keyword">from</span><span class="token_operator">:</span> <span class="token_punctuation">{</span>apt<span class="token_operator">:</span> <span class="token_string">'ripgrep'</span><span class="token_punctuation">}});</span>`});var M=e(j),te=e(i(M),14);o(),s(M);var N=e(M);u(N,`id`,`add-types`);var P=e(N,2);_(P,{lang:`ts`,dangerous_raw_html:`<span class="token_special_keyword">import</span> <span class="token_import_type_keyword token_special_keyword">type</span> <span class="token_punctuation">{</span><span class="token_capitalized_identifier token_class_name">ZapBuilder</span><span class="token_punctuation">}</span> <span class="token_special_keyword">from</span> <span class="token_string">'@fuzdev/zap/zap.ts'</span><span class="token_punctuation">;</span>

<span class="token_special_keyword">export</span> <span class="token_special_keyword">default</span> <span class="token_punctuation">(</span>zap<span class="token_operator">:</span> <span class="token_capitalized_identifier token_class_name">ZapBuilder</span><span class="token_punctuation">)</span> <span class="token_operator">=></span> <span class="token_punctuation">{</span>
	<span class="token_comment">// …</span>
<span class="token_punctuation">};</span>`});var F=e(P),ne=e(i(F));o(),s(F);var I=e(F);u(I,`id`,`2-a-server-over-ssh`);var L=e(I,2);_(L,{lang:`sh`,dangerous_raw_html:`setup-apkrepos -c -f
apk update <span class="token_operator">&amp;&amp;</span> apk add sudo
adduser ops        <span class="token_comment"># skip if the account exists</span>
adduser ops wheel
<span class="token_builtin">echo</span> <span class="token_string">'%wheel ALL=(ALL) NOPASSWD: ALL'</span> <span class="token_operator">></span> /etc/sudoers.d/wheel
chmod <span class="token_number">0440</span> /etc/sudoers.d/wheel`});var R=e(L,2);_(R,{lang:`sh`,dangerous_raw_html:`ssh-copy-id ops@<span class="token_operator">&lt;</span>host<span class="token_operator">></span>
ssh ops@<span class="token_operator">&lt;</span>host<span class="token_operator">></span> <span class="token_boolean">true</span>`});var z=e(R),re=e(i(z),4);o(9),s(z);var B=e(z);_(B,{lang:`ts`,dangerous_raw_html:`<span class="token_comment">// zap.ts</span>
<span class="token_special_keyword">export</span> <span class="token_special_keyword">default</span> <span class="token_punctuation">(</span>zap<span class="token_punctuation">)</span> <span class="token_operator">=></span> <span class="token_punctuation">{</span>
	zap<span class="token_punctuation">.</span><span class="token_function">target</span><span class="token_punctuation">({</span>
		host<span class="token_operator">:</span> zap<span class="token_punctuation">.</span><span class="token_function">env</span><span class="token_punctuation">(</span><span class="token_string">'HOST'</span><span class="token_punctuation">),</span>
		user<span class="token_operator">:</span> zap<span class="token_punctuation">.</span><span class="token_function">env</span><span class="token_punctuation">(</span><span class="token_string">'USER_NAME'</span><span class="token_punctuation">),</span>
		home<span class="token_operator">:</span> <span class="token_string">'/home/ops'</span><span class="token_punctuation">,</span> <span class="token_comment">// that user's home on the host</span>
		package_manager<span class="token_operator">:</span> <span class="token_string">'apt'</span><span class="token_punctuation">,</span> <span class="token_comment">// 'apk' on Alpine</span>
		service_manager<span class="token_operator">:</span> <span class="token_string">'systemd'</span><span class="token_punctuation">,</span> <span class="token_comment">// 'openrc' on Alpine</span>
	<span class="token_punctuation">});</span>
	zap<span class="token_punctuation">.</span><span class="token_function">pkg</span><span class="token_punctuation">({</span>id<span class="token_operator">:</span> <span class="token_string">'chrony'</span><span class="token_punctuation">,</span> <span class="token_special_keyword">from</span><span class="token_operator">:</span> <span class="token_punctuation">{</span>apt<span class="token_operator">:</span> <span class="token_string">'chrony'</span><span class="token_punctuation">,</span> apk<span class="token_operator">:</span> <span class="token_string">'chrony'</span><span class="token_punctuation">}});</span>
	zap<span class="token_punctuation">.</span><span class="token_function">service</span><span class="token_punctuation">({</span>
		id<span class="token_operator">:</span> <span class="token_string">'chronyd'</span><span class="token_punctuation">,</span>
		service<span class="token_operator">:</span> <span class="token_string">'chrony'</span><span class="token_punctuation">,</span> <span class="token_comment">// 'chronyd' on Alpine</span>
		enabled<span class="token_operator">:</span> <span class="token_boolean">true</span><span class="token_punctuation">,</span>
		running<span class="token_operator">:</span> <span class="token_boolean">true</span><span class="token_punctuation">,</span>
		depends_on<span class="token_operator">:</span> <span class="token_punctuation">[</span><span class="token_string">'chrony'</span><span class="token_punctuation">],</span>
	<span class="token_punctuation">});</span>
	zap<span class="token_punctuation">.</span><span class="token_function">file</span><span class="token_punctuation">({</span>
		id<span class="token_operator">:</span> <span class="token_string">'probe'</span><span class="token_punctuation">,</span>
		path<span class="token_operator">:</span> <span class="token_string">'/etc/zap-probe'</span><span class="token_punctuation">,</span>
		content<span class="token_operator">:</span> <span class="token_punctuation">{</span>type<span class="token_operator">:</span> <span class="token_string">'inline'</span><span class="token_punctuation">,</span> content<span class="token_operator">:</span> <span class="token_string">'managed by zap\\n'</span><span class="token_punctuation">},</span>
		mode<span class="token_operator">:</span> <span class="token_string">'644'</span><span class="token_punctuation">,</span>
	<span class="token_punctuation">});</span>
<span class="token_punctuation">};</span>`});var V=e(B,2);_(V,{lang:`sh`,dangerous_raw_html:`<span class="token_comment"># zap.env</span>
HOST=<span class="token_number">203</span>.<span class="token_number">0</span>.<span class="token_number">113</span>.<span class="token_number">10</span>
USER_NAME=ops`});var H=e(V,2);_(H,{lang:`sh`,dangerous_raw_html:`zap lock --env-file zap.env            <span class="token_comment"># pin the evaluator</span>
zap detect --env-file zap.env          <span class="token_comment"># what the host looks like now</span>
zap apply --env-file zap.env           <span class="token_comment"># the plan</span>
zap apply --env-file zap.env --wetrun  <span class="token_comment"># converge</span>
zap apply --env-file zap.env           <span class="token_comment"># idempotency: (no changes — converged)</span>`});var U=e(H),ie=e(i(U),4);ie.nodeValue=`, the
`,o(6),s(U);var W=e(U),ae=e(i(W),4);ae.nodeValue=`
shows the drift. That loop, plan then wetrun, is all of Zap.`,s(W);var G=e(W);u(G,`id`,`what-to-commit`);var K=e(G,2);u(K,`id`,`where-to-go-next`);var q=e(K),J=i(q),Y=e(i(J),2),oe=e(Y,2);o(),s(J);var X=e(J),se=e(i(X),4);o(),s(X);var Z=e(X),Q=e(i(Z),3);Q.nodeValue=`:
`;var ce=e(Q);o(),s(Z);var $=e(Z),le=e(i($),2);o(),s($),s(q),r((e,t,n,r,i,a,o,s,c,l)=>{u(f,`href`,e),u(E,`href`,t),u(te,`href`,n),u(ne,`href`,r),u(re,`href`,i),u(Y,`href`,a),u(oe,`href`,o),u(se,`href`,s),u(ce,`href`,c),u(le,`href`,l)},[()=>m(`docs/install`),()=>m(`docs/concepts#a-wetrun-executes-only-the-plan-you-reviewed`),()=>m(`docs/resources#package-names`),()=>m(`docs/install#types-and-recipes-for-your-config`),()=>m(`docs/env#references`),()=>m(`docs/recipes`),()=>m(`docs/configs`),()=>m(`docs/deploy`),()=>m(`docs/targets#the-bootstrap-user`),()=>m(`docs/cli`)]),l(t,c)},$$slots:{default:!0}})},$$slots:{default:!0}}),f()}export{b as t};