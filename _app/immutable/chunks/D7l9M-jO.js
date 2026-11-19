import{K as e,Q as t,Y as n,Z as r,ct as i,et as a,j as o,k as s,l as c,lt as l,m as u,mt as d,pt as f,q as ee}from"./DGWDGHf_.js";import{t as p}from"./hWJyV7ZK.js";import{t as m}from"./xlPESoVd.js";import{t as h}from"./B0EoXBDb.js";import{n as g}from"./BkOGAUkd.js";import{t as _}from"./DCLBpiTL.js";import"./CMLJYHjj.js";var v=o(`<p>Two walks: your own machine first, then a server over SSH. Each takes a few
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
connects as, declare both users and run the first apply with <code>--bootstrap</code> <a>targets.md</a>.</li><li><strong>What every command and exit code means.</strong> <a>cli.md</a>.</li></ul>`,1);function y(o,y){l(y,!0);let b=g(`getting-started`);u(`di86c5`,t=>{e(()=>{n.title=`Getting started — zap`})}),h(o,{get tome(){return b},children:(e,n)=>{m(e,{children:(e,n)=>{var i=v(),o=t(i),l=a(r(o));f(3),d(o);var u=a(o);c(u,`id`,`1-your-own-machine`);var m=a(u,2);_(m,{lang:`json`,dangerous_raw_html:`<span class="token_punctuation">{</span><span class="token_property">"name"</span><span class="token_operator">:</span> <span class="token_string">"infra"</span><span class="token_punctuation">,</span> <span class="token_property">"private"</span><span class="token_operator">:</span> <span class="token_boolean">true</span><span class="token_punctuation">}</span>`});var h=a(m);_(h,{lang:`ts`,dangerous_raw_html:`<span class="token_comment">// zap.ts</span>
<span class="token_special_keyword">export</span> <span class="token_special_keyword">default</span> <span class="token_punctuation">(</span>zap<span class="token_punctuation">)</span> <span class="token_operator">=></span> <span class="token_punctuation">{</span>
	zap<span class="token_punctuation">.</span><span class="token_function">target</span><span class="token_punctuation">({</span>local<span class="token_operator">:</span> <span class="token_boolean">true</span><span class="token_punctuation">});</span>
	zap<span class="token_punctuation">.</span><span class="token_function">directory</span><span class="token_punctuation">({</span>id<span class="token_operator">:</span> <span class="token_string">'notes'</span><span class="token_punctuation">,</span> path<span class="token_operator">:</span> <span class="token_string">'~/notes'</span><span class="token_punctuation">,</span> mode<span class="token_operator">:</span> <span class="token_string">'755'</span><span class="token_punctuation">});</span>
	zap<span class="token_punctuation">.</span><span class="token_function">file</span><span class="token_punctuation">({</span>
		id<span class="token_operator">:</span> <span class="token_string">'hello'</span><span class="token_punctuation">,</span>
		path<span class="token_operator">:</span> <span class="token_string">'~/notes/hello.txt'</span><span class="token_punctuation">,</span>
		content<span class="token_operator">:</span> <span class="token_punctuation">{</span>type<span class="token_operator">:</span> <span class="token_string">'inline'</span><span class="token_punctuation">,</span> content<span class="token_operator">:</span> <span class="token_string">'hello from zap\\n'</span><span class="token_punctuation">},</span>
		depends_on<span class="token_operator">:</span> <span class="token_punctuation">[</span><span class="token_string">'notes'</span><span class="token_punctuation">],</span>
	<span class="token_punctuation">});</span>
<span class="token_punctuation">};</span>`});var g=a(h,3);_(g,{lang:null,content:`$ zap lock
pinned fgro c8a3d0effbcb7ca4540fa9197dfff499c385547b10cff6931644d6450446dcb7
wrote zap.lock (no eligible resources)`});var y=a(g,2);_(y,{lang:null,content:`$ zap apply
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
2`});var b=a(y,3);_(b,{lang:null,content:`$ zap apply --wetrun
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
plan_hash: 5bb79cc9141942676c784abba55826f12be51b3feb86f5f0cf77666545674d61`});var x=a(b),te=a(r(x),2);te.nodeValue=` lines are progress, printed to standard error as each change and the
re-detection start; the report under them is standard output. Each row says how
long its change took. After the changes ran, Zap read both resources again and
found them converged, which is why the exit was 0 and the last line says
`,f(4),d(x);var S=a(x,3);_(S,{lang:null,content:`$ zap apply --wetrun
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
  …`});var C=a(S),w=a(r(C),6);w.nodeValue=` banner and stops the same way.
`;var T=a(w,3),E=a(T);E.nodeValue=`
has the rules.`,d(C);var D=a(C,2);_(D,{lang:null,content:`$ zap status
target local (pkg: none, service: none)
last run on local: zap apply --wetrun, after its changes ran, at 2026-10-11T21:09:26Z — offline; \`zap plan\` reads the target live
  a 0 exit means every declared resource read converged in the last run and its config is unchanged since — not that the target still is
  converged    notes  directory
  converged    hello  file`});var O=a(D,2);_(O,{lang:null,content:`$ zap apply
apply — target local (dry-run)
  user: ops
  home: /home/ops
  target: {"local":true}
  (no changes — converged)
plan_hash: 2d374e262633aebd2273acc69efc3122cff2bdbb6dc36f98d7d4bbc6cde5cb44`});var k=a(O,2);c(k,`id`,`add-a-package`);var A=a(k,2);_(A,{lang:`ts`,dangerous_raw_html:`zap<span class="token_punctuation">.</span><span class="token_function">target</span><span class="token_punctuation">({</span>local<span class="token_operator">:</span> <span class="token_boolean">true</span><span class="token_punctuation">,</span> package_manager<span class="token_operator">:</span> <span class="token_string">'apt'</span><span class="token_punctuation">});</span>
zap<span class="token_punctuation">.</span><span class="token_function">pkg</span><span class="token_punctuation">({</span>id<span class="token_operator">:</span> <span class="token_string">'ripgrep'</span><span class="token_punctuation">,</span> <span class="token_special_keyword">from</span><span class="token_operator">:</span> <span class="token_punctuation">{</span>apt<span class="token_operator">:</span> <span class="token_string">'ripgrep'</span><span class="token_punctuation">}});</span>`});var j=a(A),M=a(r(j),14);f(),d(j);var N=a(j);c(N,`id`,`add-types`);var P=a(N,2);_(P,{lang:`ts`,dangerous_raw_html:`<span class="token_special_keyword">import</span> <span class="token_import_type_keyword token_special_keyword">type</span> <span class="token_punctuation">{</span><span class="token_capitalized_identifier token_class_name">ZapBuilder</span><span class="token_punctuation">}</span> <span class="token_special_keyword">from</span> <span class="token_string">'@fuzdev/zap/zap.ts'</span><span class="token_punctuation">;</span>

<span class="token_special_keyword">export</span> <span class="token_special_keyword">default</span> <span class="token_punctuation">(</span>zap<span class="token_operator">:</span> <span class="token_capitalized_identifier token_class_name">ZapBuilder</span><span class="token_punctuation">)</span> <span class="token_operator">=></span> <span class="token_punctuation">{</span>
	<span class="token_comment">// …</span>
<span class="token_punctuation">};</span>`});var F=a(P),ne=a(r(F));f(),d(F);var I=a(F);c(I,`id`,`2-a-server-over-ssh`);var L=a(I,2);_(L,{lang:`sh`,dangerous_raw_html:`setup-apkrepos -c -f
apk update <span class="token_operator">&amp;&amp;</span> apk add sudo
adduser ops        <span class="token_comment"># skip if the account exists</span>
adduser ops wheel
<span class="token_builtin">echo</span> <span class="token_string">'%wheel ALL=(ALL) NOPASSWD: ALL'</span> <span class="token_operator">></span> /etc/sudoers.d/wheel
chmod <span class="token_number">0440</span> /etc/sudoers.d/wheel`});var R=a(L,2);_(R,{lang:`sh`,dangerous_raw_html:`ssh-copy-id ops@<span class="token_operator">&lt;</span>host<span class="token_operator">></span>
ssh ops@<span class="token_operator">&lt;</span>host<span class="token_operator">></span> <span class="token_boolean">true</span>`});var z=a(R),re=a(r(z),4);f(9),d(z);var B=a(z);_(B,{lang:`ts`,dangerous_raw_html:`<span class="token_comment">// zap.ts</span>
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
<span class="token_punctuation">};</span>`});var V=a(B,2);_(V,{lang:`sh`,dangerous_raw_html:`<span class="token_comment"># zap.env</span>
HOST=<span class="token_number">203</span>.<span class="token_number">0</span>.<span class="token_number">113</span>.<span class="token_number">10</span>
USER_NAME=ops`});var H=a(V,2);_(H,{lang:`sh`,dangerous_raw_html:`zap lock --env-file zap.env            <span class="token_comment"># pin the evaluator</span>
zap detect --env-file zap.env          <span class="token_comment"># what the host looks like now</span>
zap apply --env-file zap.env           <span class="token_comment"># the plan</span>
zap apply --env-file zap.env --wetrun  <span class="token_comment"># converge</span>
zap apply --env-file zap.env           <span class="token_comment"># idempotency: (no changes — converged)</span>`});var U=a(H),ie=a(r(U),4);ie.nodeValue=`, the
`,f(6),d(U);var W=a(U),ae=a(r(W),4);ae.nodeValue=`
shows the drift. That loop, plan then wetrun, is all of Zap.`,d(W);var G=a(W);c(G,`id`,`what-to-commit`);var K=a(G,2);c(K,`id`,`where-to-go-next`);var q=a(K),J=r(q),Y=a(r(J),2),oe=a(Y,2);f(),d(J);var X=a(J),se=a(r(X),4);f(),d(X);var Z=a(X),Q=a(r(Z),3);Q.nodeValue=`:
`;var ce=a(Q);f(),d(Z);var $=a(Z),le=a(r($),2);f(),d($),d(q),ee((e,t,n,r,i,a,o,s,u,d)=>{c(l,`href`,e),c(T,`href`,t),c(M,`href`,n),c(ne,`href`,r),c(re,`href`,i),c(Y,`href`,a),c(oe,`href`,o),c(se,`href`,s),c(ce,`href`,u),c(le,`href`,d)},[()=>p(`docs/install`),()=>p(`docs/concepts#a-wetrun-executes-only-the-plan-you-reviewed`),()=>p(`docs/resources#package-names`),()=>p(`docs/install#types-and-recipes-for-your-config`),()=>p(`docs/env#references`),()=>p(`docs/recipes`),()=>p(`docs/configs`),()=>p(`docs/deploy`),()=>p(`docs/targets#the-bootstrap-user`),()=>p(`docs/cli`)]),s(e,i)},$$slots:{default:!0}})},$$slots:{default:!0}}),i()}export{y as t};