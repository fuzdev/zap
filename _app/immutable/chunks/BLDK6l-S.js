import{K as e,Q as t,Y as n,Z as r,ct as i,et as a,j as o,k as s,l as c,lt as l,m as u,mt as d,pt as f,q as p}from"./DGWDGHf_.js";import{t as m}from"./hWJyV7ZK.js";import{t as h}from"./xlPESoVd.js";import{t as g}from"./B0EoXBDb.js";import{n as _}from"./BkOGAUkd.js";import{t as v}from"./DCLBpiTL.js";import"./CMLJYHjj.js";var ee=o(`<p>Zap is built from source, and so is <code>fgro</code>, Gro's runtime, which evaluates your
TypeScript config. Zap never runs a config without it.</p><h2>What you need on your machine</h2><table><thead><tr><th>Tool</th><th>Why</th><th>Check</th></tr></thead><tbody><tr><td><strong>Rust</strong> via rustup (it installs the toolchain pinned in <code>rust-toolchain.toml</code>)</td><td>to build the <code>zap</code> binary</td><td><code>cargo --version</code></td></tr><tr><td><strong>C toolchain</strong> (<code>cc</code>; on Debian, <code>build-essential</code>)</td><td>Rust links with it</td><td><code>cc --version</code></td></tr><tr><td><strong>fgro</strong>, Gro's runtime</td><td>every command that reads a config evaluates <code>zap.ts</code> with <code>fgro eval</code>, in its kernel sandbox</td><td><code>fgro --version</code></td></tr><tr><td><strong>Linux</strong> with Landlock ABI 6 or later (6.12)</td><td>the sandbox <code>fgro</code> evaluates in</td><td><code>uname -r</code></td></tr><tr><td><strong>ssh</strong></td><td>remote targets</td><td><code>ssh -V</code></td></tr><tr><td>scp</td><td>a <code>remote</code> archive or a <code>build</code> source on a remote target</td><td></td></tr><tr><td>git, tar</td><td><code>zap deploy</code></td><td></td></tr><tr><td>minisign</td><td>only for a <code>build</code> source with <code>verify</code>; on <code>PATH</code>, or named by <code>ZAP_MINISIGN</code></td><td></td></tr><tr><td>Node and npm</td><td>only to import the shipped recipes and get editor types</td><td><code>npm --version</code></td></tr></tbody></table><h2>Build</h2><p>Zap depends on crates from the sibling <code>fuz</code> repository, resolved by relative
path, so the two checkouts sit next to each other:</p><!><p><code>cargo xtask install</code> <code>~/.zap/bin/zap</code>. Add that directory to your <code>PATH</code>:</p><!><p>Then:</p><!><p> <a>contributing.md</a>.</p><p>The binary on your <code>PATH</code> <code>cargo xtask install</code> again after pulling changes.</p><h2>Getting fgro</h2><p>Build <code>fgro</code> <a target="_blank" rel="noopener">Gro</a>, on x86_64 Linux. The build downloads and
verifies a pinned V8 first, and the binary must carry its startup snapshot,
which <code>cargo xtask build</code> embeds:</p><!><p>The binary is <code>target/gro_snapshot/release/fgro</code>. Don't point <code>ZAP_FGRO</code> at it there:
each build replaces it, and a project's <code>zap.lock</code> pins the exact binary its
configs are evaluated with (<a>lock.md</a>), so a
rebuild would make every pin stale. Copy it to a place you update deliberately,
and name that copy:</p><!><p>Zap takes the binary by absolute path, from <code>--fgro &lt;path></code> or <code>ZAP_FGRO</code>, and
never looks it up on <code>PATH</code>. <code>sudo</code> resets the environment, so under <code>sudo</code> <code>--fgro</code> reaches Zap: <code>sudo zap apply --fgro ~/.zap/bin/fgro</code>. Name the
binary itself, not a link to it or a wrapper script.</p><p>Then pin it in each project: <code>zap lock</code> evaluates the config with that binary
and records its blake3 in <code>zap.lock</code>; commit the lock. When you update the copy,
run <code>zap lock</code> again in each project.</p><p>Zap and fgro talk through a versioned eval protocol. An fgro that answers in a
version this <code>zap</code> doesn't read is refused, exit 2, whatever the pin says: update
the older of the two, then <code>zap lock</code>.</p><h2>Types and recipes for your config</h2><p>A config needs a project of its own: a <code>package.json</code> <code>"type"</code> or <code>"sideEffects"</code> doesn't count; a <code>"name"</code> is enough. A <code>.js</code> module
the config imports needs <code>"type": "module"</code>:</p><!><p>A bare config needs nothing else installed:</p><!><p>For editor completion and type checking, import the builder type. The import is
type-only, so the evaluator strips it and needs nothing resolvable at run time:</p><!><p>To use the shipped <strong>recipes</strong> (nginx sites, hardened systemd units, SSH
hardening, certbot, firewalls), your project needs the <code>@fuzdev/zap</code> package
under its own <code>node_modules/@fuzdev/zap</code>. Install it from npm as a dev
dependency, pinned to one exact version so a recipe's output changes only when
you change the pin:</p><!><p> <code>@fuzdev/zap</code> resolves: a <code>node_modules</code> above the project is never searched
(<a>security.md</a>). The package holds
the authoring surface only: the builder types, the schema, and the recipes,
each as TypeScript source and as built <code>dist/</code> files. fgro resolves recipe
imports through the package's <code>exports</code>, which carry a <code>gro</code> condition pointing
at the TypeScript sources; TypeScript and your editor resolve the same imports
through <code>dist/</code>. The <code>zap</code> binary and <code>fgro</code> don't come with it: build them as
above.</p><p>To work on the recipes themselves, point a path dependency at a <code>zap</code> checkout
instead:</p><!><p><code>npm install</code> then symlinks the checkout into <code>node_modules</code> <code>npm install &amp;&amp; npm run build</code> in the checkout once (and after pulling) to keep
the <code>dist/</code> types current.</p><p>Either way, import each recipe by its full module path:</p><!><p>See <a>recipes.md</a> for the catalog.</p><h2>What a target needs</h2><p>A local target needs <code>sudo</code> only if the config touches files you don't own or
runs privileged commands. A remote target needs <code>sshd</code>, a POSIX shell with
coreutils or BusyBox, and a <code>sudo</code> <a>targets.md</a>.</p><h2>Uninstall</h2><p>Remove <code>~/.zap</code> (the binary and, unless <code>ZAP_HOME</code> moved them, the caches,
last-run reports, deploy previews, SSH sockets), and <code>$ZAP_HOME</code> if you set one;
a <code>zap</code> run under <code>sudo</code> keeps its own, in the home <code>sudo</code> <code>~/.zap</code> <code>/var/lib/zap/pending/</code>, a <code>build</code>'s <code>&lt;output>.zap-build</code> provenance sidecar,
an extracted <code>remote</code> file's <code>.zap_remote_hash</code> <code>path</code>, <code>deploy_info.json</code> and the <code>.zap-deploy.lock</code> file. A run killed outright
can also leave a <code>.zap.*</code> staged file beside a file it was writing, or a
release archive (<code>.zap-deploy-&lt;user>-&lt;version>.tar.gz</code>) in a deploy's <code>path</code>. A
killed deploy can leave <code>releases/.zap-stage</code> and <code>releases/.zap-old-*</code> there
too, which the next deploy to that <code>path</code> cleans up.</p>`,1);function y(o,y){l(y,!0);let b=_(`install`);u(`37fcns`,t=>{e(()=>{n.title=`Install — zap`})}),g(o,{get tome(){return b},children:(e,n)=>{h(e,{children:(e,n)=>{var i=ee(),o=a(t(i));c(o,`id`,`what-you-need-on-your-machine`);var l=a(o,2);c(l,`id`,`build`);var u=a(l,2);v(u,{lang:`sh`,dangerous_raw_html:`git clone https://github.com/fuzdev/fuz
git clone https://github.com/fuzdev/zap
<span class="token_builtin">cd</span> zap
cargo xtask install`});var h=a(u),g=a(r(h));g.nodeValue=` makes a release build and puts the binary at
`,f(4),d(h);var _=a(h);v(_,{lang:`sh`,dangerous_raw_html:`<span class="token_keyword">export</span> PATH=<span class="token_string">"<span class="token_variable">$HOME</span>/.zap/bin:<span class="token_variable">$PATH</span>"</span>   <span class="token_comment"># bash / zsh</span>
fish_add_path ~/.zap/bin             <span class="token_comment"># fish</span>`});var y=a(_,2);v(y,{lang:null,content:`$ zap version
zap <version>`});var b=a(y),x=r(b);x.nodeValue=`Debug and static musl builds are in
`;var te=a(x);f(),d(b);var S=a(b),C=a(r(S),2);C.nodeValue=` doesn't update when you pull. Run
`,f(2),d(S);var w=a(S);c(w,`id`,`getting-fgro`);var T=a(w),E=a(r(T),2);E.nodeValue=` from a checkout of
`;var D=a(E);c(D,`href`,`https://github.com/fuzdev/gro`),f(3),d(T);var O=a(T);v(O,{lang:`sh`,dangerous_raw_html:`git clone https://github.com/fuzdev/gro
<span class="token_builtin">cd</span> gro
cargo xtask fetch-v8
cargo xtask build --release`});var k=a(O),A=a(r(k),7);f(),d(k);var j=a(k);v(j,{lang:`sh`,dangerous_raw_html:`install -D -m <span class="token_number">755</span> target/gro_snapshot/release/fgro ~/.zap/bin/fgro
<span class="token_keyword">export</span> ZAP_FGRO=<span class="token_string">"<span class="token_variable">$HOME</span>/.zap/bin/fgro"</span>   <span class="token_comment"># bash / zsh</span>
<span class="token_keyword">set</span> -gx ZAP_FGRO ~/.zap/bin/fgro         <span class="token_comment"># fish</span>`});var M=a(j),ne=a(r(M),10);ne.nodeValue=`
only `,f(4),d(M);var N=a(M,3);c(N,`id`,`types-and-recipes-for-your-config`);var P=a(N),re=a(r(P),2);re.nodeValue=` beside it, or in a
directory above it that you own and no other user can write. One holding only
`,f(10),d(P);var F=a(P);v(F,{lang:`json`,dangerous_raw_html:`<span class="token_punctuation">{</span><span class="token_property">"name"</span><span class="token_operator">:</span> <span class="token_string">"infra"</span><span class="token_punctuation">,</span> <span class="token_property">"private"</span><span class="token_operator">:</span> <span class="token_boolean">true</span><span class="token_punctuation">,</span> <span class="token_property">"type"</span><span class="token_operator">:</span> <span class="token_string">"module"</span><span class="token_punctuation">}</span>`});var I=a(F,2);v(I,{lang:`ts`,dangerous_raw_html:`<span class="token_special_keyword">export</span> <span class="token_special_keyword">default</span> <span class="token_punctuation">(</span>zap<span class="token_punctuation">)</span> <span class="token_operator">=></span> <span class="token_punctuation">{</span>
	zap<span class="token_punctuation">.</span><span class="token_function">target</span><span class="token_punctuation">({</span>local<span class="token_operator">:</span> <span class="token_boolean">true</span><span class="token_punctuation">});</span>
	<span class="token_comment">// …</span>
<span class="token_punctuation">};</span>`});var L=a(I,2);v(L,{lang:`ts`,dangerous_raw_html:`<span class="token_special_keyword">import</span> <span class="token_import_type_keyword token_special_keyword">type</span> <span class="token_punctuation">{</span><span class="token_capitalized_identifier token_class_name">ZapBuilder</span><span class="token_punctuation">}</span> <span class="token_special_keyword">from</span> <span class="token_string">'@fuzdev/zap/zap.ts'</span><span class="token_punctuation">;</span>

<span class="token_special_keyword">export</span> <span class="token_special_keyword">default</span> <span class="token_punctuation">(</span>zap<span class="token_operator">:</span> <span class="token_capitalized_identifier token_class_name">ZapBuilder</span><span class="token_punctuation">)</span> <span class="token_operator">=></span> <span class="token_punctuation">{</span>
	<span class="token_comment">// …</span>
<span class="token_punctuation">};</span>`});var R=a(L,2);v(R,{lang:`sh`,content:`npm i -D --save-exact @fuzdev/zap`});var z=a(R),B=r(z);B.nodeValue=`That install, in the config's own project, is the one way its import of
`;var ie=a(B,5);f(13),d(z);var V=a(z,2);v(V,{lang:`json`,dangerous_raw_html:`<span class="token_punctuation">{</span>
	<span class="token_property">"devDependencies"</span><span class="token_operator">:</span> <span class="token_punctuation">{</span>
		<span class="token_property">"@fuzdev/zap"</span><span class="token_operator">:</span> <span class="token_string">"../zap"</span>
	<span class="token_punctuation">}</span>
<span class="token_punctuation">}</span>`});var H=a(V),U=a(r(H),3);U.nodeValue=`. The checkout must
not sit under a directory every user can write. A recipe edit in the checkout
reaches your next plan with no build step, since fgro reads the sources; run
`,f(4),d(H);var W=a(H,2);v(W,{lang:`ts`,dangerous_raw_html:`<span class="token_special_keyword">import</span> <span class="token_import_type_keyword token_special_keyword">type</span> <span class="token_punctuation">{</span><span class="token_capitalized_identifier token_class_name">ZapBuilder</span><span class="token_punctuation">}</span> <span class="token_special_keyword">from</span> <span class="token_string">'@fuzdev/zap/zap.ts'</span><span class="token_punctuation">;</span>
<span class="token_special_keyword">import</span> <span class="token_punctuation">{</span>ssh_hardening<span class="token_punctuation">}</span> <span class="token_special_keyword">from</span> <span class="token_string">'@fuzdev/zap/recipe_ssh.ts'</span><span class="token_punctuation">;</span>`});var G=a(W),K=a(r(G));f(),d(G);var q=a(G);c(q,`id`,`what-a-target-needs`);var J=a(q),Y=a(r(J),6);Y.nodeValue=` that works without a password for the user
Zap connects as. Details per distro:
`;var ae=a(Y);f(),d(J);var X=a(J);c(X,`id`,`uninstall`);var Z=a(X),Q=a(r(Z),12);Q.nodeValue=` gives it (root's
`;var $=a(Q,2);$.nodeValue=`). Zap keeps no other state on your machine. On a target it
leaves only what your config declared, plus any pending-trigger markers under
`;var oe=a($,10);oe.nodeValue=` sentinel, and in a deploy's
`,f(18),d(Z),p((e,t,n,r,i)=>{c(te,`href`,e),c(A,`href`,t),c(ie,`href`,n),c(K,`href`,r),c(ae,`href`,i)},[()=>m(`docs/contributing#builds`),()=>m(`docs/lock#the-toolchain-pin`),()=>m(`docs/security#the-config-can-only-describe`),()=>m(`docs/recipes`),()=>m(`docs/targets#what-the-target-needs`)]),s(e,i)},$$slots:{default:!0}})},$$slots:{default:!0}}),i()}export{y as t};