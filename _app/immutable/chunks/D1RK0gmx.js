import{$ as e,G as t,J as n,K as r,X as i,Z as a,dt as o,ft as s,j as c,k as l,l as u,m as d,ot as f,st as p}from"./CkSeWg2M.js";import{t as m}from"./Cyt8LZpN.js";import{n as h}from"./BbCw5KVU.js";import"./BPVwp-J3.js";import{t as g}from"./k6TRNp0w.js";import{t as _}from"./DH_LefOd.js";import{t as v}from"./CtsBFaJL.js";var ee=c(`<p>Zap is built from source, and so is <code>fgro</code>, Gro's runtime, which evaluates your
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
too, which the next deploy to that <code>path</code> cleans up.</p>`,1);function y(c,y){p(y,!0);let b=h(`install`);d(`37fcns`,e=>{t(()=>{n.title=`Install — zap`})}),g(c,{get tome(){return b},children:(t,n)=>{v(t,{children:(t,n)=>{var c=ee(),d=e(a(c));u(d,`id`,`what-you-need-on-your-machine`);var f=e(d,2);u(f,`id`,`build`);var p=e(f,2);_(p,{lang:`sh`,dangerous_raw_html:`git clone https://github.com/fuzdev/fuz
git clone https://github.com/fuzdev/zap
<span class="token_builtin">cd</span> zap
cargo xtask install`});var h=e(p),g=e(i(h));g.nodeValue=` makes a release build and puts the binary at
`,o(4),s(h);var v=e(h);_(v,{lang:`sh`,dangerous_raw_html:`<span class="token_keyword">export</span> PATH=<span class="token_string">"<span class="token_variable">$HOME</span>/.zap/bin:<span class="token_variable">$PATH</span>"</span>   <span class="token_comment"># bash / zsh</span>
fish_add_path ~/.zap/bin             <span class="token_comment"># fish</span>`});var y=e(v,2);_(y,{lang:null,content:`$ zap version
zap <version>`});var b=e(y),x=i(b);x.nodeValue=`Debug and static musl builds are in
`;var S=e(x);o(),s(b);var C=e(b),w=e(i(C),2);w.nodeValue=` doesn't update when you pull. Run
`,o(2),s(C);var T=e(C);u(T,`id`,`getting-fgro`);var E=e(T),D=e(i(E),2);D.nodeValue=` from a checkout of
`;var te=e(D);u(te,`href`,`https://github.com/fuzdev/gro`),o(3),s(E);var O=e(E);_(O,{lang:`sh`,dangerous_raw_html:`git clone https://github.com/fuzdev/gro
<span class="token_builtin">cd</span> gro
cargo xtask fetch-v8
cargo xtask build --release`});var k=e(O),ne=e(i(k),7);o(),s(k);var A=e(k);_(A,{lang:`sh`,dangerous_raw_html:`install -D -m <span class="token_number">755</span> target/gro_snapshot/release/fgro ~/.zap/bin/fgro
<span class="token_keyword">export</span> ZAP_FGRO=<span class="token_string">"<span class="token_variable">$HOME</span>/.zap/bin/fgro"</span>   <span class="token_comment"># bash / zsh</span>
<span class="token_keyword">set</span> -gx ZAP_FGRO ~/.zap/bin/fgro         <span class="token_comment"># fish</span>`});var j=e(A),M=e(i(j),10);M.nodeValue=`
only `,o(4),s(j);var N=e(j,3);u(N,`id`,`types-and-recipes-for-your-config`);var P=e(N),re=e(i(P),2);re.nodeValue=` beside it, or in a
directory above it that you own and no other user can write. One holding only
`,o(10),s(P);var F=e(P);_(F,{lang:`json`,dangerous_raw_html:`<span class="token_punctuation">{</span><span class="token_property">"name"</span><span class="token_operator">:</span> <span class="token_string">"infra"</span><span class="token_punctuation">,</span> <span class="token_property">"private"</span><span class="token_operator">:</span> <span class="token_boolean">true</span><span class="token_punctuation">,</span> <span class="token_property">"type"</span><span class="token_operator">:</span> <span class="token_string">"module"</span><span class="token_punctuation">}</span>`});var I=e(F,2);_(I,{lang:`ts`,dangerous_raw_html:`<span class="token_special_keyword">export</span> <span class="token_special_keyword">default</span> <span class="token_punctuation">(</span>zap<span class="token_punctuation">)</span> <span class="token_operator">=></span> <span class="token_punctuation">{</span>
	zap<span class="token_punctuation">.</span><span class="token_function">target</span><span class="token_punctuation">({</span>local<span class="token_operator">:</span> <span class="token_boolean">true</span><span class="token_punctuation">});</span>
	<span class="token_comment">// …</span>
<span class="token_punctuation">};</span>`});var L=e(I,2);_(L,{lang:`ts`,dangerous_raw_html:`<span class="token_special_keyword">import</span> <span class="token_import_type_keyword token_special_keyword">type</span> <span class="token_punctuation">{</span><span class="token_capitalized_identifier token_class_name">ZapBuilder</span><span class="token_punctuation">}</span> <span class="token_special_keyword">from</span> <span class="token_string">'@fuzdev/zap/zap.ts'</span><span class="token_punctuation">;</span>

<span class="token_special_keyword">export</span> <span class="token_special_keyword">default</span> <span class="token_punctuation">(</span>zap<span class="token_operator">:</span> <span class="token_capitalized_identifier token_class_name">ZapBuilder</span><span class="token_punctuation">)</span> <span class="token_operator">=></span> <span class="token_punctuation">{</span>
	<span class="token_comment">// …</span>
<span class="token_punctuation">};</span>`});var R=e(L,2);_(R,{lang:`sh`,content:`npm i -D --save-exact @fuzdev/zap`});var z=e(R),B=i(z);B.nodeValue=`That install, in the config's own project, is the one way its import of
`;var ie=e(B,5);o(13),s(z);var V=e(z,2);_(V,{lang:`json`,dangerous_raw_html:`<span class="token_punctuation">{</span>
	<span class="token_property">"devDependencies"</span><span class="token_operator">:</span> <span class="token_punctuation">{</span>
		<span class="token_property">"@fuzdev/zap"</span><span class="token_operator">:</span> <span class="token_string">"../zap"</span>
	<span class="token_punctuation">}</span>
<span class="token_punctuation">}</span>`});var H=e(V),U=e(i(H),3);U.nodeValue=`. The checkout must
not sit under a directory every user can write. A recipe edit in the checkout
reaches your next plan with no build step, since fgro reads the sources; run
`,o(4),s(H);var W=e(H,2);_(W,{lang:`ts`,dangerous_raw_html:`<span class="token_special_keyword">import</span> <span class="token_import_type_keyword token_special_keyword">type</span> <span class="token_punctuation">{</span><span class="token_capitalized_identifier token_class_name">ZapBuilder</span><span class="token_punctuation">}</span> <span class="token_special_keyword">from</span> <span class="token_string">'@fuzdev/zap/zap.ts'</span><span class="token_punctuation">;</span>
<span class="token_special_keyword">import</span> <span class="token_punctuation">{</span>ssh_hardening<span class="token_punctuation">}</span> <span class="token_special_keyword">from</span> <span class="token_string">'@fuzdev/zap/recipe_ssh.ts'</span><span class="token_punctuation">;</span>`});var G=e(W),K=e(i(G));o(),s(G);var q=e(G);u(q,`id`,`what-a-target-needs`);var J=e(q),Y=e(i(J),6);Y.nodeValue=` that works without a password for the user
Zap connects as. Details per distro:
`;var ae=e(Y);o(),s(J);var X=e(J);u(X,`id`,`uninstall`);var Z=e(X),Q=e(i(Z),12);Q.nodeValue=` gives it (root's
`;var $=e(Q,2);$.nodeValue=`). Zap keeps no other state on your machine. On a target it
leaves only what your config declared, plus any pending-trigger markers under
`;var oe=e($,10);oe.nodeValue=` sentinel, and in a deploy's
`,o(18),s(Z),r((e,t,n,r,i)=>{u(S,`href`,e),u(ne,`href`,t),u(ie,`href`,n),u(K,`href`,r),u(ae,`href`,i)},[()=>m(`docs/contributing#builds`),()=>m(`docs/lock#the-toolchain-pin`),()=>m(`docs/security#the-config-can-only-describe`),()=>m(`docs/recipes`),()=>m(`docs/targets#what-the-target-needs`)]),l(t,c)},$$slots:{default:!0}})},$$slots:{default:!0}}),f()}export{y as t};