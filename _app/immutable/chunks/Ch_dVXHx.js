import{$ as e,G as t,J as n,K as r,X as i,Z as a,dt as o,ft as s,j as c,k as l,l as u,m as d,ot as f,st as p}from"./CkSeWg2M.js";import{t as m}from"./Cyt8LZpN.js";import{n as h}from"./BbCw5KVU.js";import"./BPVwp-J3.js";import{t as g}from"./k6TRNp0w.js";import{t as _}from"./DH_LefOd.js";import{t as v}from"./CtsBFaJL.js";var y=c(`<p> <a target="_blank" rel="noopener">fuz.dev/contributing</a>. To install Zap for
use, see <a>install.md</a>.</p><h2>Builds</h2><table><thead><tr><th>Command</th><th>Produces</th></tr></thead><tbody><tr><td><code>cargo xtask install</code></td><td>a release build at <code>~/.zap/bin/zap</code>, the binary on your <code>PATH</code></td></tr><tr><td><code>cargo build -p zap</code></td><td>a debug binary at <code>target/debug/zap</code></td></tr><tr><td><code>cargo xtask build-musl</code></td><td>static binaries for <code>x86_64</code> and <code>aarch64</code> Linux at <code>target/&lt;triple>/release/zap</code>, with no glibc dependency (needs <code>zig</code> and <code>cargo-zigbuild</code>); evaluating a config still needs an <code>fgro</code> that runs on that machine</td></tr></tbody></table><h2>Checks</h2><!><p>CI runs each of these as a gate, a warning from clippy or rustdoc included, and
runs the suite a second time under <code>umask 000</code>, since a mode the tests assert is
only as strict as the umask their files are made under.</p><p>Run <code>npm ci</code> before <code>gro check</code> <code>cargo xtask install</code>: the <code>zap</code> on your <code>PATH</code> is whatever was last installed,
and a stale one mis-plans in ways that look like config bugs.</p><p>Format with the packages named, never <code>cargo fmt --all</code>: rustfmt follows the
path dependencies into the sibling <code>fuz</code> checkout and would reformat its files.</p><h3>The hermetic suites</h3><p> <code>required_programs</code> test fails there instead, unless <code>ZAP_TEST_ALLOW_NO_&lt;NAME>=1</code> </p><table><thead><tr><th>Crate</th><th>Programs</th></tr></thead><tbody><tr><td><code>zap</code></td><td><code>fgro</code> (<code>ZAP_FGRO</code>), <code>git</code></td></tr><tr><td><code>zap_core</code></td><td><code>fgro</code> (<code>ZAP_FGRO</code>), <code>busybox</code>, <code>git</code>, <code>setfacl</code>, <code>getfacl</code></td></tr><tr><td><code>xtask</code></td><td><code>openssl</code>, <code>curl</code>, <code>busybox</code></td></tr></tbody></table><p><code>fgro</code> is the one not looked up on <code>PATH</code>: the tests that evaluate a config run
the build <code>ZAP_FGRO</code> names, by absolute path
(<code>ZAP_FGRO=/abs/path/to/fgro cargo test --workspace</code> <code>zap config validate</code> e2e needs <code>ZAP_FGRO</code> and a built <code>target/debug/zap</code> <code>cargo build -p zap</code>), and skips without them. Legs that need <code>fakeroot</code> run
only where it is installed; a missing one is noted on stderr (<code>--nocapture</code>) and
the test passes.</p><p>CI has no <code>fgro</code> build to give the suite, so the tests that evaluate a config,
and the e2e, don't run there: CI sets <code>ZAP_TEST_ALLOW_NO_FGRO=1</code>, and the e2e
reports itself skipped. Run them locally with <code>ZAP_FGRO</code> set before you push a
change to config evaluation.</p><p> <a>testing.md</a> for the VMs, <a>differential.md</a> <code>zap</code> builds on them.</p><h2>Adding a resource kind</h2><p>A new kind touches every crate; the module maps are <code>crates/zap_types/CLAUDE.md</code> <code>crates/zap_core/CLAUDE.md</code>.</p><ol><li><strong>Schema</strong>: in <code>crates/zap_types/src/schema/</code>, the <code>ResourceKind</code> variant
(<code>mod.rs</code>) and its payload struct (<code>resources.rs</code>). <code>tests/fidelity.rs</code> guards
the round trip.</li><li><strong>Detection</strong>: <code>crates/zap_types/src/observe/&lt;kind>.rs</code> <code>queries</code> and a pure <code>interpret</code> returning a <code>Detection</code> <code>Observed::for_resource</code> (<code>crates/zap_core/src/resource/detect/observed.rs</code>;
the match is exhaustive, so a missing arm fails to compile). Every kind is read
live on every pass.</li><li><strong>Execution</strong>: the kind's arm in <code>change_commands</code> <code>crates/zap_core/src/resource/execute.rs</code> <code>run_change</code>'s match dispatches on: a kind with command steps runs them, a
native one gets an arm in <code>run_native</code>, and <code>file</code> and <code>build</code> have their own
executors.</li><li><strong>Steps and hashing</strong>: <code>crates/zap_types/src/plan/steps/&lt;kind>.rs</code>, with inline
command goldens, and the field selection in <code>crates/zap_types/src/config_hash.rs</code>.</li><li><strong>Builder</strong>: <code>src/lib/zap.ts</code>, <code>src/lib/schema.ts</code>, and the driver
(<code>crates/zap_core/src/config/builder_fgro.js</code>). Mirror the change in <code>builder.js</code> </li><li><strong>Tests</strong>: detection goldens (<code>crates/zap_core/tests/fixtures/detection/</code>) and the
fidelity round trip.</li><li><strong>Docs</strong>: the kind's entry in <a>resources.md</a>.</li></ol><h2>Recipes</h2><p> <a>recipes.md</a>.</p>`,1);function b(c,b){p(b,!0);let x=h(`contributing`);d(`1tq343v`,e=>{t(()=>{n.title=`Contributing — zap`})}),g(c,{get tome(){return x},children:(t,n)=>{v(t,{children:(t,n)=>{var c=y(),d=a(c),f=i(d);f.nodeValue=`How to build, check, and test Zap when you are changing it. The project-wide
guidelines and code of conduct are at
`;var p=e(f);u(p,`href`,`https://www.fuz.dev/contributing`);var h=e(p,2);o(),s(d);var g=e(d);u(g,`id`,`builds`);var v=e(g,2);u(v,`id`,`checks`);var b=e(v);_(b,{lang:`sh`,dangerous_raw_html:`cargo clippy --workspace --all-targets -- -D warnings   <span class="token_comment"># the engine's lints</span>
cargo <span class="token_builtin">test</span> --workspace                   <span class="token_comment"># the engine's suite</span>
gro check                                <span class="token_comment"># the site and the TypeScript surface</span>
cargo fmt -p zap -p zap_core -p zap_types -p xtask   <span class="token_comment"># format the engine</span>
cargo xtask check-release                <span class="token_comment"># production binaries link no test or audit crate</span>
RUSTDOCFLAGS=<span class="token_string">'-D warnings'</span> cargo doc --workspace --no-deps --all-features --document-private-items  <span class="token_comment"># the docs build</span>`});var x=e(b,2),S=e(i(x),4);S.nodeValue=`. After an engine change, run
`,o(6),s(x);var C=e(x,2);u(C,`id`,`the-hermetic-suites`);var w=e(C),T=i(w);T.nodeValue=`Nothing in them reaches a remote host. A test that runs an external program
checks nothing where the program is missing, so each crate's
`;var E=e(T,4);E.nodeValue=`
says the absence is expected:`,s(w);var D=e(w,2),O=e(i(D),7);O.nodeValue=`). The site's
`;var k=e(O,6);k.nodeValue=`
(`,o(6),s(D);var A=e(D,2),j=i(A);j.nodeValue=`Validating against real machines is separate:
`;var M=e(j),N=e(M,2),P=e(N);P.nodeValue=`
for the harness that compares two `,o(2),s(A);var F=e(A);u(F,`id`,`adding-a-resource-kind`);var I=e(F),L=e(i(I),2);L.nodeValue=`
and `,o(2),s(I);var R=e(I),z=e(i(R)),B=e(i(z),3);B.nodeValue=`, typed read-only
`;var V=e(B,6);V.nodeValue=`, wired in
`,o(4),s(z);var H=e(z),U=e(i(H),3);U.nodeValue=`
(`;var W=e(U,2);W.nodeValue=`; the match is exhaustive), which
`,o(8),s(H);var G=e(H,2),K=e(i(G),9);K.nodeValue=`
beside it; the drift tests fail otherwise.`,s(G);var q=e(G,2),J=e(i(q),2);o(),s(q),s(R);var Y=e(R);u(Y,`id`,`recipes`);var X=e(Y),Z=i(X);Z.nodeValue=`The shipped recipes follow the design rules in
`;var Q=e(Z);o(),s(X),r((e,t,n,r,i)=>{u(h,`href`,e),u(M,`href`,t),u(N,`href`,n),u(J,`href`,r),u(Q,`href`,i)},[()=>m(`docs/install`),()=>m(`docs/testing`),()=>m(`docs/differential`),()=>m(`docs/resources`),()=>m(`docs/recipes#design-rules`)]),l(t,c)},$$slots:{default:!0}})},$$slots:{default:!0}}),f()}export{b as t};