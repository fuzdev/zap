import{K as e,Q as t,Y as n,Z as r,ct as i,et as a,j as o,k as s,l as c,lt as l,m as u,mt as d,pt as f,q as p}from"./DGWDGHf_.js";import{t as m}from"./hWJyV7ZK.js";import{t as h}from"./xlPESoVd.js";import{t as g}from"./B0EoXBDb.js";import{n as _}from"./BkOGAUkd.js";import{t as v}from"./DCLBpiTL.js";import"./CMLJYHjj.js";var y=o(`<p> <a target="_blank" rel="noopener">fuz.dev/contributing</a>. To install Zap for
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
fidelity round trip.</li><li><strong>Docs</strong>: the kind's entry in <a>resources.md</a>.</li></ol><h2>Recipes</h2><p> <a>recipes.md</a>.</p>`,1);function b(o,b){l(b,!0);let x=_(`contributing`);u(`1tq343v`,t=>{e(()=>{n.title=`Contributing — zap`})}),g(o,{get tome(){return x},children:(e,n)=>{h(e,{children:(e,n)=>{var i=y(),o=t(i),l=r(o);l.nodeValue=`How to build, check, and test Zap when you are changing it. The project-wide
guidelines and code of conduct are at
`;var u=a(l);c(u,`href`,`https://www.fuz.dev/contributing`);var h=a(u,2);f(),d(o);var g=a(o);c(g,`id`,`builds`);var _=a(g,2);c(_,`id`,`checks`);var b=a(_);v(b,{lang:`sh`,dangerous_raw_html:`cargo clippy --workspace --all-targets -- -D warnings   <span class="token_comment"># the engine's lints</span>
cargo <span class="token_builtin">test</span> --workspace                   <span class="token_comment"># the engine's suite</span>
gro check                                <span class="token_comment"># the site and the TypeScript surface</span>
cargo fmt -p zap -p zap_core -p zap_types -p xtask   <span class="token_comment"># format the engine</span>
cargo xtask check-release                <span class="token_comment"># production binaries link no test or audit crate</span>
RUSTDOCFLAGS=<span class="token_string">'-D warnings'</span> cargo doc --workspace --no-deps --all-features --document-private-items  <span class="token_comment"># the docs build</span>`});var x=a(b,2),S=a(r(x),4);S.nodeValue=`. After an engine change, run
`,f(6),d(x);var C=a(x,2);c(C,`id`,`the-hermetic-suites`);var w=a(C),T=r(w);T.nodeValue=`Nothing in them reaches a remote host. A test that runs an external program
checks nothing where the program is missing, so each crate's
`;var E=a(T,4);E.nodeValue=`
says the absence is expected:`,d(w);var D=a(w,2),O=a(r(D),7);O.nodeValue=`). The site's
`;var k=a(O,6);k.nodeValue=`
(`,f(6),d(D);var A=a(D,2),j=r(A);j.nodeValue=`Validating against real machines is separate:
`;var M=a(j),N=a(M,2),P=a(N);P.nodeValue=`
for the harness that compares two `,f(2),d(A);var F=a(A);c(F,`id`,`adding-a-resource-kind`);var I=a(F),L=a(r(I),2);L.nodeValue=`
and `,f(2),d(I);var R=a(I),z=a(r(R)),B=a(r(z),3);B.nodeValue=`, typed read-only
`;var V=a(B,6);V.nodeValue=`, wired in
`,f(4),d(z);var H=a(z),U=a(r(H),3);U.nodeValue=`
(`;var W=a(U,2);W.nodeValue=`; the match is exhaustive), which
`,f(8),d(H);var G=a(H,2),K=a(r(G),9);K.nodeValue=`
beside it; the drift tests fail otherwise.`,d(G);var q=a(G,2),J=a(r(q),2);f(),d(q),d(R);var Y=a(R);c(Y,`id`,`recipes`);var X=a(Y),Z=r(X);Z.nodeValue=`The shipped recipes follow the design rules in
`;var Q=a(Z);f(),d(X),p((e,t,n,r,i)=>{c(h,`href`,e),c(M,`href`,t),c(N,`href`,n),c(J,`href`,r),c(Q,`href`,i)},[()=>m(`docs/install`),()=>m(`docs/testing`),()=>m(`docs/differential`),()=>m(`docs/resources`),()=>m(`docs/recipes#design-rules`)]),s(e,i)},$$slots:{default:!0}})},$$slots:{default:!0}}),i()}export{b as t};