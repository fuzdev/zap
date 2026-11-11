import{$ as e,G as t,J as ee,K as n,X as r,Z as i,dt as a,ft as o,j as s,k as c,l,m as u,ot as d,st as f}from"./CkSeWg2M.js";import{t as p}from"./Cyt8LZpN.js";import{n as m}from"./BbCw5KVU.js";import"./BPVwp-J3.js";import{t as h}from"./k6TRNp0w.js";import{t as g}from"./DH_LefOd.js";import{t as _}from"./CtsBFaJL.js";var te=s(`<p>The ideas behind every zap command. Read this once; the other docs assume it.</p><h2>The loop</h2><!><p>You <strong>describe</strong> a machine in <code>zap.ts</code>: these packages, this file with this
content, this user with these keys, this service running. Zap <strong>detects</strong> what
the machine looks like now, <strong>plans</strong> the difference, <strong>applies</strong> only that
difference when you say so, and <strong>observes</strong> the result by reading the machine
again. Every command is a slice of that loop.</p><p>A task fits Zap when it can be put as: <em>I want the machine to look like X. What
does it look like now? What needs to change? Do it. Tell me what happened.</em></p><h2>Convergence</h2><p>A <strong>resource</strong> is one typed piece of desired state with a stable <code>id</code>. Most
resources are <strong>convergent</strong>: Zap reads their current state, compares it to the
declaration, and changes only what differs. Re-running is always safe. A
converged resource contributes nothing to the plan.</p><p>How much of the live state a declaration claims depends on the field:</p><table><thead><tr><th>A field that is</th><th>Means</th><th>For example</th></tr></thead><tbody><tr><td><strong>authoritative</strong></td><td>made exactly the declared value; anything added by hand is removed</td><td>a user's <code>authorized_keys</code>, a file's content</td></tr><tr><td><strong>additive</strong></td><td>each declared entry must be present; an entry added by hand is neither detected nor removed</td><td>a firewall's allow rules, a database's <code>pg_hba</code> rules, a user's groups</td></tr><tr><td><strong>unset</strong></td><td>unmanaged: Zap neither sets it nor reverts it, and a rewrite keeps it</td><td>a <code>file</code> with no <code>mode</code></td></tr></tbody></table><p>One resource kind is <strong>imperative</strong>: a <code>pipeline</code> <code>zap deploy</code>, which produces a new release every run. You make their steps safe
to repeat.</p><p><strong>Drift</strong> is the gap between the live machine and the declaration: a file edited
on the host, a service stopped, a firewall's default policy flipped at the
console. Zap doesn't
track drift; it finds it by reading the machine on every run, and the plan is the
repair.</p><p> <code>package</code> resource from the config and the package stays installed. <code>zap status</code> <code>script</code> whose <code>check</code> confirms it's gone).</p><h2>Detection</h2><p>For each resource, detection answers one question, <em>does the desired state
already exist?</em>, with one of four verdicts:</p><table><thead><tr><th>Verdict</th><th>Meaning</th><th>The planner</th></tr></thead><tbody><tr><td><code>converged</code></td><td>the desired state is present</td><td>skips it</td></tr><tr><td><code>drifted</code></td><td>present but wrong; carries what was observed</td><td>plans an update</td></tr><tr><td><code>absent</code></td><td>not present</td><td>plans a create</td></tr><tr><td><code>undetermined</code></td><td>couldn't tell, with a reason</td><td><strong>holds</strong> it out of the plan</td></tr></tbody></table><p>When Zap can't read a resource (a probe failed, a remote path's home isn't
declared, a tracked pin has no lock entry), it doesn't guess: the resource is
held, the command leads with an <code>UNDETERMINED</code> banner naming it and why, and the
exit code is 1 (deploy's preflight refuses with 2), never 0. Nothing carries over
between passes; the next run reads it again.</p><p>The hold spreads to what can't run without the held resource: a change that
depends on it (directly, or through resources that are converged) and a change
that would restart or reload it are held behind it, and the banner lists them
under it. <a>detection.md</a></p><p>A few kinds on the bring-up path read a failed probe as <code>absent</code> instead,
because on a fresh host the probe fails for the reason the config exists
(<code>ufw status</code> <code>database</code> <a>detection.md</a>.</p><p><strong>Depth follows idempotency.</strong> If re-running a change is a true no-op, shallow
detection is fine: a <code>package</code> <code>file</code> is compared by digest, mode, and owner; a <code>user</code>'s keys and sudoers by
content; a <code>firewall</code> rule by rule. A <code>script</code>'s depth is yours: its <code>check</code> </p><p><strong>Everything is read live, every time.</strong> <code>firewall</code>, <code>user</code>, and <code>database</code> guard the host's access surface and are
exactly what gets changed by hand.</p><h2>Dry run and wetrun</h2><p>No command changes the target unless you pass <code>--wetrun</code>. <code>zap apply</code> shows what
would change and exits 2 when something would; <code>zap apply --wetrun</code> changes it.
Most tools make the dry run the option. Zap makes it the default, and gives the
flag that acts an unusual name so it isn't typed by accident or appended by a
script's <code>--yes</code> habit. The default is safe with no terminal and no prompt,
which is what makes Zap safe to hand to a script or an AI assistant.</p><h2>The plan</h2><p>A plan is the changeset for one run: per resource, the action (<code>create</code> <code>update</code>), the steps, the desired state (its references kept as written), and
the dependency order. It is content-addressed: <code>plan_hash</code> is the blake3 of the plan's
canonical JSON and of the text Zap's own steps execute, printed at the end of
every <code>plan</code> and <code>apply</code>.</p><p>Two things with different stability go into it. The <strong>declaration</strong> is a function
of your config and the files it reads: the same <code>zap.ts</code> over the same files
evaluates to the same desired state, because the config runs in a sandbox with
no network and no environment, with the clock and randomness closed and the time
zone and locale fixed (<a>configs.md</a> <strong>changeset</strong> also depends on what detection found. So the hash addresses "what
this run decided to do against this target."</p><p>The plan is for one machine. Its header names the target it resolves to; a
local plan also names the user Zap runs as and the <code>HOME</code> a <code>~</code> resolves to:</p><!><p>A remote plan prints the connecting user in a <code>user:</code> <code>host:</code> line when the declared host is a reference. All of it is in the hash, so
one config under two env files is two plans, and so is the same host with and
without <code>--bootstrap</code> <code>HOME</code>, so a review made as you binds no local wetrun under <code>sudo</code>, which runs
as root, or under another <code>HOME</code>.</p><p>The plan is for one environment too. A reference in a resource stays written as
its reference (<code></code>), and the plan records beside it what each reference
its changes use resolves to, printed in a <code>references:</code> block under the target:
the value of a plain one, and for a <a>secret</a> only that it is
one. So <code>plan_hash</code> <code>APP_DIR</code> is another plan. A secret reference's value is never in the plan or its hash,
so rotating one changes neither.</p><h3>A wetrun executes only the plan you reviewed</h3><p>A wetrun doesn't take a saved plan as input; it detects and plans again, because
the machine may have moved. What it guarantees instead is that the plan it
executes is a reviewed one: a plan whose hash you named, or one Zap printed as a
preview. Before it changes anything, it compares its fresh <code>plan_hash</code> against
the reviewed plan:</p><ul><li><code>--expect-plan &lt;hash></code> names the reviewed plan explicitly, and the wetrun
executes only if the fresh plan has exactly that hash;</li><li> <a>last-run report</a> <strong>preview</strong>: <code>zap plan</code>, a dry <code>zap apply</code>, or a wetrun that refused. Its
recorded <code>plan_hash</code> must equal the fresh one.</li></ul><p>Otherwise the wetrun <strong>refuses</strong>. It changes nothing, renders the plan it would
have run under a <code>REFUSED</code> banner that says why (no preview yet, the last run
wasn't a preview, or the plan changed since the preview), records that render as
the new preview, and exits 2. The everyday flow is <code>zap apply</code>, read
it, <code>zap apply --wetrun</code>. A wetrun fired cold becomes the preview, and the next
one executes if nothing moved. A preview covers one wetrun: one that executes,
whether its changes succeed or fail, spends it, and of two started on one
preview only one goes on. An agent given <code>--expect-plan</code> with the hash it
showed you can execute only that plan: the same changes, on the same machine,
as the same user, with the same values for every reference that isn't a secret.
An empty plan needs no review.</p><p>A preview is recorded when Zap prints it, not when anyone reads it: Zap knows
what it wrote, not what reached a reader. When the write itself fails (a full
device, a pipe whose reader has gone), Zap withdraws the preview it recorded
and says so, and the next wetrun run without <code>--expect-plan</code> refuses. A preview
that was written but not read still binds that wetrun: one sent to <code>/dev/null</code>,
or cut short by <code>head</code> after the pipe took it whole. When the output may be
truncated, or the one who reads the preview isn't the one who runs the wetrun,
bind with <code>--expect-plan</code>: its hash is the preview's last line, the first one a
cut-short preview loses.</p><p>On an interactive terminal, a wetrun whose plan has no review asks for the
first eight characters of its <code>plan_hash</code> instead of refusing
(<a>cli.md</a>).</p><p>A plan can only be reviewed if it names its machine. A plan whose host or
connecting user resolves through a reference Zap masks has no <code>plan_hash</code> <code>zap plan</code> and a dry <code>zap apply</code> show it under an <code>UNBINDABLE</code> <code>zap apply --wetrun</code> is an error before anything runs, even when nothing would
change. The ways out are in <a>env.md</a>.</p><p><code>zap deploy</code> has its own plan, hash, and recorded preview, and its wetrun
follows the same rule against them
(<a>deploy.md</a>).</p><h2>Apply asserts convergence</h2><p> <code>RESIDUAL</code> and the run exits 1: a <code>script</code> whose <code>check</code> <code>run</code>, a mutation that read back wrong. A change that failed or was skipped is
the run's failure already, a held resource its <code>undetermined</code>, and a <code>pipeline</code> </p><h2>The last-run report</h2><p>Every detection pass writes a <strong>last-run report</strong> under <code>~/.zap</code>, one per config
and host, latest only (none for a host that resolves through a masked reference,
since it would stand for every machine the reference names): when it ran, which command, the host, each resource's
verdict and a hash of its declaration, the names of the references it couldn't resolve,
the batches it ran, and the <code>plan_hash</code> when the pass planned. Nothing the
target returned is in it, and no secret's value reaches any hash
(<a>env.md</a>).</p><p>Detection never reads it. <code>zap status</code> <code>zap plan</code>.</p><h2>Triggers</h2><p>Service detection reads running and enabled, not whether the service's config
is fresh. Triggers close that gap: a <code>file</code> names the services it <code>triggers</code>, or
a <code>service</code> names the resources it <code>restart_on</code> / <code>reload_on</code>. When a source
changes in the current plan, the service is promoted from skip to restart or
reload. A trigger restarts or reloads only a running service: a stopped one is
left stopped and starts on the new state when it starts. A trigger on a service
declared <code>running: false</code> is a config error.</p><p> <code>/var/lib/zap/pending/</code>, written before the first source changes and cleared
after the service's change completes. A failed reload stays owed and re-fires on
the next plan. At least once, never zero.</p><p>A held service, whether detection can't read it or it is held behind another,
holds every source whose change would trigger it: run alone, the source would owe
a restart that no change in the plan performs. Both wait for a plan that can run
the service.</p><h2>The lock file</h2><p>A moving reference makes intent ambiguous in time: a tracked <code>remote</code> file's URL
or a <code>build</code>'s source archive can serve different bytes tomorrow. <code>zap.lock</code>,
next to <code>zap.ts</code> and committed with it, pins each tracked reference to the
blake3 of its resolved bytes. Detection compares the target against that pin, and
only an explicit act moves it: <code>zap update</code> (advance one or all), <code>zap lock</code> <a>lock.md</a>.</p><h2>Targets and privilege</h2><p>A config has one <strong>target</strong>: your own machine (<code>local: true</code>) or a host over SSH.
Your authority on a remote host is SSH: Zap connects as the user you declare,
with your keys, and escalates with the host's <code>sudo</code>. Commands that are
privileged by nature (<code>apt-get</code>, <code>systemctl</code>, <code>ufw</code>) carry <code>sudo</code>. On a local
target file operations try natively first and escalate only when denied; over
SSH they run under <code>sudo</code>. There is no agent,
no server, and no shared secret. See <a>targets.md</a>.</p><h2>Secrets and references</h2><p>A config never reads the environment. Anything that varies per machine or is
secret is written as a reference, which the plan's steps keep as written and
Zap resolves when it acts; the plan records what each plain one resolves to, so
a review covers it. A secret's value is masked out of every output, event, and
report. A secret written literally into a config is rejected when Zap can tell
(its value is referenced and set in the environment).
See <a>env.md</a>.</p><h2>Deploy</h2><p><code>zap deploy</code> is the one imperative command: it ships a versioned release to a
remote host as <code>releases/&lt;version></code> plus a <code>current</code> symlink, restarts the
service, polls health, and rolls back if the health gate fails. Before shipping,
its preflight runs the convergence pass and refuses to ship onto a host that has
drifted from its config. The same tool that built the machine ships the app.
See <a>deploy.md</a>.</p>`,1);function v(s,v){f(v,!0);let y=m(`concepts`);u(`mhazmq`,e=>{t(()=>{ee.title=`Concepts — zap`})}),h(s,{get tome(){return y},children:(t,ee)=>{_(t,{children:(t,ee)=>{var s=te(),u=e(i(s));l(u,`id`,`the-loop`);var d=e(u);g(d,{lang:null,content:`describe → detect → plan → apply → observe`});var f=e(d,3);l(f,`id`,`convergence`);var m=e(f,4),h=e(r(m),4);h.nodeValue=` runs every time, as does
`,a(2),o(m);var _=e(m,2),v=r(_);v.nodeValue=`What Zap doesn't do: it never removes something you stop declaring. Delete a
`;var y=e(v,4);y.nodeValue=`
lists such resources as orphaned, as a warning. To remove something, declare
the removal (a `,a(4),o(_);var b=e(_);l(b,`id`,`detection`);var x=e(b,4),ne=e(r(x));o(x);var S=e(x),C=e(r(S),4);C.nodeValue=` fails before the same run installs ufw). Which kinds, and how
`;var re=e(C,2);re.nodeValue=` splits the two cases:
`;var ie=e(re);a(),o(S);var w=e(S),ae=e(r(w),3);ae.nodeValue=` is checked for existence (or, when its name pins a version, that
version), because installing it again does nothing. If re-running has side effects, detection goes deeper: a
`;var oe=e(ae,10);oe.nodeValue=`
command is the whole idempotency contract.`,o(w);var T=e(w),se=e(r(T));se.nodeValue=` Zap keeps no detection cache. A stored
answer is only sound when nothing else could have changed the machine, and Zap
never assumes it is the only writer. The security controls make the point:
`,a(6),o(T);var E=e(T);l(E,`id`,`dry-run-and-wetrun`);var D=e(E,2);l(D,`id`,`the-plan`);var O=e(D),ce=e(r(O),2);ce.nodeValue=` or
`,a(8),o(O);var k=e(O),A=e(r(k),5),le=e(A);le.nodeValue=`). The
`,a(2),o(k);var j=e(k,2);g(j,{lang:null,content:`$ zap plan
plan — target local (2 change(s): +2 ~0)
  user: ops
  home: /home/ops
  target: {"local":true}
  [+] notes  (directory)
      path: ~/notes
      mode: 755
  [+] hello  (file)
      path: ~/notes/hello.txt
      content: inline (15 bytes, sha512 0c7463f032f1dc98…)
plan_hash: 5bb79cc9141942676c784abba55826f12be51b3feb86f5f0cf77666545674d61`});var M=e(j),N=e(r(M),2);N.nodeValue=` line, and the host in a
`;var ue=e(N,4);ue.nodeValue=`. A local plan's hash covers the user Zap runs as and its
`,a(6),o(M);var P=e(M),F=e(r(P));F.textContent=`{env:NAME}`;var I=e(F,4),de=e(I,3);de.nodeValue=` covers those values: the same config under another value of
`,a(2),o(P);var L=e(P);l(L,`id`,`a-wetrun-executes-only-the-plan-you-reviewed`);var R=e(L,2),z=e(r(R)),B=r(z);B.nodeValue=`with no flag, the reviewed plan is the one in this host's
`;var V=e(B);l(V,`href`,`#the-last-run-report`);var fe=e(V);fe.nodeValue=`, when the pass that wrote it was a
`,a(8),o(z),o(R);var H=e(R,3),pe=e(r(H),3);a(),o(H);var U=e(H),me=e(r(U),2);me.nodeValue=`:
`;var W=e(me,6);W.nodeValue=` note, and
`;var he=e(W,3);a(),o(U);var G=e(U),ge=e(r(G),2);a(),o(G);var K=e(G);l(K,`id`,`apply-asserts-convergence`);var q=e(K),_e=r(q);_e.nodeValue=`A wetrun doesn't stop at command success. After the changes run, it reads every
resource again. Any resource that still doesn't read converged is reported as
`;var ve=e(_e,6);ve.nodeValue=` still fails after its
`;var ye=e(ve,6);ye.nodeValue=`
never reads converged (it always runs), so none of them is residual.
"Applied: N ok" alone would be a claim about commands; the re-detection makes it
a claim about the machine. If the re-detection itself fails, the run says so and
exits 1 too, because "converged" was not established.`,o(q);var be=e(q);l(be,`id`,`the-last-run-report`);var J=e(be),xe=e(r(J),7);a(),o(J);var Y=e(J),Se=e(r(Y),2);Se.nodeValue=` renders it offline, marking each resource
whose config changed since the run, and it holds the preview a wetrun binds to. Exit
codes are about the last run, not the live machine; the live answer is always
`,a(2),o(Y);var Ce=e(Y);l(Ce,`id`,`triggers`);var X=e(Ce,2),we=r(X);we.nodeValue=`A trigger fires only on a change in the current plan, so a failed reload would
be lost: next run the file is converged and the service is running, on the old
config. Zap keeps one marker per owed service on the target under
`,a(2),o(X);var Te=e(X,2);l(Te,`id`,`the-lock-file`);var Z=e(Te),Ee=e(r(Z),12);Ee.nodeValue=`
(rebuild), or a wetrun recording a pin that was missing. A pin that isn't current is withheld from the read-only commands, so
the resource holds rather than being compared against stale bytes. Full detail:
`;var De=e(Ee);a(),o(Z);var Oe=e(Z);l(Oe,`id`,`targets-and-privilege`);var Q=e(Oe),ke=e(r(Q),17);a(),o(Q);var Ae=e(Q);l(Ae,`id`,`secrets-and-references`);var $=e(Ae),je=e(r($));a(),o($);var Me=e($);l(Me,`id`,`deploy`);var Ne=e(Me),Pe=e(r(Ne),6);a(),o(Ne),n((e,t,ee,n,r,i,a,o,s,c,u,d)=>{l(ne,`href`,e),l(ie,`href`,t),l(A,`href`,ee),l(I,`href`,n),l(pe,`href`,r),l(he,`href`,i),l(ge,`href`,a),l(xe,`href`,o),l(De,`href`,s),l(ke,`href`,c),l(je,`href`,u),l(Pe,`href`,d)},[()=>p(`docs/detection#a-hold-spreads-to-what-cant-run-without-it`),()=>p(`docs/detection#kinds-that-read-a-failed-probe-as-absent`),()=>p(`docs/configs#the-sandbox`),()=>p(`docs/env#secrets`),()=>p(`docs/cli#binding-to-the-review`),()=>p(`docs/env#masked-hosts-and-review`),()=>p(`docs/deploy#binding-a-wetrun-to-a-reviewed-plan`),()=>p(`docs/env#secrets`),()=>p(`docs/lock`),()=>p(`docs/targets`),()=>p(`docs/env`),()=>p(`docs/deploy`)]),c(t,s)},$$slots:{default:!0}})},$$slots:{default:!0}}),d()}export{v as t};