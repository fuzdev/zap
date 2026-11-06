import{G as e,Q as t,W as n,X as r,Y as i,at as a,dt as o,j as s,k as c,l,m as u,ot as d,q as f,ut as p}from"./BTZoVLbz.js";import{t as m}from"./Cyt8LZpN.js";import{n as h}from"./DhdQKFKC.js";import"./BPVwp-J3.js";import{t as g}from"./B2l94Waq.js";import{t as _}from"./BTlkJFeB.js";import{t as v}from"./D23yn-ZR.js";var y=s(`<p>The ideas behind every zap command. Read this once; the other docs assume it.</p><h2>The loop</h2><!><p>You <strong>describe</strong> a machine in <code>zap.ts</code>: these packages, this file with this
content, this user with these keys, this service running. Zap <strong>detects</strong> what
the machine looks like now, <strong>plans</strong> the difference, <strong>applies</strong> only that
difference when you say so, and <strong>observes</strong> the result by reading the machine
again. Every command is a slice of that loop.</p><p>A task fits Zap when it can be put as: <em>I want the machine to look like X. What
does it look like now? What needs to change? Do it. Tell me what happened.</em></p><h2>Convergence</h2><p>A <strong>resource</strong> is one typed piece of desired state with a stable <code>id</code>. Most
resources are <strong>convergent</strong>: Zap reads their current state, compares it to the
declaration, and changes only what differs. Re-running is always safe. A
converged resource contributes nothing to the plan.</p><p>How much of the live state a declaration claims depends on the field:</p><table><thead><tr><th>A field that is</th><th>Means</th><th>For example</th></tr></thead><tbody><tr><td><strong>authoritative</strong></td><td>made exactly the declared value; anything added by hand is removed</td><td>a user's <code>authorized_keys</code>, a file's content</td></tr><tr><td><strong>additive</strong></td><td>each declared entry must be present; an entry added by hand is neither detected nor removed</td><td>a firewall's allow rules, a database's <code>pg_hba</code> rules, a user's groups</td></tr><tr><td><strong>unset</strong></td><td>unmanaged: Zap neither sets it nor reverts it, and a rewrite keeps it</td><td>a <code>file</code> with no <code>mode</code></td></tr></tbody></table><p>One resource kind is <strong>imperative</strong>: a <code>pipeline</code> runs every time, as does <code>zap deploy</code>, which produces a new release every run. You make their steps safe
to repeat.</p><p><strong>Drift</strong> is the gap between the live machine and the declaration: a file edited
on the host, a service stopped, a firewall's default policy flipped at the
console. Zap doesn't
track drift; it finds it by reading the machine on every run, and the plan is the
repair.</p><p>What Zap doesn't do: it never removes something you stop declaring. Delete a <code>package</code> resource from the config and the package stays installed. <code>zap status</code> lists such resources as orphaned, as a warning. To remove something, declare
the removal (a <code>script</code> whose <code>check</code> confirms it's gone).</p><h2>Detection</h2><p>For each resource, detection answers one question, <em>does the desired state
already exist?</em>, with one of four verdicts:</p><table><thead><tr><th>Verdict</th><th>Meaning</th><th>The planner</th></tr></thead><tbody><tr><td><code>converged</code></td><td>the desired state is present</td><td>skips it</td></tr><tr><td><code>drifted</code></td><td>present but wrong; carries what was observed</td><td>plans an update</td></tr><tr><td><code>absent</code></td><td>not present</td><td>plans a create</td></tr><tr><td><code>undetermined</code></td><td>couldn't tell, with a reason</td><td><strong>holds</strong> it out of the plan</td></tr></tbody></table><p>When Zap can't read a resource (a probe failed, a remote path's home isn't
declared, a tracked pin has no lock entry), it doesn't guess: the resource is
held, the command leads with an <code>UNDETERMINED</code> banner naming it and why, and the
exit code is 1 (deploy's preflight refuses with 2), never 0. Nothing carries over
between passes; the next run reads it again.</p><p>The hold spreads to what can't run without the held resource: a change that
depends on it (directly, or through resources that are converged) and a change
that would restart or reload it are held behind it, and the banner lists them
under it. <a>detection.md</a></p><p>A few kinds on the bring-up path read a failed probe as <code>absent</code> instead,
because on a fresh host the probe fails for the reason the config exists
(<code>ufw status</code> fails before the same run installs ufw). Which kinds, and how <code>database</code> splits the two cases: <a>detection.md</a>.</p><p><strong>Depth follows idempotency.</strong> If re-running a change is a true no-op, shallow
detection is fine: a <code>package</code> is checked for existence (or, when its name pins a version, that
version), because installing it again does nothing. If re-running has side effects, detection goes deeper: a <code>file</code> is compared by digest, mode, and owner; a <code>user</code>'s keys and sudoers by
content; a <code>firewall</code> rule by rule. A <code>script</code>'s depth is yours: its <code>check</code> command is the whole idempotency contract.</p><p><strong>Everything is read live, every time.</strong> Zap keeps no detection cache. A stored
answer is only sound when nothing else could have changed the machine, and Zap
never assumes it is the only writer. The security controls make the point: <code>firewall</code>, <code>user</code>, and <code>database</code> guard the host's access surface and are
exactly what gets changed by hand.</p><h2>Dry run and wetrun</h2><p>No command changes the target unless you pass <code>--wetrun</code>. <code>zap apply</code> shows what
would change and exits 2 when something would; <code>zap apply --wetrun</code> changes it.
Most tools make the dry run the option. Zap makes it the default, and gives the
flag that acts an unusual name so it isn't typed by accident or appended by a
script's <code>--yes</code> habit. The default is safe with no terminal and no prompt,
which is what makes Zap safe to hand to a script or an AI assistant.</p><h2>The plan</h2><p>A plan is the changeset for one run: per resource, the action (<code>create</code> or <code>update</code>), the steps, the desired state (its references kept as written), and
the dependency order. It is content-addressed: <code>plan_hash</code> is the blake3 of the plan's
canonical JSON and of the text Zap's own steps execute, printed at the end of
every <code>plan</code> and <code>apply</code>.</p><p>Two things with different stability go into it. The <strong>declaration</strong> is a function
of your config and the files it reads: the same <code>zap.ts</code> over the same files
evaluates to the same desired state, because the config runs in a sandbox with
no network and no environment, with the clock and randomness closed and the time
zone and locale fixed (<a>configs.md</a>). The <strong>changeset</strong> also depends on what detection found. So the hash addresses "what
this run decided to do against this target."</p><p>The plan is for one machine. Its header names the target it resolves to; a
local plan also names the user Zap runs as and the <code>HOME</code> a <code>~</code> resolves to:</p><!><p>A remote plan prints the connecting user in a <code>user:</code> line, and the host in a <code>host:</code> line when the declared host is a reference. All of it is in the hash, so
one config under two env files is two plans, and so is the same host with and
without <code>--bootstrap</code>. A local plan's hash covers the user Zap runs as and its <code>HOME</code>, so a review made as you binds no local wetrun under <code>sudo</code>, which runs
as root, or under another <code>HOME</code>.</p><p>The plan is for one environment too. A reference in a resource stays written as
its reference (<code></code>), and the plan records beside it what each reference
its changes use resolves to, printed in a <code>references:</code> block under the target:
the value of a plain one, and for a <a>secret</a> only that it is
one. So <code>plan_hash</code> covers those values: the same config under another value of <code>APP_DIR</code> is another plan. A secret reference's value is never in the plan or its hash,
so rotating one changes neither.</p><h3>A wetrun executes only the plan you reviewed</h3><p>A wetrun doesn't take a saved plan as input; it detects and plans again, because
the machine may have moved. What it guarantees instead is that the plan it
executes is the plan you saw. Before it changes anything, it compares its fresh <code>plan_hash</code> against the plan you reviewed:</p><ul><li><code>--expect-plan &lt;hash></code> names the reviewed plan explicitly, and the wetrun
executes only if the fresh plan has exactly that hash;</li><li>with no flag, the reviewed plan is the one in this host's <a>last-run report</a>, when the pass that wrote it was a <strong>preview</strong>: <code>zap plan</code>, a dry <code>zap apply</code>, or a wetrun that refused. Its
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
An empty plan needs no review.</p><p>On an interactive terminal, a wetrun whose plan has no review asks for the
first eight characters of its <code>plan_hash</code> instead of refusing
(<a>cli.md</a>).</p><p>A plan can only be reviewed if it names its machine. A plan whose host or
connecting user resolves through a reference Zap masks has no <code>plan_hash</code>: <code>zap plan</code> and a dry <code>zap apply</code> show it under an <code>UNBINDABLE</code> note, and <code>zap apply --wetrun</code> is an error before anything runs, even when nothing would
change. The ways out are in <a>env.md</a>.</p><p><code>zap deploy</code> has its own plan, hash, and recorded preview, and its wetrun
follows the same rule against them
(<a>deploy.md</a>).</p><h2>Apply asserts convergence</h2><p>A wetrun doesn't stop at command success. After the changes run, it reads every
resource again. Any resource that still doesn't read converged is reported as <code>RESIDUAL</code> and the run exits 1: a <code>script</code> whose <code>check</code> still fails after its <code>run</code>, a mutation that read back wrong. A change that failed or was skipped is
the run's failure already, a held resource its <code>undetermined</code>, and a <code>pipeline</code> never reads converged (it always runs), so none of them is residual.
"Applied: N ok" alone would be a claim about commands; the re-detection makes it
a claim about the machine. If the re-detection itself fails, the run says so and
exits 1 too, because "converged" was not established.</p><h2>The last-run report</h2><p>Every detection pass writes a <strong>last-run report</strong> under <code>~/.zap</code>, one per config
and host, latest only (none for a host that resolves through a masked reference,
since it would stand for every machine the reference names): when it ran, which command, the host, each resource's
verdict and a hash of its declaration, the names of the references it couldn't resolve,
the batches it ran, and the <code>plan_hash</code> when the pass planned. Nothing the
target returned is in it, and no secret's value reaches any hash
(<a>env.md</a>).</p><p>Detection never reads it. <code>zap status</code> renders it offline, marking each resource
whose config changed since the run, and it holds the preview a wetrun binds to. Exit
codes are about the last run, not the live machine; the live answer is always <code>zap plan</code>.</p><h2>Triggers</h2><p>Service detection reads running and enabled, not whether the service's config
is fresh. Triggers close that gap: a <code>file</code> names the services it <code>triggers</code>, or
a <code>service</code> names the resources it <code>restart_on</code> / <code>reload_on</code>. When a source
changes in the current plan, the service is promoted from skip to restart or
reload. A trigger restarts or reloads only a running service: a stopped one is
left stopped and starts on the new state when it starts. A trigger on a service
declared <code>running: false</code> is a config error.</p><p>A trigger fires only on a change in the current plan, so a failed reload would
be lost: next run the file is converged and the service is running, on the old
config. Zap keeps one marker per owed service on the target under <code>/var/lib/zap/pending/</code>, written before the first source changes and cleared
after the service's change completes. A failed reload stays owed and re-fires on
the next plan. At least once, never zero.</p><p>A held service, whether detection can't read it or it is held behind another,
holds every source whose change would trigger it: run alone, the source would owe
a restart that no change in the plan performs. Both wait for a plan that can run
the service.</p><h2>The lock file</h2><p>A moving reference makes intent ambiguous in time: a tracked <code>remote</code> file's URL
or a <code>build</code>'s source archive can serve different bytes tomorrow. <code>zap.lock</code>,
next to <code>zap.ts</code> and committed with it, pins each tracked reference to the
blake3 of its resolved bytes. Detection compares the target against that pin, and
only an explicit act moves it: <code>zap update</code> (advance one or all), <code>zap lock</code> (rebuild), or a wetrun recording a pin that was missing. A pin that isn't current is withheld from the read-only commands, so
the resource holds rather than being compared against stale bytes. Full detail: <a>lock.md</a>.</p><h2>Targets and privilege</h2><p>A config has one <strong>target</strong>: your own machine (<code>local: true</code>) or a host over SSH.
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
See <a>deploy.md</a>.</p>`,1);function b(s,b){d(b,!0);let x=h(`concepts`);u(`mhazmq`,e=>{n(()=>{f.title=`Concepts — zap`})}),g(s,{get tome(){return x},children:(n,a)=>{v(n,{children:(n,a)=>{var s=y(),u=t(r(s));l(u,`id`,`the-loop`);var d=t(u);_(d,{lang:null,content:`describe → detect → plan → apply → observe`});var f=t(d,3);l(f,`id`,`convergence`);var h=t(f,7);l(h,`id`,`detection`);var g=t(h,4),v=t(i(g));o(g);var b=t(g),x=t(i(b),7);p(),o(b);var S=t(b,3);l(S,`id`,`dry-run-and-wetrun`);var C=t(S,2);l(C,`id`,`the-plan`);var w=t(C,2),T=t(i(w),5);p(3),o(w);var E=t(w,2);_(E,{lang:null,content:`$ zap plan
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
plan_hash: 5bb79cc9141942676c784abba55826f12be51b3feb86f5f0cf77666545674d61`});var D=t(E,2),O=t(i(D));O.textContent=`{env:NAME}`;var k=t(O,4);p(5),o(D);var A=t(D);l(A,`id`,`a-wetrun-executes-only-the-plan-you-reviewed`);var j=t(A,2),M=t(i(j)),N=t(i(M));l(N,`href`,`#the-last-run-report`),p(9),o(M),o(j);var P=t(j,2),F=t(i(P),3);p(),o(P);var I=t(P),L=t(i(I),11);p(),o(I);var R=t(I),z=t(i(R),2);p(),o(R);var B=t(R);l(B,`id`,`apply-asserts-convergence`);var V=t(B,2);l(V,`id`,`the-last-run-report`);var H=t(V),U=t(i(H),7);p(),o(H);var W=t(H,2);l(W,`id`,`triggers`);var G=t(W,4);l(G,`id`,`the-lock-file`);var K=t(G),q=t(i(K),13);p(),o(K);var J=t(K);l(J,`id`,`targets-and-privilege`);var Y=t(J),ee=t(i(Y),17);p(),o(Y);var X=t(Y);l(X,`id`,`secrets-and-references`);var Z=t(X),te=t(i(Z));p(),o(Z);var Q=t(Z);l(Q,`id`,`deploy`);var $=t(Q),ne=t(i($),6);p(),o($),e((e,t,n,r,i,a,o,s,c,u,d,f)=>{l(v,`href`,e),l(x,`href`,t),l(T,`href`,n),l(k,`href`,r),l(F,`href`,i),l(L,`href`,a),l(z,`href`,o),l(U,`href`,s),l(q,`href`,c),l(ee,`href`,u),l(te,`href`,d),l(ne,`href`,f)},[()=>m(`docs/detection#a-hold-spreads-to-what-cant-run-without-it`),()=>m(`docs/detection#kinds-that-read-a-failed-probe-as-absent`),()=>m(`docs/configs#the-sandbox`),()=>m(`docs/env#secrets`),()=>m(`docs/cli#binding-to-the-review`),()=>m(`docs/env#masked-hosts-and-review`),()=>m(`docs/deploy#binding-a-wetrun-to-a-reviewed-plan`),()=>m(`docs/env#secrets`),()=>m(`docs/lock`),()=>m(`docs/targets`),()=>m(`docs/env`),()=>m(`docs/deploy`)]),c(n,s)},$$slots:{default:!0}})},$$slots:{default:!0}}),a()}export{b as t};