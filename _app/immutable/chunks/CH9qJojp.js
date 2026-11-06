import{G as e,Q as t,W as n,X as r,Y as i,at as a,dt as o,j as s,k as c,l,m as u,ot as d,q as f,ut as p}from"./BTZoVLbz.js";import{t as m}from"./Cyt8LZpN.js";import{n as h}from"./DhdQKFKC.js";import"./BPVwp-J3.js";import{t as g}from"./B2l94Waq.js";import{t as _}from"./BTlkJFeB.js";import{t as v}from"./D23yn-ZR.js";var y=s(`<p><code>cargo xtask differential</code> runs two <code>zap</code> binaries against identical states of
the two VMs in <a>testing.md</a> and fails if they report anything differently. One is a trusted <strong>oracle</strong>, by default a release build of <code>origin/main</code>. The other is a <strong>candidate</strong>, by default the working tree.</p><p>It proves behavioral <strong>equivalence</strong>, not correctness: a refactor that passes it
changed nothing an operator can observe, across real apt, systemd, and ufw
hosts and real apk, OpenRC, and nftables hosts, over SSH and (on Debian)
through the local connection. What it establishes about the candidate alone,
whatever the oracle says:</p><ul><li>with <code>--base-by candidate</code>, that the candidate converges the whole kitchen
sink from <code>pristine</code> through its own review gate, in the fixture's rounds,
and that a further apply then plans nothing but a <code>pipeline</code>;</li><li>that it puts back the drifted state of every scenario that reconverges, and
that a check which never goes through Zap then reads the machine as it did on
the base;</li><li>that it can replace a host's bootstrap user in place, and plan as the user
that replaced it (<a>Replacing the bootstrap user</a>);</li><li>that its plans of one target state agree with each other and name the machine
they are for;</li><li>that nothing it prints holds a raw control character.</li></ul><p>The mechanics are in the module docs, starting at <code>crates/xtask/src/differential/mod.rs</code>; <code>cargo xtask differential --help</code> summarizes them.</p><h2>What it runs</h2><p><strong>1. Base.</strong> From <code>pristine</code>, one of the two binaries (<code>--base-by</code>, the oracle
by default) converges a kitchen-sink config, <code>crates/xtask/fixtures/differential/&lt;distro>/zap.ts</code>, the way an operator does:
a dry <code>apply</code>, then <code>apply --wetrun</code> bound to that preview, in the rounds the
fixture declares (a fixture may declare resources held from <code>pristine</code>, such as
Alpine's <code>database</code> before its service starts). Whichever side builds is held
to that declaration, so an oracle that reads <code>pristine</code> differently can't build
the base; build with <code>--base-by candidate</code>. A last dry <code>apply</code> must then
plan nothing but a <code>pipeline</code>. The config holds every resource kind that
converges on that distro, with edge cases: paths with spaces and quotes, content
with no final newline or with CRLF endings, <code>script</code> checks that read stdin, run
slowly, or carry a reference, tracked and vendored pins, a triggered service, a
firewall that allows <code>22/tcp</code> (the harness's own connection is the lockout
test), and privilege canaries that read <code>ok</code> only when a probe runs in its
expected lane.</p><p>The result is snapshotted as <code>differential-base</code> and reused until a hash of its
inputs changes (the <code>pristine</code> snapshot, the fixtures, the <code>src/lib</code> modules,
the distro's preparation, the test CA, the builder, and the <code>fgro</code> build). <code>--rebase</code> forces a
rebuild.</p><p><strong>2. Scenarios.</strong> For each scenario, the harness reverts to the base and puts
the target in the scenario's state: a root shell mutation (a same-size edit, a <code>chmod</code>, a removed package, a stopped service, <code>swapoff</code>, a flipped firewall
policy, a dropped <code>pg_hba</code> line, a pending-trigger marker), an operator-side
change (a <code>zap.lock</code> entry dropped or made stale, an env var changed or unset),
or both. Then it runs both binaries, each with its own fresh <code>ZAP_HOME</code> and its
own staged copy of the fixtures, over <code>detect --no-cache</code>, <code>plan --no-cache --diff</code>, and <code>plan --no-cache</code>. Scenarios with <code>remote</code> files
run twice, with a cold and a warm content cache. One scenario, <code>bootstrap-replace</code>, is of its own kind: it compares nothing
(<a>Replacing the bootstrap user</a>).</p><p><strong>3. Reconverge.</strong> A scenario that drifts declared state Zap can put back in one
offline round carries a <strong>probe</strong>: a root shell snippet that never goes through
Zap and prints the state the scenario touches (the firewall's policy and rules,
as the kernel holds them and as their files say, a user's password field and <code>authorized_keys</code>, the database's <code>pg_hba</code> rules), read where it is in force
rather than only where detection reads it.
The probe reads the base before the mutation and the target right after it,
where it must read differently, or the drift didn't take. Once the read-only
runs are compared and audited, the candidate alone, with its own staged tree and
a fresh <code>ZAP_HOME</code>, applies the drifted state back the way an operator does: a
dry <code>apply</code> that must plan exactly the scenario's expected resources and nothing
else but a <code>pipeline</code>, then <code>apply --wetrun</code> bound to it, which must complete
every change and run the reviewed <code>plan_hash</code>. A further dry <code>apply</code> must then
plan nothing but a <code>pipeline</code>, <code>detect</code> must read every resource but the <code>pipeline</code> <code>ok</code> (a <code>pipeline</code> reads <code>absent</code> by design), and the
probe must read what it read on the base. The probe is the check that isn't
circular: a detector that misreads wrong state as converged passes Zap's own
checks and fails it. The candidate alone applies because the read-only phase has
already compared its plan of that state with the oracle's; executing it is the
candidate's own property.</p><p><strong>4. Remote content</strong> is generated deterministically and served from inside
xtask: plain HTTP on loopback for the Zap runs on your machine, and an https
origin on the libvirt gateway address for everything a guest fetches, under a
test CA the harness makes once with <code>openssl</code> and keeps in <code>~/.cache/zap-differential/pki</code>. The CA is name-constrained to the names the
origin serves, and only the <code>differential-base</code> snapshots trust it, never your
machine or <code>pristine</code>. There is no external fetch.</p><p><strong>5. Locks.</strong> Each binary mints its own <code>zap.lock</code> with <code>zap lock</code>, and the two
are compared: a different version, toolchain pin, or entry pin is an <code>ERROR</code>;
the same pins with a different <code>config_hash</code> are a divergence under <code>--compare exact</code> and only reported under <code>--compare semantic</code>.</p><p><strong>6. Local suite</strong> (Debian only). Both binaries, and the <code>fgro</code> build, are
copied to the VM and run there as <code>ops</code>, with <code>--fgro</code>, against a <code>local: true</code> fixture (<code>debian-local/zap.ts</code>), covering
the local connection's native reads and its <code>sudo</code> fallback.</p><p>Each binary's fixtures, and the local suite's bundle on the VM, are staged as a
project of their own: a <code>package.json</code> at the root and the <code>src/lib</code> modules
copied in, so the configs' project, and the box they evaluate in, is that tree. A
run's scratch tree is a directory under <code>~/.cache/zap-differential/runs</code>, named
for its process. It is removed when the run ends, and a killed run's is removed
by the next run.</p><p>Each VM is left at <code>differential-base</code> afterwards, or at <code>pristine</code> if no base
could be built. A run writes nothing into the repo.</p><h2>What makes a scenario count</h2><p>Two binaries that fail the same way would match, so a compared scenario is an <code>ERROR</code>, and the run fails, unless:</p><ul><li>the oracle's output is a well-formed report: exit 0 or 1, a <code>detect</code> that
reports every fixture resource, and a <code>plan_hash:</code> line on each plan;</li><li>no run timed out;</li><li>the oracle's <code>detect</code> moved exactly the resources the scenario expects, with
their marks (some expectations pin a known oracle defect; the scenario table
labels each);</li><li>the runs were read-only and network-free: neither listener saw a connection,
no file changed under the audited roots (<code>/etc</code>, <code>/opt</code>, <code>/home</code>, <code>/root</code>, <code>/srv</code>, <code>/usr</code>, <code>/lib</code>, <code>/var/lib</code>, any regular file directly under <code>/</code>, and <code>/</code> itself), and the runtime state no
file shows (the firewall ruleset with handles, running services with their
identity, <code>/proc/swaps</code>, the postgres roles and databases) reads the same.
Only proven churn is excluded, and the audit must show its own anchors (the
fixture's sleeper service, the <code>postgres</code> role, an active firewall), so a
probe failing the same way before and after can't pass blind;</li><li>the candidate's own output is consistent: its <code>plan</code> and <code>plan --diff</code> of one
state (and its cold and warm runs) print one and the same <code>plan_hash</code>; each
plan names its machine directly under the header (over SSH, <code>host:</code> and <code>user:</code> lines, then <code>target:</code>; on the local suite, <code>user:</code> and <code>home:</code> lines,
then <code>target:</code>); and no line of its output holds a control character;</li><li>in a scenario that reconverges, every check of the reconverge phase holds,
the apply fetched no remote content, and it left the candidate's <code>zap.lock</code> as <code>zap lock</code> minted it. A failure here is tagged <code>[reconverge]</code>, so it reads
apart from a failure of the read-only phase.</li></ul><p>Only an SSH scenario reconverges, and only one whose expected marks are all <code>drift</code> or <code>absent</code> (a held <code>?</code> stops the preview at exit 1), with no
operator-side change and no <code>remote</code> content: the apply fetches nothing.</p><h2>Replacing the bootstrap user</h2><p><code>bootstrap-replace</code> rehearses what an operator does once a host is up: replace
the stock account it was brought up with
(<a>The bootstrap user</a>) by a user of its own,
then remove the stock account. It runs on both distros, in the default matrix,
with the candidate alone and its own small configs, <code>crates/xtask/fixtures/bootstrap/</code>, kept apart from the kitchen sinks so the
base doesn't depend on them. From the base:</p><ol><li><strong>Provision.</strong> <code>zapnext</code> doesn't exist yet. A config whose target connects
as <code>zapnext</code>, with <code>ops</code> as its <code>bootstrap_user</code>, declares that user with <code></code>, <code>sudo: 'nopasswd'</code>, and <code>/bin/sh</code>. It is
locked, previewed with <code>apply --bootstrap</code>, which must plan the user's
creation and nothing else and name <code>ops</code> as its user, applied with <code>apply --bootstrap --wetrun</code> bound to that preview, and previewed again,
which must plan nothing.</li><li><strong>Prove.</strong> Over its own login, <code>zapnext</code> is who it says, <code>sudo -n true</code> works, and the grant is Zap's: <code>/etc/sudoers.d/zapnext</code> holds Zap's line,
root's at <code>440</code>, and <code>zapnext</code> is in no <code>sudo</code>, <code>wheel</code>, or <code>admin</code> group.
Its <code>authorized_keys</code> is <code>ops</code>'s, byte for byte.</li><li><strong>Retire.</strong> As root through <code>zapnext</code>'s login (a session of <code>ops</code> can't
remove <code>ops</code>), <code>ops</code>'s sessions are ended and its processes killed, a
bounded wait sees none left, and <code>userdel -r ops</code> runs without <code>-f</code>, so a
process that outlives the kill fails it. On Debian, cloud-init's <code>/etc/sudoers.d/90-cloud-init-users</code>, which grants <code>ops</code> by name, must grant
no one else, and is removed.</li><li><strong>After.</strong> As <code>zapnext</code>: <code>ops</code> has no account, no home, no sudoers line, and
no group, <code>visudo -c</code> passes, and <code>zapnext</code>'s keys are unchanged. A login as <code>ops</code> is refused, and a login as <code>zapnext</code> right after succeeds, so a VM
that went down can't read as the refusal.</li><li><strong>Plan as <code>zapnext</code>.</strong> A second config declares the same user with the same
attributes, its keys as the list it holds (a module the harness writes from <code>zapnext</code>'s <code>authorized_keys</code>, never checked in). Its <code>plan</code>, without <code>--bootstrap</code>, reads <code>(no changes — converged)</code> and names <code>zapnext</code> as its
user. The first config, its <code>copy_from</code> source gone, plans the user again,
and its <code>detect</code> gives the reason, <code>ssh keys unreadable</code>: a missing source
reads as drift to apply, never as converged.</li></ol><!><p>It proves that sequence on these VMs, not every host's: a host whose sshd
admits only some users (<code>AllowUsers</code>), or whose stock account holds sudo some
other way, needs its own steps. It doesn't compare the two binaries or run
the read-only audit: it writes on purpose, and the audit reaches the VM as <code>ops</code>. Its own checks stand in: root's reading of the accounts and sudoers
after the retire, and the run fetching nothing. Every step after the retire
reaches the VM as <code>zapnext</code>. The revert that starts the next scenario, or the
run's last one, brings <code>ops</code> back.</p><p>Under <code>--keep</code> it stops after step 2, leaving <code>ops</code> in place: a VM left
without <code>ops</code> stops the next run before any revert, since the harness waits
for the VM as <code>ops</code>. A run killed after the retire leaves it that way; revert
the VM by hand:</p><!><h2>Prerequisites</h2><ul><li>Both VMs from <a>testing.md</a>, each with a <code>pristine</code> snapshot and your key in <code>ops</code>'s <code>authorized_keys</code>.</li><li><code>ZAP_FGRO</code>, the absolute path of the <code>fgro</code> build both binaries evaluate the
fixtures with. Each run is given it as <code>--fgro</code>; each staged config, and the
local bundle's, starts beside a <code>zap.lock</code> pinning it, generated from that
binary rather than checked in, since an <code>fgro</code> build names one machine's
bytes; and the local bundle carries a copy to the Debian VM, whose kernel
must hold <code>fgro</code>'s sandbox (Landlock ABI 6 or later).</li><li>GNU <code>tar</code> and <code>gzip</code>, and <code>ping</code>.</li><li><code>openssl</code> on <code>PATH</code>, the first time, to make the test CA.</li><li>The libvirt <code>default</code> network active, and guests able to reach a TCP port on
its gateway address (<a>the firewall note</a> applies to this too).</li><li>An oracle that evaluates through <code>fgro</code> (it takes <code>--fgro</code>), and keeps its SSH
control socket under its <code>ZAP_HOME</code>, as the working tree does. The harness
checks both before it starts a VM: a <code>zap</code> build that predates <code>fgro</code> can't read the
staged locks.</li><li>No root: your user in the <code>libvirt</code> group
(<a>Prerequisites</a>).</li></ul><h2>Running it</h2><!><table><thead><tr><th>Flag</th><th>Default</th><th>Meaning</th></tr></thead><tbody><tr><td><code>--oracle &lt;path></code></td><td>a build of <code>--oracle-rev</code></td><td>the reference binary</td></tr><tr><td><code>--oracle-rev &lt;rev></code></td><td><code>origin/main</code></td><td>the committed revision the oracle is built from; not with <code>--oracle</code></td></tr><tr><td><code>--candidate &lt;path></code></td><td>a release build of the working tree</td><td>the binary under test</td></tr><tr><td><code>--distro &lt;name></code></td><td>both</td><td><code>alpine</code> or <code>debian</code>; repeatable</td></tr><tr><td><code>--scenario &lt;name></code></td><td>all</td><td>an exact scenario name; repeatable. An unknown name lists the valid ones.</td></tr><tr><td><code>--compare &lt;level></code></td><td><code>exact</code></td><td><code>exact</code> or <code>semantic</code>; see <a>compare levels</a></td></tr><tr><td><code>--base-by &lt;side></code></td><td><code>oracle</code></td><td><code>oracle</code> or <code>candidate</code>: which binary builds the base</td></tr><tr><td><code>--rebase</code></td><td>off</td><td>rebuild the base even when its hash matches</td></tr><tr><td><code>--keep</code></td><td>off</td><td>skip the final revert and every reconverge phase, so you can inspect the VM in the last scenario's state (drifted, for a scenario that reconverges), or, after a failed base build, in the state the builder left it; <code>bootstrap-replace</code> stops before it retires <code>ops</code></td></tr></tbody></table><p>Without <code>--oracle</code>, the oracle is <code>~/.zap/oracle/zap-&lt;short-rev></code> for the commit
the revision names, as the local ref stands (nothing is fetched). It is reused
while that file is there; delete it to force a rebuild. Otherwise the harness
builds it the way you would by hand: the revision's tree from <code>git archive</code> in a
temporary directory under <code>~/.cache/zap-differential</code>, beside a link to each
sibling checkout its <code>Cargo.toml</code> names by relative path, then <code>cargo build --release -p zap</code> there under the revision's own <code>rust-toolchain.toml</code> (<code>CARGO_BUILD_JOBS</code> applies), and the executable copied
into place. A sibling such as <code>../fuz</code> is linked as it stands now,
uncommitted changes included, not as it was at the revision. The temporary
directory is removed afterwards; one an interrupted build left behind is removed
by the next build. The run prints which oracle it used:</p><!><p>The default is <code>origin/main</code> rather than the checked-out branch's upstream: the
oracle is what has landed, whatever branch the working tree is on.</p><table><thead><tr><th>Exit status</th><th>Meaning</th></tr></thead><tbody><tr><td>0</td><td>every scenario matched</td></tr><tr><td>1</td><td>any divergence or harness error</td></tr><tr><td>2</td><td>a usage error</td></tr></tbody></table><p>The run prints both binaries' blake3 and warns when they are byte-identical:
such a run checks the harness and the targets, but proves nothing about a
change.</p><h2>Reading the output</h2><p>Each scenario prints <code>PASS</code>, <code>DIVERGED</code>, or <code>ERROR</code>, its phase times, what its
mutation does, and the resources the <strong>oracle's</strong> <code>detect</code> saw leave <code>ok</code>; a
scenario that reconverges also times that phase and says when the candidate put
the state back:</p><!><p>A reconverge failure is an <code>ERROR</code> whose message starts <code>[reconverge]</code> and names
the check that failed; a probe that doesn't read the base again prints the
difference, <code>-</code> for the base and <code>+</code> for after the apply. A probe reads what the
declaration governs, no more: the <code>pg_hba</code> probe reads which of the database's
rules are present, not where, since Zap puts a missing rule ahead of the first <code>host</code> line rather than back where it stood.</p><p>A divergence prints, per command and stream, a unified diff with <code>-</code> for the
oracle and <code>+</code> for the candidate, tagged <code>[cold]</code>, <code>[warm]</code>, or <code>[local]</code>:</p><!><p>Only what differs between the runs by construction is normalized: each run's <code>ZAP_HOME</code> path (<code>&lt;ZAP_HOME></code>), the binary's own path (<code>&lt;ZAP></code>), and its staged
fixture tree (<code>&lt;STAGE></code>). Everything else, exit codes and stderr included, is
compared verbatim, so every diff line is a behavior change: either the intended
one, which you record, or a regression.</p><p>An <code>ERROR</code> is not a verdict; the message says which check above failed, or that
the VM was unreachable, the base didn't converge, the two locks pinned different
things, or an intended-divergence entry went stale.</p><h2>Compare levels</h2><p><code>--compare exact</code>, the default, compares byte for byte. <code>--compare semantic</code> is
for an oracle that renders a plan differently by design: it projects both sides
down to what each command decided (verdicts, banners, held resources, the set
and order of changes with their action, triggers, <code>--diff</code> attribute lines,
warnings, exit codes) and leaves out each plan's machine and <code>references:</code> block, the lines under a change, and the value of <code>plan_hash</code>. So a semantic <code>PASS</code> doesn't establish that the two binaries would run the same commands or
compute the same hash. The projection is <code>compare::project_lines</code>.</p><p>A change to what a plan's steps run, such as an extraction script, moves the <code>plan_hash</code> of every plan that runs it, and that hash also binds the plan's
references, among them the per-run port of the harness's loopback content server,
so no entry can record it. Against an oracle that predates such a change, an exact
run diverges on those lines by design: compare at the semantic level, where the
intended entries still apply. The exact level passes again once the oracle is a
build that carries the change.</p><h2>Intended divergences</h2><p>A candidate that changes behavior on purpose diverges by construction. Each such
change is an entry in <code>crates/xtask/src/differential/intended.rs</code>: the distro,
suite, scenario, cold or warm variant, command, the exact oracle and candidate
lines, the resource, and the reason. Matching is whole lines, exact bytes, and
only for the run the entry names; an accepted line prints as an <code>INTENDED</code> block
and doesn't fail the scenario:</p><!><p>An entry whose lines aren't among its run's changed lines is an <code>ERROR</code>, so
when the oracle is replaced by a build that already behaves the new way, its
entries fail and the table empties itself out. The table is reviewed like code.</p>`,1);function b(s,b){d(b,!0);let x=h(`differential`);u(`7mqkvy`,e=>{n(()=>{f.title=`The differential harness — zap`})}),g(s,{get tome(){return x},children:(n,a)=>{v(n,{children:(n,a)=>{var s=y(),u=r(s),d=t(i(u),4);p(7),o(u);var f=t(u,2),h=t(i(f),2),g=t(i(h));l(g,`href`,`#replacing-the-bootstrap-user`),p(),o(h),p(2),o(f);var v=t(f,2);l(v,`id`,`what-it-runs`);var b=t(v,3),x=t(i(b),22);l(x,`href`,`#replacing-the-bootstrap-user`),p(),o(b);var S=t(b,7);l(S,`id`,`what-makes-a-scenario-count`);var C=t(S,4);l(C,`id`,`replacing-the-bootstrap-user`);var w=t(C),T=t(i(w),2);p(3),o(w);var E=t(w),D=i(E),O=t(i(D),10);O.textContent=`ssh_keys: {copy_from: 'ops'}`,p(11),o(D),p(4),o(E);var k=t(E);_(k,{lang:null,content:`  PASS     ssh/bootstrap-replace           11.1s  (revert 7.5s, provision 1.3s, prove 0.8s, retire 0.5s, after 1.0s)
           the bootstrap user replaced in place: zapnext provisioned with --bootstrap, then ops retired over zapnext's own login
           zapnext logs in, its sudo is zap's grant alone, and it holds ops's keys
           ops retired: no account, home, sudoers line, or group; its login is refused
           as zapnext: the retired config reads converged; the provision config's copy_from source reads unreadable, not converged`});var A=t(k,3);_(A,{lang:`sh`,dangerous_raw_html:`virsh -c qemu:///system snapshot-revert <span class="token_operator">&lt;</span>domain<span class="token_operator">></span> differential-base`});var j=t(A);l(j,`id`,`prerequisites`);var M=t(j),N=i(M),P=t(i(N));p(7),o(N);var F=t(N,4),I=t(i(F),3);p(),o(F);var L=t(F,2),R=t(i(L),3);p(),o(L),o(M);var z=t(M);l(z,`id`,`running-it`);var B=t(z);_(B,{lang:`sh`,dangerous_raw_html:`cargo xtask differential                                  <span class="token_comment"># origin/main vs the working tree, both VMs</span>
cargo xtask differential --distro alpine --scenario firewall-policy
cargo xtask differential --oracle-rev <span class="token_operator">&lt;</span>rev<span class="token_operator">></span>               <span class="token_comment"># the oracle built from another revision</span>
cargo xtask differential --oracle ./zap-reference         <span class="token_comment"># a binary you built</span>
cargo xtask differential --candidate ./zap-under-<span class="token_builtin">test</span> --keep
cargo xtask differential --base-by candidate              <span class="token_comment"># the candidate builds the base</span>
cargo xtask differential --compare semantic               <span class="token_comment"># compare decisions, not rendering</span>
cargo xtask differential --help                           <span class="token_comment"># every flag</span>`});var V=t(B),H=t(i(V)),U=t(i(H),5),W=t(i(U),2),G=t(i(W),4);l(G,`href`,`#compare-levels`),o(W),o(U),p(3),o(H),o(V);var K=t(V,2);_(K,{lang:null,content:`oracle rev origin/main = 6cab2de (reused /home/ops/.zap/oracle/zap-6cab2de)`});var q=t(K,4);l(q,`id`,`reading-the-output`);var J=t(q,2);_(J,{lang:null,content:`  PASS     ssh/firewall-policy             25.1s  (revert 5.0s, zap runs 6.0s, audit 0.3s, reconverge 12.4s)
           default incoming policy flipped to allow
           oracle detect moved: firewall(drift)
           candidate reconverged it: the probe reads the base again`});var Y=t(J,3);_(Y,{lang:null,content:`  DIVERGED ssh/converged                   14.2s  (revert 6.5s, zap runs 7.7s, audit 0.3s)
           oracle detect moved: nothing
  [cold] detect:
    stdout:
        --- oracle
        +++ candidate
          …
            ok     sleeper-init  file  — converged
        -   ok     sleeper  service  — converged
        +   drift  sleeper  service  — drifted (running=false, enabled=true)
            ok     postgresql  package  — converged
          …`});var X=t(Y,3);l(X,`id`,`compare-levels`);var Z=t(X,3);l(Z,`id`,`intended-divergences`);var Q=t(Z,2);_(Q,{lang:null,content:`  PASS     ssh/file-edge-cases             19.9s  (revert 4.8s, zap runs 13.4s, audit 0.4s)
           …
  INTENDED [cold] detect Stdout source-copy: the unreadable-source hold names the path, not the old \`cat\` stderr
    -   ?      source-copy  file  — undetermined: failed to render content: failed to read file …
    +   ?      source-copy  file  — undetermined: failed to read the content source: …`}),p(),e((e,t,n,r,i)=>{l(d,`href`,e),l(T,`href`,t),l(P,`href`,n),l(I,`href`,r),l(R,`href`,i)},[()=>m(`docs/testing`),()=>m(`docs/targets#the-bootstrap-user`),()=>m(`docs/testing`),()=>m(`docs/testing#gotchas`),()=>m(`docs/testing#prerequisites`)]),c(n,s)},$$slots:{default:!0}})},$$slots:{default:!0}}),a()}export{b as t};