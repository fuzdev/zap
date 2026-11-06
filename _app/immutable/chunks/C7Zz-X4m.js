import{G as e,Q as t,W as n,X as r,Y as i,at as a,dt as o,j as s,k as c,l,m as u,ot as d,q as f,ut as p}from"./BTZoVLbz.js";import{t as m}from"./Cyt8LZpN.js";import{n as h}from"./DhdQKFKC.js";import"./BPVwp-J3.js";import{t as g}from"./B2l94Waq.js";import{t as _}from"./BTlkJFeB.js";import{t as v}from"./D23yn-ZR.js";var y=s(`<p><code>zap deploy</code> ships a versioned release of your application to a remote host over
SSH and swaps it in atomically, with a health gate and automatic rollback. The
host is one your config already converges with <code>zap apply</code>: the same tool that
built the machine ships the app, and the deploy refuses to ship onto a host that
has drifted from its config.</p><p>Deploy is the one imperative command. Each run produces a new release, so there
is nothing to converge to. It still plans before it acts: a dry run prints
every step with the command, script, or URL behind it, and a wetrun executes
only <a>the plan a dry run showed</a>.</p><h2>Configuration</h2><!><table><thead><tr><th>Field</th><th>Required</th><th>Meaning</th></tr></thead><tbody><tr><td><code>build</code></td><td>no</td><td>command run locally before packaging; omit it, or pass <code>--skip-build</code>, and the plan has no build step</td></tr><tr><td><code>artifacts</code></td><td>yes</td><td>files and directories, relative to the directory you run <code>zap</code> from, packaged into the release. An entry can't begin with <code>-</code> (<code>tar</code> would read it as an option; write <code>./-name</code>) or with <code>@</code> (which some <code>tar</code>s read as an archive to include)</td></tr><tr><td><code>path</code></td><td>yes</td><td>the remote app root: holds <code>releases/</code>, <code>shared/</code>, and the <code>current</code> symlink. An absolute path, written out (no reference, no <code>~</code>); it must exist and be writable by the connecting user, which <code>zap apply</code> usually arranges</td></tr><tr><td><code>releases</code></td><td>no</td><td>how many releases to keep, the live one included (default 5). At least 2: the release just deployed and the one it replaced are always kept, since a failed deploy rolls back to the second</td></tr><tr><td><code>service</code></td><td>no</td><td>the service restarted after the swap; requires <code>target.service_manager</code>; takes no reference</td></tr><tr><td><code>shared</code></td><td>no</td><td>files under <code>&lt;path>/shared/</code> symlinked into each release root. Each entry is a relative name of a file: no <code>..</code> component, no control character, not ending in <code>/</code> or in a <code>.</code> component (<code>config/.</code>); anything else is rejected by the structural gate. Each must exist (<code>zap apply</code> usually writes it): the deploy fails before extracting otherwise</td></tr><tr><td><code>prepare</code></td><td>no</td><td>commands run on the target in the new release, as the connecting user, before the swap, each in a shell of its own; the release is still under a hidden staging name then, so a command shouldn't record its absolute path</td></tr><tr><td><code>health</code></td><td>no</td><td>the post-restart health gate, below</td></tr></tbody></table><h3><code>health</code></h3><table><thead><tr><th>Field</th><th>Required</th><th>Meaning</th></tr></thead><tbody><tr><td><code>domain</code></td><td>yes</td><td>the host polled over HTTPS; usually a <code>zap.env('DEPLOY_DOMAIN')</code> reference</td></tr><tr><td><code>path</code></td><td>yes</td><td>the request path, beginning with <code>/</code> (<code>/health</code>, or <code>/ready</code> to make it the gate); takes no reference</td></tr><tr><td><code>attempts</code></td><td>no</td><td>polls before the deploy fails (default 15), at least 1</td></tr><tr><td><code>interval_ms</code></td><td>no</td><td>delay between polls in milliseconds (default 2000)</td></tr></tbody></table><p>Omit the block to deploy with no health gate and no readiness check; there is no flag to disarm a
declared one.</p><h2>Commands</h2><!><p>A wetrun binds to a preview made with the same plan-changing flags
(<a>below</a>). <code>--env-file &lt;path></code> loads the
operator env first, as for every command. Flags, exit codes, and what a dry run
reads: <a>cli.md</a>.</p><p><strong>What it needs.</strong> On your machine: <code>git</code>, <code>tar</code> with <code>gzip</code>, and <code>ssh</code>, with <code>zap</code> run from
inside the application's git checkout. On the target: what a file write needs
(<a>targets.md</a>), plus <code>tar</code>, <code>id</code>, and <code>flock</code>.</p><h2>First deploy</h2><p>A first deploy onto a fresh host is a chicken-and-egg: the binary lands via <code>deploy</code>, but <code>deploy</code>'s preflight requires a converged <code>apply</code>, and a <code>service</code> declared <code>running: true</code> can't be running before there is anything to run.
Resolve it in the config: declare the service <code>enabled</code> and leave <code>running</code> unset.</p><!><p>Then the bring-up is two reviewed runs: <code>zap apply</code>, then <code>zap apply --wetrun</code>,
provisions the host (firewall included, so deploying first would bail), and <code>zap deploy</code>, then <code>zap deploy --wetrun</code>, ships the first release, whose
restart step starts the service. Preview the deploy after the apply has run:
the dry run connects as the user the apply sets up, and a pin the apply writes
to <code>zap.lock</code> is part of the deploy plan.</p><p>The trade is explicit: a config that leaves <code>running</code> unset tells Zap never to
assert that the app is up, so <code>zap apply</code> on a host whose daemon crashed and
stayed down reports converged. Declaring <code>running: true</code> buys that assertion
back at the cost of one <code>deploy --wetrun --skip-preflight</code> on the very first
release (previewed with <code>deploy --skip-preflight</code>, since the flag is part of
the plan), and <code>--skip-preflight</code> disables the whole drift gate for that run.</p><p>When SSH hardening changes the user Zap connects as, add <code>--bootstrap</code> to the
first apply: <a>targets.md</a>.</p><h2>Binding a wetrun to a reviewed plan</h2><p>A dry run prints the whole plan and ends with its hash:</p><!><p>A wetrun executes only a plan you were shown. It computes its plan again, and
that plan's hash must equal the reviewed one:</p><ul><li><code>--expect-plan &lt;hash></code> names the reviewed plan explicitly, and binds alone;</li><li>with no flag, the reviewed plan is the <strong>deploy preview</strong> recorded for this
config and host: the last <code>zap deploy</code> dry run, or a wetrun that refused.</li></ul><p>Otherwise the wetrun <strong>refuses</strong> before the drift preflight and any step,
prints the plan it would have run under a <code>REFUSED</code> banner that says why (no
preview yet, the plan changed since the preview, or the hash doesn't match),
records that render as the new preview, and exits 2. Nothing is built or
uploaded. The everyday flow is <code>zap deploy</code>, read it, <code>zap deploy --wetrun</code> with the same flags. A wetrun fired cold becomes the preview, and the next one
executes if nothing moved. There is no flag that skips the review, and a dry
run rejects <code>--expect-plan</code>.</p><p>On an interactive terminal (standard input and standard error both terminals),
a wetrun with no review and no <code>--expect-plan</code> shows the plan instead, under an <code>UNREVIEWED</code> banner with its <code>plan_hash</code>, and ends with the question:</p><!><p>Typing those eight characters back is the review: the wetrun goes on with
exactly the plan shown, to the drift preflight, the withdrawal of any recorded
preview, and the steps, as a bound wetrun does. Any other answer is the refusal
above, under a <code>DECLINED</code> banner. The prompt follows <code>zap apply</code>'s rules: no
flag answers it, <code>--json</code> never asks, and a script stays non-interactive by
previewing first, passing <code>--expect-plan</code>, or running with standard input that
isn't a terminal (<a>cli.md</a>).</p><p>One recorded preview covers one execution: a wetrun that passes the review and
the preflight withdraws it before its first step, so a deploy that fails needs a
new preview (or <code>--expect-plan</code>) before it runs again, and of two wetruns
started on one preview only one goes on. An <code>--expect-plan</code> hash is not
single-use. A preflight bail or an already-deployed exit leaves the preview in
place. A preview doesn't expire.</p><p>The preview is a small file under <code>~/.zap</code> (<a>lock.md</a>), separate from the last-run report that <code>zap apply</code> binds to: a <code>zap plan</code> doesn't disturb a deploy preview, and a
deploy dry run doesn't disturb a convergence one. It holds the hash, not the
plan. A deploy wetrun's drift preflight does replace the convergence record: it
records its pass as the last-run report, which is no preview, so a <code>zap apply</code> previewed before it needs a new preview before its wetrun. With no state
directory nothing is recorded, the run says so, and only <code>--expect-plan</code> binds.</p><p>Everything the hash covers is printed but two of Zap's own scripts: the one the
upload installs the archive with, and the swap the auto-rollback runs. So a plan
reviewed under one <code>zap</code> build doesn't bind one whose scripts differ. It covers:</p><ul><li>the version, the tree state, and the previous release on the target;</li><li>the declared target, the host it resolves to, and the connecting user (in the
uploaded archive's name);</li><li>who is deploying (<code>user@host</code> of the operator machine, recorded in <code>deploy_info.json</code>);</li><li>the preflight's state: skipped, nothing declared, or which apply-managed
resources it checks, as a count and a digest of their declarations and the
current pins <code>zap.lock</code> holds for them;</li><li>every step: the build and tarball commands, the upload paths and the script
that installs the archive, the remote script with its <code>shared</code> links and <code>prepare</code> commands, the restart command, the health and readiness URLs as
they resolve, and the swap the auto-rollback would run;</li><li>the value of each reference the <code>deploy</code> block uses (its health domain),
printed in its <code>references:</code> block (a secret's value excepted: the plan
records only that it is one).</li></ul><p>So a plan reviewed for one host, tree, flag set, or operator does not bind a
wetrun for another: a new commit, a deploy or rollback by someone else in
between, an edit to any declared resource, a changed pin in <code>zap.lock</code>, <code>--force</code> on a dirty tree, <code>--skip-build</code>, <code>--skip-preflight</code>, or <code>--bootstrap</code> each make a different plan. The hash is printed, and the preview recorded, only
when the steps are shown: an already-deployed dry run does neither, so a
redeploy binds to the plan a <code>--force</code> dry run shows.</p><p>It does not cover:</p><ul><li>the artifact bytes. The version names the commit, and the plan says whether
the tree was dirty, but what the build produces is not hashed. The review
covers the script that verifies the archive it was sent, not the archive.</li><li>the values a resource's references resolve to. The digest takes
each declaration as written, so it is the same in every environment; the
environment reaches the hash only through the host, the connecting user, and
the health domain. The same holds for the bytes of a local <code>source</code> file.</li></ul><p><strong>A masked host, connecting user, or health domain can't be deployed to.</strong> No
review can bind such a plan: a wetrun is an error that names the reference
before anything runs, and a dry run shows the plan under an <code>UNBINDABLE</code> note,
with no <code>plan_hash</code> and no recorded preview. The ways out: <a>env.md</a>.</p><p>Text from the config, the environment, and the target is printed with control
characters written out as <code>&lt;U+XXXX></code>, so a value can't hide or forge a line of
the preview (<a>security.md</a>).</p><h2>Preflight</h2><p>Before deploy touches the network, the machine-free gates run (secrets,
structure, and, for a deploy config, a present <code>health.domain</code>), and a wetrun
rejects any unset reference and a host, connecting user, or health domain behind
a masked reference. <code>zap.lock</code> is read here too, when the drift preflight will
check. <code>--skip-preflight</code> doesn't skip the gates.</p><p>Then a wetrun checks its <a>review</a> and runs
the <strong>drift preflight</strong>: the convergence pass against the config, before
building or uploading. If apply-managed state (an nginx site, the
env file, the service unit) was edited in the config but never applied, shipping
a new artifact against it would be a silent mismatch; the preflight bails with
exit 2, and a change held behind a resource it couldn't read counts as drift. A <code>pipeline</code>, which detects absent and runs on every apply, is not drift, and
neither is a service that changes only because its trigger fires, planned or
held: it reads converged, no pending restart or reload is recorded for it, and
every source that fires it is itself not drift (a pipeline, or another such
service). A service that also drifted, one owed an action an earlier apply
never completed, or one fired by any other change is drift.
It also bails, with the same code, when any resource is <code>undetermined</code>: a gate
that couldn't check everything doesn't pass by default.</p><p>After a drift bail, review the changes with <code>zap apply</code>, converge with <code>zap apply --wetrun</code>, and re-run the deploy: its review still binds unless <code>zap.lock</code> changed.</p><p><code>--skip-preflight</code> skips the drift preflight, and a config that declares no
apply-managed resources has nothing to check. Either way the plan says so on its <code>preflight:</code> line.</p><p>The deploy also refuses when the live release already has this version, on a
dry run too (<code>server already at this version</code>, exit 0). <code>--force</code> ships anyway.
A <code>current</code> that names this version but whose release isn't on the host serves
nothing, so it isn't refused: the run plans a redeploy and warns that <code>current</code> names a release that is not on the host.</p><h3>Dirty trees</h3><p>A tree with uncommitted changes or untracked files git doesn't ignore deploys
only under <code>--force</code>, as <code>&lt;hash>-dirty-&lt;id></code>. Without it, a wetrun is refused
before the target is contacted (exit 2), since the release would ship the tree
under the commit's version; a dry run shows the plan
(<code>tree: uncommitted changes or untracked files</code>) with no hash, records nothing,
and says the wetrun is refused, even when the commit is the live release.</p><p>The id is 8 lowercase hex of a blake3 over what the tree adds to the commit, so
the same tree gets the same id (a dry run and its wetrun agree) and a second
dirty tree on one commit is a release of its own:</p><table><thead><tr><th>In the tree</th><th>Counts by</th></tr></thead><tbody><tr><td>tracked and staged changes</td><td><code>git diff HEAD --binary</code></td></tr><tr><td>an untracked file git doesn't ignore</td><td>its name and contents</td></tr><tr><td>an untracked symlink</td><td>the path it points to, as git records one, whether that is a file, a directory, or nothing</td></tr><tr><td>an untracked nested repository</td><td>its name alone</td></tr><tr><td>a submodule</td><td>its commit and whether its own index shows changes, not what they are</td></tr><tr><td>a sparse checkout</td><td>the files outside its cone, as deletions: the tree reads dirty</td></tr></tbody></table><p>Zap reads the tree against a copy of the index's entries that holds no
timestamps or flags, so every file is compared by its contents: a file the
index marks unchanged (<code>assume-unchanged</code>, <code>skip-worktree</code>) counts like any
other, and so does one whose timestamps the index's cache would take for
unchanged. Each read sets <code>core.fsmonitor=false</code>, <code>core.untrackedCache=false</code>, <code>core.ignoreStat=false</code>, <code>core.fileMode=true</code> (a mode change counts), <code>core.autocrlf=false</code> (line endings are not converted), and <code>core.splitIndex=false</code>, and passes <code>--untracked-files=normal</code> and <code>--ignore-submodules=none</code>, so <code>status.showUntrackedFiles</code>, a submodule's <code>ignore</code> setting, and <code>diff.ignoreSubmodules</code> don't narrow it either. So a
checkout on a filesystem without executable bits, or one checked out with <code>core.autocrlf=true</code>, reads dirty, and deploys only under <code>--force</code>.</p><p>Two things still decide what counts as a change. The checkout's attributes
(<code>.gitattributes</code>, <code>.git/info/attributes</code>) are applied: a clean filter, LFS
among them, or an <code>eol</code> or <code>text</code> attribute can make a file that differs from
the commit compare equal to it, and no flag turns them off. A submodule's own
index is read as it is, so an <code>assume-unchanged</code> edit or stale timestamps
inside one can read clean.</p><p>A sparse checkout reads dirty and deploys only under <code>--force</code>: the files
outside its cone aren't there, so the tree the build sees is not the commit's.</p><p>A tree Zap can't read is an error that says what git said, not a clean tree.</p><h2>The release mechanism</h2><p>Once the <a>preflight</a> passes, a wetrun runs these steps in order:</p><!><ol><li><strong>build</strong>: run <code>deploy.build</code> locally (<code>gro build</code>, <code>cargo build --release</code>,
whatever produces your artifacts). With <code>--skip-build</code>, or when no build
command is declared, the plan has no build step.</li><li><strong>tarball</strong>: package <code>deploy.artifacts</code> into a release archive, a file in a
private directory of this run on your machine, removed when the run ends.</li><li><strong>upload</strong>: install the archive into <code>&lt;path></code> as the connecting user, mode <code>600</code>, under <code>.zap-deploy-&lt;user>-&lt;version>.tar.gz</code>. It is staged beside that
name and checked against its SHA-512 before it is renamed in, so a transfer
cut short installs nothing. The archive is held in memory while it uploads.</li><li><strong>extract + swap</strong>: one remote script, generated deterministically and
printed whole by the dry run, does the release-directory work. It reads the
archive's SHA-512 on its stdin, opens the archive once, requires it to be the
connecting user's own file, writable by no one else, with that digest, and
extracts through the open file, so another account on the host can't swap
the archive between the upload and the extraction. Extracted files belong to
the connecting user, under that user's umask, without set-id bits on files.
The script removes the archive on every exit of its own. Then:<ul><li><strong>lock</strong>: take the app's deploy lock, a kernel <code>flock</code> on <code>&lt;path>/.zap-deploy.lock</code>, held until the script exits. The file is never
removed and holds no data; when Zap creates it, other users get no
permission on it. It is opened read-only, so the connecting user and its
group can hold it, the group even under a umask that gives it read alone
(022). A deploy that finds the lock held stops at once, before it touches <code>releases/</code>, with <code>another deploy is running for this app</code> (exit 1); it
doesn't wait. The kernel releases the lock when the script's process ends,
however it ends; a lock held by a hung deploy is cleared by ending that
process (<code>fuser &lt;path>/.zap-deploy.lock</code> names it). The <code>prepare</code> commands
run with the lock's descriptor closed, so a process one of them leaves
running doesn't keep the lock once the script ends;</li><li><strong>recover</strong>: under the lock, repair what an unfinished deploy (killed, or
its connection cut) left in <code>releases/</code>: a staging directory is removed,
and a release it had moved aside is put back under its version when that
name is empty, or removed when it is filled. So a <code>current</code> that a killed <code>--force</code> left naming nothing resolves on the next deploy (a redeploy of
that version needs no <code>--force</code>: <a>Preflight</a>). Each repair is a
warning in the run's text report (not in a <code>--json</code> stream), and happens
even when that deploy then fails;</li><li><strong>check</strong>: still under the lock, confirm <code>current</code> names the release the
plan read as live (by the link's last segment, trailing slashes dropped;
nothing at all at <code>current</code>, no link and no file or directory, on a first
deploy). A deploy planned before another one swapped stops here, saying <code>current</code> changed since this deploy was planned (exit 1), having made
nothing of its own; run <code>zap deploy</code> again. So the release a rollback
returns to, and the one the prune keeps, is the one live just before this
deploy's swap. A plan that couldn't read <code>current</code> (it warns) stops here
too when the host has one;</li><li>extract into a fresh hidden directory, <code>&lt;path>/releases/.zap-stage</code>;</li><li><strong>link shared</strong>: symlink each <code>deploy.shared</code> entry from <code>&lt;path>/shared/</code> into the new release (an apply-managed env file, for example); a release
that ships a directory at a shared name fails the deploy here;</li><li><strong>prepare</strong>: run each <code>deploy.prepare</code> command in the new release, before
the swap, in a shell of its own (<code>sh -ec</code>): an <code>exit</code> or <code>exec</code> in one ends
that command, not the script, and a command that fails stops the deploy
before the swap. Its working directory is the hidden one, not the release's
final path, and its output goes to the script's error stream: a step
that fails shows the script's own reason when it stopped itself, or else the
stream's last lines, and what a command prints becomes no run warning. A
command that reaches the script's own output anyway (through <code>/proc</code>, or a
descriptor it was handed) can print a line the script marks, a warning or
its reason for stopping, which is then read as the script's: text only,
since what the deploy does turns on the exit status and the swap;</li><li><strong>place</strong>: rename the complete release to <code>&lt;path>/releases/&lt;version></code>,
where the version is the commit's hash abbreviated to 12 hex digits
(<code>git rev-parse --short=12</code>, longer only where 12 would be ambiguous), with <code>-dirty-&lt;id></code> for a forced dirty tree, above. When that name already exists (an earlier
deploy of the same version, or the live release under <code>--force</code>), it is
renamed aside first, to <code>.zap-old-&lt;version></code>, and removed after the swap,
so a release never mixes files from two archives. A run that fails before
this point leaves no hidden directory and changes no release beyond what it
recovered; under <code>--force</code> of the live version, <code>current</code> names nothing for
the instant between the two renames, and a run that fails after this point
leaves the new contents live under that name, the old ones not kept. A run
killed between the two renames leaves the old release aside for the next
deploy's recovery to put back;</li><li><strong>swap</strong>: re-point <code>&lt;path>/current</code> at the new release atomically. From
here the release is live, and the run goes on to restart and check it
whatever the rest of the script does: what follows is housekeeping, and
a failure there is a warning in the run's output, not a failed step. A
script that fails after saying it swapped is taken as swapped only when <code>current</code>, read again, names the new release;</li><li><strong>record</strong>: write <code>&lt;path>/deploy_info.json</code> (version, who, when, previous release);</li><li><strong>prune</strong>: keep <code>deploy.releases</code> releases: the one just deployed, the one
it replaced, then the newest others. Only a directory named the way Zap
names a release (a commit hash of 4 to 64 hex digits, alone or with <code>-dirty-&lt;id></code>) is
ever removed; anything else under <code>releases/</code> is left alone. As a
guard, the prune removes nothing unless <code>current</code> names a release, and
on a target with no <code>sort</code> it removes nothing and warns.</li></ul></li><li><strong>restart</strong>: restart <code>deploy.service</code> through the target's service manager
(with a <code>daemon-reload</code> first on systemd).</li><li><strong>health</strong>: poll <code>https://&lt;domain>&lt;path></code> from the operator machine (the one
you run <code>zap</code> on) until
it answers 2xx, up to <code>attempts</code> times, <code>interval_ms</code> apart. Neither poll
follows a redirect: a 3xx is not healthy or ready, so a release that
redirects to a login page doesn't pass on that page's 200.</li><li><strong>readiness</strong>: when <code>health.path</code> isn't already <code>/ready</code>, poll <code>/ready</code> too.
2xx proceeds. When the attempts run out, the last HTTP status decides; a connection failure
after it doesn't replace it. A <strong>404</strong> means the app doesn't serve <code>/ready</code>: the step is recorded as <code>skipped</code>,
warns loudly, and the deploy proceeds on liveness alone. Any other answer
fails the deploy and rolls back: a 503 (the convention for a database schema
that doesn't match the running code, or an unreachable database), any other
status, or no answer at all. Point <code>health.path</code> at <code>/ready</code> to make that one
check the gate; then any non-2xx, 404 included, rolls back.</li></ol><h2>Auto-rollback</h2><p>If a step after the swap fails (the restart errors, health never goes green, <code>/ready</code> answers 503), Zap re-points <code>current</code> at the previous release,
restarts, and re-checks health (the health URL, not <code>/ready</code>), recording the
rollback as warnings and step events. The deploy still exits 1: rollback
restores service, it doesn't paper over the failure.</p><p>The re-point is a compare-and-swap under the app's deploy lock, taken without
waiting. It moves <code>current</code> back only while <code>current</code> still names this deploy's
release and the previous release is still on the host. Otherwise (another
deploy holds the lock or has replaced the release, someone re-pointed <code>current</code> by hand, <code>current</code> names nothing, or the previous release is gone) the rollback
is skipped with a warning that says why: nothing is re-pointed or restarted, and
the deploy still exits 1.</p><p>There is nothing to roll back to on a first deploy, or on a <code>--force</code> redeploy
of the live version: <code>current</code> stays at the failed release, and the run warns
that a manual rollback is needed.</p><p>When the restored release's health check fails too, the rollback step is
recorded as failed, and the warning says manual intervention is needed.</p><p>The previous release is read from the live <code>current</code> symlink at deploy time,
not from a recorded file, so a manual rollback done by hand is seen correctly
on the next deploy. A <code>current</code> whose last segment, trailing slashes dropped,
is no release's name names no previous release, so the deploy refuses before
it builds anything: point <code>current</code> at the live release by hand, or remove it
to deploy as onto a fresh host.</p><h3>Concurrent deploys</h3><p>A deploy planned before another deploy's swap stops at its check (step 4), so a
rollback never undoes a newer deploy, with one exception: a <code>--force</code> redeploy
of the same version, planned after a deploy's swap while that deploy is in its
health check, writes the same <code>current</code>, which the first deploy's rollback
can't tell from its own and can undo. A rollback skipped because another deploy
held the lock leaves <code>current</code> at the failed release if that other deploy then
fails before its own swap; the warning says to check it.</p><p>The lock covers the release-directory work only: the restart and the health
checks run after the script releases it, so a deploy can report on a host that
another deploy has since moved on. Two simultaneous deploys of one version by
one connecting user upload to the same name, so either can replace or remove
the other's archive; the other then stops at its digest check or finds no
archive (exit 1) rather than ship bytes it didn't build.</p>`,1);function b(s,b){d(b,!0);let x=h(`deploy`);u(`1d1gc0k`,e=>{n(()=>{f.title=`Deploy — zap`})}),g(s,{get tome(){return x},children:(n,a)=>{v(n,{children:(n,a)=>{var s=y(),u=t(r(s)),d=t(i(u));l(d,`href`,`#binding-a-wetrun-to-a-reviewed-plan`),p(),o(u);var f=t(u);l(f,`id`,`configuration`);var h=t(f);_(h,{lang:`ts`,dangerous_raw_html:`<span class="token_special_keyword">export</span> <span class="token_special_keyword">default</span> <span class="token_punctuation">(</span>zap<span class="token_punctuation">)</span> <span class="token_operator">=></span> <span class="token_punctuation">{</span>
	zap<span class="token_punctuation">.</span><span class="token_function">target</span><span class="token_punctuation">({</span>
		host<span class="token_operator">:</span> zap<span class="token_punctuation">.</span><span class="token_function">env</span><span class="token_punctuation">(</span><span class="token_string">'DEPLOY_HOST'</span><span class="token_punctuation">),</span>
		user<span class="token_operator">:</span> zap<span class="token_punctuation">.</span><span class="token_function">env</span><span class="token_punctuation">(</span><span class="token_string">'DEPLOY_USER'</span><span class="token_punctuation">),</span>
		package_manager<span class="token_operator">:</span> <span class="token_string">'apt'</span><span class="token_punctuation">,</span>
		service_manager<span class="token_operator">:</span> <span class="token_string">'systemd'</span><span class="token_punctuation">,</span>
		home<span class="token_operator">:</span> <span class="token_string">'/home/app'</span><span class="token_punctuation">,</span>
	<span class="token_punctuation">});</span>

	zap<span class="token_punctuation">.</span><span class="token_function">deploy</span><span class="token_punctuation">({</span>
		build<span class="token_operator">:</span> <span class="token_string">'gro build'</span><span class="token_punctuation">,</span>
		artifacts<span class="token_operator">:</span> <span class="token_punctuation">[</span><span class="token_string">'build/'</span><span class="token_punctuation">,</span> <span class="token_string">'dist_artifacts/'</span><span class="token_punctuation">],</span>
		path<span class="token_operator">:</span> <span class="token_string">'/home/app/app'</span><span class="token_punctuation">,</span>
		releases<span class="token_operator">:</span> <span class="token_number">5</span><span class="token_punctuation">,</span>
		service<span class="token_operator">:</span> <span class="token_string">'app'</span><span class="token_punctuation">,</span>
		shared<span class="token_operator">:</span> <span class="token_punctuation">[</span><span class="token_string">'.env.production'</span><span class="token_punctuation">],</span>
		prepare<span class="token_operator">:</span> <span class="token_punctuation">[</span><span class="token_string">'deno cache server.js'</span><span class="token_punctuation">],</span>
		health<span class="token_operator">:</span> <span class="token_punctuation">{</span>domain<span class="token_operator">:</span> zap<span class="token_punctuation">.</span><span class="token_function">env</span><span class="token_punctuation">(</span><span class="token_string">'DEPLOY_DOMAIN'</span><span class="token_punctuation">),</span> path<span class="token_operator">:</span> <span class="token_string">'/health'</span><span class="token_punctuation">,</span> attempts<span class="token_operator">:</span> <span class="token_number">15</span><span class="token_punctuation">,</span> interval_ms<span class="token_operator">:</span> <span class="token_number">2000</span><span class="token_punctuation">},</span>
	<span class="token_punctuation">});</span>
<span class="token_punctuation">};</span>`});var g=t(h,2);l(g,`id`,`health`);var v=t(g,3);l(v,`id`,`commands`);var b=t(v);_(b,{lang:`sh`,dangerous_raw_html:`zap deploy                             <span class="token_comment"># dry run: the whole plan and its plan_hash, recorded as the preview</span>
zap deploy --wetrun                    <span class="token_comment"># ship the previewed plan: build, upload, swap, restart, health-check</span>
zap deploy --wetrun --expect-plan <span class="token_operator">&lt;</span><span class="token_builtin">hash</span><span class="token_operator">></span>   <span class="token_comment"># ship only the plan with this hash</span>
zap deploy --wetrun --skip-build       <span class="token_comment"># no build step: ship the local artifacts as they are</span>
zap deploy --wetrun --skip-preflight   <span class="token_comment"># ship without the drift preflight</span>
zap deploy --wetrun --force            <span class="token_comment"># ship an unchanged version, or a dirty tree</span>
zap deploy --wetrun --json             <span class="token_comment"># stream step events as JSON lines</span>`});var x=t(b),S=t(i(x));l(S,`href`,`#binding-a-wetrun-to-a-reviewed-plan`);var C=t(S,4);p(),o(x);var w=t(x),T=t(i(w),12);p(7),o(w);var E=t(w);l(E,`id`,`first-deploy`);var D=t(E,2);_(D,{lang:`ts`,dangerous_raw_html:`zap<span class="token_punctuation">.</span><span class="token_function">service</span><span class="token_punctuation">({</span>
	id<span class="token_operator">:</span> <span class="token_string">'app-service'</span><span class="token_punctuation">,</span>
	service<span class="token_operator">:</span> <span class="token_string">'app'</span><span class="token_punctuation">,</span>
	enabled<span class="token_operator">:</span> <span class="token_boolean">true</span><span class="token_punctuation">,</span>
	<span class="token_comment">// no \`running\`: zap manages enablement, not runtime state, so the service</span>
	<span class="token_comment">// doesn't drift before a binary exists; the deploy's restart starts it</span>
	restart_on<span class="token_operator">:</span> <span class="token_punctuation">[</span><span class="token_string">'app-unit'</span><span class="token_punctuation">],</span>
<span class="token_punctuation">});</span>`});var O=t(D,3),k=t(i(O),3);p(),o(O);var A=t(O);l(A,`id`,`binding-a-wetrun-to-a-reviewed-plan`);var j=t(A,2);_(j,{lang:null,content:`deploy — target {env:DEPLOY_HOST} (dry-run)
  version: 3f2a9c1e7b04 (previous: 8d41e0a6c2f9)
  host: app.example.com
  target: {"local":false,"host":{"$env":"DEPLOY_HOST"},"user":{"$env":"DEPLOY_USER"},"home":"/home/app","package_manager":"apt","service_manager":"systemd"}
  references:
    DEPLOY_DOMAIN = app.example.com
  tree: clean
  preflight: no apply-managed resources declared — nothing to check
  - Build application (build)
      local$ gro build
  - Create tarball (tarball)
      local$ tar -czf "$ZAP_DEPLOY_ARCHIVE" -- 'build/' 'dist_artifacts/'
      writes $ZAP_DEPLOY_ARCHIVE: a file in a private directory of this run, removed when it ends
  - Upload tarball (upload)
      the archive → target:/home/app/app/.zap-deploy-app-3f2a9c1e7b04.tar.gz (as the connecting user, mode 600, checked against its SHA-512)
  - Extract and swap release (extract_swap)
      target script (its stdin: the archive's SHA-512):
        set -e
        zap_archive='/home/app/app/.zap-deploy-app-3f2a9c1e7b04.tar.gz'
        …
  - Restart app (restart)
      target$ sudo systemctl daemon-reload && sudo systemctl restart app
  - Health check (health)
      GET https://{env:DEPLOY_DOMAIN}/health — healthy on 2xx; up to 15 attempt(s), 2000 ms apart
      polls https://app.example.com/health
  - Readiness check (readiness)
      GET https://{env:DEPLOY_DOMAIN}/ready — ready on 2xx, unserved on 404; up to 15 attempt(s), 2000 ms apart
      polls https://app.example.com/ready
  (dry-run — re-run with --wetrun to deploy)
plan_hash: 1f98612fcbfacb69b9d31236457d549e00714e4ad0fb0a36e225c3fe6a5f4312`});var M=t(j,5);_(M,{lang:null,content:`  UNREVIEWED — this plan is not the one that was reviewed.
    no deploy plan has been previewed for this host.
plan_hash: 1f98612fcbfacb69b9d31236457d549e00714e4ad0fb0a36e225c3fe6a5f4312
Deploy this plan? Type 1f98612f, the start of its plan_hash, to confirm:`});var N=t(M),P=t(i(N),9);p(),o(N);var F=t(N,2),I=t(i(F),3);p(9),o(F);var L=t(F,6),R=t(i(L),6);p(),o(L);var z=t(L),B=t(i(z),3);p(),o(z);var V=t(z);l(V,`id`,`preflight`);var H=t(V,2),U=t(i(H));l(U,`href`,`#binding-a-wetrun-to-a-reviewed-plan`),p(7),o(H);var W=t(H,4);l(W,`id`,`dirty-trees`);var G=t(W,8);l(G,`id`,`the-release-mechanism`);var K=t(G),q=t(i(K));l(q,`href`,`#preflight`),p(),o(K);var J=t(K);_(J,{lang:null,content:`build (local) → tarball → upload → extract + swap → restart → health → readiness`});var Y=t(J),X=t(i(Y),3),Z=t(i(X),2),Q=t(i(Z)),ee=t(i(Q),10);l(ee,`href`,`#preflight`),p(3),o(Q),p(8),o(Z),o(X),p(3),o(Y);var $=t(Y);l($,`id`,`auto-rollback`);var te=t($,6);l(te,`id`,`concurrent-deploys`),p(2),e((e,t,n,r,i,a,o)=>{l(C,`href`,e),l(T,`href`,t),l(k,`href`,n),l(P,`href`,r),l(I,`href`,i),l(R,`href`,a),l(B,`href`,o)},[()=>m(`docs/cli#zap-deploy`),()=>m(`docs/targets#what-the-target-needs`),()=>m(`docs/targets#the-bootstrap-user`),()=>m(`docs/cli#zap-apply`),()=>m(`docs/lock#on-disk-state`),()=>m(`docs/env#masked-hosts-and-review`),()=>m(`docs/security#escaped-output`)]),c(n,s)},$$slots:{default:!0}})},$$slots:{default:!0}}),a()}export{b as t};