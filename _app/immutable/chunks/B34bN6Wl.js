import{$ as e,G as t,J as n,K as ee,X as r,Z as te,dt as i,ft as a,j as o,k as ne,l as s,m as c,ot as re,st as l}from"./CkSeWg2M.js";import{t as u}from"./Cyt8LZpN.js";import{n as d}from"./BbCw5KVU.js";import"./BPVwp-J3.js";import{t as f}from"./k6TRNp0w.js";import{t as p}from"./DH_LefOd.js";import{t as m}from"./CtsBFaJL.js";var ie=o(`<p><code>zap deploy</code> ships a versioned release of your application to a remote host over
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
(<a>targets.md</a>), plus <code>tar</code>, <code>id</code> <code>flock</code>.</p><h3>What a wetrun prints</h3><p>While a wetrun runs, each phase prints one line to standard error as it starts:
the drift preflight, each step, and a rollback if one starts. Nothing about how
a phase ended prints there. When the run ends, the report goes to standard
output: a table with a row for the preflight, each step, and a rollback when
one ran, each with its status, how long it took, and what it says (the
upload's size, what the health and readiness checks found, a failed step's
error, a skipped one's reason; a command's own output, such as the build log,
is left out), then the warnings and a closing line that says what is live
where.</p><!><p>The <code>→</code> <code>--json</code> neither prints: the events stream instead
(<a>cli.md</a>). A preflight that checked nothing is a <code>skip</code> <code>--skip-preflight</code>, or no apply-managed resources declared).</p><p>A failed run's closing line names the step that failed and the state the
target is in. A failure before the swap released nothing:</p><!><p>A failure of the extract-and-swap step itself is read back from <code>current</code>, and
nothing is rolled back. When <code>current</code> names another release, or none on a
first release, this one is not live:</p><!><p>When it names this version (the swap can have happened before the step failed,
or another deploy of the same version swapped), or can't be read, the line
claims neither way and points at the step's error. So does a <code>current</code> <code>current</code>, so that read is one it can't believe (an app path the connecting
user can no longer search reads that way):</p><!><p>A failure after the swap is followed by a rollback
(<a>Auto-rollback</a>).</p><h2>First deploy</h2><p> <code>deploy</code>, but <code>deploy</code>'s preflight requires a converged <code>apply</code>, and a <code>service</code> <code>running: true</code> can't be running before there is anything to run.
Resolve it in the config: declare the service <code>enabled</code> and leave <code>running</code> </p><!><p>Then the bring-up is two reviewed runs: <code>zap apply</code>, then <code>zap apply --wetrun</code> <code>zap deploy</code>, then <code>zap deploy --wetrun</code>, ships the first release, whose
restart step starts the service. Preview the deploy after the apply has run:
the dry run connects as the user the apply sets up, and a pin the apply writes
to <code>zap.lock</code> is part of the deploy plan.</p><p>The trade is explicit: a config that leaves <code>running</code> unset tells Zap never to
assert that the app is up, so <code>zap apply</code> on a host whose daemon crashed and
stayed down reports converged. Declaring <code>running: true</code> buys that assertion
back at the cost of one <code>deploy --wetrun --skip-preflight</code> on the very first
release (previewed with <code>deploy --skip-preflight</code>, since the flag is part of
the plan), and <code>--skip-preflight</code> disables the whole drift gate for that run.</p><p>When SSH hardening changes the user Zap connects as, add <code>--bootstrap</code> to the
first apply: <a>targets.md</a>.</p><h2>Binding a wetrun to a reviewed plan</h2><p>A dry run prints the whole plan and ends with its hash. It comes in groups a
blank line apart: what ships where (the version and the release it replaces,
the commit's subject, the host and the user Zap connects as, who is deploying,
the declared target, and what the references resolve to), the two gates (the
tree and the drift preflight), the steps, and what the run does with the plan.
The commit's subject is its own first line, cut at 100 characters, with any
secret's value masked; on a dirty tree it is still the commit's, and its line
says it is the commit under the uncommitted changes. The extract-and-swap step
lists the values its script is built from above the script: the app path, the
release <code>current</code> must still name, each <code>shared</code> link, each <code>prepare</code> command,
and how many releases are kept. Each poll's first line says what it does and
how long it can take; a second gives the URL as declared when a reference in it
resolves. Last, <code>in short:</code> restates the commit, version, host, user, tree, and
preflight beside the hash, below however long the script is:</p><!><p>A wetrun executes only a reviewed plan: one whose hash you named, or one Zap
printed as a preview. It computes its plan again, and that plan's hash must
equal the reviewed one:</p><ul><li><code>--expect-plan &lt;hash></code> names the reviewed plan explicitly, and binds alone;</li><li>with no flag, the reviewed plan is the <strong>deploy preview</strong> recorded for this
config and host: the last <code>zap deploy</code> dry run, or a wetrun that refused.</li></ul><p>Otherwise the wetrun <strong>refuses</strong> before the drift preflight and any step,
prints the plan it would have run under a <code>REFUSED</code> banner that says why (no
preview yet, the plan changed since the preview, or the hash doesn't match),
records that render as the new preview, and exits 2. Nothing is built or
uploaded. The everyday flow is <code>zap deploy</code>, read it, <code>zap deploy --wetrun</code> <code>--expect-plan</code>.</p><p> <code>--expect-plan</code> refuses; one sent to <code>/dev/null</code>, or cut short by <code>head</code> after
the pipe took it whole, still binds it. When the output may be truncated, or
the one who reads the preview isn't the one who deploys, pass <code>--expect-plan</code> <a>concepts.md</a>).</p><p>On an interactive terminal (standard input and standard error both terminals),
a wetrun with no review and no <code>--expect-plan</code> <code>UNREVIEWED</code> banner, then its recap and its <code>plan_hash</code>, and ends with the
question:</p><!><p>Typing those eight characters back is the review: the wetrun goes on with
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
place. A preview doesn't expire.</p><p>The preview is a small file under <code>~/.zap</code> <a>lock.md</a> <code>zap apply</code> binds to: a <code>zap plan</code> doesn't disturb a deploy preview, and a
deploy dry run doesn't disturb a convergence one. It holds the hash, not the
plan. A deploy wetrun's drift preflight does replace the convergence record: it
records its pass as the last-run report, which is no preview, so a <code>zap apply</code> <code>--expect-plan</code> binds.</p><p>Everything the hash covers is printed but two of Zap's own scripts: the one the
upload installs the archive with, and the swap the auto-rollback runs. So a plan
reviewed under one <code>zap</code> build doesn't bind one whose scripts differ. It covers:</p><ul><li>the version, the subject line of its commit, the tree state, and the
previous release on the target;</li><li>the declared target, the host it resolves to, and the connecting user;</li><li>who is deploying (<code>user@host</code> <code>deploy_info.json</code>);</li><li>the preflight's state: skipped, nothing declared, or which apply-managed
resources it checks, as a count and a digest of their declarations and the
current pins <code>zap.lock</code> holds for them;</li><li>every step: the build and tarball commands, the upload paths and the script
that installs the archive, the remote script and the values it is built from
(the app path, the <code>shared</code> links, the <code>prepare</code> commands, how many releases
are kept), the restart command, the health and readiness URLs as they resolve
and the budget each is polled with (the attempts, the wait between two, the
time each is given), and the swap the auto-rollback would run;</li><li>the plan's warnings, printed under it (a <code>deploy.service</code> the target's
service manager can't restart);</li><li>the value of each reference the <code>deploy</code> block uses (its health domain),
printed in its <code>references:</code> block (a secret's value excepted: the plan
records only that it is one).</li></ul><p>So a plan reviewed for one host, tree, flag set, or operator does not bind a
wetrun for another: a new commit, a deploy or rollback by someone else in
between, an edit to any declared resource, a changed pin in <code>zap.lock</code> <code>--force</code> on a dirty tree, <code>--skip-build</code>, <code>--skip-preflight</code>, or <code>--bootstrap</code> <code>--force</code> dry run shows.</p><p>It does not cover:</p><ul><li>the artifact bytes. The version names the commit, and the plan says whether
the tree was dirty, but what the build produces is not hashed. The review
covers the script that verifies the archive it was sent, not the archive.</li><li>the values a resource's references resolve to. The digest takes
each declaration as written, so it is the same in every environment; the
environment reaches the hash only through the host, the connecting user, and
the health domain. The same holds for the bytes of a local <code>source</code> file.</li></ul><p><strong>A masked host, connecting user, or health domain can't be deployed to.</strong> No
review can bind such a plan: a wetrun is an error that names the reference
before anything runs, and a dry run shows the plan under an <code>UNBINDABLE</code> note,
with no <code>plan_hash</code> <a>env.md</a>.</p><p>Text from the config, the environment, the checkout (the commit's subject), and
the target is printed with control characters written out as <code>&lt;U+XXXX></code>, so a
value can't hide or forge a line of the preview
(<a>security.md</a>).</p><h2>Preflight</h2><p>Before deploy touches the network, the machine-free gates run (secrets,
structure, and, for a deploy config, a present <code>health.domain</code>), and a wetrun
rejects any unset reference and a host, connecting user, or health domain behind
a masked reference. <code>zap.lock</code> is read here too, when the drift preflight will
check. <code>--skip-preflight</code> doesn't skip the gates.</p><p>Then a wetrun checks its <a>review</a> and runs
the <strong>drift preflight</strong> <code>pipeline</code>, which detects absent and runs on every apply, is not drift, and
neither is a service that changes only because its trigger fires, planned or
held: it reads converged, no pending restart or reload is recorded for it, and
every source that fires it is itself not drift (a pipeline, or another such
service). A service that also drifted, one owed an action an earlier apply
never completed, or one fired by any other change is drift.
It also bails, with the same code, when any resource is <code>undetermined</code>: a gate
that couldn't check everything doesn't pass by default.</p><p>After a drift bail, review the changes with <code>zap apply</code> <code>zap apply --wetrun</code> <code>zap.lock</code> changed.</p><p><code>--skip-preflight</code> <code>preflight:</code> line.</p><p>The deploy also refuses when the live release already has this version, on a
dry run too (<code>server already at this version</code>, exit 0). <code>--force</code> ships anyway.
A <code>current</code> that names this version but whose release isn't on the host serves
nothing, so it isn't refused: the run plans a redeploy and warns that <code>current</code> </p><h3>Dirty trees</h3><p>A tree with uncommitted changes or untracked files git doesn't ignore deploys
only under <code>--force</code>, as <code>&lt;hash>-dirty-&lt;id></code>. Without it, a wetrun is refused
before the target is contacted (exit 2), since the release would ship the tree
under the commit's version; a dry run shows the plan
(<code>tree: uncommitted changes or untracked files</code>) with no hash, records nothing,
and says the wetrun is refused, even when the commit is the live release.</p><p>The id is 8 lowercase hex of a blake3 over what the tree adds to the commit, so
the same tree gets the same id (a dry run and its wetrun agree) and a second
dirty tree on one commit is a release of its own:</p><table><thead><tr><th>In the tree</th><th>Counts by</th></tr></thead><tbody><tr><td>tracked and staged changes</td><td><code>git diff HEAD --binary</code></td></tr><tr><td>an untracked file git doesn't ignore</td><td>its name and contents</td></tr><tr><td>an untracked symlink</td><td>the path it points to, as git records one, whether that is a file, a directory, or nothing</td></tr><tr><td>an untracked nested repository</td><td>its name alone</td></tr><tr><td>a submodule</td><td>its commit and whether its own index shows changes, not what they are</td></tr><tr><td>a sparse checkout</td><td>the files outside its cone, as deletions: the tree reads dirty</td></tr></tbody></table><p>Zap reads the tree against a copy of the index's entries that holds no
timestamps or flags, so every file is compared by its contents: a file the
index marks unchanged (<code>assume-unchanged</code>, <code>skip-worktree</code> <code>refs/replace/</code> entry puts in their place (<code>--no-replace-objects</code>, as the
subject line is read too), and sets <code>core.fsmonitor=false</code> <code>core.untrackedCache=false</code>, <code>core.ignoreStat=false</code>, <code>core.fileMode=true</code> (a
mode change counts), <code>core.autocrlf=false</code> <code>core.splitIndex=false</code>, and passes <code>--untracked-files=normal</code> <code>--ignore-submodules=none</code>, so <code>status.showUntrackedFiles</code> <code>ignore</code> setting, and <code>diff.ignoreSubmodules</code> <code>core.autocrlf=true</code>, reads dirty, and deploys only under <code>--force</code>.</p><p>Two things still decide what counts as a change. The checkout's attributes
(<code>.gitattributes</code>, <code>.git/info/attributes</code>) are applied: a clean filter, LFS
among them, or an <code>eol</code> or <code>text</code> attribute can make a file that differs from
the commit compare equal to it, and no flag turns them off. A submodule's own
index is read as it is, so an <code>assume-unchanged</code> edit or stale timestamps
inside one can read clean.</p><p>A sparse checkout reads dirty and deploys only under <code>--force</code>: the files
outside its cone aren't there, so the tree the build sees is not the commit's.</p><p>A tree Zap can't read is an error that says what git said, not a clean tree.</p><h2>The release mechanism</h2><p>Once the <a>preflight</a> passes, a wetrun runs these steps in order:</p><!><ol><li><strong>build</strong>: run <code>deploy.build</code> locally (<code>gro build</code>, <code>cargo build --release</code>,
whatever produces your artifacts). With <code>--skip-build</code>, or when no build
command is declared, the plan has no build step.</li><li><strong>tarball</strong>: package <code>deploy.artifacts</code> into a release archive, a file in a
private directory of this run on your machine, removed when the run ends.</li><li><strong>upload</strong>: install the archive into <code>&lt;path></code> <code>600</code>, under <code>.zap-deploy-&lt;user>-&lt;version>.tar.gz</code>. It is staged beside that
name and checked against its SHA-512 before it is renamed in, so a transfer
cut short installs nothing. The archive is held in memory while it uploads.</li><li><strong>extract + swap</strong>: one remote script, generated deterministically and
printed whole by the dry run, does the release-directory work. It reads the
archive's SHA-512 on its stdin, opens the archive once, requires it to be the
connecting user's own file, writable by no one else, with that digest, and
extracts through the open file, so another account on the host can't swap
the archive between the upload and the extraction. Extracted files belong to
the connecting user, under that user's umask, without set-id bits on files.
The script removes the archive on every exit of its own. Then:<ul><li><strong>lock</strong>: take the app's deploy lock, a kernel <code>flock</code> <code>&lt;path>/.zap-deploy.lock</code> <code>releases/</code>, with <code>another deploy is running for this app</code> (exit 1); it
doesn't wait. The kernel releases the lock when the script's process ends,
however it ends; a lock held by a hung deploy is cleared by ending that
process (<code>fuser &lt;path>/.zap-deploy.lock</code> names it). The <code>prepare</code> commands
run with the lock's descriptor closed, so a process one of them leaves
running doesn't keep the lock once the script ends;</li><li><strong>recover</strong>: under the lock, repair what an unfinished deploy (killed, or
its connection cut) left in <code>releases/</code>: a staging directory is removed,
and a release it had moved aside is put back under its version when that
name is empty, or removed when it is filled. So a <code>current</code> <code>--force</code> left naming nothing resolves on the next deploy (a redeploy of
that version needs no <code>--force</code>: <a>Preflight</a>). Each repair is a
warning in the run's text report (not in a <code>--json</code> stream), and happens
even when that deploy then fails;</li><li><strong>check</strong>: still under the lock, confirm <code>current</code> names the release the
plan read as live (by the link's last segment, trailing slashes dropped;
nothing at all at <code>current</code> <code>current</code> changed since this deploy was planned (exit 1), having made
nothing of its own; run <code>zap deploy</code> again. So the release a rollback
returns to, and the one the prune keeps, is the one live just before this
deploy's swap. A plan that couldn't read <code>current</code> (it warns) stops here
too when the host has one;</li><li>extract into a fresh hidden directory, <code>&lt;path>/releases/.zap-stage</code>;</li><li><strong>link shared</strong>: symlink each <code>deploy.shared</code> entry from <code>&lt;path>/shared/</code> </li><li><strong>prepare</strong>: run each <code>deploy.prepare</code> command in the new release, before
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
(<code>git rev-parse --short=12</code> <code>-dirty-&lt;id></code> for a forced dirty tree, above. When that name already exists (an earlier
deploy of the same version, or the live release under <code>--force</code>), it is
renamed aside first, to <code>.zap-old-&lt;version></code>, and removed after the swap,
so a release never mixes files from two archives. A run that fails before
this point leaves no hidden directory and changes no release beyond what it
recovered; under <code>--force</code> of the live version, <code>current</code> names nothing for
the instant between the two renames, and a run that fails after this point
leaves the new contents live under that name, the old ones not kept. A run
killed between the two renames leaves the old release aside for the next
deploy's recovery to put back;</li><li><strong>swap</strong>: re-point <code>&lt;path>/current</code> <code>current</code>, read again, names the new release;</li><li><strong>record</strong>: write <code>&lt;path>/deploy_info.json</code> (version, who, when, previous release);</li><li><strong>prune</strong>: keep <code>deploy.releases</code> releases: the one just deployed, the one
it replaced, then the newest others. Only a directory named the way Zap
names a release (a commit hash of 4 to 64 hex digits, alone or with <code>-dirty-&lt;id></code>) is
ever removed; anything else under <code>releases/</code> is left alone. As a
guard, the prune removes nothing unless <code>current</code> names a release, and
on a target with no <code>sort</code> it removes nothing and warns.</li></ul></li><li><strong>restart</strong>: restart <code>deploy.service</code> through the target's service manager
(with a <code>daemon-reload</code> first on systemd).</li><li><strong>health</strong>: poll <code>https://&lt;domain>&lt;path></code> from the operator machine (the one
you run <code>zap</code> on) until
it answers 2xx, up to <code>attempts</code> times, <code>interval_ms</code> apart, each attempt
given 5 seconds. The plan states the most a poll can take. Neither poll
follows a redirect: a 3xx is not healthy or ready, so a release that
redirects to a login page doesn't pass on that page's 200.</li><li><strong>readiness</strong>: when <code>health.path</code> isn't already <code>/ready</code>, poll <code>/ready</code> too.
2xx proceeds. When the attempts run out, the last HTTP status decides; a connection failure
after it doesn't replace it. A <strong>404</strong> <code>/ready</code>: the step is recorded as <code>skipped</code>,
warns loudly, and the deploy proceeds on liveness alone. Any other answer
fails the deploy and rolls back: a 503 (the convention for a database schema
that doesn't match the running code, or an unreachable database), any other
status, or no answer at all. Point <code>health.path</code> at <code>/ready</code> to make that one
check the gate; then any non-2xx, 404 included, rolls back.</li></ol><h2>Auto-rollback</h2><p> <code>/ready</code> answers 503), Zap re-points <code>current</code> at the previous release,
restarts, and re-checks health (the health URL, not <code>/ready</code>), recording the
rollback as a row of the report and as step events. The deploy still exits 1:
rollback restores service, it doesn't paper over the failure.</p><p>The rollback has its own row in the report, after the failed step, and the
closing line says where it left the target:</p><!><p>Without a health check in the plan, the line says the previous release was
restored and restarted, not that it is live. A rollback that didn't go as
planned says so on its row and in the closing line, and a warning below the
table says why: no release was known to return to, so the failed release is live
(the row has no time: it never started); the previous release was restored,
but its restart or its health check failed, so it is not confirmed serving; the
rollback was skipped, so <code>current</code> is as the warnings say; or the re-point
itself failed, so the host may be serving the failed release.</p><p>The re-point is a compare-and-swap under the app's deploy lock, taken without
waiting. It moves <code>current</code> back only while <code>current</code> still names this deploy's
release and the previous release is still on the host. Otherwise (another
deploy holds the lock or has replaced the release, someone re-pointed <code>current</code> <code>current</code> names nothing, or the previous release is gone) the rollback
is skipped with a warning that says why: nothing is re-pointed or restarted, and
the deploy still exits 1.</p><p>There is nothing to roll back to on a first deploy, or on a <code>--force</code> redeploy
of the live version: <code>current</code> stays at the failed release, and the run warns
that a manual rollback is needed.</p><p>When the restored release's health check fails too, the rollback step is
recorded as failed, and the warning says manual intervention is needed.</p><p>The previous release is read from the live <code>current</code> symlink at deploy time,
not from a recorded file, so a manual rollback done by hand is seen correctly
on the next deploy. A <code>current</code> whose last segment, trailing slashes dropped,
is no release's name names no previous release, so the deploy refuses before
it builds anything: point <code>current</code> at the live release by hand, or remove it
to deploy as onto a fresh host.</p><p>A <code>current</code> that can't be read (the read fails, or the app path is there but
the connecting user can't enter it) leaves the deploy with no previous release:
the preview warns, with the reason, that there is nothing to roll back to. An
app path below a directory the connecting user can't search reads as missing,
so the preview says <code>(first release)</code> with no warning; its wetrun then fails at
the upload, before anything is released.</p><h3>Concurrent deploys</h3><p>A deploy planned before another deploy's swap stops at its check (step 4), so a
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
archive (exit 1) rather than ship bytes it didn't build.</p>`,1);function h(o,h){l(h,!0);let g=d(`deploy`);c(`1d1gc0k`,e=>{t(()=>{n.title=`Deploy — zap`})}),f(o,{get tome(){return g},children:(t,n)=>{m(t,{children:(t,n)=>{var o=ie(),c=e(te(o)),re=e(r(c));s(re,`href`,`#binding-a-wetrun-to-a-reviewed-plan`),i(),a(c);var l=e(c);s(l,`id`,`configuration`);var d=e(l);p(d,{lang:`ts`,dangerous_raw_html:`<span class="token_special_keyword">export</span> <span class="token_special_keyword">default</span> <span class="token_punctuation">(</span>zap<span class="token_punctuation">)</span> <span class="token_operator">=></span> <span class="token_punctuation">{</span>
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
<span class="token_punctuation">};</span>`});var f=e(d,2);s(f,`id`,`health`);var m=e(f,3);s(m,`id`,`commands`);var h=e(m);p(h,{lang:`sh`,dangerous_raw_html:`zap deploy                             <span class="token_comment"># dry run: the whole plan and its plan_hash, recorded as the preview</span>
zap deploy --wetrun                    <span class="token_comment"># ship the previewed plan: build, upload, swap, restart, health-check</span>
zap deploy --wetrun --expect-plan <span class="token_operator">&lt;</span><span class="token_builtin">hash</span><span class="token_operator">></span>   <span class="token_comment"># ship only the plan with this hash</span>
zap deploy --wetrun --skip-build       <span class="token_comment"># no build step: ship the local artifacts as they are</span>
zap deploy --wetrun --skip-preflight   <span class="token_comment"># ship without the drift preflight</span>
zap deploy --wetrun --force            <span class="token_comment"># ship an unchanged version, or a dirty tree</span>
zap deploy --wetrun --json             <span class="token_comment"># stream step events as JSON lines</span>`});var g=e(h),ae=e(r(g));s(ae,`href`,`#binding-a-wetrun-to-a-reviewed-plan`);var oe=e(ae,4);i(),a(g);var _=e(g),se=e(r(_),12),ce=e(se,5);ce.nodeValue=`, and
`,i(2),a(_);var le=e(_);s(le,`id`,`what-a-wetrun-prints`);var ue=e(le,2);p(ue,{lang:null,content:`→ preflight: checking 1 apply-managed resource for drift
→ build: Build application
→ tarball: Create tarball
→ upload: Upload tarball
→ extract_swap: Extract and swap release
→ restart: Restart app
→ health: Health check
deploy — target host.example (wetrun)
  version: abc1234 (previous: def5678)
  ok    preflight     4.1s  1 apply-managed resource, no drift
  ok    build         1.1s
  ok    tarball       2.2s
  ok    upload        3.3s  4.2 MB sent
  ok    extract_swap  4.4s
  ok    restart       5.5s
  ok    health        6.6s  healthy after 2 attempts
deployed abc1234 to host.example (previous: def5678) in 1m 23s
plan_hash: deadbeef`});var v=e(ue),de=e(r(v),2);de.nodeValue=` lines are standard error and the rest standard output, so standard
output redirected to a file holds the whole report and no progress line. Under
`;var fe=e(de,3),pe=e(fe,3);pe.nodeValue=`
row that says why (`,i(2),a(v);var me=e(v,2);p(me,{lang:null,content:"deploy FAILED at upload on host.example after 1m 23s — nothing was released, and `current` was not moved"});var he=e(me,2);p(he,{lang:null,content:"deploy FAILED at extract_swap on host.example after 1m 23s — `current` does not name this release, so nothing was released"});var y=e(he),ge=e(r(y),2);ge.nodeValue=` that
reads as missing where a release was live before the run: Zap never removes
`,i(2),a(y);var _e=e(y);p(_e,{lang:null,content:`deploy FAILED at extract_swap on host.example after 1m 23s — the swap is not known to have completed, and nothing was rolled back (see the step's error above)`});var b=e(_e),ve=e(r(b));s(ve,`href`,`#auto-rollback`),i(),a(b);var ye=e(b);s(ye,`id`,`first-deploy`);var x=e(ye),be=r(x);be.nodeValue=`A first deploy onto a fresh host is a chicken-and-egg: the binary lands via
`;var xe=e(be,8);xe.nodeValue=`
declared `;var Se=e(xe,6);Se.nodeValue=`
unset.`,a(x);var Ce=e(x);p(Ce,{lang:`ts`,dangerous_raw_html:`zap<span class="token_punctuation">.</span><span class="token_function">service</span><span class="token_punctuation">({</span>
	id<span class="token_operator">:</span> <span class="token_string">'app-service'</span><span class="token_punctuation">,</span>
	service<span class="token_operator">:</span> <span class="token_string">'app'</span><span class="token_punctuation">,</span>
	enabled<span class="token_operator">:</span> <span class="token_boolean">true</span><span class="token_punctuation">,</span>
	<span class="token_comment">// no \`running\`: zap manages enablement, not runtime state, so the service</span>
	<span class="token_comment">// doesn't drift before a binary exists; the deploy's restart starts it</span>
	restart_on<span class="token_operator">:</span> <span class="token_punctuation">[</span><span class="token_string">'app-unit'</span><span class="token_punctuation">],</span>
<span class="token_punctuation">});</span>`});var S=e(Ce),we=e(r(S),4);we.nodeValue=`,
provisions the host (firewall included, so deploying first would bail), and
`,i(6),a(S);var C=e(S,2),Te=e(r(C),3);i(),a(C);var w=e(C);s(w,`id`,`binding-a-wetrun-to-a-reviewed-plan`);var T=e(w,2);p(T,{lang:null,content:`deploy — target {env:DEPLOY_HOST} (dry-run)
  version: 3f2a9c1e7b04 (previous: 8d41e0a6c2f9)
  commit: Add the readiness gate
  host: app.example.com
  user: app
  deployed by: ops@laptop
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
      app: /home/app/app
      replaces: 8d41e0a6c2f9 — \`current\` must still name it
      links: shared/.env.production
      prepare: deno cache server.js
      keeps: 5 releases, counting this one and 8d41e0a6c2f9
      target script (its stdin: the archive's SHA-512):
        set -e
        zap_archive='/home/app/app/.zap-deploy-app-3f2a9c1e7b04.tar.gz'
        …
  - Restart app (restart)
      target$ sudo systemctl daemon-reload && sudo systemctl restart app
  - Health check (health)
      GET https://app.example.com/health — healthy on 2xx; up to 15 attempts, 2s apart, 5s each (1m 43s at most)
      declared as https://{env:DEPLOY_DOMAIN}/health
  - Readiness check (readiness)
      GET https://app.example.com/ready — ready on 2xx, unserved on 404; up to 15 attempts, 2s apart, 5s each (1m 43s at most)
      declared as https://{env:DEPLOY_DOMAIN}/ready

  (dry-run — re-run with --wetrun to deploy)

  in short:
    commit: Add the readiness gate
    version: 3f2a9c1e7b04 (previous: 8d41e0a6c2f9)
    host: app.example.com
    user: app
    tree: clean
    preflight: no apply-managed resources declared — nothing to check
plan_hash: 2d09162e11f59e2b2409f6d89dcf0f469a877baf09d6e9f770bf5218eb6fcb95`});var E=e(T,3),Ee=e(r(E),8);Ee.nodeValue=`
with the same flags. A wetrun fired cold becomes the preview, and the next one
executes if nothing moved. There is no flag that skips the review, and a dry
run rejects `,i(2),a(E);var D=e(E),O=r(D);O.nodeValue=`The preview is recorded when Zap prints it, not when anyone reads it. A dry run
whose output couldn't be written is withdrawn, so the next wetrun run without
`;var k=e(O,8);k.nodeValue=`
with the hash on the preview's last line
(`;var De=e(k);i(),a(D);var A=e(D),Oe=e(r(A),2);Oe.nodeValue=` shows the plan instead, under an
`,i(4),a(A);var ke=e(A);p(ke,{lang:null,content:`  …

  UNREVIEWED — nothing has run: this plan runs only once it is confirmed below.
    no deploy plan has been previewed for this host.

  in short:
    commit: Add the readiness gate
    version: 3f2a9c1e7b04 (previous: 8d41e0a6c2f9)
    host: app.example.com
    user: app
    tree: clean
    preflight: no apply-managed resources declared — nothing to check
plan_hash: 2d09162e11f59e2b2409f6d89dcf0f469a877baf09d6e9f770bf5218eb6fcb95
Deploy this plan? Type 2d09162e, the start of its plan_hash, to confirm:`});var j=e(ke),Ae=e(r(j),9);i(),a(j);var M=e(j,2),N=e(r(M),2);N.nodeValue=`
(`;var je=e(N),Me=e(je);Me.nodeValue=`), separate from the last-run report that
`;var Ne=e(Me,6);Ne.nodeValue=`
previewed before it needs a new preview before its wetrun. With no state
directory nothing is recorded, the run says so, and only `,i(2),a(M);var P=e(M,2),Pe=e(r(P),2),Fe=e(r(Pe),2);Fe.nodeValue=` of the operator machine, recorded in
`,i(2),a(Pe),i(4),a(P);var F=e(P),Ie=e(r(F),2);Ie.nodeValue=`,
`;var Le=e(Ie,8);Le.nodeValue=`
each make a different plan. The hash is printed, and the preview recorded, only
when the steps are shown: an already-deployed dry run does neither, so a
redeploy binds to the plan a `,i(2),a(F);var I=e(F,3),Re=e(r(I),5);Re.nodeValue=` and no recorded preview. The ways out:
`;var ze=e(Re);i(),a(I);var L=e(I),Be=e(r(L),3);i(),a(L);var Ve=e(L);s(Ve,`id`,`preflight`);var R=e(Ve,2),He=e(r(R));s(He,`href`,`#binding-a-wetrun-to-a-reviewed-plan`);var Ue=e(He,3);Ue.nodeValue=`: the convergence pass against the config, before
building or uploading. If apply-managed state (an nginx site, the
env file, the service unit) was edited in the config but never applied, shipping
a new artifact against it would be a silent mismatch; the preflight bails with
exit 2, and a change held behind a resource it couldn't read counts as drift. A
`,i(4),a(R);var z=e(R),We=e(r(z),2);We.nodeValue=`, converge with
`;var Ge=e(We,2);Ge.nodeValue=`, and re-run the deploy: its review still binds unless
`,i(2),a(z);var B=e(z),Ke=e(r(B));Ke.nodeValue=` skips the drift preflight, and a config that declares no
apply-managed resources has nothing to check. Either way the plan says so on its
`,i(2),a(B);var V=e(B),qe=e(r(V),8);qe.nodeValue=`
names a release that is not on the host.`,a(V);var Je=e(V);s(Je,`id`,`dirty-trees`);var H=e(Je,4),Ye=e(r(H),4);Ye.nodeValue=`) counts like any
other, and so does one whose timestamps the index's cache would take for
unchanged. Each read compares against the objects the commit names, not ones a
`;var Xe=e(Ye,6);Xe.nodeValue=`,
`;var Ze=e(Xe,8);Ze.nodeValue=` (line endings are not converted), and
`;var Qe=e(Ze,4);Qe.nodeValue=` and
`;var $e=e(Qe,4);$e.nodeValue=`, a submodule's
`;var et=e($e,4);et.nodeValue=` don't narrow it either. So a
checkout on a filesystem without executable bits, or one checked out with
`,i(4),a(H);var tt=e(H,4);s(tt,`id`,`the-release-mechanism`);var U=e(tt),nt=e(r(U));s(nt,`href`,`#preflight`),i(),a(U);var rt=e(U);p(rt,{lang:null,content:`build (local) → tarball → upload → extract + swap → restart → health → readiness`});var W=e(rt),G=e(r(W),2),it=e(r(G),3);it.nodeValue=` as the connecting user, mode
`,i(4),a(G);var K=e(G),at=e(r(K),2),q=r(at),ot=e(r(q),3);ot.nodeValue=` on
`;var st=e(ot,2);st.nodeValue=`, held until the script exits. The file is never
removed and holds no data; when Zap creates it, other users get no
permission on it. It is opened read-only, so the connecting user and its
group can hold it, the group even under a umask that gives it read alone
(022). A deploy that finds the lock held stops at once, before it touches
`,i(8),a(q);var J=e(q),ct=e(r(J),5);ct.nodeValue=` that a killed
`;var lt=e(ct,5);s(lt,`href`,`#preflight`),i(3),a(J);var Y=e(J),ut=e(r(Y),5);ut.nodeValue=`, no link and no file or directory, on a first
deploy). A deploy planned before another one swapped stops here, saying
`,i(6),a(Y);var X=e(Y,2),dt=e(r(X),5);dt.nodeValue=`
into the new release (an apply-managed env file, for example); a release
that ships a directory at a shared name fails the deploy here;`,a(X);var Z=e(X,2),ft=e(r(Z),5);ft.nodeValue=`, longer only where 12 would be ambiguous), with
`,i(10),a(Z);var pt=e(Z),mt=e(r(pt),3);mt.nodeValue=` at the new release atomically. From
here the release is live, and the run goes on to restart and check it
whatever the rest of the script does: what follows is housekeeping, and
a failure there is a warning in the run's output, not a failed step. A
script that fails after saying it swapped is taken as swapped only when
`,i(2),a(pt),i(2),a(at),a(K);var ht=e(K,3),gt=e(r(ht),9);gt.nodeValue=`
means the app doesn't serve `,i(8),a(ht),a(W);var _t=e(W);s(_t,`id`,`auto-rollback`);var Q=e(_t),vt=r(Q);vt.nodeValue=`If a step after the swap fails (the restart errors, health never goes green,
`,i(6),a(Q);var yt=e(Q,2);p(yt,{lang:null,content:`→ preflight: checking 1 apply-managed resource for drift
→ build: Build application
→ tarball: Create tarball
→ upload: Upload tarball
→ extract_swap: Extract and swap release
→ restart: Restart app
→ health: Health check
→ rollback: Roll back to def5678
deploy — target host.example (wetrun)
  version: abc1234 (previous: def5678)
  ok    preflight     4.1s  1 apply-managed resource, no drift
  ok    build         1.1s
  ok    tarball       2.2s
  ok    upload        3.3s  4.2 MB sent
  ok    extract_swap  4.4s
  ok    restart       5.5s
  FAIL  health        6.6s  service did not become healthy at https://app.example.com/health within 15 attempts (last: HTTP 502)
  ok    rollback      8.0s  def5678 restored and restarted, health OK
  this deploy spent its review: before re-running, preview again with \`zap deploy\` (or pass --expect-plan with the hash that preview prints)
deploy FAILED at health on host.example after 1m 23s — rolled back: def5678 is live again
plan_hash: deadbeef`});var $=e(yt,2),bt=e(r($),6);bt.nodeValue=`
by hand, `,i(2),a($);var xt=e($,5);s(xt,`id`,`concurrent-deploys`),i(2),ee((e,t,n,ee,r,te,i,a,o)=>{s(oe,`href`,e),s(se,`href`,t),s(fe,`href`,n),s(Te,`href`,ee),s(De,`href`,r),s(Ae,`href`,te),s(je,`href`,i),s(ze,`href`,a),s(Be,`href`,o)},[()=>u(`docs/cli#zap-deploy`),()=>u(`docs/targets#what-the-target-needs`),()=>u(`docs/cli#json-events`),()=>u(`docs/targets#the-bootstrap-user`),()=>u(`docs/concepts#a-wetrun-executes-only-the-plan-you-reviewed`),()=>u(`docs/cli#zap-apply`),()=>u(`docs/lock#on-disk-state`),()=>u(`docs/env#masked-hosts-and-review`),()=>u(`docs/security#escaped-output`)]),ne(t,o)},$$slots:{default:!0}})},$$slots:{default:!0}}),re()}export{h as t};