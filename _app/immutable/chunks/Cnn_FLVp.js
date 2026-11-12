import{$ as e,G as t,J as ee,K as te,X as n,Z as ne,dt as r,ft as i,j as a,k as re,l as o,m as s,ot as c,st as l}from"./CkSeWg2M.js";import{t as u}from"./Cyt8LZpN.js";import{n as ie}from"./BbCw5KVU.js";import"./BPVwp-J3.js";import{t as d}from"./k6TRNp0w.js";import{t as f}from"./DH_LefOd.js";import{t as p}from"./CtsBFaJL.js";var ae=a(`<p>Every zap command, its flags, what it reads and writes, and its exit codes. For
what the commands mean, see <a>concepts.md</a> <a>getting-started.md</a>.</p><!><p>Every command that takes a config defaults it to <code>./zap.ts</code>. <code>zap</code> with no
command prints the loop and exits 0; <code>zap --help</code> <code>--help</code> on any command prints its flags.</p><h2>Commands at a glance</h2><table><thead><tr><th>Command</th><th>Does</th><th>Touches the target</th><th>Writes</th></tr></thead><tbody><tr><td><code>zap plan</code></td><td>detect, then diff desired against live</td><td>reads</td><td>last-run report</td></tr><tr><td><code>zap apply</code></td><td>dry run: the plan, as <code>apply</code> would run it</td><td>reads</td><td>last-run report</td></tr><tr><td><code>zap apply --wetrun</code></td><td>execute the reviewed plan, then re-detect</td><td><strong>changes it</strong></td><td><code>zap.lock</code>, pending-trigger markers on the target, last-run report</td></tr><tr><td><code>zap deploy</code></td><td>dry run: the release plan, every step in full</td><td>reads <code>current</code> over SSH</td><td>the deploy preview</td></tr><tr><td><code>zap deploy --wetrun</code></td><td>execute the reviewed release plan: build, upload, swap, restart, health-check</td><td><strong>changes it</strong></td><td>releases, <code>current</code>, <code>deploy_info.json</code> and the deploy lock on the target, last-run report (preflight); withdraws the deploy preview</td></tr><tr><td><code>zap detect</code></td><td>the live verdict per resource, no diff</td><td>reads</td><td>last-run report</td></tr><tr><td><code>zap status</code></td><td>the last run's verdicts, offline</td><td>no</td><td>nothing</td></tr><tr><td><code>zap config validate</code></td><td>eval the config and run the machine-free gates</td><td>no</td><td>nothing</td></tr><tr><td><code>zap lock</code></td><td>pin the <code>fgro</code> build and rebuild <code>zap.lock</code> from upstream</td><td>no (fetches URLs)</td><td><code>zap.lock</code></td></tr><tr><td><code>zap lock --check</code></td><td>classify <code>zap.lock</code> against the config</td><td>no</td><td>nothing</td></tr><tr><td><code>zap update [ids…]</code></td><td>re-fetch and advance lock pins</td><td>no (fetches URLs)</td><td><code>zap.lock</code></td></tr><tr><td><code>zap version</code></td><td>print the version</td><td>no</td><td>nothing</td></tr></tbody></table><p>All of them but <code>version</code> evaluate the config first, with the <code>fgro</code> <code>zap.lock</code> pins (<code>zap lock</code> pins the one it is given), and run the two
machine-free gates: a hardcoded secret literal or a structural error (a duplicate id, a
dangling <code>depends_on</code> <code>service_manager</code> <a>configs.md</a>.</p><h2>Shared flags</h2><table><thead><tr><th>Flag</th><th>On</th><th>Meaning</th></tr></thead><tbody><tr><td><code>--fgro &lt;path></code></td><td>every config command</td><td>the <code>fgro</code> binary that evaluates the config, by absolute path; overrides <code>ZAP_FGRO</code>. Under <code>sudo</code>, which resets the environment, the flag is the only way to name it (<a>install.md</a>).</td></tr><tr><td><code>--env-file &lt;path></code></td><td>every config command</td><td>load <code>NAME=VALUE</code> lines into the operator environment before anything resolves (<a>env.md</a>)</td></tr><tr><td><code>--no-cache</code></td><td><code>detect</code>, <code>plan</code>, <code>apply</code>, <code>deploy</code></td><td>re-evaluate the config even under <code>ZAP_EVAL_CACHE=skip</code>, which otherwise serves a cache hit; by default every command evaluates fresh. The other commands that read a config take no <code>--no-cache</code> and serve a hit under <code>skip</code>. Only the config's evaluation is cached; the target is always read live.</td></tr><tr><td><code>--bootstrap</code></td><td><code>detect</code>, <code>plan</code>, <code>apply</code>, <code>deploy</code></td><td>connect as the target's <code>bootstrap_user</code> instead of <code>user</code>; a different plan from the primary user's (<a>targets.md</a>)</td></tr><tr><td><code>--json</code></td><td><code>apply</code>, <code>deploy</code></td><td>stream events as JSON lines to stdout during a wetrun (no effect on a dry run); a wetrun that ends before its first event prints its text report to stderr</td></tr><tr><td><code>--wetrun</code></td><td><code>apply</code>, <code>deploy</code></td><td>execute. Without it neither changes the target.</td></tr></tbody></table><h2><code>zap plan</code></h2><!><p>Detects every declared resource live and renders the changeset: one <code>[+]</code> <code>[~]</code> <code>plan_hash</code> at the end. <code>--diff</code> adds per-resource <code>current → desired</code> <code>plan_hash</code> covers, as <code>zap plan</code> does.</p><p>Under the header come the lines naming the machine and environment the plan is
for. They are part of the plan and its hash, so a preview made as one user or
under one <code>HOME</code> doesn't bind a wetrun as another: <code>sudo zap apply --wetrun</code> </p><table><thead><tr><th>Line</th><th>Printed</th><th>Shows</th></tr></thead><tbody><tr><td><code>host:</code></td><td>remote, when the declared host is a reference</td><td>the host it resolves to</td></tr><tr><td><code>user:</code></td><td>remote</td><td>the connecting user, or <code>(none — ssh chooses)</code></td></tr><tr><td><code>user:</code></td><td>local</td><td>the user Zap runs as</td></tr><tr><td><code>home:</code></td><td>local</td><td>the <code>HOME</code> a <code>~</code> resolves to (an <code>--env-file</code>'s value included), or <code>(none — HOME is unset)</code></td></tr><tr><td><code>target:</code></td><td>always</td><td>the declared target as one line of JSON (<code></code>), a reference in its exact form (<code></code>)</td></tr><tr><td><code>references:</code></td><td>when the changes use references</td><td>one line each: <code>NAME = value</code>, <code>NAME is a secret: …</code>, or <code>NAME is unset or empty: …</code>. A value past 200 characters is cut, with the rest's length and the start of the whole value's blake3.</td></tr></tbody></table><p>Under each change come the lines that say what it declares (its <code>name:</code> when it
has one, a file's <code>path:</code>, <code>mode:</code>, and <code>content:</code> descriptor, a link's <code>to:</code>, a
script's <code>check:</code>, <code>cwd:</code>, and <code>env:</code>, an <code>apt_repo</code>'s <code>key:</code> URL and the <code>pin:</code> <code>size:</code>, a pipeline's <code>max_concurrency:</code> <code>step:</code> ids and <code>step name:</code> labels), then its steps. A <code>content:</code> descriptor's
SHA-512 is of the text as written: for a template, the template before its
variables are filled, followed on the same line by its <code>vars</code> <code>kinds</code>, each as JSON.
Multi-line text prints indented under its first line, and control and invisible
characters print as <code>&lt;U+XXXX></code> <a>security.md</a>).</p><p>A step line starts with <code>></code>, <code>#</code>, or <code>=</code>. <code>></code> <code>#</code> is never run as written: it is a <code>verify</code> assertion Zap checks itself, or a
step the target's manager has no command for. <code>=</code> is one of Zap's own
operations, named with what it acts on and never printed as the script that
performs it:</p><!><ul><li><code>= put &lt;path></code> installs a file (<a>security.md</a>).
The parentheses give its mode, the account the write runs as, and a check the
staged file must pass. Text Zap holds prints whole under <code>text:</code>, less its
final newline, with its length and the start of its SHA-512; a text with no
final newline says so in the parentheses. Text the target produces has a <code>from:</code> <code>line:</code>: an apt source line (which the target's
shell expands, at every plan as well as on apply, so a <code>$VERSION_CODENAME</code> in
it is read there and a <code>$(…)</code> in it runs), an <code>/etc/fstab</code> entry.</li><li><code>= run the script fetched from &lt;url>  (piped to &lt;shell>)</code> is an <code>installer</code>:
the URL and the shell as the config declares them.</li><li><code>= dir &lt;path></code> creates a directory if it is missing and sets its mode and
owner.</li><li><code>= check &lt;path>  (not a link, below directories only root writes, as root)</code> <code>swap</code> file's creation, and refuses a link at the path or a
directory on the way to it that another account can write
(<a>resources.md</a>).</li><li><code>= pg_hba rule: &lt;line></code> adds the line to the server's <code>pg_hba.conf</code> <code>postgres</code> account, unless it is already there. A line it adds is put in
force by reloading the server's configuration; a line already there reloads
nothing. A file that doesn't belong to <code>postgres</code> is left unchanged and the
step fails, and so does a file the server can't parse (<code>pg_hba_file_rules</code> <code>error</code>, checked before the reload), a reload it doesn't confirm, or
a reload it doesn't load within 30 seconds.</li></ul><p>A <code>=</code> step that fails is reported by the same words, in the run's report and in
the <code>change_failed</code> event's <code>error</code> <code>put /etc/sudoers.d/deploy (mode 440, as root, checked by visudo) exited 93: …</code>.</p><p> <code>UNDETERMINED</code>, <code>UNVERIFIABLE</code>, or <code>LOCK</code> <a>banner</a>.</p><p>Exit codes:</p><table><thead><tr><th>Code</th><th>Meaning</th></tr></thead><tbody><tr><td>0</td><td>every resource was read, and every reference and pin resolved. Pending changes still exit 0: <code>plan</code> reports, it doesn't judge.</td></tr><tr><td>1</td><td>something is unestablished: a held resource, an unresolved reference, or a lock standing error</td></tr></tbody></table><p>The pass is recorded as a preview, so a following <code>zap apply --wetrun</code> binds to
its plan (<a>concepts.md</a>).
A plan whose host or connecting user resolves through a masked reference names
no one machine: it is shown under an <code>UNBINDABLE</code> note with no <code>plan_hash</code>, and
is not a preview. When it is the host, the pass also keeps no last-run report
and says so under an <code>UNRECORDED</code> note.</p><h2><code>zap apply</code></h2><!><p>Without <code>--wetrun</code>, the same pass as <code>plan</code>, rendered as what <code>apply</code> <code>resolved, not yet written to zap.lock</code>; the write waits for a wetrun.</p><p><code>--no-lock</code> leaves the lock's entries alone: no tracked pin is read, nothing is
fetched to pin a tracked source, and nothing is written. A tracked source then
has no pin, so its resource holds; a config with none runs as usual, offline.
The toolchain pin is still read, and without one the command refuses as any
other does.</p><p>With <code>--wetrun</code>, apply:</p><ol><li>rejects the run if any variable the config references is unset or empty, or
if the target's host or connecting user resolves through a masked reference;</li><li>detects and plans;</li><li><strong>checks the plan against the review</strong> (next section) and refuses if it
doesn't match, or on an interactive terminal shows the plan and asks;</li><li> <code>zap plan</code> and a dry run warn about the same thing ahead of time;</li><li>claims the preview it bound to, so one preview covers one wetrun: of two
wetruns started on one preview, the one that claims it first goes on and the
other stops with nothing changed (exit 2);</li><li>re-checks that every reference the plan recorded still resolves to the
recorded value, refusing (exit 2) if one moved while the run was in progress;</li><li>writes <code>zap.lock</code> when the config has tracked pins;</li><li>executes the changes in dependency order, stopping at the first failure,
writing a pending-trigger marker on the target before the first source of a
triggered service and clearing it after the service's change;</li><li> <code>RESIDUAL</code>.</li></ol><p>While steps 8 and 9 run, each change and the re-detection print one line to
standard error as they start (<code>→ notes: create directory</code>); the report, on
standard output when the run ends, holds every outcome. <code>--json</code> prints no such
line.</p><p>The report lists each change as a row: its status (<code>ok</code>, <code>FAIL</code>, or <code>skip</code>),
its id, how long it ran (a skipped change never ran, so it has no time), and a
failure's error code and message or a skip's reason. The <code>applied:</code> line counts
them, and the last line before the <code>plan_hash</code> is the verdict, with the
machine's host (<code>local</code> for the machine Zap runs on) and the time the run took
from the lock write before the first change to the end of the re-detection:</p><table><thead><tr><th>Verdict line</th><th>Exit</th></tr></thead><tbody><tr><td><code>converged &lt;host> in &lt;time>, the re-detect included</code></td><td>0</td></tr><tr><td><code>apply FAILED at &lt;id> on &lt;host> after &lt;time> — …</code>, which says what ran before it and what was skipped after it</td><td>1</td></tr><tr><td><code>apply did not establish convergence on &lt;host> in &lt;time> — the re-detect failed (RESIDUAL above)</code></td><td>1</td></tr><tr><td><code>apply did not converge &lt;host> in &lt;time> — N resources do not read converged (RESIDUAL above)</code></td><td>1</td></tr><tr><td><code>apply did not establish convergence on &lt;host> in &lt;time> — N resources were held (UNDETERMINED above)</code></td><td>1</td></tr></tbody></table><p>When more than one applies, the verdict names the first in that order.</p><h3>Binding to the review</h3><p>A wetrun executes only the plan you reviewed: the plan it computes must equal,
hash for hash, the one named by <code>--expect-plan &lt;hash></code> or the one in the most
recent preview on this host. Otherwise it <strong>refuses</strong> <code>/dev/null</code>, or cut short by <code>head</code> <a>concepts.md</a>.</p><p>On an interactive terminal, a wetrun whose plan has no review (no preview, or a
preview of a different plan) and no <code>--expect-plan</code> shows the plan and asks instead:</p><!><p>The plan and the question go to standard error, as do the <code>→</code> <code>plan_hash</code>, in either case. Input typed before the question appears is
discarded, so neither a <code>y</code> nor an earlier run's answer typed ahead while Zap
reads the machine runs anything. Those
characters execute the plan shown and nothing else; any other answer (a <code>y</code>,
the whole hash, an empty line, the end of the input) declines: the plan is
rendered again under a <code>DECLINED</code> banner, recorded as the preview, and the exit
is 2, as for a refusal. There is no flag that answers for you. Interrupting at
the question (Ctrl-C) ends the run with nothing executed and nothing recorded
as a preview, so the next wetrun asks again. It never asks under <code>--json</code>, for
a mismatched <code>--expect-plan</code>, for a plan with no hash, or for a plan a command
can't run.</p><p><strong>Scripting.</strong> The question appears only on an interactive terminal, for
a plan with no review. A script stays non-interactive by previewing first (a dry run,
then the wetrun), by passing <code>--expect-plan &lt;hash></code>, or by running with
standard input that isn't a terminal (<code>&lt; /dev/null</code>). A non-interactive wetrun
with no review of its plan refuses, and <code>--json</code> never asks.</p><p><code>--expect-plan</code> makes the binding explicit: the hash from the plan you reviewed,
perhaps in a pull request or an agent's transcript. It is the binding to use
when the preview's output may be truncated, or when the one who reads it isn't
the one who runs the wetrun. The match is exact. A dry run
rejects the flag. <code>zap deploy</code> follows the same rule against its own preview
(<a>below</a>).</p><p>Exit codes:</p><table><thead><tr><th>Code</th><th>Dry run</th><th>Wetrun</th></tr></thead><tbody><tr><td>0</td><td>no changes pending</td><td>every change completed, and the re-detection read everything converged</td></tr><tr><td>2</td><td>changes pending; <code>--expect-plan</code> without <code>--wetrun</code></td><td>refused: the plan was not the reviewed one (or was declined at the prompt), its preview was claimed by another wetrun first, or a command can't take a resolved value; or an error before anything runs: the host or connecting user is behind a masked reference</td></tr><tr><td>1</td><td>a held resource or an unresolved reference</td><td>a failed change, a residual resource, a failed re-detection, a held resource, or a preview that couldn't be withdrawn</td></tr></tbody></table><h2><code>zap deploy</code></h2><!><p>Ships a release to a remote target: build locally, tarball the artifacts,
upload, extract into <code>releases/&lt;version></code>, swap the <code>current</code> symlink, restart
the service, poll health. Full mechanism: <a>deploy.md</a>.</p><p>A dry run reads <code>zap.lock</code>, connects over SSH to read the live <code>current</code> <code>plan_hash</code>, records the plan as this host's <strong>deploy preview</strong> <code>server already at this version</code>, prints no hash, records nothing, and exits 0,
on a dry run too; <code>--force</code> deploys anyway.</p><p>A dry run prints no <code>plan_hash</code> and records no preview when:</p><ul><li>the host, connecting user, or health domain resolves through a masked
reference;</li><li>the checkout has uncommitted changes or untracked files and no <code>--force</code> </li></ul><p>A wetrun of either is refused.</p><p>A wetrun executes only the reviewed plan, as <code>zap apply</code>'s does, but against the
deploy preview: its plan's hash must equal <code>--expect-plan</code> or the recorded
preview's, or it refuses before the preflight and any step, becomes the new
preview, and exits 2 (on an interactive terminal with no <code>--expect-plan</code> it asks
for the start of the <code>plan_hash</code> <code>zap status</code> <a>deploy.md</a>.</p><p> <a>deploy.md</a>.</p><p>Flags:</p><table><thead><tr><th>Flag</th><th>Meaning</th></tr></thead><tbody><tr><td><code>--expect-plan &lt;hash></code></td><td>bind to this hash instead of the recorded preview: execute only if the plan has exactly it. Wetrun only, and not single-use.</td></tr><tr><td><code>--force</code></td><td>deploy an unchanged version, and version a dirty tree <code>&lt;hash>-dirty-&lt;id></code>, named by its changes. Without it a wetrun of a dirty tree is refused.</td></tr><tr><td><code>--skip-build</code></td><td>leave <code>deploy.build</code> out of the plan; ship the artifacts as they are</td></tr><tr><td><code>--skip-preflight</code></td><td>skip the drift preflight. The machine-free gates and the env check still run.</td></tr></tbody></table><p><code>--skip-build</code>, <code>--skip-preflight</code>, <code>--force</code> on a dirty tree, and <code>--bootstrap</code> </p><p>Exit codes:</p><table><thead><tr><th>Code</th><th>Meaning</th></tr></thead><tbody><tr><td>0</td><td>dry run rendered, release deployed, or already deployed</td></tr><tr><td>2</td><td>refused: the plan was not the reviewed one, was declined at the prompt, or its preview was spent by another run first</td></tr><tr><td>2</td><td>the preflight found drift, or couldn't read every resource</td></tr><tr><td>2</td><td>a wetrun whose host, connecting user, or health domain resolves through a masked reference, or from a dirty checkout without <code>--force</code></td></tr><tr><td>2</td><td><code>--expect-plan</code> on a dry run; a <code>zap.lock</code> that doesn't parse</td></tr><tr><td>1</td><td>a step failed, including the release script finding another deploy of the app holding its deploy lock or having swapped since this plan was made (rollback may have restored the previous release; the exit stays 1); the recorded preview couldn't be withdrawn; <code>zap.lock</code> couldn't be opened</td></tr></tbody></table><h2><code>zap detect</code></h2><!><p>The detection half of <code>plan</code>, rendered raw: one line per resource with its
mark (<code>ok</code>, <code>drift</code>, <code>absent</code>, or <code>?</code> for undetermined), its id and kind, and,
for drift, what was observed. For validating that a probe reads a real target
correctly. Over a host that resolves through a masked
reference it keeps no last-run report and ends with an <code>UNRECORDED</code> note.</p><table><thead><tr><th>Code</th><th>Meaning</th></tr></thead><tbody><tr><td>0</td><td>every resource was read and every reference and pin resolved; drift and absence still exit 0</td></tr><tr><td>1</td><td>a resource marked <code>?</code>, an unresolved reference, or a lock standing error</td></tr></tbody></table><h2><code>zap status</code></h2><!><p>Offline: evaluates the config, reads the last-run report for the host the target
resolves to (<a>detection.md</a> <code>zap.lock</code>, and never touches the target. It says what the last run saw, never
what the target is now; the live signal is <code>zap plan</code>. A referenced host needs
its env (<code>--env-file</code>), as for a run. For an exact answer it needs the same env
as the run that wrote the report, secrets included: a secret it can't mask reads
as "config changed since", never as a false "unchanged".</p><!><p>Each line is a resource's verdict in that run, with a note when:</p><table><thead><tr><th>Note</th><th>Meaning</th></tr></thead><tbody><tr><td><code>config changed since; this verdict predates it</code></td><td>the resource's hash no longer matches: it was edited, an ordinary variable it references resolves differently, or its pin moved. When the target itself changed (its package or service manager, home, user), a note names it and every verdict predates it.</td></tr><tr><td><code>depends on a secret; a changed value isn't visible offline</code></td><td>it references a secret</td></tr><tr><td><code>not read</code> (<code>not in the last run</code>)</td><td>declared, but not in the last run: added since, or there is none</td></tr><tr><td><code>orphaned</code> (<code>read …, no longer declared</code>)</td><td>in the last run, no longer declared; warn-only</td></tr></tbody></table><p>A preview's <code>plan_hash</code> is printed as the plan <code>zap apply --wetrun</code> binds to. The
lock standing and an <code>UNVERIFIABLE</code> banner, for the last run or for now, lead
the render. With no last run every resource is <code>not read</code>, so <code>status</code> exits 1
unless nothing is declared.</p><table><thead><tr><th>Code</th><th>Meaning</th></tr></thead><tbody><tr><td>0</td><td>every declared resource read converged in the last run and its config is unchanged since (a secret's value excepted); lock clean; nothing unverifiable</td></tr><tr><td>2</td><td>the last run read drift or absence</td></tr><tr><td>1</td><td>anything unestablished: not read, changed since, undetermined, unverifiable then or now, a lock error, no last run, or a host that keeps none (one behind a masked reference)</td></tr></tbody></table><h2><code>zap config validate</code></h2><!><p> <code>ok: N resource(s)</code> and exits 0, or the gate's message and exits 2. The fast
check for CI and editors: no target, no network, no secrets needed, but a copy
of the pinned <code>fgro</code> build (<a>lock.md</a>).</p><h2><code>zap lock</code></h2><!><p>The verbs over <code>zap.lock</code> <code>remote</code> files and <code>build</code> sources (<a>lock.md</a>).</p><p><code>zap lock</code> pins the toolchain, the blake3 of the <code>fgro</code> binary it evaluates the
config with, re-fetches every tracked source, re-mints every entry, drops
orphans, and rewrites the file. All or nothing. It is the only command that
evaluates with a binary the lock doesn't pin, and the only one that moves the
toolchain pin (<a>lock.md</a>).</p><p><code>zap lock --check</code> first holds the <code>fgro</code> binary to the toolchain pin: with a
binary that hashes to something else it reports the pin stale without
evaluating the config, so the entries go unchecked. Otherwise it classifies
each entry offline as current, missing, stale (the resource changed since the
pin), unverifiable (a variable the hash takes by value is unset), or orphaned.
Its 1 is a read-only verdict, like <code>plan</code>'s held resources; <code>apply</code>, which
refuses to act on a stale or unverifiable entry, treats the same finding as an
error and exits 2, as does a <code>deploy</code> wetrun's preflight.</p><table><thead><tr><th>Code</th><th>Meaning</th></tr></thead><tbody><tr><td>0</td><td><code>zap lock</code>: the lock was written. <code>--check</code>: every entry is current; orphans only warn.</td></tr><tr><td>2</td><td>no toolchain pin (<code>--check</code>); a tracked URL that references an unset or empty variable (<code>zap lock</code>, which then fetches nothing)</td></tr><tr><td>1</td><td><code>--check</code>: a pin missing, stale, or unverifiable. Either: a fetch or another operational error (<a>all commands</a>)</td></tr></tbody></table><p>Both print a <code>note:</code> for each reference the lock addresses by name only, because
its name or the form of its value reads as a secret (<a>lock.md</a>).</p><h2><code>zap update</code></h2><!><p>Re-fetches the named resources, or every tracked one, and rewrites each entry
whose pin advanced or whose recorded config hash is stale. Each advance is
written as it happens, so a later failure keeps the earlier ones. A tracked URL
that references an unset or empty variable is never fetched, and that entry
fails. The config is <code>--config &lt;path></code> here, since the positional arguments are
ids. A failed entry keeps the code its error has everywhere else: exit 1 if any
failure is operational (a fetch, a write), else 2 if any entry failed on an
input to fix (an unset reference in its URL or credential, a signature that
doesn't verify). It prints the same <code>note:</code> lines as <code>zap lock</code>.</p><h2><code>zap version</code></h2><p>Prints <code>zap &lt;version></code>.</p><h2>Banners</h2><p>What a pass couldn't establish, or why it didn't act, leads its report:</p><table><thead><tr><th>Banner</th><th>Means</th><th>Exit</th></tr></thead><tbody><tr><td><code>UNDETERMINED</code></td><td>resources detection couldn't read, each with why, then the changes held behind them, each with what it waits on or would trigger; all held out of the plan</td><td>1; 2 in a deploy's preflight</td></tr><tr><td><code>UNVERIFIABLE</code></td><td>referenced variables that were unset or empty</td><td>1; a wetrun refuses with 2</td></tr><tr><td><code>LOCK</code></td><td>a tracked pin that is missing, stale, or unverifiable</td><td>1; <code>apply</code> and a deploy wetrun refuse with 2</td></tr><tr><td><code>UNREVIEWED</code></td><td>a wetrun's plan has no review; on a terminal, Zap asks</td><td></td></tr><tr><td><code>REFUSED</code></td><td>a wetrun that didn't execute; its plan becomes the preview</td><td>2 (1 when a resource is held)</td></tr><tr><td><code>DECLINED</code></td><td>the confirmation wasn't the plan's hash prefix</td><td>2</td></tr><tr><td><code>RESIDUAL</code></td><td>resources that still don't read converged after a wetrun</td><td>1</td></tr><tr><td><code>UNBINDABLE</code></td><td>the host, connecting user, or (deploy) health domain is behind a masked reference: no <code>plan_hash</code>, not a preview</td><td></td></tr><tr><td><code>UNRECORDED</code></td><td>the host is behind a masked reference: no last-run report kept</td><td></td></tr></tbody></table><h2>Exit codes, all commands</h2><p>The pattern across commands. The tables list 2 before 1 because 2 is still an
established answer and 1 is not:</p><table><thead><tr><th>Code</th><th>Family</th></tr></thead><tbody><tr><td>0</td><td>established and fine: converged, deployed, nothing to do</td></tr><tr><td>2</td><td>established and needs a decision: changes pending (for the commands that judge them: <code>apply</code>, <code>status</code>), a refused or declined wetrun, preflight drift, a config error</td></tr><tr><td>1</td><td>unestablished or failed: a held or unverifiable resource, a failed change, a failed step, an operational error</td></tr></tbody></table><p><code>plan</code>, <code>detect</code>, and a deploy dry run report rather than judge: pending changes
exit 0 there.</p><p>A report that can't be written (standard output a pipe whose reader has gone,
or a full device) prints <code>error: the report could not be written:</code> and the
reason on standard error.
A run whose report is its answer (<code>plan</code>, <code>detect</code>, <code>status</code>, <code>lock --check</code> <code>config validate</code>, <code>version</code>, the help, a dry run, a refused wetrun) then exits
1 where it would have exited 0. A preview whose report couldn't be written is
withdrawn, and <code>its preview was withdrawn</code> follows on standard error: the next
wetrun run without <code>--expect-plan</code> refuses. The preview of a <code>plan</code> <code>apply</code> is the host's last-run report, so <code>zap status</code> then has no last run for
that host until the next pass. A record another run has written at its name
since is left alone, and a run stopped while it writes (a signal) withdraws
nothing. A run
that changed something keeps its own code, which describes the machine or the
lock: an <code>apply</code> <code>deploy</code> wetrun that reached its steps, <code>lock</code>, and an <code>update</code> that advanced or
refreshed an entry. An <code>apply</code> wetrun with nothing to do, or an <code>update</code> that
moved no entry, only answered. A non-zero code is kept either way. An error or a
usage error that standard error can't take is lost, and exits with its own code
all the same.</p><p>An error prints as <code>error:</code> and its message; a message of several lines is
indented under it, and any advice Zap adds follows at the left margin.</p><p>Errors raised before a report exists follow the same split.</p><p>Exit 2, a problem in your inputs:</p><ul><li><code>fgro</code>: none named; a path that isn't absolute; one that is missing, a link, a
script or set-ID file, or doesn't hash to the toolchain pin; one that answers in
an eval protocol or graph version this <code>zap</code> doesn't read; no toolchain pin; an <code>fgro</code> pin
cache under <code>~/.zap</code> that isn't yours.</li><li><code>zap.lock</code>: one that doesn't parse or is newer than this <code>zap</code> reads; a lock
stale or unverifiable; a content-hash or signature mismatch.</li><li>The config: not found; named as its own lock would be (<code>*.lock</code>); it or its
directory writable by every user; no project; a <code>package.json</code> on the way up
that can't be read or isn't valid; no user the evaluation may run as (a project
root owns, a project that is or holds that user's home, a directory on the way
it can't search, a group or passwd entry it can't use); eval failure; a schema
error.</li><li>The environment: an env-file error; a <code>ZAP_HOME</code> or <code>HOME</code> unset where needed
or not absolute; a state directory that isn't Zap's own; an unresolved
reference on a wetrun.</li><li>A wetrun refused before its first change: a plan that names no one machine, a
command that can't take a value its reference resolves to, or a reference that
moved while the run was in progress.</li><li>A <code>deploy</code> wetrun from a checkout with uncommitted changes or untracked files
and no <code>--force</code>.</li><li>A usage error: an unknown flag, or <code>--expect-plan</code> without <code>--wetrun</code>.</li></ul><p>Exit 1, a problem in the world: connectivity, a command that can't spawn, a file
operation, a fetch, a git error; an <code>fgro</code> that crashed, wrote output that isn't
its protocol, or couldn't be spawned; an <code>fgro</code> binary written while Zap hashed
it or before it ran, which a retry clears once nothing writes it.</p><h2>JSON events</h2><p><code>--json</code> on a wetrun of <code>apply</code> or <code>deploy</code> streams one JSON object per line to
stdout, instead of the text report. A wetrun that ends before its first event (a
refusal, a preflight bail, an already-deployed release) leaves stdout empty and
prints its text report to stderr. Control and invisible characters in a value
are written as JSON <code>\\u</code> escapes, so the stream decodes to the same values and
is safe to watch. Each event carries an <code>event</code> tag:</p><table><thead><tr><th><code>event</code></th><th>Fields</th><th>When</th></tr></thead><tbody><tr><td><code>run_started</code></td><td><code>target</code>, <code>wetrun</code>, <code>plan_hash</code>, <code>total</code></td><td>once, before any change</td></tr><tr><td><code>change_started</code></td><td><code>resource_id</code>, <code>action</code> (<code>create</code> / <code>update</code>), <code>kind</code></td><td>a change is about to run</td></tr><tr><td><code>change_completed</code></td><td><code>resource_id</code>, <code>output</code></td><td>it finished</td></tr><tr><td><code>change_failed</code></td><td><code>resource_id</code>, <code>error</code>, <code>code</code></td><td>it failed; execution stops</td></tr><tr><td><code>change_skipped</code></td><td><code>resource_id</code>, <code>reason</code></td><td>not run, because an earlier change failed</td></tr><tr><td><code>step_started</code></td><td><code>step</code>, <code>name</code></td><td>a deploy step is about to run</td></tr><tr><td><code>step_completed</code> / <code>step_failed</code> / <code>step_skipped</code></td><td><code>step</code>, plus <code>output</code> / <code>error</code> / <code>reason</code></td><td>the deploy step's outcome</td></tr><tr><td><code>run_finished</code></td><td><code>summary</code> (total / completed / failed / skipped counts)</td><td>once, at the end</td></tr></tbody></table><p>A step skipped after an earlier failure has no <code>step_started</code>, but a started
step's outcome can be <code>step_skipped</code> too: a readiness check the target doesn't
serve, or a rollback whose swap back finds nothing to do (another deploy holds
the app's lock, <code>current</code> no longer names the failed release, or names nothing, or the previous
release is gone). A rollback with nothing to return to is skipped without
starting.</p><p><code>code</code> on a failure is a triage category: <code>transient</code>, <code>permission</code> <code>not_found</code>, <code>conflict</code>, <code>permanent</code>, or <code>execution_failed</code> (<code>permission</code> <code>sudo</code>'s own refusals). A file operation Zap makes itself is classified
by the error the system returned (a symbolic link or anything else in the way,
or a full disk, is <code>conflict</code>; a timeout is <code>transient</code>); a command, or <code>ssh</code>,
by its exit code and what it printed. Every value is masked: a resolved secret
never appears in an event.</p><p>Events carry no duration: a consumer reading the stream live can time it by
when each line arrives. The <code>→</code> progress lines a text-mode wetrun prints to
standard error are not events and are not in the stream.</p><p> <code>warning:</code> lines go with it: the stream carries a warning only where an event
holds it. A deploy's rollback is always one: rolled back, failed, or skipped,
with nothing to return to (a broken release left live) among the skips. The
others, such as a deploy's repairs of an unfinished one or a failed prune,
aren't in the stream.</p><h2>Environment variables Zap reads</h2><table><thead><tr><th>Variable</th><th>Meaning</th></tr></thead><tbody><tr><td><code>ZAP_HOME</code></td><td>where Zap keeps operator-side state (default <code>~/.zap</code>): the eval cache, the <code>fgro</code> pin cache, the content cache, last-run reports, deploy previews, SSH multiplexing sockets. An absolute path; empty counts as unset. See <a>lock.md</a>.</td></tr><tr><td><code>ZAP_FGRO</code></td><td>the <code>fgro</code> binary that evaluates configs, by absolute path (an empty one is an error, not unset); never looked up on <code>PATH</code>. <code>--fgro</code> overrides it, and is the one that survives <code>sudo</code>. Name a copy you update deliberately, not Gro's build output (<a>install.md</a>).</td></tr><tr><td><code>ZAP_MINISIGN</code></td><td>the <code>minisign</code> binary a <code>build</code> source's <code>verify</code> runs, by absolute path (an empty or relative one fails the verification, saying so); unset, the first <code>minisign</code> in an absolute directory on <code>PATH</code>. Either is refused when it, or a directory on the way to it, is writable by a group or others or owned by anyone but root and you, or it sits in <code>node_modules</code> (<a>resources.md</a>)</td></tr><tr><td><code>ZAP_EVAL_CACHE</code></td><td><code>shadow</code> (default: eval fresh, compare against the cache, report a mismatch) or <code>skip</code> (serve a cache hit whose files are unchanged without running <code>fgro</code>; a change the evaluation's record doesn't name isn't seen: a symbolic link, in <code>node_modules</code> or the project, pointed at other files, or a directory turned world-writable)</td></tr><tr><td><code>ZAP_EVAL_CACHE_LOG</code></td><td>set to print eval-cache hit/miss observations</td></tr></tbody></table><p> <code>--env-file</code>.</p>`,1);function m(a,m){l(m,!0);let h=ie(`cli`);s(`y492lb`,e=>{t(()=>{ee.title=`CLI reference — zap`})}),d(a,{get tome(){return h},children:(t,ee)=>{p(t,{children:(t,ee)=>{var a=ae(),s=ne(a),c=e(n(s)),l=e(c);l.nodeValue=`; for a first run, see
`;var ie=e(l);r(),i(s);var d=e(s);f(d,{lang:null,content:`zap <command> [flags] [config]`});var p=e(d),m=e(n(p),6);m.nodeValue=` prints the command list, and
`,r(2),i(p);var h=e(p);o(h,`id`,`commands-at-a-glance`);var g=e(h,2),_=e(n(g),4);_.nodeValue=` build
`;var v=e(_,6);v.nodeValue=`, a cycle, service intent on a target with no
`;var oe=e(v,2);oe.nodeValue=`, …) fails every command with the same message. See
`;var se=e(oe);r(),i(g);var ce=e(g);o(ce,`id`,`shared-flags`);var y=e(ce),le=e(n(y)),b=n(le),ue=e(n(b),2),de=e(n(ue),7);r(),i(ue),i(b);var x=e(b),fe=e(n(x),2),pe=e(n(fe),3);r(),i(fe),i(x);var me=e(x,2),he=e(n(me),2),ge=e(n(he),5);r(),i(he),i(me),r(2),i(le),i(y);var _e=e(y);o(_e,`id`,`zap-plan`);var ve=e(_e);f(ve,{lang:null,content:`zap plan [--diff] [--no-cache] [--bootstrap] [--fgro <p>] [--env-file <p>] [config]`});var S=e(ve),ye=e(n(S),2);ye.nodeValue=`
(create) or `;var be=e(ye,2);be.nodeValue=` (update) line per resource, its steps under it, and the
`;var xe=e(be,6);xe.nodeValue=`
attribute lines above a drifted resource's steps; every change still shows its
steps, so the view prints everything the `,r(4),i(S);var C=e(S),Se=e(n(C),4);Se.nodeValue=`
runs as root and refuses a review made without it.`,i(C);var w=e(C),Ce=e(n(w)),we=e(n(Ce),4),Te=e(n(we),2),Ee=e(n(Te));Ee.textContent=`{"local":true}`;var De=e(Ee,2);De.textContent=`{"$env":"NAME"}`,r(),i(Te),i(we),r(),i(Ce),i(w);var T=e(w),Oe=e(n(T),22);Oe.nodeValue=`
its bytes must have, a swap's `;var ke=e(Oe,4);ke.nodeValue=` and its
`;var Ae=e(ke,8);Ae.nodeValue=` and their
`;var je=e(Ae,4);je.nodeValue=`
(`;var Me=e(je);r(),i(T);var E=e(T),Ne=e(n(E),8);Ne.nodeValue=` is a command Zap runs as written.
`,r(6),i(E);var Pe=e(E);f(Pe,{lang:null,content:`  [+] deploy  (user)
      > id -u -- 'deploy' >/dev/null 2>&1 || sudo useradd -m -d '/home/deploy' -s '/bin/bash' -- 'deploy'
      > sudo chown -h -- 'deploy:' '/home/deploy'
      > sudo usermod -s '/bin/bash' -- 'deploy'
      = dir /home/deploy/.ssh  (mode 700, owner deploy:deploy, as root, created if missing)
      = put /home/deploy/.ssh/authorized_keys  (mode 600, as deploy; 126 bytes, sha512 ef415c5c6a4db94b…)
          text: ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExampleKeyOne deploy@laptop
                ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExampleKeyTwo deploy@ci
      > sudo usermod -p '*' -- 'deploy'
      = put /etc/sudoers.d/deploy  (mode 440, as root, checked by visudo; 86 bytes, sha512 2434fdb3c08c85f2…)
          text: deploy ALL=(ALL) NOPASSWD: /usr/bin/systemctl restart app, /usr/bin/journalctl -u app
  [+] pgdg  (apt_repo)
      key: fetched from https://www.postgresql.org/media/keys/ACCC4CF8.asc
      pin: blake3 bb84ad7105529a9bf29a01dca1d2e400576031b070e396a9f0c669bf75457192
      = put /etc/apt/sources.list.d/pgdg.list  (mode 644, as root)
          from: the line below, as the target's shell reads it inside double quotes after reading /etc/os-release: a variable in it expands and a $(…) in it runs, at every plan too
          line: deb [signed-by=/usr/share/keyrings/pgdg.asc] https://apt.postgresql.org/pub/repos/apt $VERSION_CODENAME-pgdg main
      > sudo apt-get update`});var D=e(Pe),O=n(D),Fe=e(n(O),2),Ie=e(Fe,5);Ie.nodeValue=`
line saying where it comes from and what skips the put. Text the config
supplies for it prints under `,r(8),i(O);var k=e(O,3),Le=e(n(k));Le.nodeValue=`
comes first in a `;var Re=e(Le,3);r(),i(k);var ze=e(k),Be=e(n(ze),3);Be.nodeValue=`, as the
`;var Ve=e(Be,6);Ve.nodeValue=`
lists an `,r(2),i(ze),i(D);var A=e(D),He=e(n(A),6);He.nodeValue=`:
`,r(2),i(A);var j=e(A),Ue=n(j);Ue.nodeValue=`A pass that can't establish a verdict says so before the plan, under an
`;var We=e(Ue,7);o(We,`href`,`#banners`),r(),i(j);var M=e(j,3),Ge=e(n(M),3);r(7),i(M);var Ke=e(M);o(Ke,`id`,`zap-apply`);var qe=e(Ke);f(qe,{lang:null,content:`zap apply [--wetrun] [--expect-plan <hash>] [--json] [--no-lock]
          [--no-cache] [--bootstrap] [--fgro <p>] [--env-file <p>] [config]`});var N=e(qe),Je=e(n(N),6);Je.nodeValue=` would do,
and exit codes that judge the result (below). It also resolves any missing
tracked pin over the network and reports it as
`,r(2),i(N);var P=e(N,3),F=e(n(P),3),Ye=n(F);Ye.nodeValue=`refuses if any planned command can't take a value its reference resolves to
(a single quote in a command, for one), naming the resource and the variable;
`,r(2),i(F);var Xe=e(F,5),Ze=n(Xe);Ze.nodeValue=`re-detects every resource and reports any that still isn't converged as
`,r(2),i(Xe),i(P);var Qe=e(P,5);o(Qe,`id`,`binding-to-the-review`);var I=e(Qe),$e=e(n(I),4);$e.nodeValue=`, changes nothing, and
exits 2. A preview binds once Zap has written it, read or not: one sent to
`;var et=e($e,4);et.nodeValue=` after the pipe took it whole, binds the
same. One whose output couldn't be written is withdrawn, and binds nothing. The
rules are in
`;var tt=e(et);r(),i(I);var nt=e(I,2);f(nt,{lang:null,content:`$ zap apply --wetrun
apply — target local (wetrun, awaiting confirmation)
  user: ops
  home: /home/ops
  target: {"local":true}
  [+] notes  (directory)
      path: ~/notes
      mode: 755
  [+] hello  (file)
      path: ~/notes/hello.txt
      content: inline (15 bytes, sha512 0c7463f032f1dc98…)

  UNREVIEWED — nothing has run: this plan runs only once it is confirmed below.
    no plan has been previewed on this host.
plan_hash: 5bb79cc9141942676c784abba55826f12be51b3feb86f5f0cf77666545674d61
Apply this plan? Type 5bb79cc9, the start of its plan_hash, to confirm: 5bb79cc9
→ notes: create directory
→ hello: create file
→ re-detect: reading 2 declared resources back to confirm what the changes left
apply — target local (wetrun, confirmed)
  user: ops
  home: /home/ops
  target: {"local":true}
  ok    notes  0.0s
  ok    hello  0.0s
applied: 2 ok, 0 failed, 0 skipped (of 2)
converged local in 0.0s, the re-detect included
plan_hash: 5bb79cc9141942676c784abba55826f12be51b3feb86f5f0cf77666545674d61`});var L=e(nt),rt=e(n(L),2);rt.nodeValue=` lines a wetrun
prints as each change and the re-detection starts; the report goes where it
always does. The answer is the first eight characters of the plan's
`,r(12),i(L);var it=e(L,2),at=e(n(it),4);o(at,`href`,`#zap-deploy`),r(),i(it);var ot=e(it,3);o(ot,`id`,`zap-deploy`);var st=e(ot);f(st,{lang:null,content:`zap deploy [--wetrun] [--expect-plan <hash>] [--force] [--skip-build]
           [--skip-preflight] [--json] [--no-cache] [--bootstrap]
           [--fgro <p>] [--env-file <p>] [config]`});var R=e(st),ct=e(n(R),5);r(),i(R);var z=e(R),lt=e(n(z),4);lt.nodeValue=`
symlink, prints the plan (the version and the release it replaces, the commit's
subject, the resolved host and connecting user, the declared target, the tree
and preflight state, and every step with its command, script, paths, or URL),
closes with a recap of the commit, version, host, user, tree, and preflight, ends
with the `;var ut=e(lt,4);ut.nodeValue=`, and
exits 0. If the live release is already this version it reports
`,r(4),i(z);var B=e(z,2),dt=e(n(B)),ft=e(n(dt),2);ft.nodeValue=`
(never reported as already at this version, since the tree isn't what the
live release holds).`,i(dt),i(B);var V=e(B,2),pt=e(n(V),8);pt.nodeValue=` instead). A wetrun that passes withdraws the
preview before its first step, so one recorded preview covers one execution.
`;var mt=e(pt,2);mt.nodeValue=` doesn't show the deploy preview. The rules are in
`;var ht=e(mt);r(),i(V);var H=e(V),gt=n(H);gt.nodeValue=`A wetrun prints one line to standard error as each phase starts (the drift
preflight, each step, a rollback), and its report to standard output when it
ends: a table of the preflight, each step, and any rollback, each with its
status and how long it took, then a closing line naming the version live on the
host, or, after a failure, the step that failed and the state the target is in. Samples:
`;var _t=e(gt);r(),i(H);var U=e(H,3),vt=e(n(U),7);vt.nodeValue=`
each change the plan, and so its hash: a wetrun binds to a preview made with
the same flags.`,i(U);var yt=e(U,3);o(yt,`id`,`zap-detect`);var bt=e(yt);f(bt,{lang:null,content:`zap detect [--no-cache] [--bootstrap] [--fgro <p>] [--env-file <p>] [config]`});var xt=e(bt,3);o(xt,`id`,`zap-status`);var St=e(xt);f(St,{lang:null,content:`zap status [--fgro <p>] [--env-file <p>] [config]`});var W=e(St),Ct=e(n(W)),wt=e(Ct);wt.nodeValue=`) and the on-disk
`,r(6),i(W);var Tt=e(W);f(Tt,{lang:null,content:`$ zap status
target local (pkg: none, service: none)
last run on local: zap apply --wetrun, after its changes ran, at 2026-10-11T21:09:26Z — offline; \`zap plan\` reads the target live
  a 0 exit means every declared resource read converged in the last run and its config is unchanged since — not that the target still is
  converged    notes  directory
  converged    hello  file`});var Et=e(Tt,5);o(Et,`id`,`zap-config-validate`);var Dt=e(Et);f(Dt,{lang:null,content:`zap config validate [--fgro <p>] [--env-file <p>] [config]`});var G=e(Dt),Ot=n(G);Ot.nodeValue=`Evaluates the config and runs the two gates, nothing else. Prints
`;var kt=e(Ot,5);r(),i(G);var At=e(G);o(At,`id`,`zap-lock`);var jt=e(At);f(jt,{lang:null,content:`zap lock [--check] [--fgro <p>] [--env-file <p>] [config]`});var K=e(jt),Mt=e(n(K),2);Mt.nodeValue=`, the ledger for the toolchain pin and the tracked
`;var Nt=e(Mt,5);r(),i(K);var q=e(K),Pt=e(n(q),4);r(),i(q);var J=e(q,2),Ft=e(n(J)),It=e(n(Ft),2),Lt=e(n(It)),Rt=e(n(Lt),2);o(Rt,`href`,`#exit-codes-all-commands`),r(),i(Lt),i(It),i(Ft),i(J);var Y=e(J),zt=e(n(Y),3);r(),i(Y);var Bt=e(Y);o(Bt,`id`,`zap-update`);var Vt=e(Bt);f(Vt,{lang:null,content:`zap update [--config <p>] [--fgro <p>] [--env-file <p>] [ids…]`});var Ht=e(Vt,2);o(Ht,`id`,`zap-version`);var Ut=e(Ht,2);o(Ut,`id`,`banners`);var Wt=e(Ut,3);o(Wt,`id`,`exit-codes-all-commands`);var X=e(Wt,4),Gt=e(n(X),10);Gt.nodeValue=`,
`;var Kt=e(Gt,10);Kt.nodeValue=` or an
`;var qt=e(Kt,6);qt.nodeValue=` wetrun that ran changes or pinned what the lock lacked, a
`,r(10),i(X);var Jt=e(X,6);o(Jt,`id`,`json-events`);var Z=e(Jt,4),Yt=e(n(Z),5);Yt.nodeValue=`,
`;var Xt=e(Yt,10);Xt.nodeValue=`
includes `,r(8),i(Z);var Q=e(Z,2),Zt=n(Q);Zt.nodeValue=`A run that streamed events doesn't print its text report, and the report's
`,r(2),i(Q);var Qt=e(Q);o(Qt,`id`,`environment-variables-zap-reads`);var $=e(Qt),$t=e(n($)),en=n($t),tn=e(n(en)),nn=e(n(tn),5);r(),i(tn),i(en);var rn=e(en),an=e(n(rn)),on=e(n(an),9);r(),i(an),i(rn);var sn=e(rn),cn=e(n(sn)),ln=e(n(cn),13);r(),i(cn),i(sn),r(2),i($t),i($);var un=e($),dn=n(un);dn.nodeValue=`Nothing that shapes a plan comes from Zap's own environment. Values a config
needs come from references resolved from the operator environment or
`,r(2),i(un),te((e,t,ee,te,n,ne,r,i,a,re,s,l,u,d,f,p,ae,m,h,g,_,v)=>{o(c,`href`,e),o(ie,`href`,t),o(se,`href`,ee),o(de,`href`,te),o(pe,`href`,n),o(ge,`href`,ne),o(Me,`href`,r),o(Fe,`href`,i),o(Re,`href`,a),o(Ge,`href`,re),o(tt,`href`,s),o(ct,`href`,l),o(ht,`href`,u),o(_t,`href`,d),o(Ct,`href`,f),o(kt,`href`,p),o(Nt,`href`,ae),o(Pt,`href`,m),o(zt,`href`,h),o(nn,`href`,g),o(on,`href`,_),o(ln,`href`,v)},[()=>u(`docs/concepts`),()=>u(`docs/getting-started`),()=>u(`docs/configs#what-the-gates-reject`),()=>u(`docs/install#getting-fgro`),()=>u(`docs/env#the-env-file`),()=>u(`docs/targets#the-bootstrap-user`),()=>u(`docs/security#escaped-output`),()=>u(`docs/security#writes-on-the-host`),()=>u(`docs/resources#swap`),()=>u(`docs/concepts#a-wetrun-executes-only-the-plan-you-reviewed`),()=>u(`docs/concepts#a-wetrun-executes-only-the-plan-you-reviewed`),()=>u(`docs/deploy`),()=>u(`docs/deploy#binding-a-wetrun-to-a-reviewed-plan`),()=>u(`docs/deploy#what-a-wetrun-prints`),()=>u(`docs/detection#the-last-run-report`),()=>u(`docs/lock#the-toolchain-pin`),()=>u(`docs/lock`),()=>u(`docs/lock#the-toolchain-pin`),()=>u(`docs/lock`),()=>u(`docs/lock#on-disk-state`),()=>u(`docs/install#getting-fgro`),()=>u(`docs/resources#verification`)]),re(t,a)},$$slots:{default:!0}})},$$slots:{default:!0}}),c()}export{m as t};