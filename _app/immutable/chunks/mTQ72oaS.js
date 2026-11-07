import{$ as e,G as t,J as ee,K as n,X as r,Z as te,dt as i,ft as a,j as o,k as ne,l as s,m as c,ot as re,st as l}from"./CkSeWg2M.js";import{t as u}from"./Cyt8LZpN.js";import{n as d}from"./BbCw5KVU.js";import"./BPVwp-J3.js";import{t as f}from"./k6TRNp0w.js";import{t as p}from"./DH_LefOd.js";import{t as m}from"./BzaAmULn.js";var ie=o(`<p>How Zap reads the current state of a target: the verdicts, how deeply each
resource kind is read, the batched reads behind every pass, and the last-run
report. <a>concepts.md</a> is the short version.</p><p>Detection is the <strong>detect</strong> step of describe → detect → plan → apply → observe.
For each declared resource it answers one question, <em>does the desired state
already exist?</em>, with one of four verdicts, defined in <a>concepts.md</a>. This page is how each is reached.</p><p>A fifth word, <code>residual</code>, describes a resource that still doesn't read converged
after a wetrun acted on it. It is covered <a>below</a>.</p><h2>The governing principle</h2><p><strong>Detection depth should match execution idempotency.</strong> If re-executing a
resource is a true no-op, shallow detection is fine. If re-execution has side
effects even when the state is already correct (it restarts a service,
downloads bytes again, fires a <code>restart_on</code> chain), detection must be deep
enough to skip when nothing needs to change.</p><p>Detection runs at one of three depths:</p><table><thead><tr><th>Depth</th><th>Question</th><th>Trust</th></tr></thead><tbody><tr><td>Existence</td><td>does the thing exist at all?</td><td>low: misses attribute drift</td></tr><tr><td>Attribute</td><td>does it exist with the right properties?</td><td>medium: catches most drift</td></tr><tr><td>Content</td><td>is the full content or state correct?</td><td>high: catches all of it</td></tr></tbody></table><h2>Per-resource depth</h2><table><thead><tr><th>Kind</th><th>Depth</th><th>Reads</th></tr></thead><tbody><tr><td><code>file</code></td><td>content</td><td>existence, SHA-512 digest, mode, owner, group</td></tr><tr><td><code>link</code></td><td>content</td><td>the symlink's target, as the login user</td></tr><tr><td><code>build</code></td><td>content</td><td>the provenance sidecar (<a>below</a>)</td></tr><tr><td><code>swap</code></td><td>attribute</td><td>the file, its <code>/proc/swaps</code> entry, its <code>/etc/fstab</code> line; not <code>size</code>, so a resize isn't drift; a drifted swap repairs only the missing parts</td></tr><tr><td><code>database</code></td><td>attribute</td><td>the role, the database, its owner, its <code>pg_hba</code> rules</td></tr><tr><td><code>firewall</code></td><td>attribute</td><td>active, the default policies, each declared allow rule</td></tr><tr><td><code>apt_repo</code></td><td>content</td><td>the key's blake3 against its pin, and the whole list file against the resolved, <code>signed-by</code> source line</td></tr><tr><td><code>service</code></td><td>attribute</td><td>running and enabled (<a>below</a>); config freshness through <a>triggers</a></td></tr><tr><td><code>directory</code></td><td>attribute</td><td>existence; mode, owner, group when declared</td></tr><tr><td><code>user</code></td><td>attribute</td><td>each declared attribute</td></tr><tr><td><code>package</code></td><td>existence</td><td>the manager's query (<a>which forms compare a version</a>)</td></tr><tr><td><code>installer</code></td><td>existence</td><td>the <code>check</code> path; no version or integrity probe</td></tr><tr><td><code>script</code></td><td>yours</td><td>its <code>check</code> command's exit</td></tr><tr><td><code>verify</code></td><td>assertions</td><td>each assertion, at detect time (<a>below</a>)</td></tr><tr><td><code>pipeline</code></td><td>none</td><td>nothing: always <code>absent</code>, so a dry run of a config with one always has a pending change (exit 2), and <code>zap status</code> reads it absent</td></tr></tbody></table><p>Notes on the kinds that need them:</p><ul><li><code>file</code><ul><li>A file that exists but can't be read holds as <code>undetermined</code>. So does an
unreadable <code>stat</code> when any of mode, owner, or group is declared. Neither
reads absent or converged.</li><li>With a mode, owner, or group declared, the path itself must be a regular
file. A symlink there drifts even when what it points at matches, and the
write replaces it.</li><li>The content is compared by SHA-512 digest, so only the digest crosses the
wire. See <a>content is compared by digest</a>.</li><li>One carve-out: an extracted <code>remote</code> file (<code>extract: tar.*</code>) is compared
through its extract sentinel, a <code>.zap_remote_hash</code> file in the tree, and the
extracted tree is not hashed again. The sentinel records a digest of the
tarball pin and the <code>extract</code> form with its <code>strip_components</code>, so a new pin
or strip count re-extracts.</li><li>An extracted tree is read the way the extraction treats it, so a plan never
offers a change the wetrun refuses. Nothing at the path reads <code>absent</code>. A
symlink, or anything but a directory, at the path holds. The sentinel
counts only as a regular file, not a link. A directory without one reads <code>absent</code> when it is empty, and otherwise holds: Zap didn't extract it, and
won't replace it.</li></ul></li><li><code>link</code>: read as the login user. A path that isn't a symlink, or one the login user
can't reach, reads <code>absent</code>, and a regular file there is replaced by the link
on apply; a directory there fails the step. See <a>how detection reads the target</a>.</li><li><code>database</code><ul><li>One <code>psql -X</code> query as the <code>postgres</code> role reads the first three and the <code>hba_file</code> setting. <code>-X</code> means no <code>~/.psqlrc</code> adds to its output.</li><li>Each declared rule is then a <code>grep -qE</code> of that file. No matching line reads
the rule as missing, and a file <code>grep</code> can't read holds.</li><li>The query runs under a <code>timeout</code> of its own (50 seconds), which stops <code>psql</code> itself and not only the shell that started it.</li></ul></li><li><code>firewall</code><ul><li>A rule is matched against the whole rule target in the live ruleset, never a
substring, so <code>allow 80</code> is not satisfied by an <code>8080/tcp</code> line, and a
default-policy flip made out of band drifts.</li><li><strong>ufw</strong>: a rule counts only as the row <code>ufw allow</code> writes, an inbound <code>ALLOW</code> from <code>Anywhere</code>, matched on its parsed <code>To</code> column in <code>ufw status verbose</code> (<code>verbose</code> for the <code>Default:</code> line). A named profile
matches either its bare name or the verbose <code>&lt;ports>/&lt;proto> (&lt;name>)</code> rendering, multi-word names like <code>Nginx Full</code> included. So an out-of-band <code>ufw deny 22/tcp</code>, an outbound allow, or an allow from one address drifts.
The status is read in the <code>C</code> locale so its prose parses the same whatever
the operator's locale. A status with no readable <code>Default:</code> line holds, and
does not read the policies as converged.</li><li><strong>nftables</strong>: the read is <code>nft list table inet filter</code>. A rule counts only
as a whole rule line of the <code>input</code> chain, set aside only what doesn't change what it
admits (a <code>counter</code> and its totals, a <code>comment</code>, a <code># handle</code>). So <code>ip saddr 1.2.3.4 tcp dport 22 accept</code> or <code>iifname "lo" tcp dport 22 accept</code> doesn't satisfy a declared <code>22/tcp</code>. Each base chain's <em>effective</em> policy is read: the <code>policy</code> verb refined by the trailing bare <code>reject</code> rule, so a desired <code>reject</code> is distinguishable from <code>drop</code>. A missing <code>input</code> or <code>output</code> chain
drifts as <code>missing</code>.</li><li>Allow rules are <strong>additive</strong>: each declared rule must be present, but a rule
added out of band is neither detected nor removed.</li></ul></li><li><code>directory</code><ul><li>An unreadable <code>stat</code> holds as <code>undetermined</code> when any of mode, owner, or
group is declared. With none declared, existence is the whole desired state.</li><li>Existence is read as the login user and follows a symlink (<code>test -d</code> semantics), so a directory the login user can't reach reads <code>absent</code>.</li><li>With a mode, owner, or group declared, a symlink to a directory drifts, and
the change fails without touching what it points at.</li><li>The mode, owner, and group are read only when one of them is declared: as
root over SSH, and as the operator locally.</li></ul></li><li><code>user</code><ul><li>With <code>home_mode</code> or <code>ssh_keys</code> declared, the account's <code>/etc/passwd</code> home is
read: a home other than <code>/home/&lt;username></code>, or none, holds the user, since
Zap acts on paths under <code>/home/&lt;username></code> (<a>resources.md</a>).</li><li>With either declared, what is at <code>/home/&lt;username></code> is read with a <code>stat</code> that doesn't follow a link, for an account that doesn't exist yet too:
nothing there, or a directory the user or root owns, reads on (an existing
account's root-owned home is left as it is; the creation of an absent one
gives it to the user). Any other owner, a link, or anything but a directory
holds the user. A <code>/home</code> that is missing, or that the connecting user
can't search, holds the user naming <code>/home</code>, rather than reading as nothing
there.</li><li>SSH <code>authorized_keys</code> and sudoers, compared by content with surrounding
whitespace trimmed. Up to 1 MiB of <code>authorized_keys</code> and 64 KiB of sudoers
are read; past that the file drifts.</li><li>Supplementary group membership (<code>id -nG</code>). It is additive: a desired group
that isn't present drifts.</li><li>An <code>ssh_keys</code> account's <code>/etc/shadow</code> password field is held
authoritatively at the disabled <code>*</code>. Any other value drifts: a <code>!</code> lock, an
empty field, or a hash.</li><li>A probe of a declared attribute that exits nonzero (a <code>stat</code> of a missing
home, with <code>home_mode</code> declared) holds the user: the attribute wasn't read,
so it isn't called converged. An attribute the config doesn't declare isn't
read at all. A key file that can't be read is drift.</li><li>A <code>copy_from</code> source's <code>authorized_keys</code> is found through that user's <code>/etc/passwd</code> home and read as that user, the way apply reads it, so a
source file that user can't read drifts on every plan and fails on every
apply.</li></ul></li><li><code>package</code>: a package held back, or installed for any architecture, is
installed; one half-installed or removed with its configuration left is not.
A query that fails holds the package.</li></ul><p>The shallow rows are deliberate, not unfinished. A <code>package</code> install or an <code>installer</code> re-run is idempotent, so existence detection is enough. <code>script</code> hands the depth to you: make its <code>check</code> precise or it runs on every apply.</p><h3><code>build</code>: exact provenance, not a version string</h3><p>A <code>build</code> is content-addressed by the blake3 of its <strong>source archive</strong>, the
pin: the vendored <code>source.blake3</code>, or else the <code>zap.lock</code> entry. After a
successful build Zap writes a <code>&lt;output>.zap-build</code> sidecar recording its <strong>provenance</strong>: 64 lowercase hex, the blake3 of a fixed tag, a format version,
and the pin with the build's <code>extract</code>, <code>run</code>, <code>cwd</code>, and <code>env</code> as declared.
Detection computes the desired provenance the same way and compares:</p><table><thead><tr><th>What detection finds</th><th>Verdict</th></tr></thead><tbody><tr><td>output or sidecar missing</td><td><code>absent</code></td></tr><tr><td>sidecar differs from the desired provenance</td><td><code>drifted</code>: the upstream moved or the build changed, so rebuild</td></tr><tr><td>sidecar equals the desired provenance</td><td><code>converged</code></td></tr><tr><td>no usable pin (a tracked source with no lock entry, or a stale one)</td><td><code>undetermined</code> in <code>plan</code>, <code>detect</code>, <code>status</code> and a deploy's preflight (which bails, exit 2); <code>apply</code> mints a missing pin and refuses a stale one (exit 2)</td></tr></tbody></table><p>A reference in <code>run</code> or <code>env</code> is part of the provenance as written, not as
resolved: a secret's value never reaches the target, and a new value for a
variable alone does not rebuild.</p><p>This is why a <code>--version</code> check isn't the drift signal. The provenance is exact
and language-independent, so a moved upstream is caught even when the installed
binary still runs. See <a>resources.md</a>.</p><h3><code>verify</code>: assertions at detect time</h3><p>A <code>verify</code> resource runs its assertions during detection. If all pass, it
reports <code>converged</code> and is skipped. If any fail, it becomes a pending change; on
a wetrun its assertions run again at its place in the dependency order, and one
still failing <strong>fails the run there</strong>, so an earlier change in the same run can
satisfy it. A dry run shows it as a pending change and runs nothing. A verify
never executes anything of its own. It is a guard rail, and changes ordered
before it have already run, so order it with <code>depends_on</code> to put the guard where
it belongs.
Because the answer is live state, a verify is checked again on every pass.</p><p>For a gate that should run only after something else applies, use a <code>script</code> with <code>check</code> and <code>run</code>, ordered by <code>depends_on</code>. That keeps <code>depends_on</code> meaning
ordering, not a detection special case.</p><h3>Service probes</h3><p>A service's two probes read what the manager reports, and a probe that fails to
read holds the service: a failed read is no evidence of a stopped or disabled
service, and reading it so would take <code>running: false</code> or <code>enabled: false</code> as
converged.</p><ul><li>systemd: <code>systemctl is-active</code> exiting 0 is running, 3 (inactive or failed)
and 4 (no such unit) not running; <code>systemctl is-enabled</code> exiting 0 is enabled,
and a non-zero exit is not enabled only when it prints <code>disabled</code>, <code>masked</code>, <code>masked-runtime</code>, <code>linked</code>, <code>linked-runtime</code>, or <code>not-found</code>.</li><li>OpenRC: <code>rc-service &lt;svc> status</code> exiting 0 is started, 3 (stopped, or no such
script) and 32 (crashed) not running. 64 (unsupervised: a <code>supervise-daemon</code> service whose supervisor died, its daemon perhaps still running) holds, and
the reason says to check for the daemon and run <code>rc-service &lt;svc> zap</code> by
hand. Enabled is an entry for the service in
any runlevel under <code>/etc/runlevels</code>, as <code>rc-update add &lt;svc> &lt;runlevel></code> makes; a disable removes it from each runlevel it is in.</li></ul><p>Any other exit holds the service as <code>undetermined</code>.</p><h3>Service triggers close the config-freshness gap</h3><p>Service detection checks running and enabled, not whether the service's config
is fresh. The trigger model closes that gap by reacting to changes, not by
deepening detection: a <code>file</code> lists <code>triggers</code> (push), or a <code>service</code> lists <code>restart_on</code> or <code>reload_on</code> (pull). When the referenced resource changes, the
planner promotes the service from skip to a restart or reload.</p><h2>Holding: the <code>undetermined</code> verdict</h2><p>When Zap cannot establish current state, it refuses to guess. The usual causes
are a probe that couldn't be reached, a remote path whose target home wasn't
declared, a path or name whose reference resolves to a value Zap won't use (one
holding a reference delimiter, a path that isn't absolute or spans lines, a <code>database</code> name or host a <code>pg_hba.conf</code> line would misread), and, in <code>plan</code>, <code>detect</code>, <code>status</code> and a deploy's preflight (which bails, exit 2), a tracked pin
with no lock entry or a stale one (<code>apply</code> mints a missing pin and refuses a
stale one, exit 2). The planner holds the
resource and does not propose a create that might clobber live state. The next
pass reads it again: no verdict carries over from one pass to the next.</p><p>A held resource contributes no change, so it simply isn't in the changeset. An
empty plan would hide it, which is why every command that compares reports the
hold as a <strong>verdict</strong>:</p><ul><li><code>plan</code> and <code>apply</code> (dry or wet) show an <code>UNDETERMINED</code> banner naming each
held resource and why, and <code>detect</code> marks each one <code>?</code>. All three exit <strong>1</strong>: "converged" is a claim about the target that was never established
for the resources nobody could read, and for a dry <code>apply</code> 1 outranks 2
("drifted") too.</li><li><code>deploy</code>'s drift preflight bails (exit 2): a gate that couldn't check
everything must not pass by default.</li></ul><p>Exit codes in full: <a>cli.md</a>.</p><h3>A hold spreads to what can't run without it</h3><p>A change that waits on a held resource is held behind it: it could act on
state the held resource was meant to set up. This follows <code>depends_on</code> forward, including the implicit edge from a service to its trigger sources,
and passes through a converged resource unreported, since that resource
changes nothing. A change that would restart or reload a held service is held
too: its change would owe the service the action with nothing to run it, so
the action would never happen. This follows trigger edges in reverse (a
file's <code>triggers</code>, a service's <code>restart_on</code> and <code>reload_on</code>), and never a
plain <code>depends_on</code>: what a held resource depends on still runs. The two rules
repeat until nothing changes, so a source held for its trigger also holds what
waits on it, and a source that is itself a service holds its own sources.</p><p>One exception: a converged service whose only change is the restart or reload a <a>pending marker</a> owes waits only on what it declares, so a
trigger source detection couldn't read doesn't hold it; the owed action runs. A
source that changed and is held behind another still holds the service its
change fires.</p><p>The banner lists the resources detection couldn't read first, then the ones
held behind them, each with what it waits on or would trigger:</p><!><p>Resolving the probe failure releases the whole chain on the next pass.</p><p><code>undetermined</code> is about the observed side. Its twin on the desired side is the <code>unverifiable</code> verdict (<a>env.md</a>), where the declaration is the half
that couldn't be built.</p><h3>Kinds that read a failed probe as absent</h3><p>A few detectors deliberately map a <em>failed probe</em> to <code>absent</code>:</p><ul><li><code>firewall</code>, on both backends;</li><li><code>script</code>, when its <code>check</code> fails, and a <code>verify</code> assertion that fails;</li><li><code>link</code>, <code>directory</code>, and <code>swap</code>, for a path the login user can't reach (and,
for a <code>link</code>, one that isn't a symlink).</li></ul><p>For these, a probe failure almost always means "not set up yet" (the fresh
host, before the same config installs ufw or nftables), and their create steps
are idempotent and identical to their update steps, so a misread probe either
re-asserts the declared state or fails loudly at execution. The one
consequence to know: a regular file sitting where a <code>link</code> is declared reads <code>absent</code> and is replaced by the link (a directory there fails the step instead).</p><p>A <code>file</code> is the opposite case and holds. "Exists but unreadable" <em>proves</em> there
is state a create would clobber, which is the harm the hold exists to prevent.</p><p><code>database</code> splits the two cases:</p><ul><li><strong>No PostgreSQL reads <code>absent</code>.</strong> That means no <code>psql</code>, or no <code>postgres</code> account (a client-only host). Both are checked before the query runs, in the
same root environment the query runs in, so this is a detected fact. Zap's
probes and steps run as <code>postgres</code>, and there is no cluster they could reach,
so the fresh host's first apply creates it. A cluster run under another
account name reads <code>absent</code> too; its create steps then fail loudly under <code>sudo -u postgres</code>.</li><li><strong>A failed query holds.</strong> With both present, a query that fails (the server is
stopped, or <code>postgres</code> can't authenticate) reads nothing about the role, the
database, or its <code>pg_hba</code> rules. Output that isn't the query's one row also
holds, and so does a <code>pg_hba.conf</code> the server names that the <code>postgres</code> account
can't read: the rules are read as that account, never as root.</li></ul><h2>The <code>residual</code> verdict</h2><p>A wetrun closes the loop on the other side too. After executing, <code>apply</code> <strong>re-detects</strong> the target. This is the observe pass, and it becomes the <a>last-run report</a>. Any resource that still
doesn't read converged is reported as the <strong>residual</strong> verdict, exit 1.</p><p>A change can exit 0 without converging its resource: a <code>script</code> whose <code>check</code> still fails after <code>run</code>, or a mutation whose probe reads back differently. So
"applied: N ok" alone is command success, not convergence. The residual banner
is what makes the wetrun's final claim an <em>observed</em> fact. If the re-detection
itself fails (connectivity dropped after execution), the apply reports that and
still exits 1, because "converged" was not established.</p><p>Three cases are exempt, because "not converged" is impossible or already
reported more loudly:</p><ul><li>a <code>pipeline</code>, which detects <code>absent</code> by construction;</li><li>a change that <strong>failed</strong>, or was skipped by stop-on-first-failure, which is
already the run's headline and exit 1;</li><li>a <strong>held</strong> resource, which is already the <code>undetermined</code> verdict.</li></ul><p>A <code>script</code> runs its <code>check</code> twice per wetrun, once detecting and once verifying
convergence. That is the price of its user-defined depth.</p><h2>How detection reads the target</h2><p>Every kind detects through <strong>batched queries</strong>. (A <code>pipeline</code> reads nothing: it
always runs.) A kind declares the reads its verdict needs as typed queries, and
a pure function turns the answers into the verdict. The function sees nothing
but those answers, so a detector can't read anything it didn't declare. The
queries are:</p><ul><li>the type of what a path resolves to;</li><li>a path's own mode and ownership;</li><li>a symlink's target;</li><li>the SHA-512 of a file's bytes;</li><li>the first few bytes of a small file;</li><li>a command Zap owns: a package manager's query, a service manager's probe, an <code>awk</code> match in <code>/proc/swaps</code>, <code>ufw status verbose</code>, a <code>psql</code> query;</li><li>an operator's command: a <code>script</code>'s <code>check</code>, each of a <code>verify</code>'s assertions,
a <code>package</code>'s <code>check</code> that is a command.</li></ul><p>The pending-trigger markers
(<a>resources.md</a>) are read the same way, as one
more query of the plan's pass.</p><p>Every batched query is known before anything is read from the target: from the
config, <code>zap.lock</code>, and the operator's content cache. (An uncached <code>remote</code> file's
bytes are read after the batch; see below.) The two reads that depend on another
read's answer compose in the target shell, inside one command: a <code>database</code>'s <code>pg_hba</code> <code>grep</code>s run against the <code>hba_file</code> its catalog query just reported, and
a <code>copy_from</code> user's source <code>authorized_keys</code> is read from the home its <code>/etc/passwd</code> entry names.</p><h3>Privilege</h3><p>Every query names the privilege its read runs under. It is the privilege the
equivalent single-command probe would have, so a kind sees the same thing
whether it is read alone or in a batch.</p><ul><li><strong>login</strong>: as the connecting user, unprivileged, on every connection. Read
this way:<ul><li>a <code>directory</code>'s existence and a <code>link</code>'s target;</li><li>a package manager's query and a service manager's two probes;</li><li>the <code>swap</code> file's <code>test -f</code> and its <code>/proc/swaps</code> and <code>/etc/fstab</code> matches;</li><li>an <code>apt_repo</code>'s source line, resolved against <code>/etc/os-release</code>;</li><li>a <code>user</code>'s <code>id -u</code>, <code>/etc/passwd</code> shell and home, what is at its home and
who owns it, the home-directory mode, and <code>id -nG</code>;</li><li>a <code>verify</code>'s assertions: a <code>path_exists</code> chain of <code>test</code> and <code>stat</code> (Zap's
own command; one under a directory the connecting user can't search fails)
and a <code>command</code>'s <code>run</code>;</li><li>the other operator's commands: a <code>script</code>'s <code>check</code> and a <code>package</code>'s
command <code>check</code>;</li><li>the pending-marker read.</li></ul></li><li><strong>root</strong>: as root on every connection. It is the privilege of a probe that
carries its own <code>sudo</code>, written without it. A local target runs these through <code>sudo</code>. Read this way:<ul><li>a <code>firewall</code>'s status (<code>ufw status verbose</code>, <code>nft list table inet filter</code>);</li><li>a <code>database</code>'s catalog query and <code>pg_hba</code> greps, each run as the <code>postgres</code> account through <code>sudo -u postgres</code> from root;</li><li>a <code>user</code>'s <code>/etc/shadow</code> password field and sudoers <code>test -f</code>;</li><li>a <code>copy_from</code> source's <code>authorized_keys</code>, read as the source account
through <code>sudo -u</code> from root;</li><li>a <code>user</code>'s own <code>authorized_keys</code>, read as that user through <code>sudo -u</code> from
root, the account the file belongs to and is written as. A symbolic link or
anything but a regular file there is not read; it drifts, and apply writes
the file in its place.</li></ul></li><li><strong>elevated</strong>: as root over SSH, where the login user isn't assumed to own what
Zap manages. On a local target the read is tried as the operator first,
directly. A read that fails any way other than the path not being there (a
root-only parent, a file only root can read) is asked again as root, through <code>sudo</code>, in one batch for all of them. A local config that touches only the
operator's own files never invokes <code>sudo</code>. Read this way:<ul><li>every read of a <code>file</code>: its existence, content, and mode, owner, and group;</li><li>a <code>directory</code>'s managed mode, owner, and group;</li><li>a <code>package</code>'s or an <code>installer</code>'s <code>check</code> path;</li><li>an <code>apt_repo</code>'s key and sources list;</li><li>a <code>build</code>'s output and provenance sidecar;</li><li>a <code>user</code>'s sudoers contents.</li></ul></li></ul><p>Because a <code>file</code>'s content is compared by digest and not read as text, a file
whose bytes aren't valid UTF-8 reads like any other. It doesn't send a local
read to <code>sudo</code>.</p><p>A content read (a digest, or a bounded read of a sentinel or sudoers file) opens
only a regular file of its own. A symbolic link at the path, dangling or not, is
not followed, and a directory, a device, or a fifo is not opened: at root's
privilege, opening a device can act on the machine, and a fifo holds the read
until its timeout. The read reports the path as not a regular file instead, and
each resource says what that means: a <code>file</code> whose path is a symbolic link to a
regular file drifts, since its write replaces the link with the file; anything
else there that isn't a regular file holds it. A regular file with more than one
hard link, its link count read from the descriptor, is read by no content read
and holds the resource, saying to replace it with a copy of its own (a single
link): a hard link is the file under another name, which could make a root read
of the declared path read a file someone else linked there. A name swapped
between the check and the open is opened as it then is, under the read's
timeout.</p><h3>Content is compared by digest</h3><p>A <code>file</code>'s content is never shipped back to compare. The target runs <code>sha512sum</code> over the file and only the digest crosses the wire, however large the file. What
the digest is compared against depends on the content:</p><ul><li><strong><code>inline</code> and <code>template</code></strong>: the SHA-512 of the rendered content. Inline
content and a template's body are compared as declared; a template's <code>vars</code> have their references resolved from the operator's environment.</li><li><strong><code>source</code></strong>: the digest of the source path, read in the same batch as the
target's. A source that can't be read, or that is not a regular file of its
own (a symbolic link included), holds the resource.</li><li><strong><code>remote</code>, <code>extract: none</code></strong>: the SHA-512 of the pinned bytes, taken from
Zap's content cache (<code>~/.zap/cache/files/&lt;blake3>/&lt;name></code>, where fetching them
put them), after checking that those bytes still hash to the pin.<ul><li>The pin is the declared <code>blake3</code>, or else the <code>zap.lock</code> entry. With
neither, or with a stale lock entry, the file holds in <code>plan</code>, <code>detect</code>, <code>status</code> and a deploy's preflight (which bails, exit 2); <code>apply</code> mints a
missing pin and refuses a stale one (exit 2).</li><li>When the content cache doesn't hold the pinned bytes (a fresh <code>ZAP_HOME</code>,
another machine), Zap reads the target's bytes directly, after the batch,
and compares their blake3 to the pin. Only a regular file of its own is
read: a symbolic link or anything else at the path holds the resource. When they match, it stores them in the
content cache, so the next pass compares digests.</li><li>Detection never fetches the url.</li></ul></li><li><strong><code>remote</code>, <code>extract: tar.*</code></strong>: the extract sentinel's first 4 KiB, compared,
with surrounding whitespace trimmed, to the desired provenance (the digest of
the pin and the <code>extract</code> form). A sentinel longer than that
drifts.</li></ul><p>A drifted <code>remote</code> file reports what it observed: the target's blake3 when its
bytes were read, or its SHA-512 when only the digest was. The message is <code>remote content differs from its pin (observed sha512 …)</code>, and <code>--diff</code> shows it
as a replacement of the content pin, not as a pin of its own.</p><h3>Batches</h3><p>Over SSH, all of a pass's login reads run as <strong>one shell script</strong> in one
command, and all of its root and elevated reads as a second, under <code>sudo</code>: the
login and root <strong>lanes</strong>. The two run concurrently. A detection pass costs one
round trip per lane, however many batched resources the config declares. A
target missing a tool a lane's batch needs, or the <code>/proc/self/fd</code> its content
reads check what they opened through, fails that whole lane.</p><p><strong>Connectivity.</strong> The batches are also the pass's connectivity check. An <code>ssh</code> that can't reach the target (it exits 255, or can't start) fails the command
with a <code>cannot connect</code> error before any verdict is printed. The error carries <code>ssh</code>'s own message, with a hint when the host key changed. A pass with nothing
to batch checks connectivity with an <code>ssh true</code> of its own.</p><p><strong>One authentication.</strong> A pass authenticates once. When no connection to the
target is already open for Zap to share (its <code>ControlMaster</code>), the login batch
waits for the root batch to be under way and shares the connection it opened,
so no second one is opened.</p><p><strong>What adds a round.</strong> Two things:</p><ul><li>an unextracted <code>remote</code> file whose pinned bytes aren't in the content cache.
Its bytes are read with a command of their own, after the batch. See <a>content is compared by digest</a>.</li><li>on a local target, the elevated reads the operator was denied. A local target
answers login and elevated path reads natively, without a shell, and asks the
denied elevated ones again as root in one <code>sudo</code> batch after that. Its login
command reads run as one local batch, as the operator, and its root reads run
in the root batch.</li></ul><p><strong>Local <code>sudo</code>.</strong> A local root batch runs under <code>sudo -n</code>, after Zap has made
sure <code>sudo</code> won't prompt; operator commands run with no terminal, locally as
over SSH (<a>targets.md</a>). If <code>sudo</code> won't authenticate,
every resource with a read in that batch holds, with the fixed reason <code>sudo authentication failed</code>.</p><p><strong>The script travels on stdin</strong>, never the argv, and each probe's output comes
back framed, so bytes a probe prints (newlines and NULs included) can't be
mistaken for another probe's answer, and nothing a probe prints reaches the
stderr Zap shows when <code>ssh</code> itself fails. A probe's exit status travels apart
from its output, so nothing the probe writes can forge it; a command runs in a
session and process group of its own, so a command that signals its group
reaches only itself. The target's <code>sudo</code> log records one constant wrapper per
lane (<a>security.md</a>).</p><p><strong>Locale.</strong> Zap's own probes run under <code>LC_ALL=C</code>, so what they print parses the
same on every target. An operator's command runs in the target's own locale, as
it would by hand.</p><p><strong>Operator commands</strong> (a <code>script</code>'s <code>check</code> with its references resolved, its <code>cwd</code> and <code>env</code>) travel inside the script too, so a resolved value is on no
argv. The check's exit decides: 0 is applied, anything else (a <code>cwd</code> that can't
be entered and a check that doesn't parse included) is <code>absent</code>. The script
holds only when the check produced no exit status (a timeout, a failed lane) or
a reference can't be carried.</p><p><strong>What the target needs.</strong> <code>timeout</code>, <code>od</code>, <code>tr</code>, <code>head</code>, <code>cat</code>, <code>stat</code>, and <code>readlink</code>; <code>sha512sum</code> when the batch reads a digest; <code>ls</code> when it reads
whether an extracted tree is empty; and <code>setsid</code> and <code>sleep</code> when it runs a
command. Over SSH, <code>setsid</code> is needed in any case. These come
from GNU coreutils and util-linux, or BusyBox (validated on 1.37). A target missing
one fails the batch, and does not read every path as absent. Writes need a few
more (<a>targets.md</a>); a write that lacks one
refuses, naming it, with nothing changed.</p><p><strong>Output limit.</strong> Zap reads at most 64 MiB of a batch's output. Past that it
stops the batch and holds every resource in it.</p><p><strong>Local content reads.</strong> A local target answers content reads natively too,
except of something that is neither a regular file nor a directory (a fifo, a
device), which its probe answers under its timeout.</p><h3>What a read can conclude</h3><p><strong>Commands answer with their exit status.</strong></p><ul><li>An operator's command: a <code>script</code>'s or <code>package</code>'s <code>check</code> exiting 0 is
applied or installed, and anything else is not. A <code>verify</code> assertion holds
when its command exits 0 and, with an <code>expect</code>, its stdout contains it.</li><li>A command Zap owns: the package manager's query and the service manager's
probes exit 0 if and only if the state holds; <code>test -f</code>, the swap's <code>awk</code> match, and a <code>pg_hba</code> <code>grep</code> exit 0 if and only if the file or line is there. The package manager's query answers "not
installed" with exit 1 alone: any other status is a query that failed
(<code>dpkg-query</code> unable to read its database, or missing), and the package holds.</li></ul><p>Some commands also print what they read (a firewall's ruleset, a user's shell or
groups, a database's catalog row), which the verdict parses. A failure means
what it meant to that probe: a firewall probe that fails needs setting up, and a <code>user</code> attribute probe that fails holds the user.</p><p>Otherwise, what holds is an answer that is missing (a timeout, a garbled record,
a failed batch) or output that doesn't parse. A <code>database</code> also holds when its
catalog query failed with PostgreSQL installed, or when its <code>pg_hba.conf</code> couldn't be read.</p><p><strong>A path read concludes "nothing there" from one failure only.</strong> That is the
failure <code>stat</code> and <code>readlink</code> report for it (their exit status 1), and the
content reads, which open the path with a redirect that exits 1 when it can't be
opened. It means the path is absent, can't be reached at the read's privilege,
or, for a symlink's target, isn't a symlink. For a content read, it means the
path can't be read (a directory); for an extracted tree's emptiness read, that
it isn't a directory the read's privilege can list. A <code>file</code> that exists but whose content read
finds nothing holds, and does not read absent.</p><p>Anything else holds the resource as <code>undetermined</code> and does not guess:</p><ul><li>a probe that failed another way (it couldn't run, or was killed);</li><li>output that doesn't parse (an owner or group name containing whitespace);</li><li>a missing or garbled answer.</li></ul><p>A resource needs only the answers its verdict reads: the mode of a directory
that doesn't exist is never consulted. But a batch that failed as a whole holds
every resource with a read in it, with a fixed reason that quotes none of the
batch's output. That covers a dropped connection, a refused <code>sudo</code>, output that
stopped before its end marker, and a missing tool. So does a pass whose answers
don't line up with its reads one for one (a layout mismatch): no answer in it is
read, and the reason names the read left without one. None of these ever reads
as <code>absent</code>.</p><h3>Timeouts</h3><p>Each probe runs under <code>timeout</code> and reads <code>undetermined</code> ("timed out after 10s")
when it runs out:</p><table><thead><tr><th>Read</th><th>Limit</th><th>Why</th></tr></thead><tbody><tr><td>Zap's own path reads</td><td>10 seconds</td><td>a healthy <code>stat</code> takes milliseconds; a slow one is a hung mount</td></tr><tr><td>the mode and ownership read</td><td>30 seconds</td><td>it resolves owner and group names, which may go through a network name service</td></tr><tr><td>a digest</td><td>60 seconds</td><td>it reads the whole file</td></tr><tr><td>a command, Zap's own or an operator's</td><td>60 seconds</td><td>it may do real work</td></tr><tr><td>a database's catalog query, inside its command's limit</td><td>50 seconds</td><td>its own <code>timeout</code> stops <code>psql</code>, and leaves the <code>pg_hba</code> greps room</td></tr></tbody></table><p>Zap's own commands are a package manager's query, a service manager's probe, a
firewall's status, and a database's catalog query with its <code>pg_hba</code> greps.</p><p>A command's timeout stops its whole process group, children included, with <code>SIGTERM</code> and then <code>SIGKILL</code> a second later. A command that exits 124 or 143 on
its own reads as that exit; what reads as timed out is a command with no
report. Because something can outlive a probe's timeout (a process that left
the command's group, or one a command backgrounds), each batch also runs under a
deadline, the sum of its probes' limits plus a margin. When that passes, Zap
stops the batch, kills what it can of it on the target, and holds every resource
with a read in it, so a stuck probe costs at most the deadline.</p><h2>Nothing is cached</h2><p>Every pass reads every resource. A stored answer is sound only when nothing
outside Zap could have changed the target since it was read, and Zap never
assumes that; and a pass costs one round trip per lane however many
resources the config declares, so a stored answer would save nothing.</p><p>That matters most for the controls people change by hand: <a>security.md</a>.</p><p>The <strong>pending-trigger markers</strong> (<code>/var/lib/zap/pending/</code>) follow the same rule:
they are read on every plan for a config that declares a trigger, in the same
batch as the plan's detection reads
(<a>resources.md</a>).</p><p>The caches Zap does keep are on the operator machine and never stand in for the
target: the config eval cache, whose manifest is validated again on every
lookup, and the content cache, whose bytes are checked against their blake3 on
every read (<a>lock.md</a>).</p><h2>The last-run report</h2><p>Every detection pass records what it read in a <strong>last-run report</strong>, and <a><code>zap status</code></a> renders it offline. The passes that write it:</p><ul><li><code>detect</code> and <code>plan</code>;</li><li><code>apply</code>: a dry run's pass; a wetrun's pass before its changes, then its
re-detection after them, which is the last word; and a refused wetrun's pass,
recorded as the preview it was;</li><li><code>deploy</code>'s drift preflight.</li></ul><p>Detection never reads it. The wetrun's review gate reads only which pass wrote
it and its <code>plan_hash</code>.</p><p>The report is latest-only, one file per config and host, under <code>~/.zap</code> (<a>lock.md</a>). It holds:</p><ul><li>when the pass ran (RFC 3339, UTC), which command pass it was, and the host
(<code>local</code>, or the resolved remote host);</li><li>the names of any references the pass's comparison couldn't resolve,
names only. This is the pass's <a><code>unverifiable</code></a> finding.</li><li>per resource read: its verdict (<code>converged</code>, <code>drifted</code>, <code>absent</code>, or <code>undetermined</code>), its hash, and whether it references a secret. It never holds
the observed state, an <code>undetermined</code> reason, or anything else the target
returned.</li><li>the pass's <a>batches</a>: each one's lane and query count;</li><li>the <code>plan_hash</code> of the plan the pass computed, when it planned (<code>detect</code> doesn't). For a pass that <strong>previewed</strong> that plan (<code>zap plan</code>, a dry <code>zap apply</code>, a refused wetrun), this is the reviewed plan the next <code>zap apply --wetrun</code> binds to
(<a>concepts.md</a>).</li></ul><h3>What a resource's hash covers</h3><p>A resource's hash covers its declaration as written, less its identity (<code>id</code>, <code>name</code>, <code>depends_on</code>) and a fetch credential; the value of each reference in a
field that takes one; and the pin <code>zap.lock</code> holds for it. A reference resolves
in one of two ways:</p><ul><li>a secret one (<a>env.md</a>) resolves to a fixed <code>[MASKED:NAME]</code> token, so a <code>DATABASE_URL</code> holding a password hashes as its
own token;</li><li>any other resolves to its value, with every registered secret in that value
masked.</li></ul><p>So a changed value of an ordinary variable, wherever the resource takes a
reference (a <code>script</code>'s <code>check</code>, a path, a template var), reads as a changed
config. A <code>verify</code> command is hashed as written.</p><p>What the hash excludes is the value of every <em>registered</em> secret, whether
referenced by name or carried inside another variable. So the report can't be
used to test a guess at one, and a changed secret value can't be seen offline.
There is one exception to the first: a short secret that also happens to occur
inside a known non-secret value, where whether the masker masked that value
depends on the secret.</p><p>A value the masker doesn't know as a secret is hashed as it is. That means an
unregistered name, or text written literally into the config, which the secret
gate rejects when it can.</p><p>The host a report is filed under is always a resolved value: a host that
resolves through a masked reference keeps no report, every pass says so
(<code>UNRECORDED</code>), and <code>zap status</code> reports that none is kept and exits 1. The
report also records a <strong>target hash</strong> over the whole <code>zap.target(...)</code> (host,
users, port, key path, home, package and service manager), its references
resolved the way a resource's are, since every verdict was read against it. A
file that isn't a report of the current format version reads as no last run.</p>`,1);function h(o,h){l(h,!0);let g=d(`detection`);c(`16o797k`,e=>{t(()=>{ee.title=`Detection — zap`})}),f(o,{get tome(){return g},children:(t,ee)=>{m(t,{children:(t,ee)=>{var o=ie(),c=te(o),re=e(r(c));i(),a(c);var l=e(c),d=e(r(l),5);i(),a(l);var f=e(l),m=e(r(f),3);s(m,`href`,`#the-residual-verdict`),i(),a(f);var h=e(f);s(h,`id`,`the-governing-principle`);var g=e(h,4);s(g,`id`,`per-resource-depth`);var _=e(g),v=e(r(_)),y=e(r(v),2),b=e(r(y),2),ae=e(r(b));s(ae,`href`,`#build-exact-provenance-not-a-version-string`),i(),a(b),a(y);var x=e(y,5),oe=e(r(x),2),se=e(r(oe));s(se,`href`,`#service-probes`);var ce=e(se,2);s(ce,`href`,`#service-triggers-close-the-config-freshness-gap`),a(oe),a(x);var S=e(x,3),le=e(r(S),2),ue=e(r(le));i(),a(le),a(S);var de=e(S,3),fe=e(r(de),2),pe=e(r(fe));s(pe,`href`,`#verify-assertions-at-detect-time`),i(),a(fe),a(de),i(),a(v),a(_);var C=e(_,2),w=r(C),me=e(r(w)),he=e(r(me),2),ge=e(r(he));s(ge,`href`,`#content-is-compared-by-digest`),i(),a(he),i(2),a(me),a(w);var T=e(w),_e=e(r(T),4);s(_e,`href`,`#how-detection-reads-the-target`),i(),a(T);var ve=e(T,4),ye=e(r(ve)),be=r(ye),xe=e(r(be),11);i(),a(be),i(6),a(ye),a(ve),i(),a(C);var Se=e(C,2);s(Se,`id`,`build-exact-provenance-not-a-version-string`);var E=e(Se,4),Ce=e(r(E),3);i(),a(E);var D=e(E);s(D,`id`,`verify-assertions-at-detect-time`);var O=e(D,3);s(O,`id`,`service-probes`);var k=e(O,4);s(k,`id`,`service-triggers-close-the-config-freshness-gap`);var A=e(k,2);s(A,`id`,`holding-the-undetermined-verdict`);var j=e(A,4),we=e(r(j));i(),a(j);var M=e(j);s(M,`id`,`a-hold-spreads-to-what-cant-run-without-it`);var N=e(M,2),Te=e(r(N));i(),a(N);var P=e(N,2);p(P,{lang:null,content:`  UNDETERMINED — 1 resource(s) could not be probed, so no change is planned for them and this changeset is partial:
      web — detection failed: the unit read exited 1
  their live state is unknown: neither converged nor drifted. resolve the probe failure and re-run.
  held behind them — 2 resource(s) can't change until they do:
      after — waits on \`web\`, which is held
      site — would reload \`web\`, which is held`});var F=e(P,2),Ee=e(r(F),4);i(),a(F);var I=e(F);s(I,`id`,`kinds-that-read-a-failed-probe-as-absent`);var L=e(I,7);s(L,`id`,`the-residual-verdict`);var R=e(L),De=e(r(R),5);s(De,`href`,`#the-last-run-report`),i(3),a(R);var z=e(R,5);s(z,`id`,`how-detection-reads-the-target`);var B=e(z,3),Oe=e(r(B));i(),a(B);var ke=e(B,2);s(ke,`id`,`privilege`);var Ae=e(ke,5);s(Ae,`id`,`content-is-compared-by-digest`);var je=e(Ae,4);s(je,`id`,`batches`);var V=e(je,5),Me=r(V),Ne=e(r(Me),3);s(Ne,`href`,`#content-is-compared-by-digest`),i(),a(Me),i(),a(V);var H=e(V),Pe=e(r(H),6);i(5),a(H);var U=e(H),Fe=e(r(U),6);i(),a(U);var W=e(U,3),Ie=e(r(W),26);i(),a(W);var Le=e(W,3);s(Le,`id`,`what-a-read-can-conclude`);var Re=e(Le,9);s(Re,`id`,`timeouts`);var ze=e(Re,5);s(ze,`id`,`nothing-is-cached`);var G=e(ze,2),Be=e(r(G));i(),a(G);var K=e(G),Ve=e(r(K),5);i(),a(K);var q=e(K),He=e(r(q));i(),a(q);var Ue=e(q);s(Ue,`id`,`the-last-run-report`);var J=e(Ue),We=e(r(J),3);i(),a(J);var Y=e(J,3),Ge=e(r(Y),3);i(),a(Y);var X=e(Y),Z=e(r(X)),Ke=e(r(Z));i(),a(Z);var Q=e(Z,2),qe=e(r(Q));s(qe,`href`,`#batches`),i(),a(Q);var $=e(Q),Je=e(r($),13);i(),a($),a(X);var Ye=e(X);s(Ye,`id`,`what-a-resources-hash-covers`);var Xe=e(Ye,2),Ze=r(Xe),Qe=e(r(Ze));i(5),a(Ze),i(),a(Xe),i(4),n((e,t,ee,n,r,te,i,a,o,ne,c,l,u,f,p,m,ie,h,g,_)=>{s(re,`href`,e),s(d,`href`,t),s(ue,`href`,ee),s(xe,`href`,n),s(Ce,`href`,r),s(we,`href`,te),s(Te,`href`,i),s(Ee,`href`,a),s(Oe,`href`,o),s(Pe,`href`,ne),s(Fe,`href`,c),s(Ie,`href`,l),s(Be,`href`,u),s(Ve,`href`,f),s(He,`href`,p),s(We,`href`,m),s(Ge,`href`,ie),s(Ke,`href`,h),s(Je,`href`,g),s(Qe,`href`,_)},[()=>u(`docs/concepts#detection`),()=>u(`docs/concepts#detection`),()=>u(`docs/resources#package-names`),()=>u(`docs/resources#user`),()=>u(`docs/resources#build`),()=>u(`docs/cli#exit-codes-all-commands`),()=>u(`docs/concepts#triggers`),()=>u(`docs/env`),()=>u(`docs/resources#pending-triggers`),()=>u(`docs/targets#local-sudo`),()=>u(`docs/security#authority-on-the-host`),()=>u(`docs/targets#what-the-target-needs`),()=>u(`docs/security#security-controls-are-read-live-every-time`),()=>u(`docs/resources#pending-triggers`),()=>u(`docs/lock#on-disk-state`),()=>u(`docs/cli#zap-status`),()=>u(`docs/lock#on-disk-state`),()=>u(`docs/env`),()=>u(`docs/concepts#a-wetrun-executes-only-the-plan-you-reviewed`),()=>u(`docs/env#secrets`)]),ne(t,o)},$$slots:{default:!0}})},$$slots:{default:!0}}),re()}export{h as t};