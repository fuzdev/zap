import{G as e,Q as t,W as n,X as r,Y as i,at as a,dt as o,j as s,k as c,l,m as u,ot as d,q as f,ut as p}from"./BTZoVLbz.js";import{t as m}from"./Cyt8LZpN.js";import{n as h}from"./DhdQKFKC.js";import"./BPVwp-J3.js";import{t as g}from"./B2l94Waq.js";import{t as _}from"./D23yn-ZR.js";var ee=s(`<p>What Zap trusts, what it refuses to trust, and where the walls are.</p><h2>The threat model in one paragraph</h2><p>The operator is trusted: whoever runs <code>zap apply --wetrun</code> already holds SSH and <code>sudo</code> on the target, and could do anything by hand. Zap's job is to make what
that person (or the assistant working for them) does <strong>reviewable, bounded, and
observable</strong>: a config can't act on its own, nothing Zap does to the target
goes unshown except the checks a config declares (they run as written on every
pass, <a>before any review</a>, and Zap can't make
them read-only), a read that fails never passes as "fine", and secrets don't
leak into the places people and agents read. Zap is not a sandbox for hostile
configs you didn't write; see <a>the config is first-party</a>.</p><h2>The config can only describe</h2><p>What this means for writing a config is in <a>configs.md</a>. The walls themselves: <code>zap.ts</code> runs in <code>fgro eval</code>, Gro's runtime, a separate binary Zap runs once per evaluation. Its
walls are its own, set up before any of the config's code, or V8 itself, runs:</p><ul><li><strong>a kernel box</strong>: Landlock admits reads only under the config's project and
the packages linked into its <code>node_modules</code>, and seccomp narrows the system
calls. No write anywhere, no network socket, no exec, no read outside those
directories (<code>/proc</code> and <code>/dev</code> included; metadata such as whether a path
exists stays visible), and no signal to another process. There is no
setting that weakens it, and on a host that can't hold it (Linux below
Landlock ABI 6, an architecture its filters aren't built for) the evaluation
fails rather than run without it;</li><li><strong>no environment</strong>: the evaluator starts with <code>TZ=UTC</code> and nothing else of
yours, reads no variable for its own settings, and gives the config no <code>process</code> and no environment API. A variable in your shell can't
loosen the sandbox or reach the declaration except through <code>zap.env()</code>, which
is a reference resolved later by Zap, never a value;</li><li><strong>only static imports</strong>: every <code>import()</code> is refused, and a <code>node:</code> built-in
doesn't resolve. Resolution is strict ESM: a relative import names its
extension, and a bare import resolves through the <code>node_modules</code> of the
project and the <code>exports</code> of the package found there (never its <code>main</code>),
under the conditions <code>gro</code>, <code>import</code> and <code>default</code>;</li><li><strong>no clock, no randomness, no timers</strong>: reading the clock, a random source, or
a fact of the machine throws, and there are no timers; the time zone is UTC
and the locale <code>en-US</code> (<a>configs.md</a> lists what is
refused);</li><li><strong>jitless</strong>: V8 runs in its interpreter, so <code>WebAssembly</code> is absent;</li><li><strong>no code from strings</strong>: <code>eval</code> and <code>new Function</code> throw;</li><li><strong>bounds</strong>: a capped heap and process memory, a 30 second timeout, and a cap
on the JSON it may emit.</li></ul><p>The config's only output is a JSON declaration that Zap validates against a
strict schema. It cannot run commands, write files, or call back into the
engine.</p><p><strong>The config needs a project.</strong> The project is the nearest directory at or above
the config whose <code>package.json</code> holds more than <code>"type"</code> and <code>"sideEffects"</code> (a <code></code> marker in a subdirectory is passed over), outside any <code>node_modules</code>, looking only through directories you own that no other user can
write. Zap finds it before the evaluator runs and refuses, exit 2, when:</p><ul><li>the config file or its directory is writable by every user (for a config
reached through a link, the mode of the file it leads to);</li><li>a <code>package.json</code> on the way up can't be read or isn't valid: not a JSON
object, a <code>"name"</code> or <code>"type"</code> that isn't a string, a FIFO, socket or device
(refused unopened), a link to nothing, or a path through something that isn't
a directory;</li><li>the walk stops below a directory another user owns (the evaluator's own walk
would go past it) or every user can write, or reaches <code>/</code>, with no project <code>package.json</code> found. The refusal names where it stopped and why.</li></ul><p>The evaluator then finds the project itself and must report the same one, or
nothing it wrote is used. Its box admits the project and the packages its <code>node_modules</code> links in from outside it; a package reached through a directory
every user can write isn't read. A package that isn't installed in the project
doesn't resolve: the search for a bare import stops at the project's <code>package.json</code>, so a <code>node_modules</code> above the project is never searched. npm and
yarn workspaces aren't supported: a workspace member with its own <code>package.json</code> is its own project, and the workspace's <code>node_modules</code> above it
isn't searched.</p><p>"You own" means the user Zap runs as. Run as root, that is root, and under <code>sudo</code> also the user who ran <code>sudo</code> (<code>SUDO_UID</code>), so <code>sudo zap apply</code> on a
config in your own project walks your directories as it would without <code>sudo</code>.</p><p><strong>The evaluator never runs as root.</strong> Run as root, Zap runs it as the user who
ran <code>sudo</code> when that user owns the project, and otherwise as the project's
owner; a project root owns is refused, exit 2, since no user who could already
edit the config is there to run it as. A project that is the evaluating user's
home directory, or holds it, is refused too: the box would admit all of it. The
user it runs as must be able to search every directory down to the project, and
is never dropped into group 0: a drop whose group would be root's is refused.
Dropped to the user who ran <code>sudo</code> (who owns the project), its group is <code>SUDO_GID</code> (the group you ran <code>sudo</code> with; unset or not a number is refused);
otherwise, dropped to the project's owner, that owner's primary group. A drop
keeps no supplementary groups. Its home, and the primary group, come from the
passwd database; a static (musl) <code>zap</code> reads only <code>/etc/passwd</code> and <code>nscd</code>, so a user
known only through LDAP, sssd, or systemd-homed can have no entry there, and the
evaluation is then refused.</p><p><strong>The evaluator is pinned.</strong> Zap runs the <code>fgro</code> binary <code>--fgro</code> or <code>ZAP_FGRO</code> names, by absolute path, never one found on <code>PATH</code>, and only when its blake3 is
the toolchain pin in the config's <code>zap.lock</code>; <code>zap lock</code> is the one command that
records the pin rather than checking it (<a>lock.md</a>).
The binary is opened once and run through the descriptor that was checked, so
a binary replaced at its path afterward isn't what runs. Its blake3 is read
through that descriptor, or, once the file has settled, from the pin cache
(<code>~/.zap/cache/fgro_pins/</code>, private to the user Zap runs as): an entry there
names the blake3 of a file by its device, inode, size, and modification and
change times, and a file whose metadata matches an entry isn't hashed again.
A write moves the change time, but only to the filesystem's timestamp
granularity, so an entry is written only for a file whose times are a couple of
seconds old, and a clock set back across that margin, or a network filesystem
whose server's clock lags, defeats it. A write to the file itself between the
check and the exec, by anyone who can write it, is caught only on a best-effort
basis. A link at the binary's own name, a wrapper
script, or a set-ID binary is refused.</p><p><strong>Reads are the project's.</strong> A config reads nothing but the modules it imports,
from its project and the packages the project links. What stays the operator's:
the files in the project and the linked packages are trusted as they are, a
package installed as a directory included. The ownership walk doesn't read ACLs,
and the evaluator reads the disk again after Zap's walk: a project that changed
in between is caught by its report, not prevented. With <code>ZAP_EVAL_CACHE=skip</code>, a
cache hit is served without running the evaluator, so the project walk and the
evaluator's report aren't checked on a hit; the <code>fgro</code> binary is still held to
its pin (<a>cli.md</a>).</p><h3>The config is first-party</h3><p>Zap assumes the config and everything it imports are yours. If you ever evaluate
a config you don't trust, the plan it emits is the attack surface: review it as
you would a shell script, because its <code>script</code> resources are shell. A config
can't pull code from the network or import dynamically, and its imports stay
inside its project and the packages it links, so it can't take a project or a
package from a directory every user can write. A linked package is otherwise
trusted wherever it lives and whoever owns it.</p><h2>What the gates reject before anything runs</h2><p>Every command that reads a config, including <code>config validate</code>, runs two machine-free gates on the
declaration:</p><ul><li><strong>the secret gate</strong>: a secret written literally into the config is rejected
when Zap can tell (the same value is both referenced and
resolvable in the current environment);</li><li><strong>the structural gate</strong>: a malformed or contradictory declaration, such as a
NUL byte in a string a shell would see, a duplicate id, or a dangling or
cyclic dependency. The full list is in <a>configs.md</a>.</li></ul><p>A wetrun adds an env gate: any referenced variable that is unset or empty fails
the run before any side effect, so an empty secret never gets written into a <code>.env</code> file.</p><h2>Zap changes nothing without a wetrun</h2><p>No command changes the target unless you pass <code>--wetrun</code>, and no flag approves a
plan for you. A dry run connects, reads, and renders. Reading runs Zap's own
read-only probes and the commands the config declares as checks (a <code>script</code>'s <code>check</code>, a <code>verify</code>'s assertions, a package's command <code>check</code>, an apt <code>source</code> line's expansion), <a>before any review</a>. Zap
runs them as written: a check that writes, writes. Its only other network
traffic is fetching a missing content pin into the cache on your machine. This
holds with no terminal, in CI, and in an agent loop. <code>zap lock</code> and <code>zap update</code> write <code>zap.lock</code> on your machine, which is their job.</p><h2>A wetrun executes only the plan you reviewed</h2><p>A wetrun's fresh plan must match a reviewed one hash for hash, or it refuses
before any side effect; on an interactive terminal it asks you to type the start
of the hash instead, a question nothing typed earlier can answer. The rule, and
what <code>plan_hash</code> binds (the host, the connecting user, a local <code>HOME</code>, every
plain reference's value), is in <a>concepts.md</a>; <code>zap deploy</code> binds its own plan the same way
(<a>deploy.md</a>). So an agent given <code>--expect-plan</code> with the hash you approved, or a pipeline given the hash approved
in a pull request, can execute only that plan. A plan whose host, connecting
user, or deploy health domain resolves through a masked reference gets no hash,
and its wetrun is an error (<a>env.md</a>).</p><p>The host a hash binds is the name the config resolves it to, not where <code>ssh</code> takes that name: an <code>ssh</code> config whose <code>HostName</code>, <code>User</code>, or <code>Port</code> for it
changes between the review and the wetrun sends the reviewed plan to the machine
it now names, if that machine's key is a known one. What <code>ssh -G</code> prints is
configuration, not the machine, so the hash doesn't bind it; the machine itself
is held by host-key checking. Binding the machine to a plan would take its host
key's fingerprint, which the hash doesn't hold.</p><h3>What the hash covers that a preview doesn't print</h3><p>A preview prints the target and, under each change, what it declares and every
step, with a file's content as a descriptor: its kind, length, and the start of
its SHA-512 (for a template, of the template text as written). <code>plan_hash</code> also
covers:</p><ul><li>a <code>file</code>'s content bytes, and any literal credential;</li><li>a resource's <code>depends_on</code>, and trigger sources;</li><li>package names for managers the target doesn't use;</li><li>the text of the scripts Zap's own operations run (the put, link, directory,
extract, snapshot, <code>pg_hba.conf</code>, and swap-path scripts, and an installer's
fetch) and the command each runs in, with its arguments, privilege, and limits,
so a <code>zap</code> build whose scripts, or the way it calls them, differ from the one that
previewed computes a different hash.</li></ul><p>The hash is not a fingerprint of the zap binary: what it does natively on a
local target, and the few commands it composes directly around a path (the <code>rm -f</code> that clears a pending marker or removes what a failed validated write
created), are its own.</p><h3>What an approved hash doesn't fix</h3><p>What Zap can't know when it plans:</p><ul><li>a secret's value (the plan says only that the reference is one);</li><li>the state of the target between the read and the change;</li><li>what the target's shell expands inside a command (<code>$HOME</code>, a variable in an
apt <code>source</code> line), which on a local target is Zap's own environment, whose <code>HOME</code> an <code>--env-file</code> doesn't set;</li><li>the bytes of a <code>source</code> file already on the target;</li><li>what an <code>installer</code> URL serves that day;</li><li>the path PostgreSQL reports for its <code>pg_hba.conf</code>;</li><li>in a deploy, the artifact bytes and the environment your <code>build</code> and <code>prepare</code> commands run in.</li></ul><p>Some commands also run before any review, as the connecting user, on every pass
that reads the machine (<code>plan</code>, <code>detect</code>, <code>apply</code> dry or wet, the deploy
preflight): a <code>script</code>'s <code>check</code>, a <code>verify</code>'s <code>command</code> assertions, a package's <code>check</code> when it is a command, and an apt <code>source</code> line, which the target's shell expands
to compare with the list, so a <code>$(…)</code> in it runs at <code>zap plan</code>. This is one
reason <a>the config is first-party</a>.</p><h3>Escaped output</h3><p>A review is only as good as the text it reads. Everything Zap prints as text
writes what it takes from the config, the environment, the command line, <code>zap.lock</code>, a file under <code>~/.zap</code>, or the target with control, bidirectional,
and default-ignorable characters (every control character but tab, the line and
paragraph separators, zero-width characters and the like) spelled out as <code>&lt;U+XXXX></code>, and a tab as spaces, so such text can't move the cursor, overwrite
output, reorder what is shown, or sit in a line unseen. Text that is a block (a
command, a script, what a failed command printed) keeps its lines, each
indented under its first. The <code>--json</code> event stream writes the same characters
as JSON <code>\\u</code> escapes. The escape doesn't make look-alikes distinguishable:
homoglyphs, wide or blank spaces, and combining marks print as they are, a long
line still wraps, and text that spells <code>&lt;U+000D></code> or <code></code> prints the
same as what Zap writes for one.</p><h2>Secrets</h2><ul><li>A config never reads the environment. Values are references
(<code>zap.env('NAME')</code>), resolved by Zap when it acts. A reference holds a name,
never a value. No value a reference resolves to, nothing a command prints,
and no file's bytes can turn into one.</li><li>Which references are secrets, and the forms masking looks for: <a>env.md</a>. A secret's value is <strong>masked</strong> out of every
output: the text report, the JSON events, warnings, held reasons, drift
observations, deploy step output, and errors. Masking is by value: a secret a
tool prints in another form (the address <code>ssh</code> resolved a secret host name to)
isn't found, and a secret under an ordinary name with an ordinary-looking
value isn't known to be one until <code>mask()</code> lists it.</li><li>Zap hands every command to its shell on <strong>stdin</strong>, detection and apply alike.
No command text, <code>env</code> value, or working directory is on the argv of <code>ssh</code>,
the login shell, or <code>sh</code>, on either machine, so none shows in <code>ps</code>. File
content travels on stdin too. A program a command starts still shows its own
arguments while it runs, and that includes the ones Zap starts (<code>curl &lt;url></code>, <code>psql -c &lt;sql></code>). Give a program a secret through an <code>env</code> value or a file it
reads, not as an argument.</li><li>A value is substituted into a command as text, into whatever quoting
surrounds the reference. Zap <strong>refuses</strong> a value holding a single quote, a
NUL, or a reference delimiter (U+FDD0 or U+FDD1) in a command, and a double
quote in a <code>database</code> identifier, before anything runs:
a wetrun checks every planned command first and exits 2 with nothing changed; <code>zap plan</code> and a dry run warn. That makes a reference safe <strong>inside single quotes</strong>, where a shell reads every other byte literally, and
Zap and the shipped recipes put every value there, except the options
documented as shell words (<code>psql_args</code>, <code>command_args</code>, a stop or reload
command). A reference a config author writes outside single quotes, bare or
inside double quotes, is read by the shell like the text around it, and
keeping it safe there is the author's job. An <code>env</code> value is quoted after it
resolves and carries anything but a NUL and the reference delimiters U+FDD0
and U+FDD1.</li><li>The <strong>last-run report</strong> and <strong><code>zap.lock</code></strong> hash a secret reference as a fixed
token, and the report masks every registered secret out of any other value,
so neither can be used to test a guess at a secret. A secret the rule doesn't
recognize is hashed by value until <code>mask()</code> lists it
(<a>lock.md</a>).</li><li>A fetch error names the URL as the config declares it, its references unresolved,
and the content cache names a file from the declared URL, so a token in a URL
reaches neither a message nor a path.</li><li><code>remote</code> and <code>build</code> sources can carry a bearer <code>auth</code> token; it attaches as a
request header to the source's own origin (scheme, host, and port) only: a <code>signature_url</code> on another origin is fetched without it, and a redirect to
another origin drops it. Its resolved value is never hashed and never reaches
the lock.</li><li>There is no <code>--show-secrets</code>.</li></ul><h2>Content Zap fetches</h2><p>Every URL in a config is <code>https://</code>: a plain <code>http://</code>, <code>file://</code>, or any other
scheme doesn't validate, and neither does a URL carrying <code>user:password@</code>. The
one allowance is <code>http://</code> to a loopback host for the fetches Zap makes itself,
for a local mirror. Zap follows a redirect only to another <code>https://</code> URL (a
fetch that has stayed on loopback may be redirected on loopback), so a remote
server can't send a fetch to a plain-<code>http</code> port of the machine Zap runs on,
and a bearer <code>auth</code> goes only to the origin the config names.</p><p>Fetched bytes are pinned by blake3, verified against the pin before placement,
and cached by content address. A vendored pin is your own statement of which
bytes to trust. A tracked pin is trust on first fetch: <code>zap lock</code>, <code>zap update</code>,
or the first <code>zap apply --wetrun</code> records the hash of what the URL served then, and every
later fetch must match it. What authenticates that first fetch is TLS, plus a
minisign signature when a <code>build</code> source declares <code>verify</code>, checked before the
bytes are cached or pinned. A signature doesn't fix the version: an older
release the same key signed is caught only by the pin
(<a>resources.md</a>). The recorded pin is in <code>zap.lock</code> and in the plan hash, so it is reviewed like any other change. <code>minisign</code>'s exit status is that verdict, so the binary is found once (the
absolute path <code>ZAP_MINISIGN</code> names, else <code>PATH</code>) and run by that path, and one
inside a <code>node_modules</code> directory, or where it or any directory on the way to it
(every one up to <code>/</code>, links followed) is in reach of a group, another account,
or anyone but root and you, is refused; a refusal or a failed check names its
path. With those directories trusted, the gap between the check and the run is
only root's and yours.</p><p><code>zap.lock</code> is reviewed input, like the config: its <code>config_hash</code> detects
staleness, not forgery, so review the lock's diff before committing it
(<a>lock.md</a>).</p><p>One thing reaches the target with no pin. An <code>installer</code> is a script fetched
whole over https and then run: whatever its URL serves today, gated only by a <code>check</code> path. A fetch that fails fails the step, and so does one that
serves an empty script; nothing runs. Prefer a <code>build</code> or a pinned <code>remote</code> file when the upstream offers one. An <code>apt_repo</code>'s signing key is pinned like <code>remote</code> content: Zap installs only bytes whose blake3 is the pin, and
detection compares the installed key with it
(<a>resources.md</a>).</p><h2>Writes on the host</h2><p>Zap installs a file by staging it under a new name in the file's own directory,
setting owner and mode on the open file, and renaming it into place; it never
follows a link at the file's name or at the staged name, and a <code>file</code>'s or <code>directory</code>'s mode and owner are never set by name. The bytes are checked
against their SHA-512 before the rename, so a transfer cut short installs nothing. A directory's owner
and mode are set on the directory itself; a link at its name is refused. A <code>file</code> keeps the owner, group, and mode it leaves unset from the regular file it
replaces, read from the name without following a link, never with a set-id or
sticky bit; a new one takes its directory's owner and group. A file with a second
name (a hard link) keeps nothing, and neither does anything below a directory
with its sticky bit set or that every account may write (<code>/tmp</code>, <code>/var/tmp</code>, <code>/dev/shm</code>), however deep — Zap walks up from the file's directory by <code>..</code> to the
root, and checks every directory on the path as written, a link read as what it
leads to: there a <code>file</code> takes what Zap's own write gives, as root over SSH or as
you locally. A mode is never kept from a file with an extended POSIX access list
(ACL), whose mode bits show the list's mask: the write is refused until the
config declares <code>mode</code>. Zap sees a list through <code>getfacl</code>, else through GNU <code>ls</code>'s <code>+</code>; a target with neither (stock Alpine) can't show one, and keeps the
mode. Elsewhere, whoever can write the directory can choose what is
kept, as they could replace the file; the files Zap's steps install never keep a
planted owner. So a <code>file</code> with a <code>mode</code> but no <code>owner</code>, written into a directory
another account can write, can end up readable by that account: it inherits that
account's directory, or the account plants a file there of its own for Zap to
keep. Declare <code>mode</code>, <code>owner</code>, and <code>group</code> on any file whose content the
directory's owner or group must not read: a planted file's mode is kept even
when the owner and group are declared, so without a <code>mode</code> the content can land
readable by everyone. A <code>user</code>'s <code>authorized_keys</code> is written as that user, and a sudoers file is
installed only after <code>visudo -c</code> accepts it.</p><p>A file with a <code>validate</code> command is read before its write, so a failed check can
put it back. One script holds the file open and reads its bytes, mode, and
owner through that descriptor: as root over SSH, and locally as you, escalating
when refused. The change fails with nothing written when the name holds a link,
anything but a regular file (a fifo is refused without waiting on it), or a file
over 16 MiB. A rollback restores the bytes with the owner and group they had,
and their mode without any set-id or sticky bit the declared <code>mode</code> doesn't
carry, so root never makes a file set-id that the config didn't.</p><p>One window stays open: between the read's checks and its open, a link swapped
in is opened (not read) and the read refused, unless it leads to a fifo, which
holds the open until the read's five-minute timeout fails the change. A
directory's owner and mode change has the same window and timeout.</p><p>Missing directories are made one at a time, each inside the one before it held
open, and given, through its descriptor, the owner and group of the directory it
was made in, so it belongs to someone who could have made it; a link swapped in
for one is refused, with nothing made through it. The owner is given only to the
empty directory Zap just made: a directory renamed over it before it was opened,
by the owner of the directory it was made in, is refused and given nothing.
Anywhere below a directory with its sticky bit set or that every account may
write (<code>/tmp</code>), however deep, on the path as written or where its links lead,
what Zap makes stays its own, as root over SSH or as you locally: an account
that made <code>/tmp/cache</code>, as a directory or as a link to one of its own, can't
have the directories Zap makes there given to it.</p><p>Reads of a file's bytes, as root over SSH, read only a regular file of its own:
a name that is a symbolic link, a directory, a device, or a fifo is refused
before it is opened, and what was opened is read only when it is a regular file
and still the file at the name, so no byte comes through a symbolic link. The
checks can't close the instant before the open: an account that can write where
a managed file lives and swaps the name for a symbolic link in that instant has
Zap open what the link names, though not read it, and opening some devices acts
on the machine (a watchdog's), while a fifo holds the read until its timeout. A
regular file with more than one hard link is not read either, whoever owns it:
a hard link is the same file under another name, which an account can make in a
directory it writes, so a root read of the name could read a file that account
linked there. The link count is read from what was opened, and such a file
holds its resource, with the fix: replace it with a copy of its own (a single
link). Keep managed files in directories only root can write all the same. A <code>file</code>'s <code>source</code> is read the same way, and a <code>user</code>'s own <code>authorized_keys</code> is
read as that user.</p><p>Zap does follow a link in a directory component of the path, so a managed path
under a directory someone else can write can be redirected to another
directory: keep root-managed files in directories only root can write. One
such redirection also slips past the shared-directory checks above: a link on
the path that leads through a second link sitting in a directory every account
may write, off both the path as written and the directories it resolves to
(<code>/srv/app</code> a link to <code>/var/shared/app</code>, itself a link the account that can
write <code>/var/shared</code> points at a directory of its own). Neither check passes
through <code>/var/shared</code>, so what is kept there, or given to directories made
there, is that account's choice. Keep the links on a managed path out of
directories others can write. The staged file is made by <code>mktemp</code>, mode <code>600</code> whatever the umask or a default access list on the directory would give, and
held open; before a byte is written it must be a regular file of the writer's,
empty, with one name, and still the file at the staged name. A local user who
can write the directory could make the write fail, or stall it by swapping the
staged name for a fifo; they could not send the content, mode, or owner
anywhere, nor have root create a file where a link of theirs points. A run killed outright, or one refused at
its stage check, can leave a <code>.zap.*</code> file beside its target. A target needs <code>/proc</code>.</p><p>The same holds for the files Zap's steps install: an apt sources list, the
nftables ruleset, and <code>/etc/fstab</code> are each installed whole by rename, never
edited in place, and so is an <code>apt_repo</code>'s signing key. <code>pg_hba.conf</code> is too,
but as the <code>postgres</code> account, not root:
PostgreSQL names the file and <code>postgres</code> owns its directory, so a rewrite as
root would write wherever that account pointed it. The rewrite keeps the file's
group and mode, and refuses a file that doesn't belong to <code>postgres</code> or a
directory it can't write; detection reads the file as <code>postgres</code> as well.</p><p>A <code>remote</code> file's or <code>build</code> source's archive is extracted only into a directory
at its own name: a link there is refused. <code>tar</code> runs in a new directory inside a
private staging directory (mode <code>0700</code>, the extracting user's) beside the
destination. The staging directory is held open from the moment it is checked:
a fresh, empty directory of the extracting user's, mode <code>0700</code>, at its name,
and not a link. Everything inside it is then reached through the descriptor, so
an account that can write the destination's parent may rename the staging
directory, or put a link at its name, but can't steer where <code>tar</code> writes or
what is removed. What <code>tar</code> extracts belongs to the extracting user, with no
set-id bit on a file and nothing group- or world-writable, whatever the archive
records. Before the rename, still inside the staging directory, the new tree is
given the owner, group, and mode of the destination it replaces, read without
following a link and set on the directory held open, never with a set-id or
sticky bit; then it is renamed into place. Below a directory with its sticky bit
set or that every account may write, checked as for a <code>file</code> (the parent's path
as written and where it resolves), nothing is kept: the new tree stays the
extracting user's, at the mode <code>mkdir</code> gives it. A destination that has an
extended or default access list is refused, a declared <code>mode</code> or not; the list
must be removed (<code>setfacl -b</code>). Such an account can still move the destination
itself, or the tree once it is in place: a parent another account can write is
trusted to that extent. The
archive's contents are trusted as pinned: its author chooses the names inside
it. Neither <code>tar</code> writes through a symbolic link the archive carries. BusyBox <code>tar</code> will make a hard link to a file outside the archive that a member names, so
a new tree holding a file linked from outside it is refused, and removed before
it is renamed into place; hard links among the archive's own files extract.</p><p>A <code>remote</code> or <code>build</code> archive is uploaded as the connecting user into a
private staging directory of the run, then extracted as root. The extraction
opens it once and goes on only when the file it holds is a regular file, not a
link, owned by the account that ran <code>sudo</code>, with one link and writable by no one
else. It then copies what it holds into its own staging directory, which only
root reaches, and extracts that copy only when its SHA-512 is the digest of the
pinned bytes Zap passed, so a process running as the connecting user can't
swap or rewrite the archive between the upload and the extraction.</p><p><code>hardened_openrc_service</code> never sources an <code>env_file</code>: its init script runs as
root, so root never parses it: <code>start_pre</code> has the service user check every
line (<code>su</code>, under a 10-second <code>timeout</code>), assigning nothing, and the daemon's own
process, already dropped to that user, exports the values before it runs the
command (<a>recipes.md</a>). A service user that
can write its env file changes its own environment, as under systemd, and can
make a start wait out the timeout or fail; the refusal <code>start_pre</code> prints is
that user's process's words.</p><p>A release archive sits in no shared directory on either machine. On yours it is
a file in a private directory of the run; on the target it is installed into
the app path as the connecting user, and the release script extracts only the
file it has open, after checking that it belongs to that user, is writable by
no one else, and has the digest Zap sent. So another account on the host can't
swap or alter it between the upload and the extraction. Nothing checks what
your build put in it. A deploy trusts whoever can write the app path as much as
it trusts the connecting user: they can re-point <code>current</code>. Deploying as <code>root</code> into a path another account can write lets that account redirect what root
creates there, so deploy as the path's owner. A run killed outright, or a
connection dropped between the upload and the script, can leave the archive at
mode <code>600</code> in the app path or in your temporary directory.</p><h2>Authority on the host</h2><p>Zap's authority is SSH plus the host's <code>sudo</code>. There is no agent, server, API,
or role system to compromise. Privileged commands carry an explicit <code>sudo</code>; on a
local target file operations escalate only when denied, and over SSH they run
under <code>sudo</code> (<a>targets.md</a>). Host
keys are trusted on first use and refused when changed, which holds only while <code>ssh</code> records them: Zap reads your effective <code>ssh</code> config once per target
(<code>ssh -G</code>) and refuses to connect when every <code>UserKnownHostsFile</code> is <code>/dev/null</code>. Every session has agent, X11, and port forwarding, a tunnel
device, a terminal, and <code>LocalCommand</code> turned off, whatever your config says. The host's own <code>sudo</code> I/O log (<code>Defaults log_input</code>, replayed with <code>sudoreplay</code>) is the audit trail of
what ran as root: the plain <code>sudo</code> log records one constant wrapper per
detection batch, and the I/O log captures the script, resolved reference values
included. It never sees the unprivileged login lane, where operator commands
run. A file write appears in the <code>sudo</code> log as one <code>sh -c</code> command carrying
Zap's constant install script, with the path as its argument; the mode and owner
are arguments too, and the content and its digest arrive on stdin, so a host
that logs sudo's input records them.</p><h2>Fail closed</h2><ul><li>A resource Zap can't read is <strong>held</strong>, not guessed. The run exits 1, and <code>deploy</code>'s preflight refuses to ship (exit 2). A "converged" that wasn't
established is never reported.</li><li>A pin that isn't current is <strong>withheld</strong>, so a stale lock can't make a changed
resource read converged.</li><li>A reference the comparison needs but can't resolve makes the whole pass <strong>unverifiable</strong>, exit 1: an empty string can both hide drift and invent it.</li><li>A <code>file</code> write with <code>validate</code> is rolled back when the check fails, so a
service is never reloaded onto a rejected config.</li><li>A failed reload is remembered on the target and re-fired on the next plan.</li></ul><h2>Security controls are read live, every time</h2><p><code>firewall</code>, <code>user</code>, and <code>database</code> guard the host's access surface and are
exactly what gets changed by hand: a <code>ufw default allow incoming</code> at the console,
or a key appended to <code>authorized_keys</code>. Zap keeps no detection cache, so such a
change shows on the next plan rather than hiding behind a stored verdict. The
same holds for security-relevant files: an <code>sshd</code> drop-in, a fail2ban jail, an
nginx site carrying a CSP. The exception is the lists Zap treats as additive
(<a>below</a>): a declared entry that went missing
drifts, but an extra one, such as an injected <code>pg_hba</code> <code>trust</code> line, isn't
read.</p><h2>Limits and defaults to know</h2><ul><li>Firewall allow rules, a database's <code>pg_hba</code> rules, and a user's groups are <strong>additive</strong>. Zap asserts that each declared entry is present (and, for a
firewall, that the default policies match); an entry added out of band is
neither detected nor removed.</li><li>A <code>database</code> resource writes no <code>pg_hba</code> rule unless it declares <code>auth.hosts</code>, and never a <code>trust</code> one: the role is reached over the Unix socket
by the OS account of the same name. A <code>trust</code> rule already in the file (one an
older config added) stays until it is removed by hand; on Alpine, <code>alpine_postgres_setup</code> rewrites <code>initdb</code>'s, and any other <code>trust</code> line, to <code>peer</code> / <code>scram-sha-256</code>.</li><li>A <code>link</code> whose path is a regular file reads as absent and is replaced.</li><li>A <code>file</code> with no managed mode, owner, or group whose path is a symlink to
matching content reads converged; the link is left as it is.</li><li>Zap follows a symlink in a <strong>directory component</strong> of a managed path (see <a>Writes on the host</a>).</li><li>A <code>swap</code>'s <code>size</code> is not compared after creation.</li></ul><h2>Reporting a vulnerability</h2><p>See the repository's security policy for how to report an issue privately.</p>`,1);function v(s,v){d(v,!0);let y=h(`security`);u(`1qwo2vp`,e=>{n(()=>{f.title=`Security model — zap`})}),g(s,{get tome(){return y},children:(n,a)=>{_(n,{children:(n,a)=>{var s=ee(),u=t(r(s));l(u,`id`,`the-threat-model-in-one-paragraph`);var d=t(u),f=t(i(d),7);l(f,`href`,`#what-an-approved-hash-doesnt-fix`);var h=t(f,2);l(h,`href`,`#the-config-is-first-party`),p(),o(d);var g=t(d);l(g,`id`,`the-config-can-only-describe`);var _=t(g),v=t(i(_));p(5),o(_);var y=t(_),b=t(i(y),3),te=t(i(b),4);p(),o(b),p(3),o(y);var x=t(y,2),ne=t(i(x),8);ne.textContent=`{"type": "module"}`,p(3),o(x);var S=t(x,5),re=t(i(S),14);p(3),o(S);var C=t(S),ie=t(i(C),6);p(),o(C);var w=t(C);l(w,`id`,`the-config-is-first-party`);var T=t(w,2);l(T,`id`,`what-the-gates-reject-before-anything-runs`);var E=t(T,2),ae=t(i(E)),oe=t(i(ae),2);p(),o(ae),o(E);var se=t(E,2);l(se,`id`,`zap-changes-nothing-without-a-wetrun`);var D=t(se),ce=t(i(D),13);l(ce,`href`,`#what-an-approved-hash-doesnt-fix`),p(7),o(D);var O=t(D);l(O,`id`,`a-wetrun-executes-only-the-plan-you-reviewed`);var k=t(O),A=t(i(k),5),j=t(A,4),le=t(j,4);p(),o(k);var M=t(k,2);l(M,`id`,`what-the-hash-covers-that-a-preview-doesnt-print`);var N=t(M,4);l(N,`id`,`what-an-approved-hash-doesnt-fix`);var P=t(N,3),ue=t(i(P),23);l(ue,`href`,`#the-config-is-first-party`),p(),o(P);var F=t(P);l(F,`id`,`escaped-output`);var I=t(F),de=t(i(I),13);de.textContent=`{env:NAME}`,p(),o(I);var L=t(I);l(L,`id`,`secrets`);var R=t(L),z=t(i(R)),fe=t(i(z));p(7),o(z);var B=t(z,3),pe=t(i(B),7);p(),o(B),p(3),o(R);var V=t(R);l(V,`id`,`content-zap-fetches`);var H=t(V,2),me=t(i(H),11);p(13),o(H);var U=t(H),he=t(i(U),4);p(),o(U);var W=t(U),ge=t(i(W),13);p(),o(W);var G=t(W);l(G,`id`,`writes-on-the-host`);var K=t(G,10),_e=t(i(K),10);p(3),o(K);var q=t(K,2);l(q,`id`,`authority-on-the-host`);var J=t(q),ve=t(i(J),7);p(25),o(J);var Y=t(J);l(Y,`id`,`fail-closed`);var X=t(Y,2);l(X,`id`,`security-controls-are-read-live-every-time`);var Z=t(X),ye=t(i(Z),12);l(ye,`href`,`#limits-and-defaults-to-know`),p(5),o(Z);var be=t(Z);l(be,`id`,`limits-and-defaults-to-know`);var Q=t(be),$=t(i(Q),4),xe=t(i($),3);l(xe,`href`,`#writes-on-the-host`),p(),o($),p(),o(Q);var Se=t(Q);l(Se,`id`,`reporting-a-vulnerability`),p(),e((e,t,n,r,i,a,o,s,c,u,d,f,p,m,h)=>{l(v,`href`,e),l(te,`href`,t),l(re,`href`,n),l(ie,`href`,r),l(oe,`href`,i),l(A,`href`,a),l(j,`href`,o),l(le,`href`,s),l(fe,`href`,c),l(pe,`href`,u),l(me,`href`,d),l(he,`href`,f),l(ge,`href`,p),l(_e,`href`,m),l(ve,`href`,h)},[()=>m(`docs/configs#the-sandbox`),()=>m(`docs/configs#the-sandbox`),()=>m(`docs/lock#the-toolchain-pin`),()=>m(`docs/cli#environment-variables-zap-reads`),()=>m(`docs/configs#what-the-gates-reject`),()=>m(`docs/concepts#a-wetrun-executes-only-the-plan-you-reviewed`),()=>m(`docs/deploy#binding-a-wetrun-to-a-reviewed-plan`),()=>m(`docs/env#masked-hosts-and-review`),()=>m(`docs/env#secrets`),()=>m(`docs/lock#what-an-entry-holds`),()=>m(`docs/resources#verification`),()=>m(`docs/lock#what-an-entry-holds`),()=>m(`docs/resources#apt_repo`),()=>m(`docs/recipes#env-files-under-openrc`),()=>m(`docs/targets#two-tier-privilege-escalation`)]),c(n,s)},$$slots:{default:!0}})},$$slots:{default:!0}}),a()}export{v as t};